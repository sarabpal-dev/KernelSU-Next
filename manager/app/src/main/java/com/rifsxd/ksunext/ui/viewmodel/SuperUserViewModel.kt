package com.rifsxd.ksunext.ui.viewmodel

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.os.IBinder
import android.os.Parcelable
import android.os.SystemClock
import android.util.Log
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.edit
import android.graphics.drawable.Drawable
import androidx.lifecycle.ViewModel
import com.rifsxd.ksunext.IKsuInterface
import com.rifsxd.ksunext.KernelSUApplication
import com.rifsxd.ksunext.Natives
import com.rifsxd.ksunext.ksuApp
import com.rifsxd.ksunext.ui.KsuService
import com.rifsxd.ksunext.ui.util.HanziToPinyin
import com.topjohnwu.superuser.ipc.RootService
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.parcelize.Parcelize
import java.io.File
import java.io.FilterOutputStream
import java.text.Collator
import java.util.*
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class SuperUserViewModel : ViewModel() {

    private var ksuConnection: ServiceConnection? = null

    companion object {
        private const val TAG = "SuperUserViewModel"
        const val WEBVIEW_ZYGOTE_UID = 1053
        const val WEBVIEW_ZYGOTE_PROFILE_KEY = "webview_zygote"

        var apps by mutableStateOf<List<AppInfo>>(emptyList())

        @JvmStatic
        fun getAppIconDrawable(context: Context, packageName: String): Drawable? {
            val appDetail = apps.find { it.packageName == packageName }
            return appDetail?.packageInfo?.applicationInfo?.loadIcon(context.packageManager)
        }
        private var profileOverrides by mutableStateOf<Map<String, Natives.Profile>>(emptyMap())
    }

    @Parcelize
    data class AppInfo(
        val label: String,
        val packageInfo: PackageInfo,
        val profile: Natives.Profile?,
        val profileKey: String = packageInfo.packageName ?: "",
        val special: Boolean = false,
    ) : Parcelable {
        val packageName: String
            get() = packageInfo.packageName ?: ""

        val displayIdentifier: String
            get() = if (special) profileKey else packageName

        val uid: Int
            get() = packageInfo.applicationInfo!!.uid

        val isWebViewZygote: Boolean
            get() = special && uid == WEBVIEW_ZYGOTE_UID

        val allowSu: Boolean
            get() = !isWebViewZygote && profile != null && profile.allowSu

        val hasCustomProfile: Boolean
            get() {
                if (profile == null) {
                    return false
                }

                return if (isWebViewZygote) {
                    !profile.nonRootUseDefault
                } else if (profile.allowSu) {
                    !profile.rootUseDefault
                } else {
                    !profile.nonRootUseDefault
                }
            }
    }

    private val prefs = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE)!!

    var search by mutableStateOf("")
    var showSystemApps by mutableStateOf(prefs.getBoolean("show_system_apps", false))
        private set
    var isRefreshing by mutableStateOf(false)
        private set

    fun updateShowSystemApps(newValue: Boolean) {
        showSystemApps = newValue
        prefs.edit { putBoolean("show_system_apps", newValue) }
    }

    private val sortedList by derivedStateOf {
        val comparator = compareBy<AppInfo> {
            when {
                it.profile != null && it.profile.allowSu -> 0
                it.profile != null && (
                        if (it.profile.allowSu) !it.profile.rootUseDefault else !it.profile.nonRootUseDefault
                        ) -> 1

                else -> 2
            }
        }.then(compareBy(Collator.getInstance(Locale.getDefault()), AppInfo::label))
        apps.sortedWith(comparator).also {
            isRefreshing = false
        }
    }

    val appList by derivedStateOf {
        sortedList.map { app ->
            profileOverrides[app.displayIdentifier]?.let { app.copy(profile = it) } ?: app
        }.filter {
            it.label.contains(search, true) || it.displayIdentifier.contains(
                search,
                true
            ) || HanziToPinyin.getInstance()
                .toPinyinString(it.label).contains(search, true)
        }.filter {
            it.uid == 2000 // Always show shell
                    || it.special
                    || showSystemApps || it.packageInfo.applicationInfo!!.flags.and(ApplicationInfo.FLAG_SYSTEM) == 0
        }
    }

    fun updateAppProfile(packageName: String, newProfile: Natives.Profile) {
        profileOverrides = profileOverrides.toMutableMap().apply {
            put(packageName, newProfile)
        }
    }

    private suspend inline fun connectKsuService(
        crossinline onDisconnect: () -> Unit = {}
    ): Pair<IBinder, ServiceConnection> = suspendCancellableCoroutine { cont ->
        val connection = object : ServiceConnection {
            override fun onServiceDisconnected(name: ComponentName?) {
                onDisconnect()
            }

            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                if (cont.isActive) {
                    cont.resume(binder as IBinder to this)
                }
            }
        }

        ksuConnection = connection

        val intent = Intent(ksuApp, KsuService::class.java)

        try {
            // Ensure any existing main.jar is writable or deleted so libsu's FileOutputStream won't fail with EACCES
            KernelSUApplication.cleanStaleDexFiles(ksuApp)

            val task = RootService.bindOrTask(
                intent,
                Shell.EXECUTOR,
                connection,
            )

            task?.let { originalTask ->
                Shell.getShell().execTask { stdin, stdout, stderr ->
                    val interceptingStdin = object : FilterOutputStream(stdin) {
                        override fun write(b: ByteArray, off: Int, len: Int) {
                            val cmd = String(b, off, len, Charsets.UTF_8)
                            if (cmd.contains("RootServerMain")) {
                                val deCache = runCatching { ksuApp.createDeviceProtectedStorageContext().cacheDir }.getOrNull()
                                val jarPath = File(deCache ?: ksuApp.cacheDir, "main.jar").absolutePath
                                val patchedCmd = "chmod 0444 '$jarPath' 2>/dev/null; $cmd"
                                val bytes = patchedCmd.toByteArray(Charsets.UTF_8)
                                out.write(bytes, 0, bytes.size)
                            } else {
                                out.write(b, off, len)
                            }
                        }

                        override fun write(b: ByteArray) {
                            write(b, 0, b.size)
                        }
                    }

                    // Before running task, ensure main.jar can be written
                    KernelSUApplication.cleanStaleDexFiles(ksuApp)

                    originalTask.run(interceptingStdin, stdout, stderr)

                    // Also mark read-only from client side
                    KernelSUApplication.ensureDexFilesReadOnly(ksuApp)
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "connectKsuService failed", e)
            if (cont.isActive) {
                cont.resumeWithException(e)
            }
        }
    }

    private fun stopKsuService() {
        val intent = Intent(ksuApp, KsuService::class.java)
        ksuConnection?.let { RootService.unbind(it) }
        ksuConnection = null
        RootService.stop(intent)
        // Clean up main.jar so nothing stale remains on disk
        KernelSUApplication.cleanStaleDexFiles(ksuApp)
    }

    val fetchMutex = Mutex()
    suspend fun fetchAppList() {
        fetchMutex.withLock {

            isRefreshing = true

            try {
                val start = SystemClock.elapsedRealtime()

                val (binder, _) = connectKsuService {
                    Log.w(TAG, "KsuService disconnected")
                }

                withContext(Dispatchers.IO) {
                    val pm = ksuApp.packageManager
                    val allPackages = IKsuInterface.Stub.asInterface(binder).getPackages(0)


                    val packages = allPackages.list

                    apps = packages.filter {
                        val ai = it.applicationInfo ?: return@filter false
                        ai.uid != WEBVIEW_ZYGOTE_UID
                    }.map {
                        val appInfo = it.applicationInfo!!
                        val uid = appInfo.uid
                        val profile = Natives.getAppProfile(it.packageName, uid)
                        AppInfo(
                            label = appInfo.loadLabel(pm).toString(),
                            packageInfo = it,
                            profile = profile,
                        )
                    }.toMutableList().apply {
                        val systemInfo = ApplicationInfo(pm.getApplicationInfo("android", 0)).apply {
                            uid = WEBVIEW_ZYGOTE_UID
                        }
                        val placeholder = PackageInfo().apply {
                            packageName = ""
                            applicationInfo = systemInfo
                        }
                        add(
                            AppInfo(
                                label = "WebView Zygote",
                                packageInfo = placeholder,
                                profile = Natives.getAppProfile(
                                    WEBVIEW_ZYGOTE_PROFILE_KEY,
                                    WEBVIEW_ZYGOTE_UID
                                ),
                                profileKey = WEBVIEW_ZYGOTE_PROFILE_KEY,
                                special = true,
                            )
                        )
                    }
                }
                Log.i(TAG, "load cost: ${SystemClock.elapsedRealtime() - start}")
            } catch (e: Exception) {
                Log.e(TAG, "fetchAppList failed", e)
            } finally {
                isRefreshing = false
                withContext(Dispatchers.Main) { stopKsuService() }
            }
        }
    }
}
