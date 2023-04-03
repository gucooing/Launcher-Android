package yuuki.yuukips

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.content.res.XModuleResources
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.ShapeDrawable
import android.graphics.drawable.shapes.RoundRectShape
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.Base64
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.webkit.SslErrorHandler
import android.widget.*
import com.github.kyuubiran.ezxhelper.init.EzXHelperInit
import com.github.kyuubiran.ezxhelper.utils.*
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import org.json.JSONObject
import yuuki.yuukips.Utils.dp2px
import yuuki.yuukips.Utils.isInit
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.regex.Pattern
import javax.net.ssl.*
import kotlin.system.exitProcess
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.PorterDuff
import java.io.FileWriter
import java.io.BufferedWriter
import java.io.IOException
import java.util.Date
import java.text.SimpleDateFormat
import org.json.JSONException

class Hook {

    // just for login
    private val package_apk = "com.miHoYo.GenshinImpact"
    private val path = "/data/user/0/${package_apk}"
    private val file_json = "/data/user/0/${package_apk}/server.json"
    private val proxyListRegex = arrayListOf( 
        // CN
        "dispatchcnglobal.yuanshen.com",
        "gameapi-account.mihoyo.com",
        "hk4e-sdk-s.mihoyo.com",
        "log-upload.mihoyo.com",
        "minor-api.mihoyo.com",
        "public-data-api.mihoyo.com",
        "sdk-static.mihoyo.com",
        "webstatic.mihoyo.com",
        "user.mihoyo.com",
        // Global
        "dispatchosglobal.yuanshen.com",        
        "api-account-os.hoyoverse.com",
        "hk4e-sdk-os-s.hoyoverse.com",
        "hk4e-sdk-os-static.hoyoverse.com",
        "hk4e-sdk-os.hoyoverse.com",
        "log-upload-os.hoyoverse.com",
        "minor-api-os.hoyoverse.com",
        "sdk-os-static.hoyoverse.com",
        "sg-public-data-api.hoyoverse.com",
        "webstatic.hoyoverse.com",
        // List Server
        "osasiadispatch.yuanshen.com",
        "oseurodispatch.yuanshen.com",
        "osusadispatch.yuanshen.com"
    )
    
    private lateinit var server: String
    private lateinit var serversdklog: String
    private lateinit var showServer: String
    private lateinit var textJson: String

    private lateinit var modulePath: String
    private lateinit var moduleRes: XModuleResources
    private lateinit var windowManager: WindowManager

    private val activityList: ArrayList<Activity> = arrayListOf()
    private var activity: Activity
        get() {
            for (mActivity in activityList) {
                if (mActivity.isFinishing) {
                    activityList.remove(mActivity)
                } else {
                    return mActivity
                }
            }
            throw Throwable("Activity not found.")
        }
        set(value) {
            activityList.add(value)
        }

    private fun getDefaultSSLSocketFactory(): SSLSocketFactory {
        return SSLContext.getInstance("TLS").apply {
            init(arrayOf<KeyManager>(), arrayOf<TrustManager>(DefaultTrustManager()), SecureRandom())
        }.socketFactory
    }

    private fun getDefaultHostnameVerifier(): HostnameVerifier {
        return DefaultHostnameVerifier()
    }

    class DefaultHostnameVerifier : HostnameVerifier {
        @SuppressLint("BadHostnameVerifier")
        override fun verify(p0: String?, p1: SSLSession?): Boolean {
            return true
        }

    }

    @SuppressLint("CustomX509TrustManager")
    private class DefaultTrustManager : X509TrustManager {

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkClientTrusted(chain: Array<X509Certificate?>?, authType: String?) {
        }

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkServerTrusted(chain: Array<X509Certificate?>?, authType: String?) {
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return arrayOf()
        }
    }

    fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        modulePath = startupParam.modulePath
        moduleRes = XModuleResources.createInstance(modulePath, null)
        TrustMeAlready().initZygote()

        // default
        server = ""
    }

    private var startForceUrl = false
    private var startProxyList = false
    private lateinit var dialog: LinearLayout

    @SuppressLint("WrongConstant", "ClickableViewAccessibility")
    fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {

        log_print("\n\n=====================================\nDATE: ${Date()}\n=====================================\nNew Log")

        log_print("Hi GenshinImpact")
        log_print("Load: "+lpparam.packageName)

        if (lpparam.packageName == "${package_apk}") {

            log_print("Package found: ${lpparam.packageName}")
            EzXHelperInit.initHandleLoadPackage(lpparam) // idk what this?

            // json for get server
            val z3ro = File(file_json)
            try {
                if (z3ro.exists()) {
                    val z3roJson = JSONObject(z3ro.readText())
                    server = z3roJson.getString("server")
                    log_print("server : $server")
                } else {
                    log_print("server.json not found.")
                    server = "https://sdk.mihoyu.cn"
                    z3ro.createNewFile()
                    z3ro.writeText(TextJSON(server))
                    log_print("New server.json created")
                }
            } catch (e: JSONException) {
                log_print("Error occured: ${e.message}")
            }
            tryhook()       
        } else {
            log_print("Package not found: ${lpparam.packageName} it should be ${package_apk}")
        }

        findMethod(Activity::class.java, true) { name == "onCreate" }.hookBefore { param ->
            activity = param.thisObject as Activity
            log_print("activity: "+activity.applicationInfo.name)            
        }

        findMethod("com.miHoYo.GetMobileInfo.MainActivity") { name == "onCreate" }.hookBefore { param ->
            activity = param.thisObject as Activity
            log_print("MainActivity")
            showDialog()
        }
    }

    private fun showDialog() {
        // remove folders if exist
        val z3ro = File(file_json)
        val z3roJson = JSONObject(z3ro.readText())
        if (z3roJson.getString("remove_il2cpp_folders") != "false") {
            val foldersPath = "${path}/files/il2cpp"
            val folders = File(foldersPath)
            if (folders.exists()) {
                folders.deleteRecursively()
            }
        }
        AlertDialog.Builder(activity).apply {
            setCancelable(false)
            setTitle("欢迎来到私人服务器")
            setMessage("采用yuuki开源模块制作\n请不要将此apk应用于商业行为\n否则将不会推出后续版本\n第一次使用请直接点击前往游戏下载资源\n项目地址:https://github.com/xlpmyxhdr/Launcher-Android")

            setPositiveButton("前往游戏") { _, _ ->
                enter()
            }
            setNegativeButton("更改服务器") { _, _ ->
                RenameJSON()             
            }

        }.show()
    }

    fun TextJSON(melon:String):String{
        return "{\n\t\"server\": \""+melon+"\",\n\t\"remove_il2cpp_folders\": true,\n\t\"showText\": true,\n\t\"move_folder\": {\n\t\t\"on\": false,\n\t\t\"from\": \"\",\n\t\t\"to\": \"\"\n\t}\n}"
    }

    private fun RenameJSON(){
        AlertDialog.Builder(activity).apply {
            setCancelable(false)
            setTitle("更改服务器")
            setMessage("如 (http://2.0.0.100)和https://yuanshen.com 确认更改后将关闭app,请重新打开")
            setView(ScrollView(context).apply {
                addView(EditText(activity).apply {
                    val str = ""
                    setText(str.toCharArray(), 0, str.length)
                    addTextChangedListener(object : TextWatcher {
                        override fun beforeTextChanged(p0: CharSequence, p1: Int, p2: Int, p3: Int) {}
                        override fun onTextChanged(p0: CharSequence, p1: Int, p2: Int, p3: Int) {}
                        @SuppressLint("CommitPrefEdits")
                        override fun afterTextChanged(p0: Editable) {
                            server = p0.toString()
                            if(server == "official" || server == "blank"){
                                server = "os"
                            }else if(server == "yuuki" || server == "yuukips" || server == "melon" && server != ""){
                                server = "https://sdk.mihoyu.cn"
                            } else if (server.contains("localhost") && server != "") {
                                server = server.replace("localhost", "https://127.0.0.1")
                                if (server.contains(" ")) {
                                    server = server.replace(" ", ":")
                                }
                            } else if (server == "https://" || server == "http://" && server != "") {
                                server = ""
                            } else if (!server.startsWith("https://") && (!server.startsWith("http://")) && server != "" && server != "official" && server != "blank" && server != "yuuki" && server != "yuukips" && server != "melon") {
                                server = "https://"+server
                            } else if (server == "") {
                                server = ""
                            }
                        }
                    })
                })
            })
            
            setPositiveButton("确认更改/将关闭app/请重新打开") { _, _ ->
                if (server == "" ) {
                    Toast.makeText(activity, "已取消更改", Toast.LENGTH_LONG).show()
                    showDialog()
                } else {
                    val z3ro = File(file_json)
                    if (server == "os") {
                        server = ""
                    }
                    z3ro.writeText(TextJSON(server))
                    Toast.makeText(activity, "已更改服务器重启中...请重新打开！！！", Toast.LENGTH_LONG).show()
                    Runtime.getRuntime().exit(1);
                }
            }

            setNeutralButton("取消更改") { _, _ ->
                log_print("已取消更改")
                showDialog()
            }

        }.show()
    }

    private fun moveFolders() {
        val getFolder = File(file_json)
        val getFolderJson = JSONObject(getFolder.readText())
        if (getFolderJson.getJSONObject("move_folder").getBoolean("on")) {
            try {
                val from = getFolderJson.getJSONObject("move_folder").getString("from")
                val to = getFolderJson.getJSONObject("move_folder").getString("to")
                val fromFolder = File(from)
                val toFolder = File(to)
                if (fromFolder.exists()) {
                    log_print("Trying to move from: $from to: $to [?]")
                    fromFolder.copyRecursively(toFolder, true)
                    fromFolder.deleteRecursively()
                    log_print("moveFolders: from: $from to: $to [SUCCESS]")
                } else {
                    log_print("moveFolders: from: $from to: $to [from folder not exist]")
                }
            } catch (e: Exception) {
                log_print("moveFolders: Error: ${e.message}")
            }
        }
    }

    private fun log_print(text: String) {
        // check if folder /sdcard/Download/YuukiPS not exist then create it
        val folder = File("/data/user/0/${package_apk}")
        if (!folder.exists()) {
            folder.mkdirs()
        }
        // check if file /sdcard/Download/YuukiPS/log.txt not exist then create it
        val file = File("/data/user/0/${package_apk}/log.txt")
        if (!file.exists()) {
            file.createNewFile()
        }
        // write log to file
        try {
            val fileWriter = FileWriter(file, true)
            val bufferedWriter = BufferedWriter(fileWriter)
            bufferedWriter.write("[" + SimpleDateFormat("HH:mm:ss").format(Date()) + "] " + text)
            bufferedWriter.newLine()
            bufferedWriter.close()
        } catch (e: IOException) {
            XposedBridge.log("Error: $e")
        }
    }

    private fun tryhook(){
        hook()
        sslHook()
        val z3ro = File(file_json)
        val z3roJson = JSONObject(z3ro.readText())
        if (z3roJson.getString("showText") != "false") {
            showText()
        } else {
            XposedBridge.log("showText: false")
        }
        moveFolders()
    }

    private fun showText() {
        findMethodOrNull("com.miHoYo.GetMobileInfo.MainActivity") { name == "onCreate" }?.hookBefore {
            findMethodOrNull("android.view.View") { name == "onDraw" }?.hookBefore {
                val canvas = it.args[0] as Canvas
                val paint = Paint()
                val paint2 = Paint()
                paint.textAlign = Paint.Align.CENTER
                paint.color = Color.WHITE
                paint.textSize = 50f
                canvas.drawText("不会吧？还有人付费买这个？", canvas.width / 2f, canvas.height / 2f, paint)
                paint2.textAlign = Paint.Align.CENTER
                if (server == "") {
                    paint2.color = Color.RED
                    showServer = "您连接到官方服务器（肯定进不去的）"
                } else {
                    paint2.color = Color.GREEN
                    showServer = "加入的服务器地址: $server"
                }
                paint2.textSize = 40f
                canvas.drawText(showServer, canvas.width / 2f, canvas.height / 2f + 100, paint2)
                
            }
        }
        // Broken UHHHHHHHH
        findMethodOrNull("com.mihoyoos.sdk.platform.SdkActivity") { name == "onCreate" }?.hookBefore {
            findMethodOrNull("android.view.View") { name == "onDraw" }?.hookBefore {
                val canvas = it.args[0] as Canvas
                canvas.drawColor(Color.TRANSPARENT, PorterDuff.Mode.CLEAR)
            }
        }
        
    }

    private fun enter(){
        Toast.makeText(activity, "正在前往$server", Toast.LENGTH_LONG).show()
        log_print("稍等...")
    }


    // Bypass HTTPS
    private fun sslHook() {
        // OkHttp3 Hook
        findMethodOrNull("com.combosdk.lib.third.okhttp3.OkHttpClient\$Builder") { name == "build" }?.hookBefore {
            it.thisObject.invokeMethod("sslSocketFactory", args(getDefaultSSLSocketFactory()), argTypes(SSLSocketFactory::class.java))
            it.thisObject.invokeMethod("hostnameVerifier", args(getDefaultHostnameVerifier()), argTypes(HostnameVerifier::class.java))
        }
        findMethodOrNull("okhttp3.OkHttpClient\$Builder") { name == "build" }?.hookBefore {
            it.thisObject.invokeMethod("sslSocketFactory", args(getDefaultSSLSocketFactory(), DefaultTrustManager()), argTypes(SSLSocketFactory::class.java, X509TrustManager::class.java))
            it.thisObject.invokeMethod("hostnameVerifier", args(getDefaultHostnameVerifier()), argTypes(HostnameVerifier::class.java))
        }
        // WebView Hook
        arrayListOf(
                    "android.webkit.WebViewClient",
                    //"cn.sharesdk.framework.g",
                    //"com.facebook.internal.WebDialog\$DialogWebViewClient",
                    "com.geetest.sdk.dialog.views.GtWebView\$c",
                    "com.miHoYo.sdk.webview.common.view.ContentWebView\$6"
                ).forEach {
            findMethodOrNull(it) { name == "onReceivedSslError" && parameterTypes[1] == SslErrorHandler::class.java }?.hookBefore { param ->
                (param.args[1] as SslErrorHandler).proceed()
            }
        }
        // Android HttpsURLConnection Hook
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "getDefaultSSLSocketFactory" }?.hookBefore {
            it.result = getDefaultSSLSocketFactory()
        }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "setSSLSocketFactory" }?.hookBefore {
            it.result = null
        }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "setDefaultSSLSocketFactory" }?.hookBefore {
            it.result = null
        }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "setHostnameVerifier" }?.hookBefore {
            it.result = null
        }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "setDefaultHostnameVerifier" }?.hookBefore {
            it.result = null
        }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "getDefaultHostnameVerifier" }?.hookBefore {
            it.result = getDefaultHostnameVerifier()
        }
    }

    // Bypass HTTP
    private fun hook() {
        findMethod("com.miHoYo.sdk.webview.MiHoYoWebview") { name == "load" && parameterTypes[0] == String::class.java && parameterTypes[1] == String::class.java }.hookBefore {
            replaceUrl(it, 1)
        }
        findAllMethods("android.webkit.WebView") { name == "loadUrl" }.hookBefore {
            replaceUrl(it, 0)
        }
        findAllMethods("android.webkit.WebView") { name == "postUrl" }.hookBefore {
            replaceUrl(it, 0)
        }

        findMethod("okhttp3.HttpUrl") { name == "parse" && parameterTypes[0] == String::class.java }.hookBefore {
            replaceUrl(it, 0)
        }
        findMethod("com.combosdk.lib.third.okhttp3.HttpUrl") { name == "parse" && parameterTypes[0] == String::class.java }.hookBefore {
            replaceUrl(it, 0)
        }

        findMethod("com.google.gson.Gson") { name == "fromJson" && parameterTypes[0] == String::class.java && parameterTypes[1] == java.lang.reflect.Type::class.java }.hookBefore {
            replaceUrl(it, 0)
        }
        findConstructor("java.net.URL") { parameterTypes[0] == String::class.java }.hookBefore {
            replaceUrl(it, 0)
        }
        findMethod("com.combosdk.lib.third.okhttp3.Request\$Builder") { name == "url" && parameterTypes[0] == String::class.java }.hookBefore {
            replaceUrl(it, 0)
        }
        findMethod("okhttp3.Request\$Builder") { name == "url" && parameterTypes[0] == String::class.java }.hookBefore {
            replaceUrl(it, 0)
        }
    }

    // Rename
    private fun replaceUrl(method: XC_MethodHook.MethodHookParam, args: Int) {
        
        if (server == "") return
        if (method.args[args].toString() == "") return

        //XposedBridge.log("old: " + method.args[args].toString())
        log_print("old: " + method.args[args].toString())

        for (list in proxyListRegex) {
            for (head in arrayListOf("http://", "https://")) {
                method.args[args] = method.args[args].toString().replace(head + list, server)
            }
        }

        //XposedBridge.log("new: " + method.args[args].toString())
        log_print("new: " + method.args[args].toString())
    }
}
