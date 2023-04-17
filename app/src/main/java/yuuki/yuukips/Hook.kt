package yuuki.yuukips

import android.annotation.SuppressLint
import android.app.Activity
import android.webkit.SslErrorHandler
import android.widget.*
import com.github.kyuubiran.ezxhelper.init.EzXHelperInit
import com.github.kyuubiran.ezxhelper.utils.*
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.regex.Pattern
import javax.net.ssl.*
import org.json.JSONObject
import org.json.JSONException
import android.app.AlertDialog
import android.text.TextWatcher
import android.text.Editable

class Hook {
    // URL Server
    private var server = "https://sdk.mihoyu.cn"

    // App
    private val package_apk = "com.miHoYo.Yuanshen"
    //private val package_apk = "com.xlpmy.dev"
    private val injek_activity = "com.miHoYo.GetMobileInfo.MainActivity"
    private val path = "/data/user/0/${package_apk}"
    private val file_json = "/data/user/0/${package_apk}/server.json"

    //private lateinit var server: String
    private lateinit var textJson: String

    //  List Domain v1
    private val domain = Pattern.compile("http(s|)://.*?\\.(hoyoverse|mihoyo|yuanshen|mob)\\.com")

    //  List Domain v2
    private val more_domain =
            arrayListOf(
                    // More Domain & log
                    "overseauspider.yuanshen.com:8888",
            )

    // Activity
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
        return SSLContext.getInstance("TLS")
                .apply {
                    init(
                            arrayOf<KeyManager>(),
                            arrayOf<TrustManager>(DefaultTrustManager()),
                            SecureRandom()
                    )
                }
                .socketFactory
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
        override fun checkClientTrusted(chain: Array<X509Certificate?>?, authType: String?) {}

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkServerTrusted(chain: Array<X509Certificate?>?, authType: String?) {}

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return arrayOf()
        }
    }

    fun initZygote() {
        TrustMeAlready().initZygote()

    }

    @SuppressLint("WrongConstant", "ClickableViewAccessibility")
    fun handleLoadPackage(i: XC_LoadPackage.LoadPackageParam) {
        XposedBridge.log("Load: " + i.packageName) // debug

        // Ignore other apps
        if (i.packageName != "${package_apk}") {
            return
        }
        val z3ro = File(file_json)
        try {
                if (z3ro.exists()) {
                    val z3roJson = JSONObject(z3ro.readText())
                    server = z3roJson.getString("server")
                } else {
                    server = "https://sdk.mihoyu.cn"
                    z3ro.createNewFile()
                    z3ro.writeText(TextJSON(server))
                }
            } catch (e: JSONException) {
            }
        // Startup
        EzXHelperInit.initHandleLoadPackage(i)
        // Hook Activity
        findMethod(injek_activity) { name == "onCreate" }.hookBefore { param ->
            activity = param.thisObject as Activity
            Injek()
            Enter()
        }
        Injek()
        Enter()
    }

    private fun Injek() {
        injekhttp()
        injekssl()
    }

    private fun Enter() {
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
            setMessage("采用开源模块制作\n请不要将此apk应用于商业行为\n否则将不会推出后续版本\n第一次使用请直接点击前往游戏下载资源\n使用教程以及更多版本下载:https://mihoyu.cn\n可前往地址下载最新版和历史版本")
            setPositiveButton("前往游戏") { _, _ ->
            server = z3roJson.getString("server")
            Toast.makeText(activity, "加入的服务器地址: $server", Toast.LENGTH_LONG).show()
                Injek()
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
                            if(server == "sdk"){
                                server = "https://sdk.mihoyu.cn"
                            }else if (server == "login"){
                                    server = "https://login.mihoyu.cn"
                                } else if (server.contains("localhost") && server != "") {
                                server = server.replace("localhost", "https://127.0.0.1")
                                if (server.contains(" ")) {
                                    server = server.replace(" ", ":")
                                }
                            } else if (server == "https://" || server == "http://" && server != "") {
                                server = ""//不敢动
                            } else if (!server.startsWith("https://") && (!server.startsWith("http://")) && server != "" && server != "sdk" && server != "login") {
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
                    Enter()
                } else {
                    val z3ro = File(file_json)
                    if (server == "cn") {
                        server = "https://sdk.mihoyu.cn"
                    }
                    z3ro.writeText(TextJSON(server))
                    Toast.makeText(activity, "已更改服务器重启中...请重新打开！！！", Toast.LENGTH_LONG).show()
                    Runtime.getRuntime().exit(1);
                }
            }
            setNeutralButton("取消更改") { _, _ ->
                Enter()
            }
        }.show()
    }

    // Bypass HTTPS
    private fun injekssl() {
        // OkHttp3 Hook
        findMethodOrNull("com.combosdk.lib.third.okhttp3.OkHttpClient\$Builder") { name == "build" }
                ?.hookBefore {
                    it.thisObject.invokeMethod(
                            "sslSocketFactory",
                            args(getDefaultSSLSocketFactory()),
                            argTypes(SSLSocketFactory::class.java)
                    )
                    it.thisObject.invokeMethod(
                            "hostnameVerifier",
                            args(getDefaultHostnameVerifier()),
                            argTypes(HostnameVerifier::class.java)
                    )
                }
        findMethodOrNull("okhttp3.OkHttpClient\$Builder") { name == "build" }?.hookBefore {
            it.thisObject.invokeMethod(
                    "sslSocketFactory",
                    args(getDefaultSSLSocketFactory(), DefaultTrustManager()),
                    argTypes(SSLSocketFactory::class.java, X509TrustManager::class.java)
            )
            it.thisObject.invokeMethod(
                    "hostnameVerifier",
                    args(getDefaultHostnameVerifier()),
                    argTypes(HostnameVerifier::class.java)
            )
        }
        // WebView Hook
        arrayListOf(
                        "android.webkit.WebViewClient",
                        // "cn.sharesdk.framework.g",
                        // "com.facebook.internal.WebDialog\$DialogWebViewClient",
                        "com.geetest.sdk.dialog.views.GtWebView\$c",
                        "com.miHoYo.sdk.webview.common.view.ContentWebView\$6"
                )
                .forEach {
                    findMethodOrNull(it) {
                        name == "onReceivedSslError" &&
                                parameterTypes[1] == SslErrorHandler::class.java
                    }
                            ?.hookBefore { param -> (param.args[1] as SslErrorHandler).proceed() }
                }
        // Android HttpsURLConnection Hook
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") {
            name == "getDefaultSSLSocketFactory"
        }
                ?.hookBefore { it.result = getDefaultSSLSocketFactory() }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "setSSLSocketFactory" }
                ?.hookBefore { it.result = null }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") {
            name == "setDefaultSSLSocketFactory"
        }
                ?.hookBefore { it.result = null }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") { name == "setHostnameVerifier" }
                ?.hookBefore { it.result = null }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") {
            name == "setDefaultHostnameVerifier"
        }
                ?.hookBefore { it.result = null }
        findMethodOrNull("javax.net.ssl.HttpsURLConnection") {
            name == "getDefaultHostnameVerifier"
        }
                ?.hookBefore { it.result = getDefaultHostnameVerifier() }
    }

    // Bypass HTTP
    private fun injekhttp() {
        findMethod("com.miHoYo.sdk.webview.MiHoYoWebview") {
            name == "load" &&
                    parameterTypes[0] == String::class.java &&
                    parameterTypes[1] == String::class.java
        }
                .hookBefore { replaceUrl(it, 1) }
        findAllMethods("android.webkit.WebView") { name == "loadUrl" }.hookBefore {
            replaceUrl(it, 0)
        }
        findAllMethods("android.webkit.WebView") { name == "postUrl" }.hookBefore {
            replaceUrl(it, 0)
        }

        findMethod("okhttp3.HttpUrl") { name == "parse" && parameterTypes[0] == String::class.java }
                .hookBefore { replaceUrl(it, 0) }
        findMethod("com.combosdk.lib.third.okhttp3.HttpUrl") {
            name == "parse" && parameterTypes[0] == String::class.java
        }
                .hookBefore { replaceUrl(it, 0) }

        findMethod("com.google.gson.Gson") {
            name == "fromJson" &&
                    parameterTypes[0] == String::class.java &&
                    parameterTypes[1] == java.lang.reflect.Type::class.java
        }
                .hookBefore { replaceUrl(it, 0) }
        findConstructor("java.net.URL") { parameterTypes[0] == String::class.java }.hookBefore {
            replaceUrl(it, 0)
        }
        findMethod("com.combosdk.lib.third.okhttp3.Request\$Builder") {
            name == "url" && parameterTypes[0] == String::class.java
        }
                .hookBefore { replaceUrl(it, 0) }
        findMethod("okhttp3.Request\$Builder") {
            name == "url" && parameterTypes[0] == String::class.java
        }
                .hookBefore { replaceUrl(it, 0) }
    }

    // Rename
    private fun replaceUrl(method: XC_MethodHook.MethodHookParam, args: Int) {
        // skip if server if empty
        if (server == "") return
        var melon = method.args[args].toString()
        // skip if string is empty
        if (melon == "") return
        // skip for support download game data
        if (melon.startsWith("autopatchhk.yuanshen.com")) return
        if (melon.startsWith("autopatchcn.yuanshen.com")) return
        // normal edit 1
        for (list in more_domain) {
            for (head in arrayListOf("http://", "https://")) {
                method.args[args] = method.args[args].toString().replace(head + list, server)
            }
        }
        // normal edit 2
        val m = domain.matcher(melon)
        if (m.find()) {
            method.args[args] = m.replaceAll(server)
        } else {
        }
    }
}
