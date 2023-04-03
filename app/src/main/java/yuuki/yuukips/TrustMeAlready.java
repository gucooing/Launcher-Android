package yuuki.yuukips;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;

import static de.robv.android.xposed.XposedHelpers.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class TrustMeAlready {

    private static final String SSL_CLASS_NAME = "com.android.org.conscrypt.TrustManagerImpl";
    private static final String SSL_METHOD_NAME = "checkTrustedRecursive";
    private static final Class<?> SSL_RETURN_TYPE = List.class;
    private static final Class<?> SSL_RETURN_PARAM_TYPE = X509Certificate.class;
    private static final Path log = Paths.get("/sdcard/Download/YuukiPS/log_process.txt");

    public void initZygote() {
        log_process("========================================\nDate: " + new Date().toString().substring(0, 10) + "\nTime: " + new Date().toString().substring(11, 19) + "\n========================================", false);

        log_process("TrustMeAlready loading...", true);
        int hookedMethods = 0;

        for (Method method : findClass(SSL_CLASS_NAME, null).getDeclaredMethods()) {
            if (!checkSSLMethod(method)) {
                continue;
            }

            List<Object> params = new ArrayList<>();
            params.addAll(Arrays.asList(method.getParameterTypes()));
            params.add(new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    return new ArrayList<X509Certificate>();
                }
            });
            log_process("Hooking method:\n" + method.toString(), true);
            findAndHookMethod(SSL_CLASS_NAME, null, SSL_METHOD_NAME, params.toArray());
            hookedMethods++;
        }
        log_process(String.format(Locale.ENGLISH, "TrustMeAlready loaded! Hooked %d methods", hookedMethods), true);
    }

    private boolean checkSSLMethod(Method method) {
        if (!method.getName().equals(SSL_METHOD_NAME)) {
            log_process("Method name is not " + SSL_METHOD_NAME, true);
            return false;
        }

        // check return type
        if (!SSL_RETURN_TYPE.isAssignableFrom(method.getReturnType())) {
            log_process("Return type is not " + SSL_RETURN_TYPE, true);
            return false;
        }

        // check if parameterized return type
        Type returnType = method.getGenericReturnType();
        if (!(returnType instanceof ParameterizedType)) {
            log_process("Return type is not parameterized", true);
            return false;
        }

        // check parameter type
        Type[] args = ((ParameterizedType) returnType).getActualTypeArguments();
        if (args.length != 1 || !(args[0].equals(SSL_RETURN_PARAM_TYPE))) {
            log_process("Return type is not " + SSL_RETURN_PARAM_TYPE, true);
            return false;
        }
        log_process("Method is valid", true);
        return true;
    }
    private void log_process(String message, Boolean withTime) {
        if (!Files.exists(log)) {
            try {
                Files.createFile(log);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try {
            if (withTime) {
                Files.write(log, ("[" + new Date().toString().substring(11, 19) + "] " + message + "\n").getBytes(), StandardOpenOption.APPEND);
            } else {
                Files.write(log, (message + "\n").getBytes(), StandardOpenOption.APPEND);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}