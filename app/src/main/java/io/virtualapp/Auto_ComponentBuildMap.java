package io.virtualapp;

import android.support.annotation.Keep;

import com.lody.virtual.sandxposed.XposedConfig;

import io.virtualapp.sandxposed.XposedConfigComponent;

import static com.trend.lazyinject.lib.component.ComponentBuilder.doBuild;

@Keep
public class Auto_ComponentBuildMap {
    public static XposedConfig buildXposedConfigComponent() {
        return doBuild(com.lody.virtual.sandxposed.XposedConfig.class, XposedConfigComponent.class);
    }
}
