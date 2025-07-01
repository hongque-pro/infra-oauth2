package com.labijie.infra.oauth2.aot

import org.graalvm.nativeimage.hosted.Feature
import org.graalvm.nativeimage.hosted.RuntimeClassInitialization

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/7/1
 *
 */
@Suppress("unused")
class InfraOAuth2Feature : Feature {

    override fun beforeAnalysis(access: Feature.BeforeAnalysisAccess?) {
        RuntimeClassInitialization.initializeAtBuildTime(DeprecationLevel::class.java)
    }
}