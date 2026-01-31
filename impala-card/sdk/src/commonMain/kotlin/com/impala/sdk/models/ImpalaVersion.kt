package com.impala.sdk.models

/**
 * ImpalaVersion represents the version of the ImpalaApplet project.
 *
 * @copyright Financial Empowerment Partners
 * @version 1.0
 * @since 01.01.2026
 */
class ImpalaVersion(
    var major: Short, var minor: Short,
    /** git rev-list --count HEAD  */
    var revList: Short, var shortHash: String
)
