load("//tools/go_generics:defs.bzl", "go_template")

package(licenses = ["notice"])

go_template(
    name = "refs",
    srcs = [
        "refcounter.go",
    ],
    types = [
        "T",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/refs"],
)
