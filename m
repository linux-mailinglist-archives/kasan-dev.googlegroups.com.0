Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBQXPUCJQMGQEYZVF2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 14EE05106A3
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 20:19:48 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id i5-20020a258b05000000b006347131d40bsf16553323ybl.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 11:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650997187; cv=pass;
        d=google.com; s=arc-20160816;
        b=C8GBpEiL+16YFpu5WtEDuxQWPfPByN3fhiNTJoZ/q9fEiH0OuKIVkfqpu9ecCBrD7e
         UdmrBkCWmQK6TL2WxJAxgLh4gJ9I63qz1boW58zYH4ETZScWAb+J5VrQbFV2Wa6zqIDg
         7eZQr98Qn6CVYWRQcFqw9XFpGvzO+7qroAwTucEU9AkMTo+JD8GfkLdx+OYNXCpOyr/8
         zFNDL8MvRTJFvsxJHq5eZziQyQbv9oDhhJl9HARnqvl4+tjp1m30ttYqEBjllmyClFSn
         XivfJnRDFuLKTUdGqkyrQeWwRYaQ9rz3yxW/bl5efCGFvyAG10GhcMrnkv2OUoKvD0sd
         sCdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vKgHRKuLdO12cNv4mJ7/paMGJvNObflfnUufOpmXcOY=;
        b=eGZeV9rnrMHE8dCI89YmWnpSHVQN5WI5upOItxXtJ/7E1ZLauyIQFtibUT06LaMz8w
         Xp8Rtcs0bfe3Ag/9r15GvxE2NMbJPqsfVgjpuDCmNG5s0BdD4LzrqE6BBtaNlOLK0QFs
         hjh2rh+3ch/fbDtzbYiwqDOsWcn37qSTjIe+EnH3AsTAeVDp66HZ0cPblmsxKvspJKiB
         4hhc3b8lwWfpIN8MzKCfaYSPDwQeJbD6IHXiP/RnLssN/C7kXzTXXIpxeeeo33BkCXzH
         30DKBdtaCK/5nTSHwl9DXPw8XlJycJ4PTMpCOMv+rPWgnyWItjCaEeAXacE5bXFVuLSn
         PbxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pybsRBOi;
       spf=pass (google.com: domain of 3wjdoyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3wjdoYggKCesQYNglcbiTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vKgHRKuLdO12cNv4mJ7/paMGJvNObflfnUufOpmXcOY=;
        b=Q7mKjboOBse4QNoe77BwjSHdekVznmHYgMY7/PA21MrqisfCzXdD5UxmvLRasSaIoY
         Rs3qgGWFAT6IRzGkuRQvwWqBcULZWo32lsEYMLLWSDlFzw4TIGA6mfChL0QGxfZngRs9
         NsSSYuJRGsCk6xABr764eIllXztgNqPUAkYXCm/xz5+I2rN8rqpbsFhSmcoa2Bp4N+Bc
         aK3sZY9oZUrtIXAhwx2j8gTZunzpA+gWF3PfvflVW3Ojl/UgO3pf1+AxaL4bJuqGHxiq
         V0LoQhfbV+Ibk+nEc0X+xjvXBYzfxTN2IOFMIQsMO/lH7eYFSg0P3GKR7kHNmM0YCsYH
         sKFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vKgHRKuLdO12cNv4mJ7/paMGJvNObflfnUufOpmXcOY=;
        b=dX8C/Q2627g+q32ZASgCyWnqGqqK/343bnjZ/OheomGq/1msSA7xJiOOWhLLSDNiWu
         h8/robELaW8LN2ZkChHd+XcHJlPKX5S8NKzSmjVcKcIeUbbcaLZ7iFU8PwB4zaCmVSnD
         t4EIA4RV9WZtq+cKdZ/3NLRAOW3MlaFc7EpsnTheFROV1c39ZwuiTB0+aL+bnf2ixfES
         saWgh17Zgg1MeSlf4cjGUXNthVyUdYPvOsbVyYfk3P5P5UDO45gYGEoaUPJOVUE4CvoW
         kVeTdMT7SHkbcURwWNDdY4gilBwyrcHf2d+iiUT3KCTCXEOFnGmytXQI6T5q4fl69rPG
         2nQw==
X-Gm-Message-State: AOAM532QVinUNidRaEoFBW42ABVpUe3S9pBtvypPHPRFnDOoLD8Uv5le
	+yMoqnLXsrJFNVIoVx+qJkY=
X-Google-Smtp-Source: ABdhPJyiIQCHpQgWxhn4wqve7TgoudafIXcqre2v6i7FxquBOcL9C+t88wJDEZy+eaCjic0dFVVwiQ==
X-Received: by 2002:a25:20a:0:b0:645:74e4:8cc9 with SMTP id 10-20020a25020a000000b0064574e48cc9mr22069958ybc.518.1650997186955;
        Tue, 26 Apr 2022 11:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a16:0:b0:648:3bbf:52e4 with SMTP id q22-20020a252a16000000b006483bbf52e4ls7074795ybq.4.gmail;
 Tue, 26 Apr 2022 11:19:46 -0700 (PDT)
X-Received: by 2002:a25:a148:0:b0:641:d14b:ddd3 with SMTP id z66-20020a25a148000000b00641d14bddd3mr22993467ybh.402.1650997186492;
        Tue, 26 Apr 2022 11:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650997186; cv=none;
        d=google.com; s=arc-20160816;
        b=YCEcqwuxM8rAAzCdZKUuuEPgpe2ZAZf72xCG+eRzxiVMiN7HZYVX/EtmKFdKGejW3y
         WnqXd71OyEM/zNH1UMHd+PxaEFvKnW1+I5E8yJ4fmNdVzWlYHNIw90hmBS/5c2r4cURI
         0x5iPjbkvrkjVnxeKk+e8Rr921ljqI0/DuWbxm/Fh6OXUUabXtOrvPbXb1j8DRFtYDFj
         Fe6aTqO9B2zh00O3vqPjTn4/to20Hl0wpaU82f8lLSWKu71G77SDBaC1lilZtvoM0+FW
         1yOJ7pPKllFy1HJGVcKZduIDe9rqT64/rg+YSuVbiLDFII3Pg0CxtT43tgatYfgJWPap
         azbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=pmGguFEnVQZXUniO0qK+xxYCdVnApJ0Srb7572vJ7Dg=;
        b=asmxF/drLBWgFaPMTirF7l7UCpRaCwOk6WAADseOCiH07D1L1SppMDQ96nnUmGfL3P
         xvcfLruEWSs7C7bp71B7pMrMmZcRFy5SFBUo912p51tFDqeqkxjWWP6/wIBqdYUWk+P3
         b8wNJ/+COU3/vAAe6GL/N3KP5IWqV9G/KKt2QrD86pd8zppauJHSrUhjH46wCu+hdhkD
         7MEhC3eW6cuTf839KG2KOdJg3OFoLyHcr182cYBx3z1cd5zPlBtndW6HwJvtBQJDSEKg
         Xi7z0j6nn7jya+/Qxkc7DTwVpSO8HCADZARBJucHUTjMYnQukEPIEv5iRcY9fUxqPgid
         D5Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pybsRBOi;
       spf=pass (google.com: domain of 3wjdoyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3wjdoYggKCesQYNglcbiTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t83-20020a812d56000000b002f839637da6si50901ywt.2.2022.04.26.11.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 11:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wjdoyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id b12-20020a056902030c00b0061d720e274aso16624487ybs.20
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 11:19:46 -0700 (PDT)
X-Received: from dlatypov.svl.corp.google.com ([2620:15c:2cd:202:b03d:8d64:4a06:2c5f])
 (user=dlatypov job=sendgmr) by 2002:a5b:38d:0:b0:645:7b27:3b8b with SMTP id
 k13-20020a5b038d000000b006457b273b8bmr21950232ybp.146.1650997186276; Tue, 26
 Apr 2022 11:19:46 -0700 (PDT)
Date: Tue, 26 Apr 2022 11:19:24 -0700
In-Reply-To: <20220426181925.3940286-1-dlatypov@google.com>
Message-Id: <20220426181925.3940286-3-dlatypov@google.com>
Mime-Version: 1.0
References: <20220426181925.3940286-1-dlatypov@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH 3/3] kfence: test: use new suite_{init/exit} support, add .kunitconfig
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
To: brendanhiggins@google.com, davidgow@google.com
Cc: linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, skhan@linuxfoundation.org, 
	Daniel Latypov <dlatypov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pybsRBOi;       spf=pass
 (google.com: domain of 3wjdoyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3wjdoYggKCesQYNglcbiTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Currently, the kfence test suite could not run via "normal" means since
KUnit didn't support per-suite setup/teardown. So it manually called
internal kunit functions to run itself.
This has some downsides, like missing TAP headers => can't use kunit.py
to run or even parse the test results (w/o tweaks).

Use the newly added support and convert it over, adding a .kunitconfig
so it's even easier to run from kunit.py.

People can now run the test via
$ ./tools/testing/kunit/kunit.py run --kunitconfig=mm/kfence --arch=x86_64
...
[11:02:32] Testing complete. Passed: 23, Failed: 0, Crashed: 0, Skipped: 2, Errors: 0
[11:02:32] Elapsed time: 43.562s total, 0.003s configuring, 9.268s building, 34.281s running

Cc: kasan-dev@googlegroups.com
Signed-off-by: Daniel Latypov <dlatypov@google.com>
---
 mm/kfence/.kunitconfig  |  6 ++++++
 mm/kfence/kfence_test.c | 31 +++++++++++++------------------
 2 files changed, 19 insertions(+), 18 deletions(-)
 create mode 100644 mm/kfence/.kunitconfig

diff --git a/mm/kfence/.kunitconfig b/mm/kfence/.kunitconfig
new file mode 100644
index 000000000000..f3d65e939bfa
--- /dev/null
+++ b/mm/kfence/.kunitconfig
@@ -0,0 +1,6 @@
+CONFIG_KUNIT=y
+CONFIG_KFENCE=y
+CONFIG_KFENCE_KUNIT_TEST=y
+
+# Additional dependencies.
+CONFIG_FTRACE=y
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 1b50f70a4c0f..96206a4ee9ab 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -826,14 +826,6 @@ static void test_exit(struct kunit *test)
 	test_cache_destroy();
 }
 
-static struct kunit_suite kfence_test_suite = {
-	.name = "kfence",
-	.test_cases = kfence_test_cases,
-	.init = test_init,
-	.exit = test_exit,
-};
-static struct kunit_suite *kfence_test_suites[] = { &kfence_test_suite, NULL };
-
 static void register_tracepoints(struct tracepoint *tp, void *ignore)
 {
 	check_trace_callback_type_console(probe_console);
@@ -847,11 +839,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
 		tracepoint_probe_unregister(tp, probe_console, NULL);
 }
 
-/*
- * We only want to do tracepoints setup and teardown once, therefore we have to
- * customize the init and exit functions and cannot rely on kunit_test_suite().
- */
-static int __init kfence_test_init(void)
+static int kfence_suite_init(struct kunit_suite *suite)
 {
 	/*
 	 * Because we want to be able to build the test as a module, we need to
@@ -859,18 +847,25 @@ static int __init kfence_test_init(void)
 	 * won't work here.
 	 */
 	for_each_kernel_tracepoint(register_tracepoints, NULL);
-	return __kunit_test_suites_init(kfence_test_suites);
+	return 0;
 }
 
-static void kfence_test_exit(void)
+static void kfence_suite_exit(struct kunit_suite *suite)
 {
-	__kunit_test_suites_exit(kfence_test_suites);
 	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
 	tracepoint_synchronize_unregister();
 }
 
-late_initcall_sync(kfence_test_init);
-module_exit(kfence_test_exit);
+static struct kunit_suite kfence_test_suite = {
+	.name = "kfence",
+	.test_cases = kfence_test_cases,
+	.init = test_init,
+	.exit = test_exit,
+	.suite_init = kfence_suite_init,
+	.suite_exit = kfence_suite_exit,
+};
+
+kunit_test_suites(&kfence_test_suite);
 
 MODULE_LICENSE("GPL v2");
 MODULE_AUTHOR("Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>");
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426181925.3940286-3-dlatypov%40google.com.
