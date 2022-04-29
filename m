Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBOGVWCJQMGQEHEM55EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ACBF51536C
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Apr 2022 20:13:14 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id gb16-20020a17090b061000b001d78792caebsf4401533pjb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Apr 2022 11:13:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651255992; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z5lTakHoPJBCzBXvk1TVthjVH9SFI41bx6YxY9k9m0e5Bjz860CTZlpif4c4Jx2E0i
         QD85xWWypSbY4lpB0NwkdFdloALSFhwUqSEKU1zaRijwvIiaRAr3eHIxtZkww4kD2xdu
         NiXWSM54JTbK3vezrJamt0GhLz1yWbocYhtNVC7n2d3ZFusj2F0D/azKMCJ8Sa3ocYHC
         0PHaaqEhqX+eiRevJt23TcGjRwiMS9YYAKFwxpVZ2qABa9Q2orwS8N70qe+NNTdhU4yO
         W4IJmKPCIKgFOMyTXEH8n8yKpS7bn9TzILHwykC3mKnOjr3lXPPqJ7ki2YZgOI46KFyd
         nU2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VmybNoimgGrd/O6hrBkuUKlCu9Uv26xLCAbSkRUnp5g=;
        b=u5jzqjaIH9ST3RZ4mrE9rAxZI/cIQtABFWsEMSMaPnMnN+orM3+CSbRHe2lYEiG9S8
         kaaP0eQklu0beJE/2iS4SB+72zSpTkCVdmIG9hxr0nTzxVA4gScnZN+ZcBFk0iI7WKY8
         eTYBOEvNVBPfj/ES/NkVonfh0gdrSPrmJRfa38q6GIBpSCficuBZdwB9e4Xpsjwgi0Om
         r13Nu4sWGxPCgfCZ6Aj6UzOBTc7yzcJ0CMs4bYa40ZIv8t5MFTzWecnIFogl0e5E2Jl3
         gzuWaqo+QJVcGPBGZRhIcE50Ci7PwU4/t35w5hmLqMXfmy2+w2C5a4LYc8/SrPAe5E3H
         Uddw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wt625Qvy;
       spf=pass (google.com: domain of 3typsyggkcdy5d2lqhgn8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3typsYggKCdY5D2LQHGN8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VmybNoimgGrd/O6hrBkuUKlCu9Uv26xLCAbSkRUnp5g=;
        b=oCdq+53WvLnremoFsfKgJwVYnYLpmaFCDz4D7lI4N5Ty6uAbyHwRGvHvALXXexvbrs
         0AI+q7wRk3cqqTtk90YL7tCIccKWUUl6DX9KtnI1auJd0mOc4du/bMWeqKmft6OoJ+zu
         xSb6TMuecGLEKbVn8LdDODdAeRUVmuB0Z5vY493bKM6gAdO5jsmH/a3QE5U+L/Xwjf62
         IezJN8WA0EOHMuEBy/hJ/oYa2DQZ3Nhf0FsGywCtTl4VErwcSlGj5XzPsL9suzVu38Y4
         QRIyB3xG2ybg7gXaqf0W3waKjY+XpxZC7+A1iw7JfPZhr1/9yDd06ObcwocTtCuEMaLX
         mLRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VmybNoimgGrd/O6hrBkuUKlCu9Uv26xLCAbSkRUnp5g=;
        b=FQIJh50dAmMGB7Y4pZ9Dd5k9rrBjPYs2Di6L+tM7fiIv6KNz9V+bt0gvceBB9JCYQY
         sJsP1GdQDGfAPI56kaLbCsh0PvJbUu+x7ivoj5j1KooY8Gu5hcA7Hzt2OR2na7pK7pX0
         NGxO2M5LShTA9swAFr1Xzqpjhq0sTqlMFUSTxecN6G0T3sua7uiArjbAFFlu3wucprSS
         xSmRz1FYotVahoVAerYAiS7xLg9t9Xv6UuqiIXucTYaO2QDS4RlPsFoJYZq19Adg9V+K
         cEKSLdhFpnPXG9AXjRwwqsk/HBd0KZNCY39ycK/lDG/Ww9Byuvw3pQ2zRvpb4I9uTpiL
         owKQ==
X-Gm-Message-State: AOAM530lgSp5k5k6iDNyAP6mh43Pt8kJS8Xkh+5gzoDrsp5LC04RWfAI
	LRLLNivg/flbwhhCfjoXyUM=
X-Google-Smtp-Source: ABdhPJxxLD1DplFEdIueb3yUDLpkTAmoA3vPm1WK4r7QkuXoOhorW/EVZmkY1U5hi9YSk3EZaGD+zA==
X-Received: by 2002:a63:7d04:0:b0:378:fb34:5162 with SMTP id y4-20020a637d04000000b00378fb345162mr460740pgc.487.1651255992564;
        Fri, 29 Apr 2022 11:13:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:ace:b0:505:bb88:8eb0 with SMTP id
 c14-20020a056a000ace00b00505bb888eb0ls1819588pfl.10.gmail; Fri, 29 Apr 2022
 11:13:12 -0700 (PDT)
X-Received: by 2002:a63:2309:0:b0:398:d3fe:1c41 with SMTP id j9-20020a632309000000b00398d3fe1c41mr473283pgj.131.1651255991895;
        Fri, 29 Apr 2022 11:13:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651255991; cv=none;
        d=google.com; s=arc-20160816;
        b=yRkHfT1ssdvJrSlJECiDQxx6VtSd3ginoGPqO/bwk1oyYCYuW/iH22mi+1uiWLO3AY
         uN3SAtOnZbGI7Rab9Ipo+yS4ib8UiuSxTA7k/gMzEEn33kOsT0VKQijB+PcLU2jZn7bB
         gJ36lH81p0jU292QnPXUNETC2pRJ214sd5OMF4S01/8jtMhtm/kl+ai4DhIh+1McmvYN
         RtlbGHti2Q2xlFoWMmsvyS+2pSksDFbcIt9zU5Sw+FKf0k5+LV1IGi67GbGmMAKYUVfO
         x6BjhDpiPG5aYeVuW50J7PaPTLfEUMA/Sa9/CaMtwtYhJ72z3unOD10jze3UAiyOCEtP
         ljPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Ia9AduyfzsduaRDy65QoQpMuuQ/nrqWkXPaBfG45mh8=;
        b=iyK+lQ0dtmzo4664sHdL3M7O/pcXUqF8mQRatuIuBK1dnCURTy4nYr66L6ouK97VSr
         YyQpsrHFTZviQzvyOa+6KHa0LuA8KijcGNnT0TTXo+KGcfBfhafpWYJPpl3R5sMqPVwh
         FMPLrV+Hz5hkBxl0WOsQ0MBlkHdLrxwAo5fHN/RtgVI+gO8UbJYXAKyz/AH9fsoD4KcK
         Q3cNtrvn9xGNM7RNVc5bxItaS0cg4pcjue+tJ2t6Okx+oGfyZGSG2Q7y3uMETmlziSbG
         BQs1Yuz9JNZgra9+fw9a6mwlZwREj3G3UpgtBAPbP8fi844WrRoxsEO054Op7FIpKpdR
         QUIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wt625Qvy;
       spf=pass (google.com: domain of 3typsyggkcdy5d2lqhgn8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3typsYggKCdY5D2LQHGN8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id h11-20020a17090aa88b00b001c75ad3207fsi774689pjq.3.2022.04.29.11.13.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Apr 2022 11:13:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3typsyggkcdy5d2lqhgn8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id v17-20020a056902029100b006484d85132eso8032888ybh.14
        for <kasan-dev@googlegroups.com>; Fri, 29 Apr 2022 11:13:11 -0700 (PDT)
X-Received: from dlatypov.svl.corp.google.com ([2620:15c:2cd:202:183a:36d7:2dcb:1773])
 (user=dlatypov job=sendgmr) by 2002:a81:2c3:0:b0:2f7:c26e:5790 with SMTP id
 186-20020a8102c3000000b002f7c26e5790mr599582ywc.84.1651255991186; Fri, 29 Apr
 2022 11:13:11 -0700 (PDT)
Date: Fri, 29 Apr 2022 11:12:58 -0700
In-Reply-To: <20220429181259.622060-1-dlatypov@google.com>
Message-Id: <20220429181259.622060-3-dlatypov@google.com>
Mime-Version: 1.0
References: <20220429181259.622060-1-dlatypov@google.com>
X-Mailer: git-send-email 2.36.0.464.gb9c8b46e94-goog
Subject: [PATCH v2 3/4] kfence: test: use new suite_{init/exit} support, add .kunitconfig
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
To: brendanhiggins@google.com, davidgow@google.com
Cc: linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, skhan@linuxfoundation.org, 
	Daniel Latypov <dlatypov@google.com>, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Wt625Qvy;       spf=pass
 (google.com: domain of 3typsyggkcdy5d2lqhgn8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--dlatypov.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3typsYggKCdY5D2LQHGN8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--dlatypov.bounces.google.com;
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
Tested-by: David Gow <davidgow@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
v1 -> v2: no change (see patch 2 and 4)
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
2.36.0.464.gb9c8b46e94-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220429181259.622060-3-dlatypov%40google.com.
