Return-Path: <kasan-dev+bncBAABBNNPRGOAMGQEHBSRWKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id AEA9A639793
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 19:15:18 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id p10-20020a19f00a000000b004b028a42706sf2607266lfc.10
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 10:15:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669486518; cv=pass;
        d=google.com; s=arc-20160816;
        b=chDYdoT3f2grQFtvVx9fMCn0fXJYlXYwymH8LfFONwCI7dx0JUnKBW/JjIzPN8MK69
         d55n/5cN4vO2A//SEXv+ECMpgjMHiurByrFp16SN0JMbxQ9lfl09F29bcluzjeWEi2Cy
         PghY468fg72ZwysDahYiPjZToSbncAq3ANW65RJlyva9lDZIXsg80/at9HOuVg6Vswnw
         KAhvQSyXImq3RlQSrMbUG2ZrFstc3tygFoT8xG1fdWZ6KaXB1wgr4VMGh1pO4Nnsp325
         aoZ+RY5qfS4PHaFbG6M0OOlSij1AonjPbtVgZ8holFmzE/Y3Nn+1KW0iBOcIRBBC6pyM
         B4SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=90PzVRSe7RX6puS568Ix8ZQFGkHvttvH2dg43P53oRM=;
        b=hJJmm/IQAMFurWkOpfXK5cbhtaiALx0jCIOiGYJ+wGVuI6W69N2J+d43Jkh6SdicTb
         kxzXJuoUtT7mOT0hVNdn/L6w4pV+pUV+xMeq15RFPXN4dHttpqLKhIeLdtY4hap4n41J
         9tBx+6y85f7B3Z7s5WO/c3TOimLIYkULRUmZbDmU6VTMrlTUEEq0mrl/13ngWQEm2n6q
         xRfqouDZlXlk/pC1iBDPtNsFouexAQlIDxIiUmu5reSw2+ULvcvZr+rwklcdSelp6iRk
         uzWIiQN6px9G4Krfkxpv8wdPZF23muYJaiu74Wf4WQgMiVaqSSYYcV8gZu4sMBfLGhRY
         uloA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DCYD0KPc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=90PzVRSe7RX6puS568Ix8ZQFGkHvttvH2dg43P53oRM=;
        b=qN7zWKR7rG9qzvBijdI8Ua0FQ5soswIX679tBmwfhct64u6agWYirx9BGJvEJXtHSv
         +RCyd4q8XgjYBV/im1sXQvDamPjllvnlWFJ4l6xtHTjNVmiQgnOfaUznG18tonj74yrh
         XxMagA9f1oB8+1s4iakmGD1L1K8olZDsATuVximlyZ2+ndwYg0MAuhEsyXazqByN6Yda
         +KE+OuFTthpVXuHvHKaQmQtzpUJ1Jq8iaFlWPzFa5oY4KvWMXdD+BcJLrX7DAxG7gmVw
         +HL/o0+MKxk3SbZfQRKqXZW9UtMpG5z3S9CS9SaxkFmoYIMrpTCPY+PtvHBLe4GMHrHY
         TFUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=90PzVRSe7RX6puS568Ix8ZQFGkHvttvH2dg43P53oRM=;
        b=0X/eYdoN9P5LRlMPSpqTCsLWkByR6SEopI+2bi/LKid7XU1OY7mmNraTDQAQOCALUf
         mmUo7ZGKjc8GnpZIgKUcHheC7YaqJaMjJXZoTWdSxXfOfX+OV3qTq0+Ikh24HWz2iO46
         NazhiA2xBJ5BTmBPtVzxox47XdIh4O064VDg4BMoI/rDO1oSY2JGVL6QuV4U/Qb1vCH9
         OanfD+bY5plx/0ECIoY4Nm2tfHjKaoJ/3SowrVLwdi7SKjDsuNZ6lGW79kNmrMhlcT83
         O0BFMrtAV7+46F17hW3I7T1/+iONLeX6YaPcChvjVggJN2FryojNe0ZahXGWM/ChSxcQ
         CN3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkAFKcObh7/oi6tvUA8MO5n0I702Nq97wCRRGMmL3B4zAG7I9li
	Qu1aKgzQCWagbsCvTmulVJ4=
X-Google-Smtp-Source: AA0mqf7m4JZ196BE4C07DIELp07AIFzLPSX+G2ZydzArpguri54aGZ+bKVZLjq5tZk+Mgszzr4ijaw==
X-Received: by 2002:a2e:bd81:0:b0:26f:9736:bd5f with SMTP id o1-20020a2ebd81000000b0026f9736bd5fmr13865970ljq.285.1669486517879;
        Sat, 26 Nov 2022 10:15:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ec:0:b0:4a2:3951:eac8 with SMTP id v12-20020ac258ec000000b004a23951eac8ls4744368lfo.0.-pod-prod-gmail;
 Sat, 26 Nov 2022 10:15:17 -0800 (PST)
X-Received: by 2002:a05:6512:3986:b0:497:9810:acfc with SMTP id j6-20020a056512398600b004979810acfcmr11584438lfu.50.1669486516914;
        Sat, 26 Nov 2022 10:15:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669486516; cv=none;
        d=google.com; s=arc-20160816;
        b=g/HZaviJWbZj+pjyJozoO7B1Pdwr2KxbqCpNR3ouPiUFABvwaa0OWpqn9mf0WOLMiC
         RlWmI4Ym0azcWhkH8TxqN816qXln26qHAGCDh3pPjgNQyEisw+lJM92vSM6WMntngrgW
         R8D3A0WR62c0i/VA5zlPvZIGd9VvPRyry0SJ+pgweNksT7Lt8krOGqLnjEB86tb+eIG1
         evSc+SdqF8k4sagVbgEjnvhQFpjbSABLdxldHUS1NMA0QjZD8ZrRCd1BJe8NWGCqcK4k
         PV/cfndx7w2J+5ATruzgcVOaA8coNDgFivuyjZYwXGI1DrAriM1ImDIm673yjpYN4mCh
         FfMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=JDvTtFdWl1YXSMfasI4Saz9+J3V+bsk5xm78bG3AgR8=;
        b=O3St+kA6nvNvdFl3OXZGP8ZCwHc81bn2sT7EZOStv2yLm54hFBfgblgyVnkbvvm/Xi
         fOlraHVn7LJTx1U+Jr9cPmYIjJ9AhPVAJaKW7DySR2UGIzuzbC7mzN4khUCeYUqZBuvI
         U1DqjC2hFqXviY+fkrQc6qMrgQqSTv3KyVqad1eCWgHJrqJbZ7WwiaWuE8efk55f7/ra
         L3kBpCdiJzvmG0WkRlg8jb92sVDfNpvZB+w3iKcnAF+EVfyIg6VSQcUrxI4zFBg7r2Sk
         P/k3ISMaKaFc5bdaB8TvzOmKJFbghjgfAZuC0uFZNmBhE/7lrRRXCQ7YKdTJfi8LRZbb
         Aw9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DCYD0KPc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-250.mta0.migadu.com (out-250.mta0.migadu.com. [2001:41d0:1004:224b::fa])
        by gmr-mx.google.com with ESMTPS id g2-20020a056512118200b004b4f4360405si349705lfr.12.2022.11.26.10.15.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Nov 2022 10:15:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::fa as permitted sender) client-ip=2001:41d0:1004:224b::fa;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	David Gow <davidgow@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: fail non-kasan KUnit tests on KASAN reports
Date: Sat, 26 Nov 2022 19:15:11 +0100
Message-Id: <655fd7e303b852809d3a8167d28091429f969c73.1669486407.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DCYD0KPc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::fa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

After the recent changes done to KUnit-enabled KASAN tests, non-KASAN KUnit
tests stopped being failed when KASAN report is detected.

Recover that property by failing the currently running non-KASAN KUnit test
when KASAN detects and prints a report for a bad memory access.

Note that if the bad accesses happened in a kernel thread that doesn't
have a reference to the currently running KUnit-test available via
current->kunit_test, the test won't be failed. This is a limitation of
KUnit, which doesn't yet provide a thread-agnostic way to find the
reference to the currenly running test.

Fixes: 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT")
Fixes: 7f29493ba529 ("kasan: switch kunit tests to console tracepoints")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h      |  6 ++++++
 mm/kasan/kasan_test.c | 11 +++++++++++
 mm/kasan/report.c     | 22 ++++++++++++++++++++++
 3 files changed, 39 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a84491bc4867..08a83a7ef77f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -548,6 +548,12 @@ void kasan_restore_multi_shot(bool enabled);
 
 #endif
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+bool kasan_kunit_test_suite_executing(void);
+#else
+static bool kasan_kunit_test_suite_executing(void) { return false; }
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declared here to avoid warnings about missing declarations.
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index e27591ef2777..c9a615e892ed 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -32,6 +32,9 @@
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
+/* Whether the KASAN KUnit test suite is currently being executed. */
+static bool executing;
+
 static bool multishot;
 
 /* Fields set based on lines observed in the console. */
@@ -47,6 +50,11 @@ static struct {
 void *kasan_ptr_result;
 int kasan_int_result;
 
+bool kasan_kunit_test_suite_executing(void)
+{
+	return READ_ONCE(executing);
+}
+
 /* Probe for console output: obtains test_status lines of interest. */
 static void probe_console(void *ignore, const char *buf, size_t len)
 {
@@ -76,6 +84,8 @@ static int kasan_suite_init(struct kunit_suite *suite)
 		return -1;
 	}
 
+	WRITE_ONCE(executing, true);
+
 	/*
 	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
 	 * report the first detected bug and panic the kernel if panic_on_warn
@@ -94,6 +104,7 @@ static int kasan_suite_init(struct kunit_suite *suite)
 
 static void kasan_suite_exit(struct kunit_suite *suite)
 {
+	WRITE_ONCE(executing, false);
 	kasan_restore_multi_shot(multishot);
 	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
 	tracepoint_synchronize_unregister();
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 31355851a5ec..e718c997ecae 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -9,6 +9,7 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
+#include <kunit/test.h>
 #include <linux/bitops.h>
 #include <linux/ftrace.h>
 #include <linux/init.h>
@@ -112,10 +113,31 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
 
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+
+static void fail_nonkasan_kunit_test(void)
+{
+	struct kunit *test;
+
+	if (!kasan_kunit_test_suite_executing())
+		return;
+
+	test = current->kunit_test;
+	if (test)
+		kunit_set_failure(test);
+}
+
+#else /* CONFIG_KUNIT */
+
+static void fail_nonkasan_kunit_test(void) { }
+
+#endif /* CONFIG_KUNIT */
+
 static DEFINE_SPINLOCK(report_lock);
 
 static void start_report(unsigned long *flags, bool sync)
 {
+	fail_nonkasan_kunit_test();
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
 	disable_trace_on_warning();
 	/* Do not allow LOCKDEP mangling KASAN reports. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/655fd7e303b852809d3a8167d28091429f969c73.1669486407.git.andreyknvl%40google.com.
