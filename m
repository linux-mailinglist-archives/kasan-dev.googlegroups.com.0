Return-Path: <kasan-dev+bncBAABB4PATWOAMGQE7OKISDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 085F563D8B3
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 16:02:12 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id z9-20020a2ebe09000000b002796f022c63sf3992798ljq.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 07:02:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669820531; cv=pass;
        d=google.com; s=arc-20160816;
        b=dHZ3EvzopXL3Xfhi21c3Je0a9ZImPjYMjGcHyGZzDr+7Jgfitk8aTj870aaXhi4va8
         hhGfGxgfIZnIdds1HzfYQUQzu4sLeVguZUaAIAstCEo3cSpJAk2qIISJlc4eEP8OZI8m
         Rq1nkF4zHCsJgkeOsOW07xuJahk9c0LL4H2DqwvOdKcaIWB69KvMwO1G9ESEaCV3kilK
         YLc/1bbFBg0HVansWtWIr4iMfw0DcGG3eXgOX2LkIOUsLojROXnpbVR4gijpPWbj7zvh
         ejpnXOtZJzSvwTrzBBJT+zCy6MKk7eZLyc48MMWvDIbW3T9Z9bl9MH1aY200aUICj/QF
         8aqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CrPBl+KAVNkEvPGod5qEib94O6lJPvsNF+gIK5WPY3s=;
        b=XP5UI/lQPi+oxgHp9gltYdYqMU3Yjk3EECBT0JoalHBXb8cHqkqIB2SEUTPD7rbjPD
         SfzsDYHZzcvS4/2CvRzJcAh//Ni14WL3O/gUgG1ELFlsG7epCvfXW4ehIaWBZxaQndbJ
         0Zx0Wef8qu5ZqTt0I6Z1JFa01K56xicd58AYsFrY5qm4wLQ5797pHbu3BOoRopYg+nZn
         Y2mC5HA4rvUUfFOsB37m5sUQeid7Ewloh3pVd49LOyyMRJ+/aTkmTOcRuGVsR6vjGSWY
         fduy7PECTeMwTrOxDuSZNc3cHULC2/qP6ZQFEVsYfjJ6r1EKPLyW6NLvCsACww0HInrW
         5OZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vWLSx907;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CrPBl+KAVNkEvPGod5qEib94O6lJPvsNF+gIK5WPY3s=;
        b=hMMNWRgwTDkfWK/Ewsf9ir2gwVbjLmaa1fcvfxpapTTA1mMy9n4j2t0+a3OwRmbaVH
         1QWnqXWLqlqj039u+c0eQQgTNt8nMqDnH3qJIj+h+hNXI1e7FHcoOLDMJoWeUsJ3DOdr
         9SIELkq5YCaUOjUTaXlcDT/ejE6jCtqG3gViotm0D/NnjC/FyyRYPEqo/CmL+VcJChaS
         chd90eiQYbI6THCnGzBnKKWjp+jK//7Pfolt2mv97Z9Gqah6wTu30TUQSpaxB1ZmHewW
         zKwJSl6CT4Pz5E2ws0Wv4JrTOqroqmlh6hBxtETjX58Y1T3OHvAU4fmN+EoStibzyksA
         vOaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=CrPBl+KAVNkEvPGod5qEib94O6lJPvsNF+gIK5WPY3s=;
        b=F721fBpnHJnNpQZugiMkRq3g7xk2AvGkP8HAP/dyHRtSuJhmDSsGp9+s5tGg/XKuNB
         VGLVecRRU/VurJr35AhoR0LBlxTiOM8GpxvE7PmcwcI3yh+MElsAr4KlS1x4jCK1gYm5
         LmpIByCbhrD5Q78UYQiZtzpKQwT1QAzKLtS1B94perZgu6XearUL7ffIBdmGL3ozGdCF
         qBH3+uQGs9Pcg70oc3JrzH2IL0+o7m+9vgcwyBXVjEZHDuEcmwb8f32zphYevDuAYga9
         mXRSS28r1SUsEFeUAhAE8H3GB07/XGDUHfVxoKobNmnNgB8k8E5QMQDPGn4OLdM51Kz/
         GiiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnMylzbQO75Pg1DEa/HtxFl4ATvKMRIIu8/Mcg3xunl3z2vNFe1
	yL0/Sjht00IQO4eI0xraJgY=
X-Google-Smtp-Source: AA0mqf7XqzPjtMPACsc6w2rm/Vu2h3pvAmQ4X5ouFYmGa49oWoTsD+m6rijcP5EDZCNiXCv9ujhJDw==
X-Received: by 2002:a2e:3a15:0:b0:26e:eeb:f9cf with SMTP id h21-20020a2e3a15000000b0026e0eebf9cfmr2245606lja.480.1669820530335;
        Wed, 30 Nov 2022 07:02:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:741:b0:49a:b814:856d with SMTP id
 c1-20020a056512074100b0049ab814856dls5984730lfs.1.-pod-prod-gmail; Wed, 30
 Nov 2022 07:02:08 -0800 (PST)
X-Received: by 2002:a05:6512:a93:b0:4a2:6337:872d with SMTP id m19-20020a0565120a9300b004a26337872dmr15491459lfu.35.1669820527588;
        Wed, 30 Nov 2022 07:02:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669820527; cv=none;
        d=google.com; s=arc-20160816;
        b=OmJriUgP5VxsC4zKKv7rzdhiEy83iSdAATQ5A6m7pU38ZLEPZzaVGJFh0VEN00x6EP
         LaifAts4ZOw0RvXkOP81lUlJ7UNI8JCJ6wcIrD8RUIpWef6AfsVl6JAAH5rkRku7hL94
         cYIpRXm5zVETZ3lN3WC46NzcEcDxZAE2/aq1qF22tbxnv/TdmCm0plyBTK7yv30LaynD
         uqk8zYCOR5Bha+dB+A9OJmniYFXtB8B6T7ZnOYWGoysSvDJbDPKXdh8yMuyFoePIEqll
         XMe4mvg8qrb12mwUSXAhXogZlvy6Se0nXrU9uJMXpHXTaEfCV2EOzuw31imkRjxbbUXA
         ScqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=4QL5FnfIoD+swykCGdX15GCfYgfftAp4hvZwQtuSkRs=;
        b=Od6hfNWPFZHSQFCDSb0/arDAUFGV4siaSVUKXYJPuBmrh1HcohKjuujEhp+B3aMrzu
         FKhmG34cm5iAjlcS3XjCLZkJr96S0tRfDy4WnP2RqUIHogpVt1R9xSf6ic5rLehn08Qs
         NreJswPLPORnaHSVssJh7BN3a15VOa4JbXp39AKOR8Z8GBkQ6EWfEnBfTiKBehqbrizF
         cZCew+Zpxkip0Ad21JKjjUT+AxaiyxWceBTCsC6nLvMALFwnqzehb8LPAV+TjMX0SJTp
         vzq2VkehYGq2rZzoolHL+MAMX6/ioF+TAUqJ5BeDOJ6ewjhSc41ib9zb6T7TEWJXUpl/
         Sf3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vWLSx907;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id x5-20020a056512078500b004a273a44c4asi79356lfr.7.2022.11.30.07.02.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Nov 2022 07:02:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v2 mm] kasan: fail non-kasan KUnit tests on KASAN reports
Date: Wed, 30 Nov 2022 16:02:03 +0100
Message-Id: <7be29a8ea967cee6b7e48d3d5a242d1d0bd96851.1669820505.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vWLSx907;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Changes v1->v2:
- Fix build with KASAN built as a module.
- Rename fail_nonkasan_kunit_test to fail_non_kasan_kunit_test.
- Fix inverted condition in fail_non_kasan_kunit_test.
- Mark kasan_kunit_test_suite_executing and fail_non_kasan_kunit_test
  as inline when the corresponding configs are not enabled.
---
 mm/kasan/kasan.h      | 12 ++++++++++
 mm/kasan/kasan_test.c |  4 ++++
 mm/kasan/report.c     | 53 +++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 69 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a84491bc4867..ea8cf1310b1e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -541,6 +541,18 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
 #error kasan_arch_is_ready only works in KASAN generic outline mode!
 #endif
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+
+void kasan_kunit_test_suite_start(void);
+void kasan_kunit_test_suite_end(void);
+
+#else /* CONFIG_KASAN_KUNIT_TEST */
+
+static inline void kasan_kunit_test_suite_start(void) { }
+static inline void kasan_kunit_test_suite_end(void) { }
+
+#endif /* CONFIG_KASAN_KUNIT_TEST */
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST) || IS_ENABLED(CONFIG_KASAN_MODULE_TEST)
 
 bool kasan_save_enable_multi_shot(void);
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index e27591ef2777..9aa892e7b76c 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -76,6 +76,9 @@ static int kasan_suite_init(struct kunit_suite *suite)
 		return -1;
 	}
 
+	/* Stop failing KUnit tests on KASAN reports. */
+	kasan_kunit_test_suite_start();
+
 	/*
 	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
 	 * report the first detected bug and panic the kernel if panic_on_warn
@@ -94,6 +97,7 @@ static int kasan_suite_init(struct kunit_suite *suite)
 
 static void kasan_suite_exit(struct kunit_suite *suite)
 {
+	kasan_kunit_test_suite_end();
 	kasan_restore_multi_shot(multishot);
 	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
 	tracepoint_synchronize_unregister();
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 31355851a5ec..f2db8605ee0f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -9,6 +9,7 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
+#include <kunit/test.h>
 #include <linux/bitops.h>
 #include <linux/ftrace.h>
 #include <linux/init.h>
@@ -112,10 +113,62 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
 
 #endif
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+
+/*
+ * Whether the KASAN KUnit test suite is currently being executed.
+ * Updated in kasan_test.c.
+ */
+bool kasan_kunit_executing;
+
+void kasan_kunit_test_suite_start(void)
+{
+	WRITE_ONCE(kasan_kunit_executing, true);
+}
+EXPORT_SYMBOL_GPL(kasan_kunit_test_suite_start);
+
+void kasan_kunit_test_suite_end(void)
+{
+	WRITE_ONCE(kasan_kunit_executing, false);
+}
+EXPORT_SYMBOL_GPL(kasan_kunit_test_suite_end);
+
+static bool kasan_kunit_test_suite_executing(void)
+{
+	return READ_ONCE(kasan_kunit_executing);
+}
+
+#else /* CONFIG_KASAN_KUNIT_TEST */
+
+static inline bool kasan_kunit_test_suite_executing(void) { return false; }
+
+#endif /* CONFIG_KASAN_KUNIT_TEST */
+
+#if IS_ENABLED(CONFIG_KUNIT)
+
+static void fail_non_kasan_kunit_test(void)
+{
+	struct kunit *test;
+
+	if (kasan_kunit_test_suite_executing())
+		return;
+
+	test = current->kunit_test;
+	if (test)
+		kunit_set_failure(test);
+}
+
+#else /* CONFIG_KUNIT */
+
+static inline void fail_non_kasan_kunit_test(void) { }
+
+#endif /* CONFIG_KUNIT */
+
 static DEFINE_SPINLOCK(report_lock);
 
 static void start_report(unsigned long *flags, bool sync)
 {
+	fail_non_kasan_kunit_test();
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
 	disable_trace_on_warning();
 	/* Do not allow LOCKDEP mangling KASAN reports. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7be29a8ea967cee6b7e48d3d5a242d1d0bd96851.1669820505.git.andreyknvl%40google.com.
