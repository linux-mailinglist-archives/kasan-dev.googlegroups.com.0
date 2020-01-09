Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7MK3XYAKGQEC26FQQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5611135C9F
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 16:23:41 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id j13sf2991213wrr.20
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 07:23:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578583421; cv=pass;
        d=google.com; s=arc-20160816;
        b=W/vN2PHLTRMYjXQ4ZnVpTsIPSVrapvYaapxLteaFSYHqEL55pevbJjx0EU5PNxA/de
         sJSTduM2xQLU/69xYuE8zqSZo0FAJE2OQgNZTY5hkqsYD+SmiJ3F5fbn7OF8flYY3TRT
         mGCVcy9BXT4fQy6HmaXucdrpfYkfUEIb9l5n3n4qXExXgJolPFkieW8lfUOx/N/Z8Kk3
         c7Dzs3D97SbY3GLDAIbLjilOIl2D0bqmEEt6LJIg08uY5hT8HY5tu1ZtVnMtVkpUqNh/
         Q8QNweo1Hx0n9uWSTE/8iDp8FiJTlKwdSajhtpQPl+fldRRoZsrx69irhFbaWXqzNbBe
         DlDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=8qhAKdmPPKPHei4JPS8f1wdAm8q6DriKQich+EidZlE=;
        b=IzU2czKfFnlptROOLbbjRx61FjtBc8DxJQQMuvdr+NzPYL3kdB3NX/zG7wd9KmuY4X
         lsC4jpSGtE5dizfuwt9ASvUcybkMO6qt8A2THg3N/7cgzJHRCoFA9rE/h0PAxdywt5ar
         abIEPPMZV3knsQs406laiCv98PG6zafvZ9hXwf/3j2Pxf5HkSmQ+JH27F6P10DW1w3eM
         Jy4nQE+aYTVB5YbH3IpSL5J8tVg2m0NLY1s5Va9xUN73rVM5LiJGiWr83bFy56cQ2/hq
         TqlDzqyeyFvhPWpx+/TI1F0wncSV8+DgvkcUTC3iJ8VwvbBfaI20cfdur/DH6bg2peMb
         sdIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vffo9f1x;
       spf=pass (google.com: domain of 3feuxxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fEUXXgUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8qhAKdmPPKPHei4JPS8f1wdAm8q6DriKQich+EidZlE=;
        b=JOEHOtro2cY+xufF1/gKLJnntohVJ+sbIC0XS5h9F/3KOD3CqGLGxjbT23ekzSuYU1
         caRAfwp6W0nOMKsTbAirJ9ODFAKk5GkEP9L1rtvR2TZUDbEKR5GHxdwF8LVQ74TeMJGP
         yYxOvX3XlG0sKioL2JQBtf7lbcoQ79TF20sXq683RulqoOh3sIaul65duEq25oXrFXDv
         bMUuc0ic2aG+rNEKPoCrE865GEfOBNOXrap/bu1OgYYHnugG2aykr9jrUM344+R3jCtq
         jDi2wQG1KkUJ46n+Vu9H2NePexXQVUNJB3XkRjTVxLYKUPQ5d1qwYUhnbQfaqaLNvoA1
         Sbkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8qhAKdmPPKPHei4JPS8f1wdAm8q6DriKQich+EidZlE=;
        b=AzxtaFk8ZKrzebH3kpGJsB366YJOwly7XtK9NtP9CrbbHG/yhMMxtwQ9XyiktxGe2s
         fN30hhc5cb+C8arxDJXfLcfGa9h0F7vVtUe74ckO8x0jJJODwNfEIEvozzz5Xe0Uihr4
         EtJZvf9J8aiJcfWFNboWSHLSD/j00fn8BBj2jMbjffQ/MJ5Q4tf3+IRAB1mmzYbMpzvd
         Zm65mOODLBIUFUFC5dHLUyoBC3/8mqfvU9Ham9ICPEBG0vQ0bcWrjukFrgMCYA+133Z1
         DhKIPWQSObMVEadM2ITzKVUrSuv9i7C2boXMcQ15G74A+sTfeErxanNQeMbexd7jsoyF
         2ViA==
X-Gm-Message-State: APjAAAVddZSiGuOJPCzCRyUbyRT5h8U8Cr53qowtoLQOJjX1Kk+0b+DQ
	O47au9PfLM1KDriJ04joJSE=
X-Google-Smtp-Source: APXvYqweeigyGG6oyyPVf+GKhSqKTSJrOdKnx5yhm5p5UP1me1rWetilQeCvuap1C+beffJAAywpLA==
X-Received: by 2002:a1c:62c1:: with SMTP id w184mr5762815wmb.150.1578583421426;
        Thu, 09 Jan 2020 07:23:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb55:: with SMTP id v21ls960787wmj.4.canary-gmail; Thu,
 09 Jan 2020 07:23:40 -0800 (PST)
X-Received: by 2002:a1c:6707:: with SMTP id b7mr5779250wmc.54.1578583420821;
        Thu, 09 Jan 2020 07:23:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578583420; cv=none;
        d=google.com; s=arc-20160816;
        b=eiqmrCT321QB/92eh65AXkySrZxdermhjekecq1wuaO3xlW8hZgSk5lRjGPRB8EZJc
         sdEWMmeXquduqPpBtDm5LZBYFsBM7KWnY6zvbpYyRT7SP6tVeIlL9mC/prlx/rBxmPMv
         GpcgVOpkC8nq9XC+SDpsPtm81nZrV75IKVs8Lgg6X6l6aBffuScx6LTZqqR11M4MouYg
         aW/OEWd+8db8QaEqwZnqRT0eAls5lXYnkhvYVvpha9+KHt9YSBTdhnePtnOhUz4ScrO5
         kd2fd1crl/eRce0lfRMYEts7x8+S0IS1Yt663o+QMRnjyTWyWT+6ziBJ4prEU8b7dOh5
         Xxiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=BwDt6lrR16c2nuKNqASjxv2dJeJjfu/H1rhKllUpnIM=;
        b=XgcjQEbOmwdPdPi82NIBx9Kx6fwwYOqVvhuKuaD7J4vt2DGVHaLPMfDVxsDP+VhjZE
         dOLa0hyI2lh9zQeQDEO0Th9lkOXEHPQ3ZOwTYxB9qz3qq8k2B2qtqFdc96w6/ZEB4s3u
         rD+Zp5twklMGRE0O2GmfmRHqZZ9EnRWrSpXrANtXVIDNjAMU6dIjwd2irhcoB39KTWcU
         5BLj1uit5oX/Pp29sVLAB7ZaMvS3JcRgLANjq62pwBKLJ6rK2d6Nr9x/qghC4STragfr
         FnEfSgY7sjkrQwQtuI1cy6f4v19S58lPmbd8MOTiEsvNCKISrfmi1LeucAynuqLJlnGA
         noNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vffo9f1x;
       spf=pass (google.com: domain of 3feuxxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fEUXXgUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p23si155912wma.1.2020.01.09.07.23.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 07:23:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3feuxxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h130so1046054wme.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 07:23:40 -0800 (PST)
X-Received: by 2002:a5d:540f:: with SMTP id g15mr11173097wrv.86.1578583420349;
 Thu, 09 Jan 2020 07:23:40 -0800 (PST)
Date: Thu,  9 Jan 2020 16:23:22 +0100
In-Reply-To: <20200109152322.104466-1-elver@google.com>
Message-Id: <20200109152322.104466-3-elver@google.com>
Mime-Version: 1.0
References: <20200109152322.104466-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu 2/2] kcsan: Rate-limit reporting per data races
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vffo9f1x;       spf=pass
 (google.com: domain of 3feuxxgukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fEUXXgUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Adds support for rate limiting reports. This uses a time based rate
limit, that limits any given data race report to no more than one in a
fixed time window (default is 3 sec). This should prevent the console
from being spammed with data race reports, that would render the system
unusable.

The implementation assumes that unique data races and the rate at which
they occur is bounded, since we cannot store arbitrarily many past data
race report information: we use a fixed-size array to store the required
information. We cannot use kmalloc/krealloc and resize the list when
needed, as reporting is triggered by the instrumentation calls; to
permit using KCSAN on the allocators, we cannot (re-)allocate any memory
during report generation (data races in the allocators lead to
deadlock).

Reported-by: Qian Cai <cai@lca.pw>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 112 ++++++++++++++++++++++++++++++++++++++----
 lib/Kconfig.kcsan     |  10 ++++
 2 files changed, 112 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 9f503ca2ff7a..e324af7d14c9 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 
 #include <linux/kernel.h>
+#include <linux/ktime.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
@@ -31,12 +32,101 @@ static struct {
 	int			num_stack_entries;
 } other_info = { .ptr = NULL };
 
+/*
+ * Information about reported data races; used to rate limit reporting.
+ */
+struct report_time {
+	/*
+	 * The last time the data race was reported.
+	 */
+	ktime_t time;
+
+	/*
+	 * The frames of the 2 threads; if only 1 thread is known, one frame
+	 * will be 0.
+	 */
+	unsigned long frame1;
+	unsigned long frame2;
+};
+
+/*
+ * Since we also want to be able to debug allocators with KCSAN, to avoid
+ * deadlock, report_times cannot be dynamically resized with krealloc in
+ * rate_limit_report.
+ *
+ * Therefore, we use a fixed-size array, which at most will occupy a page. This
+ * still adequately rate limits reports, assuming that a) number of unique data
+ * races is not excessive, and b) occurrence of unique data races within the
+ * same time window is limited.
+ */
+#define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
+#define REPORT_TIMES_SIZE                                                      \
+	(CONFIG_KCSAN_REPORT_ONCE_IN_MS > REPORT_TIMES_MAX ?                   \
+		 REPORT_TIMES_MAX :                                            \
+		 CONFIG_KCSAN_REPORT_ONCE_IN_MS)
+static struct report_time report_times[REPORT_TIMES_SIZE];
+
 /*
  * This spinlock protects reporting and other_info, since other_info is usually
  * required when reporting.
  */
 static DEFINE_SPINLOCK(report_lock);
 
+/*
+ * Checks if the data race identified by thread frames frame1 and frame2 has
+ * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
+ */
+static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
+{
+	struct report_time *use_entry = &report_times[0];
+	ktime_t now;
+	ktime_t invalid_before;
+	int i;
+
+	BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 && REPORT_TIMES_SIZE == 0);
+
+	if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
+		return false;
+
+	now = ktime_get();
+	invalid_before = ktime_sub_ms(now, CONFIG_KCSAN_REPORT_ONCE_IN_MS);
+
+	/* Check if a matching data race report exists. */
+	for (i = 0; i < REPORT_TIMES_SIZE; ++i) {
+		struct report_time *rt = &report_times[i];
+
+		/*
+		 * Must always select an entry for use to store info as we
+		 * cannot resize report_times; at the end of the scan, use_entry
+		 * will be the oldest entry, which ideally also happened before
+		 * KCSAN_REPORT_ONCE_IN_MS ago.
+		 */
+		if (ktime_before(rt->time, use_entry->time))
+			use_entry = rt;
+
+		/*
+		 * Initially, no need to check any further as this entry as well
+		 * as following entries have never been used.
+		 */
+		if (rt->time == 0)
+			break;
+
+		/* Check if entry expired. */
+		if (ktime_before(rt->time, invalid_before))
+			continue; /* before KCSAN_REPORT_ONCE_IN_MS ago */
+
+		/* Reported recently, check if data race matches. */
+		if ((rt->frame1 == frame1 && rt->frame2 == frame2) ||
+		    (rt->frame1 == frame2 && rt->frame2 == frame1))
+			return true;
+	}
+
+	use_entry->time = now;
+	use_entry->frame1 = frame1;
+	use_entry->frame2 = frame2;
+	return false;
+}
+
 /*
  * Special rules to skip reporting.
  */
@@ -132,7 +222,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
 	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
-	int other_skipnr;
+	unsigned long this_frame = stack_entries[skipnr];
+	unsigned long other_frame = 0;
+	int other_skipnr = 0; /* silence uninit warnings */
 
 	/*
 	 * Must check report filter rules before starting to print.
@@ -143,34 +235,34 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
 		other_skipnr = get_stack_skipnr(other_info.stack_entries,
 						other_info.num_stack_entries);
+		other_frame = other_info.stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
-		if (skip_report(other_info.access_type, value_change,
-				other_info.stack_entries[other_skipnr]))
+		if (skip_report(other_info.access_type, value_change, other_frame))
 			return false;
 	}
 
+	if (rate_limit_report(this_frame, other_frame))
+		return false;
+
 	/* Print report header. */
 	pr_err("==================================================================\n");
 	switch (type) {
 	case KCSAN_REPORT_RACE_SIGNAL: {
-		void *this_fn = (void *)stack_entries[skipnr];
-		void *other_fn = (void *)other_info.stack_entries[other_skipnr];
 		int cmp;
 
 		/*
 		 * Order functions lexographically for consistent bug titles.
 		 * Do not print offset of functions to keep title short.
 		 */
-		cmp = sym_strcmp(other_fn, this_fn);
+		cmp = sym_strcmp((void *)other_frame, (void *)this_frame);
 		pr_err("BUG: KCSAN: data-race in %ps / %ps\n",
-		       cmp < 0 ? other_fn : this_fn,
-		       cmp < 0 ? this_fn : other_fn);
+		       (void *)(cmp < 0 ? other_frame : this_frame),
+		       (void *)(cmp < 0 ? this_frame : other_frame));
 	} break;
 
 	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
-		pr_err("BUG: KCSAN: data-race in %pS\n",
-		       (void *)stack_entries[skipnr]);
+		pr_err("BUG: KCSAN: data-race in %pS\n", (void *)this_frame);
 		break;
 
 	default:
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3f78b1434375..3552990abcfe 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -81,6 +81,16 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	  KCSAN_WATCH_SKIP. If false, the chosen value is always
 	  KCSAN_WATCH_SKIP.
 
+config KCSAN_REPORT_ONCE_IN_MS
+	int "Duration in milliseconds, in which any given data race is only reported once"
+	default 3000
+	help
+	  Any given data race is only reported once in the defined time window.
+	  Different data races may still generate reports within a duration
+	  that is smaller than the duration defined here. This allows rate
+	  limiting reporting to avoid flooding the console with reports.
+	  Setting this to 0 disables rate limiting.
+
 # Note that, while some of the below options could be turned into boot
 # parameters, to optimize for the common use-case, we avoid this because: (a)
 # it would impact performance (and we want to avoid static branch for all
-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109152322.104466-3-elver%40google.com.
