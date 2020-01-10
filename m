Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4UO4PYAKGQEVPWXPIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C771137662
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 19:50:26 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id f22sf858702lfh.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 10:50:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578682226; cv=pass;
        d=google.com; s=arc-20160816;
        b=uAjROUoZ9n2GsuN58UalQkzHydC1ZJfmqxK6MZUMdU20EeNHmxBRo007AlCBbxvYS1
         ma+N0NUTZ1urBnN1iMfxr7DKWoKUmCPdGwNhrlUCzFgoRDFcYL1pSsKk+EfQ4udSmQBr
         dIYWO/xOamoBTUEdl32MKmpLZbG5ab164gdIHHcztDSCbRbjo7IPxGfHgXVYlYV+oWvX
         I1g5IhkroPzPQcwU6KVPfbPioB9PjTwfZTIWlC6xzB+GZ35Oyb3yovmYDHaygLqwfmPJ
         cDw2zWzv5Q7FFUVqlVXP6WWbsN7/3WJHMb4jnfRk8N2bAIQwU+vXeTbtXrXejd/qz5SH
         6qxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qSWr1+jJtzGmBgdnrYuQ98uKf0kos+AjLzXi3k3qMzk=;
        b=lr7QjUkr9jbNRPkDOOLA6sg+Hm/6ae0CDC2s+BNxGjVZsXDn9ywbSyPtvgF5NPf6jO
         Ebwl/IRI/5NzmXxdoRyEYMNQYvuKMhumIXD8AG/fvHHQn148a+5pF9EQKUDU4165XRnY
         PkusF8lX6YXV4aQpoSofKB5FomrGAkG6aPSHS2GszGqbGOGJ6ZH6Tpi+733PaAFlCzsB
         OxOxpkqXbZFhbnh2r9h/G0CRvTdMEVCcFD3fJMLgiIQ/g8MJx1yxVvFjiLcy6jD4K+BM
         Zu5cCafnvhRLa6DxySTSMtvSyzVGbcsdDBjdnhWOzsYSoeAGTxhbOkvZ5+UQ64L+NmPt
         Ctgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="q/cLsYwh";
       spf=pass (google.com: domain of 3cmcyxgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cMcYXgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qSWr1+jJtzGmBgdnrYuQ98uKf0kos+AjLzXi3k3qMzk=;
        b=GE2LsbezFpmcVzkOnhIQjWTHLfnkq3TOqxsfZmaKYOo5hipwdBQ2eEhFNNuxccerTd
         GV6kKLtI3o1x2aAAjNsKoGGl7aw407gCZaoFQgJPG0KHaT0dulaszepedL0FTJwTkPSb
         EyJcKdsixOks5JU55Iyldvd92QDF1UXDRTCnnmCMzCnoW6NdhrVRQi8mk50CesiC+gyG
         rAgxkTWFEEWjgdEiOtRprm+RY4aIhdsDivl8DZEChgH3/qJTykYiSuKekLpZqlDDz7yC
         wCPiC0uEkyx0e9o6zgFuB9X8/QQ3WycdhceiJOHvkx4FnQMvZp7EPpgh2qE/+9buxYCI
         HM2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qSWr1+jJtzGmBgdnrYuQ98uKf0kos+AjLzXi3k3qMzk=;
        b=oYyG7+ajsDGGIzqd5I8x8AWIFUn1Yh6yHqskMXn2NWO7Y/JANyEsznhE6zpYf4+JpI
         AdPiYmOIOzWL1MdAzg0YiFhJcEAiHh3TINVUo+ggtHDOZ33119v3g5dGOlKtqWymG2q3
         2NxJH/bJL+IdJAWHhItNb98bWw9zmn5vRRalAz5mCaCdNBnceKPxeGhE/UHPxmdCt3qQ
         bwZomWTcdOJOb2xlz5NybayiVyV0hwt8zdO8VNFb52+mzYvo8s77pHJ+0r8rzkjAmXXK
         GXzEETNlBG8KGrTFx2HWdQQx8ka1ULLBMaEjeuQgoJOOzX5gnZ3eER1e5fWvDe5WJvNJ
         s2Jg==
X-Gm-Message-State: APjAAAXHdzPE+6evuSmRtjWZPnQJNdr2VEwXALldKa2MZfdGZtbFfI8w
	aC/uMNvwszX4/VJxZqmJ9Mg=
X-Google-Smtp-Source: APXvYqwdZhwL1OpeincAsySNaV+PmJfWACnVt7uy7hthWiQDVYqjBtT8MAb6r02A+aPsFG/l7gg0OA==
X-Received: by 2002:a2e:9248:: with SMTP id v8mr3505282ljg.189.1578682226136;
        Fri, 10 Jan 2020 10:50:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9709:: with SMTP id r9ls861382lji.14.gmail; Fri, 10 Jan
 2020 10:50:25 -0800 (PST)
X-Received: by 2002:a2e:8544:: with SMTP id u4mr3516284ljj.70.1578682225450;
        Fri, 10 Jan 2020 10:50:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578682225; cv=none;
        d=google.com; s=arc-20160816;
        b=A8XdJGTDD3blKAEc8dtU9+7njFPxU/eJWZJIA5uLkmyPiUFnRtvbrjRsRttU9EvJGH
         CMtu6kpnOUq074trMgiLemNBc0J2udVsPauD3UaRdGHemXimtTkEV7eBksJ3tQCDCrJ7
         3d7fJ42RLcs3COlXZiNlu4jZcdgVGokmz6OxI1K1FLMaiKXbjUnq1nu76+BFVVIo0JD7
         IRPsxi2IBNrhm19j/YaulJQZOrqr7UkPQzMHSFBqbBkRfkZq8Yoqbdf6fyLaGn2LW54n
         HI72dxE4PIEheHGgXT103Gxiosna8R04r0HDwpc3i3l3ofZFIJxj/1KbK31r+rYDcJqB
         eYsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SRBx19RXSNdw51idBzh3Q+Tsvdj/UAcs73kMC/XQ8nE=;
        b=EyuH4Tyj+TldgHhk8sLkmy7MQF+78D9PbZKZooctM+TMEnoF67ymKZtGPrSbrDp+4v
         lDSO4hWPvM9oVgpjtMHbUGJMg2eNytcszp27RD+ZIbz0Wkkxy+kkIhx63x14wXl0F2qC
         c3XCqoQlU0qXXm7UadjGumEfg03bkAQ/kdIn76n1e3Ia+CPSKVdQB0aIZPsT0TjXgI6Z
         ToGzRHADCRAYC24ffSSGcLuHUaAoOOjljnqKzwyGvexEtKqeGRqDDhXTAGvoky5GbJDT
         Hx/dqqBCzecBNIjY+kMNXDv6kbvPZaOsrAT/Uo0NfKr1Kx6+emEMyh3H9LKEzhhkt9Cb
         XqWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="q/cLsYwh";
       spf=pass (google.com: domain of 3cmcyxgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cMcYXgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u5si105835lfm.0.2020.01.10.10.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 10:50:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cmcyxgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f15so1338919wrr.2
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 10:50:25 -0800 (PST)
X-Received: by 2002:adf:cf0a:: with SMTP id o10mr4720679wrj.325.1578682224730;
 Fri, 10 Jan 2020 10:50:24 -0800 (PST)
Date: Fri, 10 Jan 2020 19:48:34 +0100
In-Reply-To: <20200110184834.192636-1-elver@google.com>
Message-Id: <20200110184834.192636-3-elver@google.com>
Mime-Version: 1.0
References: <20200110184834.192636-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu v2 2/2] kcsan: Rate-limit reporting per data races
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="q/cLsYwh";       spf=pass
 (google.com: domain of 3cmcyxgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cMcYXgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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

KCSAN data-race reports can occur quite frequently, so much so as
to render the system useless.  This commit therefore adds support for
time-based rate-limiting KCSAN reports, with the time interval specified
by a new KCSAN_REPORT_ONCE_IN_MS Kconfig option.  The default is 3000
milliseconds, also known as three seconds.

Because KCSAN must detect data races in allocators and in other contexts
where use of allocation is ill-advised, a fixed-size array is used to
buffer reports during each reporting interval.  To reduce the number of
reports lost due to array overflow, this commit stores only one instance
of duplicate reports, which has the benefit of further reducing KCSAN's
console output rate.

Reported-by: Qian Cai <cai@lca.pw>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
v2:
* Paul E. McKenney: commit message reword.
* Use jiffies instead of ktime -- we want to avoid calling into any
  further complex functions, since KCSAN may also detect data races in
  them, and as a result potentially leading to observing corrupt state
  (e.g. here, observing corrupt ktime_t value).
---
 kernel/kcsan/report.c | 110 ++++++++++++++++++++++++++++++++++++++----
 lib/Kconfig.kcsan     |  10 ++++
 2 files changed, 110 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 9f503ca2ff7a..b5b4feea49de 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -1,5 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#include <linux/jiffies.h>
 #include <linux/kernel.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
@@ -31,12 +32,99 @@ static struct {
 	int			num_stack_entries;
 } other_info = { .ptr = NULL };
 
+/*
+ * Information about reported data races; used to rate limit reporting.
+ */
+struct report_time {
+	/*
+	 * The last time the data race was reported.
+	 */
+	unsigned long time;
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
+	unsigned long invalid_before;
+	int i;
+
+	BUILD_BUG_ON(CONFIG_KCSAN_REPORT_ONCE_IN_MS != 0 && REPORT_TIMES_SIZE == 0);
+
+	if (CONFIG_KCSAN_REPORT_ONCE_IN_MS == 0)
+		return false;
+
+	invalid_before = jiffies - msecs_to_jiffies(CONFIG_KCSAN_REPORT_ONCE_IN_MS);
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
+		if (time_before(rt->time, use_entry->time))
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
+		if (time_before(rt->time, invalid_before))
+			continue; /* before KCSAN_REPORT_ONCE_IN_MS ago */
+
+		/* Reported recently, check if data race matches. */
+		if ((rt->frame1 == frame1 && rt->frame2 == frame2) ||
+		    (rt->frame1 == frame2 && rt->frame2 == frame1))
+			return true;
+	}
+
+	use_entry->time = jiffies;
+	use_entry->frame1 = frame1;
+	use_entry->frame2 = frame2;
+	return false;
+}
+
 /*
  * Special rules to skip reporting.
  */
@@ -132,7 +220,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
 	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
-	int other_skipnr;
+	unsigned long this_frame = stack_entries[skipnr];
+	unsigned long other_frame = 0;
+	int other_skipnr = 0; /* silence uninit warnings */
 
 	/*
 	 * Must check report filter rules before starting to print.
@@ -143,34 +233,34 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200110184834.192636-3-elver%40google.com.
