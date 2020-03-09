Return-Path: <kasan-dev+bncBAABBN5GTLZQKGQEPDCGIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 189D917E7C6
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:25 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id b72sf8040982ilg.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780664; cv=pass;
        d=google.com; s=arc-20160816;
        b=i22iqw8ahQ272Rtoy/86/WD0TbH7EfpFPoYfaQHcKevj36iXTc55v+9CnBlCuItG2P
         qLhL6MNq9Bq318Vpt/+1FO87KJuCRw9BU+oA3+fXUgaXmown4WD1v3071iwJU05EKlYw
         LIMcbAmrj4SVRgSTgobN1l+qltXAxLU9aCObk7cbB5M7R4h9MXOHrnvNyookzsGyGbmf
         88KT6NJzntLYVbie6SFOarakT6PPFvc6D50aeZNyBpBommUngvIr0uGKdjUrMbCcltWu
         /GSrJL6MVzIyGMIpsG28J6awMN+ZiamQ/wlGGBmdWoSwegV2aBPslLrsHQ1chSTRrS21
         7yxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=jjYrKg8j3sQiN+ypq90e9ys0Tm0H/NuMTKkkBtMDp4Y=;
        b=iOIVDmP/Qos6nnvzAVaiPk+F2DqaHzX5anI+9rKSLTvd1+r1TVRAqwmI7coMHswdIJ
         qP2BzM6BsgeQYGahTzjQvNa9/yMYW0v2K9RWoGz0FmIsh+fyMZRlokwX1b5TA1I0gje3
         sxjyBDs+KxbVY/Y9A/06qhcRcOtrMFUPmOectyIabjmkxkuS3Jw3IBRunw/U4MtwiLwJ
         lwbcjr6mlrBlaragwWGYJLmBbekI/JqPo5CD1j70LGgvDW8Ije8NxqM8r+7TPnOPFs7c
         GW6jvTGGXQbgBTJTgt+x02K+0NkPZ3cUIGoLXLzbhW2pTkScK5ruR6CW1yGJDUYCgHi0
         T7Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="X9kQwSz/";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jjYrKg8j3sQiN+ypq90e9ys0Tm0H/NuMTKkkBtMDp4Y=;
        b=kLGD3al/qlnJCPTIXY/alu/U84rttQ9v08bekm1b4w4Spwr4rV9p7aS7z/6xqKaXlE
         AMkQjrmAWnfJ7PIFwdsqrwAB5AWkgBmTBKLxPpBuaqrj5FlKBoGybbnlxxxY+DHuhEyC
         xX/qem6zBxI7N/2ebKzfokGHKCLEKD2FOvoLNCPqQFdD/k6jPJrYNwtbF4Q0F7mP8lnG
         jvoW+X0bKLOYBfSTuvAvJPFe3gh8a0A66yRBoOn4pvd1JwR1Dgg7/0/3j6PPH00UvKgz
         wMYBX4g9WDy0KOLDFffXftcKnBL71YTIahGTfnJR/IK5aPdn6UyGfgKD4qIVEJvom1Es
         BCAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jjYrKg8j3sQiN+ypq90e9ys0Tm0H/NuMTKkkBtMDp4Y=;
        b=CovNNfnir/onXGoKsY5GsaEqYsI6od5LY5I7ObwffBmlR7nWRCoMWKf2yHbRCTplV3
         7rYUu8V6F2V8RpmcjHqkKofKcZeCKUeMY1ozTWGjzsSHh0oDLYb7Jkhq/m4mrBMCgdUz
         WA1NW8AjsgSQbxQ6hIY0ME8RCc5Jldj0HbUxYUAWfm96rmPh3YrtQxU0dDryd0xeFsVJ
         PNQzVncwc5nkjTnYM2/jZBaZWTNE1kzPd+g+4KY5T071Aeb9RMPzoVZ83q1YPUHu1pSv
         2pZd9/Rz8AzuEXorB2Df5WclBOB1jq06dxzxqXKzjcH/i8L1hQHnjSSBpi60JUN3UtBO
         4ktQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1dW+ZsJr3lTCiwSPjNpZ/msBFqSRBZAZ1Th/vCGIpdCW5Gv+Rw
	INvJL6uaT9XGu6bZBARE9DI=
X-Google-Smtp-Source: ADFU+vu7p7JZm/XxhOL61CgU/1lqJzemrA9hImq1clsMpMVvP7Pe8deAGw0qWsm/EO/rW33JKlKkOQ==
X-Received: by 2002:a92:c510:: with SMTP id r16mr16246044ilg.119.1583780663843;
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cf0f:: with SMTP id c15ls705527ilo.2.gmail; Mon, 09 Mar
 2020 12:04:23 -0700 (PDT)
X-Received: by 2002:a05:6e02:1090:: with SMTP id r16mr8370464ilj.198.1583780663416;
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780663; cv=none;
        d=google.com; s=arc-20160816;
        b=qX2Y129Q3SoF97k6pLDiZHMFgYA8C75OJibLlwNu6dZTESULGumW5FwLCnZdT8FJ8T
         Dzj5v26A5jiRtzI/gQUWpWiCFVQVYdrjbsxoiUv190CIELHeRfCIlDOHeuVz7KNNCTXH
         Z4B3DSL4sX4MhLnI3sKHiZxQvPVhGM1OIliXkM6pmfNHG0Rpth8kP6uFzdtTUHA9ePSs
         q4Gd71QMrSgY+zCxPLSI2jjP1HIxwoGoTjsjDkNHbL/gSpzWD5/4W2uDV+SQgpzpsTRW
         /GNlNvMYmXIC/fPZnTn7nD+Z6shJc4sPg7mjEzYcsl/L8mwj90OoyGrJaKe/BwHc3hpQ
         SHQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=/JBlBDlNhm/3bdcy7skbA5gt15v/0mw3EeD3+WmPrOw=;
        b=AnRpHpEhlckGmrH9NghTx4VUHQOf8U1TXB5coJUhMrqDHFNHokTkD2AxYwlQijL75Y
         tSIG6E/QNcOed0vSByGeTQqZeWLRuOXf7v4+PCvMejQmB9H8R+lcTp2QgTwdSJAPJkrP
         6nYBsAj51hx7sEiYpMiTrZX/xPcRRC5JI+gDg0h9utuqz8HaMEAHRAGW5jFCVyz5WzN6
         oj1UN4R9uissZHqqs9C2Cp7F/l/IGdK5wH3Hw2om/6lCsnA24mywcODM7Oc3Gbqviye1
         wZsq93QbEw/AbEnjO9KvuUuaTBbxm13PTNNgs08eyuwteoTVTrh93hjp/k7EKheFZtSi
         PcNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="X9kQwSz/";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b16si603959ion.0.2020.03.09.12.04.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A631C2253D;
	Mon,  9 Mar 2020 19:04:22 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 03/32] kcsan: Rate-limit reporting per data races
Date: Mon,  9 Mar 2020 12:03:51 -0700
Message-Id: <20200309190420.6100-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="X9kQwSz/";       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

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
 kernel/kcsan/report.c | 110 +++++++++++++++++++++++++++++++++++++++++++++-----
 lib/Kconfig.kcsan     |  10 +++++
 2 files changed, 110 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 9f503ca..b5b4fee 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -1,5 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#include <linux/jiffies.h>
 #include <linux/kernel.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
@@ -32,12 +33,99 @@ static struct {
 } other_info = { .ptr = NULL };
 
 /*
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
+/*
  * This spinlock protects reporting and other_info, since other_info is usually
  * required when reporting.
  */
 static DEFINE_SPINLOCK(report_lock);
 
 /*
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
+/*
  * Special rules to skip reporting.
  */
 static bool
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
index 3f78b14..3552990 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-3-paulmck%40kernel.org.
