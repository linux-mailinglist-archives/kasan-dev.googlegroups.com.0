Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7FD3OBQMGQERKC64CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CF8E35F26F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:29:01 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id o17-20020ac869910000b02901a7c59f1c14sf1666737qtq.13
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:29:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399740; cv=pass;
        d=google.com; s=arc-20160816;
        b=qe6sGbZoCX27ErMjcl1Nf7VPUpd31Vd8GMXzVLHYq81PfVp22/SHPX5dKhMrbQLzg5
         pmuUFbYGTJolC2G0Y6rTi/2V9MJJEOPHlQgnGe2+tzkEO3Wta63uw0it2DqyJRTD1ANY
         b4Ou/XF3l6amt/TBs/64hEd21BeOeF/NuzzvZtHB9mIVw23HKeF+SoZ9gVoU+q0LBWDs
         4fbGQxVnrcJAYCR0Ek4d43fdVkOFn0Dkjml5nX+49IsH414JcedyCI97kxGx8OvcKUA6
         UUoIjgeLV2jvF3qcsoU2h50l+ikFMEVaBIyDqM4mKz352EH4S7F+JufaG6JZ7TYfZ9G+
         UuHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=IqqN9EqYypSsMfBH3B85KevHc0GAzoADmiC+96Cc1j4=;
        b=P82xBxtQM/B1QTJv9fCDZWT2SIlM/W9MiRDpGZmhotHa6P9qWagj3zuqb1VUVDBN7v
         /vkvHdPC6c1uEjWszelgBD1jbpEpwI3GuzBqQEfTzIfsG4AiD06bXl9ySzQzli2XAUmG
         oavgCUZu6D7FuMffbKKXtNQQaZvLQYn73cIE5Ao4kNGPCjCmqtFOzJFjryIpGdrPOMRS
         Ram6+vH3ukVTD3h9uf9naW048dwu4eIZIOesWkFX5WxgUyUm1Uq52c2dc40GnH3GDWS+
         9DOxJIlc4JiXpr7tilooGg7P0boPqR0a2OgaLzKAgmmKGlcygyHVvJTvI5VgHtmYIAhQ
         PCVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ui+ywIIo;
       spf=pass (google.com: domain of 3-9f2yaukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3-9F2YAUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IqqN9EqYypSsMfBH3B85KevHc0GAzoADmiC+96Cc1j4=;
        b=EY9BnpgMEjtwcmS911wtGc2y6i2o6L/YfMPwHgNjohgodWVTAdj8htxkjYCzHS6dIR
         OrZ9aD5vmMF2Hyoa8kzTmpl+mIlGEQAdxTzmrIRLIm/ancfzCJNRmuOSIBYwaDsPIgci
         wA0OhboBTl2L2Xo0DhGlFdZ9nkcEo6+q7BBhjlx4KWSu3MUqEL5uYI8/lYrbeIDceVLm
         ZKEhAPR5GkWkRjg3+aF6Z05uXlD7jMS+yG8bwhZ+rKn07ePyUiKQa1AVDhNp33AmiVQK
         P4Y7Vq6vJupT+uI3MnEm/UqE8taRB0WxJIurq02Ayf9i7ipk7s7EwF+XM0YCS3HoJRhg
         4S6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IqqN9EqYypSsMfBH3B85KevHc0GAzoADmiC+96Cc1j4=;
        b=mPAtDA6dNM0i6fyndupy7cNcJ4vHytoSG3PBMecM9FXWuHLP2lrz+0UJovznHTM0ZP
         6wgtxvUOHGA6vYjqNaE+84sRELVrJPGz+amiGoDDjVYMhn1zwlHO1tM8EFPoAt3cFivp
         RWuxBgLOiYPNvO0ToB8VwC3NveA142VHXVpGqhbr755poXYHuSvD/nqq3nkZ+8YYdHs9
         tkklgtzUD0luKPxPaJ6FE8pfK3IGH+3G2AU/gxF+rKDcunRFfTmzcAEN+jJp+Mb3FC/G
         /hGHc68YnzRerhVKT+OzhC6lcYoruKGosEQh0O1a6rT3psHL95XwLsklKfk30Dh6PEXO
         RMZw==
X-Gm-Message-State: AOAM533a/sx8ZdTCa0fvyFJG6chL7HqYz/G1gKf/+Lb9ZVp618sNA9rm
	RCpIjBt9ztBHtxO5kEwofM4=
X-Google-Smtp-Source: ABdhPJwxmJrJaDYP1DunZ0z1HUkiICGgrfWu1syhrjOIpB8AO4EShHOWAe8w80yXV9TzDXdRr/U+yg==
X-Received: by 2002:a37:9fd0:: with SMTP id i199mr18865583qke.264.1618399740423;
        Wed, 14 Apr 2021 04:29:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1046:: with SMTP id l6ls501944qvr.3.gmail; Wed, 14
 Apr 2021 04:29:00 -0700 (PDT)
X-Received: by 2002:a05:6214:2628:: with SMTP id gv8mr37869561qvb.19.1618399739959;
        Wed, 14 Apr 2021 04:28:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399739; cv=none;
        d=google.com; s=arc-20160816;
        b=h+blDYss0D+BlnHflCYRoCXX96UawhPYSCWwKYwvg6tIHDjjCpybIJaAO2xbYHI/Du
         zlTYjpWlBcI352uKV4dEcM+ixaw7t81sFS9ECTnZj1++qWQkUgEg2iwewes3qtQ8/pze
         6v1UjunhW/C9BdZMuQ7BXu3nqutfjiPStoWD6RJXCib0xhZ1+PirslqMYEC7uohh0x7b
         VF33YYxVQE9xl3iiqp62Fv9ZC6wViGxRSyDAcMO+Za0doy1Cm/CNS8nUDEuXBNY6eGPA
         jBD38b0oBzx01eqdOcR2pwK1J8ZJlUvaEcxF8qL5rCJAjFmR0kcYzI20V1x56oB1F9+z
         FKuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=2hPM+SGX2bso2P06MksOdn7k4SylcbKetGkN5XP9cNQ=;
        b=VNcdVOnPAxn7+2Lpgem5AlAaMPLyWxc5HNyXX5BpQsP3HFSeoV8FFxjbyWg24CcNZw
         z3vZoiIvtI5a9HIHTzQg60cR+gxREcjBEsBvU7oBr4qHplZ/kI2MRxeS9NJsAQVWpwNz
         O6oKWRYRssu9e70zN0UhlFDJJSCs9KgQSXDrdCEir3SYzz+8+F3l15OQyafkZRXVmml/
         w9I6f0SaEXn9gAc/uJnzVjORZmtnBrMN4R09M8/yzjRGr7H0Qw2vXo9n2ucYqfJPBSxT
         1krtuB+CmAIG6NIjACZfh4MoU1+thf0b+JnmDVHz1ECCGpX8cPRfH7gGF3/drl05oZeL
         wkgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ui+ywIIo;
       spf=pass (google.com: domain of 3-9f2yaukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3-9F2YAUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id z143si475382qkb.6.2021.04.14.04.28.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-9f2yaukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id s20-20020ac85cd40000b029019d65c35b39so1664469qta.19
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:59 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a05:6214:223:: with SMTP id
 j3mr37761745qvt.9.1618399739655; Wed, 14 Apr 2021 04:28:59 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:23 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-8-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 7/9] kcsan: Remove kcsan_report_type
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ui+ywIIo;       spf=pass
 (google.com: domain of 3-9f2yaukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3-9F2YAUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

Now that the reporting code has been refactored, it's clear by
construction that print_report() can only be passed
KCSAN_REPORT_RACE_SIGNAL or KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, and these
can also be distinguished by the presence of `other_info`.

Let's simplify things and remove the report type enum, and instead let's
check `other_info` to distinguish these cases. This allows us to remove
code for cases which are impossible and generally makes the code simpler.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
[ elver@google.com: add updated comments to kcsan_report_*() functions ]
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan.h  | 33 +++++++++++++--------------------
 kernel/kcsan/report.c | 29 +++++++----------------------
 2 files changed, 20 insertions(+), 42 deletions(-)

diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 2ee43fd5d6a4..572f119a19eb 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -116,32 +116,25 @@ enum kcsan_value_change {
 	KCSAN_VALUE_CHANGE_TRUE,
 };
 
-enum kcsan_report_type {
-	/*
-	 * The thread that set up the watchpoint and briefly stalled was
-	 * signalled that another thread triggered the watchpoint.
-	 */
-	KCSAN_REPORT_RACE_SIGNAL,
-
-	/*
-	 * A thread found and consumed a matching watchpoint.
-	 */
-	KCSAN_REPORT_CONSUMED_WATCHPOINT,
-
-	/*
-	 * No other thread was observed to race with the access, but the data
-	 * value before and after the stall differs.
-	 */
-	KCSAN_REPORT_RACE_UNKNOWN_ORIGIN,
-};
-
 /*
- * Notify the report code that a race occurred.
+ * The calling thread hit and consumed a watchpoint: set the access information
+ * to be consumed by the reporting thread. No report is printed yet.
  */
 void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
 			   int watchpoint_idx);
+
+/*
+ * The calling thread observed that the watchpoint it set up was hit and
+ * consumed: print the full report based on information set by the racing
+ * thread.
+ */
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
 			       enum kcsan_value_change value_change, int watchpoint_idx);
+
+/*
+ * No other thread was observed to race with the access, but the data value
+ * before and after the stall differs. Reports a race of "unknown origin".
+ */
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index ba924f110c95..50cee2357885 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -326,7 +326,6 @@ static void print_verbose_info(struct task_struct *task)
 }
 
 static void print_report(enum kcsan_value_change value_change,
-			 enum kcsan_report_type type,
 			 const struct access_info *ai,
 			 const struct other_info *other_info)
 {
@@ -343,7 +342,7 @@ static void print_report(enum kcsan_value_change value_change,
 	if (skip_report(KCSAN_VALUE_CHANGE_TRUE, stack_entries[skipnr]))
 		return;
 
-	if (type == KCSAN_REPORT_RACE_SIGNAL) {
+	if (other_info) {
 		other_skipnr = get_stack_skipnr(other_info->stack_entries,
 						other_info->num_stack_entries);
 		other_frame = other_info->stack_entries[other_skipnr];
@@ -358,8 +357,7 @@ static void print_report(enum kcsan_value_change value_change,
 
 	/* Print report header. */
 	pr_err("==================================================================\n");
-	switch (type) {
-	case KCSAN_REPORT_RACE_SIGNAL: {
+	if (other_info) {
 		int cmp;
 
 		/*
@@ -371,22 +369,15 @@ static void print_report(enum kcsan_value_change value_change,
 		       get_bug_type(ai->access_type | other_info->ai.access_type),
 		       (void *)(cmp < 0 ? other_frame : this_frame),
 		       (void *)(cmp < 0 ? this_frame : other_frame));
-	} break;
-
-	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
+	} else {
 		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(ai->access_type),
 		       (void *)this_frame);
-		break;
-
-	default:
-		BUG();
 	}
 
 	pr_err("\n");
 
 	/* Print information about the racing accesses. */
-	switch (type) {
-	case KCSAN_REPORT_RACE_SIGNAL:
+	if (other_info) {
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
 		       get_access_type(other_info->ai.access_type), other_info->ai.ptr,
 		       other_info->ai.size, get_thread_desc(other_info->ai.task_pid),
@@ -404,16 +395,10 @@ static void print_report(enum kcsan_value_change value_change,
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
 		       get_access_type(ai->access_type), ai->ptr, ai->size,
 		       get_thread_desc(ai->task_pid), ai->cpu_id);
-		break;
-
-	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
+	} else {
 		pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
 		       get_access_type(ai->access_type), ai->ptr, ai->size,
 		       get_thread_desc(ai->task_pid), ai->cpu_id);
-		break;
-
-	default:
-		BUG();
 	}
 	/* Print stack trace of this thread. */
 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
@@ -623,7 +608,7 @@ void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access
 	 * be done once we know the full stack trace in print_report().
 	 */
 	if (value_change != KCSAN_VALUE_CHANGE_FALSE)
-		print_report(value_change, KCSAN_REPORT_RACE_SIGNAL, &ai, other_info);
+		print_report(value_change, &ai, other_info);
 
 	release_report(&flags, other_info);
 out:
@@ -640,7 +625,7 @@ void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int acce
 	lockdep_off(); /* See kcsan_report_known_origin(). */
 
 	raw_spin_lock_irqsave(&report_lock, flags);
-	print_report(KCSAN_VALUE_CHANGE_TRUE, KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, &ai, NULL);
+	print_report(KCSAN_VALUE_CHANGE_TRUE, &ai, NULL);
 	raw_spin_unlock_irqrestore(&report_lock, flags);
 
 	lockdep_on();
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-8-elver%40google.com.
