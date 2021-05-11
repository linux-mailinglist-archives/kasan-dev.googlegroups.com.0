Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2689B37B27B
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:10 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id g26-20020a63565a0000b0290209e5bf0fd4sf13180242pgm.11
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=y5VLTKJwAbzT3IqThkZ3ShGGcwjZFmuhwNMwRY/fxBDCq889WhoPyXOKnRzzxOSxAo
         rzh2M+6EAbBBHeSzhdkGgP0Wg0ZGjYHpnUFZNakRsoLWEllxoFcVHXITIj2d4ymVVQo4
         TWQlonLIjyNh0cBE+b0smVTEHsrAVGWRejFuCHBJUk+Gt8ojiff1F7beNGOuYqqQ/Wit
         3c/jIUNlnY/rO7xD7pQl43TE9FKC5ToRLE3Ano+t8Iu5uScYteoHAT+PS3byNVyEXTnr
         MqOB2m1aARlG/mWc2167A+UX5o33sU0La0TaGytYpULw45gByum5G/uG6zhu+mBUSrh6
         TX0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uYayf2D4bVunYci3KcToZcGi26NrORjWU3fEtbG8b6A=;
        b=K0+Ss59uLli6nuXlS2+EayGU/5moZ865+5vfy4XdNx95WITLIWqmIoVkuUDy4ZQHD/
         MxAQjJROo+hSXFRBLE6l/Dr47GbtghtviF4xilDpR5TwTpSfUK1yqcdUhI/ljU1J8N2b
         sxHt733J+Yg9DwoqKIMhMBRXpmlM3EkKQ/kRCIAP8RKErEVO0ocg136E9H5Qmyaq55WY
         pZLfKLs89bn6aYy/fhR0QPrwcIwVKX+zs+Ut8CtHPib4lkettISfZc2KHJCnwgdy3bD4
         wIS2Nlgkk6n5umYSirOdUJWeVBgK7b+uYXLy0jt1rCXtz5K0NBuW8Jgd0p/AqKOfBepP
         3mPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oGmhu7ae;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uYayf2D4bVunYci3KcToZcGi26NrORjWU3fEtbG8b6A=;
        b=h9etj/ay9oYWTJzxg2+gxqW0/xYsruk/Y1KNvqAQI5yaE7OMRiNS71nwlDQWsNC6jO
         rupmEQi689VRzMDEmYmokK+FXcPpclAmaISljrvYHtd0i3jfcUDSIKICW/4Fc1AJhk0K
         NYDvwyB9E0RYc9dyQPtz3TpYzGlWMgbk5KDwf1gTp7hX4QoNujBY9NBkoJL844fyk/Bn
         9rhuugA5QBin5LmLdmc94kLlGVJylKJZfMw6D4OKOLICsAOb6LNyVv33cL91Vp9yN4vt
         GFFs7cKY3roca3/US18O2ZM0Tt0Aw68D0CbPs8b6hZlUNsZvlGIEig0tCZHnSR0HGNP0
         sEPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uYayf2D4bVunYci3KcToZcGi26NrORjWU3fEtbG8b6A=;
        b=OTqjGg/Km3hQriU9DQN58LvXD2nX566U+N7uG83ylkvXdeaf6a/rYc/TfZ9VmrzfvJ
         p8Ee9jFexvzGSc5JHvWbkRBe4c4PAqfx9dKRmWvkvk7Aie3YRwl4UculURKb3/Cciedq
         IHEFkRLgwbObujKHmWb7KSapufS8uAPeRHvfAE4zLxjPlmcLWB9UdQ0xs1q+BmaoPIPW
         tPH/ZKNty7cHxl7Q1/dONh+zBZrGzRfGW8WDbRECm9d8AV1BBd+8r/eSkWsPn9cm+ub5
         xgCRUKHSJpdtgXKQT76kGyBswpOSv1upGrQqkVNE+Hq92RF01N8tLhnmgRN5S924+YMp
         JG8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EOCBGD0aABnmFNse4r44cdKY4hQsE58U5TE5zd4gI5ag6JK/7
	M8Mx2HickDKIw249PUHBCck=
X-Google-Smtp-Source: ABdhPJzlQZomzfEd1u7YCh7b292+grR5a3BwFyZewsB06A3PrK0u20HXfEZOG3fdUEkfc22b+aMfsg==
X-Received: by 2002:a05:6a00:7c9:b029:28e:9a2a:8da3 with SMTP id n9-20020a056a0007c9b029028e9a2a8da3mr32672123pfu.60.1620775448719;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:860c:: with SMTP id f12ls190251plo.5.gmail; Tue, 11
 May 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:a17:90b:1647:: with SMTP id il7mr7581872pjb.165.1620775448078;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=hXRRpgijjAlHtpR+CqnFWujRV7aFcqw0Nk17OX2YWc4o2pu4mjCSNmma4jSqPqiLS7
         WZ+fPxy1zzBX0eRKQXivcFh6ULmjib1quMypqw6upL6gH5e21yDawV7qXRknjfttxrUm
         ooO33TxYFj+QUf8zOSWNIV4uhhdf2FsKsYyrLw6UM9oRYhOTVir+bK+eEqFrHv6p76cY
         uj2gAO6uygL2KlG8ePLBPGdVwwQT+25gq8BfMSdpZDy8dHm976yGznQbzGb1WKkZXG4D
         uP6SsKgZcKY2lwdgpwXQ45l65EhtZnS70G44VjTilVLhDEMnjzx56Hq3i/mQksuS38EO
         gwFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BhbQw6RByK4ziQfE+ZgXGbkX8nOFj7rQ2RkZgPWOHc8=;
        b=MPR9Cvp1EhkFl75gGFgZvSH5ePKhaQQ+XcbIPQcqeloUeK2HGHA7jLbRiop5T5DN9S
         3XCnHK4NRWA1Zec4Ch1eKp9Gzso86iuxgH03ITiu1KS8jMpBVlf+guW9j/Mmsr3OAfio
         4nHsV1RPmc7khCm0ipsVpM4FInROTUwnocRO8n3qSuZ96FNLPNzUJxMdE7haCLZ0t0nE
         /PjMnL57bBtajbbaMTqHCzIgJAg3hezja9AUs4DslhzuOOfl+x+Eo5/Dqwt6p/sxzx4N
         q3s5iI3NrGc6J7WqKBrtCoqpfqEY1htqqOCb26qKgdiPuRa2S4fh7DnW2Lwne547nqVh
         1LjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oGmhu7ae;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j184si1636873pfb.1.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4F7A261936;
	Tue, 11 May 2021 23:24:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A80EC5C0DE5; Tue, 11 May 2021 16:24:06 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 08/10] kcsan: Remove kcsan_report_type
Date: Tue, 11 May 2021 16:23:59 -0700
Message-Id: <20210511232401.2896217-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oGmhu7ae;       spf=pass
 (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-8-paulmck%40kernel.org.
