Return-Path: <kasan-dev+bncBCJZRXGY5YJBBF5E5SCAMGQELBLZWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9037A37B276
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id lc4-20020a17090b1584b029015c16096342sf2444136pjb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=vptP7a1qpJ4fMHA+5DfLhUr4cVvEoTPnpI37wn2+UqwHV8giWk/9ag0rON5qVykI6R
         dqCrfyqtE9cmGhFkDcW85UKtRmCSfzYezM8DroNMGAwkkHyTagjxFWRhq/rmfnmHznFH
         z/OUQaUSp0+xDYwXx0QI4XK7xp7rbX7mADzg2IKTq+FvCMBV/OTAV8A1d3SLu3G/vjNf
         ea6ZmWKnw4fKIKEGe267z5fIzjXVRjRwa6kAXUY/MMrEgYF0kp25NUtmB62Scb+Y5hZl
         Zd1wTj2ZVgHGpDEm0QNdZiaq59ntcyWgvHVnGqG/KOOkrYX63jRfTkoTciNuP8V6+O3/
         xYHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jfB+d3naZgSo+mtMVxF3IwSWT4wKpdFeVlG/mye9dVw=;
        b=hIPPm1E+5K9JJurno8o4vY5tkHKYPILfclLXIkrqI+6vOP2pdU/PiVScT6bvf/qEEm
         pZhRZPIi1k0Ll1bILZS+I5ZPzCACKJzUkNl43Kn0oaLutPPUuE0UuNRMagkdpZ3kHnxN
         TPVHD8Q3H11YN8PPs83PjSA3dkPM8fIewKJyVi0l7kISLIUr3nxcblM54wBlRYSHP7SY
         /Awk97QlZfNPA+KlA6COIlqPCcR2xsqgQv53IfP5xMITmWiKL3uGlzOT2t2FQ0kNgGxQ
         FH2WmgeFPkZ8s1uCSLsMYBEtigPilhFEbUbQP4KIq6on4s4yaSj2KpZARylxqlvo8i5b
         RRQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qUoX/e6w";
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jfB+d3naZgSo+mtMVxF3IwSWT4wKpdFeVlG/mye9dVw=;
        b=aZHy0lAvdgKcvFTaq/AhqHa2u3Y4y7v/Gn2D54pcMKThltxwlZF/X+FyG2Q0pznvXs
         zP4SdeoDZtpfI4fNlhRIVHJ14F6c7EWNzNTrZSamTJoDu86iOfvoyohHdJc8QOf7RYZo
         1vTr9JfWLD/0YLOfrKvQacSpBRHhL+G6sOB+CYnGbn2AsM5P+Jm0lVr5ClA+ze4xRUXT
         +s6Fs/JXrzKsvsCs1cV7/5uBxY97Lc1o1c9S4dy50+rwmejMudl+gZfK15cQ4L8XdW/z
         bJSxSj39IgcgbUGThpXSDskCnNxxDJldIcN23RYS8t5j3lH4Jd7UM9zvuyhExd6RGh01
         obVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jfB+d3naZgSo+mtMVxF3IwSWT4wKpdFeVlG/mye9dVw=;
        b=gcBgyr41JGLO7ovoVTVfhTXKyyS6lI7YYrZGSlF034xFzJAs0WKL8XraIob81Wpg9z
         deduDsAE27UKfAxji96Xt1tov3Te6CiD2J3bPd4ECeA7FAesc4/kZ67iDWK/qChQ08Gf
         8Yf/jFJz9GShwlbIdODzzM2yDdt/WdqEYJRdmbvIC4uc2PLY2IUboVJ4sDSGU4bWVZrC
         mUVWg3A2GuMWoUHRULR1gGZxiltGnd5p8eylH3iz8gU6zi07/8Uo6kSxbYSWJQtm+2BI
         nN3HDG1Vf3HnzRD16aPnjci1cgJgXH2ba6t/fMA7VI6ahHGJvhE+ySBCUJZnbg6RIyUV
         Qqjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xMUfTXkfZ9hm1gIYTcFSWkm1Y6+q5hSY7zOv6qo3HE+ogtMyM
	8g6zsdkjT65zsoidmYuG7oc=
X-Google-Smtp-Source: ABdhPJzC2Van2mulbSqmzS9XbwI58iRQRuLy6I39ybgQhYpAuHiQUr1hFfcbkG/9Yf/s/MH++NVc8Q==
X-Received: by 2002:a63:4c66:: with SMTP id m38mr33174157pgl.157.1620775448056;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:d5c:: with SMTP id n28ls194468pfv.1.gmail; Tue, 11
 May 2021 16:24:07 -0700 (PDT)
X-Received: by 2002:a63:b206:: with SMTP id x6mr20368306pge.341.1620775447442;
        Tue, 11 May 2021 16:24:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775447; cv=none;
        d=google.com; s=arc-20160816;
        b=wzOpdwU5VEi4F4P6MXJYw4StLDRRBdRoexPYbQV0304L2k1RAm90AU00VeG7pxe4qk
         H9Uk69RNRDjueKmJvVja4Qiy3kZS4U5r0hNhg/XTnIR51uE/IOBpDywScqeyBO95WFHV
         Ajrzj+kU8pUFvGyR4ihm/Yj7G3At9vKercT5sstvbQBVWwefX0zTJgME2BjX9N0Gvhgo
         8jK/TMXLcLLBLZOuJS4cizCcAfYYr86BazovDYVAitlaVj7f18qIiRwb9ilUBtNHzYdb
         HboyYJ4H/CA9qSMNBrSjXxBI7GUMD4906L/I41oe4zLxK8oW49hTqwzns1ih32GXfWV/
         oltg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XK8cCd4gQMylWcpd7YNYN2py2vfb2e1JwLKfgXGeRXM=;
        b=bfFUK9y5yN7iTXxl+G/dUZhQ8I1L1q146kGCv684QnHd/QHlIyFKkE++UXJFomox24
         B+gV1jjcxJnBa7HYohkKYWITz6tDxU/d73dTLF6h28NW4ixeuKt2BwTrsTHIddmx1nC4
         SZxpKe4YhY5XbgZ8x3QFsYWgXHz330IQCXafpiBO76IFLnJO2S3F58rSg0gzc0FTGHhw
         tDP3+jn160NwXVh/2Ci0+q8KoJhGUBOeYIcdVYXab+Sj/gRgQakMpSEs3OB0uhjhVOXr
         hCXvIATd5sF6dsVD8QJejdMx0ZDKizX41BnJ6uBys862ylkYDkPH91cOzVVqkfNTUg5U
         xpqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qUoX/e6w";
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p8si1524504pls.1.2021.05.11.16.24.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id ECAFB6162B;
	Tue, 11 May 2021 23:24:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A20C75C0D4A; Tue, 11 May 2021 16:24:06 -0700 (PDT)
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
Subject: [PATCH tip/core/rcu 05/10] kcsan: Fold panic() call into print_report()
Date: Tue, 11 May 2021 16:23:56 -0700
Message-Id: <20210511232401.2896217-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="qUoX/e6w";       spf=pass
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

So that we can add more callers of print_report(), lets fold the panic()
call into print_report() so the caller doesn't have to handle this
explicitly.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 21 ++++++++-------------
 1 file changed, 8 insertions(+), 13 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 88225f6d471e..8bfa970965a1 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -325,10 +325,7 @@ static void print_verbose_info(struct task_struct *task)
 	print_irqtrace_events(task);
 }
 
-/*
- * Returns true if a report was generated, false otherwise.
- */
-static bool print_report(enum kcsan_value_change value_change,
+static void print_report(enum kcsan_value_change value_change,
 			 enum kcsan_report_type type,
 			 const struct access_info *ai,
 			 const struct other_info *other_info)
@@ -344,7 +341,7 @@ static bool print_report(enum kcsan_value_change value_change,
 	 * Must check report filter rules before starting to print.
 	 */
 	if (skip_report(KCSAN_VALUE_CHANGE_TRUE, stack_entries[skipnr]))
-		return false;
+		return;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
 		other_skipnr = get_stack_skipnr(other_info->stack_entries,
@@ -353,11 +350,11 @@ static bool print_report(enum kcsan_value_change value_change,
 
 		/* @value_change is only known for the other thread */
 		if (skip_report(value_change, other_frame))
-			return false;
+			return;
 	}
 
 	if (rate_limit_report(this_frame, other_frame))
-		return false;
+		return;
 
 	/* Print report header. */
 	pr_err("==================================================================\n");
@@ -431,7 +428,8 @@ static bool print_report(enum kcsan_value_change value_change,
 	dump_stack_print_info(KERN_DEFAULT);
 	pr_err("==================================================================\n");
 
-	return true;
+	if (panic_on_warn)
+		panic("panic_on_warn set ...\n");
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
@@ -628,11 +626,8 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
 		 * be done once we know the full stack trace in print_report().
 		 */
-		bool reported = value_change != KCSAN_VALUE_CHANGE_FALSE &&
-				print_report(value_change, type, &ai, other_info);
-
-		if (reported && panic_on_warn)
-			panic("panic_on_warn set ...\n");
+		if (value_change != KCSAN_VALUE_CHANGE_FALSE)
+			print_report(value_change, type, &ai, other_info);
 
 		release_report(&flags, other_info);
 	}
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-5-paulmck%40kernel.org.
