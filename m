Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGNE5SCAMGQEP7ETQXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BD0837B27C
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:10 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id i33-20020ab042240000b029020adb6e9ffcsf1165257uai.23
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775449; cv=pass;
        d=google.com; s=arc-20160816;
        b=PUEzt7diJezrrII8+4HQ4C/KXouvETaDUilc7r1Y47w+YiWMhfr0TMXRdx495SxxYC
         v+jH7PGaoFTVsznxBYqB0GtFXPSWlS5PiIYRHkjTMqU9PF5CLRkHWkgxe82l6vfzK4U4
         0Fhp44tq6gWlt9LyG/ZTa/qTvb1fsD6hB6lpU4J0NhINZPsYXRQ3QVhQrfuAe0j2LE7d
         d4wkg3M/9GeUDkeVy5syL5nQXZV8qmVF5M24C8DURXVDf9lQVUDO5ulJMi1FsaMYct7t
         PWKptSxya2pi+0le8Y5ErfbCKjIqgRdFob3MFl9XydMwrEXiPsUHUKdwWLCqCWzpmh8b
         2GEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Nhfs/jGr3IP3givpcQF/CTrdhtda9gpTe2GxEtpaaeA=;
        b=e8jZ95EJWFKYZU9stdnPpihtqqQGKyKdb+5W69CGxl5AYtN7hm9d3DIJd7gJZT5gkP
         ZBrLVMjb5SiUHlGb5NV2/X457d/oQA+xdkAzH+7rhQljsASgZ1fFMtLB6tu5Xl9MRaX/
         lOQZ5a10WS5Fmr1rEjzIqcuo+M4yjE+13wYeOvsBl/uIS2YCM6W1TV89Tz2VcU8zpBnN
         IoiILr2/dTjbtVEPUWfHLQQAgy0uV89PM11UNw7z0s0KJWiy8PcTAdg/QY1FoLPtFRyI
         BpzSMyRkM1vtIlUiUeHMhmI9ol6SsbGf5Eqqb3IYF08aCn2VwBKGJkYtiTgxPPbjNwof
         M7wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VMzGzw07;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nhfs/jGr3IP3givpcQF/CTrdhtda9gpTe2GxEtpaaeA=;
        b=XLPKr/y4dl+GANqbHcgoKyEOGtEZuh9c5qXaCbp6Ka98u8wtfj0IgaNZC4AtVq0pGj
         N+NS9ssPbRfI1U/gU1FfqFAsnCC2TPHcnBscV6hBvMQiO10AXUW7zldVlcbUmH/HcAIE
         un1gE/XDxMqNHB2FaoIUV3lUKuEC4S5L4tPYd1IRngqvjWTHKhY1thJoeGz6kV0aX0BP
         j9IlQ3ZoRcUybbla4x/Ge9+rZXIxXjwuqmOvXCfDC20DDpTBHsn7irqyLcFN5VFSEh2X
         gmtMAc2b7qF75QIa8o8Y9sFousHcDFP5vij0fvdz8TlQllajkJ8cJrqS5CVLtRTchdm5
         H8ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nhfs/jGr3IP3givpcQF/CTrdhtda9gpTe2GxEtpaaeA=;
        b=o6F2NNlKv3T3rttpde4DBb++wa/J9SjvfoIiFzTPEatn8pTnNdArgVvuYwgxc2+uoB
         P6vEKqm5jtrZTenqDP83GKMyS3BTaKONu6nqbRXmOuRw455yXx+nsAg+9wsv1XDR0S+m
         967rl1h7khKmcZ4txdr7+tRyn7Pg7SS+JGNJXJ52xRig5VCEs7nn4sM3xYVeMdAnoJ9X
         JRsrHkLoksBqWy9JPOfbm6JeRR9Ks9NP5Kabz2rRUBwhmwZi+Z/79LIf/CWe7iNnO/Oz
         zdZWWT8GPhCf9EJikVlHCi0zF60eG7xBcg16XrHj9UcG/7bJqi+QxcL0KqwqluJt4JFo
         +GjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318Y2W/bmA1PgLNBCmmYGq7Wv15AgK6vhR1wcNwArurbX2Rlmq4
	UOkJryG+Oy2ClXoMwz7pnx4=
X-Google-Smtp-Source: ABdhPJxG3ANl0p4gW7XrmV9/QCt917fAD2mCIlRXebRpVZpASXWjk11S/SCSDTqyzq22Sh/qfDWFOA==
X-Received: by 2002:a1f:ee0c:: with SMTP id m12mr25892164vkh.1.1620775449234;
        Tue, 11 May 2021 16:24:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c759:: with SMTP id b25ls44150vkn.7.gmail; Tue, 11 May
 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:a05:6122:1796:: with SMTP id o22mr18643384vkf.8.1620775448595;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=qupf4CLLihyGxMc+ZLcpP/Bmq4dIga5lY4wp1S6pGXl12X9iMq7nhW5tVTCTFWVNXH
         RJYKOH1enY6rHd+hhSd3NQPUKI6LbA98t19s27xMDEVlSufIaLB5KD3szmmAQebS9b9V
         D5ZUKDIXmHvT8tZLvVfZCTeV7OcRHVEfaL+rAo2Y8ARCn08MGk7kOxKLz6LCJnSjb60x
         x1ex1NpYgFuSG+gSuiegTa8brSkc1vnzkeWg637lD2Eh9nwQ9BVxSrq+HtSnAojJx9Ag
         xvRdKkB0rOwY3IYIy1mn2JpvT4BqfRnzWZkyKn96t3+Z184C0Ii0PergRfM8xbdRazJR
         a9ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C1lcb6/Cuy7KLSeS3s5faCFlbXiyzQ7URU2xgN1l2Yo=;
        b=zxulaSIZvwzlPp0bemgFo2dU6PhevNVq4ezktUZEqYhm2NNTjSWdH3uclTC61pRJGP
         foUIUiwuHPi6I+wPogBDCkGZFft0hfqtFdTZF6xBK8OZzN5OFgBsBX5K1esAPhOJEvJq
         h1UdOaQJ0hxLVM3BLw+r4qhukcLbi3dJ8NzbCvwq8Prie/wLLcMiSWz6GWUKGmqoYlpO
         JoLJ4KGi9fhEkqFzDB33ZEHyE8+lgu4CAjrnABRbQ9ne/EBMfgq240oun08Yu2++NdN1
         VfCls2KSJyEwsf191Hk17NMVvfmLji3qF4L8RGjdMT/LKzMvq7Ygcpm/+75ejiPKs8yW
         8Gtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VMzGzw07;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a1si1197748uaq.0.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4538C61935;
	Tue, 11 May 2021 23:24:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A61B35C0DD7; Tue, 11 May 2021 16:24:06 -0700 (PDT)
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
Subject: [PATCH tip/core/rcu 07/10] kcsan: Remove reporting indirection
Date: Tue, 11 May 2021 16:23:58 -0700
Message-Id: <20210511232401.2896217-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VMzGzw07;       spf=pass
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

Now that we have separate kcsan_report_*() functions, we can factor the
distinct logic for each of the report cases out of kcsan_report(). While
this means each case has to handle mutual exclusion independently, this
minimizes the conditionality of code and makes it easier to read, and
will permit passing distinct bits of information to print_report() in
future.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
[ elver@google.com: retain comment about lockdep_off() ]
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 115 ++++++++++++++++++------------------------
 1 file changed, 49 insertions(+), 66 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index d8441bed065c..ba924f110c95 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -434,13 +434,11 @@ static void print_report(enum kcsan_value_change value_change,
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
 {
-	if (other_info)
-		/*
-		 * Use size to denote valid/invalid, since KCSAN entirely
-		 * ignores 0-sized accesses.
-		 */
-		other_info->ai.size = 0;
-
+	/*
+	 * Use size to denote valid/invalid, since KCSAN entirely ignores
+	 * 0-sized accesses.
+	 */
+	other_info->ai.size = 0;
 	raw_spin_unlock_irqrestore(&report_lock, *flags);
 }
 
@@ -573,61 +571,6 @@ static bool prepare_report_consumer(unsigned long *flags,
 	return false;
 }
 
-/*
- * Depending on the report type either sets @other_info and returns false, or
- * awaits @other_info and returns true. If @other_info is not required for the
- * report type, simply acquires @report_lock and returns true.
- */
-static noinline bool prepare_report(unsigned long *flags,
-				    enum kcsan_report_type type,
-				    const struct access_info *ai,
-				    struct other_info *other_info)
-{
-	switch (type) {
-	case KCSAN_REPORT_CONSUMED_WATCHPOINT:
-		prepare_report_producer(flags, ai, other_info);
-		return false;
-	case KCSAN_REPORT_RACE_SIGNAL:
-		return prepare_report_consumer(flags, ai, other_info);
-	default:
-		/* @other_info not required; just acquire @report_lock. */
-		raw_spin_lock_irqsave(&report_lock, *flags);
-		return true;
-	}
-}
-
-static void kcsan_report(const struct access_info *ai, enum kcsan_value_change value_change,
-			 enum kcsan_report_type type, struct other_info *other_info)
-{
-	unsigned long flags = 0;
-
-	kcsan_disable_current();
-
-	/*
-	 * Because we may generate reports when we're in scheduler code, the use
-	 * of printk() could deadlock. Until such time that all printing code
-	 * called in print_report() is scheduler-safe, accept the risk, and just
-	 * get our message out. As such, also disable lockdep to hide the
-	 * warning, and avoid disabling lockdep for the rest of the kernel.
-	 */
-	lockdep_off();
-
-	if (prepare_report(&flags, type, ai, other_info)) {
-		/*
-		 * Never report if value_change is FALSE, only if we it is
-		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
-		 * be done once we know the full stack trace in print_report().
-		 */
-		if (value_change != KCSAN_VALUE_CHANGE_FALSE)
-			print_report(value_change, type, ai, other_info);
-
-		release_report(&flags, other_info);
-	}
-
-	lockdep_on();
-	kcsan_enable_current();
-}
-
 static struct access_info prepare_access_info(const volatile void *ptr, size_t size,
 					      int access_type)
 {
@@ -644,22 +587,62 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
 			   int watchpoint_idx)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+	unsigned long flags;
+
+	kcsan_disable_current();
+	lockdep_off(); /* See kcsan_report_known_origin(). */
 
-	kcsan_report(&ai, KCSAN_VALUE_CHANGE_MAYBE, KCSAN_REPORT_CONSUMED_WATCHPOINT,
-		     &other_infos[watchpoint_idx]);
+	prepare_report_producer(&flags, &ai, &other_infos[watchpoint_idx]);
+
+	lockdep_on();
+	kcsan_enable_current();
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
 			       enum kcsan_value_change value_change, int watchpoint_idx)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+	struct other_info *other_info = &other_infos[watchpoint_idx];
+	unsigned long flags = 0;
 
-	kcsan_report(&ai, value_change, KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
+	kcsan_disable_current();
+	/*
+	 * Because we may generate reports when we're in scheduler code, the use
+	 * of printk() could deadlock. Until such time that all printing code
+	 * called in print_report() is scheduler-safe, accept the risk, and just
+	 * get our message out. As such, also disable lockdep to hide the
+	 * warning, and avoid disabling lockdep for the rest of the kernel.
+	 */
+	lockdep_off();
+
+	if (!prepare_report_consumer(&flags, &ai, other_info))
+		goto out;
+	/*
+	 * Never report if value_change is FALSE, only when it is
+	 * either TRUE or MAYBE. In case of MAYBE, further filtering may
+	 * be done once we know the full stack trace in print_report().
+	 */
+	if (value_change != KCSAN_VALUE_CHANGE_FALSE)
+		print_report(value_change, KCSAN_REPORT_RACE_SIGNAL, &ai, other_info);
+
+	release_report(&flags, other_info);
+out:
+	lockdep_on();
+	kcsan_enable_current();
 }
 
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+	unsigned long flags;
+
+	kcsan_disable_current();
+	lockdep_off(); /* See kcsan_report_known_origin(). */
+
+	raw_spin_lock_irqsave(&report_lock, flags);
+	print_report(KCSAN_VALUE_CHANGE_TRUE, KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, &ai, NULL);
+	raw_spin_unlock_irqrestore(&report_lock, flags);
 
-	kcsan_report(&ai, KCSAN_VALUE_CHANGE_TRUE, KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
+	lockdep_on();
+	kcsan_enable_current();
 }
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-7-paulmck%40kernel.org.
