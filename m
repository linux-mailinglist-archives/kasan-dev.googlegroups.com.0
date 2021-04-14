Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6VD3OBQMGQEGNQ47OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E149535F26E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:58 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id b5-20020a0565120b85b02901abb91c36ddsf738016lfv.5
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399738; cv=pass;
        d=google.com; s=arc-20160816;
        b=MQxz4aNjGSBAr1HXsm6Z6GCg6n8fwbaEFxjWyxUPtGdsrbXSRcR9PZ7B5dOCYpNTMY
         1z5S3s5di05+4Lukqx0UvDgYzf4CMAw9UYwP6D16DDaEnmsGn/R6Xl54OUON/KqDda20
         bLFnnvJv9h+sxSCoSHznYng8Z0TysLqLWKbKN+MRGFW4k2EyP6kmAaoUkl1zDAgDCqmn
         mvKC4YKGh5Auwxhd/V75XVcj/aPJak2cWAW2IGuBe052RswqSNmYDB2DBBXnPJ1pok5P
         VSPP0ioJEZwocdks5z4pU3Q4fC70Go+mRZYoHyWub6vE3LIHFuUkFSwIz6XczZ57/vrw
         wsiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=G5JWecKQfFm8qkWk8BApiWF51qrMnr/sSeXV1byhBvI=;
        b=Svs4YdL0ctfREbtYxHxzK/ySxn4yQVmJ4nnfSbxw9qCKLfsJApYS01WcyvOfIy+FoJ
         H2Lfjont0XNtHOhKjgDWfNI8xa8bxDAihYV4LQ9AFKQZO4gOVaxW/kdcfcuqhlRO2C8h
         uVshh5eKk4wt/KFh6+c1KuAHHlh/sYbM92kMfzg1bLiuCqJRJT9eg8OO3jhuHfT4/CS1
         K3d0fZugcPEpxqFVvqjWxUHFV1tg6wig+fqx+zgd2EpkvMnIlwfsNO+RNvF7Oenw7VrD
         QbQaxWgISzCbCZlTcMeS14ttEPREsa25VZd/M9rgWZf30aXnPOrsQN1AA8MmA0uNHkEM
         Om5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aY8yONrX;
       spf=pass (google.com: domain of 3-nf2yaukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3-NF2YAUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G5JWecKQfFm8qkWk8BApiWF51qrMnr/sSeXV1byhBvI=;
        b=UodxQRMFNaDOv81SK/dx6CXvUnPxTP7euY33iIOW9muYjOfAuIZty065wPUn8PN2iu
         GPZ+Hb5sBpsTAw6IefZIfCPhnLuxec5jqT2fw2ifzzkWGMcXZRAqCdhr1gexIcHvIh0r
         3q0F6fjCCAW/R3JYqndti22BonFfVKStGLLRSISSdWm5qtGic4APiYxZCxphhZ05WnzC
         kVSz8COeVeU+wqPuy4GMLIFSMhzxZ4fG3DG/CCXjr6mneVpslWcSMEbUlbuRfipjmsZH
         OH5R0VgMZ3yBwcBCQDYf0DcrVzfQFc6mvz1+OXfC2S51vXKsPrPHv8b8hB4M0MkEYV4j
         2QZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G5JWecKQfFm8qkWk8BApiWF51qrMnr/sSeXV1byhBvI=;
        b=MAhhKlUWNXzn+P+whNV4QyV9+JF36A0ORsxFdbTo7amf6mXcocZr8FJNWRFBY879yw
         neXhly9WMUNYDcaIVzs0Ox0bKJGpBXuaGm5/k+/8WVZmlPx3h+Ev9aQH9wpS7jXCxOgB
         7JgmPXyGaalmHKQtc7CmjifgC0gP2NxuiD2lospIoQ8mQVyRROMbz1OSGFTv7YPX6KJv
         RocjQc9DtvSb9iYKkJewZUzqi60c/1TGyPLXCyCG4/Zndz0LM/HwQ697DZMaZ2bwNKJB
         +QADfQjTPAJiSd/5SgpwehM1vmnDqmoJeBhFTXDsHpOWQJjhe71sPKe6eIrJNBGS3VPQ
         bhJQ==
X-Gm-Message-State: AOAM530ZSciNQQYcGmtzxn0iNsFZ8atNr8QgmsodeTOdk5haJCNv7FfG
	FEIMSdicUD06b2++GfTMm6I=
X-Google-Smtp-Source: ABdhPJwjpAu5fG76E7ulTaLD4eMomqwWNPVApsvII17BPWJrrQSPT/8REXyvb0gjbOE3uYP6sFzByA==
X-Received: by 2002:a05:651c:327:: with SMTP id b7mr18215297ljp.281.1618399738479;
        Wed, 14 Apr 2021 04:28:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:c22:: with SMTP id z34ls1778712lfu.2.gmail; Wed, 14
 Apr 2021 04:28:57 -0700 (PDT)
X-Received: by 2002:a19:c34c:: with SMTP id t73mr25493228lff.81.1618399737312;
        Wed, 14 Apr 2021 04:28:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399737; cv=none;
        d=google.com; s=arc-20160816;
        b=Xq2yfm4EZM1xllwWGv/7hzrDIorYXPdZyYBXh9GuD2w+6Mxll4qTJLPplSguOqA9AQ
         3TysL2M7BkNaEOANPJBDt7XsLDIZUzS8/JQF7tQptXXAZtMUvc0Hk5SJzePyd0GbEwpq
         yxpps4tdp0JKUvRA84ktUh+8/XBSM/jyfh/4RAPIfslngfAMOS+Yq++t14blOH4ZfNcz
         kiQwq7bqmc52zVJg4XFw9k286J+7hAN5kj9XK8zbZZVE2bCBeTSolHSqM/2XKQdFvZk/
         axBqgW6a72D0nTS6fvMkj0nITzvVCoBLE372PMW+aRNl98O5XCYS4WnmqBE0JnPbwHUM
         +TLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=8yNlufzVA2jCQWSX0cYvr/qzprbw9+PqCJzc62HA7Xc=;
        b=op9HI97/drmZ8r8n2pATE/CprACgSqOd9OaepbX7E1onkbWoLItJlUrGVDkFJY6zvE
         unPX5+1kXVdMlaGZJEkK39dq7YLx3FDHX5Pu2hjQocINJXostK608NVTU7hPCpOhir7F
         u0e4QwQkEW62UU0tuDZuF3goFLtvF7fgEbZNkHjvOzmD3q2IQZQq1VwOxsfH55XJ6gCH
         obHPbZWJiAsrSMxHAamM2HiorHlV3hlH3ib6992dAGQ0WNX/ikfLT7tyW3bc+Sac+N8V
         tDE8EMPG3bcc0IaV5W4MkjgnXlDKZBGeBUD0aKK3w/VJef503yJsbPJA4ml+xm5aUo0p
         xrvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aY8yONrX;
       spf=pass (google.com: domain of 3-nf2yaukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3-NF2YAUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p18si901476lji.8.2021.04.14.04.28.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-nf2yaukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id m2-20020aa7c4820000b0290382b0bad9e7so3152283edq.9
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:57 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a17:906:40da:: with SMTP id
 a26mr14032298ejk.513.1618399736735; Wed, 14 Apr 2021 04:28:56 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:22 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-7-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 6/9] kcsan: Remove reporting indirection
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aY8yONrX;       spf=pass
 (google.com: domain of 3-nf2yaukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3-NF2YAUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-7-elver%40google.com.
