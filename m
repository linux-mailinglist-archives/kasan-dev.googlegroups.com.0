Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54B6C37B274
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id c24-20020a5d9a980000b029040db7d17e09sf14143031iom.22
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=WWM2xj4L7k5G9oUUzRM8H87m2kZeY2Veq3cH7kcJYO4whEootBCS9v+ubMyjvar+lj
         EMUiIbnojJq0GW53sph9v+kQOm7tkE4v1yUBaUCEYH2T7yrZRXTxzaE1DsvzKBkdM5UF
         1J2VXgCdqqpEwPgzIdG+jX+25Q3hMd4Z3XkyWLPXUd2pDx09BAWrkw1sw19Ycu5unLwo
         lP+04FF7rx9Y3povLBse2Jgo3ej4GBOyfKAILNWHj8RK9XBVu7jHXtGuIspXogpH2gaT
         WH8Ftt2neJygxrqaWxJvcVdc6CH6EwpIEBy3WyijEsk2TSt0Exfx3mNebCHVVQsL4cN+
         QjRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MpSTCU49ocBSfNil+5Y/Q3JWrAARzFikXG1n4NY8BpU=;
        b=rTkX6Aqr4nXgRaLzZFDjwF3ipzYJIj0R/WN3iAcwQPJXHkUo7mELTn6UkJS5jLxhtS
         m7QENiRXVaMRA64vn2RXrNWH2vWws5EFjZ0ng8/9UnKBkHqKImuDB42TN4N0FX4dFOS+
         MExnUkI9eKHLggBqC9PUCp1iDmC/vMhuCR4jqOv/jRmWRdoHj/3eyzVnYlUWWabDnYIq
         poPSAyqAkpXYw547mtw2v5GewJ9a0VcqJYSyMClfxJMI2UVd8oKTktB2aWQENcyr5Xwr
         Sog1pkb7EY8BZZ33wZT2MfkWdZv4ayUcjVkk4rG2Xi4aKzL5PAHdcoIwc2aWRcJ+9/BO
         hEWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WfYNVMOm;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MpSTCU49ocBSfNil+5Y/Q3JWrAARzFikXG1n4NY8BpU=;
        b=aocR3xsR6EYTcRNBCGTe8ie0falSYR0W3HoWm1OOFLOJCdr4ca0EkV3GqpKN4imSSQ
         4dcQpx18e6n3Y6Wj/2FRWqv4ni3QRi4LzLSqtKKpPYsun74hiBP0E9wEjLpE3jiIUepB
         F/ViO1ZiVhlJYUsI8VH10/Fa77qtp6evdXMrILlgjqXwagSSECWxF+atB0tr5CHXhBby
         4Oos5th1sPNiybIY7c+zhUfOE9O+VgWD3P8JjXH76XaQLIk86JKjaNSkQEnehzNDcWHZ
         WsbbXia7vwNCowAXlBqb4ANbYuKMIPK96Wtehx9ZZi7ZGuJwHDybuR0Gm2bF55cu/IHW
         Y7ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MpSTCU49ocBSfNil+5Y/Q3JWrAARzFikXG1n4NY8BpU=;
        b=SFylwVpkUSj3qxu3WJyAexcSrTiPsnvM+O0MH60pcbf9RC+yTLHJVD8VFlYDWrmRYS
         f6yqc6QwsoVEzd86c3LXMFXSektn4fKvXere3k7NHXjHWnaKaRTfaS2C5MxkIqEx2Sf/
         qUexfPjK8iUKURaN/Ipk5O+piwWZLJSTOCbKxoyxoliTHF4k1UwfSCHPCi2XqrWcH7Fg
         B2pmV6cwauBbi5n+09nGuH2Dz/LxW/PVmw5Zb0JnMzEyrnzlKo/DpIpTjEGquZCH5FV3
         1was3DodragLGFOh6nU8V9OU0Q9qGf4NiNxWVI/ubWyAbg9h8rmbBzj8NlpglvYobF0h
         kqAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AMTV/MeY2oAsBoePBRzyw+Gzw8E7bG3nAYvrr0+A3Kqf6TsjV
	akD0ChGiJfHmC0Fb7MCnMGc=
X-Google-Smtp-Source: ABdhPJyAHCShl7tewDv+rBCRGYDTxE5yWyt2ugZjX6LEMQPnWK5BV24CdnKP316qkRTrXF+990q6wQ==
X-Received: by 2002:a05:6e02:11b0:: with SMTP id 16mr25903447ilj.63.1620775448384;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7303:: with SMTP id y3ls55351jab.9.gmail; Tue, 11 May
 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:a02:b717:: with SMTP id g23mr30313317jam.109.1620775448136;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=vaihP5L0a8iXQ0mBSOPKsoiaqFlSGeIzUy10w+OX76QsZTE7FwUC7NHbF1RibB0rUf
         1q4dCCyfK8zRnXdJ59iA36449JKejLIrG0wMmkmCa2URAsAe9ES/+9+cN2uM1MuQ5wPB
         gljGRhNs+geavfO31gYs0jY2cKXKjwanXtd5vkhR3Kzuj69hcPIUlhrhJBwALfKBPkzv
         xYut6No8M5B9u3KJNYiUWsPbQzsaQvsS3W4XpNFH/sfIZJSnUzfO0y0EvE+1YLNg88U/
         nPIIhFNYBrU6hLD5fnQffYGQyXJgpT6zaZJxFGj8GgLCj/SyecyXygJZqK4LOc6rZtGU
         772Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w4BFcFptaZwSAEORW5nLRFtFiFQt34ExKtSx/d+OTwY=;
        b=d46mBhTSsHXk/QqE6J1r9iBGkoaRRgpZGeZFlvOu+GtTHVgKMIzYeYhmkAGjoru9Ue
         lYEbuw3LsHMmSmoD8KgFCg6n8gfGjJPZ6ixcEcaQAa77T8Luq4/94F99KmeQfsqcCbgR
         Wm5HVxvySNBPdrMYYGQCepRaRYACkhX+j+YwbtK5ZuA+COR5kjPRbG1WiiDmvQ5VUxHK
         PtB8nZlYXEQBTpi+Hq7NklebR+NopfHxADDZBVgJkoOWPnKPQQYlob8+QzXsFlMneesx
         nDhdeh98q1wj1dsaD554Maw+Thu4WOgj1DcWS7WMUgmQSYV57ZOfamvBDUg/fM5GNEzv
         0z1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WfYNVMOm;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h2si303082ila.4.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3E93F61934;
	Tue, 11 May 2021 23:24:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A43275C0DB3; Tue, 11 May 2021 16:24:06 -0700 (PDT)
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
Subject: [PATCH tip/core/rcu 06/10] kcsan: Refactor access_info initialization
Date: Tue, 11 May 2021 16:23:57 -0700
Message-Id: <20210511232401.2896217-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WfYNVMOm;       spf=pass
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

In subsequent patches we'll want to split kcsan_report() into distinct
handlers for each report type. The largest bit of common work is
initializing the `access_info`, so let's factor this out into a helper,
and have the kcsan_report_*() functions pass the `aaccess_info` as a
parameter to kcsan_report().

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 42 +++++++++++++++++++++++++-----------------
 1 file changed, 25 insertions(+), 17 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 8bfa970965a1..d8441bed065c 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -596,18 +596,10 @@ static noinline bool prepare_report(unsigned long *flags,
 	}
 }
 
-static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-			 enum kcsan_value_change value_change,
+static void kcsan_report(const struct access_info *ai, enum kcsan_value_change value_change,
 			 enum kcsan_report_type type, struct other_info *other_info)
 {
 	unsigned long flags = 0;
-	const struct access_info ai = {
-		.ptr		= ptr,
-		.size		= size,
-		.access_type	= access_type,
-		.task_pid	= in_task() ? task_pid_nr(current) : -1,
-		.cpu_id		= raw_smp_processor_id()
-	};
 
 	kcsan_disable_current();
 
@@ -620,14 +612,14 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	 */
 	lockdep_off();
 
-	if (prepare_report(&flags, type, &ai, other_info)) {
+	if (prepare_report(&flags, type, ai, other_info)) {
 		/*
 		 * Never report if value_change is FALSE, only if we it is
 		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
 		 * be done once we know the full stack trace in print_report().
 		 */
 		if (value_change != KCSAN_VALUE_CHANGE_FALSE)
-			print_report(value_change, type, &ai, other_info);
+			print_report(value_change, type, ai, other_info);
 
 		release_report(&flags, other_info);
 	}
@@ -636,22 +628,38 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	kcsan_enable_current();
 }
 
+static struct access_info prepare_access_info(const volatile void *ptr, size_t size,
+					      int access_type)
+{
+	return (struct access_info) {
+		.ptr		= ptr,
+		.size		= size,
+		.access_type	= access_type,
+		.task_pid	= in_task() ? task_pid_nr(current) : -1,
+		.cpu_id		= raw_smp_processor_id()
+	};
+}
+
 void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
 			   int watchpoint_idx)
 {
-	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_MAYBE,
-		     KCSAN_REPORT_CONSUMED_WATCHPOINT, &other_infos[watchpoint_idx]);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+
+	kcsan_report(&ai, KCSAN_VALUE_CHANGE_MAYBE, KCSAN_REPORT_CONSUMED_WATCHPOINT,
+		     &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
 			       enum kcsan_value_change value_change, int watchpoint_idx)
 {
-	kcsan_report(ptr, size, access_type, value_change,
-		     KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+
+	kcsan_report(&ai, value_change, KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
 {
-	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_TRUE,
-		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+
+	kcsan_report(&ai, KCSAN_VALUE_CHANGE_TRUE, KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
 }
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-6-paulmck%40kernel.org.
