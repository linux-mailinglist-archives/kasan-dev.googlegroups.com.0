Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id E1B97474D85
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 30-20020a508e5e000000b003f02e458b17sf18248172edx.17
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=lecqcCoFtUjPpqASrIODnj+/nh4j3TXj4HFUy5SNpZsvAWoeUNCzP7bPy/sBA0U8lv
         MOGR3exDuymccL5PAzfSPYqlpfyBTWnsp+9elR6DWOBSKRPNZK+Y0gmZaWabvtSFcTZx
         oI4kHBKXfF9PrXtSHhjH6uUWDYU4VMB1YAzj/rLKip4Rqx5V4HYRjoIM5mGJPLljBAaF
         teRFXHPqSoAW0v03M29G1Id0cdPkXLV8Fmqd107aXvKgyLXpCuLs2HEE0B3OUHUmIytU
         ReUwCgGoWe3wk9alyr1zzGI+uDB8JbtK4m0vqzCFHxkEC0KbaL0YtHte/tCfWMZun44N
         1AsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vZITH2PxeZv5ynhAe/zMGKnAxlV0ESjn8BchoG9nq0I=;
        b=zLWOMnKGaQkP1QX/nnUXYXxR2LaaYCq8xdcbyZur3T3v5OyRXv9FLhuGVeRymcX5Vh
         xW/OOwoJeow0wSCpB2m04yvJt6K33N+y42CE0Wz2WkRUmUr5Nj+lB0UdFVMhcINVx9eN
         ixk0G6PaS8L8OHSQeFfEaaMZ1hZos6AWtMHTQwpw5Rrh8FvpXoyQnoXaJwAn8F2OQw/n
         ww3ZicN+ekFPIysprNM/7UzXhXPqm5/vMY5OjGsvRl5xuVs7/xYOVld7t/iQ8f1LJUPm
         0QPyce9U1yo4NAPy2mgYo7piqUMNeM/tOlQFY3R5PGedoVjdMwD1XXu0sCUO348hJp82
         EpVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HhmOnGy0;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vZITH2PxeZv5ynhAe/zMGKnAxlV0ESjn8BchoG9nq0I=;
        b=ZCS+GsgjAXP6ZYSBDTfFtUBe6yQ0DAxT0AJ36vJQvdYRSO1WHzUYFjQhBvOujdcegA
         RdkthCBhtk8pwn3QMHojVBN+SyGvigjo0cG+Rua2vf2hxH4wPy24jT9ZWqO+1awE3FWj
         a79uw7kK+WOn4xVBY5S5CogENxGLzh393Jc0YhsoxbWVkuGd2/zHIGPdFJusj22XJPbD
         2NSPauMkE3xJeUqwBGHEfAPyI7ib5aqq9bQ13ZLbAUNsH7+fOWl5S8ea63ECzC0v079L
         RuomVOtR9YJJ+bLv2u9+FAJvmKGPvDeUfB5T3DLuRUh9EurOxUj+li7epoiPH796cyH8
         M6yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vZITH2PxeZv5ynhAe/zMGKnAxlV0ESjn8BchoG9nq0I=;
        b=SwJF0HMsDgDevoTVOAWrC35GLRV8czFvORH26NBQe47hYx3o2S7m+d42lyL5fKHZB0
         9OZn7C+SHtcaqmlXTvyPXU3FU617ExW8ysjztgF587kQUhDxF7ZDW37XjKn3+QPcq7Zz
         +D5qBT0xPjrOIws8rhHMgzFIP3Z61IXtu7819C3TI+6xRVLCurnIxnqvkMXBWFLWYCBU
         T6SyBRYrNJRMPfIaZqg7yI7ufNWBuOdzL3fJSPKAzGFyBh5OEMiSn9KbhEw1j5AbZq6r
         r0j55qTYjP9RDZdXrdrMS+bcoyv1I7VeGmG/lj2JeEmPYqPeMqO095PnL7WnqurChjMW
         2+2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OJ92SQkBOf/NmAoLCFBUkzuqyODE3bGY13NraquT92p7df5/w
	/ENtRfpDPRsk5InjD9c20Cc=
X-Google-Smtp-Source: ABdhPJzNNcm5MSgbod+GdY8mQ3Vw6YAZL7FUTb9jXLrDRbXYhLeG13OSfpYr8Sf84JzR60Bb/86MsA==
X-Received: by 2002:a17:906:a091:: with SMTP id q17mr8156563ejy.669.1639519486697;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6da0:: with SMTP id sb32ls23338ejc.8.gmail; Tue, 14
 Dec 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a17:906:830b:: with SMTP id j11mr8534604ejx.161.1639519485655;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=VDmbUybFyeVEjnjKF+zB1y3PvGwX2YRETkljXZev/aiLSjNU9J80P0LONGD9RGILCm
         pPzPwVpDCNZR1BQUZ01lX5pNJ7KlQyy3Mkowg9/v9wP11J9hxTqQFjyCeam8vVwFfcsi
         +n+/R14q+pH0T9aabplYKwzTyhCCEmcAfRdxjQ2Kz+E1EZ5LKVSgxpjxEtzrr/NWL5fA
         UfYfE6pY0z4YlRXF00hI+29IjcdoS5VF/B78wFKYrx6YSqnKAkWZT3WQD0ZwZBs24czS
         W7HuYc003RHCd/909zBZWiSRTvgAgVDvvEB27UKs75c5X0oWCQQQ98pPmzqYwhJ1uc0f
         +P7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Eh1yZdiaZPbgeBdr2Rs53qJdnKrbrYETVEADq+9sMDo=;
        b=P/9+y8g1pP2KYt6vfQ4hqQlG0td6+FppdpsFQRvzQJOkNk3ynainwnw9mFPatSpeEh
         oHpCV6nvrqjhC1PYDwIdCcTNOPjQe/G+S+NZQd0mrgB9bCz42qSTEbZ3Paj+TJcK6L0N
         KIi2B9yOIGcLHK3fZe+8g+9LuyjAnKIPCh8V2tEg4zsj6gM42+Zn9ATIUrNxzkCguF7p
         NXeRLCK4b/MddJsYNELVkdC0SbvLeytmXjHCeC0xR8ykUKsNH45vz9xVQ0wf6o33gJKn
         NPXVPQg/00BIpKDKmrQmlyKm5THo4qwvvInDzpsn9WG+XbkM26XwRmHSSM2ubSY82rpV
         QEew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HhmOnGy0;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fl21si7328ejc.0.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C2CB261742;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0F9DFC34625;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 76D005C193A; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 15/29] locking/barriers, kcsan: Support generic instrumentation
Date: Tue, 14 Dec 2021 14:04:25 -0800
Message-Id: <20211214220439.2236564-15-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HhmOnGy0;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

From: Marco Elver <elver@google.com>

Thus far only smp_*() barriers had been defined by asm-generic/barrier.h
based on __smp_*() barriers, because the !SMP case is usually generic.

With the introduction of instrumentation, it also makes sense to have
asm-generic/barrier.h assist in the definition of instrumented versions
of mb(), rmb(), wmb(), dma_rmb(), and dma_wmb().

Because there is no requirement to distinguish the !SMP case, the
definition can be simpler: we can avoid also providing fallbacks for the
__ prefixed cases, and only check if `defined(__<barrier>)`, to finally
define the KCSAN-instrumented versions.

This also allows for the compiler to complain if an architecture
accidentally defines both the normal and __ prefixed variant.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/asm-generic/barrier.h | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 27a9c9edfef66..02c4339c8eebf 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -21,6 +21,31 @@
 #define nop()	asm volatile ("nop")
 #endif
 
+/*
+ * Architectures that want generic instrumentation can define __ prefixed
+ * variants of all barriers.
+ */
+
+#ifdef __mb
+#define mb()	do { kcsan_mb(); __mb(); } while (0)
+#endif
+
+#ifdef __rmb
+#define rmb()	do { kcsan_rmb(); __rmb(); } while (0)
+#endif
+
+#ifdef __wmb
+#define wmb()	do { kcsan_wmb(); __wmb(); } while (0)
+#endif
+
+#ifdef __dma_rmb
+#define dma_rmb()	do { kcsan_rmb(); __dma_rmb(); } while (0)
+#endif
+
+#ifdef __dma_wmb
+#define dma_wmb()	do { kcsan_wmb(); __dma_wmb(); } while (0)
+#endif
+
 /*
  * Force strict CPU ordering. And yes, this is required on UP too when we're
  * talking to devices.
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-15-paulmck%40kernel.org.
