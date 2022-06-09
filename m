Return-Path: <kasan-dev+bncBC7OBJGL2MHBBANUQ6KQMGQEONORRCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7520F544A24
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:14 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id b26-20020a2e989a000000b002556f92fa13sf4280327ljj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774273; cv=pass;
        d=google.com; s=arc-20160816;
        b=vwfjJzZgsMAlBPdzPzXi+o7bD8NyLm4zyU+CeO9ouJg65ksaWHnzEHu0Wn5LaK0lML
         s78a2haVTkFp7lansGQoANB/3FQO7gyZUYRNB1EqSW4d7kSyaOKdKNH83UA5bV+CfmCM
         t39pvSiu4g8cw4vGJ/xFLhM0H90j/5y3uVmu14c9GBpSN1geuTf/U+/BgOg+9IVuR3Ps
         Kyx6h5Lwf75vNrwAwonkOitDfVPOwK5yMLGvPnUDQ749k6xsu8d6woOm+qv43tYWbgjx
         chntjlqlyqblem3HJb/dSWD5IYoGi3f2SU5coKSaZCQ8cLqKPTTe3sKgEO+an+8do5Y3
         NDuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oE/BqQWmeLZgH/t0ae2AX2Awsu+HRKtPxCstqxt/IwU=;
        b=LQo4eqgxxOuBy/y+JHhRHk9CpKWjK39sh8hvePX4QcNbVxB26wmJpktOh+kD/DWUTV
         NcjQdKc/GE0EzIrf/Y04nKRPA32S8UTtnbAPp2x8P0E5ckF+45UTv+46vOkbY1yDGKXW
         1j5j5Lcc1LDVYEdLU0B6ZF/vD9Xi2iX0jcD/VjTPAqftPTfSWRx8iJ4QYkU9j0oMrNtV
         q3kjX3h8pO3nusSGxB68rduW9qcljGa2Rg2WxwOA+/tHrFQTTCo8RPaE9mYqMWYaPyiD
         kR8ypNAkH+Qu0/SUDSPc7Vg1wAzHHRPngF+dVjqCMl+WDuXbDyMpOgADIw+11JChyxZl
         w5jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FJgcqRt4;
       spf=pass (google.com: domain of 3_9mhygukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_9mhYgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oE/BqQWmeLZgH/t0ae2AX2Awsu+HRKtPxCstqxt/IwU=;
        b=fXpb9W43ZgbQrOY8WAe6uSMVXYK4F6K15mdxaPMmLT26O2XJSKXJ0D7yTYh1wmtcSM
         Nsz7ohrXyyu9Sv0aMlqAfHC8RjsbY9/2ZuBZOwm9yno0tBeeYGDfXwkhL0X/0rM+tXp9
         eZA0rwZ93x7pO9dvv0PIsAwxH4cakixDlF5ZLgPOjGj0s+XOCSBl8zOp4g9Ylxrk2IF6
         H/oBWf2UyN4nkpFz0EFB6xY7Dd1TNI53oQmY6ngWZcIif256tmmdNRpHmvS0x6Ntm44u
         3QTg2D2glNttnbUgBX9q4pwPohP/gqXbQjv2neGl7fUTDYUhsrP5UhVxHAF5P2RrfsYL
         s1Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oE/BqQWmeLZgH/t0ae2AX2Awsu+HRKtPxCstqxt/IwU=;
        b=zd+0orNGIcvTBDCSAD+Hvv1j7RJkvix6t0XE7WoybH/aXOzmIR/qZdMnnHl56ROh79
         2rzdYjEB8j3J2zjenC8ZUn80+w+2cvtX/Iz6EyzFqdEkPgnx3cMbt7x/sMD5tgh4uxC6
         l7EJav/NosEVzN2Q/Ok1DqyfMgRnDdeoV/yH7utAfNrDMODfNuNd59Y4jRQa5TJPr9Dr
         Y5mj/YU9No8v63pHH6T/SmwpgFlWaoOAJIEumbtx7xZQ/i4sgrc3Z+Lhbb3jhGGje+KJ
         sARVgoBCSixOR2rlbfoR7G4ItFIdj0iHnViGn8AOfmZfipncHUo+w1KYjLuQCu/gLOXR
         pPQw==
X-Gm-Message-State: AOAM533gTJlx1qHCRTxAu8JP+axeHuP5yfxN9rLCtunNeW2Hd0kh1gkA
	SsOHjCAyPF6cSG5rN9gWnRQ=
X-Google-Smtp-Source: ABdhPJwkmkmitOWi/JePTnak/NhHN8NQ9uRB/bmsJkIL2ZIQVhO9qvGng1hZxqUsmCFiFOB99qUFsA==
X-Received: by 2002:a05:6512:400a:b0:479:9ed:a71b with SMTP id br10-20020a056512400a00b0047909eda71bmr25433622lfb.488.1654774273502;
        Thu, 09 Jun 2022 04:31:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls3321857lfu.0.gmail; Thu, 09 Jun 2022
 04:31:12 -0700 (PDT)
X-Received: by 2002:a05:6512:3b0e:b0:479:150a:ed09 with SMTP id f14-20020a0565123b0e00b00479150aed09mr21319355lfv.231.1654774271918;
        Thu, 09 Jun 2022 04:31:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774271; cv=none;
        d=google.com; s=arc-20160816;
        b=OACQIhTllqDNRygwIIO785qpnGTRGQqus37wErV84C9k0cUnmhcMhQs+vbBayIFqHf
         us9BBvLRXQWaFYn9GEJqh9fck9PZPbO7e3s+tc65ZjwwTp9hW4Smimd35wqnYMiIdlpi
         Co8eEFAbFyexC8p3KbkPdfOcAuO4TG6EyKcQncTdMrUaXKyf62XyuKADkkEzdAABZe+w
         mgJBemIsxe1hlZ1U5519h5sfo9UC1HxCbqVAGZ7e89CW08ULkmqz9BTZCWAj32fx3X21
         LD/bq1xu3zap8dM6hLT6hEvJKhixLExkzpZVrtGU8oWP9wOx70mz+1jffVU94LSAnXzG
         MbSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vEnwLHfz8bnnz/z0hnI1W7+EOk8HMNN4MOfns1570U0=;
        b=SaXsevpWfl/8ZaFqPCzQCUmhFrTSPEjqFZ810/+OPlubPIY5NgZdYBARp24kWcWeYY
         /jN43FluxpurdZumPLB+fU2N4Y9zn4VNAN/UiaBmw6FiCihahRgSOnGvX6kV07tUxZrc
         /qnYVPIlF3WEJHnT7sTphBbEO7uWEVaB5ai3xMEh6e9rpb5LtIUol5JJxk9RgYvvhE2e
         OCoqUjaiifj9dgrkrwUoaGuApnvbGjZjMSPf4jrkk+sO0r0Bt5UztQLyYcDLEdyoABy4
         WuIUX1ZkasizgeX2HSOfkGXq5ATXFpNIBaDJFvVE/Ca2wDWN5HZ9yMisFOIfQUdhKaTv
         hP4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FJgcqRt4;
       spf=pass (google.com: domain of 3_9mhygukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_9mhYgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id x24-20020a056512131800b004786caccd4esi1213433lfu.4.2022.06.09.04.31.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_9mhygukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id s4-20020a170906500400b006feaccb3a0eso10875781ejj.11
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:11 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:a17:906:8513:b0:711:c67f:62b6 with SMTP id
 i19-20020a170906851300b00711c67f62b6mr21303657ejx.657.1654774271337; Thu, 09
 Jun 2022 04:31:11 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:43 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-6-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 5/8] perf/hw_breakpoint: Remove useless code related to
 flexible breakpoints
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FJgcqRt4;       spf=pass
 (google.com: domain of 3_9mhygukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_9mhYgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Flexible breakpoints have never been implemented, with
bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
flexible count in fetch_bp_busy_slots().

This again causes suboptimal code generation, when we always know that
`!!slots.flexible` will be 0.

Just get rid of the flexible "placeholder" and remove all real code
related to it. Make a note in the comment related to the constraints
algorithm but don't remove them from the algorithm, so that if in future
flexible breakpoints need supporting, it should be trivial to revive
them (along with reverting this change).

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/hw_breakpoint.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 5f40c8dfa042..afe0a6007e96 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -46,8 +46,6 @@ struct bp_cpuinfo {
 #else
 	unsigned int	*tsk_pinned;
 #endif
-	/* Number of non-pinned cpu/task breakpoints in a cpu */
-	unsigned int	flexible; /* XXX: placeholder, see fetch_this_slot() */
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
@@ -71,7 +69,6 @@ static bool constraints_initialized __ro_after_init;
 /* Gather the number of total pinned and un-pinned bp in a cpuset */
 struct bp_busy_slots {
 	unsigned int pinned;
-	unsigned int flexible;
 };
 
 /* Serialize accesses to the above constraints */
@@ -213,10 +210,6 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
 
 		if (nr > slots->pinned)
 			slots->pinned = nr;
-
-		nr = info->flexible;
-		if (nr > slots->flexible)
-			slots->flexible = nr;
 	}
 }
 
@@ -299,7 +292,8 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
 }
 
 /*
- * Constraints to check before allowing this new breakpoint counter:
+ * Constraints to check before allowing this new breakpoint counter. Note that
+ * flexible breakpoints are currently unsupported -- see fetch_this_slot().
  *
  *  == Non-pinned counter == (Considered as pinned for now)
  *
@@ -366,7 +360,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	fetch_this_slot(&slots, weight);
 
 	/* Flexible counters need to keep at least one slot */
-	if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
+	if (slots.pinned > hw_breakpoint_slots_cached(type))
 		return -ENOSPC;
 
 	ret = arch_reserve_bp_slot(bp);
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-6-elver%40google.com.
