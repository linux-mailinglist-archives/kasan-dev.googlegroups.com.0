Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCPGW77AKGQE5RSPX5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 806212D0CC5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 10:16:57 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id z12sf5092544wmf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 01:16:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607332617; cv=pass;
        d=google.com; s=arc-20160816;
        b=cUfgkEREYY8ZgmhLmq8oMQ0kyOS6XjEXSqeDnxllUcqS7LRXSEF3bDfE+Qwk5FqRQV
         FYX+owF12hcTMgQ9X+kYoviW+g2dBJ+wErcBf2yZTCRhGehS5A31DKqZUd7ZP19wR3JD
         yyQsC/f0AiL3k9IeRqJlrvYDBO9zUDDKhQdpz4jF8lpbMiPXKsoZqT39dUQG4oozaFOo
         T/1Vea0neZ60nV5kW+skxW88o7CvUkklgoZhgHhDlGEzOHMHa7NAGCa+ExCEXykqxOlY
         dMPc2v2JdDwhXiF3PTxZkF4y+wLivQhr7gTrSpxj8+dbV7p2DnF3n2k3VicSG8WgEhEJ
         IN6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=w8/xhbnGU2Ql3NOW/3cf3MDHFi9p8hX4aYU4MvdcHRU=;
        b=UoDUP0AEIiV0YedcUo2Ad6s1uxmj5nuuwGjKWRvD8EgGdLWsMk/akj8vnySjwiNE7R
         moEofBgeodWPMs9KWrYTfqjdg/YV6TiVZTZWui0Lc8Pnb7s2mZaZIThnTpsFVWp9hk8Y
         D6Sctb4qyA8BxsuyA8AvgDziy9xOm9naLyOAiJZQrXZRQt9YXmZ64iQdo0XjSDupOakl
         MzeDs2tybqAAsJXZO4RiqquRIXACiNxOpUHq7PtTYJnu3wrluAb/KQHtRzEIU8q1JEhD
         oZHnEIsdnB43VPYHXRPUfY2ntQaF6f5BbGkzDQLV5Ry7cBhEKw5IctAGU8ss42jFt8Va
         uh2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A7R7dYtQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w8/xhbnGU2Ql3NOW/3cf3MDHFi9p8hX4aYU4MvdcHRU=;
        b=SCDQFkhbo2a5d2L/P4Q0FXWJf+S94FnnnryVpzBdG6LAQRmchCXJd+ef6Xxk1yKbhG
         KGBBrIdzmeXOH9T76BGIBOZAxiAqaVXpPR0ml273H7+VD9i4X9ZXqdNNB1QSnHK1rDR+
         F9k2PXE2f9f4bhg/140KG5cVjVrJJOJKDBbZMVIqb0Qz7twl+EV22crf+L6uXAk2/qDA
         a54S7aqUInKRz8wSMsAhkASqmL7jTjJgR0g+Zz5KS1CMnD8Wl4RrZnSJyGZXaTFrEhS7
         6xx4HQKFW7Zdgcp6mqxMbtmlz4sJLC6lcK2PrWldsHAhptnF1I9hwZlim5VBZ0TP+Rd4
         BaWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w8/xhbnGU2Ql3NOW/3cf3MDHFi9p8hX4aYU4MvdcHRU=;
        b=YVJuiRjKqeZvrbmobMxiRGCsFVClNgZTNXQa+2ThgSQJO+CQf+Bppgf1QU2csc6ooj
         wxo4scy3o3EsWz5M8GFBTEeAaKo2EK4f09WsGMiA+vOltbkY4ZiAOKuJUC3Unl1FYzOg
         LDCjokLzzUT0VbbBQ3WlnGt/S1ZLIzBxt/s357Ho4orR2tLY0dBQ5Oa3IWf8vpTJ55u6
         voPlGWY+OmN6PeyCyaoAnJ/U/lG57WezhzgYDhZmp0d2vXrFsWzQgqASCCw4TDAfzkyv
         WOMxrQ4oh697EulDX6HkGhV+nQa6H5iZ16L4xOy/dHTU9yMkcQbT1BqPKXLHCf6cmH+J
         WAEw==
X-Gm-Message-State: AOAM5309JRttfM1/rnS2VTQkWWGYpPGEoGBVig2A7N55ELNCYvxt7dSQ
	1UbXzL5RoqvNdKOA6pGW/Z0=
X-Google-Smtp-Source: ABdhPJyCIh/jGlCGForVyenBketO0XPQ0Wzihd1qspN8zqWuUXcOSAF2A3DuUC4RE6YA/yUGyozfCg==
X-Received: by 2002:a1c:730e:: with SMTP id d14mr16917415wmb.43.1607332617285;
        Mon, 07 Dec 2020 01:16:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d14:: with SMTP id t20ls7898419wmt.3.canary-gmail; Mon,
 07 Dec 2020 01:16:56 -0800 (PST)
X-Received: by 2002:a1c:4c07:: with SMTP id z7mr17134917wmf.142.1607332616277;
        Mon, 07 Dec 2020 01:16:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607332616; cv=none;
        d=google.com; s=arc-20160816;
        b=tZ/8WdGt9WRBPioYMemxBP+CR7rSO4uTaUNqpH5nx/oC+6sE5ny+V7NrzOHwlw/PHt
         SuQq2OwG5k1Le0imXvm3un4gb43uBmMACG4VVae6cSi5t9WRa5vw4R1QhnyF+mL+eIly
         AwEbLd2RwayzNf1MwZcbcqcDjAUcL1YCo67CIaJNDk0k0uvhBlofjNkszmqnMLHwl9zG
         4Nxyqw9VcXxONj45MzOU5kIKD1jzW/RqjPPFlY2Qjq06z0Sxruvka75gBM9EJuiK8aGo
         1VDtLl8MHSwq8ZqMvJHOqj7VRlGwl5cX7UzVpwWJV4Cg5Tp2AO3+kIA07PUXIJYLYwOk
         gswQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=62J9CK9K/G2Zeln/AfAlkRTq0qukFCVYHM4339A9FCY=;
        b=UFPjluTsifs9mCjC8gUTcuQbAG4wxeN3IZpd/ayUEPSYdGF7tCqfWbE3OOabMXsY4k
         dCplfuyIyANE5mHJKU8qJkeo6oC6Duy1+4fZA6nzepuv+2l2ngwOWUGRbp3Bmqm4y0vR
         AeTOGNMkInxR/7W29jCEA8VHb6j2rivBKYRMtyryLPifwtuoPasO/bzBKsegqlszkH+Y
         mU3m1OASfdw5Ru2KTuO3HBd+SRe38bq5DyCHjrWiVBMjmPdsGjPXqEO2B1dtwxl8VMzL
         D6bKRibin/gRq/DXzjuOLj/SV5NxnqU5SsJ/yy92g3pIhVJpPdbZV6Yr6gK0OtxBG6hS
         rAIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A7R7dYtQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id i206si335615wmi.0.2020.12.07.01.16.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 01:16:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id y23so1351933wmi.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 01:16:56 -0800 (PST)
X-Received: by 2002:a1c:3c09:: with SMTP id j9mr17337024wma.180.1607332615711;
        Mon, 07 Dec 2020 01:16:55 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id z140sm13973787wmc.30.2020.12.07.01.16.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 01:16:54 -0800 (PST)
Date: Mon, 7 Dec 2020 10:16:45 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <X83y/etcPKUnPxeD@elver.google.com>
References: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <X83nnTV62M/ZXFDR@elver.google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A7R7dYtQ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Dec 07, 2020 at 09:28AM +0100, Marco Elver wrote:
[...]
> Please try the patch below and let us know if this improves your
> 1ms-sample-interval setup (of course set CONFIG_KFENCE_STATIC_KEYS=3Dn).
> If that works better for you, let's send it for inclusion in mainline.

Patch can be optimized a little further (no more wake_up()
wait_event() calls). See new version below.

Thanks,
-- Marco

------ >8 ------


From 6c48067c55faeba70778964239694ccb0c6a6c05 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Mon, 7 Dec 2020 00:45:59 +0100
Subject: [PATCH] kfence: Add option to use KFENCE without static keys
MIME-Version: 1.0
Content-Type: text/plain; charset=3DUTF-8
Content-Transfer-Encoding: 8bit

For certain usecases, specifically where the sample interval is always
set to a very low value such as 1ms, it can make sense to use a dynamic
branch instead of static branches due to the overhead of toggling a
static branch.

Therefore, add a new Kconfig option to remove the static branches and
instead check kfence_allocation_gate if a KFENCE allocation should be
set up.

Suggested-by: J=C3=B6rn Engel <joern@purestorage.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kfence.h | 11 ++++++++++-
 lib/Kconfig.kfence     | 12 +++++++++++-
 mm/kfence/core.c       | 18 ++++++++++++------
 3 files changed, 33 insertions(+), 8 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 76246889ecdb..dc86b69d3903 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -4,7 +4,6 @@
 #define _LINUX_KFENCE_H
=20
 #include <linux/mm.h>
-#include <linux/static_key.h>
 #include <linux/types.h>
=20
 #ifdef CONFIG_KFENCE
@@ -17,7 +16,13 @@
 #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
=20
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+#include <linux/static_key.h>
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
+#else
+#include <linux/atomic.h>
+extern atomic_t kfence_allocation_gate;
+#endif
=20
 /**
  * is_kfence_address() - check if an address belongs to KFENCE pool
@@ -104,7 +109,11 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size=
, gfp_t flags);
  */
 static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t siz=
e, gfp_t flags)
 {
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	if (static_branch_unlikely(&kfence_allocation_key))
+#else
+	if (unlikely(!atomic_read(&kfence_allocation_gate)))
+#endif
 		return __kfence_alloc(s, size, flags);
 	return NULL;
 }
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index d3ea24fa30fc..78f50ccb3b45 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -6,7 +6,6 @@ config HAVE_ARCH_KFENCE
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
 	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
-	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
 	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
@@ -25,6 +24,17 @@ menuconfig KFENCE
=20
 if KFENCE
=20
+config KFENCE_STATIC_KEYS
+	bool "Use static keys to set up allocations"
+	default y
+	depends on JUMP_LABEL # To ensure performance, require jump labels
+	help
+	  Use static keys (static branches) to set up KFENCE allocations. Using
+	  static keys is normally recommended, because it avoids a dynamic
+	  branch in the allocator's fast path. However, with very low sample
+	  intervals, or on systems that do not support jump labels, a dynamic
+	  branch may still be an acceptable performance trade-off.
+
 config KFENCE_SAMPLE_INTERVAL
 	int "Default sample interval in milliseconds"
 	default 100
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 933b197b8634..e1c33f86c9d0 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -88,14 +88,16 @@ struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NU=
M_OBJECTS];
 static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_freelist=
);
 static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freel=
ist. */
=20
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 /* The static key to set up a KFENCE allocation. */
 DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
=20
-/* Gates the allocation, ensuring only one succeeds in a given period. */
-static atomic_t allocation_gate =3D ATOMIC_INIT(1);
-
 /* Wait queue to wake up allocation-gate timer task. */
 static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
+#endif
+
+/* Gates the allocation, ensuring only one succeeds in a given period. */
+atomic_t kfence_allocation_gate =3D ATOMIC_INIT(1);
=20
 /* Statistics counters for debugfs. */
 enum kfence_counter_id {
@@ -590,16 +592,18 @@ static void toggle_allocation_gate(struct work_struct=
 *work)
 		return;
=20
 	/* Enable static key, and await allocation to happen. */
-	atomic_set(&allocation_gate, 0);
+	atomic_set(&kfence_allocation_gate, 0);
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	static_branch_enable(&kfence_allocation_key);
 	/*
 	 * Await an allocation. Timeout after 1 second, in case the kernel stops
 	 * doing allocations, to avoid stalling this worker task for too long.
 	 */
-	wait_event_timeout(allocation_wait, atomic_read(&allocation_gate) !=3D 0,=
 HZ);
+	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate) =
!=3D 0, HZ);
=20
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
+#endif
 	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_inter=
val));
 }
 static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
@@ -705,9 +709,11 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size=
, gfp_t flags)
 	 * sense to continue writing to it and pay the associated contention
 	 * cost, in case we have a large number of concurrent allocations.
 	 */
-	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) =
> 1)
+	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_all=
ocation_gate) > 1)
 		return NULL;
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	wake_up(&allocation_wait);
+#endif
=20
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
--=20
2.29.2.576.ga3fc446d84-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/X83y/etcPKUnPxeD%40elver.google.com.
