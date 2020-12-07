Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKOPW77AKGQEA26EDJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 812A92D0BBC
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 09:28:26 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 190sf2427771lff.4
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 00:28:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607329706; cv=pass;
        d=google.com; s=arc-20160816;
        b=HB4zVFWlEVxAKywrpi0kZ04kpjxa2ssVVBQH3+pTtTA4LyzL43e97Cpdj0RvjO2o02
         pCoJxZQbiBN5FX+XqiLRZNuZOIr7SkjF0+O9opM9G9zXmcEcjD6VpNROeFAEK5AQz507
         tpr7tRTMQy6JPVeKoDzwr5nU81dFDtrfXK9OJEE1iDkp76TUwRlBmphM80O6YCfr+yUB
         r65KM2X8aUYQJDx13h+Z2Wb5o2eakzr0i0QjeQcxm3JBeAU9ixXFn3Z2ASm23bf4dWJh
         jFt45OTvkuLzWcT6/Xcjj9WBrgjLLja3+mwlqoJXoXqrncpEt4eOvOZlZ8/+jNs4mFRF
         yaSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=l7H90TRe6LrZaiOtGz42vLX1idQfega3Eofty31Tt8s=;
        b=odfgJOiuxaKN6y0lZrVAtjSTmLusawIP849t24tgpdvbejkBEU21UWvorSi03jwDic
         UueRChQLIru7fPqp/rePt5lJORvL/uyetDHFN/+cEmCf/gyRdcjOEEG1Lcl2AfhPmh2W
         vyU0wZk0dts48MIdNwkMen4FPVOMw5JHvdTBhWvfq12vk0A77SyRzBV0EqH0TsFzs8eR
         xEuNUAYLuvMpa8RoFwKw1zp86IdcLy5DXno4v++tAo8tyu2QQeAF5L0ZGPqUprLvrAmp
         nAHJP9XiRovP001b1ZSINvzOiMeVMgP3cDRLyZvRoVOglrEX9/8DEjwkzSKGbw5ygL5F
         TrAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZbPZwup;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=l7H90TRe6LrZaiOtGz42vLX1idQfega3Eofty31Tt8s=;
        b=Pu4u9p5n6gmFP0ZYnGqdW6RuPC3DYvN2FInicANw39H6IYAVfpsj4IWfexkjePrSjT
         p83N4RUnRc79B6FzvBDuiaUOHIVk34BcsRFQsKkxkbU/NYo07NvuCLl5PTue5Q/gr4IX
         fv1iHHK9WLj8WQ8AUWUZE5Nj1iBKuGM0uwPVcocxqMEDTTRdnhQEfmi8mhz/U+D0F8bM
         0AjeiKPMrtyPWV7oiVuh2rkIv+ylzLf2xp4n2b97fQz1aqH+SvhG0R4Zq+Y2aKArQTFW
         bs1bS4jJDRfJCWXvmPFNmGxXHD4X6oY/VJCbfZ34qift299zQgtDaoYYJ32pX33c/6+o
         O+cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l7H90TRe6LrZaiOtGz42vLX1idQfega3Eofty31Tt8s=;
        b=TXQEe9vraNLZYq6+ff9JP6ppzJLvgMJE+Hq8ohDJZDBHTfo1s+w6od4ybqOJBq9GA1
         zjS/VM1cwsFKUeo83ME/1y/8K+sKMytX9Z7OfIft9yIbwAu3pcubMKcK0S8o0nBFsZSw
         h15P4Djk7m0R+60++LT3xtVHHf1YwJXDef6bn3YfXgMzPMY+F7j7QwdOQm01phQGnEWu
         VNW1MLjByi2W2wizGF0ELDP/zufi9PmQnQRRx5Tg9m4edw9y4wIenxRl+ZWuDG/wlV59
         IKA/jZ9NgRKzpFs3VgajtTgQZ2X/QlZczXzHo9I8VbUKeJUiTTvuC7DjxE1X+5KdrOOJ
         +XIQ==
X-Gm-Message-State: AOAM532VHVhs+SanM0JApzT9E04h/h/N7+ibk1F+ai8AHBk4110iyVIR
	ZFLmdlR5bvauj04HG+dPhSM=
X-Google-Smtp-Source: ABdhPJxWDWiguvKvKjgKWv1Jq8E77kzJWSgdlriV/CtCkP8f8OiH2NNWsXUd5W/6Xm8Epa61ffTjRQ==
X-Received: by 2002:a2e:bc15:: with SMTP id b21mr8603964ljf.350.1607329706017;
        Mon, 07 Dec 2020 00:28:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8895:: with SMTP id k21ls353786lji.1.gmail; Mon, 07 Dec
 2020 00:28:24 -0800 (PST)
X-Received: by 2002:a2e:9718:: with SMTP id r24mr8694128lji.20.1607329704821;
        Mon, 07 Dec 2020 00:28:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607329704; cv=none;
        d=google.com; s=arc-20160816;
        b=gOtmEzYjwcpz/qnJmM7llNCM8eXEDNZPL9dxa8uN5/HiaBd3rGBCL3UI2xa0kQ9Vc6
         6NClFoxIH5BWX2BEZYtlhgFIQNP8AEbFcfKZblY61tVQkOG6zEaDOOWXNnCv7/4jVbc5
         6AU7j4cqplRpQatRBEtzR25YTksLSHe4wZVpJvoMKW1m+3/P2+oKf1Jc0nWjcN7NX0Jj
         iJ27HIViRSMoqhYsfxHpcW8FoC0OgndbVY4fZbqBK5+TK6AD5MSV0TItm67hOW33/2Hz
         FPUVQPCDVKWA+ANe4dTJ5UDtz26WDmesYjisSu2ZfrXPleL3gTJucW1J/JIzgY6lzu3v
         lIyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GjZgx1IFKooZCIEsX6Tab0+jBYByYLmjuYHLhtrWuWM=;
        b=tHJqbbRkEwRxQmZId+cskGhlnLyS11p6UceeEzBJLraAgCpd8FeEGQcleMgWeti+gH
         Hg8w7qHoXKW+vgT4GjYuYIgPeDHhJ5QBQHXN8HER3K5DfLjs3p1f3pemERYJslq2J13q
         vmE3UPDUdCaiwY+/wK3xx7bqTf5cZAQhT4xz15/3KfguRLsxKiAW1j7vjNlmg0D2apYG
         TZHRgXo9et7o47e5EUybJQHuTZ9FQoWD+LOexd36osWqjBETGWpovauIvmWJmLflTFKq
         Y+VqERNayAQJXQ164zw+L+wrgenbHMAAY5jB6l2C8CgzX5bV2wBCcNeZ7aVvPLOlA9vK
         Pd2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZbPZwup;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id 26si467644lfr.13.2020.12.07.00.28.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 00:28:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id e25so12848932wme.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 00:28:24 -0800 (PST)
X-Received: by 2002:a1c:5605:: with SMTP id k5mr17103682wmb.99.1607329704162;
        Mon, 07 Dec 2020 00:28:24 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id 90sm14179953wrl.60.2020.12.07.00.28.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 00:28:22 -0800 (PST)
Date: Mon, 7 Dec 2020 09:28:13 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <X83nnTV62M/ZXFDR@elver.google.com>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20201206201045.GI1228220@cork>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dZbPZwup;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Sun, Dec 06, 2020 at 12:10PM -0800, J=C3=B6rn Engel wrote:
> On Sun, Dec 06, 2020 at 06:38:45PM +0100, Marco Elver wrote:
> >=20
> > Toggling the static key is expensive, because it has to patch the code
> > and flip the static branch (involves IPIs etc.).
>=20
> I see.
>=20
> > At that point, you'd need 1) a very large KFENCE pool to not exhaust
> > it immediately, and 2) maybe think about replacing the static key with
> > simply a boolean that is checked. However, this is explicitly not what
> > we wanted to design KFENCE for, because a non-static branch in the
> > SL*B fast path is not acceptable if we want to retain ~zero overhead.
>=20
> On x86 the difference between a trivially-predicted branch and a NOP
> (assuming that's what a static branch turns into) it about half a cycle.
> I haven't measured slab/slub, but my allocator takes ~40 cycles if the
> thread cache hits and ~110 cycles on a miss.  Presumably slab/slub is
> closer to the 110 cycles figure.  Therefore a regular branch would add
> about .5% overhead to the allocator.

That seems reasonable, but our benchmarks suggested something else.

We had a naive version, although that version used a per-CPU counter to
enter KFENCE. It did:

	if (count-- <=3D 0) { allocate with KFENCE; reset count to non-zero value;=
 }

I ran benchmarks where count was (2^31)-1, so only the branch and
decrement were in the fast-path. That resulted in a 3% throughput
reduction of the benchmark we ran (sysbench I/O). Details here:
https://github.com/google/kasan/issues/72#issuecomment-655549813

I hardly believe that the per-CPU decrement alone contributed to the 3%
system throughput reduction.

> In profiles I typically see the allocator consume 1% of overall CPU,
> sometimes 5% in particularly allocation-heavy workloads.  So overall
> overhead would be 50-250ppm.

The 3% slowdown we saw with the naive counter-based version suggests
it's worse than that. At least for certain workloads. Unfortunately, we
had to assume the worst case, and design for that.

> Static keys use text_poke_bp().  The do_sync_core() looks fairly cheap,
> I cannot find it in profiles.  Most of the cost is in the generic
> interrupt processing, but let's assume that to not matter either.  That
> leaves the text_poke_bp(), which appears to consume 90% of a single CPU
> with We use CONFIG_KFENCE_SAMPLE_INTERVAL=3D1.  Or .9% with the default
> value.  To match the 50-250ppm cost, you need 36-180 CPUs.
>=20
> Please check my calculation, but it appears that static keys are bad for
> performance even with your default config.

Something here is wrong, as in the end what matters is if the full
system workloads end up with measured ~zero overhead.

For our synthetic benchmarks, and a somewhat small'ish VM (8 CPUs),
100ms sample interval results in ~zero overhead, i.e. no measurable
difference to non-KFENCE baseline.

On real production workloads running on real servers, using 500ms (and
probably lower, but we wouldn't go there anyway) showed no measurable
difference to non-KFENCE baseline. And this is what matters for us!

But coming up with a one-size-fits all solution based on benchmarks and
incomplete data is hard, so let's try the following: If you're already
willing to trade off 1-3% performance at the cost of much higher sample
rates, by all means -- and do feel free to switch the static branch to a
dynamic branch. We can make this a Kconfig option, and compile KFENCE
with one or the other. For your usecase, that might be the right
trade-off. For ours probably not, because we were getting negative
feedback even thinking about adding a new dynamic branch to the
allocator fast path. :-)

Please try the patch below and let us know if this improves your
1ms-sample-interval setup (of course set CONFIG_KFENCE_STATIC_KEYS=3Dn).
If that works better for you, let's send it for inclusion in mainline.

> > And KFENCE is not designed for something like 10=C2=B5s, because the
> > resulting overhead (in terms of memory for the pool and performance)
> > just are no longer acceptable. At that point, please just use KASAN.
> > Presumably you're trying to run this in some canary environment, and
> > having a few KASAN canaries will yield better results than a few
> > KFENCE canaries. However, if you have >10000s machines, and you want
> > something in production, then KFENCE is your friend (at reasonable
> > sample intervals!) -- this is what we designed KFENCE for.
>=20
> My impression is that KASAN has noticeable performance implications.
> And that's basically a binary decision, you either enable it or you
> don't.  KFENCE is attractive because the overhead is low enough that
> people don't notice.  And I can move a slider to adjust overhead to some
> value I'm comfortable with.  Am I wrong?

Correct.

If you have special test kernels that only run tests, we still recommend
KASAN there.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Mon, 7 Dec 2020 00:45:59 +0100
Subject: [PATCH] kfence: Add option to use KFENCE without static keys

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
 include/linux/kfence.h |  9 +++++++++
 lib/Kconfig.kfence     | 12 +++++++++++-
 mm/kfence/core.c       | 14 ++++++++++----
 3 files changed, 30 insertions(+), 5 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 76246889ecdb..4178bbb8d58e 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -17,7 +17,12 @@
 #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
=20
+#ifdef CONFIG_KFENCE_STATIC_KEYS
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
index 933b197b8634..83045e2b9a37 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -88,11 +88,13 @@ struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NU=
M_OBJECTS];
 static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_freelist=
);
 static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freel=
ist. */
=20
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 /* The static key to set up a KFENCE allocation. */
 DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
+#endif
=20
 /* Gates the allocation, ensuring only one succeeds in a given period. */
-static atomic_t allocation_gate =3D ATOMIC_INIT(1);
+atomic_t kfence_allocation_gate =3D ATOMIC_INIT(1);
=20
 /* Wait queue to wake up allocation-gate timer task. */
 static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
@@ -590,16 +592,20 @@ static void toggle_allocation_gate(struct work_struct=
 *work)
 		return;
=20
 	/* Enable static key, and await allocation to happen. */
-	atomic_set(&allocation_gate, 0);
+	atomic_set(&kfence_allocation_gate, 0);
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	static_branch_enable(&kfence_allocation_key);
+#endif
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
+#ifdef CONFIG_KFENCE_STATIC_KEYS
 	static_branch_disable(&kfence_allocation_key);
+#endif
 	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_inter=
val));
 }
 static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
@@ -705,7 +711,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size,=
 gfp_t flags)
 	 * sense to continue writing to it and pay the associated contention
 	 * cost, in case we have a large number of concurrent allocations.
 	 */
-	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) =
> 1)
+	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_all=
ocation_gate) > 1)
 		return NULL;
 	wake_up(&allocation_wait);
=20
--=20
2.29.2.576.ga3fc446d84-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/X83nnTV62M/ZXFDR%40elver.google.com.
