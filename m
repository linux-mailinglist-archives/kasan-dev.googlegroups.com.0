Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTEYW6FAMGQECPY5MQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EFC54173DC
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 15:02:05 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 12-20020ac2484c000000b003fcb3298d00sf5955050lfy.13
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 06:02:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632488525; cv=pass;
        d=google.com; s=arc-20160816;
        b=jfqjN2fbEfxpkWdTkahV/pgtBkl4JYlE/ViMI7gTSPEZbaHzjMCBuyp9bHopVHpw0K
         czsNfj9LvUUNH6cKO+tc3rxLVS+5n0xkS1B59A80RYiFIIi2eTOH0PR6poltzFo7o+AI
         FED3aBMg2/w3OOwPUHFXecy3DENA9ryfloaxm9SFuTy0UUNdQIDJaKriPPA7w1fMWOvv
         ZCsPbH0FgYhsgbr5X/djLuJo0iZ73UXd6prk5Ne+9+ShLvmrEAFV9aerinnebqgWSCxf
         PLusCjUNZAkvT1alFWXleSpa/cbyEBtu1Ouly3kmxPqBdkr7j/WyVeOYFKOvK0zHZXZY
         rZ0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=imFqG+JcmEDg8uIM74cAqlN0wUZMmp1TOdv9r1L9gyE=;
        b=Kf/88tzoTGCKfdkBg5JyC6+JRNGSEWvCcf7zyX+5+eYcfKfjXECV7vO/kYogG13HIr
         8KLnWGuJXHH6kgvv+JcDoRo0gH17diEdVkByf91ucHzyBK3W5pGZtRRgSeavwppBR7NS
         QkjdhYQ5XYepIU74v5wcYFfVGra+0rSZuryS+cA7CCSo8Kv0n9oQAugK0mMyEFWLsBkH
         KFBVfdQ7pp/aN+GwFg+8LYCVSOyGRgmZU3xqSknUMnlDeFp2DvCUt1zDcj63oV4ev62a
         BmQy4wSAWI9W/2sd7nmth73WGZTLri7CTig8MDaTstMxKsewn8YMn+SQ3T5FsUgXBrki
         J9NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fZaJHWBq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=imFqG+JcmEDg8uIM74cAqlN0wUZMmp1TOdv9r1L9gyE=;
        b=HuFZeq6zS/cooUbP+BSGb3pfcRKL+s51PTom5CLy/aHWmyHatV3uXck00X3YLKOIkm
         4BNYrP7Ea4hrzWxf0s3y/v6WCMlteVzy5KwprvxDRm+w8nNO6gZiItlPyqfrag0k+HZr
         sFF3yG1UwcwD88foY3QM4nPDm8Ciaou2KYt3h3oIpQUWUD8/vkPGrO8wt/npxmGp/TnO
         lB7iZLu4acrA49I0Mhpm0d06w2BkDWD+H8zC7+5/FaZO+braE2zfxegB+UOMG0vl8PAA
         PmoNL8RXzAGh0UZKaUG1vJC+seVFYb5zjonCVrYBNFNvystb2sfgVqjlVZBSLbgk176i
         IzcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=imFqG+JcmEDg8uIM74cAqlN0wUZMmp1TOdv9r1L9gyE=;
        b=UoapHbbHV7/GM8GAVHiw8RoyrbyJtpZHD/o2xklNky241x4qnk6ypALD1M8RmANvMx
         4RWKX+13tzxF0miKhDxVNXHieyKoU/m5XDQwivGH4gmL5UIZ3ZXWsmi9f8Rn/c57fSMM
         WIlG7mBCdk2izYdXuowSeooxTM+3t6lzDspW7KOgjiDfMYbfAGNR5StA7mF88/3v5DXL
         roT7i4v/MjKYjldYwVgT4QvkaPKLo77reeGXM8NGaZ04ZVl6RAqc3D6SL4+LcDNlI5fq
         xalemmfGyL+qjXJ56XEXJbtOmqWmrhSLN38Rdcpb65Q8OLWOWdoeizmiyBlQFRPGmHV7
         69gQ==
X-Gm-Message-State: AOAM533x1rhJ4xq6HobXZ4ZOLldSI0FWxuFfQ228RK68gDsVwEdG47sN
	nqRir7xY1krCr6qFfUInAoc=
X-Google-Smtp-Source: ABdhPJzN+vhY8G3WoloDegKjDiYty6mi1iNX6XJKmk35+CcNPlBFHWSlDh7BYabYX20dZO/PvDLNEg==
X-Received: by 2002:a2e:4a19:: with SMTP id x25mr11456971lja.114.1632488524700;
        Fri, 24 Sep 2021 06:02:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:324d:: with SMTP id c13ls47478lfr.0.gmail; Fri, 24
 Sep 2021 06:02:03 -0700 (PDT)
X-Received: by 2002:a05:6512:792:: with SMTP id x18mr9235197lfr.191.1632488523545;
        Fri, 24 Sep 2021 06:02:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632488523; cv=none;
        d=google.com; s=arc-20160816;
        b=Il7ffZlE+LVaNAlPgJywq22Kk3S7V4TXm+3+BvEf63pxsDz/yXDyURhrkUqBpTU0EJ
         x+GHZ0rK1EoO1nVSDXhqh8rVBhjD6jOYTaNJMF8aLFSTgDdBw7AOKJKOJi5DXIy42kLK
         y6bryX5Bq8etCP08y38NUSTsTzq1JjCa/ooB1JprWz3KVXQu5IZIuNUQOeOadrv9AP/F
         3FrdjqV8RYX3oXa20LeBS7j/0bzP4uecZRd1S4tuPe2+xoQ89YgkgEKZFIumdEWHFOqU
         TmfvBArFzR3zRa/yoxWvxTjKR+Cc7hW6tyPlbM8x/KwK6NhuoWwZ8ReYbgCORUO3l2NA
         p9Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/nem774aIDIH449b+9j/jMCwWdjaEqBhcPs9HQ8+G6o=;
        b=CVBWz6Qd7PEl2gj1484aoF+p56sq0HNTenonc9zXvT6IBOrpGjH0DW+7g0eF1Y4yMe
         Fd3k2BZsJA0BECbIn2jzmcKP1oDcSZqJ99w1aNu0PX3lFn8nQTw15hUfAHPPh6AhhDf7
         UhdRqHEJcSAyHOgoa9NrKB9onvcBWPiu9AF2nB9d09arKvNPUQ9UVwN2P0NlQvsifZcl
         OfLfQMz49zn4HU1ztN3vwrEFr7PEVJEuMa20en0h7qY0ySS9mRwfRI8ZxPxl4249/48f
         B9KnUnFDCK1NIi953Pjc+Pf0Q/OfBUwuZ6QIZiVtsgG43zYH3tkoDBL235ruwdFsFrxG
         huPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fZaJHWBq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id y20si436795lfb.10.2021.09.24.06.02.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Sep 2021 06:02:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id t8so27429939wri.1
        for <kasan-dev@googlegroups.com>; Fri, 24 Sep 2021 06:02:03 -0700 (PDT)
X-Received: by 2002:a7b:c453:: with SMTP id l19mr1935567wmi.7.1632488522987;
        Fri, 24 Sep 2021 06:02:02 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:594c:8b31:64da:f783])
        by smtp.gmail.com with ESMTPSA id n66sm8235632wmn.2.2021.09.24.06.02.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Sep 2021 06:02:02 -0700 (PDT)
Date: Fri, 24 Sep 2021 15:01:56 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Taras Madan <tarasmadan@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 4/5] kfence: limit currently covered allocations when
 pool nearly full
Message-ID: <YU3MRGaCaJiYht5g@elver.google.com>
References: <20210923104803.2620285-1-elver@google.com>
 <20210923104803.2620285-4-elver@google.com>
 <CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com>
 <CAG_fn=V31jEBeEVh0H2+uPAd2AhV9y6hYJmcP0P_i05UJ+MiTg@mail.gmail.com>
 <CANpmjNOh0ugPq90cVRPAbR-6qr=Q4CsQ_R1Qxk_Bi4TocgwUQA@mail.gmail.com>
 <20210923162811.3cc8188d6a30d9eed2375468@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210923162811.3cc8188d6a30d9eed2375468@linux-foundation.org>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fZaJHWBq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Thu, Sep 23, 2021 at 04:28PM -0700, Andrew Morton wrote:
> On Thu, 23 Sep 2021 15:44:10 +0200 Marco Elver <elver@google.com> wrote:
[...]
> > I'm worried about next_pseudo_random32() changing their implementation
> > to longer be deterministic or change in other ways that break our
> > usecase. In this case we want pseudorandomness, but we're not
> > implementing a PRNG.
> > 
> > Open-coding the constants (given they are from "Numerical Recipes") is
> > more reliable and doesn't introduce unwanted reliance on
> > next_pseudo_random32()'s behaviour.
> 
> Perhaps we could summarize this in an additional comment?

Hmm, on second thought, while trying to write the comment realized it's
unnecessary altogether. I've switched to just using hash_32() which is
probably better suited.

> Also, this:
> 
> +static u32 get_alloc_stack_hash(unsigned long *stack_entries, size_t num_entries)
> +{
> +	/* Some randomness across reboots / different machines. */
> +	u32 seed = (u32)((unsigned long)__kfence_pool >> (BITS_PER_LONG - 32));
> 
> seems a bit weak.  Would it be better to seed this at boot time with
> a randomish number?

Sure, makes sense.

Both fixes are included in the below fixup. (Let me know if resending as
v4 is better, but I've seen the patches already appeared in -mm.)

Thank you!

-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Fri, 24 Sep 2021 14:17:38 +0200
Subject: [PATCH] fixup! kfence: limit currently covered allocations when pool
 nearly full

* Simplify and just use hash_32().
* Use more random stack_hash_seed.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 18 ++++++++++++------
 1 file changed, 12 insertions(+), 6 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 58a0f6f1acc5..545999d04af4 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -10,6 +10,7 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/debugfs.h>
+#include <linux/hash.h>
 #include <linux/irq_work.h>
 #include <linux/jhash.h>
 #include <linux/kcsan-checks.h>
@@ -122,14 +123,21 @@ atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
  *	P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
  */
 #define ALLOC_COVERED_HNUM	2
-#define ALLOC_COVERED_SIZE	(1 << (const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2))
-#define ALLOC_COVERED_HNEXT(h)	(1664525 * (h) + 1013904223)
+#define ALLOC_COVERED_ORDER	(const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2)
+#define ALLOC_COVERED_SIZE	(1 << ALLOC_COVERED_ORDER)
+#define ALLOC_COVERED_HNEXT(h)	hash_32(h, ALLOC_COVERED_ORDER)
 #define ALLOC_COVERED_MASK	(ALLOC_COVERED_SIZE - 1)
 static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
 
 /* Stack depth used to determine uniqueness of an allocation. */
 #define UNIQUE_ALLOC_STACK_DEPTH 8UL
 
+/*
+ * Randomness for stack hashes, making the same collisions across reboots and
+ * different machines less likely.
+ */
+static u32 stack_hash_seed __ro_after_init;
+
 /* Statistics counters for debugfs. */
 enum kfence_counter_id {
 	KFENCE_COUNTER_ALLOCATED,
@@ -166,12 +174,9 @@ static inline bool should_skip_covered(void)
 
 static u32 get_alloc_stack_hash(unsigned long *stack_entries, size_t num_entries)
 {
-	/* Some randomness across reboots / different machines. */
-	u32 seed = (u32)((unsigned long)__kfence_pool >> (BITS_PER_LONG - 32));
-
 	num_entries = min(num_entries, UNIQUE_ALLOC_STACK_DEPTH);
 	num_entries = filter_irq_stacks(stack_entries, num_entries);
-	return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), seed);
+	return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), stack_hash_seed);
 }
 
 /*
@@ -759,6 +764,7 @@ void __init kfence_init(void)
 	if (!kfence_sample_interval)
 		return;
 
+	stack_hash_seed = (u32)random_get_entropy();
 	if (!kfence_init_pool()) {
 		pr_err("%s failed\n", __func__);
 		return;
-- 
2.33.0.685.g46640cef36-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YU3MRGaCaJiYht5g%40elver.google.com.
