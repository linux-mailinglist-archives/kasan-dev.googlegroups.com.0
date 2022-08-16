Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUMH56LQMGQE3GYEBLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 16F2D596005
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 18:20:35 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id w6-20020a056e02190600b002e74e05fdc2sf374602ilu.21
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 09:20:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660666833; cv=pass;
        d=google.com; s=arc-20160816;
        b=lNBzm42Bx20/cQiJ1z8hp2zEpIrDnZzD71b+r1sewymM6q5pEEwFiTfjm8wQr5Wjeg
         A5M93GtykIfBsSGYuEIb48eWDP36L/usRPR6laPW4/yYwrniESD0vTZoEmvE791p1JpB
         0MTX58GkByc6Sj4Qg4BThjYY6t6c1RdkpNqvw3unOrK/gPl9krNdCELGxmaI0+IDiJGp
         FD+VXiKyuyI356qM0gTrlYuV7DOOBmSWN4TtqHrGxJe2ekVvAjRstXYDJl5UJIpaAKYt
         V1NSCLih6aw8py8/UNxLufkc8HdiP4EcI2MtadWfIM+V7OojaQzwkNHy/5x568f193ON
         7rCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WLFcnTvRv163XMnyBH7GXOhJ7eRTQLrnAplc5jnUuKM=;
        b=DhwhUKA1GjclFXfFbBqUQbRXW6JWliZ7h51w4SWgeHyoLajEDYX14p4JnWLmyUOVCs
         ZFIOtrE5kHmGsJ76It5/quQZ/UMsOsknDq20IhyLiDtc/g+DOrK2X0U+bfd1IiiWGyOW
         h+tKNFpJIEgNs3Nud+oCvM+C+jDngxHoNIAiK4xQAVQe9kTzETg3Z8tJhURhIGYH+nxx
         5mfSrlZycmPvYEwajtNKpDHj4ebuLGaxSdDCKy2CkFgGzbAL9XbLWUUVjIMia9NoYwii
         gpZ4YOOTwL6RzX6TouoegvKPgsFymhiyEcrvV9rBukS1EubJ90oq9JtxYdqpcRk8zttB
         ieUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D6VUDRfg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=WLFcnTvRv163XMnyBH7GXOhJ7eRTQLrnAplc5jnUuKM=;
        b=tN7DLDQEsL+o36cY1s0c1p87xL2oabR47SDolM0lRRUzlqxXh++MLWMQRIcE0Nnmtl
         D+ypBX71kg+wWHGQA1yyBhGl6VTF4fFcUCw/SlfDLqM0FCj4IWmISrjMJ23OxrZZDZmy
         9sGGwrrVKE0vMCPWYmg6whc0c1fSdKXL8yCu5n5TNeSPXR/LbekpHGN9Q3avi+qdWGW9
         /XPyZnGGXm3QeYeIiHvN3bjFNv0xq5lh2tBMngulxSNDQxKQzT04g+g7LK1UZIGxQqpu
         xvyjT4D2RXns9xD7RNt8yoMfrFgr/O3q5g0AANWMAVtyo3f7/iCF9JSNL8iqAfAYmsTy
         bCvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=WLFcnTvRv163XMnyBH7GXOhJ7eRTQLrnAplc5jnUuKM=;
        b=2oapydVzbBrqSGfPwTJ862naRReiBqM4b7z3/bo2iuxhzNhbs03aKvCVIZYjPPFZMZ
         tmdowx8BC0ik/ENzF/lUK1+S37hDT5bgmukCsgcszVRQwXWaZeDUrcxhPSsm0sJ+IM81
         9lxY7NW8YvTluttkLA0YmSOftovL+GViOxldyqMS5JJFmgMeK6RCFHgeYjTlZXHprBI9
         LcB6uXMQwiluSy1SaRQFXfNDUE9DQvkuzfgO+UO1uiccmpEcQrAV+FshE0rGGvrRODFw
         VYoZDsrcIUbAHT3jbDwQI8dFz9/+BPiYTf3Jmnt5MvTNBETW2zKKESr4Er2Fe+N4Y2t1
         INew==
X-Gm-Message-State: ACgBeo01qAwaX7LI9D4Rj4VRXPsvASKu438Ax7VtFQ5sujBlCAl2p55j
	6MiW/KbMNN0TrqVpKTBaVMk=
X-Google-Smtp-Source: AA6agR7BjfMrfeJDlKkwWtkj4W3ZzjZHHWa+FEHwba2xnXv7PVGlMjm9nSQBRZxWUIF+/5exSjOE1g==
X-Received: by 2002:a02:cb5b:0:b0:341:aebb:d13 with SMTP id k27-20020a02cb5b000000b00341aebb0d13mr9997528jap.176.1660666833661;
        Tue, 16 Aug 2022 09:20:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:95e9:0:b0:343:44a5:a2d1 with SMTP id b96-20020a0295e9000000b0034344a5a2d1ls3058229jai.0.-pod-prod-gmail;
 Tue, 16 Aug 2022 09:20:33 -0700 (PDT)
X-Received: by 2002:a05:6638:2411:b0:346:86a0:d325 with SMTP id z17-20020a056638241100b0034686a0d325mr4868445jat.28.1660666833134;
        Tue, 16 Aug 2022 09:20:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660666833; cv=none;
        d=google.com; s=arc-20160816;
        b=b+kCfI1pgfY6rx7SIEKxGsL2mDD4wn5r1Xo7Jc8bweye+9h5ts8AEXRDmHzMrTtEhm
         vKzQFmwc0kE6MAjSc2Dgrf24i8c0GhdOEHzGW2HEqrPi9Oj5zolnILlLvgw8klHdV9vZ
         lOrGZiePzMGuHhH62QVoTpjm8lCoJaK0zZUj59YrJO9f/qZzskD2ugOEbIXHmsEWOxSY
         ETHZHr0ExhOEvklxyqESdBlRIHGWtAmxTEaifOr0wODePDOnyPCrqmKqFZBhbRLRVqtx
         iO/5KaPwi+zEckw6uJLsQAa6R9XFefuOEwKpfsx6bO7yvJ5++1/gLLddFvyzQuc7a7Rk
         kayg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TmDmP2Yh2xB0Nw2rEpzh522PfockFUs65PSBK5ilao8=;
        b=p8/x2BOtiulny4YOauE1aNemJNfk/CTmIIibJlJaVn+3ec3NrhNbNWVwoUeTiFkrSv
         ODdh3ktYYg4aCYLSgt+c4Xotnm+RGizzdu3QWJArGSvhv52z3qSGMjMMHaq78cUenb79
         XL7uOOMRiC1eQsYiHAq1tVthp6LgcboryDfevBYvk+HEwQ/5/E3te/uGdSM2FCzsODn7
         GxGyQdQwBh+S29xKPEWQETA1lS/ZWWObK+Nml+jo6QnNP6OSwDfskClSyZ+avsoTYfLV
         rvhRDr0pp1qkT9DONjBS3iT3gcJNQou2QwX+g4QVnaDt6E5xvdxxiRt9jZznPxEQZxC8
         6fMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D6VUDRfg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id t7-20020a056e02160700b002e5af4be253si270364ilu.0.2022.08.16.09.20.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 09:20:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-324ec5a9e97so164466127b3.7
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 09:20:33 -0700 (PDT)
X-Received: by 2002:a25:828c:0:b0:68f:6fd6:56b3 with SMTP id
 r12-20020a25828c000000b0068f6fd656b3mr1106642ybk.611.1660666832507; Tue, 16
 Aug 2022 09:20:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220816142529.1919543-1-elver@google.com>
In-Reply-To: <20220816142529.1919543-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Aug 2022 18:19:56 +0200
Message-ID: <CANpmjNNFkU4QEmk7ULGsNzwK=dnyhP7zeCGdu9mevwwLNAD0cg@mail.gmail.com>
Subject: Re: [PATCH] kfence: free instead of ignore pool from kmemleak
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Max Schulze <max.schulze@online.de>, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Yee Lee <yee.lee@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=D6VUDRfg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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

Per Catalin's comment in
https://lore.kernel.org/all/Yvu4bBmykYr+0CXk@arm.com/T/#u
this patch should be ignored, because 6.0-rc1 is fine. We just have to
fix 5.19 by reverting 07313a2b29ed from it.


On Tue, 16 Aug 2022 at 16:25, Marco Elver <elver@google.com> wrote:
>
> Due to recent changes to kmemleak and how memblock allocated memory is
> stored in the phys object tree of kmemleak, 07313a2b29ed ("mm: kfence:
> apply kmemleak_ignore_phys on early allocated pool") tried to fix KFENCE
> compatibility.
>
> KFENCE's memory can't simply be ignored, but must be freed completely
> due to it being handed out on slab allocations, and the slab post-alloc
> hook attempting to insert the object to the kmemleak object tree.
>
> Without this fix, reports like the below will appear during boot, and
> kmemleak is effectively rendered useless when KFENCE is enabled:
>
>  | kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
>  | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
>  | Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
>  | Call trace:
>  |  dump_backtrace.part.0+0x1dc/0x1ec
>  |  show_stack+0x24/0x80
>  |  dump_stack_lvl+0x8c/0xb8
>  |  dump_stack+0x1c/0x38
>  |  create_object.isra.0+0x490/0x4b0
>  |  kmemleak_alloc+0x3c/0x50
>  |  kmem_cache_alloc+0x2f8/0x450
>  |  __proc_create+0x18c/0x400
>  |  proc_create_reg+0x54/0xd0
>  |  proc_create_seq_private+0x94/0x120
>  |  init_mm_internals+0x1d8/0x248
>  |  kernel_init_freeable+0x188/0x388
>  |  kernel_init+0x30/0x150
>  |  ret_from_fork+0x10/0x20
>  | kmemleak: Kernel memory leak detector disabled
>  | kmemleak: Object 0xffffff806e24d000 (size 2097152):
>  | kmemleak:   comm "swapper", pid 0, jiffies 4294892296
>  | kmemleak:   min_count = -1
>  | kmemleak:   count = 0
>  | kmemleak:   flags = 0x5
>  | kmemleak:   checksum = 0
>  | kmemleak:   backtrace:
>  |      kmemleak_alloc_phys+0x94/0xb0
>  |      memblock_alloc_range_nid+0x1c0/0x20c
>  |      memblock_alloc_internal+0x88/0x100
>  |      memblock_alloc_try_nid+0x148/0x1ac
>  |      kfence_alloc_pool+0x44/0x6c
>  |      mm_init+0x28/0x98
>  |      start_kernel+0x178/0x3e8
>  |      __primary_switched+0xc4/0xcc
>
> Reported-by: Max Schulze <max.schulze@online.de>
> Fixes: 07313a2b29ed ("mm: kfence: apply kmemleak_ignore_phys on early allocated pool")
> Fixes: 0c24e061196c ("mm: kmemleak: add rbtree and store physical address for objects allocated with PA")
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Yee Lee <yee.lee@mediatek.com>
> ---
>
> Note: This easily reproduces on v5.19, but on 6.0-rc1 the issue is
> hidden by yet more kmemleak changes, but properly freeing the pool is
> the correct thing to do either way, given the post-alloc slab hooks.
> ---
>  mm/kfence/core.c | 11 ++++++-----
>  1 file changed, 6 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c252081b11df..9e52f2b87374 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -617,12 +617,13 @@ static bool __init kfence_init_pool_early(void)
>
>         if (!addr) {
>                 /*
> -                * The pool is live and will never be deallocated from this point on.
> -                * Ignore the pool object from the kmemleak phys object tree, as it would
> -                * otherwise overlap with allocations returned by kfence_alloc(), which
> -                * are registered with kmemleak through the slab post-alloc hook.
> +                * The pool is live and will never be deallocated from this
> +                * point on. Remove the pool object from the kmemleak phys
> +                * object tree, as it would otherwise overlap with allocations
> +                * returned by kfence_alloc(), which are registered with
> +                * kmemleak through the slab post-alloc hook.
>                  */
> -               kmemleak_ignore_phys(__pa(__kfence_pool));
> +               kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
>                 return true;
>         }
>
> --
> 2.37.1.595.g718a3a8f04-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNFkU4QEmk7ULGsNzwK%3DdnyhP7zeCGdu9mevwwLNAD0cg%40mail.gmail.com.
