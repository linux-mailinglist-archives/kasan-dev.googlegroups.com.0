Return-Path: <kasan-dev+bncBCMIZB7QWENRBGODX6WQMGQERQKUKSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF9368393E1
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 16:56:10 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-40e74860cb0sf21656185e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 07:56:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706025370; cv=pass;
        d=google.com; s=arc-20160816;
        b=GwUQ9DFn3b3e7RrLjAcNwZGx2hvKbC0HEoSTuTI8d278bKcKC3inVN9eI5Y1PSpZr4
         7dSWiqhKGH3tS87oRDQHkwZOtHNXzRgpTa0qaOuCNTxx20fV1UwxonFuchnib41wlBsY
         aWhtmsb+4u3Qlz5BCQygqjRLwtOmhscl5dKAo3CZ5YkxEpRR4dWrWjbXktmtdp5HmvkL
         wyaZG6aDsQ9rnmebGPrjelpmaHVqNpPKAxbodUgNw05oPfUYGbPyuvKW/8/Sh3sE8fUa
         QuOQR/OePdCIilpSmt0xlPoNrZlqJNebRvRKybwJeZ060v/Bn5OXzVwWdyBbSzeS4nU7
         Aftw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ILhYZziFcHTJEGB+W2CbFYHJ27E8DpwSlS6wbvtR3h4=;
        fh=TvE5boxPg6pxdtepY3sVcLj9yHbWr3M5U0veyU3Yi+w=;
        b=xFrGQQ+J9VvJ4EavirP1hF1dPaFzoS1wEhydPemjvAwrOncY9jm5+IVS+Tg92SJCs4
         VQCtGPuvcrPRgFFy77y/PWD3ghh1DdKCuM7JjHfh48hQUCCPSyZNCp2ySN6K69Jc8TMu
         zkMWiRixBkDzwZUE3xg84dp7RiRCVfZPgk8zw4MTK92KxhEu+TDNIN6FbFRIz2FBbuDb
         lw/XnlT+gUfL/Z414LsPlKFEZOvMHfrqgSKnTdwldJ+sAy1SBwqQUuLhaI0LBW5clHXq
         7/WOQl1Eu0sqskK1EYAmSmqK/tc6zo7UqznrdvTi3jjFRi4/zZYLm6faNuSUOPpMfyjI
         n6kQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nEVaGO53;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706025370; x=1706630170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ILhYZziFcHTJEGB+W2CbFYHJ27E8DpwSlS6wbvtR3h4=;
        b=W5kHauD2fJ62TAZS6a1CSunLJTC2N8QOpNn0uF/W+EjxpJ9H9q2z3Py7tcYJ1BGXSo
         9T11rR/zjoxEHf5YFpnr2+w0lUuqzSI2ErcAT3OxphL6p/MiUZljyPujypeMixDpDKDS
         KIlGQokimeynV4Sf2RS7Y3v3kJIY1r/jEAguEZvCnu5tEdnTxwoJC4KS+15q4kW47ROM
         FTLzOMf/GJctx1hGgbOaR3RBhvLclHPc26SMI25ROLpX2VoMCuVWwJpm6Kg8F8juGQzA
         ZTt48AB7Efzt+VDLg9FZQOaMVZxUr6FIQFWQ3NZNUG2jU0mjUWDzZ8qTT//jGaBtZnx6
         NQCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706025370; x=1706630170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ILhYZziFcHTJEGB+W2CbFYHJ27E8DpwSlS6wbvtR3h4=;
        b=UXsdHrDX9i8TTqqQ2XhilRXV+v3J7BcuTPdmhCM2DV0H3g/fwDlAPe270zA0QrvZoI
         kGZ7pU/SrPcPhMTm5l2TKTOgIT9Ee1cC6C5PM5UTjgiXmTExMz0S4PqQf7/erMqV6Dl1
         5rv2TEgUiGuK/rr5XlxdnRkeBQtj9RhrsZnlSSEjmUE61oE6hwwvo1CSIht/a4PNNque
         mcrBBygCG2cCklpaClveLVrNH8vN2QRQkcE1L+oMPZYm1o9XbqoMgrHAAXZVK9NBz4LO
         VBZOuzc2hnwpw2rNBqTWHeeRYW/+naYc+AaSExi3Z8dRXFFN7fLlZ2xglJeq0vChqStp
         sKHw==
X-Gm-Message-State: AOJu0YzrTE6Y6GJW3FhkcfdZNeoOOaXGiHS0Vi0hvgpT4wvn9Npn9JO+
	YjCTIzwu3cS4jzhDH85FrIZo/3Xdxnqjc3/hDu3ofeiP2WkAFCbk
X-Google-Smtp-Source: AGHT+IH5YKcEGxwn8VEXUe609ZZZbL7fUV80OHtkFCCGioWYtD5CDx9MIRfwQs4Kf+odaC249Z1xRQ==
X-Received: by 2002:a05:600c:5409:b0:40e:6240:3293 with SMTP id he9-20020a05600c540900b0040e62403293mr271340wmb.40.1706025369571;
        Tue, 23 Jan 2024 07:56:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c94:b0:40d:5b7a:e302 with SMTP id
 bg20-20020a05600c3c9400b0040d5b7ae302ls68845wmb.2.-pod-prod-03-eu; Tue, 23
 Jan 2024 07:56:08 -0800 (PST)
X-Received: by 2002:a05:600c:1f90:b0:40e:a447:9fb2 with SMTP id je16-20020a05600c1f9000b0040ea4479fb2mr248039wmb.18.1706025367966;
        Tue, 23 Jan 2024 07:56:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706025367; cv=none;
        d=google.com; s=arc-20160816;
        b=Gg8vY6Crz264GzzsJl18AnlLYwDaNKmH4EzeHjC/2x94VjSuzaqxgCVNs3yvjH6WZ+
         EcX12NAOPqqzfrfC3w3N2Q8Fr7C2cQ5yYgm/vcsOryc9wiLGFr3A/H/2PC6oYD94DCRg
         EjQ3z8bmRKr0mg4JRn2G/hgUQhHRiCytoNe5DKOiLgMYFZvR9aUs2aXXQ9W8oy3t/YYc
         ZRmp4vxvj127vvz83jZ6cbG4/bRRyr0zHBdEh7bToC/UetJM2brcgBKsMoq5ZUtwMjjp
         vsT/PEkPt3uW8tUpd7/H/yMiWCDb5O9A8PVeWc/ZQn/Ty3V1GKg0Rb9ihSyZXDOByw0M
         rgpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EBv30KMy0zvXmwC7oxK4cZSZ9HSjQvy5SlIH3Zj4wIY=;
        fh=TvE5boxPg6pxdtepY3sVcLj9yHbWr3M5U0veyU3Yi+w=;
        b=hdxZEPROyb56ZwWjUdCVE0Pe/BpnU1D6lhLQHs5tsAvr9+kMyCMUOS2YyGNsxQsoI/
         VBvB0/yeDf5uScWbPiDDp0zWRHoC/WBTg+AeOD/lEkGyplQra7ulLedNcu46HZyz/2Lv
         zlxR8F6HPUW4xAKNKvJBVCZoABJ4lc9szaAU1ljh0NOLYO2lFH3eKgdfSazOrZJdKzlt
         2uhr3cB9U/0NcArFgM0qNGEqVc8QqlScNUL5zBzzcG7TVbbSl2Yb5qvp0xHlD4u+eU16
         /+hNxeRxcBFGGHEqof2nq3EJRqUktiriHzSyRkEQOgRowm3i1iXnUs2q7fweNNktfFwc
         okJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nEVaGO53;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id i12-20020adffc0c000000b00337d940043asi344432wrr.5.2024.01.23.07.56.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jan 2024 07:56:07 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-50eb9d41d57so2494e87.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Jan 2024 07:56:07 -0800 (PST)
X-Received: by 2002:ac2:4d85:0:b0:50e:7be0:3ac1 with SMTP id
 g5-20020ac24d85000000b0050e7be03ac1mr149756lfe.6.1706025367012; Tue, 23 Jan
 2024 07:56:07 -0800 (PST)
MIME-Version: 1.0
References: <20240122171215.319440-2-elver@google.com> <Za_g6QkbGoAcXBNH@elver.google.com>
In-Reply-To: <Za_g6QkbGoAcXBNH@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jan 2024 16:55:54 +0100
Message-ID: <CACT4Y+ZcWsArFZs5E8actLz1q2L4-juptLAcVPp2BcjkdscCtQ@mail.gmail.com>
Subject: Re: [RFC PATCH] stackdepot: use variable size records for
 non-evictable entries
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nEVaGO53;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 23 Jan 2024 at 16:53, Marco Elver <elver@google.com> wrote:
>
> And on top of this we can make KASAN generic happier again:
>
> Objections?

Not doing refcounting/aux locking for generic KASAN makes sense to me.

> ------ >8 ------
>
> From: Marco Elver <elver@google.com>
> Date: Tue, 23 Jan 2024 12:11:36 +0100
> Subject: [PATCH RFC] kasan: revert eviction of stack traces in generic mode
>
> This partially reverts commits cc478e0b6bdf, 63b85ac56a64, 08d7c94d9635,
> a414d4286f34, and 773688a6cb24 to make use of variable-sized stack depot
> records, since eviction of stack entries from stack depot forces fixed-
> sized stack records. Care was taken to retain the code cleanups by the
> above commits.
>
> Eviction was added to generic KASAN as a response to alleviating the
> additional memory usage from fixed-sized stack records, but this still
> uses more memory than previously.
>
> With the re-introduction of variable-sized records for stack depot, we
> can just switch back to non-evictable stack records again, and return
> back to the previous performance and memory usage baseline.
>
> Before (observed after a KASAN kernel boot):
>
>   pools: 597
>   allocations: 29657
>   frees: 6425
>   in_use: 23232
>   freelist_size: 3493
>
> After:
>
>   pools: 315
>   allocations: 28964
>   frees: 0
>   in_use: 28964
>   freelist_size: 0
>
> As can be seen from the number of "frees", with a generic KASAN config,
> evictions are no longer used but due to using variable-sized records, I
> observe a reduction of 282 stack depot pools (saving 4512 KiB).
>
> Fixes: cc478e0b6bdf ("kasan: avoid resetting aux_lock")
> Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")
> Fixes: 08d7c94d9635 ("kasan: memset free track in qlink_free")
> Fixes: a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack calls")
> Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> ---
>  mm/kasan/common.c  |  3 +--
>  mm/kasan/generic.c | 54 ++++++----------------------------------------
>  mm/kasan/kasan.h   |  8 -------
>  3 files changed, 8 insertions(+), 57 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 610efae91220..ad32803e34e9 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -65,8 +65,7 @@ void kasan_save_track(struct kasan_track *track, gfp_t flags)
>  {
>         depot_stack_handle_t stack;
>
> -       stack = kasan_save_stack(flags,
> -                       STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
> +       stack = kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
>         kasan_set_track(track, stack);
>  }
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..8bfb52b28c22 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -485,16 +485,6 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>         if (alloc_meta) {
>                 /* Zero out alloc meta to mark it as invalid. */
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
> -
> -               /*
> -                * Prepare the lock for saving auxiliary stack traces.
> -                * Temporarily disable KASAN bug reporting to allow instrumented
> -                * raw_spin_lock_init to access aux_lock, which resides inside
> -                * of a redzone.
> -                */
> -               kasan_disable_current();
> -               raw_spin_lock_init(&alloc_meta->aux_lock);
> -               kasan_enable_current();
>         }
>
>         /*
> @@ -506,18 +496,8 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>
>  static void release_alloc_meta(struct kasan_alloc_meta *meta)
>  {
> -       /* Evict the stack traces from stack depot. */
> -       stack_depot_put(meta->alloc_track.stack);
> -       stack_depot_put(meta->aux_stack[0]);
> -       stack_depot_put(meta->aux_stack[1]);
> -
> -       /*
> -        * Zero out alloc meta to mark it as invalid but keep aux_lock
> -        * initialized to avoid having to reinitialize it when another object
> -        * is allocated in the same slot.
> -        */
> -       __memset(&meta->alloc_track, 0, sizeof(meta->alloc_track));
> -       __memset(meta->aux_stack, 0, sizeof(meta->aux_stack));
> +       /* Zero out alloc meta to mark it as invalid. */
> +       __memset(meta, 0, sizeof(*meta));
>  }
>
>  static void release_free_meta(const void *object, struct kasan_free_meta *meta)
> @@ -526,9 +506,6 @@ static void release_free_meta(const void *object, struct kasan_free_meta *meta)
>         if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
>                 return;
>
> -       /* Evict the stack trace from the stack depot. */
> -       stack_depot_put(meta->free_track.stack);
> -
>         /* Mark free meta as invalid. */
>         *(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
>  }
> @@ -571,8 +548,6 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         struct kmem_cache *cache;
>         struct kasan_alloc_meta *alloc_meta;
>         void *object;
> -       depot_stack_handle_t new_handle, old_handle;
> -       unsigned long flags;
>
>         if (is_kfence_address(addr) || !slab)
>                 return;
> @@ -583,33 +558,18 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         if (!alloc_meta)
>                 return;
>
> -       new_handle = kasan_save_stack(0, depot_flags);
> -
> -       /*
> -        * Temporarily disable KASAN bug reporting to allow instrumented
> -        * spinlock functions to access aux_lock, which resides inside of a
> -        * redzone.
> -        */
> -       kasan_disable_current();
> -       raw_spin_lock_irqsave(&alloc_meta->aux_lock, flags);
> -       old_handle = alloc_meta->aux_stack[1];
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] = new_handle;
> -       raw_spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
> -       kasan_enable_current();
> -
> -       stack_depot_put(old_handle);
> +       alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
>  }
>
>  void kasan_record_aux_stack(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr,
> -                       STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
> +       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
>  }
>
>  void kasan_record_aux_stack_noalloc(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_GET);
> +       return __kasan_record_aux_stack(addr, 0);
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> @@ -620,7 +580,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>         if (!alloc_meta)
>                 return;
>
> -       /* Evict previous stack traces (might exist for krealloc or mempool). */
> +       /* Invalidate previous stack traces (might exist for krealloc or mempool). */
>         release_alloc_meta(alloc_meta);
>
>         kasan_save_track(&alloc_meta->alloc_track, flags);
> @@ -634,7 +594,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
>         if (!free_meta)
>                 return;
>
> -       /* Evict previous stack trace (might exist for mempool). */
> +       /* Invalidate previous stack trace (might exist for mempool). */
>         release_free_meta(object, free_meta);
>
>         kasan_save_track(&free_meta->free_track, 0);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d0f172f2b978..216ae0ef1e4b 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -6,7 +6,6 @@
>  #include <linux/kasan.h>
>  #include <linux/kasan-tags.h>
>  #include <linux/kfence.h>
> -#include <linux/spinlock.h>
>  #include <linux/stackdepot.h>
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> @@ -265,13 +264,6 @@ struct kasan_global {
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>         /* Free track is stored in kasan_free_meta. */
> -       /*
> -        * aux_lock protects aux_stack from accesses from concurrent
> -        * kasan_record_aux_stack calls. It is a raw spinlock to avoid sleeping
> -        * on RT kernels, as kasan_record_aux_stack_noalloc can be called from
> -        * non-sleepable contexts.
> -        */
> -       raw_spinlock_t aux_lock;
>         depot_stack_handle_t aux_stack[2];
>  };
>
> --
> 2.43.0.429.g432eaa2c6b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZcWsArFZs5E8actLz1q2L4-juptLAcVPp2BcjkdscCtQ%40mail.gmail.com.
