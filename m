Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRFVVKQQMGQEUV5NGPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id B09F76D4030
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Apr 2023 11:22:13 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-5417f156cb9sf285838707b3.8
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Apr 2023 02:22:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680513732; cv=pass;
        d=google.com; s=arc-20160816;
        b=xgxdbFutQhd3ZAxkEUQ5hyR6Tp45NVw+LgOELVO/NhC0l2G710PrbnVWt00a4xgCoO
         lbDnUlCJPXfwHVOrnRfYkBYKRE8vZq6DL6ny4kS2NB9FnhvxnDykG+HoVXD961cbZwwg
         Gb41KiEJJ+xRmo9H0qriB6LA/Ac6D/wC+J+FqJXeigbLkMuvIuV67uHR/ETKNJuV0t6H
         pHrS/sIszyL8xP+5vLWr/O/4XAuw/bBrqmwRDIbhjmwTKw0ZSEd9dcadiebDQLsiiUUS
         pu052dXjDD3pPR5jykK2XWcJX+0aq9Fr3aUjl5FEUh7VDzwrKAnnQ+PHsR/U7JIfFqCE
         fybA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k9bZ5nEsnnhT5mQbgJKiKTnx1o6ZcVYv47WCkHeAMls=;
        b=py+9J7mMOcEcUO6+96V6ILzxsOPekPXWUmemiuPepjhNt9itEsaFEyQ48RA8ghAcUE
         I6x61jwt3Sp61B2OqZZcUuLtZSO5sb/RbL3lvA+QURQIc3k5ESpej7MWaPJ+2k9haj5H
         DSEDLe0LHNjeVE1yjkTQIb//9x+cZ6AtKg1izgXpUxpgxjGsexlFN+1EKcXI77XORhpo
         2/sODvAGO2rIykHxPXkMTX1WyXGDz6BkwqzTFm2gpkGD6Zluu4CJD9jzAScddgkDTakU
         JlKahR9OPzN/GaB9v2lDlkbjYPNgLPU6tdwMVGzojLr3Na1+O/a6yyI4DTXTP/Xq3WUQ
         Hctw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kDlt0pG8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680513732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k9bZ5nEsnnhT5mQbgJKiKTnx1o6ZcVYv47WCkHeAMls=;
        b=d70rIdSpXA9cN/ASi7iUG95/3ggNFdLxQrthhKyvBQKQsJ7FLbgOaDb2r9xAJemuvm
         GEwGgqMqo6d4CFuBGr6PliYBv1WSq0VRS51wk4Ench8wsIEp+kP+zxuNdsyQRDK8MrKo
         1+NspJ8UwHwFJdFQewZvOyRHwRuyrFlLogxLbGjTycy89yJarPLn2rzi2/csnDKnzYRG
         mzHDLNHk+ZsP1eeafxcD6fNNGrNdW2FRWEQ5ob4auzwmX3j1gorDHqEdef2e4F+F+HRc
         q71DP4EZL8EMibNU0F/c6xpr6ROMSu8HDEwYw1favAlOO3X0GUanr6AUCmIbdg9F4WH4
         q+vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680513732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=k9bZ5nEsnnhT5mQbgJKiKTnx1o6ZcVYv47WCkHeAMls=;
        b=kYv/MmRO2mWWmmxNPQUbXsC1fovraOUh5E9rADrZ/k37gJKA6Wa5Vym33eY5S5Us8s
         bXVIJ17dNihsDpTnbixUZRRYIvPY+48hctKv7+18nxz4S1HoBV5ey7fDzpPzhoZCPzeJ
         cZJv6y5B3x9pzubQmpxCn1AxhS0RpZf8u29/uAHZagne67pM5OCoOjZWXltjmh3kKsmB
         Vm8SgQgXet9i016bvGfqYN5k1/fM1kQMPsp9CorORvdBz9SkJSFlAVV/xluj++SBAPIq
         o+lvTocmgKlXZ3uN6jzOihA1ZpxZlOvnsU/eTVZoOSFrGcKRaynkKfCTyxDaR0zB2i7C
         8JFw==
X-Gm-Message-State: AAQBX9eGZbyu8UTe5PO8+8ty5LhwVxls9NTRqaLQpLqjUzu1TO0JDD1T
	1Nopo1AI2ViShhsKF+OBgsg=
X-Google-Smtp-Source: AKy350Zlfv1SRP1JBivBZHVK3NwQGmSRSf4RVkDeddw+HLOs9tTOeVy7fksnOgInb4GIC+HULsQA/Q==
X-Received: by 2002:a25:db43:0:b0:b7d:5a67:8c6e with SMTP id g64-20020a25db43000000b00b7d5a678c6emr14198392ybf.6.1680513732331;
        Mon, 03 Apr 2023 02:22:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:314:b0:541:a1f8:430b with SMTP id
 bg20-20020a05690c031400b00541a1f8430bls6767565ywb.3.-pod-prod-gmail; Mon, 03
 Apr 2023 02:22:11 -0700 (PDT)
X-Received: by 2002:a81:4803:0:b0:541:bc8f:9c5f with SMTP id v3-20020a814803000000b00541bc8f9c5fmr33550901ywa.38.1680513731622;
        Mon, 03 Apr 2023 02:22:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680513731; cv=none;
        d=google.com; s=arc-20160816;
        b=lCIhm7V43p/2wkEV30ZLgTZHhwyzK2uHLD7UhQG853t2TmtvUGjjv+uvN1ixDIrKC4
         THzQZvU1yBcXOGUdz8456b01C6DCK6cn/FkizUODYeDfu+7zZl3qTvxfC3SjgtN/PJAT
         2Lo1fyxD1kab8WwWxlPhBUpigmp6s1F4jQ+9rxjXkAu640UIsZEefvDY1u6jx96WgunM
         GQzouJ5GlA8CpC/vRdOo25IQWESOamoLl2ISiwfDzAz8mMDa6xox6kzkoxbqwF50xSWo
         /fQBVdE2Y+tcSnaSTelnB+PS5YtI32lIpmkw9erWfvDQB2JiGTK88KAJ6TXrIJZ65hHZ
         Wmvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AK7BPbsHL4WuhYBXq1AZIp6CGkn7dRfiNDxu4r9Cdnk=;
        b=uCQ9ZON0gf9qOfj7ExqEHgb2ISjJ7yq5bRwbkVKlTU0xK7LeqKQ9wblOwRAPhjk9Di
         CnUG3apSA8186GgBETepMa6WbypC+zhY8z9pw7pmGH8NwK7oSwGIO11JcL1eVsoUWkzn
         U7eGXluMdthSNgn8l4ywiS3+dCHlhGjvIqID/aadXRxWHyPne2OcjtKOT9wQ1L9H1BoJ
         JDs2fsC3kxmRvSeEyfPDM+D3CBvILiSWfZOSNyuI6WJa+09zS9pEpDnyafUBk6GaJTmp
         nR1U1XwwqplJVRT2O2LFuXVI9QFuGGeeKtr0nmhb1OSz4+c4V4wKlniDIcJuxs0kVzc5
         ci8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kDlt0pG8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id da8-20020a05690c0d8800b005343a841489si512117ywb.3.2023.04.03.02.22.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Apr 2023 02:22:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id e13so12585772ioc.0
        for <kasan-dev@googlegroups.com>; Mon, 03 Apr 2023 02:22:11 -0700 (PDT)
X-Received: by 2002:a05:6602:192:b0:753:2cc5:c8b7 with SMTP id
 m18-20020a056602019200b007532cc5c8b7mr23217242ioo.3.1680513730984; Mon, 03
 Apr 2023 02:22:10 -0700 (PDT)
MIME-Version: 1.0
References: <20230403062757.74057-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230403062757.74057-1-zhangpeng.00@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Apr 2023 11:21:34 +0200
Message-ID: <CANpmjNMOJ9_AU++eNF=F9hwCveeJmM7r0sEQAf0a=0pOa=dGfg@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: Improve the performance of __kfence_alloc()
 and __kfence_free()
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kDlt0pG8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as
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

On Mon, 3 Apr 2023 at 08:28, Peng Zhang <zhangpeng.00@bytedance.com> wrote:
>
> In __kfence_alloc() and __kfence_free(), we will set and check canary.
> Assuming that the size of the object is close to 0, nearly 4k memory
> accesses are required because setting and checking canary is executed
> byte by byte.
>
> canary is now defined like this:
> KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))
>
> Observe that canary is only related to the lower three bits of the
> address, so every 8 bytes of canary are the same. We can access 8-byte
> canary each time instead of byte-by-byte, thereby optimizing nearly 4k
> memory accesses to 4k/8 times.
>
> Use the bcc tool funclatency to measure the latency of __kfence_alloc()
> and __kfence_free(), the numbers (deleted the distribution of latency)
> is posted below. Though different object sizes will have an impact on the
> measurement, we ignore it for now and assume the average object size is
> roughly equal.
>
> Before playing patch:
> __kfence_alloc:
> avg = 5055 nsecs, total: 5515252 nsecs, count: 1091
> __kfence_free:
> avg = 5319 nsecs, total: 9735130 nsecs, count: 1830
>
> After playing patch:
> __kfence_alloc:
> avg = 3597 nsecs, total: 6428491 nsecs, count: 1787
> __kfence_free:
> avg = 3046 nsecs, total: 3415390 nsecs, count: 1121

Seems like a nice improvement!

> The numbers indicate that there is ~30% - ~40% performance improvement.
>
> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
> ---
>  mm/kfence/core.c   | 71 +++++++++++++++++++++++++++++++++-------------
>  mm/kfence/kfence.h | 10 ++++++-
>  mm/kfence/report.c |  2 +-
>  3 files changed, 62 insertions(+), 21 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 79c94ee55f97..0b1b1298c738 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -297,20 +297,13 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>         WRITE_ONCE(meta->state, next);
>  }
>
> -/* Write canary byte to @addr. */
> -static inline bool set_canary_byte(u8 *addr)
> -{
> -       *addr = KFENCE_CANARY_PATTERN(addr);
> -       return true;
> -}
> -
>  /* Check canary byte at @addr. */
>  static inline bool check_canary_byte(u8 *addr)
>  {
>         struct kfence_metadata *meta;
>         unsigned long flags;
>
> -       if (likely(*addr == KFENCE_CANARY_PATTERN(addr)))
> +       if (likely(*addr == KFENCE_CANARY_PATTERN_U8(addr)))
>                 return true;
>
>         atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
> @@ -323,11 +316,27 @@ static inline bool check_canary_byte(u8 *addr)
>         return false;
>  }
>
> -/* __always_inline this to ensure we won't do an indirect call to fn. */
> -static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
> +static inline void set_canary(const struct kfence_metadata *meta)
>  {
>         const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
> -       unsigned long addr;
> +       unsigned long addr = pageaddr;
> +
> +       /*
> +        * The canary may be written to part of the object memory, but it does
> +        * not affect it. The user should initialize the object before using it.
> +        */
> +       for (; addr < meta->addr; addr += sizeof(u64))
> +               *((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
> +
> +       addr = ALIGN_DOWN(meta->addr + meta->size, sizeof(u64));
> +       for (; addr - pageaddr < PAGE_SIZE; addr += sizeof(u64))
> +               *((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
> +}
> +
> +static inline void check_canary(const struct kfence_metadata *meta)
> +{
> +       const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
> +       unsigned long addr = pageaddr;
>
>         /*
>          * We'll iterate over each canary byte per-side until fn() returns

This comment is now out-of-date ("fn" no longer exists).

> @@ -339,14 +348,38 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
>          */
>
>         /* Apply to left of object. */
> -       for (addr = pageaddr; addr < meta->addr; addr++) {
> -               if (!fn((u8 *)addr))
> +       for (; meta->addr - addr >= sizeof(u64); addr += sizeof(u64)) {
> +               if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64))
>                         break;
>         }
>
> -       /* Apply to right of object. */
> -       for (addr = meta->addr + meta->size; addr < pageaddr + PAGE_SIZE; addr++) {
> -               if (!fn((u8 *)addr))
> +       /*
> +        * If the canary is damaged in a certain 64 bytes, or the canay memory

"damaged" -> "corrupted"
"canay" -> "canary"

> +        * cannot be completely covered by multiple consecutive 64 bytes, it
> +        * needs to be checked one by one.
> +        */
> +       for (; addr < meta->addr; addr++) {
> +               if (unlikely(!check_canary_byte((u8 *)addr)))
> +                       break;
> +       }
> +
> +       /*
> +        * Apply to right of object.
> +        * For easier implementation, check from high address to low address.
> +        */
> +       addr = pageaddr + PAGE_SIZE - sizeof(u64);
> +       for (; addr >= meta->addr + meta->size ; addr -= sizeof(u64)) {
> +               if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64))
> +                       break;
> +       }
> +
> +       /*
> +        * Same as above, checking byte by byte, but here is the reverse of
> +        * the above.
> +        */
> +       addr = addr + sizeof(u64) - 1;
> +       for (; addr >= meta->addr + meta->size; addr--) {

The re-checking should forward-check i.e. not in reverse, otherwise
the report might not include some corrupted bytes that had in the
previous version been included. I think you need to check from low to
high address to start with above.

> +               if (unlikely(!check_canary_byte((u8 *)addr)))
>                         break;
>         }
>  }
> @@ -434,7 +467,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  #endif
>
>         /* Memory initialization. */
> -       for_each_canary(meta, set_canary_byte);
> +       set_canary(meta);
>
>         /*
>          * We check slab_want_init_on_alloc() ourselves, rather than letting
> @@ -495,7 +528,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>         alloc_covered_add(meta->alloc_stack_hash, -1);
>
>         /* Check canary bytes for memory corruption. */
> -       for_each_canary(meta, check_canary_byte);
> +       check_canary(meta);
>
>         /*
>          * Clear memory if init-on-free is set. While we protect the page, the
> @@ -751,7 +784,7 @@ static void kfence_check_all_canary(void)
>                 struct kfence_metadata *meta = &kfence_metadata[i];
>
>                 if (meta->state == KFENCE_OBJECT_ALLOCATED)
> -                       for_each_canary(meta, check_canary_byte);
> +                       check_canary(meta);
>         }
>  }
>
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 600f2e2431d6..2aafc46a4aaf 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -21,7 +21,15 @@
>   * lower 3 bits of the address, to detect memory corruptions with higher
>   * probability, where similar constants are used.
>   */
> -#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))
> +#define KFENCE_CANARY_PATTERN_U8(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))
> +
> +/*
> + * Define a continuous 8-byte canary starting from a multiple of 8. The canary
> + * of each byte is only related to the lowest three bits of its address, so the
> + * canary of every 8 bytes is the same. 64-bit memory can be filled and checked
> + * at a time instead of byte by byte to improve performance.
> + */
> +#define KFENCE_CANARY_PATTERN_U64 ((u64)0xaaaaaaaaaaaaaaaa ^ (u64)(0x0706050403020100))
>
>  /* Maximum stack depth for reports. */
>  #define KFENCE_STACK_DEPTH 64
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 60205f1257ef..197430a5be4a 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -168,7 +168,7 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
>
>         pr_cont("[");
>         for (cur = (const u8 *)address; cur < end; cur++) {
> -               if (*cur == KFENCE_CANARY_PATTERN(cur))
> +               if (*cur == KFENCE_CANARY_PATTERN_U8(cur))
>                         pr_cont(" .");
>                 else if (no_hash_pointers)
>                         pr_cont(" 0x%02x", *cur);
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMOJ9_AU%2B%2BeNF%3DF9hwCveeJmM7r0sEQAf0a%3D0pOa%3DdGfg%40mail.gmail.com.
