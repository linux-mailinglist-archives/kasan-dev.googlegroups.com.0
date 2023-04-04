Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCXYV6QQMGQEERK4NOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BDA996D5D7C
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 12:29:31 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id i4-20020a6b5404000000b0075ff3fb6f4csf4356856iob.9
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 03:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680604170; cv=pass;
        d=google.com; s=arc-20160816;
        b=fRcHo/s5PdqSbn4+tf0piuCfxc0q5HEk/OLKmvMX9vg1az1toZJA406zosgqppCkX/
         AlATQE9p/Mm55JTU/ZQJfkRKVbuWh0plq+erl+IO17ufKSk3zJa5XnrDnd8YwlbdvyFt
         uY5ntBOLh0i/WZfxUmzrhiKn8KXt1LKLzkTN0GZysqRmaIeFHwdW2NN/LBR4s8PDR6fZ
         m8Dp9b32nlYrl07odz/Y9aEVNXKmRn+Qp3Nd1jxSlu4Uf8dtNZ0R4PEVxy+wWD2mLVL9
         r8nxn1GemN/bl6HNQsEZHu19UMHUZY+zO6kWHTyDyT8kSzE1+TEBCbVZYwAQM8IQBXst
         3gTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KCcQK/hGH8qkcEyNPW+Ci5MUAClw69mMR+1aNT6Tkmw=;
        b=Dcjsvlwvm86FLKBOtU8BcuOJR5pDHEo1S/izBksB8PeQ//eD5cgK0Npw21S6PTfxMy
         4VVr5Gp5qsmyYFRrWKrkn16xvm+TYIEAX4Gw5zIttjeo7YREsywQx2ub9zPmLQN52tQi
         hEpsnh1W/KTwrnxnVyixAMOBdrZm75JFD3SErRE52FpyfDJH1mIuvawIFAPmtED8FmiR
         Gr9IQ/QEtgnMMZvEXbSkHzvIL+ZhqaS5spDrl1Ie+P8vNkOF+zDm8yQ8OsApRy+xkJPy
         hQwVCNBKa7I9sApBQ25/ZJbetYfJp94ItHN49kEQQ5lZU/mtlR8AgShBY6RKwlMZNh2Z
         Ipqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="UT/fEhLm";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680604170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KCcQK/hGH8qkcEyNPW+Ci5MUAClw69mMR+1aNT6Tkmw=;
        b=NxH5rdUWuGQwsdhDZ8LiCdaEsCw2A5nL8sAUyQ/DgoybgbPztKUhSLMBDzsOGX5yIi
         IR3qeeoQRgbUp45QsIhqb0T0V1mYUzPZBrGuLjsVb42QZMFnovrcWQlVSfbpfCkg9KLt
         5KH0igh4CQWYBv/H7hSXJ/89kl3BUfwMf8Yq2XzIsQCazo+p+6MF39Ksp6ihWS/cEd3h
         Imvifjs8ieiepJdw4Rs9s6QeKGOTu62O6mzlsDQatsraqZ56hhuXQBi9ovFz6YNBBapE
         VBYpjrVQohg+68sAAdUf4yK1hmgmsHFpOlibmaNWIRAknDWJYTh8cJle6Jw7YfWrwgWs
         Xu2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680604170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KCcQK/hGH8qkcEyNPW+Ci5MUAClw69mMR+1aNT6Tkmw=;
        b=quM8RMOlVnSQ3ng7uG594uEp/JixRWJUo6WppbGcslyiXX2GYYiINI40lybifDe8NA
         DT7su8YGQEahhR7Rgf/ZLDut1vf/d7Mrh+XC+KgaHfnzYYh5weCIb+vTpmKLG+t4Fdvu
         4lDiJi0ZY8m5UzWkJb2xzSWs+H5hoj2bYmZs3SPEOfsEVkUziurnzvpQZvwKE97kuirM
         +x134VrXwD7UTcK4TJtNBF40ch+962lKTUmMdZNFmNAH/eKOuulSJxZjEWwFDiSKMRod
         RUvQHdjHEuQSVd5TuMdamIiZhxkHrLxOejU64JUWz4HIz8aWUOqpkzQRs8aScQRVXrfD
         UsAw==
X-Gm-Message-State: AAQBX9dgYKAQN4GUCr6AH6P94UX9Q69/QWUFPNIg+SdkUpTvICnkreQO
	b2PZLQcln03fq/CkyHojuZ4=
X-Google-Smtp-Source: AKy350YlRIjf9rxeHkwJET96aCLtOfkjwS98d4yATkaFYLByyu92xdy1Qmk+mvT+YOeWkj9W+nA/Kw==
X-Received: by 2002:a02:848d:0:b0:3ec:dc1f:12d8 with SMTP id f13-20020a02848d000000b003ecdc1f12d8mr1270858jai.4.1680604170367;
        Tue, 04 Apr 2023 03:29:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1311:b0:75d:3721:ec12 with SMTP id
 h17-20020a056602131100b0075d3721ec12ls1965701iov.4.-pod-prod-gmail; Tue, 04
 Apr 2023 03:29:29 -0700 (PDT)
X-Received: by 2002:a6b:650e:0:b0:75f:eb54:ce55 with SMTP id z14-20020a6b650e000000b0075feb54ce55mr1897327iob.15.1680604169803;
        Tue, 04 Apr 2023 03:29:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680604169; cv=none;
        d=google.com; s=arc-20160816;
        b=fVra3wUyg5adekmtdOTq0QebazK6mS45gpAqbiZBXrorZ4m/3+ixBrSiXb2Wx0MBCc
         E1vzEcliENg+HR5QMNZphw76esgWI7d+IO0QHIx/8l5eVu5hS+2/65ddmNklkDFbfmOz
         Gklks+62GRVITqU9J9UA7szqVdZVj80xtVMRNACXgXDTWW9TSattwn00QZIhodTVM7+B
         EE10MLvptqbUlnigQ1q9GPmYGjIJS00jQXINs+bR6oKLWcS8VEdXtaJ9upOqyw95u8aO
         irbQf+r70SAcxk6I9lwSMQ9ku3gfy1pufI1vyT+lBX+2upLpt5RQ/bp8vvvhahz/AnsC
         XjcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4EmkZjYvZJVj3QnIxJ1/YfnG3WC3vCHhD00FgzBktzc=;
        b=V1qzR/tcrKkXBLwNJ1aLaBprLdU6FX6RlBYQWtlljIBmSjsbGqutmd2V33+kIAAhaS
         Ia7Ojne2KMHMNnb1ZgZDWaXmM9gJKKRvQKl1RJpHvWY3M1SJWY5mJNFb35w2VlLT07/6
         Eph5j6iLa48yzVLZVq2r1bKlunhb/S0A1w9CU55BT6Nb5rBPNOP5D0sKlEb0dV/Alh1z
         mvlcqng3RV7rUqFavRnhhTM8uBVOqkJBiouecVZsnXVhp+De4F5AfDHeETbpDKN1Cqny
         280CYs2NCjejL1u2xleI3bfG3Ai4kxQMBfXWxW/KWTV7BHMQAsL3HkLFT2CZ6Y3Qw/WL
         ZUmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="UT/fEhLm";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id cp14-20020a056638480e00b0040619abb9aasi995471jab.4.2023.04.04.03.29.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Apr 2023 03:29:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id d20so3373043ioe.4
        for <kasan-dev@googlegroups.com>; Tue, 04 Apr 2023 03:29:29 -0700 (PDT)
X-Received: by 2002:a5d:9b0a:0:b0:753:ee63:3dc with SMTP id
 y10-20020a5d9b0a000000b00753ee6303dcmr1835631ion.20.1680604169337; Tue, 04
 Apr 2023 03:29:29 -0700 (PDT)
MIME-Version: 1.0
References: <20230403122738.6006-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230403122738.6006-1-zhangpeng.00@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Apr 2023 12:28:52 +0200
Message-ID: <CANpmjNN4SAbJ7mRLJHZ1azOEp6e2HyL1FNZH_Qi1+2xc4rgXfw@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: Improve the performance of
 __kfence_alloc() and __kfence_free()
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="UT/fEhLm";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2f as
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

On Mon, 3 Apr 2023 at 14:27, 'Peng Zhang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
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
> Before patching:
> __kfence_alloc:
> avg = 5055 nsecs, total: 5515252 nsecs, count: 1091
> __kfence_free:
> avg = 5319 nsecs, total: 9735130 nsecs, count: 1830
>
> After patching:
> __kfence_alloc:
> avg = 3597 nsecs, total: 6428491 nsecs, count: 1787
> __kfence_free:
> avg = 3046 nsecs, total: 3415390 nsecs, count: 1121
>
> The numbers indicate that there is ~30% - ~40% performance improvement.
>
> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c   | 70 ++++++++++++++++++++++++++++++++--------------
>  mm/kfence/kfence.h | 10 ++++++-
>  mm/kfence/report.c |  2 +-
>  3 files changed, 59 insertions(+), 23 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 79c94ee55f97..b7fe2a2493a0 100644
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
> @@ -323,15 +316,31 @@ static inline bool check_canary_byte(u8 *addr)
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
> -        * We'll iterate over each canary byte per-side until fn() returns
> -        * false. However, we'll still iterate over the canary bytes to the
> +        * We'll iterate over each canary byte per-side until a corrupted byte
> +        * is found. However, we'll still iterate over the canary bytes to the
>          * right of the object even if there was an error in the canary bytes to
>          * the left of the object. Specifically, if check_canary_byte()
>          * generates an error, showing both sides might give more clues as to
> @@ -339,16 +348,35 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
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
> +        * If the canary is corrupted in a certain 64 bytes, or the canary
> +        * memory cannot be completely covered by multiple consecutive 64 bytes,
> +        * it needs to be checked one by one.
> +        */
> +       for (; addr < meta->addr; addr++) {
> +               if (unlikely(!check_canary_byte((u8 *)addr)))
>                         break;
>         }
> +
> +       /* Apply to right of object. */
> +       for (addr = meta->addr + meta->size; addr % sizeof(u64) != 0; addr++) {
> +               if (unlikely(!check_canary_byte((u8 *)addr)))
> +                       return;
> +       }
> +       for (; addr - pageaddr < PAGE_SIZE; addr += sizeof(u64)) {
> +               if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64)) {
> +

Unnecessary blank line, remove.

> +                       for (; addr - pageaddr < PAGE_SIZE; addr++) {
> +                               if (!check_canary_byte((u8 *)addr))
> +                                       return;
> +                       }
> +               }
> +       }
>  }
>
>  static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
> @@ -434,7 +462,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  #endif
>
>         /* Memory initialization. */
> -       for_each_canary(meta, set_canary_byte);
> +       set_canary(meta);
>
>         /*
>          * We check slab_want_init_on_alloc() ourselves, rather than letting
> @@ -495,7 +523,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>         alloc_covered_add(meta->alloc_stack_hash, -1);
>
>         /* Check canary bytes for memory corruption. */
> -       for_each_canary(meta, check_canary_byte);
> +       check_canary(meta);
>
>         /*
>          * Clear memory if init-on-free is set. While we protect the page, the
> @@ -751,7 +779,7 @@ static void kfence_check_all_canary(void)
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4SAbJ7mRLJHZ1azOEp6e2HyL1FNZH_Qi1%2B2xc4rgXfw%40mail.gmail.com.
