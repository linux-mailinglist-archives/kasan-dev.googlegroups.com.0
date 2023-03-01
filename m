Return-Path: <kasan-dev+bncBDW2JDUY5AORBB6G7KPQMGQEP3PGZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1663E6A6480
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 01:57:45 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id j21-20020a9f3095000000b006901584fb3asf1600569uab.7
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 16:57:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677632263; cv=pass;
        d=google.com; s=arc-20160816;
        b=HWgFMMLfLxzS8/xENQ1d5yYt21xUMWQjJT71d489RoI4Ol6Q0S7GqHO3I8S/bSInp8
         slEVpzHlz2Lc+YsAE0aj5FTr9AQ86zYeRYNQ1+Ua8s7gIbV4YqEzpfG3F/BPY1IC/dM1
         0uxGSZ1ccmPOXexHmds/elyda3GECppj7/ToRiJxtHP0n9Vc30olBRwvauB4ImpCJFkk
         WMPEKRpKtjpDYBDXnqKcrK+WGw3ZB+VVgEnRILPTI/dcrYWCnLLP/p3H2EoyCpqMQnUP
         9MHTL1htWPcGQe5kilcOpVuCM/qSt9l6b8GRZ1jc0BeUDi6C1MuUP0V52oYnO6gXpjv3
         h0Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OiYmV3jxtaDhpAVrKiNfoBFaJokLe+HVVNfOnAxj60M=;
        b=slAQpMbBY/cTb33zcOYho0ntYkm0j4DIjs7XIlv+NeYFc7vmaCCGU9L7rYuweNQl5g
         Xn+f8K2VY4J7cmRMNVu/ACCPys1ZuWi0LdYfRz3JhJi9mshvVuVvPNDtBv7h979TgGfC
         RFGdvXAMByyYZJKmKcxCc9FOOGx2u31M6TuHxFprYkm5isd+LygPJPHTRCkbYud0oH51
         XO2j39AQOntIemuyR7YHscPjTsnk8i/AdaYf/gZeUh+bE4gZlWYdVSnuQI457G7jIs7v
         t/NOh4iJkGY0nlpOQSoVnZOYU1CN2n1CAK2+rjqGdnL8D4RLqGSotxew7rDEuJSKtfWj
         0m6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UswGR9h8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OiYmV3jxtaDhpAVrKiNfoBFaJokLe+HVVNfOnAxj60M=;
        b=FG0Zw1KV/9c7ZcvvNRjohnv6ckyIkEShJQrUPJpqnCWynmCIN5WmPIFQhr9VhapimR
         u2haKiWB+BXQdcRKzW/M4rQkupWBu9oTeLF4hRRKa0ubrn+N9OiuyvNGkzoHiwiciC3G
         ILxvrPY8Rick+bOAbSNlwumGjmsg641ywM9LBtb1XRQuP371mLpIBIjMULLrHWmqUm5s
         DlVnyBgGOvK/0tONz7JOrD+eHnsMdyz5/W/j7R+BMejbFFQR0OihMwHB4heSmg+Xb2Zy
         EBc4meOCjBNA/fMhV1gmWEgLQIRDKTGYg1nkgIYZnsyC9TXd2tzTY9xwo/nHFrG6FJHq
         0/1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OiYmV3jxtaDhpAVrKiNfoBFaJokLe+HVVNfOnAxj60M=;
        b=ZRQwIxp+LkH5+331uzxn7QGx59/hXLXkXlHAeqCRmzPmK625jMXM09DRm7QE+fOl7I
         zCwEpL4vSufQ9aSF2NcrRMeXVlgDgBPnvJCNFFB4cWcOUrfpQSRFJz0zLNbv2kGGn3hP
         J7cvhkfhWKmKYbWy74H7rerQTFpJ6G5Pxq51oz+bphy8/KmQfIzXl18P1Kuoe2TYiQs0
         4ydIlo3xDLtvJe+p4kT1ilnO4eCwxUVTJciZH9T8CVnzhyrAbhMjQZkRkEmpSr/tjk+X
         yzI2CQHhECx5rq4E1xGF8bg5BVSSRxa8W3bPHwtH/rGinz5z3+kFSCL6+D2F8VGMZ5pG
         rW6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OiYmV3jxtaDhpAVrKiNfoBFaJokLe+HVVNfOnAxj60M=;
        b=wM8/WM1U0Q70fNeYqZD2wxwEOYljYKW/wJKBeyDXaYyG8/9RQfbysuz9wx/GlUbNjg
         aGoB5pivX5hL1pthC9FfbOQw1jvVhlnvsou7cus9dPOtyq8Tjvj1jjPXmWykNZGi8Goa
         d5/J04WDKQkRuTRqJxIeqh1uhqT8Y3BmlNo9BKjrSkM/yH9xKrrwRP2ClcgBvmnKivd4
         3a21urJfWyK0bAjbW7yuih/JpueoaPfdqjjj20vjW5FKaYGvffPqFgSSZnraFbPaToCA
         +il51b5ikjl5KxdjllYVnRRIXsXyDwneqtfqxhXczlRt9aBtYtor5d2VEm+IXNG0dXCx
         UXkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX2CN36iN2D1qpNIyjzkic1yniLMvqc9AXd34rf3+QAvfLRy0Co
	HFmPb9vPNldeUpL20KsEY14=
X-Google-Smtp-Source: AK7set+tdyEhydRJrPlsFCtx/4Qk2ZhYWiPq9F9uLafxJCvKYxG6FF0aUCIogegjnGk2IVCFcTVROw==
X-Received: by 2002:a05:6102:3d3:b0:412:565:7f7a with SMTP id n19-20020a05610203d300b0041205657f7amr3333656vsq.4.1677632263414;
        Tue, 28 Feb 2023 16:57:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f505:0:b0:412:4ec9:7df6 with SMTP id u5-20020a67f505000000b004124ec97df6ls4615164vsn.8.-pod-prod-gmail;
 Tue, 28 Feb 2023 16:57:42 -0800 (PST)
X-Received: by 2002:a05:6102:275a:b0:411:aef5:cd01 with SMTP id p26-20020a056102275a00b00411aef5cd01mr2234305vsu.34.1677632262665;
        Tue, 28 Feb 2023 16:57:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677632262; cv=none;
        d=google.com; s=arc-20160816;
        b=oj676HblLRdfkWUwx71xnyC2m2FaNxYKA1arbcEGa0E661xv6b2K4sX8U7fXFzt2aw
         HS73wUGgJiBtqk7q6TVFZR2PgRIhOGnefBkzuYbGQ25Mbp1QIqg0Tux4EgonX2jWvK7h
         TLLeYQBp428cydndfROMmCJ6Lca29n4y1aZNs8M+hDcfcByBDizdB5qXQCn7Tq/GjDqQ
         EBbxBWNDwnGv4E39a7e2z0+1N/vjSXUbEOYnW6pXDsFirKYTWsyTM69au5Q+SNVSNOog
         QrVFxMp2TNcje74MmIn8u7y36LxvfvrEUe8tLZO4dmgBPOIT1VJg23+5cvvzlkqYyWw1
         4gJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LaXnzqpU4LQzSklGf2uPpfWehIVtSyT5rsgfrLRoiek=;
        b=Xx8ounx6LwQ0GcWz68O1RnoKdnl1OZNzO5waLllUo86G9CDBUoYA7FZ/0lvCzHfr/3
         0M5HvWavDliUv8UpjEPhrDEpuq4s8XQW+KST+wI1FW5cpD+VIbBIGPi18pWXjlW1z+p8
         Ir4NOFKKEQykCd53gjcjcqhNvtYL3BKHctvJ9p9lejji/54nIkdpg8X4r1WyET+MKkry
         veTOrvOHmtR95TBgdUXI9KQkYQUzz59+OYYMXiR+SRogErA7omX7V6bJ7Iuh2AXQ4PG9
         ETbtJrYS/CJf4pHdYIC3pVrOx4qDzkVVRau1r1iYcv1c3wjwayll2thVFMZS7YKVMHsV
         5vtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UswGR9h8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id n3-20020ab013c3000000b006919cae0238si517489uae.1.2023.02.28.16.57.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 16:57:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id a7so6936256pfx.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 16:57:42 -0800 (PST)
X-Received: by 2002:a63:1e51:0:b0:503:83e8:9b54 with SMTP id
 p17-20020a631e51000000b0050383e89b54mr842570pgm.1.1677632262027; Tue, 28 Feb
 2023 16:57:42 -0800 (PST)
MIME-Version: 1.0
References: <20230301003545.282859-1-pcc@google.com> <20230301003545.282859-3-pcc@google.com>
In-Reply-To: <20230301003545.282859-3-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 1 Mar 2023 01:57:31 +0100
Message-ID: <CA+fCnZeb4hN=yQZE69soGJuKpA5_rJeSgiGhOQ4Pvw5U29BV=A@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kasan: remove PG_skip_kasan_poison flag
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UswGR9h8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 1, 2023 at 1:35=E2=80=AFAM Peter Collingbourne <pcc@google.com>=
 wrote:
>
> Code inspection reveals that PG_skip_kasan_poison is redundant with
> kasantag, because the former is intended to be set iff the latter is
> the match-all tag. It can also be observed that it's basically pointless
> to poison pages which have kasantag=3D0, because any pages with this tag
> would have been pointed to by pointers with match-all tags, so poisoning
> the pages would have little to no effect in terms of bug detection.
> Therefore, change the condition in should_skip_kasan_poison() to check
> kasantag instead, and remove PG_skip_kasan_poison and associated flags.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf45=
97c8a5821359838
> ---
> v3:
> - update comments
>
> v2:
> - also remove GFP_SKIP_KASAN_POISON and FPI_SKIP_KASAN_POISON
> - rename GFP_SKIP_KASAN_UNPOISON to GFP_SKIP_KASAN
> - update comments
> - simplify control flow by removing reset_tags
>
>  include/linux/gfp_types.h      | 30 ++++++-------
>  include/linux/page-flags.h     |  9 ----
>  include/trace/events/mmflags.h | 12 +----
>  mm/kasan/hw_tags.c             |  2 +-
>  mm/page_alloc.c                | 81 +++++++++++++---------------------
>  mm/vmalloc.c                   |  2 +-
>  6 files changed, 47 insertions(+), 89 deletions(-)
>
> diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> index 5088637fe5c2..6583a58670c5 100644
> --- a/include/linux/gfp_types.h
> +++ b/include/linux/gfp_types.h
> @@ -47,16 +47,14 @@ typedef unsigned int __bitwise gfp_t;
>  #define ___GFP_ACCOUNT         0x400000u
>  #define ___GFP_ZEROTAGS                0x800000u
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define ___GFP_SKIP_ZERO               0x1000000u
> -#define ___GFP_SKIP_KASAN_UNPOISON     0x2000000u
> -#define ___GFP_SKIP_KASAN_POISON       0x4000000u
> +#define ___GFP_SKIP_ZERO       0x1000000u
> +#define ___GFP_SKIP_KASAN      0x2000000u
>  #else
> -#define ___GFP_SKIP_ZERO               0
> -#define ___GFP_SKIP_KASAN_UNPOISON     0
> -#define ___GFP_SKIP_KASAN_POISON       0
> +#define ___GFP_SKIP_ZERO       0
> +#define ___GFP_SKIP_KASAN      0
>  #endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP       0x8000000u
> +#define ___GFP_NOLOCKDEP       0x4000000u
>  #else
>  #define ___GFP_NOLOCKDEP       0
>  #endif
> @@ -234,25 +232,24 @@ typedef unsigned int __bitwise gfp_t;
>   * memory tags at the same time as zeroing memory has minimal additional
>   * performace impact.
>   *
> - * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page alloc=
ation.
> - * Only effective in HW_TAGS mode.
> - *
> - * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocat=
ion.
> - * Typically, used for userspace pages. Only effective in HW_TAGS mode.
> + * %__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation.
> + * Used for userspace and vmalloc pages; the latter are unpoisoned by
> + * kasan_unpoison_vmalloc instead. For userspace pages, results in
> + * poisoning being skipped as well, see should_skip_kasan_poison for
> + * details. Only effective in HW_TAGS mode.
>   */
>  #define __GFP_NOWARN   ((__force gfp_t)___GFP_NOWARN)
>  #define __GFP_COMP     ((__force gfp_t)___GFP_COMP)
>  #define __GFP_ZERO     ((__force gfp_t)___GFP_ZERO)
>  #define __GFP_ZEROTAGS ((__force gfp_t)___GFP_ZEROTAGS)
>  #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
> -#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPO=
ISON)
> -#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POIS=
ON)
> +#define __GFP_SKIP_KASAN ((__force gfp_t)___GFP_SKIP_KASAN)
>
>  /* Disable lockdep for GFP context tracking */
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
>
>  /**
> @@ -335,8 +332,7 @@ typedef unsigned int __bitwise gfp_t;
>  #define GFP_DMA                __GFP_DMA
>  #define GFP_DMA32      __GFP_DMA32
>  #define GFP_HIGHUSER   (GFP_USER | __GFP_HIGHMEM)
> -#define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | \
> -                        __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOI=
SON)
> +#define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | __GFP_SKI=
P_KASAN)
>  #define GFP_TRANSHUGE_LIGHT    ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
>                          __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAI=
M)
>  #define GFP_TRANSHUGE  (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index a7e3a3405520..74f81a52e7e1 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -135,9 +135,6 @@ enum pageflags {
>  #ifdef CONFIG_ARCH_USES_PG_ARCH_X
>         PG_arch_2,
>         PG_arch_3,
> -#endif
> -#ifdef CONFIG_KASAN_HW_TAGS
> -       PG_skip_kasan_poison,
>  #endif
>         __NR_PAGEFLAGS,
>
> @@ -594,12 +591,6 @@ TESTCLEARFLAG(Young, young, PF_ANY)
>  PAGEFLAG(Idle, idle, PF_ANY)
>  #endif
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -PAGEFLAG(SkipKASanPoison, skip_kasan_poison, PF_HEAD)
> -#else
> -PAGEFLAG_FALSE(SkipKASanPoison, skip_kasan_poison)
> -#endif
> -
>  /*
>   * PageReported() is used to track reported free pages within the Buddy
>   * allocator. We can use the non-atomic version of the test and set
> diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflag=
s.h
> index 9db52bc4ce19..232bc8efc98e 100644
> --- a/include/trace/events/mmflags.h
> +++ b/include/trace/events/mmflags.h
> @@ -55,8 +55,7 @@
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define __def_gfpflag_names_kasan ,                    \
>         gfpflag_string(__GFP_SKIP_ZERO),                \
> -       gfpflag_string(__GFP_SKIP_KASAN_POISON),        \
> -       gfpflag_string(__GFP_SKIP_KASAN_UNPOISON)
> +       gfpflag_string(__GFP_SKIP_KASAN)
>  #else
>  #define __def_gfpflag_names_kasan
>  #endif
> @@ -96,12 +95,6 @@
>  #define IF_HAVE_PG_ARCH_X(flag,string)
>  #endif
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string) ,{1UL << flag, string}
> -#else
> -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string)
> -#endif
> -
>  #define __def_pageflag_names                                           \
>         {1UL << PG_locked,              "locked"        },              \
>         {1UL << PG_waiters,             "waiters"       },              \
> @@ -130,8 +123,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,    "hwpoison"      )=
               \
>  IF_HAVE_PG_IDLE(PG_young,              "young"         )               \
>  IF_HAVE_PG_IDLE(PG_idle,               "idle"          )               \
>  IF_HAVE_PG_ARCH_X(PG_arch_2,           "arch_2"        )               \
> -IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )               \
> -IF_HAVE_PG_SKIP_KASAN_POISON(PG_skip_kasan_poison, "skip_kasan_poison")
> +IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )
>
>  #define show_page_flags(flags)                                         \
>         (flags) ? __print_flags(flags, "|",                             \
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index d1bcb0205327..bb4f56e5bdec 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -318,7 +318,7 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>          * Thus, for VM_ALLOC mappings, hardware tag-based KASAN only tag=
s
>          * the first virtual mapping, which is created by vmalloc().
>          * Tagging the page_alloc memory backing that vmalloc() allocatio=
n is
> -        * skipped, see ___GFP_SKIP_KASAN_UNPOISON.
> +        * skipped, see ___GFP_SKIP_KASAN.
>          *
>          * For non-VM_ALLOC allocations, page_alloc memory is tagged as u=
sual.
>          */
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 7136c36c5d01..0db33faf760d 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -112,17 +112,6 @@ typedef int __bitwise fpi_t;
>   */
>  #define FPI_TO_TAIL            ((__force fpi_t)BIT(1))
>
> -/*
> - * Don't poison memory with KASAN (only for the tag-based modes).
> - * During boot, all non-reserved memblock memory is exposed to page_allo=
c.
> - * Poisoning all that memory lengthens boot time, especially on systems =
with
> - * large amount of RAM. This flag is used to skip that poisoning.
> - * This is only done for the tag-based KASAN modes, as those are able to
> - * detect memory corruptions with the memory tags assigned by default.
> - * All memory allocated normally after boot gets poisoned as usual.
> - */
> -#define FPI_SKIP_KASAN_POISON  ((__force fpi_t)BIT(2))
> -
>  /* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields=
 */
>  static DEFINE_MUTEX(pcp_batch_high_lock);
>  #define MIN_PERCPU_PAGELIST_HIGH_FRACTION (8)
> @@ -1355,13 +1344,19 @@ static int free_tail_pages_check(struct page *hea=
d_page, struct page *page)
>  /*
>   * Skip KASAN memory poisoning when either:
>   *
> - * 1. Deferred memory initialization has not yet completed,
> - *    see the explanation below.
> - * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
> - *    see the comment next to it.
> - * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
> - *    see the comment next to it.
> - * 4. The allocation is excluded from being checked due to sampling,
> + * 1. For generic KASAN: deferred memory initialization has not yet comp=
leted.
> + *    Tag-based KASAN modes skip pages freed via deferred memory initial=
ization
> + *    using page tags instead (see below).
> + * 2. For tag-based KASAN modes: the page has a match-all KASAN tag, ind=
icating
> + *    that error detection is disabled for accesses via the page address=
.
> + *
> + * Pages will have match-all tags in the following circumstances:
> + *
> + * 1. Pages are being initialized for the first time, including during d=
eferred
> + *    memory init; see the call to page_kasan_tag_reset in __init_single=
_page.
> + * 2. The allocation was not unpoisoned due to __GFP_SKIP_KASAN, with th=
e
> + *    exception of pages unpoisoned by kasan_unpoison_vmalloc.
> + * 3. The allocation was excluded from being checked due to sampling,
>   *    see the call to kasan_unpoison_pages.
>   *
>   * Poisoning pages during deferred memory init will greatly lengthen the
> @@ -1377,10 +1372,10 @@ static int free_tail_pages_check(struct page *hea=
d_page, struct page *page)
>   */
>  static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi=
_flags)
>  {
> -       return deferred_pages_enabled() ||
> -              (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> -               (fpi_flags & FPI_SKIP_KASAN_POISON)) ||
> -              PageSkipKASanPoison(page);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               return deferred_pages_enabled();
> +
> +       return page_kasan_tag(page) =3D=3D 0xff;
>  }
>
>  static void kernel_init_pages(struct page *page, int numpages)
> @@ -1754,7 +1749,7 @@ void __free_pages_core(struct page *page, unsigned =
int order)
>          * Bypass PCP and place fresh pages right to the tail, primarily
>          * relevant for memory onlining.
>          */
> -       __free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON)=
;
> +       __free_pages_ok(page, order, FPI_TO_TAIL);
>  }
>
>  #ifdef CONFIG_NUMA
> @@ -2456,9 +2451,9 @@ static inline bool should_skip_kasan_unpoison(gfp_t=
 flags)
>
>         /*
>          * With hardware tag-based KASAN enabled, skip if this has been
> -        * requested via __GFP_SKIP_KASAN_UNPOISON.
> +        * requested via __GFP_SKIP_KASAN.
>          */
> -       return flags & __GFP_SKIP_KASAN_UNPOISON;
> +       return flags & __GFP_SKIP_KASAN;
>  }
>
>  static inline bool should_skip_init(gfp_t flags)
> @@ -2477,7 +2472,6 @@ inline void post_alloc_hook(struct page *page, unsi=
gned int order,
>         bool init =3D !want_init_on_free() && want_init_on_alloc(gfp_flag=
s) &&
>                         !should_skip_init(gfp_flags);
>         bool zero_tags =3D init && (gfp_flags & __GFP_ZEROTAGS);
> -       bool reset_tags =3D true;
>         int i;
>
>         set_page_private(page, 0);
> @@ -2511,37 +2505,22 @@ inline void post_alloc_hook(struct page *page, un=
signed int order,
>                 /* Take note that memory was initialized by the loop abov=
e. */
>                 init =3D false;
>         }
> -       if (!should_skip_kasan_unpoison(gfp_flags)) {
> -               /* Try unpoisoning (or setting tags) and initializing mem=
ory. */
> -               if (kasan_unpoison_pages(page, order, init)) {
> -                       /* Take note that memory was initialized by KASAN=
. */
> -                       if (kasan_has_integrated_init())
> -                               init =3D false;
> -                       /* Take note that memory tags were set by KASAN. =
*/
> -                       reset_tags =3D false;
> -               } else {
> -                       /*
> -                        * KASAN decided to exclude this allocation from =
being
> -                        * (un)poisoned due to sampling. Make KASAN skip
> -                        * poisoning when the allocation is freed.
> -                        */
> -                       SetPageSkipKASanPoison(page);
> -               }
> -       }
> -       /*
> -        * If memory tags have not been set by KASAN, reset the page tags=
 to
> -        * ensure page_address() dereferencing does not fault.
> -        */
> -       if (reset_tags) {
> +       if (!should_skip_kasan_unpoison(gfp_flags) &&
> +           kasan_unpoison_pages(page, order, init)) {
> +               /* Take note that memory was initialized by KASAN. */
> +               if (kasan_has_integrated_init())
> +                       init =3D false;
> +       } else {
> +               /*
> +                * If memory tags have not been set by KASAN, reset the p=
age
> +                * tags to ensure page_address() dereferencing does not f=
ault.
> +                */
>                 for (i =3D 0; i !=3D 1 << order; ++i)
>                         page_kasan_tag_reset(page + i);
>         }
>         /* If memory is still not initialized, initialize it now. */
>         if (init)
>                 kernel_init_pages(page, 1 << order);
> -       /* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
> -       if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POIS=
ON))
> -               SetPageSkipKASanPoison(page);
>
>         set_page_owner(page, order, gfp_flags);
>         page_table_check_alloc(page, order);
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index ef910bf349e1..b0c84847e9b6 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3170,7 +3170,7 @@ void *__vmalloc_node_range(unsigned long size, unsi=
gned long align,
>                          * pages backing VM_ALLOC mapping. Memory is inst=
ead
>                          * poisoned and zeroed by kasan_unpoison_vmalloc(=
).
>                          */
> -                       gfp_mask |=3D __GFP_SKIP_KASAN_UNPOISON | __GFP_S=
KIP_ZERO;
> +                       gfp_mask |=3D __GFP_SKIP_KASAN | __GFP_SKIP_ZERO;
>                 }
>
>                 /* Take note that the mapping is PAGE_KERNEL. */
> --
> 2.39.2.722.g9855ee24e9-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you, Peter!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeb4hN%3DyQZE69soGJuKpA5_rJeSgiGhOQ4Pvw5U29BV%3DA%40mail.=
gmail.com.
