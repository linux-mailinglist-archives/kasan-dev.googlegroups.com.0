Return-Path: <kasan-dev+bncBDW2JDUY5AORBW4WSKQQMGQE56EUGWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D049E6CF2A8
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 21:02:52 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id z19-20020a056e02089300b00326098d01d9sf6480836ils.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 12:02:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680116571; cv=pass;
        d=google.com; s=arc-20160816;
        b=gwTDjeahCjAaeX+DL/a5sdaTdXcVZQZzE93w+r7Tcm/5SlLYId7W3g4PQIlekf3Rk0
         StgULs8O8C1GMo6wVckvbi+SnBe+LMpyNGqbxYxKW+oJneD4uf4THsuC7FTXJHTcaKU9
         HOjwxs2Ese+Y1hCohSPhQ2pUWFA+vBvB9VT7jnoOkaWpU/2TEvwaZOhVySrop06cM43q
         9FDf5w/2Bxx7bFUOigHkk5Jknx6rR4D3pOUjxOcCiSA8jo8GTVp28exlbjp6HR3L6VGm
         qc0ks7GC9REYU+KZzbg2pUfd6tuWfV0aPVqBsuJULGijOROg+lnWK5jpLf+Hm8onufSG
         J+ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=J3I3CuSQbazUngOsRqCehJ8mPUz+qCVBMxcL+5eKZ/E=;
        b=K4LPv/p4YuR+78u0kMEyEiygRByHceBckvtcQtALP/17uI2ggRCTorTa7+msgOpY6t
         mEshkiKXXVFrxikzZ3Oyapzg97tuaRkbBZEFgbtpgwXyyUSN19zMUC24sgr8n/P6xnft
         eSOZ188cLqQhN3HXUKjxPbDahpv43dz1TmzCGfzCYE+svDVJtMETLZLSKgg+H7mVpaQX
         i8DLnk70ZduGPSUpLjLgtdj1+D5eiwkMHIPtfvMJIavZWRE1xm1GtcHjtdumXFZ5UOq0
         MpYc+aNgkQoGaZHnAzVrBJgwuV1W7Y8PpjBuXs6/Ei2yB31wHs9KRbS0eRk989nwOhfQ
         hU4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="U//sM9A7";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680116571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J3I3CuSQbazUngOsRqCehJ8mPUz+qCVBMxcL+5eKZ/E=;
        b=teNkdnmQ04EAq4pLf1JKnRDTjjKoJS99utvtBwwFlexV7/vYo62D8kkCDpsQuakdeD
         vZqzFrsew3B5qOtM8lBYfm4imHOiSoK1IQFOKUYoMf2NaOG2UmyhS67RHOKTPzJvEVob
         FcJTkrJowxs6g6XEE5gRWVoxpzmfW4XedTDCRgJ3R0+AKh+0Xpdz+HMdrm3IvQj57/4r
         vhnwwfMG/ypukBMm3a8jIuDfRYhVZF9R2roQBmuwq/CV/YL3cXnabx/mqUgbH4p7VNAO
         Rha986eiNdMS+aei57jwU0dgzPPOwt3r3y81TusDcKhOvecV6ClDNYg7nFrjkHVs3iwC
         6mMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680116571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=J3I3CuSQbazUngOsRqCehJ8mPUz+qCVBMxcL+5eKZ/E=;
        b=hAtOdc2PPUFmkfNeMBywlRs6WGKpWCQ+1CiPqfP4o9OUF4/k2o1mNrXyQOgvzGEr0P
         HiwOv6GRIgNaQdyE3g2mFG88KbuCXeWjg2iGbHn8qtKmCUmxG/irC9vG3OycYJOcV7fn
         2uDnOd5NPiGJO74wL++CyW06bOyf4Gvi+JKDptHtrGEOZIW2UbBfiA1z1CmvemIEQxYq
         f3J8QjzcqsUP9JD6OBUHVyQrxZuvFQsufCtZqfTMjPXSO5gpCq0PfzP5Pc9OoSHq569f
         k9EX+o2kbZ+jzGUZG2MMUuTn2AOdXZFRrGM1TE6NH7xUmh6SN7meUek9YauGdDVtwUL4
         bopA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680116571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J3I3CuSQbazUngOsRqCehJ8mPUz+qCVBMxcL+5eKZ/E=;
        b=Mj3p3o/KCn/hjjLhrk8Eml3h0EfTdhnfjNzluVjszueHs8Iwy4D68nUNwtLrpr0/Oi
         yqXb4QLepXflxntBC6Ukrgt0yCTPf6iiHuJkV168VvdUCJD2SfU9CZxzscl4Cx0zYAMH
         c4uWfTSvpl/+tzhQSX3NuEt0wv44ejnOFSxQEYFHPkVLJEA6JENsXWXaR2wNgjf0HsZ/
         4FJ7NRL3gw0PbnXZql7BWFPji2fybLoUfpxDnLw+I++vX1Wx6EW4FgMreWZ4rd92NSlv
         a8ih+LEi3tmbr4f77FI1UP1GY6qYV17Z9qloK391j+7GqKHXdiYOvVaPco+L9NG4qE4D
         z7+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXJD2Dfud0HWf0m9JB4QRQEmaDyDa//+zbj8a5JOHuKFlHy1/bz
	6gXDXcf8Ixj18+KwOKpwomQ=
X-Google-Smtp-Source: AK7set8yjRD4d1GCvo8CVbitHloPHBjCV4EdfwpEzNLLEW/P47P2q8L2izuZWyuH27RtJXD7/o2zGw==
X-Received: by 2002:a5e:db05:0:b0:745:6788:149f with SMTP id q5-20020a5edb05000000b007456788149fmr7603245iop.0.1680116571490;
        Wed, 29 Mar 2023 12:02:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1205:b0:75c:98b0:98a9 with SMTP id
 y5-20020a056602120500b0075c98b098a9ls1080220iot.5.-pod-prod-gmail; Wed, 29
 Mar 2023 12:02:51 -0700 (PDT)
X-Received: by 2002:a5d:9c4f:0:b0:74c:9ca3:6347 with SMTP id 15-20020a5d9c4f000000b0074c9ca36347mr14048078iof.12.1680116571008;
        Wed, 29 Mar 2023 12:02:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680116570; cv=none;
        d=google.com; s=arc-20160816;
        b=VQq4y/qvyfQlkogdvKLDonc1ItXSImlHYrnca0XHwxOPShtf7LQqBy+LdrVG9WYdQ7
         cRiesWkJqHpTk+zNyMgPwlTpdmVobcrQkMNufM12AJKoTJhV3YDnTFfqbK/SYSFRd2XM
         PmqoIP1kAInaKVtoidGF76G26K4tLD6bfcLECc7qlHKKCY4oZLEOwrJbtLkLPqCdY0/4
         Bde/AMrWhDMVZuWEGyUrJ3BfJtzhzQKu9XJ9Tw5K4yjWkybO1ccvT/57Q59w3027P4yv
         VIStJ2b40K/mIS4d8Ehqqnvv1dNP5N3KeFP+hq/gRd+bUzLcW84T1yXjqSvCJOq7jopk
         FEVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rysh7R9x0DwpV/wCJCeDcK+KSngeOrcjw+kFGG6R2os=;
        b=h5bxNeUf0YeJtZqtUoS9QtD8jgnmaUEI1uBXj8ZSJnRDqxxzFuvdJPdvgj0z1ARKE4
         GUYhwLUU4bqC70ML8mW/4jBeTNaowjSBXrGUdTMM+00tR/nlys2QETA26F5Ugntzg5MM
         tZjBQwgw0/1KpkATpmhQTm0L32k9Wvkf/X76b56z8fXzgCOe6pQARqjfB1EYJbH65Ea8
         f+K1sXGgNG3fPAvtNBqJXPlKGDf/JTgmhJQP+2pZW7ovRKAcDkyLNe8PqBFJIZoRtCHW
         UHvGlCme+fBB7nbSbG77OpC3TfR7yQ40ZA5mneVuYKT9u8Hi/yd4BbZxiJpcOItwt9Rr
         uTjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="U//sM9A7";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id b15-20020a5d8d8f000000b00753102db9c8si1799930ioj.4.2023.03.29.12.02.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Mar 2023 12:02:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id z19so15890551plo.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 12:02:50 -0700 (PDT)
X-Received: by 2002:a17:902:c213:b0:199:49d7:cead with SMTP id
 19-20020a170902c21300b0019949d7ceadmr7378827pll.11.1680116570333; Wed, 29 Mar
 2023 12:02:50 -0700 (PDT)
MIME-Version: 1.0
References: <20230328111714.2056-1-zhangqing@loongson.cn>
In-Reply-To: <20230328111714.2056-1-zhangqing@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 29 Mar 2023 21:02:39 +0200
Message-ID: <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="U//sM9A7";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62c
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

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f7ef70661ce2..3b91b941873d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -54,11 +54,13 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>  int kasan_populate_early_shadow(const void *shadow_start,
>                                 const void *shadow_end);
>
> +#ifndef __HAVE_ARCH_SHADOW_MAP
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
>         return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>                 + KASAN_SHADOW_OFFSET;
>  }
> +#endif
>
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index e5eef670735e..f86194750df5 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -175,6 +175,11 @@ static __always_inline bool check_region_inline(unsigned long addr,
>         if (unlikely(!addr_has_metadata((void *)addr)))
>                 return !kasan_report(addr, size, write, ret_ip);
>
> +#ifndef __HAVE_ARCH_SHADOW_MAP
> +       if (unlikely(kasan_mem_to_shadow((unsigned long *)addr) == NULL))
> +               return !kasan_report(addr, size, write, ret_ip);
> +#endif

This should have been ifdef, right?

But I don't think you need this check here at all: addr_has_metadata
already checks that shadow exists.

> +
>         if (likely(!memory_is_poisoned(addr, size)))
>                 return true;
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index cc64ed6858c6..860061a22ca9 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -166,8 +166,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
>                                 if (!p)
>                                         return -ENOMEM;
>                         } else {
> -                               pud_populate(&init_mm, pud,
> -                                       early_alloc(PAGE_SIZE, NUMA_NO_NODE));
> +                               p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> +                               pmd_init(p);
> +                               pud_populate(&init_mm, pud, p);
>                         }
>                 }
>                 zero_pmd_populate(pud, addr, next);
> @@ -207,8 +208,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
>                                 if (!p)
>                                         return -ENOMEM;
>                         } else {
> -                               p4d_populate(&init_mm, p4d,
> -                                       early_alloc(PAGE_SIZE, NUMA_NO_NODE));
> +                               p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> +                               pud_init(p);
> +                               p4d_populate(&init_mm, p4d, p);

Please explain why these changes are needed in the patch description.

>                         }
>                 }
>                 zero_pud_populate(p4d, addr, next);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index a61eeee3095a..033335c13b25 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -291,16 +291,22 @@ struct kasan_stack_ring {
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
> +#ifndef __HAVE_ARCH_SHADOW_MAP
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>         return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
>                 << KASAN_SHADOW_SCALE_SHIFT);
>  }
> +#endif
>
>  static __always_inline bool addr_has_metadata(const void *addr)
>  {
> +#ifdef __HAVE_ARCH_SHADOW_MAP
> +       return (kasan_mem_to_shadow((void *)addr) != NULL);
> +#else
>         return (kasan_reset_tag(addr) >=
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> +#endif
>  }
>
>  /**
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA%40mail.gmail.com.
