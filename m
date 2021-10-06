Return-Path: <kasan-dev+bncBDW2JDUY5AORBSFI62FAMGQE4SEHIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E06FD423D98
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 14:19:21 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id r3-20020a056830236300b0054d43b72ba5sf1361436oth.17
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 05:19:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633522761; cv=pass;
        d=google.com; s=arc-20160816;
        b=QWvSfNzJYYVH71StgLPlqe4U7655qo5QJFJy4nbwzYeOTEvE6G1gRmgzMS6xSeNqsw
         0C12uGLdKvqT6i9zp/GPd7izCqL6j+IDvFQDwtRq0mSpeQSwx94cH46BJS6wngybShDk
         IcOkHhwbPqjc6feJoCjy9GqJt44iwVrH33UtlJT7JLq9MF52uybM9wnMppJsWVufGQtP
         MX0XZgxb2ffSXdceXdwoyBojKH3Vu5G0rnhffM8v0nVzAm3nNShHH3LX75RGK8eMcEDH
         tHMvzlAtOrGEiPH0GHqkXLTjPXUh9Hjie6CjKW194zcivQLkIgdyVvgtbr3h4IeaSVw9
         Ytjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0Ac/G3mitpqPfGiFti7BYttsHS0KQ0R4yHkVEbJpaJA=;
        b=qP9yUAUXugedZvlVKeEod1XoMJRpBuxyDQW9sU4e53VSHJX4gTlL85AI735+Xw+QTS
         8vV3hX4coqKcBiJxrsGyBjIzxXp7bZHKfYDqWKm5oD2wBRnyB5ZZEpilXEWIcvcnJHdr
         AhhB3GjwSUKNjeYAVdFMkBfvJl+cwui/LJMt+gcMM84kaF5tI5edoU2SVyAMUZOAqbNy
         JFB7BT3OdE72w2UUxDHGEbQjHbsc5+ioOi4xiuVJKTRU703SVIxKKRd76W0nj2HCWzwq
         zwxpd6wYVt5H8D5Uicbq03TFHFdv3llW9NzKqmhLDKQDr1KiL2OP8iM4EVeIqp5UEEVE
         5Dag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iPCsObQh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Ac/G3mitpqPfGiFti7BYttsHS0KQ0R4yHkVEbJpaJA=;
        b=rjIDLgF5ui4kFEYDYj/rWHzo5tddXxLEZ29y1mXzv6AsjXjY4ZqSCWuPnE4/7KRDFC
         opEfe06MBEnrCoN2Ya8TDGjoAqFG07ClfBG4ycv0HPyO97KRHS3H3sj8JiYirnoxKC97
         PTga98jZKLwfoXoXktThqZpsorSA3gOUIap0hjy8hDO7+p0g9Gu4dhj9oozRnchDRCFN
         8PIKbvnP81pgoD/4Jf1CiUwcFbEIr/1nzqDOfX1cxvxP3yhislpXxKJmg869VyrjEh0/
         h82HtWH7Pf60AWMDjk75vZKN+h6FAe54//TNGF4k5C5LrGiWpZ18yT0Bat+Y0fwh4W+b
         0ICg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Ac/G3mitpqPfGiFti7BYttsHS0KQ0R4yHkVEbJpaJA=;
        b=nyWDou68VHfbJXjs5ujGVleZ6FiHgntUmp3L2RL1E0j/c6dtVOf71JMLw76hyLUmax
         qQKZ/V2+pfVlkH27TehLGvCOJfEsf6mua+jG2IaspBVCDR6EIfF63/NidFoXogy26ALv
         C/YxjOamdoYmPXCNTFU3XrxTOcpEGj8NoLopYZ2CvF6tzYcfIt/EPxzsB8vcAbwK4qv8
         A1A6qc+OaQHQJupM4lzHnOVjMmNs+cN/5p+ocyNwElm6M5bcFyk+jFOOFxx+WJ5EjBtJ
         0XxnMPfr9+tDjU9i1CbmojvVRDQF4jktGDhekINQYu9Xi6GbS4dTxuKP6VXwhcThqXnh
         XC9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Ac/G3mitpqPfGiFti7BYttsHS0KQ0R4yHkVEbJpaJA=;
        b=oxdNR/O/gnj/8oT8AAqFss/UE1kTTwJXJSOx6zDz49IfhU9aYbbrGWyHjxo+3zwD/e
         vXQIH5EU2yZvFlXv9AOkAQheAeLdSCflMJkLU56/hnMa4upLFOS9L35J6uzCrFuf0/7m
         i+s2FnId4whsitFE6RHJ9W3FzVWRuk6waC/o3ftw7KgaRJZeKwLKQYxfXrOSeD1vScGi
         x1s3P6bo8VF6kjiiQ9DJQ96nWqEPe6vJYUYw3nRgvt8qn5PYtiJ6t3VHtsMl4ZlhUJLZ
         GYLHFI01p+YZoo/ps0CBBy2grh5BBSAOict2kLYW6Js9/1WuUCq3ZfBrJdeO5+EVqzl2
         Bbvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lwL9eB5UWLJxHaElJIHmVVBNzHLS5ZN1V2ReoBGNXVrQPsBJj
	oCvxjYY8Z3CDW9gIxpf0K40=
X-Google-Smtp-Source: ABdhPJzYBBiTwgOmxZqhL/SzrfsIybA6K0GQwKgufw4ybwZpEyNchVOOUboii4eT8MdwBEgUQYtVrA==
X-Received: by 2002:a05:6808:903:: with SMTP id w3mr6870327oih.59.1633522760862;
        Wed, 06 Oct 2021 05:19:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cf15:: with SMTP id l21ls1750243oos.7.gmail; Wed, 06 Oct
 2021 05:19:20 -0700 (PDT)
X-Received: by 2002:a4a:bb98:: with SMTP id h24mr17774489oop.23.1633522760505;
        Wed, 06 Oct 2021 05:19:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633522760; cv=none;
        d=google.com; s=arc-20160816;
        b=CBI/zlVtYWY4TI2xVgnWPNedre/D6mL0NPpIQtITk55IOASWUQvIPTfemVKjR0T83d
         0W/xbCVItUKFpx3Jized4gEwWTCpJ+SZlX/2dmD69Y0wsQ4TKyJomXRahzUTKSCi/LQ3
         9RCgd1ZxAdijUf7a3W3hDWA0hDTqaWUCIr+wN20FoXUOcsGGlaFQTeHddJAvw2ECiGHU
         E5z3Yf5nMhZPLHuvTfPZIGcTkIvov8nRI2jNUziLIsaK7wC/Xx1D4w1Toihqfe6VphOK
         2DMfGK2EfW9Y2TTdKbxfeJSZxJ3J+yuN4/JAgdQjx7hY93dLD5WYrD5Jws2swJeWd7Tw
         1BFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P+psjcpEfkkPYUD4niLYpNlBdseGbXQDj/wP/GbAAbI=;
        b=aDR1k550WXGMHpBKZSfD1P4J/gWc0siXXkvGiSMEZaTt8myDJFN+qpVPvp1/g8BUau
         DiI1+ayWBeKq0YmNB94TP9yiayjmffO1r2OP6dePJhtb5IB5RszduW/fmn149iecSq4v
         i667f1++6vu1f0JKvoYj1EQlUsZ48q+OTk30P9OYVElQcK6B4b8l/K9mQ0JLCrYM+DsJ
         vXW0AAIYwihSZzll/H7cu4aDDyzHP2FxFklSLFZu0wKimg/s0H5CGzWajNxcqvWa6+3C
         zlz6eB5289vhVIesOJfn3ze2dKj2ZQybpoW7jeKCrtjBDBJZxRBFbL5Ch5fgbE0BRauY
         YQ5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iPCsObQh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id bi42si2766539oib.4.2021.10.06.05.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 05:19:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id k13so2619758ilo.7
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 05:19:20 -0700 (PDT)
X-Received: by 2002:a05:6e02:bf1:: with SMTP id d17mr7028913ilu.81.1633522760314;
 Wed, 06 Oct 2021 05:19:20 -0700 (PDT)
MIME-Version: 1.0
References: <20211004202253.27857-1-vincenzo.frascino@arm.com> <20211004202253.27857-5-vincenzo.frascino@arm.com>
In-Reply-To: <20211004202253.27857-5-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 6 Oct 2021 14:19:09 +0200
Message-ID: <CA+fCnZeL48oLd8bbWgxomc6WnS4e53a7K6SwBpKBJND4f03f7A@mail.gmail.com>
Subject: Re: [PATCH v2 4/5] arm64: mte: Add asymmetric mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=iPCsObQh;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c
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

On Mon, Oct 4, 2021 at 10:23 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> MTE provides an asymmetric mode for detecting tag exceptions. In
> particular, when such a mode is present, the CPU triggers a fault
> on a tag mismatch during a load operation and asynchronously updates
> a register when a tag mismatch is detected during a store operation.
>
> Add support for MTE asymmetric mode.
>
> Note: If the CPU does not support MTE asymmetric mode the kernel falls
> back on synchronous mode which is the default for kasan=on.
>
> Cc: Will Deacon <will@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  5 +++++
>  arch/arm64/kernel/mte.c            | 33 +++++++++++++++++++++++++++++-
>  3 files changed, 38 insertions(+), 1 deletion(-)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index f1745a843414..1b9a1e242612 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -243,6 +243,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define arch_enable_tagging_sync()             mte_enable_kernel_sync()
>  #define arch_enable_tagging_async()            mte_enable_kernel_async()
> +#define arch_enable_tagging_asymm()            mte_enable_kernel_asymm()
>  #define arch_force_async_tag_fault()           mte_check_tfsr_exit()
>  #define arch_get_random_tag()                  mte_get_random_tag()
>  #define arch_get_mem_tag(addr)                 mte_get_mem_tag(addr)
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 22420e1f8c03..478b9bcf69ad 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -130,6 +130,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
>
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
> +void mte_enable_kernel_asymm(void);
>
>  #else /* CONFIG_ARM64_MTE */
>
> @@ -161,6 +162,10 @@ static inline void mte_enable_kernel_async(void)
>  {
>  }
>
> +static inline void mte_enable_kernel_asymm(void)
> +{
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e801bc5312..b6ad6b861c25 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -26,7 +26,12 @@
>  static DEFINE_PER_CPU_READ_MOSTLY(u64, mte_tcf_preferred);
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> -/* Whether the MTE asynchronous mode is enabled. */
> +/*
> + * The MTE asynchronous and asymmetric mode have the same
> + * behavior for the store operations.
> + *
> + * Whether the MTE asynchronous or asymmetric mode is enabled.
> + */
>  DEFINE_STATIC_KEY_FALSE(mte_async_mode);
>  EXPORT_SYMBOL_GPL(mte_async_mode);
>  #endif
> @@ -137,6 +142,32 @@ void mte_enable_kernel_async(void)
>         if (!system_uses_mte_async_mode())
>                 static_branch_enable(&mte_async_mode);
>  }
> +
> +void mte_enable_kernel_asymm(void)
> +{
> +       if (cpus_have_cap(ARM64_MTE_ASYMM)) {
> +               __mte_enable_kernel("asymmetric", SCTLR_ELx_TCF_ASYMM);
> +
> +               /*
> +                * MTE asymm mode behaves as async mode for store
> +                * operations. The mode is set system wide by the
> +                * first PE that executes this function.
> +                *
> +                * Note: If in future KASAN acquires a runtime switching
> +                * mode in between sync and async, this strategy needs
> +                * to be reviewed.
> +                */
> +               if (!system_uses_mte_async_mode())
> +                       static_branch_enable(&mte_async_mode);

Using this variable and function here still looks confusing. Maybe
naming the variable mte_async_or_asymm_mode? Or
mte_async_fault_possible similarly to KASAN?


> +       } else {
> +               /*
> +                * If the CPU does not support MTE asymmetric mode the
> +                * kernel falls back on synchronous mode which is the
> +                * default for kasan=on.
> +                */
> +               mte_enable_kernel_sync();
> +       }
> +}
>  #endif
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeL48oLd8bbWgxomc6WnS4e53a7K6SwBpKBJND4f03f7A%40mail.gmail.com.
