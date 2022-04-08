Return-Path: <kasan-dev+bncBDW2JDUY5AORB26TYCJAMGQEFIUQZAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 078194F95A5
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Apr 2022 14:26:21 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id i16-20020a170902cf1000b001540b6a09e3sf4432790plg.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Apr 2022 05:26:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649420779; cv=pass;
        d=google.com; s=arc-20160816;
        b=D8H3U7Me0v59tb43sSKZQhqqLWnYSnHgW5Q2LBHgJNi5Kr4vBZMWSy3D0D2JJ9Rgcs
         gOMYljH4//0lg4VjbQhGCNXafCbMRFsxSJ1oSbcI2UK0XeR9M4NDZpTb0G2FVHhvdkvs
         /RLRWihyfNQGBc2xgKuBv9XBODWSGqUD/IM2eJ5UJWb7isk41DZTp55KtlszxT3MBICH
         G3I3G5CxRcXa5kTusDT35I3Swd0VWRHV4QoehZldcOm+u41tirWmpTwiCkLcKSXAfc4z
         vapCsWlFTQF+KGVQpGoz1EheMhFeI2XhEpJLUvFZ9fEepbE+lWqQP9Wqxu4e0NW12thb
         LuuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=1XtQjiPmTouTt9Ux8g4475wwVLpssJOkIm35+zsnT4M=;
        b=WDJnkEd+iwn4k24kPuKeQobZEzFRxONKh395s536ZxzkXNuUkIycZAPDOdDIazwgJS
         AiRBVtmKkaKjD12KLi/1chBb4Eq5uF3SPSmvbmVDdJwtW8cMB39fhjU6Cb04qENLNeEa
         yy4ly3wYhItJNnDIHnDppOpIZWXisWvg/hciaiFKPMIZ+a+BqtSTFW8T8fkj0Xh/R2eq
         uyGxI4CPFYCC0naqpMOpOA8aHbGX3hVjxkYfLV66P8RNBpIQnmavVykE9ZdQfpI5AYbR
         6K9/QwDqAEwFKwWxdESGcxZK7lMT6ydoxv1vWLMcd9TI+Kx3A+IIjVA6n32SpCJ1MQhG
         nIIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=esQabPT8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1XtQjiPmTouTt9Ux8g4475wwVLpssJOkIm35+zsnT4M=;
        b=P1KAPo62ls8dxtbsZTPGxvnid16kkHlULL8OdeF71s+HR+1hz2oGMpBJfmZX7pSSK1
         HH+5bRwA+GwYB8cYrQoZ5bf2ALUKf6nHgSZQqB/pAE887imQ80ehKEbIJSjVM+oU1E5a
         Nw+8RWUoRthxMskNmxqV5yrnFp90+VmnCgh3/6RKCELTKIbjLHEN2W6lFzdpboIhrydN
         OcBGQlhX00xJAPOSSsEFKHVAZXgYWg0oLX+B7iyf2iP+9h95M9IpSY6FqfuzD4PLKXau
         9tOVc6tSLhhbtQXgAHFLXyCK8kBh3llifp9G9MPqLGL2Bz2QX9pxHka/daVN9yKMjRQ8
         pJbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1XtQjiPmTouTt9Ux8g4475wwVLpssJOkIm35+zsnT4M=;
        b=cwGL549arTIJaP0vo/k3Vvrs79H01rhTNRphEZ2GVSX6hTaafMNsDKsFnOjBqAV62f
         DiGaxZYEfMNpHRnsFF0pGSVsxt6KYHR/WXIxItr0VQG4Q9U25Qf2SK88U8m+BmRmK9j6
         fkh0Cbkx/azfhTV3PMVs97HUVqTyQq8UIdkBWUXu837795pvscDTidxHUVQjP55/ju0u
         h1qXZo9gKKYjCuSPfSqF9+sWtPYwOh+BrbVbVTEwiwhci8hwc2BRLndlRYjUkX2v8XHf
         DkIoa3j4XqshpCDhvpHlAiLEjaQK5OIsoWyQre8Jhg6SPNKApg9wNltiKt8ecdOmRprO
         V1Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1XtQjiPmTouTt9Ux8g4475wwVLpssJOkIm35+zsnT4M=;
        b=glDPgDA7GRRXTGZkOIkffZhEzjaK5T3xGEDwRbjqETJMFh8lqWZXVjKAB4l1FEbsVq
         Z3kq05J/gbpRdtkZxw5IB7FTqsGMLmY15/BgfEQkkn4+7sweuXjQqou59OUjKzej54Hc
         Kb76Ne26qiUkr+7n4zYrKXcmxAflo4/3eFpNi6e2AgxpUY0YGftdb94HW9e3ymxlPwTD
         5SZ0q5nDCKlf8CCKBpcSA0okbAKuq6N8Q4oSrskGOGNzR9dRGyk20B9+cUt3ze/JSMuH
         LPosOavZj/eXPBrns5z0hsX9UYEK3uSRioH/MvxDcgJyZ21B1+mZ6bjlhVRAiX93gfsU
         wRBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ALIu4vIBbxoyecKUbq0DZx7FaIbJ6WJWqhcZfPhodgeExOUt8
	e24cJKay8USql0KZ0PWjvgA=
X-Google-Smtp-Source: ABdhPJwTqFUR9VlJpigYcMFPqeHm/V0eYtc83N86PSxJxW9PQQpsVIkQNkKNdNEw6Wz4JvnhPxESYw==
X-Received: by 2002:a63:df0d:0:b0:373:401:6818 with SMTP id u13-20020a63df0d000000b0037304016818mr15221434pgg.34.1649420779426;
        Fri, 08 Apr 2022 05:26:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce01:b0:156:af8d:3b65 with SMTP id
 k1-20020a170902ce0100b00156af8d3b65ls1692936plg.10.gmail; Fri, 08 Apr 2022
 05:26:18 -0700 (PDT)
X-Received: by 2002:a17:90b:3c0d:b0:1c7:ecae:e609 with SMTP id pb13-20020a17090b3c0d00b001c7ecaee609mr21371110pjb.61.1649420778778;
        Fri, 08 Apr 2022 05:26:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649420778; cv=none;
        d=google.com; s=arc-20160816;
        b=R9/C5Qz+Q0PxDfaIZlLKzHeNajOkO6oNIM4Es6wPy5BdgWTXdUp2nk4upSRtHYRKTg
         pgEtu6/7NIHN73KG7//qA5v7j5uqN9QwtxsIRl1s+Ljmsl5IR9ohH6Fom+GHlcBB2Ejv
         eZVgQFAr9MWmMBEgue9qggVeUobcpQq76L9rTOxVFHeJb/VdI4xi/3XrpUdZ9yOaEzTi
         mArYhkt/XSmzghGYBbqcaRH88k0u/EnQlZbaC8iUNzNBDBdVd36Giq1aXcVAwbU1lvFB
         IFHq1wdpvJuZbfmEBNY2adGU3jvaBZqSQ8yy+VsEjmbj0UtsT39ul79KmkqeE8PSCags
         vx+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=14DprhKsqJXStRxJvQBVCHfnfpx5IJV0lotlrHWmtH8=;
        b=hK94gzp0VgV3yPRzutjhZjGR0aVkLJ8W6ILCbWveSYYjC1r/grYt4JGdquIpkDprFV
         EhJp99HGj3R2RHZ2ggTLPIjSgbj2+NKWHhfvtmUe0avrbp7mHC3YYVgP7Mwvfo7s9nhz
         l4sh6AMprKul5DKYhnrm/nMlyShW2rt2oKGEOR+moFSJ0IvZory67tuE+zr55lhBTYcR
         QcYGwP2LQs7ZZvcl3pnjQQjJWf1dFY9sbjkEf/ivkPbpgnBjyJfk+3zB64aBRPLFwAr5
         5b8yHNmrF8PNZTa5h4aEa+oTlrcO9aVYqOj+WVr4LjR+KMpZBsWIEMJXBO3tpZVV1GXk
         +ntw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=esQabPT8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id y5-20020a62ce05000000b004fdca03b475si154733pfg.5.2022.04.08.05.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Apr 2022 05:26:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id x4so10349241iop.7
        for <kasan-dev@googlegroups.com>; Fri, 08 Apr 2022 05:26:18 -0700 (PDT)
X-Received: by 2002:a05:6602:490:b0:638:c8ed:1e38 with SMTP id
 y16-20020a056602049000b00638c8ed1e38mr8279012iov.202.1649420778200; Fri, 08
 Apr 2022 05:26:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220408100340.43620-1-vincenzo.frascino@arm.com>
In-Reply-To: <20220408100340.43620-1-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 8 Apr 2022 14:26:07 +0200
Message-ID: <CA+fCnZcoFWXyhjfKSxPh2djiTWjYCh2xmirPehyJS94DaoJC9w@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix hw tags enablement when KUNIT tests are disabled
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=esQabPT8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
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

On Fri, Apr 8, 2022 at 12:04 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Kasan enables hw tags via kasan_enable_tagging() which based on the mode
> passed via kernel command line selects the correct hw backend.
> kasan_enable_tagging() is meant to be invoked indirectly via the cpu features
> framework of the architectures that support these backends.
> Currently the invocation of this function is guarded by CONFIG_KASAN_KUNIT_TEST
> which allows the enablement of the correct backend only when KUNIT tests are
> enabled in the kernel.

> ... and prevents to enable MTE on arm64 when KUNIT tests for kasan hw_tags are
> disabled.

Oh, indeed. Thanks for finding this!

> This inconsistency was introduced in commit:
>
>   f05842cfb9ae2 ("kasan, arm64: allow using KUnit tests with HW_TAGS mode")

No, that commit is fine. The issue was introduced recently in
ed6d74446cbf ("kasan: test: support async (again) and asymm modes for
HW_TAGS"), where I changed kasan_init_hw_tags_cpu() to call
kasan_enable_tagging() instead of hw_enable_tagging_*().

> Fix the issue making sure that the CONFIG_KASAN_KUNIT_TEST guard does not
> prevent the correct invocation of kasan_enable_tagging().
>
> Fixes: f05842cfb9ae2 ("kasan, arm64: allow using KUnit tests with HW_TAGS mode")
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/hw_tags.c |  4 ++--
>  mm/kasan/kasan.h   | 10 ++++++----
>  2 files changed, 8 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 07a76c46daa5..e2677501c36e 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -336,8 +336,6 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
>
>  #endif
>
> -#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> -
>  void kasan_enable_tagging(void)
>  {
>         if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
> @@ -349,6 +347,8 @@ void kasan_enable_tagging(void)
>  }
>  EXPORT_SYMBOL_GPL(kasan_enable_tagging);

Please keep this EXPORT_SYMBOL_GPL under CONFIG_KASAN_KUNIT_TEST.

>
> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> +
>  void kasan_force_async_fault(void)
>  {
>         hw_force_async_tag_fault();
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d79b83d673b1..b01b4bbe0409 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -355,25 +355,27 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define hw_set_mem_tag_range(addr, size, tag, init) \
>                         arch_set_mem_tag_range((addr), (size), (tag), (init))
>
> +void kasan_enable_tagging(void);
> +
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  #define hw_enable_tagging_sync()
>  #define hw_enable_tagging_async()
>  #define hw_enable_tagging_asymm()
>
> +static inline void kasan_enable_tagging(void) { }
> +
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
>  #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
> -void kasan_enable_tagging(void);
>  void kasan_force_async_fault(void);
>
> -#else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
> +#else /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>
> -static inline void kasan_enable_tagging(void) { }
>  static inline void kasan_force_async_fault(void) { }
>
> -#endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
> +#endif /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>  u8 kasan_random_tag(void);
> --
> 2.35.1
>

Thank you, Vincenzo!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcoFWXyhjfKSxPh2djiTWjYCh2xmirPehyJS94DaoJC9w%40mail.gmail.com.
