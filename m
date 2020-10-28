Return-Path: <kasan-dev+bncBCMIZB7QWENRBSM44X6AKGQEND4O7UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9096329CF97
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 11:56:10 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id j190sf798072vsc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 03:56:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603882569; cv=pass;
        d=google.com; s=arc-20160816;
        b=PSWa9Oco2+x35HTuyBap3Aesa4RC1ovt2VUdkzNvuE8V8NQieb9XHh5c7gqHS6hkV1
         I6fMVaJABWxarqUAXbj/4hgfX82XW/pZhZBZNMtctahwSUKGiiyiMtL1DIJmdwaTVkKa
         LBBPIytSTCErsSkcmJzggSI2FAPGr3+QPBV5pQrINy96Auy/FVmbWlcVLv5MHi8Q2B11
         4dfWL8uc5F+EB0cjQ+lAJuyQR68sTw5fucntkFdepNYRA/H3VDAQCtxOaKySCTgkmdvU
         wc/st8kBAscYjDWM9CBg9KK/p5K2KRsoWrTdRzmMfNfGMKliA9fe79ZXElsKLuy8PLsX
         /01Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3T5bRFvpxq0JOb6mZhi13KhItxrPOljBvM9OpliBRMw=;
        b=qnqrbp5hxzYzKHzwO2aQa8orCcjuewrz8dAizthQVBnuOaTemwp1RA42V8CvakqGef
         yelbWNsqPOsilBlvrdxHNRJXuOvPJziqMlXwzdigLo4Pmii8a/rInDHGSSC4ylmJ6shZ
         Ej7lx18cTq5hvj/XUnpFJS7wgnJ8+cqx1jdZ/0B+sSqP49SLjfQEbGgAex1NLrHhHhLk
         bNHYh/g2m4+Ut9ZbvKFKOBEdF4v5xtbC35w3vGKXqFLOstIM7tjTEGdNe8IgGe0iQ66p
         O+gsFD85o9x2MQevbSURnq59onKNXtLs+fpDrGvgYp7VNa/+LiM40EM3Avd1A6AymTvP
         uITw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EchNxfjW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3T5bRFvpxq0JOb6mZhi13KhItxrPOljBvM9OpliBRMw=;
        b=QWzs3g82EnGy/08gQ13MjD3yP8rw7iEqzxvT17+itofhtGn99cS+Fu4tI2fQArT3SK
         7Y64G44qMKsqldsO7Jso3pD30tQVa/CQkGHDHcuHKDpnfI1qwddBy1wMpMXaTb+VInVQ
         Vjg/hT82odOhH8K3An9s8qD/hXO39Ih81kov4qYB2lIzY7pC8BgAQFjhDGR9kZPg++LB
         3SboFPZyxzXMsjfyHiDYMa2ohNBj+CgVgh8qJj5QLKKAgLrNd041rBiW47U0cpe/hcu5
         QMEPsG7WXd0Sr+8LbGhQCfor78EKEYvgXHRrb6GMSx9vTNnRD62bD4/2D4J1/8zpIP7W
         LMKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3T5bRFvpxq0JOb6mZhi13KhItxrPOljBvM9OpliBRMw=;
        b=ebndm3jE7dWnyHhFDt0sryfAAsx3fHYJd+Q/+vd7GkDa/yj2sMfpNNm/XYIynY/7nf
         a403ebW6TF/fK4bwfwa3qoAlJzXPEcSO08CEkBqPi7DSjXhmKj0cTyb5FaiYdoxyplAQ
         mNBSNT/mdlJ+h9tbqo+Bb0PwfXrlCqQoC9O61xkMp+T08gWvNBjiViQ5vzJYHQVL3nno
         OhP4pvoXkh03A0THElcBxbXCL/W/JuHBkratvo4bPkrR4wgbkUVSzZCTekDZUCqsnTaA
         +4N1Sv8XR7oEb9KaKtDU+3/2jmWgx/1/fVUGyxiI8D4qbZ8Zpb1XzfgtDgyrntf9Zs/S
         99pg==
X-Gm-Message-State: AOAM530lP53+qGkIytPWSqDP5P8pkTGOIiJp7zdCeRxfnWzWpfCqBh74
	pmGDWKJeYkEVNtK/4jZWDw4=
X-Google-Smtp-Source: ABdhPJwbhW4+XiPv2wc5l2Itm5sy3/bfsl88tyqpvpkqn/IukoabA9YlgeZ73PKDIpKWI2XUryUUXQ==
X-Received: by 2002:a9f:2436:: with SMTP id 51mr3671819uaq.103.1603882569571;
        Wed, 28 Oct 2020 03:56:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e29a:: with SMTP id g26ls576502vsf.6.gmail; Wed, 28 Oct
 2020 03:56:09 -0700 (PDT)
X-Received: by 2002:a67:fa50:: with SMTP id j16mr4395733vsq.51.1603882569073;
        Wed, 28 Oct 2020 03:56:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603882569; cv=none;
        d=google.com; s=arc-20160816;
        b=cnI59N6Lh86cVunl1UQrbmJ5E5gb6nJxTIjIal04LykV1U/oIYXu/+NNSyOlGDNYHG
         G2omc21jzQc6GuYeILtPKairiilSvaUC0UQuktFXvi3SoGZbfu/U8/PpmSj62XpZeo0/
         gmLemKfx3mxvoLKMYaRvOmfN8DAMMgO53FFxaLh/xjbYrYDNbLsDKCtP7VV7XVQoD0jq
         lHpgGDjOC9WRMXgmfgFgJTgbUybAitiAb0cJg7cD79ud1DQ+OiawSfoJu6ejM+j3r8Yi
         vcw8zjGfRJOztEmS5nPrrQCDQndS7eyLgI6Lcm6wVk/h+aO46nKO8CUM7/9HHijzQMYr
         4xsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hsdkNzdMfWbXcZddXcT8aNBIhrkn1PkorkEU1qPCnjs=;
        b=LnOiRam+j9ruTivrdgzjoR/ZRARicrMcwlGkyMHc0xd1ptZjM0CN6Jsl5LJjemIZxP
         LC3J289925tTr9PH3BNhKW6uw6TNx7mGHOT+hRuiM6M6VswBR0pfxeKdLWvmLxRhLsRi
         GSXxRvpbhwdMn/yIs1W0K5jsXPDnVfOLPfmeyA1u2n1+LrXG3tptVVk+us8Uc7PqHROK
         RRrgX7B/StDUy6pcuym4oJaFlsup6NxbLjI9HumsAspD8ScRPLZN+t3yshsX3SqD9cG6
         ooMEsI4kI2As0D2XQvGLduRhoEwJ7337iNgaDx90XyEWzcQxQ1hz3vXsFel3lhwRYZ9+
         EFRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EchNxfjW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id b16si337309vkn.5.2020.10.28.03.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 03:56:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id c5so3171524qtw.3
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 03:56:09 -0700 (PDT)
X-Received: by 2002:ac8:6c54:: with SMTP id z20mr6093592qtu.337.1603882568390;
 Wed, 28 Oct 2020 03:56:08 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <1d87f0d5a282d9e8d14d408ac6d63462129f524c.1603372719.git.andreyknvl@google.com>
In-Reply-To: <1d87f0d5a282d9e8d14d408ac6d63462129f524c.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 11:55:57 +0100
Message-ID: <CACT4Y+Y6jbXh28U=9oK_1ihMhePRhZ6WP9vBwr8nVm_aU3BmNQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2 07/21] kasan, arm64: move initialization message
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EchNxfjW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Tag-based KASAN modes are fully initialized with kasan_init_tags(),
> while the generic mode only requireds kasan_init(). Move the
> initialization message for tag-based modes into kasan_init_tags().
>
> Also fix pr_fmt() usage for KASAN code: generic mode doesn't need it,

Why doesn't it need it? What's the difference with tag modes?

> tag-based modes should use "kasan:" instead of KBUILD_MODNAME.

With generic KASAN I currently see:

[    0.571473][    T0] kasan: KernelAddressSanitizer initialized

So KBUILD_MODNAME somehow works. Is there some difference between files?

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Idfd1e50625ffdf42dfc3dbf7455b11bd200a0a49
> ---
>  arch/arm64/mm/kasan_init.c | 3 +++
>  mm/kasan/generic.c         | 2 --
>  mm/kasan/hw_tags.c         | 4 ++++
>  mm/kasan/sw_tags.c         | 4 +++-
>  4 files changed, 10 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b6b9d55bb72e..8f17fa834b62 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -290,5 +290,8 @@ void __init kasan_init(void)
>  {
>         kasan_init_shadow();
>         kasan_init_depth();
> +#if defined(CONFIG_KASAN_GENERIC)
> +       /* CONFIG_KASAN_SW/HW_TAGS also requires kasan_init_tags(). */

A bit cleaner way may be to introduce kasan_init_early() and
kasan_init_late(). Late() will do tag init and always print the
message.

>         pr_info("KernelAddressSanitizer initialized\n");
> +#endif
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index de6b3f03a023..d259e4c3aefd 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -9,8 +9,6 @@
>   *        Andrey Konovalov <andreyknvl@gmail.com>
>   */
>
> -#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> -
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
>  #include <linux/init.h>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 0128062320d5..b372421258c8 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -6,6 +6,8 @@
>   * Author: Andrey Konovalov <andreyknvl@google.com>
>   */
>
> +#define pr_fmt(fmt) "kasan: " fmt
> +
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
>  #include <linux/memory.h>
> @@ -18,6 +20,8 @@
>  void __init kasan_init_tags(void)
>  {
>         init_tags(KASAN_TAG_MAX);
> +
> +       pr_info("KernelAddressSanitizer initialized\n");
>  }
>
>  void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index bf1422282bb5..099af6dc8f7e 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -6,7 +6,7 @@
>   * Author: Andrey Konovalov <andreyknvl@google.com>
>   */
>
> -#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> +#define pr_fmt(fmt) "kasan: " fmt
>
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
> @@ -41,6 +41,8 @@ void __init kasan_init_tags(void)
>
>         for_each_possible_cpu(cpu)
>                 per_cpu(prng_state, cpu) = (u32)get_cycles();
> +
> +       pr_info("KernelAddressSanitizer initialized\n");
>  }
>
>  /*
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY6jbXh28U%3D9oK_1ihMhePRhZ6WP9vBwr8nVm_aU3BmNQ%40mail.gmail.com.
