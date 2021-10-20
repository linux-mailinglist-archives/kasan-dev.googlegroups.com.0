Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBEIX6FQMGQEOHKWHPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 539FA4345DA
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 09:23:49 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id gw8-20020a0562140f0800b0038366347de1sf2065960qvb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 00:23:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634714628; cv=pass;
        d=google.com; s=arc-20160816;
        b=TsuRVYhT5U9/qii3ljCI5N5nue5NwX4x49xjdpIQtn5aLwVoLIuUyVsuRpMRz9xFPn
         2nqMIgiSTKcWatprcl/FakZdvxoXFo7n29yztwngdTFeQX/aJr4G8GqP90dQfUjkIj9Z
         UABaRLXDgweNVirb5TvQEqNltk5A2PPEo8Z37RGQg+DtRlVfjD8/NoGZq9Z9o6SxTMAU
         LiGIuYRbqupvNhp2724b4hATcLGEeFXZryGxlDp308+LuBCjzcIzODHU51EeA29yqbPO
         CeF+61tgVod7sW7Y06pMULCQPmDLEftVvvD4WuhzHdOVlTpVfcB86hHcH3kX07cykRc+
         xf1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5oefJuJEOpKm5VEy0I9BCVTI0jl7bvR1ED1GYK72mz8=;
        b=YNhuWAaVhnPrrhh7SfXisdCvyUdDP7zRtrwxnEkYBWU4MzaCVOiAbXBwS9X+CZ/RH1
         w+E+8WB8wQPX6XLV0ZNF//DHj+N4bA1tpEbqyDbPKDHB/a6RSWd8GN2jFQk2seva0Ucw
         A8ch7KOFshm2fF/yYP/6ngSN62T1fT8bEPZ7KrwbmKJhwjHg9Vm6R3YP/frNSEo7G6pj
         egV54abF/JO9K89asJS9pFexyFb9o/txzZrpMdA2/+QL0y/IUVVIXR14TcSiIYofE4jJ
         lQGAw9DikkjxGAWJxsZKo8lBIY9l8iW+poQWbFb559b4ZLLOyn3CxvzA8PwdTEqx4gQt
         Ab7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z9H2n0S4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5oefJuJEOpKm5VEy0I9BCVTI0jl7bvR1ED1GYK72mz8=;
        b=aH0UgmaNO35rqhJbn5Om2FX3T55lzyszVBE7swUuOF5UHd/EnL1Z7sgKkWan1IxMD6
         XfHk2V9OxDmcoDsOsDZ+jkepD0uLFev0/ydOBqZY0Ac4SSuEP7YVEzbSg3qZZoBJ/8IU
         thzvezedgszkalI9Wpxna9j7v9a4TcrudQauon1D/3hnCGjstnYxWGGpneDY9mhnLIYI
         /1vSlyDBVMnxHaCA0NWV74Jz9r/m+/nMOQKiK7rY6jG2vAlPxC8tSpBiSqd8jmV8tXYz
         DBidhlvxIGFMFhmK74ujwtzJFldaGAQW43l8d48v755jEmaDoqFGy33sJxmmnuJN5UbG
         1xBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5oefJuJEOpKm5VEy0I9BCVTI0jl7bvR1ED1GYK72mz8=;
        b=6ZwH6rI8xEb0MJgHmetvr9ZH8lHvMD2yYKxm9rdB3/rYLIYnEj1PiMI414LQVVJrU0
         d1Bm8agNAZFzVbccGTDiLtIgZhZgPJED4PnLWWFrugrArQoBXr2Fd4jO6Rblz98BhKbA
         GzNy6pO2VrZVZFdk1nng1HssW+aJHOD94Es3T96pUjpMisw5ulAt2dG3S9zPMk9oE8Yy
         sJN6kSMRgbWUTFfEdgigVXAbLW1VFJTv61VHXcMXumoeUKx121lg57u+gVr2rkYFM8XE
         72A/2aYWL+hF3GVTlwvFjJYOl7zJPC6MrbtOll5YeeCtU4QHpGz/RHUEcq1VnRXJtDee
         C85w==
X-Gm-Message-State: AOAM531GVwmtx/KGBIxn1Rr9CUL4K1hiCKFBQ6afXMDPH2q8G//D2M2g
	MbKvpvGA63tF4JW23sA16cI=
X-Google-Smtp-Source: ABdhPJy/TTGa5CF6ByjPKo785xQp99f/3hKLBZchYZB092DD0UHhgXJ7LHQxPmumYaOOgmomC9fn9g==
X-Received: by 2002:a05:620a:4014:: with SMTP id h20mr3796573qko.449.1634714628158;
        Wed, 20 Oct 2021 00:23:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:11a:: with SMTP id e26ls741776qtg.5.gmail; Wed, 20 Oct
 2021 00:23:47 -0700 (PDT)
X-Received: by 2002:ac8:7294:: with SMTP id v20mr4965084qto.51.1634714627688;
        Wed, 20 Oct 2021 00:23:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634714627; cv=none;
        d=google.com; s=arc-20160816;
        b=sabOyV1WtqBqClsPVE0cbzK7jrPntt2HwZH1A8vC84ocu1se7C4AymTKg4n+RzloAn
         l+AFSpQYJkOdeXDx9ye3T01n5bb2jEzW2rHTG+m9iK94yaWMM4JW+UlRJvN1hqym6X6f
         EVFdIBNnp28fd0W3HF8B06numAGimN2nKKdTirbGXvekyQnmTRXrG+fZ7C2Hj6dnvKjJ
         Dm/Yx8hWaV+e4VCYTtFDD1wMymspQ1qUlNd71MnijZ/0x6xRo2BEgXxFLQ46XEYvoHrp
         zAncfCjmjSkh425S3BDRFRzq8Kov7eCiCY7Uo61U3KYp67vnP7H2613d6/Ory31hrc0j
         rUBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kU2IPRL8ftmwSTb+WFMJqCEa8tDzkDYqWbLRrE2BrPc=;
        b=pZCFDB3p6+f5DrGuRIGufyDN0wymTh1IvObDgwdwCZ3AiM4SUv3BNevaUgJsUoW2Vn
         DXYgipyZlXAyUHneKVmmogO6xmsnUIVkCtSHd8+pMyDePKZRzpzH4kKhc1n/7+cVfQoK
         1MDkZnFeXsTUi49SFt0Vuyzh6NMU8iq6+MJyUHbyzHJ5OMtYC0afQWQAZvIrblTWv2qg
         39pMfCRoriE/0LVmwr3BX3D4L17xsajl7YtihNgGy63mCcte3+47flagVfiT+QgC/7Px
         L0nTEbF+f8DhYqiTM+S31Ycjo+7+tku4ObZlKpm9md6RklLcITbkOqr7w9Br/0bYvcQP
         B1zA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z9H2n0S4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id n20si138646qtl.1.2021.10.20.00.23.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Oct 2021 00:23:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id x27-20020a9d459b000000b0055303520cc4so7152944ote.13
        for <kasan-dev@googlegroups.com>; Wed, 20 Oct 2021 00:23:47 -0700 (PDT)
X-Received: by 2002:a9d:2ac2:: with SMTP id e60mr1361127otb.92.1634714627015;
 Wed, 20 Oct 2021 00:23:47 -0700 (PDT)
MIME-Version: 1.0
References: <20211020061248.13270-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20211020061248.13270-1-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Oct 2021 09:23:35 +0200
Message-ID: <CANpmjNNxQRM5rSxcdxNOicpOvwQ=vsutQO3j1hUmGAfS9+pQDA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add kasan mode messages when kasan init
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, yee.lee@mediatek.com, nicholas.tang@mediatek.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Z9H2n0S4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Wed, 20 Oct 2021 at 08:13, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> There are multiple kasan modes. It makes sense that we add some messages
> to know which kasan mode is when booting up. see [1].
>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> ---
> change since v2:
>  - Rebase to linux-next
>  - HW-tags based mode need to consider asymm mode
>  - Thanks for Marco's suggestion
>
>  arch/arm64/mm/kasan_init.c |  2 +-
>  mm/kasan/hw_tags.c         |  4 +++-
>  mm/kasan/kasan.h           | 10 ++++++++++
>  mm/kasan/sw_tags.c         |  2 +-
>  4 files changed, 15 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 5b996ca4d996..6f5a6fe8edd7 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -309,7 +309,7 @@ void __init kasan_init(void)
>         kasan_init_depth();
>  #if defined(CONFIG_KASAN_GENERIC)
>         /* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (generic)\n");
>  #endif
>  }
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index dc892119e88f..1d5c89c7cdfe 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -177,7 +177,9 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
> +               kasan_mode_info(),
> +               kasan_stack_collection_enabled() ? "on" : "off");
>  }
>
>  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index aebd8df86a1f..387ed7b6de37 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -36,6 +36,16 @@ static inline bool kasan_sync_fault_possible(void)
>  {
>         return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
>  }
> +
> +static inline const char *kasan_mode_info(void)
> +{
> +       if (kasan_mode == KASAN_MODE_ASYNC)
> +               return "async";
> +       else if (kasan_mode == KASAN_MODE_ASYMM)
> +               return "asymm";
> +       else
> +               return "sync";
> +}

This creates an inconsistency, because for
kasan_stack_collection_enabled(), kasan_async_fault_possible(), and
kasan_sync_fault_possible() there are !KASAN_HW_TAGS stubs.

A stub for kasan_mode_info() if !KASAN_HW_TAGS appears useless though,
and I wouldn't know what its return value should be.

Do you expect this helper to be used outside hw_tags.c? If not,
perhaps just move it into hw_tags.c.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNxQRM5rSxcdxNOicpOvwQ%3DvsutQO3j1hUmGAfS9%2BpQDA%40mail.gmail.com.
