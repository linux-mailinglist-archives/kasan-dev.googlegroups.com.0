Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVFXOFQMGQEXT7BMBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 13E9B433825
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 16:14:20 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id g26-20020a63521a000000b0029524f04f5asf11696775pgb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 07:14:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634652858; cv=pass;
        d=google.com; s=arc-20160816;
        b=lDbvFXxudmGYez1/DveaHC65W1Hd8ulVmxfCYfRBAw1gCSkz+uAebUY1Fla7Md3KFh
         kJQl/NmCcdTKF3Jpf74ZS6MVKBdcgUwGqOZahulsQOMySYiRNGW64v9t6E2VLsIilG41
         H7+TnxwTn7keRFlGFLodrxk6ZlLjbEjUjB2p/lX6iw7B+FkNMx9zSmdCJ/qyJ3QPRQ00
         khQ29irrXo07PfVghKqHTkLlzTzumdxinQMynMTCBOdAav+a3VvgmApyZ8JhErRZstt2
         Sm5dbR9uc8lFTJnXo1LCJAha/x5QuXT4HdBOSDRdvWPSLhNlQfS5NN3n4zvSa4q2sLzz
         i9aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=S7gSHDf0EpgwdhQWCb9/WBP+Fo1DtzeqiUlnq2Mz47I=;
        b=Xy/w4TYwpWoU+yAbzTs2T3WxHFE3jpAWuspQ5lXVm9Gat465v/XlszlL3UI4UywiUd
         K8cAsOr46FT3cjthym8UWnn1BxDzkqL7laRXnzE+y882rQEEJfmPU68lw5kObUNq+nnO
         rw4lXJgReXH5mJ/azOqCuzUHwNm6VXmzF14lKf+2wOOe47Xys5yRfpGtCoF47+paaIyJ
         aWZCr3AFfhF7ublHWTS+U0JfyfpXDk++aeBkSuzq46pYgjYXSSryRdzoizYuMjjJ57Og
         s39CeI+naGSmAAfXuURnGJ2btM/SmG4w5zNwC0B917ixgiJet4p+gl3zroAgUNn2p3XS
         ++7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cMEnDjIU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S7gSHDf0EpgwdhQWCb9/WBP+Fo1DtzeqiUlnq2Mz47I=;
        b=gicDHEavOT5yJDawtCQruXcyYMNgHQGkiy0NZXi2FF1Pn22CoD4nYZqHu7eJrh1/4j
         IwZuqtp/TovMHeImQXkdnmtcmc8gouknlOM7IkWGVS0t3xXYvFMwm1LCRYNDMEpoJiIb
         UM6zRh8+9yM4UWYlxPI/afTOVjAWj9f4yEHTq9+VIo/E0etYMHh/tBZq28rAGUiIvevP
         wYMY2yIhUGcig8aFlbEquRHFsH102171cp0s2tx7OMjncqe63DCghe+DY4AjVhIV6BtR
         qmGaelAPyuEVdhzUFPIyiY192jDH6XVcuSGwcdAkYNCr/O5zgk/xVlBaq70urPvhqBTe
         mTyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S7gSHDf0EpgwdhQWCb9/WBP+Fo1DtzeqiUlnq2Mz47I=;
        b=U294TvpEBgHeOH3XbYtHSUrqpneehdpNqvoyO8g6jI0GuSfzxlUpCu3VAq2hc+QVBB
         6VUZNBjEWUER+w0ULeMuP0xTa4+QPFHOxfh6m6fPxEMd7POef10Cg8N3TeNhLno2lOAB
         tzdkqxzGSk+2eMl5xf3a1jAnDqQA3JU+MVIXlgrCVpJHyVQnDr1GYN+/lGLSg6KJe8nV
         wTniAE+wYsmvx3uEQhtoY0MQMQXiIQs8T/w6/D/T6Va63zWQMsB/AhUHMDGVCNVtltkG
         dSPv8rDyyt/sV/uO39ts5x3/aTocdB0TIDMqUu1jMHmj5O6yJ+rtY2sgPVZqc6LRvAVG
         FTfw==
X-Gm-Message-State: AOAM531StQDMDaKsGVqHK6fq5RGf8M1ZKmzQnBNeBQnqq2XoziHTalOk
	CH1D5qUigqcpqyd7BvuDlLg=
X-Google-Smtp-Source: ABdhPJzLH6xEijtSKP6Fm/CCPVkvx81zZ0h7n6FgTJSkTGPjANwgrfFSofQokCIfV37lpJ6Yr5c87g==
X-Received: by 2002:a17:90a:1a42:: with SMTP id 2mr46161pjl.202.1634652858545;
        Tue, 19 Oct 2021 07:14:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:758f:: with SMTP id j15ls11045706pll.11.gmail; Tue,
 19 Oct 2021 07:14:18 -0700 (PDT)
X-Received: by 2002:a17:90b:164b:: with SMTP id il11mr195610pjb.98.1634652857895;
        Tue, 19 Oct 2021 07:14:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634652857; cv=none;
        d=google.com; s=arc-20160816;
        b=0bVKv6Vo33luDrNu7WCGq81Uvj7RQfQZWu0FURvdHGWZ/2d6ajrmyiotAAIz1UhY7z
         iqJnnieupRJky5q6ZgVsYcYDouja7GkCoi9pGISCHO9Vbak/WUkJOeQQ4e4IOj16C11C
         d+arjg0LloUb4Qxb0KQ0MK5q9tutbD1cgS90E2HaFAiujwo6KV5ZGmI7IYFKT0dyQmKb
         c6V/epihojO/D2XjC4TGyd5fY+jKAZ1m70n3cyRnAOzhLsQgmK3lUTrSjX7Js9S11V5+
         KM5ETiXLckpo5KUlvNI0f2lXc0J6y2NTTllreG0JHRs82FMUegn02egkB+GxzVgcT6gU
         uPCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NdUwBl5vJzEY+z2qLVViXJz11eLRD5JHwkOtv2fvRgE=;
        b=LjdvsTmPwHZZ74ch7O46pigh1P2UjfPKaUUc/4pNJXfhdj8ZnJPTp5bfiRDgLLvcKH
         WNxVQM7qyLYQMUuaKf660TDJXFdm79lGTFKD1D7J1pa0wHY+xpXEzswwagAsRS0fW9SS
         GoJTXpq7CKHtUct/HpvQChvaS2MWAT9auHFiAYH3PBn6JN9uRZ/LB8WIjir0CmEme3uj
         wbVk479SOrevcJCHpQt1u2kddB8f/ZqdO2wVLeB3n5xapt5R781Xx4HkcHz1smfr1OsT
         iUSytDBWIj/rMQ/tb5FpFInoXpPJvTEGe1HcDD3JWpuzjCHI7BBpg2beAWD1B3WljAbi
         3s9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cMEnDjIU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id f11si493765plb.5.2021.10.19.07.14.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Oct 2021 07:14:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id s18-20020a0568301e1200b0054e77a16651so4220880otr.7
        for <kasan-dev@googlegroups.com>; Tue, 19 Oct 2021 07:14:17 -0700 (PDT)
X-Received: by 2002:a05:6830:1092:: with SMTP id y18mr5449783oto.329.1634652857393;
 Tue, 19 Oct 2021 07:14:17 -0700 (PDT)
MIME-Version: 1.0
References: <20211019120413.20807-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20211019120413.20807-1-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Oct 2021 16:14:05 +0200
Message-ID: <CANpmjNMMQUHhFTdaqfx6HErnv0aXkCJn+eBGN-kfeznN8H+f3g@mail.gmail.com>
Subject: Re: [PATCH] kasan: add kasan mode messages when kasan init
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
 header.i=@google.com header.s=20210112 header.b=cMEnDjIU;       spf=pass
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

On Tue, 19 Oct 2021 at 14:04, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> There are multiple kasan modes. It make sense that we add some messages
> to know which kasan mode is when booting up. see [1].
>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>

Looks good, however, you need to rebase to -next because of "kasan:
Extend KASAN mode kernel parameter"...

> ---
>  arch/arm64/mm/kasan_init.c | 2 +-
>  mm/kasan/hw_tags.c         | 4 +++-
>  mm/kasan/sw_tags.c         | 2 +-
>  3 files changed, 5 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 61b52a92b8b6..b4e78beac285 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -293,7 +293,7 @@ void __init kasan_init(void)
>         kasan_init_depth();
>  #if defined(CONFIG_KASAN_GENERIC)
>         /* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (generic)\n");
>  #endif
>  }
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 05d1e9460e2e..3e28ecbe1d8f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -168,7 +168,9 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
> +               kasan_flag_async ? "async" : "sync",

... which means this will have a 3rd option "asymm".

> +               kasan_stack_collection_enabled() ? "on" : "off");
>  }
>
>  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index bd3f540feb47..77f13f391b57 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -42,7 +42,7 @@ void __init kasan_init_sw_tags(void)
>         for_each_possible_cpu(cpu)
>                 per_cpu(prng_state, cpu) = (u32)get_cycles();
>
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
>  }
>
>  /*
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMMQUHhFTdaqfx6HErnv0aXkCJn%2BeBGN-kfeznN8H%2Bf3g%40mail.gmail.com.
