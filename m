Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPI46EQMGQELFNABAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 36FD6404A75
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 13:46:15 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id c4-20020a170902848400b0013a24e27075sf675700plo.16
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 04:46:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631187974; cv=pass;
        d=google.com; s=arc-20160816;
        b=B1ICVqMzElcp68iIBpVpOgJXcUYiPm2da9IDSsMXvX+JRQcIt+SlBqV5jf42a24G1I
         UX9nsCEASm7UAboz5Or16O/UhI3HlMF6fiRHSKXVvptY5Vmjc7A1QhdUQbhcDHLEyjwr
         Pba2eTEeJZosnYZXadhu0E8ErqIfB29gdPy2uaF9EQMdOfXeTCU3yA+p8kyUC5nPuivY
         riPjvdH1Rb21eFBBnuiPMhTm/FxEzuxTpluQE6rugj33IBfBHUhCA9YPlcbOfIrW7hGQ
         28nNjd0vMIpyjHHO0tmHnnqDpGy/f/v7grWKcERYtRz0wx2aKXogxgtg4869oNISk+63
         dpUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z6AjUrMwZH+yyzXUafN5pvTTmSmxiLar1w/8ZD9HOLg=;
        b=TKHJUUOFJfNtYty7F++a3RQLzQ3xbXKtiyzCP73LljTSA4P+/xX/laadvRlGM21f9t
         7NAggsKpEqusGCzsxva3Iqau1+nl9thgQeTmJUjcXlKsz+c1EuX4dBoAGVdtvA2m5bdS
         9BuR3SZobHAxGGZhJ+wD2D7BxnNaQsSJ7yTGoX4Q3cKSGWgZBF0u7EeuL4ClOaxdAmhR
         EwR8RVC/+FEHzOgErvO96E2thyorSyUoJGVRE5Qr/aaKnhl49ikNeeSpqRjFqmPmQ/LM
         yQM6ycpeFmCRhUXdNHQPZhhZoiYBYIJrMtFyZTAZVkC+rW+vOeGs6BarlCrO1sIQXYV/
         jaQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HocwwpvI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z6AjUrMwZH+yyzXUafN5pvTTmSmxiLar1w/8ZD9HOLg=;
        b=D5pvKAIZvIHZGYYpR+U0NLOSVK3nklSBw0B3SbA8y7SxuF0TPYH0FK2uDNxJYhws+T
         Qno1ZXEf2aChEPTjF79upcpGUzHxg5deAkAO+70i84d//kHx1hZNObkggpOPYvtG8yYP
         UE7d73zH8r2faRuSi1sqdtKUf7KSvW1Sj8j2W7H5frOutpf4WiVNXnNXUfU7NQcb5PHR
         5aAv5FQ6uv+q0OnOkdj8h8mR1vsfoihuPQ4MY696TRdlK12dZmc1slMzHTyZsuw4EfHw
         yVEa/5+G4+Nuc+0lW5TqP8iL7tTRfvAgQqVJY+BsP2gG0M5LQByGrLMJW3/PUV80K6BA
         YWww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z6AjUrMwZH+yyzXUafN5pvTTmSmxiLar1w/8ZD9HOLg=;
        b=DTcBP54F81z2rrvJ4SG8mHUFYzRCm/vebJYUQKjGomwYd59amyg+TbfPqD1JGpr0nu
         FqGDZfomctLm8kxp/FIvXSaxA28374uQtQs7E+gYGMtoLeTIaJUJmloR1Nymm3E/FV1X
         DcNGGSFWkGONs1c93/pCf+5YGrihm8k70Uc+FhLuR7WgEpH9x8rhALNRJHFxGrGM2AdS
         ygC9505mQmJKD7U4XsyIZls4X2ZJ046odGUjzdleal9qfyr9/RWDS2e4zv4C0Wc5ye6Y
         fjUA+W7476A596Q0olW5WhafNVviBHDrfvR9ZQjD28/khrWFCqHg6kX2FO2rNm/JiJoY
         UrZQ==
X-Gm-Message-State: AOAM532W+OhkQmAQzETIgSnKJv3xRpU0uaAG0IFh/brcpGHwtQoneM8G
	dubukKTmf/i7qBqPxz2fBhY=
X-Google-Smtp-Source: ABdhPJxScoN7V2FuKNn+hqfuDDf2pSNsQaeWfr8HnIBxZiXJJbYAydyOME7KOnB4mwRYpo0PPXoGxQ==
X-Received: by 2002:a62:e302:0:b0:3f2:628b:3103 with SMTP id g2-20020a62e302000000b003f2628b3103mr2783129pfh.39.1631187973943;
        Thu, 09 Sep 2021 04:46:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:cec4:: with SMTP id y187ls852052pfg.1.gmail; Thu, 09 Sep
 2021 04:46:13 -0700 (PDT)
X-Received: by 2002:a63:f84f:: with SMTP id v15mr2304543pgj.204.1631187973356;
        Thu, 09 Sep 2021 04:46:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631187973; cv=none;
        d=google.com; s=arc-20160816;
        b=gKoY1gSR5zfleoTU0x4x9AObqL3TA5zdv/7ObV+e4tWvzeogSSK5mbU9RHa+ofbQiG
         Xbuxi08Uv9OHjGZnUWj5V4LmqdP2A7VRge3nswjA2lf4n3U0xTEGSaUGG8SDwh61Ixfu
         ne64P67ne71z23nQiNNC070xyNMUURpykNrcfeI/rHKj/no/4lTZfNwiJMwyKbM8rJob
         k8ZElO02bRsbqe/VuTr3R39PN2++5y5aJeDlZaONLu61Wfx3iaf0fY8YbZKlDx5U5cZy
         TAytyOBpB5KWZnzCgUgI6QpUUzzgKaUU28TXMStAdygQXQefMY9IqeMFfVu/9KuxXLER
         7wdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=scnpuQEkIxlsg5dECCNfy9fibrsqF7ou9Zg/wTCMvoU=;
        b=uwIT4APBt4pYhuc2OtE5cRiQdSRdMG4Epuxv/xOy7GXmbhW/wgGpvwxsFyh5LHoo2Y
         5T2y/VH1IM3jNJjm9mJbwUjd66kf3W8Pli03LQPPYDP0JNh9CinzO2ZyiC8I+ocynAyY
         uVQWv1H/8zPHy61oKGOKCeEEXQNGfVwqOL02P3b6r8sF8BsD0M/C8ENW/NOHD3GlPplr
         djzYxHZT0vkFSt2/heUogzBYzSPICMpDoAT88Wg5ltULIpHH7QLo+vpkz4yezFvN9je4
         d0WcOiXExYOU5wWLhGoQMx3r1ZhdhDoW0ViygiypUKAn8eZOuN9uNgeJY9DCjpnwYdaF
         gxzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HocwwpvI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id m1si121564pjv.1.2021.09.09.04.46.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 04:46:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id x10-20020a056830408a00b004f26cead745so2067170ott.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 04:46:13 -0700 (PDT)
X-Received: by 2002:a9d:71db:: with SMTP id z27mr2066335otj.292.1631187972828;
 Thu, 09 Sep 2021 04:46:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210909104925.809674-1-elver@google.com>
In-Reply-To: <20210909104925.809674-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Sep 2021 13:46:01 +0200
Message-ID: <CANpmjNOHG3z7qPKWBukjqHC6f1pxbdR1WOMUhsij9whyx0W=VQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: double -Wframe-larger-than threshold if KASAN
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Arnd Bergmann <arnd@kernel.org>, Christoph Hellwig <hch@infradead.org>, Guenter Roeck <linux@roeck-us.net>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-mm@kvack.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HocwwpvI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

On Thu, 9 Sept 2021 at 12:49, Marco Elver <elver@google.com> wrote:
> All architectures at least double stack size when using one of the KASAN
> software modes that rely on compiler instrumentation.
>
> Until now, warnings emitted by -Wframe-larger-than could easily be
> ignored, as we would still get a working kernel.
>
> However, with the introduction of -Werror (CONFIG_WERROR=y), it makes
> sense to at least double the -Wframe-larger-than threshold for
> software-based KASAN modes to reflect the already increased stack sizes
> when building a kernel with KASAN enabled.
>
> Link: https://lkml.kernel.org/r/YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain
> Signed-off-by: Marco Elver <elver@google.com>

FWIW, there's still no consensus if this is what we want, and the
discussion continues at:
https://lkml.kernel.org/r/CANpmjNPBdx4b7bp=reNJPMzSNetdyrk+503_1LLoxNMYwUhSHg@mail.gmail.com

> ---
>  lib/Kconfig.debug | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index ed4a31e34098..2055bbb6724a 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -345,6 +345,8 @@ endif # DEBUG_INFO
>  config FRAME_WARN
>         int "Warn for stack frames larger than"
>         range 0 8192
> +       default 4096 if 64BIT && (KASAN_GENERIC || KASAN_SW_TAGS)
> +       default 2048 if !64BIT && (KASAN_GENERIC || KASAN_SW_TAGS)
>         default 2048 if GCC_PLUGIN_LATENT_ENTROPY
>         default 1536 if (!64BIT && PARISC)
>         default 1024 if (!64BIT && !PARISC)
> --
> 2.33.0.153.gba50c8fa24-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHG3z7qPKWBukjqHC6f1pxbdR1WOMUhsij9whyx0W%3DVQ%40mail.gmail.com.
