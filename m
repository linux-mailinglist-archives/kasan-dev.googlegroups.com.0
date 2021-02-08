Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNWQSAQMGQEPMMRG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B0E9313011
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 12:06:50 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id c1sf10919112ljj.8
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 03:06:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612782410; cv=pass;
        d=google.com; s=arc-20160816;
        b=dVhYjPvkdgXNLWrqGR+JBj1VXzesLi2am/WJ6MyvoeO2a4JAvlIYcOHFba0MT8ncW2
         qzx4zFEmdjD94X7Hym3AflQFrrQBR6TPeVuYuuhsOIZiDb9KXVViYGqUFPQeH2yx0Nhw
         eA8+LP6hN0ycs4r62GOPPRbZYP8LyK2HkTgoNbwznVtOukBWitezZjQYKoIQnzVq1vOO
         IxXfochvwR4cJb1+B4oqGJI5tUdHRHfyYmfiEYxECWv0E53xVbBqgw5DlBjEB/WmrBKe
         6k2inwicpBtPOwKSDAMeSgghKqeJOsoEzV3jj3R8zJoMkm2cT73JH21WqnuUzhPFpRRi
         MxTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GNyVohYaAFF6CyEUyZu2De2ympbZMOdF6tsj1kQcv08=;
        b=JnX6bPGNUptrNAiXbNzaU4wTBkuFLYmH57HgbHOHfo/oRL+iGyEtg6Ad3spy3yRie8
         Z6vfGrH/tgg2UTnU6peJRlxv/F+IUCtJxRzAsSSQ6pA9rm5xCXCy72Z4vUKIei29wVSa
         XBG3mbCQwOCtxcQbCdDTkZtQpCd8V3KaByY9+LUGQQPvhSgQoxNEavTLOz8hqZkl5Ynd
         j6zCq/S7aVV/c2L+SywN+svOmkW2gQFh64Z7xJ2rRlbGa+LmHgS8nrxZqHqATdtxhElg
         YD602PoGVT/5TQx74bC/kSKOawpZ8Ptvk5PP9UkJwSwullX3WKaP7rnuj2Xtf/mzA5Ma
         wRKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NG8H9UUS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GNyVohYaAFF6CyEUyZu2De2ympbZMOdF6tsj1kQcv08=;
        b=c9/0GbZh+da91uhNCn8oRB5OfsYXUXw3zXhnXjdb2gY/Drr5X2hQpMcdWJcULT3RDl
         gjP50ytBUsOZFGUuNKeRGDbI16grct8KfY/1nm59BQWHy9BlpAmsOzpU3pYfvjghQrTL
         lVIYiiaLiJ6zHGJ9Z8LJezTyFDwrHx9yrrvmvW9+j3/bMhnKF8sDwyH+GovvFRMDFy9V
         pyjZqH3yP1jECigYcgwkOalNVw9qpHlEJngIpGcw11xE9gj71wZaHKaGd6CdH4icQU/6
         oxgN4z/YVS4lIGCYGmLd5Tz7ZpTAuga6PSLW4D9UA4hNeRVI572Y+VPDg/SeIMSjMUVn
         dEcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GNyVohYaAFF6CyEUyZu2De2ympbZMOdF6tsj1kQcv08=;
        b=r8VCH7TDt7IQ4rW6klgq8GLUgMw/0Hp7FLn56jcjbu26uwiEpLJORix6yRWZwR1FxG
         LV6MMheRJg/7QdGN5PYr+mIA2+OhEDPqdKjjU5Y9nvIaVw4ZBwwwnieoTyfEamij4Xkp
         PMm2pJTt3pkfe95STsUZRQ0tCSCEDk05gyEeKNyAE6UAB8pJmpMw3ic3XYeENm5p8hKL
         y1bJnPKpS4NaLAqaiETm5AYUtUFiMpGD7Wy5ETFGBPXN+sgNqstiDgSgSCjyNoqRHqBP
         BP6SCgRoBRcuK4sAsN13YyQkscJM373YEo/E/YARyhTARYM7dymN5RJwZ6FZDCdJ3hBJ
         YCYA==
X-Gm-Message-State: AOAM532GxgYUnmHuWfSc2evp9q9X5I1atAOa09/LfRgkEVGlbB2Olj19
	5qv+ac6tP1lA5DbiXAa2ETU=
X-Google-Smtp-Source: ABdhPJxSrO/I812VQdTyzdXBL8X3iyLuK/CT8aAhL0eRBqyE9Juk8RxH5WRlSXt4PMGjf0qemo935w==
X-Received: by 2002:a2e:980a:: with SMTP id a10mr10717922ljj.280.1612782410031;
        Mon, 08 Feb 2021 03:06:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls3637452lfp.0.gmail; Mon, 08 Feb
 2021 03:06:49 -0800 (PST)
X-Received: by 2002:a05:6512:3047:: with SMTP id b7mr10547787lfb.279.1612782408919;
        Mon, 08 Feb 2021 03:06:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612782408; cv=none;
        d=google.com; s=arc-20160816;
        b=LBsRN8n08XVG7FGVxvn7eGbReLnU7h550vijWtaPGPhTltC1wiPDvNYGGQ145y/Az6
         I0VszHwv6GDlwa1gKK+SgmWFICUwLAW7DaM/rJ/tehu3pPKjicdy2aCX3LOYtmZeHGF4
         8bPi14nWWbJ32psapELwhhnisgPkdmzhxnxo3E1Qbo8S92+3n/0GaFWZci1WA7QQag6/
         /XrAuKqSLbNCeINNJmL4eHpOFm8mObTeTseasW7Md4V8d1GyMjs5HoHCtQ5M7kzAn4e6
         NdsXqqZhc2n6/wHqjeibEQniO2Z+S3+KWGL4aLO20hQ45mTO80hUJFuCv3biVCSXH7xT
         Q83A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YCKQyJ5X4pSKK2TbNsb8boRdw0GR7LFT4BRguWXjjyI=;
        b=F0wNANWq0keZ3r6uMNldb/5GBe8N8u1CAzy+aqwBlQk8G+IMx9cq0qqSyBcI1cfTD9
         LjOOerpD7BurTKul6l+IcK5i4tyG3nPXhJJmvJ4AyFbtaK+zyEEumOyBNk+4roXRpqyB
         oCXFRIwRQA1nNjZDTJe0zqebvI8VVnrUU6v1AFafn/qHzx2DajIU2jl2hdo/wimMrNCU
         8vpQF7pNPYkRp94g/14F/8CR9G7o5anFgu4PjfYtfM4Vy4TVNhDObQ2qaAuPxCVO2ctw
         T00gbavPAcdyoKmylXhrZ4Ct1ClloEW6FKbCNrHhJoA0E7RmH06O0Gl42bXnS0a5lPUc
         4Uhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NG8H9UUS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id l22si649749ljh.4.2021.02.08.03.06.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 03:06:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id w4so12193859wmi.4
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 03:06:48 -0800 (PST)
X-Received: by 2002:a05:600c:4f4d:: with SMTP id m13mr14358030wmq.118.1612782408117;
        Mon, 08 Feb 2021 03:06:48 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:497f:76ef:2e62:d028])
        by smtp.gmail.com with ESMTPSA id g16sm19401367wmi.30.2021.02.08.03.06.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Feb 2021 03:06:47 -0800 (PST)
Date: Mon, 8 Feb 2021 12:06:41 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 mm 13/13] kasan: clarify that only first bug is
 reported in HW_TAGS
Message-ID: <YCEbQdE8FfUUFvuo@elver.google.com>
References: <cover.1612546384.git.andreyknvl@google.com>
 <00383ba88a47c3f8342d12263c24bdf95527b07d.1612546384.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <00383ba88a47c3f8342d12263c24bdf95527b07d.1612546384.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NG8H9UUS;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Fri, Feb 05, 2021 at 06:34PM +0100, Andrey Konovalov wrote:
> Hwardware tag-based KASAN only reports the first found bug. After that MTE
> tag checking gets disabled. Clarify this in comments and documentation.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 8 ++++++--
>  mm/kasan/hw_tags.c                | 2 +-
>  2 files changed, 7 insertions(+), 3 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index e022b7506e37..1faabbe23e09 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -155,7 +155,7 @@ Boot parameters
>  ~~~~~~~~~~~~~~~
>  
>  Hardware tag-based KASAN mode (see the section about various modes below) is
> -intended for use in production as a security mitigation. Therefore it supports
> +intended for use in production as a security mitigation. Therefore, it supports
>  boot parameters that allow to disable KASAN competely or otherwise control
>  particular KASAN features.
>  
> @@ -166,7 +166,8 @@ particular KASAN features.
>    ``off``).
>  
>  - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> -  report or also panic the kernel (default: ``report``).
> +  report or also panic the kernel (default: ``report``). Note, that tag
> +  checking gets disabled after the first reported bug.
>  
>  For developers
>  ~~~~~~~~~~~~~~
> @@ -296,6 +297,9 @@ Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
>  enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
>  support MTE (but supports TBI).
>  
> +Hardware tag-based KASAN only reports the first found bug. After that MTE tag
> +checking gets disabled.
> +
>  What memory accesses are sanitised by KASAN?
>  --------------------------------------------
>  
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index e529428e7a11..6c9285c906b8 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -48,7 +48,7 @@ EXPORT_SYMBOL(kasan_flag_enabled);
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>  
> -/* Whether panic or disable tag checking on fault. */
> +/* Whether to panic or print a report and disable tag checking on fault. */
>  bool kasan_flag_panic __ro_after_init;
>  
>  /* kasan=off/on */
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YCEbQdE8FfUUFvuo%40elver.google.com.
