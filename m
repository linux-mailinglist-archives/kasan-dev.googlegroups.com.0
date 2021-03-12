Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNMHV2BAMGQEATWYCFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 056583390C0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:07:34 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id u4sf9885541ljo.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:07:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561653; cv=pass;
        d=google.com; s=arc-20160816;
        b=gBHp4uZU2Up9U21ZBG9z04vxSG4pOKc3NCXSqZuGwQ6Te60x4cM+1meB+EmsazhMPH
         SMBpyvoFRTxAMaDxVr0QdODZLd0fMkKSnfZjusMQTHZrkMjFee7C/Bi1jGG24CjyVI82
         AdQTTILltfKq9Im1C1wVqiM/8MK3f5VLdhV3NXqcvK4D/YQ+JXtWpVJR6P+p7dfxjCjh
         68tRQkBS1CQrZwaaYQIkDz0hCa4VXEc5WprIoN66DC+HU1EwG69oRvaFvMpr2Zv8jyf0
         ySD4LufzWqHuGEoLSqrcAssHDuxVYjpi52kvLVvbvfPtACkUwVAN8zQSjc8wQ5RkWaGT
         LIog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AinzUMcqaQhGXI2/Qngxbe0ee7FwlioTin6WTtyO0A4=;
        b=scpWHJeJaj8ePS/o7+jGRbsiGZpHWKGpGOCcUImQ3v+agVlOOIgj33BY7Hy8DG45Vp
         m7ro0accAHCSJ/2LSHC8wwXpicLddkMuraVbptiWBK2Oo3Gl8oBwydVarzt3T0Ln75To
         nZv3wAIpFYa4iDr48sZjPZl75Cgn1kbCN4whpeeidrquu4DlA/jfogGulsuGNuMjG2Wd
         c26+7d+WOdWa8+Z4RPGU6k2ZBWfL4Pi61GD9LwYazAfB8ka274UvmzpbhEftxbwoyOo7
         YsdwHbGv6C1CRjG1X+T8XA4d/CSVKYQqcLrvYNvGo4ei+LECY7h6a1pzMmnmUad/eoUR
         kHMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OK9FMmpH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=AinzUMcqaQhGXI2/Qngxbe0ee7FwlioTin6WTtyO0A4=;
        b=fOxi47uwr5P/DuLEuCKYBYo10+l7715QWanZqrNSoe8A8FYoWQ8rDBUB7cNNTgidSF
         PvkQEjlDegYuseKKVRuPqcioukLKVzPeKIcWJwwtyouiE3lz2GhFiH6k3mq9pg3QSccy
         5MGC88RAPkHnZL4gYK347ZEKA07u180y3ZRrzO4Yg3qbs0ySA0K14ZQAzpBv1TSgTY3C
         E9PTPBvt6XNYbR8cntKCdywOGEXwNgMChkJUdJwT/vO+0Q4V/NbJaEPviEtOiWiyQ9D1
         59sZ4mB3KcUnrHk2FWVH3yA7UGHB5+hjFGo6y8m5TUribPAOf7O+AuL1Spk1GgzP5CsU
         MtmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AinzUMcqaQhGXI2/Qngxbe0ee7FwlioTin6WTtyO0A4=;
        b=cDljxnkDcXYvB//Ysh0PfRnfvq/BCrLHOTCysIcV1fiT+keBOwjKLlIvG+SkFOWKhz
         olNFVe9ncqh/oM1oJpoW+reamzFiJqWo+o8aMfhHL+OsZz/IFlcmfzOzU2iG2nCaaSyK
         R+Br6sXP+PcLEyAmVLpI2Zz0zBeeE1IwgXBzEAxknQJSfWM/pD5Rr86PDd3Ho56QthTL
         D0CMUegNSWBEYcTTat+0zyWajpjawsBhkwpvHa303mxSqERgrRcTGdfm9DBR8OGOBG2s
         D79gKjCI0YYy0nqBE/kx38anGCOEhTADy945dGXOPWxo11drwvnGGAW7NvliDzzeOKzS
         pxOg==
X-Gm-Message-State: AOAM531yLfHskTGKBozgCw4msSvRPuucb2uueHUaHCGRuP/fY52HbxtK
	ofk37L0mYi0cCXYENA1bKYY=
X-Google-Smtp-Source: ABdhPJwH0DCiQjH6DP/riaIHgsiUvrNcXPlechmpOhjBOHt/hvpe5nFZKtI2Ia3Nmo5HZE0Ep9Lodg==
X-Received: by 2002:a2e:8ed4:: with SMTP id e20mr2555551ljl.129.1615561653572;
        Fri, 12 Mar 2021 07:07:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a48:: with SMTP id k8ls2012382ljj.10.gmail; Fri, 12 Mar
 2021 07:07:32 -0800 (PST)
X-Received: by 2002:a2e:910b:: with SMTP id m11mr2653637ljg.179.1615561652407;
        Fri, 12 Mar 2021 07:07:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561652; cv=none;
        d=google.com; s=arc-20160816;
        b=aFeWmE2e913afbSvF2rwuNY3JMAv0tbAnrikjQ+ygHdIHGdVCDZJdjrM36Yt6xHTbd
         XZY5xzOOeRh9p7LuTieeH2rRIPDr7XAhVsfKWrCQMBeQnMibairun5vlIrQzUAYCkL44
         80xHC0P6gExQ1b/hU0pBIkK6tSqTSQLYkVo+XW2UrdbpNOXFbkI4VF9VDd6lVEG2tFVe
         ERGAGnpGHwLDSxt/JKmJtDFHdhJsBHDqMEX/bqMcfRPHed46tpOKv6YMyBZNACh56eSY
         nCcduwCCURc6v5349x6FPKkQ6tZTd/oBoYh2kXCDTGA+p45sn9lRx0VMwUboqrlmsT0A
         H2OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NxCzouo00jLfy5JFbVee5vzdNlkY0nXEKiHSuDiLt14=;
        b=KuSPqX9xfN0+B1cJ2v1wkjbpcMzDmDMK9ArndseRAKiqT5yfXvPTcE6SDnbGgcrlYV
         4TehBCCWEGfL4GRPxgJFada7wv0axkcvlJe0mhts2C8AIP+hagdlOi0hW3piYs1xqFoA
         SQryFUN/N/qNB8F5Itb51fUaBi+LNDEnSIC93tBptMwld0WX0TVN9WGgvf4c6/9TFTJu
         KXIBNS5i9kVZicXWOj1bHrwYB6dwWTrhSx7cfHU7TkPYEJoWrX0cC7ltspesquNgArS8
         ocVqREoaeefMlmyFZBLfxhZul/+FB0qxyXKuDsE1XYcqRD6ILBnQMMa4RjSNABL4y24B
         LbWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OK9FMmpH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id p18si229327lji.8.2021.03.12.07.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:07:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id t5-20020a1c77050000b029010e62cea9deso15366790wmi.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:07:32 -0800 (PST)
X-Received: by 2002:a1c:6605:: with SMTP id a5mr13891700wmc.85.1615561651710;
        Fri, 12 Mar 2021 07:07:31 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id b131sm2441214wmb.34.2021.03.12.07.07.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:07:31 -0800 (PST)
Date: Fri, 12 Mar 2021 16:07:25 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 02/11] kasan: docs: update overview section
Message-ID: <YEuDrdCkIjYywuyj@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <1486fba8514de3d7db2f47df2192db59228b0a7b.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1486fba8514de3d7db2f47df2192db59228b0a7b.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OK9FMmpH;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update the "Overview" section in KASAN documentation:
> 
> - Outline main use cases for each mode.
> - Mention that HW_TAGS mode need compiler support too.
> - Move the part about SLUB/SLAB support from "Usage" to "Overview".
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> 
> Changes v1->v2:
> - Mention GCC support for HW_TAGS.
> ---
>  Documentation/dev-tools/kasan.rst | 27 +++++++++++++++++++--------
>  1 file changed, 19 insertions(+), 8 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index b3b2c517db55..2f2697b290d5 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -11,17 +11,31 @@ designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
>  2. software tag-based KASAN (similar to userspace HWASan),
>  3. hardware tag-based KASAN (based on hardware memory tagging).
>  
> -Software KASAN modes (1 and 2) use compile-time instrumentation to insert
> -validity checks before every memory access, and therefore require a compiler
> +Generic KASAN is mainly used for debugging due to a large memory overhead.
> +Software tag-based KASAN can be used for dogfood testing as it has a lower
> +memory overhead that allows using it with real workloads. Hardware tag-based
> +KASAN comes with low memory and performance overheads and, therefore, can be
> +used in production. Either as an in-field memory bug detector or as a security
> +mitigation.
> +
> +Software KASAN modes (#1 and #2) use compile-time instrumentation to insert
> +validity checks before every memory access and, therefore, require a compiler
>  version that supports that.
>  
> -Generic KASAN is supported in both GCC and Clang. With GCC it requires version
> +Generic KASAN is supported in GCC and Clang. With GCC, it requires version
>  8.3.0 or later. Any supported Clang version is compatible, but detection of
>  out-of-bounds accesses for global variables is only supported since Clang 11.
>  
> -Tag-based KASAN is only supported in Clang.
> +Software tag-based KASAN mode is only supported in Clang.
>  
> -Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
> +The hardware KASAN mode (#3) relies on hardware to perform the checks but
> +still requires a compiler version that supports memory tagging instructions.
> +This mode is supported in GCC 10+ and Clang 11+.
> +
> +Both software KASAN modes work with SLUB and SLAB memory allocators,
> +while the hardware tag-based KASAN currently only supports SLUB.
> +
> +Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
>  and riscv architectures, and tag-based KASAN modes are supported only for arm64.
>  
>  Usage
> @@ -39,9 +53,6 @@ For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
>  CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
>  The former produces smaller binary while the latter is 1.1 - 2 times faster.
>  
> -Both software KASAN modes work with both SLUB and SLAB memory allocators,
> -while the hardware tag-based KASAN currently only support SLUB.
> -
>  For better error reports that include stack traces, enable CONFIG_STACKTRACE.
>  
>  To augment reports with last allocation and freeing stack of the physical page,
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuDrdCkIjYywuyj%40elver.google.com.
