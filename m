Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAN4TWGQMGQEM2RTXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 984A6464D0D
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 12:35:30 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id i6-20020a0565123e0600b00417d29eede4sf5005271lfv.12
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 03:35:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638358530; cv=pass;
        d=google.com; s=arc-20160816;
        b=0u7pfHHw7D2+FZPQr5h7Fm/NLkNR2yA1e5SddDY7SkHfAwgIgO7qE7mikYEWuE4IHi
         fp42rENPyH/i41QEW+CS7QaSHhR1t2Yz/YHp5Plkm1Wg2bJjq+PMJrPCGwguuSTSXHY2
         H5IKTY0/i81aE20l/Vt4aHpFtve4mQccayfcWNm60ykO0sTELrb5WFXIDwLEjJks2KKv
         kvFAwpDfbFTrE7H4gAXEXSUFd+R6o+fqOzKlsuBh8k255v6FmQ/+BuTwX4upCdW5GnFn
         dqMQbCHKfPUV4Rxt5ZjEgbHRl0xLFABiwFwJ3/RYB6B7B1PBmOI62q0r62FPpp4niMWc
         YJpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Xyzma2+CvXvZEM7AZzst2cdsGb1ks9bP9a2k5mtXDD4=;
        b=iWMH0Uza9KHTln5dYRhKrmpEReaYtF3MB9JhfXuutuTf28A/MdUmAsPRpMXZ1cxFUp
         tvnm/y6i2sOjZVZH1g2P0o4XQw3BL4PCJdlpPcAMYT+bkIm2TkI0cSIKryZdfz5Y+KNF
         YixrQRaeZMSwgEjTw1MzkmJ7yLToSJXQmXI73cSuPbRTJlrL6A90P9rxjXF96jfLsL3d
         AYzQj4Wte2zWqcpv4UJHNV2GpMpsqHZPJlhiQpbXe6DzlZFEr6rxWSSQ8wCRZQeBMWdN
         S/DREwkkpSaL9QEv0yPr4t6IoC4sULQAhGM9T8OlPTF9xvA/Ha5mzxwt3rXYLL3a5A5o
         15Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BlKjYbOM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Xyzma2+CvXvZEM7AZzst2cdsGb1ks9bP9a2k5mtXDD4=;
        b=BXqt3jds0XSMQL4+jH5Etey6BAwNpLExKvwDpN6tzutRyJR1Z4tBHzjtBLctTCRZZs
         HvDzlLNBHZRpWar+yS0elBMVyMBFWtmMZKzx8vWBdE76SlJh+Ip6YiwwdG2FDD9FVHcc
         lVYjP0ZKWJId65MZwmMeltNYu4Dyf9SwxB0s/WSmw7Fj54HwwDW1bgTgoAEFfvunJF4W
         +jGbsVnQ8TqHp6ShXFWkAwH0/ZB32i/2+rHuMrRzVVanclwa4SfsLhpmI4/KDp+DgwQe
         1CZCAQjuERPPI1ugMedBLdD1KTtEjtXvejDtfGjHz1Bm+HG2ZLcM4gqIwgnYes0+7WYB
         faTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xyzma2+CvXvZEM7AZzst2cdsGb1ks9bP9a2k5mtXDD4=;
        b=rchKSIcnqq7GGLH3JZ7nJhUz/UKlT78jiLxnBqZTtyBDUhgiFaPHAWqZYuoD+Da2yA
         F/KPUX+0Fde3UM0Ty/TSON4BVYCPKSDRmr1C+wI+FUcToKQa5QM4+kxs3ZotnFlxDZhI
         Jvs/k67V1SR9pj677FA5S/C9HznZW7cQIG9ceWhOFfkBpvvh+IS91CTG4NcRLMqFYLuA
         EuH4GioFVCkSYtMZ0yaaX79GRA2JxuBCRrZwreRbAwKFP8sxE54NYU2rv9BT1Lgd5BpC
         dOPkuG0eLfVLDv/L9Q6zjliZ/v/gS3P5IElDnDstDV7R63q+Tgyeqm9VGeEKbwW38WCj
         8D1w==
X-Gm-Message-State: AOAM533A/j9mnDtZchBP45kZo8GgLsjPhEni5K0uozLqpLxHOxWjcoND
	8IKaLp4vsAe1XRPy7HyJwuo=
X-Google-Smtp-Source: ABdhPJzvO3C99YqTAjKJZkpOcb35wNypJwc4Z9DMaTyWlqLoPjKpXh5si7m29avNcPTSPsvE4ac43g==
X-Received: by 2002:a05:6512:318f:: with SMTP id i15mr5017458lfe.341.1638358530108;
        Wed, 01 Dec 2021 03:35:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls494647lfv.1.gmail; Wed, 01
 Dec 2021 03:35:29 -0800 (PST)
X-Received: by 2002:a05:6512:b1d:: with SMTP id w29mr5288524lfu.219.1638358529037;
        Wed, 01 Dec 2021 03:35:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638358529; cv=none;
        d=google.com; s=arc-20160816;
        b=bH19PuC81gaMKLfRbcQwkUFR/4jMme1tyqFm6vLlGl40WjqscWI9XYTZtF/0Up6bVa
         LGCzvOk7JbhU5utrH49h4lR1T5E0+upnNH7S90PiZxUC6t4yuPdeuAMF6eVDxRYkfB9u
         aeRrVZ1bFe4oOFgyr40q3jtT0SZCg6rpkHL5LOioIURjHcOpG7cn72C0+j0S+b7wko1B
         naMCb7Jbj1bZZqrK1b9v6yM5EUUFiW8E4RvvmLnzsnlUke9vNzmlV5UatebBkJR0hdhQ
         Lj/kHZHDw+x1Be9c+SoN/DTJvmkhNMrKN+KDjxt1oTK2fKFBHkSsoPa/fLhMjHcNZ6Qv
         pYDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7oFCw3r7bT3X7Dv+eyjA/okr2FmaHILwO7XorQYmoTs=;
        b=VFrhCxmOPUwa3VcBZXHZEkULs3ezy/1pCpr5C4FS0xTLyhJykE5ywxVsw6zW92WLMQ
         wb0gPyLGznXqhrHC0TZyF4e2rtD8Ubznnl+/MJTwbYdbJtpIAQAhbhZblmcP2KuDvJ7A
         wdf+yDXflXjpY2mizl+b0XSp6+xQOBbnNnUDe5yT6QZovFd65M3qXTrf8qceNN/S596N
         yQ4IHXfr58XpN1fvrOcpUodPDCYMBgQLJhqVJ4gPhAFiD5fBkhxEikRYAUmEsHe/PiWz
         ExFHIsG+N4EHdaoc9fctjClKf6aWmH8rfLejUSQADIJo7LpaYQoJrM92AMkOMIplPh/h
         fr6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BlKjYbOM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id u19si1610411ljl.5.2021.12.01.03.35.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Dec 2021 03:35:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id j3so51537460wrp.1
        for <kasan-dev@googlegroups.com>; Wed, 01 Dec 2021 03:35:29 -0800 (PST)
X-Received: by 2002:a5d:54cf:: with SMTP id x15mr6333226wrv.30.1638358528549;
        Wed, 01 Dec 2021 03:35:28 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:95ad:1401:cf07:6d1a])
        by smtp.gmail.com with ESMTPSA id u15sm638839wmq.13.2021.12.01.03.35.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Dec 2021 03:35:28 -0800 (PST)
Date: Wed, 1 Dec 2021 12:35:22 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 29/31] kasan, arm64: allow KASAN_VMALLOC with HW_TAGS
Message-ID: <Yadd+oOVYSOPoWMS@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BlKjYbOM;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
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

On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> vmalloc tagging support for HW_TAGS KASAN is now complete.
> 
> Allow enabling CONFIG_KASAN_VMALLOC.

This actually doesn't "allow" enabling it, it unconditionally enables it
and a user can't disable CONFIG_KASAN_VMALLOC.

I found some background in acc3042d62cb9 why arm64 wants this.

> Also adjust CONFIG_KASAN_VMALLOC description:
> 
> - Mention HW_TAGS support.
> - Remove unneeded internal details: they have no place in Kconfig
>   description and are already explained in the documentation.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/Kconfig |  3 +--
>  lib/Kconfig.kasan  | 20 ++++++++++----------
>  2 files changed, 11 insertions(+), 12 deletions(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index c05d7a06276f..5981e5460c51 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -205,8 +205,7 @@ config ARM64
>  	select IOMMU_DMA if IOMMU_SUPPORT
>  	select IRQ_DOMAIN
>  	select IRQ_FORCED_THREADING
> -	select KASAN_VMALLOC if KASAN_GENERIC
> -	select KASAN_VMALLOC if KASAN_SW_TAGS
> +	select KASAN_VMALLOC

This produces the following warning when making an arm64 defconfig:

 | WARNING: unmet direct dependencies detected for KASAN_VMALLOC
 |   Depends on [n]: KASAN [=n] && HAVE_ARCH_KASAN_VMALLOC [=y]
 |   Selected by [y]:
 |   - ARM64 [=y]
 | 
 | WARNING: unmet direct dependencies detected for KASAN_VMALLOC
 |   Depends on [n]: KASAN [=n] && HAVE_ARCH_KASAN_VMALLOC [=y]
 |   Selected by [y]:
 |   - ARM64 [=y]

To unconditionally select KASAN_VMALLOC, it should probably be

	select KASAN_VMALLOC if KASAN

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yadd%2BoOVYSOPoWMS%40elver.google.com.
