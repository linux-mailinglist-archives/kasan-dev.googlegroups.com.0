Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VI3D5QKGQEUD7QQRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E4310280599
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:39:54 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id g7sf2094840lfh.20
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573994; cv=pass;
        d=google.com; s=arc-20160816;
        b=RCUdgptmMIE3td4a84uhTIe/qh9JLUsZepiqq+/6599/HwRYxD7Vkrb/zR7lSoOJk/
         HIbqkVSZChWxo9QeKyHaEZJ9sixtNsvxQAgQAwAvu9orAWaHC/KIlVPACqifdkXZkHC+
         CiNmmvQ1djD9luOhqxCTUPEwIzOXXIXR83qNFBlye7VU4VwqYsx5DbteDn171TRT3F8X
         cuR0pCnLPoIQCrtGxqWnE8YgYEtSD09FZxpxCYihdi2TVmuj74Ym4Lmr02TCDWInYoHu
         GmMs8qjKwIqEnfnrn/uYWQULsw222aYxPIvBsFWW5MSTYdJ1QWDV62yqNrY4baAm+Ne9
         W9UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4dnJR4T9T8m1383BXbGQrgXTpxjku02iKhNsakw5bYs=;
        b=naoSmCxg4BtmtHznJOsMXITUJ9CDYzZUFzDgu10zxQrSbWSx4dT2jgJuG4lPU+MVDP
         NTBhG098F2/7W/b9mtAQbImHHjL84nqgvdo5LLRVlQIEITpNkuqIkQTu7xrRvel5gVnp
         ODKSqiKfmb1aou4WSpNgmOTu1pqrQQrIQ7AkVBisuFNmsQmzk9OWrYbOH+pNI2LhF2RO
         4sPlX9hR4XX9kR45nffWv9BbJQshm/eBHearF8+PiVbP+FRDSesZ/iDnFxpWn7ygNvUf
         JSMBrNlp9ufxDJr3WyWjwS26MDcKOIjKGHw3AK0ZZLuVKpsM/tVLdBQoDzYc/51U76tm
         Z1kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ptyqzr5K;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=4dnJR4T9T8m1383BXbGQrgXTpxjku02iKhNsakw5bYs=;
        b=HQ1OdeOjW2bzDlYoUxnqdS8ZRpZpEC2oklUOPm8+jXRbFCk5+XxAWppZ4GRT2rK/r+
         yyeeBtwlKCddsDKmBhrSuYbpgHTlflcvE9HZixmUBYr/CqKONb2vjDvR0sfEHIX9kyFE
         Ici1zihvLkbIytfZigf7s/Lnd3pX7jHeBuc3YS2V0iDorFirBdPsCV1Cy6zjqYiIPtoc
         kdlsRotGgY1iSq9/9syIESpA14HvyHSTMPDfLFnXv9mCDtVhMZAoslEz4c4u626YL5xx
         feoFUdMhWciKYX1xOcJAzrpU8GszKYav678ApplZjT+QDY+ndICPtTBnXrvAaiWYRXUI
         /Rvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4dnJR4T9T8m1383BXbGQrgXTpxjku02iKhNsakw5bYs=;
        b=lqtPtAoTAJ3bZiRC4tEF+Ww3/8qO/tURGEIFBNcJlh15wl2cE61bdDTWEJ9Xt1TwS/
         M8B/DD5wxptZJIC/40moiW3k04akkjN1wDDENpNSxHBZbpCQ+aWBcjgcplaMlhgUTgMV
         vbUrjZVA6WAxJbHFN11JKtOVn6J3mNDkeKJAx36fcnVy45ByyDlJ6LFPcajl6N+wCyxr
         XRtxZ4cvLVxEKlxpYGUwXafYmhqshIe1h0RW4Njh+Tm/vjdI03ypRLg0O3pFmuWzl2+B
         oG4ieFwJRdm1FoEP8RdbtgQ/wL8xVxjZhGVa49oqkQC5t8T1PtkNbHuupomRF7mLtU8D
         qnsw==
X-Gm-Message-State: AOAM531tUxFW3MlC4NN1cx928N0FzPuUEQ5RlmgtPVngdDCC9hGoWdRk
	SAJvfNTSxg0Iq8B/pEHId6g=
X-Google-Smtp-Source: ABdhPJwV4/Hsi0Ka0+5J+K7ReDl9E16Fj6373h2fk5RdfkAJwGBxYXiiDLA47POOdiino5L/JkXLNg==
X-Received: by 2002:a2e:3c04:: with SMTP id j4mr2815654lja.397.1601573994487;
        Thu, 01 Oct 2020 10:39:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1697401lfn.2.gmail; Thu, 01 Oct
 2020 10:39:53 -0700 (PDT)
X-Received: by 2002:a19:404:: with SMTP id 4mr2977840lfe.343.1601573993406;
        Thu, 01 Oct 2020 10:39:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573993; cv=none;
        d=google.com; s=arc-20160816;
        b=oL+f7HYW4bg+rWdhWQlZ8KlyPdrWtXm6AWjKjw5Hwp4wVWrNYwwfQN1jQdZYNjD+C6
         Dj2JoojjFSL/M/f6ouZou9zCK4zx/0uqniGwLH4BpYhon/JY7XtFtOFrXcV+L2R+bzyT
         NtH+G3PGF+qAigumjv6BoEV1/Sl7F58DRlErnlQ90MH9VsVNUCZ0NHcwE5ZWT1GtbR0K
         6GXJf/SkPDmiuhu693+t7yOwDyadJ/wmLIYMdC/oQ7SkV2BA/u8NvdZ8Jqfqgxmz+Z1x
         bcs5jcwVn2v/+ZOzPLwf9Qmfif5FDB4t8epA7J/253rEq+3JpNbUMG7I//9EHZEI3hnG
         tH1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7216dcRRE3Wn/EM/apMUAUVbD6PsUdlPnAr0Igr7XOw=;
        b=npaaxLSbOAUz+rO//axJc7I7U8T5rvqqDzUf/JrFfGwFsVaT9S3PMkoiXdgxp52Cc8
         nA07J3wTET9lYnjt+NSh2+c2NTBtxQctCPBOiC1H1tmiHYG2HF8d6WHcLzOF44KHK/pf
         hKodtkjNh/1anz0QFjhh8iozj3odFn3bfrcT4ZSgD6ylBnczDvDcRg8UcVk7iZ7GKi25
         hpcZoUnzXmc5r3oXam5VLlfQOcIcZKG3tNDsZqpPhKRFho3SfwzYLHd5vfTYwoOp2z/m
         QHCDwuLLfxqj0Vvu1JjPd2Cb/UTbHV4U07VcFB6pjDHX41ijej0pxGSBZpx3+BiI2Ceu
         oxjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ptyqzr5K;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id z6si203813lfe.8.2020.10.01.10.39.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:39:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id s12so6777425wrw.11
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:39:53 -0700 (PDT)
X-Received: by 2002:a5d:4151:: with SMTP id c17mr11009569wrq.302.1601573992713;
        Thu, 01 Oct 2020 10:39:52 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id y14sm854478wma.48.2020.10.01.10.39.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:39:51 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:39:45 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 11/39] kasan: don't duplicate config dependencies
Message-ID: <20201001173945.GI4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <728981bdedbca9dc1e4cca853699b6a6e8f244e0.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <728981bdedbca9dc1e4cca853699b6a6e8f244e0.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ptyqzr5K;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
> those to KASAN.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

But see comment below:

> ---
> Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
> ---
>  lib/Kconfig.kasan | 11 +++--------
>  1 file changed, 3 insertions(+), 8 deletions(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index e1d55331b618..b4cf6c519d71 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -24,6 +24,9 @@ menuconfig KASAN
>  		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
>  	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>  	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> +	select SLUB_DEBUG if SLUB
> +	select CONSTRUCTORS
> +	select STACKDEPOT

In the later patch your move 'select SLUB_DEBUG' back to where they were
here it seems. The end result is the same, so I leave it to you if you
want to change it.

>  	help
>  	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
>  	  designed to find out-of-bounds accesses and use-after-free bugs.
> @@ -46,10 +49,6 @@ choice
>  config KASAN_GENERIC
>  	bool "Generic mode"
>  	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
> -	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> -	select SLUB_DEBUG if SLUB
> -	select CONSTRUCTORS
> -	select STACKDEPOT
>  	help
>  	  Enables generic KASAN mode.
>  
> @@ -70,10 +69,6 @@ config KASAN_GENERIC
>  config KASAN_SW_TAGS
>  	bool "Software tag-based mode"
>  	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> -	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> -	select SLUB_DEBUG if SLUB
> -	select CONSTRUCTORS
> -	select STACKDEPOT
>  	help
>  	  Enables software tag-based KASAN mode.
>  
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001173945.GI4162920%40elver.google.com.
