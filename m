Return-Path: <kasan-dev+bncBDDL3KWR4EBRBX5AR35QKGQEOQHTKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4098926E0D4
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 18:35:45 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id q2sf2738989ybo.5
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 09:35:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600360544; cv=pass;
        d=google.com; s=arc-20160816;
        b=DrZzU8RwXqxLOrBaWoZHBn/U86dp0FDtb0AdMgciFso8/hprhd5voA7/PU7PME0g4E
         yyxrbI3GjbkdVn8cIDV/J6bbU7bCL4XtV4RNFqrxNL7mRH0xIDbeNnJ4EA8YkGaP1vkz
         f/fLUOsZXT2qx1v0h5e4/WGIIjP/QSxQhFd7dv9SELGRbblMIVb8S7fYnA0UqIpN9ZL8
         lWJSC1gnydKP9bgxiQwU1jFswl1rkZxZAIoQBfBPfp3FbIrSkyrFsCnRrMzCwklrx4ww
         XnBG/4YtVpkVCS2BvF371M2Xjx6aofx6cQsR+vXUC2YfpoQHWU4mJoMr0DFViAC5YeeB
         qxXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ZDEaD/Rw/XkLM6128ncJmEwbYVqXoWVxbyg8AabEnz4=;
        b=IRsovpLMJC77jAAiiREahfYitzi7SQxA4+U3jZDlZ7g3wd30k8W4nkswM0pIwhNMKX
         E7LJXxame4ovF0gMFFnA6E8eD4CiHy3HZZsenoBWHUDkNUcXSd1CWgrQlAFsH75BR4ib
         gKe2EGFlWnhFWD7uBk2GeaNbyXOQxqOF428MIGLnNZb26AcbuqMVgcmcyQWgnme8Q9IH
         AmuGNma4MB+PQCKnwfqclM3tzYEfje9q8Ry+pCUpUZUyMqeVLMyBmu4ZpZYPzgC8JiqD
         ixNy2/SJWnNAp12mrM0gPyQvllEihvy/q/OmzKKG8tuaM6c7aaPVlT975udqMLYRcoN+
         FtCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZDEaD/Rw/XkLM6128ncJmEwbYVqXoWVxbyg8AabEnz4=;
        b=qV5lLiS8+Us6T9ZwMH1LBJkEd3vgC7EjpyJeJlZ8w2z+xyOt/KfD88/CfpvTvuJbjm
         Tlb1mTKTGogeavjMHb7ozKNWwT1Ymy81zWGtkw6Dsr/mmTmCgg14SUeNrZSMBBcXbPi/
         Rgfi1WbkWTB1xTYnLz38iBYNChbfrNtpBfvhMRS1uso1WrAiYfN5367rSIz0fIlwwSm3
         VObeUNFEUBSpP2m4pL7exXJdH7Jvfgrf5vbal1u5T+zVNZmIrPCSP7Dyz7klGE0beH7c
         ipmm7o+B+jbBnVKWRRO4BDATUMF4d622K6+gMibOgo7sWrOb7qnlscwxdTntrgcjpo3f
         HPqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZDEaD/Rw/XkLM6128ncJmEwbYVqXoWVxbyg8AabEnz4=;
        b=IbA8OmI7RVMLPLYYl/lqwRECg2b5JAaZlIGtsBpTs5uT4f/uO7dnt4FuOP3NfGLCxU
         r3w0CRpAaQiQgz7RaUwPHBvHp65UM9f9fZGTUoWKPJbcrwn1/KxEfHuUihQLWvn58bzQ
         licISeTHzA3wS5t1gZQiwaESodirjWrvR2tqPLFxUQrQIhhXxEL7FQ/RTVZZLYbwArkk
         61gQ7C06M03UiOZHTwefZcQtDS8Pu432aHoR12b9txYUiEahcvpUOX8xPQ8/GWoix4iK
         HGDU/MG4rY4B1P2/ngxhWH5dgV6708oSdvrFkMz4Rf4nD1v0vTCudv6JLApfVfdtys92
         LoFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/4CyIqbMClZS8Awh6fcd3jNMDG6IFq42Nzv2r2hRrfyPxhOkf
	7YEPzTTRacIHddaTECYClCc=
X-Google-Smtp-Source: ABdhPJyegTRliaQ0xsxVdIO7ZLomUH2DsDfTKGL10iUTj+H+4ejVmtnbFSB13mwlqZj5dOf4tLoGlA==
X-Received: by 2002:a25:a408:: with SMTP id f8mr2304085ybi.332.1600360544158;
        Thu, 17 Sep 2020 09:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4055:: with SMTP id n82ls1176034yba.4.gmail; Thu, 17 Sep
 2020 09:35:43 -0700 (PDT)
X-Received: by 2002:a25:bcc6:: with SMTP id l6mr30718796ybm.251.1600360543572;
        Thu, 17 Sep 2020 09:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600360543; cv=none;
        d=google.com; s=arc-20160816;
        b=r8QtjDyP8bC8uu3f08WVk/+pH3GnXMLfzjRHLJ5Jje3X2I5klZu05SA2cVlLYT17mb
         LdZslWQIPJ+GJaQUjVXGfwnDECja3D9JRTniR31RsVWyz6bvIhorUXeYyTZWMUruJlY+
         /htw0nxiwwzHQfJHtWfjgBVaGWuizppGnBUvV3ftny5mNszNwdIj6DcVauJGwbJgr3se
         npbHoavPtqWScXv4ghUFej9kAYuhKqgqRHiUMf291pJR2WvHG+H9h9hoa+KHf/tOe6R0
         ymw7bvxeiHbehiSmrcRJRXuhwZVHaaiJNGjsCOHcq4ctddb7r1M0rp0ylUWkUF6VoNtJ
         H4Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=wvxcioGoNULh+Fns77pIcs1xHwt/TUOQ8dvmlwywOcc=;
        b=LpMv2unTI0vkhaSBVRRaUbesSrqbV2JKVPY3EKdDdw4Hfzr06WpomVaIv0EdqWSH1+
         NxI2U7h4JPhzKQ3jrTBRu90QSPVcegh53aMEbS9ttwZJNrgZ/pizKyjjMb/bUIpYpHv7
         Ptk7XjxG6ydKPKmIRS/BF9cKYJ3VkxAGnLGywiwyZwzcEW11t0Nhs0tnv6htObcz1zJU
         y12d204EObwDnpQoBmzRmQTUUP+owP5V/UlDKjZIgJuDyjSMD54LEuVoaNtdjCD7JTHo
         Z4oloOlIB2kyhNI6KoON4baMEuvnddkHPOeeQOgkcaGogh8uD4hYOvt7DKCLizw/jWhf
         Zizg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s9si31191ybk.3.2020.09.17.09.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 09:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0D54420672;
	Thu, 17 Sep 2020 16:35:39 +0000 (UTC)
Date: Thu, 17 Sep 2020 17:35:37 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 25/37] arm64: kasan: Enable in-kernel MTE
Message-ID: <20200917163536.GE10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <859111cf1d862ce26f094cf14511461c372e5bbc.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <859111cf1d862ce26f094cf14511461c372e5bbc.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:07PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 23c326a06b2d..5ba7ac5e9c77 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -427,6 +427,10 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x5, MAIR_EL1_SET
>  #ifdef CONFIG_ARM64_MTE
> +	mte_present	.req	x20
> +
> +	mov	mte_present, #0
> +
>  	/*
>  	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
>  	 * (ID_AA64PFR1_EL1[11:8] > 1).
> @@ -447,6 +451,8 @@ SYM_FUNC_START(__cpu_setup)
>  	/* clear any pending tag check faults in TFSR*_EL1 */
>  	msr_s	SYS_TFSR_EL1, xzr
>  	msr_s	SYS_TFSRE0_EL1, xzr
> +
> +	mov	mte_present, #1
>  1:
>  #endif
>  	msr	mair_el1, x5
> @@ -485,6 +491,13 @@ SYM_FUNC_START(__cpu_setup)
>  	orr	x10, x10, #TCR_HA		// hardware Access flag update
>  1:
>  #endif	/* CONFIG_ARM64_HW_AFDBM */
> +#ifdef CONFIG_ARM64_MTE
> +	/* Update TCR_EL1 if MTE is supported (ID_AA64PFR1_EL1[11:8] > 1) */
> +	cbz	mte_present, 1f
> +	orr	x10, x10, #SYS_TCR_EL1_TCMA1
> +1:
> +	.unreq	mte_present
> +#endif
>  	msr	tcr_el1, x10
>  	/*
>  	 * Prepare SCTLR

I'd keep this simpler, no branches or #ifdefs (you can still add the
.req if you want):

diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 23c326a06b2d..a35344754081 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -426,6 +426,7 @@ SYM_FUNC_START(__cpu_setup)
 	 * Memory region attributes
 	 */
 	mov_q	x5, MAIR_EL1_SET
+	mov	x8, #0
 #ifdef CONFIG_ARM64_MTE
 	/*
 	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
@@ -447,6 +448,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	/* set the TCR_EL1 bits */
+	orr	x8, x8, #SYS_TCR_EL1_TCMA1
 1:
 #endif
 	msr	mair_el1, x5
@@ -457,6 +461,7 @@ SYM_FUNC_START(__cpu_setup)
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
 			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+	orr	x10, x10, x8
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917163536.GE10662%40gaia.
