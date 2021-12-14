Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSFW4KGQMGQEKXOPO3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 01A71474360
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:25:29 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id bg20-20020a05600c3c9400b0033a9300b44bsf7920555wmb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 05:25:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639488328; cv=pass;
        d=google.com; s=arc-20160816;
        b=XvRMatXhJJJ/KTC1J+o3kwEnUCRFwF2aWAKEAv/n3yu/3cIWKedVVWESt/Lzybgdql
         1Ru7931NMvbAZnjk42XC61yBRy0adiqbKiKfBLFC5Pe3UfdutHRXCDICVQNnLpH1bDiz
         qZSvflYDOkgvAXnAnfC+Lb0i+jXWy5l9eX6m+NYKkba5CHMp06982M+p90m7vdaXuFpL
         6Ghfx35WOJ9znye5MkhebIppg6o2bGPVDSbj52hFsLDrjqVkoJMGPnWRGYw1TFUMnUVS
         ud2hiKF+uBKcYhrBJ1kxmPZ6HcpUXsb30Rf38mfz9hmqLoMvEvvwIZtssd9q88RTrFCN
         Jt7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gYjef+GTtg02HJBxHBRz0U2lKsE9o/vz9lSg8bpWoxg=;
        b=Roczul5AsNX+vEynuz9ZpUgdlLObYTwkf8HYWaRyU/7PQ/AGnW1ShYgF3AVjQD5EkM
         2EvwPRTKmP5TMe7wVRr2DCgkJ72ocxzAYArlM/qHcbvzjczha9/Le9dzF8CraVMxKFj7
         RPyYNBxKbeI8sGVOTSlGeYQPpU5GGeM4yZZ2xqurCtt0xbLsm87JCWdEL8eb13Rn3TQ4
         lx+BAATzbKl2SKCB5+wlnj4CPrTZdKPBWpbY9541yVc/v37wkRnKVRFTrlfSItgE0Cdm
         9DdLkSBH+j/88gRM3Rs4sEOlyNcZYcbhcJn7wh5YIshXlwB3PdJjtuCJ1/BkemjKxCFL
         EQhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gYjef+GTtg02HJBxHBRz0U2lKsE9o/vz9lSg8bpWoxg=;
        b=E3tVIUOgKxbBMwe3scOSqtb6iqnZRv1Rjm6NXVF4J/5qB6Cv7vW/g96e9VxV8bOJkn
         xFxbcJNRKPcOIssVDjjf7vL1+F7bYy327JTi+Lz543LQ4yHdJr00e4QP+FWjvsmPjC5p
         yAgl/qZsVpiJeEHrh/LIYU3Fgw1VMEZWkfK9pbwqkC6peKJPe3lM8mpXglBY2eFQb1yR
         DL/Te5OrlxbSW6k/g0Y0pDt3R2zIg7hMoqjSNcbW7Vw/S28wG5WuzCYNO5Sp2fBprtvJ
         Y/rHtozYLhQjWLoYd/MyX6WPEnQsBmxNkMd6ZmZTRW3ot1U1d2Inct44aVFxtXVsLiYk
         oPEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gYjef+GTtg02HJBxHBRz0U2lKsE9o/vz9lSg8bpWoxg=;
        b=1nXosXnY4GCSlKp4aFSPu68WzVZIY3Z8F2pHbglYYY9F+4vyNz9UQYEPALNBIzXmRe
         mNTdpLpIcS25A3jqR+ScMYXP+GiamjubjooZikyxpzipghHcTxsaqwGJR5Hn5gjIewJk
         REEK+PverE4K/Mut8YKIulZWGn17FYCMYhGIAHUAlybQcjYoV2O2IAL40WaUV4pWeMuu
         UMNSa1Dkoiwfe/iu3ZOBZKo9k2FEeGk81nUj3io2qhIOjElw58aik1u6ErVKtQmaImE2
         Ey0MfADK+8wNJZ7j+n7n2++zpn8Ia+9GA9WW9de8j16RWZ675aV10O9j8kgp10reVF6O
         wRaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zgHldQkGK/BW2Whqq8DfQRuFyIMTXg+eij/AfinRaxD3dFEmd
	VpBflK/bRGM+rf5IhJF+k34=
X-Google-Smtp-Source: ABdhPJzvNRS/HxCxnd+kSv8qC7UgmE8yAHmAzlBE++eprZ/xQV2b6YpxEKF2oLveZOU3GnqpIe48Qg==
X-Received: by 2002:adf:a512:: with SMTP id i18mr4606866wrb.287.1639488328648;
        Tue, 14 Dec 2021 05:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls605702wrp.3.gmail; Tue, 14 Dec
 2021 05:25:27 -0800 (PST)
X-Received: by 2002:adf:d1e2:: with SMTP id g2mr5727964wrd.346.1639488327719;
        Tue, 14 Dec 2021 05:25:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639488327; cv=none;
        d=google.com; s=arc-20160816;
        b=ZARbGIMweBX9i/5UYAG/48bJLwKiYIbJYCw9cMEsxfYRfmqFGv2hxvGnbggRh19+rW
         m1UGtalGBRxkXDS+I4nDIRcTV2UrojKURcqOBMDTKYhG0VfoVnfYSBRMHVINYyyZV4bl
         GYsjZwarOtneO0qRGxV6QoA7zMPV4DESs7Jz4wq+3jU+GY74esjEfcufamaP7TeXvf5Z
         N0Vjv05mbruH/u4zMBz9/G/skJg6WzpHW1Dy4vECkcpXArluwbLjhcGOXSobhi7UV+kX
         zUPFwi9O8ncPV73GCKGnWQXHLQ2e8CSsKd1jHw3y30zy54KWubosc4cAb7TTXmPHvPUt
         giGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=wX1tujhFYanHryIGMKwl21Wfjqx5Yp83VOoL1ZSfGyE=;
        b=zVDVHYb2OKpIDE1hJXAm5CzqDGoBLLULuYMHuelwx2ic0vCAu3DMfS1n3lHmwLrdUe
         TCaTquXKzIbvlEXuNNUXHhM/n3H0C0Auz/9nhaqCeJQtBWMUpmGmQTbT+S7sWcEv+3aR
         0vwtb9BFtG4w4NdNXnP0OGsKapfG+dAy+UI1MyjTv0cTolZWIWPUuws4tuxf42JvJxwm
         PsMFi6tL6YGSJBikOlpwkSmKiufG5ixjgL3moPDnvxPObB2aFHWJY0t6yMsFVDz6sjMr
         XXcSXTM6AGgTEF/1sRFgBv+nwQbCC22X1PVJRWQMGwLDsXWk76OHBy7qIq1I0S+kDzod
         7rWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 138si91127wme.0.2021.12.14.05.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 05:25:27 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 87773614E9;
	Tue, 14 Dec 2021 13:25:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 08494C34606;
	Tue, 14 Dec 2021 13:25:22 +0000 (UTC)
Date: Tue, 14 Dec 2021 13:25:19 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 23/38] kasan, arm64: reset pointer tags of vmapped
 stacks
Message-ID: <YbibPyHQXjU2A/jg@arm.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <bc9f6cb3df24eb076a6d99f91f97820718f3e29e.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bc9f6cb3df24eb076a6d99f91f97820718f3e29e.1639432170.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Dec 13, 2021 at 10:54:19PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Once tag-based KASAN modes start tagging vmalloc() allocations,
> kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.
> 
> Reset the tag of kernel stack pointers after allocation in
> arch_alloc_vmap_stack().
> 
> For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
> instrumentation can't handle the SP register being tagged.
> 
> For HW_TAGS KASAN, there's no instrumentation-related issues. However,
> the impact of having a tagged SP register needs to be properly evaluated,
> so keep it non-tagged for now.
> 
> Note, that the memory for the stack allocation still gets tagged to
> catch vmalloc-into-stack out-of-bounds accesses.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbibPyHQXjU2A/jg%40arm.com.
