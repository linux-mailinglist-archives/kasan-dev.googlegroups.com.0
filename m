Return-Path: <kasan-dev+bncBDDL3KWR4EBRB35KT35AKGQEKNMLOYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 33E6725442A
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:13:52 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id b76sf4413036qkg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:13:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598526831; cv=pass;
        d=google.com; s=arc-20160816;
        b=VANNnucHs9Et13z1TwGeKONpXWeGfRtsdnY64Mb5GytWvFOVm7TwGOpv5kER1aW2cA
         Dp1+UWK29IO9utFLfTfi+wULPLbyh/eLM/hsasCmUieHmPFztktRLZhhZu/NJBDst5BF
         x8szl9W7UE15w+rnraKEFxnja2VngYUatZCngWFQSpT6WhPoDJoTNmfSDSdHfubWez+S
         kMNmoebDzSCkWYT4YvDUnHkaUi5aKGfFsTaNdXKnCe3s5s4w3Dxf6u6L6jjUAfkyjv7F
         RQ2myLDKuJHvmKARAbh/CP4GlsfAGcdoF4422DlTr2JZ6efWIbJcTu/AvLHKa1yg0W0m
         yUHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=X7SqpRlsd5yVItcLKr2nU0k3s4SxsTUC0UrCUVxezh8=;
        b=I1TpijvrXOOWQ2rqI9JbLeqeGdFbCyMe3ajHcNmDm6tO2c1iFEpCVmd33WGUn5+UU+
         OsvuHTpCJ/+ZSvhAvIH6KLfKLEScD5ySGKT6YN6L/MH+J2Skp/DbadEFP2QjOWjbflRq
         rxubcU8SyqufIDpb5E3YBsruWHPOVtaLUMAeNCdQBVs59WPMCiqmlF1YWlsbH5S/s4zc
         wMfXARC2ttJyYlwEXukSA+iHIYzpbZODzXC3pW36e6o0tIBxovGhazogLR3nBSsKTLBy
         qrqUIpC1WFGm+O/7OpoDpAf889nETOIS3bTmef3fOD2Sj7Dj6Tlj+CFO25KSDvwPsHN8
         D/oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X7SqpRlsd5yVItcLKr2nU0k3s4SxsTUC0UrCUVxezh8=;
        b=MpyEl4LWte2eT9PaygjTHexXmUNsHLjHAEBWpvAjCSdnEAKRfXcFAuSXVETXEaGAE4
         5zothy15xKtdiyhjZAB9pA89/LilU82rqlM2a+b9xXz30N0OoCN9Zmi9yfRGeOebjM1u
         NYCvgc/mlNgw4Rmmssg2eU0lFYzNhZW6y/0pKdTwjHFWM+hy3U5+me7Nvk1SQZT2yoga
         nM+Lzbtt5JsCS3Ayn4MmKFt+wP0PsnYKJUB8ztgeaEVfWoguFYUp26UiAWWI4I7nXmOa
         09UzloS/CAVKdSOFL+/qAXK8oMNkGATlMNsgA+Z+Yve99I3s2uTYd8Ta3uBH/FUjSLCu
         tLQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X7SqpRlsd5yVItcLKr2nU0k3s4SxsTUC0UrCUVxezh8=;
        b=sIMWmdTThY3otpPaMMBA9/EEZZPt8Ulx8iqRDmT9+5chwaMV6I1Eb9MHk5I3geWMF3
         DVsqzjWHbz7H4RibZG0XtUpLUWeSbuMrva1p5mI97S6OdpZx/YsUvcK68wAgTJJ6sOhz
         jU1TX411ujvzpGEEWel6HTqyv5MdqA5GPhuATIg0AR7r/Zs84yXomfPxdDPaxOYHE9An
         Qjo5LXfRc4nzRGqwVSgCftPqt+O76YVvf5Pxv6Iaz6moLFT9Y1eOiafE3GXFoHhIZSdv
         asfSw1keHmC8BFchVmCYOk9HkGKTl9yzTrAUiNz/j3fKfVYslqAM48l6/+HWjYzRXnhN
         EtzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SCBSd8fQY8b45N0OPfkVjAKIxB58gv8caqpPLzNTz5zopG0PM
	0WMyTNi/XPlDrVygHzHAdOg=
X-Google-Smtp-Source: ABdhPJzJFv/jKE/17VLY+h1zStacs3a2AprD5AJwzgPVjHbTqy8LvWNDEv9FeaMPbl+d0WgpQRBDNQ==
X-Received: by 2002:ac8:4643:: with SMTP id f3mr18461330qto.128.1598526831313;
        Thu, 27 Aug 2020 04:13:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:33e5:: with SMTP id v92ls732864qtd.11.gmail; Thu, 27 Aug
 2020 04:13:50 -0700 (PDT)
X-Received: by 2002:ac8:24d9:: with SMTP id t25mr18684173qtt.15.1598526830851;
        Thu, 27 Aug 2020 04:13:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598526830; cv=none;
        d=google.com; s=arc-20160816;
        b=klpNfhKUu1TLNnqOp2CeMz3jU8POAKh5TE3shiYpNPbZNqkEonnP12KD1LzGX1DOSI
         YNpySYHoP/UJUZagsrdpGEuG8cZE81o5LX0q50Ky+HmvHJDrjkLpoTBUiVmcDCjYOUJg
         hnQZwGkiZkiHhbISjquiIkmRLnT3LPUBieHz7Dfl444KZw5+Z3NQaMnohoq1mpVwuDOg
         BMI1qvyHpXQk7cteVwPlrFN/xURYnWDKtmFhJKCxwQeqi+BZf/kc0pOZysMHUHZLeHaq
         UCUYAJ54ENLYHTUEkCMtQc0muSnwSWoFEfhmYMcj87MOHCP6UGVOHNqa8o47vZIbQ1AJ
         s7ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=B5bjKdXYKQNtlg7fO7G9l8LPDPQRkLnxmiPAT5pJ+uI=;
        b=Zxjbj/R1awGkf6skVWaHh2QXOW8hnc1H7w2QwR+jI0rixOUTpqgrJzs+X7g0a5L1ot
         1ELGK1MRQc2chj7cFa/pxIHpcEOOwg0Vlq5IkcCrrT9lBuffvmkU8uxtc9XibngF9NMG
         O+XPwFKZQZJGsJGe6p7yKmbt+5IkRhUvzvRSqJifq0iHuaI/TH30euvUdiMU01+5qbJf
         T3MM1rKQGMaO3iMHtpZS8aqYDOAerj2Hg6ENik9Z6G1IHccfZ3+xq2+3doNJ/ByBE5qb
         j0h7OASmCNqxigMRQUlsRri45VMjurBOqucW2N3qJK921JXOFhx7Myv6sM+vdCkrdMYN
         mP5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e16si97413qto.5.2020.08.27.04.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 04:13:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 867CA22CB3;
	Thu, 27 Aug 2020 11:13:47 +0000 (UTC)
Date: Thu, 27 Aug 2020 12:13:45 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
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
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
Message-ID: <20200827111344.GK29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia>
 <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
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

On Thu, Aug 27, 2020 at 12:05:55PM +0100, Vincenzo Frascino wrote:
> On 8/27/20 11:40 AM, Catalin Marinas wrote:
> > On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> >> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> >> index 152d74f2cc9c..6880ddaa5144 100644
> >> --- a/arch/arm64/mm/proc.S
> >> +++ b/arch/arm64/mm/proc.S
> >> @@ -38,7 +38,7 @@
> >>  /* PTWs cacheable, inner/outer WBWA */
> >>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
> >>  
> >> -#ifdef CONFIG_KASAN_SW_TAGS
> >> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >>  #define TCR_KASAN_FLAGS TCR_TBI1
> >>  #else
> >>  #define TCR_KASAN_FLAGS 0
> > 
> > I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> > user series, just do this in __cpu_setup.
> 
> Not sure I understand... Enabling TBI1 only if MTE is present would break
> KASAN_SW_TAGS which is based on TBI1 but not on MTE.

You keep the KASAN_SW_TAGS as above but for HW_TAGS, only set TBI1 later
in __cpu_setup().

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827111344.GK29264%40gaia.
