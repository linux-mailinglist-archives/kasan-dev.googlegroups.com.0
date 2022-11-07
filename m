Return-Path: <kasan-dev+bncBDAZZCVNSYPBBCWEUSNQMGQEC7DQFSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 11A6261F771
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Nov 2022 16:19:39 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id i5-20020a0565123e0500b004a26e99bcd5sf3798795lfv.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Nov 2022 07:19:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667834378; cv=pass;
        d=google.com; s=arc-20160816;
        b=QM6ss4JkMtSccH1wynDzxksuyIl5H+rlyv0rM8M6ogFsJMyOyI8duP9sfhpW3ULCq8
         O16JlsfCVS/lOanWHh+obBaW2V62Yb4EeCX1m//Q5GWeqjenJuwM8HFv49W+G+Uq3PPZ
         KeHWahQ/ekwFfvxNeUC/35vfz3k1n6Gzu62fKJnxbZvrC8U9X4+Vy5gAfoX8nK14U+fD
         OTvW5zHNMFsuSkRG9A2DBLwRFglMMEnvvY0OBgd5gSIfRkqiG4ftXdiB+3w3sOzTp9zN
         qIsEUpjRVMyNlmrbcDgj7Of/5HxBE17ctaKLS1Ga3k2i5LNQgrpr2fSFwt6xy4cxbMl4
         mXNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=1IH6P2MQD6AW7NS5wsINa//Mlo6VDmP1gWw4xVCd+S4=;
        b=E4UZcLIIzpWcZqYkiJgsdYVC+wYp2LYMaqpuK+0C9FbPtQ/29Hneum3uOLKCM/TIEm
         pnAvBxoA1CrtKKStMuzeZjiMXt4mAzaLwalCF7tzxFSiLMkPnWSZT5YyXTMWlXNdKTSr
         YKEvK+72M6hYGVgcsMp3roPj3DPjEYoBU/fgnehh0M5RxOM+I/uCI69YqQii/3OhzoPF
         QrWX1pCmbhfRLl2LNM9qrQXPLDXVPnCUjuek1BZ9grX9DWteqfpmmjudmwTJictwGjOo
         E8UAf4O4t5B2Ai/TTTd7fb+ojAtAKYfgQZKuxuDKrXqysx5ZGoqa++GDfWqbvzPBQpCk
         vU5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l2EcSwCD;
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1IH6P2MQD6AW7NS5wsINa//Mlo6VDmP1gWw4xVCd+S4=;
        b=cun1W2K5yMU3rBNdix78aEJghrcvtSCMidosSjO7f1SdhHKGIjdpNNcrbeTblgO//b
         /twBdRe6L2+RnQDNTg7CKIl2g8dmvagswkEyduu5yPkRgQ+Hd9L1xe1ejaj88QhO/Rbz
         AktNMKxRYZC93RIHZux1PiToy/cZCqSqBUbORQrDbG6gnHe3BwAE7+MYjWc3+3nMUlYF
         eQADdVidI8Jt8m+83aqvlQeqkUH5H8VDngVK+mKgLyH48UXlY+sL03Paa9ANi9eE8fjo
         dT0QFlp1rQPNU1YzWzlF/X0TOZ+gqynZ19DRyOMVqJGEV24AjqExXYOfQ0r1yiAQDNNq
         PEqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1IH6P2MQD6AW7NS5wsINa//Mlo6VDmP1gWw4xVCd+S4=;
        b=vwlyf0MXWqEiLk6zeGzSFNhJnLW2/o7KNYLCVmibfWULGP1fVcZsbFBMiztfAeEd3W
         3sdYfTVhII84Nx021Pco+88/5QqiaraDXllQUI+eEON+GeoYlbzKW2/vDfx2js2h5jI/
         sxrZ3pPUHn3wlJ8Njm6CW2YXyCeOORazpRbFrUSIhzGBvUC6IIcu1D4EwL9J5YDi47Wi
         4rMPz4PANLweXfzv2pUvK+PniGZgj1b5lboMgPcAYyge4UZ9pL61bcF/8Zj6UOOZw6pR
         15w3JNqqbUI3Y18apk2P84s1/1FTIRgkW0HteLEkL56cuNUdwsL/osLwjSvco0+wOv65
         MOSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0KmqeJYKN0iACC5UAgjcu8clq7MbSG24Y7J8l4rGOqo80sfEW4
	cpVEcTO7HrmIg6iNfJ10MZY=
X-Google-Smtp-Source: AMsMyM7t5fEC7Lo6jbTP7F3IdB9C/WNg6K2slkgPmhl/oGHuXruEqck3Nk6n94Ydi+nNoHXEWNIwrg==
X-Received: by 2002:a2e:9184:0:b0:277:c41:d44b with SMTP id f4-20020a2e9184000000b002770c41d44bmr5918597ljg.326.1667834378396;
        Mon, 07 Nov 2022 07:19:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:358c:b0:48b:2227:7787 with SMTP id
 m12-20020a056512358c00b0048b22277787ls517785lfr.3.-pod-prod-gmail; Mon, 07
 Nov 2022 07:19:37 -0800 (PST)
X-Received: by 2002:a05:6512:31ca:b0:4a2:7dc7:6967 with SMTP id j10-20020a05651231ca00b004a27dc76967mr16777620lfe.423.1667834377247;
        Mon, 07 Nov 2022 07:19:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667834377; cv=none;
        d=google.com; s=arc-20160816;
        b=NH5cAT2/eUoeJAqqwY6YGrpR3DEHpEv/g6QDP8+rgYzUvJfU9+7NIiYjQa/95hENPg
         efLeCFKaAjAeZ9Z55CtS2DfgRICrXEJ7gUFz2ey5RLaOphm7liRYnYC1Py7ByQZXJOgO
         qTbFkdqkROWKDQIWzC3OPzdnTDQPwzVBftwdNHCY8OwaCmJJcBmOgPkmmUmVU3BzTZC1
         NJOXykWR3KondyrKd2bRBTwJO7YQuAHwv7an6WdoYaNj74ZZm/I7Z6bhcvA4aco5iG0l
         r2j8Nyc9oDfH8ZRtuQ7LC37DM4iQFy9VM9uCk9+VQelvAAUFOpyH6xIY8qbgTpIm5Ine
         nwgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WP3EPJUkC3MsbCQ2RdpSiK0YpXdLb38+hU9Aqxzuoy0=;
        b=J3cxJuSJgQkx9Qx/46o+xIbtH0c0Mwlg5TL2GDxGTLEJ+xht2pB+AmFKJKsH7eewCS
         gKR5aZSZwH3Num5wX5D/5c41HDV1uZ5U3RTSao6thSIXzOVWhQD2/opB9oXarT4kYOXz
         k+BUKBNo/LtsONRqkGOdFlgF0vlggEXHxHi8CRCIQjL2HCWUoSPzx15bbB0BOABNQyQb
         9FH81V7ZB27G7kSVBAypM6vS03yMRvIlpOYwA1nhua9v27HYyDaXN7FHX283mu/QNnv1
         k2BKYbNBB/fhngCpZeQy+W5NtHMyhsOqCJ1TG8gBKB1xEZEULuOsXDzMX+dKnT17/Qjp
         mXlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l2EcSwCD;
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id k9-20020a2ea269000000b0027737e93a12si233575ljm.0.2022.11.07.07.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Nov 2022 07:19:37 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 77F91B812A2;
	Mon,  7 Nov 2022 15:19:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 17879C433C1;
	Mon,  7 Nov 2022 15:19:33 +0000 (UTC)
Date: Mon, 7 Nov 2022 15:19:30 +0000
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
Message-ID: <20221107151929.GB21002@willie-the-truck>
References: <20220907110015.11489-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907110015.11489-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l2EcSwCD;       spf=pass
 (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Sep 07, 2022 at 12:00:15PM +0100, Vincenzo Frascino wrote:
> When the kernel is entered on aarch64, the MTE allocation tags are in an
> UNKNOWN state.
> 
> With MTE enabled, the tags are initialized:
>  - When a page is allocated and the user maps it with PROT_MTE.
>  - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).
> 
> If the tag pool is zeroed by the hardware at reset, it makes it
> difficult to track potential places where the initialization of the
> tags was missed.
> 
> This can be observed under QEMU for aarch64, which initializes the MTE
> allocation tags to zero.
> 
> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
> places where the initialization of the tags was missed.
> 
> This is done introducing a new kernel command line parameter
> "mte.tags_init" that enables the debug option.
> 
> Note: The proposed solution should be considered a debug option because
> it might have performance impact on large machines at boot.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 47 insertions(+)

I don't really see the point in this change -- who is going to use this
option?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221107151929.GB21002%40willie-the-truck.
