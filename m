Return-Path: <kasan-dev+bncBDAZZCVNSYPBBIE4Q6BQMGQENOKQGBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 616CF34D085
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:54:58 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id e25sf5259473oie.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 05:54:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617022497; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYGPuE8FDeaJrtuLysZLm9vNHgHJ6Cybzz7ZGSzsklAte3yI44ECfX7lOo0/KmxKvg
         SnOOWdpjZqE7P0juDdDa1l2O1hM1enhLSoVjMlrqIAEQnkJN38ZCnlOFSkWhn+q3CQl9
         W+0D2/Xtzix6x/b2YWD6S61u1osQrPJkgikjz0AcCB0e2iMDca3nR87hCmftJq65UWmb
         7xCxa5Gvk2ZhS/gazqXWicacWgaegEjPZmmPZWV9SXWS4Q/DyLBbWgkGQA6JXCCavUFo
         0ICNSzbpWWRn3HQ8w8rRTZbo4A76nbni2HwWChMRp65uHoEkXS3AquI07hzeWaSauaqM
         ApAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=KhrauPJRXQW046mRY4Hm3KzVue0mTY/Ppo/YA8N6kQU=;
        b=jQJ+58xg5lJfSJ/6JX1OsvV34UvcGRbT7jgWJCYOUjLsac+PBNqVNSJ/0hLa+H4sIR
         2lgjbX3WbBLT1pYg5ttBV7SG3Ira6MIsd35heomdemc197B5svWg4br2S/BDB0l9uZ20
         WI7pQS9Fs/U1odhlSyvMhlYrnw+1F1/TCpWYaGYD+Ej5H8Z6dAubKBTgDmUWEuu+r2YF
         7Gjo5zyjfzxWjXGyalZ5AMv8BFkMeBWKqct7n4TVWxmG3Yiz3bHuGgP+Q5yzW2GlDTrO
         uELTEp89CX8RlVsBmLFdz0rqyywwO7gD27zwLhfg1b3in73GV1/QdOI17aFyafErZJa0
         OsNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="DQIvO4y/";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KhrauPJRXQW046mRY4Hm3KzVue0mTY/Ppo/YA8N6kQU=;
        b=OJFIZ/Q/eqtzUrwDS3dJi3UccG5J/bFlH9OMEJ515WaufdEZ7wIMy0i9UdDrZdT7ma
         kSGOxYztX039KDsqBrr3mfVnHDgkDOKC4CCzFe2OZaaZ8LHAW0a5OVtdlpDXrEKdnFFb
         J0xub4F1iQyLt79znKtFYyCf1uyxMd5INRCrtqnm11kp/sj2DJ5Vuanr02YzX3ofkhsy
         QgNpD/OQpitM+CT+C1Kga4n2ldNBQFK9UEDxV6zPmClih5qLzMOzwk5kiEkkXxcygVXZ
         acSFdvwoTvzhfJTom4fsrSmX5HAk+bnl21sFLRVeF1AY2ppNBXP9YU0GrxWZx0cCVeqj
         sEkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KhrauPJRXQW046mRY4Hm3KzVue0mTY/Ppo/YA8N6kQU=;
        b=L5fS17RgWEaNc9stAg1sZvo/yjIupNElkg9SKbVcA+KsgQJJgsKuQ2wvWBLoV/gLF/
         K+gfMEk4i9Sw0tK5LyUnrNaE41ykrBF3PdpfvldzAoSOtjmPnMXUwEBVklpA0US1oE0u
         2hyIl5gflXBmkKjgNh1dJ5Vbn3xJSY2Dq32bY0oxF2eM4PS8fD2nF4/g+MLzlT4GSAWk
         H+3r48vSkd95tzQE6XGMZZ2irK4+lJQe0L8gZWp/sbGSbM7VpjYfZjv44bixnWombUKx
         sAxFEgH4Ni0PZGaB1w0bKp4jrK2910oKEQ6/Huq+J8Z34I33J8PW1lVgyAB6ubZvBiVv
         9Bmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533khjn9X7WiFTwdOijUXrqJHbfMI6PHpWldLQIZHOkrj/J4Fo1o
	NTaPPrm++WiLOHYc5PtPXks=
X-Google-Smtp-Source: ABdhPJxGgyCZzubSKySiDo0UH4H6t4uvrofcoTP3zO3QNWtNLWPFruuVX1eNCA9HmsT6eBiyHL9NVA==
X-Received: by 2002:a4a:9671:: with SMTP id r46mr21265101ooi.69.1617022497025;
        Mon, 29 Mar 2021 05:54:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1146:: with SMTP id u6ls3732919oiu.9.gmail; Mon, 29
 Mar 2021 05:54:56 -0700 (PDT)
X-Received: by 2002:a05:6808:b21:: with SMTP id t1mr18309359oij.35.1617022496688;
        Mon, 29 Mar 2021 05:54:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617022496; cv=none;
        d=google.com; s=arc-20160816;
        b=Nuscyh93I3D+qiJqLXFpPpPQ1yVF8P8p9Us8ZgnfkxubN5CMylAEKaY4kM+SmdGr96
         lCvOqwW5fveVSSPlDfxu+8yCAi2iEFtxoFI7mfLxgVRXUIXsfvb9rYmF0HH0ZNx1ovhr
         Ivgk5xnIPuYku/kZP2DAVvL7Lb7M5YCwxykfJhfNpH1h/3ff8qIIgJRPVR0ZYbCCEMuk
         7IrLjGFYS+qW619477uyz868hbn6WynCEh1ry1gdnc5BtQWZ8OiR4r0lch4RAhs2p+mf
         EdV5ArciGoA3Z7swga18v54epZgF1QiNTm/ALML2t+pwToITYpeUOi4PgsBPdBjZoHn+
         JgFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=InwCmxYMSdSK30tPIOIjxwg8+5+xBZih5Je7WVfDo4M=;
        b=eS0MKYYTR4n9SeWil2l7SVHyRnqU+r7KPSDeyTmpQiIx8j88TeNDhVrcnLvg0OW3Jh
         lnNFvXrO2G+fE8xb4TlCGNsrXNaxF89YdR8k9/lZBzQ4aZJ7q/K5ZfX1Gcu4fPh+/ZEk
         LYNTukhReb4j6SSoz7+rcSTFghcZxsZf9SATLjHaawT7Cjovhe7iU2mjwuXoTZ1mAoI2
         UJYHlnRzYp8Yua125/ZibBYPTIUxru/GNAL8vkpHA1NcH9FTVES4L9F3NY/DGl2pahZ8
         PIclyAvBWqE199YGboYhN6AB+Qe+ilzdiwVzJYsW4WXh0iduLwbbKTx6yf7On88nkVCY
         IRUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="DQIvO4y/";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v31si553317ott.5.2021.03.29.05.54.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 05:54:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 411E2614A5;
	Mon, 29 Mar 2021 12:54:53 +0000 (UTC)
Date: Mon, 29 Mar 2021 13:54:49 +0100
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, akpm@linux-foundation.org,
	tyhicks@linux.microsoft.com, maz@kernel.org, rppt@kernel.org,
	linux@roeck-us.net, gustavoars@kernel.org, yj.chiang@mediatek.com
Subject: Re: [PATCH v4 5/5] arm64: Kconfig: select KASAN_VMALLOC if
 KANSAN_GENERIC is enabled
Message-ID: <20210329125449.GA3805@willie-the-truck>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
 <20210324040522.15548-6-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210324040522.15548-6-lecopzer.chen@mediatek.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="DQIvO4y/";       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
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

On Wed, Mar 24, 2021 at 12:05:22PM +0800, Lecopzer Chen wrote:
> Before this patch, someone who wants to use VMAP_STACK when
> KASAN_GENERIC enabled must explicitly select KASAN_VMALLOC.
> 
> From Will's suggestion [1]:
>   > I would _really_ like to move to VMAP stack unconditionally, and
>   > that would effectively force KASAN_VMALLOC to be set if KASAN is in use
> 
> Because VMAP_STACK now depends on either HW_TAGS or KASAN_VMALLOC if
> KASAN enabled, in order to make VMAP_STACK selected unconditionally,
> we bind KANSAN_GENERIC and KASAN_VMALLOC together.
> 
> Note that SW_TAGS supports neither VMAP_STACK nor KASAN_VMALLOC now,
> so this is the first step to make VMAP_STACK selected unconditionally.

Do you know if anybody is working on this? It's really unfortunate that
we can't move exclusively to VMAP_STACK just because of SW_TAGS KASAN.

That said, what is there to do? As things stand, won't kernel stack
addresses end up using KASAN_TAG_KERNEL?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210329125449.GA3805%40willie-the-truck.
