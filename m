Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQVOTOAAMGQEXSCZ52A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id C88452FB628
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 13:57:39 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id m9sf13838767plt.5
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 04:57:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611061058; cv=pass;
        d=google.com; s=arc-20160816;
        b=LLgsJn9Qe8jdbXOIAV4kwZ2byXw2dh2wJ4G5uYFvN1lk08Jnig2wtGFBCZO/u4qvoi
         IesWTfGZeWdcrb57Fx63weCsgYFn69cBJkNB39oElVS2pjk/ks5V7O8cOLEHcwvKvdKQ
         ZV1ZshZ/xSVZjrIG15QC1IwiL0/IIOJRqupeyTS8hNrP+TIpIMSMiFInJbz45ROIyLFM
         Ca3awDwO2UoSWYAZwPAapsiPbT+5bQRoR/RQ2otG92gAcb+nbTPaFSs0QA/8tu1HaKg7
         x2ddu3z9GA0czFaORWrKO1P4Bb61XYP5858jlnTReNU44ZxGzMTICnR+PDOgftqR0GO4
         MIrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=vVZt5NhTcprvyIJ2y7eabNRYgWa1bSIRvbI5xoGvpGM=;
        b=kcxirDMWyZz7tjbpNk1Qyf0KRSMywgN+ZsdRePo2x9/NVST0RQBkfr7kVV0QLggM/c
         g4v3bPurBBVX7RQ0E5R3bc2Lk5mhru4DjT8cHb5CvqJfmCXuWpFJy631KaGpZ8C1ZWwb
         78VVP7BHlmeI03aZPY2XES81ID6Czvzy/VCPQAFzcKbyjVZQeLX1dgDjVcYN62ofSzQQ
         bQCwx0sLuXumgKs5LyGSQnW7AhtCvfQr+tCEbT3IPI9ngbGhe4wSfFBTISDvxmAnesdr
         F/BhV1L5zi1TCUrocB9H2KDPQzN2RO3aZNGA2KTYB+DL0in8IRxDSEVMJRbEbhirdoUs
         KN2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vVZt5NhTcprvyIJ2y7eabNRYgWa1bSIRvbI5xoGvpGM=;
        b=NSEmCKhXML7xFxq9eLFnt37apUJSA475sDZ2xEff8RJoZDMmrZU67zdbKfDhfuvang
         oOiRTrbdetO7mDOxXaqLfDtEdijTjTEaSasPlcgIEk2Qt5Gh+CmeQhSzO5pQpN+elTI6
         DniAMlxmP2oW3h9+bKaLt0rh12eG0GmG9ZtD9bhKb7ufP+yv/oDwxIZqDq1MB29nBzmE
         IoWBPrMyBChrRiminU8E/vpH+EHAHOAD0MVuXGHjZMSNT8F/BpRFuLdeRk/KjuDhrQ2R
         dXmBMS+OQYZmm1O2Zx43jLCgtGCk0SuSjiHFp11bANvzomR5jfsU33laIolRT+MiLFyq
         /qiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vVZt5NhTcprvyIJ2y7eabNRYgWa1bSIRvbI5xoGvpGM=;
        b=WMmOhFu+fLngFxmS2Rk7HoRcjTkxyo2DwT44xYelHP86XGoRCj4+t1o1V7tGLVZhO3
         c58vEv/z+EC1v8e4pw7HbEYQIFNjkhOHuPbFqvOXjughy0CGZpb86h2eF4uqXwC6udgq
         slYw6pzHLOwZb+f4UvSn/1FbwZsrnDAoe8XTcVxH8xR3D1IDSLr+zn9EJx+Yo8e+SNS3
         PVkDy0SUJaTVoCVb86TwwkgwBeUYavGe9qmeTczU/Y/meAEAkSf9IZ9ukWKH1e+fHzwD
         npn8ZIUShgy01PyD8qmmW2M9U1E6Zp7jtqNV9e7032d5erxoO6IvAw+Ck0R8sH0jZ//r
         +vlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jK+OR7WSuu1jwk1D+iesqIYRmeqi8JDXZcVEkA+EpjWLlvFZv
	vnHAhBm/mgjNFZycFrIhk2o=
X-Google-Smtp-Source: ABdhPJwVNQIK1M+OK+wbK/3xxf3/PQKLhufbk/B99S+58/b1RC8cj7vasz7YDUH0gtkMnpu1Sz+Ejg==
X-Received: by 2002:a17:90a:154f:: with SMTP id y15mr5270089pja.217.1611061058598;
        Tue, 19 Jan 2021 04:57:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:768d:: with SMTP id r135ls2125209pfc.4.gmail; Tue, 19
 Jan 2021 04:57:38 -0800 (PST)
X-Received: by 2002:a63:2fc5:: with SMTP id v188mr4203420pgv.243.1611061058009;
        Tue, 19 Jan 2021 04:57:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611061058; cv=none;
        d=google.com; s=arc-20160816;
        b=fcMfDwawlPNCpVbC3Jf4YY9fJIXoSrUTRpD6N8tufiTV+xYrAMNKlKzi5eYEiOOqwC
         NIHdXIyyQLT60E2KQK+jy2iu1Xm8pnQDfE1WiaVJiHj0iEqbdWl+JC5ivtYXDUNPwE7U
         BKjU90kNzv8zE+6KDzk0kYVsVvsUqa2kRn/8aUuJOyrC593PUiL+cQsu1vsM1J/PfObh
         W/l0gIsC9syNJQENM2MAIKce5uG3kD5SNC+ORL6tdJ2nq0FB/4RLCfHS3q5zc/pzUqtq
         zew70kFwty58OcjU4fGwlGBYAl3jUCk0ynAa8jzp4yGTCdA6+ocO2+jTCnNYSgj671ai
         MO2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=p0jmuU/NP1nJaHsnIjuk1cEImlXdYt8dDEQpPs7JHhI=;
        b=uD5Do/ueaQlJaewgK/0g2gX+GvW5csITJqm9XzuHbdG55L7thnIJxomURkAukC0pGh
         msA2CbGnPA5m2Iv+MldUTIuFld9PV5R2oU9aoVmVotGlzD7ywvSL4ADVG076Kses3VDw
         zr/gFkvA7yJzRp1K77Pay0xLqmAQMMpLqtMPO8a71c0ogh62+r5UzdsuMNOUVvBMnhlt
         vUJNo/kikEAvZ/vC5Sr+kfNaHCy+rxL6kSnYc/ld0r8iUCSB3YD0lUEerbxjFH/v1IG5
         XTgQPbEGwpnU9pkkcVulvKcmBNqksHGMHoCXPj4AJg5HK93FiWqbUga8fGaVawcrph/R
         KNMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o14si298111pjt.0.2021.01.19.04.57.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 04:57:38 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C086A2311C;
	Tue, 19 Jan 2021 12:57:35 +0000 (UTC)
Date: Tue, 19 Jan 2021 12:57:33 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 1/5] arm64: mte: Add asynchronous mode support
Message-ID: <20210119125732.GB17369@gaia>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210118183033.41764-2-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Mon, Jan 18, 2021 at 06:30:29PM +0000, Vincenzo Frascino wrote:
> MTE provides an asynchronous mode for detecting tag exceptions. In
> particular instead of triggering a fault the arm64 core updates a
> register which is checked by the kernel after the asynchronous tag
> check fault has occurred.
> 
> Add support for MTE asynchronous mode.
> 
> The exception handling mechanism will be added with a future patch.
> 
> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
> The default mode is set to synchronous.
> The code that verifies the status of TFSR_EL1 will be added with a
> future patch.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119125732.GB17369%40gaia.
