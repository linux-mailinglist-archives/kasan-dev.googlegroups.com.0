Return-Path: <kasan-dev+bncBDAZZCVNSYPBBD452XVAKGQEEGZ6MQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 49B788EB70
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 14:22:41 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id q12sf1460071pfl.14
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 05:22:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565871760; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2W9NJoxsQfyUKYO/h31t28YVLk149SrOZCvSLeKb7O8DQvx447gYmPddw9ZIPs15u
         585tU7kBmictyd3+U9RR8yo/hxS03QyBSL0/X2jOGTGhYJVOtQcmg3hqnZZSu8l9GDTb
         DDfKq9Qy729jPJvKccOqNYUSJZbGEYNX4POxue4TJT/GBjk2U6sTCbAUE0HvUnCNkVY7
         WeJpDgry3lMdPkZAJSuR91Su+ARcNS4vhs4rQMYv8q2al48xEvHvweg0AI8Q8X14udie
         wmZxtHF5OccIRWpgvASk4E79sAri1TF2EWmSGnudgyEh1hdVvNZGrZGZvUoBoUMQAA+X
         ++WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2AtIpHdVJFaED1w9hHKS2VG/4KjcrYz0hii1P/UsXPE=;
        b=ewKZ8XlFFXx/98vvuIjEdW1rZbCZhwbSe9jcUlnSfbD6UH5JFoRs5Y3QaEtOVtYH5r
         uQfQOMZtDZMxDRfNEjNyc8rCR8+6Bqqa+MZhEBNxCfHsFEjZCnrJLEumCrrrO9dYB6OT
         NWXUxyGt8LGePWqvV4k4i7FvBEJyfmxZ/HNtKsDJ9aMlLCFG5q1/vfuzNWJ/keTrybnI
         1xTOph7BkWkwj/+DnYESAabFZYJLWaFr6aGEwKqKhi0xsdTDa15waqxnc6aeIiblBWR3
         F9ByQDCOJW9VStctPQrBDPR8weicUgVUZu/RAdApWgCT1BMxR1zuezvxKIssQcU3UCe4
         nmRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=D3RznPyj;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2AtIpHdVJFaED1w9hHKS2VG/4KjcrYz0hii1P/UsXPE=;
        b=UzAGjDPsfQYivP02VkyR2ItMvk3H4ngnE3L66POQv/yp/9mUBgPTMgtmGrFaZ3MhYu
         Fmo85tjd5sCH5zh4LbQztsIrIdG84DhyTj7xBY/IBgCPkpCU/DrfvOgjGaEbTilPQZKz
         ifqQtD0aEq3Omkp5kvnOZLnTmnUSVOSr7xy6nT6UApFcIXz8Gq5pZzXI/3Zj8yxstJlC
         MMIBBspoB2ItTXREqkWEb3raPh8UN0mm9wqruhFcjgHaK77Eco5JrzfWpVen5mb3nTlD
         vniuW6BEQSEjs8AQIkasdcHqtRmuODlJfGhc55tu39kcifxvSFP9qrQz9q8oUKOI1whU
         Pfjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2AtIpHdVJFaED1w9hHKS2VG/4KjcrYz0hii1P/UsXPE=;
        b=ZkKEp+bIs/bQngbw6PnQOTFGfrAH/GHzX3wkEiHpIsavS5Yp8nUtlpfug6jJKYE1fM
         4KWLQjjB/tk1taNRoJN5dxhO7ATJUbQM81GlDmScrMFsGAc4cCXehYbZNo/AaYIopsCY
         LO3HIIXKeIkPvb333lyGv1XACdix6ucjxmm2qh5jp2hXuXUrFuJloAAWpRGffT7/6+BK
         ZI4D6QNjDVCNS+ypR7iC81y5ah/7MCjf5jfIQl1+3XcMHvOcv0RjOFfA+wXVVF/VN1V2
         KZq826uZ63DQodWxTsdXjJniDefibYzOX0L5uradqri7j+gT8A3PL6rjdj/K7SPD7SH+
         tupg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWPbxsRNzncI4780tNTDzN5MfD97hpEUOdwjeK00QyJEoNY3c40
	+kHLkg1t0qw//62uanZemL4=
X-Google-Smtp-Source: APXvYqzMWzN/SCrcK3xeGNmUKLU0nqDYKq3JlahaFVYFoKjAVu/3q+u19ELw0UeuExDNdLtU7ui9Mg==
X-Received: by 2002:a17:902:6b88:: with SMTP id p8mr3932030plk.95.1565871759860;
        Thu, 15 Aug 2019 05:22:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:db53:: with SMTP id u19ls397666pjx.3.gmail; Thu, 15
 Aug 2019 05:22:39 -0700 (PDT)
X-Received: by 2002:a17:90a:c391:: with SMTP id h17mr1989091pjt.131.1565871759539;
        Thu, 15 Aug 2019 05:22:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565871759; cv=none;
        d=google.com; s=arc-20160816;
        b=ECG8Gis52B+K88bx3MmaWki7YHfOiSzqxQo4t2TtyzmHHEUqvrWuRlC8G4jo6H8SHY
         g18cAik/YgAY3xPtftqPr+LRMTdOnBKQTUGMUl9/y/revjRQUJWw7AegiA1l1hipQexj
         10C78nLQRUMrsw1O8a5ox045C31Oc0CNGgizCv4sIkhn8Iqd5yfA5/0tItdSF/Fqj7LL
         fcJIOfZzrOLT622pR0WJ8KXTq8AgDEcYUA1URZ51xyGDxlU9tCNewqtt8C7j27q3tHUW
         lAOn2I261Ib154jwA7z7vaTWjxZanEd5iVcufk7oAnG3mskq2ejbL2MHr9yzL2LC+9Ja
         kGbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=phN0K1giGpOfiWwRN85JJC0lLDnDjBrtna6THCbr6UY=;
        b=R6+68HVS7c1p7pTAcGlzlrqOxdIfTPRh3tT4Dq7cddHjQWBY6iCXpRQVdYCpYMBctC
         YHVCpJb0md8sO7M/batlRUzZX+OaPxf1ShtPKbmEZzlGzdaQ3A1+Vj7G5DhOQiFGM1nB
         5tWfaSIeG+w/Rx8Ft0kSoKB0AVmYrQuWWLqhSu/yFwk31SWm05Ae4veg4afhuwIaf9xM
         eF6JPzmflmXcgHH00fEx4iGLvW1xOSibpS5zUBJhZvUQQH/kHkmrQ7qA0Zow3Xjs1+/l
         Z4aTsp4mwHlCnhSHwhIPRbH0vIY9HZmPnaVCLIleP72rmqMRaNS/qRlvaSOYc0OaAiCr
         j2jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=D3RznPyj;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a79si13361pfa.5.2019.08.15.05.22.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Aug 2019 05:22:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 52CCD208C2;
	Thu, 15 Aug 2019 12:22:37 +0000 (UTC)
Date: Thu, 15 Aug 2019 13:22:34 +0100
From: Will Deacon <will@kernel.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Steve Capper <steve.capper@arm.com>,
	linux-arm-kernel@lists.infradead.org, crecklin@redhat.com,
	ard.biesheuvel@linaro.org, catalin.marinas@arm.com,
	bhsharma@redhat.com, maz@kernel.org, glider@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: [PATCH] arm64: fix CONFIG_KASAN_SW_TAGS && CONFIG_KASAN_INLINE
Message-ID: <20190815122234.44rcthx657atqdbe@willie-the-truck>
References: <20190807155524.5112-1-steve.capper@arm.com>
 <20190807155524.5112-4-steve.capper@arm.com>
 <20190814152017.GD51963@lakrids.cambridge.arm.com>
 <20190814155711.ldwot7ezrrqjlswc@willie-the-truck>
 <20190814160324.GE51963@lakrids.cambridge.arm.com>
 <20190815120908.kboyqfnr2fivuva4@willie-the-truck>
 <8e472cf5-21d1-be9e-9e47-ec40e35b3192@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8e472cf5-21d1-be9e-9e47-ec40e35b3192@virtuozzo.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=D3RznPyj;       spf=pass
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

On Thu, Aug 15, 2019 at 03:21:48PM +0300, Andrey Ryabinin wrote:
> On 8/15/19 3:09 PM, Will Deacon wrote:
> 
> > On Wed, Aug 14, 2019 at 05:03:24PM +0100, Mark Rutland wrote:
> >> From ecdf60051a850f817d98f84ae9011afa2311b8f1 Mon Sep 17 00:00:00 2001
> >> From: Mark Rutland <mark.rutland@arm.com>
> >> Date: Wed, 14 Aug 2019 15:31:57 +0100
> >> Subject: [PATCH] kasan/arm64: fix CONFIG_KASAN_SW_TAGS && KASAN_INLINE
> >>
> >> The generic Makefile.kasan propagates CONFIG_KASAN_SHADOW_OFFSET into
> >> KASAN_SHADOW_OFFSET, but only does so for CONFIG_KASAN_GENERIC.
> >>
> >> Since commit:
> >>
> >>   6bd1d0be0e97936d ("arm64: kasan: Switch to using KASAN_SHADOW_OFFSET")
> >>
> >> ... arm64 defines CONFIG_KASAN_SHADOW_OFFSET in Kconfig rather than
> >> defining KASAN_SHADOW_OFFSET in a Makefile. Thus, if
> >> CONFIG_KASAN_SW_TAGS && KASAN_INLINE are selected, we get build time
> >> splats due to KASAN_SHADOW_OFFSET not being set:
> >>
> >> | [mark@lakrids:~/src/linux]% usellvm 8.0.1 usekorg 8.1.0  make ARCH=arm64 CROSS_COMPILE=aarch64-linux- CC=clang
> >> | scripts/kconfig/conf  --syncconfig Kconfig
> >> |   CC      scripts/mod/empty.o
> >> | clang (LLVM option parsing): for the -hwasan-mapping-offset option: '' value invalid for uint argument!
> >> | scripts/Makefile.build:273: recipe for target 'scripts/mod/empty.o' failed
> >> | make[1]: *** [scripts/mod/empty.o] Error 1
> >> | Makefile:1123: recipe for target 'prepare0' failed
> >> | make: *** [prepare0] Error 2
> >>
> >> Let's fix this by always propagating CONFIG_KASAN_SHADOW_OFFSET into
> >> KASAN_SHADOW_OFFSET if CONFIG_KASAN is selected, moving the existing
> >> common definition of +CFLAGS_KASAN_NOSANITIZE to the top of
> >> Makefile.kasan.
> >>
> >> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
> >> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Steve Capper <steve.capper@arm.com>
> >> Cc: Will Deacon <will@kernel.org>
> >> ---
> 
> 
> Acked-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

Thanks, Andrey!

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815122234.44rcthx657atqdbe%40willie-the-truck.
