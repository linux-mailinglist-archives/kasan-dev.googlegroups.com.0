Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSMY2GAAMGQEUG7XHJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D2FDE308BFB
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 18:56:26 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id e62sf7112789yba.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:56:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611942986; cv=pass;
        d=google.com; s=arc-20160816;
        b=em6Da8IFIrgUownH3jGXcOs+qIcRlqweCCC/23a9u79SxMYhkzvXbnBvmkOkRucEcj
         o4+lVdcR8Wb+gJrxwk+N2ozzphlBb2pdr463v5kZGWFh8PqVI3iUoLDpsDjj+Eo+611h
         miXcBAxwvnOaX5xTgn1onDT/127CrdflACZONAhsacwOUDQKm7rIYiq9RvGFcRqnghPZ
         iaQkaAe/jUD6EMQIOXeCdpmd9wYfifNEnwHcmHckFfQOkO2k2L5e1U0SGnsS8wO7pZln
         H0yW/pSGtt68tE6Y21ZdIMqavbo4WvVcoLhUC575efDZAWDh6jR/M83FusuAmubvWLq8
         UkQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=qaRbp0bKx0uDDxZsgv+UeoqWPK6nBlz6Jnwt/FeqZWo=;
        b=qW1myPsf5fYg0qwEHzmhryDgasCuv2NwvJDO30UXsQKe8Jb49yvVDS4oZ1qCW/syGR
         AXILg+09ye2STwwBAy01XK9GcpnEiW7jn/RSZyVeXn0zBWVbHWHB6lUpRrn/O9Ben/ev
         9/M6kVinTgGT745iyy77GGYRxceLxyWKRi/9h3CfOsD6j1DiqsI4+vKeYlPyEirJcr/R
         zTngOgL0X2oZB8DENBBNxp8P4lf5JtMMgR5YePMO4Q/Ykfa4CWc2SLxJMorim7sgNY+y
         O7lacd5LMOrRhH+2OuKajGM4eYB+wIssfDPWs1hJe4K4MntVdR0+7YaWADdl0enk5IMI
         z2sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qaRbp0bKx0uDDxZsgv+UeoqWPK6nBlz6Jnwt/FeqZWo=;
        b=nwijJiBUFjmJeej0GOwOz64zyPTyxPS1mrAGitytkoGBgpsewxPZX9b10xRPReaGsG
         9uVRgpvKF7wVOePANjBJ2PD4hCWr9dZGoN9B9IMyiIjiIxSXI3WudziEa9winBvk136o
         lK1UpMX4lbzujIEIe3ClEYIjxurfoZJK6/sjg56syN3EbcO1udiRqa0wvsqqAmjoSA/U
         vbMEv83Ay1DPAqkjbfiVJekz388x9paAsdbhCQxTFLTe4j190lhen9F79jJ0HFE2gxx0
         L9u4rkJ0+OfqFkKyu+LRz+VRXfpoY91TRt1sKb8EMTwGNeCYspb2LzY6iGFXj84mObMP
         oOZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qaRbp0bKx0uDDxZsgv+UeoqWPK6nBlz6Jnwt/FeqZWo=;
        b=YmT0whOy0Yenb73U+L/lhAHhPuJhEaR5LlZ0J++jZNggtCDwf8StTv/EcSA8PLsHZ0
         Ajg/weexNoXVziircNnBZB3KixzgHMkaDQILrpn32zwmf7SvCZAA4tj5ImfDG3IGeWOP
         VxZr4Wm1OmLj5/b+1sdU79TzWM5gp88NocQL6xt7FYIfa9qF/+ZbWwSdp3ppBJDfsKtG
         SPa8ECPZvc7nwalm/bZmDtr8dYNcu4UZXxdBV/DGLXy8Yn/MI8+cq37jdZ3y8Yhmmn2d
         1eZmNug1rvasGZQwIUVQNlZEPOLqQeIKRMIB9ZE50U7U7+fPVoWkQ+CiHAm6ZOCINrhY
         qI2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nzRKoPWTpbe5eWcbyMZidQjUti6Y8+mBIfRHXV4inCb8KmAyq
	bHJ/Lss4nDma7cxsl77CROo=
X-Google-Smtp-Source: ABdhPJyy6h0O70jCQp1lRXH1cjPolhuOLfD/adxP1W6FgY1XiPkxtNfgjjPDQF1Ar2tL3SO5L/irAQ==
X-Received: by 2002:a25:3cc3:: with SMTP id j186mr7894154yba.344.1611942985963;
        Fri, 29 Jan 2021 09:56:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d14b:: with SMTP id i72ls747287ybg.11.gmail; Fri, 29 Jan
 2021 09:56:25 -0800 (PST)
X-Received: by 2002:a25:7614:: with SMTP id r20mr7221793ybc.364.1611942985598;
        Fri, 29 Jan 2021 09:56:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611942985; cv=none;
        d=google.com; s=arc-20160816;
        b=KXDQwP//tuCYvL+65EG3CZdnX2syHvhzND9Y9Jm6c25DMvYoJGh7n0iz6vt0TqZS6n
         P+X+WYMDHkJ4DrlsqLWy/Cwd4xU7G8E7SJPLEAETeAqyForJZ+YApYu7QnnUOps+X07Z
         o3Wu/mB4af8o2KFkKskNOSEJqdRj2un8nB+T8zWftYYlBgu/4KSl/HdWvIes+2Ekm+vq
         qTN2/JPgvqLbqMiCWpXGOS3m2rabS4FgFqhYggkX9Fe47j6O3ygB69BzRCwWAkQZ5yUb
         kaFFNDg+YlptyIoIYq6EXOicHXTfm4ES8rt9e4j29jw9JVL+erWCxImLILsgOG7+igg6
         9A8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=uNq+S5hM/fPqgR658lMJLYy9ATqGm7SczvMo0jkIMLY=;
        b=fLpp/+AVY0FBp5JUBOd4Z+rg2GIEeV3he0+c3VoV21O9dDABMLR8Lzx3iBGJLalT4o
         NOiorHPxBAo5hy8DSRrpTM/34ZZ+pqSfP1hZ0DoHX/3XT1pDekH2y/rpFe3GflbpYqfu
         wAzerF53FzxFQvw8qwhemkwmZF8O0IRh/TAbCyfj3wdHoTZ8mBnvqTFxZ2xxU4epRdxn
         TiFRzAGtrVcSeYsXk7IhRmfncsiR+YOdKFPY+iOaXO9jDt2rE8kIvzaAFDhvbPPbC8Qp
         pufoChfWhjTStWwdqkeiMnXaEuHL5hWbbnQpqUinmqX+eRMNvQ4O7nfO0Orrnb+dsmbF
         Y34Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b16si328196ybq.0.2021.01.29.09.56.25
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 09:56:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EADE413A1;
	Fri, 29 Jan 2021 09:56:24 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6F73F3F885;
	Fri, 29 Jan 2021 09:56:22 -0800 (PST)
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com>
 <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <e5582f87-2987-a258-350f-1fac61822657@arm.com>
Date: Fri, 29 Jan 2021 18:00:17 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 1/29/21 5:40 PM, Andrey Konovalov wrote:
> I suggest to call end_report(&flags, 0) here and check addr !=0 in
> end_report() before calling trace_error_report_end().
> 

Probably this is better as:

if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))

Because that condition passes always addr == 0.

What do you think?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e5582f87-2987-a258-350f-1fac61822657%40arm.com.
