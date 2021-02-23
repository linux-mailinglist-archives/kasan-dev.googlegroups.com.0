Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCPF2OAQMGQE5PYBMWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 63A23322A65
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 13:18:18 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id w10sf9894366plg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 04:18:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614082697; cv=pass;
        d=google.com; s=arc-20160816;
        b=xehlw2E9bFeAZjTi4lE0Dk64x+9y4RIDYKou2IwJFMzM13BmUBXgGKRBOGrF7OgzmB
         dEybrpJk5YX8hFr8X+Xr0S2E5VBlJm1DiYn1Dvp7gG0j0ViJObH6hgZ+H5SRemzNw4y/
         5JICha2jM+450rpkOxHwLuTliJ8NPSu/ZWb1OvCVwpPnlmqTu5jRKERWYASOPMJqIhK8
         RWQtYCNcO6aEYCh8DVhGAkhOGk3ij+DRoLOlKDoyE6+DDSwVTWtpm3hl/ZhTS5NXg2VM
         pk+luKB6+4jVQj7DLOJw5IijbNTs+lZ92U7ZkaCO5FS7CyuSkGrFEgCWxG+AZ41CdZ0Y
         8I+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=pyewZzcLGmwwX6MwwUxTZTrn3Uwy/DIdoZayQ4dwhnc=;
        b=HXj9VorEfhoYkPF+iNnUi7MTRD0djXzqwuC4XEfNSFg2rj82Ekfg6h5ZQoVvoW85jK
         tvrojFRKRQAt9NKcInky3X/FYb8atXYZHXrscwq4Xs+wKUPOPKHf22YKAF5baBGJJADI
         +SSvp0aYZqWZfN0vV98QOpE0oVbxR7ySiKSoXtAfImV/SQP6yVwcFHz5SUyseXtGhNW8
         5mVXAMIx4xpr/nSnM9OC376PtyI11Y++qkpAqgdVSez89zzg7ayNJpCZAtwNKOZV9gi9
         hOGy/F95mWSmnj1RUcTuAEPsBldE8qcrcuIpdy2S71c3rj5U33kuct1AO6HATGwBH+io
         +lvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pyewZzcLGmwwX6MwwUxTZTrn3Uwy/DIdoZayQ4dwhnc=;
        b=LpXopSBLF3wgh8hbph6J5EqMpdIukNn3SjYnKR3XiWpVowLFOGW+HJ1SU9yvNtsNzI
         9wEjc5BLqRZ3tLilyitRiWfYq6DIhPj0TkseAb5zNFRowKFImDH6LAllwF3Bf15ZUfBi
         R9XgnTjO+9YVCc7hnK87xHAz+rLTAywJzkg50Bhj34/HhzyLmoFgr/eSD3XTpCN1VyhN
         2Jm0cDiYLlaWvGvTASMvnt7DWbNO6pSt/kj5xoD1JmYzYfygJpKYAllAGTFxDjrGThvR
         4TtyWefaa1vXBNC1wVbKEsKPRtiHYbBx8ql6xfaskfN59Us/f77x2B3tC/2UbOLC4kl8
         BruA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pyewZzcLGmwwX6MwwUxTZTrn3Uwy/DIdoZayQ4dwhnc=;
        b=ZRFc5RqqDo0l4VFhmH8IcvW54BEvC8Z0uDbJ5t4Xv+YPm2XtXlvQt/Ogr12t8hF4I2
         4EKhJEp6ZmuB9iO+UbJzzJM2qUw2JW5kxsY6yEIvFXAV9Uht6c+p4FHbORRPIhjLTahq
         uTsSc68MqWmhWXC3j2X0CwLAvZh72d8LPqaMnR137sWFzNbmQSvEJgDBbDmzBN1MgB/4
         NmQZvuEfi6bVu7nHpcOBaxsDAu+QPjjmSWMhvsEOzI4JK2zcNv8t3YVuZ/LXmRthV+L0
         +mOYzHacAnJUMIrFarJierzk/eDnrFrxWVznKWDlj7KXZLMwUzvUv5CE60dhr3uqSgsC
         wG9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Eud7yLAY8yFEjNbI/p0DXQqBHX7qTYlSDQeFB55fgw8aU/hKt
	Nwx4nv6q8lB+8nzAoewGp9A=
X-Google-Smtp-Source: ABdhPJxAltV/ULOE1Pl1QcTbS/VqFw8E3Gt43/WocGtd5dNr+sVGyH8S91tDXePQQISDFXWXmCMycQ==
X-Received: by 2002:a17:90a:ae14:: with SMTP id t20mr8062883pjq.90.1614082697158;
        Tue, 23 Feb 2021 04:18:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls7336186pgu.6.gmail; Tue, 23 Feb
 2021 04:18:16 -0800 (PST)
X-Received: by 2002:a63:7d6:: with SMTP id 205mr23979977pgh.256.1614082696502;
        Tue, 23 Feb 2021 04:18:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614082696; cv=none;
        d=google.com; s=arc-20160816;
        b=sUlLnttPekH8tagV3hXsWUAakfROm9Z2MWkFAXittE+aJDkDlVyXAT+MosYXWQk9vD
         EiYjs5hOG0BowLTFtQ9iR35F+hJ5yBQhZ2f1KPK9iHZzqkcg+axGAowO9VZAY/X8EpQ+
         lBUmn2MOjMSYacZHrqRpTRUCmvMiKApPyM7pOUBHF/CUc7o+E7cQB69/BtM3ImdYK9oP
         zFuj8L1G8EMDKEYrD3DOqRRZb6V9n8ZsXKGPlStWqf0JMU8/thGnfSezuSoE2nRrNuSJ
         HhrfNg88oS+ZTiUSCGrrZKIO0wworB9aOkfluEcyiOOx1lKO+QS4gNyfNevmP+aSUn7Z
         aBFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=iTQvOA6RIK/62AjpK/6mpJWPQkVh3Hcfm2XaqHfpnuI=;
        b=IMYunBOzZsYKL4V+QpXkFBbYIQsY86xAg61N5sYYIAkgQim22+kOJJ0CkmsjV073a/
         8DaQgwJUr5D8vUy7FDdUPnD0eB5wiOeKbK4uTShmmC1fpjyK26o9tUXAfz7m3aTBOUdx
         VdiJqlfPptRuEB3Brk30AFA5rQDWc9jU5J1ecs3l8kgjCO1u60ETW3AYY/b3BIMtcCuJ
         wAsZYCDH1hhyzFPx8FdfCFKI4szzmhMQsqzH3+UWOaStV0hXVgjMjiVHTRvcDkpRRpNk
         ks+cXw3dshpm93kM0dPlQLVselODxJVGQHnBy3QUJWIMpzdJW2IjoKa+Sq7oq5/qcqcn
         creQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f11si942981plo.4.2021.02.23.04.18.16
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Feb 2021 04:18:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9676831B;
	Tue, 23 Feb 2021 04:18:15 -0800 (PST)
Received: from [10.37.8.9] (unknown [10.37.8.9])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C54B63F70D;
	Tue, 23 Feb 2021 04:18:12 -0800 (PST)
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
 <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
 <20210223120530.GA20769@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6865788c-7e63-fbd7-bb88-ba01eafb2f63@arm.com>
Date: Tue, 23 Feb 2021 12:22:27 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210223120530.GA20769@arm.com>
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


On 2/23/21 12:05 PM, Catalin Marinas wrote:
>> I totally agree on this point. In the case of runtime switching we might need
>> the rethink completely the strategy and depends a lot on what we want to allow
>> and what not. For the kernel I imagine we will need to expose something in sysfs
>> that affects all the cores and then maybe stop_machine() to propagate it to all
>> the cores. Do you think having some of the cores running in sync mode and some
>> in async is a viable solution?
> stop_machine() is an option indeed. I think it's still possible to run
> some cores in async while others in sync but the static key here would
> only be toggled when no async CPUs are left.
> 

In such a case we might need to track the state based on cpuid() and have a mask
that tells us when cpus are all sync.
Not as expensive as stop_machine() but still requires a valid use case to be
introduced according to me.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6865788c-7e63-fbd7-bb88-ba01eafb2f63%40arm.com.
