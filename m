Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNNXVOAAMGQECXYA7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id C7B0B3004D0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:05:42 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id z9sf3145760plg.19
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:05:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324341; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+zudBNp7GON6HmT42Z4mEsCgQ4b+CjNDrKgR4f797Wb9tR4tN5Ud/+CYkacwxhTYA
         SH9qzGfAckuvR+H8s7VvwLba89QcRnbSDLE+W2pUXZziF3upiu/UexQIy8vyxNwHdLuj
         +F9QiXRFwSgvKhKBqaZnKEoOzyJbtfXOkR/+XNAWF5lWwfExqvAKPvVlno5m7bp08Xxa
         1H8tvoXFjDmQvra8gUOGn1sNlJiOo4eZF2NZZDYxhppanJ+rXXaF+/WWrCoAajD6Xu0b
         I0zqBqsZWjByLmg6x//A8i9Kc/I7ECvL4SXrobZWnhrurBu3ZVmAaW8K23d5utt0OZVj
         JTmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=wU1hw8FFLyWZIiejHvMeDYaMLvbWZbhISO2/GosZ9og=;
        b=FrS3TuUkQbykszrK65j5rfxwZiG7UWOaAfkPCMAggmZv38LXx5HOB35WC9Ruu0lqFs
         1HpjTWsK54JBS/jZ4gVWa5NF08DFW+8t1REp6fWyyCyM/UCCSfEgSEQENk8Lv2qInS0w
         rTpogGMRsNCcWX56CFXkkMNpL1BxxVtbyPPiXEFx9rgq57WvxcGMRAtoK2jDuUE6AHuc
         V7Le8R1VdAfpPcfq6XB5n/enpueUowdwOcfJgh6KJhd9svfu4JwLW3rkWRWT44hPZKV6
         ClS30micqVUj2yBIEHS5GAePPt6Sh8r3IYYVqaWhLjT/KgV22kXz/74JaYvuoLrio5iJ
         W5oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wU1hw8FFLyWZIiejHvMeDYaMLvbWZbhISO2/GosZ9og=;
        b=X5nhbeISKRx+gfO8gi3ikfb7fhWFvZnfKHuAU87pnmyB4ornl71l+1mnaAiFr9aMvF
         EnAmKeDRzILorr5T/6cwq4Z4w80TxPvnSFmGnMfHgk/NdG1MXD8lTtDl2kUOkJhLVIFh
         fWq9YzmUWOGlF1FtseZaZA6CgrFYkHqTuI573heOHXVojboPNt64LkHh+iL/SWQX570j
         /XIqgrJGmX1i3Fgrr3ZAEqFQK9d/jx54xVpETQnZDHE3th+0A0RBJ6YdqujB0DcnFo23
         ke5cW1JjOJsyCGBlWmKROMSyROlnDxYQzlRbHox359RNyHKSLimyvKwngoZyZp4e4RU3
         tJPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wU1hw8FFLyWZIiejHvMeDYaMLvbWZbhISO2/GosZ9og=;
        b=Y25Gw9EJOzpZa99vlc//P8iDjiUlFAOt2d3xt+Td0+9LxEx9ztBZloEggItNHF/Cvx
         jF/Ai32WBaPZLTaLw88TeaBEwMMg+q8GoZ2XZ7LngN86D9IRfTtT4HXJrX9GXKwJZZJM
         QoNdZDBo83sumacbEssoSNnccqFV+blNa9elbk6RbBbA2BRnPFgSwep8NqIhUCikSxrl
         6tNDbVvwRxE96FRRR6ukz38cWE69caEF1JQczGjGnzzEYqGD7CSi7Pe856Lq6VvwNLGc
         Gae2xscfXZAivvcmmOIX3jGiXaNxa2tG/Zjp0BfoeVo/TlHEnPm2pMHLRB7q1gb8NRVX
         OGYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZEgDFdWKxUvJH8/vGiaOL/rym6M5BTqJtZCh3Pul6ih1y+4Iv
	5IhTwucol3sckdWuXO7Sx58=
X-Google-Smtp-Source: ABdhPJwUK8PTcPqlgniGb5RmAE3NKQ2M47bXRIlY/E7JvEkSDdTpu1XcpvjWRitJG423wa2IodTUDA==
X-Received: by 2002:a63:3d0f:: with SMTP id k15mr3579052pga.160.1611324341558;
        Fri, 22 Jan 2021 06:05:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls3257317pjz.1.canary-gmail;
 Fri, 22 Jan 2021 06:05:41 -0800 (PST)
X-Received: by 2002:a17:90a:aa8d:: with SMTP id l13mr972535pjq.0.1611324340982;
        Fri, 22 Jan 2021 06:05:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324340; cv=none;
        d=google.com; s=arc-20160816;
        b=a6u7GphytxhEwgDxNYxNYCTM1PE5irOifqHJohu1ufj0GenDnv/48a57fcrq+MAeIX
         crsDB4VCeUOlUeO6WOF1NMNHj9saIilKs7GZbtMbuOILxcGq+p046aUC0fkY6rrAPbvo
         oeC/ydi0XFxNeCMhSqaZULpcFIy3whsZSuGKTw1NXHXYTO3BUaDlUFHuOouIbq/0Gx/R
         /L3dQgq1/FE6RnNXJI2Mnx/jbaithwsf9lGmm7XxwCEprjLPvy/79a+GxsFAu3i/L/OA
         TiPXx5YXwentdQmEcQcAbxKpVv0Zx7rFXMphxI3B4HzqPRQxLWUYd7935XkSngHiAZQ/
         ULEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=I9bav2i5LEghObbMLnT0dciRPxc2CEol8j4GVQe85FI=;
        b=VfUonznj2oDqVBE1VT/RUuOJN5ZeqM+4mua/0Mbr++CTtuSQ8l5jmhHLkMlsgdp1C3
         zAr5Y+j254YSAy0vCBG2Xx9GEBeegC52uSDDxu+QIAb+XBIYGIoE2VEMreXOPJ4aoS5w
         A/I1M4FwHbGYde4Q2Xcgvqxgr5YFJ1kehcXnOSA+dc0pH/K3Gkl+zWTOFwlInt4EVuUg
         xOLRVQP41nvrGnJB1NZmjVh6UiwCnQv9vfcEfZcnwMTstE3Ibx6E+YCJ4F7Pb/HZLk5Y
         2/Oie+Tgh+fKr91GTSMeokGq2atrWKdC0/y8RWx2GXGRBmNDluUyWZOKaWODl93U3Bgq
         fOHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j11si536887pgm.4.2021.01.22.06.05.40
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:05:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6C5B211B3;
	Fri, 22 Jan 2021 06:05:40 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7A90C3F66E;
	Fri, 22 Jan 2021 06:05:38 -0800 (PST)
Subject: Re: [PATCH v6 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
To: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210122135955.30237-1-vincenzo.frascino@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <36b73b67-178b-4871-16ce-e35e02f2fa67@arm.com>
Date: Fri, 22 Jan 2021 14:09:29 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210122135955.30237-1-vincenzo.frascino@arm.com>
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

On 1/22/21 1:59 PM, Vincenzo Frascino wrote:
> This patchset implements the asynchronous mode support for ARMv8.5-A
> Memory Tagging Extension (MTE), which is a debugging feature that allows
> to detect with the help of the architecture the C and C++ programmatic
> memory errors like buffer overflow, use-after-free, use-after-return, etc.
> 
> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> subset of its address space that is multiple of a 16 bytes granule. MTE
> is based on a lock-key mechanism where the lock is the tag associated to
> the physical memory and the key is the tag associated to the virtual
> address.
> When MTE is enabled and tags are set for ranges of address space of a task,
> the PE will compare the tag related to the physical memory with the tag
> related to the virtual address (tag check operation). Access to the memory
> is granted only if the two tags match. In case of mismatch the PE will raise
> an exception.
> 
> The exception can be handled synchronously or asynchronously. When the
> asynchronous mode is enabled:
>   - Upon fault the PE updates the TFSR_EL1 register.
>   - The kernel detects the change during one of the following:
>     - Context switching
>     - Return to user/EL0
>     - Kernel entry from EL1
>     - Kernel exit to EL1
>   - If the register has been updated by the PE the kernel clears it and
>     reports the error.
> 
> The series is based on linux-next/akpm.
> 
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
> 
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm

Please ignore this series, I missed a fix. I will re-post it shortly. Sorry for
the inconvenience.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/36b73b67-178b-4871-16ce-e35e02f2fa67%40arm.com.
