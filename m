Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6GL277QKGQE5QDS36A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C8202EC139
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 17:31:54 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id d187sf4993675ybc.6
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 08:31:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609950713; cv=pass;
        d=google.com; s=arc-20160816;
        b=OG62MOD3fRLRdQiWZvZqCsSxOAuJcS1FDWBMGXGJejT9ANd6TPK8okoLsvbSRZkXrp
         M7+wNRC9jyqneEWmyhUzj9NSJDuJ1EuRsKSxQ78brkyhniFZUkszbRuwt4RCsh+izV8A
         ZVaHHLclYHeR7PTOJnKG7PoQtsoHG5G2AhR4Y/5A+4XS5GhC93+e7seAeDAtBB3yDpc4
         nnxdjvfNqUvalYjUskay+O7T8hxYzM0GdxRnSLOHMes+pmUzQ86wpey/xTM67OVx1RCq
         pDdB7glMn9EA5E3H/vRmKNerbZhYISyYGv+qi/SHgHDwYmOFCftH40Pc005pVcpPL2Zn
         M3fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=hTsD4vUTDxuTu+tKLtmKG8GFeLOhHOhf5BFjso9nDCM=;
        b=mcXf8bg3ahf7EVG7XadbmbcMXAyPY8cep6VMVWoC3QUJn8v2lU0QGgWuETu/pvd1iH
         vPOnH3u2TWpzLMSJ94IklbOx6Ju7cpuPi2P0KW/Xj0DbGpHcL1MvdyVXZIbAoOGZ+G5J
         Rfz5aT++hnjTEDGPSOsLv9WU7QuVZI1Kv9mJMalY0hM+VYigflbraTPKbdKnZ3JT4fHT
         5ryCaof8TpO3za7RM8+B9URdapmrUImg+TQDyEAUhg8MRoiJYkhTNeT03hQ+iIfraQnn
         WciMh+vPlIVKChT3wjR/t2q3em9EVJzhTeyX2QhqUWY8av23BxI0QvkKmfYkIS9Qcx4y
         DCWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hTsD4vUTDxuTu+tKLtmKG8GFeLOhHOhf5BFjso9nDCM=;
        b=tJ8f6NxsQR7t+LGOnWCafzFbs+4rygOCpOGCVHgLiCQOpYY24FeXbS7GXZ8fYVvHf1
         zdY89l2e3HqPl6g1oaouXrVKZCD3t5XAaoSQOylUksJLpGhjDGbcMlIn8A6kCRlh+rcm
         Z4mwNK93k+lvTExDyUa3eFDe4B7rWisiShw/2U6RDqC4rFIkKhjoeVO5hUu3gnXTAUeg
         /NV9BCe+0uQ/tkINkKpN5lsh/IiChnAnkYMucvPkPUDIk+IhDnWSLsYphjTcY6HVH0Fe
         Pe6emzBT5TecdYQijVVMfZf74Dm9CHOjs7A9p4eyCpGJlbBk26GKNoIcaqrW1ubl2Z7f
         mt0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hTsD4vUTDxuTu+tKLtmKG8GFeLOhHOhf5BFjso9nDCM=;
        b=q2lkuzRolwoQJoGILlXuzQeVXhBMTTG3SfSMHdBZwRqNPU10DjNo3ruu5l8v1LR8h/
         ueGC3HMBdt9UlEAG47KX6fRDr8hTjQwOG5mYjO1+xsKsfXDTIoR+lOwaEL+dNmmHonmf
         bvVfFfqzHNQc43vuRhnlON76ErBapDiG63pXzN10i0dI8v1sNcMoA50+2CzqPFiwupwB
         qbdZsMl9jHNqrrefOXyqY0MYO3ijJ6Xq/B3OHa+UK9ECqbtX3NzI5n0qyLOY/ffo/Blx
         MVOp09GgNdaRDHPPEiqWzcghciL6/McrJ7CnWB0GIaCjwMPgBTpOa7NSmlEGPjZUzYCt
         dj1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IFsfScn5To/FE5nGq8P666bUM2L1d3ngBOWBmYCC9wRtkhG8T
	CmPLjy7mOk05qvr5rS9Ly2Y=
X-Google-Smtp-Source: ABdhPJzybQDncBFQ+1+oysEJf95933lMjiv7dndENWlKvC9gunSgVxkutBv6+QT97VVWzRaWr1gzzA==
X-Received: by 2002:a25:d913:: with SMTP id q19mr7751333ybg.180.1609950712997;
        Wed, 06 Jan 2021 08:31:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c594:: with SMTP id v142ls2065740ybe.9.gmail; Wed, 06
 Jan 2021 08:31:52 -0800 (PST)
X-Received: by 2002:a25:3801:: with SMTP id f1mr7323808yba.321.1609950712530;
        Wed, 06 Jan 2021 08:31:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609950712; cv=none;
        d=google.com; s=arc-20160816;
        b=M0JCO2KMLjS5ck/bJsUpQHjw5bk4onZQcaM34F65x66wkLMhAyaI9rwiq5N+I80Gx8
         c1IOsBKKi4OfDYmvADyNDehozjC3BEM9sONmMLAEhv3/uem5YGewzdFwp8jNFYhtr8Sc
         WpoktP1S3R6FizwP3f8KHkdNu3Pf25Nwt83pe15mafmJ+d7x7PUU54KhxSDMsxR7dzd2
         mH/W9R9RO2TChcXTEcD3Md+8gYk4nC/O4y3g1MLbR09mO1PTNke5zXC4INMgz6DM6zeg
         8Rn6VNPUzofo6Izr19s7p3Ot1dtRTHVucpFsZGyrAxTPHIpZE27zEeV846pX2AdYypOU
         Na6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=KRpFGt4pSdhgLV2t4iBOqYfI1qxy7K0J8VbcidxI6Ns=;
        b=iIDBOfpn/fYbV+SfcvYa338q5kWE+AhUZ/ZzzkXjGxpiGbd/E6h8jYbqG9yyDRjbQY
         AkC5osJ7JvC4dcB8A/uZVGVy+Q8M3WqF9yL3C0fhcXgrwqi64+T8izlyUgsh/nbxAPDY
         zwIOTW5j7SRz1QHNLulEkP0SdnIjrPtDbP45fAQigHPDCMo5jiW3Qa4C35nGgWogN3ND
         Y82EBLOU8k0nhBDiNanxk/xgX8Jg+dZzYHFJZQeliaAMGJkno6YWVIUDJQbpbB4Jy/2h
         e6o8ko77VTHzBgT2JzlneB6AEcD4BSo/PZSlMtbTTUfTCybLw3uEEsz6nEc5jbvso5Vv
         4i1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i70si228434ybg.1.2021.01.06.08.31.52
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 08:31:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 11169D6E;
	Wed,  6 Jan 2021 08:31:52 -0800 (PST)
Received: from [10.37.8.33] (unknown [10.37.8.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EC2883F719;
	Wed,  6 Jan 2021 08:31:49 -0800 (PST)
Subject: Re: [PATCH 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
To: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Will Deacon <will@kernel.org>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <9a78cd4f-838d-0410-62fa-16e4ab921681@arm.com>
Date: Wed, 6 Jan 2021 16:35:29 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210106115519.32222-1-vincenzo.frascino@arm.com>
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


On 1/6/21 11:55 AM, Vincenzo Frascino wrote:
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
> The series contains as well an optimization to mte_assign_mem_tag_range().
> 
> The series is based on linux 5.11-rc2.
> 
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
> 
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will.deacon@arm.com>

Will is not in arm anymore :( Sorry Will... I will fix this in v2.

> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Evgenii Stepanov <eugenis@google.com>
> Cc: Branislav Rankov <Branislav.Rankov@arm.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Vincenzo Frascino (4):
>   kasan, arm64: Add KASAN light mode
>   arm64: mte: Add asynchronous mode support
>   arm64: mte: Enable async tag check fault
>   arm64: mte: Optimize mte_assign_mem_tag_range()
> 
>  arch/arm64/include/asm/memory.h    |  2 +-
>  arch/arm64/include/asm/mte-kasan.h |  5 ++-
>  arch/arm64/include/asm/mte.h       | 27 +++++++++++-
>  arch/arm64/kernel/entry-common.c   |  6 +++
>  arch/arm64/kernel/mte.c            | 67 ++++++++++++++++++++++++++++--
>  arch/arm64/lib/mte.S               | 15 -------
>  include/linux/kasan.h              |  1 +
>  include/linux/kasan_def.h          | 39 +++++++++++++++++
>  mm/kasan/hw_tags.c                 | 24 ++---------
>  mm/kasan/kasan.h                   |  2 +-
>  10 files changed, 145 insertions(+), 43 deletions(-)
>  create mode 100644 include/linux/kasan_def.h
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9a78cd4f-838d-0410-62fa-16e4ab921681%40arm.com.
