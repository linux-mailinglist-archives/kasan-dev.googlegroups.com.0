Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBVHQ6WAAMGQEM76YGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 20F1F310E33
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 17:54:45 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id 22sf5677345qty.14
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 08:54:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612544084; cv=pass;
        d=google.com; s=arc-20160816;
        b=jn/hARNuaU+DW+vMDmxSdV19yaKVLlE4CuIt5QErdDMaa7MTyBK/wwAMSMx2Y/808m
         Ii3Ef09cdXwyPq1TcSrFguebEdYKPRizUfVpHRv3sl3NWBn0vcXkhIxmTHOmSSubt1aJ
         53lO9xYJXXtKb9n854TvKGKZenv2AlNrB2EKWZ9kIolw517heL6cMjl6C6o1qT5/+Mck
         XUIZBM1d2bvR/yws5lHwpW+5wWpcw1OQYHe0ZZWOe06vcFP+16bZvSsZbudd2VfTOMcP
         c/bI3giExmY3zFXpYw+Ux1654CtmvgckogWGRqhWbUiF0s7Hd3pMpO1EW/RtM/tvObXQ
         FOFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=kzhaaO41tRAEvtWPc3xPoLy05riOaPbj0jYY8j6EdL0=;
        b=oQM3BUu14Fs4wCKxWtykyxU0bDibcMtmg+S1TDM9duX/Qoott0AMfvSdqS6TCUtLN+
         gNKT2oL3+lvCnxnK2aXgjTiO5etj3kGUqsjd6yC50hGDyRadI9I6daSaUqC8fehFhzs9
         Lh5dFhRQfd1+yb6qQoUyRIlnhQQC3A2UvEoST9dPEtuCW+rMfDbIxw0y2lvcVUmeIlKV
         47fcN1rGRVdb1SO3Ffbfr2jvyMguOYK7ehZiLmMczuUL9J5dgGlzYBHI8L0zIa9055hs
         Ww81KOCQTSXb3bzitF78PDoZP0T6AVFrb8hrAYTPvZmdRkkJZv1wykL8mRyxxdkuPejJ
         V7lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kzhaaO41tRAEvtWPc3xPoLy05riOaPbj0jYY8j6EdL0=;
        b=neGaE7noJuwtnCm6xuNfykHi111Pfjt3K1QYC6SYcl9tFBWrnuDkA/CeKYBPA6E1m2
         9CFS1G4IRq6AiQ48qAYXuJgEbId2znukL1ll1/C/QgQJ+yf1yIm6DuQdgh9Xrb8d3EB5
         tlEym8hlFv2+HBDx73HqRlF/htCegv0oDvR6pojpGVclzRglAKtC92ZQHxOzDm/2CA9D
         dZ1SBCu2LPSwavYgb7g8umrF1w6IaZCAnbUJJwvbQbHs/+ZvVIEwgkll9RtRhjS3VdrE
         IoqaBPhdyEjM+KLhWWxCj/2UM/Vmh+sqmIvLRjicf1kSJJgCQiiyqabbyk9brbGInvhO
         Qk8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kzhaaO41tRAEvtWPc3xPoLy05riOaPbj0jYY8j6EdL0=;
        b=JkdGPi7sdVFI7N8nGDMCMELdHQVoj5Vgb8UvZ7ozn9wRg4QRdK2gkHsUW970z8/YW+
         dnosEHMCeshsLcxhmRSbqsnOqf0RobRsd5OM7gVZohMag5/nbl3Tkfi5pdCCPpvzBrtX
         XtqPcXrys1RASmQxEy7ELQTVNYAjPffezrGcD0D58bml4kKg8zciX2/Ojj/89NHZC8XX
         mvEMSJY5gPW/0WDAUgCZsPhN4HE/yAWHR4xQjHgXS2pVZHPi1+yMeD/nooqT445J12qp
         iRuHadxDoKfgr/d+1qJiLelo/OCxoPBsZkp/Z/OHpcvmGfaTZ5tSkfbT9e71cveIhaTy
         H9sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Z8An7IU5zgSqU9cKWi1WHampI35hMrFLg0QveuCS69xx9UjWM
	BmjGBZX4lDlfjI7XWgB0/vA=
X-Google-Smtp-Source: ABdhPJzJnQdaZdwZwI0mJ3FXPDz4kUfCpvcHNPwZwD2Qrrf0LsKkVhA3XFuEFeBH7rM7d//aWCz7uw==
X-Received: by 2002:a05:622a:4cc:: with SMTP id q12mr5052918qtx.277.1612544084169;
        Fri, 05 Feb 2021 08:54:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f402:: with SMTP id y2ls62023qkl.7.gmail; Fri, 05 Feb
 2021 08:54:43 -0800 (PST)
X-Received: by 2002:a37:73c3:: with SMTP id o186mr4952159qkc.194.1612544083811;
        Fri, 05 Feb 2021 08:54:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612544083; cv=none;
        d=google.com; s=arc-20160816;
        b=sFaKZK7c7Cgcwp6Jd1FVgGXFajA3y4ee8X8OHf47B0GuGNVVki4B7evjs9ZcCkDXov
         3BA6uab2x1DGlPPz9fSpMj5xN73xv1LnVmSyKI5WdYOg1AU19z7RpVToyKjmv/rVm4M5
         Pbg+LDObFQaDTMZRuRDx15TMlzW7pfWnWpucyZBL6ISWxNgxXGuiKn5VI/Ykth8wYeVd
         0oPPr05/AG7LtlZnDLcl8b6HQI6o6mQbBpYG5KpcMsRzGDw4KGh4LTded6YHj5jaMFIF
         CngTGA/OTXPro1Vq+STzzOGPvlSs6QLcWn4m9ZYaSd6IELfwW+1/j2QsyPpeisbftBU3
         gTGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Ul39ircbUyXKXpcQsh985jyF86FxdTF+WusP9eEabIk=;
        b=zYc3TQ9DZ6lyRgig3/YWYtZSEc7qj9TgD8dAuEs/gT0Onzy/9VNLIE2j7u/ZsB+G0d
         ID1UBbk+bMKT+mRmvNSZux4LdQaFahv4SHNseEwT949DFZyuEzghmUqqIdPJ2UvpJM+l
         vitD2kn8rW8xxMZhzSFz3Q7BfFmkrktszx5dM3PLm0inQuMwFt+YD25tefvDW+nZ4c7s
         TWPtaaWcrNrlc4ENrqeJP9gyrvWnwfoHKFlNgCMCQUwcJFHzn/O0KHgyAVHBHZr0U0+T
         wnY9PoCfZ/FUtDodpyAFQNBt4WFo86dV5bvzTtPiS7wXbfaxaV2PB4xZzLAF0+k9PLqf
         BQYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a26si585561qkl.1.2021.02.05.08.54.43
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Feb 2021 08:54:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 081A9106F;
	Fri,  5 Feb 2021 08:54:43 -0800 (PST)
Received: from [10.37.8.15] (unknown [10.37.8.15])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3202E3F718;
	Fri,  5 Feb 2021 08:54:41 -0800 (PST)
Subject: Re: [PATCH v11 0/5] arm64: ARMv8.5-A: MTE: Add async mode support
To: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1477c6da-a0fe-903c-4257-84c45908c836@arm.com>
Date: Fri, 5 Feb 2021 16:58:42 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210130165225.54047-1-vincenzo.frascino@arm.com>
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

On 1/30/21 4:52 PM, Vincenzo Frascino wrote:
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

We are suspecting an issue with with the kernel access nofault functions
triggering async faults that impacts Android init process.
Please do not merge this series until this is sorted.

> To simplify the testing a tree with the new patches on top has been made
> available at [1].
> 
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm
> 
> Changes:
> --------
> v11:
>   - Added patch that disables KUNIT tests in async mode
> v10:
>   - Rebase on the latest linux-next/akpm
>   - Address review comments.
> v9:
>   - Rebase on the latest linux-next/akpm
>   - Address review comments.
> v8:
>   - Address review comments.
> v7:
>   - Fix a warning reported by kernel test robot. This
>     time for real.
> v6:
>   - Drop patches that forbid KASAN KUNIT tests when async
>     mode is enabled.
>   - Fix a warning reported by kernel test robot.
>   - Address review comments.
> v5:
>   - Rebase the series on linux-next/akpm.
>   - Forbid execution for KASAN KUNIT tests when async
>     mode is enabled.
>   - Dropped patch to inline mte_assign_mem_tag_range().
>   - Address review comments.
> v4:
>   - Added support for kasan.mode (sync/async) kernel
>     command line parameter.
>   - Addressed review comments.
> v3:
>   - Exposed kasan_hw_tags_mode to convert the internal
>     KASAN represenetation.
>   - Added dsb() for kernel exit paths in arm64.
>   - Addressed review comments.
> v2:
>   - Fixed a compilation issue reported by krobot.
>   - General cleanup.
> 
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Evgenii Stepanov <eugenis@google.com>
> Cc: Branislav Rankov <Branislav.Rankov@arm.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Andrey Konovalov (1):
>   kasan: don't run tests in async mode
> 
> Vincenzo Frascino (4):
>   arm64: mte: Add asynchronous mode support
>   kasan: Add KASAN mode kernel parameter
>   kasan: Add report for async mode
>   arm64: mte: Enable async tag check fault
> 
>  Documentation/dev-tools/kasan.rst  |  9 +++++
>  arch/arm64/include/asm/memory.h    |  3 +-
>  arch/arm64/include/asm/mte-kasan.h |  9 ++++-
>  arch/arm64/include/asm/mte.h       | 32 ++++++++++++++++
>  arch/arm64/kernel/entry-common.c   |  6 +++
>  arch/arm64/kernel/mte.c            | 60 +++++++++++++++++++++++++++++-
>  include/linux/kasan.h              |  6 +++
>  lib/test_kasan.c                   |  6 ++-
>  mm/kasan/hw_tags.c                 | 51 ++++++++++++++++++++++++-
>  mm/kasan/kasan.h                   |  7 +++-
>  mm/kasan/report.c                  | 17 ++++++++-
>  11 files changed, 196 insertions(+), 10 deletions(-)
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1477c6da-a0fe-903c-4257-84c45908c836%40arm.com.
