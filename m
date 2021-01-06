Return-Path: <kasan-dev+bncBDAZZCVNSYPBB6GQ277QKGQEB7LLOBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 976242EC154
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 17:42:33 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id l18sf2298311iok.7
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 08:42:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609951352; cv=pass;
        d=google.com; s=arc-20160816;
        b=dL+bPZhcHBDah9HAR0GTjnGfL44iD2iTyr13vm/Tb1R52ixmeEYZlGOCi6K0wNEWpk
         sFOrGKU5RanqYJUfMLoT2cjAZeCh9vVZjuRZjJVmJOv80+I4GKm1+LtV+0VXa2oWmDc9
         bnd6b19+kpUDA0wy5oD/yR5Eo57gz978eA97ITglnXuLs5zIirRy6eq4kOt/B94HhKAG
         i8eClWeaVAZ8FKgVq/nsR5YsZ/vB/OyGdua4vkYIaldW3HVriP/keUkjQDR29bIUkvj1
         O1kLwwhzct5pDNEtqJYsWOcaGsawPNWY8mqGuk614TtIa3BGS2nbAXtMQTSNoJRNWfm1
         RQJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Da9GcrROH47psvWy/TuM/lbqQumvtME62jJ3TD/9qGc=;
        b=XgZ0b4kkVpRZNaA/inFiEMVs3N5PjKrS9Ca45pKe94dyJu8t0yt4u/t5SX7LpVUyzH
         0jtfxRNXwxgovX4NPt7m4DeM5dScF87XIzgy0j4miaUMTr2E2A5Ky8isHRA0YYe7/70p
         gtsp3LJGxTAbSXqau5LpxCHX3uYSAQHS+0d2r19q7AvGhYiaMFLVjyQua5bLf66xIVAT
         BrGQu4yXUipDDUxdnCHktKLTOhUUQDR5XJ1gUYDtBXD2g/xq3dNluu4fYyMB5JhyKBci
         BK8GHV+0SqD5G/xSEvFsVHOWlovjJ8KjAfDBzGqljxJ5j7RPnd50OUZvkurNIdICvAat
         +bpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="KB/Etz3u";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Da9GcrROH47psvWy/TuM/lbqQumvtME62jJ3TD/9qGc=;
        b=qlqJml4S2fjeq4zTh3SKc+nA8GV1dIi7dMetPpsSVE7XKUXzTghv/73jjfZOd5npuV
         Q7viNSgL21c+kM1HTSIZeRWcWM9KxYwRu3SkqODyfXj0TJXldQAKvUDB4PtFSZsZdzTD
         eWdAkOrmbZiuyaJdGT4/5KhuXJHmp8iCO7NU4Yp86eWrvudB/mYtJggVTAIkj32hUVUw
         pkdWgOkeog4qLP1Jj1GfOP5RX/93z+ZNPSCC2A+qeRAmOBjh3Lh8p0eVWLPHKgNVgrle
         o1r+BRykkUg9R2fa+Jr0RVK8S7ozRhOYWMOxhiCCw1wiZQTRDC2Ui/wj00cx2L25/3hE
         rGpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Da9GcrROH47psvWy/TuM/lbqQumvtME62jJ3TD/9qGc=;
        b=YeobPd23LjSbDnXvYuJ/NAliF8FIpSLonUkuwqZynfJ7IQXlz4cbZfpGkjWjt+dTrm
         r5EYQi0UzI4VitcycvxHoMYDj64mxj1gYM7Ki3e7A9WdhS5SSPosnp1ZbZiykwPni8Um
         BEN8CSqQE231alivfv8ChgreHx2+uC7903ayaa1zr0Qy2XH5htl0NZmNtDnUGe3tzq3k
         G4QM83F9R1TSdorhX/vYxxb5IhSJjFn5E5ojODcsGtn4IbcmO6HIKEWED5gsZyVYjUmO
         2anVzcGRK9CGvT6BPTJ/Qz8QMmw7CnKwwbQ3wYAQjvyG304tfGpAbNT1HJE07BaiazV7
         3Z2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/u3ya8IxBDwqGtRlSlS809ZLNVeJ8lYvmI8GPnWGQzsqKP4rb
	sY4mmm7s7uc24DV4KcKGey4=
X-Google-Smtp-Source: ABdhPJxxfWUtHhHTWJoDwzBUUcqE/m+ZDEzNJP6AbKlwQGEw9uiIXOXMmReE9PXXo7G3vrz0VrakIA==
X-Received: by 2002:a05:6e02:104a:: with SMTP id p10mr4826360ilj.247.1609951352649;
        Wed, 06 Jan 2021 08:42:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:4e83:: with SMTP id r125ls438630jaa.1.gmail; Wed, 06 Jan
 2021 08:42:32 -0800 (PST)
X-Received: by 2002:a02:b607:: with SMTP id h7mr4477821jam.120.1609951352236;
        Wed, 06 Jan 2021 08:42:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609951352; cv=none;
        d=google.com; s=arc-20160816;
        b=eqKGZZHiQnTgex12XaBbiKoakS76GUy9vzSLIQQXUUN7OMwecdy0Hkw9ouLfzgPb+6
         c2rdLWBJcKMfdXtaSybGLrsqoqepR/5JdU2fN0Foey3uP2Dqs9AmEv7KZdL4JLkL+lLN
         zjmvOlcIrtzrDolD81Q52cYTZl3zJLPuW1qLwHhQDDCxQUhJpGxAL1c1tklbgYqT+5BG
         kJwYhrCmfhz0IeOyAd0wZUXJaB+byW30cPoQiQV60SD9fYAkTNcP7cUq/o+qYxzEKwaM
         7Fi0L+URojO5nj26B9Vx35bX+eY1mozJDHFmlkJRguhuf1y8LWXzDeCYHV8ZK9p3UAOS
         ihUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SckHFmxxmuLoa0cNjFtg8vGPZg5TqVGM/iMWxwgn+bg=;
        b=Tc1uWfEpiu/ZzokHuoggXQ2ko0q7pyJ4PQilxJGVp9ZN3K8P1bX70q8FLXCSYN5t1h
         rLgCSw1ISqcKhhkPcvB5xnazKLPry88NlmlIUCdakZBr4YaKw9yo6lHNVjXLCfGePzRa
         0iMq+XRysGPakiGcve4m87L3bugTez5VivzmDhLRhgMmY+adBOJrOZFELI5NzG3LVTIc
         x089+4BzxQvuy9vfTys343o1XB77I8Ej0pwuPTQF7j8yG1LqhCsrXAseXY7b5KPmzQ7n
         eVLCUfiIj+472VPMpDe5epPMCpZQT58MwR9ysn1sSJufkhP2K76Po93L6RLm8ufVDi5s
         xhqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="KB/Etz3u";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k131si203500iof.1.2021.01.06.08.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Jan 2021 08:42:32 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6278423136;
	Wed,  6 Jan 2021 16:42:29 +0000 (UTC)
Date: Wed, 6 Jan 2021 16:42:26 +0000
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Message-ID: <20210106164225.GA1916@willie-the-truck>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
 <9a78cd4f-838d-0410-62fa-16e4ab921681@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9a78cd4f-838d-0410-62fa-16e4ab921681@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="KB/Etz3u";       spf=pass
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

On Wed, Jan 06, 2021 at 04:35:29PM +0000, Vincenzo Frascino wrote:
> 
> On 1/6/21 11:55 AM, Vincenzo Frascino wrote:
> > This patchset implements the asynchronous mode support for ARMv8.5-A
> > Memory Tagging Extension (MTE), which is a debugging feature that allows
> > to detect with the help of the architecture the C and C++ programmatic
> > memory errors like buffer overflow, use-after-free, use-after-return, etc.
> > 
> > MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> > (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> > subset of its address space that is multiple of a 16 bytes granule. MTE
> > is based on a lock-key mechanism where the lock is the tag associated to
> > the physical memory and the key is the tag associated to the virtual
> > address.
> > When MTE is enabled and tags are set for ranges of address space of a task,
> > the PE will compare the tag related to the physical memory with the tag
> > related to the virtual address (tag check operation). Access to the memory
> > is granted only if the two tags match. In case of mismatch the PE will raise
> > an exception.
> > 
> > The exception can be handled synchronously or asynchronously. When the
> > asynchronous mode is enabled:
> >   - Upon fault the PE updates the TFSR_EL1 register.
> >   - The kernel detects the change during one of the following:
> >     - Context switching
> >     - Return to user/EL0
> >     - Kernel entry from EL1
> >     - Kernel exit to EL1
> >   - If the register has been updated by the PE the kernel clears it and
> >     reports the error.
> > 
> > The series contains as well an optimization to mte_assign_mem_tag_range().
> > 
> > The series is based on linux 5.11-rc2.
> > 
> > To simplify the testing a tree with the new patches on top has been made
> > available at [1].
> > 
> > [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async
> > 
> > Cc: Catalin Marinas <catalin.marinas@arm.com>
> > Cc: Will Deacon <will.deacon@arm.com>
> 
> Will is not in arm anymore :( Sorry Will... I will fix this in v2.

If only you worked for payroll ;)

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106164225.GA1916%40willie-the-truck.
