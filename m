Return-Path: <kasan-dev+bncBDAZZCVNSYPBB6UV2KFAMGQEOZICMXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 89B1A41C8B8
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 17:49:16 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id t28-20020a63461c000000b00252078b83e4sf2331463pga.15
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 08:49:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632930554; cv=pass;
        d=google.com; s=arc-20160816;
        b=K1/vWak5TWSrRKw3tzNFEoJva1IyeP6E1PRM3dKjifW3rU8oRf7daB2yccgV8FpsgM
         fpcjLT8O6I0EDyWeY5Q8s1nsEbfGfbPFQ8Q8XPAvK1TDQrYV1fD2bT/EKKmDEWVEc0/t
         7fscaOWpZh/Zu/roHuhMF1kDiLh+L5RJgkCohXsnwF7TNLNrI4Vo4iBYVsDeyvgx6jIS
         k+kRvlU1iDXdvYSRtjyxgQdHEaV/nzEit6Bg3ey+a3LJBsK0yWjGpx6oV5HiH/J9ITQs
         u3pq8h+RC6kOjLSCAyrIlBYY2nlh0kj9jY75i27ubenYeEL6ZT0eG1YSYxaHkBht/JsL
         02xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=mICU08jjjhjbiWi9h7+iHR+fFaXzXoOX3Aw0EKfxkO4=;
        b=S6NF4P4dspL/M0Bo5UF2ReErVKsuulLdcmM4/RGJ594cqalehYeJbP4fugpSJDnTLe
         N8LVhCFI82wsrWuFe7jCJxq96q/UmyDiL0rbBASKbPksjy6CcUj8DFWwJbkBSx7a0Ao9
         xDp3eCI9XvsoWbKVt5RoG0QjCzlvXOZWIog416I2Ml9MnctPJ+NiIWcUhWKfOGHh9AxG
         F0sO3GTei477bKJgyXteMkXTBY+P25WtFF34qU8MK2yL+hfoV26LqjaXvWFFVUN25Op6
         Iy30ysYt/blPFMV1QdCBxfzoa/yu2xo73UmQuaxb+U4Sxnw61cfQZxI/h6xp12j7JNDv
         83lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yni+YWJS;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mICU08jjjhjbiWi9h7+iHR+fFaXzXoOX3Aw0EKfxkO4=;
        b=sYT1fpESvKFZmbyZVMCqQssjZEnpJz3tYCmEzdS0zaSEsVa51D6L+ZAYzx+SA+Wnnc
         kDZ2rzX7tq7qKZbXulBQGIVh9TieMoxMu1uiURV912O6d6Ybm/op15y38KLo1rMURjP+
         g394w31ecJhtBu/NVrNfPlSEO1lipQC+X9LLJAdLMRw/UVuJDrj4UKEhdAabi0mWspNp
         DVE4mn4P4RAsEdU0IMVF9gNZlaTN5kU74eqmPhv304nFWZmOoqPRNogigU5AQTfMlUwm
         GIsiPsLWEMF9f4lAGxlqiX0JSV7q4KNBv5Bwty7JmRakbG5S0HDsPtZtiuXV2IT5GK9x
         Js1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mICU08jjjhjbiWi9h7+iHR+fFaXzXoOX3Aw0EKfxkO4=;
        b=yuJbRZnHiRxJYGCctPA/74bPoKq/8Od9nkZGl6SP0kJH9ex1QKZP/fke/GP0NZfzRz
         ajOgz8B22HAYel2jNs1Ta73wyEIX4pJRx5ZTSfMgqYoDqfbRVF5RYBKbP2vBH9sdX/jp
         2EaRQvvLDyzxswfE4m8syuYfnE5UIWTP37hp/UnBhtsEMhoPoFqEAQFCx3bQW6E8f7W1
         xknARPv1zg1BpolUDTvoGBLf4Jcls1D+4syjKQFMXmDI4WwAlKFYM6Zoa/PHeTfl85Vl
         yLkD/lZx6Tfr2WJ9W3yvzBekNpmKq1tBlaAjAf1FsRiDRAQEY9+tRBBLvzjA+jP/nIIZ
         I5OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jf0XSlMdOZoL/tIa4xcMU4aBqAEGXzDJopmhuPN3jGkZQq2kq
	0sT69zENB16sZKQHzm2jZeQ=
X-Google-Smtp-Source: ABdhPJy3DscH3K8zeTT5EMqBGByTU/Jho0BwoQNcgmgI6aYbhZ9jV1/SxOt14hgnRr9zeGUc2C8G4w==
X-Received: by 2002:a17:90b:1bd2:: with SMTP id oa18mr7236579pjb.123.1632930554750;
        Wed, 29 Sep 2021 08:49:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1d0f:: with SMTP id c15ls2103030pjd.0.canary-gmail;
 Wed, 29 Sep 2021 08:49:14 -0700 (PDT)
X-Received: by 2002:a17:90a:ad47:: with SMTP id w7mr680392pjv.110.1632930554104;
        Wed, 29 Sep 2021 08:49:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632930554; cv=none;
        d=google.com; s=arc-20160816;
        b=EKBW8VWNEAePqZVmX/DM1Sjf76MKJgLGb3RLxnLcg0vEdQFp4OiHD5DaAP45OdkeAg
         CDTr2tnjiQmc1M7OuI17uk6DNfOupKek7+IqfPC+ADVjIUCw7GtXytNd8txH/S4BQ+rC
         fdUwXYVMy2aZJlxdsnF2QqAPMgBiga8wy5XIYJuKgph6ZMkz1oNNuO48ADr6fQLLlDdN
         OfIl3SiCCe083oQQjD7hzM0JDSGqRQRwkxeH9OtR67e8KSD1KdCyhVgDR3wlBlOXrmy+
         tDn+euPNJQS3WIEEeRzRrwtabc+UfJIqtzwvgR5bLoC/GeW+vN6VAxlKNjAXwUHI6N4H
         nXLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IrBRF2Gn9frgbDCRyuiNjLiVneMvAlQsIedPPbnal/Y=;
        b=r2b4ZnDBdvDrF6DMe39t6imxgbv+DFO57GWvrNre9SnoUwvDF6AuA251DGSUv12+3v
         y0ilOQK0L/VYX32tcC9AXfZwTKdUVMgjjSTZb0RfdZ+UhvsvYhGzziA/+jBNV1kABJ6Q
         KwXgt7ZA99vuTvDMGzd/Z0reKyCvAws5KGx89G1HT2OcLmCoyI+lbNu4rb3XNT37Mi9u
         pFlbKaBXDkjH0/b2J/M1MwQa1xTShgXGMPb7eMqKuW1UHAorG8BZARUZzH7co22mTTwo
         mHi8xZykmaeqr5555753nUhZNsAOhRLoM32I1iGyn2W7Ztiy9tDvoWmQgy+Ptd2fw7Ka
         0MYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yni+YWJS;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a11si324323pjg.3.2021.09.29.08.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Sep 2021 08:49:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 92CC9613DA;
	Wed, 29 Sep 2021 15:49:11 +0000 (UTC)
Date: Wed, 29 Sep 2021 16:49:08 +0100
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH 0/5] arm64: ARMv8.7-A: MTE: Add asymm mode support
Message-ID: <20210929154907.GC22029@willie-the-truck>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913081424.48613-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Yni+YWJS;       spf=pass
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

On Mon, Sep 13, 2021 at 09:14:19AM +0100, Vincenzo Frascino wrote:
> This series implements the asymmetric mode support for ARMv8.7-A Memory
> Tagging Extension (MTE), which is a debugging feature that allows to
> detect with the help of the architecture the C and C++ programmatic
> memory errors like buffer overflow, use-after-free, use-after-return, etc.
> 
> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> subset of its address space that is multiple of a 16 bytes granule. MTE
> is based on a lock-key mechanism where the lock is the tag associated to
> the physical memory and the key is the tag associated to the virtual
> address.
> 
> When MTE is enabled and tags are set for ranges of address space of a task,
> the PE will compare the tag related to the physical memory with the tag
> related to the virtual address (tag check operation). Access to the memory
> is granted only if the two tags match. In case of mismatch the PE will raise
> an exception.
> 
> When asymmetric mode is present, the CPU triggers a fault on a tag mismatch
> during a load operation and asynchronously updates a register when a tag
> mismatch is detected during a store operation.
> 
> The series is based on linux-v5.15-rc1.
> 
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
> 
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v1.asymm
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
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Vincenzo Frascino (5):
>   kasan: Remove duplicate of kasan_flag_async
>   arm64: mte: Bitfield definitions for Asymm MTE
>   arm64: mte: CPU feature detection for Asymm MTE
>   arm64: mte: Add asymmetric mode support
>   kasan: Extend KASAN mode kernel parameter
> 
>  Documentation/dev-tools/kasan.rst  | 10 ++++++++--

I'm surprised not to see any update to:

	Documentation/arm64/memory-tagging-extension.rst

particularly regarding the per-cpu preferred tag checking modes. Is
asymmetric mode not supported there?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929154907.GC22029%40willie-the-truck.
