Return-Path: <kasan-dev+bncBDV37XP3XYDRB4MIZX5QKGQETLPDYWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 309C327D10E
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 16:28:03 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id s12sf3826662pfu.11
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 07:28:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601389682; cv=pass;
        d=google.com; s=arc-20160816;
        b=jW5ameuC7Ucp11QiHR486fDN37JvBweCA9Em+MH5Wu8rrTeFrpi1Dfl3nrI06yVHxk
         K/R6y9SXXa6Ad0xaJlwvoKKkjEG/e+noHXxg8nU5tNWSBxfvGAZ7kR02fog2HSIiATrb
         TuO5VWwah5t+E1TVTuVWUt7TnV3MsCWRweakmF4xT/IGpusBis3dMa61x11mMzeh69wC
         usE4H8BQoT2BCaktV4tOV+Jwpm/VBOheL+zt7SQoghXhcVqTWLcpFQy7/8gfVtiWhIlr
         0j4pTATNnELdrPFfcokH6qRk2Dbs+/B/xKiRC5kwIEaGtt4iYTaTkwD/julDQwt8nZnR
         8D4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rS7bqzqZigpLWGN1XnZKmNktWfWmNfndVvIJZFXvIwg=;
        b=CzgU6XGJDsOPAdIbBctq5bWy41m35yh2P7o6ODzb7l1aps3sLFpEaBZHUS06+rUiVV
         2v27I9atzXzR6Q8aJBxkU6QxdWKXUqn+CfyNwRChjijhOKJHO8j7h9tFCooEMzJnRuFM
         hNyFDkiL9c6ZBJ23ABKoTiV7cGdoZYWO55rTqWfNWmOSSDtNmgXumDIX/XBjzm08mhie
         5OAf/U7V1QdWX5nOBSh5dUqFUCpaEp8P7RDgsKjMxgNGjYxEe/+bG2MY011XcFSpL5Bv
         OKZVWurSOIhoIH6ks3EzL9T+rEd1XQSw8Qaspz2zzrTYFAnXhtsxBfKtJxaytIK4tkEO
         h16w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rS7bqzqZigpLWGN1XnZKmNktWfWmNfndVvIJZFXvIwg=;
        b=jnje81L62iDOQVScCJqQjDciSzKt0XDVTgMJta+53g1EW1aDh4xvuGJIVLgAQfIy4C
         aqez0hPQugtmGMWfVlXDy+LtAa5tIuQcu7fYhRdYiP8PeuqngI6k1pIIbhmFPw300aNk
         74lpjGSv0AmCKJIZySSAFFbA/ZKQPYlDcU97bvVX7gUFjJBi3leMGEw1hdqjCu2WV6Xm
         cUaZbUQvB9iiF1JMZ8qYJgsbD40MPFpDJoAlbsApatkC4K6jz70AElKssx930onC5Kqc
         EN5uGI8/JvvEcXR++phjqVV3yDWrHmGMPeVLm7cvMQ65mcP4UerdqfRNSFAZYmaWztF5
         obIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rS7bqzqZigpLWGN1XnZKmNktWfWmNfndVvIJZFXvIwg=;
        b=f5Oq/UqzSR/VlNtIuHKt56j2dkKdGSIm8OYbvlLo8YXfaZb1Oc4O8E4A2hmAz4wx9y
         Jef2eyN+X5ogY4kQUdpMyom/9upfOR7rJunK8TRCtADBN40gVziSTKmls1PHBXJbYcnb
         1BuJg3n2wUJGppgQ+sCyUqKN0cUG4xyOQKKeBD9L5hSaN583ricPSEb2nzO2L1ZlOHh/
         skblxeLRQ7J1invabXcnaHrCuLSWC1qyYlcaUZ6BRtMIbElEd90q9B//3BkmUjLs8/SP
         JhwlWLFUINhl2hyuY/UDmGfDoBQyn2Pfe+mLnOp61/kDGW4eLSFV1ZgjV00zla3XcUjk
         xhTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332BoOssamNI8d1xapF64y63VkNNLD8O5GV3PV4gvTmMQ7RkvhH
	bH7BxBlevMyn9d5Yg8fZBtc=
X-Google-Smtp-Source: ABdhPJzaWV8U/biPF+v0GnEB4/ILpxQm4MeE0FdcVqnSqCg23jJJ9mMC8Pjf0516uugx/TRSHu4k8Q==
X-Received: by 2002:a17:90a:b287:: with SMTP id c7mr4150683pjr.141.1601389681840;
        Tue, 29 Sep 2020 07:28:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7613:: with SMTP id k19ls1000314pll.10.gmail; Tue,
 29 Sep 2020 07:28:01 -0700 (PDT)
X-Received: by 2002:a17:90a:fb52:: with SMTP id iq18mr4232490pjb.162.1601389681011;
        Tue, 29 Sep 2020 07:28:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601389681; cv=none;
        d=google.com; s=arc-20160816;
        b=rUxS9xr8S0MDT8giBin435h9W836wWfghIiYMP+B/H/1r1EBQ4CdapHBdBRjjNAqi+
         Fy6tae5kSCY1BNprcEuWmMwiCayueU6iRptrL0FZQLDZf1sUCLCt4EkJkzgvTNw1sYrQ
         2bnxfGkrrIVSizJiBe7xIbRfpAmNqE67pDL2vdHnQ8E0UhIgO1BYBB4FKNpySd58miTB
         lmsv1WkUesFeQLna7yfOavKSLeXzqAN6mM9hKSaeauYqnSfaDwwBoZlBkRuT5B/o8Pff
         /yvT1bEnC7l1i3t8jrPGAguZuY9v8BBvAXH8zocpWLWDwgZ0lUulSrqHBzqa341LUZDk
         KihQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=6hGOr0rvJqjs7nguNpt2BuU3Yn6Ojp0YzE7EHgq4RoM=;
        b=jDKZse8vs6lXV7tmfZuFq0WsrhMGJRpv+mGowIm/C1NjgSaFu1BS4vPPtFurba6qfh
         wI8ZjLXinQkf/2QpsTbmmsFnYunJCD5Kx3xcitndiPBZN23XThsrBKQ1pjN4x39hK/Xk
         XXTHle2FCTq+ZCFnZCcxPlB2h5yKzb1VN0S4coGcnuwGsAgTd/1KlOg2hVWQq4yl+xdB
         97lBnMVOZtVKpL71yR7VEM5veU9x1M3wtxj+JB1khJuwsbaGB1su8iZqeVzl6Acpy/eV
         CR5AasS+zxPjRXADTZz4PPR43bda3RCQ4Fg/FFb+zYlo5oPVTyaKfIqAtQjSx9ifzR3p
         h8rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a15si616544pgw.4.2020.09.29.07.28.00
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Sep 2020 07:28:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1F3D031B;
	Tue, 29 Sep 2020 07:28:00 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2B01F3F6CF;
	Tue, 29 Sep 2020 07:27:55 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:27:52 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com,
	cl@linux.com, dave.hansen@linux.intel.com, rientjes@google.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	hdanton@sina.com, mingo@redhat.com, jannh@google.com,
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com,
	keescook@chromium.org, penberg@kernel.org, peterz@infradead.org,
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz,
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20200929142752.GD53442@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200921132611.1700350-4-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>. Currently, the arm64 version does
> not yet use a statically allocated memory pool, at the cost of a pointer
> load for each is_kfence_address().
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> For ARM64, we would like to solicit feedback on what the best option is
> to obtain a constant address for __kfence_pool. One option is to declare
> a memory range in the memory layout to be dedicated to KFENCE (like is
> done for KASAN), however, it is unclear if this is the best available
> option. We would like to avoid touching the memory layout.
> ---
>  arch/arm64/Kconfig              |  1 +
>  arch/arm64/include/asm/kfence.h | 39 +++++++++++++++++++++++++++++++++
>  arch/arm64/mm/fault.c           |  4 ++++
>  3 files changed, 44 insertions(+)
>  create mode 100644 arch/arm64/include/asm/kfence.h
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 6d232837cbee..1acc6b2877c3 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -132,6 +132,7 @@ config ARM64
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>  	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
>  	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> +	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
>  	select HAVE_ARCH_KGDB
>  	select HAVE_ARCH_MMAP_RND_BITS
>  	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> new file mode 100644
> index 000000000000..608dde80e5ca
> --- /dev/null
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -0,0 +1,39 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef __ASM_KFENCE_H
> +#define __ASM_KFENCE_H
> +
> +#include <linux/kfence.h>
> +#include <linux/log2.h>
> +#include <linux/mm.h>
> +
> +#include <asm/cacheflush.h>
> +
> +#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
> +
> +/*
> + * FIXME: Support HAVE_ARCH_KFENCE_STATIC_POOL: Use the statically allocated
> + * __kfence_pool, to avoid the extra pointer load for is_kfence_address(). By
> + * default, however, we do not have struct pages for static allocations.
> + */
> +
> +static inline bool arch_kfence_initialize_pool(void)
> +{
> +	const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
> +	struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
> +
> +	if (!pages)
> +		return false;
> +
> +	__kfence_pool = page_address(pages);
> +	return true;
> +}
> +
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +	set_memory_valid(addr, 1, !protect);
> +
> +	return true;
> +}

This is only safe if the linear map is force ot page granularity. That's
the default with rodata=full, but this is not always the case, so this
will need some interaction with the MMU setup in arch/arm64/mm/mmu.c.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929142752.GD53442%40C02TD0UTHF1T.local.
