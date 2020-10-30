Return-Path: <kasan-dev+bncBDV37XP3XYDRBLHL6D6AKGQEL3DROCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7B1F2A0A32
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:47:57 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id m7sf1805982pls.12
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604072876; cv=pass;
        d=google.com; s=arc-20160816;
        b=i32eBTLaVvl8thG9OCnO44MoeYbIPLRhvifp5VDgkq/15DKSo6K5A5ZnKyMB4yaUnA
         ddfKSS0TCU74C6PyQJEh0e24rRdUjWPamIHJsJeekkvTjVbhitV20uYGjmehSRC6GAus
         6MPqPSJJrFiCgcCZsIr5My/gkBvjLZBg9YcopYSPIqUPqxtxlxQte0ZEWAEQo20UfN43
         H522ge487nEuSi1sco7fWCck3UIARXIFThDJRx2wonyVpBi7u+IaGBfhFH36jvzwBldA
         NTbQZ6SdlRDLEuWgQA2c0mW5znvTLDWoduy8XSVYO9VFFt8+z/OSEjrhEarv4o2le5OX
         nhFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yAf945NfimgTEvdjOdXP860ic4F3v0xY/OochDPRwC0=;
        b=UvJnbEQF+gwWZ0SXOKEQVncU5HakVs1cdKYsr14yfXMoCpA3TnrU5z8aC7FtR/G/4t
         qlBrXfn5w0SAnPpV1yfnxKbH7zYcwi1RS88pHjiOnowsBiYYoOdMQBUT1SYOFaoc5K0d
         /vVKkqfGNK4yS8PY/DP5qKQhbTM1EEpMyoN7pODUrNvxZWKddcqd4Rag3vSvO03/ucgR
         b8uN78Zp/YA51szzY3lgqwp8iv+b4XXN4MBgRoH3/aJQoVhmSP6hXGSHuAvXQbxp/7ec
         POupBv35WjW5BCmCKpvN3wX1WdYjR+fEvPB4+Nek9GbWeMhvJjiufXY2oI5hHxHH6rPa
         fGIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yAf945NfimgTEvdjOdXP860ic4F3v0xY/OochDPRwC0=;
        b=iFct36h3SrDgLUhEVOvbuibuuYOIDqPx5zY0B8IuSRrwAeqTi23aLXt3bR8VlJkfCg
         h+dT+4A5YzJBIEFespZBvDUbesMdu9+3g6FGeano+xkRt8mhRaQ2c/jHj1fLrDScK/J9
         DZ+hyzY4f3et7S3WWlaNjs24UI3BHvJUjVsBDf7cRF0UT8HEKjNFrqK0fW7EpfKCSCH7
         vPRVCPYrAplYqqdWZme6ojY2mi5ToYFlCzw6uq+G8CFQ4uSUJ0pOYrYCe7jMCBdEEEB4
         6cKsBMckPy3DZZrFnNwi8wx/n7pcu07KjhtB+jvkbZSicBNWhoLSQCFmmussFDDeStct
         Vnnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yAf945NfimgTEvdjOdXP860ic4F3v0xY/OochDPRwC0=;
        b=ICI8axXlzkH7N/TV3RVbyOfiEJwEScwiZqd7lobnIPfaO8R3HGtRnvwrb+pm08dd8U
         znuZ2XxTBW8PJV3EEHQS6Muaf4WHq3iKurS05Y+G+Cso9ttrA4v+STcso4JmeO6xKTqr
         V/ScO4glYahdS2CiW2ir6/9uxXRPX8ypMBdhEbJiCnr1NkWWfZ6jV1RDvRG0fpJph26f
         7j6XSDhrCqRXSO+Grwjq6uqzP8QjPANXRR5o3q0Vf33m9dAqZmFTAxiRbO44NRSMEBfS
         YngEMEfke1R/yenexQNDfuOKfqZnukTqZkBea3e0ULr0ufuengIYl/vd9tX7UCJiwhrH
         kFbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531elhyehcDJ/OKbXRO3mWFw70z9rWRD33DX9pNK77EOotLNk8Py
	fThmGO5BAnb0pyznjdgMtrw=
X-Google-Smtp-Source: ABdhPJxFvfAABRGf83hGVRN+mrvAPg1YsAbSB9FX+EA9egjVcWEF7bCfIkcREKRqdr/qhdFGBSPumw==
X-Received: by 2002:a63:7c54:: with SMTP id l20mr2650644pgn.151.1604072876186;
        Fri, 30 Oct 2020 08:47:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:941a:: with SMTP id m26ls2432030pge.10.gmail; Fri, 30
 Oct 2020 08:47:55 -0700 (PDT)
X-Received: by 2002:a63:7d07:: with SMTP id y7mr2746045pgc.437.1604072875427;
        Fri, 30 Oct 2020 08:47:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604072875; cv=none;
        d=google.com; s=arc-20160816;
        b=w29kb57c31WOFRZB9yepMTWESn+GUppMnFcYc9tXylCO4H1ijGiePm+bH2kB9K84xZ
         ewIjV7LY2VcmuEmIwe5ZIpM2q+tCltyXXXjRoy2q8k3c7ytBARIq5rXI0Nkn7i8hitai
         c/iuR+HPZRHqDxNXnTlNwk1ZtIYYkObLTxcY9aZp+X9mrgdoZaB/adDerSHsWe0iyf3O
         U2wBmZIhsjECfsNbRYq7yGRJBp1MmPn4Rq42u1Cdgo9BIKoVi9eXEsqrmczKUwYn99fj
         9jmnpOVdWecQjlyzoB/FYMnKV+Ds50WufEVm10iPBLc45cXFemXGTxTLDmGhmtCHrgP5
         JkgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=u07wTeCGK2vDy14H9NwZatANJZITfF+Vjhlwyuzb8RQ=;
        b=niuUk+sdjUTVWsbhnRqfarGIOHP8EEGhZG0fLj7954HY+z1q2G8/5zAM8lvXVnyDUk
         XsVMFQEkYISL+H45aD7rAeq6bDyy+1aULY9T5yStvIJ5rHprUx8iY8Mw5pIzWl3eGFT7
         ejnLK9S+FHbapvf3thSlJwuuDRE9eYHwUpl1wcZAFvCRyhO2PveFsRqNHgtHCWfDHNfz
         njxyMEmFVOyA3Do6KYjGD0GNkdEMbZt/7v+TQVGleHVttnybpvAMHdkj9Vewi6r4p/Os
         fYGKbFzSq+iNqlaY4gEKazYAejZO2GY6W1WPx0wskRxP0UylTPKWtBUo81xsDjpGKoza
         BOnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i4si363680pjj.2.2020.10.30.08.47.55
        for <kasan-dev@googlegroups.com>;
        Fri, 30 Oct 2020 08:47:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 70122139F;
	Fri, 30 Oct 2020 08:47:54 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.53.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 164E83F719;
	Fri, 30 Oct 2020 08:47:47 -0700 (PDT)
Date: Fri, 30 Oct 2020 15:47:45 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com,
	cl@linux.com, dave.hansen@linux.intel.com, rientjes@google.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	hdanton@sina.com, mingo@redhat.com, jannh@google.com,
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com,
	joern@purestorage.com, keescook@chromium.org, penberg@kernel.org,
	peterz@infradead.org, sjpark@amazon.com, tglx@linutronix.de,
	vbabka@suse.cz, will@kernel.org, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v6 3/9] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20201030154745.GD50718@C02TD0UTHF1T.local>
References: <20201029131649.182037-1-elver@google.com>
 <20201029131649.182037-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201029131649.182037-4-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Oct 29, 2020 at 02:16:43PM +0100, Marco Elver wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
> 
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the entire linear map to be mapped
> at page granularity. Doing so may result in extra memory allocated for
> page tables in case rodata=full is not set; however, currently
> CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
> is therefore not affected by this change.
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v5:
> * Move generic page allocation code to core.c [suggested by Jann Horn].
> * Remove comment about HAVE_ARCH_KFENCE_STATIC_POOL, since we no longer
>   support static pools.
> * Force page granularity for the linear map [suggested by Mark Rutland].
> ---
>  arch/arm64/Kconfig              |  1 +
>  arch/arm64/include/asm/kfence.h | 19 +++++++++++++++++++
>  arch/arm64/mm/fault.c           |  4 ++++
>  arch/arm64/mm/mmu.c             |  7 ++++++-
>  4 files changed, 30 insertions(+), 1 deletion(-)
>  create mode 100644 arch/arm64/include/asm/kfence.h
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index f858c352f72a..2f8b32dddd8b 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -135,6 +135,7 @@ config ARM64
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>  	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
>  	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> +	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)

Why does this depend on the page size?

If this is functional, but has a larger overhead on 16K or 64K, I'd
suggest removing the dependency, and just updating the Kconfig help text
to explain that.

Otherwise, this patch looks fine to me.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201030154745.GD50718%40C02TD0UTHF1T.local.
