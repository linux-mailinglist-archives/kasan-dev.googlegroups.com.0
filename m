Return-Path: <kasan-dev+bncBC7OBJGL2MHBB556RSDQMGQEBSE2IVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE793BBE9A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 17:04:23 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id r11-20020a5d52cb0000b02901309f5e7298sf2944548wrv.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 08:04:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625497463; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZTh8LEuJQxftwGi6762ql4uq5T6EMJtIha3rcEIZl/195W/81CCp7qXffE2EML3Ark
         RHXFi7smwzwKYGoItGek9a6Fup4CditezVyKmrzIGSCpJvA7HGNSN7DPVZj7aO9aSDZm
         UAzp/BgeXRe/qT5v/dnLz2y/rV57M3euXWm0i1t5BQxsUozfvJ83JDZt/zKBM0VGBWKv
         IYvON8CJLtXKzIhjgEVZPWdp3yfS498DogWFRx2jEH2dpDSbfzANbP6uqJ7jKMz1ArQu
         kBFyidJj0cWuAu7PVsJcBMpRNqW4cupo3SjQ1QWxrL0jEQxSFJNpt5gcdQoX+ejPvTUe
         BSzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Xzm+KMjnKJADT/8tnznAin4QLZROrHL5aNhxOtJ9fNY=;
        b=uX4Jyc92JECK9t3dn42IXWgmNQlnLSDALUJAeJFF0A78ZE4DrnM9qC0HzdIhty+d/J
         1ESF+rqk+u+Elj1BqILUgP2yBBLYKgWxqiEpfv/3G0dGMc9irtw/tgmSVqE9HQ6Pa2RQ
         P0/m5Ru4/n7VbW/qNQF4hA/3d1cxzFPBssX3zp9XYcCJYkFjLtbn0lxRZimJT/BdlNYm
         rFUcls13Pnwkiu4J8tFzApeFs7RyWlOKm8JswgYhaFAiXU1g0LvkzkWhkY6I6hupuKVf
         vyyK4eFdgS7g9yjNIva1jYRpsLiZQbj7lrFCayWyRrw3fBLyGll14QOT7FJmq44PSa/8
         mhUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="v70/7r/s";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Xzm+KMjnKJADT/8tnznAin4QLZROrHL5aNhxOtJ9fNY=;
        b=GxswFfUf28XlPcRdJeAI68KmTDi0wU8ZLiQUI2tUAaZqeZlL68jP3+DJTdCEX5EzgK
         CM3tQIWrkBxm6lgO3rE+dM7y8G7JBQqKaqw2zcgAfcLPXmaX06GXFAMyDbWQGULg4jIP
         5wL9MZ0zvWjW4DRDvoB/PKG+LefUQL5kaKUDKsLYHNs3Oe/RP9rs2U6wHaf3UAi/snbu
         UKTNpKASUWvPwgJ4ClawXZ+BTbNx5fZqfY/SmFLWjgVGgmglDjr7TiGQJsYqBitXTlfS
         iSmuzHSfzSZO+eNi6UzdFuyd1ArDB+d9oj3GsIiUJZOEaIDxRCL4wHjAmALq3l3OuMOI
         zkQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xzm+KMjnKJADT/8tnznAin4QLZROrHL5aNhxOtJ9fNY=;
        b=UgioATUiSNUtYVg1kDL1GRTUjIXzdA9rlYoSj2+Aagac6nk1w5jSOhi7iqyWOdYswa
         OtunQBFM/A1PHZ0GmZs8Av9SaTY9J5Zdi0WxamNrTz2ZW6+DpYBA2BGNstmD/tDIzEEu
         ucC+Vv9lBIfhzrZWkskwwu+xOzj9aSLiwQQEpy84wsCfcb8K8h3LCBAMVWHpyNUIVg5d
         i/fyHdqgR+fn3ao5wRmqwLteNevw3gbFNvKxcgZgbxu5ci3oL9E3g6re63PUggvRX/vh
         LoUXT6CPSS/SANl8K/9TCc7qQRVeUWrCLaGOfjXZ87FfTonUthrBYoVIqd4iWlp3HvQV
         ctlQ==
X-Gm-Message-State: AOAM531sBOi8OI4f4owuhYGYMmIO0+gSCMKvFylqUlbQdO+cpgafP01m
	S1d8iRylbb9C6F58jezEngo=
X-Google-Smtp-Source: ABdhPJwjX7xlp1nPQLKqEugWYbuKYdRQPzfbSCsQ0x6aafI/M51ZIIVyPFa3Rq98DcCkSo+JYaqAmQ==
X-Received: by 2002:adf:f68c:: with SMTP id v12mr15625698wrp.43.1625497463662;
        Mon, 05 Jul 2021 08:04:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:69c7:: with SMTP id s7ls7074266wrw.1.gmail; Mon, 05 Jul
 2021 08:04:22 -0700 (PDT)
X-Received: by 2002:adf:e690:: with SMTP id r16mr1951473wrm.196.1625497462715;
        Mon, 05 Jul 2021 08:04:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625497462; cv=none;
        d=google.com; s=arc-20160816;
        b=Impm/Yy8u7Q4aqNj8pLFobR5K97IL6UYMDLy3thUKeIeYVcAl87wLpFGDUtyylG42I
         Mem1i9XXzDQ+Shs+deQZEQz/Rxz1Jl2EhyL9/HaAMpKHnSWaXlP4liU6szXI0xKr7f3r
         98/T3rwraBKWDQ68ALgb1OqWE21TK7nQX1dSQ2rY/OM75Qf24HX2YkH5FhnsFhl7kwXJ
         JtXrsKSy9iCvkMtLl50zlBKW1cKlWClDtq7Bm1EezsqtAKPFXzbexjFWoxiN2tY94Ybp
         t2xuHDQw0zT8TU3dn23epm5AF7k79ZsVBQu+IF5dzw+be6jFePRZqXIheyFf2V//jUrM
         kVQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=At8qjqAN8f+W2do/QMp0ecm1lFUsBPDE6HfKaXVwDro=;
        b=REu2l2IVoa0qoTvIaE7TjkbbV0G5TynxdMy8FxNXp4pvVUskgGRiCh0DBA8xN4+TgH
         pyUkE+xJu6yelNw1HVAh4hmAVYZKH5SXPYwUv4Sdgo3Ob/K2yOcW704q5OX7tgkNuoa5
         L49LpFQhjVWSwyOvH4/xWydb/6wC9YQok9YQIYuF+Mp5Q/m+q1IIx32Kad/+fuEomBmG
         Cl6kC3vlk9Wrl1BRTb6akYXy/rfN1JO97tyRthhOHHthDYtT2I7m/vied822Xz6c3QZy
         syVVnh2kA1lN7/qIklHWt06bL+2ur8QumnGhhJ2hhv0Qbzsi1eJ3rAsmWdZQfJXC5JXM
         BGlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="v70/7r/s";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id z14si120895wrs.0.2021.07.05.08.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 08:04:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id q18-20020a1ce9120000b02901f259f3a250so163768wmc.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 08:04:22 -0700 (PDT)
X-Received: by 2002:a7b:c15a:: with SMTP id z26mr15436389wmi.109.1625497462273;
        Mon, 05 Jul 2021 08:04:22 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:3207:330f:6162:ea09])
        by smtp.gmail.com with ESMTPSA id t9sm14493333wmq.14.2021.07.05.08.04.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Jul 2021 08:04:21 -0700 (PDT)
Date: Mon, 5 Jul 2021 17:04:16 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Daniel Axtens <dja@axtens.net>
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
Message-ID: <YOMfcE7V7lSE3N/z@elver.google.com>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210705111453.164230-4-wangkefeng.wang@huawei.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="v70/7r/s";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Jul 05, 2021 at 07:14PM +0800, Kefeng Wang wrote:
[...]
> +#ifdef CONFIG_KASAN_VMALLOC
> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)

This should probably not be __weak, otherwise you now have 2 __weak
functions.

> +{
> +	unsigned long shadow_start, shadow_end;
> +
> +	if (!is_vmalloc_or_module_addr(start))
> +		return;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow(start);
> +	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +	shadow_end = (unsigned long)kasan_mem_to_shadow(start + size);
> +	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +	kasan_map_populate(shadow_start, shadow_end,
> +			   early_pfn_to_nid(virt_to_pfn(start)));
> +}
> +#endif

This function looks quite generic -- would any of this also apply to
other architectures? I see that ppc and sparc at least also define
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK.

>  void __init kasan_init(void)
>  {
>  	kasan_init_shadow();
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5310e217bd74..79d3895b0240 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>  int kasan_populate_early_shadow(const void *shadow_start,
>  				const void *shadow_end);
>  
> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
> +
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
>  	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index cc64ed6858c6..d39577d088a1 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  	return 0;
>  }
>  
> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{
> +}

I'm just wondering if this could be a generic function, perhaps with an
appropriate IS_ENABLED() check of a generic Kconfig option
(CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
not only an arm64 problem.

But I haven't looked much further, so would appeal to you to either
confirm or reject this idea.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YOMfcE7V7lSE3N/z%40elver.google.com.
