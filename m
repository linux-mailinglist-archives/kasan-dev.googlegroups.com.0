Return-Path: <kasan-dev+bncBDAZZCVNSYPBBSWZ56AAMGQEXKI7N7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 92FC930F35C
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 13:47:07 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id f204sf1683693oob.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 04:47:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612442826; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZYgxO4tw6juJQ7YiEFcsDtc0fXvloFxgwQdnVRuUVammYbQvQ7DyoAGQHXFwbyYRwF
         Ibak4a0m15IIed+uIgt7OIwMt4wUDXepYkI0iFrn1aJqn4DrN68IEAFFN8UC1AaI1ZLG
         dr0gHZcmH9/wRj75OWsX2WFsNxTT5Md+CP9pIni4BEZSyTHLhz+Jm9wuSMhiWQleRVvQ
         VJd4yb0F5t89bBW/o1iiqU443FzFUpRe3+IIUDWyyKmAELDpPQohWXnG8Bh5xKddzgze
         2IiF0DF6woSkX4QO0xc4CXZPZYsNruDb3tcE8yF1Ieh6MH9DDWnI4/GwcoAO0jX0aTTu
         yxww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=y7gVA/W2G+TNPVD/LBhx6bIk+VfpnSmlEkM7U0qgJpk=;
        b=X5147R68UyNq4PCx1BtTcylwyV/Z9LpDtWYtHGETjsJz4+YGQgCVBoxq5+511G4qtl
         XoljsaRfRXd4fR6bu/XGoBxjZ4ogHUqYyL8UgUIFg5t1bobFmhvbc/wApTkbHwsOgSYP
         iUIOkUPpKpzmymuECoDykN+Gbex0xFXbUevK2/n1Btd6XmWI5YPso/biSE/xJ650xxWY
         0+fdj78yjJjZtWEkfHYhNs20kalk1SNR1KoIoB535cWRgWRrixDrdcMR6LMRlrm8uCEd
         d3ZQhMyF1NnXU11kbC6L2c3GH+7qySvr6atYMBrejP8XBQ2gYADGQV70hLwrBcF8dF8b
         Qzhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WYztO1KE;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y7gVA/W2G+TNPVD/LBhx6bIk+VfpnSmlEkM7U0qgJpk=;
        b=c3wRS8/R9SOzLgyaTfQmqW2tRGdhTeL1ZWO4TYupbMtJqCsAUuP11gdQJpRl8qJCXx
         cd5o2nuwOF/623hnAe69S9lQXh7QG6ijjASc7clpDX7c1yusrYZQbvrU89QuxGMpeWM1
         0EtqSfuzz+4ZIDG6+5GiG08Tk5y2kXkrvjB4umkVr9V4Dhb79heHVK37PslX0X/SMcjp
         8Rvb6+GWbqQ/Fr1FMfbSs2DuHGUAIe7iRR38pMTYBLCBR2u/+l1f8wpAHGtKTk2ySLx8
         1M88ChNxnWiulmwHcu6S246vnBFseXsyUSdtyn4GaIuFNRHPH0s8S+fDGU9ZHY7MJYoS
         orKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y7gVA/W2G+TNPVD/LBhx6bIk+VfpnSmlEkM7U0qgJpk=;
        b=DsDQ5t7Uf9Ke87MotmiF9RGI0LwUnIebDOWNKnvF+CBRfjMsEsH1gQAhYihP7UUYmW
         1RNcyboOxzjWHhVdkKgqckaNDNOrnriIoc859nxHJlRGGMIJRfq/tN0Y/JTnJRAvxe6L
         +vbFhBVrm9q/f3Viw5ELFWmulh2LqxeVSRrEEBBgVgF8fHH+INuE/w/K1+ujVURzveYO
         rt5g2m7aAoZbJLZsMox36Xwneazc/e4r2s8dnzZuaai5o4xbQx+qa1jJWu6Wl+dLKdtd
         id3lww9o/dJRtv7LvlHvZhsmn/vSXM0BD+KzBKu3pBfO0IOIS7vHt/jTnuGC8xbiYA58
         XmsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Vj8fT7D5gq7zmYAOMDq9hbT/LyLoSDaa61+qIkQlk7fIxfpTK
	eEhb+afepbP9fm7eXsdItB0=
X-Google-Smtp-Source: ABdhPJzVlMcS8kUHvR1DjhYvZmHUSKLJp2SqZG9X3TMfh1HHygKUWJMLS+xKCHMzLalCSvYVWoei5w==
X-Received: by 2002:aca:ac10:: with SMTP id v16mr5100996oie.133.1612442826629;
        Thu, 04 Feb 2021 04:47:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1391:: with SMTP id d17ls1303079otq.2.gmail; Thu,
 04 Feb 2021 04:47:06 -0800 (PST)
X-Received: by 2002:a05:6830:191:: with SMTP id q17mr5387677ota.110.1612442826302;
        Thu, 04 Feb 2021 04:47:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612442826; cv=none;
        d=google.com; s=arc-20160816;
        b=VtpIMJ2jOte70BQsJqggBeAFME/hmdjP1/4WgY+yftiQIlZb3QMVCnSsmdxgwGvUJT
         6At3I4s7eJQYtACSIv5y050Zm+QL34nAIhWrSttH9XHFvPcLtBZkmyQgmd2XvVYmZPeB
         8ozj63/OKiZ4CHSe2tHU4A2n+dGPKCJ/oRMXOTKJTFCptaAb/Zc1cjokK6PcCV7JFppU
         mstq/rad9p39JoHX3jhA1p5UznoFfDLZnu1gCxVsBBAr4E342b0zL2IM4N2OBUXDY3/S
         BheniZw2yaLgg9Gs14HxwOWD7Bgs+WGwhEE7CS55CFOCu9T0SGVxHK5CROL80Aw892rb
         8srA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AdUMwtaMvSvVxJnHSIonGJOHEuMlt00u3bZVIJwUUiU=;
        b=jjGlDqWBTkJeiFrCJM1mbBnesGMjFiz/P7ic1wQi/01ZAcXk1htcHQ8Ssbc/rLolKf
         6E6zqRpYq6p593MdiocN3TX71cpWefTjnCm+H7vNgmv8hxOPxvosAIrYzbNnWo1mD5p+
         V75Xbd+jqGphWFd60xKt4uH2/HgZhj11oUt/UTPYskMvLMnBwEVvcPEHpcJOjD0aSAsn
         cMCWKTeuzQuiHAY0767mOdhkKwXRwgC5rlUX7cUjP4Kv4U0OyRjl4ykruK0nRoroDYVn
         BqYBEFSnbYyZobAGidjYQg+Rv4FcAiqrckibSxbLfmhzVhsgaf4sl7uWkCSE4F8zWIhE
         9/hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WYztO1KE;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e184si458516oif.0.2021.02.04.04.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 04:47:06 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BCA6B64F53;
	Thu,  4 Feb 2021 12:47:01 +0000 (UTC)
Date: Thu, 4 Feb 2021 12:46:58 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	dan.j.williams@intel.com, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com,
	catalin.marinas@arm.com, ardb@kernel.org, andreyknvl@google.com,
	broonie@kernel.org, linux@roeck-us.net, rppt@kernel.org,
	tyhicks@linux.microsoft.com, robin.murphy@arm.com,
	vincenzo.frascino@arm.com, gustavoars@kernel.org,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: Re: [PATCH v2 2/4] arm64: kasan: abstract _text and _end to
 KERNEL_START/END
Message-ID: <20210204124658.GB20468@willie-the-truck>
References: <20210109103252.812517-1-lecopzer@gmail.com>
 <20210109103252.812517-3-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210109103252.812517-3-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WYztO1KE;       spf=pass
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

On Sat, Jan 09, 2021 at 06:32:50PM +0800, Lecopzer Chen wrote:
> Arm64 provide defined macro for KERNEL_START and KERNEL_END,
> thus replace them by the abstration instead of using _text and _end.
> 
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm64/mm/kasan_init.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 39b218a64279..fa8d7ece895d 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
>  	phys_addr_t pa_start, pa_end;
>  	u64 i;
>  
> -	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
> -	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
> +	kimg_shadow_start = (u64)kasan_mem_to_shadow(KERNEL_START) & PAGE_MASK;
> +	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_END));
>  
>  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
>  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> @@ -241,7 +241,7 @@ static void __init kasan_init_shadow(void)
>  	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
>  
>  	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
> -			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));
> +			   early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_START))));

To be honest, I think this whole line is pointless. We should be able to
pass NUMA_NO_NODE now that we're not abusing the vmemmap() allocator to
populate the shadow.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204124658.GB20468%40willie-the-truck.
