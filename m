Return-Path: <kasan-dev+bncBDZMFEH3WYFBBOU763CAMGQEAF4JBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id A395DB25D28
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 09:26:52 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-321cfa79cb3sf1545285a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 00:26:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755156411; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qo7BOwPxdn+bqREdzmJ1lnfSa4d7zhdaOn/SdoazTC7EU9MXiENuxZGW7zdY4eV6bI
         sqbZonRca1LdewKW0bt5xPvj2yLAOvS8vbJEvfXj+fPdCioPymCKoTfyG8i5R55GOKLT
         b41W6KdCcbObmkie3Yy9LykVLVU4fp8IZkQOJXmklhfUovFrQ3ALgbqYGeTyX2QOx9rO
         wY0/rm0QZM9bDuLLfiwpJZj7hnXw81MpnrHCP+yll4XkokIP2ExUD77DKwsjCNBqw61H
         rVQTPZNip+LeDT/1L2MnEgIBU1SVAwMDshOFy5BIesXIgL5paKSXWbM1MJ1bZKtg8GCv
         D30g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Mfpn+xC6H5iVlOlXGNKNEPxQt/GXKM8BvTQZTPX4iV0=;
        fh=sF4hvq5t44zROtJZtyeUg0S8n6x1+gSlq+ffrmzqKp8=;
        b=LH3aBLSfS7cmMGlPqamAYCdkLoIIO9EI9RMuw69HxXipLj5NNhzNg1ZQF4htmjkGBy
         vf/SDCjOKRekyL8iXIO7LjqgZLkJQCf5M3GTK3XvBmxcLl7C9HLbmZV84bfvbMThnMU6
         TcLMvTUSJbYgVjilts9mdw+EIKtH+3Y5SHyzzUK9L9xx1w+l0XuUW09Uul8UACQiGzBp
         hnTvXi2PRQ5/6KgsQDvXdycdJzdv4nZiMRmNYO+kpuVgfi4S6L+bZNNb2NFLW+yjQpww
         H4F8X0aEVBRetRgaljyo3EXy0ST88+XscCqr6wIo529kYLLxnUIJyXC3Qx2leG+QvDDC
         APZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R6qffIlo;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755156411; x=1755761211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Mfpn+xC6H5iVlOlXGNKNEPxQt/GXKM8BvTQZTPX4iV0=;
        b=LSBN1pJgRLpK7r2MUanFUiph9osXuq3cH9KQNvqulpKiLm2dan+ss1UMYG7rVcFiJ7
         xwjPPReHkov/K6NYSgNW1mJRDV/oHi8fDXMC15zS8y0hC/SekWK+cSKY5oOzaK0vdwgr
         FCyaZCro4qVKqwQduvxV6hoe0RX+gSg4FDvc7mrVCi4wMeivWpE7/YCAlwTXvIIKchmK
         XTeRLzeJEKV9wVyw3m8jJPXuvK3Ok1R3JtXjKXMJcnJnh1KXquN1HqG3D2C8RjjxkmyW
         nBIf/1Ulya4rfHT8+IJ1F8g+QLuIhHijNjZ264VY44ANGjOxifaAvslZIywSovmMP8Ok
         gdog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755156411; x=1755761211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Mfpn+xC6H5iVlOlXGNKNEPxQt/GXKM8BvTQZTPX4iV0=;
        b=tAGsefjrinhiCHH66CMBQFuEQT3GFDOsuFj4QbHL+oecqYYaEVnfq3thKwdxVkXn22
         +c6IsgsMCooGAocGnx1ExTl5gIFJnjf/DK6w7mjeJv5WqpaRW1+QEIddZe3124gJYMGp
         TogdgMjjlSfE12/vw8gt8HGHsG8Us3iLDwLz9vSas32QuQGysXhMW3INhLNJ7f5J5J1N
         KQ7Rm5iVZP3GqmPBUQ9J88CzKW9iaqhdFR0gAzZIdnxebapZlVERxfBPGrt3VGysRnvz
         dfvs54tjh7AkPPhVmOq+DmMi+DsHcBnEFqlwt2IjWVVWtn84tSjgptJO7MQQhT6p9Imx
         j9BQ==
X-Forwarded-Encrypted: i=2; AJvYcCXpuvdvUoYWHJ4mlTPNDiOxGIdKYnV5qT5AIUdm5SJ/axW+goKhtSGdoraBD0uV9nwlhrFpsA==@lfdr.de
X-Gm-Message-State: AOJu0YzULhCC1Hs4PNJrOmqZUYw57jS76p0z9sa4RXowy+CdxS/IpAMD
	/zYzhqSg1t7RpPyevwi+dYsANLrjhOmFlLP7wwOZZiJpNsDmC4wUJ6xD
X-Google-Smtp-Source: AGHT+IHVIRezybP/JanmLv7MEgGBlqN3SV//d+j3U1AQVTNMk3nS4C8OF8nU1xOGIUoGwCDamRGvEg==
X-Received: by 2002:a17:903:1a6f:b0:240:72d8:96fa with SMTP id d9443c01a7336-244598013ebmr27379935ad.20.1755156410970;
        Thu, 14 Aug 2025 00:26:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc1H8VqdkDiP5J7jfX8WFZDzbE0Om7icaVK3y6BvVVjzA==
Received: by 2002:a17:90b:508c:b0:30c:4d44:cf23 with SMTP id
 98e67ed59e1d1-321cfb7ebebls690725a91.1.-pod-prod-00-us-canary; Thu, 14 Aug
 2025 00:26:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxgBXDvwBaoVg2zz/PSIO4cJrwDV+R9WMIIcs++CJyEEGwNL/1HPmt5YwquHBOr2P5MotbM8xVKk0=@googlegroups.com
X-Received: by 2002:a05:6a20:2587:b0:23f:f729:2e72 with SMTP id adf61e73a8af0-240bdf49d66mr2758739637.1.1755156409564;
        Thu, 14 Aug 2025 00:26:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755156409; cv=none;
        d=google.com; s=arc-20240605;
        b=aQ6VlP2zOQhcp3r9MiSfZF5pOPU8vbN5o6rNOGzj8X+4Xj7XaOcyMCvdOxNgHdMAd8
         8noO6MEE4K6s4tGFd2C3elJY3f4fArRxNJEFDFskmpLB7ZSWdcpUvXjtcXb3w8jkEHId
         MS4KA/knLeGqN6Q9hWQGTYg3Nw7gtqEWp4d9L5LCEavOHSpPJshO/kApBMuc+FGDXxZD
         Ie1dFgsxX9Q0BedtOyqNBBsnFrnl+R8hUKhmQUUTMcZj/B3pgzysrX3BNLtCQZCjw3L9
         7Vje2r2KiSVwVWKRsLyAkEBSDiQ1FkupriJecHrbFH352/4WmiSaEViEdNu1AjEETFIt
         PEHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CfApIHI972kWbSR3U0B1BpYQYv1HxE5zGDXKDQ24uLE=;
        fh=An29kc1fWHUbq+trOJowZZoCiDy+Kj7isCjoanY75Zw=;
        b=UerDAmUO/OQPhLradw/ZULooOXfQemHvzD6b5aWzekJ2xn1ZorbhRPEGiBzfEy6OMq
         QQIPG/p3v76sRaB8pR9WrKbW9rbDsuXj8zT43yrDYZs+7to7idKUcDl0XS3ebEQ+kX8n
         91hgFKkws/knhidJ3LSCslX/lhBh1YtPpoCr+3p56aIikoLIJhkV+X+MEFFNtKfOVspz
         dyR4huXyKgmAy8PFUgpO4sjj+6+5FGMuKK+FNyW/AY48R8siPJv3Lby9ESjFpTZg0mWV
         P8vh5Y/H+eS7VcJT/DnEgE6CD/b0MVCLBMlU/q9zx3uE4JBwjIQL88P8fTuNs1MyayPl
         3R4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R6qffIlo;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76c626c5c3esi520834b3a.6.2025.08.14.00.26.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 00:26:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3F07043F72;
	Thu, 14 Aug 2025 07:26:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D3D17C4CEEF;
	Thu, 14 Aug 2025 07:26:23 +0000 (UTC)
Date: Thu, 14 Aug 2025 10:26:19 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
	Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
	kaleshsingh@google.com, leitao@debian.org, coxu@redhat.com,
	surenb@google.com, akpm@linux-foundation.org, luto@kernel.org,
	jpoimboe@kernel.org, changyuanl@google.com, hpa@zytor.com,
	dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
	vincenzo.frascino@arm.com, smostafa@google.com,
	nick.desaulniers+lkml@gmail.com, morbo@google.com,
	andreyknvl@gmail.com, alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org, catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com, jan.kiszka@siemens.com, jbohac@suse.cz,
	dan.j.williams@intel.com, joel.granados@kernel.org,
	baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
	pcc@google.com, andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org, bp@alien8.de, ada.coupriediaz@arm.com,
	xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
	glider@google.com, jgross@suse.com, kees@kernel.org,
	jhubbard@nvidia.com, joey.gouly@arm.com, ardb@kernel.org,
	thuth@redhat.com, pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de,
	lorenzo.stoakes@oracle.com, jason.andryuk@amd.com, david@redhat.com,
	graf@amazon.com, wangkefeng.wang@huawei.com, ziy@nvidia.com,
	mark.rutland@arm.com, dave.hansen@linux.intel.com,
	samuel.holland@sifive.com, kbingham@kernel.org,
	trintaeoitogc@gmail.com, scott@os.amperecomputing.com,
	justinstitt@google.com, kuan-ying.lee@canonical.com, maz@kernel.org,
	tglx@linutronix.de, samitolvanen@google.com, mhocko@suse.com,
	nunodasneves@linux.microsoft.com, brgerst@gmail.com,
	willy@infradead.org, ubizjak@gmail.com, peterz@infradead.org,
	mingo@redhat.com, sohil.mehta@intel.com, linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	x86@kernel.org, llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 07/18] mm: x86: Untag addresses in EXECMEM_ROX related
 pointer arithmetic
Message-ID: <aJ2Pm2XzcM3H4aTN@kernel.org>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <aa501a8133ee0f336dc9f905fdc3453d964109ed.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aa501a8133ee0f336dc9f905fdc3453d964109ed.1755004923.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R6qffIlo;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Tue, Aug 12, 2025 at 03:23:43PM +0200, Maciej Wieczor-Retman wrote:
> ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
> Related code has multiple spots where page virtual addresses end up used
> as arguments in arithmetic operations. Combined with enabled tag-based
> KASAN it can result in pointers that don't point where they should or
> logical operations not giving expected results.
> 
> vm_reset_perms() calculates range's start and end addresses using min()
> and max() functions. To do that it compares pointers but some are not
> tagged - addr variable is, start and end variables aren't.
> 
> within() and within_range() can receive tagged addresses which get
> compared to untagged start and end variables.
> 
> Reset tags in addresses used as function arguments in min(), max(),
> within() and within_range().
> 
> execmem_cache_add() adds tagged pointers to a maple tree structure,
> which then are incorrectly compared when walking the tree. That results
> in different pointers being returned later and page permission violation
> errors panicking the kernel.
> 
> Reset tag of the address range inserted into the maple tree inside
> execmem_cache_add().
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Add patch to the series.
> 
>  arch/x86/mm/pat/set_memory.c | 1 +
>  mm/execmem.c                 | 4 +++-
>  mm/vmalloc.c                 | 4 ++--
>  3 files changed, 6 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/x86/mm/pat/set_memory.c b/arch/x86/mm/pat/set_memory.c
> index 8834c76f91c9..1f14a1297db0 100644
> --- a/arch/x86/mm/pat/set_memory.c
> +++ b/arch/x86/mm/pat/set_memory.c
> @@ -222,6 +222,7 @@ static inline void cpa_inc_lp_preserved(int level) { }
>  static inline int
>  within(unsigned long addr, unsigned long start, unsigned long end)
>  {
> +	addr = (unsigned long)kasan_reset_tag((void *)addr);
>  	return addr >= start && addr < end;
>  }
>  
> diff --git a/mm/execmem.c b/mm/execmem.c
> index 0822305413ec..743fa4a8c069 100644
> --- a/mm/execmem.c
> +++ b/mm/execmem.c
> @@ -191,6 +191,8 @@ static int execmem_cache_add_locked(void *ptr, size_t size, gfp_t gfp_mask)
>  	unsigned long lower, upper;
>  	void *area = NULL;
>  
> +	addr = arch_kasan_reset_tag(addr);

Shouldn't this use kasan_reset_tag()?
And the calls below as well?

Also this can be done when addr is initialized 

> +
>  	lower = addr;
>  	upper = addr + size - 1;
>  
> @@ -216,7 +218,7 @@ static int execmem_cache_add(void *ptr, size_t size, gfp_t gfp_mask)
>  static bool within_range(struct execmem_range *range, struct ma_state *mas,
>  			 size_t size)
>  {
> -	unsigned long addr = mas->index;
> +	unsigned long addr = arch_kasan_reset_tag(mas->index);

AFAIU, we use plain address without the tag as an index in
execmem_cache_add(), so here mas->index will be a plain address as well
  
>  	if (addr >= range->start && addr + size < range->end)
>  		return true;
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 6dbcdceecae1..83d666e4837a 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3328,8 +3328,8 @@ static void vm_reset_perms(struct vm_struct *area)
>  			unsigned long page_size;
>  
>  			page_size = PAGE_SIZE << page_order;
> -			start = min(addr, start);
> -			end = max(addr + page_size, end);
> +			start = min((unsigned long)arch_kasan_reset_tag(addr), start);
> +			end = max((unsigned long)arch_kasan_reset_tag(addr) + page_size, end);
>  			flush_dmap = 1;
>  		}
>  	}
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJ2Pm2XzcM3H4aTN%40kernel.org.
