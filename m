Return-Path: <kasan-dev+bncBD22BAF5REGBBFGAYC7QMGQEFAI4H3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B977A7C311
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 20:08:22 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-85db4460f5dsf433161639f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 11:08:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743790100; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rl3feNJygBZUmVD3z2pL2NERVYwldSmw12rjZsR/Qw9rSbnV22R160AayDEc1NM1Bx
         4ZT6S4cIBaSoxC0YBu5/AbXJr6oRYLa7YZ6Mf92MEu0yHRZVBh1W68OexCdkodwWn0C2
         saUNHBnTKoIdsySUV0Hdi35p1ZqLLKzCgAa+wzSEZkErylTQZyDKN5hdouiJbao83neX
         c+PQIVdbRZ2OCrCarUUIrvdxq01bixYPIvKIqOBVSoW1zakMgGDGTKN2uPbmVFks83fT
         wEPvJIv2yikwGi/a8ksJByKTVOoOU0sLqNsEQqxJa49jVAiZPGSJwsKGs4ppAJQIMcRX
         VNog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=Lack4SnstHjGPQJIC9PgyhWDvkJOdfuu5Le5hMxHBJA=;
        fh=PHmFOHa5L6HX2w5aL9MBI/cZ5dhrkRWaE7qJmtWCwWc=;
        b=SQ5+tEEyea2HiE1sOlXBu0j/AU4UuCAu7iXphefHQDQgmQ9e/aT472uCrTq4I3zOVl
         J2/XeoHzNTekxhytHMPLTP2Zx71NFB8qb9V5Yo5rUQOdL+P+2aLUGMZPB9jCUW90Ez+V
         YbCRHB9dKFDdfJd9pHcn6175/v+4sFs75itrqj8/OlEl9Jy3eIkyi3QV8V3Er+sfTfpF
         bfnjNBC+etB9BZ6FNZPNtm7wutAdB0SEYWXSin2nigw2VDvyn956KM9PrNjaeumv0uAA
         ohLxNvQ+FKN/uj5D9ZDzwNprfVgp6pLLDKngoeiaSToqg25X4LrEY+TO5Bif4LUbq45u
         03ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jLmSVK0m;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743790100; x=1744394900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Lack4SnstHjGPQJIC9PgyhWDvkJOdfuu5Le5hMxHBJA=;
        b=jGVR0xuKq23ehqxEi0JgCO7qhrLRvoT64e6XQNl+NAtKw7CgMdSYdjr08rymWy6YY5
         N2EA2/DW+9RpSJSxFXlC/6CI0oRC1riDWNlwNYkMcIrXoCmWA69R6vFxj4uSuvjI3bix
         jFUFEuYK+s9sg8d8Df7UrDMNDarOzMq3Nq644iFtRi1xrrRXjXemMAZwqDhmpdWhTu8g
         q62pZ2Z6T0rZ6NKO4saM/wLZkNKm7dUGQLY9TpYXvo5zL+S698a5/PTEX+d2hv+eGNgK
         uS+J9slSuO8IP4txXGvKhD92THrh8Y9wXsnyawUCk5ybGVVeJgpPzl7NAj+zOzCUFatq
         RFTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743790100; x=1744394900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Lack4SnstHjGPQJIC9PgyhWDvkJOdfuu5Le5hMxHBJA=;
        b=gB8cMbGpGLL283PMVXB8dSe6v118lflOZb7NupSF0OhVATe25p/FIuVTHlMH3Smm4x
         InvCt+LAO7ZjTw1a8QAe96h3bCcww8NZg7YeDMI4/QwnXuNpOuPdTT/Gjlgmx7E7hEuT
         GO6uDlM+G+W1Cwc8mvp6jWVLfR9zxSYNFqRz28PeLq94F9eklVqlc72AASMmLT4tCEVj
         fMAZl/hd+/OzxIpfDcXQd2dCWyzI1gx1/P8Dil/80wKNmEwLNDXCoDTJm/akOeEqK6BF
         UvsQdPSgqrFCCgOdBWtlF84jUb7w66RvJwb1FxewXATi+++t/BWpiNc8HS17yNONE8+k
         7YZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJYu6ABPeLCZdnOZYUSVYn4YD+SAqjLWN8HVLqprLbpx5dvtL9Af49n5XSZ+5LjhXDQ9S9Hw==@lfdr.de
X-Gm-Message-State: AOJu0YxDtPrdisx77ZqD3N98b2bpVU/PNroO65J075mVLAvzttBUfiyC
	kcf2o9WwAAZl2yTZIFy4ugZSaDxCusdyMYqDe5rkvIYbmKFyjN7Y
X-Google-Smtp-Source: AGHT+IEZnVEa141PDj2ACzJpvK+6U1L5PLrXUvSsBSssqD+KXSMzf10tegsNXy1DRdGQftSbolB7dw==
X-Received: by 2002:a05:6e02:1fcd:b0:3d4:35d3:87d3 with SMTP id e9e14a558f8ab-3d6e3ee192bmr52234055ab.4.1743790100650;
        Fri, 04 Apr 2025 11:08:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJSdF9hCYFDnlHxHCZRaeYnfRBH5seWw7eljPepdD6LJw==
Received: by 2002:a05:6e02:2610:b0:3d4:3543:15b7 with SMTP id
 e9e14a558f8ab-3d6dc8d8e19ls6731485ab.0.-pod-prod-05-us; Fri, 04 Apr 2025
 11:08:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnJ5IkgXQU0phl2oPQWpHRoHNXoOU0Yz5XFFkiFhgsb1RQPeBf1wSEyrNJ3XQjlQrKNNTqDVJK1+Y=@googlegroups.com
X-Received: by 2002:a05:6602:b82:b0:85b:43a3:66ad with SMTP id ca18e2360f4ac-8611b465418mr529176339f.8.1743790099929;
        Fri, 04 Apr 2025 11:08:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743790099; cv=none;
        d=google.com; s=arc-20240605;
        b=A9IJ08JgDAE7VvjwCtovhVUgJq6VDiIo3ppDlB+0n/m3SeCrU2JV9tJAm0nl6nQ0Fw
         0LIJEv/ooUUJHqTlzUbs3cyW1FttnzZev/icW4lLw0d8qm17iGoYBfAY7ilxJtYcr41I
         qqQFxxW1zTDFlbSgJ4H9gdITkOKMIo2fUiSaWuy2b9hBbOWkUAM4litc2kGzJbIQl3Ur
         OIzpOWm6wHVcn7mtyi8hkMvJfaYYcfi9FswvwFoDS5yUlpy1JjElz1kSaZccI2rsXe4a
         4cDK/i4Hjuo7h0ErLksDQBlBs7JdDaeFXNY6U4OewtInKATE3b/GF2OLJnEV6KbrHjXZ
         +wlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=yZYN6o5SIJaGPv7DJ8ETcSf2nZqQH2nOo4BGLBOH/SY=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=AvsaZ85XhK1oM1RycOQ9tj2ggs4F+mWM6fKOeHhU4ndeM/p+lZVM1KOGyBrBIXRGQW
         vODyjetXcaaRGoV08oGEcic80o5alrde9ibcBQjconlHSGeIfh3wxWoXU2ulFRQRYhWv
         ZosnskxMQ8fFXeftKRMl9dEMA972fjB8MsUZBFsjJth566lH+7xhfymiHoqyTtdckaza
         eymaotZ3MJAsHgRO4TZ+ijxNMPdX54R98wElKQcIN9l9omTIFvXD8P0wdCwbKHKxvJeO
         sVaIJj4CZSqNBhv6r4lFx/H/gXdJMDH8gs/DuTSvT60StjVl0Nz/NmtciIT4NXlQDo/V
         +6Aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jLmSVK0m;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f4b5c2e1e1si207841173.2.2025.04.04.11.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 11:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: HmzN9S+xQ8CgAothoKTX5A==
X-CSE-MsgGUID: pFbHyWXiQ8+gcX9aWYp5WQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55871723"
X-IronPort-AV: E=Sophos;i="6.15,189,1739865600"; 
   d="scan'208";a="55871723"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 11:08:18 -0700
X-CSE-ConnectionGUID: 2p8hjetBSImgAuDysM4x7Q==
X-CSE-MsgGUID: RysEYU0yQnqd7KpAb9OCrg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,189,1739865600"; 
   d="scan'208";a="158354509"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 11:08:14 -0700
Message-ID: <fb0d5f33-4636-4de0-82f4-93a9def63a26@intel.com>
Date: Fri, 4 Apr 2025 11:08:12 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 13/14] mm: Unpoison pcpu chunks with base address tag
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, hpa@zytor.com,
 hch@infradead.org, nick.desaulniers+lkml@gmail.com,
 kuan-ying.lee@canonical.com, masahiroy@kernel.org,
 samuel.holland@sifive.com, mingo@redhat.com, corbet@lwn.net,
 ryabinin.a.a@gmail.com, guoweikang.kernel@gmail.com, jpoimboe@kernel.org,
 ardb@kernel.org, vincenzo.frascino@arm.com, glider@google.com,
 kirill.shutemov@linux.intel.com, apopple@nvidia.com,
 samitolvanen@google.com, kaleshsingh@google.com, jgross@suse.com,
 andreyknvl@gmail.com, scott@os.amperecomputing.com, tony.luck@intel.com,
 dvyukov@google.com, pasha.tatashin@soleen.com, ziy@nvidia.com,
 broonie@kernel.org, gatlin.newhouse@gmail.com, jackmanb@google.com,
 wangkefeng.wang@huawei.com, thiago.bauermann@linaro.org, tglx@linutronix.de,
 kees@kernel.org, akpm@linux-foundation.org, jason.andryuk@amd.com,
 snovitoll@gmail.com, xin@zytor.com, jan.kiszka@siemens.com, bp@alien8.de,
 rppt@kernel.org, peterz@infradead.org, pankaj.gupta@amd.com,
 thuth@redhat.com, andriy.shevchenko@linux.intel.com,
 joel.granados@kernel.org, kbingham@kernel.org, nicolas@fjasle.eu,
 mark.rutland@arm.com, surenb@google.com, catalin.marinas@arm.com,
 morbo@google.com, justinstitt@google.com, ubizjak@gmail.com,
 jhubbard@nvidia.com, urezki@gmail.com, dave.hansen@linux.intel.com,
 bhe@redhat.com, luto@kernel.org, baohua@kernel.org, nathan@kernel.org,
 will@kernel.org, brgerst@gmail.com
Cc: llvm@lists.linux.dev, linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <61033ef5b70277039ceeb8f6173e8b3fbc271c08.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <61033ef5b70277039ceeb8f6173e8b3fbc271c08.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jLmSVK0m;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.9 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 4/4/25 06:14, Maciej Wieczor-Retman wrote:
> The problem presented here is related to NUMA systems and tag-based
> KASAN mode. Getting to it can be explained in the following points:
> 
> 	1. A new chunk is created with pcpu_create_chunk() and
> 	   vm_structs are allocated. On systems with one NUMA node only
> 	   one is allocated, but with more NUMA nodes at least a second
> 	   one will be allocated too.
> 
> 	2. chunk->base_addr is assigned the modified value of
> 	   vms[0]->addr and thus inherits the tag of this allocated
> 	   structure.
> 
> 	3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
> 	   executed which calculates per cpu pointers that correspond to
> 	   the vms structure addresses. The calculations are based on
> 	   adding an offset from a table to chunk->base_addr.
> 
> Here the problem presents itself since for addresses based on vms[1] and
> up, the tag will be different than the ones based on vms[0] (base_addr).
> The tag mismatch happens and an error is reported.
> 
> Unpoison all the vms[]->addr with the same tag to resolve the mismatch.

I think there's a bit too much superfluous information in there. For
instance, it's not important to talk about how or why there can be more
than one chunk, just say there _can_ be more than one.

	1. There can be more than one chunk
	2. The chunks are virtually contiguous
	3. Since they are virtually contiguous, the chunks are all
	   addressed from a single base address
	4. The base address has a tag
	5. The base address points at the first chunk and thus inherits
	   the tag of the first chunk
	6. The subsequent chunks will be accessed with the tag from the
	   first chunk
	7. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Right?

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 54481f8c30c5..bd033b2ba383 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -613,6 +613,13 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
>  		__kasan_poison_vmalloc(start, size);
>  }
>  
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
> +static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +	if (kasan_enabled())
> +		__kasan_unpoison_vmap_areas(vms, nr_vms);
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>  
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> @@ -637,6 +644,9 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
>  static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
>  { }
>  
> +static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{ }
> +
>  #endif /* CONFIG_KASAN_VMALLOC */
>  
>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 88d1c9dcb507..9496f256bc0f 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -582,6 +582,17 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
>  	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>  
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +	int area;
> +
> +	for (area = 0 ; area < nr_vms ; area++) {
> +		kasan_poison(vms[area]->addr, vms[area]->size,
> +			     arch_kasan_get_tag(vms[0]->addr), false);
> +		arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vms[0]->addr));
> +	}
> +}

-ENOCOMMENTS

>  #else /* CONFIG_KASAN_VMALLOC */
>  
>  int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 61981ee1c9d2..fbd56bf8aeb2 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4783,8 +4783,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>  	 */
>  	for (area = 0; area < nr_vms; area++)
> -		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
> -				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
> +		kasan_unpoison_vmap_areas(vms, nr_vms);
>  
>  	kfree(vas);
>  	return vms;

So, the right way to do this is refactor, first, then add your changes
after. This really wants to be two patches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fb0d5f33-4636-4de0-82f4-93a9def63a26%40intel.com.
