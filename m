Return-Path: <kasan-dev+bncBDN7FYMXXEORBJ5RVSDAMGQEEKT47IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 56ECD3AAFF3
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:40:57 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id a6-20020a1709027d86b02901019f88b046sf1534670plm.21
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:40:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623922856; cv=pass;
        d=google.com; s=arc-20160816;
        b=mp+bXNimr6jt4b1Dd+q+jxAQPdzTjmd5481wZSCFST6wWECMsxmymhPu9Gp0i1QcDO
         uQ2iXh3c+b2Xd5oTHnPhFIdmlfLQimI0jDjtgSVyTkY4nJNUAWuM0dxsPQX8cHWx1L+0
         doBPm50HV3vB+0bBwIxWTG1KxnBQfOytaao/thMIvDVTBLslG1CNPabKsRQkQoWuuCTC
         6ZLfoL1EEE2bBJdeqypS4AXF7kwHU08itVUSJXcGxHXbZ4LoscBt1uPBOBdEcdUm1nX1
         75wLdtLroxng/XqJwTZbz4ZWsnJuSBDIiD7D7yOd1U6M0s3iBnLH5/Qj8+Ta0aCZoddE
         MYlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:mime-version:in-reply-to
         :references:cc:to:subject:from:date:sender:dkim-signature
         :dkim-signature;
        bh=XIaQS8u+HXVFYYsFn1YV2bbvzXLUIuG1ScyVOxYvi7w=;
        b=y88Lq/4P9oOfrg2WGROrkxeEV3+vjLkHls1Ww29KPjYyclbgZty80aTCct7wRagc/w
         3XFhF9z6/j9KdXLHt1AOD6tPBi1Jh5GW69vFYdxcQb3F/M6EKOtlhLeLyXXp1C8+H9pO
         ZimPZyyPpVw01Vn1drWyORfLp19T2vp8rpSkUNC7Av8p8rBGxGGonGBUBRJJmrEahZmC
         BrPGVC93nVXHHGO6HTUIw6OF26QcUEot1W5GOT/b7iS9dv4twZ0rlaDRx4TqGlfhi62O
         1KdwrCUWYTtQXtfNzBOkTTvRwpJt1OD8W8itYbmcvVa0dSBNQrtVb/eCHrOVavjh0Vhe
         5oWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BrhlGOFi;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:subject:to:cc:references:in-reply-to:mime-version
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XIaQS8u+HXVFYYsFn1YV2bbvzXLUIuG1ScyVOxYvi7w=;
        b=V/mXiT5kmM3IvqZLCzJavpaty6YNNru8pGQ450aQOn4Eoc8gGrsdeI1xW9qxSABd4u
         pj458N+48WvGzer5EXUXgxRmv82ld5V3Mtwj7KLMpW91HwpIWH57Beb+X4YLyqdxNUh2
         LZDEZbscHo0Uuytf1CStnKbmahiBOuailh+Kl/MX8jT7G64QDovFgkSVx83W4AT/XnVG
         yeS9eP68dnF0Y+wFTXz2p5LXN34bAWJVWYNYCjcL9pAcTOucnE1BEKt/r4IgT0rM+WJK
         1ziRMH1b+3g9oDtoWqiQkepW50Nv31ckp7bYsTuV+w4OxCU3cx7/4jpfiLhIcKP/gBpZ
         6gHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:subject:to:cc:references:in-reply-to:mime-version
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XIaQS8u+HXVFYYsFn1YV2bbvzXLUIuG1ScyVOxYvi7w=;
        b=Zl+cqgAnmcXcQYbeDKz5iJ5xdVSHtmP10QxlLH67dUlVe3gP9WpE57RKhpXpZaLTyw
         lLaHygTpspWj6cLly7+eTqJqzNqFFPhnapYVsVeOmhM2BXH96gMLwGTBzjuvh1s8A5jd
         rkz65yDP46phVi79KtFm9/pKiBextH9Jw0DfX+KdfRvnOnpDvJeyXse3GCeSxqxC0rvD
         1Td/ZmrCOLPWAI/SYV4CyRt1Ew8Hg9P/Lc4QnuQVyDyg9knuEA4E9PkYOWcrPP8LA8sC
         p7XBZMrqIdLXJ/9qbESYuzFp34ALygsTQg00uZ0V7phw5A3H3g8K5/8vkldahupn9rnk
         ySUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:subject:to:cc:references
         :in-reply-to:mime-version:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XIaQS8u+HXVFYYsFn1YV2bbvzXLUIuG1ScyVOxYvi7w=;
        b=t0AXJBpNsKyDE2wD0XR6jgY2OPsfKGuThmPexqXxNlgjzQOCxcxgB7iQRfMwI1MgH7
         Nmxk9zTpaxkn1/PooFEpF2cv7Cj7e30xU+SdZDPUHAUpsPL5Wm8tV0/mbFMyE+BDysxP
         tFimH9CKv7nnf3WkPx/OVhnih52gfDbg3740W6I7ZOsX7gwXrDOiqFTFlT0RUTbEjJgx
         tjwAQu7delsJPwezd19V7tsLWG88S1jIGcTHgmMe6zX8a8XS42z94KC7qpwDfKFgK5ai
         SBnnlueyq69V3xSB0Pj/J7Y5vFkc297Bi/fYRehTEhJ5GlSYmjJ9I5euaiRb+4oMsCoT
         SaJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DqdK/5q1E6XppOR/mEn3S8hjxc68K1h6tdQTMB3Av25e8een4
	TKeSnQ1wRtSBID2ZrY1EY70=
X-Google-Smtp-Source: ABdhPJzoGAaRn8/yVuYw93DLklfKw1283xLpQh3dQ8K0z7FrhwmXzHhFyb3+RqYRqC6CX1jIaxBsew==
X-Received: by 2002:a17:903:188:b029:114:a132:1e9 with SMTP id z8-20020a1709030188b0290114a13201e9mr3743769plg.24.1623922856016;
        Thu, 17 Jun 2021 02:40:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8609:: with SMTP id f9ls2711511plo.5.gmail; Thu, 17
 Jun 2021 02:40:55 -0700 (PDT)
X-Received: by 2002:a17:902:a70e:b029:10d:3f69:dff4 with SMTP id w14-20020a170902a70eb029010d3f69dff4mr3727341plq.65.1623922855495;
        Thu, 17 Jun 2021 02:40:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623922855; cv=none;
        d=google.com; s=arc-20160816;
        b=T10xsmlmFD+rJfQsXj/EfHM7Zw4BW8Ur0mFJz6SAGiHCLh2Vgv7Tb2qBQKdSBlisdK
         a7r39x4znF7AYw0sfgbdG7Nb64nIE5Ca2m9iBlSzvlQBimTATiTtakGuV2PJo5C7RaUG
         HxExP3HxRFa3AvbZW/29scFHGzgYR7ZMNR8xa49gAk9gEPnUxFQXArpxi3ivv6xD128m
         Ogz5DXmPjwdmgx8Tk9wf3D0/SFRLRyOWoGYJTLNBNQIyS0DBp2aasIW8IOcFIRrHxcRz
         mNAGJOdDopz7VXSJQlclyjdAPm49DUKFISKyyjvpW+/mfIV7rdibOj8klEjqVgLOci2u
         CUJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:message-id:mime-version:in-reply-to
         :references:cc:to:subject:from:date:dkim-signature;
        bh=XjLNVS8FTx5mg1CNbMomnZVz+ZmOYcIpwKWpVxPSZ9w=;
        b=nApXexUDCBvsXUyOtuIlSA1fSROlPzCocMb421Fq0Rnl2PxKYlxJMLHlpP5DeFdeQS
         6R+opXpk+DYuHJGVvYR6gW575ktu78455QFVLIaeOC6Qp1FTq9lbeI5MP+6YZz91VqV2
         6KuQeZx3IU0c60ZC7ltLKzGd0/G2kgBE00doiiCum2oSyMWYfvlWT58U4XjsYBwVmJzJ
         b6C++b73BxmYVhPIg1oBtat6n+0IoVOhG4D8dCH57yL6D/0yK72MefqPJUPoMB+gIbpH
         xZ1ZFmdHNzo7Jy2/Phz1G3Ky7Wn5v007tb5otPIv8JVPANSKCHsaJlRTYSlDd9yr8E4v
         HEKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BrhlGOFi;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 67si219484pla.4.2021.06.17.02.40.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:40:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id 69so2632432plc.5
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 02:40:55 -0700 (PDT)
X-Received: by 2002:a17:903:2310:b029:109:e746:89a2 with SMTP id d16-20020a1709032310b0290109e74689a2mr3775750plh.8.1623922855231;
        Thu, 17 Jun 2021 02:40:55 -0700 (PDT)
Received: from localhost (60-242-147-73.tpgi.com.au. [60.242.147.73])
        by smtp.gmail.com with ESMTPSA id h8sm4506707pjf.7.2021.06.17.02.40.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 02:40:54 -0700 (PDT)
Date: Thu, 17 Jun 2021 19:40:49 +1000
From: Nicholas Piggin <npiggin@gmail.com>
Subject: Re: [PATCH] mm/vmalloc: unbreak kasan vmalloc support
To: akpm@linux-foundation.org, Daniel Axtens <dja@axtens.net>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>, David Gow <davidgow@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Uladzislau Rezki <urezki@gmail.com>
References: <20210617081330.98629-1-dja@axtens.net>
In-Reply-To: <20210617081330.98629-1-dja@axtens.net>
MIME-Version: 1.0
Message-Id: <1623922742.sam09kpmhp.astroid@bobo.none>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=BrhlGOFi;       spf=pass
 (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::629 as
 permitted sender) smtp.mailfrom=npiggin@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Excerpts from Daniel Axtens's message of June 17, 2021 6:13 pm:
> In commit 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings"),
> __vmalloc_node_range was changed such that __get_vm_area_node was no
> longer called with the requested/real size of the vmalloc allocation, but
> rather with a rounded-up size.
> 
> This means that __get_vm_area_node called kasan_unpoision_vmalloc() with
> a rounded up size rather than the real size. This led to it allowing
> access to too much memory and so missing vmalloc OOBs and failing the
> kasan kunit tests.
> 
> Pass the real size and the desired shift into __get_vm_area_node. This
> allows it to round up the size for the underlying allocators while
> still unpoisioning the correct quantity of shadow memory.
> 
> Adjust the other call-sites to pass in PAGE_SHIFT for the shift value.
> 
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: David Gow <davidgow@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=213335
> Fixes: 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings")

Thanks Daniel, good debugging.

Reviewed-by: Nicholas Piggin <npiggin@gmail.com>

> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  mm/vmalloc.c | 24 ++++++++++++++----------
>  1 file changed, 14 insertions(+), 10 deletions(-)
> 
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index aaad569e8963..3471cbeb083c 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2362,15 +2362,16 @@ static void clear_vm_uninitialized_flag(struct vm_struct *vm)
>  }
>  
>  static struct vm_struct *__get_vm_area_node(unsigned long size,
> -		unsigned long align, unsigned long flags, unsigned long start,
> -		unsigned long end, int node, gfp_t gfp_mask, const void *caller)
> +		unsigned long align, unsigned long shift, unsigned long flags,
> +		unsigned long start, unsigned long end, int node,
> +		gfp_t gfp_mask, const void *caller)
>  {
>  	struct vmap_area *va;
>  	struct vm_struct *area;
>  	unsigned long requested_size = size;
>  
>  	BUG_ON(in_interrupt());
> -	size = PAGE_ALIGN(size);
> +	size = ALIGN(size, 1ul << shift);
>  	if (unlikely(!size))
>  		return NULL;
>  
> @@ -2402,8 +2403,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
>  				       unsigned long start, unsigned long end,
>  				       const void *caller)
>  {
> -	return __get_vm_area_node(size, 1, flags, start, end, NUMA_NO_NODE,
> -				  GFP_KERNEL, caller);
> +	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
> +				  NUMA_NO_NODE, GFP_KERNEL, caller);
>  }
>  
>  /**
> @@ -2419,7 +2420,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
>   */
>  struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
>  {
> -	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
> +	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
> +				  VMALLOC_START, VMALLOC_END,
>  				  NUMA_NO_NODE, GFP_KERNEL,
>  				  __builtin_return_address(0));
>  }
> @@ -2427,7 +2429,8 @@ struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
>  struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
>  				const void *caller)
>  {
> -	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
> +	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
> +				  VMALLOC_START, VMALLOC_END,
>  				  NUMA_NO_NODE, GFP_KERNEL, caller);
>  }
>  
> @@ -2949,9 +2952,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	}
>  
>  again:
> -	size = PAGE_ALIGN(size);
> -	area = __get_vm_area_node(size, align, VM_ALLOC | VM_UNINITIALIZED |
> -				vm_flags, start, end, node, gfp_mask, caller);
> +	area = __get_vm_area_node(real_size, align, shift, VM_ALLOC |
> +				  VM_UNINITIALIZED | vm_flags, start, end, node,
> +				  gfp_mask, caller);
>  	if (!area) {
>  		warn_alloc(gfp_mask, NULL,
>  			"vmalloc error: size %lu, vm_struct allocation failed",
> @@ -2970,6 +2973,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	 */
>  	clear_vm_uninitialized_flag(area);
>  
> +	size = PAGE_ALIGN(size);
>  	kmemleak_vmalloc(area, size, gfp_mask);
>  
>  	return addr;
> -- 
> 2.30.2
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1623922742.sam09kpmhp.astroid%40bobo.none.
