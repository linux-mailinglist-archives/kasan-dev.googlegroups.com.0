Return-Path: <kasan-dev+bncBCSL7B6LWYHBBKGG5DAAMGQELW5KODI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id F0295AAC8CF
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 16:56:41 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-441c96c1977sf17619565e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 07:56:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746543401; cv=pass;
        d=google.com; s=arc-20240605;
        b=d+vM9mCieCOhVEsoJ1e9NgJ3SaiKo2265+NCJm96WKK7C0mWQjj0co8sWs1DqZz3Ts
         sHGmcX8itZWr8J3HzfimLkWjI9TW7l5VyXuUDsoxzOxkBNXGw972jsoI8zV33y2mjOE9
         0JByFDl4aBRgBgcc9ZQMe+GTv3LfF0M/yUBP3yO+CV78oQL2HoX5SxqZrqPnuK9QyF21
         8Bft4KN2PInCAlsda/ZyYxPBb9D9S1RHElUyGwNx1Zm3y1S+f4f9GvWUBsy86Y14zwkb
         kL/K4VXuUwV/Y4jssRon6YdwBMV1TBUL4ockZ942/k8/sgzq/VS0DPfmhJ/pqrBzZ2KE
         QwFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=MudJNd8qwt+CPUWG+2CMz93E8lVhLSt9qfu+Hom+LrE=;
        fh=/2npQCx6gUynsz5gAKjfE2dCHD3SHvEYnyD5MtHxJL0=;
        b=D83Oc9Vi3HMUzA9WMkCYNlscAYpno3Nt8KtDuz8Mt6/XJeUlZ/Og2Eq9KUKAuWPOil
         bRWZ/SIxui11ggihYMGjwBdjfErMLJjAwc3jWHkSmhLp+VQI13aCrPTUpcHj4WQ5ds07
         wXD920iLO3dWaxAGxvQmCbP1jVk6FlMpO0K3Wh1bsYa8JCOeySkYszHb/11v6gpNAxYs
         puox6xD2Mfl5UQe3SHLhBtxZi2p7ri9yC0n/rUZMKHWYvvwl6ta5ujEKwYQe8xJnJ51B
         7LAw5wbYKTvOHSj6qGYtGeidF9QRPXnoFk/GqpBnAJVNvEF5TI51d9R0UlIXkyJD+piv
         N5ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HWLawBOz;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746543401; x=1747148201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MudJNd8qwt+CPUWG+2CMz93E8lVhLSt9qfu+Hom+LrE=;
        b=w/1c494LPt9fPCIpN2TLfX9sDMBzMAnHs9djZJsjKRTEuRFKIvMdRC8A5x8yJDLYQS
         yaSpuvb54vzsaEYCnaYkP/7Oq/vDCO+My++8eW6K6Ydttl+J53ZYrlO5sKyviRVybZlz
         IChL7cw72kq2kJFot5Z4SH8NXofm91Kp63hdUOBTuvrhEHKJHT15t9eBbC4AzlhxSc+s
         QFPs4deQWgvpzU5ck9iRvdRrHZFm1HCNCqFXwaQD6FuoKs8zjYqN+HcWgbJVQHb5NDrs
         Hnq9ujscodzE/6ufls6Gj/Wagh64S81YcvCFYz+epN2vefeqdY8thI/znAyzE3hOsfY7
         j3bQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1746543401; x=1747148201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MudJNd8qwt+CPUWG+2CMz93E8lVhLSt9qfu+Hom+LrE=;
        b=DKnxgiGbz//gwHOc3G6/4p8zkjdt8yyJOmjRVKA8pSrzuZCF32fP0lcOBsX+ExvasU
         h0lNNFYoeukr21GhMhyaQrbCYeH3p3cwSX+TELF4rLkXhCpGyg1b++cDcY60AFtas+NX
         cuoVArpb3zaE1Vvg0eSP+/9OuVET03R7hKoLnsf5cfG3TOjyOWRMy2Kpnm/TIhW2P/XJ
         CG5cPqCgocg02nS/Nz8AtqrahJDsM/vhNSRVVb79GSKSyWw2ATkZz/Q8SITPRTgobMBZ
         ktPxj21vFhiJ8JV2H0p8B65UTZRxv5pvxBE5tsSx+ErFYKrwdtPM9tMgHhzjyd7A2TmK
         Ycig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746543401; x=1747148201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MudJNd8qwt+CPUWG+2CMz93E8lVhLSt9qfu+Hom+LrE=;
        b=ikbhCUQxnBnKdivpxae1rFzHxMg43WFnmkqF4cfH+spdoXURnNH5GxZFT6dcOqIadh
         erC6efcB/OY6hWBgA2xWfLGRuawY3WBYxRQcksjFwekVc164WtpJBiU0RPGeYbTMm/T0
         oWkOrqCbcnYdvH8kITi2pxAkzON0tTYYjfRVYvDVnrlPEMDzkRGMRDhkklGL3cBn1nro
         QZJBtP+A9CSF/yGunaJJqTm8qfel2KbvOYNYvh6669Q4AcdKl2SpA7+VY9VGALEtq5I0
         Hn3E5sxOQzKRlGygLA0sasEQxTpofQQTf9k2zoONoGiKYd9Zy+fI/RHWG0yqBNTyCisl
         dqxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXMy5iOcJhNs5mse2iDmqsLLooMpgl79OfcEIZSZhUf+bemAa7vtm862peaNUip1+pO1MX8bA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1mWz3nHcYA35o4agfBua0+MUfHvSEODURrI7x8cXNqZvmOqxr
	odcWnn1vtlFzahevy2JUGdthd0T42P0lzYaYlyjkAMNA1WVZT2zc
X-Google-Smtp-Source: AGHT+IHiLnFXvwCx8bmz3vPeEByBgoFLPzLn55Q0GP453UT43DAVrKplegWQY8CGPKRmKf4TZF0vKw==
X-Received: by 2002:a05:6000:22c7:b0:3a0:8098:b6c with SMTP id ffacd0b85a97d-3a0ac0d96d1mr2837957f8f.14.1746543400675;
        Tue, 06 May 2025 07:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEAtDgzoMRL5ytF5tbG4aH9citS0svISLj5bH3/cJxVvg==
Received: by 2002:a05:600c:1c8c:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-441b5c8f03als2879165e9.1.-pod-prod-05-eu; Tue, 06 May 2025
 07:56:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPufe/8GvhxPpIrPLiW2+yiADGX75xKrU6/DGmQjggLahmB6hReynHwZmJzpEQZfhLldWlbmq879s=@googlegroups.com
X-Received: by 2002:a05:600c:35cb:b0:43c:e481:3353 with SMTP id 5b1f17b1804b1-441d0524b5bmr36926275e9.17.1746543397628;
        Tue, 06 May 2025 07:56:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746543397; cv=none;
        d=google.com; s=arc-20240605;
        b=ElThPfGUgrwU4wL7H7lAXNV2TnXejXElhLsmNAJGGfCCHfSy0DyZfbAPTxW4kVGNc6
         HjvJzbMb5R37aajsOh5iuKj1fvwocPQKTkIZf/tNcOTwd+asYrkRzxIOskfRlHaW0uzA
         TX2+KshpJq/8HxmsQH414uOua24pwn1WqqIEFFhJulWxjngtR+j94Nz6RkF6uEhe5OJj
         FF9bMUCIeaDCeEl3OoaVJKBL3Xc91GpsxXQs0xO/WtVrLYWKNNpNrPG0WoV1DeIgYdIN
         58M2QAshB3o2+jyIqjEZ9BH1go3TP3/INuPcP/KscFDMapJgi6rhtrd6k1kh5ycR6Gej
         P7Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=zGl6sg7j0zxSLThVkHoNmDxdriQ/RPO7fP3JuwQs5eI=;
        fh=M+FQNWt5uoMjH2dmUo+Ab5PzK1kyZnl2JJmYTrsLTgk=;
        b=CFRa0euBMkQAme5aIISjQ1XcEeVkzQ/4FzpMD5MJ5rWWOcUCpTX+tFuRGgGIvR8Urz
         mp1BKBiFMGgwE9zUCZ6s02usfwUUump1JMm1aE6loJ/0vYMPzncNQv50T8VYMku1ntzx
         tV6vWy9HOHcze8ajijFFe3Y6AZxfxlQXNe4hBYcaWo5/B12kGsCBfKgfaer31tKWBUVg
         01UYpP//MWH0A6xdzomHzYX0/VUfxOXduaSs9oRHansT5Zfip3rzOEi/nStxt6yg5BG/
         HbU8FqdEKfPEjH9OkbKS3M8be81P4u48dDTQTyqdDv4HPHo9vBJZr+OdZ+9kQE5UKwCW
         tBkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HWLawBOz;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441b2afa812si3085025e9.2.2025.05.06.07.56.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 May 2025 07:56:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-5499af0cecdso780844e87.2
        for <kasan-dev@googlegroups.com>; Tue, 06 May 2025 07:56:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX51uR5BZyTLgHBLflg+M6Pi7yIAOE2TL84X/WXCbL1/5xM4nByZEK5F1QecWk/UeB1GkzlbPL1Mjc=@googlegroups.com
X-Gm-Gg: ASbGncshYk1WFKamXOAPpRJHwvInNIi7bNw+NpuDDJmLyoXPPOVzLUyzjuZcafnqvPg
	fywC626hzyx82CvSXhm5OcPNpwXlHElG5Ij+qtF89xCiW0XvlJ1KYZtkFn8EuFM8Pm2+uHbw1Um
	CKz5nOBMdl+JrPIwhpw1qG+hrcAowVJpKrFz/s28ihZS6ZedAS5cpJAndSU1Ym47rgrXT4GQVKG
	5WBht1CIX8rteOmPzuLGD7eDiTrfe/UjimuEWLu9jh8VeoIJozDdHOPrSOgI4dLVDQ27vdI5R2g
	jRVTFoBbeedDy/DTnFC2jf0oswRL/ZWeSxmvxnqxfBiKFsY=
X-Received: by 2002:a05:6512:159a:b0:549:8f39:3e63 with SMTP id 2adb3069b0e04-54eac20dcbdmr1776226e87.9.1746543396571;
        Tue, 06 May 2025 07:56:36 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-54ea94b16b6sm2071820e87.12.2025.05.06.07.56.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 May 2025 07:56:35 -0700 (PDT)
Message-ID: <d77f4afd-5d4e-4bd0-9c83-126e8ef5c4ed@gmail.com>
Date: Tue, 6 May 2025 16:55:20 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from atomic
 context
To: Alexander Gordeev <agordeev@linux.ibm.com>,
 Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Daniel Axtens
 <dja@axtens.net>, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
 stable@vger.kernel.org
References: <cover.1745940843.git.agordeev@linux.ibm.com>
 <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
 <aBFbCP9TqNN0bGpB@harry>
 <aBoGFr5EaHFfxuON@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <aBoGFr5EaHFfxuON@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HWLawBOz;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 5/6/25 2:52 PM, Alexander Gordeev wrote:
> On Wed, Apr 30, 2025 at 08:04:40AM +0900, Harry Yoo wrote:
> 

>>>  
>>> +struct vmalloc_populate_data {
>>> +	unsigned long start;
>>> +	struct page **pages;
>>> +};
>>> +
>>>  static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>>> -				      void *unused)
>>> +				      void *_data)
>>>  {
>>> -	unsigned long page;
>>> +	struct vmalloc_populate_data *data = _data;
>>> +	struct page *page;
>>> +	unsigned long pfn;
>>>  	pte_t pte;
>>>  
>>>  	if (likely(!pte_none(ptep_get(ptep))))
>>>  		return 0;
>>>  
>>> -	page = __get_free_page(GFP_KERNEL);
>>> -	if (!page)
>>> -		return -ENOMEM;
>>> -
>>> -	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
>>> -	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
>>> +	page = data->pages[PFN_DOWN(addr - data->start)];
>>> +	pfn = page_to_pfn(page);
>>> +	__memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
>>> +	pte = pfn_pte(pfn, PAGE_KERNEL);
>>>  
>>>  	spin_lock(&init_mm.page_table_lock);
>>> -	if (likely(pte_none(ptep_get(ptep)))) {
>>> +	if (likely(pte_none(ptep_get(ptep))))
>>>  		set_pte_at(&init_mm, addr, ptep, pte);
>>> -		page = 0;
>>
>> With this patch, now if the pte is already set, the page is leaked?
> 
> Yes. But currently it is leaked for previously allocated pages anyway,
> so no change in behaviour (unless I misread the code).

Current code doesn't even allocate page if pte set, and if set pte discovered only after
taking spinlock, the page will be freed, not leaked.

Whereas, this patch leaks page for every single !pte_none case. This will build up over time
as long as vmalloc called.

> 
>> Should we set data->pages[PFN_DOWN(addr - data->start)] = NULL 
>> and free non-null elements later in __kasan_populate_vmalloc()?
> 
> Should the allocation fail on boot, the kernel would not fly anyway.

This is not boot code, it's called from vmalloc() code path.

> If for whatever reason we want to free, that should be a follow-up
> change, as far as I am concerned.
> 
We want to free it, because we don't want unbound memory leak.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d77f4afd-5d4e-4bd0-9c83-126e8ef5c4ed%40gmail.com.
