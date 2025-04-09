Return-Path: <kasan-dev+bncBCSL7B6LWYHBBSEV3K7QMGQEFGFKONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D350A828F7
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 16:57:14 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43cf44b66f7sf57499515e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 07:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744210634; cv=pass;
        d=google.com; s=arc-20240605;
        b=TMR02/IFXnJQQaUGz0g0LF7T0my3oIYDrL2f4Okrcgw7dDq8ZiwBrbSqNDD8UvBk3k
         sGRl9Ct0X1fOU0N3UlNn0KS0yLCoZW0AvDkyxnramoCGCn6MyAZvOCb5pxiBNO8uanv8
         QTgtlc+g6Y2PFYcEUyJUKoOehiKXl1UJMBvJI9tdx3uMMsSnB+Yx+W8jFBgxBb6MRrNR
         3WWovDDCZ/5bHzNXSrOafton4WtlRDzjjNuIlKj+WNqQw5J2mvNbhqqG7wflQH7xztKA
         PinpqGbrFojdqEWRhCfzeDOlKTpojYIeBBY+7W7uOcF2aRT5Emo3Eu3NxjXSXlE7/8WH
         kiTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=MryfFqUSAJkki33ipuYg1ZnfeCwDsIQD4QNvmfZQAYs=;
        fh=WRAEeoI7zoguN01A9rkekwup64JMH6LurTp4E2vPX60=;
        b=T3qNnuzAN0kGb7Q4ptexGPF+vDaXxKkZzIv3peBcs09EnHBIE1BEEtR1segfptz/jy
         lfbs1HG1REYqIHqIIa0zgjOKJkjUHD2BBaqZtzSWV5cGmVFJ8lM6h4NExBqXI0yIHx0V
         dKVVfOJd49G7StrhQ7QclYX7tYdV0mN2VlcALv8MteOsWx4g3aCSKivTzxmp7weZQPDn
         AbUPpB+G6rQnIom+aAKjJJE+TmHjG+bIG8E/Bs3LH7ypSJKgm7v8QTIEhIEETVFj6i/9
         cRtITLSp5hV5/Vk6HuVNiwOcrevYrYqKwFM0GfqCtqV3qRSzXV2Nbo/7jflvHTJqys/2
         pHDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Dc1PHabK;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744210634; x=1744815434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MryfFqUSAJkki33ipuYg1ZnfeCwDsIQD4QNvmfZQAYs=;
        b=U5wAs7HXJBT57/AGY9fsBh6Bk1hWBj+L3ThB4g32m5n8pETED3Gfo65NXplbP1BkGJ
         3C8VG2kbFEsWWZFHWEt6ELOsHLx1CmLi8CtemcsDTTzQGXXj8tbWd5L3Im3EMwCkDBCK
         42OBHgfnwXd8OPh3jHaZq+eLjWUP8TbGlidb3Oh80s5AdZbkIYU3QTANjsFDDduQ5lWk
         yyQOMnYQahfK89vuv3TMvaT625tpiGki32RmvOqL72aGQSwAFoeU7QPQYQssPOC/qzEy
         L2sbJ6Ua3KGHIM8oxZKErMjlAAofbylcUcNJUavGmFlcRUzPrFRkgKolXaWThejnB+Ej
         xyyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744210634; x=1744815434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MryfFqUSAJkki33ipuYg1ZnfeCwDsIQD4QNvmfZQAYs=;
        b=R8onyy+fHYEjFyVpAtB9KD4Jgyc3BDKQUBPz7yuYM9ZCwwKUw3GGJJ4UhcPRcREp92
         QCLxA0zUVXN2x33G62xy32jPTGIL2VvKISaVvUvFHuD+V3sI6rJYRcz1F7vG+k18GxVU
         ZtFo8OyjxBSb0bv3eaL2hiM7I4PYYSWNuBTQCBI9wdvEeOTSmbrJLWaK7DbhTN94XiiC
         rp5/8kkmVlLB614ZuKx7/UMA+OIP+4Nr/azAuB2OMv8jOlTyymjGI860y8ADQZ9XfJ3e
         y58Z/MFceO2X3TTuKqg6rQs0Agnf21XLIKXEHBuwaLx2wIOEGzCTDTf41LZZSx22FNZV
         T+Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744210634; x=1744815434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MryfFqUSAJkki33ipuYg1ZnfeCwDsIQD4QNvmfZQAYs=;
        b=ev7yO+C0EMJ7R16W5PmrGOMBxuKqXZXpkNeTHCuSWddw4YDew2JOucD42ytDfkzab0
         7Mogu1G0+CGyP5u0JxQjao32sqIhi5QxEKUCVH0IaucnZr54mme8sUVsibIcw9cvwjqB
         iKb7tAT7FI0IRZtX6OSD5VSOXYSZIRLHcLv/pj6qMlCUqsOBbSRN7SxjtR/P4sg4PXMR
         4MH637T/hAsoTzcGtbsnezTeniVDbFU8klK1hpjHGaeITo27vDE9eb9yynoLCsnIMo4i
         EU2m9U0Necc2mZ/hQsz7Xz0JVQ3X+xSjWV/8EYMguRuvl42wkx1QzzSKR6JClxBvGFpX
         tnHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrJ2FdOu15e0snbh8JihkqNTQif5z1i48pcaOp68lRXzZEorD9Fhn4i4F28uOywnNUKUcQdg==@lfdr.de
X-Gm-Message-State: AOJu0YyobFVFZaAppL+u17y3AKC537Jca/dfRZviq1j0wBzMbN5w+Fe6
	aIOKQCtVBD6tU9N9FwSpeImaSYPp4gfs3h8F6e8OoKFd0hVFXLNg
X-Google-Smtp-Source: AGHT+IF0xo7wiXYoLIn5Q+MlFfomX1NW6PYZHiZrPCt64VTIQ2w17YI7FimNXDCYjUwp41Wo5Qos9A==
X-Received: by 2002:a05:600c:46ca:b0:43d:fa58:700d with SMTP id 5b1f17b1804b1-43f1ed6f0abmr30296585e9.32.1744210633406;
        Wed, 09 Apr 2025 07:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJuBkyHjgIBn3ntfbldpW2WPEne9C+pKMyW1Qy/Dd1Ekw==
Received: by 2002:a05:600c:1d87:b0:43c:f7b4:5d58 with SMTP id
 5b1f17b1804b1-43ebebcdc3cls37206315e9.1.-pod-prod-03-eu; Wed, 09 Apr 2025
 07:57:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxn6TCEaZS3RNsvYGHB/eLjgudia2Mev74I/3jJcQ+ZH00tT2HY7oPd5rxTCYFDH3GGTzGFtN/nDs=@googlegroups.com
X-Received: by 2002:a05:600c:35c7:b0:43c:f0ae:da7 with SMTP id 5b1f17b1804b1-43f1ec7ccfdmr27925015e9.7.1744210630522;
        Wed, 09 Apr 2025 07:57:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744210630; cv=none;
        d=google.com; s=arc-20240605;
        b=RRdkvsrPwkSHs6nduqRjV/qNE/DnEQEMg9LRORNS8ePlrS5jTL+M5+3OlqILV1Hwnb
         64ckmZu6jzG/JWtHaWtuH1nuBt9vSu7wR4ElqPMptvXIdRVOoYRz4lVaGkxunluVj/kc
         RcoJQUcs9NxNnNgMhu9+n0ACBvXjhHh3bgJb03Ebzwn1Ko110vc1MNlyoktJN9C1a8t3
         egnyS/4/kqeDWYRqPHCC8/c/l78BYmE/A3E7e1OKuHUJmITPWVv4bxjxxos5YRRxKe7A
         WN8tCooeNPFU+umBi8N486U4FXiSBP5DB3ecpwWwOT/A7RL0cv/VYCIfW5+4gGny1DF4
         4ddA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=XTxp3qW+KPuzf+zXWuGUYa2ldWHd+1dpKttsCAAJnR4=;
        fh=ASkrPuik1f8+Dtt8Cf20sSSg79HGgMwnr89FBbdWXfA=;
        b=B+ewcstpKcWZ4xzPuiNI45cx3DRa3h+VfT3E2VuE3WCZ47bPAXB70VBhZhnI2rI2Ja
         /8bb42NOiDrnhC7WwW0qu0e29NSxkBFN7mqOIXuTLGhhl6nDp2HH+/eyghReJNzgoQLT
         uF/gjN2/sM4JuzI+Zc6RVZlXFSu/8532vhuVTSdAZ/45zzO7K/nFbToYQo7qbw4srxwF
         mNmbdnvQXiapo+3e6egASOa6kaGn+tyRUZCElI0/bM5TRJTB6POOiAfgzPwIZKOrhQXd
         LjFPhv2305KK8iYusH5jnIweJRWRKkX8btpUGBCbKz5HjlY1H0elP21N7cyz8y3K2zr8
         GWeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Dc1PHabK;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43f20668becsi293655e9.2.2025.04.09.07.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Apr 2025 07:57:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-30d8cb711e2so9430201fa.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Apr 2025 07:57:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+akbAoTfO/zpRTovRQAl/MsS5bM5Dn6+efUr1s8QTs5+PUT6r9xBO6rGCK2b6J/jUYjrAOFRbNp0=@googlegroups.com
X-Gm-Gg: ASbGncuTihSJ6c3+a/5QFY+xCXCMJCRuxFRub0qCzMjbys3IcIBdvapIsrKeHpYuIfc
	hYVvPmxUDorshO8BCIQWCuCLnvETHuXaJISUlRTgMxgbYwjcS2oED7ekd7aGfjEzBQfHQVzTo4e
	urif2vcy75BCLDYswYuZqWfERcM3tnHW5kYu0A5+dg8QUfu1ja90PEL7T+5dboOkokjp9SHOdKc
	vw2IqQOTLFGFfj03lDIkEVF6FMa2Mwz3BQe2UNxuOwF91zD5o3xbAyPsYkI+sBUI4SZ0UFbBESX
	Yji4YKJcD1QGprAnyuuLiPpnuIk2c6NLFEKsYG+S23ZOqFR/8wqw+2lBS1GTAtenAxULpQ==
X-Received: by 2002:a05:651c:221a:b0:30d:62c1:3bfc with SMTP id 38308e7fff4ca-30f4387ba49mr2911011fa.7.1744210629436;
        Wed, 09 Apr 2025 07:57:09 -0700 (PDT)
Received: from [172.27.52.232] (auburn-lo423.yndx.net. [93.158.190.104])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-30f4649d61csm1929521fa.7.2025.04.09.07.57.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Apr 2025 07:57:09 -0700 (PDT)
Message-ID: <02d570de-001b-4622-b4c4-cfedf1b599a1@gmail.com>
Date: Wed, 9 Apr 2025 16:56:29 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/3] kasan: Avoid sleepable page allocation from atomic
 context
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Hugh Dickins
 <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
 Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
 Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
 xen-devel@lists.xenproject.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, stable@vger.kernel.org
References: <cover.1744128123.git.agordeev@linux.ibm.com>
 <2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev@linux.ibm.com>
 <3e245617-81a5-4ea3-843f-b86261cf8599@gmail.com>
 <Z/aDckdBFPfg2h/P@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <Z/aDckdBFPfg2h/P@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Dc1PHabK;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231
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



On 4/9/25 4:25 PM, Alexander Gordeev wrote:
> On Wed, Apr 09, 2025 at 04:10:58PM +0200, Andrey Ryabinin wrote:
> 
> Hi Andrey,
> 
>>> @@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>>>  	if (likely(!pte_none(ptep_get(ptep))))
>>>  		return 0;
>>>  
>>> -	page = __get_free_page(GFP_KERNEL);
>>> +	page = __get_free_page(GFP_ATOMIC);
>>>  	if (!page)
>>>  		return -ENOMEM;
>>>  
>>
>> I think a better way to fix this would be moving out allocation from atomic context. Allocate page prior
>> to apply_to_page_range() call and pass it down to kasan_populate_vmalloc_pte().
> 
> I think the page address could be passed as the parameter to kasan_populate_vmalloc_pte().

We'll need to pass it as 'struct page **page' or maybe as pointer to some struct, e.g.:
struct page_data {
 struct page *page;
};


So, the kasan_populate_vmalloc_pte() would do something like this:

kasan_populate_vmalloc_pte() {
	if (!pte_none)
		return 0;
	if (!page_data->page)
		return -EAGAIN;

	//use page to set pte

        //NULLify pointer so that next kasan_populate_vmalloc_pte() will bail
	// out to allocate new page
	page_data->page = NULL; 
}

And it might be good idea to add 'last_addr' to page_data, so that we know where we stopped
so that the next apply_to_page_range() call could continue, instead of starting from the beginning. 


> 
>> Whenever kasan_populate_vmalloc_pte() will require additional page we could bail out with -EAGAIN,
>> and allocate another one.
> 
> When would it be needed? kasan_populate_vmalloc_pte() handles just one page.
> 

apply_to_page_range() goes over range of addresses and calls kasan_populate_vmalloc_pte()
multiple times (each time with different 'addr' but the same '*unused' arg). Things will go wrong
if you'll use same page multiple times for different addresses.


> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/02d570de-001b-4622-b4c4-cfedf1b599a1%40gmail.com.
