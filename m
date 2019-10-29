Return-Path: <kasan-dev+bncBC5L5P75YUERBOGY4HWQKGQE5X5AEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 800D8E8CF3
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 17:43:36 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id l9sf9136929edi.8
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 09:43:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572367416; cv=pass;
        d=google.com; s=arc-20160816;
        b=TT8lyCc9KDkxcHXJKI3AHIR4RUZ9IcGKk0YFnoGjaIH982GXwpgVWCqbJZVxpq/6uq
         ZNdzhHExone3ypBt7IZTn1bjxiO3pVDJZmu/JU+8yq8q6/J+zBNVYCqGxh2hq57BfUC0
         90razp+Ayt2fUscfVJ2XrsssB1ST+/kBUshQNzU8GpOIN19fwzOSHOd9eNLfTQvqykDo
         uxkLdFTgGP23MfDaVJauSRpD48Vd9jGSmbsTHkZAPxlT5rwB5afEA6PoV/ttL8C2Avkc
         uVxhRleDzpDCthwjgPF3OzfPm3nl/DpdwsMpFdkhG+HP2afTTh3cC9J7tPOvuhPK03NW
         RsRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=IZsph4xm3sYG5Qbs1sTxC+KW+TN6OHsQu7w9DXXq3YU=;
        b=laFVXI7DD3lLe+cRp6S83nRM+jQbNtY1cACk+PH9JYjvrl+7PNQKIteA4j6zXx6B7e
         WCgTV4/m6B8Expu56eA8JMcJAZVbsJFJWpNNTjNMxAUIXYE34XL/U9izY4WJdxECeAKg
         XjbskewvGHZ3phfGzszDpsnI4bEk3tu1+ZsncWx7YG7432MjOUhzfWO2D0HDCBxpsbsV
         ZKWKh1ySdzt1RFRtYRFCRDzOKm9/PmZdvMOSeBqWtCTRDoTWyJwj85MmUasKHKm9FwtK
         oDJf5Zduzxk3IwJ/C06uMLj/B058czaEK29KOHRNpUdmnD5hmjaOD7jt2rgaUjVYKuk/
         NTcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IZsph4xm3sYG5Qbs1sTxC+KW+TN6OHsQu7w9DXXq3YU=;
        b=nVeaiCXAG/ah5EbcULPFQHdbHo7xQ4WxL3ie0CuJmFmjm6d9OT5x4tqCHjh3kBubPA
         NG/xO2TPdRCqQ0NZTWjmqAjNSWshYBw62BZDAucAAO0YsZ5+JMocRh1tjsh95OPunvCc
         leYZ2RjuFfhkPdpqiG/+Fi0wXLZ73+2z4EvtIuDJEBvgx40gfjsiLbq2tFsVciizo0Hu
         VcLjohqK8GRWmP4TvHKUONcrx6FndiZ2YCxbpPZvJMPkfVHdRjkl7tD9feTZkmfHdYKk
         xYhTs1FI+YM91UiXLdajB5+2ko5bsIKzNBtnAG9QEm4NSDe7iTfSK5/LRMAZKZUnvJUC
         DQtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IZsph4xm3sYG5Qbs1sTxC+KW+TN6OHsQu7w9DXXq3YU=;
        b=F7m8RUXHLz1IqcJRDf8V5A9kMKLWPfMx5USLetjQ5xnw/auXoI1z9O3a8Fl96uOBn6
         XqIsSQlsBTIX8d3nRtvvNlgv3lzm4c0vsRFRFBBJXw4ZgXHukjp0gh8eqDxQP55qjQ/v
         HjbtGvsk1N5GFBzzscWyLEQUsaAXcn+f0kkLyjNKOwhz/JAXuP+zBfvi5eUxlcl5bFVz
         5yxiZ6xe4Isml5G3wM6wiN8KZs2TTBRYfCR4BzfXN6XidKLIMBbqOMg6VB1vNbn/dRUW
         j8DUV/6lSPzniNdBwO6q6S4npQAZagLZYzuK2B9xAM4eNNao8Flqy+5jgSHHugR3yJ/z
         idZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUB39YcAcBhH+QxrD7JvPCWjsxvm1Zk41iGsJOBb1GQtbkV07zF
	zMWOMbD1lPdKWj5ij9qa0V4=
X-Google-Smtp-Source: APXvYqxAhronpbQrqeC25OOaKuqVnpLgJTWIvevIiO5WeuL062qbMr2rZ8nKrm8r1OuZscknIisdHA==
X-Received: by 2002:a17:906:b347:: with SMTP id cd7mr4426521ejb.105.1572367416191;
        Tue, 29 Oct 2019 09:43:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:405d:: with SMTP id ns21ls1787379ejb.6.gmail; Tue,
 29 Oct 2019 09:43:35 -0700 (PDT)
X-Received: by 2002:a17:906:80c1:: with SMTP id a1mr4362024ejx.37.1572367415627;
        Tue, 29 Oct 2019 09:43:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572367415; cv=none;
        d=google.com; s=arc-20160816;
        b=eL8Bx8jM1qLkMu0H0OIir60PcgmYMBrd6vR9Acj4y0cp9dzi5tDd32tJNgjeynghwf
         QZxmmNCVnCqPqFz1iaPP7Dbhbs+uZn5tJWGzl7wGooFo4brZIPITMvVap0Yna9BAOjmP
         8p/r9g0fUDdK2NJuYpR3V21JYxF3nwyO+ol/Mw1HioOMBFBX1ilyDho/FMCs9Hs282ve
         /uml5vq+RRisq0b6Vkk8w3uR0JakgfsY7gCwc4zXacWBAoCqaTwHsrWkxZogJTnKM3NY
         5qH0GI9zObmJVjRKBTww1Tc2PXP8caR1rNtVVIUtLbOHnaJuCsKjTSYQi680Ah129n+I
         EOPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BoUS8sI2Y0PRHVkD+8sTGgihdSSm7C0ThXdZ4OWfLUA=;
        b=m2OVLSIhJup/n4HOk417xGOpiIibIhvxW5SBSuks0UmXSVPyUyFacwHKoKx+t+RkBz
         poPYUBiminePZ5wb0pB2GqPB8k7ljODmJ+Xdqs5JU8Yxn0RcvfvwauZPcWG+jplnfYdA
         2rAPp+UuRquK08HEs2Tixg8HYgmPOSt8VNHCjxMB7/Se4lGWVwukIeflKb6ZEp2xnYZW
         GpUz4jJkRPq5MpGmFGZa+uu3a+PTYie9YFLn8nKBSEsi824En+BLkZDcUwdLAhJVxGuU
         O7HuFUq5KTK6loeLuh0Y8DoVEFj657ok3pxs3xsA1HJs9XH8KN6MeF1IQ7TfUcGe9DpY
         QXyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id q17si1213766edi.1.2019.10.29.09.43.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Oct 2019 09:43:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iPUaS-0006WW-BR; Tue, 29 Oct 2019 19:43:16 +0300
Subject: Re: [PATCH v10 1/5] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-2-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <f847fc8c-f875-8d93-9d49-8f03d4c6303a@virtuozzo.com>
Date: Tue, 29 Oct 2019 19:42:57 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191029042059.28541-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 10/29/19 7:20 AM, Daniel Axtens wrote:
> Hook into vmalloc and vmap, and dynamically allocate real shadow
> memory to back the mappings.
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate a
> backing page when a mapping in vmalloc space uses a particular page of
> the shadow region. This page can be shared by other vmalloc mappings
> later on.
> 
> We hook in to the vmap infrastructure to lazily clean up unused shadow
> memory.
> 
> To avoid the difficulties around swapping mappings around, this code
> expects that the part of the shadow region that covers the vmalloc
> space will not be covered by the early shadow page, but will be left
> unmapped. This will require changes in arch-specific code.
> 
> This allows KASAN with VMAP_STACK, and may be helpful for architectures
> that do not have a separate module space (e.g. powerpc64, which I am
> currently working on). It also allows relaxing the module alignment
> back to PAGE_SIZE.
> 
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> Acked-by: Vasily Gorbik <gor@linux.ibm.com>
> Co-developed-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Mark Rutland <mark.rutland@arm.com> [shadow rework]
> Signed-off-by: Daniel Axtens <dja@axtens.net>


Small nit bellow, otherwise looks fine:

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>



>  static __always_inline bool
> @@ -1196,8 +1201,8 @@ static void free_vmap_area(struct vmap_area *va)
>  	 * Insert/Merge it back to the free tree/list.
>  	 */
>  	spin_lock(&free_vmap_area_lock);
> -	merge_or_add_vmap_area(va,
> -		&free_vmap_area_root, &free_vmap_area_list);
> +	(void)merge_or_add_vmap_area(va, &free_vmap_area_root,
> +				     &free_vmap_area_list);
>  	spin_unlock(&free_vmap_area_lock);
>  }
>  
..
>  
> @@ -3391,8 +3428,8 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  	 * and when pcpu_get_vm_areas() is success.
>  	 */
>  	while (area--) {
> -		merge_or_add_vmap_area(vas[area],
> -			&free_vmap_area_root, &free_vmap_area_list);
> +		(void)merge_or_add_vmap_area(vas[area], &free_vmap_area_root,

I don't think these (void) casts are necessary.

> +					     &free_vmap_area_list);
>  		vas[area] = NULL;
>  	}
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f847fc8c-f875-8d93-9d49-8f03d4c6303a%40virtuozzo.com.
