Return-Path: <kasan-dev+bncBC32535MUICBBWGJXGPAMGQEPOCIYMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 602E3677964
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:43:37 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id c1-20020a0561023c8100b003db4e4d407esf1552536vsv.21
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:43:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470616; cv=pass;
        d=google.com; s=arc-20160816;
        b=i0e2nt0eTlb4C4ZCU6mXE4eofK69nVwl5U5iOT5pNL1zUI0Wwss//Avi9TwNsoM6iH
         cWbGdl7ZTuK55Mznaq9JudauhwXadK4ETegaRyDzCGCxsg+mgnL+7+0KkfJIboR1S9hn
         9HVneJkwKD/hS20iXkC2Ufj23TNWPK/gv3kBBJtMb4cyeeGl2Vn28Hf3gblVHdfDbBS0
         Vj8S3UAi2tocvvZMm0wlwVo5RlezooV3PIeammjOKTuAmh8J2SM857HxRxQcfF+snlUE
         6Ie60Fbdh8lNuNZNSoTCss+dFlgeOJoalvJ/lh8Io8MisUyJ7cFXxdSrNcd6H+vtn0nK
         8VFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=ZRv4CLQwbGImRvsmCsDNrUEWR4REKnI2RyLEArRR4g4=;
        b=dFghG8nyWVhVkqUktjXlQF+VzwtuDbpaN6rl09D//I09zDaM+yfsVknjAu2r5LLADD
         3hMM1K06oNFjv+oQiu5wTKbsh0uPC2KbsBGB68tVa4u+w2YE6nFls3NzDm1weWIjdKOj
         pPL+Cn636H1IT/kHKej5wAErpN6Me2WSCPTfgjxA5y0gMcbQw48gztMXKxJtD+Rp/4XL
         lnLQ1WivHvsiDydBKhJmJXRCjG/J2Bs4jG5lgpepC0jMYcr0wBycR0FAsCsPpAudDtLC
         7keoBC4qf8K3i/61cTeGbp2uheOa/Uz7NunxQCk7Q6bP9+QHgAJQP9eebeqUNqTfzYtF
         7MIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=U5s3kYAb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZRv4CLQwbGImRvsmCsDNrUEWR4REKnI2RyLEArRR4g4=;
        b=KTqfTvGqSPHO3yRkRgeoYWFIBfh6EdfNMIChwfY4Giri5CsYsLwsaer4m6iq5ycnzK
         D2qAcW+CODkTG0gI4W5XMUCCY+WZbgG0j9xO4vzWZpMpws10OvIO3hsOHvvwTb2Qp7TD
         L1pAc4/b6fc3ij7wLgjW0/rvLC+dShBb/kySHOjxhBv97hNRCYbNbssP0lC61V5e+CtU
         i53dcrw/9dQr5u2DF53x1PeJ/WKthQzE/BZcEB7P8e2+PlgZRdMlA8oW8c5/7xfHsjmF
         naFnfDkkvDmkqD6bwXjcOyLw3VIeZT+AZI3BPTxFWDLpnfNnQ8Sh7Ta/MSww8a0akwg4
         wpEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZRv4CLQwbGImRvsmCsDNrUEWR4REKnI2RyLEArRR4g4=;
        b=l5eTDLvS74j5v3RAPY6+/PhN0Kd3jrLT1/HakxqvsBRKbAiEMBeUCX+HSHSIzMwYJL
         eXV8/kcFczDr2sY44aOPwBb37rYwZycruua1xzaIRPAJCkVmYtdLcJH+/II8DrLgvBH3
         dNeY3I/5GE5p90K7CPc3VYLyc9nn1JDDD6QRHCVHbLFlZKTlycrsVSEtge5uhTgMwvfX
         dppGyW23fs3oiiCtvTEaOhiyi66CZhS3xCT9njtytDtbrqK5N/GsVOdv4CNsplzhUFdW
         6EttUCyGqTbokSlP4wYFUUP1n3g7eBub/1gUW/6/PSGXD7n5Lig2kUYJbY/T1bwm3fxj
         HWDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpBykDH38djlgZFgqvMD2QlcI5is/52ZCYkwSKufMFYjyVGHw1O
	Ygf44Zsnkys2do3lAnS89eg=
X-Google-Smtp-Source: AMrXdXuA3dgsWC5gQu4rZFnmbC/slaxGkMeKRxRzqY4znxptTohDpqdbeshgIE7pq9CpKwI+bM8Idw==
X-Received: by 2002:a1f:5705:0:b0:3e1:ae3a:5571 with SMTP id l5-20020a1f5705000000b003e1ae3a5571mr2884535vkb.25.1674470616293;
        Mon, 23 Jan 2023 02:43:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9d97:0:b0:3e1:cb2e:e15d with SMTP id g145-20020a1f9d97000000b003e1cb2ee15dls2012088vke.1.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:43:35 -0800 (PST)
X-Received: by 2002:a1f:3d93:0:b0:3d3:1c0b:1b05 with SMTP id k141-20020a1f3d93000000b003d31c0b1b05mr13043400vka.16.1674470615540;
        Mon, 23 Jan 2023 02:43:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470615; cv=none;
        d=google.com; s=arc-20160816;
        b=yUwil5ggeBT4gMgIdvEtHsBoHXoO3x3RKeASdX70XDJk9jCFGcF8OIQJpKnm93mbMR
         G7/d45Me1PawwlI6Z4uWczXJtTgxm8Jp8DWBCRvjqdhpGlsIfY+FHxkODbqtKdpCJMYB
         GIg2AvUJ9EHoIrjfOVwNyQtMTwb1mLt5o1OBkCosxYZO3PmdR2Cm0FkoJwgJjYsNuHw3
         YpFEklbno+ROq3SypIPMztGCKFwd2cWty/iqg33RwfOtqUrCLsrqn/0b4kswC2mZXu56
         Y5V53BmMytMXtgAfwyVh4uqPoVNHCIkHPyzYkifucMifOwFGhpDtGsIluWufEL5G6dQI
         tpcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=3S/hxP8bYZ34/3gqxEk5MUbZrc/WTJVLxhNd9rhpOcU=;
        b=HL5Vsdj700jx205Rl+czDf1IlFEGb8jErWNgxgcQfTwnQ+J5s2k5jgC0YQfptJpMKL
         Gt2b54und84R6LhllRJVGdvfGEx0APi6CPwgfSKSWRxUIXDe5CnF4yPTIighE4SrGjVf
         cwP/qUk73F3+0ywdpq5j4ZJ7MqJd9JkrnDow3ijTL7COyTzImpU4Bfa7xo1DpLI0HuUl
         3Ja4PtE12HUBVeUffV7y1M20TiQCuCn1++py3f7UrxouP5diT8DdlA++1mQq7Ja8z/lb
         GywDiRc122tNrAICRVXAmBQxA1BFsJxS1C8fgMzuMa4io7bwqbUHEmeByC7iyZyAUcry
         7epg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=U5s3kYAb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 140-20020a1f1692000000b003daf0a8001asi3025179vkw.2.2023.01.23.02.43.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:43:35 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-589-O2Wy7DHfMPS63FLHhfWn-A-1; Mon, 23 Jan 2023 05:43:33 -0500
X-MC-Unique: O2Wy7DHfMPS63FLHhfWn-A-1
Received: by mail-wm1-f69.google.com with SMTP id j8-20020a05600c190800b003db2dc83dafso5871724wmq.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:43:33 -0800 (PST)
X-Received: by 2002:a05:600c:1695:b0:3d3:4ae6:a71b with SMTP id k21-20020a05600c169500b003d34ae6a71bmr22540952wmn.2.1674470612616;
        Mon, 23 Jan 2023 02:43:32 -0800 (PST)
X-Received: by 2002:a05:600c:1695:b0:3d3:4ae6:a71b with SMTP id k21-20020a05600c169500b003d34ae6a71bmr22540937wmn.2.1674470612385;
        Mon, 23 Jan 2023 02:43:32 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id 17-20020a05600c021100b003dafb0c8dfbsm11777199wmi.14.2023.01.23.02.43.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:43:31 -0800 (PST)
Message-ID: <02bc3d67-3457-ff17-0810-e75555609873@redhat.com>
Date: Mon, 23 Jan 2023 11:43:31 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 08/10] mm: move debug checks from __vunmap to
 remove_vm_area
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-9-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-9-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=U5s3kYAb;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 21.01.23 08:10, Christoph Hellwig wrote:
> All these checks apply to the free_vm_area interface as well, so move
> them to the common routine.
> 
> Signed-off-by: Christoph Hellwig <hch@lst.de>
> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> ---
>   mm/vmalloc.c | 18 +++++++++---------
>   1 file changed, 9 insertions(+), 9 deletions(-)
> 
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 97156eab6fe581..5b432508319a4f 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2588,11 +2588,20 @@ struct vm_struct *remove_vm_area(const void *addr)
>   
>   	might_sleep();
>   
> +	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
> +			addr))
> +		return NULL;

While at it, might want to use WARN_ONCE() instead.

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/02bc3d67-3457-ff17-0810-e75555609873%40redhat.com.
