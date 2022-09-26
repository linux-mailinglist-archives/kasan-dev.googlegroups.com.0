Return-Path: <kasan-dev+bncBAABBHFTYSMQMGQETDXVJNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C48D5E982A
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 05:16:46 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id q11-20020a0568080a8b00b0034fbbc585f3sf1392551oij.4
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 20:16:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664162205; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cw0rEFcL/n/lZmbelpfwsUhK8L36Slsb4ne+udaLOYPKGNVRTrO5b48Wz/v9FmMEPf
         Cw7/dJLx3/AOm76DjQkVlSn7rzcu8UPuUSgncsWuVCV/NLiiSJzuNlxge9XOy3hUNLrJ
         4YxYI3wJU0/key7a45F1skIvm8YxGA1RyA7YjhRPVodYEMDWRSgXicd32Tv+Kuhvbgsr
         0+Lob7ITueBjp1YZET5bHjG7Wb/elL25JJh1eDXUFsbfDN6eZh3VCvfjqaoorbQhDz2A
         SAXd7LtaIaYGn5IyOEcFpHmcHwNB4YpuUVbMNVI+7lEtX8KPRsoEjcWivFn/cKXfI23e
         7efQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:thread-index
         :mime-version:date:subject:in-reply-to:references:cc:to:from
         :message-id:sender:dkim-signature;
        bh=rahE0DpX+aJqBBB6/RA3ttlzlEwcPc7fs8veVxYjeYM=;
        b=yoieGnDns5PovbR70+3n/bAghQilYJiMosd2w237BDjSk2Bk9ay8Lyijk7LdatERCX
         Q/bztrT27+pVi4e0JOxhHLHxkexn3pZWH/WljcifhOrBmWa+yPPD6GmMfQasBdNB6B/h
         TZGRKwK0KpDix/XCNtb4fONNBVcfg4PyNpv4f1ubpwj//da1zeZpwX1hmEa5OKUH0eg/
         GC5G6LBiKwReph5MFLUKu8y4Sm23o/pegPaKEO6J44mBaKX96Yu57i0iANfvib61GC3H
         f6SdxRBKhSJ6R1uhJmWwuo0yM4AMHM8lbZ8Gi9g0OSzTDrQqGKEBPAdqOCNjMOMvCBOp
         FoXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@foxmail.com header.s=s201512 header.b=D7AWuTw3;
       spf=pass (google.com: domain of xkernel.wang@foxmail.com designates 203.205.251.82 as permitted sender) smtp.mailfrom=xkernel.wang@foxmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:thread-index:mime-version:date
         :subject:in-reply-to:references:cc:to:from:message-id:sender:from:to
         :cc:subject:date;
        bh=rahE0DpX+aJqBBB6/RA3ttlzlEwcPc7fs8veVxYjeYM=;
        b=CSQpjG2dFjgsslwtkEJ+hM3UmbAtc7M9M6QD0Zkj5VDmKl9B1AWouU3Eqw+cXl/IP5
         SXL1FgqOkXlZjZvzoRKrYzdmuS72uo9vyFj/bGL7MNho+zb2PZccMbP8Rcs5pTYFuXES
         yskc42U6KOC+SoxsX3x04ViyZvwyZ6RHN5xxB2Hne/3SVI+oacHXfeMuvDeP6LP3lZ8q
         5Ra14fmF/BEIIRVU1rUQYLokaCF3zflFv9A7M7aGUSUvPv+qPOw0RD5ERqOWnQp6SHxB
         jKSSsDYUj1kk74jKDSAxjt8xLQJrumhk8aryazhyPA7cCdCfIkBbzBRue7n9lo7+GJBI
         u+gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:thread-index:mime-version:date:subject:in-reply-to
         :references:cc:to:from:message-id:x-gm-message-state:sender:from:to
         :cc:subject:date;
        bh=rahE0DpX+aJqBBB6/RA3ttlzlEwcPc7fs8veVxYjeYM=;
        b=7U2FLjVQj9vQncuHOVLTS6YVsrneqvh3SYhAA5lCwJaCLQenjbQDHdUp3dFhxTgx/0
         ueYUOSpr3LcgBMJpITVdsaRWuVd9e7WB0TMxeuqhAeTK/4O6S/rqQMKGTGwUY5AR9pWC
         esxqBcvF0X1J66BLKyyOym9MxhUdfKDhaJ5CzgfV/C5sbUfHIf3NCln5ZcTNt+QruXo7
         thNldJJZqNIRjhh5Kq1eTqQBIPHvs0zCRkp0P8MjjIPoAPvsITYBWxMHGg4yTxZiTsgb
         15Uu0RBwXHT2qgVNQ0jt4MISwQoygWF2tMeWwZk3gLiGAN9SEO04XAPOOnaSfKQRBNcW
         r6KQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1IYv7Ms8Bu6WgcrAG4KN0tDwMMYd0oQ0EE/4DvszeLWbZKHYHM
	R1uMtd1imRyC06awFdH9iTs=
X-Google-Smtp-Source: AMsMyM4UyErg5zkNwekZmpJuGHCeGILq8Pqk1ka33AIYa8bq0/U4bYj9vV2rb3Lz2w9xISPC/wo7Gg==
X-Received: by 2002:a9d:3c4:0:b0:65a:774:4079 with SMTP id f62-20020a9d03c4000000b0065a07744079mr9376336otf.17.1664162204820;
        Sun, 25 Sep 2022 20:16:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5a06:0:b0:351:4a02:fe31 with SMTP id o6-20020aca5a06000000b003514a02fe31ls55381oib.0.-pod-prod-gmail;
 Sun, 25 Sep 2022 20:16:44 -0700 (PDT)
X-Received: by 2002:a05:6808:1892:b0:350:7c49:649f with SMTP id bi18-20020a056808189200b003507c49649fmr13792647oib.219.1664162204376;
        Sun, 25 Sep 2022 20:16:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664162204; cv=none;
        d=google.com; s=arc-20160816;
        b=NRjxKszGCKSmQqUO9MgNTQdSck0y9Ev8zEN8h0LxBZtvUuNfLchq4v0hU1fsuKTlak
         gdsjLboWOwf6QougVmCtOVob8tFV2g+0wIqFh0xt0XYcanZDV8By6la9MKDJ+eHLnhxQ
         nVmL7vGFdKQ7dWZQ5ZIyb95YKA9C925P+lV6xEIT5SWBOQtTp+HDXkz4hgq5ZqQ4eoez
         13ruZs9M5hTjXptve2ZniLOgxkpdnzmBrlZ5dGpjO/6e+sLsip4HVyW7Rx/YitZbGPsr
         FqX9ET+mawmpStFl6eZVfNiZz6qYDJhGakAMFcTgxCUoTCDZhNbZBC0++fCkWGQZqYyz
         DaXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:thread-index:content-transfer-encoding
         :mime-version:date:subject:in-reply-to:references:cc:to:from
         :message-id:dkim-signature;
        bh=j9SSpreHKvKfroYfmbuT3oTsBVOFOzVT/lwKwVPfe1A=;
        b=ZQsHG7/XPFh7R4Y1p9ApNomTG8ELD3Paz0ixuA+urlBIlJxW2bRAMElPwUMmAyl9B9
         wX6VXh/nsmTUJ03rGeT6TRKjO2amXc3BnPrAMWnBqrBEAQZZ803KkKVvFfGGbbEc7og5
         k3Y7AJ9aR2D4lqQpCq6qxpcEt4QsOvzM8vMYhXy71y27PNJBz2YaY6NEr9oNDVBgjSEy
         3W8DEu0308xvZy3c6i5sY0ZxpEd7693AQ9GLfgV/fY11nhJzlGWJO7ID8TNe2EDjPd9w
         CEd2T13wdsCPkZ2UmiWBNQMIdKIvu7X322+t/EA/Q2RyluSpqwDH8ErKRcOWCHZxo8nH
         UfLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@foxmail.com header.s=s201512 header.b=D7AWuTw3;
       spf=pass (google.com: domain of xkernel.wang@foxmail.com designates 203.205.251.82 as permitted sender) smtp.mailfrom=xkernel.wang@foxmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
Received: from out203-205-251-82.mail.qq.com (out203-205-251-82.mail.qq.com. [203.205.251.82])
        by gmr-mx.google.com with ESMTPS id l16-20020a056830055000b006540f7a45b8si852011otb.3.2022.09.25.20.16.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 25 Sep 2022 20:16:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of xkernel.wang@foxmail.com designates 203.205.251.82 as permitted sender) client-ip=203.205.251.82;
Received: from helloworld ([59.172.176.225])
	by newxmesmtplogicsvrsza30.qq.com (NewEsmtp) with SMTP
	id 4252604B; Mon, 26 Sep 2022 11:16:37 +0800
X-QQ-mid: xmsmtpt1664162197tr12jpg81
Message-ID: <tencent_F9A4327FE4DE726C503C873F2871FF0F810A@qq.com>
X-QQ-XMAILINFO: NkHKfw09D6j8lZX/8QmW4y6DiQoTbz6jyRTCWGspqq1eTU6oBJ0g/l+wrNdPSW
	 zTk/a7+RVEfKdGMdSnyXtkfffONBr/XwTQ3F/FKxCa4osVR6GCSkBbi5KS/YVcCR2WarQ0YeLn1L
	 mCHoTrVch/yEq58jTgwUmPEsmBe+GMMVMdNfQgV1RcKkuLfhypMwAe/CDqmWMCD2GQ4gXbRNAQ2g
	 D3glvW+Ne/Swyi0WXlSN/KNSQvuxuxx73u46q+yrzPXncIJUEbMZFDs4B3elPTyzp+UC67oftV2D
	 PJoiHsCfcmlLqNZX+2zT9FJ++6lIIBnNZ0pPcCQ1eYjpvRVTWSUAv7I5tA6Iev0gMM/I9aYB23Dm
	 C3DzLMFRnmdmiuUl8tbtz1crDZr56jX1po85ISKLkQtExqt4bXoHxEivcOqolQsjAoxfPy0b2oV+
	 TOjC7E62NduH2JKJyLTO7VKJokEjaK3UTiiQ3qgPXErvU71HgU6NgJbLqgR2EuCU7PhRkXhaUvUV
	 MS1DoTGbIUOjOaUYrfy6SEb+hS48VjzztmLA1x+kCJeo8ppkTTFaaRNgfWBvU8uTe5bviq8x4QYr
	 wruMeUARxxQEmRnZ6I0CiLWwgwawYBonzUCZoTxqJiUFRk6NTt1q1P/P+Rz/1Rh0xg0EH6f/M4C/
	 txwnEASMy5UpAe0X/+0dyZ6d/o/pOT756Cr4vLAZQMk+9fZID6t8WrLkb4MU+3k+QHVp25gOjTZ4
	 sOg+maUf1BrORWeWk89yJfFffpdLhmasPHiI7wJjAZ/QRFujbuuKx/jlSuQbTQZBTIa/mjCGFScu
	 SkMFMYvBbonak8QWRSWUAr8r1JeNJXBBHuXNUQa37HGmipHMG9eCCKwLaqZi4VZz79QW/Com9tfZ
	 ukCRrZ+MBPCVDPcx2nxcKbIuQacpBy5J208J917/+XGZB7O0F1+/siyyM2t0aWqlAge+IcQE4L1e
	 W+PLen60CB9ba+HDcNALpxks/RQ2CLFJZAk6g/l1dJ4U6RyEuEm8q4A+2583i8
From: <xkernel.wang@foxmail.com>
To: <akpm@linux-foundation.org>
Cc: <glider@google.com>,
	<andreyknvl@gmail.com>,
	<elver@google.com>,
	<dvyukov@google.com>,
	<ryabinin.a.a@gmail.com>,
	<kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>,
	<xkernel.wang@foxmail.com>
References: <tencent_D44A49FFB420EDCCBFB9221C8D14DFE12908@qq.com>
In-Reply-To: <tencent_D44A49FFB420EDCCBFB9221C8D14DFE12908@qq.com>
Subject: Re: [PATCH] lib/test_meminit: add checks for the allocation functions
Date: Mon, 26 Sep 2022 11:16:37 +0800
X-OQ-MSGID: <000301d8d156$648e0010$2daa0030$@foxmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Microsoft Outlook 16.0
Thread-Index: AQJ0HYwArhWftIfEaS2bvHNj7adm+ay6bDcw
Content-Language: zh-cn
X-Original-Sender: xkernel.wang@foxmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@foxmail.com header.s=s201512 header.b=D7AWuTw3;       spf=pass
 (google.com: domain of xkernel.wang@foxmail.com designates 203.205.251.82 as
 permitted sender) smtp.mailfrom=xkernel.wang@foxmail.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=foxmail.com
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

Hi Andrew,

This patch seems to have been forgotten.

Regards,
Xiaoke Wang

On Friday, March 4, 2022 5:12 PM, <xkernel.wang@foxmail.com> wrote:
> From: Xiaoke Wang <xkernel.wang@foxmail.com>
> 
> alloc_pages(), kmalloc() and vmalloc() are all memory allocation
> functions which can return NULL when some internal memory failures
> happen. So it is better to check the return of them to catch the failure
> in time for better test them.
> 
> Signed-off-by: Xiaoke Wang <xkernel.wang@foxmail.com>
> ---
>  lib/test_meminit.c | 21 +++++++++++++++++++++
>  1 file changed, 21 insertions(+)
> 
> diff --git a/lib/test_meminit.c b/lib/test_meminit.c
> index e4f706a..2f4c4bc 100644
> --- a/lib/test_meminit.c
> +++ b/lib/test_meminit.c
> @@ -67,17 +67,24 @@ static int __init do_alloc_pages_order(int order, int
> *total_failures)
>  	size_t size = PAGE_SIZE << order;
> 
>  	page = alloc_pages(GFP_KERNEL, order);
> +	if (!page)
> +		goto err;
>  	buf = page_address(page);
>  	fill_with_garbage(buf, size);
>  	__free_pages(page, order);
> 
>  	page = alloc_pages(GFP_KERNEL, order);
> +	if (!page)
> +		goto err;
>  	buf = page_address(page);
>  	if (count_nonzero_bytes(buf, size))
>  		(*total_failures)++;
>  	fill_with_garbage(buf, size);
>  	__free_pages(page, order);
>  	return 1;
> +err:
> +	(*total_failures)++;
> +	return 1;
>  }
> 
>  /* Test the page allocator by calling alloc_pages with different orders. */
> @@ -100,15 +107,22 @@ static int __init do_kmalloc_size(size_t size, int
> *total_failures)
>  	void *buf;
> 
>  	buf = kmalloc(size, GFP_KERNEL);
> +	if (!buf)
> +		goto err;
>  	fill_with_garbage(buf, size);
>  	kfree(buf);
> 
>  	buf = kmalloc(size, GFP_KERNEL);
> +	if (!buf)
> +		goto err;
>  	if (count_nonzero_bytes(buf, size))
>  		(*total_failures)++;
>  	fill_with_garbage(buf, size);
>  	kfree(buf);
>  	return 1;
> +err:
> +	(*total_failures)++;
> +	return 1;
>  }
> 
>  /* Test vmalloc() with given parameters. */
> @@ -117,15 +131,22 @@ static int __init do_vmalloc_size(size_t size, int
> *total_failures)
>  	void *buf;
> 
>  	buf = vmalloc(size);
> +	if (!buf)
> +		goto err;
>  	fill_with_garbage(buf, size);
>  	vfree(buf);
> 
>  	buf = vmalloc(size);
> +	if (!buf)
> +		goto err;
>  	if (count_nonzero_bytes(buf, size))
>  		(*total_failures)++;
>  	fill_with_garbage(buf, size);
>  	vfree(buf);
>  	return 1;
> +err:
> +	(*total_failures)++;
> +	return 1;
>  }
> 
>  /* Test kmalloc()/vmalloc() by allocating objects of different sizes. */
> --

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/tencent_F9A4327FE4DE726C503C873F2871FF0F810A%40qq.com.
