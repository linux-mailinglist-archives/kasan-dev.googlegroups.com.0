Return-Path: <kasan-dev+bncBCM2HQW3QYHRBM7LZ6GAMGQEZ5LZS4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 17D7545394F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 19:17:24 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id m17-20020aa7d351000000b003e7c0bc8523sf6270125edr.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 10:17:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637086643; cv=pass;
        d=google.com; s=arc-20160816;
        b=n4ACebMpGuuAfGJKP8uM+RkDIe4lCRLxDd2GMQdSWE+0T/L+eTA5M0eJ1KM1uUvYCj
         bBQ8cnqGo0+ZzP+2Sytk0nnyIJqheGWamHmxzwDAAdSrWfHQXq35sKyCRS3wT3eHBm/S
         y4pkqlgCGzbOeQiOWbrPH86pN6eHGWO8z2Tm8fcQJTqWqNtxGdwdq2R+k8DGTgL5oAZc
         SBWSla31Y4MhL8nGjyQx/5QylkOGargdLUV3Www9jIrEEezjfO73Quy9hxPCrfkpQVzt
         6IyHZeHRT0tWBRVkDAwSFa4viRI0EyIDrDNcavwU8b7M9z8FtHBeVzauNcTEneAIbZEQ
         CH9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=e9DEO3dvC3awAOoQ/rz2Avn5MdsXOzu3ZUolkZqipjQ=;
        b=rqzMbxeqFy3bMAGFm6z/D4LnyboHaJVHv7wunS9kqpdLVizL8eXhXmiqwQFfzdZDpi
         7qXzkLFtThbUczRYMqB9sESwcOrml3axcX7JjvHuQ5tkdzjW+vSLFotZAPzYnUTH7VNO
         Ly5/nzzZHpNlKx/Q34rPC5ezA1vLbJx56wT1iebDIvTL9HqMVoImgJKHGZSGH2UowvT/
         NDd7VE91a87RLDl4RKzP9jtjNq0zh6fcSeneyWJXTalVG/bYRFKFiwIKbakYLZmEv4Au
         f8yMB09HhAb8rjmrTEtPGAxNiDyB+VQYTL+NI0cZxu0gMuWlWxU9S2cPK3yNj+IfiF5z
         Ov8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=nGcMxkdw;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e9DEO3dvC3awAOoQ/rz2Avn5MdsXOzu3ZUolkZqipjQ=;
        b=qkJUdh9JmFgJab54x+Xz02b6PCD+ytXzpNAlTZAnMG+/obvceQYm79zrmM0R2NuVyK
         8Q3Bg8AX4SRI3OAYlBP07gI2Si2uH6f+6nOX2IVdIedTtGvZ4e3OOqJgqRbrYaI1m9bF
         Y17We5kTO5h58WuLlRwc/DcN+nMZCYtPL66oYLvzXBeqfZGaq1KAPM6p2ymKwrTG5Yoo
         pZdD3cRscjZvHbq/XHOD+q5vSiVEiWEh5yXqCFGv+ESMij17wX3UwfZIAY21vnZSy1Gm
         nnPmzKkHep3wLjvF3Hml9x0qXu7xGfjFf7ktAJaWyboS1xAHh8P9mpl3cE7rcM/QHEfe
         wYoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e9DEO3dvC3awAOoQ/rz2Avn5MdsXOzu3ZUolkZqipjQ=;
        b=gv6j1iM+4d/74ckZdpYbnhH/jOU6RkxOXzJLtgBB/cig6+t/wck6Pgxx3pnmoa8oCO
         wD8WRLl1ehJqU1kfrdBQ1C7f63ZJHSQWetpn0mYCwEhW85WKxGJ5h0v9v4aRAk02JAUm
         J5c60LSFrGWpYLPzP8CNHGdeHurLcKKXFaZ6BWUy+ozwDu9xrevXfNQzPNBmR/wsmjDK
         CBU9JJhCOZATv+lx7fvxbFcUJkQJgep0ostQlkostAWle4g5SRO2OYT6zqQkEC+XLHVA
         pJWWuR+/U9wFGMs8dsRfpXzeOnG/eX0As7lgnTGNaUZoTsn+NIIWzM0jaEo3ftl5xnYw
         Fw3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530AfTlGtZiqD1Y/eo9uCNXywqrQ8Dx2fyRxtenHGjkj2Ax7nmSV
	cA77TK7PTan1pSw6jhs+mvg=
X-Google-Smtp-Source: ABdhPJzm9fJJ+zJtuoTbDiVSLEFEI39+0zOEVQEm6uiOVmaERCZHLmMKroMfRf3mKKKWYid7rn7lBA==
X-Received: by 2002:a17:907:7242:: with SMTP id ds2mr12781012ejc.269.1637086643793;
        Tue, 16 Nov 2021 10:17:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c517:: with SMTP id o23ls3567672edq.2.gmail; Tue, 16 Nov
 2021 10:17:22 -0800 (PST)
X-Received: by 2002:a05:6402:40d1:: with SMTP id z17mr3524608edb.340.1637086642939;
        Tue, 16 Nov 2021 10:17:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637086642; cv=none;
        d=google.com; s=arc-20160816;
        b=Mq6tVJmMq1/DMmvOnQc0uTnUfRtBUc76N8E0rfBPKhra1LGQn1MSzSbKOT7xSLD9yw
         8Fx2jQs7To6ZFUuF8E0/IJJdwAZC4p1hdJqBRhnqxnMgs2yUs56xSVvXfQW/UTwMZLtf
         114wlb1Wys2rxKuAW/ZAL8+0eSovl3ZBShAvYAFlSajpulWBkJUDH8oL6i3GregHqfeU
         Vgmp6fbzjTI/a/75u2paN/HfgzLc7onDeLFHMpWxbRnSrdpt1aU7Z2igx7bsUhT3Johw
         frn4RzAqTtkXNhXCFVjPkPu4zV4mr5d2tyw0o6bK6VLNl23WHmJJ/zD+u/deCRN4BzgL
         90Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XWpo6DiVx+RT2K5N/yi44WQQy+KIXMaDGxOohES1JpQ=;
        b=fh2cSiVocIgSdoVaiyMX8HDBX+wm0q35f4vBApa9QcQgryZKdpLgzmTOjNI39lqoUQ
         gV/oIAnOQz6E/zlxXM6RFvQSE227cWMZlVuiWjoTqnBYPl5Yb3urr/WrfOo0/KBCaZgh
         PtTSkKNbx5KWrB6yh6z0tTftgzrClvdFv25Sl+4tO+TQ8XJy4ibIKK6us7rlFvvX+f9k
         5xr4dD1mEPrencXA+l7ciNS1eYW/3mAzECuRbtmelahiJ1oju0FnS+olV3YX/XKa94X6
         ZVsxvjaQ6WqD1BNFfqzUQnCl7WqchwYMTcjiLwTblZ/cFUx3/DGSO2lt8oAd6EaA0L+L
         W1hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=nGcMxkdw;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id w5si1247963ede.3.2021.11.16.10.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 10:17:22 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mn310-006yyT-3p; Tue, 16 Nov 2021 18:17:06 +0000
Date: Tue, 16 Nov 2021 18:17:06 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: linux-mm@kvack.org, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [RFC PATCH 24/32] mm/kasan: Convert to struct slab
Message-ID: <YZP1olbNmm6FAzuq@casper.infradead.org>
References: <20211116001628.24216-1-vbabka@suse.cz>
 <20211116001628.24216-25-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211116001628.24216-25-vbabka@suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=nGcMxkdw;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Tue, Nov 16, 2021 at 01:16:20AM +0100, Vlastimil Babka wrote:
> @@ -411,12 +412,12 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  	 * !PageSlab() when the size provided to kmalloc is larger than
>  	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
>  	 */
> -	if (unlikely(!PageSlab(page))) {
> +	if (unlikely(!folio_test_slab(folio))) {
>  		if (____kasan_kfree_large(ptr, ip))
>  			return;
> -		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
> +		kasan_poison(ptr, folio_size(folio), KASAN_FREE_PAGE, false);
>  	} else {
> -		____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
> +		____kasan_slab_free(folio_slab(folio)->slab_cache, ptr, ip, false, false);

I'd avoid this long line by doing:
		struct slab *slab = folio_slab(folio);
		____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZP1olbNmm6FAzuq%40casper.infradead.org.
