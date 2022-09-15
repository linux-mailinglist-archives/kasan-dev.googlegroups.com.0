Return-Path: <kasan-dev+bncBCT4XGV33UIBBAVER2MQMGQEXY2D4VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 874345BA216
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 22:58:43 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id r11-20020a05640251cb00b004516feb8c09sf10948791edd.10
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 13:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663275523; cv=pass;
        d=google.com; s=arc-20160816;
        b=X2zthHybwlmmpItosalTjl9n3ejsRDik71qwjJr9KfvCEey1W9/sVx2rVMTWY325q9
         J6Z+x6sqwjbSeqIT17SHN+zgHRatcubrxU1LSdUgjLW4Fd75DrQJ2/SffiN8PIxFozTp
         eD2yU03vblnRJVzY7oj/00ytPhBfv3WTjcmeedNRWyRKpvu8PEdjz5v7YRFANCrNH1xC
         7QhQwv7CO4IgCeFXW+aA0ihiG45S5xqU3NEtbjLsGvIOWJMMdo/DhceCgYsWHlOSS+jH
         vtK1nbr+rf4Z99JagyDW9nqxLEgrTNZR+1Z+ztVmLpvS0IrH7ax7GD9kH+ctFHMpWqi2
         Su7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=m9AWLvmf8FBnqRphnpSTCg8YUtuRSsygQKpt+AoAvTw=;
        b=DR2sabLX6oA0gIeB1WcELQmoaYjBtEEzvLx4yXUKtlq549y4NOddFCXMzvwtrtFLBY
         wqfugwZwwIbQN5/r289n/WnfLUv+IJMZ4FynUB3iTA8tXyLpYhekP1FUC0i9N+AyUW7V
         KFApodmtxG6/qEoJm0Qcn2heFPYcSJ7KSKWq/lJrQdLwaOlZP3cwc/4ucnZ6hfjskCw+
         ELKtFm32Vph6tZgtIBdKVRaB8r2J2VIaxGhfFlZ04/PwncJID+VAcxwTvphQWjkVJWx/
         ZyZWVv/LdURxKaHYdF4jlBPXYgPDatllHq3XN1unEbVBbA5NoT3RydZ1BnBk/IW/sHwF
         l/AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AiKuJ0pU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=m9AWLvmf8FBnqRphnpSTCg8YUtuRSsygQKpt+AoAvTw=;
        b=skqKmaLDvnUUrKyZ6gN8OUDpXp2HEdxsJDHYIcmIo38aXAxW/x7gQZcsQBg6bg7Qzr
         okGg7zkbQcoI6Lh0GfUDq0yqoIb5CEyQhOkNTb3cfdZk1qN1QtvlIR0nHEar2ZbzyNoG
         jZKLRMkImK8QCRjPuEYWQJQKex26gSiDlw6qWHhm+1C+mKLuYaWedXtKXWOrbHC3Gzor
         cMdfMYrHLQUgKUv+cyHtUil5RSlzYY6Q9QoZ0jZATmwTwPZSvKPmXlIXatkYnEUK3GTS
         3mYN3Y350mV0gXCDBxzQuS3UHECaNuerWJVBbEdMWsSADScUAO1t5q9JZRr8JWAAYC7b
         b0BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=m9AWLvmf8FBnqRphnpSTCg8YUtuRSsygQKpt+AoAvTw=;
        b=5zUOySFbYx7Ev8NnfdFWQjL4IH0xwORdTlAv3ZTtZtxito+4Codh1ZEtjkKwXhDts4
         nAOlgkJ4iEz/79yBpXgrvDMCgqrCbZh7MQe0P2+fVAtfkOcN+13HUuYJIfu0udnrl8I6
         FjUVP0ELeG6/xWtaWmt3rBZYyzFjnyMzvuknB0FppjWsKLGZpEUmkFV0WvFSG5qKS+8D
         I2Je51e9GS8C3+4dcFJHcX3T3DrxEYIKeXOc9BvLhm1rnqBLyxWFUx5T8CbkE7uW5QwK
         ax9k2PW1yGXWPx15y3lwvMwBIsIOickRrofSzDLNVp1KP3tRQ5ESb/Z+L+55iNT14zno
         TvrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2ftJa2zuhXMJrhmh8LiJiiTTAV06191/TshsZzXO09+BwBUUwz
	ReyqLbyfaQmz/Q79cALufZg=
X-Google-Smtp-Source: AMsMyM47waIqOMxrtqDAk86ShBFlOVaOa/aFyJjawGPN7vjV6IYxjWOMrbyB6je13JFKttiFJNX4jg==
X-Received: by 2002:a05:6402:3552:b0:451:2037:639e with SMTP id f18-20020a056402355200b004512037639emr1466251edd.136.1663275523101;
        Thu, 15 Sep 2022 13:58:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c2:b0:44e:93b9:21c8 with SMTP id
 x2-20020a05640226c200b0044e93b921c8ls286566edd.1.-pod-prod-gmail; Thu, 15 Sep
 2022 13:58:41 -0700 (PDT)
X-Received: by 2002:a05:6402:40c2:b0:44f:963d:1ab4 with SMTP id z2-20020a05640240c200b0044f963d1ab4mr1409421edb.319.1663275521825;
        Thu, 15 Sep 2022 13:58:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663275521; cv=none;
        d=google.com; s=arc-20160816;
        b=yv2BJHLkfEZYQgX9BEzFfcpJZTaWqtm2k/NB3UXfDBbhl3rfDefYCc2XAjjVwKlq1j
         Q0Aq9YRH9W+gL4yx3c7pHYyoASUIeP0p2xTlt1UlTX6WeJ5sR7LBYvH3+QkfA2k5CQe1
         vIBu3QW9vr17AaGWHqw8TWOkOOuBmEdLLd+dsjhhyCbsq6Ad9N25Rfab7zEV23ucgBRi
         5Tc59HqmvH2HFWNWAYT9yaRafIcU1yL6VPkTOWVDqNCJy91TsF0BG2GobCYVPMW9pniH
         fOHbrG9ZICk6LLBwv2MQ9JjiiSlZIsT1rybeTpR2T/FRgO2Yn2eXaMRSWn6/FPsZI72o
         cZjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WAzq6T4IcWcpMCLuyAzl7o0sCBrlUXNcyNpqxHsFyQ0=;
        b=hBrjqkMPmUlN7o5EUnOKmT7UBx/oKlt+SMGwhL7KLbupDM0lqgOs8ER91ilHtmYybL
         /vtfsLpph1Wks/OgIq38cR58Yq6sK9Y6oRiVKnXs18qHm6bmFi5RCiDNVfZXqiaBvpKs
         bE7RsTiYjadA6Hww/wvx0upHi8MQwmDmhdIsHvN9V15iw9mMwJ/jwAexbfwidPnUBvuX
         iUGcroKXu+4Hy/XEE4mn0wgYCeazJTlnaaiQVqrQovpwfTjs2QT16IMNDbFxeH6twPMM
         hVHIG0cE33yI7GD3WTpVUI7XoeXxQifDzXdzyvD3hedIQxs9Gzf1wlJmXC3bP3Xwba3X
         32Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=AiKuJ0pU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v21-20020aa7d9d5000000b0044db0bb77bdsi593924eds.5.2022.09.15.13.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Sep 2022 13:58:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 610D7B8225B;
	Thu, 15 Sep 2022 20:58:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0A6C0C433D7;
	Thu, 15 Sep 2022 20:58:38 +0000 (UTC)
Date: Thu, 15 Sep 2022 13:58:38 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski
 <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
 <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, Eric Dumazet
 <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich
 <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
 <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
 <keescook@chromium.org>, Marco Elver <elver@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>,
 "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>,
 Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>,
 Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt
 <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 27/43] kmsan: disable physical page merging in biovec
Message-Id: <20220915135838.8ad6df0363ccbd671d9641a1@linux-foundation.org>
In-Reply-To: <20220915150417.722975-28-glider@google.com>
References: <20220915150417.722975-1-glider@google.com>
	<20220915150417.722975-28-glider@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=AiKuJ0pU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 15 Sep 2022 17:04:01 +0200 Alexander Potapenko <glider@google.com> wrote:

> KMSAN metadata for adjacent physical pages may not be adjacent,
> therefore accessing such pages together may lead to metadata
> corruption.
> We disable merging pages in biovec to prevent such corruptions.
> 
> ...
>
> --- a/block/blk.h
> +++ b/block/blk.h
> @@ -88,6 +88,13 @@ static inline bool biovec_phys_mergeable(struct request_queue *q,
>  	phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
>  	phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;
>  
> +	/*
> +	 * Merging adjacent physical pages may not work correctly under KMSAN
> +	 * if their metadata pages aren't adjacent. Just disable merging.
> +	 */
> +	if (IS_ENABLED(CONFIG_KMSAN))
> +		return false;
> +
>  	if (addr1 + vec1->bv_len != addr2)
>  		return false;
>  	if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_page))

What are the runtime effects of this?  In other words, how much
slowdown is this likely to cause in a reasonable worst-case?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915135838.8ad6df0363ccbd671d9641a1%40linux-foundation.org.
