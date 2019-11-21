Return-Path: <kasan-dev+bncBC5L5P75YUERBJUF3LXAKGQEA6NYIAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EDE4F105241
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 13:27:18 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 70sf521166ljf.13
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 04:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574339238; cv=pass;
        d=google.com; s=arc-20160816;
        b=cZSHGmLVmO0z39RuiYMAzrXe75ixwZSpSo5R97+SpWBJQGLmnBOog57VL3Ar3nCPwP
         jYUBROLZilo5jh607z60ALmd8LjkpDy3Iq3+vPwCfrsgOx34x4qvPlv3G2L6LYZnsvY+
         sO2ivsFr7Omblut7LwNfduIb0ET/O800GKvbGk4+YOtXmYAw7p8DbY145CfCXXNji12V
         ihccQFs9VUrMHvrJFANKOV3kaCHrSyXzIbWC8NLr7oVEVIvvmmoak0x8wJyjwQQJHWJa
         wwi9BUQUl9OnQPPjKjPW7cVYTa1mPgue9POkjTiGNKJm6+UlG7DuQdhX92KAVgdILWtt
         fiYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=b1nAhv10LeEWKWER5btyoiilbP+6l0j6tPwVAWvIsfA=;
        b=tc+K1CBpije+gvR/1H/kj+ChSwsQeddZCk7IkDJRmlIG4YrdcvcChPv2p0YA6KtJDV
         vRi3+pyEmDmoBvruLjMmhxdfNNkuL+J5hnd+QCkbabAPgOV60LrNh1QXfKZPlVtk31X2
         w5beZn41Dw6VOCrICPR4J+zVH27GKTUJEClSgRbkHYEo2/vMZiCPruA3PXFHGYYOe5m+
         Omey9HNIcHmy4dv1L3NQzSPkNe66lprkVUi7wkPCaOkYQG/xo7gluhw7m6Ku0Pxkm+BB
         hA5hwqMDYnXa770OPX6RWIj3Uret2AiDBeqxhapN9tG2YBRdBQiTXQWyFAfypjH+a+9E
         umVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b1nAhv10LeEWKWER5btyoiilbP+6l0j6tPwVAWvIsfA=;
        b=BBTbccxlFfHKEzHHacfjY/6LUaF3MQKy4ZSgL1pf+4hlOFta9abiUoZav3r7mobZIC
         iCmKTHW2ANOzrIyzhXHtmXqa11q10uNtpL8CGnwy4QXZ8QFi0uHrRbBZm1+X2ig4tP2d
         MjJuetoADkLFxGbMS+AmHxhxl/h+IhJIUwkzpDYv6CJt2ohgCj8TAYbnaM0E2uDL9w+5
         ijBSMaDwQCZtSumNT/hdi/4tgNTfUE5GUh0AENx7WtPWiSrT8VahoUc5F0ZlabwqBgfL
         rosnzljwiLB4eAIFJb0hWQaGMJm0GeW5lf0G4S+2Y0D4Hydby/xBUevVsS0v+X6/yzUp
         csog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b1nAhv10LeEWKWER5btyoiilbP+6l0j6tPwVAWvIsfA=;
        b=ib0lML0FFiFiOmtaOCnZD1Sq69ep+FJcW0X1q8fqprcjvwwMv7FKYTfkfTiAiXcCo4
         mMlBT+2NLHjPPALwKPRb6NIq/wTpzIMEXEv3hL8b2x2YnxSy8TA9oGlNLEGo1ffNvMcP
         Q2AaGds8ci5yrq2AeEJzbFTqOYBBvBaQzCFK25xishzO1YxX2wLaQ+pVw09/P5u7q92V
         hnGGrli6urv+SMER8ZlYIuqdCXp3uGf/CJELKTHX/dd1P0ocP8tUtxNH8DCj7L51iHl3
         DWH9zaCSXzI4j0SQmj3lhEaQcHqn8KTEKCFMW1iIC1mvIkmEH1DgaZHTHvQc1+Hpkvel
         ejlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUWXCdES+e6qRmhvudEzoPH7//SdbYwJh18IYNQj2pcQY1vZkFZ
	WRUV6x1GLvfYT5jKE80rX90=
X-Google-Smtp-Source: APXvYqzc4IyzLIZ8+RaEncwyPvqKHJudkCbo4CarOGSOrwtKm6cbqO35C8hEzTo+HvF/wAMLi1cJhA==
X-Received: by 2002:a19:7e10:: with SMTP id z16mr7335605lfc.1.1574339238531;
        Thu, 21 Nov 2019 04:27:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ed11:: with SMTP id y17ls715459lfy.14.gmail; Thu, 21 Nov
 2019 04:27:18 -0800 (PST)
X-Received: by 2002:a19:a406:: with SMTP id q6mr7490582lfc.0.1574339237994;
        Thu, 21 Nov 2019 04:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574339237; cv=none;
        d=google.com; s=arc-20160816;
        b=mFzOKGGEZ2L2jkLw8b3YW28AOW+A4Z2ycuE4SFAmPClsZwpFW+mB6vCj6SzdxqW4M/
         NFPX7GW/o5S4wp24fcI9lH6vp9UeaBmLSTI6U1fQ+bzmmJrywel9LsVejnNQWr9wp5xK
         M0igDTDgpmSzvQuGe2qvP8bdpNEPHOxpMjAz4Ns084DLAjxTPDDBd6W2mwcZ7SL+W7CC
         WGnlIVRTFyFWvuRYFSFMuV6GHKLFfAKVmKiIZsfbPe2UIxDWZJDKzjZ3NLiicJCgumqP
         /bM1+GAPgkV0X4krcF1ooizlmdlqdob3GejtRZePzuzxLwtv9YDq2ug9FLNeY3F249g6
         okfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YRH4RjUqX9yiI6hGKAh9OwDvvxLkSoCIt8I1YqnzAko=;
        b=q6gLrtZ1D/sKaiF/5ZotPd3SlYKsYm6ZjJu3smYhXUChDTfqW0WzHYsDQ0o0ACSvJH
         RMVHXyWPAq9xjc3Xxhz5pSadNNoOrRHTmClf46HwXaDIKPq8kb1+bpbr67MvWlEd+eqU
         Su7ws+e6hTjQXLZc+dZuvDSpXSmGPd5uQ1FLvrFTHnvl5eMFuSeWNDY9HHbA1jx1a0Jx
         AWX8wgUY8Z3kxkFaMrjNTceSs6iNOz90849PpIHINAA5SSyCLfqxBMjEeGY6/3kBdIdA
         lEyf82db8uUNoUNc1ESI1PBnmcx56ynynxCK0oEC4F7U94Pa4ITB8+3xpOYXTx7kkt/H
         Vuqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id b13si133321ljk.4.2019.11.21.04.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 04:27:17 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXlXu-00015y-97; Thu, 21 Nov 2019 15:26:50 +0300
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
Date: Thu, 21 Nov 2019 15:26:38 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
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



On 11/12/19 9:53 AM, Walter Wu wrote:

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..4bfce0af881f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +		return NULL;
>  
>  	return __memset(addr, c, len);
>  }
> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return NULL;
>  
>  	return __memmove(dest, src, len);
>  }
> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return NULL;
>  

I realized that we are going a wrong direction here. Entirely skipping mem*() operation on any
poisoned shadow value might only make things worse. Some bugs just don't have any serious consequences,
but skipping the mem*() ops entirely might introduce such consequences, which wouldn't happen otherwise.

So let's keep this code as this, no need to check the result of check_memory_region().


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/040479c3-6f96-91c6-1b1a-9f3e947dac06%40virtuozzo.com.
