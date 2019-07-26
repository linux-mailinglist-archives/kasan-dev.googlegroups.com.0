Return-Path: <kasan-dev+bncBC5L5P75YUERB7XO5PUQKGQEN2QCJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29C3176675
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 14:52:15 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id b1sf25612331wru.4
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2019 05:52:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564145535; cv=pass;
        d=google.com; s=arc-20160816;
        b=CIwTMpEUA9UquITOlNsAaOd9EGLmtp5wHybAZ6NpRhmUWhZ2026UbJfKfyRhSvj4fI
         /F8uJo+T9ZlOxoq0a/toG3mOdQojkzOWWSPmuz38OnDWixLuW3LiHQLfwo1ABfaJJnuK
         Td9NCAA9j9d2v3yoTZMryQZm97xxAu4McXTvDfoTG5f67hVDaHYv34YFbHrUGBXDrT0y
         EV2nglZ6QHQA3GWDNWh0E7IWRyAx1Ihvs5gr1NTjme6D9f25G0aOlbWr8jsCVfQTfeUJ
         F2sGn0V8GWKdqI+6mNtNNNZegXb4/oS1i0oVCIl/QcQJoiHfHcOcMPHVakqnSBFgmfQT
         9PWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=vwgOteyqTlJXd7BVruRvO2ojx2UqzhVttVJPqeI23eQ=;
        b=pRVFSbQwX8ddqdPtR9QTIbMME7NZnsSIsRcPNSKrrmAqd6ucNA1ovYwRkLTG6xPpo5
         9FY+tNq8S7DUAHB6BfxACZUvBAOVYpwn00MIGy08UabH17gfe4fQuRJBroIknbY8h3bj
         Jhi6iI56OD1sxHqMB+x8EjCvFES9j9ykvbwDBcnhdjhXFcFHp+S6ZOc66BaJdeVoGZp1
         XAHEZUQ64ho9wDNIkbKZ2dwC0eSzqDeNYgx3PZB6JJN1Tkyz8kXHdQ4ucSSluZJ0QUDC
         /oUz+2/Gf6JU5nnjCXFxk9T0j2wTZ6MxirTAR4o8oAP27GCGg9IFRmrxum1O6cATeetS
         I9BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vwgOteyqTlJXd7BVruRvO2ojx2UqzhVttVJPqeI23eQ=;
        b=lzyiAgsQIsct/rpPWOmWeckS9gX53RxsTpGpJCeL6VzDpcRCrM787ZmtujLt1j5LG7
         HqJbWiJ8QSqpCeBen0BzovzB3Zn4Chm9ABmL82ohEQLg63x/+MB2exIog8ok1yN3tFW0
         4tDCg5rNi3pAdq+MzXXwU/qDn4AOZTVHgy36VaRo2pA92xZ6CsreOxVJTKYv3/3GMMT/
         YKzNxtAOF+EkVf3UmJFLG73m6wUJxBqsMXaqZfliZUUU/xlVydJjghsH3CKIcFiQYKb4
         a2rciQUPKCVXWiB4k1QUEZY6nq4OKgZkBp7DEAtSLBHhg2Xw9c+Q/Sk7cyuD4i+eMl7D
         QBXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vwgOteyqTlJXd7BVruRvO2ojx2UqzhVttVJPqeI23eQ=;
        b=RWCiW7FCCMS/UDp/A3rqI+rAudxd+CXdgLJ5y82PcLB427WT9MScL+ei1/XyX65enH
         B6JyYOqMj0gLB5/so/cWUYdmX6ilPJILaGLfYK0NA9txFewv594Q9ux3CeyFEhXUd1VY
         Xv7gQxug+Ko4xVgumxhc0vExYcfC2RyHxrx21XfsZF2hgxtVC/7BFpctTsD2NxyKDdLb
         mB6RdRGvklAWD95I+F028ff6jj42vurlDEbOFa6br9IKJ3OLy47HIvuUwWUNa6aLEzTN
         sdE1nDyaCp9ys1Iyixx0/3nsC/q0ZLoiCIadiuYvVwIrMogrJvtEJ55RuTFQNAZVSc2J
         nEVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUdQZgo+kY7fBiSLjKthHhONVng7cV58TiGO8Jip2vwky98ZzhG
	lZri5Vo/hWPlW/GJAhJyl4k=
X-Google-Smtp-Source: APXvYqxbvtJH1wwj4VMMVTB44bBEGGyl8EGzBebwaigvCd+7tnsHCNLhPo1CpzVj5ifF5Hq2KjqdCQ==
X-Received: by 2002:adf:e50c:: with SMTP id j12mr17546642wrm.117.1564145534910;
        Fri, 26 Jul 2019 05:52:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:db44:: with SMTP id f4ls15876968wrj.15.gmail; Fri, 26
 Jul 2019 05:52:14 -0700 (PDT)
X-Received: by 2002:a5d:4087:: with SMTP id o7mr58290798wrp.277.1564145534551;
        Fri, 26 Jul 2019 05:52:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564145534; cv=none;
        d=google.com; s=arc-20160816;
        b=h80JYEg3TvAXqg+BI7ScqjxaQZddGvXTj7KF+Hqh2FZX7C/dbtacqzC28JVG5/0Ezv
         Dm3y3vsEzuOkYwMzfWgIXtRDJOzhDGBG0FLz39NRYoFlmU5jT82OQup1mDojLnQgWqKs
         VyX6Y4dO0EtneYzEksk9I055omKgEnIEcKxBdYVE9f+GinbfWWgRRE+EARsbMgoJ8if6
         PmIkpiuyMTU31rc/uY5zQVRhfSAzdIjpEi/Agt5HRn+KX/79T5OgLPxcgtfZA15PDKlI
         M45bN/OleFkoOuOmveiL2p3dy75VDd7F26onrDmH8zuhKzR5NWzR/Ug+Xu8XJ0IGzBav
         SqdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=+E2gPxrIouv9oSF6tb6T+yMioGcNKU3BukFFMkra0WE=;
        b=TsUCrctDOPBFw6oLSLfOeW6qOaIzSPc/B1do+QrAegUmmb4B7TaSSxa9lncErLwyMG
         5ksa9WCBqJxz5ndT7kfyvnidzv/ZbCHIfUwq0VIlv2M58vEeQ/6bdTAK2v+cUmJiERkt
         PHXC3HkvjOHeaJhoSZge1KeMDH+PrySwfihHqoTOA5DmghUdP2M2MX6wjWp7Ez+qIKMS
         F9HOTtBSrwGg7EA/vbh4T0lu4waRMRPaXrHN6RUBomb465J7owySmW7YJZFYWGuyR92h
         hZOnf1NT6NUZxM8gQt28pa8zjc3lzJUj9L4b6eW42+TRhddNHnsk6e3ePGCNZ5JYhigs
         LEyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id y4si1459686wrp.0.2019.07.26.05.52.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Jul 2019 05:52:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hqzhc-0007Xf-H3; Fri, 26 Jul 2019 15:52:04 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
 <1560447999.15814.15.camel@mtksdccf07> <1560479520.15814.34.camel@mtksdccf07>
 <1560744017.15814.49.camel@mtksdccf07>
 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
 <1560774735.15814.54.camel@mtksdccf07> <1561974995.18866.1.camel@mtksdccf07>
 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
 <1562640832.9077.32.camel@mtksdccf07>
 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
 <1562839579.5846.12.camel@mtksdccf07>
 <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
 <1563160001.4793.4.camel@mtksdccf07>
 <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
 <1563789162.31223.3.camel@mtksdccf07>
 <e62da62a-2a63-3a1c-faeb-9c5561a5170c@virtuozzo.com>
 <1564144097.515.3.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <71df2bd5-7bc8-2c82-ee31-3f68c3b6296d@virtuozzo.com>
Date: Fri, 26 Jul 2019 15:52:10 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1564144097.515.3.camel@mtksdccf07>
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



On 7/26/19 3:28 PM, Walter Wu wrote:
> On Fri, 2019-07-26 at 15:00 +0300, Andrey Ryabinin wrote:
>>
>
>>>
>>>
>>> I remember that there are already the lists which you concern. Maybe we
>>> can try to solve those problems one by one.
>>>
>>> 1. deadlock issue? cause by kmalloc() after kfree()?
>>
>> smp_call_on_cpu()
> 
>>> 2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?
>>
>> No, this is not gonna work. Ideally we shouldn't have any allocations there.
>> It's not reliable and it hurts performance.
>>
> I dont know this meaning, we need create a qobject and put into
> quarantine, so may need to call kmem_cache_alloc(), would you agree this
> action?
> 

How is this any different from what you have now?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71df2bd5-7bc8-2c82-ee31-3f68c3b6296d%40virtuozzo.com.
