Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTWE7OGAMGQE34S6HEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9819545D254
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 02:09:35 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id w13-20020a05620a0e8d00b0045fad6245e8sf4325560qkm.8
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 17:09:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637802574; cv=pass;
        d=google.com; s=arc-20160816;
        b=rl0DWtubNq4LJ0U+qnrk+DujjCIOPz0IEakOfDKOlbp5L2PEasgskV8pH9lxAnW6Kp
         Nb7MV+02AH6LXTA+XFfUPfYdVg7s+VbXtvLBuUjZhllmSNDkcJVPueV89YYxJmJ25bwO
         Flp0ZNokJKl2F7Ox7b8eF0ULUDb0UyagQe53nus7EHRMFNqTTG1pKsyRMYhjhAieCDOz
         mjvMUvMuJmscXPuZr9QS0EHU4Q4Pk8P47qzoCSL4vGRMIbu4sDn90aw0413oonf1Vzzq
         aKbee0Cr8l50EW1z14gOjvZcIPfWdY6Sy/I8f1wHlsvJBjoLa+Q7yY2lizF565VqB4JX
         tDGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=t+cUXcdy2pO2MVTSJ7VWQz1/BwS6HJGXylcAX+9EKTI=;
        b=UbunJVY3rJ0uk1X6qUDBkk8jP751qaf2tGPYtCHw8QV9vEFm2xqZdXTA63h9Pw4lAG
         SWwDIrFF5Rve2AKQVDAbeg3V502JMpulz7HvkcViuoz3gG9bukWlFctO6lHQkZyukiuj
         XF23K8ZQgnGq4JTbNXEH56IPAoze1OoIfC7+rBDxpTn17g9fp/rWWK4TVqOYHz/QVBLO
         4ORSjNP7GoV69Fm3zZiYe52te+hbLGI5lBrBBOPNrfg8/6K2JAH8lqTozcprTrj64t2z
         REh7RnNgIJ/oZLSJJYlgsR6a2w/srFMx3uvEmLAsB7muV2aIEInTqCBseJzZSPIhyVDZ
         2LYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=t+cUXcdy2pO2MVTSJ7VWQz1/BwS6HJGXylcAX+9EKTI=;
        b=Rt0Zjvz0HSRWkHxsNhlFcpwJ6SVKEnhJr7aWEXrrKlek/LqXSbayj1h6qksVM+Hc9a
         AJ5jTqGVUhoHIMWQfiNy9V+3Uyb4/8jE/W2xekA3Qj6SwtG/0XHFY4jYm0fM9sC/bsQd
         oPXz3kdMOqbHsEF87J8ptIxiuFinMoHGKuadWl7a1g2750rcQ74IBl5y/aSrx59k+Uo6
         szNM7JvrpDbkz5s+n5QqrBg2sIf6DFi8f/B11mfkNCLiQwsGk1fqL//hH6lPHP9bfEqS
         PuX0fxW1nc1DXExWrNMgl4TdF7RfH5qHy7//UuK//AyGNG2Axx+nL+Rjp8BRJh4T6yUw
         tuAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t+cUXcdy2pO2MVTSJ7VWQz1/BwS6HJGXylcAX+9EKTI=;
        b=U+JTN9j7B/rcSJWgIsLHisze64yNqPYVa+X2ZM1jj2E8N6cW0Tye1Hb2BpRf9ZF7X2
         fCu4xbNVGIU5yeMjHHvQumlllO3KffjbZujy46hGTP+shKuIz7IdL4OGS4C9EUjACjC3
         UkXwGYSs61BBS0SYipMrU+SwIHJ+wGZbuGe1u06Xvy9V0Lc3n+koViVydCblsTl1bhBH
         CNtAOeUIheOoftoq/fIPS/2n8hXroxYgphZHin7Lagd4omvaxO7BnkIJkJz59i4IGxQt
         qYAkIj4gf03dmSayIEoLjtzs5vexf8zcd/tchT+mAb9u1Nhxrty67IUtaVXTlw2pNJmu
         wEiw==
X-Gm-Message-State: AOAM532GJYn1oZIjD718F5ZQpDbPa3x5KAnyPtF0lARgPWVelvC28XAp
	aBtU98sOYuD/WgYQxIY0l4g=
X-Google-Smtp-Source: ABdhPJz/XH3L1SUlkg/2C821MLjt+IR+ns89Qu85ZYoD78LwDXoLiV8qCKbHFLlxjG5Jhc+6Sk7y2w==
X-Received: by 2002:a37:a714:: with SMTP id q20mr3096342qke.688.1637802574541;
        Wed, 24 Nov 2021 17:09:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:294b:: with SMTP id n11ls972169qkp.3.gmail; Wed, 24
 Nov 2021 17:09:34 -0800 (PST)
X-Received: by 2002:a05:620a:46ac:: with SMTP id bq44mr11351447qkb.414.1637802574134;
        Wed, 24 Nov 2021 17:09:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637802574; cv=none;
        d=google.com; s=arc-20160816;
        b=Nreelc6nm1g4Hn/R/ieLQTgShEtRACfrmzoxJTK+8T5kmD0sX6y8bMjtcI2iS4KKdE
         OaahyRBZrnBlx7lDjETLRLiskcq+g8mm0zJC4xO0hZT3QBN/OIV+K5TQHv2VCw800XWY
         7f1mikW2RV5SMhuTCHU1I0qbzfZwB32w1l3CGNyeLszwzpRTexaH/3MzqBNoLWzVqg5T
         8aqFustFuj5RJ7DckdzNyhLeU5sBWyCCATNLbkUpz7igvu7yPoFbrPsuPi236f+byq4G
         DkR2gB3fBhfAy6TEzhzyZsvIOyebImlnYcrTCHY5Xkgq9A+A11tP0uZibgSmsBCCA04X
         GoeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=da5kwA6Ha76W1JfVQo56W9OauwHE47Hs6GnIwvn4j04=;
        b=YOXM80GTLEjz7pJ6EsLqLBhtQMuV0RL0czxWywuSElv7zqaCOj7/IBtofQIiBFJGyu
         OmI4uVyewRNK5XQoNVJGi6l1FzVs7p5ldxum8TPZEhU3oPY+vji1+e044pMbr8HW8eQA
         ySbDe6uK6oox8W+ch0ESqsjuTGAlSzMyi51YZ39NrF0d++p3/goI7+JyqV9R7oVeaiGu
         vKM+iTVO76DYmnCSvWFUqCUUQ8MankJG+pCllQt4gSNKp6wKloYAWF1tqR6LvHY1SHY1
         CfVdzaoKVufEMUslK9MueKjKXX5dU/z4ozREW1TWp1oQzRKH4pjMxrhr/XNqSq+5qSFI
         fuHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id d14si215011qkn.4.2021.11.24.17.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Nov 2021 17:09:34 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm500022.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4J007m3PLPz1DJWs;
	Thu, 25 Nov 2021 09:06:28 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500022.china.huawei.com (7.185.36.162) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 25 Nov 2021 09:09:01 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.20; Thu, 25 Nov 2021 09:09:00 +0800
Message-ID: <356d857b-1813-6132-d4ae-5bb41190a1a7@huawei.com>
Date: Thu, 25 Nov 2021 09:08:59 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH v3] mm: Defer kmemleak object creation of module_alloc()
Content-Language: en-US
To: Andrew Morton <akpm@linux-foundation.org>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-s390@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Heiko Carstens
	<hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Christian Borntraeger
	<borntraeger@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	Alexander Potapenko <glider@google.com>, Yongqiang Liu
	<liuyongqiang13@huawei.com>
References: <20211124142034.192078-1-wangkefeng.wang@huawei.com>
 <20211124135014.665649a0bcb872367b248cef@linux-foundation.org>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20211124135014.665649a0bcb872367b248cef@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme701-chm.china.huawei.com (10.1.199.97) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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


On 2021/11/25 5:50, Andrew Morton wrote:
> On Wed, 24 Nov 2021 22:20:34 +0800 Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>
>> Yongqiang reports a kmemleak panic when module insmod/rmmod
>> with KASAN enabled(without KASAN_VMALLOC) on x86[1].
>>
>> When the module area allocates memory, it's kmemleak_object
>> is created successfully, but the KASAN shadow memory of module
>> allocation is not ready, so when kmemleak scan the module's
>> pointer, it will panic due to no shadow memory with KASAN check.
>>
>> module_alloc
>>    __vmalloc_node_range
>>      kmemleak_vmalloc
>> 				kmemleak_scan
>> 				  update_checksum
>>    kasan_module_alloc
>>      kmemleak_ignore
>>
>> Note, there is no problem if KASAN_VMALLOC enabled, the modules
>> area entire shadow memory is preallocated. Thus, the bug only
>> exits on ARCH which supports dynamic allocation of module area
>> per module load, for now, only x86/arm64/s390 are involved.
>>
>> Add a VM_DEFER_KMEMLEAK flags, defer vmalloc'ed object register
>> of kmemleak in module_alloc() to fix this issue.
>>
> I guess this is worth backporting into -stable kernels?  If so, what
> would be a suitable Fixes: target?  I suspect it goes back to the
> initial KASAN merge date?

The kasan_module_alloc() was introduced from v4.0,

s390: v4.20

793213a82de4 s390/kasan: dynamic shadow mem allocation for modules

arm64: v4.4

39d114ddc682 arm64: add KASAN support

x86: v4.0

bebf56a1b176 kasan: enable instrumentation of global variables

> .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/356d857b-1813-6132-d4ae-5bb41190a1a7%40huawei.com.
