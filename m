Return-Path: <kasan-dev+bncBCRKFI7J2AJRBLWC4WDQMGQESVTFOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 50C4E3D2330
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jul 2021 14:14:39 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id bk12-20020a05620a1a0cb02903b899a4309csf3973665qkb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jul 2021 05:14:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626956078; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jn8Pl7YXBaYacmmyyTHS1T7k6OIKkbFJXicnV0n8lGU5wy6+po3i6zEZUMX1Iaaqpm
         N19U4fUJQ9J2uIRGiqe5s/ocmQfRP1inj9JTX5MRRxPyobXb/KbYlGM8DdsBw5p56bdO
         OypVaLzTPTD/PezBKRKDEEqz1xuWdC+FwHs+gDATEp4JyIP2rhYFGpWSVaTNKYrSWkpT
         iUQu4BIZBRPXL2XhJmBc2qrdsLrcozktIoAXJ0FkpAyEZ26TBjyh6xnSP7s8p0K/U7Na
         onO+RzusMtsemObJbZGcj2R/y51G1lVdDviVt76w4opxtelOpocF3rQUCFrcBWZRf9PC
         nuvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=PuYi9MnFzarAkgfFEZAkUVk5738r8DZLYJFKXsJf7ic=;
        b=kSejwNgtvVq239DyCS4yElegINUb+KLi1AvLeaCY0gF+9mutdpOhSQ7/E3AawdAGS5
         WPR8JI01nwQTG9emBJbA3E541LX2JZ9wga1buulkIm4IcAMG2D9mWeaqFmBsrACW+bN8
         xBUHex2eka+TlgElyukgqJVDT6knKPzeNuFlz0vYPatNBhkeJiBoJmBlJY+ZSbd9UuqM
         XwOemOd1Xz2x4vUa/PqBcLAaG8xE+xqh4To8+eplch6fuQXhvGO4gmvW/ZoZkqVugway
         gCWmzTxXnCdwMJf1/lCD3Wleh0KstDqPDGjbgTS8doe/4IZ/MPK2vMLqR41zVZ4TS9fL
         fu5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PuYi9MnFzarAkgfFEZAkUVk5738r8DZLYJFKXsJf7ic=;
        b=JUozYFioRo8/rs4f3qqeeIykChcDYhTAVF//aL/2k1EANrJn0fdVXmRwfmOQK7JkoA
         dp9pvRjIL44w+Cx9kHzJs3284Cy7XKuru3fCThj7l+i+wJd7J+0fLQBk7TfUm8fPj1E8
         KQz3KXAfkfCbq1S+IDYcitmOesanCCZRWvbrLoPZtlMZqIIyr7YKVz0cWwJiSqoLZr0u
         Ei2PSttcJO11vaf/8OdjIVjX/wJ0rCQmcJkxyf97nDE2z1WPC7r+gagvtZtDgx16DEqM
         Ds7qCAKkNNGb33FFSv9AM9SL/wTDBLnsgPyBaGfPE5vM1nsqq4IM4gPWwWHhnSHq2MGV
         hyGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PuYi9MnFzarAkgfFEZAkUVk5738r8DZLYJFKXsJf7ic=;
        b=aex0XLx7YvboWA0g2j+zCMp4L6gGueSZuz7mTvzti52Xs/cXGGOgVbzhtkUhaXaoWm
         aB/ATwaWWiRsaqYPMNab0RDg8J9u3/KCdjIvhDinQO3CoPdEz3796Y5/5S2kloZA4KCW
         6mhYA4oZGjAvINcPTWHUhpwxmigg4shlQrGHJDGqkVuNcA7NzX0MYXORvR9/3Yg4+QFI
         OiWBgkiyloV0HEgFghaRE5Y5PKLRpiSlrJNZ8n4f9BMbclv0LskK4Er1wn+DKd6UKSDf
         1WMmjCPKZ5ziXwz9KJA2ez1zpHfmbR7j53ObJLU1FNF8QKk5zDJe8SpaEzWuFS5gRy1Z
         dgLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530pYlEupDIUcwjyHqnS6habm3hVRYSGtDa5QHsdovkPBXap3R+D
	jXtrXwNj1OG4FOCYZ0XAjLY=
X-Google-Smtp-Source: ABdhPJyGMb0dmcC7td148SYYxTwl+PLFuc1dplauTT6Lz/GKmlzzCkXee6+AFirshHRxSL9w8IzxVA==
X-Received: by 2002:aed:30e6:: with SMTP id 93mr34910151qtf.41.1626956078323;
        Thu, 22 Jul 2021 05:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e054:: with SMTP id y20ls2151728qvk.10.gmail; Thu, 22
 Jul 2021 05:14:37 -0700 (PDT)
X-Received: by 2002:ad4:568a:: with SMTP id bc10mr41504274qvb.20.1626956077836;
        Thu, 22 Jul 2021 05:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626956077; cv=none;
        d=google.com; s=arc-20160816;
        b=AIPrNjJbMG0j7kv/TgGNikM8RgP3Yvnge4a97tkMhIDL1RN73Zo4IUy0JB/QQwhSLT
         vj80guhSiJe5v38Oc/5yeMaytTgpdMfmbsWsCJwlp0AySV6ifyZTBQHpu7BzILNbdU4T
         EbUTNoy28R5DH155QxIKGxiQvr1fXTdJiN6Yfp1NUssG9bHMX1EAX+0mB408gD2UKxto
         myZCDsl8dH513CcmO62ATBCmeUF2AB/J9GiooJtDzOZmlI5J0tDyCOkiwhl6d6hfNoKj
         R7Qn0nAJGPQYUovqmxCEuqJ1kxjynpQ6jnAO3guKP1eXhsWcdO8Gbau8AGyuKqrqkjsN
         qx1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=atsgim67h4jIXkxb1IXcZ5rEjMxaFMbz0a1N9t+8U7w=;
        b=KVRiPh8jqx8cSFszGNnA4LqtsixACeDNr7rMRyLVS47o5biyDsRyWMbdfNAccxCADr
         xQfG4uKwAcs9stEnLHuedRWvOzFI7FOZHodu1ubrY9RLi+wkOntDrHfknQTKf3GP0x+J
         prM3yOzDGI0Jig5KggNyM1DOx+xIFlekmLnPYFRdFBJvkz7orgNTmb0xh08GuniZ2dOB
         d2SvitKNw09/+g9Gf/wGmZmaB+aNxU9J+tPbdE179v41Ii4Ts4Z9lo5CEckdHR199d7E
         wK8a7gCBaMVlZch+5ixVvZvYIB/KP3RIsjcE0thsY0dKi0jYgqLaIr1gH0M3zGWHzsPv
         wavw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id y14si504089qtm.0.2021.07.22.05.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jul 2021 05:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GVrp63MY8z1CLm4;
	Thu, 22 Jul 2021 20:08:46 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 22 Jul 2021 20:14:34 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 22 Jul 2021 20:14:34 +0800
Subject: Re: [PATCH v2 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with
 KASAN_VMALLOC
To: Marco Elver <elver@google.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-4-wangkefeng.wang@huawei.com>
 <YPlP6h4O1WA0NVDs@elver.google.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <99a9334e-ccda-dde9-954f-6717946324f8@huawei.com>
Date: Thu, 22 Jul 2021 20:14:33 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YPlP6h4O1WA0NVDs@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/7/22 19:00, Marco Elver wrote:
> On Tue, Jul 20, 2021 at 10:51AM +0800, Kefeng Wang wrote:
>> With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
>>
>> Unable to handle kernel paging request at virtual address ffff7000028f2000
>> ...
>> swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
>> [ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
>> Internal error: Oops: 96000007 [#1] PREEMPT SMP
>> Modules linked in:
>> CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
>> Hardware name: linux,dummy-virt (DT)
>> pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
>> pc : kasan_check_range+0x90/0x1a0
>> lr : memcpy+0x88/0xf4
>> sp : ffff80001378fe20
>> ...
>> Call trace:
>>   kasan_check_range+0x90/0x1a0
>>   pcpu_page_first_chunk+0x3f0/0x568
>>   setup_per_cpu_areas+0xb8/0x184
>>   start_kernel+0x8c/0x328
>>
>> The vm area used in vm_area_register_early() has no kasan shadow memory,
>> Let's add a new kasan_populate_early_vm_area_shadow() function to populate
>> the vm area shadow memory to fix the issue.
>>
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> Acked-by: Marco Elver <elver@google.com>
>
> for the kasan bits.
Thanks Marco.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99a9334e-ccda-dde9-954f-6717946324f8%40huawei.com.
