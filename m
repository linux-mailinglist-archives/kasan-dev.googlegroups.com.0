Return-Path: <kasan-dev+bncBCRKFI7J2AJRB355SOFQMGQEOIN3KCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 71165429AB3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 03:03:44 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id r10-20020a056122014a00b002a3bd59eda8sf2183578vko.6
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 18:03:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634000623; cv=pass;
        d=google.com; s=arc-20160816;
        b=NYmZCKE6MXaoFDGQntSvUaK72faw9Iadik6epAN3RfaYeMGFyEzUjJbNkwQNwBfCZH
         Fjmpmib/dhsAC8/DHklCFbzcP4odbBztey+z7d1xjcs89c+s44GypFYSbXNFiNyOjpK2
         w9Nt85HzmBuvq1/5Rtd8DUd5yXPVaNaEFCUCOgq+K94DwxlDFNXMP3358mFIol5L+NJu
         iJmf1yoy5HR70hICFGRkk+29Bt38v1mp1O2nsTHiK1MMVwBbLTHgXJShsMFDH7E5PFm5
         clZJOFkNZ+LsD7o/UzChSpn/4TZi+0l9DZIgqMdY6NzTNdlY2RrzgcIWSQ+2FtHG4klW
         78LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=qeuVcYl94ZjtExF/glyPHNpwhqR7tSUo5Vzm8uQ2soA=;
        b=aZkcT1JRYYXTHcLeryRTBwTvAeufkOd054JxYm6O5QghAjvhJt/RNEnaczhLy+XA3i
         ceGarqLVOjdjFZyPz5kj+LM/Joq++9lqmeeSVTJEu8ikHivhxSYuKeIEnwA+6SASBa3V
         +s6Vz0CUbRNy9fiW624R8vwUPHyx9hOpiX7MrBxR9bBy2+mBpTgnJaRf6iRaMjYZgfzh
         IXdcR/SKG39UH1esgZ/K6HR50WaOQeGgsb2At4/x5OLzLllpID7lW/ehwwcl5iFZU8wp
         jWGlm84OJxEVdO0Gf75h8dz5WdnMqGwYwVgsJ/De2wCA+Ndn/actsEd/h2Pr8qW5JnM6
         h43Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qeuVcYl94ZjtExF/glyPHNpwhqR7tSUo5Vzm8uQ2soA=;
        b=fv+F852cHBYSYeT8HBTf4hvIQefZNAAEkBcNfYNqUqLOi9kHZB0cn4HniExryMQFAr
         nvKddP2MHcZLwUvZnkHEv8PFS94heqDQPcYmDoq/l2M+y5w2a9ruViU/oln9dlON04al
         M0F0JVBGDPGiiZahuw9ZwB6Ij+5QEyru4pqFwi5eZstJQj0YcVe8inguCHLDLF+LlFvM
         EOpSTdBte7Yu7G6rSjfobukDih9ZXRoONiMyo+Ncopo+UmQyKS/lSBrEFbmaOfHcHQ45
         ZBYKJEQ0HaxEklGViRTu/eYMkR+pLahp8OHogCZepKHquxvvNngmmJa2TDnzVBeXQ7ep
         mH1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qeuVcYl94ZjtExF/glyPHNpwhqR7tSUo5Vzm8uQ2soA=;
        b=XAbHJ4eLXTFvI23vZjUWnad1/+ClSfitMOEvtYq13Z7OFKJJ4yeT1QsrfoiTAAduLr
         nuRnrGj2ckryx/XlFVjhXzbVqu2Y2M2abTSHuS7aravhhTO8fUlGwlSa6/HG3JB+htIL
         3CMQRytf7cxccqIw0AN9cQ7rfqAgHTF+rvNx08+z0BRqbGzx/0oDhNYY+b3nKQO/NZJf
         A4kEdpCkthyuqQtgC/Jlz06OafdPwPwX8wdp5vqABNejkPQUgSzxcjSl9VE5OkM/2koe
         ESjsGxCFgETThtwH8iqQ35HO7pG1owUajojrAGT3yMptNt8WvAJGnRgWey7+2lcCb3dj
         5Smg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532owOb/1eh5PSmAMkIi9Le5Zy1p02bKlMX5WDIoIJkiFzQn/ByH
	gB9GLHp4bEMIK77UtKkMJd0=
X-Google-Smtp-Source: ABdhPJwuS7YLV1W38gxw/WbrQC/fGyi1KWOGRmWNhwRl7/zDdortpkyAVbgg0M4fmOJMfIwnrwk7Bw==
X-Received: by 2002:a1f:1bc6:: with SMTP id b189mr23898042vkb.15.1634000623371;
        Mon, 11 Oct 2021 18:03:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:34d8:: with SMTP id a24ls3049711vst.0.gmail; Mon,
 11 Oct 2021 18:03:42 -0700 (PDT)
X-Received: by 2002:a05:6102:3e84:: with SMTP id m4mr26013271vsv.51.1634000622891;
        Mon, 11 Oct 2021 18:03:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634000622; cv=none;
        d=google.com; s=arc-20160816;
        b=YH3BGJ1FbM7Agf855h3nYsT8/1/RG6ebQIulFTCjj/vqfWaxMEcch2IrZn4XgulWOM
         UZgvESy2b62NnT51TmAPACS1Gwzwr/RQ8WKW43o4tLbw4vyE7sD48PARwfe3uSa4BIPK
         xXkzqLpt8JZHb+D/TLNrd8kKzNpgvJZ0uXME2JhqXyEZpbqRtaa7LJJlSTjF7jX9Vy30
         o8r0w1X5Dah28rxQAiVJJUXQamq0jPUTawK+1kz6O19S79n7nH9J8CTh/WTz0D4BiXWW
         zmu1sgUHmyP9siVX5dip+d81N8zu48Ij9XJiNKwspfuPX2NN5gT82VCLb5J/53RgBkv9
         uqGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=HC19gpeFovHUcB3vyj0/n2jojgWRIsxlxViPobDW03g=;
        b=FRpSkIoc71ELjVzRkY5zgTLVJ7BuGYncIoRtB5ophrsYz3qNgDIBJxHLpkNU9413wX
         U4WBZuI8fC8TSiICbVWlizeXaOn2qTv5r8DedvVW7+3Gtfj9O9UEtDTp3q3qt2yTCkW+
         iy4grLpd0gXezRPfgVbvX/ZXaT/xvMG/O3V3jupjxtOgw1vagUkFzylZJzalHHAp6U9l
         hTwVoV7EXBph0H8R8ep6I9vxy+OoW4jPrkEH+E3l0w3YAqUsCrMrZaSynEbDcyNJwfRQ
         LwY40j5uAsIQlu3zNbuDf1CisPDur7/rPrp9QDVl3t+RzLhqW8LZmu97z4W3nMWDSjWD
         lGCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id u23si797552vsn.2.2021.10.11.18.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Oct 2021 18:03:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HSy3G6HCHz8ypD;
	Tue, 12 Oct 2021 08:58:50 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 12 Oct 2021 09:03:39 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.8; Tue, 12 Oct 2021 09:03:39 +0800
Message-ID: <3796d319-10a9-9721-f300-44a28f1f7507@huawei.com>
Date: Tue, 12 Oct 2021 09:03:38 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.1
Subject: Re: mm/kasan/init.c:282:20: error: redefinition of
 'kasan_populate_early_vm_area_shadow'
Content-Language: en-US
To: Andrew Morton <akpm@linux-foundation.org>, Naresh Kamboju
	<naresh.kamboju@linaro.org>
CC: Linux-Next Mailing List <linux-next@vger.kernel.org>, open list
	<linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, kasan-dev
	<kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Stephen Rothwell
	<sfr@canb.auug.org.au>
References: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
 <CA+G9fYtD2EFu7-j1wPLCiu2yVpZb_wObXXXebKNSW5o4gh9vgA@mail.gmail.com>
 <20211011135345.9506437ee2504a81054dc06f@linux-foundation.org>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
In-Reply-To: <20211011135345.9506437ee2504a81054dc06f@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme720-chm.china.huawei.com (10.1.199.116) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
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



On 2021/10/12 4:53, Andrew Morton wrote:
> On Mon, 11 Oct 2021 18:12:44 +0530 Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> 
>> + Andrew Morton <akpm@linux-foundation.org>
>>
>> On Mon, 11 Oct 2021 at 17:08, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>>>
>>> Regression found on x86_64 gcc-11 built with KASAN enabled.
>>> Following build warnings / errors reported on linux next 20211011.
>>>
>>> metadata:
>>>      git_describe: next-20211011
>>>      git_repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
>>>      git_short_log: d3134eb5de85 (\"Add linux-next specific files for 20211011\")
>>>      target_arch: x86_64
>>>      toolchain: gcc-11
>>>
>>> build error :
>>> --------------
>>> mm/kasan/init.c:282:20: error: redefinition of
>>> 'kasan_populate_early_vm_area_shadow'
>>>    282 | void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>>>        |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>>> In file included from include/linux/mm.h:34,
>>>                   from include/linux/memblock.h:13,
>>>                   from mm/kasan/init.c:9:
>>> include/linux/kasan.h:463:20: note: previous definition of
>>> 'kasan_populate_early_vm_area_shadow' with type 'void(void *, long
>>> unsigned int)'
>>>    463 | static inline void kasan_populate_early_vm_area_shadow(void *start,
>>>        |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>>> make[3]: *** [scripts/Makefile.build:288: mm/kasan/init.o] Error 1
>>> make[3]: Target '__build' not remade because of errors.
>>>
>>>
>>> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>>>
>>> build link:
>>> -----------
>>> https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/build.log
>>>
>>> build config:
>>> -------------
>>> https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config
>>>
>>> # To install tuxmake on your system globally
>>> # sudo pip3 install -U tuxmake
>>> tuxmake --runtime podman --target-arch x86_64 --toolchain gcc-11
>>> --kconfig defconfig --kconfig-add
>>> https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config
> 
> Presumably "kasan: arm64: fix pcpu_page_first_chunk crash with
> KASAN_VMALLOC".  Let's cc Kefeng.

Yes, I send a fix patch, and reply this mail, see
https://lore.kernel.org/linux-mm/5077aa7e-0167-33b6-35f0-0ea7df8f2375@huawei.com/

> 
> .
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3796d319-10a9-9721-f300-44a28f1f7507%40huawei.com.
