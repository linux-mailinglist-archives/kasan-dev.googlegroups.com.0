Return-Path: <kasan-dev+bncBCRKFI7J2AJRBS5VTWEAMGQESOF7XDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32C093DCEB9
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Aug 2021 04:39:09 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id a16-20020a0568300090b02904bbc3b57656sf7499399oto.9
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Aug 2021 19:39:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627871948; cv=pass;
        d=google.com; s=arc-20160816;
        b=w0JkQNVfTMDqSfbSeFNFpay20UM7EyqG4HzZaFc8LChbJo0zaCEFXu3aPQ1xac3Zih
         fFvpwnzYjY8HCCdiC9LpkhDWKIogoRa5HBK+7Anf6GLVKSA4qptmFhHwX0k3o33nQid4
         apuejfef3+fz1r9gHTOBGy5S5ZMP8e7X4t527j4d6PMkfhKJv84lY1ARBdlv7pAzgBh8
         fUrkbuwxMsUINZEI8wbOGFXsOKBw6dPnxLAqQ5A9XEo2c4OJZnfBk9xzCZ40cUSJ5GK6
         s/24x0yZ5POtNPZj6/MgzHZxXUMPoXNLnK/1V2BpAGxJ5vTVEJu0bQKOmk0DuX3zua9T
         hh5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=yGsFwk0OdoLD9bhKmiXBu5oaK8VY84Q3s39aj8OGmOE=;
        b=xY+y4sL1Kpx3qBWPaa8eYeaYMOK2zJaatJrlDFfJaRInH2EHJXcqQtWJHpOgdPZs3/
         JAPgQ29+WhOkBp/8XcILO08GkbYWbjBYEFBpOzEZiieVwWcm+RiBXLHburKdk7lp82Qe
         XwmYNf43OvQlxEymkwR21TchDPTKDBCXoHfbabg+WmsNFdeAje0190JqtAU+uJ6pBKlF
         J4yHPYnXHmYW9eU1H1PQEtPYhU/enAEIjOgZdAyztSkwEXJmMYzN5Lda4eyyvToFqIe6
         UeXZq25w+wt+47tuKGbv30iXgxAhPJmhi/AaQ7zfp4IT0UcKijeSZ/1c/vb6NM5zHsNZ
         U03Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yGsFwk0OdoLD9bhKmiXBu5oaK8VY84Q3s39aj8OGmOE=;
        b=nsxificZlW7n59xY29EaiYyfEBSCafalOhBrN/mh5z9l5+QuQ7V8K8WuBuzkt9RZPb
         IJl9sqYXq9A/QmR+lvA1GDKBqxHDqPh06HB+itdKN8ubF2Yv5ESdNPSM0FqObibxfOgg
         fOXB7oVW5l3EOKi47rUsH3svfTTcLK+npxKFyHVha6a+Y9YU41xI8ml6OgHz13+czwwE
         2O17djTW6FvGi8CNq/1kTX2uy96CsQ9yzwS82q/H81gk2ITfprghsvge+cBPwuA8Ulkm
         Mk9R212D3S6Rqhfnl7i+vPp4dux99weCrTiHcpWd0/LdLUrikFq9/gjdJMrPRCQDb/Jw
         OZ6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yGsFwk0OdoLD9bhKmiXBu5oaK8VY84Q3s39aj8OGmOE=;
        b=EXlR4ZFdwqcWjoQCO+MTPSGHfG62zmiRpZD6SAjJ2uiiLUSV7EY8TccOEloneNgz+s
         O1JlqRmEI/nBTYrDFSJW5gy1+M0oyVDDQuStLcUma3B7fsTMdEbq12mv7dlymYnLyJ9j
         PWrTDt7V1Un1ijgIGpUcfDoKv8QypygcqRGmVI8HJBmz1vavJs2iqrD/DJzxX0BGKcrC
         AZ3rI9TWk9f3MCi5WYHCDLNA/7ixSxDw+7fKvRSr6sGgggCUKfAh/T7oJ9jUnrpo2Qf5
         5NqWGifiktbuWsiOo9PyZc6jeoo4Xsqj4l0GspIvLWuPvAbLlsQhGdx0i1+7Br+E0wSI
         4Sjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322YB9p1S+RdY0eK9UIcP1mBCtbdULpBuBUDfSVU26rbfy05Jiy
	lpvsfgaumCZ5FdYxMdcg+ak=
X-Google-Smtp-Source: ABdhPJxAKmVyARiGXCibtIUonK1KyzsQuosNLaeBOHVSn+H3azO3vfliy4K7iuWz8p/B0RIZvZACpQ==
X-Received: by 2002:a9d:6b8e:: with SMTP id b14mr10555710otq.103.1627871947936;
        Sun, 01 Aug 2021 19:39:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:649a:: with SMTP id g26ls1958022otl.1.gmail; Sun, 01 Aug
 2021 19:39:07 -0700 (PDT)
X-Received: by 2002:a9d:a17:: with SMTP id 23mr10288144otg.343.1627871947630;
        Sun, 01 Aug 2021 19:39:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627871947; cv=none;
        d=google.com; s=arc-20160816;
        b=IfaAoQ6datOwuRbepcsPktV8vmbe1j7+CMAlGonUCI9D+vKsDfPdibNnL7sWF3rATt
         qV5LNlgfJ5di/MCA5rqEL/9+Wok/CYH/Cb6hp7wM0c3ctZ4xa+PwPBir9ST1vvbUs3M2
         q6yc2r5FKl8ocvmdSOyAVJLIkfhdrZT8SabkQvqFyYCqvudt5SmmCqdCNXkUaDCIZvUU
         vjsvoSGnBfdZkKurLG2uCBPl9ZnetjcUhMWGLRJAZr7Rl48qE8ex/dsVXxyfpn1u+qUo
         3YohdUUni0nFp5w6kt+plaV50JsyjTkzu2ZuGLV0CYGTQsbokV7IoVNAkKlFaHKB55/w
         145Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=fIEWXeGa3gGRdVCaaXd3bk+/UzPnE3NcMpT/7CuXdvA=;
        b=oFbXpXb3Of/LlZzD6gIZ6ekukh16+X1BDG1IUzQtDHcvTa37X3Cbr82stnpCZyvqpw
         nZhmxT69LUNXmw35iOGZJH17iE1mDm7oLIDIPk3LDJpOljagTclqcjIioxq5zXEtzpVd
         AlNTTc7B3ispyPaFA274EiFtaOc+9rbk5/q0ZO1v/Dy0ls1dGvAo2ibdKtXyDlyYqPqz
         71tFGEg65CoDPmA3YpOfYFH6pLZ76abwxFTMwoYsBXPtV+Lo4/xUc3MTpH/NX8JvRamA
         I5zdrdk22Dl/iw/dZQ57IPQDquMWB6/U1LXpiGvYjif1k6veMTlKUaH6EI0BFFP5T7jG
         WhUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id m17si714524otk.1.2021.08.01.19.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 01 Aug 2021 19:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GdMYH6z5zz82x6;
	Mon,  2 Aug 2021 10:35:15 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 2 Aug 2021 10:39:05 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 2 Aug 2021 10:39:04 +0800
Subject: Re: [PATCH v2 1/3] vmalloc: Choose a better start address in
 vm_area_register_early()
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-2-wangkefeng.wang@huawei.com>
 <20210801152311.GB28489@arm.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <0de87be6-7041-c58b-a01f-3d6e3333c6f0@huawei.com>
Date: Mon, 2 Aug 2021 10:39:04 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210801152311.GB28489@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
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


On 2021/8/1 23:23, Catalin Marinas wrote:
> On Tue, Jul 20, 2021 at 10:51:03AM +0800, Kefeng Wang wrote:
>> There are some fixed locations in the vmalloc area be reserved
>> in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
>> pcpu_page_first_chunk(), it calls vm_area_register_early() and
>> choose VMALLOC_START as the start address of vmap area which
>> could be conflicted with above address, then could trigger a
>> BUG_ON in vm_area_add_early().
>>
>> Let's choose the end of existing address range in vmlist as the
>> start address instead of VMALLOC_START to avoid the BUG_ON.
>>
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>> ---
>>   mm/vmalloc.c | 8 +++++---
>>   1 file changed, 5 insertions(+), 3 deletions(-)
>>
>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>> index d5cd52805149..a98cf97f032f 100644
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -2238,12 +2238,14 @@ void __init vm_area_add_early(struct vm_struct *=
vm)
>>    */
>>   void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>>   {
>> -	static size_t vm_init_off __initdata;
>> +	unsigned long vm_start =3D VMALLOC_START;
>> +	struct vm_struct *tmp;
>>   	unsigned long addr;
>>  =20
>> -	addr =3D ALIGN(VMALLOC_START + vm_init_off, align);
>> -	vm_init_off =3D PFN_ALIGN(addr + vm->size) - VMALLOC_START;
>> +	for (tmp =3D vmlist; tmp; tmp =3D tmp->next)
>> +		vm_start =3D (unsigned long)tmp->addr + tmp->size;
>>  =20
>> +	addr =3D ALIGN(vm_start, align);
>>   	vm->addr =3D (void *)addr;
>>  =20
>>   	vm_area_add_early(vm);
> Is there a risk of breaking other architectures? It doesn't look like to
> me but I thought I'd ask.

Before this patch, vm_init_off is to record the offset from VMALLOC_START,

but it use VMALLOC_START as start address on the function=20
vm_area_register_early()

called firstly,=C2=A0 this will cause the BUG_ON.

With this patch, the most important change is that we choose the start=20
address via

dynamic calculate the 'start' address by traversing the list.

[wkf@localhost linux-next]$ git grep vm_area_register_early
arch/alpha/mm/init.c: vm_area_register_early(&console_remap_vm, PAGE_SIZE);
arch/x86/xen/p2m.c:=C2=A0=C2=A0=C2=A0=C2=A0 vm_area_register_early(&vm, PMD=
_SIZE *=20
PMDS_PER_MID_PAGE);
mm/percpu.c:=C2=A0=C2=A0=C2=A0 vm_area_register_early(&vm, PAGE_SIZE);
[wkf@localhost linux-next]$ git grep vm_area_add_early
arch/arm/mm/ioremap.c:=C2=A0 vm_area_add_early(vm);
arch/arm64/mm/mmu.c:=C2=A0=C2=A0=C2=A0 vm_area_add_early(vma);

x86/alpha won't call vm_area_add_early(), only arm64 could call both vm_are=
a_add_early()
and  vm_area_register_early() when this patchset is merged. so it won't bre=
ak other architectures.

>
> Also, instead of always picking the end, could we search for a range
> that fits?
We only need a space in vmalloc range,=C2=A0 using end or a range in the=20
middle is not different.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0de87be6-7041-c58b-a01f-3d6e3333c6f0%40huawei.com.
