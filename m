Return-Path: <kasan-dev+bncBCRKFI7J2AJRBIN3V6EAMGQENEO64PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 70C3D3E14FF
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Aug 2021 14:46:26 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id p7-20020a6b63070000b02904f58bb90366sf3586962iog.14
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Aug 2021 05:46:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628167585; cv=pass;
        d=google.com; s=arc-20160816;
        b=wbv7KMF8WTGF0abVJqUXtUyOrASNHt3e01FEcBldRbYntLc9K8h+Kzb2L69cNTWXF5
         I0UVPfd5s3agAPbBJw5XsGxUb3YCxjjE3cLFgnvS7XujWyAjJvVABNj9hHUmEDPrbyST
         Jf7PK4Aq8agQ7EfTNw3dv4p3fp45NmSgg2iLcNnjVuA9PgZYIvr9M2Rektg+xwXQQYI9
         1/FR1uKokH34VWaTyzzOARM+ngias27hwtPqw9jOMNa39DoLKsNZbcCBbldRw4fHECYv
         OZbhUNDRmChnAKtUPIEeQYI/mvqx6KMdEAkSGz2e0W/n4c1UKLYi/xNZF0VDm8gTru99
         RGZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=zIHMjOVcF9aUXeE8pSibYIM8qrWqxRgXqLNOHZutPc0=;
        b=A+Ko8F5yXqmkvcgfS1KiipscwTWADvoHaPG48BB8efCpthr+0Lr1BUu/9+kWXZfqs2
         AgFyVDb4AD5hVcsAPKDwR/sL+PciAjLzdp9UrMeQQIUYKfRERGzFlwcDRjJSSmkfPtX9
         9dImgv2LGoQwWMWSL1B/B2T/9gTrjon2g6DgMIOT//meqUyYHIE9MXqPphv0yuXJX9qH
         9YRR6CH2aeXHBYXaS7kCI0uhXfGfeDvFrABTJkN5JqUm2e7fCHBHsC8DvHVZGSus2H5J
         S0tgIp1ComDyNAZFz0LnifkTtuP+FzoA3aZz4yvTbOdZ1yv/8QS38g9UUI5mOSRGS6Ib
         RY+w==
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
        bh=zIHMjOVcF9aUXeE8pSibYIM8qrWqxRgXqLNOHZutPc0=;
        b=inHoV5PZpgFioe/5xPy6nCnnCDjt2FKl46fknsp1+Yazq5xj2Y/BwyB/U2lcDslK0i
         ebyHVGAxCofJvtfX7jbg/N7vARktn3JXjm443kpGdwapNg55ZSyUsuOkuel+36v6EpPN
         BHvwQXdV+fp5z2nZklF7juH4JcrVJz5XN+xynJkoSm4PgQqh8ecN2xTu/4kmuNr8ba9f
         BtLurigx2mbyXWbzZb14quCSyzSvfRqfUDP8GtV9HpBANVnX4YKe1E4A/4KUKQzTpVlf
         mYtUQ0MhPNX9b7CrBY9s9OvQDNy63f7dwLjFXdkQr00Ka3TP+6Y55Q9kHmbt8pGQ0Dx0
         ExMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zIHMjOVcF9aUXeE8pSibYIM8qrWqxRgXqLNOHZutPc0=;
        b=keU+Rp6dP5Ph12zF+3A4xQPggdf3e/oSTETDOzLh1nHhfb8wtzYfpXMybGFK4mAsu3
         WOKuAF3k6IrJZkGfeuVVhfXit4TT6rBBbHcxlyiNphiujPWgqslU55dl2gy+7dgzIb9M
         +Ne5Evsgc+ljyrBbOvi2XpjRf4keQZBzXTrUGe6kLW23uFsubyp8mQnl22QH1FIPnVIs
         TW+JYSQcBW2RmGbXIPG8JOPYO0GqLtUwzs1kzlFNJJhu+akCZV7sSA4iR39t/LzUmH4J
         UjfSomsydjjqTty08HqJfqSaYxk3Hw0cfNIHOiG+J8eN2nGPVceFfTQe0e/d/eEZqz4+
         U4Ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XZyFNwhC5kN4WMWaVVR/sXgTERGqgek1dKfX077dUnBdGzmGe
	B6l2CYWbfaL9RNbcHNyDZx4=
X-Google-Smtp-Source: ABdhPJxm5Gj486V1W0MLql9uqi6mcBuUuXgc46+gJuWBah577se3WYtkkmGHn4tstU+pApMRoPLE0g==
X-Received: by 2002:a6b:490d:: with SMTP id u13mr462479iob.176.1628167585303;
        Thu, 05 Aug 2021 05:46:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2c11:: with SMTP id t17ls1189266ile.6.gmail; Thu, 05 Aug
 2021 05:46:25 -0700 (PDT)
X-Received: by 2002:a92:6503:: with SMTP id z3mr1378500ilb.258.1628167584963;
        Thu, 05 Aug 2021 05:46:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628167584; cv=none;
        d=google.com; s=arc-20160816;
        b=vlx61xbYqbeBACthGjOFiMXYH8B4PTqf73qh6g00xDolGkxNvvgFVwsP2QNb/cxV5k
         p3nVz1Qefir/QtmHIMR5Gck5jgR6TlD3uHlg/5Fejf0OfERlBAPChJ/joG2t1dcxc6rl
         6/Xv9YeOMKLQJzzbD8QF8WxYRflELMgs1k5MygOsPoDQDt6Hp/NOWJnqACsiyzVLcyXK
         pAl3U2iLOVkCwXpEddWbpw9ZSwTEQhjnofvKi4ozkWbM0zoQzoWqFP8z9c46VlgVhR86
         1pMQQab8iQ79rTnOVlE8ZsxsUOMWNl4An75tO6HJCS/fLhyKCQtKIAf9z66v3a9nsw4w
         /rxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=LVTcru6beuYhVoSVfzr+pRPAyY6bxNApWWR8V/26OUg=;
        b=HPFEbToW4mRLeuzWdAJkxW4RW0ou55sVPdIh69sTuf5ZlfsHhhdzWbIFO1Xs17/wwi
         Mu2pdewUzWGDZRqt2wULcqJ3qz4bW7xuaeBRQDRg9OGIkPfqcxGIvHfz4WWc5EReGyu2
         HJwYEBGl01pJCGTb5xg0LY8J9RHNok+G7dZ6S0MRBwYJEb8UPBB6goAe0tK2orb/RizL
         Juz77QHuUqofC6dz6NsPUHbnYNLLpJ4XAuxSFRx8Ok/8wIF2QNzavbyqaizIzPE1U+0n
         lbXr006QiB39nYGmUZ2DDJtNf8heyfbZJ0wOmjtBNBnocHyiaFJcD9InZpSxjzyZT/+N
         QtSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id q5si261506iof.0.2021.08.05.05.46.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Aug 2021 05:46:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GgStv3bbkzcl9Q;
	Thu,  5 Aug 2021 20:42:47 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 5 Aug 2021 20:46:22 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 5 Aug 2021 20:46:21 +0800
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
 <0de87be6-7041-c58b-a01f-3d6e3333c6f0@huawei.com>
 <20210804111402.GB4857@arm.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <d2280ab3-2c31-7525-b03d-b4717273b2c3@huawei.com>
Date: Thu, 5 Aug 2021 20:46:20 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210804111402.GB4857@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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


On 2021/8/4 19:14, Catalin Marinas wrote:
> On Mon, Aug 02, 2021 at 10:39:04AM +0800, Kefeng Wang wrote:
>> On 2021/8/1 23:23, Catalin Marinas wrote:
>>> On Tue, Jul 20, 2021 at 10:51:03AM +0800, Kefeng Wang wrote:
>>>> There are some fixed locations in the vmalloc area be reserved
>>>> in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
>>>> pcpu_page_first_chunk(), it calls vm_area_register_early() and
>>>> choose VMALLOC_START as the start address of vmap area which
>>>> could be conflicted with above address, then could trigger a
>>>> BUG_ON in vm_area_add_early().
>>>>
>>>> Let's choose the end of existing address range in vmlist as the
>>>> start address instead of VMALLOC_START to avoid the BUG_ON.
>>>>
>>>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>>>> ---
>>>>    mm/vmalloc.c | 8 +++++---
>>>>    1 file changed, 5 insertions(+), 3 deletions(-)
>>>>
>>>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>>>> index d5cd52805149..a98cf97f032f 100644
>>>> --- a/mm/vmalloc.c
>>>> +++ b/mm/vmalloc.c
>>>> @@ -2238,12 +2238,14 @@ void __init vm_area_add_early(struct vm_struct=
 *vm)
>>>>     */
>>>>    void __init vm_area_register_early(struct vm_struct *vm, size_t ali=
gn)
>>>>    {
>>>> -	static size_t vm_init_off __initdata;
>>>> +	unsigned long vm_start =3D VMALLOC_START;
>>>> +	struct vm_struct *tmp;
>>>>    	unsigned long addr;
>>>> -	addr =3D ALIGN(VMALLOC_START + vm_init_off, align);
>>>> -	vm_init_off =3D PFN_ALIGN(addr + vm->size) - VMALLOC_START;
>>>> +	for (tmp =3D vmlist; tmp; tmp =3D tmp->next)
>>>> +		vm_start =3D (unsigned long)tmp->addr + tmp->size;
>>>> +	addr =3D ALIGN(vm_start, align);
>>>>    	vm->addr =3D (void *)addr;
>>>>    	vm_area_add_early(vm);
>>> Is there a risk of breaking other architectures? It doesn't look like t=
o
>>> me but I thought I'd ask.
>> Before this patch, vm_init_off is to record the offset from VMALLOC_STAR=
T,
>>
>> but it use VMALLOC_START as start address on the function
>> vm_area_register_early()
>>
>> called firstly,=C2=A0 this will cause the BUG_ON.
>>
>> With this patch, the most important change is that we choose the start
>> address via
>>
>> dynamic calculate the 'start' address by traversing the list.
>>
>> [wkf@localhost linux-next]$ git grep vm_area_register_early
>> arch/alpha/mm/init.c: vm_area_register_early(&console_remap_vm, PAGE_SIZ=
E);
>> arch/x86/xen/p2m.c:=C2=A0=C2=A0=C2=A0=C2=A0 vm_area_register_early(&vm, =
PMD_SIZE *
>> PMDS_PER_MID_PAGE);
>> mm/percpu.c:=C2=A0=C2=A0=C2=A0 vm_area_register_early(&vm, PAGE_SIZE);
>> [wkf@localhost linux-next]$ git grep vm_area_add_early
>> arch/arm/mm/ioremap.c:=C2=A0 vm_area_add_early(vm);
>> arch/arm64/mm/mmu.c:=C2=A0=C2=A0=C2=A0 vm_area_add_early(vma);
>>
>> x86/alpha won't call vm_area_add_early(), only arm64 could call both vm_=
area_add_early()
>> and  vm_area_register_early() when this patchset is merged. so it won't =
break other architectures.
> Thanks for checking.
>
>>> Also, instead of always picking the end, could we search for a range
>>> that fits?
>> We only need a space in vmalloc range,=C2=A0 using end or a range in the=
 middle
>> is not different.
> I was thinking of making it more future-proof in case one registers a
> vm area towards the end of the range. It's fairly easy to pick a range
> in the middle now that you are adding a list traversal.
ok,=C2=A0 will chose a suitable hole in the vmalloc range.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d2280ab3-2c31-7525-b03d-b4717273b2c3%40huawei.com.
