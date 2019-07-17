Return-Path: <kasan-dev+bncBAABBMGGXPUQKGQESH44TII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 581EF6B8B3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jul 2019 10:58:26 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id h184sf9095983oif.16
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jul 2019 01:58:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563353905; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2PlCuUZfKiGhWuPRx6FxUsd9ZPkJr1LH6M8XYB+xknP4R8FBcjya8u0EEJmBqCIPN
         XRCY80X97+8JdLfsyep5+xWD1MciBMKP8wX6BxVYaO0uo7DU30fMYwzi1h3y76ztgf3W
         olF9pg9aD/NrOIpdKS7eG3tQNP9iIctcIpF2qcVAQpBX0fLdnwSCr0JtWZiox5dvbBCO
         ZnEn/mLjxPP3y6JuKI3qE8xQ7yNerJKVPGGSD3TtosN0AW4Roa2aZOVZivxuj7aFpJt1
         78fn38zbAn+TFyY2xV7MDg8ZI37mOQGsHUG8xbg/1ctMimBBc+4N4wBq32ouqjHKDtOI
         Cvqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=51x/ZvLEEIBOUJzNtR0/sOw9rmD7xfG4EP32qROjDbQ=;
        b=midZIPI2wYyO+zHY+/Q6eDPfLWf2nPZWCxnGFcMe//TuEzA7rpSzi9CkKbT3iNUs9r
         IoifQevVTLMWL6xJhjdy5EhD+4kcRzZ4lbNzo03tdVj9PZ8aDJfjMTl+aqnbRhDb4Rl5
         P2nHDWeHFGjS61EOgjk4RleT6zryfKkYTAtUmoCQZjMG489PUpZkfzLoCHMwoBJj6Jm0
         mRAP19h8fmLV4N4YrNBqcG3l2inhzPfbZN/8wB+/JCldJmpZqPCqmqEV/AEfwCVSxutz
         ATQ5QhxdUiXoG63Pb9wCLHc2KD01tg0JerwsrQBIq9h71QQTs8jsFtcb0xrKd0VRZN85
         8vCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=yuzenghui@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=51x/ZvLEEIBOUJzNtR0/sOw9rmD7xfG4EP32qROjDbQ=;
        b=pWSbRPW2MAifaVc893UrhGw8J7oULHat+abQLMkVyAntrhFxE9qMhyw/nmsslWvNqL
         khBstSkKtTJIJRx2C2e6XFmGEyQfGula5TUdsewgAAIrhDqlo61EO/Ze/cDWwgLtyc61
         RCHIssWnbnjO+SF1ATz3vvxsaMQz3ayJQdyyYCDIU54Yk7HEoCXEUi15DkB3HIr1eOM/
         FylnVBoKZk83iVVhuXoF0zAc+jeKK3hEVXs27SaPu+5qGGGPDkGCfEOcKMjTeeMQb7U3
         mjNviAu/bjdtbHNjreVCnmuBEDNHzKAIqv/k/FTvBuBKczLbIFFFIAw2TdqdVF8S48nv
         xoQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=51x/ZvLEEIBOUJzNtR0/sOw9rmD7xfG4EP32qROjDbQ=;
        b=ZL5wjD1ww+F3NvU8MnySJ9QRiaAgqCagnR6a9Cd82LwJntMdf9RrVbYGw1xBQQF08a
         ySWi1nEykDD5zXHElET2dxG1SBAYqk1/lmLYhSYBAXJ/5hETHk24nFHml2f+eIrJl387
         RNfKrxLAhZGgLjizh7Rg9+yYktu7bUvnzGdFXIEVChuUGvd3/idSjBb6kMebeOE33Jsr
         U3dyXrKzEOPPqgPYM6DKLbQkeU9iJ0Ika8/12J8auPTM3XduYRfXWMeCVCApPecj2fmD
         SE2CFvyY8AF3Y+QaV7GxIdKa58LG/6pvrEbC+srjPPDBm3qFnDOxUWcgA5+lY0sBQBvX
         b4/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFa5YFfKhR8qbVTOinIAR4OQ8yvmJaiPJRcrgxd75KgGJ9Cp4k
	Qx1bNaLGLmLST5FlTLVG81I=
X-Google-Smtp-Source: APXvYqwJiQ2dmQVTjb+ev3Gv+Lyh+hiyqkymQgVJCZlOHdq7EmOuoHPfU26WXv9QJJA0bD2YJnlXjw==
X-Received: by 2002:a9d:5182:: with SMTP id y2mr7482729otg.271.1563353904810;
        Wed, 17 Jul 2019 01:58:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6ac9:: with SMTP id m9ls4425665otq.6.gmail; Wed, 17 Jul
 2019 01:58:24 -0700 (PDT)
X-Received: by 2002:a05:6830:128e:: with SMTP id z14mr23756142otp.172.1563353904551;
        Wed, 17 Jul 2019 01:58:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563353904; cv=none;
        d=google.com; s=arc-20160816;
        b=Xao12D9DAJH6C4WXRJVd5qptiZe/7wn7PJVZ5Xyd6G4c9X76HyxfrR21XiTRAefLho
         FaTwr3dNfsOpimKWJof5l8doKq3TjFdUxLfXuZSKz3cGjNRBbZiSJMKJFZSamFidI12V
         I4rFrhkm6E2eCHiVZ5ZAyW3RlbWcdpFOQhuvuyMYOdl7oo2nL56CXtjxr92umWSeMqjK
         BTu26dow/McJi/WA34OrMjBDP7f78K4Aacz/q4ODD9O/BVY/hvBap1vlTwZg7f+FkInb
         X+SSWLqbwyOAwhdt4TXrpQOWznJPYNtLTJNWkbpqYP36GWWIDRsX6AH+FDIon6Rnt+3O
         mUEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=415qB4FhAUqdpSO7ppvBoOYajGv1FBnkCGqD6qoKYCo=;
        b=fF2EBbOfpJkqWQDZORbYujNSaUhKxpjYon/kYhIoQJzj7PS8B6LAduRCi3y0bC7ZDN
         eqw43KUHNsmA8S1sxVGxvG8KGLnd2ghZkAYTebcMCB801O6zgEpPeNZUqyuUDBI0A2BU
         Vj9Ibd3wyn4vz3TuU8Mv+hhDAGrsIkdwGIp2majmvOJNs1SzMOEflsn5JFpywp/DepRn
         3MRyObNEY9kxkn91KfIjR0V6QzMZjnoSvYyJPa32vYGs49g3/zA1UhSsYE/aA8GuUd7v
         LI3Perxv7fKNu4apiCJet/N/ALRV7uzAn5HSMLbmwGYPYCSBHBISPeqKLQGCxYeJ4VPi
         ShtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=yuzenghui@huawei.com
Received: from huawei.com (szxga07-in.huawei.com. [45.249.212.35])
        by gmr-mx.google.com with ESMTPS id q82si1307969oic.1.2019.07.17.01.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jul 2019 01:58:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzenghui@huawei.com designates 45.249.212.35 as permitted sender) client-ip=45.249.212.35;
Received: from DGGEMS414-HUB.china.huawei.com (unknown [172.30.72.58])
	by Forcepoint Email with ESMTP id 3FE53B411F28E99262E4;
	Wed, 17 Jul 2019 16:58:22 +0800 (CST)
Received: from [127.0.0.1] (10.184.12.158) by DGGEMS414-HUB.china.huawei.com
 (10.3.19.214) with Microsoft SMTP Server id 14.3.439.0; Wed, 17 Jul 2019
 16:58:13 +0800
Subject: Re: BUG: KASAN: slab-out-of-bounds in
 kvm_pmu_get_canonical_pmc+0x48/0x78
To: Andrew Murray <andrew.murray@arm.com>
CC: <kvmarm@lists.cs.columbia.edu>, Marc Zyngier <marc.zyngier@arm.com>,
	<kasan-dev@googlegroups.com>, <kvm@vger.kernel.org>, "Wanghaibin (D)"
	<wanghaibin.wang@huawei.com>
References: <644e3455-ea6d-697a-e452-b58961341381@huawei.com>
 <f9d5d18a-7631-f3e2-d73a-21d8eee183f1@huawei.com>
 <20190716185043.GV7227@e119886-lin.cambridge.arm.com>
From: Zenghui Yu <yuzenghui@huawei.com>
Message-ID: <3b128267-7879-0205-3571-e219fc7b8d42@huawei.com>
Date: Wed, 17 Jul 2019 16:54:34 +0800
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101
 Thunderbird/64.0
MIME-Version: 1.0
In-Reply-To: <20190716185043.GV7227@e119886-lin.cambridge.arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.184.12.158]
X-CFilter-Loop: Reflected
X-Original-Sender: yuzenghui@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuzenghui@huawei.com designates 45.249.212.35 as
 permitted sender) smtp.mailfrom=yuzenghui@huawei.com
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

On 2019/7/17 2:50, Andrew Murray wrote:
> On Tue, Jul 16, 2019 at 11:14:37PM +0800, Zenghui Yu wrote:
>>
>> On 2019/7/16 23:05, Zenghui Yu wrote:
>>> Hi folks,
>>>
>>> Running the latest kernel with KASAN enabled, we will hit the following
>>> KASAN BUG during guest's boot process.
>>>
>>> I'm in commit 9637d517347e80ee2fe1c5d8ce45ba1b88d8b5cd.
>>>
>>> Any problems in the chained PMU code? Or just a false positive?
>>>
>>> ---8<---
>>>
>>> [=C2=A0 654.706268]
>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> [=C2=A0 654.706280] BUG: KASAN: slab-out-of-bounds in
>>> kvm_pmu_get_canonical_pmc+0x48/0x78
>>> [=C2=A0 654.706286] Read of size 8 at addr ffff801d6c8fea38 by task
>>> qemu-kvm/23268
>>>
>>> [=C2=A0 654.706296] CPU: 2 PID: 23268 Comm: qemu-kvm Not tainted 5.2.0+=
 #178
>>> [=C2=A0 654.706301] Hardware name: Huawei TaiShan 2280 /BC11SPCD, BIOS =
1.58
>>> 10/24/2018
>>> [=C2=A0 654.706305] Call trace:
>>> [=C2=A0 654.706311]=C2=A0 dump_backtrace+0x0/0x238
>>> [=C2=A0 654.706317]=C2=A0 show_stack+0x24/0x30
>>> [=C2=A0 654.706325]=C2=A0 dump_stack+0xe0/0x134
>>> [=C2=A0 654.706332]=C2=A0 print_address_description+0x80/0x408
>>> [=C2=A0 654.706338]=C2=A0 __kasan_report+0x164/0x1a0
>>> [=C2=A0 654.706343]=C2=A0 kasan_report+0xc/0x18
>>> [=C2=A0 654.706348]=C2=A0 __asan_load8+0x88/0xb0
>>> [=C2=A0 654.706353]=C2=A0 kvm_pmu_get_canonical_pmc+0x48/0x78
>>
>> I noticed that we will use "pmc->idx" and the "chained" bitmap to
>> determine if the pmc is chained, in kvm_pmu_pmc_is_chained().
>>
>> Should we initialize the idx and the bitmap appropriately before
>> doing kvm_pmu_stop_counter()?  Like:
>=20
> Hi Zenghui,
>=20
> Thanks for spotting this and investigating - I'll make sure to use KASAN
> in the future when testing...
>=20
>>
>>
>> diff --git a/virt/kvm/arm/pmu.c b/virt/kvm/arm/pmu.c
>> index 3dd8238..cf3119a 100644
>> --- a/virt/kvm/arm/pmu.c
>> +++ b/virt/kvm/arm/pmu.c
>> @@ -224,12 +224,12 @@ void kvm_pmu_vcpu_reset(struct kvm_vcpu *vcpu)
>>   	int i;
>>   	struct kvm_pmu *pmu =3D &vcpu->arch.pmu;
>>
>> +	bitmap_zero(vcpu->arch.pmu.chained, ARMV8_PMU_MAX_COUNTER_PAIRS);
>> +
>>   	for (i =3D 0; i < ARMV8_PMU_MAX_COUNTERS; i++) {
>> -		kvm_pmu_stop_counter(vcpu, &pmu->pmc[i]);
>>   		pmu->pmc[i].idx =3D i;
>> +		kvm_pmu_stop_counter(vcpu, &pmu->pmc[i]);
>>   	}
>> -
>> -	bitmap_zero(vcpu->arch.pmu.chained, ARMV8_PMU_MAX_COUNTER_PAIRS);
>>   }
>=20
> We have to be a little careful here, as the vcpu may be reset after use.
> Upon resetting we must ensure that any existing perf_events are released =
-
> this is why kvm_pmu_stop_counter is called before bitmap_zero (as
> kvm_pmu_stop_counter relies on kvm_pmu_pmc_is_chained).
>=20
> (For example, by clearing the bitmap before stopping the counters, we wil=
l
> attempt to release the perf event for both pmc's in a chained pair. Where=
as
> we should only release the canonical pmc. It's actually OK right now as w=
e
> set the non-canonical pmc perf_event will be NULL - but who knows that th=
is
> will hold true in the future. The code makes the assumption that the
> non-canonical perf event isn't touched on a chained pair).

Indeed!

> The KASAN bug gets fixed by moving the assignment of idx before
> kvm_pmu_stop_counter. Therefore I'd suggest you drop the bitmap_zero hunk=
s.
>=20
> Can you send a patch with just the idx assignment hunk please?

Sure. I will send a patch with your Suggested-by, after some tests.


Thanks,
zenghui

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3b128267-7879-0205-3571-e219fc7b8d42%40huawei.com.
For more options, visit https://groups.google.com/d/optout.
