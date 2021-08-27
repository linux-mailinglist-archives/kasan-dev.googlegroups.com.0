Return-Path: <kasan-dev+bncBCRKFI7J2AJRBEOIUKEQMGQEMEODX5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C83363F963D
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Aug 2021 10:36:34 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id l3-20020a056214104300b00366988901acsf3406013qvr.2
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Aug 2021 01:36:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630053393; cv=pass;
        d=google.com; s=arc-20160816;
        b=YeOGeD9wrRDUx3hxlpGGJXFsfexD5VgboJ5PRMQcFl78p6+MIma9B5Hgi6fs4JOCBa
         P1D9t3rsU1RDywwyHpGvYmdJ1RWthJdYCz9mZWf4sRAkIj6qeWM0xyVEarBGd100gYPr
         EAm/yMgqg9L7tdFuPo/4YSAjiQKiI5t+BoKPuD5FUu939Opl4/fe2VyuvQwUgfhDn309
         SGg6gSarbTP7ONT2/6/d4vGlpG7exkEd6Od89l6sbxBfGjG4LlICvTUqq9xTC8kjfIfy
         vw4zD6nqJZpj9mzPk6bBlj9ORkQmaSt7dyPMwjre0jKQn+8f98v5n0s4WRWM+b8Q4/qw
         5lEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=0+BlDO7thLd1FdPUw17UuxGVOo/JEmqTS2lI2sKfXPY=;
        b=FvlV+BkcBY3U5m6pAZhVOVIyRx4URj1lfMSYDKOkPCzZeJjFHl43Cnez/LWpNVy4Wt
         sfLf75ZHd3NytSWT8JTSM93FBpeOoSsc/fw3ZOf5PKxdixiMgzB+RI2jEXgL3Rw9SiJp
         OVfSIT+inSH8Qagj53kRCmXNvB8thiluwO/AqNPPhnfaPMGMi+fm4u7fi72Ov1YOEDDe
         d9QQJ5IRY/LIGjDfBIzUI0ocfINwfschz+sxpyiuoK7+uE5OhmQRwmgtxtwJA+EI4SoZ
         /5ofzmpTnLGOAJ8DDkRSBoiuj9O3eQ4euWXZAoRGuxMHg2iwzP8XrjGq/5hg6KMbdkEt
         GpvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+BlDO7thLd1FdPUw17UuxGVOo/JEmqTS2lI2sKfXPY=;
        b=AbYcFL2SEwM8Hw0uLwRfeQIDwfDqMMhStS71pTCqeVxhHuMZyFO0S+8+hMZoYNAj9c
         +hmohTyACWUU0dyZYUWcYVBKXajqDK5Q8kfyRMWIFwQQ83uQh48MQkVjojXlVejmRavS
         Y40YusfD0tLfH9AhvezxuuiLZjiXe6Y/78xXPitEWBMnBVluGxUFeNkxIdTt1Y7k6vIP
         C2eT5LJXiHXmoKkja2Vz5yX2NsaJw1UNrb2uNuuzgcBivEtD8Xu2ODzKidmdeG6dDFX+
         UtgsPUov5fZSQe+1qqkDa+mtD9iBP+y0gwZY4dzwYaCwhMZOeGqVz2OwrDpdw7I5O0rI
         g7EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+BlDO7thLd1FdPUw17UuxGVOo/JEmqTS2lI2sKfXPY=;
        b=YMr91nW0DIfHUVynJTwh79KkqDLqumo6jRcUqpFjaxtn7+8hXSQ/+LYZk5D8QBeqcG
         iDN1B3m8oNZ6laEA5HEZ34xKxgLiKr97HdNA/Sw8ut5fVuzGlYJ0QPY6IfBlg3ad8NKm
         92rKIAU/XxsjuvGmjQgPB+vwaOneZkG7oPFnmV1ALaLwjQoQ/CuTmFlmww1CeayrWO9W
         EHq0lPATdryhhDeWRQDdpYdm0Ntff6mK4riGxB68PU99+fNzU6P+c94D9FmKi6a0ZaU5
         NhwUlza2B3/L6BVPnV//0n5rNLzDjo1Dc79DcJDrZsKD3+zxCpZFK3vmvMKFhVGDGDKB
         dTKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fBqQRpjusHurHLn9gneEPyfiQu0/zrbQu+6IiSw4ppGSWDAF9
	HvNHQSTCwWkm2SonLtpwkYc=
X-Google-Smtp-Source: ABdhPJyeabDVh3IgnemK1tMFvCDiWSOs8qMFI1O0Q/EPKc77/9EN6hDqvGUImEwxkg/GtSkhuJ2bpQ==
X-Received: by 2002:a37:688f:: with SMTP id d137mr7880068qkc.3.1630053393535;
        Fri, 27 Aug 2021 01:36:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4111:: with SMTP id q17ls3649450qtl.8.gmail; Fri, 27 Aug
 2021 01:36:33 -0700 (PDT)
X-Received: by 2002:ac8:108f:: with SMTP id a15mr7241281qtj.126.1630053393127;
        Fri, 27 Aug 2021 01:36:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630053393; cv=none;
        d=google.com; s=arc-20160816;
        b=kiOpzLwcojmYNhcMxU+NIdKZa1OnE0oMsyuY0S8Wz/d/GW2Z4JN1GhTGiO9cHvthi4
         uXzkbLKaVVr4M7pz3PamKNBSRG02KGjgpiBmW4JG1Ig0CHka+nR+fRcwIeSLPrXFNSK3
         WwDslq6RkOp3XOig6gp8M0ug7mog2Qa9mX5rvWgjDbYqps1FAmzhGedKxzzbUJhjrsfm
         1O2lD3xbiZ7VtQNfYWCdEWVYQrWueT2DTf3Qu4O8cSsERdNScEU0H9H8aZh2wc4Mbmek
         OqPUBnXaScFaIaJnarIbIzAUFGWSdXGneKiYM5SWLK+O9ZW6ByzxCD+2aVFRX2yK+eJ/
         l4AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=mA+ngz/u/VoQeS58olAEnqkP7K8+Z8GVaO5KWwM8358=;
        b=oGo5ErPEipYBZHyFGo4RtwVEJQ2CDpYJ/2W1xihBIcPiQW7r/9AF5un6wH8QaxuncH
         S+YZoDWCbrDhHIdx4mxsrFyw0yHSr05kFUQA441+ff+arKbHl4HBsxJlG4mlJxoCqmLj
         eurw9x3S9+GIRXLTXRN7OG7ppFaFhn2OVsZ6VxNr/2FBIIRf7VAqjpNqf27TCLbJmA9R
         d1yW9QHCCbtXgFtCxdl0p/daZDJon7Yr32DSvMPnPOgFztUu+uPh6O++WssZK8bdEz+p
         ZX2FU8t05cFz0mGHK/6gOx4Dcs/AQXbc97yd0eIoe9koI613EAu5YUa4FgWNMsOWNmxF
         QbkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id a13si124893qta.0.2021.08.27.01.36.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 Aug 2021 01:36:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4GwtND5BGGz8BMF;
	Fri, 27 Aug 2021 16:36:12 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Fri, 27 Aug 2021 16:36:29 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Fri, 27 Aug 2021 16:36:28 +0800
Subject: Re: [PATCH v3 1/3] vmalloc: Choose a better start address in
 vm_area_register_early()
To: Catalin Marinas <catalin.marinas@arm.com>
CC: <will@kernel.org>, <ryabinin.a.a@gmail.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <elver@google.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <20210809093750.131091-2-wangkefeng.wang@huawei.com>
 <20210825175953.GI3420@arm.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <587a3a75-bbee-2ae4-8e69-563b9f277306@huawei.com>
Date: Fri, 27 Aug 2021 16:36:28 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210825175953.GI3420@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
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


On 2021/8/26 1:59, Catalin Marinas wrote:
> On Mon, Aug 09, 2021 at 05:37:48PM +0800, Kefeng Wang wrote:
>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>> index d5cd52805149..1e8fe08725b8 100644
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -2238,11 +2238,17 @@ void __init vm_area_add_early(struct vm_struct *=
vm)
>>    */
>>   void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>>   {
>> -	static size_t vm_init_off __initdata;
>> -	unsigned long addr;
>> -
>> -	addr =3D ALIGN(VMALLOC_START + vm_init_off, align);
>> -	vm_init_off =3D PFN_ALIGN(addr + vm->size) - VMALLOC_START;
>> +	struct vm_struct *head =3D vmlist, *curr, *next;
>> +	unsigned long addr =3D ALIGN(VMALLOC_START, align);
>> +
>> +	while (head !=3D NULL) {
> Nitpick: I'd use the same pattern as in vm_area_add_early(), i.e. a
> 'for' loop. You might as well insert it directly than calling the add
> function and going through the loop again. Not a strong preference
> either way.
>
>> +		next =3D head->next;
>> +		curr =3D head;
>> +		head =3D next;
>> +		addr =3D ALIGN((unsigned long)curr->addr + curr->size, align);
>> +		if (next && (unsigned long)next->addr - addr > vm->size)
> Is greater or equal sufficient?
>
>> +			break;
>> +	}
>>  =20
>>   	vm->addr =3D (void *)addr;
> Another nitpick: it's very unlikely on a 64-bit architecture but not
> impossible on 32-bit to hit VMALLOC_END here. Maybe some BUG_ON.

Hi Catalin, thank for your review, I will update in the next version,

Could you take a look the following change, is it OK?

void __init vm_area_register_early(struct vm_struct *vm, size_t align)

{

 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct vm_struct *next, *=
cur, **p;
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long addr =3D AL=
IGN(VMALLOC_START, align);
BUG_ON(vmap_initialized);

 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (p =3D &vmlist; (cur =
=3D *p) !=3D NULL, next =3D cur->next; p =3D=20
&next) {
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 addr =3D ALIGN((unsigned long)cur->addr + cur->siz=
e,=20
align);
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 if (next && (unsigned long)next->addr - addr >=3D=
=20
vm->size) {
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D &next;
break;
}
}

 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(addr > VMALLOC_END=
 - vm->size);
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vm->addr =3D (void *)addr=
;
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vm->next =3D *p;
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *p =3D vm;
}


>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/587a3a75-bbee-2ae4-8e69-563b9f277306%40huawei.com.
