Return-Path: <kasan-dev+bncBAABBINU4OWQMGQEO4KGFGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B256484227E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 12:14:42 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-205fc343d1asf5364267fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 03:14:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706613281; cv=pass;
        d=google.com; s=arc-20160816;
        b=cgXgptPnwBXSxX++fwQdT7dFtyxquzdw9WFAzDiUwwwtvMERt9mdlGMgRrB2ZNipqD
         tzXfBgwioT/kZRSgnT7h5hlcy68ISR56K9DSAiivzXkok+CniOKPDiyrS8oMLtqzp2uL
         bg8C0JXyc3YeEZXvNnb75WrYTa+bioEgoB5mtAKf08dVskJinNLxHP9MNErsbovZ808N
         etObTFDYu3IUpxV9RwFz9ruM/gGiGzUMITylJJmFeStr6P87DMadaeQCJdgrE3DrfDhm
         3XYyeOBoNC04wGFCJSyimKzCqDoXbp3jkS1LfzFUYXR7D9o6q98azY9BhyXuiTKUPZk8
         YNAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:references:cc:to:subject:from:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=jtxs0h5+12ud5KHvevHGPK/V1rH5qzcEMecq/f0Jk7g=;
        fh=G89fJmrTKR900h8vK8FMOH/SZR964aan84EZl0jBPsI=;
        b=rfJqX242VKrKjDoKOaDSEc3Fq8p3lF/9XqJF7EEceG8Ew+bjetirCWAN3KL7BtTRwy
         c9mE+mrvK0NlAQj1lrlVnn/Ri8fZiATXQsR/FufkUXmCVzTJbrxuV/MU37t53xt51Ccl
         MjWmkjUPSDNek5gUscN8eVA16otufcAQacWglx/I9bwAkAAYH+8zTv8YzDgMc2iKqxd3
         890/Yv9Ci9kAwL9GrSFfd6EJv7kOlXXklkkKGVgMhaflmlQUs9Q8fvhfH2xSw4M9tiRF
         9A42kyAObCv/wHlQwE9AmCQKAywPowjD/FXJ7RSbt9rs8+7g3Nk31ivCPdyHq9ae4GcB
         nu5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706613281; x=1707218081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jtxs0h5+12ud5KHvevHGPK/V1rH5qzcEMecq/f0Jk7g=;
        b=KjZbatRLYRPSfpO3oUCXqYCkKZwFEkPx+qQ1a0/uDZdtAtBBmjpRcj3qwnk5ZUdHMd
         YBMBe9a4z0rI3M4vYCrTK3cypOY6LyhqYIaTzh/N6mmCUI1C1I/G1Dyk1iIGDlleheoE
         GDCC6o/nV/2xfMqYbdRZXu5CcZ6xvPHKSrUR3yoapLbQgRG0ikoDW+oC0YGFdjXz545f
         M6pncWHJUtIJBtqHG2Gb5ZN6DW/WyGsAE2ym6nA9Zs4Zc8E5UDGTfrzebkqc4DWe8qKm
         YJdonfqZuiW93MtPqEa1QKF3KxWijdutZeqLgIlABSt83aLA228bPuHpX/XIQkmwbxCy
         Ms+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706613281; x=1707218081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=jtxs0h5+12ud5KHvevHGPK/V1rH5qzcEMecq/f0Jk7g=;
        b=jycz3JUcLi0YDqEYXJlqEbqHIhQfcZVybwb7BjALR0Qg/ZLOcmqX8fp9GAETbbChTO
         DBQSzddFG7dzupfxvPopPx/JKHvAREV665BW6vYXv1mW9dNg5X8xEqGrWbgQtyPsWYYh
         MJqougcE8XEtR9IVtWld3AHxKtoTSu/XP2AARZ26n9gyxEinURi+md98Lga0nWR+WuoY
         Goa+EyXsU34Wye8oOIdj/51K2Ky6ENj8qaQW2VHlWouIW/sWF039jJ6P3WxoLzJYHXVW
         FlOHyCm5U6+R3h8BhgGV9zZSc+Uag0TyOgZfP+cC9FS9YS67X+zKDrwsWR09/SmZB6EB
         y/Cw==
X-Gm-Message-State: AOJu0YyNINxdpj8W+djseZvsJucUspTIf1W1pxBr4lxhfRhbQv7r/Zhk
	pcCXJv143x8BdwRr4U+l9rVu9PtzrDPUHEGg3ZGQDFsV/enb8IV+
X-Google-Smtp-Source: AGHT+IGwJ3c3K+T/q+pilfm5VB8iTuaow1lmhQw6Q9HNz1N3godbI4dNRtl5YNKopjRHdjaS9naiIw==
X-Received: by 2002:a05:6870:ea05:b0:210:e99d:3ad6 with SMTP id g5-20020a056870ea0500b00210e99d3ad6mr5161283oap.59.1706613281440;
        Tue, 30 Jan 2024 03:14:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2309:b0:218:b1d1:f45e with SMTP id
 w9-20020a056870230900b00218b1d1f45els313277oao.2.-pod-prod-08-us; Tue, 30 Jan
 2024 03:14:40 -0800 (PST)
X-Received: by 2002:a05:6870:610a:b0:214:294d:7835 with SMTP id s10-20020a056870610a00b00214294d7835mr5275521oae.28.1706613280731;
        Tue, 30 Jan 2024 03:14:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706613280; cv=none;
        d=google.com; s=arc-20160816;
        b=hFbYw1iRxlEiEwMVEXeKf++dtYI/VPcs+3680feu4odEreoiCY2/ueHkrleE4gepNR
         mX2JngQtguoqzJlMdsxBsLOWxg8/5n2hAjE/h97r9KTG1P4zQAtwvryDPpms6Foq6Y5G
         /KWnvkCSTSrg8fRpu8zHW2wxF/1N8UzVqcRciVaAkwCjhcgIlkwTR5kKiZsslhqqL3bF
         GiPvzafpFy2TFcTIPfx8yEfUMwZjOT70kEkBkLgcrHYcI+NYAVgTsHeQmOEEP8yl5ynW
         ggsyzx1qAEskaetdE5JH9Zm9d0dZONcu4/2j9uw3+zYIP7VTJwLYmwe0nv2vDF5tkonB
         +cMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id;
        bh=p1M0nMvq4TnAyxWVcH7MRInSedi2ZxhZWORO9OA8gFI=;
        fh=G89fJmrTKR900h8vK8FMOH/SZR964aan84EZl0jBPsI=;
        b=QFvZqAbN1dJo5s7vcQUAYAJ7xYdHrerGjxDc1ZpZx3HVxc08xnMJBt2JrK3uC/jApP
         mNpxBLKzKn+wklvjKCOW6HPNtkdABzh1QaW16BuYnY4pTrKGoSzCExM17OX4Ri8h4Mnn
         VzfnfXey9WxQfkRt6B+oRk+20ZL8yXOhR7Uxkn7qhO2+P6HaUPFdUAfx37a9EejYce4/
         sp3wwHhvdbsCUSqgGOWv77aH9xqHyE7p2V6eagjebV9JoOmlbldlKLREs0hh7hmCy3Lb
         gMIhpVhK6+dmVUVsLqNq4cIcNZvFycZrf1sdOA469eabIvHD7EoRuZmKScfotfgcdQfL
         slVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCUENgoXCnyadCNk7ptjJZPCX9TmoGy4S+NWKMrJ9iDBSbUsc2ZHptiqcpOUdNeywvz1eAbMf9tECjEyZpLwzcRDcGjA/AGTv7Fk0Q==
Received: from szxga07-in.huawei.com (szxga07-in.huawei.com. [45.249.212.35])
        by gmr-mx.google.com with ESMTPS id nx19-20020a056870be9300b00214d44ae5a1si1366432oab.5.2024.01.30.03.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jan 2024 03:14:40 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) client-ip=45.249.212.35;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga07-in.huawei.com (SkyGuard) with ESMTP id 4TPMvz6zx9z1Q89B;
	Tue, 30 Jan 2024 19:12:47 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id D80601A016C;
	Tue, 30 Jan 2024 19:14:37 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Tue, 30 Jan 2024 19:14:35 +0800
Message-ID: <23795738-b86e-7709-bc2b-5abba2e77b68@huawei.com>
Date: Tue, 30 Jan 2024 19:14:35 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v10 3/6] arm64: add uaccess to machine check safe
To: Mark Rutland <mark.rutland@arm.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	James Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
 Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	Aneesh Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mm@kvack.org>, <linuxppc-dev@lists.ozlabs.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-4-tongtiangen@huawei.com>
 <ZbfjvD1_yKK6IVVY@FVFF77S0Q05N>
In-Reply-To: <ZbfjvD1_yKK6IVVY@FVFF77S0Q05N>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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



=E5=9C=A8 2024/1/30 1:43, Mark Rutland =E5=86=99=E9=81=93:
> On Mon, Jan 29, 2024 at 09:46:49PM +0800, Tong Tiangen wrote:
>> If user process access memory fails due to hardware memory error, only t=
he
>> relevant processes are affected, so it is more reasonable to kill the us=
er
>> process and isolate the corrupt page than to panic the kernel.
>>
>> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
>> ---
>>   arch/arm64/lib/copy_from_user.S | 10 +++++-----
>>   arch/arm64/lib/copy_to_user.S   | 10 +++++-----
>>   arch/arm64/mm/extable.c         |  8 ++++----
>>   3 files changed, 14 insertions(+), 14 deletions(-)
>>
>> diff --git a/arch/arm64/lib/copy_from_user.S b/arch/arm64/lib/copy_from_=
user.S
>> index 34e317907524..1bf676e9201d 100644
>> --- a/arch/arm64/lib/copy_from_user.S
>> +++ b/arch/arm64/lib/copy_from_user.S
>> @@ -25,7 +25,7 @@
>>   	.endm
>>  =20
>>   	.macro strb1 reg, ptr, val
>> -	strb \reg, [\ptr], \val
>> +	USER(9998f, strb \reg, [\ptr], \val)
>>   	.endm
>=20
> This is a store to *kernel* memory, not user memory. It should not be mar=
ked
> with USER().

This does cause some misconceptions, and my original idea was to reuse=20
the fixup capability of USER().

>=20
> I understand that you *might* want to handle memory errors on these store=
s, but
> the commit message doesn't describe that and the associated trade-off. Fo=
r
> example, consider that when a copy_form_user fails we'll try to zero the
> remaining buffer via memset(); so if a STR* instruction in copy_to_user
> faulted, upon handling the fault we'll immediately try to fix that up wit=
h some
> more stores which will also fault, but won't get fixed up, leading to a p=
anic()
> anyway...

When copy_from_user() triggers a memory error, there are two cases: ld
user memory error and st kernel memory error. The former can clear the
remaining kernel memory, and the latter cannot be cleared because the
page is poison.

The purpose of memset() is to keep the data consistency of the kernel
memory (or multiple subsequent pages) (the data that is not copied
should be set to 0). My consideration here is that since our ultimate
goal is to kill the owner thread of the kernel memory data, the
"consistency" of the kernel memory data is not so important, but
increases the processing complexity.

The trade-offs do need to be added to commit message after agreement
is reached :)
>=20
> Further, this change will also silently fixup unexpected kernel faults if=
 we
> pass bad kernel pointers to copy_{to,from}_user, which will hide real bug=
s.

I think this is better than the panic kernel, because the real bugs
belongs to the user process. Even if the wrong pointer is
transferred, the page corresponding to the wrong pointer has a memroy
error. In addition, the panic information contains necessary information
for users to check.

>=20
> So NAK to this change as-is; likewise for the addition of USER() to other=
 ldr*
> macros in copy_from_user.S and the addition of USER() str* macros in
> copy_to_user.S.
>=20
> If we want to handle memory errors on some kaccesses, we need a new EX_TY=
PE_*
> separate from the usual EX_TYPE_KACESS_ERR_ZERO that means "handle memory
> errors, but treat other faults as fatal". That should come with a rationa=
le and
> explanation of why it's actually useful.

This makes sense. Add kaccess types that can be processed properly.

>=20
> [...]
>=20
>> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
>> index 478e639f8680..28ec35e3d210 100644
>> --- a/arch/arm64/mm/extable.c
>> +++ b/arch/arm64/mm/extable.c
>> @@ -85,10 +85,10 @@ bool fixup_exception_mc(struct pt_regs *regs)
>>   	if (!ex)
>>   		return false;
>>  =20
>> -	/*
>> -	 * This is not complete, More Machine check safe extable type can
>> -	 * be processed here.
>> -	 */
>> +	switch (ex->type) {
>> +	case EX_TYPE_UACCESS_ERR_ZERO:
>> +		return ex_handler_uaccess_err_zero(ex, regs);
>> +	}
>=20
> Please fold this part into the prior patch, and start ogf with *only* han=
dling
> errors on accesses already marked with EX_TYPE_UACCESS_ERR_ZERO. I think =
that
> change would be relatively uncontroversial, and it would be much easier t=
o
> build atop that.

OK, the two patches will be merged in the next release.

Many thanks.
Tong.

>=20
> Thanks,
> Mark.
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/23795738-b86e-7709-bc2b-5abba2e77b68%40huawei.com.
