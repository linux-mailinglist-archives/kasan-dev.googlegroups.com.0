Return-Path: <kasan-dev+bncBDGZVRMH6UCRBSGZV63QMGQE4SZIKZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 80F3197C6DC
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 11:20:10 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3a0a4db9807sf11325795ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 02:20:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726737609; cv=pass;
        d=google.com; s=arc-20240605;
        b=H1mUdRWXcKAtRxZSutZgYX1uMA+KmrbcB+rS1GqLSyk8R07iybfTaOvPcJ4kLRKEz3
         LyrDCKbKRI6SbeBPFz5X6vJYejynJWDXW3DOaMKWPcJVGMudIzTzoUfpTcdCXRhi3VY+
         Y+QdLsKLciBVDfRAM9JSscCxsRJT5nNCIgAPDI0ZC8IWdMq46EO60uTB89EVD9uqwfHM
         eVgozuCJkeNjd6H0CYBkToZsKiGhn5laABGNDe0dN9DjqvJXHHVnGAtvYfSfbGWq8998
         fGgmX+/37cDMnD2kvSSSnQn7Ydncb3zRA9OmI6B384cYSd8LXnQnea5miWePrF5/W3Sl
         h4kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=5LgJsnpbjP24d37CszkX7kQsdBeT0BM5NNhyGc55gA8=;
        fh=IVuCqU4g4NvraZmnqaJMQBKJI/9ldKXKRp5+P63FMyw=;
        b=Z1Ha4id37+yuz+h5FMXrL4hOMRGELZm1W8g17frRCrNOYd6FHFFfDSEa3WdV3p0Kil
         wTZsUr7rQkxU5yqUvWarcklSmb+I1EsDvtPvyP7NtQEAEOks1Ki9ZUyQL3oNJ3MPz4Ip
         nHiMzoFSHVv4L1N+9y2y6ur3IzGjODkZuT4CnkwILAVlEbuCtx5gDLN3aGI/hJqVhkUW
         CshI4VFGfLDx5HnnR+lBY+lGJFlCTJgwfprtGO0qwoBG6m7N6NEjfaonYgjxWGrZGbIP
         UAaFPn3cuQKXgKQusHTg3Or/6h7p8YNWDYBzrjGCsZA14tbVEE93+glHWCPLIY0n5uPQ
         D/cA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726737609; x=1727342409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5LgJsnpbjP24d37CszkX7kQsdBeT0BM5NNhyGc55gA8=;
        b=G13me8pcnU/Tn2ol5mKtxEC4uW1tegyo7PLRTB4StRni2iIorUb79WDE8gJJZ6n9iF
         ezKo7RnVevi3e8QVysaet+RFxLN3WoOCPYs8aqM+jYs8PgL7Lu5pVnL7LEgaUYO98RPK
         G1dmT7qGMpNZZ9Gfgzl2mY3CfY2HriLky1aanDChtq3+2KkJQNJocW+yBHgF73uUIUV0
         hIbIpDrBrvxAN5C5dTxcGLrfnzaIFwttpb/ugqyQ7Bwtde1xZ8RurvvIopAQjfElYuR5
         iOWRftYiTKkWyh0EHchLUwRW2hoJ+mn/chiPzKNfzRyuJipumrE0bAyWs9I9YhGFE7wY
         2juQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726737609; x=1727342409;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5LgJsnpbjP24d37CszkX7kQsdBeT0BM5NNhyGc55gA8=;
        b=Fhn0DK1QQS5uzqSZik+MdxpWJrjovoa4BYRt2S23vbn09GVlMVsLCzPjqgliYSrZ5q
         +x5Nyk7FOSQQyVgaBfg9WVF1lZRGu9rHMrvgQNFND5sA9gnmHxYUZvQu3WiR++dCUj5u
         kgfrvCVQUJAY31IBRzNn/ihChBtT0bjhvY15qitFIuExPC+8Hfn0sTQO+YX3W5agMcJt
         yOQdyPt7/dKKiKRCQtYuIhP5CB4b/m/ypshHFJw0xFDkmW3vOLCj00aFnbrcVFNResxS
         d69Uvom1cSodj0HlmHEhMDxg/hxsJHiJaK5kDLwHfCr34d60q4Ge1ls9wU9jT8KFdr/u
         alWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbZHEcbG74d1dZ1L+6vh5nz+0Xwtrm/T4a9rtfggN1eXd952E68FVaod8KI47zAPSmHJqItg==@lfdr.de
X-Gm-Message-State: AOJu0YyRKgsIpNK6tVmR2WUDnR+zU0PwbrN6rYewrZ99dNp6a53ZKn/x
	X0OE2cQWaA0Dq8LSNlBFgyYUuMrQSsX9gE1yHI+bs07p4cwssYIn
X-Google-Smtp-Source: AGHT+IFwMy8sYpHUL2rNsvZVKp2CYXCCAbS3qZLQihQSSK5WyhuIU6mSVHvdgCjCZO4lDgcqvS10kw==
X-Received: by 2002:a05:6e02:1d01:b0:3a0:4e2b:9ab9 with SMTP id e9e14a558f8ab-3a0848ac8efmr282524005ab.5.1726737609018;
        Thu, 19 Sep 2024 02:20:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a0d:b0:3a0:a130:66bd with SMTP id
 e9e14a558f8ab-3a0bf1a991cls106855ab.1.-pod-prod-08-us; Thu, 19 Sep 2024
 02:20:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUE4T+dQQENzH3EtqR8pceu9m/KhFSaGRoNpBvhtQD4otFCEbNVVSjY1frl8YtUL+xbbRpQIBgplyw=@googlegroups.com
X-Received: by 2002:a05:6602:6b87:b0:804:f2be:ee33 with SMTP id ca18e2360f4ac-82d1f8c45dcmr2413826639f.2.1726737608092;
        Thu, 19 Sep 2024 02:20:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726737608; cv=none;
        d=google.com; s=arc-20240605;
        b=jLDaefncMFP+aMSM+YX4FDQU75FdEVB+TnUcvof9Sa0IrApxNTsYAxObVP6NZg2NdG
         XfeiBwr09hoNoV76Pjs3pfC/Y294v6fpqELwNjN8OVKAZ1sM5Ddv2f+CXjgZcGVmqUSF
         LmHxgAHTUcpR5p/aHAxNvI/7qMpRX3RwtON+KhHqM91v+7W4cfEDE/PQGa5AplHqChqk
         dX9Vpf3XcnOkC3ryG/uRas9192/4n9t+tAlvtER2Fbi0C13EBYCrY2RTlnDz0JmkB/oU
         Ua13jvhuqs9QW0eOGbfSc93SGQBEtYnu0DYeR6GOwwrS/fACzGsG0UkMzt4bRjy2kuW2
         WzxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Di6WOZpK0vZIlV10s5uClF60KLfnVE1RQxRILeythSs=;
        fh=6gg0ght8wldm0GlcQKu2mojnASHp4ZVfvdboFPG5SJw=;
        b=HixRaGg7WvaFOH/V9HQIqOhNZkVOWVgzJKXLi7zMkjDAymM6Bo9R0bjThRdB3MkgEe
         ohYou7Y7wGDx02Msxj0kKprkfrwHOMjHK3zlsxjB0KCWHMJKyhJ9jE06fRavIDuhMFk8
         x6hDDp6AT/jKrHJKimoP0HpSC6674X9UGh9F2WhQOW9B991FOqGmaDCVASSfqQ4exgJs
         XlTl7BXN6r0jkVo1mU0TGPxjrlj1W/U/a8yQqdPWb3tKX7Eci6OyXnYZ2A9c/UzL5D73
         SdZLoO9bymRKMwOd9hdLUI135B9ResKRLpwgvXtjS8is7brYVPpZd7X8K5/JuOW2oM4T
         NUIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ca18e2360f4ac-82d48f7a48bsi45644839f.0.2024.09.19.02.20.07
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 02:20:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A9BC71007;
	Thu, 19 Sep 2024 02:20:36 -0700 (PDT)
Received: from [10.163.34.169] (unknown [10.163.34.169])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 402293F86F;
	Thu, 19 Sep 2024 02:20:02 -0700 (PDT)
Message-ID: <3ac8c39c-e842-41e4-960a-6b41cd83848d@arm.com>
Date: Thu, 19 Sep 2024 14:50:00 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 3/7] mm: Use ptep_get() for accessing PTE entries
To: David Hildenbrand <david@redhat.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-4-anshuman.khandual@arm.com>
 <f9a7ebb4-3d7c-403e-b818-29a6a3b12adc@redhat.com>
 <8cafe140-35cf-4e9d-8218-dfbfc156ca69@arm.com>
 <d32136d4-94ab-432a-89ae-5f41935404ff@redhat.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <d32136d4-94ab-432a-89ae-5f41935404ff@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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


On 9/19/24 13:34, David Hildenbrand wrote:
> On 18.09.24 08:32, Anshuman Khandual wrote:
>>
>>
>> On 9/17/24 15:58, David Hildenbrand wrote:
>>> On 17.09.24 09:31, Anshuman Khandual wrote:
>>>> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE(=
) but
>>>> also provides the platform an opportunity to override when required. T=
his
>>>> stores read page table entry value in a local variable which can be us=
ed in
>>>> multiple instances there after. This helps in avoiding multiple memory=
 load
>>>> operations as well possible race conditions.
>>>>
>>>
>>> Please make it clearer in the subject+description that this really only=
 involves set_pte_safe().
>>
>> I will update the commit message with some thing like this.
>>
>> mm: Use ptep_get() in set_pte_safe()
>>
>> This converts PTE accesses in set_pte_safe() via ptep_get() helper which
>> defaults as READ_ONCE() but also provides the platform an opportunity to
>> override when required. This stores read page table entry value in a loc=
al
>> variable which can be used in multiple instances there after. This helps
>> in avoiding multiple memory load operations as well as some possible rac=
e
>> conditions.
>>
>>>
>>>
>>>> Cc: Andrew Morton <akpm@linux-foundation.org>
>>>> Cc: David Hildenbrand <david@redhat.com>
>>>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>>>> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
>>>> Cc: linux-mm@kvack.org
>>>> Cc: linux-kernel@vger.kernel.org
>>>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>>>> ---
>>>> =C2=A0=C2=A0 include/linux/pgtable.h | 3 ++-
>>>> =C2=A0=C2=A0 1 file changed, 2 insertions(+), 1 deletion(-)
>>>>
>>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>>> index 2a6a3cccfc36..547eeae8c43f 100644
>>>> --- a/include/linux/pgtable.h
>>>> +++ b/include/linux/pgtable.h
>>>> @@ -1060,7 +1060,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pg=
d_b)
>>>> =C2=A0=C2=A0=C2=A0 */
>>>> =C2=A0=C2=A0 #define set_pte_safe(ptep, pte) \
>>>> =C2=A0=C2=A0 ({ \
>>>> -=C2=A0=C2=A0=C2=A0 WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep=
, pte)); \
>>>> +=C2=A0=C2=A0=C2=A0 pte_t __old =3D ptep_get(ptep); \
>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON_ONCE(pte_present(__old) && !pte_same(__old=
, pte)); \
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(ptep, pte); \
>>>> =C2=A0=C2=A0 })
>>>> =C2=A0=C2=A0=20
>>>
>>> I don't think this is necessary. PTE present cannot flip concurrently, =
that's the whole reason of the "safe" part after all.
>>
>> Which is not necessary ? Converting de-references to ptep_get() OR cachi=
ng
>> the page table read value in a local variable ? ptep_get() conversion al=
so
>> serves the purpose providing an opportunity for platform to override.
>=20
> Which arch override are you thinking of where this change here would make=
 a real difference? Would it even make a difference with cont-pte on arm?

As we figured out already this code is not used any where other than x86 pl=
atform.
So changing this, won't make a difference for arm64 unless I am missing som=
ething.
The idea behind the series is to ensure that, there are no direct de-refere=
ncing
of page table entries in generic MM code and all accesses should go via ava=
ilable
helpers instead. But if we move these set_pxd_safe() helpers into platform =
code as
you have suggested earlier, those changes will not be necessary anymore.

>=20
>>
>>>
>>> Can we just move these weird set_pte/pmd_safe() stuff to x86 init code =
and be done with it? Then it's also clear *where* it is getting used and fo=
r which reason.
>>>
>> set_pte/pmd_safe() can be moved to x86 platform - as that is currently t=
he
>> sole user for these helpers. But because set_pgd_safe() gets used in ris=
cv
>> platform, just wondering would it be worth moving only the pte/pmd helpe=
rs
>> but not the pgd one ?
>=20
> My take would be just to move them where they are used, and possibly even=
 inlining them.
>=20
> The point is that it's absolutely underdocumented what "_safe" is suppose=
d to be here, and I don't really see the reason to have this in common code=
 (making the common API more complicated).

Agreed, it makes sense for these helpers to be in the platform code instead=
 where
they get used (x86, riscv). Will move them as required.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3ac8c39c-e842-41e4-960a-6b41cd83848d%40arm.com.
