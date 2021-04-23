Return-Path: <kasan-dev+bncBC447XVYUEMRBS7FRSCAMGQEF5U6AAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DF63D369B86
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 22:49:15 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id t18-20020adfdc120000b02900ffe4432d8bsf15530348wri.6
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 13:49:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619210955; cv=pass;
        d=google.com; s=arc-20160816;
        b=ARzKWkPGT/9bPM+ut6J0vRHI0jixlvE4IJR9ZY3bTG9ldi4duAwRZ8/7yEquNokoxq
         NauV4YSiZeQnuubmUqG0HwqGOikROivdQZJTJ+XfYKTfodhpgFKBqM4ArAWNS7XA2e++
         QpSpkcAFmfEzAwmHAc1KrwymkI9tT6naCyI7I82Myc6knB5AI9w8ev9Uh5UARYn1J3xt
         eXZvvWkL4O/SKOcbcKGSuuTEaAs5baH0PSooYDw12mB0NBW/4CAfVaA4zsWyp/zojRmE
         KfKO8IajgumVh7pyAEWMx0+F5WFHMdhysrhooe8Orb/4PbybhfOADdIZAfAgqpth9NNm
         CEhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Snsbu2HSCTnXCoXftcASziaYZ02ffRn5O0qyio2TDK0=;
        b=sm/Ff9gIR27yk2Xog8PZlylHyk7NRO0bhZmBqQcaHp3LajEsczyze5iyGrcb1qNPLV
         3U0C8j3siuEIFmSNctRfS+kja9dPKg5NwTddsclGln5BhKBLHQWwG00kh3cAOl+DsE5P
         ibQc5yuKHxvgervpt5+rPJT0QUIjlzSFYMP+TOEXtuFsEjHa2TyaTDGKHzJOsT5spjek
         E0Yjqck8r5FuL25R5ODP7Y3lMXkWPiI83sOvctPJlFgZZH6EcsEoAssaDBtrBmXNB+1o
         xwHy5H8VX5eWjeyAd5V51fN0i5DsrcOGJGqDq5pSdI1X6Hj8AqX0Rf4QOz3SUAI5fy66
         CDfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Snsbu2HSCTnXCoXftcASziaYZ02ffRn5O0qyio2TDK0=;
        b=M9rQoqdiTSN5PYNMduoeCODvXcvEnJ0rf4bgNEdYmBFNVWpE/9V2e4YFHw61Fyl/AA
         lB3idxe7S3jyg1zoK/a9y2YMNNcPCnrqR1z/PApBwBlyJdHVGHXxW5PuDccgJNKuVzyj
         Vt0GYbxe8g6jXpvpbDyPPymCY3pC1sw+Cc1/+GIUNhQNfWnxasuwfg9iTEMAjBp6SqvV
         1us55CiHvH7D0yH3G+Hb1YV5KR6/Jz2YA2g6V8kjFH3CWR4AjqVEiLRJuhDKPPxCc/gt
         vTP+2aWsHUDeYQjwp0JB1ck7CzGZdK0Mbdia5p1Cg89NZ/OC/7kybPT8tTka/pVVvclz
         E+Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Snsbu2HSCTnXCoXftcASziaYZ02ffRn5O0qyio2TDK0=;
        b=FnKooycbTbIHedX4eOZDWQ7nYaZXpLHA5LGZj8XQJ+QMQK7F7f1zpxsPuw19yCZTPP
         c/W0p5lS/nwqE24NodHblW6F0pu43s4o0peFytiVWK1U9z5XWufb0vYkZGCTmdkc+sr3
         DLTJhnQitCaGpUwkLBhu4KHBGDLB5CHsdHZU+nb+5otnlAp/zncZXZKmC8uk2afbeFNa
         ZiyvQWRn3bdAVuAt/xkUA+A/BjaFhZluM++iOATKhWI19vKp34Z7B1aE7a0IadF3CJwe
         b5JBiUi0f8i1DhzXVU05vXom2VOPGACs/3LlcVzgFKz+48K+BpaFW1ZuY4CF0ZofcQvN
         5ANA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BQJ7vobnUu0EpP/HG7z6lJgcnUuD9zwkbQXExVhaN+Vfmevnr
	bctu8gf16Smq4Bs7MhEf26U=
X-Google-Smtp-Source: ABdhPJxeaCTYVlG0t6XT0uv3H+5aDpEd/x8BLiFZuAxVVwLoTlrmqAh4zd/6y1Ey+Hfv1OwjzF9qPw==
X-Received: by 2002:adf:fe12:: with SMTP id n18mr6789331wrr.17.1619210955630;
        Fri, 23 Apr 2021 13:49:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e5:: with SMTP id g5ls759099wrd.1.gmail; Fri, 23 Apr
 2021 13:49:14 -0700 (PDT)
X-Received: by 2002:a5d:538a:: with SMTP id d10mr6959672wrv.38.1619210954719;
        Fri, 23 Apr 2021 13:49:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619210954; cv=none;
        d=google.com; s=arc-20160816;
        b=QR8Az9/L7HYdBGETi3fdNRD6hhEV8UniibWl7w5PPXnDlUwKqxCFUgMReoNp5pLzOs
         ql38LDKVRu5dOkWyA7I6jk2WVFaUv6hPQFQo/VbYLFwpkPydqGK/N/XM/NyGXtQAZq1z
         FlhHkrkNXjh9MNQ9IQG1+0f+SOyIv5/RQphnwxWJ57jPMiweNT2i4jGWzrkbyXXfT4Uo
         Cpuhn0idfl+/x0/03pqUmea/BcCSZz7aZvFBGfAs3eWtqoylc4wXXvOBfy6f9sFA5iIi
         NgddLdty1fH+5537G41xAVxq4BgSfZQYT8lOARJ5d+RQaJuFrAdB3ci5dghHmGRo8MZO
         pddA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=xR/tUjXl6MAtcWSVYufU2/GSB9Da/wuC1JWX6HyiiOw=;
        b=P9VTOwf9hVyEyBkcOihiL0mp0QhkQPHLcE2HaZr/35ekBAW0ZsJPynY+wIhICY+hKa
         zJQwlX7KNsIJ0oa8WXsuOJfnmok0WzQRRHLJbCPr/Efqn8ts0zcg7cnmhh3YiInMu4HB
         xEZpITYNlh+MwUuPgdf4kwPxhwQMBY9ZspBBhCdVJGZZ6NjLfjGRM7rFCOXy78mp9TPX
         fJgu7SLpwsb+8T2oxyMv2xAchlFNQlnhdh6NvE6DBxDlW5nASt+UpDoenh0voB626M2R
         x3M6X+4acWzNu3pnSvjST/LOQ0c3WcFNuVe+IddhB6eOTTwvot+cGK9LFrq9+vd92A/4
         iIjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [217.70.183.195])
        by gmr-mx.google.com with ESMTPS id a191si1420475wme.3.2021.04.23.13.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 23 Apr 2021 13:49:14 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.195;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay3-d.mail.gandi.net (Postfix) with ESMTPSA id CAC7460003;
	Fri, 23 Apr 2021 20:49:10 +0000 (UTC)
Subject: Re: [PATCH] riscv: Fix 32b kernel caused by 64b kernel mapping moving
 outside linear mapping
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: anup@brainfault.org, corbet@lwn.net,
 Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
 Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com,
 dvyukov@google.com, linux-doc@vger.kernel.org,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <mhng-5579c61f-d95b-4f9b-9f12-4df6bb24df0c@palmerdabbelt-glaptop>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <97819559-0af0-0422-5b6c-30872f759daa@ghiti.fr>
Date: Fri, 23 Apr 2021 16:49:10 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.0
MIME-Version: 1.0
In-Reply-To: <mhng-5579c61f-d95b-4f9b-9f12-4df6bb24df0c@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.195 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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



Le 4/23/21 =C3=A0 12:57 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Fri, 23 Apr 2021 01:34:02 PDT (-0700), alex@ghiti.fr wrote:
>> Le 4/20/21 =C3=A0 12:18 AM, Anup Patel a =C3=A9crit=C2=A0:
>>> On Sat, Apr 17, 2021 at 10:52 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>>
>>>> Fix multiple leftovers when moving the kernel mapping outside the=20
>>>> linear
>>>> mapping for 64b kernel that left the 32b kernel unusable.
>>>>
>>>> Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear=20
>>>> mapping")
>>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>>
>>> Quite a few #ifdef but I don't see any better way at the moment.=20
>>> Maybe we can
>>> clean this later. Otherwise looks good to me.
>=20
> Agreed.=C2=A0 I'd recently sent out a patch set that got NACK'd because w=
e're=20
> supposed to be relying on the compiler to optimize away references that=
=20
> can be staticly determined to not be exercised, which is probably the=20
> way forward to getting rid of a lot of of preprocessor stuff.=C2=A0 That =
all=20
> seems very fragile and is a bigger problem than this, though, so it's=20
> probably best to do it as its own thing.
>=20
>>> Reviewed-by: Anup Patel <anup@brainfault.org>
>>
>> Thanks Anup!
>>
>> @Palmer: This is not on for-next yet and then rv32 is broken. This does
>> not apply immediately on top of for-next though, so if you need a new
>> version, I can do that. But this squashes nicely with the patch it fixes
>> if you prefer.
>=20
> Thanks.=C2=A0 I just hadn't gotten to this one yet, but as you pointed ou=
t=20
> it's probably best to just squash it.=C2=A0 It's in the version on for-ne=
xt=20
> now, it caused few conflicts but I think I got everything sorted out.
>=20
> Now that everything is in I'm going to stop rewriting this stuff, as it=
=20
> touches pretty much the whole tree.=C2=A0 I don't have much of a patch ba=
ck=20
> log as of right now, and as the new stuff will be on top of it that will=
=20
> make everyone's lives easier.
>=20
>>
>> Let me know, I can do that very quickly.
>>
>> Alex
>>
>>>
>>> Regards,
>>> Anup
>>>
>>>> ---
>>>> =C2=A0 arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0 |=C2=A0 9 +++++=
++++
>>>> =C2=A0 arch/riscv/include/asm/pgtable.h | 16 ++++++++++++----
>>>> =C2=A0 arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 25 ++++++++++++++++++++++++-
>>>> =C2=A0 3 files changed, 45 insertions(+), 5 deletions(-)
>>>>
>>>> diff --git a/arch/riscv/include/asm/page.h=20
>>>> b/arch/riscv/include/asm/page.h
>>>> index 22cfb2be60dc..f64b61296c0c 100644
>>>> --- a/arch/riscv/include/asm/page.h
>>>> +++ b/arch/riscv/include/asm/page.h
>>>> @@ -90,15 +90,20 @@ typedef struct page *pgtable_t;
>>>>
>>>> =C2=A0 #ifdef CONFIG_MMU
>>>> =C2=A0 extern unsigned long va_pa_offset;
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0 extern unsigned long va_kernel_pa_offset;
>>>> +#endif
>>>> =C2=A0 extern unsigned long pfn_base;
>>>> =C2=A0 #define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (pfn_base)
>>>> =C2=A0 #else
>>>> =C2=A0 #define va_pa_offset=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 0
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0 #define va_kernel_pa_offset=C2=A0=C2=A0=C2=A0 0
>>>> +#endif
>>>> =C2=A0 #define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET >> PAGE_SH=
IFT)
>>>> =C2=A0 #endif /* CONFIG_MMU */
>>>>
>>>> +#ifdef CONFIG_64BIT

This one is incorrect as kernel_virt_addr is used also in 32b kernel,=20
which causes 32b failure when CONFIG_DEBUG_VIRTUAL is set, the following=20
diff fixes it:

diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index e280ba60cb34..6a7761c86ec2 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -106,9 +106,9 @@ extern unsigned long pfn_base;
  #define ARCH_PFN_OFFSET                (PAGE_OFFSET >> PAGE_SHIFT)
  #endif /* CONFIG_MMU */

-#ifdef CONFIG_64BIT
  extern unsigned long kernel_virt_addr;

+#ifdef CONFIG_64BIT
  #define linear_mapping_pa_to_va(x)     ((void *)((unsigned long)(x) +=20
va_pa_offset))
  #ifdef CONFIG_XIP_KERNEL
  #define kernel_mapping_pa_to_va(y)     ({=20
                  \

>>>> =C2=A0 extern unsigned long kernel_virt_addr;
>>>>
>>>> =C2=A0 #define linear_mapping_pa_to_va(x)=C2=A0=C2=A0=C2=A0=C2=A0 ((vo=
id *)((unsigned=20
>>>> long)(x) + va_pa_offset))
>>>> @@ -112,6 +117,10 @@ extern unsigned long kernel_virt_addr;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (_x < kernel_virt_add=
r)=20
>>>> ?=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 linear_mapping_va_to_pa(_x) :=20
>>>> kernel_mapping_va_to_pa(_x);=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 })
>>>> +#else
>>>> +#define __pa_to_va_nodebug(x)=C2=A0 ((void *)((unsigned long) (x) +=
=20
>>>> va_pa_offset))
>>>> +#define __va_to_pa_nodebug(x)=C2=A0 ((unsigned long)(x) - va_pa_offse=
t)
>>>> +#endif
>>>>
>>>> =C2=A0 #ifdef CONFIG_DEBUG_VIRTUAL
>>>> =C2=A0 extern phys_addr_t __virt_to_phys(unsigned long x);
>>>> diff --git a/arch/riscv/include/asm/pgtable.h=20
>>>> b/arch/riscv/include/asm/pgtable.h
>>>> index 80e63a93e903..5afda75cc2c3 100644
>>>> --- a/arch/riscv/include/asm/pgtable.h
>>>> +++ b/arch/riscv/include/asm/pgtable.h
>>>> @@ -16,19 +16,27 @@
>>>> =C2=A0 #else
>>>>
>>>> =C2=A0 #define ADDRESS_SPACE_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (UL(-1)=
)
>>>> -/*
>>>> - * Leave 2GB for kernel and BPF at the end of the address space
>>>> - */
>>>> +
>>>> +#ifdef CONFIG_64BIT
>>>> +/* Leave 2GB for kernel and BPF at the end of the address space */
>>>> =C2=A0 #define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (A=
DDRESS_SPACE_END - SZ_2G + 1)
>>>> +#else
>>>> +#define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_OFF=
SET
>>>> +#endif
>>>>
>>>> =C2=A0 #define VMALLOC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0 (KERN_VIRT_SIZE >>=
 1)
>>>> =C2=A0 #define VMALLOC_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET =
- 1)
>>>> =C2=A0 #define VMALLOC_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - VMALLOC_=
SIZE)
>>>>
>>>> -/* KASLR should leave at least 128MB for BPF after the kernel */
>>>> =C2=A0 #define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>>>> +#ifdef CONFIG_64BIT
>>>> +/* KASLR should leave at least 128MB for BPF after the kernel */
>>>> =C2=A0 #define BPF_JIT_REGION_START=C2=A0=C2=A0 PFN_ALIGN((unsigned lo=
ng)&_end)
>>>> =C2=A0 #define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0=C2=A0 (BPF_JIT_REG=
ION_START +=20
>>>> BPF_JIT_REGION_SIZE)
>>>> +#else
>>>> +#define BPF_JIT_REGION_START=C2=A0=C2=A0 (PAGE_OFFSET - BPF_JIT_REGIO=
N_SIZE)
>>>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
>>>> +#endif
>>>>
>>>> =C2=A0 /* Modules always live before the kernel */
>>>> =C2=A0 #ifdef CONFIG_64BIT
>>>> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
>>>> index 093f3a96ecfc..dc9b988e0778 100644
>>>> --- a/arch/riscv/mm/init.c
>>>> +++ b/arch/riscv/mm/init.c
>>>> @@ -91,8 +91,10 @@ static void print_vm_layout(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)VMALLOC_END);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 print_mlm("lowmem", (=
unsigned long)PAGE_OFFSET,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)high_memory);
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 print_mlm("kernel", (=
unsigned long)KERNEL_LINK_ADDR,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)ADDRESS_SPACE_END);
>>>> +#endif
>>>> =C2=A0 }
>>>> =C2=A0 #else
>>>> =C2=A0 static void print_vm_layout(void) { }
>>>> @@ -165,9 +167,11 @@ static struct pt_alloc_ops pt_ops;
>>>> =C2=A0 /* Offset between linear mapping virtual address and kernel loa=
d=20
>>>> address */
>>>> =C2=A0 unsigned long va_pa_offset;
>>>> =C2=A0 EXPORT_SYMBOL(va_pa_offset);
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0 /* Offset between kernel mapping virtual address and kernel loa=
d=20
>>>> address */
>>>> =C2=A0 unsigned long va_kernel_pa_offset;
>>>> =C2=A0 EXPORT_SYMBOL(va_kernel_pa_offset);
>>>> +#endif
>>>> =C2=A0 unsigned long pfn_base;
>>>> =C2=A0 EXPORT_SYMBOL(pfn_base);
>>>>
>>>> @@ -410,7 +414,9 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 load_sz =3D (uintptr_=
t)(&_end) - load_pa;
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 va_pa_offset =3D PAGE=
_OFFSET - load_pa;
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 va_kernel_pa_offset =
=3D kernel_virt_addr - load_pa;
>>>> +#endif
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn_base =3D PFN_DOWN=
(load_pa);
>>>>
>>>> @@ -469,12 +475,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa=
)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (voi=
d *)DTB_EARLY_BASE_VA + (dtb_pa &=20
>>>> (PMD_SIZE - 1));
>>>> =C2=A0 #else /* CONFIG_BUILTIN_DTB */
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * __va can't be=
 used since it would return a linear=20
>>>> mapping address
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * whereas dtb_e=
arly_va will be used before setup_vm_final=20
>>>> installs
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * the linear ma=
pping.
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D kern=
el_mapping_pa_to_va(dtb_pa);
>>>> +#else
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>>>> +#endif /* CONFIG_64BIT */
>>>> =C2=A0 #endif /* CONFIG_BUILTIN_DTB */
>>>> =C2=A0 #else
>>>> =C2=A0 #ifndef CONFIG_BUILTIN_DTB
>>>> @@ -486,7 +496,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (voi=
d *)DTB_EARLY_BASE_VA + (dtb_pa &=20
>>>> (PGDIR_SIZE - 1));
>>>> =C2=A0 #else /* CONFIG_BUILTIN_DTB */
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D kern=
el_mapping_pa_to_va(dtb_pa);
>>>> +#else
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>>>> +#endif /* CONFIG_64BIT */
>>>> =C2=A0 #endif /* CONFIG_BUILTIN_DTB */
>>>> =C2=A0 #endif
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_pa =3D dtb_=
pa;
>>>> @@ -571,12 +585,21 @@ static void __init setup_vm_final(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (pa =3D start; pa < end; pa +=3D map_size) =
{
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 va =3D (uintptr_t)__va(pa);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 create_pgd_mapping(swapper_pg_dir, va, pa,
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, PAGE_KERNEL);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size,
>>>> +#ifdef CONFIG_64BIT
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL
>>>> +#else
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL_EXEC
>>>> +#endif
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 );
>>>> +
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>
>>>> +#ifdef CONFIG_64BIT
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Map the kernel */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_kernel_page_ta=
ble(swapper_pg_dir, PMD_SIZE);
>>>> +#endif
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Clear fixmap PTE a=
nd PMD mappings */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PTE)=
;
>>>> --=20
>>>> 2.20.1
>>>>

I agree with you, too much #ifdef, it is hardly readable: I take a look=20
at how I can make it simpler.

Sorry for all those fixes,

Alex

>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/97819559-0af0-0422-5b6c-30872f759daa%40ghiti.fr.
