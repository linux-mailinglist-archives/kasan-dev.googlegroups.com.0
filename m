Return-Path: <kasan-dev+bncBC447XVYUEMRBBUO36BQMGQEHY44DMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AC62360138
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 06:54:31 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id o14-20020a5d474e0000b029010298882dadsf2130804wrs.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 21:54:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618462471; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aj7Ww8cSemMIKS+ekOGa2VRxTTjjtZyZNp0bPv792ksA6gBe6px0WsY+Q55XC6McOv
         X6+KiOLCuhxuDwWxEPl9z28IHGACYD5RsiWOUIECmTRXbuhElNr+fZ17d1986+oA3uSR
         jIOCur/WV4z0OHpV58cNA7nEguXaUzpa+L81kyH/CRjbhFsmm2ExBNdhX9I1VXVqM4Tl
         aWIq91cAO84KgXfkPWB/5BSvJn8knR/DcEUplBkJwFPJEIi3C8r8wbInSE191FteRLv0
         tq2HfTVfVWVu3fmw054yLVkyuRL4iZW8l2Qn29HfsmGsZ9daZtGDULFW4tVxAF9l+/Ga
         vZzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Ff9lEUbsNBF3TCog+TDbM+4G5JuGkfLKjwYF0D+r8F4=;
        b=oTbMJswVHgGDH9QoVVtsJvsNG9Oal5lr03cjnQt7DPi6ro4DCtdxGgvbu6Kxe0MWLY
         ZNcZxCWWa9r/dtP6TqLqaSKvR3Cv1M9SKHYbGjDZjHkCBP+AvlVSZKGvr3vDMLl4aKLq
         BJ23orq5KoTU/EQPlju65vWPBAlV99SK5CCkiz7TiUNmFqxYsuXKGzkdrKcHxcquJIuG
         bCyyfFzHsy83KkGk8boVBHDRMKjC2tU8+Bm1d3gIqENTrSQTaETvsYReyntiJUFfdHeN
         sC+Y4KpvVShCwhKQp7/FDB7JXifEFhVlhkFKF2a5F97EssVPBnycUjs6uPyLeYY+Jqbu
         gc+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ff9lEUbsNBF3TCog+TDbM+4G5JuGkfLKjwYF0D+r8F4=;
        b=RMVMcIngmxBaht6h9u7FR3DS8lncUHWnkuRTVVY5XJ8KkOk3qzcy0pEVKY+NzcAZ2y
         Vp9OK12JuY5PzqJaeSVOzD8is9R8vAlMfStFuInwv2XnqXujzT6FObGk4BBgMPvQcz+I
         o+RZRJ8SGpiYzLwUMAnUTAB/Ml1zx4Q4A5QNswdHl1k+5qFF4O7LCkOu+R1tyq6LeNdg
         e6sUhuhMAMuy9ZeowzVDMQ3YwG2ZiI/k9tA30yvCt7Ubcc7kRHGuXdnF/3QM4Lq3hMTt
         DjuHksjW+bk2F+3XiJNK+v3Ghrax3EEfD47Gv/0RkwfnXfJ0dZI2VX4X9212r0IJEgan
         YiIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ff9lEUbsNBF3TCog+TDbM+4G5JuGkfLKjwYF0D+r8F4=;
        b=Y1/9qKiq5L3jbk/BOJPuS34f/nCkekgnqzYo+kxE3uOh6pTm+Oj5UIHDkmYAZyUGhr
         UFBbSOU3YUdOKNCSxxZgeCkfl5R2xYUXM2ujty7rZ8j5eW0vgRNAMOIuAl28iPGWuiby
         CZiZHhBbDadx0sgVHMXb5/pjqSdDZxX9l4e77YK6RUQ+oxU8IhOaF3H+EZ6WiYSjEY1z
         c58cslCznWuZ7WoRGDKSDvs84NNqMhhERpMWQWNfa5aEew2Nk4YYzHiKqe3G5XoUhEIe
         40cnjaz/5gEpejxJznJnZnErw8cZ6i5sU9uOce3Y+k2h7uXC2mEBLQk1NvF9I2Mk43mx
         UrPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315BK3f7dPkLfY6d/G2HorhIrGtYOYY062HbXMcj3I7d06Bor+8
	Ya0zp9+NbCu/lY58w77ROxo=
X-Google-Smtp-Source: ABdhPJxwOqIKsOkTRucASEeev9BkcORFMnuzAS2SxuW4tmZNcAUi5LM+tm5KBQTJuHxiOgaa2cTxCA==
X-Received: by 2002:a7b:c8cf:: with SMTP id f15mr1110848wml.135.1618462470930;
        Wed, 14 Apr 2021 21:54:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:285:: with SMTP id 5ls2077105wmk.3.gmail; Wed, 14
 Apr 2021 21:54:30 -0700 (PDT)
X-Received: by 2002:a7b:cb45:: with SMTP id v5mr1171958wmj.2.1618462470024;
        Wed, 14 Apr 2021 21:54:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618462470; cv=none;
        d=google.com; s=arc-20160816;
        b=KkXFrlf2nUqmVOQkOCXKhZLSE/2J+m3zmqXOVpA66Q8WtvnGAJEaaYLT2x7O8NdV4p
         lhgASARyFUGHBbGKXNYnAKWm4aabUJ7TrqYlQIcYdFWiwGz+SaiiH8oTUuNkNnWz2Gz8
         5+aDS/I+TMn4nDZL9oSh1OPLgCtnr2N7O3LrGmpsWbKdmI0u+H2iRyofZu3/vGtwGa5r
         pO2irb9R5fbyj5xkGl167alH1mccB1MyAewOuJKMhm0XvJwLuoeEd3/lY7TM9vutP4hH
         j1SnNwS+W9mVbOrnV9SJrRJLq8Pen9NPH+dsFTnoaeqraXJs7YdPDMYO71rRvBA05jeX
         v9kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BjAB55AjiF4dV7/D95Y8+hHvuUJlLqRs8hq2wnclMsQ=;
        b=c4EaGqkb8/nZ2DbgoHtm75lgXMTvwjQ4oJwA2yQipFSOnLDiA31HiDqtxNeBEmYHyf
         5yYVBAxjS46OhZbQACr0gWq6kZndw3U/bBADiRFn91D0dY9O3TLJdF+O2IsZglzz9YmS
         Eyga8ynJSL3KBkjTxTD54cHgWpmbNm9RLoPbqRwlFL2SJXp6jpCzhHZyqM4lokAmDYMF
         oJNL6sw1WSJRC2J26Du1P6HjVxZtXlJveICZ4ZzEVQpydz5DeV5ZhAxOUwKbax2NkkAJ
         MVUz9IvrMB1z+WZa0y9s/y59AT32lBfmwHz37E8egHPzCLTTUp9rL4iGKhft8gTufO4J
         wiRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id e17si68258wrx.1.2021.04.14.21.54.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 14 Apr 2021 21:54:29 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id 4BBB7E0002;
	Thu, 15 Apr 2021 04:54:25 +0000 (UTC)
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
 aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>,
 aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
Date: Thu, 15 Apr 2021 00:54:25 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
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

Le 4/15/21 =C3=A0 12:20 AM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Sun, 11 Apr 2021 09:41:44 PDT (-0700), alex@ghiti.fr wrote:
>> This is a preparatory patch for relocatable kernel and sv48 support.
>>
>> The kernel used to be linked at PAGE_OFFSET address therefore we could=
=20
>> use
>> the linear mapping for the kernel mapping. But the relocated kernel base
>> address will be different from PAGE_OFFSET and since in the linear=20
>> mapping,
>> two different virtual addresses cannot point to the same physical=20
>> address,
>> the kernel mapping needs to lie outside the linear mapping so that we=20
>> don't
>> have to copy it at the same physical offset.
>>
>> The kernel mapping is moved to the last 2GB of the address space, BPF
>> is now always after the kernel and modules use the 2GB memory range righ=
t
>> before the kernel, so BPF and modules regions do not overlap. KASLR
>> implementation will simply have to move the kernel in the last 2GB range
>> and just take care of leaving enough space for BPF.
>>
>> In addition, by moving the kernel to the end of the address space, both
>> sv39 and sv48 kernels will be exactly the same without needing to be
>> relocated at runtime.
>>
>> Suggested-by: Arnd Bergmann <arnd@arndb.de>
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>> ---
>> =C2=A0arch/riscv/boot/loader.lds.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 3 +-
>> =C2=A0arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
| 17 +++++-
>> =C2=A0arch/riscv/include/asm/pgtable.h=C2=A0=C2=A0=C2=A0 | 37 ++++++++--=
--
>> =C2=A0arch/riscv/include/asm/set_memory.h |=C2=A0 1 +
>> =C2=A0arch/riscv/kernel/head.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 +-
>> =C2=A0arch/riscv/kernel/module.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 6 +-
>> =C2=A0arch/riscv/kernel/setup.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 5 ++
>> =C2=A0arch/riscv/kernel/vmlinux.lds.S=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 =
+-
>> =C2=A0arch/riscv/mm/fault.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 13 +++++
>> =C2=A0arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 87 ++++++++++++++++++++++--=
-----
>> =C2=A0arch/riscv/mm/kasan_init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 9 +++
>> =C2=A0arch/riscv/mm/physaddr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 2 +-
>> =C2=A012 files changed, 146 insertions(+), 40 deletions(-)
>>
>> diff --git a/arch/riscv/boot/loader.lds.S b/arch/riscv/boot/loader.lds.S
>> index 47a5003c2e28..62d94696a19c 100644
>> --- a/arch/riscv/boot/loader.lds.S
>> +++ b/arch/riscv/boot/loader.lds.S
>> @@ -1,13 +1,14 @@
>> =C2=A0/* SPDX-License-Identifier: GPL-2.0 */
>>
>> =C2=A0#include <asm/page.h>
>> +#include <asm/pgtable.h>
>>
>> =C2=A0OUTPUT_ARCH(riscv)
>> =C2=A0ENTRY(_start)
>>
>> =C2=A0SECTIONS
>> =C2=A0{
>> -=C2=A0=C2=A0=C2=A0 . =3D PAGE_OFFSET;
>> +=C2=A0=C2=A0=C2=A0 . =3D KERNEL_LINK_ADDR;
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 .payload : {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *(.payload)
>> diff --git a/arch/riscv/include/asm/page.h=20
>> b/arch/riscv/include/asm/page.h
>> index adc9d26f3d75..22cfb2be60dc 100644
>> --- a/arch/riscv/include/asm/page.h
>> +++ b/arch/riscv/include/asm/page.h
>> @@ -90,15 +90,28 @@ typedef struct page *pgtable_t;
>>
>> =C2=A0#ifdef CONFIG_MMU
>> =C2=A0extern unsigned long va_pa_offset;
>> +extern unsigned long va_kernel_pa_offset;
>> =C2=A0extern unsigned long pfn_base;
>> =C2=A0#define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
(pfn_base)
>> =C2=A0#else
>> =C2=A0#define va_pa_offset=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0
>> +#define va_kernel_pa_offset=C2=A0=C2=A0=C2=A0 0
>> =C2=A0#define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
(PAGE_OFFSET >> PAGE_SHIFT)
>> =C2=A0#endif /* CONFIG_MMU */
>>
>> -#define __pa_to_va_nodebug(x)=C2=A0=C2=A0=C2=A0 ((void *)((unsigned lon=
g) (x) +=20
>> va_pa_offset))
>> -#define __va_to_pa_nodebug(x)=C2=A0=C2=A0=C2=A0 ((unsigned long)(x) - v=
a_pa_offset)
>> +extern unsigned long kernel_virt_addr;
>> +
>> +#define linear_mapping_pa_to_va(x)=C2=A0=C2=A0=C2=A0 ((void *)((unsigne=
d long)(x) +=20
>> va_pa_offset))
>> +#define kernel_mapping_pa_to_va(x)=C2=A0=C2=A0=C2=A0 ((void *)((unsigne=
d long)(x) +=20
>> va_kernel_pa_offset))
>> +#define __pa_to_va_nodebug(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 linear_mapping_pa_to_va(x)
>> +
>> +#define linear_mapping_va_to_pa(x)=C2=A0=C2=A0=C2=A0 ((unsigned long)(x=
) -=20
>> va_pa_offset)
>> +#define kernel_mapping_va_to_pa(x)=C2=A0=C2=A0=C2=A0 ((unsigned long)(x=
) -=20
>> va_kernel_pa_offset)
>> +#define __va_to_pa_nodebug(x)=C2=A0=C2=A0=C2=A0 ({=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 unsigned long _x =3D x;=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 (_x < kernel_virt_addr) ?=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 linear_mapping_va_to_pa(_x) =
: kernel_mapping_va_to_pa(_x);=C2=A0=C2=A0=C2=A0 \
>> +=C2=A0=C2=A0=C2=A0 })
>>
>> =C2=A0#ifdef CONFIG_DEBUG_VIRTUAL
>> =C2=A0extern phys_addr_t __virt_to_phys(unsigned long x);
>> diff --git a/arch/riscv/include/asm/pgtable.h=20
>> b/arch/riscv/include/asm/pgtable.h
>> index ebf817c1bdf4..80e63a93e903 100644
>> --- a/arch/riscv/include/asm/pgtable.h
>> +++ b/arch/riscv/include/asm/pgtable.h
>> @@ -11,23 +11,30 @@
>>
>> =C2=A0#include <asm/pgtable-bits.h>
>>
>> -#ifndef __ASSEMBLY__
>> -
>> -/* Page Upper Directory not used in RISC-V */
>> -#include <asm-generic/pgtable-nopud.h>
>> -#include <asm/page.h>
>> -#include <asm/tlbflush.h>
>> -#include <linux/mm_types.h>
>> +#ifndef CONFIG_MMU
>> +#define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0 PAGE_OFFSET
>> +#else
>>
>> -#ifdef CONFIG_MMU
>> +#define ADDRESS_SPACE_END=C2=A0=C2=A0=C2=A0 (UL(-1))
>> +/*
>> + * Leave 2GB for kernel and BPF at the end of the address space
>> + */
>> +#define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0 (ADDRESS_SPACE_END - SZ_2G +=
 1)
>>
>> =C2=A0#define VMALLOC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0 (KERN_VIRT_SIZE >> 1)
>> =C2=A0#define VMALLOC_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - 1=
)
>> =C2=A0#define VMALLOC_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - VMALLOC_SIZ=
E)
>>
>> +/* KASLR should leave at least 128MB for BPF after the kernel */
>> =C2=A0#define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>> -#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - BPF_JIT_R=
EGION_SIZE)
>> -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
>> +#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 PFN_ALIGN((unsigned long=
)&_end)
>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_START +=20
>> BPF_JIT_REGION_SIZE)
>> +
>> +/* Modules always live before the kernel */
>> +#ifdef CONFIG_64BIT
>> +#define MODULES_VADDR=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)&_end=
) - SZ_2G)
>> +#define MODULES_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)&_start=
))
>> +#endif
>>
>> =C2=A0/*
>> =C2=A0 * Roughly size the vmemmap space to be large enough to fit enough
>> @@ -57,9 +64,16 @@
>> =C2=A0#define FIXADDR_SIZE=C2=A0=C2=A0=C2=A0=C2=A0 PGDIR_SIZE
>> =C2=A0#endif
>> =C2=A0#define FIXADDR_START=C2=A0=C2=A0=C2=A0 (FIXADDR_TOP - FIXADDR_SIZ=
E)
>> -
>> =C2=A0#endif
>>
>> +#ifndef __ASSEMBLY__
>> +
>> +/* Page Upper Directory not used in RISC-V */
>> +#include <asm-generic/pgtable-nopud.h>
>> +#include <asm/page.h>
>> +#include <asm/tlbflush.h>
>> +#include <linux/mm_types.h>
>> +
>> =C2=A0#ifdef CONFIG_64BIT
>> =C2=A0#include <asm/pgtable-64.h>
>> =C2=A0#else
>> @@ -484,6 +498,7 @@ static inline int ptep_clear_flush_young(struct=20
>> vm_area_struct *vma,
>>
>> =C2=A0#define kern_addr_valid(addr)=C2=A0=C2=A0 (1) /* FIXME */
>>
>> +extern char _start[];
>> =C2=A0extern void *dtb_early_va;
>> =C2=A0extern uintptr_t dtb_early_pa;
>> =C2=A0void setup_bootmem(void);
>> diff --git a/arch/riscv/include/asm/set_memory.h=20
>> b/arch/riscv/include/asm/set_memory.h
>> index 6887b3d9f371..a9c56776fa0e 100644
>> --- a/arch/riscv/include/asm/set_memory.h
>> +++ b/arch/riscv/include/asm/set_memory.h
>> @@ -17,6 +17,7 @@ int set_memory_x(unsigned long addr, int numpages);
>> =C2=A0int set_memory_nx(unsigned long addr, int numpages);
>> =C2=A0int set_memory_rw_nx(unsigned long addr, int numpages);
>> =C2=A0void protect_kernel_text_data(void);
>> +void protect_kernel_linear_mapping_text_rodata(void);
>> =C2=A0#else
>> =C2=A0static inline int set_memory_ro(unsigned long addr, int numpages) =
{=20
>> return 0; }
>> =C2=A0static inline int set_memory_rw(unsigned long addr, int numpages) =
{=20
>> return 0; }
>> diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
>> index f5a9bad86e58..6cb05f22e52a 100644
>> --- a/arch/riscv/kernel/head.S
>> +++ b/arch/riscv/kernel/head.S
>> @@ -69,7 +69,8 @@ pe_head_start:
>> =C2=A0#ifdef CONFIG_MMU
>> =C2=A0relocate:
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Relocate return address */
>> -=C2=A0=C2=A0=C2=A0 li a1, PAGE_OFFSET
>> +=C2=A0=C2=A0=C2=A0 la a1, kernel_virt_addr
>> +=C2=A0=C2=A0=C2=A0 REG_L a1, 0(a1)
>> =C2=A0=C2=A0=C2=A0=C2=A0 la a2, _start
>> =C2=A0=C2=A0=C2=A0=C2=A0 sub a1, a1, a2
>> =C2=A0=C2=A0=C2=A0=C2=A0 add ra, ra, a1
>> diff --git a/arch/riscv/kernel/module.c b/arch/riscv/kernel/module.c
>> index 104fba889cf7..ce153771e5e9 100644
>> --- a/arch/riscv/kernel/module.c
>> +++ b/arch/riscv/kernel/module.c
>> @@ -408,12 +408,10 @@ int apply_relocate_add(Elf_Shdr *sechdrs, const=20
>> char *strtab,
>> =C2=A0}
>>
>> =C2=A0#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
>> -#define VMALLOC_MODULE_START \
>> -=C2=A0=C2=A0=C2=A0=C2=A0 max(PFN_ALIGN((unsigned long)&_end - SZ_2G), V=
MALLOC_START)
>> =C2=A0void *module_alloc(unsigned long size)
>> =C2=A0{
>> -=C2=A0=C2=A0=C2=A0 return __vmalloc_node_range(size, 1, VMALLOC_MODULE_=
START,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMALLOC_END, GFP_KERNEL,
>> +=C2=A0=C2=A0=C2=A0 return __vmalloc_node_range(size, 1, MODULES_VADDR,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MODULES_END, GFP_KERNEL,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL_EXEC, 0, NUMA_=
NO_NODE,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __builtin_return_address(0=
));
>> =C2=A0}
>> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
>> index e85bacff1b50..30e4af0fd50c 100644
>> --- a/arch/riscv/kernel/setup.c
>> +++ b/arch/riscv/kernel/setup.c
>> @@ -265,6 +265,11 @@ void __init setup_arch(char **cmdline_p)
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 protect_kernel_text_dat=
a();
>> +
>> +#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
>> +=C2=A0=C2=A0=C2=A0 protect_kernel_linear_mapping_text_rodata();
>> +#endif
>> +
>> =C2=A0#ifdef CONFIG_SWIOTLB
>> =C2=A0=C2=A0=C2=A0=C2=A0 swiotlb_init(1);
>> =C2=A0#endif
>> diff --git a/arch/riscv/kernel/vmlinux.lds.S=20
>> b/arch/riscv/kernel/vmlinux.lds.S
>> index de03cb22d0e9..0726c05e0336 100644
>> --- a/arch/riscv/kernel/vmlinux.lds.S
>> +++ b/arch/riscv/kernel/vmlinux.lds.S
>> @@ -4,7 +4,8 @@
>> =C2=A0 * Copyright (C) 2017 SiFive
>> =C2=A0 */
>>
>> -#define LOAD_OFFSET PAGE_OFFSET
>> +#include <asm/pgtable.h>
>> +#define LOAD_OFFSET KERNEL_LINK_ADDR
>> =C2=A0#include <asm/vmlinux.lds.h>
>> =C2=A0#include <asm/page.h>
>> =C2=A0#include <asm/cache.h>
>> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
>> index 8f17519208c7..1b14d523a95c 100644
>> --- a/arch/riscv/mm/fault.c
>> +++ b/arch/riscv/mm/fault.c
>> @@ -231,6 +231,19 @@ asmlinkage void do_page_fault(struct pt_regs *regs)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> =C2=A0=C2=A0=C2=A0=C2=A0 }
>>
>> +#ifdef CONFIG_64BIT
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Modules in 64bit kernels lie in their own vi=
rtual region which=20
>> is not
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * in the vmalloc region, but dealing with page=
 faults in this=20
>> region
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * or the vmalloc region amounts to doing the s=
ame thing:=20
>> checking that
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * the mapping exists in init_mm.pgd and updati=
ng user page=20
>> table, so
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * just use vmalloc_fault.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 if (unlikely(addr >=3D MODULES_VADDR && addr < MODUL=
ES_END)) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vmalloc_fault(regs, code, ad=
dr);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> +=C2=A0=C2=A0=C2=A0 }
>> +#endif
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Enable interrupts if they were enabled in th=
e parent context. */
>> =C2=A0=C2=A0=C2=A0=C2=A0 if (likely(regs->status & SR_PIE))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_irq_enable();
>> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
>> index 7f5036fbee8c..093f3a96ecfc 100644
>> --- a/arch/riscv/mm/init.c
>> +++ b/arch/riscv/mm/init.c
>> @@ -25,6 +25,9 @@
>>
>> =C2=A0#include "../kernel/head.h"
>>
>> +unsigned long kernel_virt_addr =3D KERNEL_LINK_ADDR;
>> +EXPORT_SYMBOL(kernel_virt_addr);
>> +
>> =C2=A0unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __page_aligned_bss;
>> =C2=A0EXPORT_SYMBOL(empty_zero_page);
>> @@ -88,6 +91,8 @@ static void print_vm_layout(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned l=
ong)VMALLOC_END);
>> =C2=A0=C2=A0=C2=A0=C2=A0 print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned l=
ong)high_memory);
>> +=C2=A0=C2=A0=C2=A0 print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)A=
DDRESS_SPACE_END);
>> =C2=A0}
>> =C2=A0#else
>> =C2=A0static void print_vm_layout(void) { }
>> @@ -116,8 +121,13 @@ void __init setup_bootmem(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* The maximal physical memory size is -PAGE_OF=
FSET. */
>> =C2=A0=C2=A0=C2=A0=C2=A0 memblock_enforce_memory_limit(-PAGE_OFFSET);
>>
>> -=C2=A0=C2=A0=C2=A0 /* Reserve from the start of the kernel to the end o=
f the kernel */
>> -=C2=A0=C2=A0=C2=A0 memblock_reserve(vmlinux_start, vmlinux_end - vmlinu=
x_start);
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Reserve from the start of the kernel to the =
end of the kernel
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * and make sure we align the reservation on PM=
D_SIZE since we will
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * map the kernel in the linear mapping as read=
-only: we do not want
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * any allocation to happen between _end and th=
e next pmd aligned=20
>> page.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 memblock_reserve(vmlinux_start, (vmlinux_end - vmlin=
ux_start +=20
>> PMD_SIZE - 1) & PMD_MASK);
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * memblock allocator is not aware of the =
fact that last 4K bytes of
>> @@ -152,8 +162,12 @@ void __init setup_bootmem(void)
>> =C2=A0#ifdef CONFIG_MMU
>> =C2=A0static struct pt_alloc_ops pt_ops;
>>
>> +/* Offset between linear mapping virtual address and kernel load=20
>> address */
>> =C2=A0unsigned long va_pa_offset;
>> =C2=A0EXPORT_SYMBOL(va_pa_offset);
>> +/* Offset between kernel mapping virtual address and kernel load=20
>> address */
>> +unsigned long va_kernel_pa_offset;
>> +EXPORT_SYMBOL(va_kernel_pa_offset);
>> =C2=A0unsigned long pfn_base;
>> =C2=A0EXPORT_SYMBOL(pfn_base);
>>
>> @@ -257,7 +271,7 @@ static pmd_t *get_pmd_virt_late(phys_addr_t pa)
>>
>> =C2=A0static phys_addr_t __init alloc_pmd_early(uintptr_t va)
>> =C2=A0{
>> -=C2=A0=C2=A0=C2=A0 BUG_ON((va - PAGE_OFFSET) >> PGDIR_SHIFT);
>> +=C2=A0=C2=A0=C2=A0 BUG_ON((va - kernel_virt_addr) >> PGDIR_SHIFT);
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 return (uintptr_t)early_pmd;
>> =C2=A0}
>> @@ -372,17 +386,32 @@ static uintptr_t __init=20
>> best_map_size(phys_addr_t base, phys_addr_t size)
>> =C2=A0#error "setup_vm() is called from head.S before relocate so it sho=
uld=20
>> not use absolute addressing."
>> =C2=A0#endif
>>
>> +uintptr_t load_pa, load_sz;
>> +
>> +static void __init create_kernel_page_table(pgd_t *pgdir, uintptr_t=20
>> map_size)
>> +{
>> +=C2=A0=C2=A0=C2=A0 uintptr_t va, end_va;
>> +
>> +=C2=A0=C2=A0=C2=A0 end_va =3D kernel_virt_addr + load_sz;
>> +=C2=A0=C2=A0=C2=A0 for (va =3D kernel_virt_addr; va < end_va; va +=3D m=
ap_size)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(pgdir, va=
,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 load_pa + (va - kernel_virt_addr),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, PAGE_KERNEL_EXEC);
>> +}
>> +
>> =C2=A0asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>> =C2=A0{
>> -=C2=A0=C2=A0=C2=A0 uintptr_t va, pa, end_va;
>> -=C2=A0=C2=A0=C2=A0 uintptr_t load_pa =3D (uintptr_t)(&_start);
>> -=C2=A0=C2=A0=C2=A0 uintptr_t load_sz =3D (uintptr_t)(&_end) - load_pa;
>> +=C2=A0=C2=A0=C2=A0 uintptr_t pa;
>> =C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t map_size;
>> =C2=A0#ifndef __PAGETABLE_PMD_FOLDED
>> =C2=A0=C2=A0=C2=A0=C2=A0 pmd_t fix_bmap_spmd, fix_bmap_epmd;
>> =C2=A0#endif
>> +=C2=A0=C2=A0=C2=A0 load_pa =3D (uintptr_t)(&_start);
>> +=C2=A0=C2=A0=C2=A0 load_sz =3D (uintptr_t)(&_end) - load_pa;
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 va_pa_offset =3D PAGE_OFFSET - load_pa;
>> +=C2=A0=C2=A0=C2=A0 va_kernel_pa_offset =3D kernel_virt_addr - load_pa;
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0 pfn_base =3D PFN_DOWN(load_pa);
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>> @@ -410,26 +439,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>> =C2=A0=C2=A0=C2=A0=C2=A0 create_pmd_mapping(fixmap_pmd, FIXADDR_START,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE);
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Setup trampoline PGD and PMD */
>> -=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
>> +=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, kernel_virt_ad=
dr,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE);
>> -=C2=A0=C2=A0=C2=A0 create_pmd_mapping(trampoline_pmd, PAGE_OFFSET,
>> +=C2=A0=C2=A0=C2=A0 create_pmd_mapping(trampoline_pmd, kernel_virt_addr,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 load_pa, PMD_SIZE, PAGE_KERNEL_EXEC);
>> =C2=A0#else
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Setup trampoline PGD */
>> -=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
>> +=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, kernel_virt_ad=
dr,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 load_pa, PGDIR_SIZE, PAGE_KERNEL_EXEC);
>> =C2=A0#endif
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>> -=C2=A0=C2=A0=C2=A0=C2=A0 * Setup early PGD covering entire kernel which=
 will allows
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Setup early PGD covering entire kernel which=
 will allow
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * us to reach paging_init(). We map all m=
emory banks later
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * in setup_vm_final() below.
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> -=C2=A0=C2=A0=C2=A0 end_va =3D PAGE_OFFSET + load_sz;
>> -=C2=A0=C2=A0=C2=A0 for (va =3D PAGE_OFFSET; va < end_va; va +=3D map_si=
ze)
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(early_pg_=
dir, va,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 load_pa + (va - PAGE_OFFSET),
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, PAGE_KERNEL_EXEC);
>> +=C2=A0=C2=A0=C2=A0 create_kernel_page_table(early_pg_dir, map_size);
>>
>> =C2=A0#ifndef __PAGETABLE_PMD_FOLDED
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Setup early PMD for DTB */
>> @@ -444,7 +469,12 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>> =C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (void *)DTB_EARLY_BASE_VA + (d=
tb_pa & (PMD_SIZE -=20
>> 1));
>> =C2=A0#else /* CONFIG_BUILTIN_DTB */
>> -=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * __va can't be used since it would return a l=
inear mapping address
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * whereas dtb_early_va will be used before set=
up_vm_final installs
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * the linear mapping.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>> =C2=A0#endif /* CONFIG_BUILTIN_DTB */
>> =C2=A0#else
>> =C2=A0#ifndef CONFIG_BUILTIN_DTB
>> @@ -456,7 +486,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>> =C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (void *)DTB_EARLY_BASE_VA + (d=
tb_pa & (PGDIR_SIZE=20
>> - 1));
>> =C2=A0#else /* CONFIG_BUILTIN_DTB */
>> -=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>> +=C2=A0=C2=A0=C2=A0 dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>> =C2=A0#endif /* CONFIG_BUILTIN_DTB */
>> =C2=A0#endif
>> =C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_pa =3D dtb_pa;
>> @@ -492,6 +522,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>> =C2=A0#endif
>> =C2=A0}
>>
>> +#ifdef CONFIG_64BIT
>> +void protect_kernel_linear_mapping_text_rodata(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long text_start =3D (unsigned long)lm_alias=
(_start);
>> +=C2=A0=C2=A0=C2=A0 unsigned long init_text_start =3D (unsigned=20
>> long)lm_alias(__init_text_begin);
>> +=C2=A0=C2=A0=C2=A0 unsigned long rodata_start =3D (unsigned=20
>> long)lm_alias(__start_rodata);
>> +=C2=A0=C2=A0=C2=A0 unsigned long data_start =3D (unsigned long)lm_alias=
(_data);
>> +
>> +=C2=A0=C2=A0=C2=A0 set_memory_ro(text_start, (init_text_start - text_st=
art) >>=20
>> PAGE_SHIFT);
>> +=C2=A0=C2=A0=C2=A0 set_memory_nx(text_start, (init_text_start - text_st=
art) >>=20
>> PAGE_SHIFT);
>> +
>> +=C2=A0=C2=A0=C2=A0 set_memory_ro(rodata_start, (data_start - rodata_sta=
rt) >>=20
>> PAGE_SHIFT);
>> +=C2=A0=C2=A0=C2=A0 set_memory_nx(rodata_start, (data_start - rodata_sta=
rt) >>=20
>> PAGE_SHIFT);
>> +}
>> +#endif
>> +
>> =C2=A0static void __init setup_vm_final(void)
>> =C2=A0{
>> =C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t va, map_size;
>> @@ -513,7 +559,7 @@ static void __init setup_vm_final(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 __pa_symbol(fixmap_pgd_next),
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 PGDIR_SIZE, PAGE_TABLE);
>>
>> -=C2=A0=C2=A0=C2=A0 /* Map all memory banks */
>> +=C2=A0=C2=A0=C2=A0 /* Map all memory banks in the linear mapping */
>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &start, &end) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D end)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 break;
>> @@ -525,10 +571,13 @@ static void __init setup_vm_final(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (pa =3D start; pa <=
 end; pa +=3D map_size) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 va =3D (uintptr_t)__va(pa);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 create_pgd_mapping(swapper_pg_dir, va, pa,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, P=
AGE_KERNEL_EXEC);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, P=
AGE_KERNEL);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0=C2=A0=C2=A0=C2=A0 }
>>
>> +=C2=A0=C2=A0=C2=A0 /* Map the kernel */
>> +=C2=A0=C2=A0=C2=A0 create_kernel_page_table(swapper_pg_dir, PMD_SIZE);
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Clear fixmap PTE and PMD mappings */
>> =C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PTE);
>> =C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PMD);
>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> index 2c39f0386673..28f4d52cf17e 100644
>> --- a/arch/riscv/mm/kasan_init.c
>> +++ b/arch/riscv/mm/kasan_init.c
>> @@ -171,6 +171,10 @@ void __init kasan_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
>> =C2=A0=C2=A0=C2=A0=C2=A0 u64 i;
>>
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Populate all kernel virtual address space wi=
th=20
>> kasan_early_shadow_page
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * except for the linear mapping and the module=
s/kernel/BPF mapping.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow((void *)KASAN_SHADO=
W_START,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_mem_to_shado=
w((void *)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMEMMAP_END));
>> @@ -183,6 +187,7 @@ void __init kasan_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 (void *)kasan_mem_to_shadow((void *)VMALLOC_START),
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 (void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>
>> +=C2=A0=C2=A0=C2=A0 /* Populate the linear mapping */
>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start, &_end) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void *=
)__va(_start);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *end =3D (void *)_=
_va(_end);
>> @@ -193,6 +198,10 @@ void __init kasan_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_me=
m_to_shadow(start),=20
>> kasan_mem_to_shadow(end));
>> =C2=A0=C2=A0=C2=A0=C2=A0 };
>>
>> +=C2=A0=C2=A0=C2=A0 /* Populate kernel, BPF, modules mapping */
>> +=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_mem_to_shadow((const void *)MOD=
ULES_VADDR),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_mem_to_shadow((const void *)BPF_JIT_REGION_END));
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < PTRS_PER_PTE; i++)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(&kasan_early_sh=
adow_pte[i],
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 mk_pte(virt_to_page(kasan_early_shadow_page),
>> diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
>> index e8e4dcd39fed..35703d5ef5fd 100644
>> --- a/arch/riscv/mm/physaddr.c
>> +++ b/arch/riscv/mm/physaddr.c
>> @@ -23,7 +23,7 @@ EXPORT_SYMBOL(__virt_to_phys);
>>
>> =C2=A0phys_addr_t __phys_addr_symbol(unsigned long x)
>> =C2=A0{
>> -=C2=A0=C2=A0=C2=A0 unsigned long kernel_start =3D (unsigned long)PAGE_O=
FFSET;
>> +=C2=A0=C2=A0=C2=A0 unsigned long kernel_start =3D (unsigned long)kernel=
_virt_addr;
>> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long kernel_end =3D (unsigned long)_en=
d;
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>=20
> This is breaking boot for me with CONFIG_STRICT_KERNEL_RWX=3Dn.=C2=A0 I'm=
 not=20
> even really convinced that's a useful config to support, but it's=20
> currently optional and I'd prefer to avoid breaking it if possible.
>=20
> I can't quite figure out what's going on here and I'm pretty much tired=
=20
> out for tonight.=C2=A0 LMK if you don't have time to look at it and I'll =
try=20
> to give it another shot.

I'm taking a look at that.

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/76353fc0-f734-db47-0d0c-f0f379763aa0%40ghiti.fr.
