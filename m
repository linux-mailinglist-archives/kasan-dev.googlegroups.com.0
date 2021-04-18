Return-Path: <kasan-dev+bncBC447XVYUEMRBJNU6CBQMGQEFSGUB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9420E3634DE
	for <lists+kasan-dev@lfdr.de>; Sun, 18 Apr 2021 13:38:14 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id q24-20020a0565122118b02901ae16b0713asf5236653lfr.16
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Apr 2021 04:38:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618745894; cv=pass;
        d=google.com; s=arc-20160816;
        b=LQYiZk3lIhdmkvw0CVj3ft8t//ujH9VZmdhe8Q36zT+0kjKuKx7ncLgplYxUeUGB8a
         Z4oVJnrdckL2c2BJHqaShnz6cUVE9k2jg93BgSX3UUVEped21Cloz9QmxjCf3XBv5TY+
         NkWQ0HKXxJvd+TJJn3+LeNShx+5c/AWCejeX3gf8Dip7GXGx3BOj3Jtxib7XZ5SdajY3
         sVHwW2eZhY6xG3NPwCqXPg6UikKoqghVRB3LVPTqkqcgV6QCgznnZZQ2+ypk42JvrD3z
         uMlMTfTnUabB9EbCjYXz+hFQTI+gWqKKLDF87nJLINaaYv7jPmtHTNTKafcw0sOWY3KE
         62pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=oZIGc6GU/fonsXdhpHZ3O58ET3s83PYl9+1q63JicD4=;
        b=HS+Ah6KdVohwKCjsvThox21etj0di26zMPkMUMZcVuU/hXV63pR4JT4Dmg33IzmCsj
         FITmJGflC2yL3rzDHzABkVZQE69my7xNRc9IAJumvoBBTcc1GsFPBeTWqw3585bNA1UN
         32wtmtV8Yoa8233LMnQkeuUe0b7zePpn6h/h/W6opfdlnk0QaictnvLCS8J3YQyldgBC
         UWJB8SKdB3mlXfApCOynNFuyAqzHcQOxxoXaAYc9iIeKFe0hzflrb3uod/zYizCFtio4
         1TZu/l7BPw/mjT4oR8UbZG5tluk2viX96iojsfu2lWiMqTgxO2Lm3smv+Ix80naeLaZ+
         Yw1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oZIGc6GU/fonsXdhpHZ3O58ET3s83PYl9+1q63JicD4=;
        b=NKRSVk9rvgKm5cIblXpzh5geAYuo+VcPJgl1eUyBxcjzPqwxR+CA05alcSc02+fxHf
         QVTGdX7o2Jgf9Qu+r+JT4sko4LV3YKfjq5iDWAHbzig/hU8kuHb2jqKbKYZ3FFvZUrWN
         MPE5zSKIqJ05afmQkVJSdBiTUvK5jn+Db2Zvk73BmqM3dn8tsUlYMv0b0mYktwFq37jd
         NHaQYU3v4IwylZxPZjV4QOOhHXZ0dsHYDcfy9ZL8svENFAvqUeZKiagdHGvPbM4fkbPj
         IimM8VSWff0LmEaedA7XVTh+5wd0unbodiE957ceN5ZqI7QNhnDyEyvQ843pts9U7Ntl
         2OTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oZIGc6GU/fonsXdhpHZ3O58ET3s83PYl9+1q63JicD4=;
        b=CaMYB+xEe9bIiGoKTsV2tzJQffJ6+gRjYHnJK3ab5+Q0Ce2d6sRCmS9O1m9QlZPG3L
         lJoU+qw6p5FOL0AUbbVDdf06K8weatYq8qmuZFfTHVXWn+gT274CSOQdK6CEpgkEaUq1
         okE9CSAUhbl+sk+0eVpl63KNUF/Xu9AfbB/Y7icgoZQc8PA2+pWvmDHUa6r1MuE97TOs
         1acQblyNBr9IkfOJPNCFkB0B7HJpZC/tDJyURwoZcwZY6CqnmDhi4nmTJ0+coR4YaXAt
         Yl+6S+DLLEtlg52XqWwsX7PadxjHUzc7KrMooqO9JVlJqkf6WzmJDr6DSpX4XwmQLiwM
         x+Lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vVNWKr17ilWoR/hJYV1l0BcuP2FCVIWgCRLYUfSMnImsbdmvU
	1rZ+dm75OmVUE5pHp2vGmTw=
X-Google-Smtp-Source: ABdhPJxoClUiDoTeakLYKSncEbeoAo0KEcycv9AZ5EUKj+Q56sMSu3DtdRSQXXwNhBAd0sEKgs6ONQ==
X-Received: by 2002:a05:6512:21cc:: with SMTP id d12mr8711670lft.512.1618745894056;
        Sun, 18 Apr 2021 04:38:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5624:: with SMTP id b4ls1917438lff.0.gmail; Sun, 18 Apr
 2021 04:38:13 -0700 (PDT)
X-Received: by 2002:a19:ed13:: with SMTP id y19mr9218557lfy.338.1618745893035;
        Sun, 18 Apr 2021 04:38:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618745893; cv=none;
        d=google.com; s=arc-20160816;
        b=daS3mSrLS5pripyfP0h5UdoeFwajINEn1iXCv/6f9bK3photmLDzFFFPjE41hUEHPW
         eBJ3wiYI74yJY3ewb9F8lmMud48dYm7IAtHbdz03kNf50JLcoPpVcuLx0EIlZ8XtCRSI
         pS1CaU5Q0O3fX678WnJDBxa2KdHD9pfYE+4eppY/2giaSqQV+03NjHbcnzuhyoiO0/KH
         MWOm+0/ujel6PsJXF7IZ0gxAefKxFkHG2vQQgLYe+IrTfkcStExNgROuyDnT3W8tHcMd
         EW5vSUlqL2KBVC8rUiBYGJjo6Ge2IdExboO3GF44WM1VZ7Km1Nj1tPST+eW6deAhm0o4
         oyLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=Lyb6Lsv8EnYAq1LbyxrgNnGiNW1eFac1myCagtoheHM=;
        b=MmAa7ZGHeb0BKnwMfQgKEu/VxVk9hnVAC1jXQMKXZw19xyJbMy9Xb/SDYfNlv4LOEe
         HbLGs1dHJUq5mNJf8RQudXA77Kqc41RFrFaH7NOWgUj6PUlfhgWME24lR+zLJokn9FZI
         YMAXKPZeQM8ejy57cqyi7KdUg3Ym3Fybih6AS4+luQHQ8zglPXt4xWM0Tc20y7Yl8TMy
         3YSY1i+cguIAndRLfASN2tunGabn2tKZi3V+LT53/0UvDVavaomNhCADFKfGp7J748aE
         FDnDAdKQI8Rv2OBaHAPEWiWLzV9AQ6cjtU+P2W/4vJjwaPZmu1XA//beyo2QV8y1uPqp
         fwzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id a36si358277ljq.5.2021.04.18.04.38.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 18 Apr 2021 04:38:13 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id 92C35E0002;
	Sun, 18 Apr 2021 11:38:09 +0000 (UTC)
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
From: Alex Ghiti <alex@ghiti.fr>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
 aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>,
 aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-mm@kvack.org,
 Guenter Roeck <linux@roeck-us.net>
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
 <76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
 <a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
Message-ID: <7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
Date: Sun, 18 Apr 2021 07:38:09 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
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

Hi Palmer,

Le 4/15/21 =C3=A0 2:00 PM, Alex Ghiti a =C3=A9crit=C2=A0:
> Le 4/15/21 =C3=A0 12:54 AM, Alex Ghiti a =C3=A9crit=C2=A0:
>> Le 4/15/21 =C3=A0 12:20 AM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>>> On Sun, 11 Apr 2021 09:41:44 PDT (-0700), alex@ghiti.fr wrote:
>>>> This is a preparatory patch for relocatable kernel and sv48 support.
>>>>
>>>> The kernel used to be linked at PAGE_OFFSET address therefore we=20
>>>> could use
>>>> the linear mapping for the kernel mapping. But the relocated kernel=20
>>>> base
>>>> address will be different from PAGE_OFFSET and since in the linear=20
>>>> mapping,
>>>> two different virtual addresses cannot point to the same physical=20
>>>> address,
>>>> the kernel mapping needs to lie outside the linear mapping so that=20
>>>> we don't
>>>> have to copy it at the same physical offset.
>>>>
>>>> The kernel mapping is moved to the last 2GB of the address space, BPF
>>>> is now always after the kernel and modules use the 2GB memory range=20
>>>> right
>>>> before the kernel, so BPF and modules regions do not overlap. KASLR
>>>> implementation will simply have to move the kernel in the last 2GB=20
>>>> range
>>>> and just take care of leaving enough space for BPF.
>>>>
>>>> In addition, by moving the kernel to the end of the address space, bot=
h
>>>> sv39 and sv48 kernels will be exactly the same without needing to be
>>>> relocated at runtime.
>>>>
>>>> Suggested-by: Arnd Bergmann <arnd@arndb.de>
>>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>>> ---
>>>> =C2=A0arch/riscv/boot/loader.lds.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 3 +-
>>>> =C2=A0arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0| 17 +++++-
>>>> =C2=A0arch/riscv/include/asm/pgtable.h=C2=A0=C2=A0=C2=A0 | 37 ++++++++=
----
>>>> =C2=A0arch/riscv/include/asm/set_memory.h |=C2=A0 1 +
>>>> =C2=A0arch/riscv/kernel/head.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 +-
>>>> =C2=A0arch/riscv/kernel/module.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 |=C2=A0 6 +-
>>>> =C2=A0arch/riscv/kernel/setup.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 5 ++
>>>> =C2=A0arch/riscv/kernel/vmlinux.lds.S=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A03=
 +-
>>>> =C2=A0arch/riscv/mm/fault.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 13 +++++
>>>> =C2=A0arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 87 +++++++++++++++++++++=
+-------
>>>> =C2=A0arch/riscv/mm/kasan_init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 |=C2=A0 9 +++
>>>> =C2=A0arch/riscv/mm/physaddr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 2 +-
>>>> =C2=A012 files changed, 146 insertions(+), 40 deletions(-)
>>>>
>>>> diff --git a/arch/riscv/boot/loader.lds.S=20
>>>> b/arch/riscv/boot/loader.lds.S
>>>> index 47a5003c2e28..62d94696a19c 100644
>>>> --- a/arch/riscv/boot/loader.lds.S
>>>> +++ b/arch/riscv/boot/loader.lds.S
>>>> @@ -1,13 +1,14 @@
>>>> =C2=A0/* SPDX-License-Identifier: GPL-2.0 */
>>>>
>>>> =C2=A0#include <asm/page.h>
>>>> +#include <asm/pgtable.h>
>>>>
>>>> =C2=A0OUTPUT_ARCH(riscv)
>>>> =C2=A0ENTRY(_start)
>>>>
>>>> =C2=A0SECTIONS
>>>> =C2=A0{
>>>> -=C2=A0=C2=A0=C2=A0 . =3D PAGE_OFFSET;
>>>> +=C2=A0=C2=A0=C2=A0 . =3D KERNEL_LINK_ADDR;
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 .payload : {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *(.payload)
>>>> diff --git a/arch/riscv/include/asm/page.h=20
>>>> b/arch/riscv/include/asm/page.h
>>>> index adc9d26f3d75..22cfb2be60dc 100644
>>>> --- a/arch/riscv/include/asm/page.h
>>>> +++ b/arch/riscv/include/asm/page.h
>>>> @@ -90,15 +90,28 @@ typedef struct page *pgtable_t;
>>>>
>>>> =C2=A0#ifdef CONFIG_MMU
>>>> =C2=A0extern unsigned long va_pa_offset;
>>>> +extern unsigned long va_kernel_pa_offset;
>>>> =C2=A0extern unsigned long pfn_base;
>>>> =C2=A0#define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0(pfn_base)
>>>> =C2=A0#else
>>>> =C2=A0#define va_pa_offset=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0
>>>> +#define va_kernel_pa_offset=C2=A0=C2=A0=C2=A0 0
>>>> =C2=A0#define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0(PAGE_OFFSET >> PAGE_SHIFT)
>>>> =C2=A0#endif /* CONFIG_MMU */
>>>>
>>>> -#define __pa_to_va_nodebug(x)=C2=A0=C2=A0=C2=A0 ((void *)((unsigned l=
ong) (x) +=20
>>>> va_pa_offset))
>>>> -#define __va_to_pa_nodebug(x)=C2=A0=C2=A0=C2=A0 ((unsigned long)(x) -=
 va_pa_offset)
>>>> +extern unsigned long kernel_virt_addr;
>>>> +
>>>> +#define linear_mapping_pa_to_va(x)=C2=A0=C2=A0=C2=A0 ((void *)((unsig=
ned long)(x)=20
>>>> + va_pa_offset))
>>>> +#define kernel_mapping_pa_to_va(x)=C2=A0=C2=A0=C2=A0 ((void *)((unsig=
ned long)(x)=20
>>>> + va_kernel_pa_offset))
>>>> +#define __pa_to_va_nodebug(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 linear_mapping_pa_to_va(x)
>>>> +
>>>> +#define linear_mapping_va_to_pa(x)=C2=A0=C2=A0=C2=A0 ((unsigned long)=
(x) -=20
>>>> va_pa_offset)
>>>> +#define kernel_mapping_va_to_pa(x)=C2=A0=C2=A0=C2=A0 ((unsigned long)=
(x) -=20
>>>> va_kernel_pa_offset)
>>>> +#define __va_to_pa_nodebug(x)=C2=A0=C2=A0=C2=A0 ({=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long _x =3D x;=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>> +=C2=A0=C2=A0=C2=A0 (_x < kernel_virt_addr) ?=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 linear_mapping_va_to_pa(_x=
) :=20
>>>> kernel_mapping_va_to_pa(_x);=C2=A0=C2=A0=C2=A0 \
>>>> +=C2=A0=C2=A0=C2=A0 })
>>>>
>>>> =C2=A0#ifdef CONFIG_DEBUG_VIRTUAL
>>>> =C2=A0extern phys_addr_t __virt_to_phys(unsigned long x);
>>>> diff --git a/arch/riscv/include/asm/pgtable.h=20
>>>> b/arch/riscv/include/asm/pgtable.h
>>>> index ebf817c1bdf4..80e63a93e903 100644
>>>> --- a/arch/riscv/include/asm/pgtable.h
>>>> +++ b/arch/riscv/include/asm/pgtable.h
>>>> @@ -11,23 +11,30 @@
>>>>
>>>> =C2=A0#include <asm/pgtable-bits.h>
>>>>
>>>> -#ifndef __ASSEMBLY__
>>>> -
>>>> -/* Page Upper Directory not used in RISC-V */
>>>> -#include <asm-generic/pgtable-nopud.h>
>>>> -#include <asm/page.h>
>>>> -#include <asm/tlbflush.h>
>>>> -#include <linux/mm_types.h>
>>>> +#ifndef CONFIG_MMU
>>>> +#define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0 PAGE_OFFSET
>>>> +#else
>>>>
>>>> -#ifdef CONFIG_MMU
>>>> +#define ADDRESS_SPACE_END=C2=A0=C2=A0=C2=A0 (UL(-1))
>>>> +/*
>>>> + * Leave 2GB for kernel and BPF at the end of the address space
>>>> + */
>>>> +#define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0 (ADDRESS_SPACE_END - SZ_2G=
 + 1)
>>>>
>>>> =C2=A0#define VMALLOC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0 (KERN_VIRT_SIZE >>1=
)
>>>> =C2=A0#define VMALLOC_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET -=
 1)
>>>> =C2=A0#define VMALLOC_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - VMALLOC_S=
IZE)
>>>>
>>>> +/* KASLR should leave at least 128MB for BPF after the kernel */
>>>> =C2=A0#define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>>>> -#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - BPF_JIT=
_REGION_SIZE)
>>>> -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
>>>> +#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 PFN_ALIGN((unsigned lo=
ng)&_end)
>>>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_START +=
=20
>>>> BPF_JIT_REGION_SIZE)
>>>> +
>>>> +/* Modules always live before the kernel */
>>>> +#ifdef CONFIG_64BIT
>>>> +#define MODULES_VADDR=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)&_e=
nd) - SZ_2G)
>>>> +#define MODULES_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)&_sta=
rt))
>>>> +#endif
>>>>
>>>> =C2=A0/*
>>>> =C2=A0 * Roughly size the vmemmap space to be large enough to fit enou=
gh
>>>> @@ -57,9 +64,16 @@
>>>> =C2=A0#define FIXADDR_SIZE=C2=A0=C2=A0=C2=A0=C2=A0 PGDIR_SIZE
>>>> =C2=A0#endif
>>>> =C2=A0#define FIXADDR_START=C2=A0=C2=A0=C2=A0 (FIXADDR_TOP - FIXADDR_S=
IZE)
>>>> -
>>>> =C2=A0#endif
>>>>
>>>> +#ifndef __ASSEMBLY__
>>>> +
>>>> +/* Page Upper Directory not used in RISC-V */
>>>> +#include <asm-generic/pgtable-nopud.h>
>>>> +#include <asm/page.h>
>>>> +#include <asm/tlbflush.h>
>>>> +#include <linux/mm_types.h>
>>>> +
>>>> =C2=A0#ifdef CONFIG_64BIT
>>>> =C2=A0#include <asm/pgtable-64.h>
>>>> =C2=A0#else
>>>> @@ -484,6 +498,7 @@ static inline int ptep_clear_flush_young(struct=20
>>>> vm_area_struct *vma,
>>>>
>>>> =C2=A0#define kern_addr_valid(addr)=C2=A0=C2=A0 (1) /* FIXME */
>>>>
>>>> +extern char _start[];
>>>> =C2=A0extern void *dtb_early_va;
>>>> =C2=A0extern uintptr_t dtb_early_pa;
>>>> =C2=A0void setup_bootmem(void);
>>>> diff --git a/arch/riscv/include/asm/set_memory.h=20
>>>> b/arch/riscv/include/asm/set_memory.h
>>>> index 6887b3d9f371..a9c56776fa0e 100644
>>>> --- a/arch/riscv/include/asm/set_memory.h
>>>> +++ b/arch/riscv/include/asm/set_memory.h
>>>> @@ -17,6 +17,7 @@ int set_memory_x(unsigned long addr, int numpages);
>>>> =C2=A0int set_memory_nx(unsigned long addr, int numpages);
>>>> =C2=A0int set_memory_rw_nx(unsigned long addr, int numpages);
>>>> =C2=A0void protect_kernel_text_data(void);
>>>> +void protect_kernel_linear_mapping_text_rodata(void);
>>>> =C2=A0#else
>>>> =C2=A0static inline int set_memory_ro(unsigned long addr, int numpages=
) {=20
>>>> return 0; }
>>>> =C2=A0static inline int set_memory_rw(unsigned long addr, int numpages=
) {=20
>>>> return 0; }
>>>> diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
>>>> index f5a9bad86e58..6cb05f22e52a 100644
>>>> --- a/arch/riscv/kernel/head.S
>>>> +++ b/arch/riscv/kernel/head.S
>>>> @@ -69,7 +69,8 @@ pe_head_start:
>>>> =C2=A0#ifdef CONFIG_MMU
>>>> =C2=A0relocate:
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Relocate return address */
>>>> -=C2=A0=C2=A0=C2=A0 li a1, PAGE_OFFSET
>>>> +=C2=A0=C2=A0=C2=A0 la a1, kernel_virt_addr
>>>> +=C2=A0=C2=A0=C2=A0 REG_L a1, 0(a1)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 la a2, _start
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 sub a1, a1, a2
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 add ra, ra, a1
>>>> diff --git a/arch/riscv/kernel/module.c b/arch/riscv/kernel/module.c
>>>> index 104fba889cf7..ce153771e5e9 100644
>>>> --- a/arch/riscv/kernel/module.c
>>>> +++ b/arch/riscv/kernel/module.c
>>>> @@ -408,12 +408,10 @@ int apply_relocate_add(Elf_Shdr *sechdrs,=20
>>>> const char *strtab,
>>>> =C2=A0}
>>>>
>>>> =C2=A0#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
>>>> -#define VMALLOC_MODULE_START \
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0 max(PFN_ALIGN((unsigned long)&_end - SZ_2G),=
 VMALLOC_START)
>>>> =C2=A0void *module_alloc(unsigned long size)
>>>> =C2=A0{
>>>> -=C2=A0=C2=A0=C2=A0 return __vmalloc_node_range(size, 1, VMALLOC_MODUL=
E_START,
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMALLOC_END, GFP_KERNEL,
>>>> +=C2=A0=C2=A0=C2=A0 return __vmalloc_node_range(size, 1, MODULES_VADDR=
,
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MODULES_END, GFP_KERNEL,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL_EXEC, 0, NU=
MA_NO_NODE,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __builtin_return_addres=
s(0));
>>>> =C2=A0}
>>>> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
>>>> index e85bacff1b50..30e4af0fd50c 100644
>>>> --- a/arch/riscv/kernel/setup.c
>>>> +++ b/arch/riscv/kernel/setup.c
>>>> @@ -265,6 +265,11 @@ void __init setup_arch(char **cmdline_p)
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 protect_kernel_text_d=
ata();
>>>> +
>>>> +#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
>>>> +=C2=A0=C2=A0=C2=A0 protect_kernel_linear_mapping_text_rodata();
>>>> +#endif
>>>> +
>>>> =C2=A0#ifdef CONFIG_SWIOTLB
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 swiotlb_init(1);
>>>> =C2=A0#endif
>>>> diff --git a/arch/riscv/kernel/vmlinux.lds.S=20
>>>> b/arch/riscv/kernel/vmlinux.lds.S
>>>> index de03cb22d0e9..0726c05e0336 100644
>>>> --- a/arch/riscv/kernel/vmlinux.lds.S
>>>> +++ b/arch/riscv/kernel/vmlinux.lds.S
>>>> @@ -4,7 +4,8 @@
>>>> =C2=A0 * Copyright (C) 2017 SiFive
>>>> =C2=A0 */
>>>>
>>>> -#define LOAD_OFFSET PAGE_OFFSET
>>>> +#include <asm/pgtable.h>
>>>> +#define LOAD_OFFSET KERNEL_LINK_ADDR
>>>> =C2=A0#include <asm/vmlinux.lds.h>
>>>> =C2=A0#include <asm/page.h>
>>>> =C2=A0#include <asm/cache.h>
>>>> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
>>>> index 8f17519208c7..1b14d523a95c 100644
>>>> --- a/arch/riscv/mm/fault.c
>>>> +++ b/arch/riscv/mm/fault.c
>>>> @@ -231,6 +231,19 @@ asmlinkage void do_page_fault(struct pt_regs=20
>>>> *regs)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>
>>>> +#ifdef CONFIG_64BIT
>>>> +=C2=A0=C2=A0=C2=A0 /*
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Modules in 64bit kernels lie in their ownv=
irtual region=20
>>>> which is not
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * in the vmalloc region, but dealing with pa=
ge faults in this=20
>>>> region
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * or the vmalloc region amounts to doing the=
 same thing:=20
>>>> checking that
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * the mapping exists in init_mm.pgd and upda=
ting user page=20
>>>> table, so
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * just use vmalloc_fault.
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> +=C2=A0=C2=A0=C2=A0 if (unlikely(addr >=3D MODULES_VADDR && addr < MOD=
ULES_END)) {
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vmalloc_fault(regs, code,a=
ddr);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>>>> +=C2=A0=C2=A0=C2=A0 }
>>>> +#endif
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Enable interrupts if they were enabled int=
he parent context. */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 if (likely(regs->status & SR_PIE))
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_irq_enable();
>>>> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
>>>> index 7f5036fbee8c..093f3a96ecfc 100644
>>>> --- a/arch/riscv/mm/init.c
>>>> +++ b/arch/riscv/mm/init.c
>>>> @@ -25,6 +25,9 @@
>>>>
>>>> =C2=A0#include "../kernel/head.h"
>>>>
>>>> +unsigned long kernel_virt_addr =3D KERNEL_LINK_ADDR;
>>>> +EXPORT_SYMBOL(kernel_virt_addr);
>>>> +
>>>> =C2=A0unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 __page_aligned_bss;
>>>> =C2=A0EXPORT_SYMBOL(empty_zero_page);
>>>> @@ -88,6 +91,8 @@ static void print_vm_layout(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned=
 long)VMALLOC_END);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 print_mlm("lowmem", (unsigned long)PAGE_OFFSE=
T,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned=
 long)high_memory);
>>>> +=C2=A0=C2=A0=C2=A0 print_mlm("kernel", (unsigned long)KERNEL_LINK_ADD=
R,
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long=
)ADDRESS_SPACE_END);
>>>> =C2=A0}
>>>> =C2=A0#else
>>>> =C2=A0static void print_vm_layout(void) { }
>>>> @@ -116,8 +121,13 @@ void __init setup_bootmem(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* The maximal physical memory size is -PAGE_=
OFFSET. */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 memblock_enforce_memory_limit(-PAGE_OFFSET);
>>>>
>>>> -=C2=A0=C2=A0=C2=A0 /* Reserve from the start of the kernel to the end=
 of the=20
>>>> kernel */
>>>> -=C2=A0=C2=A0=C2=A0 memblock_reserve(vmlinux_start, vmlinux_end - vmli=
nux_start);
>>>> +=C2=A0=C2=A0=C2=A0 /*
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Reserve from the start of the kernel to th=
e end of the kernel
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * and make sure we align the reservation onP=
MD_SIZE since we will
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * map the kernel in the linear mapping as re=
ad-only: we do not=20
>>>> want
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * any allocation to happen between _end andt=
he next pmd=20
>>>> aligned page.
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> +=C2=A0=C2=A0=C2=A0 memblock_reserve(vmlinux_start, (vmlinux_end - vml=
inux_start +=20
>>>> PMD_SIZE - 1) & PMD_MASK);
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * memblock allocator is not aware of th=
e fact that last 4K=20
>>>> bytes of
>>>> @@ -152,8 +162,12 @@ void __init setup_bootmem(void)
>>>> =C2=A0#ifdef CONFIG_MMU
>>>> =C2=A0static struct pt_alloc_ops pt_ops;
>>>>
>>>> +/* Offset between linear mapping virtual address and kernel load=20
>>>> address */
>>>> =C2=A0unsigned long va_pa_offset;
>>>> =C2=A0EXPORT_SYMBOL(va_pa_offset);
>>>> +/* Offset between kernel mapping virtual address and kernel load=20
>>>> address */
>>>> +unsigned long va_kernel_pa_offset;
>>>> +EXPORT_SYMBOL(va_kernel_pa_offset);
>>>> =C2=A0unsigned long pfn_base;
>>>> =C2=A0EXPORT_SYMBOL(pfn_base);
>>>>
>>>> @@ -257,7 +271,7 @@ static pmd_t *get_pmd_virt_late(phys_addr_t pa)
>>>>
>>>> =C2=A0static phys_addr_t __init alloc_pmd_early(uintptr_t va)
>>>> =C2=A0{
>>>> -=C2=A0=C2=A0=C2=A0 BUG_ON((va - PAGE_OFFSET) >> PGDIR_SHIFT);
>>>> +=C2=A0=C2=A0=C2=A0 BUG_ON((va - kernel_virt_addr) >> PGDIR_SHIFT);
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 return (uintptr_t)early_pmd;
>>>> =C2=A0}
>>>> @@ -372,17 +386,32 @@ static uintptr_t __init=20
>>>> best_map_size(phys_addr_t base, phys_addr_t size)
>>>> =C2=A0#error "setup_vm() is called from head.S before relocate so it=
=20
>>>> should not use absolute addressing."
>>>> =C2=A0#endif
>>>>
>>>> +uintptr_t load_pa, load_sz;
>>>> +
>>>> +static void __init create_kernel_page_table(pgd_t *pgdir, uintptr_t=
=20
>>>> map_size)
>>>> +{
>>>> +=C2=A0=C2=A0=C2=A0 uintptr_t va, end_va;
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 end_va =3D kernel_virt_addr + load_sz;
>>>> +=C2=A0=C2=A0=C2=A0 for (va =3D kernel_virt_addr; va < end_va; va +=3D=
map_size)
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(pgdir,v=
a,
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 load_pa + (va - kernel_virt_addr),
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, PAGE_KERNEL_EXEC);
>>>> +}
>>>> +
>>>> =C2=A0asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>> =C2=A0{
>>>> -=C2=A0=C2=A0=C2=A0 uintptr_t va, pa, end_va;
>>>> -=C2=A0=C2=A0=C2=A0 uintptr_t load_pa =3D (uintptr_t)(&_start);
>>>> -=C2=A0=C2=A0=C2=A0 uintptr_t load_sz =3D (uintptr_t)(&_end) - load_pa=
;
>>>> +=C2=A0=C2=A0=C2=A0 uintptr_t pa;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t map_size;
>>>> =C2=A0#ifndef __PAGETABLE_PMD_FOLDED
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 pmd_t fix_bmap_spmd, fix_bmap_epmd;
>>>> =C2=A0#endif
>>>> +=C2=A0=C2=A0=C2=A0 load_pa =3D (uintptr_t)(&_start);
>>>> +=C2=A0=C2=A0=C2=A0 load_sz =3D (uintptr_t)(&_end) - load_pa;
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 va_pa_offset =3D PAGE_OFFSET - load_pa;
>>>> +=C2=A0=C2=A0=C2=A0 va_kernel_pa_offset =3D kernel_virt_addr - load_pa=
;
>>>> +
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 pfn_base =3D PFN_DOWN(load_pa);
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>> @@ -410,26 +439,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa=
)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 create_pmd_mapping(fixmap_pmd, FIXADDR_START,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Setup trampoline PGD and PMD */
>>>> -=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
>>>> +=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, kernel_virt_=
addr,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE);
>>>> -=C2=A0=C2=A0=C2=A0 create_pmd_mapping(trampoline_pmd, PAGE_OFFSET,
>>>> +=C2=A0=C2=A0=C2=A0 create_pmd_mapping(trampoline_pmd, kernel_virt_add=
r,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 load_pa, PMD_SIZE, PAGE_KERNEL_EXEC);
>>>> =C2=A0#else
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Setup trampoline PGD */
>>>> -=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
>>>> +=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_dir, kernel_virt_=
addr,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 load_pa, PGDIR_SIZE, PAGE_KERNEL_EXEC);
>>>> =C2=A0#endif
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0 * Setup early PGD covering entire kernel whi=
ch will allows
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Setup early PGD covering entire kernel whi=
ch will allow
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * us to reach paging_init(). We map all=
 memory banks later
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * in setup_vm_final() below.
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> -=C2=A0=C2=A0=C2=A0 end_va =3D PAGE_OFFSET + load_sz;
>>>> -=C2=A0=C2=A0=C2=A0 for (va =3D PAGE_OFFSET; va < end_va; va +=3D map_=
size)
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(early_p=
g_dir, va,
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 load_pa + (va - PAGE_OFFSET),
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, PAGE_KERNEL_EXEC);
>>>> +=C2=A0=C2=A0=C2=A0 create_kernel_page_table(early_pg_dir, map_size);
>>>>
>>>> =C2=A0#ifndef __PAGETABLE_PMD_FOLDED
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Setup early PMD for DTB */
>>>> @@ -444,7 +469,12 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (void *)DTB_EARLY_BASE_VA +(=
dtb_pa & (PMD_SIZE -=20
>>>> 1));
>>>> =C2=A0#else /* CONFIG_BUILTIN_DTB */
>>>> -=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>>>> +=C2=A0=C2=A0=C2=A0 /*
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * __va can't be used since it would return a=
 linear mapping=20
>>>> address
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * whereas dtb_early_va will be used before s=
etup_vm_final=20
>>>> installs
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * the linear mapping.
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> +=C2=A0=C2=A0=C2=A0 dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>>>> =C2=A0#endif /* CONFIG_BUILTIN_DTB */
>>>> =C2=A0#else
>>>> =C2=A0#ifndef CONFIG_BUILTIN_DTB
>>>> @@ -456,7 +486,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (void *)DTB_EARLY_BASE_VA +(=
dtb_pa & (PGDIR_SIZE=20
>>>> - 1));
>>>> =C2=A0#else /* CONFIG_BUILTIN_DTB */
>>>> -=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>>>> +=C2=A0=C2=A0=C2=A0 dtb_early_va =3D kernel_mapping_pa_to_va(dtb_pa);
>>>> =C2=A0#endif /* CONFIG_BUILTIN_DTB */
>>>> =C2=A0#endif
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_pa =3D dtb_pa;
>>>> @@ -492,6 +522,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>> =C2=A0#endif
>>>> =C2=A0}
>>>>
>>>> +#ifdef CONFIG_64BIT
>>>> +void protect_kernel_linear_mapping_text_rodata(void)
>>>> +{
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long text_start =3D (unsigned long)lm_ali=
as(_start);
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long init_text_start =3D (unsigned=20
>>>> long)lm_alias(__init_text_begin);
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long rodata_start =3D (unsigned=20
>>>> long)lm_alias(__start_rodata);
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long data_start =3D (unsigned long)lm_ali=
as(_data);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 set_memory_ro(text_start, (init_text_start - text_=
start) >>=20
>>>> PAGE_SHIFT);
>>>> +=C2=A0=C2=A0=C2=A0 set_memory_nx(text_start, (init_text_start - text_=
start) >>=20
>>>> PAGE_SHIFT);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 set_memory_ro(rodata_start, (data_start - rodata_s=
tart) >>=20
>>>> PAGE_SHIFT);
>>>> +=C2=A0=C2=A0=C2=A0 set_memory_nx(rodata_start, (data_start - rodata_s=
tart) >>=20
>>>> PAGE_SHIFT);
>>>> +}
>>>> +#endif
>>>> +
>>>> =C2=A0static void __init setup_vm_final(void)
>>>> =C2=A0{
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t va, map_size;
>>>> @@ -513,7 +559,7 @@ static void __init setup_vm_final(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __pa_symbol(fixmap_pgd_next),
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 PGDIR_SIZE, PAGE_TABLE);
>>>>
>>>> -=C2=A0=C2=A0=C2=A0 /* Map all memory banks */
>>>> +=C2=A0=C2=A0=C2=A0 /* Map all memory banks in the linear mapping */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &start, &end) {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D end)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 break;
>>>> @@ -525,10 +571,13 @@ static void __init setup_vm_final(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (pa =3D start; pa=
 < end; pa +=3D map_size) {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 va =3D (uintptr_t)__va(pa);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 create_pgd_mapping(swapper_pg_dir, va, pa,
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size,PA=
GE_KERNEL_EXEC);
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size,PA=
GE_KERNEL);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>
>>>> +=C2=A0=C2=A0=C2=A0 /* Map the kernel */
>>>> +=C2=A0=C2=A0=C2=A0 create_kernel_page_table(swapper_pg_dir, PMD_SIZE)=
;
>>>> +
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /* Clear fixmap PTE and PMD mappings */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PTE);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PMD);
>>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>>> index 2c39f0386673..28f4d52cf17e 100644
>>>> --- a/arch/riscv/mm/kasan_init.c
>>>> +++ b/arch/riscv/mm/kasan_init.c
>>>> @@ -171,6 +171,10 @@ void __init kasan_init(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 u64 i;
>>>>
>>>> +=C2=A0=C2=A0=C2=A0 /*
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Populate all kernel virtual address spacew=
ith=20
>>>> kasan_early_shadow_page
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * except for the linear mapping and the modu=
les/kernel/BPF=20
>>>> mapping.
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow((void *)KASAN_SHA=
DOW_START,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_mem_to_sh=
adow((void *)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMEMMAP_END));
>>>> @@ -183,6 +187,7 @@ void __init kasan_init(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (void *)kasan_mem_to_shadow((void *)VMALLOC_START),
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>>>
>>>> +=C2=A0=C2=A0=C2=A0 /* Populate the linear mapping */
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start, &_end) {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void=
 *)__va(_start);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *end =3D (void *=
)__va(_end);
>>>> @@ -193,6 +198,10 @@ void __init kasan_init(void)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_=
mem_to_shadow(start),=20
>>>> kasan_mem_to_shadow(end));
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 };
>>>>
>>>> +=C2=A0=C2=A0=C2=A0 /* Populate kernel, BPF, modules mapping */
>>>> +=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_mem_to_shadow((const void *)M=
ODULES_VADDR),
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kasan_mem_to_shadow((const void *)BPF_JIT_REGION_END));
>>>> +
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < PTRS_PER_PTE; i++)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(&kasan_early_=
shadow_pte[i],
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 mk_pte(virt_to_page(kasan_early_shadow_page),
>>>> diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
>>>> index e8e4dcd39fed..35703d5ef5fd 100644
>>>> --- a/arch/riscv/mm/physaddr.c
>>>> +++ b/arch/riscv/mm/physaddr.c
>>>> @@ -23,7 +23,7 @@ EXPORT_SYMBOL(__virt_to_phys);
>>>>
>>>> =C2=A0phys_addr_t __phys_addr_symbol(unsigned long x)
>>>> =C2=A0{
>>>> -=C2=A0=C2=A0=C2=A0 unsigned long kernel_start =3D (unsigned long)PAGE=
_OFFSET;
>>>> +=C2=A0=C2=A0=C2=A0 unsigned long kernel_start =3D (unsigned long)kern=
el_virt_addr;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long kernel_end =3D (unsigned long)_=
end;
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>
>>> This is breaking boot for me with CONFIG_STRICT_KERNEL_RWX=3Dn.=C2=A0 I=
'm=20
>>> not even really convinced that's a useful config to support, but it's=
=20
>>> currently optional and I'd prefer to avoid breaking it if possible.
>>>
>>> I can't quite figure out what's going on here and I'm pretty much=20
>>> tired out for tonight.=C2=A0 LMK if you don't have time to look at it a=
nd=20
>>> I'll try to give it another shot.
>>
>> I'm taking a look at that.
>=20
> Just to make sure you don't miss it, I fixed this issue in=20
> https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.223=
8-1-alex@ghiti.fr/

Guenter reported that this patchset broke 32b kernel build: I had=20
neglected it. So I pushed 2 other fixes for this where I added Fixes tag=20
and that can be squashed in case you want to squash them.

To sum up, there are 3 patches that fix this series:

https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-=
1-alex@ghiti.fr/

https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085=
-1-alex@ghiti.fr/

https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078=
-1-alex@ghiti.fr/

Sorry for that,

Thanks,

Alex

>=20
>=20
> Thanks,
>=20
> Alex
>=20
>>
>> Thanks,
>>
>> Alex
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7b647da1-b3aa-287f-7ca8-3b44c5661cb8%40ghiti.fr.
