Return-Path: <kasan-dev+bncBCXLBLOA7IGBBT4W5XXQKGQE2ED3CVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B812125E76
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 11:05:04 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id w205sf1176441wmb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 02:05:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576749904; cv=pass;
        d=google.com; s=arc-20160816;
        b=QTT8y8ss7qJNSHeGm2mUqgVgkhS+oQhxBSis5DYVTfYlX4hUWsNuxgWmuzBgTmM3aR
         A2tGHECk5ngKffPH79ai9/cVWFXZNOOFxSdPJrWuuXmy8bdlprrJn5gQopTT4xGZdYpE
         yfxvAnebsKaN3l2YQw5RawP9wfzHFL0cfh0/udPZICzqIDKtaTqDlq6yWA/k9jGtqkmW
         /XHylGryaCLNWzqfjpPuth2HBksarCNM+zCTnpHaa5438PIEYwhBMr9iOXRWjDNsPZwW
         ooPtHMqVPsspep1GvM4wqFQyHzLBQbRICfZrn3m00hRDuNMRp0XOYbyOaMTed7wQZFHA
         3kKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=/Nd2rcevq1hm2ahxilROTgTVbeEg0RNftECpeWXHDqw=;
        b=MSfbf+YJXVGwcWkA0TaQvHoDsG+hw3LV/OoA5R085b81sJbvcl0WfJnzuSrRqJk8ig
         Wc4dQNycjGNCzvewbuy/Lfkszzmhj/pdcz6fH5G1lYHyp/H6wat+6ZSBjcaAL38VgL+6
         woe2lyIw2oluovJX79N12uvhUkq+Pdrglo5YiFVcKE3v6YYA0M//JhkOgH6RhvXpfrvQ
         GifOsYfijbUscdDGNYIJrwEUbrDjRwMN3GG9rYoHRv1vHGw3J4jRXNquyc4whXauEa4t
         kyRiqFcQ+8+kOQ9EcVyi55NGONyhuCXE3BUjjngUJ6xlHL/rKMIX5h6t/4hlnphB7wEg
         ERrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=VRJrSe1w;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/Nd2rcevq1hm2ahxilROTgTVbeEg0RNftECpeWXHDqw=;
        b=LAqtT1NQsrF+ihYAjxme/E8UKF/mgT9FqpqnEZgPqvOEVnl1gH3zNJ0UTi/o0eDEjC
         NjKWNDR00tdsjYPHbYs4nPnN70aELmzJb9UjlP5kgV1caiI3mxCiJnD9Td8MwbIH10lw
         f2IW1x3Zz5iYSumcpJa2zZjOMDvQMQHtBM7C4BY/kBknHoSyAeqH3JxF2RSMU7Q0QoHY
         hXVVk0GborUTCOhkZSxDa+EpNPHUbY1SdqWZUbJungNkWEZYTZuoH0DrXKvrfAd4hRJy
         sCExpEgWxVKuEDAgjKFzX+6w595VoM/OCB0mTsrEcY6zyhiLGCkNp1u/6sh0ZyA/jjWk
         ly6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/Nd2rcevq1hm2ahxilROTgTVbeEg0RNftECpeWXHDqw=;
        b=SvUyjmNZyqavBmAjKkABOT9JDVIdU8WJ9+uECYCVSBb2FG6U7ySlWHbjVNAB9/yf1b
         WdY4qKAQMCDVDtg0YMPzNa19rDfibWm56h8/aQ5diFHDklOptrOFxIeqWHclILfrXVZo
         w41WW0aVq/p8ubkEd2YdIVGgIRA4W2SQKtRWCuqaNiUdbvL1mLgk3njGi+AP5LGgvf46
         3vUlLbGuR+hnng+dLy78LAJNe5Dt+vkj85xI1G668pG3bmEE/zQGcRIMz++jIzo0NdBt
         e3ACxTsaHig4b9dblCvPb1cAjBxUFn5JUp9ec7B59mO2ECfnHQCE9tAkv83lIanjIRNF
         umyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUso5O48WBA2oPQSF+wAo781eCc0dWesryQKOm+v6FAB8wFI6Kr
	AmxLPe3T/DRQOINgn5ISuV0=
X-Google-Smtp-Source: APXvYqxVaj8jk4ewsIpZ/yASYZghtyslqwXHggu9MryrwhrhPUovBG98h7uZQ+qpi73yr62GGsZ7Ow==
X-Received: by 2002:a1c:4b09:: with SMTP id y9mr9314704wma.103.1576749903195;
        Thu, 19 Dec 2019 02:05:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7409:: with SMTP id p9ls1617093wmc.4.gmail; Thu, 19 Dec
 2019 02:05:02 -0800 (PST)
X-Received: by 2002:a05:600c:d5:: with SMTP id u21mr8748813wmm.85.1576749902670;
        Thu, 19 Dec 2019 02:05:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576749902; cv=none;
        d=google.com; s=arc-20160816;
        b=zSBKdIfYILxJC4VDOAyEAtF4D7jioOYoo7u/RpEHx6tosdam02q5eO/i+DZ3zmA7ZA
         Q/mbQLk0mAYPYDxl6MrD28OBFlmAQKjMJ1Bo+AwnGkGZP5lIQO4nUesk1KxBMovqdN8u
         tIm1/WJJaedsjwNnGJosGNIste9qIr5PPiITjvtkIOnYS8mWwJBZNv15dHD1rnY+5Wfo
         yzyLbx1rcNHhrJxaeaOPkV/cKpIR01++dOrNfbtNuQkWOnFKZ0yisSjf1MHpPZOhaPA0
         fqzUPR3jMJtFHIcsAEZWReKa0VuRVlXTrvd+uxcNHPHZP/1kCJ7Z+RhRveT4YOA2+5ih
         l8LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=aBMNlZSdHN9hHSwCigq8pLHNrlooKzHKv50c74v52kk=;
        b=Hk499/i2ewGHKK1GvYkRMV6CGPfMjHLjwJQzf3RB8+j8SYyddeld9+Yh1D5CzAgWqP
         XeNMKoNdI0ITPf1EI8WpQY4L9LE4+eBqVL1MMpEHoQfuyOXBb66C6BLM3oY6iV0lf6c3
         q/++CjuVaslh9XxFwHq9ft//OW0cpEYYlJYiexS0AqJtYI/ZdneD2DGqxH0RWHSkX74o
         jG1OVjnHM+mWUmaTQea2xpz5ETY5uXH6jUPKOmJIR3SxkmZUWEP9E+t8SeFPoJh/J5BA
         0h/nmkgsR9M8FqdWQ6GxJ1J5YBnUqVM907YOwjuxXVVIo0KYxEfv8JLBH8+kHHR3DBJz
         JtUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=VRJrSe1w;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id g3si204005wrw.5.2019.12.19.02.05.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Dec 2019 02:05:02 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47dnYT0l6Gz9txdb;
	Thu, 19 Dec 2019 11:05:01 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id LbMxqmJHojDe; Thu, 19 Dec 2019 11:05:01 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47dnYS6cvbz9txdX;
	Thu, 19 Dec 2019 11:05:00 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E72858B7AC;
	Thu, 19 Dec 2019 11:05:01 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 3wWYzfMEiS00; Thu, 19 Dec 2019 11:05:01 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 33E8C8B787;
	Thu, 19 Dec 2019 11:05:01 +0100 (CET)
Subject: Re: [PATCH v4 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
References: <20191219003630.31288-1-dja@axtens.net>
 <20191219003630.31288-5-dja@axtens.net>
 <c4d37067-829f-cd7d-7e94-0ec2223cce71@c-s.fr>
 <87bls4tzjn.fsf@dja-thinkpad.axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <4f2fffb3-5fb6-b5ea-a951-a7910f2439b8@c-s.fr>
Date: Thu, 19 Dec 2019 11:05:00 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <87bls4tzjn.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=VRJrSe1w;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 19/12/2019 =C3=A0 10:50, Daniel Axtens a =C3=A9crit=C2=A0:
> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>=20
>> On 12/19/2019 12:36 AM, Daniel Axtens wrote:
>>> KASAN support on Book3S is a bit tricky to get right:
>>>
>>>    - It would be good to support inline instrumentation so as to be abl=
e to
>>>      catch stack issues that cannot be caught with outline mode.
>>>
>>>    - Inline instrumentation requires a fixed offset.
>>>
>>>    - Book3S runs code in real mode after booting. Most notably a lot of=
 KVM
>>>      runs in real mode, and it would be good to be able to instrument i=
t.
>>>
>>>    - Because code runs in real mode after boot, the offset has to point=
 to
>>>      valid memory both in and out of real mode.
>>>
>>>       [ppc64 mm note: The kernel installs a linear mapping at effective
>>>       address c000... onward. This is a one-to-one mapping with physica=
l
>>>       memory from 0000... onward. Because of how memory accesses work o=
n
>>>       powerpc 64-bit Book3S, a kernel pointer in the linear map accesse=
s the
>>>       same memory both with translations on (accessing as an 'effective
>>>       address'), and with translations off (accessing as a 'real
>>>       address'). This works in both guests and the hypervisor. For more
>>>       details, see s5.7 of Book III of version 3 of the ISA, in particu=
lar
>>>       the Storage Control Overview, s5.7.3, and s5.7.5 - noting that th=
is
>>>       KASAN implementation currently only supports Radix.]
>>>
>>> One approach is just to give up on inline instrumentation. This way all
>>> checks can be delayed until after everything set is up correctly, and t=
he
>>> address-to-shadow calculations can be overridden. However, the features=
 and
>>> speed boost provided by inline instrumentation are worth trying to do
>>> better.
>>>
>>> If _at compile time_ it is known how much contiguous physical memory a
>>> system has, the top 1/8th of the first block of physical memory can be =
set
>>> aside for the shadow. This is a big hammer and comes with 3 big
>>> consequences:
>>>
>>>    - there's no nice way to handle physically discontiguous memory, so =
only
>>>      the first physical memory block can be used.
>>>
>>>    - kernels will simply fail to boot on machines with less memory than
>>>      specified when compiling.
>>>
>>>    - kernels running on machines with more memory than specified when
>>>      compiling will simply ignore the extra memory.
>>>
>>> Implement and document KASAN this way. The current implementation is Ra=
dix
>>> only.
>>>
>>> Despite the limitations, it can still find bugs,
>>> e.g. http://patchwork.ozlabs.org/patch/1103775/
>>>
>>> At the moment, this physical memory limit must be set _even for outline
>>> mode_. This may be changed in a later series - a different implementati=
on
>>> could be added for outline mode that dynamically allocates shadow at a
>>> fixed offset. For example, see https://patchwork.ozlabs.org/patch/79521=
1/
>>>
>>> Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
>>> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix vers=
ion
>>> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
>>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>>
>>> ---
>>> Changes since v3:
>>>    - Address further feedback from Christophe.
>>>    - Drop changes to stack walking, it looks like the issue I observed =
is
>>>      related to that particular stack, not stack-walking generally.
>>>
>>> Changes since v2:
>>>
>>>    - Address feedback from Christophe around cleanups and docs.
>>>    - Address feedback from Balbir: at this point I don't have a good so=
lution
>>>      for the issues you identify around the limitations of the inline i=
mplementation
>>>      but I think that it's worth trying to get the stack instrumentatio=
n support.
>>>      I'm happy to have an alternative and more flexible outline mode - =
I had
>>>      envisoned this would be called 'lightweight' mode as it imposes fe=
wer restrictions.
>>>      I've linked to your implementation. I think it's best to add it in=
 a follow-up series.
>>>    - Made the default PHYS_MEM_SIZE_FOR_KASAN value 1024MB. I think mos=
t people have
>>>      guests with at least that much memory in the Radix 64s case so it'=
s a much
>>>      saner default - it means that if you just turn on KASAN without re=
ading the
>>>      docs you're much more likely to have a bootable kernel, which you =
will never
>>>      have if the value is set to zero! I'm happy to bikeshed the value =
if we want.
>>>
>>> Changes since v1:
>>>    - Landed kasan vmalloc support upstream
>>>    - Lots of feedback from Christophe.
>>>
>>> Changes since the rfc:
>>>
>>>    - Boots real and virtual hardware, kvm works.
>>>
>>>    - disabled reporting when we're checking the stack for exception
>>>      frames. The behaviour isn't wrong, just incompatible with KASAN.
>>>
>>>    - Documentation!
>>>
>>>    - Dropped old module stuff in favour of KASAN_VMALLOC.
>>>
>>> The bugs with ftrace and kuap were due to kernel bloat pushing
>>> prom_init calls to be done via the plt. Because we did not have
>>> a relocatable kernel, and they are done very early, this caused
>>> everything to explode. Compile with CONFIG_RELOCATABLE!
>>> ---
>>>    Documentation/dev-tools/kasan.rst            |   8 +-
>>>    Documentation/powerpc/kasan.txt              | 112 +++++++++++++++++=
+-
>>>    arch/powerpc/Kconfig                         |   2 +
>>>    arch/powerpc/Kconfig.debug                   |  21 ++++
>>>    arch/powerpc/Makefile                        |  11 ++
>>>    arch/powerpc/include/asm/book3s/64/hash.h    |   4 +
>>>    arch/powerpc/include/asm/book3s/64/pgtable.h |   7 ++
>>>    arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
>>>    arch/powerpc/include/asm/kasan.h             |  21 +++-
>>>    arch/powerpc/kernel/prom.c                   |  61 +++++++++-
>>>    arch/powerpc/mm/kasan/Makefile               |   1 +
>>>    arch/powerpc/mm/kasan/init_book3s_64.c       |  70 ++++++++++++
>>>    arch/powerpc/platforms/Kconfig.cputype       |   1 +
>>>    13 files changed, 316 insertions(+), 8 deletions(-)
>>>    create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>>>
>>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/as=
m/kasan.h
>>> index 296e51c2f066..f18268cbdc33 100644
>>> --- a/arch/powerpc/include/asm/kasan.h
>>> +++ b/arch/powerpc/include/asm/kasan.h
>>> @@ -2,6 +2,9 @@
>>>    #ifndef __ASM_KASAN_H
>>>    #define __ASM_KASAN_H
>>>   =20
>>> +#include <asm/page.h>
>>> +#include <asm/pgtable.h>
>>
>> What do you need asm/pgtable.h for ?
>>
>> Build failure due to circular inclusion of asm/pgtable.h:
>=20
> I see there's a lot of ppc32 stuff, I clearly need to bite the bullet
> and get a ppc32 toolchain so I can squash these without chewing up any
> more of your time. I'll sort that out and send a new spin.
>=20

I'm using a powerpc64 toolchain to build both ppc32 and ppc64 kernels=20
(from https://mirrors.edge.kernel.org/pub/tools/crosstool/ )


Another thing, did you test PTDUMP stuff with KASAN ? It looks like=20
KASAN address markers don't depend on PPC32, but are only initialised by=20
populate_markers() for PPC32.

Regarding kasan.h, I think we should be able to end up with something=20
where the definition of KASAN_SHADOW_OFFSET should only depend on the=20
existence of CONFIG_KASAN_SHADOW_OFFSET, and where only=20
KASAN_SHADOW_SIZE should depend on the target (ie PPC32 or BOOK3S64)
Everything else should be common. KASAN_END should be START+SIZE.

It looks like what you have called KASAN_SHADOW_SIZE is not similar to=20
what is called KASAN_SHADOW_SIZE for PPC32, as yours only covers the=20
SHADOW_SIZE for linear mem while PPC32 one covers the full space.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4f2fffb3-5fb6-b5ea-a951-a7910f2439b8%40c-s.fr.
