Return-Path: <kasan-dev+bncBDQ27FVWWUFRB3GW5XXQKGQEPSEDK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id D4F05126210
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 13:22:05 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id o1sf3826497ywl.1
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 04:22:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576758124; cv=pass;
        d=google.com; s=arc-20160816;
        b=yKtPXNfqEZu4MRrOd5hAXim4k9vt7DkWRCexDwdnhsBDrXm2X2OBeSrg+o9ZsvJHAA
         KxI3h2YnDiCJ3NV/K9w2lo/orEjFgliLa7HWBxYhv2Z6VIml5wMq+loEbLltK0Gz/h8m
         NdBqpwvPqB1GeMDHhRk9kqAi8+fTEqIeTLANLETy8Hdjz+JyHPXiTDAKOi3tBECVsZyh
         VprPEsGE/J+vL0+rqZxi6O2Xi46jMj0OfWVK9mxmZ+xgP1WLDjGUm+0+WlH7oguPcybP
         lYpVwIx5DeU7PT2VfoNoQpI6xR6lSv0RR8kIssPORDP3BJWdPrW9DQGB2XahXnPqh475
         9ulg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=8lE/bnQ/hjx3igDXYeDsN+rJncF6WRCKUJeNspmMqbc=;
        b=wBXAko769nuxBCzDo9iVSp3WZwKUfZgtMhcY3TAltlUMKtFXE1Z25ij63/wFLiPx7X
         zSPSriXiGkcf7sHo7UwsRuVaQhy2tRvmsEDO3iGLGpOE8pLQ7tUdL5vb23P0yX6vWhqv
         hwMGNW+B/E6KGNt51kS8G9/5fi9MtFBB5PvMr7aWrlgH4j1rmGyeNFrDV0yY+urHD8jR
         92Ac21mNGQpD2iX3F19UAAsez1LtNIodKLT22pf2Qa9xM6fwTmEZ2EleEupliu7YoKOf
         zxUDXMJkVaL5aY5ACTJbCbgcxqYQUi6DnqrZ889SIjbSfEZZdFzX19jjtpK/bq/JDKDQ
         mupQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Q2Nkm6fd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8lE/bnQ/hjx3igDXYeDsN+rJncF6WRCKUJeNspmMqbc=;
        b=ScRUFUEPYJ0TQyd3WUK28W9cEgmH8C5gO7rkhHXZo+qnR3UcOFzz7fDc74BTg7k2Nd
         ytoF9Rpq6Uguga/pIZGHVVXoX0eU2x5u6eKrDPlSX5atyfIe7bWEiCeC7Oe7BpxluS6g
         hc0kjex+g+5/bb2zVqHh5tqajkc9KLxOolqBpZ59r81Xxp6ugOorEFsNFx4q06dfK1dy
         Arh9WMTrHPRIPmepwCl0cgBWf/4YX2aDqvy1zLLoJhjswa87RmjXWPEwlV389PbRhhjo
         +cYJHvvgETUh+uQBjSHwwthmo9M4bBTnYGaG+sVimRi4TJWsn6ihm8zIwT9ht74Spu63
         oJWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8lE/bnQ/hjx3igDXYeDsN+rJncF6WRCKUJeNspmMqbc=;
        b=fOfSM7lp7tcaApeKxTEeXuiem6blhojDz03/go+V1l1LZAyuYIJf5NCnu4jA7iZODo
         1zGP2filKAXG+rGFAvUlEiUW4BekP4f4D+7JYrtP8uOBPaaiXEEMh5opB8+bDFdlXHrQ
         vo3oE5FX4hymTY2fjryS+sL6uhIEc7oBRth3XDuiSIESHPrfr/o5mvvgsnuuAktuH/RB
         0RwvG6zjHTGwkynO6fPEdz3Drr0hGfxUn7EwTXTzEVMFpL90tD5+1oCP9JU8Z4RFuk4u
         /mrrGJgRLWVPhCoWldug7lfr7ic1LZJGiNq3ZXlj+ISLi91Z8IZWomfOGXIrBb+ZSGom
         MVUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWtnimTW1wGI6wv83uXBkV3OlQyOqDKsTcTLiYHByGU/TyHW3V9
	el8aoKkqOd22If8eggDMcNE=
X-Google-Smtp-Source: APXvYqwEDoB8R6NJRQyTaLxwLhkCPCkSwVnNgcvlCbuudOGdvIvrRX4MmuSdBLd3rXEIEKVfYtuEpQ==
X-Received: by 2002:a25:8087:: with SMTP id n7mr5783539ybk.451.1576758124329;
        Thu, 19 Dec 2019 04:22:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:81cf:: with SMTP id n15ls823841ybm.9.gmail; Thu, 19 Dec
 2019 04:22:03 -0800 (PST)
X-Received: by 2002:a25:5543:: with SMTP id j64mr5993817ybb.252.1576758123771;
        Thu, 19 Dec 2019 04:22:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576758123; cv=none;
        d=google.com; s=arc-20160816;
        b=DD/csHVkPC6j4aFxG2d+LN6CYP0ThHT0GpwWXn2T5BFISZbvTeb4eo6dvzW0MpNK18
         +GlTOeKEmXwyFm+MdbP9TRkloSfHE4qWgBinWVEVqMxVEveSpXbzj05I1qKyTn4WOsDC
         OJNXoe0TBsw1RlEJOLTZm5Mfll77RYe7KkYDeNzQyAAEWhUrZMBH0ZY2S2FG0gU8PAbw
         1xTRmTX6AXtzJWhkaiZpxya3weN8o1RTugz43Ou8eLa1J/uuLTB+GNVFzPPWZPyD/j6k
         6ELbjzPJkhoevtK9ZhVtSKcmGvRYtkLXESy6aWNKHVBsMbkVoq1ITTEDHgf/HHkSW5mI
         LHaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=KUZMCzJDajvAWgOwIGaMCQmEpud/sI+HWwVZ5z66PfA=;
        b=aZiwdFL5a60lnWD0vMV9gRF17YgFBgjX0Tq6sUk9V5S1VQ8XX6pP1PIcFJ+STASb6O
         uDt+M9JTqDmvsgzPRTNY9uNNmFa/nDCdSmai0sHoSs4uDcf00lAsfKiZHTEUeUSNd08b
         N73lVnAB/zrDm40kNFL2JkYtZi1G9UfO57seS8GT58oCfUOEqVg1jMWgxePF1853kPTg
         I9RGO8ms7bOptUS81ExYsNAAQGUTFczaHjL2q0S0jvqj8WU20jev1093e92hSjNKEgWt
         yslHRKVgwCZqBsYLRR0B7itjg+9/pdR0Ne1GgVg8CDNS8WKQ4wq8r8GOVhmzQZQb4iWd
         JgHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Q2Nkm6fd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id j7si240098ywc.2.2019.12.19.04.22.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Dec 2019 04:22:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id g6so2484610plt.2
        for <kasan-dev@googlegroups.com>; Thu, 19 Dec 2019 04:22:03 -0800 (PST)
X-Received: by 2002:a17:90a:1992:: with SMTP id 18mr9506461pji.46.1576758122786;
        Thu, 19 Dec 2019 04:22:02 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-b05d-cbfe-b2ee-de17.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b05d:cbfe:b2ee:de17])
        by smtp.gmail.com with ESMTPSA id x4sm8347303pfx.68.2019.12.19.04.22.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Dec 2019 04:22:01 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v4 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <4f2fffb3-5fb6-b5ea-a951-a7910f2439b8@c-s.fr>
References: <20191219003630.31288-1-dja@axtens.net> <20191219003630.31288-5-dja@axtens.net> <c4d37067-829f-cd7d-7e94-0ec2223cce71@c-s.fr> <87bls4tzjn.fsf@dja-thinkpad.axtens.net> <4f2fffb3-5fb6-b5ea-a951-a7910f2439b8@c-s.fr>
Date: Thu, 19 Dec 2019 23:21:59 +1100
Message-ID: <877e2stsig.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Q2Nkm6fd;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Le 19/12/2019 =C3=A0 10:50, Daniel Axtens a =C3=A9crit=C2=A0:
>> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>>=20
>>> On 12/19/2019 12:36 AM, Daniel Axtens wrote:
>>>> KASAN support on Book3S is a bit tricky to get right:
>>>>
>>>>    - It would be good to support inline instrumentation so as to be ab=
le to
>>>>      catch stack issues that cannot be caught with outline mode.
>>>>
>>>>    - Inline instrumentation requires a fixed offset.
>>>>
>>>>    - Book3S runs code in real mode after booting. Most notably a lot o=
f KVM
>>>>      runs in real mode, and it would be good to be able to instrument =
it.
>>>>
>>>>    - Because code runs in real mode after boot, the offset has to poin=
t to
>>>>      valid memory both in and out of real mode.
>>>>
>>>>       [ppc64 mm note: The kernel installs a linear mapping at effectiv=
e
>>>>       address c000... onward. This is a one-to-one mapping with physic=
al
>>>>       memory from 0000... onward. Because of how memory accesses work =
on
>>>>       powerpc 64-bit Book3S, a kernel pointer in the linear map access=
es the
>>>>       same memory both with translations on (accessing as an 'effectiv=
e
>>>>       address'), and with translations off (accessing as a 'real
>>>>       address'). This works in both guests and the hypervisor. For mor=
e
>>>>       details, see s5.7 of Book III of version 3 of the ISA, in partic=
ular
>>>>       the Storage Control Overview, s5.7.3, and s5.7.5 - noting that t=
his
>>>>       KASAN implementation currently only supports Radix.]
>>>>
>>>> One approach is just to give up on inline instrumentation. This way al=
l
>>>> checks can be delayed until after everything set is up correctly, and =
the
>>>> address-to-shadow calculations can be overridden. However, the feature=
s and
>>>> speed boost provided by inline instrumentation are worth trying to do
>>>> better.
>>>>
>>>> If _at compile time_ it is known how much contiguous physical memory a
>>>> system has, the top 1/8th of the first block of physical memory can be=
 set
>>>> aside for the shadow. This is a big hammer and comes with 3 big
>>>> consequences:
>>>>
>>>>    - there's no nice way to handle physically discontiguous memory, so=
 only
>>>>      the first physical memory block can be used.
>>>>
>>>>    - kernels will simply fail to boot on machines with less memory tha=
n
>>>>      specified when compiling.
>>>>
>>>>    - kernels running on machines with more memory than specified when
>>>>      compiling will simply ignore the extra memory.
>>>>
>>>> Implement and document KASAN this way. The current implementation is R=
adix
>>>> only.
>>>>
>>>> Despite the limitations, it can still find bugs,
>>>> e.g. http://patchwork.ozlabs.org/patch/1103775/
>>>>
>>>> At the moment, this physical memory limit must be set _even for outlin=
e
>>>> mode_. This may be changed in a later series - a different implementat=
ion
>>>> could be added for outline mode that dynamically allocates shadow at a
>>>> fixed offset. For example, see https://patchwork.ozlabs.org/patch/7952=
11/
>>>>
>>>> Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
>>>> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix ver=
sion
>>>> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
>>>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>>>
>>>> ---
>>>> Changes since v3:
>>>>    - Address further feedback from Christophe.
>>>>    - Drop changes to stack walking, it looks like the issue I observed=
 is
>>>>      related to that particular stack, not stack-walking generally.
>>>>
>>>> Changes since v2:
>>>>
>>>>    - Address feedback from Christophe around cleanups and docs.
>>>>    - Address feedback from Balbir: at this point I don't have a good s=
olution
>>>>      for the issues you identify around the limitations of the inline =
implementation
>>>>      but I think that it's worth trying to get the stack instrumentati=
on support.
>>>>      I'm happy to have an alternative and more flexible outline mode -=
 I had
>>>>      envisoned this would be called 'lightweight' mode as it imposes f=
ewer restrictions.
>>>>      I've linked to your implementation. I think it's best to add it i=
n a follow-up series.
>>>>    - Made the default PHYS_MEM_SIZE_FOR_KASAN value 1024MB. I think mo=
st people have
>>>>      guests with at least that much memory in the Radix 64s case so it=
's a much
>>>>      saner default - it means that if you just turn on KASAN without r=
eading the
>>>>      docs you're much more likely to have a bootable kernel, which you=
 will never
>>>>      have if the value is set to zero! I'm happy to bikeshed the value=
 if we want.
>>>>
>>>> Changes since v1:
>>>>    - Landed kasan vmalloc support upstream
>>>>    - Lots of feedback from Christophe.
>>>>
>>>> Changes since the rfc:
>>>>
>>>>    - Boots real and virtual hardware, kvm works.
>>>>
>>>>    - disabled reporting when we're checking the stack for exception
>>>>      frames. The behaviour isn't wrong, just incompatible with KASAN.
>>>>
>>>>    - Documentation!
>>>>
>>>>    - Dropped old module stuff in favour of KASAN_VMALLOC.
>>>>
>>>> The bugs with ftrace and kuap were due to kernel bloat pushing
>>>> prom_init calls to be done via the plt. Because we did not have
>>>> a relocatable kernel, and they are done very early, this caused
>>>> everything to explode. Compile with CONFIG_RELOCATABLE!
>>>> ---
>>>>    Documentation/dev-tools/kasan.rst            |   8 +-
>>>>    Documentation/powerpc/kasan.txt              | 112 ++++++++++++++++=
++-
>>>>    arch/powerpc/Kconfig                         |   2 +
>>>>    arch/powerpc/Kconfig.debug                   |  21 ++++
>>>>    arch/powerpc/Makefile                        |  11 ++
>>>>    arch/powerpc/include/asm/book3s/64/hash.h    |   4 +
>>>>    arch/powerpc/include/asm/book3s/64/pgtable.h |   7 ++
>>>>    arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
>>>>    arch/powerpc/include/asm/kasan.h             |  21 +++-
>>>>    arch/powerpc/kernel/prom.c                   |  61 +++++++++-
>>>>    arch/powerpc/mm/kasan/Makefile               |   1 +
>>>>    arch/powerpc/mm/kasan/init_book3s_64.c       |  70 ++++++++++++
>>>>    arch/powerpc/platforms/Kconfig.cputype       |   1 +
>>>>    13 files changed, 316 insertions(+), 8 deletions(-)
>>>>    create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>>>>
>>>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/a=
sm/kasan.h
>>>> index 296e51c2f066..f18268cbdc33 100644
>>>> --- a/arch/powerpc/include/asm/kasan.h
>>>> +++ b/arch/powerpc/include/asm/kasan.h
>>>> @@ -2,6 +2,9 @@
>>>>    #ifndef __ASM_KASAN_H
>>>>    #define __ASM_KASAN_H
>>>>   =20
>>>> +#include <asm/page.h>
>>>> +#include <asm/pgtable.h>
>>>
>>> What do you need asm/pgtable.h for ?
>>>
>>> Build failure due to circular inclusion of asm/pgtable.h:
>>=20
>> I see there's a lot of ppc32 stuff, I clearly need to bite the bullet
>> and get a ppc32 toolchain so I can squash these without chewing up any
>> more of your time. I'll sort that out and send a new spin.
>>=20
>
> I'm using a powerpc64 toolchain to build both ppc32 and ppc64 kernels=20
> (from https://mirrors.edge.kernel.org/pub/tools/crosstool/ )

I am now using the distro toolchain that Ubuntu provides, and I've
reproduced and fixed the 32bit issues you identifed.

> Another thing, did you test PTDUMP stuff with KASAN ? It looks like=20
> KASAN address markers don't depend on PPC32, but are only initialised by=
=20
> populate_markers() for PPC32.

Hmm, OK. This is my last workday for the year, so I will look at this
and the simplifications to kasan.h early next year.

Thanks,
Daniel

>
> Regarding kasan.h, I think we should be able to end up with something=20
> where the definition of KASAN_SHADOW_OFFSET should only depend on the=20
> existence of CONFIG_KASAN_SHADOW_OFFSET, and where only=20
> KASAN_SHADOW_SIZE should depend on the target (ie PPC32 or BOOK3S64)
> Everything else should be common. KASAN_END should be START+SIZE.
>
> It looks like what you have called KASAN_SHADOW_SIZE is not similar to=20
> what is called KASAN_SHADOW_SIZE for PPC32, as yours only covers the=20
> SHADOW_SIZE for linear mem while PPC32 one covers the full space.
>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/877e2stsig.fsf%40dja-thinkpad.axtens.net.
