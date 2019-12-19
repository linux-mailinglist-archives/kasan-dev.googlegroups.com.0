Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUUP5XXQKGQE5CPNRPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC4D125E15
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 10:50:12 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id r17sf3414333pfl.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 01:50:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576749011; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qa5B83uhdOK+ZaKx0Jvum2+eNHHQQWuh5QO8m2kxl9/b2KaUBjwM7kU2YL9Rq97vhD
         OI7GQYZxj+RbuXhRQbTnTvDq4BP+lTR8jro6k7ej2uUEcPtrUo3p7a3dqPHSeDBrApJg
         HXvmV6qDY4DfAlKtvLtz+TTZEbvFakFdAoWeVVa91vkgH9tEyMCm+Qcx4f42T3Oh1Aqn
         qRB3DTU5CDjs71FCAEUrrolnik5mGudzyO3VP4gFpdVChZLhRYGEP62RcWkRuz/nuvfc
         gyFO0vpMuB1tfB6V5Z7qQPye+sOa7S1WmMs7S/vUjBeknUliRuJcBEwKjEHxxUBvOIt9
         7ZdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=PLpYrY0vv+EYoOaPym6FnvKqXQNt/TJ6nLyBG0Rh098=;
        b=npO0z50T/KQUUwrQ2kO7Oc3cx0QDWm4L0BbVGjd4rqi/zgUwePlxExmFDzKot9PAY7
         QBqFlSL4JdGft4cga9CoUAS0yJL5VT+jb2qTKyjaFNszEbli6crKOnA6Hs26ZWbzFP9C
         oy/Q1NAr2rxwkszLIwXPhvFWZeaYJm7/q/nQDn23BEcZNMsA/AjGjOJIhQ+Qvy2epcAs
         1pjqGU86oX2JLT6ypMGIKwr40DDQMXhiLVb19CkBfRDF13RZfl9GVbVWHE4t5E3bsnbr
         B47rMlFP169YksmT08UvASUF8gF8J0G5sIGmscs2iE30pNqhKCj3UCX5iv01MJrK/dru
         44GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=l8B3RJ6q;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PLpYrY0vv+EYoOaPym6FnvKqXQNt/TJ6nLyBG0Rh098=;
        b=E9wcL/Dwl6XANIjXOgTRUoqbUSb5qn9Fw71fMIchGexrPW8DVFjMd2oFW0tC56oTwh
         Jf83aKq0TPrFkXfxcP6IcW4NdP5D/9I6L+jYMVyTypMNdUHxA8XNRqqlbND2jL3yBR5L
         /3gXTdOGhli6Dh70lMREbbBMOsSoQn8hJNWFtkaA26MryqKyY+LTkcQZ9oarE0qnF/lN
         xA8En6+HqLqTrwqw2ppZ37TAp5ctA+cmy2WtpUN/MSFiDUMTt2Q5Zsz5LRoz/XWIdSij
         LuHnOi9fW75qx/UnXcHml2TvwMMVNYutYPngw4guEG4GCbLx9Lw/cIhD8rS5EynwJocN
         6LGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PLpYrY0vv+EYoOaPym6FnvKqXQNt/TJ6nLyBG0Rh098=;
        b=MNtiPQL1c/wEx6OKHa+jG9AUYzQewbGyp35H2bilGLTgGavBwrK05wIlvHRI7jyYN3
         sExU0JNmFe/j7X0Rtn2vzipihmMc0rfcuXSxIGdalJ+je9RvOzGgpWAlacVmcsrjl/7H
         fKk0+ArHeOwkUq1RhdNLQKr49CNa5Xh75KqrJyRoclpqNmU5kkzKZiaMJ+e3qoEU+YxV
         KD8NrAiR2nmXAWfAZnaR+31Ql4PnCj97FLPX1ztWy00UvVppCd1FW89veRn5BBalUnqu
         4Zqp7T3XzPjnKEP2wkPRSW07rHS97pOJzscpmDKQt6uSGVGPwXzmUrTpS2uJmKbbnN/w
         7GKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWGkHvGGqsLoBbSuFKmDn6sH61cvkNvr7cLTpJeL33G0ScpAX9X
	S/dcn10Phvn+yu6cuXqyKQc=
X-Google-Smtp-Source: APXvYqz3LJB5ilWW6++UvOwo5RreS2h8VYZPZNC6k489xtvYIkiLawriidJAWbMrcee5+eYFBQkcbw==
X-Received: by 2002:a17:90a:cb83:: with SMTP id a3mr8508580pju.80.1576749010827;
        Thu, 19 Dec 2019 01:50:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8303:: with SMTP id bd3ls1374901plb.3.gmail; Thu, 19
 Dec 2019 01:50:10 -0800 (PST)
X-Received: by 2002:a17:90a:b78e:: with SMTP id m14mr8881464pjr.14.1576749010332;
        Thu, 19 Dec 2019 01:50:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576749010; cv=none;
        d=google.com; s=arc-20160816;
        b=IGAxzb795mYzvXvTDDINKP7vKMt1WM05N8PXVHKf+mliWukAWoIU32IyB2RmdZCWZz
         ilsjh06t8auO6d4pr/hiI+BEsoyqGwTrvDtjzDmBvqgkcVOqGNWza1L8HAn4f9P2+pRN
         AelHw2KCDlCeeQ8ZBTit+ce7j2pSz4jB1lkfFrUc+h+wNzkhbXSYMmF5a9PgZAB8bCnT
         ZkLKhXaEae72U5kGh7Cc3f6aqd9sa6xWWgOXH4lb06PqfTpmdZ0ONyHP0kJ/Mik6X5FZ
         Df6uDsFwH6Qtnq+kbUmkQr/B58e5gvP6OGBQQdSHUAlIHnlCN5ggrRhUI1+D7oX03H+9
         rs2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=GmXHzb4IYsQ4wd2xtEbWgG3tocbmsvFI//hZNYMvjBM=;
        b=rFFsh6Gq0w+Y3Kc6Jo82yRRMK5lJNoZox/3M78LMFRN0/NElvbItEYFhzayw4Wl9wX
         Lan7PdPpTxiIdMl726/g3ikdCFGPxL3yxcOcReBlTS/NWAWcw2ux+MZr2hQeqzI4Nnko
         hNuXnEw+ObOzmBrSrB2Lgh+SttSY5B7pHo/lR+BuacTjzy4LasKUSlzHTBnqoZd2nwRB
         2cUIqsu+GV8xW59/9fKgumIJ6/pTzdXFrz9gZ3B92njswawuquZwvlcrmaIxiFpklG+k
         /XembfJNtnqEaDW5tlyvuJD3UuOckKcIyUaZEiWXM6hOdYhe2dkTvFFQap6dHZLUzgeN
         wDZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=l8B3RJ6q;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id b192si226014pga.5.2019.12.19.01.50.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Dec 2019 01:50:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id u63so2388958pjb.0
        for <kasan-dev@googlegroups.com>; Thu, 19 Dec 2019 01:50:10 -0800 (PST)
X-Received: by 2002:a17:90a:fb87:: with SMTP id cp7mr8690446pjb.56.1576749009677;
        Thu, 19 Dec 2019 01:50:09 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-b05d-cbfe-b2ee-de17.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b05d:cbfe:b2ee:de17])
        by smtp.gmail.com with ESMTPSA id r6sm7431424pfh.91.2019.12.19.01.50.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Dec 2019 01:50:08 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v4 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <c4d37067-829f-cd7d-7e94-0ec2223cce71@c-s.fr>
References: <20191219003630.31288-1-dja@axtens.net> <20191219003630.31288-5-dja@axtens.net> <c4d37067-829f-cd7d-7e94-0ec2223cce71@c-s.fr>
Date: Thu, 19 Dec 2019 20:50:04 +1100
Message-ID: <87bls4tzjn.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=l8B3RJ6q;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as
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

> On 12/19/2019 12:36 AM, Daniel Axtens wrote:
>> KASAN support on Book3S is a bit tricky to get right:
>> 
>>   - It would be good to support inline instrumentation so as to be able to
>>     catch stack issues that cannot be caught with outline mode.
>> 
>>   - Inline instrumentation requires a fixed offset.
>> 
>>   - Book3S runs code in real mode after booting. Most notably a lot of KVM
>>     runs in real mode, and it would be good to be able to instrument it.
>> 
>>   - Because code runs in real mode after boot, the offset has to point to
>>     valid memory both in and out of real mode.
>> 
>>      [ppc64 mm note: The kernel installs a linear mapping at effective
>>      address c000... onward. This is a one-to-one mapping with physical
>>      memory from 0000... onward. Because of how memory accesses work on
>>      powerpc 64-bit Book3S, a kernel pointer in the linear map accesses the
>>      same memory both with translations on (accessing as an 'effective
>>      address'), and with translations off (accessing as a 'real
>>      address'). This works in both guests and the hypervisor. For more
>>      details, see s5.7 of Book III of version 3 of the ISA, in particular
>>      the Storage Control Overview, s5.7.3, and s5.7.5 - noting that this
>>      KASAN implementation currently only supports Radix.]
>> 
>> One approach is just to give up on inline instrumentation. This way all
>> checks can be delayed until after everything set is up correctly, and the
>> address-to-shadow calculations can be overridden. However, the features and
>> speed boost provided by inline instrumentation are worth trying to do
>> better.
>> 
>> If _at compile time_ it is known how much contiguous physical memory a
>> system has, the top 1/8th of the first block of physical memory can be set
>> aside for the shadow. This is a big hammer and comes with 3 big
>> consequences:
>> 
>>   - there's no nice way to handle physically discontiguous memory, so only
>>     the first physical memory block can be used.
>> 
>>   - kernels will simply fail to boot on machines with less memory than
>>     specified when compiling.
>> 
>>   - kernels running on machines with more memory than specified when
>>     compiling will simply ignore the extra memory.
>> 
>> Implement and document KASAN this way. The current implementation is Radix
>> only.
>> 
>> Despite the limitations, it can still find bugs,
>> e.g. http://patchwork.ozlabs.org/patch/1103775/
>> 
>> At the moment, this physical memory limit must be set _even for outline
>> mode_. This may be changed in a later series - a different implementation
>> could be added for outline mode that dynamically allocates shadow at a
>> fixed offset. For example, see https://patchwork.ozlabs.org/patch/795211/
>> 
>> Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
>> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix version
>> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> 
>> ---
>> Changes since v3:
>>   - Address further feedback from Christophe.
>>   - Drop changes to stack walking, it looks like the issue I observed is
>>     related to that particular stack, not stack-walking generally.
>> 
>> Changes since v2:
>> 
>>   - Address feedback from Christophe around cleanups and docs.
>>   - Address feedback from Balbir: at this point I don't have a good solution
>>     for the issues you identify around the limitations of the inline implementation
>>     but I think that it's worth trying to get the stack instrumentation support.
>>     I'm happy to have an alternative and more flexible outline mode - I had
>>     envisoned this would be called 'lightweight' mode as it imposes fewer restrictions.
>>     I've linked to your implementation. I think it's best to add it in a follow-up series.
>>   - Made the default PHYS_MEM_SIZE_FOR_KASAN value 1024MB. I think most people have
>>     guests with at least that much memory in the Radix 64s case so it's a much
>>     saner default - it means that if you just turn on KASAN without reading the
>>     docs you're much more likely to have a bootable kernel, which you will never
>>     have if the value is set to zero! I'm happy to bikeshed the value if we want.
>> 
>> Changes since v1:
>>   - Landed kasan vmalloc support upstream
>>   - Lots of feedback from Christophe.
>> 
>> Changes since the rfc:
>> 
>>   - Boots real and virtual hardware, kvm works.
>> 
>>   - disabled reporting when we're checking the stack for exception
>>     frames. The behaviour isn't wrong, just incompatible with KASAN.
>> 
>>   - Documentation!
>> 
>>   - Dropped old module stuff in favour of KASAN_VMALLOC.
>> 
>> The bugs with ftrace and kuap were due to kernel bloat pushing
>> prom_init calls to be done via the plt. Because we did not have
>> a relocatable kernel, and they are done very early, this caused
>> everything to explode. Compile with CONFIG_RELOCATABLE!
>> ---
>>   Documentation/dev-tools/kasan.rst            |   8 +-
>>   Documentation/powerpc/kasan.txt              | 112 ++++++++++++++++++-
>>   arch/powerpc/Kconfig                         |   2 +
>>   arch/powerpc/Kconfig.debug                   |  21 ++++
>>   arch/powerpc/Makefile                        |  11 ++
>>   arch/powerpc/include/asm/book3s/64/hash.h    |   4 +
>>   arch/powerpc/include/asm/book3s/64/pgtable.h |   7 ++
>>   arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
>>   arch/powerpc/include/asm/kasan.h             |  21 +++-
>>   arch/powerpc/kernel/prom.c                   |  61 +++++++++-
>>   arch/powerpc/mm/kasan/Makefile               |   1 +
>>   arch/powerpc/mm/kasan/init_book3s_64.c       |  70 ++++++++++++
>>   arch/powerpc/platforms/Kconfig.cputype       |   1 +
>>   13 files changed, 316 insertions(+), 8 deletions(-)
>>   create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>> 
>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
>> index 296e51c2f066..f18268cbdc33 100644
>> --- a/arch/powerpc/include/asm/kasan.h
>> +++ b/arch/powerpc/include/asm/kasan.h
>> @@ -2,6 +2,9 @@
>>   #ifndef __ASM_KASAN_H
>>   #define __ASM_KASAN_H
>>   
>> +#include <asm/page.h>
>> +#include <asm/pgtable.h>
>
> What do you need asm/pgtable.h for ?
>
> Build failure due to circular inclusion of asm/pgtable.h:

I see there's a lot of ppc32 stuff, I clearly need to bite the bullet
and get a ppc32 toolchain so I can squash these without chewing up any
more of your time. I'll sort that out and send a new spin.

Regards,
Daniel

>
>    CC      arch/powerpc/kernel/asm-offsets.s
> In file included from ./arch/powerpc/include/asm/nohash/32/pgtable.h:77:0,
>                   from ./arch/powerpc/include/asm/nohash/pgtable.h:8,
>                   from ./arch/powerpc/include/asm/pgtable.h:20,
>                   from ./arch/powerpc/include/asm/kasan.h:6,
>                   from ./include/linux/kasan.h:14,
>                   from ./include/linux/slab.h:136,
>                   from ./include/linux/crypto.h:19,
>                   from ./include/crypto/hash.h:11,
>                   from ./include/linux/uio.h:10,
>                   from ./include/linux/socket.h:8,
>                   from ./include/linux/compat.h:15,
>                   from arch/powerpc/kernel/asm-offsets.c:14:
> ./include/asm-generic/fixmap.h: In function 'fix_to_virt':
> ./arch/powerpc/include/asm/fixmap.h:28:22: error: 'KASAN_SHADOW_START' 
> undeclared (first use in this function)
>   #define FIXADDR_TOP (KASAN_SHADOW_START - PAGE_SIZE)
>                        ^
> ./include/asm-generic/fixmap.h:21:27: note: in expansion of macro 
> 'FIXADDR_TOP'
>   #define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
>                             ^
> ./include/asm-generic/fixmap.h:33:9: note: in expansion of macro 
> '__fix_to_virt'
>    return __fix_to_virt(idx);
>           ^
> ./arch/powerpc/include/asm/fixmap.h:28:22: note: each undeclared 
> identifier is reported only once for each function it appears in
>   #define FIXADDR_TOP (KASAN_SHADOW_START - PAGE_SIZE)
>                        ^
> ./include/asm-generic/fixmap.h:21:27: note: in expansion of macro 
> 'FIXADDR_TOP'
>   #define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
>                             ^
> ./include/asm-generic/fixmap.h:33:9: note: in expansion of macro 
> '__fix_to_virt'
>    return __fix_to_virt(idx);
>           ^
> In file included from ./include/linux/bug.h:5:0,
>                   from ./include/linux/thread_info.h:12,
>                   from ./include/asm-generic/preempt.h:5,
>                   from ./arch/powerpc/include/generated/asm/preempt.h:1,
>                   from ./include/linux/preempt.h:78,
>                   from ./include/linux/spinlock.h:51,
>                   from ./include/linux/seqlock.h:36,
>                   from ./include/linux/time.h:6,
>                   from ./include/linux/compat.h:10,
>                   from arch/powerpc/kernel/asm-offsets.c:14:
> ./include/asm-generic/fixmap.h: In function 'virt_to_fix':
> ./arch/powerpc/include/asm/fixmap.h:28:22: error: 'KASAN_SHADOW_START' 
> undeclared (first use in this function)
>   #define FIXADDR_TOP (KASAN_SHADOW_START - PAGE_SIZE)
>                        ^
> ./arch/powerpc/include/asm/bug.h:73:27: note: in definition of macro 
> 'BUG_ON'
>    if (__builtin_constant_p(x)) {    \
>                             ^
> ./include/asm-generic/fixmap.h:38:18: note: in expansion of macro 
> 'FIXADDR_TOP'
>    BUG_ON(vaddr >= FIXADDR_TOP || vaddr < FIXADDR_START);
>                    ^
> In file included from ./arch/powerpc/include/asm/nohash/32/pgtable.h:77:0,
>                   from ./arch/powerpc/include/asm/nohash/pgtable.h:8,
>                   from ./arch/powerpc/include/asm/pgtable.h:20,
>                   from ./arch/powerpc/include/asm/kasan.h:6,
>                   from ./include/linux/kasan.h:14,
>                   from ./include/linux/slab.h:136,
>                   from ./include/linux/crypto.h:19,
>                   from ./include/crypto/hash.h:11,
>                   from ./include/linux/uio.h:10,
>                   from ./include/linux/socket.h:8,
>                   from ./include/linux/compat.h:15,
>                   from arch/powerpc/kernel/asm-offsets.c:14:
> ./arch/powerpc/include/asm/fixmap.h: In function '__set_fixmap':
> ./arch/powerpc/include/asm/fixmap.h:28:22: error: 'KASAN_SHADOW_START' 
> undeclared (first use in this function)
>   #define FIXADDR_TOP (KASAN_SHADOW_START - PAGE_SIZE)
>                        ^
> ./include/asm-generic/fixmap.h:21:27: note: in expansion of macro 
> 'FIXADDR_TOP'
>   #define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
>                             ^
> ./arch/powerpc/include/asm/fixmap.h:102:18: note: in expansion of macro 
> '__fix_to_virt'
>    map_kernel_page(__fix_to_virt(idx), phys, flags);
>                    ^
> make[2]: *** [arch/powerpc/kernel/asm-offsets.s] Error 1
> make[1]: *** [prepare0] Error 2
> make: *** [sub-make] Error 2
>
>
>
>> +
>>   #ifdef CONFIG_KASAN
>>   #define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
>>   #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
>> @@ -14,13 +17,19 @@
>>   
>>   #ifndef __ASSEMBLY__
>>   
>> -#include <asm/page.h>
>> +#ifdef CONFIG_KASAN
>> +void kasan_init(void);
>> +#else
>> +static inline void kasan_init(void) { }
>> +#endif
>
> I don't think it is worth moving this. Just keep everything out of the 
> #ifdef CONFIG_PPC32. Having undefined/unused functions there shouldn't 
> matter.
>
>>   
>>   #define KASAN_SHADOW_SCALE_SHIFT	3
>>   
>>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>>   				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>>   
>> +#ifdef CONFIG_PPC32
>> +
>>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>>   
>>   #define KASAN_SHADOW_END	0UL
>> @@ -30,11 +39,17 @@
>
> Keep the block below out of the CONFIG_PPC32 ifdef, don't need to move 
> kasan_init()
>
>>   #ifdef CONFIG_KASAN
>>   void kasan_early_init(void);
>>   void kasan_mmu_init(void);
>> -void kasan_init(void);
>>   #else
>> -static inline void kasan_init(void) { }
>>   static inline void kasan_mmu_init(void) { }
>>   #endif
>> +#endif
>> +
>> +#ifdef CONFIG_PPC_BOOK3S_64
>> +
>> +#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
>> +				1024 * 1024 * 1 / 8)
>
> What about:
>
> (ASM_CONST(CONFIG_PHYS_MEM_SIZE_FOR_KASAN) * SZ_1G) >> 
> KASAN_SHADOW_SCALE_SHIFT
>
>> +
>> +#endif /* CONFIG_PPC_BOOK3S_64 */
>>   
>>   #endif /* __ASSEMBLY */
>>   #endif
>> diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
>> index 6620f37abe73..f8ef0074b320 100644
>> --- a/arch/powerpc/kernel/prom.c
>> +++ b/arch/powerpc/kernel/prom.c
>> @@ -72,6 +72,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
>>   u64 ppc64_rma_size;
>>   #endif
>>   static phys_addr_t first_memblock_size;
>> +static phys_addr_t top_phys_addr;
>>   static int __initdata boot_cpu_count;
>>   
>>   static int __init early_parse_mem(char *p)
>> @@ -449,6 +450,26 @@ static bool validate_mem_limit(u64 base, u64 *size)
>>   {
>>   	u64 max_mem = 1UL << (MAX_PHYSMEM_BITS);
>>   
>> +	/*
>> +	 * To handle the NUMA/discontiguous memory case, don't allow a block
>> +	 * to be added if it falls completely beyond the configured physical
>> +	 * memory. Print an informational message.
>> +	 *
>> +	 * Frustratingly we also see this with qemu - it seems to split the
>> +	 * specified memory into a number of smaller blocks. If this happens
>> +	 * under qemu, it probably represents misconfiguration. So we want
>> +	 * the message to be noticeable, but not shouty.
>> +	 *
>> +	 * See Documentation/powerpc/kasan.txt
>> +	 */
>> +	if (IS_ENABLED(CONFIG_KASAN) &&
>> +	    (base >= ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20))) {
>> +		pr_warn("KASAN: not adding memory block at %llx (size %llx)\n"
>> +			"This could be due to discontiguous memory or kernel misconfiguration.",
>> +			base, *size);
>> +		return false;
>> +	}
>> +
>>   	if (base >= max_mem)
>>   		return false;
>>   	if ((base + *size) > max_mem)
>> @@ -572,8 +593,10 @@ void __init early_init_dt_add_memory_arch(u64 base, u64 size)
>>   
>>   	/* Add the chunk to the MEMBLOCK list */
>>   	if (add_mem_to_memblock) {
>> -		if (validate_mem_limit(base, &size))
>> +		if (validate_mem_limit(base, &size)) {
>>   			memblock_add(base, size);
>> +			top_phys_addr = max(top_phys_addr, base + size);
>
> Build failure, you have to cast (base + size) to (phys_addr_t) as 
> phys_addr_t is not always u64.
>
>    CC      arch/powerpc/kernel/asm-offsets.s
>    CALL    scripts/checksyscalls.sh
>    CALL    scripts/atomic/check-atomics.sh
>    CC      arch/powerpc/kernel/prom.o
> In file included from arch/powerpc/kernel/prom.c:15:0:
> arch/powerpc/kernel/prom.c: In function 'early_init_dt_add_memory_arch':
> ./include/linux/kernel.h:844:29: error: comparison of distinct pointer 
> types lacks a cast [-Werror]
>     (!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))
>                               ^
> ./include/linux/kernel.h:858:4: note: in expansion of macro '__typecheck'
>     (__typecheck(x, y) && __no_side_effects(x, y))
>      ^
> ./include/linux/kernel.h:868:24: note: in expansion of macro '__safe_cmp'
>    __builtin_choose_expr(__safe_cmp(x, y), \
>                          ^
> ./include/linux/kernel.h:884:19: note: in expansion of macro '__careful_cmp'
>   #define max(x, y) __careful_cmp(x, y, >)
>                     ^
> arch/powerpc/kernel/prom.c:598:20: note: in expansion of macro 'max'
>      top_phys_addr = max(top_phys_addr, base + size);
>                      ^
> cc1: all warnings being treated as errors
> make[3]: *** [arch/powerpc/kernel/prom.o] Error 1
> make[2]: *** [arch/powerpc/kernel] Error 2
> make[1]: *** [arch/powerpc] Error 2
> make: *** [sub-make] Error 2
>
>> +		}
>>   	}
>>   }
>>   
>> @@ -613,6 +636,8 @@ static void __init early_reserve_mem_dt(void)
>>   static void __init early_reserve_mem(void)
>>   {
>>   	__be64 *reserve_map;
>> +	phys_addr_t kasan_shadow_start;
>> +	phys_addr_t kasan_memory_size;
>>   
>>   	reserve_map = (__be64 *)(((unsigned long)initial_boot_params) +
>>   			fdt_off_mem_rsvmap(initial_boot_params));
>> @@ -651,6 +676,40 @@ static void __init early_reserve_mem(void)
>>   		return;
>>   	}
>>   #endif
>> +
>> +	if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
>> +		kasan_memory_size =
>> +			((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
>> +
>> +		if (top_phys_addr < kasan_memory_size) {
>> +			/*
>> +			 * We are doomed. We shouldn't even be able to get this
>> +			 * far, but we do in qemu. If we continue and turn
>> +			 * relocations on, we'll take fatal page faults for
>> +			 * memory that's not physically present. Instead,
>> +			 * panic() here: it will be saved to __log_buf even if
>> +			 * it doesn't get printed to the console.
>> +			 */
>> +			panic("Tried to boot a KASAN kernel configured for %u MB with only %llu MB! Aborting.",
>> +			      CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
>> +			      (u64)(top_phys_addr >> 20));
>> +		} else if (top_phys_addr > kasan_memory_size) {
>> +			/* print a biiiig warning in hopes people notice */
>> +			pr_err("===========================================\n"
>> +				"Physical memory exceeds compiled-in maximum!\n"
>> +				"This kernel was compiled for KASAN with %u MB physical memory.\n"
>> +				"The physical memory detected is at least %llu MB.\n"
>> +				"Memory above the compiled limit will not be used!\n"
>> +				"===========================================\n",
>> +				CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
>> +				(u64)(top_phys_addr >> 20));
>> +		}
>> +
>> +		kasan_shadow_start = _ALIGN_DOWN(kasan_memory_size * 7 / 8, PAGE_SIZE);
>> +		DBG("reserving %llx -> %llx for KASAN",
>> +		    kasan_shadow_start, top_phys_addr);
>> +		memblock_reserve(kasan_shadow_start, top_phys_addr - kasan_shadow_start);
>> +	}
>>   }
>>   
>>   #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
>
> Christophe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87bls4tzjn.fsf%40dja-thinkpad.axtens.net.
