Return-Path: <kasan-dev+bncBDQ27FVWWUFRBYGRXTXQKGQESDHKQII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F25117F72
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 06:10:58 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id e11sf13210448ybn.12
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 21:10:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575954657; cv=pass;
        d=google.com; s=arc-20160816;
        b=r7AN/z56uC7hRm39NUXivJM1J5bK8R2qs/qihaFQFektlst2yjxE1rcBYRS/bAo2Z6
         4FGizoL66PYMSp9XgRYCbN0EZocKj7IfigTlmkT5RQJhan8ooYTWkKb34rckWAmZ6Bgh
         senwGzBDU9X6ZIH2J8yni5VgOV9n98Of7EyLETX85eH5EX5Ws2/QyOCoRLdagz2vyXGc
         SB7nXNc84VA7fclXp8vrfHfS400sUM10umsUL3v2yspX02+kTSO4rNl1g8i5r7oUePSy
         7KtpoNra8+zsOPnaYHo76FrEYAZGHanyqbWIb2coBSMfgNhl8X7XCtsHNbxmGBqMqGqk
         dPsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=3uGsdjoiO3NVek2r97eBo2RfxzSqFO0qFTLCEcvvm0k=;
        b=UjuOYOWds5VZVAUtJL6DQjyz1YjlovbFVy7P0q3aiGikuiJsOqXjwNVbbtpRumVR2L
         5EXT8BjLU8IE3cKzZPg3vx5x7dWQas17ZMDp89P+8ogfV4vjGPlUw9xmwSbJ9hD6FUWb
         90xG9VoVHFhDFq0C3C+25AddTIJH6jxRU9LanzeGieVFWSvQG1hAHQfsRaRukWLefnEy
         K6PPELRvuZ93cLVwluvNlIjXShhJaRUpcJ6PVeR2XF6k26AKhK4miZHu80dXJVbO5oAp
         OVb/f2S3eBw0zNe1A8RDjxWYazlT+5K+s74xx5dv2GXLB65yXjiL/HUJ1ODRTF3B1zu2
         52Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="b0/iauif";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3uGsdjoiO3NVek2r97eBo2RfxzSqFO0qFTLCEcvvm0k=;
        b=a8Y2Vpf5jGoPdWM4PyvlPDyHHrjQl80BZlxg4voNEq5Iz5aCGOsRlpKiUo5Q7RgOtA
         6o1wUkJ/o5Y4OLuaFY2Jk6XAouXkqC1yZmnAlmVTEDKE+NwhQYEmp2fc8yC6SIk406sf
         XmAW+pacUvrcX0fbd2AlCSns/iozvEQopDPj80EAVd3Lp2Ov1I6y2jZN1htC1o91JoeC
         hithDstX+23wmsDgkE718jW3lwutQRHVVldILJHMSIkJA7H2HPSqnaTHlCWH4b0l4Uao
         ZjJYGumuQO0nw0PNodr878Lg8AXza3pBt3p8KBBVpujGJwdXOtyq2Tbn2jmExJjmFknj
         enEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3uGsdjoiO3NVek2r97eBo2RfxzSqFO0qFTLCEcvvm0k=;
        b=Kd0+U3ohbIChYo9G6bW2SDXN0BZZgRTEJK6jnueapt9fOQ6zfx+/NjrwRF6aVVxksQ
         x05CZm0Unfsky0VHHVCNN/em4hBX0+62GzMNAIR7RN3LktmGHEwQFKNvPoLuR9PLGqVi
         zHKtQUPYYGUfxT2dGv+G0GG/BebP3Xrtx5D8ql5x+EAq59iKu0yqNuRG0s7lnZHV2Gah
         7vBxkp61OcxD+lJzo6pQsoCOckrqxeouRGOj7Ds8Eo4m3SPqcgsfts/wSm5hdN+oVJzd
         gDlzxOPny49xCJBWCm9yFwy++HlQVZXG3xsymPJymWmYMnJLmjpsx6UAc086l2uI9YgN
         339Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVX9ySBDPevjrTW+eBcf9o6lGlESPYKxfCKPeLaqubqpObvLoV4
	N9Js/mjgFDyTLHcfbC41yYI=
X-Google-Smtp-Source: APXvYqyvkG9pfPuSRjsnQxiWe/E5HSDpbXoBLWZeZdmzqVJWFhzH1SPJClA72NpMgFfnGbKiaTvF7A==
X-Received: by 2002:a81:602:: with SMTP id 2mr24159337ywg.81.1575954656994;
        Mon, 09 Dec 2019 21:10:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:4709:: with SMTP id u9ls2363812ywa.4.gmail; Mon, 09 Dec
 2019 21:10:56 -0800 (PST)
X-Received: by 2002:a0d:cc55:: with SMTP id o82mr24316563ywd.426.1575954656556;
        Mon, 09 Dec 2019 21:10:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575954656; cv=none;
        d=google.com; s=arc-20160816;
        b=bDZp02cAFAyJwem6zmo/ZkUnpYkE482goOMSb0RSHRMqkPjtuVQ3yWZIlMZ4o7AzCR
         eNoc7c7M3UvGsbqfgG6nu/uaad3fYUFbHSMvPFaF39pjZHG2ohvzfbvfGeunQXp52r3a
         TIA2LBXg/dF703KSZMWfr2FPJ/0/u81/JKGJENEj4nuK2mSy5O0F1fVaVSIyauH3PxUN
         0JE0d8zb0Wk33CFv6UYkLxLeJWZpe/4noXuhefAtTfyvVoveLDBIkd7fq8+IpaX9FpQB
         7zoQdHr17MYBHmwgXy5a3hrXt36hGmnZswjvrriAXPK/TtZW/9FvNPn5GiUtTu5kopZN
         Ph6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=Un850LfvjtyPmDqhVZ2V+HUe8+w/TpHE3OAJim2wry0=;
        b=foawWKa3Cqj6heuZBzxTDuHdMymST62HgMkoBJBu9+M/3X8FIZm4SijgSqRofCRkbo
         Es4LdKHRYUsQqhAe7JETys3xcwWW+T92gUCxtdamWvaOwOeNd5z7AqAjyjzTecKdZv9M
         QDHSfBKZY99z25lHQYGR0cVIxFDJN1NWU2h7NSAtfwFk8/Lz4iS0wRtFCFY0C50gthbf
         //njimkAcy8PUya9kl3fEnLhcnQlPKUlaE1lKlslt8V6MM2zlBFZJuYMNR50Goj0GNbQ
         DxaT/CV/kCVw/Izzu9HeTtZYKW2/qVMn4iOkrehzXjrvBwn0qI53E1o+OZDJ3F6vP4ub
         1ATQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="b0/iauif";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id r1si109713ybr.3.2019.12.09.21.10.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 21:10:56 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id q8so8423213pfh.7
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 21:10:56 -0800 (PST)
X-Received: by 2002:a63:5fd7:: with SMTP id t206mr22887491pgb.281.1575954655098;
        Mon, 09 Dec 2019 21:10:55 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e460-0b66-7007-c654.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e460:b66:7007:c654])
        by smtp.gmail.com with ESMTPSA id 9sm1281943pfx.177.2019.12.09.21.10.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 21:10:54 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <372df444-27e7-12a7-0bdb-048f29983cf4@c-s.fr>
References: <20190806233827.16454-1-dja@axtens.net> <20190806233827.16454-5-dja@axtens.net> <372df444-27e7-12a7-0bdb-048f29983cf4@c-s.fr>
Date: Tue, 10 Dec 2019 16:10:48 +1100
Message-ID: <878snkdauf.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="b0/iauif";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
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

> Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
>> KASAN support on powerpc64 is interesting:
>>=20
>>   - We want to be able to support inline instrumentation so as to be
>>     able to catch global and stack issues.
>>=20
>>   - We run a lot of code at boot in real mode. This includes stuff like
>>     printk(), so it's not feasible to just disable instrumentation
>>     around it.
>
> Have you definitely given up the idea of doing a standard implementation=
=20
> of KASAN like other 64 bits arches have done ?
>
> Isn't it possible to setup an early 1:1 mapping and go in virtual mode=20
> earlier ? What is so different between book3s64 and book3e64 ?
> On book3e64, we've been able to setup KASAN before printing anything=20
> (except when using EARLY_DEBUG). Isn't it feasible on book3s64 too ?

So I got this pretty wrong when trying to explain it. The problem isn't
that we run the code in boot as I said, it's that a bunch of the KVM
code runs in real mode.

>>   - disabled reporting when we're checking the stack for exception
>>     frames. The behaviour isn't wrong, just incompatible with KASAN.
>
> Does this applies to / impacts PPC32 at all ?

It should. I found that when doing stack walks, the code would touch
memory that KASAN hadn't unpoisioned. I'm a bit surprised you haven't
seen it arise, tbh.

>>   - Dropped old module stuff in favour of KASAN_VMALLOC.
>
> You said in the cover that this is done to avoid having to split modules=
=20
> out of VMALLOC area. Would it be an issue to perform that split ?
> I can understand it is not easy on 32 bits because vmalloc space is=20
> rather small, but on 64 bits don't we have enough virtual space to=20
> confortably split modules out of vmalloc ? The 64 bits already splits=20
> ioremap away from vmalloc whereas 32 bits have them merged too.

I could have done this. Maybe I should have done this. But now I have
done vmalloc space support.

>> The bugs with ftrace and kuap were due to kernel bloat pushing
>> prom_init calls to be done via the plt. Because we did not have
>> a relocatable kernel, and they are done very early, this caused
>> everything to explode. Compile with CONFIG_RELOCATABLE!
>>=20
>> ---
>>   Documentation/dev-tools/kasan.rst            |   7 +-
>>   Documentation/powerpc/kasan.txt              | 111 +++++++++++++++++++
>>   arch/powerpc/Kconfig                         |   4 +
>>   arch/powerpc/Kconfig.debug                   |  21 ++++
>>   arch/powerpc/Makefile                        |   7 ++
>>   arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
>>   arch/powerpc/include/asm/kasan.h             |  35 +++++-
>>   arch/powerpc/kernel/process.c                |   8 ++
>>   arch/powerpc/kernel/prom.c                   |  57 +++++++++-
>>   arch/powerpc/mm/kasan/Makefile               |   1 +
>>   arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  76 +++++++++++++
>>   11 files changed, 326 insertions(+), 6 deletions(-)
>>   create mode 100644 Documentation/powerpc/kasan.txt
>>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c
>>=20
>> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools=
/kasan.rst
>> index 35fda484a672..48d3b669e577 100644
>> --- a/Documentation/dev-tools/kasan.rst
>> +++ b/Documentation/dev-tools/kasan.rst
>> @@ -22,7 +22,9 @@ global variables yet.
>>   Tag-based KASAN is only supported in Clang and requires version 7.0.0 =
or later.
>>  =20
>>   Currently generic KASAN is supported for the x86_64, arm64, xtensa and=
 s390
>> -architectures, and tag-based KASAN is supported only for arm64.
>> +architectures. It is also supported on powerpc for 32-bit kernels, and =
for
>> +64-bit kernels running under the radix MMU. Tag-based KASAN is supporte=
d only
>> +for arm64.
>
> Could the 32 bits documentation stuff be a separate patch ?

Done.
>
>>  =20
>>   Usage
>>   -----
>> @@ -252,7 +254,8 @@ CONFIG_KASAN_VMALLOC
>>   ~~~~~~~~~~~~~~~~~~~~
>>  =20
>>   With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
>> -cost of greater memory usage. Currently this is only supported on x86.
>> +cost of greater memory usage. Currently this is optional on x86, and
>> +required on 64-bit powerpc.
>>  =20
>>   This works by hooking into vmalloc and vmap, and dynamically
>>   allocating real shadow memory to back the mappings.
>> diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kas=
an.txt
>> new file mode 100644
>> index 000000000000..a5592454353b
>> --- /dev/null
>> +++ b/Documentation/powerpc/kasan.txt
>> @@ -0,0 +1,111 @@
>> +KASAN is supported on powerpc on 32-bit and 64-bit Radix only.
>> +
>> +32 bit support
>> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> +
>> +KASAN is supported on both hash and nohash MMUs on 32-bit.
>> +
>> +The shadow area sits at the top of the kernel virtual memory space abov=
e the
>> +fixmap area and occupies one eighth of the total kernel virtual memory =
space.
>> +
>> +Instrumentation of the vmalloc area is not currently supported, but mod=
ules are.
>> +
>> +64 bit support
>> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> +
>> +Currently, only the radix MMU is supported. There have been versions fo=
r Book3E
>> +processors floating around on the mailing list, but nothing has been me=
rged.
>> +
>> +KASAN support on Book3S is interesting:
>
> And support for others is not interesting ? :)
>
:) I've reworded it to be a bit more professional.

>> +
>> + - We want to be able to support inline instrumentation so as to be abl=
e to
>> +   catch global and stack issues.
>> +
>> + - Inline instrumentation requires a fixed offset.
>> +
>> + - We run a lot of code at boot in real mode. This includes stuff like =
printk(),
>> +   so it's not feasible to just disable instrumentation around it.
>> +
>> + - Because of our running things in real mode, the offset has to point =
to valid
>> +   memory both in and out of real mode.
>> +
>> +This makes finding somewhere to put the KASAN shadow region a bit fun.
>> +
>> +One approach is just to give up on inline instrumentation. This way we =
can delay
>> +all checks until after we get everything set up to our satisfaction. Ho=
wever,
>> +we'd really like to do better.
>> +
>> +If we know _at compile time_ how much contiguous physical memory we hav=
e, we can
>> +set aside the top 1/8th of physical memory and use that. This is a big =
hammer
>> +and comes with 2 big consequences:
>> +
>> + - kernels will simply fail to boot on machines with less memory than s=
pecified
>> +   when compiling.
>> +
>> + - kernels running on machines with more memory than specified when com=
piling
>> +   will simply ignore the extra memory.
>> +
>> +If you can live with this, you get full support for KASAN.
>> +
>> +Tips
>> +----
>> +
>> + - Compile with CONFIG_RELOCATABLE.
>> +
>> +   In development, we found boot hangs when building with ftrace and KU=
AP. These
>> +   ended up being due to kernel bloat pushing prom_init calls to be don=
e via the
>> +   PLT. Because we did not have a relocatable kernel, and they are done=
 very
>> +   early, this caused us to jump off into somewhere invalid. Enabling r=
elocation
>> +   fixes this.
>> +
>> +NUMA/discontiguous physical memory
>> +----------------------------------
>> +
>> +We currently cannot really deal with discontiguous physical memory. You=
 are
>> +restricted to the physical memory that is contiguous from physical addr=
ess zero,
>> +and must specify the size of that memory, not total memory, when config=
uring
>> +your kernel.
>> +
>> +Discontiguous memory can occur when you have a machine with memory spre=
ad across
>> +multiple nodes. For example, on a Talos II with 64GB of RAM:
>> +
>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>> + - then there's a gap,
>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_0=
000_0000.
>> +
>> +This can create _significant_ issues:
>> +
>> + - If we try to treat the machine as having 64GB of _contiguous_ RAM, w=
e would
>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserve=
 the last
>> +   1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the shadow
>> +   region. But when we try to access any of that, we'll try to access p=
ages that
>> +   are not physically present.
>> +
>> + - If we try to base the shadow region size on the top address, we'll n=
eed to
>> +   reserve 0x2008_0000_0000 / 8 =3D 0x0401_0000_0000 bytes =3D 4100 GB =
of memory,
>> +   which will clearly not work on a system with 64GB of RAM.
>> +
>> +Therefore, you are restricted to the memory in the node starting at 0x0=
. For
>> +this system, that's 32GB. If you specify a contiguous physical memory s=
ize
>> +greater than the size of the first contiguous region of memory, the sys=
tem will
>> +be unable to boot or even print an error message warning you.
>
> Can't we restrict ourselve to the first block at startup while we are in=
=20
> real mode, but then support the entire mem once we have switched on the=
=20
> MMU ?

We could only do this if we could guarantee that all memory accessed by
KVM real mode handlers was in the the first block. I don't think I can
guarantee tihs.

>> +
>> +You can determine the layout of your system's memory by observing the m=
essages
>> +that the Radix MMU prints on boot. The Talos II discussed earlier has:
>> +
>> +radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB p=
ages (exec)
>> +radix-mmu: Mapped 0x0000000040000000-0x0000000800000000 with 1.00 GiB p=
ages
>> +radix-mmu: Mapped 0x0000200000000000-0x0000200800000000 with 1.00 GiB p=
ages
>> +
>> +As discussed, you'd configure this system for 32768 MB.
>> +
>> +Another system prints:
>> +
>> +radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB p=
ages (exec)
>> +radix-mmu: Mapped 0x0000000040000000-0x0000002000000000 with 1.00 GiB p=
ages
>> +radix-mmu: Mapped 0x0000200000000000-0x0000202000000000 with 1.00 GiB p=
ages
>> +
>> +This machine has more memory: 0x0000_0040_0000_0000 total, but only
>> +0x0000_0020_0000_0000 is physically contiguous from zero, so we'd confi=
gure the
>> +kernel for 131072 MB of physically contiguous memory.
>> +
>> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
>> index d8dcd8820369..3d6deee100e2 100644
>> --- a/arch/powerpc/Kconfig
>> +++ b/arch/powerpc/Kconfig
>> @@ -171,6 +171,10 @@ config PPC
>>   	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
>>   	select HAVE_ARCH_JUMP_LABEL
>>   	select HAVE_ARCH_KASAN			if PPC32
>> +	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU
>> +	select ARCH_HAS_KASAN_EARLY_SHADOW	if PPC_BOOK3S_64
>
> See comment on patch 1, would be better to avoid that.
>
>> +	select HAVE_ARCH_KASAN_VMALLOC		if PPC_BOOK3S_64
>> +	select KASAN_VMALLOC			if KASAN
>>   	select HAVE_ARCH_KGDB
>>   	select HAVE_ARCH_MMAP_RND_BITS
>>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
>> diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
>> index c59920920ddc..2d6fb7b1ba59 100644
>> --- a/arch/powerpc/Kconfig.debug
>> +++ b/arch/powerpc/Kconfig.debug
>> @@ -394,6 +394,27 @@ config PPC_FAST_ENDIAN_SWITCH
>>           help
>>   	  If you're unsure what this is, say N.
>>  =20
>> +config PHYS_MEM_SIZE_FOR_KASAN
>> +	int "Contiguous physical memory size for KASAN (MB)"
>> +	depends on=20
>
> Drop the depend and maybe do:
> 	int "Contiguous physical memory size for KASAN (MB)" if KASAN &&=20
> PPC_BOOK3S_64
> 	default 0
>

Done.

> Will allow you to not enclose it into #ifdef KASAN in the code below
>
>> +	help
>> +
>> +	  To get inline instrumentation support for KASAN on 64-bit Book3S
>> +	  machines, you need to know how much contiguous physical memory your
>> +	  system has. A shadow offset will be calculated based on this figure,
>> +	  which will be compiled in to the kernel. KASAN will use this offset
>> +	  to access its shadow region, which is used to verify memory accesses=
.
>> +
>> +	  If you attempt to boot on a system with less memory than you specify
>> +	  here, your system will fail to boot very early in the process. If yo=
u
>> +	  boot on a system with more memory than you specify, the extra memory
>> +	  will wasted - it will be reserved and not used.
>> +
>> +	  For systems with discontiguous blocks of physical memory, specify th=
e
>> +	  size of the block starting at 0x0. You can determine this by looking
>> +	  at the memory layout info printed to dmesg by the radix MMU code
>> +	  early in boot. See Documentation/powerpc/kasan.txt.
>> +
>>   config KASAN_SHADOW_OFFSET
>>   	hex
>>   	depends on KASAN
>> diff --git a/arch/powerpc/Makefile b/arch/powerpc/Makefile
>> index c345b79414a9..33e7bba4c8db 100644
>> --- a/arch/powerpc/Makefile
>> +++ b/arch/powerpc/Makefile
>> @@ -229,6 +229,13 @@ ifdef CONFIG_476FPE_ERR46
>>   		-T $(srctree)/arch/powerpc/platforms/44x/ppc476_modules.lds
>>   endif
>>  =20
>> +ifdef CONFIG_KASAN
>> +ifdef CONFIG_PPC_BOOK3S_64
>> +# 0xa800000000000000 =3D 12105675798371893248
>> +KASAN_SHADOW_OFFSET =3D $(shell echo 7 \* 1024 \* 1024 \* $(CONFIG_PHYS=
_MEM_SIZE_FOR_KASAN) / 8 + 12105675798371893248 | bc)
>> +endif
>> +endif
>> +
>>   # No AltiVec or VSX instructions when building kernel
>>   KBUILD_CFLAGS +=3D $(call cc-option,-mno-altivec)
>>   KBUILD_CFLAGS +=3D $(call cc-option,-mno-vsx)
>> diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/i=
nclude/asm/book3s/64/radix.h
>> index e04a839cb5b9..4c011cc15e05 100644
>> --- a/arch/powerpc/include/asm/book3s/64/radix.h
>> +++ b/arch/powerpc/include/asm/book3s/64/radix.h
>> @@ -35,6 +35,11 @@
>>   #define RADIX_PMD_SHIFT		(PAGE_SHIFT + RADIX_PTE_INDEX_SIZE)
>>   #define RADIX_PUD_SHIFT		(RADIX_PMD_SHIFT + RADIX_PMD_INDEX_SIZE)
>>   #define RADIX_PGD_SHIFT		(RADIX_PUD_SHIFT + RADIX_PUD_INDEX_SIZE)
>> +
>> +#define R_PTRS_PER_PTE		(1 << RADIX_PTE_INDEX_SIZE)
>> +#define R_PTRS_PER_PMD		(1 << RADIX_PMD_INDEX_SIZE)
>> +#define R_PTRS_PER_PUD		(1 << RADIX_PUD_INDEX_SIZE)
>> +
>
> See my suggestion in patch 1.
>
>>   /*
>>    * Size of EA range mapped by our pagetables.
>>    */
>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm=
/kasan.h
>> index 296e51c2f066..d6b4028c296b 100644
>> --- a/arch/powerpc/include/asm/kasan.h
>> +++ b/arch/powerpc/include/asm/kasan.h
>> @@ -14,13 +14,20 @@
>>  =20
>>   #ifndef __ASSEMBLY__
>>  =20
>> -#include <asm/page.h>
>> +#ifdef CONFIG_KASAN
>> +void kasan_init(void);
>> +#else
>> +static inline void kasan_init(void) { }
>> +#endif
>>  =20
>>   #define KASAN_SHADOW_SCALE_SHIFT	3
>>  =20
>>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>>   				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>>  =20
>> +#ifdef CONFIG_PPC32
>> +#include <asm/page.h>
>> +
>>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>>  =20
>>   #define KASAN_SHADOW_END	0UL
>> @@ -30,11 +37,33 @@
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
>> +#include <asm/pgtable.h>
>> +
>> +/*
>> + * The KASAN shadow offset is such that linear map (0xc000...) is shado=
wed by
>> + * the last 8th of linearly mapped physical memory. This way, if the co=
de uses
>> + * 0xc addresses throughout, accesses work both in in real mode (where =
the top
>> + * 2 bits are ignored) and outside of real mode.
>> + */
>> +#define KASAN_SHADOW_OFFSET ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
>> +				1024 * 1024 * 7 / 8 + 0xa800000000000000UL)
>
> Already calculated in the Makefile, can't we reuse it ?
>
> 'X * 1024 * 1024' is usually better understood is 'X << 20' instead.
>
>
>> +
>> +#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
>> +				1024 * 1024 * 1 / 8)
>> +
>> +extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>> +
>> +extern pte_t kasan_early_shadow_pte[R_PTRS_PER_PTE];
>> +extern pmd_t kasan_early_shadow_pmd[R_PTRS_PER_PMD];
>> +extern pud_t kasan_early_shadow_pud[R_PTRS_PER_PUD];
>> +extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>> +#endif /* CONFIG_PPC_BOOK3S_64 */
>>  =20
>>   #endif /* __ASSEMBLY */
>>   #endif
>> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process=
.c
>> index 8fc4de0d22b4..31602536e72b 100644
>> --- a/arch/powerpc/kernel/process.c
>> +++ b/arch/powerpc/kernel/process.c
>> @@ -2097,7 +2097,14 @@ void show_stack(struct task_struct *tsk, unsigned=
 long *stack)
>>   		/*
>>   		 * See if this is an exception frame.
>>   		 * We look for the "regshere" marker in the current frame.
>> +		 *
>> +		 * KASAN may complain about this. If it is an exception frame,
>> +		 * we won't have unpoisoned the stack in asm when we set the
>> +		 * exception marker. If it's not an exception frame, who knows
>> +		 * how things are laid out - the shadow could be in any state
>> +		 * at all. Just disable KASAN reporting for now.
>>   		 */
>> +		kasan_disable_current();
>>   		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
>>   		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
>>   			struct pt_regs *regs =3D (struct pt_regs *)
>> @@ -2107,6 +2114,7 @@ void show_stack(struct task_struct *tsk, unsigned =
long *stack)
>>   			       regs->trap, (void *)regs->nip, (void *)lr);
>>   			firstframe =3D 1;
>>   		}
>> +		kasan_enable_current();
>>  =20
>>   		sp =3D newsp;
>>   	} while (count++ < kstack_depth_to_print);
>> diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
>> index 7159e791a70d..dde5f2896ab6 100644
>> --- a/arch/powerpc/kernel/prom.c
>> +++ b/arch/powerpc/kernel/prom.c
>> @@ -71,6 +71,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
>>   u64 ppc64_rma_size;
>>   #endif
>>   static phys_addr_t first_memblock_size;
>> +static phys_addr_t top_phys_addr;
>>   static int __initdata boot_cpu_count;
>>  =20
>>   static int __init early_parse_mem(char *p)
>> @@ -448,6 +449,21 @@ static bool validate_mem_limit(u64 base, u64 *size)
>>   {
>>   	u64 max_mem =3D 1UL << (MAX_PHYSMEM_BITS);
>>  =20
>> +#ifdef CONFIG_KASAN
>> +	/*
>> +	 * To handle the NUMA/discontiguous memory case, don't allow a block
>> +	 * to be added if it falls completely beyond the configured physical
>> +	 * memory.
>> +	 *
>> +	 * See Documentation/powerpc/kasan.txt
>> +	 */
>> +	if (base >=3D (u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * 1024 * 1024) {
>> +		pr_warn("KASAN: not adding mem block at %llx (size %llx)",
>> +			base, *size);
>> +		return false;
>> +	}
>> +#endif
>> +
>>   	if (base >=3D max_mem)
>>   		return false;
>>   	if ((base + *size) > max_mem)
>> @@ -571,8 +587,11 @@ void __init early_init_dt_add_memory_arch(u64 base,=
 u64 size)
>>  =20
>>   	/* Add the chunk to the MEMBLOCK list */
>>   	if (add_mem_to_memblock) {
>> -		if (validate_mem_limit(base, &size))
>> +		if (validate_mem_limit(base, &size)) {
>>   			memblock_add(base, size);
>> +			if (base + size > top_phys_addr)
>> +				top_phys_addr =3D base + size;
>> +		}
>>   	}
>>   }
>>  =20
>> @@ -612,6 +631,8 @@ static void __init early_reserve_mem_dt(void)
>>   static void __init early_reserve_mem(void)
>>   {
>>   	__be64 *reserve_map;
>> +	phys_addr_t kasan_shadow_start __maybe_unused;
>> +	phys_addr_t kasan_memory_size __maybe_unused;
>
> Could we avoid those uggly __maybe_unused ?
>
>>  =20
>>   	reserve_map =3D (__be64 *)(((unsigned long)initial_boot_params) +
>>   			fdt_off_mem_rsvmap(initial_boot_params));
>> @@ -650,6 +671,40 @@ static void __init early_reserve_mem(void)
>>   		return;
>>   	}
>>   #endif
>> +
>> +#if defined(CONFIG_KASAN) && defined(CONFIG_PPC_BOOK3S_64)
>
> Would be better to do following instead of the #ifdef
>
> if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
> }
>
> This would avoid the __maybe_unused above, and would allow to valide the=
=20
> code even when CONFIG_KASAN is not selected.
>
> This would probably require to set a default value for=20
> CONFIG_PHYS_MEM_SIZE_FOR_KASAN when KASAN is not set, or maybe define an=
=20
> intermediate const somewhere in some .h which takes=20
> CONFIG_PHYS_MEM_SIZE_FOR_KASAN when KASAN is there and 0 when KASAN is=20
> not there
>
Done.

>> +	kasan_memory_size =3D ((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN
>> +		* 1024 * 1024);
>> +
>> +	if (top_phys_addr < kasan_memory_size) {
>> +		/*
>> +		 * We are doomed. Attempts to call e.g. panic() are likely to
>> +		 * fail because they call out into instrumented code, which
>> +		 * will almost certainly access memory beyond the end of
>> +		 * physical memory. Hang here so that at least the NIP points
>> +		 * somewhere that will help you debug it if you look at it in
>> +		 * qemu.
>> +		 */
>> +		while (true)
>> +			;
>
> A bit gross ?
>

It is, but I don't know how to do it better. I don't want to panic(), as
explained... What did you have in mind?

>
>> +	} else if (top_phys_addr > kasan_memory_size) {
>> +		/* print a biiiig warning in hopes people notice */
>> +		pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n"
>> +			"Physical memory exceeds compiled-in maximum!\n"
>> +			"This kernel was compiled for KASAN with %u MB physical memory.\n"
>> +			"The actual physical memory detected is %llu MB.\n"
>> +			"Memory above the compiled limit will not be used!\n"
>> +			"=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n",
>> +			CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
>> +			top_phys_addr / (1024 * 1024));
>> +	}
>> +
>> +	kasan_shadow_start =3D _ALIGN_DOWN(kasan_memory_size * 7 / 8, PAGE_SIZ=
E);
>> +	DBG("reserving %llx -> %llx for KASAN",
>> +	    kasan_shadow_start, top_phys_addr);
>> +	memblock_reserve(kasan_shadow_start,
>> +			 top_phys_addr - kasan_shadow_start);
>> +#endif
>>   }
>>  =20
>>   #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
>> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Make=
file
>> index 6577897673dd..ff8143ba1e4d 100644
>> --- a/arch/powerpc/mm/kasan/Makefile
>> +++ b/arch/powerpc/mm/kasan/Makefile
>> @@ -3,3 +3,4 @@
>>   KASAN_SANITIZE :=3D n
>>  =20
>>   obj-$(CONFIG_PPC32)           +=3D kasan_init_32.o
>> +obj-$(CONFIG_PPC_BOOK3S_64)   +=3D kasan_init_book3s_64.o
>> diff --git a/arch/powerpc/mm/kasan/kasan_init_book3s_64.c b/arch/powerpc=
/mm/kasan/kasan_init_book3s_64.c
>
> In the same spirit as what was done in other mm subdirs, could we rename=
=20
> those files to:
> init_32.o
> init_book3s64.o

Done.

>
>> new file mode 100644
>> index 000000000000..fafda3d5e9a3
>> --- /dev/null
>> +++ b/arch/powerpc/mm/kasan/kasan_init_book3s_64.c
>> @@ -0,0 +1,76 @@
>> +// SPDX-License-Identifier: GPL-2.0
>> +/*
>> + * KASAN for 64-bit Book3S powerpc
>> + *
>> + * Copyright (C) 2019 IBM Corporation
>> + * Author: Daniel Axtens <dja@axtens.net>
>> + */
>> +
>> +#define DISABLE_BRANCH_PROFILING
>> +
>> +#include <linux/kasan.h>
>> +#include <linux/printk.h>
>> +#include <linux/sched/task.h>
>> +#include <asm/pgalloc.h>
>> +
>> +unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
>
> What's the difference with what's defined in the kasan generic part and=
=20
> that you have opted out in first patch ?
>
>> +
>> +pte_t kasan_early_shadow_pte[R_PTRS_PER_PTE] __page_aligned_bss;
>> +pmd_t kasan_early_shadow_pmd[R_PTRS_PER_PMD] __page_aligned_bss;
>> +pud_t kasan_early_shadow_pud[R_PTRS_PER_PUD] __page_aligned_bss;
>> +p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
>
> See my suggestion for those in patch 1.
>
>> +
>> +void __init kasan_init(void)
>> +{
>> +	int i;
>> +	void *k_start =3D kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
>> +	void *k_end =3D kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
>> +
>> +	unsigned long pte_val =3D __pa(kasan_early_shadow_page)
>> +					| pgprot_val(PAGE_KERNEL) | _PAGE_PTE;
>> +
>> +	if (!early_radix_enabled())
>> +		panic("KASAN requires radix!");
>> +
>> +	for (i =3D 0; i < PTRS_PER_PTE; i++)
>> +		kasan_early_shadow_pte[i] =3D __pte(pte_val);
>
> Shouldn't you use __set_pte_at() here ?
>
Yes, done.

>> +
>> +	for (i =3D 0; i < PTRS_PER_PMD; i++)
>> +		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
>> +				    kasan_early_shadow_pte);
>> +
>> +	for (i =3D 0; i < PTRS_PER_PUD; i++)
>> +		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
>> +			     kasan_early_shadow_pmd);
>> +
>> +
>> +	memset(kasan_mem_to_shadow((void *)PAGE_OFFSET), KASAN_SHADOW_INIT,
>> +		KASAN_SHADOW_SIZE);
>> +
>> +	kasan_populate_early_shadow(
>> +		kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START),
>> +		kasan_mem_to_shadow((void *)RADIX_VMALLOC_START));
>> +
>> +	/* leave a hole here for vmalloc */
>> +
>> +	kasan_populate_early_shadow(
>> +		kasan_mem_to_shadow((void *)RADIX_VMALLOC_END),
>> +		kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END));
>> +
>> +	flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);
>> +
>> +	/* mark early shadow region as RO and wipe */
>> +	for (i =3D 0; i < PTRS_PER_PTE; i++)
>> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
>> +			&kasan_early_shadow_pte[i],
>> +			pfn_pte(virt_to_pfn(kasan_early_shadow_page),
>> +			__pgprot(_PAGE_PTE | _PAGE_KERNEL_RO | _PAGE_BASE)),
>
> Isn't there an already existing val for the above set of flags ?
>
See if you like the simplified version in v2.

>> +			0);
>> +	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>> +
>> +	kasan_init_tags();
>
> You said in the doc that only arm supports that ...
>
Indeed - serves me right for copying arm code!

Regards,
Daniel

>> +
>> +	/* Enable error messages */
>> +	init_task.kasan_depth =3D 0;
>> +	pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
>> +}
>>=20
>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/878snkdauf.fsf%40dja-thinkpad.axtens.net.
