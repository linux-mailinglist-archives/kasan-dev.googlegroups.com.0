Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQHYYPXQKGQEN2P2VNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D126E11AD5E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 15:25:06 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d24sf1763546pll.14
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 06:25:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576074305; cv=pass;
        d=google.com; s=arc-20160816;
        b=0/fkfiby5xk9E0RBRwJ3CQ+WKHQ0ksAUEj5veXl7wT0/KtCae096DrTzCriCTL4c1n
         VPQMe6zN1Z0zLAf8C4IuZrpal6tGfBpQ157eCm4gJtlcs+kzUWBvLEo54v8pymYVkZjR
         JlqktpTIUduCFrNI+4fdbs27jyYoKiYRxet5Tqs85Pp+/Pfufgg7Bh1QTB1cQ/Kej64g
         F7wCCFVXK2pR7VX9vjRCWQxSCjNFfVb+FwZyLGRSnQsVeUGCxG86oupwGlKecVG34KAw
         HIgLtFb3h34fh4RqueMdd91wbpiuz6b6l7NGrwNDtVoV6j5UpjQbhJ2coY4ws2JTrMEK
         VnHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:to:from
         :sender:dkim-signature;
        bh=f4VSYIgxE9olFhpZBB2FHAN6rAgFvcMi0MEvSNtgkRg=;
        b=eYTzl+YW17HuDKYShEpwRToC276MCdxCjG0GowIKCGBNMgjofUxLL5N1weSCjlUeJn
         vf4gHPup8xkmrTNfGxDedoBuKkh8D+9vW2UXz3L9a9ApSJrUfgJ2ZdLPDJ3w9Q9HvGcH
         Ew0oFVrPoCBr5AZZMHSkDYKitKn4CRRUOyG/EW1MAm0FUWdxXGaEtOhZCaR1Lv+ftVQo
         EfFVTiL5rkURWx7Bn1UucUZ592pWQ+ymbBqlc6E4T9L7ezo0Q2z3GV5dUtBU+qqrwWk9
         o+cUP03g8bYt5bkzDQdcf3jPoIwdMuqmCa4NR1ACkaGJ6XEgMjbvVvre/L7RFmgEjXP1
         ufXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bFMQWnI1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f4VSYIgxE9olFhpZBB2FHAN6rAgFvcMi0MEvSNtgkRg=;
        b=sJi3XW35QAJzaFBIeb383OCLMK2lJ5LqPiABIM3997Pex+v06fPbyQ+oFNthoi9sv6
         kmmWSn2LBguREMBparrC2V6Ff3H+09xm9Lg8eZepmqG3j9K3UeSAEAVOO5AMbeNVQFgI
         DvstgoSqrM5rb+EktL1Jq9nVWgoBNWxRh3BLa5GvjOCbhqRlCAEHQAmPMN9WtU7BBALW
         0T6AbBN9x4BNA3plNO+G3Soy83q1p2+s4bnI901yRUpArRnKQhCNEQrFWXGjcpNv///h
         //2TFoayLytNlEjS5OGZPsJYI2DmXN3yaWeIPCNw/VNiBIjHbnpVjcZthr3090x8+IJ8
         Y1ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f4VSYIgxE9olFhpZBB2FHAN6rAgFvcMi0MEvSNtgkRg=;
        b=N8R3LpdJmn+6V1UQcupmdrxF17w0kytgaaviD042YOA7uy1WbLOso5RZjtMIqGUZLo
         ThNJc6f9peH/roJqa+XlsjbBuXyDsxts4YWUXcsHwhO2OhCEgFVU646uwdUGXTCq0XH6
         ILkJOsr3CTnz1PXWuv1ocCLgM33gN35l3Y0rNeOUBLPFHzzg0JJOL07VzeYFPOzC2sVu
         Y2PBI9yuYAoFoCrK9Que4cRGMhrkFtL4/qa+9eLsqWxav2nnB7v6zl2r5BSREha2VkgE
         idAwk6LMsFlB4pNwMgUSJtA4/Nb5iKVL0u3GTu9z/wawlakd4SWNiEmFNVDHUwVOqedc
         GobQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVakHz3H16stXU7hkerVNmC836rFdTPhONawIKrxqn6c6bah8Zj
	qExJJAYdyKNi8oepeRheJqk=
X-Google-Smtp-Source: APXvYqwQv23tdqHI8TW7Td6qh28WVTe+RBf5WAtlXNaj+FfyGa8lDObwtSjLl7z+vOmVwc35jdFPmQ==
X-Received: by 2002:a63:6b07:: with SMTP id g7mr4326752pgc.243.1576074304650;
        Wed, 11 Dec 2019 06:25:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:47c3:: with SMTP id f3ls559847pgs.10.gmail; Wed, 11 Dec
 2019 06:25:04 -0800 (PST)
X-Received: by 2002:a65:55cc:: with SMTP id k12mr4554541pgs.184.1576074304154;
        Wed, 11 Dec 2019 06:25:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576074304; cv=none;
        d=google.com; s=arc-20160816;
        b=r9YNkmhc08mCJ95uIEoHJzHtw+RpN5XOtZIb1aif2vE1RU1amJvfrtkcS/QgyTnHyH
         9Hrznc8O7HHbpQMHvNhj3xKf7EGvtEhOrCcbFGOslGFLYqzsq2opr5meXy2JUWj7vHm6
         z80mtDf/hWfbN9pzoQd5outKcfG9JgVRHpAbctqGDaCJPjCDZrwJF13PPu1eqpz7kuwv
         jnoiKICjsjDyVYRhFwCWLmQCe3uD9uEIIFauSlB7L4LFitPk1Vwqu3LejQnFPzyN3I2c
         zGoUezBg7/JF+G9QVP+votF3Z+agHOkeyuZSa407/a2NvDCJUf3f7qtDYL21TrGXvTJh
         gKiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=098L4qWOo/dhHj7up13Q/6AGsTiEtq7zvqd33y20xho=;
        b=tpEX/hPE3ChZJh9500/EilwJ/ULRc0anPGagQGc/+JQDBq1Xnoh4Nj00kHu/XbwNv4
         656KXhCXlEraab+cS7qi2I8Ot9P0sQb7jVaVkoJ2I6mqVr+TAqKCAuyYWYp3CSwcyf4s
         gl/oWJg/3HgwLiz5K0iPsImjf78VcfLfltyMkKjfBY1kfeSuH96E9igfX4W83HYu7LLS
         zhEIcysN+dd5+ymBJOltM4d15Y8HPJm0gF5PnR38Y8xGoAEtK/tSy5Lat3tJIX29h3De
         /i1hTCc0Cly50NgE4cA3uHPS0rxkhIoxpkUHuH49vxZnQ5dDYQymha8+faQA1byGXd2U
         8tdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bFMQWnI1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id j2si141067pfi.1.2019.12.11.06.25.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 06:25:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id z124so10828236pgb.13
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 06:25:04 -0800 (PST)
X-Received: by 2002:a65:6916:: with SMTP id s22mr4325069pgq.244.1576074303700;
        Wed, 11 Dec 2019 06:25:03 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b116-2689-a4a9-76f8.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b116:2689:a4a9:76f8])
        by smtp.gmail.com with ESMTPSA id j16sm3395784pfi.165.2019.12.11.06.25.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Dec 2019 06:25:02 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Balbir Singh <bsingharora@gmail.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org, linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, christophe.leroy@c-s.fr, aneesh.kumar@linux.ibm.com, Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <2e0f21e6-7552-815b-1bf3-b54b0fc5caa9@gmail.com>
References: <20191210044714.27265-1-dja@axtens.net> <20191210044714.27265-5-dja@axtens.net> <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com> <875zincu8a.fsf@dja-thinkpad.axtens.net> <2e0f21e6-7552-815b-1bf3-b54b0fc5caa9@gmail.com>
Date: Thu, 12 Dec 2019 01:24:59 +1100
Message-ID: <87wob3aqis.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=bFMQWnI1;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Transfer-Encoding: quoted-printable
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

Hi Balbir,

>>>> +Discontiguous memory can occur when you have a machine with memory sp=
read
>>>> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
>>>> +
>>>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>>>> + - then there's a gap,
>>>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008=
_0000_0000
>>>> +
>>>> +This can create _significant_ issues:
>>>> +
>>>> + - If we try to treat the machine as having 64GB of _contiguous_ RAM,=
 we would
>>>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reser=
ve the
>>>> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the=
 shadow
>>>> +   region. But when we try to access any of that, we'll try to access=
 pages
>>>> +   that are not physically present.
>>>> +
>>>
>>> If we reserved memory for KASAN from each node (discontig region), we m=
ight survive
>>> this no? May be we need NUMA aware KASAN? That might be a generic chang=
e, just thinking
>>> out loud.
>>=20
>> The challenge is that - AIUI - in inline instrumentation, the compiler
>> doesn't generate calls to things like __asan_loadN and
>> __asan_storeN. Instead it uses -fasan-shadow-offset to compute the
>> checks, and only calls the __asan_report* family of functions if it
>> detects an issue. This also matches what I can observe with objdump
>> across outline and inline instrumentation settings.
>>=20
>> This means that for this sort of thing to work we would need to either
>> drop back to out-of-line calls, or teach the compiler how to use a
>> nonlinear, NUMA aware mem-to-shadow mapping.
>
> Yes, out of line is expensive, but seems to work well for all use cases.

I'm not sure this is true. Looking at scripts/Makefile.kasan, allocas,
stacks and globals will only be instrumented if you can provide
KASAN_SHADOW_OFFSET. In the case you're proposing, we can't provide a
static offset. I _think_ this is a compiler limitation, where some of
those instrumentations only work/make sense with a static offset, but
perhaps that's not right? Dmitry and Andrey, can you shed some light on
this?

Also, as it currently stands, the speed difference between inline and
outline is approximately 2x, and given that we'd like to run this
full-time in syzkaller I think there is value in trading off speed for
some limitations.

> BTW, the current set of patches just hang if I try to make the default
> mode as out of line

Do you have CONFIG_RELOCATABLE?

I've tested the following process:

# 1) apply patches on a fresh linux-next
# 2) output dir
mkdir ../out-3s-kasan

# 3) merge in the relevant config snippets
cat > kasan.config << EOF
CONFIG_EXPERT=3Dy
CONFIG_LD_HEAD_STUB_CATCH=3Dy

CONFIG_RELOCATABLE=3Dy

CONFIG_KASAN=3Dy
CONFIG_KASAN_GENERIC=3Dy
CONFIG_KASAN_OUTLINE=3Dy

CONFIG_PHYS_MEM_SIZE_FOR_KASAN=3D2048
EOF

ARCH=3Dpowerpc CROSS_COMPILE=3Dpowerpc64-linux-gnu- ./scripts/kconfig/merge=
_config.sh -O ../out-3s-kasan/ arch/powerpc/configs/pseries_defconfig arch/=
powerpc/configs/le.config kasan.config

# 4) make
make O=3D../out-3s-kasan/ ARCH=3Dpowerpc CROSS_COMPILE=3Dpowerpc64-linux-gn=
u- -j8 vmlinux

# 5) test
qemu-system-ppc64  -m 2G -M pseries -cpu power9  -kernel ../out-3s-kasan/vm=
linux  -nographic -chardev stdio,id=3Dcharserial0,mux=3Don -device spapr-vt=
y,chardev=3Dcharserial0,reg=3D0x30000000 -initrd ./rootfs-le.cpio.xz -mon c=
hardev=3Dcharserial0,mode=3Dreadline -nodefaults -smp 4=20

This boots fine for me under TCG and KVM, with both CONFIG_KASAN_OUTLINE
and CONFIG_KASAN_INLINE. You do still need to supply the size even in
outline mode - I don't have code that switches over to vmalloced space
when in outline mode. I will clarify the docs on that.


>>>> +	if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
>>>> +		kasan_memory_size =3D
>>>> +			((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
>>>> +
>>>> +		if (top_phys_addr < kasan_memory_size) {
>>>> +			/*
>>>> +			 * We are doomed. Attempts to call e.g. panic() are
>>>> +			 * likely to fail because they call out into
>>>> +			 * instrumented code, which will almost certainly
>>>> +			 * access memory beyond the end of physical
>>>> +			 * memory. Hang here so that at least the NIP points
>>>> +			 * somewhere that will help you debug it if you look at
>>>> +			 * it in qemu.
>>>> +			 */
>>>> +			while (true)
>>>> +				;
>>>
>>> Again with the right hooks in check_memory_region_inline() these are re=
coverable,
>>> or so I think
>>=20
>> So unless I misunderstand the circumstances in which
>> check_memory_region_inline is used, this isn't going to help with inline
>> instrumentation.
>>=20
>
> Yes, I understand. Same as above?

Yes.

>>> NOTE: I can't test any of these, well may be with qemu, let me see if I=
 can spin
>>> the series and provide more feedback
>>=20
>> It's actually super easy to do simple boot tests with qemu, it works fin=
e in TCG,
>> Michael's wiki page at
>> https://github.com/linuxppc/wiki/wiki/Booting-with-Qemu is very helpful.
>>=20
>> I did this a lot in development.
>>=20
>> My full commandline, fwiw, is:
>>=20
>> qemu-system-ppc64  -m 8G -M pseries -cpu power9  -kernel ../out-3s-radix=
/vmlinux  -nographic -chardev stdio,id=3Dcharserial0,mux=3Don -device spapr=
-vty,chardev=3Dcharserial0,reg=3D0x30000000 -initrd ./rootfs-le.cpio.xz -mo=
n chardev=3Dcharserial0,mode=3Dreadline -nodefaults -smp 4
>
> qemu has been crashing with KASAN enabled/ both inline/out-of-line option=
s. I am running linux-next + the 4 patches you've posted. In one case I get=
 a panic and a hang in the other. I can confirm that when I disable KASAN, =
the issue disappears

Hopefully my script above can help narrow that down.

Regards,
Daniel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87wob3aqis.fsf%40dja-thinkpad.axtens.net.
