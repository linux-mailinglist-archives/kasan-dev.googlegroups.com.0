Return-Path: <kasan-dev+bncBDQ27FVWWUFRB6XZYHXQKGQEQUPNVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4690E11A3B6
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 06:22:04 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id f186sf5916969ybf.22
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 21:22:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576041723; cv=pass;
        d=google.com; s=arc-20160816;
        b=EPK6CbvtD5ZiV5ruhsdpfFpvexDvvT/Bcwq11ujVWKxjydgW3Ze5n8I6eiUdGbsZ1H
         0eaXUQikdA6EGHJEq81lqCKDWDumoDm4oxojOOtML6LmPDLghZcB9AxuSL101pSp4ZEz
         USg1zCFRTbDeEJFb/HeEt5YFEXFwYAPppsO0EPnNUTWVwk+RtakZqlVXnD7F3FNLkN/f
         JarN03dADm1EoGRwv56CB7ICFsptsiXIVLzUnqWL0DZW0pNZvQ+aPS3t5tjtMvm9Bwuc
         azHFuU1X4ih/VGewh30jr0IyuhEAjCa2oFjeUVlX//2Myndk/WU/bxNdabi1b7auW71T
         ZJfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:to:from
         :sender:dkim-signature;
        bh=9KEUQ/SgGuQMA3ZUo8jCebRv61Az/mov3qmBNGuBg3U=;
        b=PawgMpzLT6IA5OjpF4RQK+GpdTeS7fNLEZaANwe3SAsPJGYioiNIWpzYva27bAC+vE
         +D1emSj8kgDH7QhySyiZ1R+JfxSlhdXc8Ksn9B6k3u/x1LSFWut9AdgIRAZP1XEv4Lvt
         RyWspFVUCyf1Y3DRij1B+fFmVbMJMV2GCZL8+yHN8wOgeLtBEXu1LoPa08jRj1nHQh7n
         lC2tOJF2c5A/m0mH91bhqp/j4YSte8e0ZxzlGP9eeynXZ4RxEu/P8Bb1l1xn1OzTLhIP
         wCTh+X/6D5gDb9LBeQu5SYvFh+rlBCRxbAiqxAAQ6TNNQYLbmYyzprUbnXzp0C9TEdHo
         g1dQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=d+vkKjwN;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9KEUQ/SgGuQMA3ZUo8jCebRv61Az/mov3qmBNGuBg3U=;
        b=XzSiZy+xo3rbHOORncUABL8zbZ8tdYGjpoIqSPsPDlwYXloH8xnjs4nDJRaBpXFh7+
         C+imXUUO6Ln2Ek6cE/F6vENv0t0oOK95xGOLZNsXdR9Y8LOID6QLJfjvUZ2ekWLGatWz
         dhdtDq5tFDDC7/QukaI7oUPwavZ4W++L6HvPfl/J1FGxlccvjg5uufQVI/gKouwJRtVA
         PRPNx4bxxyxXtaQ9tEQNKeTGhZW88IYF/JDPKixIATMuUTbOUbj8p20vO3+VDSS3x4/G
         7UN34I7lAD6nTG3YBDajk1YZqchDGgQULcnFaPtAWRX+SUZJBHC4r1rwE8pMGAOFoVdC
         m/Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9KEUQ/SgGuQMA3ZUo8jCebRv61Az/mov3qmBNGuBg3U=;
        b=AI5RdYzOMle4dMbl6qP/oOfggX4khp/3rGJk4Qpvex9vwxBM7ny5eUeRCfld803ZqB
         D88ljw04snYzW8X4VPtCqYQ8xmJvie8lLxcX4n/os/Oo28MKApKAaJRT/sUVbA5tZEVQ
         hGpCW0P7v4PSwoRIiOuG59l3MnMHl91qAAK/rXND4fESnhDbTOB+zS9pGklQuITRG2+I
         ZxaV+HViGyAyGhZzuab+bWW73Q1SgxYxYxNrq1ZkhmYWIoTQz7glZefkwgFkCh4yqZ0T
         n3XsGlf1RR5ojHAUK21DX/JGjFXBva724pvNfzsPPKa62w3zce02c5pJrfB2P8/c+GAQ
         VRQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUyPUiCgJXqFdwuaGy3JrCwnKg2cMROnfJXiSeHV/xcrYyD81bZ
	tY//SKO2Yj/c62nDg+d3Mnw=
X-Google-Smtp-Source: APXvYqyGfaeC75qHZYPkRBHZzBBTo42rp1cYOnLtj0byANcqjeGyU+CtGytkujVOJhJ35bm/HV7kzw==
X-Received: by 2002:a81:6656:: with SMTP id a83mr755610ywc.508.1576041722810;
        Tue, 10 Dec 2019 21:22:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:2d5:: with SMTP id 204ls101043ywc.0.gmail; Tue, 10 Dec
 2019 21:22:02 -0800 (PST)
X-Received: by 2002:a81:79c2:: with SMTP id u185mr929152ywc.313.1576041722366;
        Tue, 10 Dec 2019 21:22:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576041722; cv=none;
        d=google.com; s=arc-20160816;
        b=aSErRAh6PGHvZwkL8qcDcPEamkpIp0kG6L/7tIMM9zQB14jX+diwsThPqjn8v+q457
         Sv1cEYZti8nk/+zQhVF5Hdtg/s089KVxS6MBQeKrDA1jUFx/2p8vDiiuZlA8y6DRPyhn
         dhmJvToUm7e3XgjKQX1316SLLdqB3XzhwnZnhda7iijzSD+5C8E3f9fVU9xbwXX7lrhq
         u3pqWB1x1YSTR3hflQMsqtL6GUi/2xNT4hlbzK1uOhkP+eZsq4pMhDZrVo+yJXsvEU1g
         QDC+7aqPz8Y5dnuJ/P/yGKHcBW1sPk5DURZjDI9EBLCFMNkE4XZlHlaISDiOIdzYcO/l
         ZLBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=OGsdV5jSDDEFcnOk4gJS+m/O081C8UQbyskvOH4VTPw=;
        b=0Dd4NGqBWYzktDGedmMLrCAswrSDwq+6amudx+/Ncq1QDajJJLr2TfB1GjkACfuHt8
         chEAli1FKWmHszC5prX9HFKim9qM0F5pBr+pbBJgUkX3Yg2UYSXUseXYz5gp/dUgZFPb
         SiiUTrFoLUw3kzy1iBEPhcloa81QTQnpnjumHd/N2yKJxKqlmzZ50VpOiqGT4iyO8Bqi
         oJfUI7V7qi25vStbi2FCwpNBNLhmsvcpYinPZONXl4v4PZawZq2Y4Xgxw3w0ukOsa7sU
         k4S9yAOoCOXFwf5IC2z04EO9OZMFN4jg1s6wNfwi1h3h3BL1b1SQSR8/p+KumM814her
         qZvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=d+vkKjwN;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s64si50885ywf.0.2019.12.10.21.22.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Dec 2019 21:22:02 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id x185so1190878pfc.5
        for <kasan-dev@googlegroups.com>; Tue, 10 Dec 2019 21:22:02 -0800 (PST)
X-Received: by 2002:a63:5d4d:: with SMTP id o13mr2058179pgm.182.1576041721369;
        Tue, 10 Dec 2019 21:22:01 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-899f-c50f-5647-b1f9.static.ipv6.internode.on.net. [2001:44b8:1113:6700:899f:c50f:5647:b1f9])
        by smtp.gmail.com with ESMTPSA id y62sm966374pfg.45.2019.12.10.21.21.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Dec 2019 21:22:00 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Balbir Singh <bsingharora@gmail.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org, linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, christophe.leroy@c-s.fr, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com>
References: <20191210044714.27265-1-dja@axtens.net> <20191210044714.27265-5-dja@axtens.net> <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com>
Date: Wed, 11 Dec 2019 16:21:57 +1100
Message-ID: <875zincu8a.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=d+vkKjwN;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

>> +Discontiguous memory can occur when you have a machine with memory spre=
ad
>> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
>> +
>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>> + - then there's a gap,
>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_0=
000_0000
>> +
>> +This can create _significant_ issues:
>> +
>> + - If we try to treat the machine as having 64GB of _contiguous_ RAM, w=
e would
>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserve=
 the
>> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the s=
hadow
>> +   region. But when we try to access any of that, we'll try to access p=
ages
>> +   that are not physically present.
>> +
>
> If we reserved memory for KASAN from each node (discontig region), we mig=
ht survive
> this no? May be we need NUMA aware KASAN? That might be a generic change,=
 just thinking
> out loud.

The challenge is that - AIUI - in inline instrumentation, the compiler
doesn't generate calls to things like __asan_loadN and
__asan_storeN. Instead it uses -fasan-shadow-offset to compute the
checks, and only calls the __asan_report* family of functions if it
detects an issue. This also matches what I can observe with objdump
across outline and inline instrumentation settings.

This means that for this sort of thing to work we would need to either
drop back to out-of-line calls, or teach the compiler how to use a
nonlinear, NUMA aware mem-to-shadow mapping.

I'll document this a bit better in the next spin.

>> +	if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
>> +		kasan_memory_size =3D
>> +			((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
>> +
>> +		if (top_phys_addr < kasan_memory_size) {
>> +			/*
>> +			 * We are doomed. Attempts to call e.g. panic() are
>> +			 * likely to fail because they call out into
>> +			 * instrumented code, which will almost certainly
>> +			 * access memory beyond the end of physical
>> +			 * memory. Hang here so that at least the NIP points
>> +			 * somewhere that will help you debug it if you look at
>> +			 * it in qemu.
>> +			 */
>> +			while (true)
>> +				;
>
> Again with the right hooks in check_memory_region_inline() these are reco=
verable,
> or so I think

So unless I misunderstand the circumstances in which
check_memory_region_inline is used, this isn't going to help with inline
instrumentation.

>> +void __init kasan_init(void)
>> +{
>> +	int i;
>> +	void *k_start =3D kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
>> +	void *k_end =3D kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
>> +
>> +	pte_t pte =3D __pte(__pa(kasan_early_shadow_page) |
>> +			  pgprot_val(PAGE_KERNEL) | _PAGE_PTE);
>> +
>> +	if (!early_radix_enabled())
>> +		panic("KASAN requires radix!");
>> +
>
> I think this is avoidable, we could use a static key for disabling kasan =
in
> the generic code. I wonder what happens if someone tries to boot this
> image on a Power8 box and keeps panic'ing with no easy way of recovering.

Again, assuming I understand correctly that the compiler generates raw
IR->asm for these checks rather than calling out to a function, then I
don't think we get a way to intercept those checks. It's too late to do
anything at the __asan report stage because that will already have
accessed memory that's not set up properly.

If you try to boot this on a Power8 box it will panic and you'll have to
boot into another kernel from the bootloader. I don't think it's
avoidable without disabling inline instrumentation, but I'd love to be
proven wrong.

>
> NOTE: I can't test any of these, well may be with qemu, let me see if I c=
an spin
> the series and provide more feedback

It's actually super easy to do simple boot tests with qemu, it works fine i=
n TCG,
Michael's wiki page at
https://github.com/linuxppc/wiki/wiki/Booting-with-Qemu is very helpful.

I did this a lot in development.

My full commandline, fwiw, is:

qemu-system-ppc64  -m 8G -M pseries -cpu power9  -kernel ../out-3s-radix/vm=
linux  -nographic -chardev stdio,id=3Dcharserial0,mux=3Don -device spapr-vt=
y,chardev=3Dcharserial0,reg=3D0x30000000 -initrd ./rootfs-le.cpio.xz -mon c=
hardev=3Dcharserial0,mode=3Dreadline -nodefaults -smp 4

Regards,
Daniel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/875zincu8a.fsf%40dja-thinkpad.axtens.net.
