Return-Path: <kasan-dev+bncBAABBQHZTH7AKGQEEHHQWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7602C2CA98A
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 18:26:25 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id f2sf1433340lfm.3
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 09:26:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606843585; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpxAz4cUi1EAeNVrNdrpa+LCcN3jzOeKk+QZHBSb3+LVYbwrdJKc/u2n+D9pV+3fCf
         cylDss8BkOLVsJct8be3fkJJ3wdQGP+oNTv21ya6zNNss0dWafWEBeSWt8VVdL+0rGSn
         n5IjiWJCXWBkYZtrmWscAlDsHde8EcFCv25vtgcHq7Fn5qxivE3RJ8uCFsakDVvgGSiT
         HrRNAAlHvGbIk7Y2goDzRy1xEd8K078sWPfjRxWE/hr1O+/JZw0Z7y5oy9nEMHDRm3/L
         LK27djRId256z/lskXxqoGR2Eve75FhQIdAGKK9cVzB3cXesbcq99/n96z3v80IQjLkl
         0LUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=Nb77Ij8fTgpTOhc/uGPBL6MGZw5J9Sw1aNTZ/9oo+Fs=;
        b=uN/uLMzeu7jgllOiaJMPOhI4uJGx8ognDH90UxDDZXjenEnukiqyhBcCZ4vsebbWnS
         atFzGB179Oi8l/jLO0CXM81dXFGO3vh3/wB2b3D2oHH1uwWRMIuLkNOIsf1SlxQJGSnb
         20Y2+cm5CMbQKz9XpcVmcdlmvvywzB4dzQ14FrBVbW9Z+6A4JpQe/oifPbBz2zeIQ+jP
         KALdQWuBl3sEqLzBDTPHGEP8vP9t0SrO3ttvsnjeVGD/OcjxkpUrD1USQUy2ZOpZh1R5
         OMVJpG8tlPWlBym9V0EoPH0gSWAkiKuXlqSXMZh0HhDqW2RutfJHqaLNcRzwBFjz9Fvv
         IjUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nb77Ij8fTgpTOhc/uGPBL6MGZw5J9Sw1aNTZ/9oo+Fs=;
        b=F9u4McxWxmBeCFV+ymx2CNT1Izgsi9nhBTiXtfTA4T9aVMeD2OuUPQpNLZVaajigee
         xCVbNzqB5vwGezLNWgIKhe2h0ajIyih+RVfmVf7fiI7twHEuqk/5LoqPaTOlSzIJ/Xi4
         Uhi+cFDjmS1Ws3Zorjv5L6N1MwQ2gct3JyN/k4v/8UOhef/NRiRtpP/GdAvlG3lBBFDP
         XOcelmDNMH+lVXg1aoUdIxhI+L3/osrYajeV4rgAU2Dp9YkYQypAaMeZwQsnHWm5F48J
         vhtyek4fSEpDooL1Iion0+eYpiUmcej7TcQbyvHfZqfKAbmq+pbLhXpwP+fyaMN3OQ5o
         QY8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nb77Ij8fTgpTOhc/uGPBL6MGZw5J9Sw1aNTZ/9oo+Fs=;
        b=p24wDBrLtCd8PSF0lZAcCXeBk4SRdX5J7hLM0RUuUVf2cQtwOPPuEcgOGLYTfm/sEx
         K+OzOz0uZRu4GIGreNOJ/HV70Fzkmoe4Jn3jyPDmUAxK8FxuwrVfwCs8FxjBwVnVQQgv
         CQRj+x+vtnLIna0NzXGvDpt3RG9u25MV+N0r2cdDdHoGnk+e9PrCk1voYjzqvs85KUmN
         yqzzGRpYjsDzdxIIWE6A0sRc2xWaYbcU/nXRt+lHe79YT0ZvUomGn4Fzhdc1IGShhkxk
         pd+XQynChQt4nm0ZydKsIFHoYg9rnQM3uyTkToT2u5sI6pKUP61+ufK18vKyl6jJSFJt
         h3QQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dUresuvgMt20ZJKpVoat+uoz2NiPdouEuAqXkOvoaGlKP10Wh
	ENHH1K86gjl4nwLZ8uvqgLg=
X-Google-Smtp-Source: ABdhPJwd4Z463LJG4U0wgbBeTM1pN7qWLBvFV84hesAANjUI0XLoF2/dajmrbes9ZPIHVEJq/BzwVw==
X-Received: by 2002:ac2:5e9e:: with SMTP id b30mr1758330lfq.145.1606843584922;
        Tue, 01 Dec 2020 09:26:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a02:: with SMTP id q2ls2158632lfn.1.gmail; Tue, 01 Dec
 2020 09:26:23 -0800 (PST)
X-Received: by 2002:ac2:5939:: with SMTP id v25mr1703977lfi.490.1606843583741;
        Tue, 01 Dec 2020 09:26:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606843583; cv=none;
        d=google.com; s=arc-20160816;
        b=riryXZ02t2kJeUXcCy5+MXzJXmhfxpiriHcPF8w1mwRVFzmHzEHSw+gLZO9HBdTxdA
         6wbET0VhNVq0ScfxFSLL86eTuYQdNSHlnYwGpp4P3YbtUaOB6yNyLZxu+5dSRqfKce1q
         U/AjOC92jm6N7sC+j7VSTj9Spi2oAy145MqLoYQhVINGKiFcXpOevzTwk0c07Q363mMQ
         B5nZlOgfnzunFqAByYnhuTNEHCghv2zZnomL7vG5NgwLAxuPNCD5qdEsyfOUHX1GHTNE
         9YHbUGPTvwU5L9R0Ji+jNyZlkF5h6+8Z2bfFPv9isLD0OsPyi9KNQG9LOrsGblLqaydT
         9Miw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=gQ4HX/pP63opNu317tzRsipCAWxUR4mxzLX28A2Z0vI=;
        b=eaEylswhdj2yhyzSWiA9z8MoK0rrOUJ5JeKxNNyqaE4qYss5wgndEgR/OpxTzOfIpL
         RQ7zxyhPG4YV+ojyKzQva70jDvchsvQP0FwDhFoL/89mAsJyPgyFP3XaH9N/tiFoIslX
         0FUMyuFndFxGny56eWlcRtGoxRFGIB6cBYN/CHyFqEQ/PcvxG7b398tqUUkC64fGkwYR
         ux9PvVcqZHbTuGLzyvyixcesfzqL9NtRPm1X93QkDl4N+syURv7+74OyzrHILjIVznuU
         R1hydO4zfOgSN2GtniUfuoUac1+4KbGXB5K7+4/ON/gTRcdrBMDC2ZYV7+oBM3issdjP
         3EWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i12si17761lfl.0.2020.12.01.09.26.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 09:26:23 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Clpt35jHLz9tygF;
	Tue,  1 Dec 2020 18:26:19 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id ULjWeckRBOf2; Tue,  1 Dec 2020 18:26:19 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Clpt322c5z9tygD;
	Tue,  1 Dec 2020 18:26:19 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EB77A8B7B9;
	Tue,  1 Dec 2020 18:26:20 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id aRnYwt3H2Bn0; Tue,  1 Dec 2020 18:26:20 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 10E648B7B7;
	Tue,  1 Dec 2020 18:26:20 +0100 (CET)
Subject: Re: [PATCH v9 6/6] powerpc: Book3S 64-bit outline-only KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20201201161632.1234753-1-dja@axtens.net>
 <20201201161632.1234753-7-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <251530bd-49ab-4d6e-13bc-03f97edafcc4@csgroup.eu>
Date: Tue, 1 Dec 2020 18:26:04 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <20201201161632.1234753-7-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 01/12/2020 =C3=A0 17:16, Daniel Axtens a =C3=A9crit=C2=A0:
> Implement a limited form of KASAN for Book3S 64-bit machines running unde=
r
> the Radix MMU, supporting only outline mode.
>=20
>   - Enable the compiler instrumentation to check addresses and maintain t=
he
>     shadow region. (This is the guts of KASAN which we can easily reuse.)
>=20
>   - Require kasan-vmalloc support to handle modules and anything else in
>     vmalloc space.
>=20
>   - KASAN needs to be able to validate all pointer accesses, but we can't
>     instrument all kernel addresses - only linear map and vmalloc. On boo=
t,
>     set up a single page of read-only shadow that marks all iomap and
>     vmemmap accesses as valid.
>=20
>   - Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
>     generic code, arm64, s390 and x86 all do this for similar sorts of
>     reasons: when unwinding a stack, we might touch memory that KASAN has
>     marked as being out-of-bounds. In our case we often get this when
>     checking for an exception frame because we're checking an arbitrary
>     offset into the stack frame.
>=20
>     See commit 20955746320e ("s390/kasan: avoid false positives during st=
ack
>     unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
>     frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
>     Prevent KASAN false positive warnings") and commit 6e22c8366416
>     ("tracing, kasan: Silence Kasan warning in check_stack of stack_trace=
r")
>=20
>   - Document KASAN in both generic and powerpc docs.
>=20
> Background
> ----------
>=20
> KASAN support on Book3S is a bit tricky to get right:
>=20
>   - It would be good to support inline instrumentation so as to be able t=
o
>     catch stack issues that cannot be caught with outline mode.
>=20
>   - Inline instrumentation requires a fixed offset.
>=20
>   - Book3S runs code with translations off ("real mode") during boot,
>     including a lot of generic device-tree parsing code which is used to
>     determine MMU features.
>=20
>      [ppc64 mm note: The kernel installs a linear mapping at effective
>      address c000...-c008.... This is a one-to-one mapping with physical
>      memory from 0000... onward. Because of how memory accesses work on
>      powerpc 64-bit Book3S, a kernel pointer in the linear map accesses t=
he
>      same memory both with translations on (accessing as an 'effective
>      address'), and with translations off (accessing as a 'real
>      address'). This works in both guests and the hypervisor. For more
>      details, see s5.7 of Book III of version 3 of the ISA, in particular
>      the Storage Control Overview, s5.7.3, and s5.7.5 - noting that this
>      KASAN implementation currently only supports Radix.]
>=20
>   - Some code - most notably a lot of KVM code - also runs with translati=
ons
>     off after boot.
>=20
>   - Therefore any offset has to point to memory that is valid with
>     translations on or off.
>=20
> One approach is just to give up on inline instrumentation. This way
> boot-time checks can be delayed until after the MMU is set is up, and we
> can just not instrument any code that runs with translations off after
> booting. Take this approach for now and require outline instrumentation.
>=20
> Previous attempts allowed inline instrumentation. However, they came with
> some unfortunate restrictions: only physically contiguous memory could be
> used and it had to be specified at compile time. Maybe we can do better i=
n
> the future.
>=20
> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix versio=
n
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com> # ppc64 hash version
> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   Documentation/dev-tools/kasan.rst            |  9 +-
>   Documentation/powerpc/kasan.txt              | 48 +++++++++-
>   arch/powerpc/Kconfig                         |  4 +-
>   arch/powerpc/Kconfig.debug                   |  2 +-
>   arch/powerpc/include/asm/book3s/64/hash.h    |  4 +
>   arch/powerpc/include/asm/book3s/64/pgtable.h |  7 ++
>   arch/powerpc/include/asm/book3s/64/radix.h   | 13 ++-
>   arch/powerpc/include/asm/kasan.h             | 34 ++++++-
>   arch/powerpc/kernel/Makefile                 |  5 +
>   arch/powerpc/kernel/process.c                | 16 ++--
>   arch/powerpc/kvm/Makefile                    |  5 +
>   arch/powerpc/mm/book3s64/Makefile            |  8 ++
>   arch/powerpc/mm/kasan/Makefile               |  1 +
>   arch/powerpc/mm/kasan/init_book3s_64.c       | 98 ++++++++++++++++++++
>   arch/powerpc/mm/ptdump/ptdump.c              | 20 +++-
>   arch/powerpc/platforms/Kconfig.cputype       |  1 +
>   arch/powerpc/platforms/powernv/Makefile      |  6 ++
>   arch/powerpc/platforms/pseries/Makefile      |  3 +
>   18 files changed, 265 insertions(+), 19 deletions(-)
>   create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>=20
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index eaf868094a8e..28f08959bd2e 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -19,8 +19,9 @@ out-of-bounds accesses for global variables is only sup=
ported since Clang 11.
>   Tag-based KASAN is only supported in Clang.
>  =20
>   Currently generic KASAN is supported for the x86_64, arm64, xtensa, s39=
0 and
> -riscv architectures. It is also supported on 32-bit powerpc kernels. Tag=
-based
> -KASAN is supported only on arm64.
> +riscv architectures. It is also supported on powerpc, for 32-bit kernels=
, and
> +for 64-bit kernels running under the Radix MMU. Tag-based KASAN is suppo=
rted
> +only on arm64.
>  =20
>   Usage
>   -----
> @@ -257,8 +258,8 @@ CONFIG_KASAN_VMALLOC
>  =20
>   With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
>   cost of greater memory usage. Currently this supported on x86, s390
> -and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
> -with module support, where it is required.
> +and powerpc. It is optional, except on 64-bit powerpc kernels, and on
> +32-bit powerpc kernels with module support, where it is required.
>  =20
>   This works by hooking into vmalloc and vmap, and dynamically
>   allocating real shadow memory to back the mappings.
> diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasa=
n.txt
> index 26bb0e8bb18c..f032b4eaf205 100644
> --- a/Documentation/powerpc/kasan.txt
> +++ b/Documentation/powerpc/kasan.txt
> @@ -1,4 +1,4 @@
> -KASAN is supported on powerpc on 32-bit only.
> +KASAN is supported on powerpc on 32-bit and Radix 64-bit only.
>  =20
>   32 bit support
>   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> @@ -10,3 +10,49 @@ fixmap area and occupies one eighth of the total kerne=
l virtual memory space.
>  =20
>   Instrumentation of the vmalloc area is optional, unless built with modu=
les,
>   in which case it is required.
> +
> +64 bit support
> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> +
> +Currently, only the radix MMU is supported. There have been versions for=
 hash
> +and Book3E processors floating around on the mailing list, but nothing h=
as been
> +merged.
> +
> +KASAN support on Book3S is a bit tricky to get right:
> +
> + - It would be good to support inline instrumentation so as to be able t=
o catch
> +   stack issues that cannot be caught with outline mode.
> +
> + - Inline instrumentation requires a fixed offset.
> +
> + - Book3S runs code with translations off ("real mode") during boot, inc=
luding a
> +   lot of generic device-tree parsing code which is used to determine MM=
U
> +   features.
> +
> + - Some code - most notably a lot of KVM code - also runs with translati=
ons off
> +   after boot.
> +
> + - Therefore any offset has to point to memory that is valid with
> +   translations on or off.
> +
> +One approach is just to give up on inline instrumentation. This way boot=
-time
> +checks can be delayed until after the MMU is set is up, and we can just =
not
> +instrument any code that runs with translations off after booting. This =
is the
> +current approach.
> +
> +To avoid this limitiation, the KASAN shadow would have to be placed insi=
de the
> +linear mapping, using the same high-bits trick we use for the rest of th=
e linear
> +mapping. This is tricky:
> +
> + - We'd like to place it near the start of physical memory. In theory we=
 can do
> +   this at run-time based on how much physical memory we have, but this =
requires
> +   being able to arbitrarily relocate the kernel, which is basically the=
 tricky
> +   part of KASLR. Not being game to implement both tricky things at once=
, this
> +   is hopefully something we can revisit once we get KASLR for Book3S.
> +
> + - Alternatively, we can place the shadow at the _end_ of memory, but th=
is
> +   requires knowing how much contiguous physical memory a system has _at=
 compile
> +   time_. This is a big hammer, and has some unfortunate consequences: i=
nablity
> +   to handle discontiguous physical memory, total failure to boot on mac=
hines
> +   with less memory than specified, and that machines with more memory t=
han
> +   specified can't use it. This was deemed unacceptable.
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index e9f13fe08492..e6bd02af6ebd 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -180,7 +180,9 @@ config PPC
>   	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_KASAN			if PPC32 && PPC_PAGE_SHIFT <=3D 14
> -	select HAVE_ARCH_KASAN_VMALLOC		if PPC32 && PPC_PAGE_SHIFT <=3D 14
> +	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU

PPC_RADIX_MMU already depends on PPC_BOOK3S_64 so 'if PPC_RADIX_MMU' would =
be enough

> +	select HAVE_ARCH_NO_KASAN_INLINE	if PPC_BOOK3S_64 && PPC_RADIX_MMU

This list must respect Alphabetical order.

> +	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_MMAP_RND_BITS
>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
> diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
> index b88900f4832f..60c1bba72a6f 100644
> --- a/arch/powerpc/Kconfig.debug
> +++ b/arch/powerpc/Kconfig.debug
> @@ -396,5 +396,5 @@ config PPC_FAST_ENDIAN_SWITCH
>  =20
>   config KASAN_SHADOW_OFFSET
>   	hex
> -	depends on KASAN
> +	depends on KASAN && PPC32
>   	default 0xe0000000

Instead of the above, why not doing:

	default 0xe0000000 if PPC32
	default 0xa80e000000000000 is PPC_BOOK3S_64

> diff --git a/arch/powerpc/include/asm/book3s/64/hash.h b/arch/powerpc/inc=
lude/asm/book3s/64/hash.h
> index 73ad038ed10b..105b90594a8a 100644
> --- a/arch/powerpc/include/asm/book3s/64/hash.h
> +++ b/arch/powerpc/include/asm/book3s/64/hash.h
> @@ -18,6 +18,10 @@
>   #include <asm/book3s/64/hash-4k.h>
>   #endif
>  =20
> +#define H_PTRS_PER_PTE		(1 << H_PTE_INDEX_SIZE)
> +#define H_PTRS_PER_PMD		(1 << H_PMD_INDEX_SIZE)
> +#define H_PTRS_PER_PUD		(1 << H_PUD_INDEX_SIZE)
> +
>   /* Bits to set in a PMD/PUD/PGD entry valid bit*/
>   #define HASH_PMD_VAL_BITS		(0x8000000000000000UL)
>   #define HASH_PUD_VAL_BITS		(0x8000000000000000UL)
> diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/=
include/asm/book3s/64/pgtable.h
> index a39886681629..767e239d75e3 100644
> --- a/arch/powerpc/include/asm/book3s/64/pgtable.h
> +++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
> @@ -230,6 +230,13 @@ extern unsigned long __pmd_frag_size_shift;
>   #define PTRS_PER_PUD	(1 << PUD_INDEX_SIZE)
>   #define PTRS_PER_PGD	(1 << PGD_INDEX_SIZE)
>  =20
> +#define MAX_PTRS_PER_PTE	((H_PTRS_PER_PTE > R_PTRS_PER_PTE) ? \
> +				  H_PTRS_PER_PTE : R_PTRS_PER_PTE)

Nowadays we allow 100 chars per line. Could this fit on a single line ?

> +#define MAX_PTRS_PER_PMD	((H_PTRS_PER_PMD > R_PTRS_PER_PMD) ? \
> +				  H_PTRS_PER_PMD : R_PTRS_PER_PMD)
> +#define MAX_PTRS_PER_PUD	((H_PTRS_PER_PUD > R_PTRS_PER_PUD) ? \
> +				  H_PTRS_PER_PUD : R_PTRS_PER_PUD)
> +
>   /* PMD_SHIFT determines what a second-level page table entry can map */
>   #define PMD_SHIFT	(PAGE_SHIFT + PTE_INDEX_SIZE)
>   #define PMD_SIZE	(1UL << PMD_SHIFT)
> diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/in=
clude/asm/book3s/64/radix.h
> index c7813dc628fc..b3492b80f858 100644
> --- a/arch/powerpc/include/asm/book3s/64/radix.h
> +++ b/arch/powerpc/include/asm/book3s/64/radix.h
> @@ -35,6 +35,11 @@
>   #define RADIX_PMD_SHIFT		(PAGE_SHIFT + RADIX_PTE_INDEX_SIZE)
>   #define RADIX_PUD_SHIFT		(RADIX_PMD_SHIFT + RADIX_PMD_INDEX_SIZE)
>   #define RADIX_PGD_SHIFT		(RADIX_PUD_SHIFT + RADIX_PUD_INDEX_SIZE)
> +
> +#define R_PTRS_PER_PTE		(1 << RADIX_PTE_INDEX_SIZE)
> +#define R_PTRS_PER_PMD		(1 << RADIX_PMD_INDEX_SIZE)
> +#define R_PTRS_PER_PUD		(1 << RADIX_PUD_INDEX_SIZE)
> +
>   /*
>    * Size of EA range mapped by our pagetables.
>    */
> @@ -68,11 +73,11 @@
>    *
>    *
>    * 3rd quadrant expanded:
> - * +------------------------------+
> + * +------------------------------+  Highest address (0xc010000000000000=
)
> + * +------------------------------+  KASAN shadow end (0xc00fc0000000000=
0)
>    * |                              |
>    * |                              |
> - * |                              |
> - * +------------------------------+  Kernel vmemmap end (0xc010000000000=
000)
> + * +------------------------------+  Kernel vmemmap end/shadow start (0x=
c00e000000000000)
>    * |                              |
>    * |           512TB		  |
>    * |                              |
> @@ -126,6 +131,8 @@
>   #define RADIX_VMEMMAP_SIZE	RADIX_KERN_MAP_SIZE
>   #define RADIX_VMEMMAP_END	(RADIX_VMEMMAP_START + RADIX_VMEMMAP_SIZE)
>  =20
> +/* For the sizes of the shadow area, see kasan.h */
> +
>   #ifndef __ASSEMBLY__
>   #define RADIX_PTE_TABLE_SIZE	(sizeof(pte_t) << RADIX_PTE_INDEX_SIZE)
>   #define RADIX_PMD_TABLE_SIZE	(sizeof(pmd_t) << RADIX_PMD_INDEX_SIZE)
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index 7355ed05e65e..c72fd9281b44 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -28,9 +28,41 @@
>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>   				 (KASAN_KERN_START >> KASAN_SHADOW_SCALE_SHIFT))
>  =20
> +#ifdef CONFIG_KASAN_SHADOW_OFFSET
>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
> +#endif
>  =20
> +#ifdef CONFIG_PPC32
>   #define KASAN_SHADOW_END	(-(-KASAN_SHADOW_START >> KASAN_SHADOW_SCALE_S=
HIFT))
> +#endif
> +
> +#ifdef CONFIG_PPC_BOOK3S_64
> +/*
> + * We define the  offset such that the shadow of the linear map lives
> + * at the end of vmemmap space, that is, we choose offset such that
> + * shadow(c000_0000_0000_0000) =3D c00e_0000_0000_0000. This gives:
> + * c00e000000000000 - c000000000000000 >> 3 =3D a80e000000000000
> + */
> +#define KASAN_SHADOW_OFFSET ASM_CONST(0xa80e000000000000)

Why can't you use CONFIG_KASAN_SHADOW_OFFSET ?

> +
> +/*
> + * The shadow ends before the highest accessible address
> + * because we don't need a shadow for the shadow. Instead:
> + * c00e000000000000 << 3 + a80e000000000000000 =3D c00fc00000000000
> + */
> +#define KASAN_SHADOW_END 0xc00fc00000000000UL

I think we should be able to have a common formula for PPC32 and PPC64.

> +
> +DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> +
> +static inline bool kasan_arch_is_ready_ppc64(void)

I'd make it __always_inline

> +{
> +	if (static_branch_likely(&powerpc_kasan_enabled_key))
> +		return true;
> +	return false;
> +}
> +
> +#define kasan_arch_is_ready kasan_arch_is_ready_ppc64

Usually we keep the generic name, you don't need to have an arch specific n=
ame.

> +#endif
>  =20
>   #ifdef CONFIG_KASAN
>   void kasan_early_init(void);
> @@ -47,5 +79,5 @@ void kasan_update_early_region(unsigned long k_start, u=
nsigned long k_end, pte_t
>   int kasan_init_shadow_page_tables(unsigned long k_start, unsigned long =
k_end);
>   int kasan_init_region(void *start, size_t size);
>  =20
> -#endif /* __ASSEMBLY */
> +#endif /* !__ASSEMBLY__ */

This patch is already big. Is that worth it ?

>   #endif
> diff --git a/arch/powerpc/kernel/Makefile b/arch/powerpc/kernel/Makefile
> index fe2ef598e2ea..cd58202459dd 100644
> --- a/arch/powerpc/kernel/Makefile
> +++ b/arch/powerpc/kernel/Makefile
> @@ -32,6 +32,11 @@ KASAN_SANITIZE_early_32.o :=3D n
>   KASAN_SANITIZE_cputable.o :=3D n
>   KASAN_SANITIZE_prom_init.o :=3D n
>   KASAN_SANITIZE_btext.o :=3D n
> +KASAN_SANITIZE_paca.o :=3D n
> +KASAN_SANITIZE_setup_64.o :=3D n

The entire setup_64 ?
Can you split things out into an early_64.o like was done for ppc32 ?

> +KASAN_SANITIZE_mce.o :=3D n
> +KASAN_SANITIZE_traps.o :=3D n

Why ? ppc32 doesn't need that.

> +KASAN_SANITIZE_mce_power.o :=3D n
>  =20
>   ifdef CONFIG_KASAN
>   CFLAGS_early_32.o +=3D -DDISABLE_BRANCH_PROFILING
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index d421a2c7f822..f02b2766015c 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2151,8 +2151,8 @@ void show_stack(struct task_struct *tsk, unsigned l=
ong *stack,
>   			break;
>  =20
>   		stack =3D (unsigned long *) sp;
> -		newsp =3D stack[0];
> -		ip =3D stack[STACK_FRAME_LR_SAVE];
> +		newsp =3D READ_ONCE_NOCHECK(stack[0]);
> +		ip =3D READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);
>   		if (!firstframe || ip !=3D lr) {
>   			printk("%s["REG"] ["REG"] %pS",
>   				loglvl, sp, ip, (void *)ip);
> @@ -2170,14 +2170,16 @@ void show_stack(struct task_struct *tsk, unsigned=
 long *stack,
>   		 * See if this is an exception frame.
>   		 * We look for the "regshere" marker in the current frame.
>   		 */
> -		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
> -		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
> +		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE) &&
> +		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) =3D=3D
> +		     STACK_FRAME_REGS_MARKER)) {
>   			struct pt_regs *regs =3D (struct pt_regs *)
>   				(sp + STACK_FRAME_OVERHEAD);
> -			lr =3D regs->link;
> +			lr =3D READ_ONCE_NOCHECK(regs->link);
>   			printk("%s--- interrupt: %lx at %pS\n    LR =3D %pS\n",
> -			       loglvl, regs->trap,
> -			       (void *)regs->nip, (void *)lr);
> +			       loglvl, READ_ONCE_NOCHECK(regs->trap),
> +			       (void *)READ_ONCE_NOCHECK(regs->nip),
> +			       (void *)READ_ONCE_NOCHECK(lr));
>   			firstframe =3D 1;
>   		}
>  =20
> diff --git a/arch/powerpc/kvm/Makefile b/arch/powerpc/kvm/Makefile
> index 2bfeaa13befb..7f1592dacbeb 100644
> --- a/arch/powerpc/kvm/Makefile
> +++ b/arch/powerpc/kvm/Makefile
> @@ -136,3 +136,8 @@ obj-$(CONFIG_KVM_BOOK3S_64_PR) +=3D kvm-pr.o
>   obj-$(CONFIG_KVM_BOOK3S_64_HV) +=3D kvm-hv.o
>  =20
>   obj-y +=3D $(kvm-book3s_64-builtin-objs-y)
> +
> +# KVM does a lot in real-mode, and 64-bit Book3S KASAN doesn't support t=
hat
> +ifdef CONFIG_PPC_BOOK3S_64
> +KASAN_SANITIZE :=3D n
> +endif
> diff --git a/arch/powerpc/mm/book3s64/Makefile b/arch/powerpc/mm/book3s64=
/Makefile
> index fd393b8be14f..41a86d2c7da4 100644
> --- a/arch/powerpc/mm/book3s64/Makefile
> +++ b/arch/powerpc/mm/book3s64/Makefile
> @@ -21,3 +21,11 @@ obj-$(CONFIG_PPC_MEM_KEYS)	+=3D pkeys.o
>  =20
>   # Instrumenting the SLB fault path can lead to duplicate SLB entries
>   KCOV_INSTRUMENT_slb.o :=3D n
> +
> +# Parts of these can run in real mode and therefore are
> +# not safe with the current outline KASAN implementation
> +KASAN_SANITIZE_mmu_context.o :=3D n
> +KASAN_SANITIZE_pgtable.o :=3D n
> +KASAN_SANITIZE_radix_pgtable.o :=3D n
> +KASAN_SANITIZE_radix_tlb.o :=3D n
> +KASAN_SANITIZE_slb.o :=3D n
> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makef=
ile
> index 42fb628a44fd..07eef87abd6c 100644
> --- a/arch/powerpc/mm/kasan/Makefile
> +++ b/arch/powerpc/mm/kasan/Makefile
> @@ -5,3 +5,4 @@ KASAN_SANITIZE :=3D n
>   obj-$(CONFIG_PPC32)           +=3D init_32.o
>   obj-$(CONFIG_PPC_8xx)		+=3D 8xx.o
>   obj-$(CONFIG_PPC_BOOK3S_32)	+=3D book3s_32.o
> +obj-$(CONFIG_PPC_BOOK3S_64)   +=3D init_book3s_64.o
> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kas=
an/init_book3s_64.c
> new file mode 100644
> index 000000000000..b26ada73215d
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -0,0 +1,98 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * KASAN for 64-bit Book3S powerpc
> + *
> + * Copyright (C) 2019-2020 IBM Corporation
> + * Author: Daniel Axtens <dja@axtens.net>
> + */
> +
> +#define DISABLE_BRANCH_PROFILING
> +
> +#include <linux/kasan.h>
> +#include <linux/printk.h>
> +#include <linux/sched/task.h>
> +#include <linux/memblock.h>
> +#include <asm/pgalloc.h>
> +
> +DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> +
> +static void __init kasan_init_phys_region(void *start, void *end)
> +{
> +	unsigned long k_start, k_end, k_cur;
> +	void *va;
> +
> +	if (start >=3D end)
> +		return;
> +
> +	k_start =3D ALIGN_DOWN((unsigned long)kasan_mem_to_shadow(start), PAGE_=
SIZE);
> +	k_end =3D ALIGN((unsigned long)kasan_mem_to_shadow(end), PAGE_SIZE);
> +
> +	va =3D memblock_alloc(k_end - k_start, PAGE_SIZE);
> +	for (k_cur =3D k_start; k_cur < k_end; k_cur +=3D PAGE_SIZE) {
> +		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);
> +		va +=3D PAGE_SIZE;
> +	}

What about:

	for (k_cur =3D k_start; k_cur < k_end; k_cur +=3D PAGE_SIZE, va +=3D PAGE_=
SIZE)
		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);


> +}
> +
> +void __init kasan_init(void)
> +{
> +	/*
> +	 * We want to do the following things:
> +	 *  1) Map real memory into the shadow for all physical memblocks
> +	 *     This takes us from c000... to c008...
> +	 *  2) Leave a hole over the shadow of vmalloc space. KASAN_VMALLOC
> +	 *     will manage this for us.
> +	 *     This takes us from c008... to c00a...
> +	 *  3) Map the 'early shadow'/zero page over iomap and vmemmap space.
> +	 *     This takes us up to where we start at c00e...
> +	 */
> +
> +	void *k_start =3D kasan_mem_to_shadow((void *)RADIX_VMALLOC_END);
> +	void *k_end =3D kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
> +	phys_addr_t start, end;
> +	u64 i;
> +	pte_t zero_pte =3D pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_K=
ERNEL);
> +
> +	if (!early_radix_enabled())
> +		panic("KASAN requires radix!");
> +
> +	for_each_mem_range(i, &start, &end) {
> +		kasan_init_phys_region((void *)start, (void *)end);
> +	}

No need of { } for single line loops. Check the kernel codyign stype


> +
> +	for (i =3D 0; i < PTRS_PER_PTE; i++)
> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
> +			     &kasan_early_shadow_pte[i], zero_pte, 0);
> +
> +	for (i =3D 0; i < PTRS_PER_PMD; i++)
> +		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
> +				    kasan_early_shadow_pte);
> +
> +	for (i =3D 0; i < PTRS_PER_PUD; i++)
> +		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
> +			     kasan_early_shadow_pmd);
> +
> +	/* map the early shadow over the iomap and vmemmap space */
> +	kasan_populate_early_shadow(k_start, k_end);
> +
> +	/* mark early shadow region as RO and wipe it */
> +	zero_pte =3D pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL_=
RO);
> +	for (i =3D 0; i < PTRS_PER_PTE; i++)
> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
> +			     &kasan_early_shadow_pte[i], zero_pte, 0);
> +
> +	/*
> +	 * clear_page relies on some cache info that hasn't been set up yet.
> +	 * It ends up looping ~forever and blows up other data.
> +	 * Use memset instead.
> +	 */
> +	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +
> +	static_branch_inc(&powerpc_kasan_enabled_key);
> +
> +	/* Enable error messages */
> +	init_task.kasan_depth =3D 0;
> +	pr_info("KASAN init done (64-bit Book3S)\n");
> +}
> +
> +void __init kasan_late_init(void) { }
> diff --git a/arch/powerpc/mm/ptdump/ptdump.c b/arch/powerpc/mm/ptdump/ptd=
ump.c
> index aca354fb670b..63672aa656e8 100644
> --- a/arch/powerpc/mm/ptdump/ptdump.c
> +++ b/arch/powerpc/mm/ptdump/ptdump.c
> @@ -20,6 +20,7 @@
>   #include <linux/seq_file.h>
>   #include <asm/fixmap.h>
>   #include <linux/const.h>
> +#include <linux/kasan.h>
>   #include <asm/page.h>
>   #include <asm/hugetlb.h>
>  =20
> @@ -317,6 +318,23 @@ static void walk_pud(struct pg_state *st, p4d_t *p4d=
, unsigned long start)
>   	unsigned long addr;
>   	unsigned int i;
>  =20
> +#if defined(CONFIG_KASAN) && defined(CONFIG_PPC_BOOK3S_64)
> +	/*
> +	 * On radix + KASAN, we want to check for the KASAN "early" shadow
> +	 * which covers huge quantities of memory with the same set of
> +	 * read-only PTEs. If it is, we want to note the first page (to see
> +	 * the status change), and then note the last page. This gives us good
> +	 * results without spending ages noting the exact same PTEs over 100s o=
f
> +	 * terabytes of memory.
> +	 */
> +	if (p4d_page(*p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_pud)=
)) {
> +		walk_pmd(st, pud, start);
> +		addr =3D start + (PTRS_PER_PUD - 1) * PUD_SIZE;
> +		walk_pmd(st, pud, addr);
> +		return;
> +	}
> +#endif

Why do you need that ? When PTEs are all pointing to the same page, it shou=
d already appear in a=20
single line into []

> +
>   	for (i =3D 0; i < PTRS_PER_PUD; i++, pud++) {
>   		addr =3D start + i * PUD_SIZE;
>   		if (!pud_none(*pud) && !pud_is_leaf(*pud))
> @@ -387,11 +405,11 @@ static void populate_markers(void)
>   #endif
>   	address_markers[i++].start_address =3D FIXADDR_START;
>   	address_markers[i++].start_address =3D FIXADDR_TOP;
> +#endif /* CONFIG_PPC64 */
>   #ifdef CONFIG_KASAN
>   	address_markers[i++].start_address =3D KASAN_SHADOW_START;
>   	address_markers[i++].start_address =3D KASAN_SHADOW_END;
>   #endif
> -#endif /* CONFIG_PPC64 */
>   }
>  =20
>   static int ptdump_show(struct seq_file *m, void *v)
> diff --git a/arch/powerpc/platforms/Kconfig.cputype b/arch/powerpc/platfo=
rms/Kconfig.cputype
> index c194c4ae8bc7..b6eb8ec1e5ad 100644
> --- a/arch/powerpc/platforms/Kconfig.cputype
> +++ b/arch/powerpc/platforms/Kconfig.cputype
> @@ -92,6 +92,7 @@ config PPC_BOOK3S_64
>   	select ARCH_SUPPORTS_NUMA_BALANCING
>   	select IRQ_WORK
>   	select PPC_MM_SLICES
> +	select KASAN_VMALLOC if KASAN
>  =20
>   config PPC_BOOK3E_64
>   	bool "Embedded processors"
> diff --git a/arch/powerpc/platforms/powernv/Makefile b/arch/powerpc/platf=
orms/powernv/Makefile
> index 2eb6ae150d1f..f277e4793696 100644
> --- a/arch/powerpc/platforms/powernv/Makefile
> +++ b/arch/powerpc/platforms/powernv/Makefile
> @@ -1,4 +1,10 @@
>   # SPDX-License-Identifier: GPL-2.0
> +
> +# nothing that deals with real mode is safe to KASAN
> +# in particular, idle code runs a bunch of things in real mode
> +KASAN_SANITIZE_idle.o :=3D n
> +KASAN_SANITIZE_pci-ioda.o :=3D n
> +
>   obj-y			+=3D setup.o opal-call.o opal-wrappers.o opal.o opal-async.o
>   obj-y			+=3D idle.o opal-rtc.o opal-nvram.o opal-lpc.o opal-flash.o
>   obj-y			+=3D rng.o opal-elog.o opal-dump.o opal-sysparam.o opal-sensor.=
o
> diff --git a/arch/powerpc/platforms/pseries/Makefile b/arch/powerpc/platf=
orms/pseries/Makefile
> index c8a2b0b05ac0..202199ef9e5c 100644
> --- a/arch/powerpc/platforms/pseries/Makefile
> +++ b/arch/powerpc/platforms/pseries/Makefile
> @@ -30,3 +30,6 @@ obj-$(CONFIG_PPC_SVM)		+=3D svm.o
>   obj-$(CONFIG_FA_DUMP)		+=3D rtas-fadump.o
>  =20
>   obj-$(CONFIG_SUSPEND)		+=3D suspend.o
> +
> +# nothing that operates in real mode is safe for KASAN
> +KASAN_SANITIZE_ras.o :=3D n
>=20

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/251530bd-49ab-4d6e-13bc-03f97edafcc4%40csgroup.eu.
