Return-Path: <kasan-dev+bncBCXLBLOA7IGBBEMPXXXQKGQEF43YWGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 418AF118141
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 08:21:54 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id b26sf2114589lfq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 23:21:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575962513; cv=pass;
        d=google.com; s=arc-20160816;
        b=t1aEuE82KmCzmaBiwxgbS1jVu3lsmRtMRkS6FRAiYNMp1AuIVzP23z/oaOxiwNFaXw
         WA02p80xwdrbpvLAgYKE3NWVhxOSPM0mQruSggNGnBOOTabkB+szqFp/FJulNyob7ZtU
         fdwGdnzhpubB2bgLIhm/u6i09+ZdXrxEKTBrMOOB0t8LqzLSpyJik6Nm3Y/MnQOo1saZ
         lXiAooPWhabXTW8NtNuWvOfIj3eiaLgZloE+imhJOXcQgBcMo9tvBf0WcIahtCFk6Wdh
         mCOLYcnrinifv8N3zU22umiYHCnjnaOy6lkq/y4ybsuYezWKFRDY01n2/9N61v2UvGHP
         vNrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=ipRyE6GwK/soYont2E3vPQcg+jXZ6IIc/4AuuU5vTJY=;
        b=h32PjqQ8q5omW1ZdaK5/yisT8eiyIZcy76VUKEWy90rVBxX0qU3ankXx7/A1eZqZSi
         aOT095XF2ZkMbMeiQ3y05r0iDj9Gb3e5dBVTWQj/EIshbzUTbCMV4pVM8grhgs5kEyRW
         r2ty4sm66t++J4io0reAKrYNuKhJzaVUXvjFWYe5MDyYAz0mhOrrXE17GYjmmCnduXxG
         3ylC0RzECA9lf6AkksEtEqmkWTgJI2IypP9onv1cgqxg40c4kjNSX8diAgaGYEQFTCSJ
         lWxXvoFvcgB2xbww2Eank7HHq3aP/hDzHBUrNCRjjfdwGcrf0wmAIbjZ8tQq84V3/FEr
         mwIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Sh2lcJOe;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ipRyE6GwK/soYont2E3vPQcg+jXZ6IIc/4AuuU5vTJY=;
        b=q36cUojxdbmigea3RzKp9JV4IERKDkF3QuvOD+8unJJo6ppnAGIMyJChCWxTd9eknA
         jQ14YxBLafFx3BiqPhYSv+9iBdjlQlJP1WQmqcHikMkmMQODQjVv0a3ejYO8qeZm2ys2
         8f7w3Wgev5eGXX/ZJpbHa0kfHP3GhXTArA05DqE5+34dJG8fgxndFnfzi94BgEvcJ94n
         vRRfXCr4/McQz5DnHvpA3ZBxxFPsvzQieACY8QVrcOl3Ua1qSiIEusuBkQmcku4ALV+7
         FehZdmAHyAQmfF3tkPhgx+hhi0bQPNb6GYlLYbjmS0YGdrj3p79RxR7hkk28i1LfShaB
         Li9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ipRyE6GwK/soYont2E3vPQcg+jXZ6IIc/4AuuU5vTJY=;
        b=YpsgKIh3e1De3Z4yeNz9RafNoPBlgExey2kjNrXmLRSPx84crdVJiQs2N8byFA+jBI
         iQJPnUQ0zF5nGJZUKLT5HFbe3OU4ofh41UxCd7/+mCavODH4AqW43qlFz/Rj4eYk828c
         OKKb7nzzMw4OXiK+qjjVqec/X8QJry5Ujy42uGt/ZlnuIwPacEn5AzcrPBTFzNXMcwbv
         HiIo/Wdxgb4bvWIulzLPR5rUCJ82+EM1XG0KQA/RrZ4sWGJ8sYy6XxPI9Adrqshk47Ll
         KzwEcTrkvYLGxUDF9r6Rqqn7BvTzDap7why3CKAbt7lGDUtqnRxK66IiG97liS5dPVES
         PCfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVkxGQlPPWk9DNSMlJ2GKoYUtqyNe6fqTTeuEFYGGgqtxGwL1mF
	zkLGUSVH9dVE0/ZkDPC/QOA=
X-Google-Smtp-Source: APXvYqzi4ReDGSMNgBJIWZq9ahRilskOhgf+1lCSEwbr+Bz34Ncmg9bUhODyPhaz/RxdhwuJahnUcg==
X-Received: by 2002:a2e:58c:: with SMTP id 134mr19979429ljf.12.1575962513497;
        Mon, 09 Dec 2019 23:21:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1b6:: with SMTP id c22ls2280703ljn.14.gmail; Mon,
 09 Dec 2019 23:21:52 -0800 (PST)
X-Received: by 2002:a2e:9942:: with SMTP id r2mr19996347ljj.182.1575962512631;
        Mon, 09 Dec 2019 23:21:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575962512; cv=none;
        d=google.com; s=arc-20160816;
        b=CK6t0aURuXC2CUIp3HP97qwnKosZwq3TlkQkYPSGYYsRFN/hnbG3TndvYzRkwpy6vd
         tqNlzQRgGLgT1wTRh+bxGl5dChsQByHNqmiFwhHovjuG9380ds7bx14y/eCm2YjUajP6
         SqICo4e6HZneQDghTIgDZaMAk/joDcGdsHshKL8rgMjNTAL8NseAugmKfOD+sjcuHXnK
         R/l4DZEr8a0OwUcerJpF8UweaN7aFHEXy8Oht9wS8VOJr/nmowrC3xznR4EIsYzXKsK9
         hIGUpk61nQSYpX6ZvrPKbPfrJ+Y5Km2S/qkz4KIqlCx1NhJ2uf+yHdbn6gguqyrOqSmW
         9Xuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=uw/F8X3/XeM42YLAiTScJek2jrg0cKz2LEnncR/eVb4=;
        b=wOfRc8mcoPu8tR9f05Fcd5iMLbpyMGTAkqOkQqz6tERH39wjOudEEjyJMa7OdfiYUK
         51DiWeaHs4q5bdNdGkzgnT4xYeWxOQ94W0CS5gvAsFJYlqvGz4VO7ylFciwKbK5MHICK
         gOuzW3hl8DF8rU9Bz+NAUwtTHNVcBcj7LmGrF7GbKGwXD/ibY6ODb/l2m5v6zO4Z4KT6
         /G+zN0NPbm0awzMxsGULoVqd08hKOXL1Ekpr1Mo7O7kp1/Z2i3wxzolDlWSye4UPI+iW
         2m9Eesaz2xRAqgDpizXtzr+zL86WNBv/qRswutkcfb6IJtEBBfL62puGn25czPg5qsS5
         SGNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Sh2lcJOe;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id j30si80805lfp.5.2019.12.09.23.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Dec 2019 23:21:52 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47XBML6bfjzB09ZL;
	Tue, 10 Dec 2019 08:21:50 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id vCUL7gKPQyab; Tue, 10 Dec 2019 08:21:50 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47XBML52zSz9vBnX;
	Tue, 10 Dec 2019 08:21:50 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 852568B802;
	Tue, 10 Dec 2019 08:21:51 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id FUSEp61DjNZZ; Tue, 10 Dec 2019 08:21:51 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4CCDC8B754;
	Tue, 10 Dec 2019 08:21:49 +0100 (CET)
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-5-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <414293e0-3b75-8e78-90d8-2c14182f3739@c-s.fr>
Date: Tue, 10 Dec 2019 08:21:49 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20191210044714.27265-5-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=Sh2lcJOe;       spf=pass (google.com:
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



Le 10/12/2019 =C3=A0 05:47, Daniel Axtens a =C3=A9crit=C2=A0:
> KASAN support on powerpc64 is challenging:
>=20
>   - We want to be able to support inline instrumentation so as to be
>     able to catch global and stack issues.
>=20
>   - We run some code in real mode after boot, most notably a lot of
>     KVM code. We'd like to be able to instrument this.
>=20
>     [For those not immersed in ppc64, in real mode, the top nibble or
>     2 bits (depending on radix/hash mmu) of the address is ignored. The
>     linear mapping is placed at 0xc000000000000000. This means that a
>     pointer to part of the linear mapping will work both in real mode,
>     where it will be interpreted as a physical address of the form
>     0x000..., and out of real mode, where it will go via the linear
>     mapping.]
>=20
>   - Inline instrumentation requires a fixed offset.
>=20
>   - Because of our running things in real mode, the offset has to
>     point to valid memory both in and out of real mode.
>=20
> This makes finding somewhere to put the KASAN shadow region challenging.
>=20
> One approach is just to give up on inline instrumentation and override
> the address->shadow calculation. This way we can delay all checking
> until after we get everything set up to our satisfaction. However,
> we'd really like to do better.

I think all the 'we' wordings should be rephrased in line with kernel=20
process (see=20
https://www.kernel.org/doc/html/latest/process/submitting-patches.html):

Describe your changes in imperative mood, e.g. "make xyzzy do frotz"
instead of "[This patch] makes xyzzy do frotz" or "[I] changed xyzzy
to do frotz", as if you are giving orders to the codebase to change
its behaviour.

For instance, could instead be:
"This way all checking can be delay after everything get set up to=20
satisfaction. However, better could really be done."


>=20
> What we can do - if we know _at compile time_ how much contiguous
> physical memory we have - is to set aside the top 1/8th of the memory
> and use that. This is a big hammer (hence the "heavyweight" name) and
> comes with 3 big consequences:
>=20
>   - kernels will simply fail to boot on machines with less memory than
>     specified when compiling.
>=20
>   - kernels running on machines with more memory than specified when
>     compiling will simply ignore the extra memory.
>=20
>   - there's no nice way to handle physically discontiguous memory, so
>     you are restricted to the first physical memory block.
>=20
> If you can bear all this, you get full support for KASAN.
>=20
> Despite the limitations, it can still find bugs,
> e.g. http://patchwork.ozlabs.org/patch/1103775/
>=20
> The current implementation is Radix only.
>=20
> Massive thanks to mpe, who had the idea for the initial design.
>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
> ---
> Changes since v1:
>   - Landed kasan vmalloc support upstream
>   - Lots of feedback from Christophe.
>=20
> Changes since the rfc:
>=20
>   - Boots real and virtual hardware, kvm works.
>=20
>   - disabled reporting when we're checking the stack for exception
>     frames. The behaviour isn't wrong, just incompatible with KASAN.
>=20
>   - Documentation!
>=20
>   - Dropped old module stuff in favour of KASAN_VMALLOC.
>=20
> The bugs with ftrace and kuap were due to kernel bloat pushing
> prom_init calls to be done via the plt. Because we did not have
> a relocatable kernel, and they are done very early, this caused
> everything to explode. Compile with CONFIG_RELOCATABLE!
> ---
>   Documentation/dev-tools/kasan.rst             |   8 +-
>   Documentation/powerpc/kasan.txt               | 102 +++++++++++++++++-
>   arch/powerpc/Kconfig                          |   3 +
>   arch/powerpc/Kconfig.debug                    |  21 ++++
>   arch/powerpc/Makefile                         |  11 ++
>   arch/powerpc/include/asm/kasan.h              |  20 +++-
>   arch/powerpc/kernel/process.c                 |   8 ++
>   arch/powerpc/kernel/prom.c                    |  59 +++++++++-
>   arch/powerpc/mm/kasan/Makefile                |   3 +-
>   .../mm/kasan/{kasan_init_32.c =3D> init_32.c}   |   0
>   arch/powerpc/mm/kasan/init_book3s_64.c        |  67 ++++++++++++
>   11 files changed, 293 insertions(+), 9 deletions(-)
>   rename arch/powerpc/mm/kasan/{kasan_init_32.c =3D> init_32.c} (100%)
>   create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>=20
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 4af2b5d2c9b4..d99dc580bc11 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -22,8 +22,9 @@ global variables yet.
>   Tag-based KASAN is only supported in Clang and requires version 7.0.0 o=
r later.
>  =20
>   Currently generic KASAN is supported for the x86_64, arm64, xtensa and =
s390
> -architectures. It is also supported on 32-bit powerpc kernels. Tag-based=
 KASAN
> -is supported only on arm64.
> +architectures. It is also supported on powerpc, for 32-bit kernels, and =
for
> +64-bit kernels running under the Radix MMU. Tag-based KASAN is supported=
 only
> +on arm64.
>  =20
>   Usage
>   -----
> @@ -256,7 +257,8 @@ CONFIG_KASAN_VMALLOC
>   ~~~~~~~~~~~~~~~~~~~~
>  =20
>   With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
> -cost of greater memory usage. Currently this is only supported on x86.
> +cost of greater memory usage. Currently this is optional on x86, and
> +required on 64-bit powerpc.
>  =20
>   This works by hooking into vmalloc and vmap, and dynamically
>   allocating real shadow memory to back the mappings.
> diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasa=
n.txt
> index a85ce2ff8244..d6e7a415195c 100644
> --- a/Documentation/powerpc/kasan.txt
> +++ b/Documentation/powerpc/kasan.txt
> @@ -1,4 +1,4 @@
> -KASAN is supported on powerpc on 32-bit only.
> +KASAN is supported on powerpc on 32-bit and 64-bit Radix only.

May be understood as : KASAN is supported on powerpc on 32-bit Radix and=20
64-bit Radix only.
Maybe would be more clear as : KASAN is supported on powerpc on 32-bit=20
and Radix 64-bit only.

>  =20
>   32 bit support
>   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> @@ -10,3 +10,103 @@ fixmap area and occupies one eighth of the total kern=
el virtual memory space.
>  =20
>   Instrumentation of the vmalloc area is not currently supported, but mod=
ules
>   are.
> +
> +64 bit support
> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

A lot of 'we' form here as well. Can it be avoided ?

> +
> +Currently, only the radix MMU is supported. There have been versions for=
 Book3E
> +processors floating around on the mailing list, but nothing has been mer=
ged.
> +
> +KASAN support on Book3S is a bit tricky to get right:
> +
> + - We want to be able to support inline instrumentation so as to be able=
 to
> +   catch global and stack issues.
> +
> + - Inline instrumentation requires a fixed offset.
> +
> + - We run a lot of code in real mode. Most notably a lot of KVM runs in =
real
> +   mode, and we'd like to be able to instrument it.
> +
> + - Because we run code in real mode after boot, the offset has to point =
to
> +   valid memory both in and out of real mode.
> +
> +One approach is just to give up on inline instrumentation. This way we c=
an
> +delay all checks until after we get everything set up correctly. However=
, we'd
> +really like to do better.
> +
> +If we know _at compile time_ how much contiguous physical memory we have=
, we
> +can set aside the top 1/8th of the first block of physical memory and us=
e
> +that. This is a big hammer and comes with 3 big consequences:
> +
> + - there's no nice way to handle physically discontiguous memory, so
> +   you are restricted to the first physical memory block.
> +
> + - kernels will simply fail to boot on machines with less memory than sp=
ecified
> +   when compiling.
> +
> + - kernels running on machines with more memory than specified when comp=
iling
> +   will simply ignore the extra memory.
> +
> +If you can live with this, you get full support for KASAN.
> +
> +Tips
> +----
> +
> + - Compile with CONFIG_RELOCATABLE.
> +
> +   In development, we found boot hangs when building with ftrace and KUA=
P
> +   on. These ended up being due to kernel bloat pushing prom_init calls =
to be
> +   done via the PLT. Because we did not have a relocatable kernel, and t=
hey are
> +   done very early, this caused us to jump off into somewhere invalid. E=
nabling
> +   relocation fixes this.
> +
> +NUMA/discontiguous physical memory
> +----------------------------------
> +
> +We currently cannot really deal with discontiguous physical memory. You =
are
> +restricted to the physical memory that is contiguous from physical addre=
ss
> +zero, and must specify the size of that memory, not total memory, when
> +configuring your kernel.
> +
> +Discontiguous memory can occur when you have a machine with memory sprea=
d
> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
> +
> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
> + - then there's a gap,
> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_00=
00_0000
> +
> +This can create _significant_ issues:
> +
> + - If we try to treat the machine as having 64GB of _contiguous_ RAM, we=
 would
> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserve =
the
> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the sh=
adow
> +   region. But when we try to access any of that, we'll try to access pa=
ges
> +   that are not physically present.
> +
> + - If we try to base the shadow region size on the top address, we'll ne=
ed to
> +   reserve 0x2008_0000_0000 / 8 =3D 0x0401_0000_0000 bytes =3D 4100 GB o=
f memory,
> +   which will clearly not work on a system with 64GB of RAM.
> +
> +Therefore, you are restricted to the memory in the node starting at 0x0.=
 For
> +this system, that's 32GB. If you specify a contiguous physical memory si=
ze
> +greater than the size of the first contiguous region of memory, the syst=
em will
> +be unable to boot or even print an error message warning you.
> +
> +You can determine the layout of your system's memory by observing the me=
ssages
> +that the Radix MMU prints on boot. The Talos II discussed earlier has:
> +
> +radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB pa=
ges (exec)
> +radix-mmu: Mapped 0x0000000040000000-0x0000000800000000 with 1.00 GiB pa=
ges
> +radix-mmu: Mapped 0x0000200000000000-0x0000200800000000 with 1.00 GiB pa=
ges
> +
> +As discussed, you'd configure this system for 32768 MB.
> +
> +Another system prints:
> +
> +radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB pa=
ges (exec)
> +radix-mmu: Mapped 0x0000000040000000-0x0000002000000000 with 1.00 GiB pa=
ges
> +radix-mmu: Mapped 0x0000200000000000-0x0000202000000000 with 1.00 GiB pa=
ges
> +
> +This machine has more memory: 0x0000_0040_0000_0000 total, but only
> +0x0000_0020_0000_0000 is physically contiguous from zero, so we'd config=
ure the
> +kernel for 131072 MB of physically contiguous memory.
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 1ec34e16ed65..f68650f14e61 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -173,6 +173,9 @@ config PPC
>   	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_KASAN			if PPC32
> +	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU
> +	select HAVE_ARCH_KASAN_VMALLOC		if PPC_BOOK3S_64

Does it mean, if PPC_RADIX_MMU, HAVE_ARCH_KASAN_VMALLOC will be defined=20
and not HAVE_ARCH_KASAN ?


> +	select KASAN_VMALLOC			if KASAN && PPC_BOOK3S_64
>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_MMAP_RND_BITS
>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
> diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
> index 4e1d39847462..90bb48455cb8 100644
> --- a/arch/powerpc/Kconfig.debug
> +++ b/arch/powerpc/Kconfig.debug
> @@ -394,6 +394,27 @@ config PPC_FAST_ENDIAN_SWITCH
>   	help
>   	  If you're unsure what this is, say N.
>  =20
> +config PHYS_MEM_SIZE_FOR_KASAN
> +	int "Contiguous physical memory size for KASAN (MB)" if KASAN && PPC_BO=
OK3S_64
> +	default 0
> +	help
> +
> +	  To get inline instrumentation support for KASAN on 64-bit Book3S
> +	  machines, you need to know how much contiguous physical memory your
> +	  system has. A shadow offset will be calculated based on this figure,
> +	  which will be compiled in to the kernel. KASAN will use this offset
> +	  to access its shadow region, which is used to verify memory accesses.
> +
> +	  If you attempt to boot on a system with less memory than you specify
> +	  here, your system will fail to boot very early in the process. If you
> +	  boot on a system with more memory than you specify, the extra memory
> +	  will wasted - it will be reserved and not used.
> +
> +	  For systems with discontiguous blocks of physical memory, specify the
> +	  size of the block starting at 0x0. You can determine this by looking
> +	  at the memory layout info printed to dmesg by the radix MMU code
> +	  early in boot. See Documentation/powerpc/kasan.txt.
> +
>   config KASAN_SHADOW_OFFSET
>   	hex
>   	depends on KASAN
> diff --git a/arch/powerpc/Makefile b/arch/powerpc/Makefile
> index f35730548e42..eff693527462 100644
> --- a/arch/powerpc/Makefile
> +++ b/arch/powerpc/Makefile
> @@ -230,6 +230,17 @@ ifdef CONFIG_476FPE_ERR46
>   		-T $(srctree)/arch/powerpc/platforms/44x/ppc476_modules.lds
>   endif
>  =20
> +ifdef CONFIG_PPC_BOOK3S_64
> +# The KASAN shadow offset is such that linear map (0xc000...) is shadowe=
d by
> +# the last 8th of linearly mapped physical memory. This way, if the code=
 uses
> +# 0xc addresses throughout, accesses work both in in real mode (where th=
e top
> +# 2 bits are ignored) and outside of real mode.
> +#
> +# 0xc000000000000000 >> 3 =3D 0xa800000000000000 =3D 1210567579837189324=
8
> +KASAN_SHADOW_OFFSET =3D $(shell echo 7 \* 1024 \* 1024 \* $(CONFIG_PHYS_=
MEM_SIZE_FOR_KASAN) / 8 + 12105675798371893248 | bc)
> +KBUILD_CFLAGS +=3D -DKASAN_SHADOW_OFFSET=3D$(KASAN_SHADOW_OFFSET)UL
> +endif
> +
>   # No AltiVec or VSX instructions when building kernel
>   KBUILD_CFLAGS +=3D $(call cc-option,-mno-altivec)
>   KBUILD_CFLAGS +=3D $(call cc-option,-mno-vsx)
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index 296e51c2f066..98d995bc9b5e 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -14,13 +14,20 @@
>  =20
>   #ifndef __ASSEMBLY__
>  =20
> -#include <asm/page.h>
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +#else
> +static inline void kasan_init(void) { }
> +#endif
>  =20
>   #define KASAN_SHADOW_SCALE_SHIFT	3
>  =20
>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>   				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>  =20
> +#ifdef CONFIG_PPC32
> +#include <asm/page.h>

Is that a problem to include page.h is not PPC32 ?

> +
>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>  =20
>   #define KASAN_SHADOW_END	0UL
> @@ -30,11 +37,18 @@
>   #ifdef CONFIG_KASAN
>   void kasan_early_init(void);
>   void kasan_mmu_init(void);
> -void kasan_init(void);
>   #else
> -static inline void kasan_init(void) { }
>   static inline void kasan_mmu_init(void) { }
>   #endif
> +#endif
> +
> +#ifdef CONFIG_PPC_BOOK3S_64
> +#include <asm/pgtable.h>
> +
> +#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
> +				1024 * 1024 * 1 / 8)
> +
> +#endif /* CONFIG_PPC_BOOK3S_64 */
>  =20
>   #endif /* __ASSEMBLY */
>   #endif
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index 4df94b6e2f32..c60ff299f39b 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2081,7 +2081,14 @@ void show_stack(struct task_struct *tsk, unsigned =
long *stack)
>   		/*
>   		 * See if this is an exception frame.
>   		 * We look for the "regshere" marker in the current frame.
> +		 *
> +		 * KASAN may complain about this. If it is an exception frame,
> +		 * we won't have unpoisoned the stack in asm when we set the
> +		 * exception marker. If it's not an exception frame, who knows
> +		 * how things are laid out - the shadow could be in any state
> +		 * at all. Just disable KASAN reporting for now.
>   		 */
> +		kasan_disable_current();
>   		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
>   		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
>   			struct pt_regs *regs =3D (struct pt_regs *)
> @@ -2091,6 +2098,7 @@ void show_stack(struct task_struct *tsk, unsigned l=
ong *stack)
>   			       regs->trap, (void *)regs->nip, (void *)lr);
>   			firstframe =3D 1;
>   		}
> +		kasan_enable_current();
>  =20
>   		sp =3D newsp;
>   	} while (count++ < kstack_depth_to_print);
> diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
> index 6620f37abe73..b32036f61cad 100644
> --- a/arch/powerpc/kernel/prom.c
> +++ b/arch/powerpc/kernel/prom.c
> @@ -72,6 +72,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
>   u64 ppc64_rma_size;
>   #endif
>   static phys_addr_t first_memblock_size;
> +static phys_addr_t top_phys_addr;
>   static int __initdata boot_cpu_count;
>  =20
>   static int __init early_parse_mem(char *p)
> @@ -449,6 +450,21 @@ static bool validate_mem_limit(u64 base, u64 *size)
>   {
>   	u64 max_mem =3D 1UL << (MAX_PHYSMEM_BITS);
>  =20
> +#ifdef CONFIG_KASAN

CONFIG_PHYS_MEM_SIZE_FOR_KASAN is know defined at all time, so this=20
ifdef can be avoided and replaced for instance by adding verification of=20
IS_ENABLED(CONFIG_KASAN) in the if() below.

> +	/*
> +	 * To handle the NUMA/discontiguous memory case, don't allow a block
> +	 * to be added if it falls completely beyond the configured physical
> +	 * memory.
> +	 *
> +	 * See Documentation/powerpc/kasan.txt
> +	 */
> +	if (base >=3D (u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * 1024 * 1024) {
> +		pr_warn("KASAN: not adding mem block at %llx (size %llx)",
> +			base, *size);
> +		return false;
> +	}
> +#endif
> +
>   	if (base >=3D max_mem)
>   		return false;
>   	if ((base + *size) > max_mem)
> @@ -572,8 +588,11 @@ void __init early_init_dt_add_memory_arch(u64 base, =
u64 size)
>  =20
>   	/* Add the chunk to the MEMBLOCK list */
>   	if (add_mem_to_memblock) {
> -		if (validate_mem_limit(base, &size))
> +		if (validate_mem_limit(base, &size)) {
>   			memblock_add(base, size);
> +			if (base + size > top_phys_addr)
> +				top_phys_addr =3D base + size;
> +		}
>   	}
>   }
>  =20
> @@ -613,6 +632,8 @@ static void __init early_reserve_mem_dt(void)
>   static void __init early_reserve_mem(void)
>   {
>   	__be64 *reserve_map;
> +	phys_addr_t kasan_shadow_start;
> +	phys_addr_t kasan_memory_size;
>  =20
>   	reserve_map =3D (__be64 *)(((unsigned long)initial_boot_params) +
>   			fdt_off_mem_rsvmap(initial_boot_params));
> @@ -651,6 +672,42 @@ static void __init early_reserve_mem(void)
>   		return;
>   	}
>   #endif
> +
> +	if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
> +		kasan_memory_size =3D
> +			((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
> +
> +		if (top_phys_addr < kasan_memory_size) {
> +			/*
> +			 * We are doomed. Attempts to call e.g. panic() are
> +			 * likely to fail because they call out into
> +			 * instrumented code, which will almost certainly
> +			 * access memory beyond the end of physical
> +			 * memory. Hang here so that at least the NIP points
> +			 * somewhere that will help you debug it if you look at
> +			 * it in qemu.
> +			 */

This function is called from early_init_devtree() which also includes a=20
call to panic(). That panic call should be changed then ?

> +			while (true)
> +				;

Can we trap instead, with BUG() or __builtin_trap() ?

Maybe define a function prom_panic() which calls panic() when=20
CONFIG_KASAN is not set, and does whatever works when CONFIG_KASAN is set ?


> +		} else if (top_phys_addr > kasan_memory_size) {
> +			/* print a biiiig warning in hopes people notice */
> +			pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n"
> +				"Physical memory exceeds compiled-in maximum!\n"
> +				"This kernel was compiled for KASAN with %u MB physical memory.\n"
> +				"The actual physical memory detected is %llu MB.\n"
> +				"Memory above the compiled limit will not be used!\n"
> +				"=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n",
> +				CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
> +				top_phys_addr / (1024 * 1024));
> +		}
> +
> +		kasan_shadow_start =3D _ALIGN_DOWN(kasan_memory_size * 7 / 8,
> +						 PAGE_SIZE);
> +		DBG("reserving %llx -> %llx for KASAN",
> +		    kasan_shadow_start, top_phys_addr);
> +		memblock_reserve(kasan_shadow_start,
> +				 top_phys_addr - kasan_shadow_start);
> +	}
>   }
>  =20
>   #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makef=
ile
> index 6577897673dd..f02b15c78e4d 100644
> --- a/arch/powerpc/mm/kasan/Makefile
> +++ b/arch/powerpc/mm/kasan/Makefile
> @@ -2,4 +2,5 @@
>  =20
>   KASAN_SANITIZE :=3D n
>  =20
> -obj-$(CONFIG_PPC32)           +=3D kasan_init_32.o
> +obj-$(CONFIG_PPC32)           +=3D init_32.o
> +obj-$(CONFIG_PPC_BOOK3S_64)   +=3D init_book3s_64.o
> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasa=
n/init_32.c
> similarity index 100%
> rename from arch/powerpc/mm/kasan/kasan_init_32.c
> rename to arch/powerpc/mm/kasan/init_32.c
> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kas=
an/init_book3s_64.c
> new file mode 100644
> index 000000000000..43e9252c8bd3
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -0,0 +1,67 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * KASAN for 64-bit Book3S powerpc
> + *
> + * Copyright (C) 2019 IBM Corporation
> + * Author: Daniel Axtens <dja@axtens.net>
> + */
> +
> +#define DISABLE_BRANCH_PROFILING
> +
> +#include <linux/kasan.h>
> +#include <linux/printk.h>
> +#include <linux/sched/task.h>
> +#include <asm/pgalloc.h>
> +
> +void __init kasan_init(void)
> +{
> +	int i;
> +	void *k_start =3D kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
> +	void *k_end =3D kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
> +
> +	pte_t pte =3D __pte(__pa(kasan_early_shadow_page) |
> +			  pgprot_val(PAGE_KERNEL) | _PAGE_PTE);
> +
> +	if (!early_radix_enabled())
> +		panic("KASAN requires radix!");
> +
> +	for (i =3D 0; i < PTRS_PER_PTE; i++)
> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
> +			     &kasan_early_shadow_pte[i], pte, 0);
> +
> +	for (i =3D 0; i < PTRS_PER_PMD; i++)
> +		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
> +				    kasan_early_shadow_pte);
> +
> +	for (i =3D 0; i < PTRS_PER_PUD; i++)
> +		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
> +			     kasan_early_shadow_pmd);
> +
> +	memset(kasan_mem_to_shadow((void *)PAGE_OFFSET), KASAN_SHADOW_INIT,
> +	       KASAN_SHADOW_SIZE);
> +
> +	kasan_populate_early_shadow(
> +		kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START),
> +		kasan_mem_to_shadow((void *)RADIX_VMALLOC_START));
> +
> +	/* leave a hole here for vmalloc */
> +
> +	kasan_populate_early_shadow(
> +		kasan_mem_to_shadow((void *)RADIX_VMALLOC_END),
> +		kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END));
> +
> +	flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);
> +
> +	/* mark early shadow region as RO and wipe */
> +	pte =3D __pte(__pa(kasan_early_shadow_page) |
> +		    pgprot_val(PAGE_KERNEL_RO) | _PAGE_PTE);

Any reason for _PAGE_PTE being required here and not being included in=20
PAGE_KERNEL_RO ?

> +	for (i =3D 0; i < PTRS_PER_PTE; i++)
> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
> +			     &kasan_early_shadow_pte[i], pte, 0);
> +
> +	memset(kasan_early_shadow_page, 0, PAGE_SIZE);

Can use clear_page() instead ?

> +
> +	/* Enable error messages */
> +	init_task.kasan_depth =3D 0;
> +	pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
> +}
>=20


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/414293e0-3b75-8e78-90d8-2c14182f3739%40c-s.fr.
