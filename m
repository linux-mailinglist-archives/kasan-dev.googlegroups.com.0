Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZHI4KBAMGQEG6VJQJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id F0C513448F8
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 16:14:44 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id 9sf10690308wrb.16
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 08:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616426084; cv=pass;
        d=google.com; s=arc-20160816;
        b=jMGCIfYCdU0qhKO2+Umw6y94Yolbz1YvdpnTs+aSraojzSeVjXGcxn1ZP6s1fMk2rV
         M25QbJ3Diq9MR3kwMkdRUoskzuVeOpEow9Px0T5/8wNQ07wODNlsDwryGF2VJR7zbH+I
         ZlOIkqV4jYMT43FnsHKHwOZdtKlSjJhSGWphFAcIx3I7oNeAgTXqoE6dLtwMLtxGBdPs
         HExoiHlYqdwdcTlK5bsWC8Azdm+pl+EhUpYV8XJ0gWfgbxLtwoGA9D0nzqBTj1kN9mv3
         mSnYxMF611KBkFOsfdeID3VBvDCUaD9T8nsYBxvYKdtfHkOV79HURBIx/Su/nq96sDB9
         IZSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=vY5c2Tf+boYLvIgKmH9jRbO2nW1yMsv6EVHlQ80rrso=;
        b=VwhCGNpvuvYQDnETyyAZ9vwGdhqnNiVche8re69Up0ylBC5PHXF3kPd8Bq4VT/BWru
         TKhr0Fwnk7sn1MUhnMVouzTI6SbA+1Myv1V1AkZ8ZxVHeLbH8ussI3K4P3KRmY8ord5D
         YlF3XIvdDcnEtFNWEWedmdKITW/1Dn03RHGUd6Uw6l/u58ZdkSbNS7T/Ku6BeJ93FJ3G
         w9Mg389UWP3JYUtkbjbZX1a531mwLfIj5S3SmqWjumPhIb19AagG5tlfHEIOTm94m4BD
         RLtE76gYP2O/MnN75rUFGQf7+KUG6JPIIfoAxjjXGiufb+Mmvr5b5C/10LD6Lx8kAEj1
         9QkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vY5c2Tf+boYLvIgKmH9jRbO2nW1yMsv6EVHlQ80rrso=;
        b=LpMnIDxJ9B9zGi3AIyluCOawS/4pKfNzIF5HO73NttES9U/bpQh98qtn7k/AHzSw0w
         o8uMmY/RdRg4x4eCa2N9aFkjjhe7rZhLeG0nIAbWERQGd86iI3ruXDBO10K5mcREMho/
         v67qy4xI949q3hMFhASP/0JVGxyyD1bsTkay2wJo1lx9RGF4tZBc/0flYoZTd+zswut+
         mG3JjYQeX3AhWG3zXoshEPcRZ9PrFDoJhoq+8f+9R962Bs84JFuu1lEsTU/YT55+Jyl7
         7BrmcklKGWmRKdKXX/HFtUJV0WDnRJs0a3esLjOIdXh3bcjQfOEPR5M4nsoqCtu22lBY
         koZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vY5c2Tf+boYLvIgKmH9jRbO2nW1yMsv6EVHlQ80rrso=;
        b=trJHlYcU5YrWDoRIU5SSyVNLOnoAoJIaPUcU3Cu3iKNyMFKlGJhMkk7WVm+zhGbUZ6
         pjmJ5p0h2aLQ4sBvcEprjpecPG6IIEkNrm9aNFdgN7xNHkVOn7cv4Te5Rx5mvebUtcRC
         nq4ftwY4gToeVZ/dKe3/dT8ZeBdEATeF/0eFGu5TNIhuDfRMHgW87lKOrWc6bUa5sUFq
         pAywcTbSNF7stHoZt2SZ0MjcDxdDWtGGve+44nzPmXIpBauzGa3vGdMAyNmeGer866/V
         RqUZqhthv4xnb9rfpTCVpkj4+3q3lQcCd4w+qrfSHJcgfZWBBUVAah+QNgbCQFogdR01
         2gwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303m8zhD3V2XgxLyCjveId5Z9Xx7IkKo3UG9a49UU+YjzyeLgV8
	jUBneqgPsx4+m+erMy4+R0E=
X-Google-Smtp-Source: ABdhPJwlyXZZMsA/X3HzeusAm3v45YuZq2mctDLuZomOOpV9Kfmqqux+FiRGqybx0vDaVFeEoawQFg==
X-Received: by 2002:a1c:7ed4:: with SMTP id z203mr293107wmc.89.1616426084685;
        Mon, 22 Mar 2021 08:14:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:162d:: with SMTP id v13ls2390615wrb.1.gmail; Mon,
 22 Mar 2021 08:14:43 -0700 (PDT)
X-Received: by 2002:adf:f44b:: with SMTP id f11mr19313458wrp.345.1616426083826;
        Mon, 22 Mar 2021 08:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616426083; cv=none;
        d=google.com; s=arc-20160816;
        b=hYuevLKi6aQyaRfiq9S/2dbEDfQje18fRWn5mCuSkGg75n0nvYeoFl+LhYMiH69Vwp
         uySs0/CRcrYutkH/TP2JlRCXP73Q+vBYcYuscVASWeL7gw5Xs3ewlI9Qchu9pN+BbJMQ
         TGO7uyO26sHZUNfnZ8xFaGvC1KdlPHVMca+0xr2lsT6DDm0U/AMVfw0oPKmrCGqTReLX
         u3rDqX2Fe9U353iB/Yw9t7dmIRFfvAt6MZbyAuUJ2oMxxY9M/B+JHOv556IDLTloRAES
         BMYnAUpn5ELemszjN0MQ4zXfZt2GlzHMmUn8u3IzzsL4NH5QJ7ynG5SEfWN4RF01Ha8g
         HAWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=MArAATJHDBk+fhD0/sfhRtPQBwVfDrG2xg2ukBp6UFM=;
        b=jDVzDEOLWQFy0aiPx7ZssjU3V/xIG69L/2Mgs/HZ6n007bndGcFydZ62I4jAQCmd/J
         HkWV8x7cZzba+gQlhX0/tn+JUl4wTA8RunJwM6Ho+aAdBoEw5Jtznq/zFHOei9wp33Up
         1C9IthZRNDcszOXQ78eN4VJZVDF/XiToc3DcMnGX1XDYbeYW5Ki38YCwtAwSIJJxOC7Q
         yJyiehxX1A4CoBaHpcxrpFk56TBLfvVTBbq5r7nX2tapJaJOE19fWbZkhdsX8abHQzSp
         JIftDmcvfT2n4Mhxs5d1RR0IKzx6IysGbfiY6X6sKVUjSpg5tIVk2xqjz0KcZxLSiZVu
         LXzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y12si567854wrs.0.2021.03.22.08.14.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Mar 2021 08:14:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F3yhs4zWFz9tx56;
	Mon, 22 Mar 2021 16:14:37 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id xrFnyo3xBiDa; Mon, 22 Mar 2021 16:14:37 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F3yhs3WhLz9tx55;
	Mon, 22 Mar 2021 16:14:37 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E78BA8B7A4;
	Mon, 22 Mar 2021 16:14:42 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id GS3w4eeKc7cM; Mon, 22 Mar 2021 16:14:42 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 435378B79C;
	Mon, 22 Mar 2021 16:14:42 +0100 (CET)
Subject: Re: [PATCH v11 6/6] powerpc: Book3S 64-bit outline-only KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20210319144058.772525-1-dja@axtens.net>
 <20210319144058.772525-7-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <24abf728-3070-c482-7623-ad575a4de809@csgroup.eu>
Date: Mon, 22 Mar 2021 16:14:36 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <20210319144058.772525-7-dja@axtens.net>
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



Le 19/03/2021 =C3=A0 15:40, Daniel Axtens a =C3=A9crit=C2=A0:
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
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu> # ppc32 version
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---

> diff --git a/arch/powerpc/kernel/Makefile b/arch/powerpc/kernel/Makefile
> index 6084fa499aa3..163755b1cef4 100644
> --- a/arch/powerpc/kernel/Makefile
> +++ b/arch/powerpc/kernel/Makefile
> @@ -32,6 +32,17 @@ KASAN_SANITIZE_early_32.o :=3D n
>   KASAN_SANITIZE_cputable.o :=3D n
>   KASAN_SANITIZE_prom_init.o :=3D n
>   KASAN_SANITIZE_btext.o :=3D n
> +KASAN_SANITIZE_paca.o :=3D n
> +KASAN_SANITIZE_setup_64.o :=3D n
> +KASAN_SANITIZE_mce.o :=3D n
> +KASAN_SANITIZE_mce_power.o :=3D n
> +
> +# we have to be particularly careful in ppc64 to exclude code that
> +# runs with translations off, as we cannot access the shadow with
> +# translations off. However, ppc32 can sanitize this.

Which functions of this file can run with translations off on PPC64 ?
On PPC32 no functions run with translation off.

> +ifdef CONFIG_PPC64
> +KASAN_SANITIZE_traps.o :=3D n
> +endif
>  =20
>   ifdef CONFIG_KASAN
>   CFLAGS_early_32.o +=3D -DDISABLE_BRANCH_PROFILING
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index 3231c2df9e26..d4ae21b9e9b7 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2160,8 +2160,8 @@ void show_stack(struct task_struct *tsk, unsigned l=
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
> @@ -2179,17 +2179,19 @@ void show_stack(struct task_struct *tsk, unsigned=
 long *stack,
>   		 * See if this is an exception frame.
>   		 * We look for the "regshere" marker in the current frame.
>   		 */
> -		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS)
> -		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
> +		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS) &&
> +		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) =3D=3D
> +		     STACK_FRAME_REGS_MARKER)) {
>   			struct pt_regs *regs =3D (struct pt_regs *)
>   				(sp + STACK_FRAME_OVERHEAD);
>  =20
> -			lr =3D regs->link;
> +			lr =3D READ_ONCE_NOCHECK(regs->link);
>   			printk("%s--- interrupt: %lx at %pS\n",
> -			       loglvl, regs->trap, (void *)regs->nip);
> +			       loglvl, READ_ONCE_NOCHECK(regs->trap),
> +			       (void *)READ_ONCE_NOCHECK(regs->nip));
>   			__show_regs(regs);
>   			printk("%s--- interrupt: %lx\n",
> -			       loglvl, regs->trap);
> +			       loglvl, READ_ONCE_NOCHECK(regs->trap));
>  =20
>   			firstframe =3D 1;
>   		}


All changes in that file look more as a bug fix than a thing special for PP=
C64 KASAN. Could it be a=20
separate patch ?


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
> index 1b56d3af47d4..a7d8a68bd2c5 100644
> --- a/arch/powerpc/mm/book3s64/Makefile
> +++ b/arch/powerpc/mm/book3s64/Makefile
> @@ -21,3 +21,12 @@ obj-$(CONFIG_PPC_PKEY)	+=3D pkeys.o
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
> +KASAN_SANITIZE_pkeys.o :=3D n
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
> index 000000000000..ca913ed951a2
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -0,0 +1,95 @@
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
> +	for (k_cur =3D k_start; k_cur < k_end; k_cur +=3D PAGE_SIZE, va +=3D PA=
GE_SIZE)
> +		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);
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
> +	for_each_mem_range(i, &start, &end)
> +		kasan_init_phys_region((void *)start, (void *)end);
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

Could you use huge pages to map shadow memory ?

We do that on PPC32 now.

> +	if (p4d_page(*p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_pud)=
)) {
> +		walk_pmd(st, pud, start);
> +		addr =3D start + (PTRS_PER_PUD - 1) * PUD_SIZE;
> +		walk_pmd(st, pud, addr);
> +		return;
> +	}
> +#endif
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
> index 3ce907523b1e..9063c13e7221 100644
> --- a/arch/powerpc/platforms/Kconfig.cputype
> +++ b/arch/powerpc/platforms/Kconfig.cputype
> @@ -101,6 +101,7 @@ config PPC_BOOK3S_64
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
kasan-dev/24abf728-3070-c482-7623-ad575a4de809%40csgroup.eu.
