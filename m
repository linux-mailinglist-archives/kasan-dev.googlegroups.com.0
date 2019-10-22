Return-Path: <kasan-dev+bncBAABBBPQXHWQKGQER6QXUDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A87BFDFC38
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 05:31:18 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id m7sf7852770otc.11
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 20:31:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571715077; cv=pass;
        d=google.com; s=arc-20160816;
        b=CQ8S3vzFkW0yUcmuDr7pUd3JdggkqO32k7RtRgos12VAJJVZFnZwf8Euj1PuTLgjJ6
         Va6JL2BahFNmEPQwrz+7ezQriGSIhOBBCdWR+hjxg6gap2p9v26hzjoqnsSZyEP8OmAf
         3b6Q9ZIrtOmV9hc1i3VBUbwG7vucmEXBe/tzNc+z7u2loz7UXRRF5Sg+5lXNLYNWFAB1
         opIJ5YmFHZTyH5rDK4Wiuxh3gvUq39iUR3YdhxiaknSxzi07khdCc0fX8PdU/5w1PiV/
         MSP+pybK1zEtre0z3JnK34V3/1HD5EG6XD2iYGrrj72YzsXNTcxGDoFvZgH2qzjjNt8F
         uGCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=adZKhW8+gbnwHkzB7xTpOEFIUMNJzumWePUEh0sAUQc=;
        b=u1rgmzOtpAngWvmKGbTgLvjwRg8QDE1QxDwkZav4pdkbnFtc/B73tpW4MraNg+sXov
         BMcLldESY7+g9h5neOES4YPvetAfKcp2+4Jmoku0uVFvlgeAs9tRPvppUBs7xJ4LfuX8
         QEoTA+uhjq7u6TOxozwe4C783hljUjwZ1wYqK5Z5LsuqFxYkekKCZKQF25ths9vgL7z2
         +30ESEHE9nlopiE+HiWK9U/P1CXIRq5vfQ0aDGZ5hhL/pqgHnJ6VUthtDQNXHpezalg+
         pmBnSh0ELjcTscW8DpSb8Oq5O37DKTLA3Kj6Bnpc7oihtYv9TFPBlOz+cQFgbckNoFis
         DI3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adZKhW8+gbnwHkzB7xTpOEFIUMNJzumWePUEh0sAUQc=;
        b=n1LBmt6p8QxKzrdiy24W6QjdPcd7VV/RYTKhL2ZVe/vRT2UUwfbxUsZraMYCNmHPqH
         gYJqykQ2MGCfYJxBPby50AY/+tU4Kz5d+oc42dzs4V1VASWjnOOiXcGjm34/H0H0ZbNq
         sz6B7XEqiJCSg3a0kBw+sqUBJt8yz7rp3eOqAJDCNZN0quNzVVgB6HvOSFa7NErCRtil
         yc/+tTv3oD4EyNDpzFYYLSOsqzD2DmwDhUZmxcQ0x9vz+9xQ852EUXDNw6Mkgd+LXu11
         Nm4maCFZciB1yc2Y3TbB8I6/ybgqX4Zs9hq9HOO2oWjvifY3zQRV/T3cchpD+gJpELFb
         n3Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adZKhW8+gbnwHkzB7xTpOEFIUMNJzumWePUEh0sAUQc=;
        b=g3W+c+fsQ8XQm5eEMOanL29o+WkHaSNeFJ5KZ8UyC0p+JOX6QDygJs37aJ5oCRsQoF
         xA3WAApVmla5WzycJBjdFZ3CJPs399/7HKrpbZSAjcju/RUJugu4rno2hxp9CLgufLxo
         yLEej1VvFxOFjVyEI8iJl5dAT094Plbue5bdBT1LSYvXkt98emiZi6jpcn2s70sWO2tV
         njS4q5BJCidqaRd+FznIucDahgtXw1NZP8Jj8lUUVNpp1m6DwnZoQFRtC8QaVmNWZF+e
         MW9hqg6pAkJjk6DZllhhegkVtw2xYzMz6wxFks4TGCOY+gPy9p3ntklUQPkBaIQ6VT+X
         GwMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVY3A4JKf/2/lU1CHjrtOu1a3jIpIhAv6yBD+juNwTQMW37xcGV
	m2SBk5jwDZ6ipuUazb5ArvI=
X-Google-Smtp-Source: APXvYqyD1OGcnMCh7uk/M5NcMfOf5w4Om6qvJ9ZkFoJ7c5sON/BMV0aPOK2eVkDXtJxpJJUUB43CVw==
X-Received: by 2002:aca:d1a:: with SMTP id 26mr1102281oin.136.1571715077303;
        Mon, 21 Oct 2019 20:31:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:126:: with SMTP id 35ls452297otu.15.gmail; Mon, 21 Oct
 2019 20:31:16 -0700 (PDT)
X-Received: by 2002:a9d:578c:: with SMTP id q12mr902196oth.185.1571715076831;
        Mon, 21 Oct 2019 20:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571715076; cv=none;
        d=google.com; s=arc-20160816;
        b=NFOSjmNE/4SRY1YmniI1/oRarjMWH0K8ZNWlMWEIuZEszw8G0wFnF82CUvil3OXtvY
         sYr7UYIOqBeUImTWEgyPJ2vgL1W3rGbBc0CQa0Nk8Fcr/PFsYBPEZQ9Gdd022GlrqvUD
         FNPF+i6HNAhvXZbtcemy7d2IQp5/yPnJL7R7Ek8VeOk0mKnajAzmSHS+E7BZtDOnD16O
         TaBI21ixGc3Nya3CNKF46WcRmFoebi1pbX3AFyZ9Toq8GkDFnyJGUoCpRXrIldaFek7Z
         m1sElGZUKoNQ1wzCKZzVSi4Jo8fwRvG2kKyYXV7m9IfFmWdj7dD6GiCDdFeCgWSTGCVJ
         zLcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=69XEKp27c61OT7Lg41c962iGrCFu3j35e92znfdIaxg=;
        b=pT+OkeOsfoGGV4Uz8IqrlmouGIlJbd91F8awaSEY+3uU1NKvhMGH9hjVKHvGNr6hMj
         G9I4KZjX63laeIz4OZyYVzxqRByMeAWoYc1pEt+htTlP+XR0FMcUCyRqTrUqcY95yClA
         /qPyQqCqIoYkbXSmhNZucaDjja20i0DEwKdNdKXrvoFKrjWUs+CZsKKuLcl0nxPpobqT
         wQ2T3qaQ3ZBuj7+cSzrWOT351vJtKOjMF2kYYBkak71+J2PcsFfANn9luLQehVskCHHE
         BUy6ENTLsRiXRU60I+w1/AxUBbjscfvlbAu/w297BGoYafL25YifF0/OT3sdoikcbbYO
         8H6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id k61si641894otc.1.2019.10.21.20.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Oct 2019 20:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9M3DoXs081015;
	Tue, 22 Oct 2019 11:13:50 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Tue, 22 Oct 2019
 11:30:51 +0800
Date: Tue, 22 Oct 2019 11:30:51 +0800
From: Nick Hu <nickhu@andestech.com>
To: Greentime Hu <green.hu@gmail.com>
CC: Greentime Hu <greentime.hu@sifive.com>,
        Alan Quey-Liang
 =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        Paul Walmsley
	<paul.walmsley@sifive.com>,
        Palmer Dabbelt <palmer@sifive.com>, Albert Ou
	<aou@eecs.berkeley.edu>,
        "aryabinin@virtuozzo.com" <aryabinin@virtuozzo.com>,
        "glider@google.com" <glider@google.com>,
        "dvyukov@google.com"
	<dvyukov@google.com>,
        "corbet@lwn.net" <corbet@lwn.net>,
        "alexios.zavras@intel.com" <alexios.zavras@intel.com>,
        "allison@lohutok.net"
	<allison@lohutok.net>,
        "Anup.Patel@wdc.com" <Anup.Patel@wdc.com>,
        "Thomas
 Gleixner" <tglx@linutronix.de>,
        "gregkh@linuxfoundation.org"
	<gregkh@linuxfoundation.org>,
        "atish.patra@wdc.com" <atish.patra@wdc.com>,
        Kate Stewart <kstewart@linuxfoundation.org>,
        "linux-doc@vger.kernel.org"
	<linux-doc@vger.kernel.org>,
        "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>,
        Linux Kernel Mailing List
	<linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>
Subject: Re: [PATCH v3 2/3] riscv: Add KASAN support
Message-ID: <20191022033051.GB29285@andestech.com>
References: <cover.1570514544.git.nickhu@andestech.com>
 <8d86d53e904bece0623cb8969cdc70f782fa2bae.1570514544.git.nickhu@andestech.com>
 <CAEbi=3fTKqt545tEz6c-RCdKniq2ZxOqvamFpJsbe=D+gpGBcQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAEbi=3fTKqt545tEz6c-RCdKniq2ZxOqvamFpJsbe=D+gpGBcQ@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9M3DoXs081015
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

On Mon, Oct 21, 2019 at 05:33:31PM +0800, Greentime Hu wrote:
> Nick Hu <nickhu@andestech.com> =E6=96=BC 2019=E5=B9=B410=E6=9C=888=E6=97=
=A5 =E9=80=B1=E4=BA=8C =E4=B8=8B=E5=8D=882:17=E5=AF=AB=E9=81=93=EF=BC=9A
> >
> > This patch ports the feature Kernel Address SANitizer (KASAN).
> >
> > Note: The start address of shadow memory is at the beginning of kernel
> > space, which is 2^64 - (2^39 / 2) in SV39. The size of the kernel space=
 is
> > 2^38 bytes so the size of shadow memory should be 2^38 / 8. Thus, the
> > shadow memory would not overlap with the fixmap area.
> >
> > There are currently two limitations in this port,
> >
> > 1. RV64 only: KASAN need large address space for extra shadow memory
> > region.
> >
> > 2. KASAN can't debug the modules since the modules are allocated in VMA=
LLOC
> > area. We mapped the shadow memory, which corresponding to VMALLOC area,=
 to
> > the kasan_early_shadow_page because we don't have enough physical space=
 for
> > all the shadow memory corresponding to VMALLOC area.
> >
> > Signed-off-by: Nick Hu <nickhu@andestech.com>
> > ---
> >  arch/riscv/Kconfig                  |   1 +
> >  arch/riscv/include/asm/kasan.h      |  27 ++++++++
> >  arch/riscv/include/asm/pgtable-64.h |   5 ++
> >  arch/riscv/include/asm/string.h     |   9 +++
> >  arch/riscv/kernel/head.S            |   3 +
> >  arch/riscv/kernel/riscv_ksyms.c     |   2 +
> >  arch/riscv/kernel/setup.c           |   5 ++
> >  arch/riscv/kernel/vmlinux.lds.S     |   1 +
> >  arch/riscv/lib/memcpy.S             |   5 +-
> >  arch/riscv/lib/memset.S             |   5 +-
> >  arch/riscv/mm/Makefile              |   6 ++
> >  arch/riscv/mm/kasan_init.c          | 104 ++++++++++++++++++++++++++++
> >  12 files changed, 169 insertions(+), 4 deletions(-)
> >  create mode 100644 arch/riscv/include/asm/kasan.h
> >  create mode 100644 arch/riscv/mm/kasan_init.c
> >
> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> > index 8eebbc8860bb..ca2fc8ba8550 100644
> > --- a/arch/riscv/Kconfig
> > +++ b/arch/riscv/Kconfig
> > @@ -61,6 +61,7 @@ config RISCV
> >         select SPARSEMEM_STATIC if 32BIT
> >         select ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT if MMU
> >         select HAVE_ARCH_MMAP_RND_BITS
> > +       select HAVE_ARCH_KASAN if MMU && 64BIT
> >
> >  config ARCH_MMAP_RND_BITS_MIN
> >         default 18 if 64BIT
> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/ka=
san.h
> > new file mode 100644
> > index 000000000000..eb9b1a2f641c
> > --- /dev/null
> > +++ b/arch/riscv/include/asm/kasan.h
> > @@ -0,0 +1,27 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/* Copyright (C) 2019 Andes Technology Corporation */
> > +
> > +#ifndef __ASM_KASAN_H
> > +#define __ASM_KASAN_H
> > +
> > +#ifndef __ASSEMBLY__
> > +
> > +#ifdef CONFIG_KASAN
> > +
> > +#include <asm/pgtable.h>
> > +
> > +#define KASAN_SHADOW_SCALE_SHIFT       3
> > +
> > +#define KASAN_SHADOW_SIZE      (UL(1) << (38 - KASAN_SHADOW_SCALE_SHIF=
T))
> > +#define KASAN_SHADOW_START     0xffffffc000000000 // 2^64 - 2^38
> > +#define KASAN_SHADOW_END       (KASAN_SHADOW_START + KASAN_SHADOW_SIZE=
)
> > +
> > +#define KASAN_SHADOW_OFFSET    (KASAN_SHADOW_END - (1ULL << \
> > +                                       (64 - KASAN_SHADOW_SCALE_SHIFT)=
))
> > +
> > +void kasan_init(void);
> > +asmlinkage void kasan_early_init(void);
> > +
> > +#endif
> > +#endif
> > +#endif /* __ASM_KASAN_H */
> > diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/a=
sm/pgtable-64.h
> > index 7df8daa66cc8..777a1dddb3df 100644
> > --- a/arch/riscv/include/asm/pgtable-64.h
> > +++ b/arch/riscv/include/asm/pgtable-64.h
> > @@ -59,6 +59,11 @@ static inline unsigned long pud_page_vaddr(pud_t pud=
)
> >         return (unsigned long)pfn_to_virt(pud_val(pud) >> _PAGE_PFN_SHI=
FT);
> >  }
> >
> > +static inline struct page *pud_page(pud_t pud)
> > +{
> > +       return pfn_to_page(pud_val(pud) >> _PAGE_PFN_SHIFT);
> > +}
> > +
> >  #define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
> >
> >  static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
> > diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/s=
tring.h
> > index 1b5d44585962..a4451f768826 100644
> > --- a/arch/riscv/include/asm/string.h
> > +++ b/arch/riscv/include/asm/string.h
> > @@ -11,8 +11,17 @@
> >
> >  #define __HAVE_ARCH_MEMSET
> >  extern asmlinkage void *memset(void *, int, size_t);
> > +extern asmlinkage void *__memset(void *, int, size_t);
> >
> >  #define __HAVE_ARCH_MEMCPY
> >  extern asmlinkage void *memcpy(void *, const void *, size_t);
> > +extern asmlinkage void *__memcpy(void *, const void *, size_t);
> >
> > +// For those files which don't want to check by kasan.
> > +#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> > +
> > +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> > +#define memset(s, c, n) __memset(s, c, n)
> > +
> > +#endif
> >  #endif /* _ASM_RISCV_STRING_H */
> > diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> > index 72f89b7590dd..95eca23cd811 100644
> > --- a/arch/riscv/kernel/head.S
> > +++ b/arch/riscv/kernel/head.S
> > @@ -102,6 +102,9 @@ clear_bss_done:
> >         sw zero, TASK_TI_CPU(tp)
> >         la sp, init_thread_union + THREAD_SIZE
> >
> > +#ifdef CONFIG_KASAN
> > +       call kasan_early_init
> > +#endif
> >         /* Start the kernel */
> >         call parse_dtb
> >         tail start_kernel
> > diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_=
ksyms.c
> > index 4800cf703186..376bba7f65ce 100644
> > --- a/arch/riscv/kernel/riscv_ksyms.c
> > +++ b/arch/riscv/kernel/riscv_ksyms.c
> > @@ -14,3 +14,5 @@ EXPORT_SYMBOL(__asm_copy_to_user);
> >  EXPORT_SYMBOL(__asm_copy_from_user);
> >  EXPORT_SYMBOL(memset);
> >  EXPORT_SYMBOL(memcpy);
> > +EXPORT_SYMBOL(__memset);
> > +EXPORT_SYMBOL(__memcpy);
> > diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
> > index a990a6cb184f..41f7eae9bc4d 100644
> > --- a/arch/riscv/kernel/setup.c
> > +++ b/arch/riscv/kernel/setup.c
> > @@ -23,6 +23,7 @@
> >  #include <asm/smp.h>
> >  #include <asm/tlbflush.h>
> >  #include <asm/thread_info.h>
> > +#include <asm/kasan.h>
> >
> >  #ifdef CONFIG_DUMMY_CONSOLE
> >  struct screen_info screen_info =3D {
> > @@ -70,6 +71,10 @@ void __init setup_arch(char **cmdline_p)
> >         swiotlb_init(1);
> >  #endif
> >
> > +#ifdef CONFIG_KASAN
> > +       kasan_init();
> > +#endif
> > +
> >  #ifdef CONFIG_SMP
> >         setup_smp();
> >  #endif
> > diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinu=
x.lds.S
> > index 23cd1a9e52a1..97009803ba9f 100644
> > --- a/arch/riscv/kernel/vmlinux.lds.S
> > +++ b/arch/riscv/kernel/vmlinux.lds.S
> > @@ -46,6 +46,7 @@ SECTIONS
> >                 KPROBES_TEXT
> >                 ENTRY_TEXT
> >                 IRQENTRY_TEXT
> > +               SOFTIRQENTRY_TEXT
> >                 *(.fixup)
> >                 _etext =3D .;
> >         }
> > diff --git a/arch/riscv/lib/memcpy.S b/arch/riscv/lib/memcpy.S
> > index b4c477846e91..51ab716253fa 100644
> > --- a/arch/riscv/lib/memcpy.S
> > +++ b/arch/riscv/lib/memcpy.S
> > @@ -7,7 +7,8 @@
> >  #include <asm/asm.h>
> >
> >  /* void *memcpy(void *, const void *, size_t) */
> > -ENTRY(memcpy)
> > +ENTRY(__memcpy)
> > +WEAK(memcpy)
> >         move t6, a0  /* Preserve return value */
> >
> >         /* Defer to byte-oriented copy for small sizes */
> > @@ -104,4 +105,4 @@ ENTRY(memcpy)
> >         bltu a1, a3, 5b
> >  6:
> >         ret
> > -END(memcpy)
> > +END(__memcpy)
> > diff --git a/arch/riscv/lib/memset.S b/arch/riscv/lib/memset.S
> > index 5a7386b47175..34c5360c6705 100644
> > --- a/arch/riscv/lib/memset.S
> > +++ b/arch/riscv/lib/memset.S
> > @@ -8,7 +8,8 @@
> >  #include <asm/asm.h>
> >
> >  /* void *memset(void *, int, size_t) */
> > -ENTRY(memset)
> > +ENTRY(__memset)
> > +WEAK(memset)
> >         move t0, a0  /* Preserve return value */
> >
> >         /* Defer to byte-oriented fill for small sizes */
> > @@ -109,4 +110,4 @@ ENTRY(memset)
> >         bltu t0, a3, 5b
> >  6:
> >         ret
> > -END(memset)
> > +END(__memset)
> > diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
> > index 9d9a17335686..b8a8ca71f86e 100644
> > --- a/arch/riscv/mm/Makefile
> > +++ b/arch/riscv/mm/Makefile
> > @@ -17,3 +17,9 @@ ifeq ($(CONFIG_MMU),y)
> >  obj-$(CONFIG_SMP) +=3D tlbflush.o
> >  endif
> >  obj-$(CONFIG_HUGETLB_PAGE) +=3D hugetlbpage.o
> > +obj-$(CONFIG_KASAN)   +=3D kasan_init.o
> > +
> > +ifdef CONFIG_KASAN
> > +KASAN_SANITIZE_kasan_init.o :=3D n
> > +KASAN_SANITIZE_init.o :=3D n
> > +endif
> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > new file mode 100644
> > index 000000000000..c3152768cdbe
> > --- /dev/null
> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -0,0 +1,104 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +// Copyright (C) 2019 Andes Technology Corporation
> > +
> > +#include <linux/pfn.h>
> > +#include <linux/init_task.h>
> > +#include <linux/kasan.h>
> > +#include <linux/kernel.h>
> > +#include <linux/memblock.h>
> > +#include <asm/tlbflush.h>
> > +#include <asm/pgtable.h>
> > +#include <asm/fixmap.h>
> > +
> > +extern pgd_t early_pg_dir[PTRS_PER_PGD];
> > +asmlinkage void __init kasan_early_init(void)
> > +{
> > +       uintptr_t i;
> > +       pgd_t *pgd =3D early_pg_dir + pgd_index(KASAN_SHADOW_START);
> > +
> > +       for (i =3D 0; i < PTRS_PER_PTE; ++i)
> > +               set_pte(kasan_early_shadow_pte + i,
> > +                       mk_pte(virt_to_page(kasan_early_shadow_page),
> > +                       PAGE_KERNEL));
> > +
> > +       for (i =3D 0; i < PTRS_PER_PMD; ++i)
> > +               set_pmd(kasan_early_shadow_pmd + i,
> > +                pfn_pmd(PFN_DOWN(__pa((uintptr_t)kasan_early_shadow_pt=
e)),
> > +                       __pgprot(_PAGE_TABLE)));
> > +
> > +       for (i =3D KASAN_SHADOW_START; i < KASAN_SHADOW_END;
> > +            i +=3D PGDIR_SIZE, ++pgd)
> > +               set_pgd(pgd,
> > +                pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_p=
md))),
> > +                       __pgprot(_PAGE_TABLE)));
> > +
> > +       // init for swapper_pg_dir
> > +       pgd =3D pgd_offset_k(KASAN_SHADOW_START);
> > +
> > +       for (i =3D KASAN_SHADOW_START; i < KASAN_SHADOW_END;
> > +            i +=3D PGDIR_SIZE, ++pgd)
> > +               set_pgd(pgd,
> > +                pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_p=
md))),
> > +                       __pgprot(_PAGE_TABLE)));
> > +
> > +       flush_tlb_all();
> > +}
> > +
> > +static void __init populate(void *start, void *end)
> > +{
> > +       unsigned long i;
> > +       unsigned long vaddr =3D (unsigned long)start & PAGE_MASK;
> > +       unsigned long vend =3D PAGE_ALIGN((unsigned long)end);
> > +       unsigned long n_pages =3D (vend - vaddr) / PAGE_SIZE;
> > +       unsigned long n_pmds =3D
> > +               (n_pages % PTRS_PER_PTE) ? n_pages / PTRS_PER_PTE + 1 :
> > +                                               n_pages / PTRS_PER_PTE;
> > +       pgd_t *pgd =3D pgd_offset_k(vaddr);
> > +       pmd_t *pmd =3D memblock_alloc(n_pmds * sizeof(pmd_t), PAGE_SIZE=
);
> > +       pte_t *pte =3D memblock_alloc(n_pages * sizeof(pte_t), PAGE_SIZ=
E);
> > +
> > +       for (i =3D 0; i < n_pages; i++) {
> > +               phys_addr_t phys =3D memblock_phys_alloc(PAGE_SIZE, PAG=
E_SIZE);
> > +
> > +               set_pte(pte + i, pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
> > +       }
> > +
> > +       for (i =3D 0; i < n_pages; ++pmd, i +=3D PTRS_PER_PTE)
> > +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa((uintptr_t)(pte + i)=
)),
> > +                               __pgprot(_PAGE_TABLE)));
> > +
> > +       for (i =3D vaddr; i < vend; i +=3D PGDIR_SIZE, ++pgd)
> > +               set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(((uintptr_t)pmd))),
> ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
> > +                               __pgprot(_PAGE_TABLE)));
> > +
>=20
> Hi Nick,
>=20
> I verify this patch in Qemu and Unleashed board.
> I found it works well if DRAM size is less than 4GB.
> It will get an access fault if the DRAM size is larger than 4GB.
>=20
> I spend some time to debug this case and I found it hang in the
> following memset().
> It is because the mapping is not created correctly. I check the page
> table creating logic again and I found it always sets the last pmd
> here.
Hi Greentime,

Thanks! I would fix it in v4 patch.

Nick.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191022033051.GB29285%40andestech.com.
