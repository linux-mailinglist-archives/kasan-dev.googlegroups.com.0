Return-Path: <kasan-dev+bncBCPOL6NTRIARBDFHZPXQKGQEIW34TUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A806111DA4A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 00:55:57 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id s9sf588706ilk.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 15:55:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576194956; cv=pass;
        d=google.com; s=arc-20160816;
        b=ByEoT3vg1hD+e/PkzAvAXRDUZQ4ZGhtuQXd+JapYGR5U3d9gHP1yhReUHPuoLNHD9X
         fnmRmbgW+B7/A3C5wjcKrFZYZdbotsxM/KFdwX3SHILV+YvBYaUKPGV3D9ivUoyMVMOT
         i6ul4UpJbblOa6RPgn2alHmwPd0K8QgfPgiSv+aNlGO6u2Sr+qW1xwzsqoJl5nIxEG34
         rThiUr58u7wtgd4GcUuRA2dkWKyLLHCQbC2kmXwWnVDPJHydwLvC0wSf+37fSwoZZgJN
         RK6qy949MUpCEWyjFZravK35XpkWj0y0bs6AwNK9qWdL7dW7e5Rooy41EAz42IaVBXW3
         CNSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=FQrFE2nesYRO+6qF8Hju7L0ajSUskKX27fNnam8NGG4=;
        b=VEVZ7rc8oIesmnsQr3fjcXfXL/jFbT1bWNbuS803x4pEGk8RvL7wLCcNd/PJeEji0d
         7hrAFPgO++EkxZ8ALVkqd+i6GlE9Sv6qP1dA8guwEktpm+HzCOdzIDcHFfIAaNU9oMFa
         YJ2qHXqkj8qlkif/DAo/XGGcAL7VHNnN+LYPcNwk/uvA13uvepRzlswlY3hSoidQBQrg
         rc796dBALf5CMu1Zoz/oSXEltRsj/i1UrJa0MsMNDza3aeoJ5Bb+0GKbt47pZJ99QpBK
         BqEMCniEmuHXFKsGDm4OgyoIz/s5ILDPemn2T4WA6k1PrUl9zbu2Z5LFjMOXOzYC0V92
         38EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=DfRCIRQ6;
       spf=pass (google.com: domain of jniethe5@gmail.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=jniethe5@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQrFE2nesYRO+6qF8Hju7L0ajSUskKX27fNnam8NGG4=;
        b=PSoWWLnMJWx+WDXtCt0ldQXkblUjh51nH+02DfiFtP/Zs2xBhzzemuvmrydmeX2mgr
         iDB/Cu5QVJ2Qanq2bv16rBXFGbhxPw/8/wc1G0XRbFDfxQo3h58BGDWdL6wM4tYZavJO
         gTb1ZqLVjsn+t4+12Qu3fr180s3otgnMa86R0fFLv5Pt/f6Pi+SpkLEC1A3SlcqjN52D
         05Jo9r4g6aZVnbE5/xsGzCAhs1pwqzqK3uv8liwLhXMZLHLnwjN6fLsxq6lmyBFvbcZE
         56jHPP7XaGqTxPyGgiF6WyhklNjzNw1CGvnBU7I2qThK04pjp3uz2SaK23KpNDHKDc9t
         MQrw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQrFE2nesYRO+6qF8Hju7L0ajSUskKX27fNnam8NGG4=;
        b=ZO4nzSkbr+pJdA/fzPDG4s69oOYi63p5hup1dJLQY3U+mnfgN209E+PqVKK31Pu010
         VoxG+7y9/f7x/T37lBQCzmJIo7Xa1gomsVUkIx+jNA7P25eeAmgiOA5Gr8onZgDxplWb
         jQKCgQVqO4BUzF0eTJJgKYsQTWNauhL9zkxZX+NanXvvJTRwsvZUVpIWt/FqzGrKyybu
         REdlQvtZd+C4wSRJrWb+5gwgJgqByhmxD2luxcQU3oMHf4HKmEFPXkfEik/wu9CSAj1I
         sipOsSTpUoqEO3jV5xWZYa5+yaTU/rXuKYTcbB4ruTeisEigYKAgLfAgsjH/cK+DVtCr
         KdhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQrFE2nesYRO+6qF8Hju7L0ajSUskKX27fNnam8NGG4=;
        b=mtBNVN/E4gpdThsrPYcnlkU1JGo+ZaoS1wbztIWNEcJda8grSOWfjm2pvgdUYPYp/c
         iyxFp5XJ6dKZb0KXZmn4GDqqQmJOeb2VpT+mWDCuv9RgCtaQB+GNFnEZ3hzkCy5znV4F
         eXbi/fZaMBcL3a945UxJtlp1BmYoizOp9IHp1DkqYOy+VZM3Im//zMFCvP6bsgiRYucA
         0/OZgC5bNYb+og75Q+c07k9VZm/GOFzzaa56+rFFUhqUO9o6ddwHwpbW2kN8/iy4s7Yn
         uIx07NNBhhKZPVOvxWOIHGOWC1hrNW6mtC4J5Lx7yP5aQW25SO9Utp190me4bq4a2+t5
         aS0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUOEAPCpPjZ5N38scS+2jM0dIl4LYYrb6s6bub1XOTmGmw2OdSq
	b8HaIR0z/ktKGaY7lzqB6Xw=
X-Google-Smtp-Source: APXvYqxG+77YGN9RIVadp5kgKRyfQyGwgxp0xtMKezQHRmVqfqCkJKLltOZ5hDyTCyDHRjMwOjqIaw==
X-Received: by 2002:a92:3984:: with SMTP id h4mr10412600ilf.36.1576194956135;
        Thu, 12 Dec 2019 15:55:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:dd4a:: with SMTP id u10ls408846iop.5.gmail; Thu, 12 Dec
 2019 15:55:55 -0800 (PST)
X-Received: by 2002:a6b:6202:: with SMTP id f2mr5252378iog.272.1576194955617;
        Thu, 12 Dec 2019 15:55:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576194955; cv=none;
        d=google.com; s=arc-20160816;
        b=wcI+lQN0dTheeIb++Zs7p/IqYfG6LPXLg9xCXRXOuNshhMHKH4gNdQORJO875BmOoo
         1nZi8CiQ1eKSTdReLl8DSb3PXJft3Rn9n/j8ubIulM7DiOgF0ZXEt+dEvGJZdu2IxYwm
         WvzYE4x6g5/J1X7GRHGyUpdwoKUx7iALuTl5dC+uHyh6bnQjcI/vPh7tO0mOaXaGRKri
         LNDW4DmmolMV2tmSVlLftQnshfs/aW/EZDrc4Nrabsbdq//7oqa1bmtcNFq4VTgev0O5
         awcCnS/yIgAVZWrCFHSNI/Ao2r24JkGu/bsWlVwTzSQIvweUsCQEG0z5FmNBPAKeVLmC
         LUgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ztKiKS9kDpcRmXJKe1XqlJokHmkmscn2Mwt+6zEVKRM=;
        b=vDETkw4ITi1y3nM/rDxYHBnoPDWjlB1wiTSwkMElOButuucO7NFpSrZELlpNSHrJid
         zZVeZSwxbspWi0lsoDUwNQBCoLXhTUrqU5DWCSAGOYi/jop1F8e2O33nZ70513BAeTxM
         GwbATEpeU/ifr36Exb7fpZvIeHFddONfmIomSXqIt6cgoZBNs5kMjdCvTLIMIZEbRWri
         70Sl66aiTNImxGLsmPl994q3sSg4KWWG8bJpcWqfQgJRycbzBXakJ5/LEOqX9uOAYlq6
         79h2Ji05x7uEt8OVgJ7WdXQce5cByFt3yha34uGjt6DNcx50PRbdqYb2g+6GyvNdGOVl
         GR5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=DfRCIRQ6;
       spf=pass (google.com: domain of jniethe5@gmail.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=jniethe5@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id k9si267226ili.4.2019.12.12.15.55.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 15:55:55 -0800 (PST)
Received-SPF: pass (google.com: domain of jniethe5@gmail.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id o9so3970717ote.2
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 15:55:55 -0800 (PST)
X-Received: by 2002:a05:6830:50:: with SMTP id d16mr11890289otp.155.1576194954730;
 Thu, 12 Dec 2019 15:55:54 -0800 (PST)
MIME-Version: 1.0
References: <20191212151656.26151-1-dja@axtens.net> <20191212151656.26151-4-dja@axtens.net>
In-Reply-To: <20191212151656.26151-4-dja@axtens.net>
From: Jordan Niethe <jniethe5@gmail.com>
Date: Fri, 13 Dec 2019 10:55:43 +1100
Message-ID: <CACzsE9q1iLgoMLzVy0AYeRvWbj=kY-Ry52y84PGtWw3YXXFipA@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	christophe.leroy@c-s.fr, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com, 
	Michael Ellerman <mpe@ellerman.id.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jniethe5@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=DfRCIRQ6;       spf=pass
 (google.com: domain of jniethe5@gmail.com designates 2607:f8b0:4864:20::343
 as permitted sender) smtp.mailfrom=jniethe5@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 13, 2019 at 2:19 AM Daniel Axtens <dja@axtens.net> wrote:
>
> KASAN support on Book3S is a bit tricky to get right:
>
>  - It would be good to support inline instrumentation so as to be able to
>    catch stack issues that cannot be caught with outline mode.
>
>  - Inline instrumentation requires a fixed offset.
>
>  - Book3S runs code in real mode after booting. Most notably a lot of KVM
>    runs in real mode, and it would be good to be able to instrument it.
>
>  - Because code runs in real mode after boot, the offset has to point to
>    valid memory both in and out of real mode.
>
>    [For those not immersed in ppc64, in real mode, the top nibble or 2 bits
>    (depending on radix/hash mmu) of the address is ignored. The linear
>    mapping is placed at 0xc000000000000000. This means that a pointer to
>    part of the linear mapping will work both in real mode, where it will be
>    interpreted as a physical address of the form 0x000..., and out of real
>    mode, where it will go via the linear mapping.]
>

How does hash or radix mmu mode effect how many bits are ignored in real mode?

> One approach is just to give up on inline instrumentation. This way all
> checks can be delayed until after everything set is up correctly, and the
> address-to-shadow calculations can be overridden. However, the features and
> speed boost provided by inline instrumentation are worth trying to do
> better.
>
> If _at compile time_ it is known how much contiguous physical memory a
> system has, the top 1/8th of the first block of physical memory can be set
> aside for the shadow. This is a big hammer and comes with 3 big
> consequences:
>
>  - there's no nice way to handle physically discontiguous memory, so only
>    the first physical memory block can be used.
>
>  - kernels will simply fail to boot on machines with less memory than
>    specified when compiling.
>
>  - kernels running on machines with more memory than specified when
>    compiling will simply ignore the extra memory.
>
> Implement and document KASAN this way. The current implementation is Radix
> only.
>
> Despite the limitations, it can still find bugs,
> e.g. http://patchwork.ozlabs.org/patch/1103775/
>
> At the moment, this physical memory limit must be set _even for outline
> mode_. This may be changed in a later series - a different implementation
> could be added for outline mode that dynamically allocates shadow at a
> fixed offset. For example, see https://patchwork.ozlabs.org/patch/795211/
>
> Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix version
> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> ---
> Changes since v2:
>
>  - Address feedback from Christophe around cleanups and docs.
>  - Address feedback from Balbir: at this point I don't have a good solution
>    for the issues you identify around the limitations of the inline implementation
>    but I think that it's worth trying to get the stack instrumentation support.
>    I'm happy to have an alternative and more flexible outline mode - I had
>    envisoned this would be called 'lightweight' mode as it imposes fewer restrictions.
>    I've linked to your implementation. I think it's best to add it in a follow-up series.
>  - Made the default PHYS_MEM_SIZE_FOR_KASAN value 1024MB. I think most people have
>    guests with at least that much memory in the Radix 64s case so it's a much
>    saner default - it means that if you just turn on KASAN without reading the
>    docs you're much more likely to have a bootable kernel, which you will never
>    have if the value is set to zero! I'm happy to bikeshed the value if we want.
>
> Changes since v1:
>  - Landed kasan vmalloc support upstream
>  - Lots of feedback from Christophe.
>
> Changes since the rfc:
>
>  - Boots real and virtual hardware, kvm works.
>
>  - disabled reporting when we're checking the stack for exception
>    frames. The behaviour isn't wrong, just incompatible with KASAN.
>
>  - Documentation!
>
>  - Dropped old module stuff in favour of KASAN_VMALLOC.
>
> The bugs with ftrace and kuap were due to kernel bloat pushing
> prom_init calls to be done via the plt. Because we did not have
> a relocatable kernel, and they are done very early, this caused
> everything to explode. Compile with CONFIG_RELOCATABLE!
> ---
>  Documentation/dev-tools/kasan.rst             |   8 +-
>  Documentation/powerpc/kasan.txt               | 112 +++++++++++++++++-
>  arch/powerpc/Kconfig                          |   3 +
>  arch/powerpc/Kconfig.debug                    |  21 ++++
>  arch/powerpc/Makefile                         |  11 ++
>  arch/powerpc/include/asm/book3s/64/hash.h     |   4 +
>  arch/powerpc/include/asm/book3s/64/pgtable.h  |   7 ++
>  arch/powerpc/include/asm/book3s/64/radix.h    |   5 +
>  arch/powerpc/include/asm/kasan.h              |  21 +++-
>  arch/powerpc/kernel/process.c                 |   8 ++
>  arch/powerpc/kernel/prom.c                    |  64 +++++++++-
>  arch/powerpc/mm/kasan/Makefile                |   3 +-
>  .../mm/kasan/{kasan_init_32.c => init_32.c}   |   0
>  arch/powerpc/mm/kasan/init_book3s_64.c        |  72 +++++++++++
>  14 files changed, 330 insertions(+), 9 deletions(-)
>  rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
>  create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 4af2b5d2c9b4..d99dc580bc11 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -22,8 +22,9 @@ global variables yet.
>  Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
>
>  Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
> -architectures. It is also supported on 32-bit powerpc kernels. Tag-based KASAN
> -is supported only on arm64.
> +architectures. It is also supported on powerpc, for 32-bit kernels, and for
> +64-bit kernels running under the Radix MMU. Tag-based KASAN is supported only
> +on arm64.
>
>  Usage
>  -----
> @@ -256,7 +257,8 @@ CONFIG_KASAN_VMALLOC
>  ~~~~~~~~~~~~~~~~~~~~
>
>  With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
> -cost of greater memory usage. Currently this is only supported on x86.
> +cost of greater memory usage. Currently this is optional on x86, and
> +required on 64-bit powerpc.
>
>  This works by hooking into vmalloc and vmap, and dynamically
>  allocating real shadow memory to back the mappings.
> diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
> index a85ce2ff8244..f134a91600ad 100644
> --- a/Documentation/powerpc/kasan.txt
> +++ b/Documentation/powerpc/kasan.txt
> @@ -1,4 +1,4 @@
> -KASAN is supported on powerpc on 32-bit only.
> +KASAN is supported on powerpc on 32-bit and Radix 64-bit only.
>
>  32 bit support
>  ==============
> @@ -10,3 +10,113 @@ fixmap area and occupies one eighth of the total kernel virtual memory space.
>
>  Instrumentation of the vmalloc area is not currently supported, but modules
>  are.
> +
> +64 bit support
> +==============
> +
> +Currently, only the radix MMU is supported. There have been versions for Book3E
> +processors floating around on the mailing list, but nothing has been merged.
> +
> +KASAN support on Book3S is a bit tricky to get right:
> +
> + - It would be good to support inline instrumentation so as to be able to catch
> +   stack issues that cannot be caught with outline mode.
> +
> + - Inline instrumentation requires a fixed offset.
> +
> + - Book3S runs code in real mode after booting. Most notably a lot of KVM runs
> +   in real mode, and it would be good to be able to instrument it.
> +
> + - Because code runs in real mode after boot, the offset has to point to
> +   valid memory both in and out of real mode.
> +
> +One approach is just to give up on inline instrumentation. This way all checks
> +can be delayed until after everything set is up correctly, and the
> +address-to-shadow calculations can be overridden. However, the features and
> +speed boost provided by inline instrumentation are worth trying to do better.
> +
> +If _at compile time_ it is known how much contiguous physical memory a system
> +has, the top 1/8th of the first block of physical memory can be set aside for
> +the shadow. This is a big hammer and comes with 3 big consequences:
> +
> + - there's no nice way to handle physically discontiguous memory, so only the
> +   first physical memory block can be used.
> +
> + - kernels will simply fail to boot on machines with less memory than specified
> +   when compiling.
> +
> + - kernels running on machines with more memory than specified when compiling
> +   will simply ignore the extra memory.
> +
> +At the moment, this physical memory limit must be set _even for outline mode_.
> +This may be changed in a future version - a different implementation could be
> +added for outline mode that dynamically allocates shadow at a fixed offset.
> +For example, see https://patchwork.ozlabs.org/patch/795211/
> +
> +This value is configured in CONFIG_PHYS_MEM_SIZE_FOR_KASAN.
> +
> +Tips
> +----
> +
> + - Compile with CONFIG_RELOCATABLE.
> +
> +   In development, boot hangs were observed when building with ftrace and KUAP
> +   on. These ended up being due to kernel bloat pushing prom_init calls to be
> +   done via the PLT. Because the kernel was not relocatable, and the calls are
> +   done very early, this caused execution to jump off into somewhere
> +   invalid. Enabling relocation fixes this.
> +
> +NUMA/discontiguous physical memory
> +----------------------------------
> +
> +Currently the code cannot really deal with discontiguous physical memory. Only
> +physical memory that is contiguous from physical address zero can be used. The
> +size of that memory, not total memory, must be specified when configuring the
> +kernel.
> +
> +Discontiguous memory can occur on machines with memory spread across multiple
> +nodes. For example, on a Talos II with 64GB of RAM:
> +
> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
> + - then there's a gap,
> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_0000_0000
> +
> +This can create _significant_ issues:
> +
> + - If the machine is treated as having 64GB of _contiguous_ RAM, the
> +   instrumentation would assume that it ran from 0x0 to
> +   0x0000_0010_0000_0000. The last 1/8th - 0x0000_000e_0000_0000 to
> +   0x0000_0010_0000_0000 would be reserved as the shadow region. But when the
> +   kernel tried to access any of that, it would be trying to access pages that
> +   are not physically present.
> +
> + - If the shadow region size is based on the top address, then the shadow
> +   region would be 0x2008_0000_0000 / 8 = 0x0401_0000_0000 bytes = 4100 GB of
> +   memory, clearly more than the 64GB of RAM physically present.
> +
> +Therefore, the code currently is restricted to dealing with memory in the node
> +starting at 0x0. For this system, that's 32GB. If a contiguous physical memory
> +size greater than the size of the first contiguous region of memory is
> +specified, the system will be unable to boot or even print an error message.
> +
> +The layout of a system's memory can be observed in the messages that the Radix
> +MMU prints on boot. The Talos II discussed earlier has:
> +
> +radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB pages (exec)
> +radix-mmu: Mapped 0x0000000040000000-0x0000000800000000 with 1.00 GiB pages
> +radix-mmu: Mapped 0x0000200000000000-0x0000200800000000 with 1.00 GiB pages
> +
> +As discussed, this system would be configured for 32768 MB.
> +
> +Another system prints:
> +
> +radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB pages (exec)
> +radix-mmu: Mapped 0x0000000040000000-0x0000002000000000 with 1.00 GiB pages
> +radix-mmu: Mapped 0x0000200000000000-0x0000202000000000 with 1.00 GiB pages
> +
> +This machine has more memory: 0x0000_0040_0000_0000 total, but only
> +0x0000_0020_0000_0000 is physically contiguous from zero, so it would be
> +configured for 131072 MB of physically contiguous memory.
> +
> +This restriction currently also affects outline mode, but this could be
> +changed in future if an alternative outline implementation is added.
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 6987b0832e5f..2561446e85a8 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -173,6 +173,9 @@ config PPC
>         select HAVE_ARCH_HUGE_VMAP              if PPC_BOOK3S_64 && PPC_RADIX_MMU
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_KASAN                  if PPC32
> +       select HAVE_ARCH_KASAN                  if PPC_BOOK3S_64 && PPC_RADIX_MMU
> +       select HAVE_ARCH_KASAN_VMALLOC          if PPC_BOOK3S_64 && PPC_RADIX_MMU
> +       select KASAN_VMALLOC                    if KASAN && PPC_BOOK3S_64
>         select HAVE_ARCH_KGDB
>         select HAVE_ARCH_MMAP_RND_BITS
>         select HAVE_ARCH_MMAP_RND_COMPAT_BITS   if COMPAT
> diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
> index 4e1d39847462..5c454f8fa24b 100644
> --- a/arch/powerpc/Kconfig.debug
> +++ b/arch/powerpc/Kconfig.debug
> @@ -394,6 +394,27 @@ config PPC_FAST_ENDIAN_SWITCH
>         help
>           If you're unsure what this is, say N.
>
> +config PHYS_MEM_SIZE_FOR_KASAN
> +       int "Contiguous physical memory size for KASAN (MB)" if KASAN && PPC_BOOK3S_64
> +       default 1024
> +       help
> +
> +         To get inline instrumentation support for KASAN on 64-bit Book3S
> +         machines, you need to know how much contiguous physical memory your
> +         system has. A shadow offset will be calculated based on this figure,
> +         which will be compiled in to the kernel. KASAN will use this offset
> +         to access its shadow region, which is used to verify memory accesses.
> +
> +         If you attempt to boot on a system with less memory than you specify
> +         here, your system will fail to boot very early in the process. If you
> +         boot on a system with more memory than you specify, the extra memory
> +         will wasted - it will be reserved and not used.
> +
> +         For systems with discontiguous blocks of physical memory, specify the
> +         size of the block starting at 0x0. You can determine this by looking
> +         at the memory layout info printed to dmesg by the radix MMU code
> +         early in boot. See Documentation/powerpc/kasan.txt.
> +
>  config KASAN_SHADOW_OFFSET
>         hex
>         depends on KASAN
> diff --git a/arch/powerpc/Makefile b/arch/powerpc/Makefile
> index f35730548e42..eff693527462 100644
> --- a/arch/powerpc/Makefile
> +++ b/arch/powerpc/Makefile
> @@ -230,6 +230,17 @@ ifdef CONFIG_476FPE_ERR46
>                 -T $(srctree)/arch/powerpc/platforms/44x/ppc476_modules.lds
>  endif
>
> +ifdef CONFIG_PPC_BOOK3S_64
> +# The KASAN shadow offset is such that linear map (0xc000...) is shadowed by
> +# the last 8th of linearly mapped physical memory. This way, if the code uses
> +# 0xc addresses throughout, accesses work both in in real mode (where the top
> +# 2 bits are ignored) and outside of real mode.
> +#
> +# 0xc000000000000000 >> 3 = 0xa800000000000000 = 12105675798371893248
> +KASAN_SHADOW_OFFSET = $(shell echo 7 \* 1024 \* 1024 \* $(CONFIG_PHYS_MEM_SIZE_FOR_KASAN) / 8 + 12105675798371893248 | bc)
> +KBUILD_CFLAGS += -DKASAN_SHADOW_OFFSET=$(KASAN_SHADOW_OFFSET)UL
> +endif
> +
>  # No AltiVec or VSX instructions when building kernel
>  KBUILD_CFLAGS += $(call cc-option,-mno-altivec)
>  KBUILD_CFLAGS += $(call cc-option,-mno-vsx)
> diff --git a/arch/powerpc/include/asm/book3s/64/hash.h b/arch/powerpc/include/asm/book3s/64/hash.h
> index 2781ebf6add4..fce329b8452e 100644
> --- a/arch/powerpc/include/asm/book3s/64/hash.h
> +++ b/arch/powerpc/include/asm/book3s/64/hash.h
> @@ -18,6 +18,10 @@
>  #include <asm/book3s/64/hash-4k.h>
>  #endif
>
> +#define H_PTRS_PER_PTE         (1 << H_PTE_INDEX_SIZE)
> +#define H_PTRS_PER_PMD         (1 << H_PMD_INDEX_SIZE)
> +#define H_PTRS_PER_PUD         (1 << H_PUD_INDEX_SIZE)
> +
>  /* Bits to set in a PMD/PUD/PGD entry valid bit*/
>  #define HASH_PMD_VAL_BITS              (0x8000000000000000UL)
>  #define HASH_PUD_VAL_BITS              (0x8000000000000000UL)
> diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/include/asm/book3s/64/pgtable.h
> index b01624e5c467..209817235a44 100644
> --- a/arch/powerpc/include/asm/book3s/64/pgtable.h
> +++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
> @@ -231,6 +231,13 @@ extern unsigned long __pmd_frag_size_shift;
>  #define PTRS_PER_PUD   (1 << PUD_INDEX_SIZE)
>  #define PTRS_PER_PGD   (1 << PGD_INDEX_SIZE)
>
> +#define MAX_PTRS_PER_PTE       ((H_PTRS_PER_PTE > R_PTRS_PER_PTE) ? \
> +                                 H_PTRS_PER_PTE : R_PTRS_PER_PTE)
> +#define MAX_PTRS_PER_PMD       ((H_PTRS_PER_PMD > R_PTRS_PER_PMD) ? \
> +                                 H_PTRS_PER_PMD : R_PTRS_PER_PMD)
> +#define MAX_PTRS_PER_PUD       ((H_PTRS_PER_PUD > R_PTRS_PER_PUD) ? \
> +                                 H_PTRS_PER_PUD : R_PTRS_PER_PUD)
> +
>  /* PMD_SHIFT determines what a second-level page table entry can map */
>  #define PMD_SHIFT      (PAGE_SHIFT + PTE_INDEX_SIZE)
>  #define PMD_SIZE       (1UL << PMD_SHIFT)
> diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/include/asm/book3s/64/radix.h
> index d97db3ad9aae..4f826259de71 100644
> --- a/arch/powerpc/include/asm/book3s/64/radix.h
> +++ b/arch/powerpc/include/asm/book3s/64/radix.h
> @@ -35,6 +35,11 @@
>  #define RADIX_PMD_SHIFT                (PAGE_SHIFT + RADIX_PTE_INDEX_SIZE)
>  #define RADIX_PUD_SHIFT                (RADIX_PMD_SHIFT + RADIX_PMD_INDEX_SIZE)
>  #define RADIX_PGD_SHIFT                (RADIX_PUD_SHIFT + RADIX_PUD_INDEX_SIZE)
> +
> +#define R_PTRS_PER_PTE         (1 << RADIX_PTE_INDEX_SIZE)
> +#define R_PTRS_PER_PMD         (1 << RADIX_PMD_INDEX_SIZE)
> +#define R_PTRS_PER_PUD         (1 << RADIX_PUD_INDEX_SIZE)
> +
>  /*
>   * Size of EA range mapped by our pagetables.
>   */
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
> index 296e51c2f066..f18268cbdc33 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -2,6 +2,9 @@
>  #ifndef __ASM_KASAN_H
>  #define __ASM_KASAN_H
>
> +#include <asm/page.h>
> +#include <asm/pgtable.h>
> +
>  #ifdef CONFIG_KASAN
>  #define _GLOBAL_KASAN(fn)      _GLOBAL(__##fn)
>  #define _GLOBAL_TOC_KASAN(fn)  _GLOBAL_TOC(__##fn)
> @@ -14,13 +17,19 @@
>
>  #ifndef __ASSEMBLY__
>
> -#include <asm/page.h>
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +#else
> +static inline void kasan_init(void) { }
> +#endif
>
>  #define KASAN_SHADOW_SCALE_SHIFT       3
>
>  #define KASAN_SHADOW_START     (KASAN_SHADOW_OFFSET + \
>                                  (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>
> +#ifdef CONFIG_PPC32
> +
>  #define KASAN_SHADOW_OFFSET    ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>
>  #define KASAN_SHADOW_END       0UL
> @@ -30,11 +39,17 @@
>  #ifdef CONFIG_KASAN
>  void kasan_early_init(void);
>  void kasan_mmu_init(void);
> -void kasan_init(void);
>  #else
> -static inline void kasan_init(void) { }
>  static inline void kasan_mmu_init(void) { }
>  #endif
> +#endif
> +
> +#ifdef CONFIG_PPC_BOOK3S_64
> +
> +#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
> +                               1024 * 1024 * 1 / 8)
> +
> +#endif /* CONFIG_PPC_BOOK3S_64 */
>
>  #endif /* __ASSEMBLY */
>  #endif
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
> index 4df94b6e2f32..c60ff299f39b 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2081,7 +2081,14 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
>                 /*
>                  * See if this is an exception frame.
>                  * We look for the "regshere" marker in the current frame.
> +                *
> +                * KASAN may complain about this. If it is an exception frame,
> +                * we won't have unpoisoned the stack in asm when we set the
> +                * exception marker. If it's not an exception frame, who knows
> +                * how things are laid out - the shadow could be in any state
> +                * at all. Just disable KASAN reporting for now.
>                  */
> +               kasan_disable_current();
>                 if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
>                     && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
>                         struct pt_regs *regs = (struct pt_regs *)
> @@ -2091,6 +2098,7 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
>                                regs->trap, (void *)regs->nip, (void *)lr);
>                         firstframe = 1;
>                 }
> +               kasan_enable_current();
>
>                 sp = newsp;
>         } while (count++ < kstack_depth_to_print);
> diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
> index 6620f37abe73..d994c7c39c8d 100644
> --- a/arch/powerpc/kernel/prom.c
> +++ b/arch/powerpc/kernel/prom.c
> @@ -72,6 +72,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
>  u64 ppc64_rma_size;
>  #endif
>  static phys_addr_t first_memblock_size;
> +static phys_addr_t top_phys_addr;
>  static int __initdata boot_cpu_count;
>
>  static int __init early_parse_mem(char *p)
> @@ -449,6 +450,26 @@ static bool validate_mem_limit(u64 base, u64 *size)
>  {
>         u64 max_mem = 1UL << (MAX_PHYSMEM_BITS);
>
> +       /*
> +        * To handle the NUMA/discontiguous memory case, don't allow a block
> +        * to be added if it falls completely beyond the configured physical
> +        * memory. Print an informational message.
> +        *
> +        * Frustratingly we also see this with qemu - it seems to split the
> +        * specified memory into a number of smaller blocks. If this happens
> +        * under qemu, it probably represents misconfiguration. So we want
> +        * the message to be noticeable, but not shouty.
> +        *
> +        * See Documentation/powerpc/kasan.txt
> +        */
> +       if (IS_ENABLED(CONFIG_KASAN) &&
> +           (base >= ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20))) {
> +               pr_warn("KASAN: not adding memory block at %llx (size %llx)\n"
> +                       "This could be due to discontiguous memory or kernel misconfiguration.",
> +                       base, *size);
> +               return false;
> +       }
> +
>         if (base >= max_mem)
>                 return false;
>         if ((base + *size) > max_mem)
> @@ -572,8 +593,11 @@ void __init early_init_dt_add_memory_arch(u64 base, u64 size)
>
>         /* Add the chunk to the MEMBLOCK list */
>         if (add_mem_to_memblock) {
> -               if (validate_mem_limit(base, &size))
> +               if (validate_mem_limit(base, &size)) {
>                         memblock_add(base, size);
> +                       if (base + size > top_phys_addr)
> +                               top_phys_addr = base + size;
> +               }
>         }
>  }
>
> @@ -613,6 +637,8 @@ static void __init early_reserve_mem_dt(void)
>  static void __init early_reserve_mem(void)
>  {
>         __be64 *reserve_map;
> +       phys_addr_t kasan_shadow_start;
> +       phys_addr_t kasan_memory_size;
>
>         reserve_map = (__be64 *)(((unsigned long)initial_boot_params) +
>                         fdt_off_mem_rsvmap(initial_boot_params));
> @@ -651,6 +677,42 @@ static void __init early_reserve_mem(void)
>                 return;
>         }
>  #endif
> +
> +       if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
> +               kasan_memory_size =
> +                       ((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
> +
> +               if (top_phys_addr < kasan_memory_size) {
> +                       /*
> +                        * We are doomed. We shouldn't even be able to get this
> +                        * far, but we do in qemu. If we continue and turn
> +                        * relocations on, we'll take fatal page faults for
> +                        * memory that's not physically present. Instead,
> +                        * panic() here: it will be saved to __log_buf even if
> +                        * it doesn't get printed to the console.
> +                        */
> +                       panic("Tried to book a KASAN kernel configured for %u MB with only %llu MB! Aborting.",
> +                             CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
> +                             (u64)(top_phys_addr >> 20));
> +               } else if (top_phys_addr > kasan_memory_size) {
> +                       /* print a biiiig warning in hopes people notice */
> +                       pr_err("===========================================\n"
> +                               "Physical memory exceeds compiled-in maximum!\n"
> +                               "This kernel was compiled for KASAN with %u MB physical memory.\n"
> +                               "The physical memory detected is at least %llu MB.\n"
> +                               "Memory above the compiled limit will not be used!\n"
> +                               "===========================================\n",
> +                               CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
> +                               (u64)(top_phys_addr >> 20));
> +               }
> +
> +               kasan_shadow_start = _ALIGN_DOWN(kasan_memory_size * 7 / 8,
> +                                                PAGE_SIZE);
> +               DBG("reserving %llx -> %llx for KASAN",
> +                   kasan_shadow_start, top_phys_addr);
> +               memblock_reserve(kasan_shadow_start,
> +                                top_phys_addr - kasan_shadow_start);
> +       }
>  }
>
>  #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
> index 6577897673dd..f02b15c78e4d 100644
> --- a/arch/powerpc/mm/kasan/Makefile
> +++ b/arch/powerpc/mm/kasan/Makefile
> @@ -2,4 +2,5 @@
>
>  KASAN_SANITIZE := n
>
> -obj-$(CONFIG_PPC32)           += kasan_init_32.o
> +obj-$(CONFIG_PPC32)           += init_32.o
> +obj-$(CONFIG_PPC_BOOK3S_64)   += init_book3s_64.o
> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
> similarity index 100%
> rename from arch/powerpc/mm/kasan/kasan_init_32.c
> rename to arch/powerpc/mm/kasan/init_32.c
> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
> new file mode 100644
> index 000000000000..f961e96be136
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -0,0 +1,72 @@
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
> +       int i;
> +       void *k_start = kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
> +       void *k_end = kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
> +
> +       pte_t pte = __pte(__pa(kasan_early_shadow_page) |
> +                         pgprot_val(PAGE_KERNEL) | _PAGE_PTE);
> +
> +       if (!early_radix_enabled())
> +               panic("KASAN requires radix!");
> +
> +       for (i = 0; i < PTRS_PER_PTE; i++)
> +               __set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
> +                            &kasan_early_shadow_pte[i], pte, 0);
> +
> +       for (i = 0; i < PTRS_PER_PMD; i++)
> +               pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
> +                                   kasan_early_shadow_pte);
> +
> +       for (i = 0; i < PTRS_PER_PUD; i++)
> +               pud_populate(&init_mm, &kasan_early_shadow_pud[i],
> +                            kasan_early_shadow_pmd);
> +
> +       memset(kasan_mem_to_shadow((void *)PAGE_OFFSET), KASAN_SHADOW_INIT,
> +              KASAN_SHADOW_SIZE);
> +
> +       kasan_populate_early_shadow(
> +               kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START),
> +               kasan_mem_to_shadow((void *)RADIX_VMALLOC_START));
> +
> +       /* leave a hole here for vmalloc */
> +
> +       kasan_populate_early_shadow(
> +               kasan_mem_to_shadow((void *)RADIX_VMALLOC_END),
> +               kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END));
> +
> +       flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);
> +
> +       /* mark early shadow region as RO and wipe */
> +       pte = __pte(__pa(kasan_early_shadow_page) |
> +                   pgprot_val(PAGE_KERNEL_RO) | _PAGE_PTE);
> +       for (i = 0; i < PTRS_PER_PTE; i++)
> +               __set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
> +                            &kasan_early_shadow_pte[i], pte, 0);
> +
> +       /*
> +        * clear_page relies on some cache info that hasn't been set up yet.
> +        * It ends up looping ~forever and blows up other data.
> +        * Use memset instead.
> +        */
> +       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +
> +       /* Enable error messages */
> +       init_task.kasan_depth = 0;
> +       pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
> +}
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACzsE9q1iLgoMLzVy0AYeRvWbj%3DkY-Ry52y84PGtWw3YXXFipA%40mail.gmail.com.
