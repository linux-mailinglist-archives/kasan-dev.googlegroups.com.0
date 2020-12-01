Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7OYTH7AKGQEAHON2QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D56E2CA7F3
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:17:03 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id x4sf1392121pjp.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:17:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839422; cv=pass;
        d=google.com; s=arc-20160816;
        b=U1u4fg94Jn20BghorDOR3qBAO4Qui6OZHdBGtQJCY8EAG1eJfNv/7BpogF4KEeX1ex
         HJa9tr9RYa/PSOSFajr3bJri1/L7XcjuP+2SbPsD2+nz3Ir5dQgXr387S6q1lWUUg0Le
         6CRcV2B3mKtO5evqlGotsd/SK0i+zDb84ZVeKTKYbcUnpRulXUg2wJzSBs0rWNS08JNZ
         /TRhdy1vQceYok5GXdPCluMF7Pl+KFWbWwPxk1k+JDnXJeMRob0uUmZ2Rxfd1gCjA9Ln
         44YduEHw/gR2vODEWmHOmba9GHXrc5w22K08DvyR2bH8OwussT3NRapW4CMtGmtD7qVa
         nzRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+Esr1kym8rOr1TKBon9mlaHrci3ZGwyI+eP0aDU3g6k=;
        b=epR1hxx9ET/cfYVihy0wzCO0gB71lN5pwqRC4d+xuRe6y2/kidgL0GDHCb4W+aMV+c
         FeASUYiTSBOr5BU3TojWN1WjK0kbp2TT0XhnS6bf4uITP56BJJZHPm1Q87du2TOU5iW6
         0m5NQg4XClSZfjsaQbkGTRrtVeb2fKvIfWgzDvWM+D4JgXIreGYiKGjoOZ52NrPrvkFv
         5q7q7Mpo3DiWdntCF5H+bPVq35aWujoU7r1m9d8CWTTxOUrQ2+dDsac/rxXMB/YG+H4E
         OluiTFBMRzI6JlHeIeaQ/+8S7mWuKJasKXH/1jkO+rtB9QjoOFUnIXNOsDAOs2vw4DrO
         eBBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fLhuZMWf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Esr1kym8rOr1TKBon9mlaHrci3ZGwyI+eP0aDU3g6k=;
        b=o/Y7QclcRuoXj8+kY994fYSjPgFL7Kvwt99925RmP0ImaOjP/xbyWvCT3Vu7nJwcie
         w8ZMXGaxtuPDCF7IINy+hESZzQmrRf6Rap3Pnmyou8kP5JNcpfsE0CVaBtM6f6lMOUp8
         PImyB5pPQVwWd7IWHuxTOnlGo1d7t07Eao66bPrseVKzSy/Rf9sW8VANwHa2MBulvz/f
         J95e27hQJwHyFQv8aK7EqsKcy8duTnC1EPvaR7j6GXhd8os4a4tvLAU02KWa9zs3CwNd
         qugrf0fgSdMwGCb39TCy+wpzUBjr0MDlB446kiMlVsYvf55CcvGujnhaSPCJxQlwTBf8
         npvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Esr1kym8rOr1TKBon9mlaHrci3ZGwyI+eP0aDU3g6k=;
        b=M4nmK/c/wqLkoDAGmAeYM8qGGxK7GZeJcd+arbXpCC1LGnYe06ELydErjdyIUEPXCy
         3evuOSz+RzdI9mocDfkMwEcDOrtMYBq+SQCfaygr6WyQBgmzSCOrY5tuniQtD/JicCfb
         GkS4+E5JMnsncNuYTkkyKWhQCv5crkuSnZ2x1dn7jkQG8H2gndc6V7rS3YSi4nT/yKKt
         IW63/3wMwq60SnzKBvd+RWpn5kVYBoVHPMEwezCMIur+MlBSg9AEQMCiBz1316WKALo5
         js4AzOpTOapsRoJHbiFpxBvnT3wDu7iZ97swVrw7UQNUAi9rb87YzRC5TtLdNs0xKmoY
         kUzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532e4HPZkwAgC1IG2EuLhhygnKTI+nUxTgSpPTTygWvF0FdDamaD
	xjniVEIxgsWeh7c6T/GbP/I=
X-Google-Smtp-Source: ABdhPJwFAfbj/+4VnJH/7j3GZtQXwHw9mmuD96/6hF9Ez/WuNGT2jX0AmJkrrF9CcykXrqi04+76EA==
X-Received: by 2002:a62:d108:0:b029:163:d3cf:f00e with SMTP id z8-20020a62d1080000b0290163d3cff00emr3198087pfg.43.1606839422118;
        Tue, 01 Dec 2020 08:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c142:: with SMTP id p2ls917762pgi.1.gmail; Tue, 01 Dec
 2020 08:17:01 -0800 (PST)
X-Received: by 2002:a63:1a02:: with SMTP id a2mr2834931pga.359.1606839421482;
        Tue, 01 Dec 2020 08:17:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839421; cv=none;
        d=google.com; s=arc-20160816;
        b=nKsIEVXXlDKfbFZWSTu8lHZpoDEkfdKxLJV2D9qUCmDV0EJF1Qt8ot1EZcjDdJfQf8
         jcvRi3Vq+Yx1H0qDhulk5A4gtTXhHfxPVEJ4Ch+9YQ/WrKpREeRpsmjsUT/FvGd/2oJA
         rlwD5krEuNQwr43ntM2grBI0h6ns8bISdpwvcsLEXDEQvynP4dPUT1eLtA2RPqw632X2
         3DtgOttlowz8XjUVADkPfTeLmoKCHOFOMO7sev5HcfAaFlqpCkTSw5RG0FZ32T6IDcYz
         lLGNCGQwhC6CZFrrosDg2YqXqcQHxHhHyT/Kvw7lMo6BHaRmh5TjsmoPbG8fu3j+/1C+
         +qyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oLskoAHdTBMFzX/EeMzhI2T0BiOPmzG/p9pnfZknvZE=;
        b=0o+qy9RrqPt4YlQ1UfDdha2BXhhvNBLz3+0adMQmcQOAL9TLxzlzW4iZzpipJ+Fwkz
         3tfRrqLk3shs0eMWc4wDYp4vv0zErtDgGWMu+ybeBQrhFp/314m+8EHyFNPEAlnLEDKY
         Pkr2nDvVXDnWIiftNRAyMdoSbD8gXZpSCZRl9fD3bpAmNHSumnZ4PQjeXJMvh7Mzbdye
         /AxSIaDNgnJ99AiVBten9tK8Ui8acQBi+t8jZk5BpWEhRLJP8rC8JRvUshGcnmpFVMgG
         77Wuuf/Mj4whqMdiFOElihMtcJZjBtOAfopI7Q9w6V514PfZdsa66WK5s6VX5SRbosMT
         I/5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fLhuZMWf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id d1si19870pjo.1.2020.12.01.08.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:17:01 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id t3so1443492pgi.11
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:17:01 -0800 (PST)
X-Received: by 2002:a63:f203:: with SMTP id v3mr2848251pgh.39.1606839421080;
        Tue, 01 Dec 2020 08:17:01 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id l66sm86319pgl.24.2020.12.01.08.16.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:17:00 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 6/6] powerpc: Book3S 64-bit outline-only KASAN support
Date: Wed,  2 Dec 2020 03:16:32 +1100
Message-Id: <20201201161632.1234753-7-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
References: <20201201161632.1234753-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fLhuZMWf;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Implement a limited form of KASAN for Book3S 64-bit machines running under
the Radix MMU, supporting only outline mode.

 - Enable the compiler instrumentation to check addresses and maintain the
   shadow region. (This is the guts of KASAN which we can easily reuse.)

 - Require kasan-vmalloc support to handle modules and anything else in
   vmalloc space.

 - KASAN needs to be able to validate all pointer accesses, but we can't
   instrument all kernel addresses - only linear map and vmalloc. On boot,
   set up a single page of read-only shadow that marks all iomap and
   vmemmap accesses as valid.

 - Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
   generic code, arm64, s390 and x86 all do this for similar sorts of
   reasons: when unwinding a stack, we might touch memory that KASAN has
   marked as being out-of-bounds. In our case we often get this when
   checking for an exception frame because we're checking an arbitrary
   offset into the stack frame.

   See commit 20955746320e ("s390/kasan: avoid false positives during stack
   unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
   frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
   Prevent KASAN false positive warnings") and commit 6e22c8366416
   ("tracing, kasan: Silence Kasan warning in check_stack of stack_tracer")

 - Document KASAN in both generic and powerpc docs.

Background
----------

KASAN support on Book3S is a bit tricky to get right:

 - It would be good to support inline instrumentation so as to be able to
   catch stack issues that cannot be caught with outline mode.

 - Inline instrumentation requires a fixed offset.

 - Book3S runs code with translations off ("real mode") during boot,
   including a lot of generic device-tree parsing code which is used to
   determine MMU features.

    [ppc64 mm note: The kernel installs a linear mapping at effective
    address c000...-c008.... This is a one-to-one mapping with physical
    memory from 0000... onward. Because of how memory accesses work on
    powerpc 64-bit Book3S, a kernel pointer in the linear map accesses the
    same memory both with translations on (accessing as an 'effective
    address'), and with translations off (accessing as a 'real
    address'). This works in both guests and the hypervisor. For more
    details, see s5.7 of Book III of version 3 of the ISA, in particular
    the Storage Control Overview, s5.7.3, and s5.7.5 - noting that this
    KASAN implementation currently only supports Radix.]

 - Some code - most notably a lot of KVM code - also runs with translations
   off after boot.

 - Therefore any offset has to point to memory that is valid with
   translations on or off.

One approach is just to give up on inline instrumentation. This way
boot-time checks can be delayed until after the MMU is set is up, and we
can just not instrument any code that runs with translations off after
booting. Take this approach for now and require outline instrumentation.

Previous attempts allowed inline instrumentation. However, they came with
some unfortunate restrictions: only physically contiguous memory could be
used and it had to be specified at compile time. Maybe we can do better in
the future.

Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix version
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com> # ppc64 hash version
Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst            |  9 +-
 Documentation/powerpc/kasan.txt              | 48 +++++++++-
 arch/powerpc/Kconfig                         |  4 +-
 arch/powerpc/Kconfig.debug                   |  2 +-
 arch/powerpc/include/asm/book3s/64/hash.h    |  4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h |  7 ++
 arch/powerpc/include/asm/book3s/64/radix.h   | 13 ++-
 arch/powerpc/include/asm/kasan.h             | 34 ++++++-
 arch/powerpc/kernel/Makefile                 |  5 +
 arch/powerpc/kernel/process.c                | 16 ++--
 arch/powerpc/kvm/Makefile                    |  5 +
 arch/powerpc/mm/book3s64/Makefile            |  8 ++
 arch/powerpc/mm/kasan/Makefile               |  1 +
 arch/powerpc/mm/kasan/init_book3s_64.c       | 98 ++++++++++++++++++++
 arch/powerpc/mm/ptdump/ptdump.c              | 20 +++-
 arch/powerpc/platforms/Kconfig.cputype       |  1 +
 arch/powerpc/platforms/powernv/Makefile      |  6 ++
 arch/powerpc/platforms/pseries/Makefile      |  3 +
 18 files changed, 265 insertions(+), 19 deletions(-)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index eaf868094a8e..28f08959bd2e 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -19,8 +19,9 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures. It is also supported on 32-bit powerpc kernels. Tag-based
-KASAN is supported only on arm64.
+riscv architectures. It is also supported on powerpc, for 32-bit kernels, and
+for 64-bit kernels running under the Radix MMU. Tag-based KASAN is supported
+only on arm64.
 
 Usage
 -----
@@ -257,8 +258,8 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently this supported on x86, s390
-and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
-with module support, where it is required.
+and powerpc. It is optional, except on 64-bit powerpc kernels, and on
+32-bit powerpc kernels with module support, where it is required.
 
 This works by hooking into vmalloc and vmap, and dynamically
 allocating real shadow memory to back the mappings.
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
index 26bb0e8bb18c..f032b4eaf205 100644
--- a/Documentation/powerpc/kasan.txt
+++ b/Documentation/powerpc/kasan.txt
@@ -1,4 +1,4 @@
-KASAN is supported on powerpc on 32-bit only.
+KASAN is supported on powerpc on 32-bit and Radix 64-bit only.
 
 32 bit support
 ==============
@@ -10,3 +10,49 @@ fixmap area and occupies one eighth of the total kernel virtual memory space.
 
 Instrumentation of the vmalloc area is optional, unless built with modules,
 in which case it is required.
+
+64 bit support
+==============
+
+Currently, only the radix MMU is supported. There have been versions for hash
+and Book3E processors floating around on the mailing list, but nothing has been
+merged.
+
+KASAN support on Book3S is a bit tricky to get right:
+
+ - It would be good to support inline instrumentation so as to be able to catch
+   stack issues that cannot be caught with outline mode.
+
+ - Inline instrumentation requires a fixed offset.
+
+ - Book3S runs code with translations off ("real mode") during boot, including a
+   lot of generic device-tree parsing code which is used to determine MMU
+   features.
+
+ - Some code - most notably a lot of KVM code - also runs with translations off
+   after boot.
+
+ - Therefore any offset has to point to memory that is valid with
+   translations on or off.
+
+One approach is just to give up on inline instrumentation. This way boot-time
+checks can be delayed until after the MMU is set is up, and we can just not
+instrument any code that runs with translations off after booting. This is the
+current approach.
+
+To avoid this limitiation, the KASAN shadow would have to be placed inside the
+linear mapping, using the same high-bits trick we use for the rest of the linear
+mapping. This is tricky:
+
+ - We'd like to place it near the start of physical memory. In theory we can do
+   this at run-time based on how much physical memory we have, but this requires
+   being able to arbitrarily relocate the kernel, which is basically the tricky
+   part of KASLR. Not being game to implement both tricky things at once, this
+   is hopefully something we can revisit once we get KASLR for Book3S.
+
+ - Alternatively, we can place the shadow at the _end_ of memory, but this
+   requires knowing how much contiguous physical memory a system has _at compile
+   time_. This is a big hammer, and has some unfortunate consequences: inablity
+   to handle discontiguous physical memory, total failure to boot on machines
+   with less memory than specified, and that machines with more memory than
+   specified can't use it. This was deemed unacceptable.
diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index e9f13fe08492..e6bd02af6ebd 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -180,7 +180,9 @@ config PPC
 	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_KASAN			if PPC32 && PPC_PAGE_SHIFT <= 14
-	select HAVE_ARCH_KASAN_VMALLOC		if PPC32 && PPC_PAGE_SHIFT <= 14
+	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU
+	select HAVE_ARCH_NO_KASAN_INLINE	if PPC_BOOK3S_64 && PPC_RADIX_MMU
+	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
index b88900f4832f..60c1bba72a6f 100644
--- a/arch/powerpc/Kconfig.debug
+++ b/arch/powerpc/Kconfig.debug
@@ -396,5 +396,5 @@ config PPC_FAST_ENDIAN_SWITCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	depends on KASAN && PPC32
 	default 0xe0000000
diff --git a/arch/powerpc/include/asm/book3s/64/hash.h b/arch/powerpc/include/asm/book3s/64/hash.h
index 73ad038ed10b..105b90594a8a 100644
--- a/arch/powerpc/include/asm/book3s/64/hash.h
+++ b/arch/powerpc/include/asm/book3s/64/hash.h
@@ -18,6 +18,10 @@
 #include <asm/book3s/64/hash-4k.h>
 #endif
 
+#define H_PTRS_PER_PTE		(1 << H_PTE_INDEX_SIZE)
+#define H_PTRS_PER_PMD		(1 << H_PMD_INDEX_SIZE)
+#define H_PTRS_PER_PUD		(1 << H_PUD_INDEX_SIZE)
+
 /* Bits to set in a PMD/PUD/PGD entry valid bit*/
 #define HASH_PMD_VAL_BITS		(0x8000000000000000UL)
 #define HASH_PUD_VAL_BITS		(0x8000000000000000UL)
diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/include/asm/book3s/64/pgtable.h
index a39886681629..767e239d75e3 100644
--- a/arch/powerpc/include/asm/book3s/64/pgtable.h
+++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
@@ -230,6 +230,13 @@ extern unsigned long __pmd_frag_size_shift;
 #define PTRS_PER_PUD	(1 << PUD_INDEX_SIZE)
 #define PTRS_PER_PGD	(1 << PGD_INDEX_SIZE)
 
+#define MAX_PTRS_PER_PTE	((H_PTRS_PER_PTE > R_PTRS_PER_PTE) ? \
+				  H_PTRS_PER_PTE : R_PTRS_PER_PTE)
+#define MAX_PTRS_PER_PMD	((H_PTRS_PER_PMD > R_PTRS_PER_PMD) ? \
+				  H_PTRS_PER_PMD : R_PTRS_PER_PMD)
+#define MAX_PTRS_PER_PUD	((H_PTRS_PER_PUD > R_PTRS_PER_PUD) ? \
+				  H_PTRS_PER_PUD : R_PTRS_PER_PUD)
+
 /* PMD_SHIFT determines what a second-level page table entry can map */
 #define PMD_SHIFT	(PAGE_SHIFT + PTE_INDEX_SIZE)
 #define PMD_SIZE	(1UL << PMD_SHIFT)
diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/include/asm/book3s/64/radix.h
index c7813dc628fc..b3492b80f858 100644
--- a/arch/powerpc/include/asm/book3s/64/radix.h
+++ b/arch/powerpc/include/asm/book3s/64/radix.h
@@ -35,6 +35,11 @@
 #define RADIX_PMD_SHIFT		(PAGE_SHIFT + RADIX_PTE_INDEX_SIZE)
 #define RADIX_PUD_SHIFT		(RADIX_PMD_SHIFT + RADIX_PMD_INDEX_SIZE)
 #define RADIX_PGD_SHIFT		(RADIX_PUD_SHIFT + RADIX_PUD_INDEX_SIZE)
+
+#define R_PTRS_PER_PTE		(1 << RADIX_PTE_INDEX_SIZE)
+#define R_PTRS_PER_PMD		(1 << RADIX_PMD_INDEX_SIZE)
+#define R_PTRS_PER_PUD		(1 << RADIX_PUD_INDEX_SIZE)
+
 /*
  * Size of EA range mapped by our pagetables.
  */
@@ -68,11 +73,11 @@
  *
  *
  * 3rd quadrant expanded:
- * +------------------------------+
+ * +------------------------------+  Highest address (0xc010000000000000)
+ * +------------------------------+  KASAN shadow end (0xc00fc00000000000)
  * |                              |
  * |                              |
- * |                              |
- * +------------------------------+  Kernel vmemmap end (0xc010000000000000)
+ * +------------------------------+  Kernel vmemmap end/shadow start (0xc00e000000000000)
  * |                              |
  * |           512TB		  |
  * |                              |
@@ -126,6 +131,8 @@
 #define RADIX_VMEMMAP_SIZE	RADIX_KERN_MAP_SIZE
 #define RADIX_VMEMMAP_END	(RADIX_VMEMMAP_START + RADIX_VMEMMAP_SIZE)
 
+/* For the sizes of the shadow area, see kasan.h */
+
 #ifndef __ASSEMBLY__
 #define RADIX_PTE_TABLE_SIZE	(sizeof(pte_t) << RADIX_PTE_INDEX_SIZE)
 #define RADIX_PMD_TABLE_SIZE	(sizeof(pmd_t) << RADIX_PMD_INDEX_SIZE)
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index 7355ed05e65e..c72fd9281b44 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -28,9 +28,41 @@
 #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
 				 (KASAN_KERN_START >> KASAN_SHADOW_SCALE_SHIFT))
 
+#ifdef CONFIG_KASAN_SHADOW_OFFSET
 #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
+#endif
 
+#ifdef CONFIG_PPC32
 #define KASAN_SHADOW_END	(-(-KASAN_SHADOW_START >> KASAN_SHADOW_SCALE_SHIFT))
+#endif
+
+#ifdef CONFIG_PPC_BOOK3S_64
+/*
+ * We define the  offset such that the shadow of the linear map lives
+ * at the end of vmemmap space, that is, we choose offset such that
+ * shadow(c000_0000_0000_0000) = c00e_0000_0000_0000. This gives:
+ * c00e000000000000 - c000000000000000 >> 3 = a80e000000000000
+ */
+#define KASAN_SHADOW_OFFSET ASM_CONST(0xa80e000000000000)
+
+/*
+ * The shadow ends before the highest accessible address
+ * because we don't need a shadow for the shadow. Instead:
+ * c00e000000000000 << 3 + a80e000000000000000 = c00fc00000000000
+ */
+#define KASAN_SHADOW_END 0xc00fc00000000000UL
+
+DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
+
+static inline bool kasan_arch_is_ready_ppc64(void)
+{
+	if (static_branch_likely(&powerpc_kasan_enabled_key))
+		return true;
+	return false;
+}
+
+#define kasan_arch_is_ready kasan_arch_is_ready_ppc64
+#endif
 
 #ifdef CONFIG_KASAN
 void kasan_early_init(void);
@@ -47,5 +79,5 @@ void kasan_update_early_region(unsigned long k_start, unsigned long k_end, pte_t
 int kasan_init_shadow_page_tables(unsigned long k_start, unsigned long k_end);
 int kasan_init_region(void *start, size_t size);
 
-#endif /* __ASSEMBLY */
+#endif /* !__ASSEMBLY__ */
 #endif
diff --git a/arch/powerpc/kernel/Makefile b/arch/powerpc/kernel/Makefile
index fe2ef598e2ea..cd58202459dd 100644
--- a/arch/powerpc/kernel/Makefile
+++ b/arch/powerpc/kernel/Makefile
@@ -32,6 +32,11 @@ KASAN_SANITIZE_early_32.o := n
 KASAN_SANITIZE_cputable.o := n
 KASAN_SANITIZE_prom_init.o := n
 KASAN_SANITIZE_btext.o := n
+KASAN_SANITIZE_paca.o := n
+KASAN_SANITIZE_setup_64.o := n
+KASAN_SANITIZE_mce.o := n
+KASAN_SANITIZE_traps.o := n
+KASAN_SANITIZE_mce_power.o := n
 
 ifdef CONFIG_KASAN
 CFLAGS_early_32.o += -DDISABLE_BRANCH_PROFILING
diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index d421a2c7f822..f02b2766015c 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -2151,8 +2151,8 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
 			break;
 
 		stack = (unsigned long *) sp;
-		newsp = stack[0];
-		ip = stack[STACK_FRAME_LR_SAVE];
+		newsp = READ_ONCE_NOCHECK(stack[0]);
+		ip = READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);
 		if (!firstframe || ip != lr) {
 			printk("%s["REG"] ["REG"] %pS",
 				loglvl, sp, ip, (void *)ip);
@@ -2170,14 +2170,16 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
 		 * See if this is an exception frame.
 		 * We look for the "regshere" marker in the current frame.
 		 */
-		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
-		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
+		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE) &&
+		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) ==
+		     STACK_FRAME_REGS_MARKER)) {
 			struct pt_regs *regs = (struct pt_regs *)
 				(sp + STACK_FRAME_OVERHEAD);
-			lr = regs->link;
+			lr = READ_ONCE_NOCHECK(regs->link);
 			printk("%s--- interrupt: %lx at %pS\n    LR = %pS\n",
-			       loglvl, regs->trap,
-			       (void *)regs->nip, (void *)lr);
+			       loglvl, READ_ONCE_NOCHECK(regs->trap),
+			       (void *)READ_ONCE_NOCHECK(regs->nip),
+			       (void *)READ_ONCE_NOCHECK(lr));
 			firstframe = 1;
 		}
 
diff --git a/arch/powerpc/kvm/Makefile b/arch/powerpc/kvm/Makefile
index 2bfeaa13befb..7f1592dacbeb 100644
--- a/arch/powerpc/kvm/Makefile
+++ b/arch/powerpc/kvm/Makefile
@@ -136,3 +136,8 @@ obj-$(CONFIG_KVM_BOOK3S_64_PR) += kvm-pr.o
 obj-$(CONFIG_KVM_BOOK3S_64_HV) += kvm-hv.o
 
 obj-y += $(kvm-book3s_64-builtin-objs-y)
+
+# KVM does a lot in real-mode, and 64-bit Book3S KASAN doesn't support that
+ifdef CONFIG_PPC_BOOK3S_64
+KASAN_SANITIZE := n
+endif
diff --git a/arch/powerpc/mm/book3s64/Makefile b/arch/powerpc/mm/book3s64/Makefile
index fd393b8be14f..41a86d2c7da4 100644
--- a/arch/powerpc/mm/book3s64/Makefile
+++ b/arch/powerpc/mm/book3s64/Makefile
@@ -21,3 +21,11 @@ obj-$(CONFIG_PPC_MEM_KEYS)	+= pkeys.o
 
 # Instrumenting the SLB fault path can lead to duplicate SLB entries
 KCOV_INSTRUMENT_slb.o := n
+
+# Parts of these can run in real mode and therefore are
+# not safe with the current outline KASAN implementation
+KASAN_SANITIZE_mmu_context.o := n
+KASAN_SANITIZE_pgtable.o := n
+KASAN_SANITIZE_radix_pgtable.o := n
+KASAN_SANITIZE_radix_tlb.o := n
+KASAN_SANITIZE_slb.o := n
diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index 42fb628a44fd..07eef87abd6c 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -5,3 +5,4 @@ KASAN_SANITIZE := n
 obj-$(CONFIG_PPC32)           += init_32.o
 obj-$(CONFIG_PPC_8xx)		+= 8xx.o
 obj-$(CONFIG_PPC_BOOK3S_32)	+= book3s_32.o
+obj-$(CONFIG_PPC_BOOK3S_64)   += init_book3s_64.o
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
new file mode 100644
index 000000000000..b26ada73215d
--- /dev/null
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -0,0 +1,98 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KASAN for 64-bit Book3S powerpc
+ *
+ * Copyright (C) 2019-2020 IBM Corporation
+ * Author: Daniel Axtens <dja@axtens.net>
+ */
+
+#define DISABLE_BRANCH_PROFILING
+
+#include <linux/kasan.h>
+#include <linux/printk.h>
+#include <linux/sched/task.h>
+#include <linux/memblock.h>
+#include <asm/pgalloc.h>
+
+DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
+
+static void __init kasan_init_phys_region(void *start, void *end)
+{
+	unsigned long k_start, k_end, k_cur;
+	void *va;
+
+	if (start >= end)
+		return;
+
+	k_start = ALIGN_DOWN((unsigned long)kasan_mem_to_shadow(start), PAGE_SIZE);
+	k_end = ALIGN((unsigned long)kasan_mem_to_shadow(end), PAGE_SIZE);
+
+	va = memblock_alloc(k_end - k_start, PAGE_SIZE);
+	for (k_cur = k_start; k_cur < k_end; k_cur += PAGE_SIZE) {
+		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);
+		va += PAGE_SIZE;
+	}
+}
+
+void __init kasan_init(void)
+{
+	/*
+	 * We want to do the following things:
+	 *  1) Map real memory into the shadow for all physical memblocks
+	 *     This takes us from c000... to c008...
+	 *  2) Leave a hole over the shadow of vmalloc space. KASAN_VMALLOC
+	 *     will manage this for us.
+	 *     This takes us from c008... to c00a...
+	 *  3) Map the 'early shadow'/zero page over iomap and vmemmap space.
+	 *     This takes us up to where we start at c00e...
+	 */
+
+	void *k_start = kasan_mem_to_shadow((void *)RADIX_VMALLOC_END);
+	void *k_end = kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
+	phys_addr_t start, end;
+	u64 i;
+	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL);
+
+	if (!early_radix_enabled())
+		panic("KASAN requires radix!");
+
+	for_each_mem_range(i, &start, &end) {
+		kasan_init_phys_region((void *)start, (void *)end);
+	}
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
+			     &kasan_early_shadow_pte[i], zero_pte, 0);
+
+	for (i = 0; i < PTRS_PER_PMD; i++)
+		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
+				    kasan_early_shadow_pte);
+
+	for (i = 0; i < PTRS_PER_PUD; i++)
+		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
+			     kasan_early_shadow_pmd);
+
+	/* map the early shadow over the iomap and vmemmap space */
+	kasan_populate_early_shadow(k_start, k_end);
+
+	/* mark early shadow region as RO and wipe it */
+	zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL_RO);
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
+			     &kasan_early_shadow_pte[i], zero_pte, 0);
+
+	/*
+	 * clear_page relies on some cache info that hasn't been set up yet.
+	 * It ends up looping ~forever and blows up other data.
+	 * Use memset instead.
+	 */
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+
+	static_branch_inc(&powerpc_kasan_enabled_key);
+
+	/* Enable error messages */
+	init_task.kasan_depth = 0;
+	pr_info("KASAN init done (64-bit Book3S)\n");
+}
+
+void __init kasan_late_init(void) { }
diff --git a/arch/powerpc/mm/ptdump/ptdump.c b/arch/powerpc/mm/ptdump/ptdump.c
index aca354fb670b..63672aa656e8 100644
--- a/arch/powerpc/mm/ptdump/ptdump.c
+++ b/arch/powerpc/mm/ptdump/ptdump.c
@@ -20,6 +20,7 @@
 #include <linux/seq_file.h>
 #include <asm/fixmap.h>
 #include <linux/const.h>
+#include <linux/kasan.h>
 #include <asm/page.h>
 #include <asm/hugetlb.h>
 
@@ -317,6 +318,23 @@ static void walk_pud(struct pg_state *st, p4d_t *p4d, unsigned long start)
 	unsigned long addr;
 	unsigned int i;
 
+#if defined(CONFIG_KASAN) && defined(CONFIG_PPC_BOOK3S_64)
+	/*
+	 * On radix + KASAN, we want to check for the KASAN "early" shadow
+	 * which covers huge quantities of memory with the same set of
+	 * read-only PTEs. If it is, we want to note the first page (to see
+	 * the status change), and then note the last page. This gives us good
+	 * results without spending ages noting the exact same PTEs over 100s of
+	 * terabytes of memory.
+	 */
+	if (p4d_page(*p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud))) {
+		walk_pmd(st, pud, start);
+		addr = start + (PTRS_PER_PUD - 1) * PUD_SIZE;
+		walk_pmd(st, pud, addr);
+		return;
+	}
+#endif
+
 	for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
 		addr = start + i * PUD_SIZE;
 		if (!pud_none(*pud) && !pud_is_leaf(*pud))
@@ -387,11 +405,11 @@ static void populate_markers(void)
 #endif
 	address_markers[i++].start_address = FIXADDR_START;
 	address_markers[i++].start_address = FIXADDR_TOP;
+#endif /* CONFIG_PPC64 */
 #ifdef CONFIG_KASAN
 	address_markers[i++].start_address = KASAN_SHADOW_START;
 	address_markers[i++].start_address = KASAN_SHADOW_END;
 #endif
-#endif /* CONFIG_PPC64 */
 }
 
 static int ptdump_show(struct seq_file *m, void *v)
diff --git a/arch/powerpc/platforms/Kconfig.cputype b/arch/powerpc/platforms/Kconfig.cputype
index c194c4ae8bc7..b6eb8ec1e5ad 100644
--- a/arch/powerpc/platforms/Kconfig.cputype
+++ b/arch/powerpc/platforms/Kconfig.cputype
@@ -92,6 +92,7 @@ config PPC_BOOK3S_64
 	select ARCH_SUPPORTS_NUMA_BALANCING
 	select IRQ_WORK
 	select PPC_MM_SLICES
+	select KASAN_VMALLOC if KASAN
 
 config PPC_BOOK3E_64
 	bool "Embedded processors"
diff --git a/arch/powerpc/platforms/powernv/Makefile b/arch/powerpc/platforms/powernv/Makefile
index 2eb6ae150d1f..f277e4793696 100644
--- a/arch/powerpc/platforms/powernv/Makefile
+++ b/arch/powerpc/platforms/powernv/Makefile
@@ -1,4 +1,10 @@
 # SPDX-License-Identifier: GPL-2.0
+
+# nothing that deals with real mode is safe to KASAN
+# in particular, idle code runs a bunch of things in real mode
+KASAN_SANITIZE_idle.o := n
+KASAN_SANITIZE_pci-ioda.o := n
+
 obj-y			+= setup.o opal-call.o opal-wrappers.o opal.o opal-async.o
 obj-y			+= idle.o opal-rtc.o opal-nvram.o opal-lpc.o opal-flash.o
 obj-y			+= rng.o opal-elog.o opal-dump.o opal-sysparam.o opal-sensor.o
diff --git a/arch/powerpc/platforms/pseries/Makefile b/arch/powerpc/platforms/pseries/Makefile
index c8a2b0b05ac0..202199ef9e5c 100644
--- a/arch/powerpc/platforms/pseries/Makefile
+++ b/arch/powerpc/platforms/pseries/Makefile
@@ -30,3 +30,6 @@ obj-$(CONFIG_PPC_SVM)		+= svm.o
 obj-$(CONFIG_FA_DUMP)		+= rtas-fadump.o
 
 obj-$(CONFIG_SUSPEND)		+= suspend.o
+
+# nothing that operates in real mode is safe for KASAN
+KASAN_SANITIZE_ras.o := n
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-7-dja%40axtens.net.
