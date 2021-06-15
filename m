Return-Path: <kasan-dev+bncBDQ27FVWWUFRBOMNUCDAMGQEBFBSQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C30243A7377
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:38 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id 203-20020a1f18d40000b029021cd90a5ec4sf4107575vky.4
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721657; cv=pass;
        d=google.com; s=arc-20160816;
        b=SVogguSIpTmTxF0kU1CkEWGj1WO7O7GYaWfVCE7ERihfBEICUhNjIRtN56iOYfVebv
         U9SgYiA9iFVJHuUcC7UBIaq6ipC9Gq62Ods/RaSWOPFNbiXFdu6siPH3/5C1yuSWlh8q
         R6hbGI18HogqzGwHUnapem/ziyOprdCBI9LdloHlTCQk/sVmtw4YIWtvAzmBV3fakxW0
         slrEiCpxH6Hh6TeBprEJXcCOPfUuqk/XxR/Qz9Yzd+jHAn3BuEy5d4YGKRrRSn94uEJN
         Ic/yZkNranx0x7502+mjGxLTXHIA5upappYN9do1hHCA0YZuyclWn060NeP53ygIiRBu
         KA2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+EjGYzxzeG0xlVVQeM+BL/oOcTqZFSlJ8Sk/axNC5vQ=;
        b=i1LvXXh+lELYOyGcWXY8xi/z8DhRmB+JwmiWG5VnILPYpj62dMaMToeARsrzELiWzL
         27hfOWQ2sYYeRSm9YyAibQ40f/ivh/vizXBum5eCejDFqb7lEOceUHUNt77vNItaq7eF
         KybxLn6qHaY2+N0jenek+coo1u32/hXXATL0zSmF82aP5Y0bMFXNjypQVgw4l96kPPn1
         Dc6NHgUjgOI+jdgmoWIoLfZUxJ78X8ZU6rCc5GyfzGofmKkpUyQC08DvyvA4Y+t6milk
         OsacLtUygjlrhIL53p2ApxRbho5B3Dn0zE51HtLtQtI/J4pRDFOidb4IAibyQRn6xY3I
         qgBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BUcj6Ti4;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+EjGYzxzeG0xlVVQeM+BL/oOcTqZFSlJ8Sk/axNC5vQ=;
        b=UCYtamVGi56K2+WaUsGYPF4FqEeadFYtR6nGhSgNruIfyFTrHMOZI3e8Qhb6kQReVB
         4HAHePMGgOVEuNANeeH3ORJxscji65Wil6L9HHNzA9FE7MIdWsIDSGHTkAOOSbkWCDWe
         lRh7AhOs2ihAlCkZoQbeVB52/omWB84zHLBkUCCpiragABypEIne7iysP9/tTw7McxMP
         MJkFRV7Heo5aWUM3DuOToqt/TB67qNBshLg0FLb5+S2p1/gCcNgRJZQx3gSooJIslclh
         m0eIgnJ1w9wjn5EyOMC32H8B5sEE7DEtRxEsAcnrIvEpIh1SE8R4L9vEfRnkKt0WugwH
         a6ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+EjGYzxzeG0xlVVQeM+BL/oOcTqZFSlJ8Sk/axNC5vQ=;
        b=kumkM1QdKtWNfpm5Qkd3DHnGa/MI3inizq4d+75+piOQzsJPDnKri/Je99bemEnJzc
         vxs2gYPZ19M6o5IvMKVq3bVUGXjowD19N4Ev7UYAeaAqHv2rDWPfvFvpSMHT/rTR6/0e
         AK49QWQPeSQCIPkuR+XLDA2zSxlUv8yH4A9RM/1cLgT42Geg0FdlyxVUdDhUCLyi5LxN
         WLhPHLdvi5UA81JYF8Zvrmt8Tbm7Xt8zha4V1Ff1yeOleUNJZSJOpVXTqWMvdzcR33rZ
         HTnoB3zMIsTqnMlh04RL4Ne5o/t6eGf+Rlcm+aDYgYvil9a70FnbmAKWxGsET8F+941U
         r9vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mMy7V6y4ogCj9MyPDQJOPY+d3J+zkTy8in7URl8rqvN2SkSlB
	VqBh7/hKMn7gBxzgjj1GFE8=
X-Google-Smtp-Source: ABdhPJzw2ylppsZplc4Nms/x1lvAZwY7I/Zskae+1DLXHHB/kxvQaPD9MBA17JZKXH5DkPKlL8vqBA==
X-Received: by 2002:a1f:5043:: with SMTP id e64mr2287317vkb.21.1623721657707;
        Mon, 14 Jun 2021 18:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c4f6:: with SMTP id b22ls326876vkl.10.gmail; Mon, 14 Jun
 2021 18:47:37 -0700 (PDT)
X-Received: by 2002:a05:6122:2a4:: with SMTP id 4mr2366089vkq.4.1623721657085;
        Mon, 14 Jun 2021 18:47:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721657; cv=none;
        d=google.com; s=arc-20160816;
        b=phzgaKCIFzG5/LHIhlbfdDTLetg5yCgx5/nibfNiVAfh3JiYZRf0NtlaKc5XPFl5TL
         Vgzxb37aV1q0TKiwZIk687eM7WTr1ZVkZwx7SuuSKkDVEJSKCnn6rvhLyJtsa1qPRz13
         BTfEQXxEVKc9d5TuLWT9FwgYdQ7IA7UNtlSNuzFvoca1D9eG2drvrUANhR8f/iX9jDmr
         YIDtPDTImIRbaDXNnIRmqokKmnIh1Lf6eJ1z+Lh61HX0TSwLXCIewICmMAZcCRg+LYW5
         Gyg4/gkzZezCaSTHLASL33yDwljf27kz99o6dURLeUXr8DHEeRblHS6fjbUM8nd+eJkY
         dx+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4DvEiUhwkvJpcW6XfZgOhq/5DFtjmun49D+0ZASFjog=;
        b=J2KGMo5M9LxysHF+rjlPe3zT7H6V742aAnKoKeYv0rEPLUB/pPh8ivpNIZpV0WaYXx
         G63/meKyN1xi2ATyEg2Jez72EhcULjQge7jz5a3G9zKtdcETCAKQIgaFPxg6KgZxZCEY
         spr1W2omD5w4qjoNenieme6q6uR1pJK55PsiMNwCB1LleHAB7+9pPAnPwgd+EP5ACquY
         bXX4X3izS6kyS+ViwF9kdQDbo9G1f8WcP/viVggmAa5qHXwEco5M71qUrdSq3BtB3bZ9
         cFAbNfjhHmsNO9xctLfq9Wv8DKU3jkF/nz7dkTMf/VgRKgJKntpOeN21bNerW+he0yDW
         udug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BUcj6Ti4;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id a1si87054uaq.0.2021.06.14.18.47.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id ei4so10844080pjb.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:36 -0700 (PDT)
X-Received: by 2002:a17:90a:5b07:: with SMTP id o7mr7946865pji.35.1623721655895;
        Mon, 14 Jun 2021 18:47:35 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id h8sm13957135pfn.0.2021.06.14.18.47.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:35 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v12 6/6] [RFC] powerpc: Book3S 64-bit outline-only KASAN support
Date: Tue, 15 Jun 2021 11:47:05 +1000
Message-Id: <20210615014705.2234866-7-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
References: <20210615014705.2234866-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=BUcj6Ti4;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1034 as
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

[I'm hoping to get this in a subsequent merge window after we get the core
changes in. I know there are still a few outstanding review comments, I just
wanted to make sure that I supplied a real use-case for the core changes I'm
proposing.]

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

Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com> # ppc64 hash version
Cc: Christophe Leroy <christophe.leroy@csgroup.eu> # ppc32 version
Originally-by: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix version
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst            | 11 +--
 Documentation/powerpc/kasan.txt              | 48 +++++++++-
 arch/powerpc/Kconfig                         |  4 +-
 arch/powerpc/Kconfig.debug                   |  3 +-
 arch/powerpc/include/asm/book3s/64/hash.h    |  4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h |  4 +
 arch/powerpc/include/asm/book3s/64/radix.h   | 13 ++-
 arch/powerpc/include/asm/kasan.h             | 22 +++++
 arch/powerpc/kernel/Makefile                 | 11 +++
 arch/powerpc/kernel/process.c                | 16 ++--
 arch/powerpc/kvm/Makefile                    |  5 ++
 arch/powerpc/mm/book3s64/Makefile            |  9 ++
 arch/powerpc/mm/kasan/Makefile               |  1 +
 arch/powerpc/mm/kasan/init_book3s_64.c       | 95 ++++++++++++++++++++
 arch/powerpc/mm/ptdump/ptdump.c              | 20 ++++-
 arch/powerpc/platforms/Kconfig.cputype       |  1 +
 arch/powerpc/platforms/powernv/Makefile      |  6 ++
 arch/powerpc/platforms/pseries/Makefile      |  3 +
 18 files changed, 257 insertions(+), 19 deletions(-)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 05d2d428a332..f8d6048db1bb 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -36,8 +36,9 @@ Both software KASAN modes work with SLUB and SLAB memory allocators,
 while the hardware tag-based KASAN currently only supports SLUB.
 
 Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
-and riscv architectures. It is also supported on 32-bit powerpc kernels.
-Tag-based KASAN modes are supported only for arm64.
+and riscv architectures. It is also supported on powerpc for 32-bit kernels and
+for 64-bit kernels running under the Radix MMU. Tag-based KASAN modes are
+supported only for arm64.
 
 Usage
 -----
@@ -344,10 +345,10 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently, this is supported on x86,
-riscv, s390, and 32-bit powerpc.
+riscv, s390, and powerpc.
 
-It is optional, except on 32-bit powerpc kernels with module support,
-where it is required.
+It is optional, except on 64-bit powerpc kernels, and on 32-bit
+powerpc kernels with module support, where it is required.
 
 This works by hooking into vmalloc and vmap and dynamically
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
index dbccb0676e48..ff16af7022b1 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -118,6 +118,7 @@ config PPC
 	# Please keep this list sorted alphabetically.
 	#
 	select ARCH_32BIT_OFF_T if PPC32
+	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
 	select ARCH_ENABLE_MEMORY_HOTPLUG
 	select ARCH_ENABLE_MEMORY_HOTREMOVE
 	select ARCH_HAS_COPY_MC			if PPC64
@@ -191,7 +192,8 @@ config PPC
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if PPC32 && PPC_PAGE_SHIFT <= 14
-	select HAVE_ARCH_KASAN_VMALLOC		if PPC32 && PPC_PAGE_SHIFT <= 14
+	select HAVE_ARCH_KASAN			if PPC_RADIX_MMU
+	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KFENCE			if PPC32
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
index 6342f9da4545..ad5b776a96e7 100644
--- a/arch/powerpc/Kconfig.debug
+++ b/arch/powerpc/Kconfig.debug
@@ -399,4 +399,5 @@ config PPC_FAST_ENDIAN_SWITCH
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN
-	default 0xe0000000
+	default 0xe0000000 if PPC32
+	default 0xa80e000000000000 if PPC64
diff --git a/arch/powerpc/include/asm/book3s/64/hash.h b/arch/powerpc/include/asm/book3s/64/hash.h
index d959b0195ad9..222669864ff6 100644
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
index a666d561b44d..49f2a2bbc0cf 100644
--- a/arch/powerpc/include/asm/book3s/64/pgtable.h
+++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
@@ -232,6 +232,10 @@ extern unsigned long __pmd_frag_size_shift;
 #define PTRS_PER_PUD	(1 << PUD_INDEX_SIZE)
 #define PTRS_PER_PGD	(1 << PGD_INDEX_SIZE)
 
+#define MAX_PTRS_PER_PTE ((H_PTRS_PER_PTE > R_PTRS_PER_PTE) ? H_PTRS_PER_PTE : R_PTRS_PER_PTE)
+#define MAX_PTRS_PER_PMD ((H_PTRS_PER_PMD > R_PTRS_PER_PMD) ? H_PTRS_PER_PMD : R_PTRS_PER_PMD)
+#define MAX_PTRS_PER_PUD ((H_PTRS_PER_PUD > R_PTRS_PER_PUD) ? H_PTRS_PER_PUD : R_PTRS_PER_PUD)
+
 /* PMD_SHIFT determines what a second-level page table entry can map */
 #define PMD_SHIFT	(PAGE_SHIFT + PTE_INDEX_SIZE)
 #define PMD_SIZE	(1UL << PMD_SHIFT)
diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/include/asm/book3s/64/radix.h
index 59cab558e2f0..191399143dc8 100644
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
index 3c478e5ef24c..6efc822e70fd 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -30,9 +30,31 @@
 
 #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
 
+#ifdef CONFIG_PPC32
 #define KASAN_SHADOW_END	(-(-KASAN_SHADOW_START >> KASAN_SHADOW_SCALE_SHIFT))
+#endif
 
 #ifdef CONFIG_KASAN
+#ifdef CONFIG_PPC_BOOK3S_64
+/*
+ * The shadow ends before the highest accessible address
+ * because we don't need a shadow for the shadow. Instead:
+ * c00e000000000000 << 3 + a80e000000000000 = c00fc00000000000
+ */
+#define KASAN_SHADOW_END 0xc00fc00000000000UL
+
+DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
+
+static __always_inline bool kasan_arch_is_ready(void)
+{
+	if (static_branch_likely(&powerpc_kasan_enabled_key))
+		return true;
+	return false;
+}
+
+#define kasan_arch_is_ready kasan_arch_is_ready
+#endif
+
 void kasan_early_init(void);
 void kasan_mmu_init(void);
 void kasan_init(void);
diff --git a/arch/powerpc/kernel/Makefile b/arch/powerpc/kernel/Makefile
index f66b63e81c3b..aabac84106f1 100644
--- a/arch/powerpc/kernel/Makefile
+++ b/arch/powerpc/kernel/Makefile
@@ -32,6 +32,17 @@ KASAN_SANITIZE_early_32.o := n
 KASAN_SANITIZE_cputable.o := n
 KASAN_SANITIZE_prom_init.o := n
 KASAN_SANITIZE_btext.o := n
+KASAN_SANITIZE_paca.o := n
+KASAN_SANITIZE_setup_64.o := n
+KASAN_SANITIZE_mce.o := n
+KASAN_SANITIZE_mce_power.o := n
+
+# we have to be particularly careful in ppc64 to exclude code that
+# runs with translations off, as we cannot access the shadow with
+# translations off. However, ppc32 can sanitize this.
+ifdef CONFIG_PPC64
+KASAN_SANITIZE_traps.o := n
+endif
 
 ifdef CONFIG_KASAN
 CFLAGS_early_32.o += -DDISABLE_BRANCH_PROFILING
diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 89e34aa273e2..430cf06f9406 100644
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
@@ -2170,17 +2170,19 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
 		 * See if this is an exception frame.
 		 * We look for the "regshere" marker in the current frame.
 		 */
-		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS)
-		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
+		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS) &&
+		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) ==
+		     STACK_FRAME_REGS_MARKER)) {
 			struct pt_regs *regs = (struct pt_regs *)
 				(sp + STACK_FRAME_OVERHEAD);
 
-			lr = regs->link;
+			lr = READ_ONCE_NOCHECK(regs->link);
 			printk("%s--- interrupt: %lx at %pS\n",
-			       loglvl, regs->trap, (void *)regs->nip);
+			       loglvl, READ_ONCE_NOCHECK(regs->trap),
+			       (void *)READ_ONCE_NOCHECK(regs->nip));
 			__show_regs(regs);
 			printk("%s--- interrupt: %lx\n",
-			       loglvl, regs->trap);
+			       loglvl, READ_ONCE_NOCHECK(regs->trap));
 
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
index 1b56d3af47d4..a7d8a68bd2c5 100644
--- a/arch/powerpc/mm/book3s64/Makefile
+++ b/arch/powerpc/mm/book3s64/Makefile
@@ -21,3 +21,12 @@ obj-$(CONFIG_PPC_PKEY)	+= pkeys.o
 
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
+KASAN_SANITIZE_pkeys.o := n
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
index 000000000000..ca913ed951a2
--- /dev/null
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -0,0 +1,95 @@
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
+	for (k_cur = k_start; k_cur < k_end; k_cur += PAGE_SIZE, va += PAGE_SIZE)
+		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);
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
+	for_each_mem_range(i, &start, &end)
+		kasan_init_phys_region((void *)start, (void *)end);
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
index 113431604035..de70bfea2982 100644
--- a/arch/powerpc/platforms/Kconfig.cputype
+++ b/arch/powerpc/platforms/Kconfig.cputype
@@ -105,6 +105,7 @@ config PPC_BOOK3S_64
 	select PPC_MM_SLICES
 	select PPC_HAVE_KUEP
 	select PPC_HAVE_KUAP
+	select KASAN_VMALLOC if KASAN
 
 config PPC_BOOK3E_64
 	bool "Embedded processors"
diff --git a/arch/powerpc/platforms/powernv/Makefile b/arch/powerpc/platforms/powernv/Makefile
index be2546b96816..d50f6fc71ac6 100644
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-7-dja%40axtens.net.
