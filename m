Return-Path: <kasan-dev+bncBDQ27FVWWUFRBEM7VDVAKGQE44D5ARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id B4D7A83DE2
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 01:38:58 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id g30sf80367841qtm.17
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 16:38:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565134738; cv=pass;
        d=google.com; s=arc-20160816;
        b=a1nQICy9IIwDeen+15g6eokcQY5Om9D7+DB61VGwj5gIz4XfZV3rQobvtgK3xmOidu
         xZ2rLi8dsWsv1yY7OmV4IrAFuE1IGoavwXihx6vdzLgKOIHH88Cm0As7cjT3/4RfcGKI
         VN08irFQGy0Im2k+T8oKSZCQFS2G5mB9gpC1ThDhyRNX5lByEPH/tdBxDNLHrHs5ohVn
         Mm13zEyL+VmJDulRSE5h+8iILRFsbLB++qtv8CM0xVoS0sNOszvbMjuUNRL6JSAyXXx9
         6Io1sPi7WdDeOmBNUAW71+0Oja4QG+KvyW67bbt6rvTVc7w9WuZZpcZA69HL2Oqxkuf1
         RrVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7kEODwoYOI0OD3PQPQZRqLfiIPaxMDXGrc+b/i3NkVo=;
        b=eDYIFwFJ4ZIhx9t3euxaU/pPD9y7dLNTjfwQ3nKg7VrUHyPuepbGHWWY4QlOTGyF+V
         aCOOZ1Ak4mYtuQiQnCH5jl4v4ln3/TGdbUrFLPgl+xliGXLIdtMYE4+HpmOqeSXKiBmB
         QS31FNgqk/nZZNE6mcwGNMw49GbfRxoXXCRhoFRVbUTB0tR5mwB6uRWw4X95mqB1ZIhj
         E0pPsu0VWfxSDhgA7jaCFq9TTiLHr4xP1klhCIUY+SmaZ8LQDSJMbIAg4mRFwBGDluGM
         m+LOyiRBkVTAxaumjxenfPS4rDGLBeSyljj3Dufzf+cWlspMBNJ5GQWKgOwIU9tq4WO9
         IbjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=JicdM7k7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kEODwoYOI0OD3PQPQZRqLfiIPaxMDXGrc+b/i3NkVo=;
        b=FVn80+0zp7O9daS1TzKNfh/6k7hIepANSaNu289P/Zl9Mwno+abzxzIHKmeB5sxgC0
         96fEb7K5DmkA297DOqLAY2VDXI0Es+Xd7Qx+bX4KnuNBQzMhSWIIDP37fv7zPAzdcsmv
         jyN5WlUuYzIeasj25Hqd4iB78LlwWdu8Ol3Y9heGqVxtNstsTYezVnqzJgEpqF0yhtHQ
         21GvJvskVDlXp93JhK9h+vafWJW/Y8lRBIbhv+RQKVZ4yQGuK8qGbdUeeXHOg4jfefYo
         CrpSF5Ir5dglXpZj81f3Ptuo9+3Aho1BOX7L1pfuY8j+iHo5hqufViYQakkEcW1kR7g4
         0GAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kEODwoYOI0OD3PQPQZRqLfiIPaxMDXGrc+b/i3NkVo=;
        b=q52mFv+m2zIsBGQV1UbcMPb9NHy499+55xO5C9psSD2Oq2T01NiYAFkEb5kOCSWOpj
         4dmqbJIdeftH0TQ1hi3F70GHmeNaMzs/yF9i76qYQkAnm19w8cwUjgs0+MaePIdNo9AV
         TeuahiuXXIHBtDpSOHoiStNsPJ30KoFNz4T7/Br6anxxvsmBjdtt8M7pUnCBlu4WAWe3
         FDsafXZFohaOaVs5eA8DXtLCXXyD+YsmK9EPfXtt+zRc2R8P81ME15DQanx5MuJbTuJ8
         5EHGTMKP1NeAcNt0ILeuktbTcxohz2Ra4GLSmnyL1FjQNH9TZ2pfPc1LI6z/8r5Ffx4s
         fMyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVI7poGugjbeX9bc4tOb76or63XSGMv9SU3GvET5uIa6wdy4GK2
	lVcqQGYvW/R6fHi2n5y9Cw8=
X-Google-Smtp-Source: APXvYqyk4lfH1RFR08+GZzD2XsvwgL/cKo8vgceEYFjBCAjw0yJPHExaTACfPGr54Lr2jA2chhRFVA==
X-Received: by 2002:a37:a603:: with SMTP id p3mr5827736qke.297.1565134737792;
        Tue, 06 Aug 2019 16:38:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9aec:: with SMTP id k44ls3135905qvf.2.gmail; Tue, 06 Aug
 2019 16:38:57 -0700 (PDT)
X-Received: by 2002:a0c:a8d2:: with SMTP id h18mr5611257qvc.16.1565134737461;
        Tue, 06 Aug 2019 16:38:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565134737; cv=none;
        d=google.com; s=arc-20160816;
        b=GjmGC6isNv5qzMEV6sHQ9J/hcZvz27zy73RFAEdhmvchc0JhnQt1TXKilot88YiEe4
         2UkNDQcO1E4OlLCfmTtzQOlEKcDckWPoJTXLDQiSqOhaM60CQAwbzYEHbvO8rruUXbPv
         9PRobLmhhd1xbK3BtIOem9PbgDeXWV2+xEF0tEkh2k5ZeG022lAlZnghcDPJYb49kcKt
         sPFb5O3l4aH7Iuw8RXCQjRvUkZZWu6yEAIIYGCSpjr4opsRjA8TcbX5m7or62Dk6sIwq
         85zM5mYm4IDKubB9uafDHdpzXalu1NjqSRtVshZS6lB8cFMB7JkQwWJSuP2ifGjmxEgI
         vMHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vKUdQ4OjZKtw2XHy7QMISE99Vq6NOygkV52QoPHeIV8=;
        b=YX3HxyHFL4rUofOKFXzEA9/rIgIWhyHxj9XeL7VGN3e4vpm23d+zRL4DKcfVaAVJYV
         YyqIuz2ZP3058NWpJNO4Cp+iuMW2igFW4HcOyD7EG7M5aVXMT4SCVESefS1G/DcP78hL
         nuJcJBIZcanZofGe+f7pvrk9pUmbrU7gto+QubCusmNZvQcN4S+hNo/lLP6rKrpzoeNM
         6act6Gd9KQPGmxyHwQkokvVkxZQq37PzLB9ddnmwcgfDHvu4yUy8WJrCowwqqzftTM5j
         y77KwSbhWgK6MjJqQJ3RTU7jkW+xhc/33uCJ5u4RsNCNjTWRmJCpFGovzbc4imI7CJoE
         vtdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=JicdM7k7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id r4si3901963qkb.1.2019.08.06.16.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Aug 2019 16:38:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id r26so6454693pgl.10
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2019 16:38:57 -0700 (PDT)
X-Received: by 2002:a65:5a86:: with SMTP id c6mr4820049pgt.95.1565134735825;
        Tue, 06 Aug 2019 16:38:55 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id z13sm89294339pfa.94.2019.08.06.16.38.53
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 06 Aug 2019 16:38:55 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
Date: Wed,  7 Aug 2019 09:38:27 +1000
Message-Id: <20190806233827.16454-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190806233827.16454-1-dja@axtens.net>
References: <20190806233827.16454-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=JicdM7k7;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
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

KASAN support on powerpc64 is interesting:

 - We want to be able to support inline instrumentation so as to be
   able to catch global and stack issues.

 - We run a lot of code at boot in real mode. This includes stuff like
   printk(), so it's not feasible to just disable instrumentation
   around it.

   [For those not immersed in ppc64, in real mode, the top nibble or
   2 bits (depending on radix/hash mmu) of the address is ignored. To
   make things work, we put the linear mapping at
   0xc000000000000000. This means that a pointer to part of the linear
   mapping will work both in real mode, where it will be interpreted
   as a physical address of the form 0x000..., and out of real mode,
   where it will go via the linear mapping.]

 - Inline instrumentation requires a fixed offset.

 - Because of our running things in real mode, the offset has to
   point to valid memory both in and out of real mode.

This makes finding somewhere to put the KASAN shadow region a bit fun.

One approach is just to give up on inline instrumentation and override
the address->shadow calculation. This way we can delay all checking
until after we get everything set up to our satisfaction. However,
we'd really like to do better.

What we can do - if we know _at compile time_ how much contiguous
physical memory we have - is to set aside the top 1/8th of the memory
and use that. This is a big hammer (hence the "heavyweight" name) and
comes with 3 big consequences:

 - kernels will simply fail to boot on machines with less memory than
   specified when compiling.

 - kernels running on machines with more memory than specified when
   compiling will simply ignore the extra memory.

 - there's no nice way to handle physically discontiguous memory, so
   you are restricted to the first physical memory block.

If you can bear all this, you get pretty full support for KASAN.

Despite the limitations, it can still find bugs,
e.g. http://patchwork.ozlabs.org/patch/1103775/

The current implementation is Radix only. I am open to extending
it to hash at some point but I don't think it should hold up v1.

Massive thanks to mpe, who had the idea for the initial design.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---
Changes since the rfc:

 - Boots real and virtual hardware, kvm works.

 - disabled reporting when we're checking the stack for exception
   frames. The behaviour isn't wrong, just incompatible with KASAN.

 - Documentation!

 - Dropped old module stuff in favour of KASAN_VMALLOC.

The bugs with ftrace and kuap were due to kernel bloat pushing
prom_init calls to be done via the plt. Because we did not have
a relocatable kernel, and they are done very early, this caused
everything to explode. Compile with CONFIG_RELOCATABLE!

---
 Documentation/dev-tools/kasan.rst            |   7 +-
 Documentation/powerpc/kasan.txt              | 111 +++++++++++++++++++
 arch/powerpc/Kconfig                         |   4 +
 arch/powerpc/Kconfig.debug                   |  21 ++++
 arch/powerpc/Makefile                        |   7 ++
 arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
 arch/powerpc/include/asm/kasan.h             |  35 +++++-
 arch/powerpc/kernel/process.c                |   8 ++
 arch/powerpc/kernel/prom.c                   |  57 +++++++++-
 arch/powerpc/mm/kasan/Makefile               |   1 +
 arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  76 +++++++++++++
 11 files changed, 326 insertions(+), 6 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 35fda484a672..48d3b669e577 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,9 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+architectures. It is also supported on powerpc for 32-bit kernels, and for
+64-bit kernels running under the radix MMU. Tag-based KASAN is supported only
+for arm64.
 
 Usage
 -----
@@ -252,7 +254,8 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently this is optional on x86, and
+required on 64-bit powerpc.
 
 This works by hooking into vmalloc and vmap, and dynamically
 allocating real shadow memory to back the mappings.
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..a5592454353b
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,111 @@
+KASAN is supported on powerpc on 32-bit and 64-bit Radix only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is not currently supported, but modules are.
+
+64 bit support
+==============
+
+Currently, only the radix MMU is supported. There have been versions for Book3E
+processors floating around on the mailing list, but nothing has been merged.
+
+KASAN support on Book3S is interesting:
+
+ - We want to be able to support inline instrumentation so as to be able to
+   catch global and stack issues.
+
+ - Inline instrumentation requires a fixed offset.
+
+ - We run a lot of code at boot in real mode. This includes stuff like printk(),
+   so it's not feasible to just disable instrumentation around it.
+
+ - Because of our running things in real mode, the offset has to point to valid
+   memory both in and out of real mode.
+
+This makes finding somewhere to put the KASAN shadow region a bit fun.
+
+One approach is just to give up on inline instrumentation. This way we can delay
+all checks until after we get everything set up to our satisfaction. However,
+we'd really like to do better.
+
+If we know _at compile time_ how much contiguous physical memory we have, we can
+set aside the top 1/8th of physical memory and use that. This is a big hammer
+and comes with 2 big consequences:
+
+ - kernels will simply fail to boot on machines with less memory than specified
+   when compiling.
+
+ - kernels running on machines with more memory than specified when compiling
+   will simply ignore the extra memory.
+
+If you can live with this, you get full support for KASAN.
+
+Tips
+----
+
+ - Compile with CONFIG_RELOCATABLE.
+
+   In development, we found boot hangs when building with ftrace and KUAP. These
+   ended up being due to kernel bloat pushing prom_init calls to be done via the
+   PLT. Because we did not have a relocatable kernel, and they are done very
+   early, this caused us to jump off into somewhere invalid. Enabling relocation
+   fixes this.
+
+NUMA/discontiguous physical memory
+----------------------------------
+
+We currently cannot really deal with discontiguous physical memory. You are
+restricted to the physical memory that is contiguous from physical address zero,
+and must specify the size of that memory, not total memory, when configuring
+your kernel.
+
+Discontiguous memory can occur when you have a machine with memory spread across
+multiple nodes. For example, on a Talos II with 64GB of RAM:
+
+ - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
+ - then there's a gap,
+ - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_0000_0000.
+
+This can create _significant_ issues:
+
+ - If we try to treat the machine as having 64GB of _contiguous_ RAM, we would
+   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserve the last
+   1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the shadow
+   region. But when we try to access any of that, we'll try to access pages that
+   are not physically present.
+
+ - If we try to base the shadow region size on the top address, we'll need to
+   reserve 0x2008_0000_0000 / 8 = 0x0401_0000_0000 bytes = 4100 GB of memory,
+   which will clearly not work on a system with 64GB of RAM.
+
+Therefore, you are restricted to the memory in the node starting at 0x0. For
+this system, that's 32GB. If you specify a contiguous physical memory size
+greater than the size of the first contiguous region of memory, the system will
+be unable to boot or even print an error message warning you.
+
+You can determine the layout of your system's memory by observing the messages
+that the Radix MMU prints on boot. The Talos II discussed earlier has:
+
+radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB pages (exec)
+radix-mmu: Mapped 0x0000000040000000-0x0000000800000000 with 1.00 GiB pages
+radix-mmu: Mapped 0x0000200000000000-0x0000200800000000 with 1.00 GiB pages
+
+As discussed, you'd configure this system for 32768 MB.
+
+Another system prints:
+
+radix-mmu: Mapped 0x0000000000000000-0x0000000040000000 with 1.00 GiB pages (exec)
+radix-mmu: Mapped 0x0000000040000000-0x0000002000000000 with 1.00 GiB pages
+radix-mmu: Mapped 0x0000200000000000-0x0000202000000000 with 1.00 GiB pages
+
+This machine has more memory: 0x0000_0040_0000_0000 total, but only
+0x0000_0020_0000_0000 is physically contiguous from zero, so we'd configure the
+kernel for 131072 MB of physically contiguous memory.
+
diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index d8dcd8820369..3d6deee100e2 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -171,6 +171,10 @@ config PPC
 	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_KASAN			if PPC32
+	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU
+	select ARCH_HAS_KASAN_EARLY_SHADOW	if PPC_BOOK3S_64
+	select HAVE_ARCH_KASAN_VMALLOC		if PPC_BOOK3S_64
+	select KASAN_VMALLOC			if KASAN
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
index c59920920ddc..2d6fb7b1ba59 100644
--- a/arch/powerpc/Kconfig.debug
+++ b/arch/powerpc/Kconfig.debug
@@ -394,6 +394,27 @@ config PPC_FAST_ENDIAN_SWITCH
         help
 	  If you're unsure what this is, say N.
 
+config PHYS_MEM_SIZE_FOR_KASAN
+	int "Contiguous physical memory size for KASAN (MB)"
+	depends on KASAN && PPC_BOOK3S_64
+	help
+
+	  To get inline instrumentation support for KASAN on 64-bit Book3S
+	  machines, you need to know how much contiguous physical memory your
+	  system has. A shadow offset will be calculated based on this figure,
+	  which will be compiled in to the kernel. KASAN will use this offset
+	  to access its shadow region, which is used to verify memory accesses.
+
+	  If you attempt to boot on a system with less memory than you specify
+	  here, your system will fail to boot very early in the process. If you
+	  boot on a system with more memory than you specify, the extra memory
+	  will wasted - it will be reserved and not used.
+
+	  For systems with discontiguous blocks of physical memory, specify the
+	  size of the block starting at 0x0. You can determine this by looking
+	  at the memory layout info printed to dmesg by the radix MMU code
+	  early in boot. See Documentation/powerpc/kasan.txt.
+
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN
diff --git a/arch/powerpc/Makefile b/arch/powerpc/Makefile
index c345b79414a9..33e7bba4c8db 100644
--- a/arch/powerpc/Makefile
+++ b/arch/powerpc/Makefile
@@ -229,6 +229,13 @@ ifdef CONFIG_476FPE_ERR46
 		-T $(srctree)/arch/powerpc/platforms/44x/ppc476_modules.lds
 endif
 
+ifdef CONFIG_KASAN
+ifdef CONFIG_PPC_BOOK3S_64
+# 0xa800000000000000 = 12105675798371893248
+KASAN_SHADOW_OFFSET = $(shell echo 7 \* 1024 \* 1024 \* $(CONFIG_PHYS_MEM_SIZE_FOR_KASAN) / 8 + 12105675798371893248 | bc)
+endif
+endif
+
 # No AltiVec or VSX instructions when building kernel
 KBUILD_CFLAGS += $(call cc-option,-mno-altivec)
 KBUILD_CFLAGS += $(call cc-option,-mno-vsx)
diff --git a/arch/powerpc/include/asm/book3s/64/radix.h b/arch/powerpc/include/asm/book3s/64/radix.h
index e04a839cb5b9..4c011cc15e05 100644
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
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index 296e51c2f066..d6b4028c296b 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -14,13 +14,20 @@
 
 #ifndef __ASSEMBLY__
 
-#include <asm/page.h>
+#ifdef CONFIG_KASAN
+void kasan_init(void);
+#else
+static inline void kasan_init(void) { }
+#endif
 
 #define KASAN_SHADOW_SCALE_SHIFT	3
 
 #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
 				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
 
+#ifdef CONFIG_PPC32
+#include <asm/page.h>
+
 #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
 
 #define KASAN_SHADOW_END	0UL
@@ -30,11 +37,33 @@
 #ifdef CONFIG_KASAN
 void kasan_early_init(void);
 void kasan_mmu_init(void);
-void kasan_init(void);
 #else
-static inline void kasan_init(void) { }
 static inline void kasan_mmu_init(void) { }
 #endif
+#endif
+
+#ifdef CONFIG_PPC_BOOK3S_64
+#include <asm/pgtable.h>
+
+/*
+ * The KASAN shadow offset is such that linear map (0xc000...) is shadowed by
+ * the last 8th of linearly mapped physical memory. This way, if the code uses
+ * 0xc addresses throughout, accesses work both in in real mode (where the top
+ * 2 bits are ignored) and outside of real mode.
+ */
+#define KASAN_SHADOW_OFFSET ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
+				1024 * 1024 * 7 / 8 + 0xa800000000000000UL)
+
+#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
+				1024 * 1024 * 1 / 8)
+
+extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
+
+extern pte_t kasan_early_shadow_pte[R_PTRS_PER_PTE];
+extern pmd_t kasan_early_shadow_pmd[R_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[R_PTRS_PER_PUD];
+extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
+#endif /* CONFIG_PPC_BOOK3S_64 */
 
 #endif /* __ASSEMBLY */
 #endif
diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 8fc4de0d22b4..31602536e72b 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -2097,7 +2097,14 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
 		/*
 		 * See if this is an exception frame.
 		 * We look for the "regshere" marker in the current frame.
+		 *
+		 * KASAN may complain about this. If it is an exception frame,
+		 * we won't have unpoisoned the stack in asm when we set the
+		 * exception marker. If it's not an exception frame, who knows
+		 * how things are laid out - the shadow could be in any state
+		 * at all. Just disable KASAN reporting for now.
 		 */
+		kasan_disable_current();
 		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
 		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
 			struct pt_regs *regs = (struct pt_regs *)
@@ -2107,6 +2114,7 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
 			       regs->trap, (void *)regs->nip, (void *)lr);
 			firstframe = 1;
 		}
+		kasan_enable_current();
 
 		sp = newsp;
 	} while (count++ < kstack_depth_to_print);
diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
index 7159e791a70d..dde5f2896ab6 100644
--- a/arch/powerpc/kernel/prom.c
+++ b/arch/powerpc/kernel/prom.c
@@ -71,6 +71,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
 u64 ppc64_rma_size;
 #endif
 static phys_addr_t first_memblock_size;
+static phys_addr_t top_phys_addr;
 static int __initdata boot_cpu_count;
 
 static int __init early_parse_mem(char *p)
@@ -448,6 +449,21 @@ static bool validate_mem_limit(u64 base, u64 *size)
 {
 	u64 max_mem = 1UL << (MAX_PHYSMEM_BITS);
 
+#ifdef CONFIG_KASAN
+	/*
+	 * To handle the NUMA/discontiguous memory case, don't allow a block
+	 * to be added if it falls completely beyond the configured physical
+	 * memory.
+	 *
+	 * See Documentation/powerpc/kasan.txt
+	 */
+	if (base >= (u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * 1024 * 1024) {
+		pr_warn("KASAN: not adding mem block at %llx (size %llx)",
+			base, *size);
+		return false;
+	}
+#endif
+
 	if (base >= max_mem)
 		return false;
 	if ((base + *size) > max_mem)
@@ -571,8 +587,11 @@ void __init early_init_dt_add_memory_arch(u64 base, u64 size)
 
 	/* Add the chunk to the MEMBLOCK list */
 	if (add_mem_to_memblock) {
-		if (validate_mem_limit(base, &size))
+		if (validate_mem_limit(base, &size)) {
 			memblock_add(base, size);
+			if (base + size > top_phys_addr)
+				top_phys_addr = base + size;
+		}
 	}
 }
 
@@ -612,6 +631,8 @@ static void __init early_reserve_mem_dt(void)
 static void __init early_reserve_mem(void)
 {
 	__be64 *reserve_map;
+	phys_addr_t kasan_shadow_start __maybe_unused;
+	phys_addr_t kasan_memory_size __maybe_unused;
 
 	reserve_map = (__be64 *)(((unsigned long)initial_boot_params) +
 			fdt_off_mem_rsvmap(initial_boot_params));
@@ -650,6 +671,40 @@ static void __init early_reserve_mem(void)
 		return;
 	}
 #endif
+
+#if defined(CONFIG_KASAN) && defined(CONFIG_PPC_BOOK3S_64)
+	kasan_memory_size = ((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN
+		* 1024 * 1024);
+
+	if (top_phys_addr < kasan_memory_size) {
+		/*
+		 * We are doomed. Attempts to call e.g. panic() are likely to
+		 * fail because they call out into instrumented code, which
+		 * will almost certainly access memory beyond the end of
+		 * physical memory. Hang here so that at least the NIP points
+		 * somewhere that will help you debug it if you look at it in
+		 * qemu.
+		 */
+		while (true)
+			;
+	} else if (top_phys_addr > kasan_memory_size) {
+		/* print a biiiig warning in hopes people notice */
+		pr_err("===========================================\n"
+			"Physical memory exceeds compiled-in maximum!\n"
+			"This kernel was compiled for KASAN with %u MB physical memory.\n"
+			"The actual physical memory detected is %llu MB.\n"
+			"Memory above the compiled limit will not be used!\n"
+			"===========================================\n",
+			CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
+			top_phys_addr / (1024 * 1024));
+	}
+
+	kasan_shadow_start = _ALIGN_DOWN(kasan_memory_size * 7 / 8, PAGE_SIZE);
+	DBG("reserving %llx -> %llx for KASAN",
+	    kasan_shadow_start, top_phys_addr);
+	memblock_reserve(kasan_shadow_start,
+			 top_phys_addr - kasan_shadow_start);
+#endif
 }
 
 #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index 6577897673dd..ff8143ba1e4d 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -3,3 +3,4 @@
 KASAN_SANITIZE := n
 
 obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC_BOOK3S_64)   += kasan_init_book3s_64.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_book3s_64.c b/arch/powerpc/mm/kasan/kasan_init_book3s_64.c
new file mode 100644
index 000000000000..fafda3d5e9a3
--- /dev/null
+++ b/arch/powerpc/mm/kasan/kasan_init_book3s_64.c
@@ -0,0 +1,76 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KASAN for 64-bit Book3S powerpc
+ *
+ * Copyright (C) 2019 IBM Corporation
+ * Author: Daniel Axtens <dja@axtens.net>
+ */
+
+#define DISABLE_BRANCH_PROFILING
+
+#include <linux/kasan.h>
+#include <linux/printk.h>
+#include <linux/sched/task.h>
+#include <asm/pgalloc.h>
+
+unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
+
+pte_t kasan_early_shadow_pte[R_PTRS_PER_PTE] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[R_PTRS_PER_PMD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[R_PTRS_PER_PUD] __page_aligned_bss;
+p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
+
+void __init kasan_init(void)
+{
+	int i;
+	void *k_start = kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
+	void *k_end = kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
+
+	unsigned long pte_val = __pa(kasan_early_shadow_page)
+					| pgprot_val(PAGE_KERNEL) | _PAGE_PTE;
+
+	if (!early_radix_enabled())
+		panic("KASAN requires radix!");
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		kasan_early_shadow_pte[i] = __pte(pte_val);
+
+	for (i = 0; i < PTRS_PER_PMD; i++)
+		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
+				    kasan_early_shadow_pte);
+
+	for (i = 0; i < PTRS_PER_PUD; i++)
+		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
+			     kasan_early_shadow_pmd);
+
+
+	memset(kasan_mem_to_shadow((void *)PAGE_OFFSET), KASAN_SHADOW_INIT,
+		KASAN_SHADOW_SIZE);
+
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START),
+		kasan_mem_to_shadow((void *)RADIX_VMALLOC_START));
+
+	/* leave a hole here for vmalloc */
+
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)RADIX_VMALLOC_END),
+		kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END));
+
+	flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);
+
+	/* mark early shadow region as RO and wipe */
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
+			&kasan_early_shadow_pte[i],
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+			__pgprot(_PAGE_PTE | _PAGE_KERNEL_RO | _PAGE_BASE)),
+			0);
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+
+	kasan_init_tags();
+
+	/* Enable error messages */
+	init_task.kasan_depth = 0;
+	pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
+}
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190806233827.16454-5-dja%40axtens.net.
