Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB46UW6GQMGQEL5PAUTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 45C6046942B
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:48:20 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id i14-20020a2e864e000000b00218a2c57df8sf3236922ljj.20
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:48:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787699; cv=pass;
        d=google.com; s=arc-20160816;
        b=dZt5gHguyymoxh1hlMXJ439d1WZPDDW/NeuQ0Lk1RqUArsj6iK47eMeWbFQLruy/Wz
         biMt25qudEOgPoZvLshhvT8yAQMwcOta9aOhZkpqkRVjFmkWK1emDRDr000FLpGMeeEI
         6WLHTnKOFkVonJsTlIIN7OpOoQvUv3BHjtnuslPop4OHL3YlWQI3uTEPrz8N5PTQKuWv
         oA+J0Pj95+h5DdxEKe0p+YG2RJsOG9ev8RIPhVk9sETDI/a/+WqLNAumUL76gqiHjo54
         1GsuQq9YWbSCubOHAlNO2CrHFYM2hk7dU3OciD92KwtIoKPN9Xzx3r4e5kCGCc/7Gs1X
         cvFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Qy/6H4JMIFEImp2waKUjJsBlH7wlj17MqPeBW5cohDI=;
        b=K0P3gfvEE4HLvfkwxOcNaJh/y90zRvYWW6qAF80EBk+C+6QvzEnWnJmpMnrQ446CVU
         lDovfgFBWG0UkjE40mV4g8B68wEsQvm6iq5OZ9gl2ofMAsKtGC9GZa3L0hTeDddTgOsr
         N2zyh749HOAp5ZujEO4rRzsi4RMNR4/1nKZJ6RRljzNpff273j53tkge41/Xys3o91UF
         LqqDX/Djq8Rl0Tz9e6hmnqOiCQtJlSNNUjVsDLWwvkunqu0ZTFZuowWFT/OYRBm/pRh2
         tYhCpy++0ZOHK4+ncHSt9dCBWugIZnqhim4rloY6VLQT84Bbh6ddIW0kZ1zNc9itYHXO
         spaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=CSbLIA0E;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qy/6H4JMIFEImp2waKUjJsBlH7wlj17MqPeBW5cohDI=;
        b=BoMZL7SXqy3jltBeA+1ofKA6uYdpQ9LH6Eu3I8xOUw7JveBEEC2Ql/7KRwItDYHUH5
         ARMU4Eb8P3DDLkZLtKgQUvOaTDqYY0eYbhaXYahOVY6/bQCJVpqVqtibXTvEcMdT443b
         PNXQucHHeRBmxCvMF4ruZpxaJEfaZ8CxlkaZXbJVZQX4y1xs6zDPKtk3epwoeJetOfci
         6HO4bLfV3Y6R2aD1MBDIcVistS7y2hgeN7chHAluAwGJLitwEks5TT4UTk4OwDRXDxBC
         XfC3i95sPxlWa6JBW4IiUhB33Gn0m/fMjgM4BXb9BwRbw5zIs6JF8UcO2KBX82LYuoxu
         XVfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qy/6H4JMIFEImp2waKUjJsBlH7wlj17MqPeBW5cohDI=;
        b=M3sB8T+NTI298fSMDYs/HtVdLvA72DG6woH21nqh22bOdUeg2bBPgkjXKe/ByTrnJk
         Vu/MPHbRy+AiG6pg6qR8GEJaNDupNv4313uoDGEBo60AeC++4Ijd1WCrZzP7dxzyKc36
         rcfFM0PPPwlzQUg1c1Ra7h7Ho/6iE/Y3HWuPGCWCkcWFnYo2iJfSxe0jBNo57+ujAbYa
         xkxEnB+2eYyRR/8TJUJaaDOOxN8EVveWGcS0gXPGzadp0wXA78E6Fqt7Dm4jJQi0xHjg
         gUCq++uUwgCjbBaRY5KCBWVT3bjjjw+V8WtsUK26P6LO3j9YodBjrHAVhe0tRXSkAXEV
         zg1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336jaOhbb7s6BBcaxuuv5566DOUc3OnBsV/GqNnVX292CS4EmOM
	CxXFo9as0KbojykutZEadnw=
X-Google-Smtp-Source: ABdhPJx+GizUn+ceTzyA8SVDKllKLc3qwXQ19nHs6wbzsH/TxF3iX5gcLY+g8qQUx0KbpKdkBlQOfw==
X-Received: by 2002:a2e:8396:: with SMTP id x22mr34953510ljg.255.1638787699854;
        Mon, 06 Dec 2021 02:48:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls688443lfu.0.gmail; Mon, 06
 Dec 2021 02:48:18 -0800 (PST)
X-Received: by 2002:a05:6512:3501:: with SMTP id h1mr35068966lfs.231.1638787698919;
        Mon, 06 Dec 2021 02:48:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787698; cv=none;
        d=google.com; s=arc-20160816;
        b=wigvHYW2im8h4JFiiuoEqCVn5oeCFgzPuiec/kXyBi1KeYBwoNgu5Gp5DikmXwl5ZT
         VR7VGS7kva0CCHj3DIux0mjXV5NPRaYr6+7HfSgoxdFKbl8w4bCQ6abh8AHTI/6GN6dp
         tudrFCy97U7+hof3F8FB+vXaQRy49NM6IIgXXEtHrR3qK7nYFsSuPY5oflhedQ2BvQ8q
         wkBA5LNG2JCGhvkki4n9kWxXnvBLVz+JxrzzZg1q5hyqIJPni1NFDgNSsWXm/elTl/gL
         VdMXU4M73WQodBAqC0YC+mWgDqG+v4NsQPfef36Pn2QVx05N923U2WAs/EJiM7m1e1qJ
         IXyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uBHu8SZdjJQkCA/FR348EzSoCIWhCD+JHxQLyWBcing=;
        b=JapdTs7je/v/cVpoaRUoZPNSiss0fd+LSF2rdVw1SNpaEM+cvEJYLqOF4Mv4mz1meZ
         RHD4WpXfm+3Ud6iog6VQtY4a8Zk96L8BT8BD/HM4ThnGPJtj2/HCaKp3li57nJlko/LM
         PV++uc/DWm9hpViTmvCN4d33ibENOdxcxMjaUZ1dJsvCOmhJBeellQiGi2ndtIKVgZs/
         LfaHwu2XGf6/HvHS7DX8FdXQ8x/CgF8dDZiuxsJ5DrZAhVny0qU9GRvzt4fX13hO1N+m
         qL9oG24O0g/vCAhW/e5cpTD/yaBUTuzxDoEvwHfnShDpuLaZhg74tyvBAK8mU67LOA8X
         oulg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=CSbLIA0E;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id u19si693907ljl.5.2021.12.06.02.48.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:48:18 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com [209.85.221.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 516F63F1F4
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:48:18 +0000 (UTC)
Received: by mail-wr1-f71.google.com with SMTP id d7-20020a5d6447000000b00186a113463dso1890835wrw.10
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:48:18 -0800 (PST)
X-Received: by 2002:a7b:c763:: with SMTP id x3mr37984597wmk.31.1638787697931;
        Mon, 06 Dec 2021 02:48:17 -0800 (PST)
X-Received: by 2002:a7b:c763:: with SMTP id x3mr37984567wmk.31.1638787697752;
        Mon, 06 Dec 2021 02:48:17 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id d2sm10975342wmb.31.2021.12.06.02.48.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:48:17 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 01/13] riscv: Move KASAN mapping next to the kernel mapping
Date: Mon,  6 Dec 2021 11:46:45 +0100
Message-Id: <20211206104657.433304-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=CSbLIA0E;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Now that KASAN_SHADOW_OFFSET is defined at compile time as a config,
this value must remain constant whatever the size of the virtual address
space, which is only possible by pushing this region at the end of the
address space next to the kernel mapping.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 Documentation/riscv/vm-layout.rst | 12 ++++++------
 arch/riscv/Kconfig                |  4 ++--
 arch/riscv/include/asm/kasan.h    |  4 ++--
 arch/riscv/include/asm/page.h     |  6 +++++-
 arch/riscv/include/asm/pgtable.h  |  6 ++++--
 arch/riscv/mm/init.c              | 25 +++++++++++++------------
 6 files changed, 32 insertions(+), 25 deletions(-)

diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-layout.rst
index b7f98930d38d..1bd687b97104 100644
--- a/Documentation/riscv/vm-layout.rst
+++ b/Documentation/riscv/vm-layout.rst
@@ -47,12 +47,12 @@ RISC-V Linux Kernel SV39
                                                               | Kernel-space virtual memory, shared between all processes:
   ____________________________________________________________|___________________________________________________________
                     |            |                  |         |
-   ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
-   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixmap
-   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI io
-   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemmap
-   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB | vmalloc/ioremap space
-   ffffffe000000000 | -128    GB | ffffffff7fffffff |  124 GB | direct mapping of all physical memory
+   ffffffc6fee00000 | -228    GB | ffffffc6feffffff |    2 MB | fixmap
+   ffffffc6ff000000 | -228    GB | ffffffc6ffffffff |   16 MB | PCI io
+   ffffffc700000000 | -228    GB | ffffffc7ffffffff |    4 GB | vmemmap
+   ffffffc800000000 | -224    GB | ffffffd7ffffffff |   64 GB | vmalloc/ioremap space
+   ffffffd800000000 | -160    GB | fffffff6ffffffff |  124 GB | direct mapping of all physical memory
+   fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               |
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 6d5b63bd4bd9..6cd98ade5ebc 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -161,12 +161,12 @@ config PAGE_OFFSET
 	default 0xC0000000 if 32BIT && MAXPHYSMEM_1GB
 	default 0x80000000 if 64BIT && !MMU
 	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
-	default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
+	default 0xffffffd800000000 if 64BIT && MAXPHYSMEM_128GB
 
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN_GENERIC
-	default 0xdfffffc800000000 if 64BIT
+	default 0xdfffffff00000000 if 64BIT
 	default 0xffffffff if 32BIT
 
 config ARCH_FLATMEM_ENABLE
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index b00f503ec124..257a2495145a 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -28,8 +28,8 @@
 #define KASAN_SHADOW_SCALE_SHIFT	3
 
 #define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
-#define KASAN_SHADOW_START	KERN_VIRT_START
-#define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
+#define KASAN_SHADOW_START	(KASAN_SHADOW_END - KASAN_SHADOW_SIZE)
+#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
 void kasan_init(void);
diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 109c97e991a6..e03559f9b35e 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -33,7 +33,11 @@
  */
 #define PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)
 
-#define KERN_VIRT_SIZE (-PAGE_OFFSET)
+/*
+ * Half of the kernel address space (half of the entries of the page global
+ * directory) is for the direct mapping.
+ */
+#define KERN_VIRT_SIZE		((PTRS_PER_PGD / 2 * PGDIR_SIZE) / 2)
 
 #ifndef __ASSEMBLY__
 
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 39b550310ec6..d34f3a7a9701 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -39,8 +39,10 @@
 
 /* Modules always live before the kernel */
 #ifdef CONFIG_64BIT
-#define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
-#define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
+/* This is used to define the end of the KASAN shadow region */
+#define MODULES_LOWEST_VADDR	(KERNEL_LINK_ADDR - SZ_2G)
+#define MODULES_VADDR		(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
+#define MODULES_END		(PFN_ALIGN((unsigned long)&_start))
 #endif
 
 /*
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index c0cddf0fc22d..4224e9d0ecf5 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -103,6 +103,9 @@ static void __init print_vm_layout(void)
 	print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
 		  (unsigned long)high_memory);
 #ifdef CONFIG_64BIT
+#ifdef CONFIG_KASAN
+	print_mlm("kasan", KASAN_SHADOW_START, KASAN_SHADOW_END);
+#endif
 	print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
 		  (unsigned long)ADDRESS_SPACE_END);
 #endif
@@ -130,18 +133,8 @@ void __init mem_init(void)
 	print_vm_layout();
 }
 
-/*
- * The default maximal physical memory size is -PAGE_OFFSET for 32-bit kernel,
- * whereas for 64-bit kernel, the end of the virtual address space is occupied
- * by the modules/BPF/kernel mappings which reduces the available size of the
- * linear mapping.
- * Limit the memory size via mem.
- */
-#ifdef CONFIG_64BIT
-static phys_addr_t memory_limit = -PAGE_OFFSET - SZ_4G;
-#else
-static phys_addr_t memory_limit = -PAGE_OFFSET;
-#endif
+/* Limit the memory size via mem. */
+static phys_addr_t memory_limit;
 
 static int __init early_mem(char *p)
 {
@@ -613,6 +606,14 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 
 	riscv_pfn_base = PFN_DOWN(kernel_map.phys_addr);
 
+	/*
+	 * The default maximal physical memory size is KERN_VIRT_SIZE for 32-bit
+	 * kernel, whereas for 64-bit kernel, the end of the virtual address
+	 * space is occupied by the modules/BPF/kernel mappings which reduces
+	 * the available size of the linear mapping.
+	 */
+	memory_limit = KERN_VIRT_SIZE - (IS_ENABLED(CONFIG_64BIT) ? SZ_4G : 0);
+
 	/* Sanity check alignment and size */
 	BUG_ON((PAGE_OFFSET % PGDIR_SIZE) != 0);
 	BUG_ON((kernel_map.phys_addr % PMD_SIZE) != 0);
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-2-alexandre.ghiti%40canonical.com.
