Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBG6ZW6GQMGQEKDA7UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 69F7E469487
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:57:32 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf7670815wme.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:57:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788252; cv=pass;
        d=google.com; s=arc-20160816;
        b=sJOFi6bbG6FlaXrP2MKGfD15MRHJ9sS4Sc6qyR2PXTlhDeZtagkZzCy2n2RO/my/2E
         4rK7bgN4tDKMWchkL2wcsmiaP6S6m/bJ+moifu5Sa/VV+yKOpGtsq2ppWtq/RJMSRTWb
         nOhNQz+TuPnm28OQ3Zfs9ggBnYJ0lrKJcU+pL+sTSmWGPbpKpD7f5Ss0cWbjnkgzROb1
         /lAEbkE46zxVx8agRUBhKc7wKWc+g9wqFin7y27hbzHBeyFv0KkD5davTw0fTK2IyvWV
         ag85EpHWyUbJ+hb2uxnymXaRUeF1eBwnKeb2k05oOTjBZtcqlsUZ9y6kaaMEA4rH/xk/
         8xlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UNVzhAxEeaJCYt/m/YMfq+0+hF8b0UqnSiRfysz5rO0=;
        b=WbwaYJZDKTS6VK4G0xcgWnW4XyvegIWGGB/j63Khm0Kgw6NENzq4E+HlsyjLURnQsD
         FF7yKZZf3/r6vO5VYOMlfjdS8RvmWW0stQJsk1//v2uz/LXvAu79HJRa+sNgKPburmIM
         7na3vVFRciptYXHHqWQrdtiLKA5QXKs0XXpHqdqvxYGlhRukWrxmnz5U+JlhWqxJVrJY
         v4z2Rw0HY398lh4FeNOi6nC6jE0LXOPN/ozxUCGnrsmBcz9wHdlJuFEfiinaXklEe/LV
         sLnqIQ2uF24CiA124AacEoRE03JTAWh6Ovo2pHtQR2vJdhPQkEFU/m6AKwEQIyc8lwPO
         kWoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=rlLlQ3fZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UNVzhAxEeaJCYt/m/YMfq+0+hF8b0UqnSiRfysz5rO0=;
        b=fslPKtJDMj4Td7jGF5b+JAdycUffUYTlfoaJjUfSvV2yQvSJQLAIDYlTavkfnU9HhU
         VIhqiRednwOHx7hZM+NW3WAp8lA62XHX4Uny8cwQLxbK4d2uIpexRxL+SGeqhg66eLuS
         H133NXIy3csXc8wX5ujKGGd7ibcieQ/M+bdwQTqousczICtOD5kjkpWduFlde0Id7xAJ
         FPvaYNrG3lJ5qH/UF4fFFbaAvl2v1R/+j7WQYFfa2Tm5FC6sDEu4uOjAPkf2WuOtnuB9
         MGXw2MK/FTLZQ+/uc+rAWpIB91OvZ7Q6ZrN3W2Zmw7LsAZ+GQFUJIA9STL06FCyxCN8c
         dLqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UNVzhAxEeaJCYt/m/YMfq+0+hF8b0UqnSiRfysz5rO0=;
        b=OihL3WkOK4tJAv8pDzSEUcVCWmFDnzy8fADv4iGTCYvx+P0VdD2CmbaARqHEpQlJdO
         R7RgfwUAgZnb0dh1c+Eokb1PsW4QEwV6oNEiLJS0jzC9+DHZSaRYmeSVPFmahJ9N+slg
         njO/TUVljM8B3odTfLo/+NvBhAwUxejO1GST9fl8hJnMk36C4T9AGv8epDuTsjHpIfOf
         wNVGF8vUhZpzgYKsS2yCH7hAdaP35qQR6SfheZ7OjCRo6+P5PZu2iNiZdC3jkW+4Wg6o
         xA1lT6PH8u7GjZ5fp06oZUM+6sRp6icfiZjhfGPCHePfRuzgzVPRmCHJCYiEc8LBjz3P
         V5eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NVJqEim3EfTLYZ0W0nYH+WBmbPtO5D69TkvYaT5Uym4otbIxn
	FZdpettCaxeAWVNsoKX/qd0=
X-Google-Smtp-Source: ABdhPJxp9oFuU3V5mZ9H7GB0bqxYZypUpmFFWu+9Dk/4G1RjY6qOCJc31HzLvp824BcR8QxWDLMR+g==
X-Received: by 2002:a05:600c:4ed2:: with SMTP id g18mr38793748wmq.122.1638788252117;
        Mon, 06 Dec 2021 02:57:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls9964250wme.0.canary-gmail; Mon,
 06 Dec 2021 02:57:31 -0800 (PST)
X-Received: by 2002:a05:600c:4f03:: with SMTP id l3mr38867593wmq.47.1638788251241;
        Mon, 06 Dec 2021 02:57:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788251; cv=none;
        d=google.com; s=arc-20160816;
        b=jhaWB1LhC1+4C42EcAOuEGfW1/xrAleQs9nmVxakt69ROJhA8BkjAQgFePmHR9h9+0
         s7x021HNVpyxriy4CkmkiFxfYoWeuFIUk94oO9ngcOXQi3up+FujkiaHWlRXPRUKr0Qm
         khUXfZ7CwRYC/G30iESelDXu8AbA0xM2vNLRDr6Fq/uknkU1WKiBsl6qIdRVS+w4/Tu5
         GI3EXoZRWFIHBF7mLd1avJuk7r+UVc4mw05w2QXpirbvJZxRpkXOjQtY5x4bSYB634Dx
         +r4sgO7od4NorxB8gcIJURE5v4h+I/Rb8ZaPOJ+Wrodsb0Fl07crMGyzPHpuwiZoZbEj
         oQHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fuCo6GlipVLANouxdlUj9UPk8z3xqJtBdYt3yi5vrR4=;
        b=QasLkifhJ2MVSeyL0kD1O460Ec3JbnlvdpzWlxB3uAg88J7SWKoZJKNfLG/lE1WFFs
         keI3e22E9HlritGMzccLhoB2rEQyYUFCDqZLNMz6mF03DxRvdYiy5PNF2Jjrprg7Uyui
         jKz14Al3f7dba9v/v1Df0JV/yyBA6TxdkxPVEJzbGhroPepFhM/NHXUF7BDIoJOyW2U5
         /DmQ5a2ev1MtoDD5yfDYGPEkc6fjvXp7/i9z+1Dh2ujmQAY31iH1rWnCmYFxDSpk/9bE
         9ih0T48peZ886BwSVB43KNrTScRfmkDHKXQ8aycuYnHKZpSdUgt0wk19mFoxjGxFC6cd
         ksAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=rlLlQ3fZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id a1si666029wrv.4.2021.12.06.02.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:57:31 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id C0F973F1F1
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:57:30 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id a64-20020a1c7f43000000b003335e5dc26bso5915448wmd.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:57:30 -0800 (PST)
X-Received: by 2002:a1c:96:: with SMTP id 144mr38540570wma.126.1638788249419;
        Mon, 06 Dec 2021 02:57:29 -0800 (PST)
X-Received: by 2002:a1c:96:: with SMTP id 144mr38540542wma.126.1638788249196;
        Mon, 06 Dec 2021 02:57:29 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id t127sm13430498wma.9.2021.12.06.02.57.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:57:28 -0800 (PST)
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
Subject: [PATCH v3 10/13] riscv: Improve virtual kernel memory layout dump
Date: Mon,  6 Dec 2021 11:46:54 +0100
Message-Id: <20211206104657.433304-11-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=rlLlQ3fZ;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

With the arrival of sv48 and its large address space, it would be
cumbersome to statically define the unit size to use to print the different
portions of the virtual memory layout: instead, determine it dynamically.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/init.c               | 67 +++++++++++++++++++++++-------
 drivers/pci/controller/pci-xgene.c |  2 +-
 include/linux/sizes.h              |  1 +
 3 files changed, 54 insertions(+), 16 deletions(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 6a19a1b1caf8..28de6ea0a720 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -79,37 +79,74 @@ static void __init zone_sizes_init(void)
 }
 
 #if defined(CONFIG_MMU) && defined(CONFIG_DEBUG_VM)
+
+#define LOG2_SZ_1K  ilog2(SZ_1K)
+#define LOG2_SZ_1M  ilog2(SZ_1M)
+#define LOG2_SZ_1G  ilog2(SZ_1G)
+#define LOG2_SZ_1T  ilog2(SZ_1T)
+
 static inline void print_mlk(char *name, unsigned long b, unsigned long t)
 {
 	pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld kB)\n", name, b, t,
-		  (((t) - (b)) >> 10));
+		  (((t) - (b)) >> LOG2_SZ_1K));
 }
 
 static inline void print_mlm(char *name, unsigned long b, unsigned long t)
 {
 	pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld MB)\n", name, b, t,
-		  (((t) - (b)) >> 20));
+		  (((t) - (b)) >> LOG2_SZ_1M));
+}
+
+static inline void print_mlg(char *name, unsigned long b, unsigned long t)
+{
+	pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld GB)\n", name, b, t,
+		  (((t) - (b)) >> LOG2_SZ_1G));
+}
+
+#ifdef CONFIG_64BIT
+static inline void print_mlt(char *name, unsigned long b, unsigned long t)
+{
+	pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld TB)\n", name, b, t,
+		  (((t) - (b)) >> LOG2_SZ_1T));
+}
+#endif
+
+static inline void print_ml(char *name, unsigned long b, unsigned long t)
+{
+	unsigned long diff = t - b;
+
+#ifdef CONFIG_64BIT
+	if ((diff >> LOG2_SZ_1T) >= 10)
+		print_mlt(name, b, t);
+	else
+#endif
+	if ((diff >> LOG2_SZ_1G) >= 10)
+		print_mlg(name, b, t);
+	else if ((diff >> LOG2_SZ_1M) >= 10)
+		print_mlm(name, b, t);
+	else
+		print_mlk(name, b, t);
 }
 
 static void __init print_vm_layout(void)
 {
 	pr_notice("Virtual kernel memory layout:\n");
-	print_mlk("fixmap", (unsigned long)FIXADDR_START,
-		  (unsigned long)FIXADDR_TOP);
-	print_mlm("pci io", (unsigned long)PCI_IO_START,
-		  (unsigned long)PCI_IO_END);
-	print_mlm("vmemmap", (unsigned long)VMEMMAP_START,
-		  (unsigned long)VMEMMAP_END);
-	print_mlm("vmalloc", (unsigned long)VMALLOC_START,
-		  (unsigned long)VMALLOC_END);
-	print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
-		  (unsigned long)high_memory);
+	print_ml("fixmap", (unsigned long)FIXADDR_START,
+		 (unsigned long)FIXADDR_TOP);
+	print_ml("pci io", (unsigned long)PCI_IO_START,
+		 (unsigned long)PCI_IO_END);
+	print_ml("vmemmap", (unsigned long)VMEMMAP_START,
+		 (unsigned long)VMEMMAP_END);
+	print_ml("vmalloc", (unsigned long)VMALLOC_START,
+		 (unsigned long)VMALLOC_END);
+	print_ml("lowmem", (unsigned long)PAGE_OFFSET,
+		 (unsigned long)high_memory);
 #ifdef CONFIG_64BIT
 #ifdef CONFIG_KASAN
-	print_mlm("kasan", KASAN_SHADOW_START, KASAN_SHADOW_END);
+	print_ml("kasan", KASAN_SHADOW_START, KASAN_SHADOW_END);
 #endif
-	print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
-		  (unsigned long)ADDRESS_SPACE_END);
+	print_ml("kernel", (unsigned long)KERNEL_LINK_ADDR,
+		 (unsigned long)ADDRESS_SPACE_END);
 #endif
 }
 #else
diff --git a/drivers/pci/controller/pci-xgene.c b/drivers/pci/controller/pci-xgene.c
index e64536047b65..187dcf8a9694 100644
--- a/drivers/pci/controller/pci-xgene.c
+++ b/drivers/pci/controller/pci-xgene.c
@@ -21,6 +21,7 @@
 #include <linux/pci-ecam.h>
 #include <linux/platform_device.h>
 #include <linux/slab.h>
+#include <linux/sizes.h>
 
 #include "../pci.h"
 
@@ -50,7 +51,6 @@
 #define OB_LO_IO			0x00000002
 #define XGENE_PCIE_VENDORID		0x10E8
 #define XGENE_PCIE_DEVICEID		0xE004
-#define SZ_1T				(SZ_1G*1024ULL)
 #define PIPE_PHY_RATE_RD(src)		((0xc000 & (u32)(src)) >> 0xe)
 
 #define XGENE_V1_PCI_EXP_CAP		0x40
diff --git a/include/linux/sizes.h b/include/linux/sizes.h
index 1ac79bcee2bb..0bc6cf394b08 100644
--- a/include/linux/sizes.h
+++ b/include/linux/sizes.h
@@ -47,6 +47,7 @@
 #define SZ_8G				_AC(0x200000000, ULL)
 #define SZ_16G				_AC(0x400000000, ULL)
 #define SZ_32G				_AC(0x800000000, ULL)
+#define SZ_1T				_AC(0x10000000000, ULL)
 #define SZ_64T				_AC(0x400000000000, ULL)
 
 #endif /* __LINUX_SIZES_H__ */
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-11-alexandre.ghiti%40canonical.com.
