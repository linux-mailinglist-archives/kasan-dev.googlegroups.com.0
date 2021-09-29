Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBJX62GFAMGQEVOGLZ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0191841C798
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:58:47 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id c8-20020adfef48000000b00160646ed62csf694614wrp.18
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:58:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927526; cv=pass;
        d=google.com; s=arc-20160816;
        b=R63R3AnsXgAfV0/ZKw4ud9GYZdbLDjTes/kJiusT3jbJwJPuDq1gBLHP0tLeSMo3zr
         VeqfxasfUCFHXWV4eii+0DO5w6qaomeouRn2h6Wz9Q2P0Pt7e2QM3RjY1Hik4HEWlyfO
         ZkiUuJZzmc3cILf7owbY34bJZKZJcWdkKyZt4C7JMiOq8m+rnwMYGgj1Z8mH2FxtuVSm
         E+ZQg/ErM+Vc9KGZ9+w18281KMG+oCki+RfIoW2O1KTkWf3u2R/md38C9OxRfpUWC3rS
         mUi4AsEw67CBS56rY5WPANc1jBKBnctiwCl7zOrwmsiWB6btZQu0C5s9WmIPQvLKxQw0
         1KLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aBu3V9wWEVJvlkvG+k6F6+LVjtC+8qmCqu2XW5eMoSs=;
        b=I2o+ND2bakpnF7vCS9VYbbTXtkyNXgtPBIqNOOTRdx5HYdZfyDm7sWfaoZYZgsYbiH
         ZGRlfwcYhEUk85qhLaeHR2SVpYsfrUkq97nUepEDRU2XAFZovD7IbB0FHEWSGj7HpzFy
         y15HB1BQtMJ20Evscls+aNJyt+VbN37y9yE9U2pfVebe+yCahuQZf6rA8RT7tkn4bkWp
         bdVi8BRHjWhW9OoFa5fdlURxyDDpL/GGOn0kt+HlKeg4Rvj9DxGBiToalbXMpHqyd4+q
         hT2A9SZX6JDZJhZu2/AEg10jV7sKb1OX3kH3LgQjw1SyQta/opjOkvj6gCcqBRluRUa8
         6zeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=JY12piwZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aBu3V9wWEVJvlkvG+k6F6+LVjtC+8qmCqu2XW5eMoSs=;
        b=U/8713XwCkU9ih57ZvrFPLzDE3vdi/IoR/ZTnY419UmwzAOph4WSTtsAZ8NjZTHxm0
         IzRPxFfXtpKOYBG/3/l7W3DisFfF+snPnwA1UInvU22ZqzIcEL97dLWnFYzaikkoKUM8
         DaFIiMmsJ/2YYDd7HsP+xGYXgDpKWd8hVcLvhqjy4MFwYaa4mw51K1qCm1Y6BvLJ7CkJ
         gma65spVm7+WfS395q3j1fL/ZcNaowIoYhXjPSmgCYvfR84ESBSlQOmE6UOp3q8Je7vy
         HiXIGnv5z8MDqwylEC8589BpbJKr3zYcLC1QxryIzYI/nLaHmgkQtr2dnEzjWrD715FW
         396w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aBu3V9wWEVJvlkvG+k6F6+LVjtC+8qmCqu2XW5eMoSs=;
        b=n9nB5EeojqT7QKJPADD1w37t/Hjg3VTDNgZ18jlOSKQhtMhXRi06w/VA7h35Rtgz9a
         efPfIDJYHjVIltQXuCiu5ZeJjTo/GrDCIm4miTs3QNmKrh1XZbaBkFRynmJZm3+4Z7Pc
         NqqVHsbVUf9nZr8bwNVXlx8PdIoxae/H4lqwkwIfHzYPszfPafEDfusYDiTAtD57cea8
         HWj3ZrYjs+p/UtPiCzJQSqyFw+Ii9WYXeINSBwofnK+bjuw9lHcmGDYvmbw2VVQsJfEC
         0q/8o6sS/t/7JmAlJHXShowHTInytStn/IRkafOkwVg/nJqBUE48C/fLPrno1jph3jy/
         DEbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kArtmMhTYCpk9ntZ2d+KbEnLfJBii9DFxtOb6wNCCvxe46ao8
	+0FePxc5UT3FlkR+yR7276M=
X-Google-Smtp-Source: ABdhPJyB92iTd3zTHKrIDQZ2brfNtF28BCVj+gGSCCxDu4REvJujJzzhfVpcSNCZ6UpF99WbbC5AQQ==
X-Received: by 2002:a1c:8010:: with SMTP id b16mr11093395wmd.54.1632927526747;
        Wed, 29 Sep 2021 07:58:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3c8:: with SMTP id t8ls1363586wmj.3.gmail; Wed, 29 Sep
 2021 07:58:45 -0700 (PDT)
X-Received: by 2002:a05:600c:35d2:: with SMTP id r18mr10725594wmq.97.1632927525782;
        Wed, 29 Sep 2021 07:58:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927525; cv=none;
        d=google.com; s=arc-20160816;
        b=kbQizWxN57N31bUASoZy/6kuoeeibIPsoFw3zADm0hqKvuL0N/jNO9bX+zmDOpM9m5
         d3djKMj/eUEDxvVHms7J4sPSb6FlFxXaIYOXlB6ljcszjWnC5ktrNjVfdlDdwDGJfSWv
         UG5qMRzqWBO320o7dYzJEWrTu7sO7T+XZlqUiH4MRaTyqbBZ9Mb3kpVCJLOpoIrAFGpA
         zWfmphUeOz0jza/zsfl6XwCflrVt/srAqo1llKBHEWN7FbKa4BPVNerTJHcwdxuN5qrZ
         tOTDAkJ+oxLjcix7lHTCF/lnkEOyDaKgiDkuxDyGN+BT39po/eGSrtF0BtfstAcHL+v7
         rNDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RA0oQ/GNq6rz6phpPIFpMyTQ81TXHbN7QIZjBCAB7To=;
        b=zH/OKcNKprd3d4ERwrON+SfmElflv9l+5KBuQqmpDTXc7utqv4v5L6SuZclNmZWcLT
         /8cXAw6DXj8NaOZmW09mXJgnl0yaOQMkJWPdlOZf3+uhzzhMT0QfDl7P5BqodWqCaBDI
         qpE1MSlXLgUFJPK6f/8knD2Zx8XCjVlsHrD51gTph6nHzCkWJB8Y5zT+ovgluXZFXzlP
         I2Us0/EL0EMHtvhWfSIVxUs9frcazDrtDk5SAXRrz8GjP/vdKIpk8ZVKQoVJR6EBW8yu
         FmIGUU1f2ha4tDbjPknxTSQB8O7EjGRF9bnB2DrsM8gAA4KofctF/CvZWekrLvSygDqK
         JDbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=JY12piwZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id g83si405171wme.1.2021.09.29.07.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:58:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id F2F7540600
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:58:44 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id r66-20020a1c4445000000b0030cf0c97157so1351103wma.1
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:58:44 -0700 (PDT)
X-Received: by 2002:a5d:4601:: with SMTP id t1mr337443wrq.298.1632927523931;
        Wed, 29 Sep 2021 07:58:43 -0700 (PDT)
X-Received: by 2002:a5d:4601:: with SMTP id t1mr337419wrq.298.1632927523734;
        Wed, 29 Sep 2021 07:58:43 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id c7sm142194wmq.13.2021.09.29.07.58.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:58:43 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
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
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 07/10] riscv: Improve virtual kernel memory layout dump
Date: Wed, 29 Sep 2021 16:51:10 +0200
Message-Id: <20210929145113.1935778-8-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=JY12piwZ;       spf=pass
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
 arch/riscv/mm/init.c  | 65 +++++++++++++++++++++++++++++++++----------
 include/linux/sizes.h |  1 +
 2 files changed, 52 insertions(+), 14 deletions(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index d7de414c6500..a304f2b3c178 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -90,34 +90,71 @@ static void __init zone_sizes_init(void)
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
-	print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
-		  (unsigned long)ADDRESS_SPACE_END);
+	print_ml("kernel", (unsigned long)KERNEL_LINK_ADDR,
+		 (unsigned long)ADDRESS_SPACE_END);
 #endif
 }
 #else
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
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-8-alexandre.ghiti%40canonical.com.
