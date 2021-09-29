Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBNX32GFAMGQEGVV2EDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7137541C753
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:52:39 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id c18-20020a056512075200b003fd0e54a0desf1756089lfs.17
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:52:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927159; cv=pass;
        d=google.com; s=arc-20160816;
        b=RTCpkX8xnESKgwwhuIhxqayXAYysEfR2OFdmY7WmE5FSNRmQI2aycbjyZ0Y5Z+GA5F
         DLVFVVxiLGBzcttP0omGQTgua0Ar+vJaWgbxV29RT3WeDy/K+JsJwVEjjtqAwLgdI9FN
         0ETqdNPd6TyUi7AYcPURVoi6zRjIjqJNjZ8wWc+pqFEdxFYp63hC/78Xcbw6VqrxB6lD
         MIleKAK1TbzHGtescbnNH5UcJr7MYrVqlm4r4yi61UJGhPRBlSQZDViD4X/Q4EXbTdKZ
         lNd0opvfwym+zInDTKvEu0KmC58AOM/3BOyuL43UKmpBz5QQ9X5XHqWzPrk/QhmGu+7W
         WCcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0nXEOWwLsybynM5E8aVNq/0SLTi1bIUriqeDsFzUo9I=;
        b=ewFu5zfJ9w2bNq8n7jaleIOzKVHHMUDD6aF98n/ArUN3esbMlCtRU8Y6WW+pdmqn9/
         Wg6UrSwxF3F/lribOsFs/u2rORZR5cWgSo3plagNQtfDYstuSj3wNdJ8nFFv1BiYzFoq
         G63FtmBYzEsYSZLQ0MbEoY+RMlF4wbx1SckFwIVuwUGd5XEnlnrl1PpT6be+Gc0eVeTB
         JqZc07HY+8fvVVggjYNANOl4ey8a4imZ3TMNWnbA674/r7Pe9cFTBPyJDQ4a2Cm1L8Ew
         ox8DcvTK7IV6L/NwDTUVH7AInAXeshwAZah4s1v37eHmZz4TufqNWe6yp7lsegVlvmM8
         gYPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=jLgiigb2;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nXEOWwLsybynM5E8aVNq/0SLTi1bIUriqeDsFzUo9I=;
        b=YSkDxhuwdZERdlB5n/ecSML00x2QDRIlqF/l2WoIwa1F8q1qxSIZuBXJUjuBX0Bmum
         49uW9efcOzzDMFV/fAiCpPJ2ASPRLdi4FaDT3quQu2hNDXRdLk7KqZMG5tRwggU6Y2ZJ
         xJpgywiXHGB4eiPoNR8GOwotjARmuTmO7TX88LJbTvAhmIBGV8pq57d4froDHb9UfQ5D
         feu765BhSPLPSu2jhqj7locdd2SMcVp7vklrjzAj4dcMuesmJCoHMC0rBzcZp3cs1F4Q
         Oza3yNGUye5dJdiXoX65CQ/HinCrwyo5ZNs06frcMNFwsEjWQ5xRCP3JJfHFy/OSFfJx
         lniA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nXEOWwLsybynM5E8aVNq/0SLTi1bIUriqeDsFzUo9I=;
        b=U0NdzGWGZ31As0mkWXjbbXwZodNZO+VZkmXblRW/Zu4bSoY3RwDHO8ZKcU8XPUa9oe
         25GeYTScJqXV7Nwgg25Xw7bo2ptSMeDgR/4O2f7+WRwnMODeePx227tSl+JtUB5l/R2c
         +atyJ8iwDO6/SRV8csF9l9iNWffjfjQUenlP6+Mb2bEZozGBKdxWjvIQw6GQtG1rwiQ+
         hDopkg0L22a3ULiWzv+bR+GXT8CCXMiL8gNgYBIppYhz9wHsPhoa+gIBpZ26N6p7lult
         WCRLMu27UEthWoRHY74JZNnB0GwshxzTlwNYHyEriAAl1DgIVBaepGcPUISsAIh3txZG
         bsHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uojhpoJVugXuHSovRxlxBIYL3AAxRrN7uLe7MJzRtHZeNaxml
	VyKP5xRoyjtti+z5vsiGtL8=
X-Google-Smtp-Source: ABdhPJxFkrpDe0+ZONVnwJ4Lp9rxOG3YWrviqnPuMu/KAy8yxOd41iWx1kPj2IcbwNvTEYcSSuI24A==
X-Received: by 2002:a2e:924d:: with SMTP id v13mr344822ljg.380.1632927158935;
        Wed, 29 Sep 2021 07:52:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls574689lfu.2.gmail; Wed, 29
 Sep 2021 07:52:38 -0700 (PDT)
X-Received: by 2002:a05:6512:705:: with SMTP id b5mr142714lfs.82.1632927157930;
        Wed, 29 Sep 2021 07:52:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927157; cv=none;
        d=google.com; s=arc-20160816;
        b=wpxoq0NDFEY2TEdVFzWR6quMWl0OUa8xCMCuJmlWjMGtxPXNmplJnFbmcxU4q7qwAG
         20ysSfbn8PxPQ+g5sn1fzK8+MkvfiiBeYfcwvc9rLKEJfmmw/n+E2N2EcZrXs/R24ikA
         E6q70mbS9raNS4/iuT9J82sPSYZJNWhHhiCneatFeRpejRq4JrZ4Y6D0oUnY+YBca5Oj
         AueLWnCJC08ItW2SB1hq2xmlZw6e5tjdg6VdNZ94xYjxLCoPGAy0Xg5EsM7CqlBkU9kN
         M5Vm2P4R3n6jG84YxgjKTt9SMO6aarMd2A72w5HphE1isUKUjWsproVwE6m94Gv7eNYn
         SHog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w+ItQrTCaMVUbpdrDeVWHNI7WQYLMpa9OWlT3PsgkZk=;
        b=0T+8XSY9gXGlwQE2N9h1Wm0BfPF/Y2SFDrJJJOeMIpy7Su6lpEk7hBC9MTDFHPDnGc
         riajdOKRy2iL7JorHLGxUbRGRpE5YuMDv6scf7+LT2L7PidUH24pKjFCOM9zkTCVHrjd
         bv9GCPYlZk3Lg4qoUv/xAubhXp9mqkg0t+AaRrIJWJufN/E+oWJL/L2MSzikth0vq1LJ
         pAxrcV59DV6Aj4mMmeDK8b05paacmgd2kNEbW0Cb4tH5k8YKpM5u8LRUrNd9v9zfui45
         NsNzrTLe4MsfpzGQA2Iz4JZ23bXa9QCF/NI4vZmDGKCIvfWvbx3ELPZdUHd1CSV34iBe
         Ikww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=jLgiigb2;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id z12si4824lfd.13.2021.09.29.07.52.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:52:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com [209.85.221.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id C0013402BC
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:52:35 +0000 (UTC)
Received: by mail-wr1-f71.google.com with SMTP id r21-20020adfa155000000b001608162e16dso146093wrr.15
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:52:35 -0700 (PDT)
X-Received: by 2002:adf:de86:: with SMTP id w6mr253962wrl.287.1632927155215;
        Wed, 29 Sep 2021 07:52:35 -0700 (PDT)
X-Received: by 2002:adf:de86:: with SMTP id w6mr253923wrl.287.1632927155024;
        Wed, 29 Sep 2021 07:52:35 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id k11sm104889wrn.84.2021.09.29.07.52.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:52:34 -0700 (PDT)
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
Subject: [PATCH v2 01/10] riscv: Allow to dynamically define VA_BITS
Date: Wed, 29 Sep 2021 16:51:04 +0200
Message-Id: <20210929145113.1935778-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=jLgiigb2;       spf=pass
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

With 4-level page table folding at runtime, we don't know at compile time
the size of the virtual address space so we must set VA_BITS dynamically
so that sparsemem reserves the right amount of memory for struct pages.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/Kconfig                 | 10 ----------
 arch/riscv/include/asm/pgtable.h   | 10 ++++++++--
 arch/riscv/include/asm/sparsemem.h |  6 +++++-
 3 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index c1abbc876e5b..ee61ecae3ae0 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -145,16 +145,6 @@ config MMU
 	  Select if you want MMU-based virtualised addressing space
 	  support by paged memory management. If unsure, say 'Y'.
 
-config VA_BITS
-	int
-	default 32 if 32BIT
-	default 39 if 64BIT
-
-config PA_BITS
-	int
-	default 34 if 32BIT
-	default 56 if 64BIT
-
 config PAGE_OFFSET
 	hex
 	default 0xC0000000 if 32BIT && MAXPHYSMEM_1GB
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 39b550310ec6..e3e03226a50a 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -48,8 +48,14 @@
  * struct pages to map half the virtual address space. Then
  * position vmemmap directly below the VMALLOC region.
  */
+#ifdef CONFIG_64BIT
+#define VA_BITS		39
+#else
+#define VA_BITS		32
+#endif
+
 #define VMEMMAP_SHIFT \
-	(CONFIG_VA_BITS - PAGE_SHIFT - 1 + STRUCT_PAGE_MAX_SHIFT)
+	(VA_BITS - PAGE_SHIFT - 1 + STRUCT_PAGE_MAX_SHIFT)
 #define VMEMMAP_SIZE	BIT(VMEMMAP_SHIFT)
 #define VMEMMAP_END	(VMALLOC_START - 1)
 #define VMEMMAP_START	(VMALLOC_START - VMEMMAP_SIZE)
@@ -651,7 +657,7 @@ static inline pmd_t pmdp_establish(struct vm_area_struct *vma,
  * and give the kernel the other (upper) half.
  */
 #ifdef CONFIG_64BIT
-#define KERN_VIRT_START	(-(BIT(CONFIG_VA_BITS)) + TASK_SIZE)
+#define KERN_VIRT_START	(-(BIT(VA_BITS)) + TASK_SIZE)
 #else
 #define KERN_VIRT_START	FIXADDR_START
 #endif
diff --git a/arch/riscv/include/asm/sparsemem.h b/arch/riscv/include/asm/sparsemem.h
index 45a7018a8118..63acaecc3374 100644
--- a/arch/riscv/include/asm/sparsemem.h
+++ b/arch/riscv/include/asm/sparsemem.h
@@ -4,7 +4,11 @@
 #define _ASM_RISCV_SPARSEMEM_H
 
 #ifdef CONFIG_SPARSEMEM
-#define MAX_PHYSMEM_BITS	CONFIG_PA_BITS
+#ifdef CONFIG_64BIT
+#define MAX_PHYSMEM_BITS	56
+#else
+#define MAX_PHYSMEM_BITS	34
+#endif /* CONFIG_64BIT */
 #define SECTION_SIZE_BITS	27
 #endif /* CONFIG_SPARSEMEM */
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-2-alexandre.ghiti%40canonical.com.
