Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBK6WW6GQMGQEJPAYQLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CE4E469450
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:51:23 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id d3-20020adfa343000000b0018ed6dd4629sf1908404wrb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:51:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787883; cv=pass;
        d=google.com; s=arc-20160816;
        b=SaoKAICl4K8ZL5Lt46u6r7kEBAQJ44o1hB6ffJ5NL6ZBfEYa1InYay/XzxHFkPN6cC
         BmuyiWDcBhLSik1pScPhCJOuAOevuOSavtJ1r6cGWcNVE//T0uWL+V7sPaBqKlvhPm8+
         VyOpDEwdv53uyJTd6lm9j3Mx/FxcS5rCu8/v8xjQ8hgajH5nHInZWxuvllPdhmshjBMV
         kcHzBnMQKW0RdiJ6Wyit7PlkWhCJZnsKK+9SYFsz8XqhGsgHRwjd9MEte6MZY3cXDaUt
         tvQ5R1odgMowB3bunWWx3Ax8qajaAmikaPWr+ibZtuz59Ltdb1ypT5Dgc8VSRuF8KNDy
         ubSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4TvTk2n70RD2R+5ViVTKqct/1OCsJZufBpKvFTJ5Puo=;
        b=a89XcLm2l9Dug+QbfGjYDtJWoaIassT7JG729pwey5M9wnBNa3eDoBEkqEquyAQpkh
         eRg0A33OdxC+/UreLN6VMYCDtqUNFE6Mu/O6hs9zEvpCkr8b+mKq2IkjNWTqpqTsOV21
         XauKOtA0FqJj9mO2IZUGAGRzSBAou4CKfT97Te1L+Lp+vWYM40AqCT4KiQ2RGHYwfLv4
         6xLSbbgMhcCHYqjX8uOwuUhBIoCzcedh1gVx4pwx30CQ+xGjXW/5nAb4bhm7P++9ygo1
         YcOKKgK8QMHwMRnPBRaO6DpgB0+SIfdkN/bq3WksaDtLpNZKt1zJXihc20ZxtacIMULe
         fExg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=EZSOK1AV;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4TvTk2n70RD2R+5ViVTKqct/1OCsJZufBpKvFTJ5Puo=;
        b=R8HBtI2OW6DesL/mg/RklmKl34HDkRP2w9h+vd5LqETzw5wL/+ASmTS73yRhtGQoR9
         A2zXraZOVNUHlVwe8rDuMzndGyd+1fhsoYxA+icFPHtY6yZVN3UCRvYqic5gDgyis8qM
         lBflTzXdAeiZggTyakH49gxXXxHGp/YTEKvXSM3ugqun271K2a8cT6l/RXubMuqZH5sM
         7aeyKiGT301oqSETUIUYjrlhv386FqunqJ5eOuVTfrKKfKVcmlrTTiAnKJrqMb5/52uv
         oqlozTyma8NGnbNQ7VKIUUcxAzv9tUfIjLsS0fRENERExQSvNe97DP50cu8IiT076cKk
         zzkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4TvTk2n70RD2R+5ViVTKqct/1OCsJZufBpKvFTJ5Puo=;
        b=oqd0Cqm/VdYtt33t3pkoSvuViOM3dA6+kKk8yGCGDQBU5VOShkkzXxZxFB3Sbc+Ayj
         BoNGj1qcEx2RCDPCmygD4+Db7A7mjN1f57RB82GJMiuemxbZKQMin+wTas0YC+pnHBMp
         avPkLTJA8ShiDjL6nUv6pMs+tv5aIiVMbg9aOOCb1cugxa4HDp9Bs7vTQSm9XoiqZUDt
         ctAPU5nm+K6JL6K3qsDdpvze6nqFqgLSK1mXHax4NLQfV+vcjsOazbVcmWE49fAzGpeT
         j902Fv4023LgLThFqkvc4JAf5sD/4dLzwhlPcXqw4lyGZP8FN0rLJpFkwsToaPEmjpsI
         Imrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XwUNw1tsy8Kt6Lp5kzsElZnEHVi9DB0nyDKUljNFOdPcUDIHR
	PHEX6/4ibk3dUPkEs7DD3vI=
X-Google-Smtp-Source: ABdhPJwjmD6MJEw3K4FwVJTP2WOnl6u0mK1/n4nn2pzXgGip3AyALUMgWY4ugWJUPApIDEnFuPMXzw==
X-Received: by 2002:a5d:4ccc:: with SMTP id c12mr43087695wrt.453.1638787883247;
        Mon, 06 Dec 2021 02:51:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls334089wrp.1.gmail; Mon, 06 Dec
 2021 02:51:22 -0800 (PST)
X-Received: by 2002:a5d:668d:: with SMTP id l13mr41863100wru.526.1638787882425;
        Mon, 06 Dec 2021 02:51:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787882; cv=none;
        d=google.com; s=arc-20160816;
        b=YZRVjMRlOld78VF4OLpe9OZjMEh+k1sDi5LygmebYW9cS2BrkH3DWhxcLjahN4HhmX
         X105dWMlQunkACX7Xp4LpNMkeKACyz+soIBP/l6aOGj4ZrxCScrebUdgXyeeOMRsoxIu
         aQ5JOUPH1FN7qhBVrOGcHUNAOJVwGHMySnTIcYC+GBItGs678b69ijUAeZHEGqPgM8g3
         khkaGd5++A85P5d540DluKAEvGqr6twBCs5IbJifdQewllKJa8KQ0hSoxzdnHxqEN8/t
         auRf2om3ajojaxLNXT8kOBeD8vzSPfBgsFuuJa0SzUW4VJ8MW/zJNDG0f/khXWUBvnTk
         qnqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RhDgG2MxbU+/Y0zOamju9twdysjbp89/nSRpYLjOzDo=;
        b=tx/5Ph1r/omAe7hgaUk6Af4E12OfBmMZ7xC+2C67w+Wgcvn309Yv2kZqXgjjxkOSST
         lH2DqUDqZiR1TCcfTgPNb0XdcbkrHZJ+6NUlckiiQgB2C0kPm1SgPeqQYzDbZ3JvNMZk
         Oq8zqYI5NM5lwurCFIHfCEFrRygSXEdMLRK8mfEPDAkIfWfR6L8mGrOlV4kRne2Zn0GP
         /ohq7ZNUOLimKNIa0MpStm8QuI/HD9ImDct4UFlNRPnShb4JLE/wwo9N3EJO96frGlTp
         dJdZ/ESB9uk4WkFjZhWINguA8xUB6levcLAInPDvNboPLdsGjAnB8MDjzcfdduxaMjSZ
         j4rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=EZSOK1AV;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id q74si927332wme.0.2021.12.06.02.51.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:51:22 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com [209.85.128.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 08A3B3F1F7
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:51:22 +0000 (UTC)
Received: by mail-wm1-f72.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03aso7664105wme.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:51:22 -0800 (PST)
X-Received: by 2002:a1c:a503:: with SMTP id o3mr38875023wme.98.1638787881589;
        Mon, 06 Dec 2021 02:51:21 -0800 (PST)
X-Received: by 2002:a1c:a503:: with SMTP id o3mr38874988wme.98.1638787881428;
        Mon, 06 Dec 2021 02:51:21 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id d2sm13816061wmb.24.2021.12.06.02.51.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:51:21 -0800 (PST)
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
Subject: [PATCH v3 04/13] riscv: Allow to dynamically define VA_BITS
Date: Mon,  6 Dec 2021 11:46:48 +0100
Message-Id: <20211206104657.433304-5-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=EZSOK1AV;       spf=pass
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

With 4-level page table folding at runtime, we don't know at compile time
the size of the virtual address space so we must set VA_BITS dynamically
so that sparsemem reserves the right amount of memory for struct pages.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/Kconfig                 | 10 ----------
 arch/riscv/include/asm/kasan.h     |  2 +-
 arch/riscv/include/asm/pgtable.h   | 10 ++++++++--
 arch/riscv/include/asm/sparsemem.h |  6 +++++-
 4 files changed, 14 insertions(+), 14 deletions(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 6cd98ade5ebc..c3a167eea011 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -146,16 +146,6 @@ config MMU
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
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index 2788e2c46609..743e6ff57996 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -27,7 +27,7 @@
  */
 #define KASAN_SHADOW_SCALE_SHIFT	3
 
-#define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
+#define KASAN_SHADOW_SIZE	(UL(1) << ((VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
 #define KASAN_SHADOW_START	(KASAN_SHADOW_END - KASAN_SHADOW_SIZE)
 #define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index d34f3a7a9701..e1a52e22ad7e 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -50,8 +50,14 @@
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
@@ -653,7 +659,7 @@ static inline pmd_t pmdp_establish(struct vm_area_struct *vma,
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
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-5-alexandre.ghiti%40canonical.com.
