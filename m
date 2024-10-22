Return-Path: <kasan-dev+bncBCMIFTP47IJBBAEO3S4AMGQE5ZBS7DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D04FD9A95CF
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:34 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-7ea8baba60dsf4842238a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562369; cv=pass;
        d=google.com; s=arc-20240605;
        b=ERuOI1KOHtE07NV0sq06PSKhIdNeVgzoCDxV18O/TEXUYS4dCR4IKaYQoJ04fwQ5UU
         cftf578oSC2BOX/QB1G4WKEp0CnU1kxfRPcUPxU8eNczUd/zjuUCd60AAMZEAgbJq+n8
         dvEFiaNmtJecrudcjU8ZmVAWFcREe5zmETfUy+OuBkzCeFCdeWp+INNUQTRi/3Ra4bAv
         6yj2YyQtfpjX+UADVu0F9Iycrb+4zfWoGmBItL1JQzLglv+Vldafrf/gb/7td0A9252y
         8zvnfcZkCj7N22mh8BnjkvrgMzo4yxDxWNiU5T5WA1TCDvdCvHm7+T5K92f5sygYqcJl
         I1pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=9JDLxX5N1zbxkH2pifjW775km7yyPzSe/EM/AOH5ZlI=;
        fh=0oMOi3y2jKcy3h/WG2DUW9Eh9/jz5sH9RiqqYzIa0pA=;
        b=hyq2xSCAcWs8xtsnSRjxXlURUaTwLEorErYYNW+rfhxsUPGnptFN2nESPdgjs/bumS
         tkVoD8vXn+p64OLVVybqDclsDVL3w8lrZ+uQ5Wx3U0fhJ8jZj1K/Ezuq/EshFmnM/y52
         jT3d2+WtKFJK5g5MjTkMnDf9FuzmuAjBZAXua3Px1AO2udeCVocJYM1w1d1tVKRdXF3v
         P9L1l5Fk/FVC7jiNgx7UlLScaAot5ehyRr41gd8ooOidxw4u6upBk8hrtQrFH+hpQMFI
         U3QKc4PKYomYOqoLp/gpNdwki5nnw2LMJ3sh8lc9qT0iRaAMOUhvS6jmcbFtGhFIGH0a
         vsmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=TJ46eRZF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::33 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562369; x=1730167169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9JDLxX5N1zbxkH2pifjW775km7yyPzSe/EM/AOH5ZlI=;
        b=pL0XAwg+BmYYJRH2u1zbuQx8CozwyHILiyFrd4EXqlRhBQfxF0wB0ewrxkm1q2Qhr/
         ZldHMUoCSVsUS9VPtEAM4bctPWZxQAIOYGoN7JH7IXo9D2O7hivOyREy52K6S5uK0Lf0
         3T8L6l1thDd4xwIFOBWj6sjI1Jhx5qp6ioBthybsZPaK6DKzwo+UAw2wYNguJcFfrbuQ
         deqJy/9m/JbETKNLktmjBhsLcFBe4AFoUN5Z8/u13yshI54s0O6ZVj0KgD4TaP75+tue
         OnaZnlgDVFqaYfw45d2EMd/3PvDahfBXPGhzr8L/OcTGxbZSUHoUZFJPWLMufvN9gIB1
         Kx/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562369; x=1730167169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9JDLxX5N1zbxkH2pifjW775km7yyPzSe/EM/AOH5ZlI=;
        b=fSI48yywozlz8eSi6+c4iNO6ivQ6KRG1LCpFOyqrYUbx7iV82NSpJEuQaoEKrudhZc
         JyVAJV5oIlQsDO+l4Xotufypsf3FX2JMp8KGoZnzhhqkxrziJQ0dRbJHuQxdxKpzNmuO
         7RJcGCTLGkQP03vIgtwmBnEiIwqL9ydB2YQUIhjvgZQooJbzWfI9SPinNFLPycNjxn6a
         qllyVEwpU8s+Lx7VzZQnN2eE+eVoVju0PvsZbc8REK19hX0dhfWTUhFMBx+f4jEz7bjj
         Vnw58qv5wCNMP92/aO4npQC7ZNZMIRfz6TdENCXGV7ZsMvAr/yIR98AndDTZSIG8YcCE
         meKA==
X-Forwarded-Encrypted: i=2; AJvYcCXWOv5FqrOUlsrhqJ5kikfw690yDh/TuAnRlmaXYL4ryr9X3cfOVBCZzAjM2VA7bU41MYvUxA==@lfdr.de
X-Gm-Message-State: AOJu0YzHzFjM7EKdQVC9bXBQ5aLTJva2DreJYaTPADpRTq7BkQIT8ct4
	YLL+R+e8Uxjzndi1UbiTcxppImjh+45Q4fNaHPps1zgesbon2nIy
X-Google-Smtp-Source: AGHT+IEUJRayf6kGU0pzQPiMq7aOUQuAfky4ee+sL4TUmehJQeZHwvk2EWO1oK6na30490I4akJHUA==
X-Received: by 2002:a05:6a20:e347:b0:1c6:fb66:cfe with SMTP id adf61e73a8af0-1d96decda3fmr1001221637.21.1729562368882;
        Mon, 21 Oct 2024 18:59:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6347:b0:2e2:94c0:4490 with SMTP id
 98e67ed59e1d1-2e3dbf35789ls3280364a91.0.-pod-prod-02-us; Mon, 21 Oct 2024
 18:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVL8TNx3qgFWzkyblvICHVvGVyFZCdvgdu+tQrB2T4LO4oBW2PBPFkwh/1qiv/JXK0cVEhSCnGQ+gI=@googlegroups.com
X-Received: by 2002:a17:90a:cf96:b0:2e2:b21b:2247 with SMTP id 98e67ed59e1d1-2e5ddc5c50bmr1172432a91.27.1729562367675;
        Mon, 21 Oct 2024 18:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562367; cv=none;
        d=google.com; s=arc-20240605;
        b=cNxh3GXoieTgmd+tczsMODGSbulL9O3AJBNePObrYLorSpbZOU1wPq46ef8HuYw3TU
         O+W+aR5xHHyD2wrR35hs9MyPzX1yH3osGITquahM8GXuUCW4AKP0CAaeGqROQJE6F9YU
         qIXx/f7k2St+wdvaUu3zTxyzlRbhQqtQzlPsY3Ft9Y9rwJtqipZdTaXG989xq4Sn/AR1
         FWroD5sQaXhLdvFFIWzlYSRItBWZyf5vXZ5qFNrIazTG+hy/lV5AlSnbr5zRWIfcYBXu
         uyrANCmf5+g5konGi1HnPD9KDW+2zIxSAAF+4F7QK9Gp/hg2ikoA3VwAa9uLHM4mzoyS
         5KaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jOWNg37CI6wBNjlK3WTwIizp4MumcxiO1pDVtn3VcZ8=;
        fh=OasN8Sntql1dmOTvPoMdRdk4rXuL0hyA4VYhSKVmzh0=;
        b=iML4yUXh2hUl3KerW1Veyc+m/WWEPtl9tw6VA57gkYCBRpqldyr4lXbrovSiau55Zj
         L8HiAAly/V1dy9Y8QwO6PKHrpxnRhr0I5ZyqaKQk4f8K29vdZVd0n1sZ0ZEOJPdCsto3
         B52sKaJ0w4pB2UXozetd9oyPCxotxXIt75EXcfjMygj0GSLCgLOC6BIrWHb0XtZuzPK0
         iGbZrYNxafSgVObte9IDCmCc97odsRnjLCqtgppzhxQKe+IHTTFTE2oMCL603cjn7tBR
         gZ1zjgQOFQ+aqn1EGZ+u5uIGBThZzgVQ3v/5b++oAetuZuewwUKDIz8OL2rpVW0Ac2CL
         gOiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=TJ46eRZF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::33 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x33.google.com (mail-oa1-x33.google.com. [2001:4860:4864:20::33])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e5df41105fsi27345a91.0.2024.10.21.18.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::33 as permitted sender) client-ip=2001:4860:4864:20::33;
Received: by mail-oa1-x33.google.com with SMTP id 586e51a60fabf-2884910c846so2507664fac.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWws07/RkQPZ89qlrv2CRsiPAtimjiftTmxeaWtKamuBmjRMJ1DRuAsSGs3RqFc2bIRG3o/Iu5EI2c=@googlegroups.com
X-Received: by 2002:a05:6871:109:b0:288:b220:a57e with SMTP id 586e51a60fabf-28cb0184ff2mr946194fac.40.1729562366823;
        Mon, 21 Oct 2024 18:59:26 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:26 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 6/9] riscv: Do not rely on KASAN to define the memory layout
Date: Mon, 21 Oct 2024 18:57:14 -0700
Message-ID: <20241022015913.3524425-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=TJ46eRZF;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2001:4860:4864:20::33 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Commit 66673099f734 ("riscv: mm: Pre-allocate vmemmap/direct map/kasan
PGD entries") used the start of the KASAN shadow memory region to
represent the end of the linear map, since the two memory regions were
immediately adjacent. This is no longer the case for Sv39; commit
5c8405d763dc ("riscv: Extend sv39 linear mapping max size to 128G")
introduced a 4 GiB hole between the regions. Introducing KASAN_SW_TAGS
will cut the size of the shadow memory region in half, creating an even
larger hole.

Avoid wasting PGD entries on this hole by using the size of the linear
map (KERN_VIRT_SIZE) to compute PAGE_END.

Since KASAN_SHADOW_START/KASAN_SHADOW_END are used inside an IS_ENABLED
block, it's not possible to completely hide the constants when KASAN is
disabled, so provide dummy definitions for that case.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v1)

 arch/riscv/include/asm/kasan.h | 11 +++++++++--
 arch/riscv/mm/init.c           |  2 +-
 2 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index e6a0071bdb56..a4e92ce9fa31 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -6,6 +6,8 @@
 
 #ifndef __ASSEMBLY__
 
+#ifdef CONFIG_KASAN
+
 /*
  * The following comment was copied from arm64:
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
@@ -33,13 +35,18 @@
 #define KASAN_SHADOW_START	((KASAN_SHADOW_END - KASAN_SHADOW_SIZE) & PGDIR_MASK)
 #define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
 
-#ifdef CONFIG_KASAN
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
 void kasan_init(void);
 asmlinkage void kasan_early_init(void);
 void kasan_swapper_init(void);
 
-#endif
+#else /* CONFIG_KASAN */
+
+#define KASAN_SHADOW_START	MODULES_LOWEST_VADDR
+#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
+
+#endif /* CONFIG_KASAN */
+
 #endif
 #endif /* __ASM_KASAN_H */
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 0e8c20adcd98..1f9bb95c2169 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -1494,7 +1494,7 @@ static void __init preallocate_pgd_pages_range(unsigned long start, unsigned lon
 	panic("Failed to pre-allocate %s pages for %s area\n", lvl, area);
 }
 
-#define PAGE_END KASAN_SHADOW_START
+#define PAGE_END (PAGE_OFFSET + KERN_VIRT_SIZE)
 
 void __init pgtable_cache_init(void)
 {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-7-samuel.holland%40sifive.com.
