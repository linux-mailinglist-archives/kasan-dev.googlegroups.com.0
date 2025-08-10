Return-Path: <kasan-dev+bncBDAOJ6534YNBBZVO4LCAMGQEGCJEM2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A4E22B1FA08
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 14:58:15 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-459d665a87asf27286435e9.1
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 05:58:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754830695; cv=pass;
        d=google.com; s=arc-20240605;
        b=J79IMJZephP3VvKkT+qNqpFXvtX2NTNjBgmjQ8goJ8Cvtj84SiCizG/tP9BPcWUHYT
         Iyvn7Hbu38PZXvjPzLP9zaN3LMfnznagE88WtZ135vAuLRNgzcUpmf6vtg4nUaX5OWZn
         D/EDJR4XqEjV4RuAsxu4D3AmznZOR0mfG+nB4PA3tH/67Is5Y5fQ5Mb6ab284k1YaeO3
         2sF/X+4cxb9XO1l+FqW1Eu637ayFZmHH8QSSTkGduq87YYgPdGqTChu05r2VcaVgvwlX
         Y+wF71scmBg14V8VB7tG0ddvMI22k6lh64PdXTybFsum6USQOiZFcLtPTsr/v6Bc5qJ2
         +kzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=QX5/6XCljXR8x+SpWGXHMLoCxFBCVwqmeF7Ku2r4XMI=;
        fh=9ns/uesmwNDo+oOyerw8nsw/7Si4GEXnqE44wJU/zPo=;
        b=P0Fjpl6nSFNxyXLq/m7yqQ2RGlN6g/E7li/5jWfZNV5j3ls2IzYvsxVu8A6HnX9GJS
         PmCUHli8l4XuuHeRRd+dQ+zxik6l7lsyfJ2SaEaialCnmcs31FmVqrbHSzLQHROnH71r
         6C7QibcHkqbBi1FmusS1lQJhjeLuawL8Bc0WCLJ6nbIZrJLXUXwp7nZlkAetsAiVObdG
         yaHYGfB6VhpjiKYgrIyLZrdIUsmZrcW6T58z2ge7wTuDdN20ZTKNVhzSD1qNxOwLLEE8
         Ug2+Z+OVatGN5EvQbL3MCPyt5U3Wh27xiX146iPhApUCRcNayjkSL7l0aBjPaAfi8t3I
         gTRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OC8G6hk3;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754830695; x=1755435495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QX5/6XCljXR8x+SpWGXHMLoCxFBCVwqmeF7Ku2r4XMI=;
        b=Js4A+EsdVYMHtZJFL5rHnSuJ3zOwaSQnCImB0dA+4VHVoS9rOoqBqH+zkrDdR5S+LI
         BDVF7R65NI9iuwxpjzOvdqjiOZUD+8pLXhmTAa357GP8SwHyV8sIxfSdHSCRI/8oVFpb
         OsKBM/NfBudKtDrTitT1zGUbT01QwYOlPbqaNJbRH6hu4VQEPWt8Uru/u7yyw2cm3G9p
         1SGKrcl2MWJW4lFnMA1AoDnAKEhChsUR3Dtb9VkfkAts7LHz4ympOQnmZdIEyMTIokyK
         Dj8N4uXfVYMxEwCJcP8miD4lXzWodPMehAhHdiNOrgWRBWaJPnnrsP2tMsfH0OK4sN9V
         IDmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754830695; x=1755435495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=QX5/6XCljXR8x+SpWGXHMLoCxFBCVwqmeF7Ku2r4XMI=;
        b=R25EymDY7oLS9Qy+50T17tvql8hHlyKTIlc4jxRK7zz5WRpbEH3I4RcDosLmfkDPRG
         A3UWabjuAzv4yNkxLGXRv0upzt1cmuG0XR1CANKxkEIISL4VXDvG0ieG9z4BE1Oma2/K
         4bohr6LrrfvWPTbRewQYEMKmkcvhM2rVZSSQGRVi47QEn0OcfV7+wO05pRcG3vWWs4B5
         95oMuZw686uHk54N9LWNzKDj7A5FKppDSnNXjRfY9kVlJPccilzjWSxIUjBEtvT1MVKl
         JtGqO6JtREqOG+eQEpRER+DXETvaiy67TmsPK25KqaQwDo3HTGd6vyxb7rBB4/ElQkti
         fT+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754830695; x=1755435495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QX5/6XCljXR8x+SpWGXHMLoCxFBCVwqmeF7Ku2r4XMI=;
        b=nnLdpMFZqQgvhaXF/yJrR5OggSiq4s8CUlcO/BgMrufFqO+M5gYYAgXw9W4167lKZM
         NRvIsippvyyuCJUTppszqaG4hzGzQ0as8VeA+wCz1fTATAEYXfkuFBrLIytqxufvzJEQ
         tOHwuduTmd0RBb/esf2FstgmAtaxhjUWZ6CvzFMGcZ5i0Q02u+nfp61MT673IeFOMGyZ
         PeAYrHzSBAuS0Nz8Vsc8gN3qpPSFMpk5JCFMMDWmJo2bZiyaI4wDiyuTQAr/jw5uxiij
         HvRPyKZyEVVpzzdX5jKV+ke3DF1MvJ2NamuyHO/3sHiO8Iu6RrWLWswYdqiZ0MsivnQf
         gqeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW36O3QFhRmZFIDpCmSq77E+WvuthGGB9i1mO9N3OyqoQ7DrknBtdQe9KPB1TutefP9j6tu9Q==@lfdr.de
X-Gm-Message-State: AOJu0YzzijBJL0aIBnC4Btl07/Oh4fOUV9rg9qkTWSPzwGR0SnkKTMDW
	zKG/dvFQYHM3y/vCrufk4nMqucPQWUZdPX7iHSJ6+vk6ldd3KP6LZFwj
X-Google-Smtp-Source: AGHT+IFt6cd6zuf0B1NbF5KTCtpLN22Oxl7SEzwbdvpJco51Z/UBWnIaBmpbjnlWu0RDgQ/A+NgCQg==
X-Received: by 2002:a05:600c:358a:b0:456:1ac8:cac8 with SMTP id 5b1f17b1804b1-459f4ec638cmr95663835e9.15.1754830694869;
        Sun, 10 Aug 2025 05:58:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhJksgk2vAtgitq6M1kleJDcWsxO6Pke0tYE5IayhouA==
Received: by 2002:a05:600c:3f1a:b0:459:d92a:8496 with SMTP id
 5b1f17b1804b1-459edc3ad49ls18686705e9.0.-pod-prod-07-eu; Sun, 10 Aug 2025
 05:58:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4b98Ovji4J4O37mSLEMzvcys8Yxr0uWEvZJJuwRi6/aJNlwIvQGOHlSwqvoO6ZRz/Fqf+Fc8tqCs=@googlegroups.com
X-Received: by 2002:a5d:5d0d:0:b0:3b8:f8d0:f75c with SMTP id ffacd0b85a97d-3b900b7376amr8407988f8f.35.1754830692337;
        Sun, 10 Aug 2025 05:58:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754830692; cv=none;
        d=google.com; s=arc-20240605;
        b=HVs5COkin7w6cBmvxhvhHInmzJq8WiSsC94hvGKmEYMDLsMtU4RbOM7DC+sWRmGoDC
         3mWMoVqo6TNoscqrLq3z2r9DYxy37wsMTPidgeJNQg+cL2nUW6AqFnAo+2+k+dC4P+ax
         6jHbS9HRelRl0KYU3konR+APz31/8Z73ThhBNBkWLxkyCNfv1rJtFEHnTBet/4kr0Kej
         geH7brlIDxJUdA4nLBARwztjEtUmnyAa3Q09uPFo2GpfhgLIWCUlznyl79pUNQzvF8h1
         ZrPnaHJhNiLj4xY7lFzWbTME2GMoor9B5QA7yx7SyRDLYhYWE38CZewyRH4kuahQ5SPi
         7igw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qPUEdIdCRmt+MYJsQtBbxjY1GnPuX9CU1RwbVybqcDU=;
        fh=vu4HnItXWVgieob/NRR7nbwFwqvEmEzgmfauTcdZXTo=;
        b=ieMwWUU+xuhjNKyexmcURnhjRDtsoefjeUONM0d+oRYfq1R7yC6lgAqfsZzJlVqGak
         cnAj99dOkWR//DvtvxWwKCRYccnP+Y6uY8VLsUa8DRRtoUxbsfhoZOzU1SwOVpytesfx
         3m3o2Mf1XYd0UMtM9o0zfpl9//gktiD8oGBN1C0mpwAmIsXNzAA7t9j6SfDktbadYCWg
         icXEE1tiRpTlFuFa9qELxtd4uNxCMXG3pe7fkg6WzugP3EoTFbqk0TnYcdQP4YYasPW3
         Ns2rMPUJehu5yV+/PCXENLZgueJzWo2NnaZ9w2KFMC/47m8th+t/HEDqVhOgRN0i6eAF
         JTQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OC8G6hk3;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458b77e7c15si5211175e9.2.2025.08.10.05.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Aug 2025 05:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-3323b99094fso30324311fa.0
        for <kasan-dev@googlegroups.com>; Sun, 10 Aug 2025 05:58:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU26Z89sndjNoaoZ/Trf/iFB5/ToKlM1BZUP/ixFUiaBuN0Kmy7LqwVgXxjbDKl8Ojq3bqRy8tkvak=@googlegroups.com
X-Gm-Gg: ASbGncuwygnSfd2ueJ1I/kjIeyRx1wniSQmX+0GAWS9/mum0Qh7u2IySaHKQfOFz/ru
	Z3uZKAJbWog28OQyUpHPERQ5zmbbu/vQPLdyxC5m4v1wbntufVVXulhnQbGdg/3s7N+wpYLH5fH
	lheDQNOOi3IT3L2Kyw95Isw82sm9ybFXm/BF9HbC2HxAn/I1PRuuwvHrn/5N2wEaWSXQmp6ZI0c
	zZYGVyR6ipk5whgWwZVxMDLCk46TJEtiVfs18Bv0Np+WhqrrYfbDWYGWGZ3wZ4AiHBgQVtz/yye
	kBlXqrhBzOZw2gWHPcGWZRZi/6rqj30+2jWcVkDKsU3uBCWppOjxHkVLwPnvWLcxPKUIlgNuC1f
	nHXWMkUeRxTzo06tzVVcsW4xw2skt1HXT1hwDYQ==
X-Received: by 2002:a05:6512:3502:b0:55b:732d:931 with SMTP id 2adb3069b0e04-55cc00b14c8mr2560689e87.12.1754830691289;
        Sun, 10 Aug 2025 05:58:11 -0700 (PDT)
Received: from localhost.localdomain ([2a03:32c0:2e:37dd:bfc4:9fdc:ddc6:5962])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b88c9908esm3804561e87.76.2025.08.10.05.58.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 05:58:10 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	christophe.leroy@csgroup.eu,
	bhe@redhat.com,
	hca@linux.ibm.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	davidgow@google.com,
	glider@google.com,
	dvyukov@google.com,
	alexghiti@rivosinc.com
Cc: alex@ghiti.fr,
	agordeev@linux.ibm.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v6 2/2] kasan: call kasan_init_generic in kasan_init
Date: Sun, 10 Aug 2025 17:57:46 +0500
Message-Id: <20250810125746.1105476-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250810125746.1105476-1-snovitoll@gmail.com>
References: <20250810125746.1105476-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OC8G6hk3;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization.
For architectures that do not select ARCH_DEFER_KASAN,
this will be a no-op for the runtime flag but will
print the initialization banner.

For SW_TAGS and HW_TAGS modes, their respective init functions will
handle the flag enabling, if they are enabled/implemented.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com> # riscv
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390
---
Changes in v6:
- Call kasan_init_generic() in arch/riscv _after_ local_flush_tlb_all()
---
 arch/arm/mm/kasan_init.c    | 2 +-
 arch/arm64/mm/kasan_init.c  | 4 +---
 arch/riscv/mm/kasan_init.c  | 1 +
 arch/s390/kernel/early.c    | 3 ++-
 arch/x86/mm/kasan_init_64.c | 2 +-
 arch/xtensa/mm/kasan_init.c | 2 +-
 6 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f703136..c6625e808bf8 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -300,6 +300,6 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
-	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 }
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45daeb..abeb81bf6ebd 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -399,14 +399,12 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
-#if defined(CONFIG_KASAN_GENERIC)
+	kasan_init_generic();
 	/*
 	 * Generic KASAN is now fully initialized.
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
-	pr_info("KernelAddressSanitizer initialized (generic)\n");
-#endif
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca4..c4a2a9e5586e 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -533,4 +533,5 @@ void __init kasan_init(void)
 
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
+	kasan_init_generic();
 }
diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
index 9adfbdd377dc..544e5403dd91 100644
--- a/arch/s390/kernel/early.c
+++ b/arch/s390/kernel/early.c
@@ -21,6 +21,7 @@
 #include <linux/kernel.h>
 #include <asm/asm-extable.h>
 #include <linux/memblock.h>
+#include <linux/kasan.h>
 #include <asm/access-regs.h>
 #include <asm/asm-offsets.h>
 #include <asm/machine.h>
@@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
 {
 #ifdef CONFIG_KASAN
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 #endif
 }
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d216..998b6010d6d3 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -451,5 +451,5 @@ void __init kasan_init(void)
 	__flush_tlb_all();
 
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173a..0524b9ed5e63 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -94,5 +94,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250810125746.1105476-3-snovitoll%40gmail.com.
