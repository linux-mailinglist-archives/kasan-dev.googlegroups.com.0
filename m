Return-Path: <kasan-dev+bncBDXY7I6V6AMRBBVB56YQMGQEQSZ536Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id E4B0B8C04CF
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:20:39 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2e32c301353sf537071fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196039; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJBO7a9wis3i7AfG7uxpDe6/jTbsE7dwBAVZA/qJnV7A8iWpD7jaH+Rn0t6T6VN1MC
         xHpdNJHDO2jcYYUxQ3tL49h1tJoUHT7eA9kreZXfhTAGMHb89Gv05Zfnq+g8Swfj9thl
         zGLK6KjSLQ8y/FqyAshjdTgkFpAPovgAkhFzOKXU02dHS0CQMFy/N657mp0crsxMWygL
         jZK4u5UmAx9/x1S++OtpzCMIqkWUd90yU3IcKL4HuiB5TSBuJPzGriTE6VhGiuHlUwbx
         pDhH6E+UuT/Q1JDv1kdVe1sIFJQ7JhtcDkkVawrZceDhe9vMzyYJXwFqEulMimeH8Jiz
         7RUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iRtXJjd2uUgSMkVqahcyCY2+q512gmLWiNQxZi0Z9MY=;
        fh=Ust4dyvJnxdEN5WNs4QUoYxo48fDZE6fVB6T24RI9x8=;
        b=0m2zY9UBGsKn2NDWyMQPZYlY+L/UHFT1T0YHwBAw4SLI6YP9bpN+5l1W1GEJUQOe5g
         da3psOVElfwfWRX/qGtC31YwvpEbWqoOk0I0w93s6iywC0vMfEfZDQkpMOS7yUjKdkkL
         bxgaCjojZDGZ/SVEWfBL0tRSOYRjt1qsd4fj6mQf7GgxhIAHgjXjf2MDLuhw5ZOWi49D
         VX2ZWHQyGf/KFSaieQ0rUWbZsl9s6AkJzQBjua1SnwqLpkDNkcAdlsnUQgpx7kJQqUqE
         4uEGd0BU1N5BW+678/FNPHsQDPJuA3Y5aw6lcrY9tTPk9kVCrLQ/GPTNOMem6m6LB9PF
         EKcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=kQFfEcBk;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196039; x=1715800839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iRtXJjd2uUgSMkVqahcyCY2+q512gmLWiNQxZi0Z9MY=;
        b=ZB8gNis4Z88DFIw7DvDuNastyBR4rvFTj8n/wz7xEhh3waeiYlGCUYrntsX6QFXbdU
         jtHxyvoN7nhfEG8St0o/4W8DPj+7XnMUpntQOYY9o0ofAwyTbWnMiw52OWKQvRKQNvyM
         dvhovrwU16s2oNQEb94tXbm77MjaNQRVAqp2+E6aq/lrZ9avNUrtRupAfFG7CGd8bObR
         jPu09pIaiGaDHeF3I0CTAlDoZoKkG09JeDCacsfMLAn0nHvS2kPth5iJXPcI46GKtbwx
         DHaf/M9WpTyr25JuDze9CecpZQXrO1FVL7Bo7VaHd6RdVaAdYAgwBMpKyywKrH+9k+p7
         Y/zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196039; x=1715800839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iRtXJjd2uUgSMkVqahcyCY2+q512gmLWiNQxZi0Z9MY=;
        b=Rw1dOIBqVihQTRDr+pFdpTd+hKMFQgm5KX89khw03dQ1sObaYKsIrjPlJESegHQfEB
         ryKlcO/VyGGwRB/YJvD7knIH8OjDSk8L5X41Zw7/AoR+fxXtESUZD3L8D3sci9jNLtz8
         bfhZUeOc+fVWK/8q3bIJxKdCkW69cqYTdCVLpyZgvTFVYcKJFDIqAlTMJvPGaxN3Ul+j
         N+YQF8cphpsQGFK5PkQMIjQZghJr6NluX7HLgoknkI3eUMtyTaeLLdxjTMtWBWL9F3pP
         gpUeLFcY/mgEJxkL+QfH25u2KZOloMIlXEbRC26JsLx0o3PbJ/LVGvTO/K5/NYnsgKsC
         DJfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSawYIRq5KtzOjrwAuo7AzBhxwo7bCWHzLF4epCdb+gJLpYkodyFFcjaW4Yn/MecQlGwa7FwZfc6TzXeItw6Kv/vMHHCRsSQ==
X-Gm-Message-State: AOJu0Yw4qf2iJRSGJvVMEEngootR2bw7ZTAkrMe/MVVSodllqEYtov4w
	x66W4nAXYg0DQgPbS6bJplC9lMOuWbSAiuEqLPObTQ7Ev+oobVuw
X-Google-Smtp-Source: AGHT+IFKn1Ik8Jpzi1Y9N1sGahrhC0EhCZbws7EDgQ6+4NWdl6dPea20eh7uI+xCiCcniPN9Djwy/w==
X-Received: by 2002:a2e:8906:0:b0:2e3:4f79:4d25 with SMTP id 38308e7fff4ca-2e446d82bb0mr21932901fa.3.1715196038454;
        Wed, 08 May 2024 12:20:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9007:0:b0:2e1:a117:3c01 with SMTP id 38308e7fff4ca-2e4b57209a3ls426411fa.0.-pod-prod-06-eu;
 Wed, 08 May 2024 12:20:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3Hl0BXrQlzRUeX/npW3p4RKD+c2YCSj6mkd3MOdVzD/0cO7qc6Rp2I7A+uc8Og1RLmLcnmhY9GnWMCDDX+0PpA2wY3xywaapt1g==
X-Received: by 2002:a2e:9f17:0:b0:2d8:da4c:5909 with SMTP id 38308e7fff4ca-2e4477b34demr20025751fa.51.1715196035268;
        Wed, 08 May 2024 12:20:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196035; cv=none;
        d=google.com; s=arc-20160816;
        b=O08t7B/CcgbSeCq41h8gh7XD3Ab3+J1phJrHPTGpIGNcehtf7K1I8vQIuwemdwtKfF
         1Pixzm2ylRA6ZvjPd+iEC7l3b310vRbzoI2mxu6S2htxFaylPNtNNVx//W1LN+4IP55d
         p3qvjqCuQk6KUuTWa52JnIzgQCNrWf6BDXP89ebRaQ8oVCQGcY00dluyHtJH6vkKdWAi
         chN+w1dHCuulcV7FALoiT2np/KPdwKosWgAJkpTUd+fRJYvnyvJLVKaNbpvC4qwwAlWO
         gDskp1TIrgnO20dGvUUqBKhdEjJU3voZqgvihENDZdne6HwhSIFTHLdOXYdVAcwMJReF
         x/Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=datyv3e5LLeWOM64wvZ1mfI1WId3P2rVazcirFn2Oxk=;
        fh=t7SQ89y2tKLdXtCxXRbxbFaUehPrCnCxDOrziWIF3Yc=;
        b=JXiP0Z9WlQ3mu1kpleedipT57V7jlt6GgZ8/Fz5iQ/8yksmbpwcSEg4NGhD0bRnysh
         j1lqU+WjuUqqCPB2cuRBC3lx+FWEfCoknGuFAIpgYiLB30j2M8erROd0f5puAljXtV+k
         sbxgwhLn2k3RTohjJcRjisOpYH7q0vXPPwnrnRg48QM2JnibgCz4htERpqj8lnnpmvbM
         UVGMu5Na41itOoUTP1eTiHaaaise8JvauHKfkCqZkcfL7YRcgnBdjoGmYZedZ5O8r5Ph
         +h1gkzHZX4O/6HM3hjnf9vsL9TpXL520aUtmXCY2d7CZl/w7AzjTgfAdv426oABhY9lv
         Mkcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=kQFfEcBk;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id q23-20020a05600c331700b00418fd26d618si68941wmp.1.2024.05.08.12.20.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:20:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-a5a13921661so16680266b.2
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:20:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWDXCewcC4UZEj5/DE7z6oKwxr8H5q+6/QKQv4kqzqaRNANPVL2mMvZZJlQHcJK6mWl4hhm6jytbcFZjXr5B4B+AAZZ0In9H1i2Iw==
X-Received: by 2002:a50:ab59:0:b0:570:3b8:a990 with SMTP id 4fb4d7f45d1cf-5731da6977emr2508293a12.39.1715196034646;
        Wed, 08 May 2024 12:20:34 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id g17-20020a056402091100b00571bbaa1c45sm7881992edz.1.2024.05.08.12.20.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:20:34 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Ard Biesheuvel <ardb@kernel.org>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 01/12] mm, arm64: Rename ARM64_CONTPTE to THP_CONTPTE
Date: Wed,  8 May 2024 21:19:20 +0200
Message-Id: <20240508191931.46060-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=kQFfEcBk;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The ARM64_CONTPTE config represents the capability to transparently use
contpte mappings for THP userspace mappings, which will be implemented
in the next commits for riscv, so make this config more generic and move
it to mm.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/Kconfig               | 9 ---------
 arch/arm64/include/asm/pgtable.h | 6 +++---
 arch/arm64/mm/Makefile           | 2 +-
 mm/Kconfig                       | 9 +++++++++
 4 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index ac2f6d906cc3..9d823015b4e5 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -2227,15 +2227,6 @@ config UNWIND_PATCH_PAC_INTO_SCS
 	select UNWIND_TABLES
 	select DYNAMIC_SCS
 
-config ARM64_CONTPTE
-	bool "Contiguous PTE mappings for user memory" if EXPERT
-	depends on TRANSPARENT_HUGEPAGE
-	default y
-	help
-	  When enabled, user mappings are configured using the PTE contiguous
-	  bit, for any mappings that meet the size and alignment requirements.
-	  This reduces TLB pressure and improves performance.
-
 endmenu # "Kernel Features"
 
 menu "Boot options"
diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 7c2938cb70b9..1758ce71fae9 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1369,7 +1369,7 @@ extern void ptep_modify_prot_commit(struct vm_area_struct *vma,
 				    unsigned long addr, pte_t *ptep,
 				    pte_t old_pte, pte_t new_pte);
 
-#ifdef CONFIG_ARM64_CONTPTE
+#ifdef CONFIG_THP_CONTPTE
 
 /*
  * The contpte APIs are used to transparently manage the contiguous bit in ptes
@@ -1622,7 +1622,7 @@ static inline int ptep_set_access_flags(struct vm_area_struct *vma,
 	return contpte_ptep_set_access_flags(vma, addr, ptep, entry, dirty);
 }
 
-#else /* CONFIG_ARM64_CONTPTE */
+#else /* CONFIG_THP_CONTPTE */
 
 #define ptep_get				__ptep_get
 #define set_pte					__set_pte
@@ -1642,7 +1642,7 @@ static inline int ptep_set_access_flags(struct vm_area_struct *vma,
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags			__ptep_set_access_flags
 
-#endif /* CONFIG_ARM64_CONTPTE */
+#endif /* CONFIG_THP_CONTPTE */
 
 int find_num_contig(struct mm_struct *mm, unsigned long addr,
 		    pte_t *ptep, size_t *pgsize);
diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
index 60454256945b..52a1b2082627 100644
--- a/arch/arm64/mm/Makefile
+++ b/arch/arm64/mm/Makefile
@@ -3,7 +3,7 @@ obj-y				:= dma-mapping.o extable.o fault.o init.o \
 				   cache.o copypage.o flush.o \
 				   ioremap.o mmap.o pgd.o mmu.o \
 				   context.o proc.o pageattr.o fixmap.o
-obj-$(CONFIG_ARM64_CONTPTE)	+= contpte.o
+obj-$(CONFIG_THP_CONTPTE)	+= contpte.o
 obj-$(CONFIG_HUGETLB_PAGE)	+= hugetlbpage.o
 obj-$(CONFIG_PTDUMP_CORE)	+= ptdump.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
diff --git a/mm/Kconfig b/mm/Kconfig
index c325003d6552..fd4de221a1c6 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -984,6 +984,15 @@ config ARCH_HAS_CACHE_LINE_SIZE
 config ARCH_HAS_CONTPTE
 	bool
 
+config THP_CONTPTE
+	bool "Contiguous PTE mappings for user memory" if EXPERT
+	depends on ARCH_HAS_CONTPTE && TRANSPARENT_HUGEPAGE
+	default y
+	help
+	  When enabled, user mappings are configured using the PTE contiguous
+	  bit, for any mappings that meet the size and alignment requirements.
+	  This reduces TLB pressure and improves performance.
+
 config ARCH_HAS_CURRENT_STACK_POINTER
 	bool
 	help
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-2-alexghiti%40rivosinc.com.
