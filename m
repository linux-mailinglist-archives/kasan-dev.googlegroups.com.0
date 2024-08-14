Return-Path: <kasan-dev+bncBCMIFTP47IJBB6OO6G2QMGQEYPSVPOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F401395164B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:50 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6b7917c2b69sf76991986d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623289; cv=pass;
        d=google.com; s=arc-20160816;
        b=IDQg0BWBA/MF7oUTW3mqZe3+7/qOF7CdxPqI1vx7O5Lof/JriihTjH0tKcW/v8t3FX
         2wmLKzKP4qLO5d0n452K8rCPlvb1zHfkVzgLn1uQBY3eP7vl151wp44G+mfKnJm5tWFG
         zmRGlvdrTCjD0mqajXrmU7f2cXrGB9vDZ+gxfPlJJhD7fQl22K7xfzfky/+daGlJ/kev
         IV8PY+RCwvuo+QvhnwXtU4FGOIyqECxQGTRfUT6tfx1Qa2/9dc7Oa9VsTgLrA8ODKxSf
         eo79ieeW7uBq6j/laItRUOF/c/FzI9lVg5VqSxpnCie56zl+i81SRo5KbB/5tNM93gdy
         LR7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=9nFHfE8lfIth3JW6DPdZjPkk/GVMeZ20ZgtYo3+48Wk=;
        fh=oGOAZwsm9h/2gGdbvd2pjGcTyhhJ8yCtZZH65WuVL8U=;
        b=PuM/75kKjm5b9MudcgATg9uWORPsus5cvyaznlv8NxlFMKqJJJwnEpXNsTisVSbJT0
         5+AdqmvI4WQLNWvo9jR4KwQYYH9/E6EX9sstUMNTOUxlx5y3T4QcX7Gas+nAh/iL2mIu
         ywXxQgabtUNc3lMQUhAwrIn3fQDBSU79YRLyRKaqztRVc4ekWWZMOD3gvWsP+BAI2pTS
         KkCybUJlP5O55+U3VxLyvSQ+jWzK1oKbuwZL0pRMXAvBLhY51Nz+AtWX3rUf0SZOqfBC
         61qZY+CntjJCrGVfJZ5C2zqzWOmeSZud/DaY9Rf6oh8tNUgilYFh8C796DFaQ150U9L8
         q5Mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=IotAcTce;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623289; x=1724228089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9nFHfE8lfIth3JW6DPdZjPkk/GVMeZ20ZgtYo3+48Wk=;
        b=fVusnPMgd93rL3Oq/Qw6UsVaNbfWKrMu63452VWGwvVSboITB90KH8SqP7rexfYFsf
         6YPJAsEOCxHtYerexkWTHdHbBIMad3GPpye0s1xYG4q1BzXEhMkf/RMXXkR/QriwjweE
         BmKNYaE9EuN81MCsZoAEvmwt9IsxPkjoSDs3wabtCjf/0iPMhfvC6DKcUN2Fs3hBopdV
         5+aR5PVBEjQl9NFPvLlIlOOE0Xe5IYPAj5wWU6q5/iUP5j804HPREJ0XbXI4lsisAIIv
         +KasG6sLucHekHiyJUySQqhiPgZq/nfUC2i+c1p8AXi0LVE21oj2sgX5INmZObJmyrKv
         XIZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623289; x=1724228089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9nFHfE8lfIth3JW6DPdZjPkk/GVMeZ20ZgtYo3+48Wk=;
        b=rarWNLK2ttsstHfa6ASGzPAtnUCySF/g5dDP6CDkzSpnAcwT6CXL1ob1dYihXUhyLS
         e5ypbMJX6TdPRCGwUbFwhHW7DVGg8nR9os96WvGXfKSpNqf74GzMXxRgyPkCpTLnfpR/
         tYR8E2A99zGsYMNQd2feR28LzUdIb4ghdz5vxnPFRNzJhbI51/8SfkIKKWkq9GRzPbmA
         Bf/mL41WBt6Y3CvYc2MtAkv7A0JgqTF05X84OHv4URHFFL0ETIyjhtSQhW464D8g3H1p
         ceaWQkPEqTVUArqIc0nFasgIi2XUrksYJiOPLoY8Ur5XbfJP5yCjPmP3/Cri1Ku9ufKy
         T6zg==
X-Forwarded-Encrypted: i=2; AJvYcCUP2WqfvLWqVxpIJ7jS+3Ay0l50gOKwJ1dmKjAiIHhuZQ9Sbpi9dCWjFoK212jdkLGU41lvSw==@lfdr.de
X-Gm-Message-State: AOJu0YxI2QLMVDByTxP4c7oPG25xwhGA8AVk9uzqz2W0/dKlT/kcPkou
	n9z+6qyjhgPsX6W7DIakZXQAi2G36bXG4okI3G33BECRDf8akLcP
X-Google-Smtp-Source: AGHT+IGq55McHsTbQelazilvEeE+hmol+Rz4ges0Gfin2hwAteqZgAGQwTn23eCMhHyZ2LdA2o7n9Q==
X-Received: by 2002:a05:622a:6113:b0:44f:f83d:469f with SMTP id d75a77b69052e-4535ba91f08mr16251181cf.14.1723623289597;
        Wed, 14 Aug 2024 01:14:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d50:0:b0:451:8d59:9c03 with SMTP id d75a77b69052e-451d10e0710ls83662341cf.0.-pod-prod-01-us;
 Wed, 14 Aug 2024 01:14:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpDKG9uZFGrQLQ1WbGkGpeARlgzJqbleNy1yceqb/pw9MQOXv0M+Mx+iIuCKvpt2ymi8KlOenbrB8=@googlegroups.com
X-Received: by 2002:a05:620a:46a4:b0:79f:84f:809f with SMTP id af79cd13be357-7a4ee35073fmr256502985a.33.1723623288687;
        Wed, 14 Aug 2024 01:14:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623288; cv=none;
        d=google.com; s=arc-20160816;
        b=Iq+iDWvpPDlYEHmIDTFIczOUlQXxPoUc7UZ/JkTZ2jprRs9sPnK/UsTnhg7IPD7Wfq
         PZMniq4n2s3g6Tb10vyqng2NcRtsPz97R2VOsjWgXMkp2iXg3cpe78sbt6D/AjuKCJuD
         B8bhaNarvEyU6Fnn7VKr/w5xVWD75UPTzQp4ML+AbbatiokHtJygjUfVTDA21Mqy8hbj
         fEWCblkDvosSJIiZOlAw25Vh//9PguDvtJKaNKrvdpKfb7vNH6xWwZXHKAYTBTINph9n
         HT0RvoWmS1abRKcJYhDYSKoGmbfnKbI/kVofy0XPntK4qRKIOahN+c+arvd7vqere6W+
         IKCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LxODSbbo0H8ZTAbdWRuc0oSygFaST00WU3n3OKhnSJY=;
        fh=BVy8kBnBjlaZG05hlGkr9gQnnuZPgj3AufZQRYu7o2I=;
        b=MMKXodGUuxAVjuSOo6Absg1s82WJsOWx1c6S/fXwtRddQoY5H2Ps1E4Vg1qI8Naf2H
         58nTz5w8pss2v3KrDhiyCWOqJrg2cJw1zTwza0ShLjbtXG1pCp3KwHasEQ31dEbCMgo1
         RjT0wDnjkrUu/tGcFXukqjCKpeREZKqvQuUiyCsI7fX0ZbVmLnlecFEaMkwoEcvrjP7O
         iPVYR2ZbgHfyK6K3LRn626FDpPeDrzIOVljLxZXRsfjtPT0/L5m/tdVk+jEa5IE2CgsP
         B+8vyXXrq+xdRCDiNRYQJy3nACJsAtBeKTGFcVn6zYg4LpO9WgepC0ZyJelCjZhQV0t7
         hg1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=IotAcTce;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a4c7e01cc9si36649985a.4.2024.08.14.01.14.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1fc692abba4so54360275ad.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVq994ZX1jE4GmXur82nhn7i3ys69mkTYK0Zws/a6CYVoGvJOuL1b6tsLPgEDXSQ/WgegwHdFP/rkk=@googlegroups.com
X-Received: by 2002:a17:902:cf07:b0:1fc:3600:5cd7 with SMTP id d9443c01a7336-201d63bc101mr25303265ad.10.1723623287627;
        Wed, 14 Aug 2024 01:14:47 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:47 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v3 05/10] riscv: Add support for the tagged address ABI
Date: Wed, 14 Aug 2024 01:13:32 -0700
Message-ID: <20240814081437.956855-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=IotAcTce;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

When pointer masking is enabled for userspace, the kernel can accept
tagged pointers as arguments to some system calls. Allow this by
untagging the pointers in access_ok() and the uaccess routines. The
uaccess routines must peform untagging in software because U-mode and
S-mode have entirely separate pointer masking configurations. In fact,
hardware may not even implement pointer masking for S-mode.

Since the number of tag bits is variable, untagged_addr_remote() needs
to know what PMLEN to use for the remote mm. Therefore, the pointer
masking mode must be the same for all threads sharing an mm. Enforce
this with a lock flag in the mm context, as x86 does for LAM. The flag
gets reset in init_new_context() during fork(), as the new mm is no
longer multithreaded.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v3:
 - Use IS_ENABLED instead of #ifdef when possible
 - Implement mm_untag_mask()
 - Remove pmlen from struct thread_info (now only in mm_context_t)

Changes in v2:
 - Implement untagged_addr_remote()
 - Restrict PMLEN changes once a process is multithreaded

 arch/riscv/include/asm/mmu.h         |  7 +++
 arch/riscv/include/asm/mmu_context.h | 13 +++++
 arch/riscv/include/asm/uaccess.h     | 58 ++++++++++++++++++++--
 arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
 4 files changed, 141 insertions(+), 10 deletions(-)

diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
index c9e03e9da3dc..1cc90465d75b 100644
--- a/arch/riscv/include/asm/mmu.h
+++ b/arch/riscv/include/asm/mmu.h
@@ -25,9 +25,16 @@ typedef struct {
 #ifdef CONFIG_BINFMT_ELF_FDPIC
 	unsigned long exec_fdpic_loadmap;
 	unsigned long interp_fdpic_loadmap;
+#endif
+	unsigned long flags;
+#ifdef CONFIG_RISCV_ISA_SUPM
+	u8 pmlen;
 #endif
 } mm_context_t;
 
+/* Lock the pointer masking mode because this mm is multithreaded */
+#define MM_CONTEXT_LOCK_PMLEN	0
+
 #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
 #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
 
diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
index 7030837adc1a..8c4bc49a3a0f 100644
--- a/arch/riscv/include/asm/mmu_context.h
+++ b/arch/riscv/include/asm/mmu_context.h
@@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
 static inline void activate_mm(struct mm_struct *prev,
 			       struct mm_struct *next)
 {
+#ifdef CONFIG_RISCV_ISA_SUPM
+	next->context.pmlen = 0;
+#endif
 	switch_mm(prev, next, NULL);
 }
 
@@ -30,11 +33,21 @@ static inline int init_new_context(struct task_struct *tsk,
 #ifdef CONFIG_MMU
 	atomic_long_set(&mm->context.id, 0);
 #endif
+	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
+		clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
 	return 0;
 }
 
 DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
 
+#ifdef CONFIG_RISCV_ISA_SUPM
+#define mm_untag_mask mm_untag_mask
+static inline unsigned long mm_untag_mask(struct mm_struct *mm)
+{
+	return -1UL >> mm->context.pmlen;
+}
+#endif
+
 #include <asm-generic/mmu_context.h>
 
 #endif /* _ASM_RISCV_MMU_CONTEXT_H */
diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
index 72ec1d9bd3f3..6416559232a2 100644
--- a/arch/riscv/include/asm/uaccess.h
+++ b/arch/riscv/include/asm/uaccess.h
@@ -9,8 +9,56 @@
 #define _ASM_RISCV_UACCESS_H
 
 #include <asm/asm-extable.h>
+#include <asm/cpufeature.h>
 #include <asm/pgtable.h>		/* for TASK_SIZE */
 
+#ifdef CONFIG_RISCV_ISA_SUPM
+static inline unsigned long __untagged_addr(unsigned long addr)
+{
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
+		u8 pmlen = current->mm->context.pmlen;
+
+		/* Virtual addresses are sign-extended; physical addresses are zero-extended. */
+		if (IS_ENABLED(CONFIG_MMU))
+			return (long)(addr << pmlen) >> pmlen;
+		else
+			return (addr << pmlen) >> pmlen;
+	}
+
+	return addr;
+}
+
+#define untagged_addr(addr) ({						\
+	unsigned long __addr = (__force unsigned long)(addr);		\
+	(__force __typeof__(addr))__untagged_addr(__addr);		\
+})
+
+static inline unsigned long __untagged_addr_remote(struct mm_struct *mm, unsigned long addr)
+{
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
+		u8 pmlen = mm->context.pmlen;
+
+		/* Virtual addresses are sign-extended; physical addresses are zero-extended. */
+		if (IS_ENABLED(CONFIG_MMU))
+			return (long)(addr << pmlen) >> pmlen;
+		else
+			return (addr << pmlen) >> pmlen;
+	}
+
+	return addr;
+}
+
+#define untagged_addr_remote(mm, addr) ({				\
+	unsigned long __addr = (__force unsigned long)(addr);		\
+	mmap_assert_locked(mm);						\
+	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);	\
+})
+
+#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), size))
+#else
+#define untagged_addr(addr) (addr)
+#endif
+
 /*
  * User space memory access functions
  */
@@ -130,7 +178,7 @@ do {								\
  */
 #define __get_user(x, ptr)					\
 ({								\
-	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
+	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
 	long __gu_err = 0;					\
 								\
 	__chk_user_ptr(__gu_ptr);				\
@@ -246,7 +294,7 @@ do {								\
  */
 #define __put_user(x, ptr)					\
 ({								\
-	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
+	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
 	__typeof__(*__gu_ptr) __val = (x);			\
 	long __pu_err = 0;					\
 								\
@@ -293,13 +341,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
 static inline unsigned long
 raw_copy_from_user(void *to, const void __user *from, unsigned long n)
 {
-	return __asm_copy_from_user(to, from, n);
+	return __asm_copy_from_user(to, untagged_addr(from), n);
 }
 
 static inline unsigned long
 raw_copy_to_user(void __user *to, const void *from, unsigned long n)
 {
-	return __asm_copy_to_user(to, from, n);
+	return __asm_copy_to_user(untagged_addr(to), from, n);
 }
 
 extern long strncpy_from_user(char *dest, const char __user *src, long count);
@@ -314,7 +362,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
 {
 	might_fault();
 	return access_ok(to, n) ?
-		__clear_user(to, n) : n;
+		__clear_user(untagged_addr(to), n) : n;
 }
 
 #define __get_kernel_nofault(dst, src, type, err_label)			\
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index 1280a7c4a412..f4d8e5c3bb84 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -203,6 +203,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
 	unsigned long tls = args->tls;
 	struct pt_regs *childregs = task_pt_regs(p);
 
+	/* Ensure all threads in this mm have the same pointer masking mode. */
+	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
+		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
+
 	memset(&p->thread.s, 0, sizeof(p->thread.s));
 
 	/* p->thread holds context to be restored by __switch_to() */
@@ -248,10 +252,16 @@ enum {
 static bool have_user_pmlen_7;
 static bool have_user_pmlen_16;
 
+/*
+ * Control the relaxed ABI allowing tagged user addresses into the kernel.
+ */
+static unsigned int tagged_addr_disabled;
+
 long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
 {
-	unsigned long valid_mask = PR_PMLEN_MASK;
+	unsigned long valid_mask = PR_PMLEN_MASK | PR_TAGGED_ADDR_ENABLE;
 	struct thread_info *ti = task_thread_info(task);
+	struct mm_struct *mm = task->mm;
 	unsigned long pmm;
 	u8 pmlen;
 
@@ -266,16 +276,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
 	 * in case choosing a larger PMLEN has a performance impact.
 	 */
 	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
-	if (pmlen == PMLEN_0)
+	if (pmlen == PMLEN_0) {
 		pmm = ENVCFG_PMM_PMLEN_0;
-	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
+	} else if (pmlen <= PMLEN_7 && have_user_pmlen_7) {
+		pmlen = PMLEN_7;
 		pmm = ENVCFG_PMM_PMLEN_7;
-	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
+	} else if (pmlen <= PMLEN_16 && have_user_pmlen_16) {
+		pmlen = PMLEN_16;
 		pmm = ENVCFG_PMM_PMLEN_16;
-	else
+	} else {
 		return -EINVAL;
+	}
+
+	/*
+	 * Do not allow the enabling of the tagged address ABI if globally
+	 * disabled via sysctl abi.tagged_addr_disabled, if pointer masking
+	 * is disabled for userspace.
+	 */
+	if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disabled || !pmlen))
+		return -EINVAL;
+
+	if (!(arg & PR_TAGGED_ADDR_ENABLE))
+		pmlen = PMLEN_0;
+
+	if (mmap_write_lock_killable(mm))
+		return -EINTR;
+
+	if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags) && mm->context.pmlen != pmlen) {
+		mmap_write_unlock(mm);
+		return -EBUSY;
+	}
 
 	envcfg_update_bits(task, ENVCFG_PMM, pmm);
+	mm->context.pmlen = pmlen;
+
+	mmap_write_unlock(mm);
 
 	return 0;
 }
@@ -288,6 +323,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 	if (is_compat_thread(ti))
 		return -EINVAL;
 
+	/*
+	 * The mm context's pmlen is set only when the tagged address ABI is
+	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
+	 */
 	switch (task->thread.envcfg & ENVCFG_PMM) {
 	case ENVCFG_PMM_PMLEN_7:
 		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
@@ -297,6 +336,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 		break;
 	}
 
+	if (task->mm->context.pmlen)
+		ret |= PR_TAGGED_ADDR_ENABLE;
+
 	return ret;
 }
 
@@ -306,6 +348,24 @@ static bool try_to_set_pmm(unsigned long value)
 	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
 }
 
+/*
+ * Global sysctl to disable the tagged user addresses support. This control
+ * only prevents the tagged address ABI enabling via prctl() and does not
+ * disable it for tasks that already opted in to the relaxed ABI.
+ */
+
+static struct ctl_table tagged_addr_sysctl_table[] = {
+	{
+		.procname	= "tagged_addr_disabled",
+		.mode		= 0644,
+		.data		= &tagged_addr_disabled,
+		.maxlen		= sizeof(int),
+		.proc_handler	= proc_dointvec_minmax,
+		.extra1		= SYSCTL_ZERO,
+		.extra2		= SYSCTL_ONE,
+	},
+};
+
 static int __init tagged_addr_init(void)
 {
 	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
@@ -319,6 +379,9 @@ static int __init tagged_addr_init(void)
 	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
 	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
 
+	if (!register_sysctl("abi", tagged_addr_sysctl_table))
+		return -EINVAL;
+
 	return 0;
 }
 core_initcall(tagged_addr_init);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-6-samuel.holland%40sifive.com.
