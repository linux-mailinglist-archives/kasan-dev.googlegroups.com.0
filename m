Return-Path: <kasan-dev+bncBCMIFTP47IJBBC4RX63AMGQEAWHOA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D331963731
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:05 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2d626e36d2esf103069a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893324; cv=pass;
        d=google.com; s=arc-20240605;
        b=GbguyxL4ogXWnnMhZtFp/bFXUrG68TBIe7/86t31PMrjf7Jr9/+7/nYBI8swRPXW88
         St6NvdYy06fpv2/n2S1CYOIBL/3DYeo07EQkpsLt0i5Bc6hdsaKn9etyE+grjRqif2NX
         S8UM+cbh85c/DE+VI6kA/NV+l9pKEs7c1sAVXxjRX4W6cQRuHMxLYf43cgtuJf2rThfk
         syyfJIx33cKsSrDwakmxI95FTJk5T0i7YOyOV05XhQHP+g1/53VhHcQaEJKA2qtXR2Jn
         BCYip3NJjuYM/DNw9ave5nliQPrTUp2zzMcUGPnhXoYFIvSsbvD7yx4eWHt6LOmBI3rF
         2/Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mu8CTnpQErUqf8DfGrTUCxaHG45UL7TVXV48Mk5BiWk=;
        fh=RFdSwNE+AYgjkqJUQWgMjlbNBCjKj1WwGcFEGkSRjNA=;
        b=ZaWSkCK9VMP1+oC2f9J+uMVgPFmGADirxt6Y6I0oIC4sdy5lgrqgPlZNjaXH7IgQC7
         YiStzflbH1aobdpdSuzSD9H9npIINlyH+0yQnwnSf4B47XjdOHLbpZXgm8CckWFgcUOy
         bUYFcCZTDiYr7OOd6LxI+MKfQMQDUy5OBYeXq7/WQ2l+41aRhOdPuKKveu4XQYPdT9Rk
         FmWUvBfmcVEW2+aMJR+srlf6xccNtfftAFTcotzzBANkSfym1vVqLPYqhhbjFxbvtrvr
         PjvVVIQkRbYpvyUHYeohyBXi6UucRya13XWtLF2PdeTSV1HeNyjAHjtpQPTGIJfkIdpX
         uj9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Hk4J6j8S;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893324; x=1725498124; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Mu8CTnpQErUqf8DfGrTUCxaHG45UL7TVXV48Mk5BiWk=;
        b=hwi2qcO9YqwUdNZWMynLk10UwkI7wftSdw9AuQQAdlp9h+fhv5JMfqTt/c3+aQFutb
         c/44TEFDXt5rcG2RjzBT4FjdX1wGHX7QuBLkdnwu9v0fOIL2xjfv868k0EoeuAO5HGlY
         uIO7+9dLf5q29a/MQhwgooNB7Xs56SkpAEVQJyqT6rn/Jm+R9IK7tFnN4hjEnga0832y
         /+Kt5BwwsMVrZPVc+exxLoYmH/l71Hm9S4cwgT9ID/qKwybCDr6Q6EqfVJJUOHe8j7O7
         iDALFjviYMWYDAonCdCyL3wsI9pLh5xMZtAMQf6UaqrAZykxgzjGUZHrGZ/24RtRjYlC
         AW5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893324; x=1725498124;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mu8CTnpQErUqf8DfGrTUCxaHG45UL7TVXV48Mk5BiWk=;
        b=rqVoaVJFgSgivMfXi15l7jSVicPZNkCfZseqlJbhv7lEVxtEGB454qzna3GnZdpXFg
         +iyJLYA2eGCn/qa3BJKQInLl2EboIWifC3Y/EN7JZ+AOKBG76WbRXhQ2EFUQPyjGOVXp
         FgJYMMh9DQu55rkv7IQhYYWs18CbWVPiwONd7SKyqLCT80AVZxbER7OgrLzlGNt7qHIE
         I30ybr87WA8CM2Y1FzpLaVRBQ4mGH4Rg5NgnaOq6z/ySY6QZlFh2nxpffVFK2INLETNI
         gb0SuCbYYGhErKW+z/txzQJgUxzH+Kqxp/V5+CiKMZIUvyQtUMcavJkoaaEPAsL9t+gW
         C4RQ==
X-Forwarded-Encrypted: i=2; AJvYcCXCLh7K7RmOH4YqbHWsGwTl5TGOI2xGUbfwcJy35KW+2UenjEbpSErLG3A6HNkUOlum/zyZ0g==@lfdr.de
X-Gm-Message-State: AOJu0YxOUx8RqjrKukF2BmKs+tqd7dnbJHkyVDz6asANMbJ9gURz+UF9
	8krd0FYaRBK3rlCEmBevwIwj0Qh9Dmdnyrpec4rYgkoYt8Ysgqxo
X-Google-Smtp-Source: AGHT+IEugyO57KccY28Z9qcBvmLdYjnEEQ78didvZPIdVqFNKwLNVz43IjBIxj3QQWxxLRt5evxUSg==
X-Received: by 2002:a17:90a:f3c2:b0:2cf:2ab6:a157 with SMTP id 98e67ed59e1d1-2d8561b185cmr1100402a91.12.1724893324020;
        Wed, 28 Aug 2024 18:02:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:270b:b0:2cb:5feb:a0b6 with SMTP id
 98e67ed59e1d1-2d8548d48aels303779a91.2.-pod-prod-05-us; Wed, 28 Aug 2024
 18:02:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjxGQb9LAQKX3TTmOMTbbWU6UBlS2OTTvPUkw71yMM4tX10rUR8o3HZdd5hbZXvOsxi+3++Lge4Hg=@googlegroups.com
X-Received: by 2002:a17:903:124c:b0:202:18de:b419 with SMTP id d9443c01a7336-2050c524e84mr16429315ad.63.1724893322757;
        Wed, 28 Aug 2024 18:02:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893322; cv=none;
        d=google.com; s=arc-20160816;
        b=T3LHgIifIAGRzTgL9yzVAy1XXR/wino0AZiRNwpRqxF8RkERK9YKr3f3HEIGp9GjlA
         fWUya5J4G9+eVLhe6cCXJiNZAzapvyG2L4NNxSnIsdkDiUMSxKK6WUhH76mqYoQ619kY
         t46b8wLd8EyZdfq29c8XzOxQOchNEfxERmef2jddt0hAO6T4o6YLV9/HvdGDl2nZDFpY
         nMgN+SnpXmbeiIOzO0DSjPTNB8cRNd2AiGxng2xnmQhNI8r0uIg8UKJbvfz7O/CEBcO+
         znBBOlNrRRasQpU+nHzyo2R6q9ci7nayw7I+WrEE2UMoQQhBXNhZjENy1C9sYCn4lGDv
         kbWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mi965EzHXRRG42eOTmPcGhK9BxnfGfgGEBjoVVprAAQ=;
        fh=EuUm4s6vxM+2Xu5ul7smRgKN20E+bpsrhkkpjIvcPVc=;
        b=EJmMJOi1Yq/xJofZ/d9/oWb7SYchlSlHkDcnktZeozPyqA7ETKkUumuL0OHDKd3da/
         8hG5N7Kf9uZ1MqUjfrJntrpFz4ZMXjwWGecEqxbsRzZ/05eq0yN1y4bFeD4H4u5w/eKp
         h1efr2DnAhl4Tx/XAvWXQHRQ8ZqyL0V08W7fR9ZofOOeEMMy8cdYpXcBooYHh/CRgR3r
         heUD9fHnUFDxzR8jjvAADfn7jgqg0QBrUEu2YitfHdezTXCktAY5bGYbIbGdbbcbYP0o
         V509g3tmXKvm7RDO+jTOtWUckI3YXPl3Q4G5RoXWLDAZxi3u5MquaonczCYOclx772bf
         jmqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Hk4J6j8S;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20515522762si65645ad.10.2024.08.28.18.02.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-7141feed424so107843b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqry2Qf+1FlKVZYaQFrFWKQDuq3m5Oq5EblGYF9Aawpg1PCd1iGhxqeIrNlZXD24JWk5yxf8iiFv0=@googlegroups.com
X-Received: by 2002:a05:6a00:2196:b0:70d:1dcf:e2b4 with SMTP id d2e1a72fcca58-715dfb698f9mr1218508b3a.1.1724893322003;
        Wed, 28 Aug 2024 18:02:02 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.02.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:02:01 -0700 (PDT)
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
Subject: [PATCH v4 05/10] riscv: Add support for the tagged address ABI
Date: Wed, 28 Aug 2024 18:01:27 -0700
Message-ID: <20240829010151.2813377-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Hk4J6j8S;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Changes in v4:
 - Combine __untagged_addr() and __untagged_addr_remote()

Changes in v3:
 - Use IS_ENABLED instead of #ifdef when possible
 - Implement mm_untag_mask()
 - Remove pmlen from struct thread_info (now only in mm_context_t)

Changes in v2:
 - Implement untagged_addr_remote()
 - Restrict PMLEN changes once a process is multithreaded

 arch/riscv/include/asm/mmu.h         |  7 +++
 arch/riscv/include/asm/mmu_context.h | 13 +++++
 arch/riscv/include/asm/uaccess.h     | 43 ++++++++++++++--
 arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
 4 files changed, 126 insertions(+), 10 deletions(-)

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
index 72ec1d9bd3f3..fee56b0c8058 100644
--- a/arch/riscv/include/asm/uaccess.h
+++ b/arch/riscv/include/asm/uaccess.h
@@ -9,8 +9,41 @@
 #define _ASM_RISCV_UACCESS_H
 
 #include <asm/asm-extable.h>
+#include <asm/cpufeature.h>
 #include <asm/pgtable.h>		/* for TASK_SIZE */
 
+#ifdef CONFIG_RISCV_ISA_SUPM
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
+#define untagged_addr(addr) ({							\
+	unsigned long __addr = (__force unsigned long)(addr);			\
+	(__force __typeof__(addr))__untagged_addr_remote(current->mm, __addr);	\
+})
+
+#define untagged_addr_remote(mm, addr) ({					\
+	unsigned long __addr = (__force unsigned long)(addr);			\
+	mmap_assert_locked(mm);							\
+	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);		\
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
@@ -130,7 +163,7 @@ do {								\
  */
 #define __get_user(x, ptr)					\
 ({								\
-	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
+	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
 	long __gu_err = 0;					\
 								\
 	__chk_user_ptr(__gu_ptr);				\
@@ -246,7 +279,7 @@ do {								\
  */
 #define __put_user(x, ptr)					\
 ({								\
-	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
+	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
 	__typeof__(*__gu_ptr) __val = (x);			\
 	long __pu_err = 0;					\
 								\
@@ -293,13 +326,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
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
@@ -314,7 +347,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
 {
 	might_fault();
 	return access_ok(to, n) ?
-		__clear_user(to, n) : n;
+		__clear_user(untagged_addr(to), n) : n;
 }
 
 #define __get_kernel_nofault(dst, src, type, err_label)			\
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index f39221ab5ddd..6e9c84a41c29 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -204,6 +204,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
 	unsigned long tls = args->tls;
 	struct pt_regs *childregs = task_pt_regs(p);
 
+	/* Ensure all threads in this mm have the same pointer masking mode. */
+	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
+		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
+
 	memset(&p->thread.s, 0, sizeof(p->thread.s));
 
 	/* p->thread holds context to be restored by __switch_to() */
@@ -249,10 +253,16 @@ enum {
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
 
@@ -267,16 +277,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
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
@@ -289,6 +324,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 	if (is_compat_thread(ti))
 		return -EINVAL;
 
+	/*
+	 * The mm context's pmlen is set only when the tagged address ABI is
+	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
+	 */
 	switch (task->thread.envcfg & ENVCFG_PMM) {
 	case ENVCFG_PMM_PMLEN_7:
 		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
@@ -298,6 +337,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 		break;
 	}
 
+	if (task->mm->context.pmlen)
+		ret |= PR_TAGGED_ADDR_ENABLE;
+
 	return ret;
 }
 
@@ -307,6 +349,24 @@ static bool try_to_set_pmm(unsigned long value)
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
@@ -320,6 +380,9 @@ static int __init tagged_addr_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-6-samuel.holland%40sifive.com.
