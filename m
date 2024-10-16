Return-Path: <kasan-dev+bncBCMIFTP47IJBB26DYC4AMGQELA2F3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 6601A9A13C9
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:29 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4603efe6c92sf3110321cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110508; cv=pass;
        d=google.com; s=arc-20240605;
        b=gy+4J/rUwI8WolVAKJ8digB03+eVw9LbM50AlEsZz/YcRFALhuW0j/2/G1WlnHdje2
         L/g1GJiY9yV1gErb+/WJzMF6FGIXoRG2++XpHwV/Nm/1so9j0klK2knUqnKBC0RefyCk
         JUXCKyYHd8S+HC7ahSpSvv/wHd1i8XaubwUy6Ae0Vc9KHk6OyiX+xtO13RFiWSos839T
         55v1NkppITCJOXMn+AEdATkaZqvnmTnRCQ5JYwAxgE8etJ88hc0p0Gbl/P55DCc4HKXp
         WfUZZ5GogF3xbXq3OsuDm+yXL2YCrEGuWZ860eeb5Rh0CaQr+7SxU6TOrfmFz1gtDESD
         g61Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GIyl6V/hzwHH9pxoQyQg1F3s8kbpyNnriA8d+DbisMY=;
        fh=a+XlbFgjebpZbYLp+rQ1R9TKkhH3b9GIR99IalkdRIM=;
        b=DkJ7ja1bcODf8SslYiuW00pBgpz8+enlfYQ4E01m1rtujiStu6ze93sSEuoqxY4nDq
         cCXg1B0kL/AwAiorOxT3aOibaPwwhKK9aSzkmIZoPj76L5flPKs8cy8+HOpI2VJQ2NsB
         J5PkJqRccfXEbpC0bx8t4RUef524uj4CHRUm+61slSpnEf3V9meYXTNoVXiUhK9IFbw4
         2dHe5jNvdIVNj2oB9frPU1TltYozuyY/kwdOsNugp/TJMZ6kogGSyz9DqtnYSpZwWUwO
         lEYHE7BSiZcvf0bC3/9T1namOfvpywO3EzS668Gd/n71LjoeDHC852k853+5ZrC6LNDM
         NEww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="ltpTud/O";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110508; x=1729715308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GIyl6V/hzwHH9pxoQyQg1F3s8kbpyNnriA8d+DbisMY=;
        b=piGpktm3nlrfghPqayGTrOapylFOLCP3RyYWxZ4jYZrq5Crnc6kh6SPs0wYgtDSgsa
         3WJPvXa9t0E4ejaJmhPtY9OlEahgrSMghNp86ABlgM1c6OAQ854D0oit+qb9X/h1aYKW
         jDBhAlI5uMq7iYsvmBtMquGLl4fY5GTFSCSmDnH27jRBn1b3/nIV8hm26qlIzMDOQ46c
         rfOxYHRwkQR6ptxeg17lNHL2gIVZ+SNsyislwHfgmz6Njre34eprM7ewAaLugcIRVDwX
         0s4SuEz+fflwqEWMgNWA0JISe4gbZjHH3pRIUPxKZOSaHRDCeAYmRyovzlGOFZOPlzjq
         ya3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110508; x=1729715308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GIyl6V/hzwHH9pxoQyQg1F3s8kbpyNnriA8d+DbisMY=;
        b=F8f6mCbPIf93j7pnf+TmlrSZ/YJbRS8HbSVuK9jYqeZihuAZWCUF/lU+4yz4Rl8Fyl
         crIJxyLOEcRicA2aBMuBtBTXvlRUZ+SEw3MK1QKvuzBPUcO4fBeNUChdbx4L7WCJleeD
         MYvbYkFkpyWhKhTuWVowSICgIrpQ4pPWyeXbglgEqooQKkwX/JOHMdCesKihvgzq/ax5
         vtWIeu43r4rcMpApIVC51XsQpsjirtPUKwqXmnyJj8z4pnhmKea21erC+kjZFyMI8pWy
         EG81hVF9ZPOKuS8fkriphYnMvmTmDQTi3cxirgkgZyom21N+gLOmydAEhupCOCGZEzDr
         Wfvg==
X-Forwarded-Encrypted: i=2; AJvYcCUimE2pJl2nuWXpwOn3C7johUxxGJXJO3SiQlV7uwp2bJGWINrBpfiEgxJVJCk1uX1cQ7P/9g==@lfdr.de
X-Gm-Message-State: AOJu0YzBLayY5/GWJccA/a9hyd/XCpOioj/3P9BycqSeh6YKl4YpV4kK
	piVA4LxIlYZ3KqegMao/ffX6bcE8xVlHObH2eyOiBUUFxy5VphoQ
X-Google-Smtp-Source: AGHT+IGDnSHzBVY6z602dpenWozgYVwsfS6uLjYUZ6flu85DgsxVl+537Fk/E33dkenHXAEiY3BBog==
X-Received: by 2002:a05:622a:428b:b0:45b:5cdf:54b8 with SMTP id d75a77b69052e-4604bbb76c2mr286844711cf.19.1729110508041;
        Wed, 16 Oct 2024 13:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:180a:b0:460:89b7:cab1 with SMTP id
 d75a77b69052e-4609b7f7c35ls2825771cf.2.-pod-prod-03-us; Wed, 16 Oct 2024
 13:28:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqviRk7Zkki8gZbP6dCMa/qzAWONE5NgYssW/6FI6n6tL2N5CTKVCrnrc73zYoHtAAds1fkvUNegQ=@googlegroups.com
X-Received: by 2002:a05:620a:24c2:b0:7a6:6453:359 with SMTP id af79cd13be357-7b11a3b6b0fmr2358282185a.53.1729110507397;
        Wed, 16 Oct 2024 13:28:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110507; cv=none;
        d=google.com; s=arc-20240605;
        b=Jf6IQaF1H1TrsZbrHq8isEY/Mz5T8NYd5Dnb2bVk0R3g0v6jh91dQZ+E5V/faFl5ZX
         v7XGBJ+rourVMu99TcNdVgRGFWXHsPF8h5i6WclfTV9RbLsn4rKDqYcs5+J7bG1sdKzV
         8MzjLL6Yhf9ehcMDlIPMv+5ufmwbS/Z4IZYG0j4lyi7uiXy/+6befPL5Tw3t+dmfreK9
         bDDv4R5eJnC06DCxzLs7YVTQoIEiMqfqXQftz+kZ5jTM9O68W3m70+zs+3GLK40Wc0ll
         2v8x4Ndaxh3KAH7DNQKsosIyTBaDn3wR0YqOElDdsdLuJh7OYlhJROSkbSJ3ORr1DBcu
         hJsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5hzxLyRKZWecSXP6tI9h1HTyfXmIADQzaZQzgJ3j2CQ=;
        fh=1GIL29wXc7s1qtNZcnjG9kqv7LPcABdeAVAaPHpDhvQ=;
        b=e88fst5F+mV3lxX5HRYeRdYtPYoDOjgzizVEvcekj2jpy1fENudyL30PuRelcO8LmY
         91PNjJaSa3De1dYZ0u0ps4kKWjJnBHHv6opzXYNzEcFBb0tZGwd+yTdi9F+Hr11MnpaO
         Vn94xis3zHJbtuyM6KcvuYFJUxMcVw5GR1OpckLFLqyDSmrUhMaxWHLV778KdUXDZM0N
         3hxClP5MeAO/aGM/Tnqn9ZB7R7MD1vbPmCGLsMvP3LwfeaOX+KYLhpMvtNc8wLmCpc9q
         Fg1OXg69aRVSy832D3WC4MZF6Wf1NJpsdKisNHFveY45wSYBo41rfjc3JuyPQPn0q2S1
         zEMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="ltpTud/O";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b136163245si22926885a.2.2024.10.16.13.28.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-2e2eb9dde40so180956a91.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV5HzZNCl2JY/Pn6V76ImvkoC9mR7FMoGlE3JDW8T24DPqG6RgAfJ8YnAyHMQY6pPDJi/nPG3xPCgQ=@googlegroups.com
X-Received: by 2002:a17:90b:4b8e:b0:2e2:eaa0:7103 with SMTP id 98e67ed59e1d1-2e2f0dccf55mr20844968a91.39.1729110506230;
        Wed, 16 Oct 2024 13:28:26 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:25 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Atish Patra <atishp@atishpatra.org>,
	linux-kselftest@vger.kernel.org,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Shuah Khan <shuah@kernel.org>,
	devicetree@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	kvm-riscv@lists.infradead.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	Evgenii Stepanov <eugenis@google.com>,
	Charlie Jenkins <charlie@rivosinc.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v5 05/10] riscv: Add support for the tagged address ABI
Date: Wed, 16 Oct 2024 13:27:46 -0700
Message-ID: <20241016202814.4061541-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="ltpTud/O";       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Tested-by: Charlie Jenkins <charlie@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v5:
 - Document that the RISC-V tagged address ABI is the same as AArch64

Changes in v4:
 - Combine __untagged_addr() and __untagged_addr_remote()

Changes in v3:
 - Use IS_ENABLED instead of #ifdef when possible
 - Implement mm_untag_mask()
 - Remove pmlen from struct thread_info (now only in mm_context_t)

Changes in v2:
 - Implement untagged_addr_remote()
 - Restrict PMLEN changes once a process is multithreaded

 Documentation/arch/riscv/uabi.rst    |  4 ++
 arch/riscv/include/asm/mmu.h         |  7 +++
 arch/riscv/include/asm/mmu_context.h | 13 +++++
 arch/riscv/include/asm/uaccess.h     | 43 ++++++++++++++--
 arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
 5 files changed, 130 insertions(+), 10 deletions(-)

diff --git a/Documentation/arch/riscv/uabi.rst b/Documentation/arch/riscv/uabi.rst
index ddb8359a46ed..243e40062e34 100644
--- a/Documentation/arch/riscv/uabi.rst
+++ b/Documentation/arch/riscv/uabi.rst
@@ -80,3 +80,7 @@ number of mask/tag bits needed by the application. ``PR_PMLEN`` is interpreted
 as a lower bound; if the kernel is unable to satisfy the request, the
 ``PR_SET_TAGGED_ADDR_CTRL`` operation will fail. The actual number of tag bits
 is returned in ``PR_PMLEN`` by the ``PR_GET_TAGGED_ADDR_CTRL`` operation.
+
+Additionally, when pointer masking is enabled (``PR_PMLEN`` is greater than 0),
+a tagged address ABI is supported, with the same interface and behavior as
+documented for AArch64 (Documentation/arch/arm64/tagged-address-abi.rst).
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
index 200d2ed64dfe..58b6482c2bf6 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -213,6 +213,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
 	unsigned long tls = args->tls;
 	struct pt_regs *childregs = task_pt_regs(p);
 
+	/* Ensure all threads in this mm have the same pointer masking mode. */
+	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
+		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
+
 	memset(&p->thread.s, 0, sizeof(p->thread.s));
 
 	/* p->thread holds context to be restored by __switch_to() */
@@ -258,10 +262,16 @@ enum {
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
 
@@ -276,16 +286,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
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
@@ -298,6 +333,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 	if (is_compat_thread(ti))
 		return -EINVAL;
 
+	/*
+	 * The mm context's pmlen is set only when the tagged address ABI is
+	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
+	 */
 	switch (task->thread.envcfg & ENVCFG_PMM) {
 	case ENVCFG_PMM_PMLEN_7:
 		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
@@ -307,6 +346,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 		break;
 	}
 
+	if (task->mm->context.pmlen)
+		ret |= PR_TAGGED_ADDR_ENABLE;
+
 	return ret;
 }
 
@@ -316,6 +358,24 @@ static bool try_to_set_pmm(unsigned long value)
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
@@ -329,6 +389,9 @@ static int __init tagged_addr_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-6-samuel.holland%40sifive.com.
