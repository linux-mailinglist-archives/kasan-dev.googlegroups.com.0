Return-Path: <kasan-dev+bncBCMIFTP47IJBBGXE5SZQMGQEXEFYFOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 085519172F7
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:48 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3761e678b99sf33465ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349786; cv=pass;
        d=google.com; s=arc-20160816;
        b=EwrEcVcInQA0mHi2uPArYK4MqY8a1tHIEcS2MNzPlpyZp5cHJxbt14axJbU2DOdHa7
         OTLa4RQLiCPH2pHOt+muF0n5lygvheNV/hO0D3iYtKvEYsqPFH6AiNOMRc3AnF49zk9C
         QkTouQTab0Tu9NsQdeJXomUhmlkL6a38WNfYzcuVRmLSarjR/vhHy0pH1ufk9tfqCYHv
         rimeuEiBFpohq2wyV9YJ57X90vP/kHD+FOl3xYFrytTxZnh+phYh0jUMkLNiBhmooM3D
         2oAhRDjt1xuY1zHsuxjxrwLx73FpsN6q4JWc3D9GdvwFf5Ze29rZOVhvTYOnznSx4OKJ
         i/Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VKlBvKRJn0hmZxcSRZLA1uqd2423dCDK4N/beNsG3BE=;
        fh=oWB5kje2z8X1aDa52t0cj/dS3JGOSHgxFNBaoXtyetk=;
        b=g6eoafdBKCVsxQAw5JFUFjw/mwVrmH9T6HD1XFrO5DzD9ztsCSihLKms2T9uMlAIfk
         OKd2X1tXPl3lQ9Rt8jG7B1mtn9ItYYEj1xMD7skGje4ZxSdK0lqf1CHS5d1rmWp4mf/0
         xqER5q6JuhzQGP8J0hgDGVVC9vKsmwz4MWuR90o0f7UlaLNBJW4RQaaSuTlvLtioDBzT
         x1WvNptDIFwH42YEpg1fBBtgKbli2WWpEp18wjYbsp4akJvdLzTxWrbJ5qbcxNc3DYl/
         kbeCSsjaWOrJ3T0CEhUfv84IMRL6S1mNMZVeD9E05I2Qfo5dkYYNYbqJ5VtgxdQCTK36
         66UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="e1wcAuI/";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349786; x=1719954586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VKlBvKRJn0hmZxcSRZLA1uqd2423dCDK4N/beNsG3BE=;
        b=f20qJFwFRWOrRn42yPdM6w1UpdSO3dsVrwtefqKvQ7he95jvbtLM/5merT93+5hIax
         vhrNtSlHrZyCVWv3hH7b07+FHD08n8HD8WbuFSxWyWzxM7FFxYnICUFF0LBLlIJrwUoe
         GguTCtCRed3gRI+v0a0q3y2Ky0yCE5GK07ozo52wuIS9xm13Z3GzRejo+LSAIxqAi4Ol
         aNtcZR40x2ysOdmOkwuQDyKk01yNOzSdSYZVJn2tapvu6qNjAZa1tCMnJPRBvq3fvUcb
         uo2tlCiKOVpK/kL5WjqgCNnmBkDhewUUDZeOMimZVetEEgarLCcNnNIUbGXD63vrQYrx
         o1hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349786; x=1719954586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VKlBvKRJn0hmZxcSRZLA1uqd2423dCDK4N/beNsG3BE=;
        b=Up4vhmPaKUh3N0Cc3v8FFnigdTbIn2PWnqYSe61bTNLtFCDvemCMs0+psVI70DRKKQ
         Exu7ws1WTS85qySIFM1M/1Ljie89+ic4F7oNxYkImtWSB4drQDgrAPiCCrNytS4snyiC
         5+CaGjQja7d4EdDvzQ929bgVPfE5PRWObk07H4dUvc0rI4SGGEzwbVOslNNNnWh0Wn9e
         7FCec2edGaHz3XM4qU/PlwwrcbS+/Edf9R8u2DUg+UfSowIxbha/YuWeiumuLylrvFtV
         JEf63eScNX0ujo7KtU9mWdneYbaw8OadUwbdN3iMHlc1SSzHOwPPu7PQZG6Udu5k5SdR
         EkTQ==
X-Forwarded-Encrypted: i=2; AJvYcCUn+qDnedplHcFDVVsLdK0h0ZFeEAYpZq0Gv5i7KcLXesTM2RJKhazHis1793mp9wkZSE/Xpc/IiP8PN7mAeBg/mH9jZRQt9A==
X-Gm-Message-State: AOJu0YyAV0WbkSOG/vW0tPseusjoWzsLm6GijtV4ZmbX63bduXphIoOG
	Lh8/S71TmC3h1iaKQ1QcmwSOmv1f2+rbsgOxVozAGKIkoLphSks7
X-Google-Smtp-Source: AGHT+IEsBHzrUk5GwUweYRprL9uY9JSXrDEFtpvVJ329I6CGlB9YVMfKqa6l4U9xkb5zWXTV58CZgw==
X-Received: by 2002:a92:c64e:0:b0:376:37e7:c9b with SMTP id e9e14a558f8ab-3782722a507mr186155ab.29.1719349786521;
        Tue, 25 Jun 2024 14:09:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12c4:b0:375:b30c:ffd with SMTP id
 e9e14a558f8ab-37626b2a46els46999005ab.2.-pod-prod-06-us; Tue, 25 Jun 2024
 14:09:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWfdUghJ2oYcNDy0V0hB5zT+yp0S1glMHCa63Eh1yZxY92YwVjT2RhYwbZSB1aCUxzYnAAmlF1nBXs2qTuXmCLZTfokKJyDUJd0iw==
X-Received: by 2002:a05:6602:27cc:b0:7f3:c683:2266 with SMTP id ca18e2360f4ac-7f3c6832304mr284816539f.4.1719349785651;
        Tue, 25 Jun 2024 14:09:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349785; cv=none;
        d=google.com; s=arc-20160816;
        b=gSL5/7VrWu/aQ/pCrq+GvUeM9cK/yqwd6+jnyS3bvXSlrV7pDSPO1wRL3QJPMC+iGo
         tTzJck/X6pftFQ0MhYmJTC2tXWX4wr0OmxUIBbr+t4iFqohNzBRB5dSxItMNuw3MNvOo
         F0lXvvT678fsQCGodA7Ty2T0vHlhlnibM9h81BTJ5UP/gpEBCokDME5uRJr8jC2Jdvp8
         U1eJba7dtyzXo5/8GaS0OWdgIyU/T+72ZP38oQzpPAEtNT5o6en608hloS7bCRu4Q6d0
         myOqs4KPH9B95W8ODBgymstcm2dm7NyQ2DrrozkXGYIIo9G3Bu9c7yvG2NbG+Fb4ySBB
         pM1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Icm6uA8wnqdys37A8Kzf4AV1ey+zBIexi2g5XJMtDfE=;
        fh=9aV4Zsnth73tYJ6eNsnwN5VVFYr5pCG4N6qEV6T8YwE=;
        b=G6uWCoJzR7hpqHlEoAiXAwXa4ykNIzkAN1Fw1cFQ6ChUM4oRx0JZUl01kv4wZyMl9/
         mBPCA+ZWfRi0oxZ104DFI6Pr9Wse2O4IH0L4AlvV9HphTEXsgn2WIYfvy3fm1ShMSjbz
         0lQSySRerjcYh1y/Hh7v6FeVoCoB3flGjIGbXy4TkT6riGGf5xhjffGNkGxheKxjWgen
         BerFycoswa51kUghwrDqEdcMJ78IHq4c6UrgUhoiQ2sbLD3XcbcqdNL+mjyb/cWfSKV9
         ILmMzGNpyOmil184ZfnLsoWSn13o+oInnBco+poKtFzzLFNZ4DkI63Andy3gxkupjon1
         irfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="e1wcAuI/";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9fa2b516asi207679173.4.2024.06.25.14.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1fa2ea1c443so24278755ad.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXA2oUtUh/l/RevhtVLf7f1ZD8VcRWo5cn/GH4VQMNgTFkvHCiFqPi/LZf+ju4oiH0D1cLrUGKfwQQtiwFojVLREzSwxorvN8jW8g==
X-Received: by 2002:a17:903:32ce:b0:1fa:643:f424 with SMTP id d9443c01a7336-1fa238e46ddmr113134855ad.14.1719349784670;
        Tue, 25 Jun 2024 14:09:44 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:44 -0700 (PDT)
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
Subject: [PATCH v2 05/10] riscv: Add support for the tagged address ABI
Date: Tue, 25 Jun 2024 14:09:16 -0700
Message-ID: <20240625210933.1620802-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="e1wcAuI/";       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
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

Unlike x86, untagged_addr() gets pmlen from struct thread_info instead
of a percpu variable, as this both avoids context switch overhead and
loads the value more efficiently.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Implement untagged_addr_remote()
 - Restrict PMLEN changes once a process is multithreaded

 arch/riscv/include/asm/mmu.h         |  7 +++
 arch/riscv/include/asm/mmu_context.h |  6 +++
 arch/riscv/include/asm/thread_info.h |  3 ++
 arch/riscv/include/asm/uaccess.h     | 58 +++++++++++++++++++++--
 arch/riscv/kernel/process.c          | 69 +++++++++++++++++++++++++++-
 5 files changed, 136 insertions(+), 7 deletions(-)

diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
index 947fd60f9051..361a9623f8c8 100644
--- a/arch/riscv/include/asm/mmu.h
+++ b/arch/riscv/include/asm/mmu.h
@@ -26,8 +26,15 @@ typedef struct {
 	unsigned long exec_fdpic_loadmap;
 	unsigned long interp_fdpic_loadmap;
 #endif
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	unsigned long flags;
+	u8 pmlen;
+#endif
 } mm_context_t;
 
+/* Lock the pointer masking mode because this mm is multithreaded */
+#define MM_CONTEXT_LOCK_PMLEN	0
+
 #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
 #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
 
diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
index 7030837adc1a..62a9f76cf257 100644
--- a/arch/riscv/include/asm/mmu_context.h
+++ b/arch/riscv/include/asm/mmu_context.h
@@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
 static inline void activate_mm(struct mm_struct *prev,
 			       struct mm_struct *next)
 {
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	next->context.pmlen = 0;
+#endif
 	switch_mm(prev, next, NULL);
 }
 
@@ -29,6 +32,9 @@ static inline int init_new_context(struct task_struct *tsk,
 {
 #ifdef CONFIG_MMU
 	atomic_long_set(&mm->context.id, 0);
+#endif
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
 #endif
 	return 0;
 }
diff --git a/arch/riscv/include/asm/thread_info.h b/arch/riscv/include/asm/thread_info.h
index 5d473343634b..cd355f8a550f 100644
--- a/arch/riscv/include/asm/thread_info.h
+++ b/arch/riscv/include/asm/thread_info.h
@@ -60,6 +60,9 @@ struct thread_info {
 	void			*scs_base;
 	void			*scs_sp;
 #endif
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	u8			pmlen;
+#endif
 };
 
 #ifdef CONFIG_SHADOW_CALL_STACK
diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
index 72ec1d9bd3f3..153495997bc1 100644
--- a/arch/riscv/include/asm/uaccess.h
+++ b/arch/riscv/include/asm/uaccess.h
@@ -9,8 +9,56 @@
 #define _ASM_RISCV_UACCESS_H
 
 #include <asm/asm-extable.h>
+#include <asm/cpufeature.h>
 #include <asm/pgtable.h>		/* for TASK_SIZE */
 
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+static inline unsigned long __untagged_addr(unsigned long addr)
+{
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
+		u8 pmlen = current->thread_info.pmlen;
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
index dec5ccc44697..7bd445dade92 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -173,8 +173,10 @@ void flush_thread(void)
 	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
 #endif
 #ifdef CONFIG_RISCV_ISA_POINTER_MASKING
-	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
 		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
+		current->thread_info.pmlen = 0;
+	}
 #endif
 }
 
@@ -204,6 +206,12 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
 	unsigned long tls = args->tls;
 	struct pt_regs *childregs = task_pt_regs(p);
 
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	/* Ensure all threads in this mm have the same pointer masking mode. */
+	if (p->mm && (clone_flags & CLONE_VM))
+		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
+#endif
+
 	memset(&p->thread.s, 0, sizeof(p->thread.s));
 
 	/* p->thread holds context to be restored by __switch_to() */
@@ -243,10 +251,16 @@ void __init arch_task_cache_init(void)
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
 
@@ -277,6 +291,14 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
 			return -EINVAL;
 	}
 
+	/*
+	 * Do not allow the enabling of the tagged address ABI if globally
+	 * disabled via sysctl abi.tagged_addr_disabled, if pointer masking
+	 * is disabled for userspace.
+	 */
+	if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disabled || !pmlen))
+		return -EINVAL;
+
 	if (pmlen == 7)
 		pmm = ENVCFG_PMM_PMLEN_7;
 	else if (pmlen == 16)
@@ -284,7 +306,22 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
 	else
 		pmm = ENVCFG_PMM_PMLEN_0;
 
+	if (!(arg & PR_TAGGED_ADDR_ENABLE))
+		pmlen = 0;
+
+	if (mmap_write_lock_killable(mm))
+		return -EINTR;
+
+	if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags) && mm->context.pmlen != pmlen) {
+		mmap_write_unlock(mm);
+		return -EBUSY;
+	}
+
 	envcfg_update_bits(task, ENVCFG_PMM, pmm);
+	task->mm->context.pmlen = pmlen;
+	task->thread_info.pmlen = pmlen;
+
+	mmap_write_unlock(mm);
 
 	return 0;
 }
@@ -297,6 +334,13 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 	if (is_compat_thread(ti))
 		return -EINVAL;
 
+	if (task->thread_info.pmlen)
+		ret = PR_TAGGED_ADDR_ENABLE;
+
+	/*
+	 * The task's pmlen is only set if the tagged address ABI is enabled,
+	 * so the effective PMLEN must be extracted from envcfg.PMM.
+	 */
 	switch (task->thread.envcfg & ENVCFG_PMM) {
 	case ENVCFG_PMM_PMLEN_7:
 		ret |= FIELD_PREP(PR_PMLEN_MASK, 7);
@@ -315,6 +359,24 @@ static bool try_to_set_pmm(unsigned long value)
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
@@ -328,6 +390,9 @@ static int __init tagged_addr_init(void)
 	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
 	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
 
+	if (!register_sysctl("abi", tagged_addr_sysctl_table))
+		return -EINVAL;
+
 	return 0;
 }
 core_initcall(tagged_addr_init);
-- 
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-6-samuel.holland%40sifive.com.
