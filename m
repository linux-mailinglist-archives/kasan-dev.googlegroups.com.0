Return-Path: <kasan-dev+bncBCMIFTP47IJBBQEV5CXQMGQE2DF477A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84CE2880703
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:29 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3c38f6fa664sf1832099b6e.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885568; cv=pass;
        d=google.com; s=arc-20160816;
        b=FzMnLnRkudI2805Ank4367K5/xGq8/5m4sQjGQcDOC1f9SMsIbAj0wtnT8SruOLSdY
         1NeiT9UEobt3GMQb5LpPmmfIzfXiQPTRKG5Ztgo0MoUgf5H4iu7Vz403mbfNd2Tdbu63
         iNGGOs1ebwDHXsaHekWms6DPcWjZlrjhgoJLcjvJdJED8HbxN1gTXVzCcvJQr4w9bmv3
         KjfhONh6Da84yYHSv8b7faH+kgsdJbhYrDpHiK3alW/9XvINutqj8DfpewQm105DXoBr
         IgfzHomjZkA9rUiAqT8CyWY5s30d8BNPjiqyubHq95RncQ3HPQYxTdzwt/Uof/lFcT00
         yx7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NrkdT69+HRQ+jkiSJm1gTWd8VCmI5nm8bMcC22jnr70=;
        fh=qYQGjuITtKbBN7In6/J2nazN758xAXc42ISgWCGJOf8=;
        b=Jp8MdKw2XegL8xyxJDegfNAbiaboNedYaLvpgTc6BJTuVeXzBT306oiqcHxsQIpqUI
         25xjH0KWc4wAQvL+4aXnLFNl+KqyxYKozkmN1JU1yfIz/1aSw57EcP2f8/Ip8+ljmD1/
         oObZcYD0VHb7AHCinmkjInTuaJrd+hJHDL0/jpI1d4a7guLbf72PjvhHVxIjYKR/MlYt
         QscEE3e8zBtNuF0XJBWiejrlSeiopNrBBgu7txo6G+XxGa4fwSt2oIdsS/snxEKdgqRZ
         UZCNz18ybuOot1cNta4XoUrQ1qKc4xjoZ8Tjo29IgCEK7pU5C/1meEkvLlhD+Ih9N9aM
         zsig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="jFwlce/5";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885568; x=1711490368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NrkdT69+HRQ+jkiSJm1gTWd8VCmI5nm8bMcC22jnr70=;
        b=tcxqgDWvedxr++UnQQBUzX6WA430Hs+mNsd6M1X7lSqqGy9kP8KurU3wAhfO2fndv+
         W8V6PaQF0QxZXjow48LPWUrWesQrpvYkKNt9Bn91at1dpCs/gvHEeu69c9+x4Cs9uTMu
         tHGsQsA52JjKSLZ6H4j6V9ikd8z+TZhEEZUAQon5m9CANHjDGrNWNzVv+vgaDBwMIVIA
         mnlUK53FOW6pnzPLKvs0+u6KYUhpOLzgpd4tlrrAl18eU+64dm+VLx1uRGDxhsa4BlWw
         LUxc16dOexPh69ok6zC4i6jYBOeIBiccGc1o3L8t0n6hO1myEHAIwEzAxDxbqDFdfRZR
         SG/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885568; x=1711490368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NrkdT69+HRQ+jkiSJm1gTWd8VCmI5nm8bMcC22jnr70=;
        b=hAOvzgY6NdoBSoMRZr2ZwFoNkqSOw2Ed77/ZwzoH9F52bX7n4xeOxmzMEbtTzqrQ5U
         0zAA3IsyzljbDGCJQTA/4oHwOS4CN8FCkPb1zG5JEmx/tmgEj8+1wWmG9Y+3nu5iCzg7
         duOUPylqi+/RPEDA09z4Zih53n1xvw36TcloCh5+e2jgjATUB3IZdxrqM617H5D8IqJc
         TiAVM2JqixhD4SWwdmZLo+fkptWadUkU7xISYdSH7sFLjN/NbLJmsOr3kuIizB2rCmO7
         J+t8ZL8+Y87KvIDiPjrAK0AElvyW/r7NLzdZS0g0jXaqivthENZasr6zKV0xGNp4diUs
         MMLw==
X-Forwarded-Encrypted: i=2; AJvYcCVTRZAFoOWxec2A1r2mElZosAVwuN9v0EdHpG+MYtaDLKbLtpXrdQ89anVBJdUOSeyvO6ks+/U7iTJdR5ePO27JPNChfirjGA==
X-Gm-Message-State: AOJu0YzJcVzqOHsUilveZpYGNdigw8wnb/XeAm6GBXqltJ2oW9kbe9l+
	RQUQAPciPHBy3BnKc7NalylT13FhgZV4dEAIs/CzLzx1B3aq6i3g
X-Google-Smtp-Source: AGHT+IHgmGCncqpuZi138Rt7Sz3owghxTpq6ay5oWysWxKkKnPipHJgjMKVwdc/CZYOWHIXDqRryWA==
X-Received: by 2002:a05:6808:3c4a:b0:3c3:804e:547e with SMTP id gl10-20020a0568083c4a00b003c3804e547emr11729312oib.22.1710885568405;
        Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d41:0:b0:430:8d9e:5847 with SMTP id g1-20020ac85d41000000b004308d9e5847ls5712917qtx.0.-pod-prod-03-us;
 Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzuIdYri3DJS0ubuBEx3iargDhzd6XR7pngQFxjTDhZzXObSjZByLbxn2PHKSky+sEH2Lpt4ftRXbPQ6mwOqicDOjHUS/TXSKeoA==
X-Received: by 2002:a67:f246:0:b0:473:a00:faff with SMTP id y6-20020a67f246000000b004730a00faffmr12854760vsm.27.1710885567700;
        Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885567; cv=none;
        d=google.com; s=arc-20160816;
        b=vKUQyAwmgkqItSZDH/026QSdlWcRIClZVXKy0IK5ZdMIk7rEwbnvJH+UvEiKQc5H5W
         sY0uqSGMHUE4gfQJeeWkm1sdnZ8XDtELjI8qU0qb5ThN/wzll1FBYiz6tWn5J9kRf4I5
         OlqeG8nPlw7kF/73O10oNuc7gQ0cQueP+a/K1fwK3qQuEVDtaipgWqaEWwT+hERhtuIB
         KkRZfP9NHZT3MtO6zxIV2rkI7AvJlnL/3L+OtrxLxXXX9SQgk4t7HAhv8QqZ19RkGWZV
         X0YpPUqK+xtT/OqPZJSwSj3xM3QxCTt8exajHOt16ipKT+DV0NS/MOEHDwD/OUrGjQ0O
         fbOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=//J7AYtv61iHxtKJQn3MiSxiIHpG2s0TTUnDmfuJahA=;
        fh=aGaVJ4Y/qoeTzDOub+HiWewojMllX+Jn5YgDjbq3wL8=;
        b=K+G0oJ4g2ItuPNgqbLFSK3WMbocuyU0AVn0LwsYW4Ax6173LghLCiTsJCUsH7iYPTh
         dzShce/X7wtRIWL4/SIG0IB32wGRntOV4VQxZIh86U3As7Gqg30OF6DucPj42xkX6Bhq
         i27LAch2k8Q95zjv4FBNJFcQ0NitT4ZofIKXTIStaXQHtJLfSI+XASXYW8ud6VRld6D2
         XZ9hyEemtR8IuzvSky9ADWG5eqbtQwEScIpUXnx+gj8GSqUFjGYy6pBmo4TCk8l/tuG2
         hdT+TfCfcqlHu/k3lflV6IuCEUKf6nyK8+Jn5D7dEvpOVsjDCsIGDySgBNjqKwK2Qr0y
         z8rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="jFwlce/5";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id r5-20020a67ef85000000b00474d2ccf7c1si1323885vsp.1.2024.03.19.14.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-6e782e955adso75014b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXluobhjnvj6E/J1wVjHWHN+k9+Z5iRERHUB/KpYfPGR5zFerAf2y9QGR9BPbQWvS4LaHsem4iY3BhUVkTxutWqNFXQpfJhYaSYWA==
X-Received: by 2002:a05:6a00:2447:b0:6e6:aae6:acfe with SMTP id d7-20020a056a00244700b006e6aae6acfemr19345714pfj.23.1710885565732;
        Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Greentime Hu <greentime.hu@sifive.com>
Subject: [RFC PATCH 7/9] riscv: Add support for the tagged address ABI
Date: Tue, 19 Mar 2024 14:58:33 -0700
Message-ID: <20240319215915.832127-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="jFwlce/5";       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
software untagging in the uaccess routines is required because U-mode
and S-mode have entirely separate pointer masking configurations.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/include/asm/processor.h |  1 +
 arch/riscv/include/asm/uaccess.h   | 40 +++++++++++++++++++++---
 arch/riscv/kernel/process.c        | 49 +++++++++++++++++++++++++++++-
 3 files changed, 84 insertions(+), 6 deletions(-)

diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
index 64b34e839802..cdc8569b2118 100644
--- a/arch/riscv/include/asm/processor.h
+++ b/arch/riscv/include/asm/processor.h
@@ -124,6 +124,7 @@ struct thread_struct {
 	struct __riscv_v_ext_state vstate;
 	unsigned long align_ctl;
 	struct __riscv_v_ext_state kernel_vstate;
+	u8 pmlen;
 };
 
 /* Whitelist the fstate from the task_struct for hardened usercopy */
diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
index ec0cab9fbddd..ed282dcf9a6d 100644
--- a/arch/riscv/include/asm/uaccess.h
+++ b/arch/riscv/include/asm/uaccess.h
@@ -9,8 +9,38 @@
 #define _ASM_RISCV_UACCESS_H
 
 #include <asm/asm-extable.h>
+#include <asm/cpufeature.h>
 #include <asm/pgtable.h>		/* for TASK_SIZE */
 
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+static inline unsigned long __untagged_addr(unsigned long addr)
+{
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SxNPM)) {
+		u8 shift = current->thread.pmlen;
+
+		/*
+		 * Virtual addresses are sign-extended, while
+		 * physical addresses are zero-extended.
+		 */
+		if (IS_ENABLED(CONFIG_MMU))
+			return (long)(addr << shift) >> shift;
+		else
+			return (addr << shift) >> shift;
+	}
+
+	return addr;
+}
+
+#define untagged_addr(addr) ({					\
+	unsigned long __addr = (__force unsigned long)(addr);	\
+	(__force __typeof__(addr))__untagged_addr(__addr);	\
+})
+
+#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), size))
+#else
+#define untagged_addr(addr) addr
+#endif
+
 /*
  * User space memory access functions
  */
@@ -130,7 +160,7 @@ do {								\
  */
 #define __get_user(x, ptr)					\
 ({								\
-	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
+	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
 	long __gu_err = 0;					\
 								\
 	__chk_user_ptr(__gu_ptr);				\
@@ -246,7 +276,7 @@ do {								\
  */
 #define __put_user(x, ptr)					\
 ({								\
-	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
+	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
 	__typeof__(*__gu_ptr) __val = (x);			\
 	long __pu_err = 0;					\
 								\
@@ -293,13 +323,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
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
@@ -314,7 +344,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
 {
 	might_fault();
 	return access_ok(to, n) ?
-		__clear_user(to, n) : n;
+		__clear_user(untagged_addr(to), n) : n;
 }
 
 #define __get_kernel_nofault(dst, src, type, err_label)			\
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index 3578e75f4aa4..36129040b7bd 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -162,6 +162,7 @@ static void flush_tagged_addr_state(void)
 		return;
 
 	current->thread.envcfg &= ~ENVCFG_PMM;
+	current->thread.pmlen = 0;
 
 	sync_envcfg(current);
 #endif
@@ -255,9 +256,14 @@ void __init arch_task_cache_init(void)
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
 	u8 pmlen;
 
@@ -288,12 +294,25 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
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
 	task->thread.envcfg &= ~ENVCFG_PMM;
 	if (pmlen == 7)
 		task->thread.envcfg |= ENVCFG_PMM_PMLEN_7;
 	else if (pmlen == 16)
 		task->thread.envcfg |= ENVCFG_PMM_PMLEN_16;
 
+	if (arg & PR_TAGGED_ADDR_ENABLE)
+		task->thread.pmlen = pmlen;
+	else
+		task->thread.pmlen = 0;
+
 	if (task == current)
 		sync_envcfg(current);
 
@@ -308,6 +327,13 @@ long get_tagged_addr_ctrl(struct task_struct *task)
 	if (is_compat_thread(ti))
 		return -EINVAL;
 
+	if (task->thread.pmlen)
+		ret = PR_TAGGED_ADDR_ENABLE;
+
+	/*
+	 * The task's pmlen is only set if the tagged address ABI is enabled,
+	 * so the effective PMLEN must be extracted from envcfg.PMM.
+	 */
 	switch (task->thread.envcfg & ENVCFG_PMM) {
 	case ENVCFG_PMM_PMLEN_7:
 		ret |= FIELD_PREP(PR_PMLEN_MASK, 7);
@@ -326,6 +352,24 @@ static bool try_to_set_pmm(unsigned long value)
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
 	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SxNPM))
@@ -339,6 +383,9 @@ static int __init tagged_addr_init(void)
 	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
 	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
 
+	if (!register_sysctl("abi", tagged_addr_sysctl_table))
+		return -EINVAL;
+
 	return 0;
 }
 core_initcall(tagged_addr_init);
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-8-samuel.holland%40sifive.com.
