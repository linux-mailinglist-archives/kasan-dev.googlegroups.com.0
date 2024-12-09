Return-Path: <kasan-dev+bncBAABB3NS3G5AMGQERDG364A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AC8F9E894B
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2024 03:44:00 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5f1d3fb6bb0sf1067684eaf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2024 18:44:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733712239; cv=pass;
        d=google.com; s=arc-20240605;
        b=JMJ+NYyALHYdi2cmfayUVyuG+EbuqLWEoqBbchVayDk6IRKb7HgH6iFwKW+6s5ID/7
         ykih1366iH7sHGtHzOaXUAr2p3eDhyvgK7iBBg5hcfjlxG9S4V+pUonEOsBkVMGmbZDd
         rn2EdVff0NKPb1RpVRbdk/3FJ488gGZYTu/1EUM09Qk1MtWxrIfmskG8X+RM+DryHyfn
         uU/64q7IKW9wDZE17xE66pCmPdb/hWA35nZIA1vZtajhQXhgmn6W5aK16RsKCNe8rTOx
         0ofBA2gP8PRSvsuVTn6Sn6XCXP4S/lB7f/mIn4Mnf0DJYGZLZO3527NdVg4GTRHxA3b8
         MHyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=s4jRo5Jrn9ncYimSI1iny485tkeYHoEndVWlRfmhTDI=;
        fh=/bk7Yw70yNbHjlUnQF7wgDJkoIyfECd2NzO6LfO7BJg=;
        b=DjcjO/ZChfEbybMvlsdo/YAoJERYD2+6uOOLLjYbyJ/CiDqhpunpar4wO4EnRO3+Dp
         t2sOYBbN0e3nB8p9kWBBLlfrnkqDYv1pOJCqiuN6GRrkBEs+AFEWZZ9EHm9OCXds2+fv
         9tN2aZ/uTtF+bqj+mocjkZ4rwPc8bjotdMCJNzN7cuZ3lxyN81y2pm2Sk1IY9sFL5OlI
         Pbwv+6ruTro3aMN/XEmyFdIjtNf9jD2jJ0ugdjtV5IftlTX9JXCJmx+r6uiNho2ox5u8
         klAqtWtcumMTlgU7sbxe2OIMOBp+9euyaUJi5URLYIEWl4TO+3tvbsgd6YcDAbCExpje
         y8ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733712239; x=1734317039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=s4jRo5Jrn9ncYimSI1iny485tkeYHoEndVWlRfmhTDI=;
        b=nMrZGjVi8RY5/U/ktn1acXuKmggofxwWzhSltKR+79HZ6h5tbRQ+SNE6E/KN5N1liS
         YgfPM5uPoCLWI1qOtPN1H2jH1vEqYGxR00O9ymnvkSCc15eTHG9eVTCmKObgPRu3ewP9
         Vkj/Isi6oLWKGxbNaDDt2WzqDJiiMaMRZ6Lx8xcWYK7XcogCfdVQnozGoKfBV7zVkzgJ
         8h4q0N/KKFTCsbFUl3uoP4J8BZY+twMNPF/LanPGCuOk0TGU+1RNHiU1LBzOkoUNrl1V
         WiInIdXocAwm693pY3ZpNowNEhgMFwb+1Iab8Ddrt5NIUYR3JjfcOu19Qr98HFy3FB2i
         vPIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733712239; x=1734317039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s4jRo5Jrn9ncYimSI1iny485tkeYHoEndVWlRfmhTDI=;
        b=bG+K2DezMt/Tnfi18kI3/V+wSuFkB55fGeWVNZogSCjkw7/3jpVxUKZ9pesK2BBSTG
         OpIW22BJuqsP1iXanbEcwCiEFAJpFabM+qiitgmXUCyAeL8u4p7cDeDUZgYbtYrpPuRJ
         DTmnpF8RcTyylVEa95hMImxPJkqXuaa++GLGHc65DDW+tjjCDh7/pTxU/6DZ7hijgCfu
         RdDu/1AGmBLaNJXnMOPB+ey24eV7lxmyQLOf5Iyr+/pHisqUFa4I1wofurSAa+EoHn5P
         E79jcmWsUbTLOW1LQMnDELfZ5sNN2eRenI7MtepjN6JodOeocTHs+6OqJUfX58cUWifQ
         3V3w==
X-Forwarded-Encrypted: i=2; AJvYcCVaoAOB8D+E5M2iZKZ2XIZ7xKlVyiVlXm6X9abwIq9PT2TAl3EpFJYXUon1hqeTeVP/u2DcOw==@lfdr.de
X-Gm-Message-State: AOJu0YyA4YKKTELMZThhSLybIbDwOc+iuJzJ4P5Z+FvU33pTYl+4ns+6
	W7oTgHfDK6tEcszTBUp65C3oN9vIiszxANEE4QIHcfwdnQQYsgPw
X-Google-Smtp-Source: AGHT+IHG+poUjrM5rZXmq5e7xIWOwGoXO2i6tuXDzPAtLlKGbU95MB3iBdndwPBwjYhFmtb9b/2nAA==
X-Received: by 2002:a9d:7cd5:0:b0:71d:f343:5f5b with SMTP id 46e09a7af769-71df3436661mr1344143a34.12.1733712237588;
        Sun, 08 Dec 2024 18:43:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ca05:0:b0:5f2:9f45:f115 with SMTP id 006d021491bc7-5f29f45f63als230377eaf.1.-pod-prod-04-us;
 Sun, 08 Dec 2024 18:43:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAxTJnQPP6IdLz9bdtdaRa8/YtHWkW9l+gqAj18Ms25wyUQA36ONlSrM+aztHcKpoxUiBDyfAMny8=@googlegroups.com
X-Received: by 2002:a05:6830:700e:b0:71d:5f22:aff5 with SMTP id 46e09a7af769-71dcf4d05a2mr6326914a34.10.1733712236562;
        Sun, 08 Dec 2024 18:43:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733712236; cv=none;
        d=google.com; s=arc-20240605;
        b=SQXk4Mnpk6QjTB0FgFsBcDwxlR51HY2j1EATGTeaqMFQGrKUgHTAy4OdDnnvHMDVjb
         j9i/qXbo+vAAD+pbtJmxgvqRNBOzxRnK2VgZus+mxYJZhHSQ6ro4YH8HACvqv5P7VJHD
         Bx/9JBNHBc2AUX6iLVtwqMglQWhYDRnxcN5DnrsaST8g8W9PbJYCs7YN/1yCk/b5VfgM
         FUQR1hSNgNp82E6BTZfKXjPb0QUBe6/hvsDO/VSY0sKrdV0I5y2Zm7Jy/nw2sOwsYh38
         ena0knP2TFbUSdw5qLIN932ynU6GtpErAmqSivBqvvHG4EufDNjo4TJ1ticBfFtuYuZf
         UeMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=iDrZfdrMnIOWDOEvnU3lBEDaJYl49vcnJr2daN4zEaU=;
        fh=zBWha3m7j9g4fOlI2Dk54gN6qyAThRjo4Lp4VAY4w1U=;
        b=IYrYeKgRxpbj3S9B/ZxxrXikGjhBTM+0YLLxcqxANIvrDROsvE+xA+PKHu+PedQwl7
         L/RwMcCXgsdZ10KWitEEkkq7gVPf1F2+im7xp8Oq5l5TFWwDT8HhieiLi6O/i38/J1Ds
         N+B0Utl8/DiMzalOJVz40d/YhmvkcNeNrMY2TitIPrAg4dvUqvdeZSImUyVB2xqAeCIq
         CST1mshKiT4Rrw07eIWmw7pQ6+hddf40CbEkhbmm4FIZOYmOzNELoEHHj6db/t227mvg
         ApYIXgGjTYJD5LBI6vTgxwbB9d4L9BfiV3KDwdxCrU7Jd/NPx3FyQZ7qQ0ATwb5l+R0E
         /8UQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71dc4a40566si424452a34.3.2024.12.08.18.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Dec 2024 18:43:56 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from mail.maildlp.com (unknown [172.19.163.17])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4Y65l23pZpz1JDw3;
	Mon,  9 Dec 2024 10:43:10 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 23F251A0188;
	Mon,  9 Dec 2024 10:43:23 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Mon, 9 Dec 2024 10:43:21 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@Huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, Will
 Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, James
 Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Christophe
 Leroy <christophe.leroy@csgroup.eu>, Aneesh Kumar K.V
	<aneesh.kumar@kernel.org>, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Madhavan Srinivasan
	<maddy@linux.ibm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
Date: Mon, 9 Dec 2024 10:42:54 +0800
Message-ID: <20241209024257.3618492-3-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20241209024257.3618492-1-tongtiangen@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

For the arm64 kernel, when it processes hardware memory errors for
synchronize notifications(do_sea()), if the errors is consumed within the
kernel, the current processing is panic. However, it is not optimal.

Take copy_from/to_user for example, If ld* triggers a memory error, even in
kernel mode, only the associated process is affected. Killing the user
process and isolating the corrupt page is a better choice.

Add new fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR to identify insn
that can recover from memory errors triggered by access to kernel memory,
and this fixup type is used in __arch_copy_to_user(), This make the regular
copy_to_user() will handle kernel memory errors.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 arch/arm64/Kconfig                   |  1 +
 arch/arm64/include/asm/asm-extable.h | 31 +++++++++++++++++++++++-----
 arch/arm64/include/asm/asm-uaccess.h |  4 ++++
 arch/arm64/include/asm/extable.h     |  1 +
 arch/arm64/lib/copy_to_user.S        | 10 ++++-----
 arch/arm64/mm/extable.c              | 19 +++++++++++++++++
 arch/arm64/mm/fault.c                | 30 ++++++++++++++++++++-------
 7 files changed, 78 insertions(+), 18 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 100570a048c5..5fa54d31162c 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -21,6 +21,7 @@ config ARM64
 	select ARCH_ENABLE_THP_MIGRATION if TRANSPARENT_HUGEPAGE
 	select ARCH_HAS_CACHE_LINE_SIZE
 	select ARCH_HAS_CC_PLATFORM
+	select ARCH_HAS_COPY_MC if ACPI_APEI_GHES
 	select ARCH_HAS_CURRENT_STACK_POINTER
 	select ARCH_HAS_DEBUG_VIRTUAL
 	select ARCH_HAS_DEBUG_VM_PGTABLE
diff --git a/arch/arm64/include/asm/asm-extable.h b/arch/arm64/include/asm/asm-extable.h
index b8a5861dc7b7..0f9123efca0a 100644
--- a/arch/arm64/include/asm/asm-extable.h
+++ b/arch/arm64/include/asm/asm-extable.h
@@ -5,11 +5,13 @@
 #include <linux/bits.h>
 #include <asm/gpr-num.h>
 
-#define EX_TYPE_NONE			0
-#define EX_TYPE_BPF			1
-#define EX_TYPE_UACCESS_ERR_ZERO	2
-#define EX_TYPE_KACCESS_ERR_ZERO	3
-#define EX_TYPE_LOAD_UNALIGNED_ZEROPAD	4
+#define EX_TYPE_NONE				0
+#define EX_TYPE_BPF				1
+#define EX_TYPE_UACCESS_ERR_ZERO		2
+#define EX_TYPE_KACCESS_ERR_ZERO		3
+#define EX_TYPE_LOAD_UNALIGNED_ZEROPAD		4
+/* kernel access memory error safe */
+#define EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR	5
 
 /* Data fields for EX_TYPE_UACCESS_ERR_ZERO */
 #define EX_DATA_REG_ERR_SHIFT	0
@@ -51,6 +53,17 @@
 #define _ASM_EXTABLE_UACCESS(insn, fixup)				\
 	_ASM_EXTABLE_UACCESS_ERR_ZERO(insn, fixup, wzr, wzr)
 
+#define _ASM_EXTABLE_KACCESS_ERR_ZERO_MEM_ERR(insn, fixup, err, zero)	\
+	__ASM_EXTABLE_RAW(insn, fixup, 					\
+			  EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR,		\
+			  (						\
+			    EX_DATA_REG(ERR, err) |			\
+			    EX_DATA_REG(ZERO, zero)			\
+			  ))
+
+#define _ASM_EXTABLE_KACCESS_MEM_ERR(insn, fixup)			\
+	_ASM_EXTABLE_KACCESS_ERR_ZERO_MEM_ERR(insn, fixup, wzr, wzr)
+
 /*
  * Create an exception table entry for uaccess `insn`, which will branch to `fixup`
  * when an unhandled fault is taken.
@@ -69,6 +82,14 @@
 	.endif
 	.endm
 
+/*
+ * Create an exception table entry for kaccess `insn`, which will branch to
+ * `fixup` when an unhandled fault is taken.
+ */
+	.macro          _asm_extable_kaccess_mem_err, insn, fixup
+	_ASM_EXTABLE_KACCESS_MEM_ERR(\insn, \fixup)
+	.endm
+
 #else /* __ASSEMBLY__ */
 
 #include <linux/stringify.h>
diff --git a/arch/arm64/include/asm/asm-uaccess.h b/arch/arm64/include/asm/asm-uaccess.h
index 5b6efe8abeeb..19aa0180f645 100644
--- a/arch/arm64/include/asm/asm-uaccess.h
+++ b/arch/arm64/include/asm/asm-uaccess.h
@@ -57,6 +57,10 @@ alternative_else_nop_endif
 	.endm
 #endif
 
+#define KERNEL_MEM_ERR(l, x...)			\
+9999:	x;					\
+	_asm_extable_kaccess_mem_err	9999b, l
+
 #define USER(l, x...)				\
 9999:	x;					\
 	_asm_extable_uaccess	9999b, l
diff --git a/arch/arm64/include/asm/extable.h b/arch/arm64/include/asm/extable.h
index 72b0e71cc3de..bc49443bc502 100644
--- a/arch/arm64/include/asm/extable.h
+++ b/arch/arm64/include/asm/extable.h
@@ -46,4 +46,5 @@ bool ex_handler_bpf(const struct exception_table_entry *ex,
 #endif /* !CONFIG_BPF_JIT */
 
 bool fixup_exception(struct pt_regs *regs);
+bool fixup_exception_me(struct pt_regs *regs);
 #endif
diff --git a/arch/arm64/lib/copy_to_user.S b/arch/arm64/lib/copy_to_user.S
index 802231772608..bedab1678431 100644
--- a/arch/arm64/lib/copy_to_user.S
+++ b/arch/arm64/lib/copy_to_user.S
@@ -20,7 +20,7 @@
  *	x0 - bytes not copied
  */
 	.macro ldrb1 reg, ptr, val
-	ldrb  \reg, [\ptr], \val
+	KERNEL_MEM_ERR(9998f, ldrb  \reg, [\ptr], \val)
 	.endm
 
 	.macro strb1 reg, ptr, val
@@ -28,7 +28,7 @@
 	.endm
 
 	.macro ldrh1 reg, ptr, val
-	ldrh  \reg, [\ptr], \val
+	KERNEL_MEM_ERR(9998f, ldrh  \reg, [\ptr], \val)
 	.endm
 
 	.macro strh1 reg, ptr, val
@@ -36,7 +36,7 @@
 	.endm
 
 	.macro ldr1 reg, ptr, val
-	ldr \reg, [\ptr], \val
+	KERNEL_MEM_ERR(9998f, ldr \reg, [\ptr], \val)
 	.endm
 
 	.macro str1 reg, ptr, val
@@ -44,7 +44,7 @@
 	.endm
 
 	.macro ldp1 reg1, reg2, ptr, val
-	ldp \reg1, \reg2, [\ptr], \val
+	KERNEL_MEM_ERR(9998f, ldp \reg1, \reg2, [\ptr], \val)
 	.endm
 
 	.macro stp1 reg1, reg2, ptr, val
@@ -64,7 +64,7 @@ SYM_FUNC_START(__arch_copy_to_user)
 9997:	cmp	dst, dstin
 	b.ne	9998f
 	// Before being absolutely sure we couldn't copy anything, try harder
-	ldrb	tmp1w, [srcin]
+KERNEL_MEM_ERR(9998f, ldrb	tmp1w, [srcin])
 USER(9998f, sttrb tmp1w, [dst])
 	add	dst, dst, #1
 9998:	sub	x0, end, dst			// bytes not copied
diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
index 228d681a8715..9ad2b6473b60 100644
--- a/arch/arm64/mm/extable.c
+++ b/arch/arm64/mm/extable.c
@@ -72,7 +72,26 @@ bool fixup_exception(struct pt_regs *regs)
 		return ex_handler_uaccess_err_zero(ex, regs);
 	case EX_TYPE_LOAD_UNALIGNED_ZEROPAD:
 		return ex_handler_load_unaligned_zeropad(ex, regs);
+	case EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR:
+		return false;
 	}
 
 	BUG();
 }
+
+bool fixup_exception_me(struct pt_regs *regs)
+{
+	const struct exception_table_entry *ex;
+
+	ex = search_exception_tables(instruction_pointer(regs));
+	if (!ex)
+		return false;
+
+	switch (ex->type) {
+	case EX_TYPE_UACCESS_ERR_ZERO:
+	case EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR:
+		return ex_handler_uaccess_err_zero(ex, regs);
+	}
+
+	return false;
+}
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index ef63651099a9..278e67357f49 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -801,21 +801,35 @@ static int do_bad(unsigned long far, unsigned long esr, struct pt_regs *regs)
 	return 1; /* "fault" */
 }
 
+/*
+ * APEI claimed this as a firmware-first notification.
+ * Some processing deferred to task_work before ret_to_user().
+ */
+static int do_apei_claim_sea(struct pt_regs *regs)
+{
+	int ret;
+
+	ret = apei_claim_sea(regs);
+	if (ret)
+		return ret;
+
+	if (!user_mode(regs) && IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC)) {
+		if (!fixup_exception_me(regs))
+			return -ENOENT;
+	}
+
+	return ret;
+}
+
 static int do_sea(unsigned long far, unsigned long esr, struct pt_regs *regs)
 {
 	const struct fault_info *inf;
 	unsigned long siaddr;
 
-	inf = esr_to_fault_info(esr);
-
-	if (user_mode(regs) && apei_claim_sea(regs) == 0) {
-		/*
-		 * APEI claimed this as a firmware-first notification.
-		 * Some processing deferred to task_work before ret_to_user().
-		 */
+	if (do_apei_claim_sea(regs) == 0)
 		return 0;
-	}
 
+	inf = esr_to_fault_info(esr);
 	if (esr & ESR_ELx_FnV) {
 		siaddr = 0;
 	} else {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241209024257.3618492-3-tongtiangen%40huawei.com.
