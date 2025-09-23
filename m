Return-Path: <kasan-dev+bncBDB3VRFH7QKRBNN3ZPDAMGQE7AEN3FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 60240B971A1
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:44 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b5529da7771sf2779053a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649782; cv=pass;
        d=google.com; s=arc-20240605;
        b=JtGBKG4PrqJ+MoUszRL47KnJdJe9bgFbunOiJjbLsLy41h1NknXo0YxgL/ojWUaRVm
         nM3KOxZrifQLNV59fKBBqE29abvwxftqYqvc9F7NTo8u5xwoDlSZS1wZX7b+QuSoZM81
         Zq+jdDepbMzzzDNOjhutqbp1ulQszUrNC/YKTkfXIS8UwUsNXmWIyIAGXcbu7jTEJp7c
         AvEjxCT35VP0nmZKbEK64wuEKKZ+8Jd7rbzIaQ5vRZq25Hcybcp6fzVwCj3EsflRd+uK
         5ZFy7lXIN8cgHf5yC2cXZnFdFyI+hxCU2bpcBrtwSZXhfFQh+EBBRw96sTOGkUtgS8We
         M5GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YcWXJjYcWVTK5piwteBKRUwseDZjO2p9dnrvT21y7/0=;
        fh=mC7dm0Ofwv8TAxoAxlxLGFAFzj3prE3HfONyxGMRzYw=;
        b=VDtg1ou2NMv/v1wDX9W6nj+Ce4vE6UsoPUZWL1Bs4kbVjRO3M8Q4tEwoO3zkj5zpMq
         LzyhZc+Tr2dBU449Zto+IOwmyQVALdd0kp0o4NkB1YJr0ti+JQuJ3amuh5fhmUiO+Tdp
         PqWDQVkoQvZvMDtkJUyEuXcQPlx3sBfLS/z4SztIMwU9ItFE/CA7ZlfwrL8u3OTEZpi5
         NlxSxyin+GZr6PzMTYTUrc33l0djQY90KRwsJTJCOCduiUp08dcv8RIGzl3aY2a2IDg/
         WHl92pGnzW95V8ty3NWUH+6qCL+TBvrfr3JW0J4mEV0Asgjb6e/a8vfZ/To3Tzzh+f0T
         a8TQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649782; x=1759254582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YcWXJjYcWVTK5piwteBKRUwseDZjO2p9dnrvT21y7/0=;
        b=SctmLluz64OlnApmokbhJsc3rwA5pJ/fBCHAWTrm51ydSz8l9D/krJHcVV3B4PzrkF
         /z0PlnjJVMSfgTP/5BC9GsF3RgEeDy0heE8uFG+M5fCoQWcMlyp9Mfktr/1VuQ/PkETP
         BiVM5cz26ifcGjGPfCv0WGzncESJ6lvn61uPD7f1UIiXZhJdb/Q8WzQkVb8XSBTQ9FjC
         E0HZRB6uVkHp7kAeJRjxmeQG2HLUXpxi853Doiah5Cd/fJRk6QzabRMG2iZFU+YRUtq7
         +dcXA6yaWpKxJ9p3yTmvWJMJh19OPhm8dgJsKLLoXGiLxccD4pATGaaumyJ9D7mH90xB
         AlzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649782; x=1759254582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YcWXJjYcWVTK5piwteBKRUwseDZjO2p9dnrvT21y7/0=;
        b=sbXTsz+gcdl73nFNy4wNebzcEWMjQStbi10xdXq5aMO1JLWnDCebkF8+meRYVZT6jG
         sueh+ERjUzO1CvK/7N6UriQeh4fCKL9ADuFj6fTpM7WTxkgjKDETaW5cE51/4zmxlyxd
         FY880vqMKnRaRNAG4y9jf96yUFu+IlQMrU+Ml22VFrooMCitZ7JI8h5jZk+qXxvnSfH2
         s/2I0Gm6qA64uTGDJsJrWOAMb9bg+n/sUfen6Viv5Dj6uWh7l3UeZLSQUFjE/hZwHgvS
         dE1YqV0mbbzcWWwDRbxOlDmGu2PhXxkz8PwHRgKXzdT+8M8KsBfAzTvFhIn6HXPtqXmb
         BC/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSSLQ/a8fYuplhNs2NtSkxdcIY4hwkSD2C1aut4pK3gVKzhqPpiId+GP7fkENbRPKHrlSvOQ==@lfdr.de
X-Gm-Message-State: AOJu0YwMJIvN2LGjy8VPTiO3ZEtsaJqQvN01cQ68dQ5x/KdnZ68eowJW
	0gcPvBCopM7ZDiCicE6skbYDgcfYpIcZfktm4b2QU2tKnYe3in8gbM+E
X-Google-Smtp-Source: AGHT+IGHtBhu60UORsurI0Qq8XZ1c9gzByl8AG9EVzaOVjr/sNw3OfdLu7ZR+r5gKuIDaQUlnxz4Og==
X-Received: by 2002:a05:6a20:914c:b0:251:a106:d96c with SMTP id adf61e73a8af0-2cfdf479752mr5403806637.10.1758649782190;
        Tue, 23 Sep 2025 10:49:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5jVlGGvfIVd8BR0PDv94Rb59SpgNWnS7Q32E/6oXuorQ==
Received: by 2002:a05:6a00:99c:b0:772:445b:19ee with SMTP id
 d2e1a72fcca58-77d16103877ls5543482b3a.2.-pod-prod-04-us; Tue, 23 Sep 2025
 10:49:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTJa3twYSCWSrd8KqAFIOBvc55N8zzsWP/EqumXMKefXiXd1zMaz9TuXv6qbKsHGP0KVhXx3UqpvU=@googlegroups.com
X-Received: by 2002:a05:6a00:988:b0:772:823b:78a4 with SMTP id d2e1a72fcca58-77f5387ef49mr4378264b3a.13.1758649780394;
        Tue, 23 Sep 2025 10:49:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649780; cv=none;
        d=google.com; s=arc-20240605;
        b=gKpuclHPqxc7klvrqEtUTDOwqOEKF6aMX35TilKuxA9/MwRHis0Esf+yDG1binXWcL
         G6t7dy31cCF6g6H5vvKcvHq/BFxtTuNv+2EL7yD9KIazx0k95sWKq9Xw+0YOQrJbtcdh
         u0Dh7Xc3QSc4KI8pxS+1NLcr7F4aCzU/4Gc2SJkuKPg52QUY6nGPn94lK+c81nKf4Pbd
         zD8LBNcOA3F7Ou2KaUa6rOz/QHwDddufeQrdZsME+Pu/4Zsn+g9/QAihSxqedQ+udYGM
         SQyjGyxcQ4/7al1hZuRDP+8jszVWolVcqdmNmWxvScIgE/TZk3E1DHC5qY+fY8K17wv5
         t2sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ZqYibTnFM44xJTQqZ0OlXXIW0f/qrXTbbi1hnR5eil0=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=WiUMDuIefJhHOExzaDeLbffoq3I5+REyBxzSqEybeDxwG3naAdQS8Ly8sXfyry08rw
         /aMm38Nvy1sGwbyjsQunmszpzGZJF+cK8RKZYqmhDLsO7L3JLnifRIL3MzA2JNt+Espw
         6Fs4ozgmyzEwWfax31H/J1K5bf+0bnGdjTuop/yCMP89Es2ihgIJAExpnfWDMRzJ7aeM
         VqmAYndXcCoFyUikqIHw4dQhtZuNZsL1Cd8eIfhHUmChnDhEmJZi4lpGEqiG56I/R/Q9
         Le8n2W+++TdTdJ2nR9JXIxOTBiKtXU8XQpB7hX3egNhkXGPRpgnbvYcuPo5067WKcgDU
         xuyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-77f1bb6ff1fsi371819b3a.3.2025.09.23.10.49.40
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 55F86497;
	Tue, 23 Sep 2025 10:49:31 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id C991B3F5A1;
	Tue, 23 Sep 2025 10:49:35 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [RFC PATCH 06/16] arm64/insn: always inline aarch64_insn_gen_movewide()
Date: Tue, 23 Sep 2025 18:48:53 +0100
Message-ID: <20250923174903.76283-7-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250923174903.76283-1-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

As it is always called with an explicit movewide type, we can
check for its validity at compile time and remove the runtime error print.

The other error prints cannot be verified at compile time, but should not
occur in practice and will still lead to a fault BRK, so remove them.

This makes `aarch64_insn_gen_movewide()` safe for inlining
and usage from patching callbacks, as both
`aarch64_insn_encode_register()` and `aarch64_insn_encode_immediate()`
have been made safe in previous commits.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 58 ++++++++++++++++++++++++++++++++---
 arch/arm64/lib/insn.c         | 56 ---------------------------------
 2 files changed, 54 insertions(+), 60 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 5f5f6a125b4e..5a25e311717f 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -624,6 +624,8 @@ static __always_inline bool aarch64_get_imm_shift_mask(
 #define ADR_IMM_LOSHIFT		29
 #define ADR_IMM_HISHIFT		5
 
+#define AARCH64_INSN_SF_BIT	BIT(31)
+
 enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
 
@@ -796,10 +798,58 @@ u32 aarch64_insn_gen_bitfield(enum aarch64_insn_register dst,
 			      int immr, int imms,
 			      enum aarch64_insn_variant variant,
 			      enum aarch64_insn_bitfield_type type);
-u32 aarch64_insn_gen_movewide(enum aarch64_insn_register dst,
-			      int imm, int shift,
-			      enum aarch64_insn_variant variant,
-			      enum aarch64_insn_movewide_type type);
+
+static __always_inline u32 aarch64_insn_gen_movewide(
+				 enum aarch64_insn_register dst,
+				 int imm, int shift,
+				 enum aarch64_insn_variant variant,
+				 enum aarch64_insn_movewide_type type)
+{
+	compiletime_assert(type >=  AARCH64_INSN_MOVEWIDE_ZERO &&
+		type <= AARCH64_INSN_MOVEWIDE_INVERSE, "unknown movewide encoding");
+	u32 insn;
+
+	switch (type) {
+	case AARCH64_INSN_MOVEWIDE_ZERO:
+		insn = aarch64_insn_get_movz_value();
+		break;
+	case AARCH64_INSN_MOVEWIDE_KEEP:
+		insn = aarch64_insn_get_movk_value();
+		break;
+	case AARCH64_INSN_MOVEWIDE_INVERSE:
+		insn = aarch64_insn_get_movn_value();
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	if (imm & ~(SZ_64K - 1)) {
+		return AARCH64_BREAK_FAULT;
+	}
+
+	switch (variant) {
+	case AARCH64_INSN_VARIANT_32BIT:
+		if (shift != 0 && shift != 16) {
+			return AARCH64_BREAK_FAULT;
+		}
+		break;
+	case AARCH64_INSN_VARIANT_64BIT:
+		insn |= AARCH64_INSN_SF_BIT;
+		if (shift != 0 && shift != 16 && shift != 32 && shift != 48) {
+			return AARCH64_BREAK_FAULT;
+		}
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	insn |= (shift >> 4) << 21;
+
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
+
+	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn, imm);
+}
+
 u32 aarch64_insn_gen_add_sub_shifted_reg(enum aarch64_insn_register dst,
 					 enum aarch64_insn_register src,
 					 enum aarch64_insn_register reg,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index d77aef7f84f1..7530d51f9b2a 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -16,7 +16,6 @@
 #include <asm/insn.h>
 #include <asm/kprobes.h>
 
-#define AARCH64_INSN_SF_BIT	BIT(31)
 #define AARCH64_INSN_N_BIT	BIT(22)
 #define AARCH64_INSN_LSL_12	BIT(22)
 
@@ -702,61 +701,6 @@ u32 aarch64_insn_gen_bitfield(enum aarch64_insn_register dst,
 	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, imms);
 }
 
-u32 aarch64_insn_gen_movewide(enum aarch64_insn_register dst,
-			      int imm, int shift,
-			      enum aarch64_insn_variant variant,
-			      enum aarch64_insn_movewide_type type)
-{
-	u32 insn;
-
-	switch (type) {
-	case AARCH64_INSN_MOVEWIDE_ZERO:
-		insn = aarch64_insn_get_movz_value();
-		break;
-	case AARCH64_INSN_MOVEWIDE_KEEP:
-		insn = aarch64_insn_get_movk_value();
-		break;
-	case AARCH64_INSN_MOVEWIDE_INVERSE:
-		insn = aarch64_insn_get_movn_value();
-		break;
-	default:
-		pr_err("%s: unknown movewide encoding %d\n", __func__, type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	if (imm & ~(SZ_64K - 1)) {
-		pr_err("%s: invalid immediate encoding %d\n", __func__, imm);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	switch (variant) {
-	case AARCH64_INSN_VARIANT_32BIT:
-		if (shift != 0 && shift != 16) {
-			pr_err("%s: invalid shift encoding %d\n", __func__,
-			       shift);
-			return AARCH64_BREAK_FAULT;
-		}
-		break;
-	case AARCH64_INSN_VARIANT_64BIT:
-		insn |= AARCH64_INSN_SF_BIT;
-		if (shift != 0 && shift != 16 && shift != 32 && shift != 48) {
-			pr_err("%s: invalid shift encoding %d\n", __func__,
-			       shift);
-			return AARCH64_BREAK_FAULT;
-		}
-		break;
-	default:
-		pr_err("%s: unknown variant encoding %d\n", __func__, variant);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	insn |= (shift >> 4) << 21;
-
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
-
-	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn, imm);
-}
-
 u32 aarch64_insn_gen_add_sub_shifted_reg(enum aarch64_insn_register dst,
 					 enum aarch64_insn_register src,
 					 enum aarch64_insn_register reg,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-7-ada.coupriediaz%40arm.com.
