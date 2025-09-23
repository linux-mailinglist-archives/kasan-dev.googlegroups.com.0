Return-Path: <kasan-dev+bncBDB3VRFH7QKRBP53ZPDAMGQE7DW6HGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 85D52B971A7
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:53 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b7ad72bc9fsf127155481cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649792; cv=pass;
        d=google.com; s=arc-20240605;
        b=RWzigCDrzpUb60g2BXXN4PNxGsrdRaASPHQPLTPBLjUezvbjt3PaJ+UuDbYV8dZoNj
         35blviTfoXTPSJ7kbUTNIC7/YxlUUoDJSgYeURHMQy0MocTiJ9jKSe3ceRzpUbVu7kT8
         QiokJXxmBRB45Uwub2M0TtlAx/RqjbT6S1+TvL+1yvpbYq4JY0DSfNZfktr7ccMpFFR8
         N3mbDHt2aF07bbIAGH1MLJoEzWE1YRW5DWi2YaBl37DdaDBf/TbdXaUGhsvaLhHULx93
         KsMIPwYwdd6NU7YSqjwa7gsi7Cwb9jArmtD6vvgQZDLslq73BnDC9KejOK/t68JJlPh+
         ZS0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DED4ALTC1arP1LIuXsB6696RKg2aKgLD77a3cUoRhOA=;
        fh=nuxztUdMZ3uRrw2pjFMLZUi54vOC7FgAKo52XJtgvH8=;
        b=QAFzXhLuGVbeEvwvqP/pnYwGngAdLvEZ7jApfvUA7P+YHgJz00me/Uy6h7QS5kFuln
         107iWJJhFvmYaLZ7ckK+hHPTby3iRmIGt0P2uV4BH+qLTcAu07uGSJKzUq1+1QM38GVn
         sOfAo8h1O9lc1pnaNSgt6F0LIZ27trIZuROke15rBikel5wXiwXmjYOWMcFDL4PQKgWH
         pZlApEPk3T6Y8C6yYF82pg+Soaq+Sw5ww8E7H0PAaqf1NMibDME/GG+Yysn6o7b3Hvd2
         FQw1r/9mGYqag5I9IgUC0zDT7gc+swgMKcYg9muTe07KpaegKWOESOuT/DYmncx+/iYs
         fqJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649792; x=1759254592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DED4ALTC1arP1LIuXsB6696RKg2aKgLD77a3cUoRhOA=;
        b=C9+Qr6sUOy7TO6eKZ2YsjkUB4mYyBrkZbvy3jfmALsoTlsbC+8OsT7Aspc9+0XUR/W
         6w4iWQI9KJb/LXxj9t1fPfh2ENpvpIZOCmAsAVJ4RPdv6aDP62N+Lhp6GTCxaUtDzJ79
         UTUBL5W+DbNcChQ0D7vYSe/lpXTXM7iDq4ALiiIgXyd8kRS90VFkT/LkrcTlI6IuoHJ8
         OJHOrc8MChUO4dwDTSzON31h5Q5Z+TiwR2e457MGlljMlfIZOzJqyvDw9w3CKKUJfTmq
         qvSw86TJCh7zmHnIIebdRzcm5zKxkk+cjKmVJdEnYWsYd8siSywNln1d8NHWBrMLSO9Y
         3K7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649792; x=1759254592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DED4ALTC1arP1LIuXsB6696RKg2aKgLD77a3cUoRhOA=;
        b=DZCRm9rlOMYMv3GtvpZP8lHveu027lYkhifbn0dbEBYdncsMDF+kcFjFEpL7noHy3u
         IOLZxOjajNxtLACsp0hCq61baoAHBMk7JVILrK0RRZQN6DcMxKdOZVH0Pl7kdOrU7u1I
         H3B7WqzWoIxvOqwlhT3/+zIl1CU36rFuVSvNYCQW8DGJpg26ZpERrcb8n3OufckmS+tX
         JGo+qn/S6+AjjH6QYBPS2SvGhuwMQCHJ2XTcQAaEag7rNUc0f4euyZSLwR8zkt7AKajZ
         5mKuQGDRJcLhzMsTgmMgQBk8sx3722I6MG7la/sZzXPnz9hDL//HSoEd34HKDbk7J9Xk
         zq5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5oX352pqItJ1m6+ubVVfyKb1AWT/ktmKm1UlhaqZlROMAL9heC984Ojk768aAVPV2OMDZHA==@lfdr.de
X-Gm-Message-State: AOJu0Yy06wcnW/Kbr/Ukwc6jkoGfDDmY3tyHram1ocq5oSRNrdE6MrdE
	LpRjz9xBQ8xsh/X9Mm5uiSHeGH7JJv7a/bx8WBX7CXJ5lwtctwOjMx+4
X-Google-Smtp-Source: AGHT+IGvOxl1ga0miHEUTNTOdm1iYbom4JSKZQs/Ez74ox+QY1q1STJgAvZvOCVoM2jBvZleJ22vYg==
X-Received: by 2002:ac8:7e81:0:b0:4b5:f5ab:941e with SMTP id d75a77b69052e-4d36fc029e2mr34291031cf.51.1758649791964;
        Tue, 23 Sep 2025 10:49:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4u/BLB3zyhFsz0G8c+jN3hg8BfrxN3HGsgZ2aXnxCDDA==
Received: by 2002:a05:622a:4b0b:b0:4d6:c3a2:e1c6 with SMTP id
 d75a77b69052e-4d6c3a2e875ls8138361cf.2.-pod-prod-02-us; Tue, 23 Sep 2025
 10:49:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDILebbTSg6UDGk9p+apvxW5IC5xLVaLIytH9yVb94VKBUsW8+XHj5hmi5y3orVKDMeP7z5HPaeQU=@googlegroups.com
X-Received: by 2002:a05:620a:1aa9:b0:84d:319b:ec8d with SMTP id af79cd13be357-8516d72319dmr432351385a.3.1758649788318;
        Tue, 23 Sep 2025 10:49:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649788; cv=none;
        d=google.com; s=arc-20240605;
        b=Qf2o0Zj6O4TZStjwMy0+gx1vNwWaAhfFyC8dE66mpX++k95mAAj1y+/3tAk8siwP/U
         LsG7gd2W57X+jtDiDGKR5qOGmrgkjxrXoDySglBDi2B/H/I+tuhW9xFNUJkIRDDHlhLy
         G7xtwmrlv897LTYCRh+E6mVAdUQwpG9hhtucuX+hzbCyXduU6fAeaJu9CIzIvHzC1FR/
         itw61fkKXSmwaib404xDBTXEf1nNTr0IYwEbJ8BTgVy+I1/ypsTHznRIMNpG3Sd2Z3h1
         FGD4kn1Pu74CBL+0mGY5hM/C1Pr8DvUEVKD5LvhRqUPC3U4dnc4BUTUbe+v7z5pZHAqG
         3rCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=bCyeH+Se1Xlslcg+YrHByFgUbYZ2PyipV94Q/KGVar0=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=lUmRshgREVp//LKdJCX/0bUrwLpAn2eEsiBwPmLn4kkAoli3ejXiBkaIy6AP7GafxE
         O5NsT/BDiJY6ivNi39ufBxPqSmAbE1MNba4B/9ke7QLC+6avEzSOXooNi/pPz4eoWh2+
         0m2e1yuSuH3HeJWHcX6eHH4IS3SV+dJ1nEDkrms9znedeVziiORyCyrmCn8bu1QL3woA
         Eehrg7Ct3JlmrLYwkeZzDMy2agtyLfHHpr03L+tyHiaKL00v1zSK5sI5rGGk6Z/3Mnbp
         1upb9Pt03sPfkIppXaOIWaf0p5MMBxIDBgRxz2rHQJhVL3P0HjATgN4FRKXoqqXyg+p3
         1TKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-84b53c91cc5si22355985a.1.2025.09.23.10.49.48
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 86C7D497;
	Tue, 23 Sep 2025 10:49:39 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 4E63D3F5A1;
	Tue, 23 Sep 2025 10:49:44 -0700 (PDT)
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
Subject: [RFC PATCH 08/16] arm64/insn: always inline aarch64_insn_gen_logical_immediate()
Date: Tue, 23 Sep 2025 18:48:55 +0100
Message-ID: <20250923174903.76283-9-ada.coupriediaz@arm.com>
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

As it is always called with an explicit logic instruction type, we can
check for its validity at compile time and remove the runtime error print.

Pull its helper functions, `aarch64_encode_immediate()` and
`range_of_ones()`, into the header and make them `__always_inline`
as well.
This is safe as they only call other `__always_inline` functions.

This makes `aarch64_insn_gen_logical_immediate()` safe for inlining
and usage from patching callbacks.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 149 ++++++++++++++++++++++++++++++++--
 arch/arm64/lib/insn.c         | 136 -------------------------------
 2 files changed, 144 insertions(+), 141 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 5a25e311717f..a94ecc9140f1 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -16,6 +16,8 @@
 
 #ifndef __ASSEMBLY__
 
+#include <linux/bitops.h>
+
 enum aarch64_insn_hint_cr_op {
 	AARCH64_INSN_HINT_NOP	= 0x0 << 5,
 	AARCH64_INSN_HINT_YIELD	= 0x1 << 5,
@@ -880,11 +882,148 @@ u32 aarch64_insn_gen_logical_shifted_reg(enum aarch64_insn_register dst,
 u32 aarch64_insn_gen_move_reg(enum aarch64_insn_register dst,
 			      enum aarch64_insn_register src,
 			      enum aarch64_insn_variant variant);
-u32 aarch64_insn_gen_logical_immediate(enum aarch64_insn_logic_type type,
-				       enum aarch64_insn_variant variant,
-				       enum aarch64_insn_register Rn,
-				       enum aarch64_insn_register Rd,
-				       u64 imm);
+
+static __always_inline bool range_of_ones(u64 val)
+{
+	/* Doesn't handle full ones or full zeroes */
+	u64 sval = val >> __ffs64(val);
+
+	/* One of Sean Eron Anderson's bithack tricks */
+	return ((sval + 1) & (sval)) == 0;
+}
+
+static __always_inline u32 aarch64_encode_immediate(u64 imm,
+				 enum aarch64_insn_variant variant,
+				 u32 insn)
+{
+	unsigned int immr, imms, n, ones, ror, esz, tmp;
+	u64 mask;
+
+	switch (variant) {
+	case AARCH64_INSN_VARIANT_32BIT:
+		esz = 32;
+		break;
+	case AARCH64_INSN_VARIANT_64BIT:
+		insn |= AARCH64_INSN_SF_BIT;
+		esz = 64;
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	mask = GENMASK(esz - 1, 0);
+
+	/* Can't encode full zeroes, full ones, or value wider than the mask */
+	if (!imm || imm == mask || imm & ~mask)
+		return AARCH64_BREAK_FAULT;
+
+	/*
+	 * Inverse of Replicate(). Try to spot a repeating pattern
+	 * with a pow2 stride.
+	 */
+	for (tmp = esz / 2; tmp >= 2; tmp /= 2) {
+		u64 emask = BIT(tmp) - 1;
+
+		if ((imm & emask) != ((imm >> tmp) & emask))
+			break;
+
+		esz = tmp;
+		mask = emask;
+	}
+
+	/* N is only set if we're encoding a 64bit value */
+	n = esz == 64;
+
+	/* Trim imm to the element size */
+	imm &= mask;
+
+	/* That's how many ones we need to encode */
+	ones = hweight64(imm);
+
+	/*
+	 * imms is set to (ones - 1), prefixed with a string of ones
+	 * and a zero if they fit. Cap it to 6 bits.
+	 */
+	imms  = ones - 1;
+	imms |= 0xf << ffs(esz);
+	imms &= BIT(6) - 1;
+
+	/* Compute the rotation */
+	if (range_of_ones(imm)) {
+		/*
+		 * Pattern: 0..01..10..0
+		 *
+		 * Compute how many rotate we need to align it right
+		 */
+		ror = __ffs64(imm);
+	} else {
+		/*
+		 * Pattern: 0..01..10..01..1
+		 *
+		 * Fill the unused top bits with ones, and check if
+		 * the result is a valid immediate (all ones with a
+		 * contiguous ranges of zeroes).
+		 */
+		imm |= ~mask;
+		if (!range_of_ones(~imm))
+			return AARCH64_BREAK_FAULT;
+
+		/*
+		 * Compute the rotation to get a continuous set of
+		 * ones, with the first bit set at position 0
+		 */
+		ror = fls64(~imm);
+	}
+
+	/*
+	 * immr is the number of bits we need to rotate back to the
+	 * original set of ones. Note that this is relative to the
+	 * element size...
+	 */
+	immr = (esz - ror) % esz;
+
+	insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_N, insn, n);
+	insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_R, insn, immr);
+	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, imms);
+}
+
+static __always_inline u32 aarch64_insn_gen_logical_immediate(
+					 enum aarch64_insn_logic_type type,
+					 enum aarch64_insn_variant variant,
+					 enum aarch64_insn_register Rn,
+					 enum aarch64_insn_register Rd,
+					 u64 imm)
+{
+	compiletime_assert(type == AARCH64_INSN_LOGIC_AND ||
+		type == AARCH64_INSN_LOGIC_ORR ||
+		type == AARCH64_INSN_LOGIC_EOR ||
+		type == AARCH64_INSN_LOGIC_AND_SETFLAGS,
+		"unknown logical encoding");
+	u32 insn;
+
+	switch (type) {
+	case AARCH64_INSN_LOGIC_AND:
+		insn = aarch64_insn_get_and_imm_value();
+		break;
+	case AARCH64_INSN_LOGIC_ORR:
+		insn = aarch64_insn_get_orr_imm_value();
+		break;
+	case AARCH64_INSN_LOGIC_EOR:
+		insn = aarch64_insn_get_eor_imm_value();
+		break;
+	case AARCH64_INSN_LOGIC_AND_SETFLAGS:
+		insn = aarch64_insn_get_ands_imm_value();
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, Rd);
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, Rn);
+	return aarch64_encode_immediate(imm, variant, insn);
+}
+
+
 u32 aarch64_insn_gen_extr(enum aarch64_insn_variant variant,
 			  enum aarch64_insn_register Rm,
 			  enum aarch64_insn_register Rn,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 7530d51f9b2a..15634094de05 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -1106,142 +1106,6 @@ u32 aarch32_insn_mcr_extract_crm(u32 insn)
 	return insn & CRM_MASK;
 }
 
-static bool range_of_ones(u64 val)
-{
-	/* Doesn't handle full ones or full zeroes */
-	u64 sval = val >> __ffs64(val);
-
-	/* One of Sean Eron Anderson's bithack tricks */
-	return ((sval + 1) & (sval)) == 0;
-}
-
-static u32 aarch64_encode_immediate(u64 imm,
-				    enum aarch64_insn_variant variant,
-				    u32 insn)
-{
-	unsigned int immr, imms, n, ones, ror, esz, tmp;
-	u64 mask;
-
-	switch (variant) {
-	case AARCH64_INSN_VARIANT_32BIT:
-		esz = 32;
-		break;
-	case AARCH64_INSN_VARIANT_64BIT:
-		insn |= AARCH64_INSN_SF_BIT;
-		esz = 64;
-		break;
-	default:
-		pr_err("%s: unknown variant encoding %d\n", __func__, variant);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	mask = GENMASK(esz - 1, 0);
-
-	/* Can't encode full zeroes, full ones, or value wider than the mask */
-	if (!imm || imm == mask || imm & ~mask)
-		return AARCH64_BREAK_FAULT;
-
-	/*
-	 * Inverse of Replicate(). Try to spot a repeating pattern
-	 * with a pow2 stride.
-	 */
-	for (tmp = esz / 2; tmp >= 2; tmp /= 2) {
-		u64 emask = BIT(tmp) - 1;
-
-		if ((imm & emask) != ((imm >> tmp) & emask))
-			break;
-
-		esz = tmp;
-		mask = emask;
-	}
-
-	/* N is only set if we're encoding a 64bit value */
-	n = esz == 64;
-
-	/* Trim imm to the element size */
-	imm &= mask;
-
-	/* That's how many ones we need to encode */
-	ones = hweight64(imm);
-
-	/*
-	 * imms is set to (ones - 1), prefixed with a string of ones
-	 * and a zero if they fit. Cap it to 6 bits.
-	 */
-	imms  = ones - 1;
-	imms |= 0xf << ffs(esz);
-	imms &= BIT(6) - 1;
-
-	/* Compute the rotation */
-	if (range_of_ones(imm)) {
-		/*
-		 * Pattern: 0..01..10..0
-		 *
-		 * Compute how many rotate we need to align it right
-		 */
-		ror = __ffs64(imm);
-	} else {
-		/*
-		 * Pattern: 0..01..10..01..1
-		 *
-		 * Fill the unused top bits with ones, and check if
-		 * the result is a valid immediate (all ones with a
-		 * contiguous ranges of zeroes).
-		 */
-		imm |= ~mask;
-		if (!range_of_ones(~imm))
-			return AARCH64_BREAK_FAULT;
-
-		/*
-		 * Compute the rotation to get a continuous set of
-		 * ones, with the first bit set at position 0
-		 */
-		ror = fls64(~imm);
-	}
-
-	/*
-	 * immr is the number of bits we need to rotate back to the
-	 * original set of ones. Note that this is relative to the
-	 * element size...
-	 */
-	immr = (esz - ror) % esz;
-
-	insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_N, insn, n);
-	insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_R, insn, immr);
-	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, imms);
-}
-
-u32 aarch64_insn_gen_logical_immediate(enum aarch64_insn_logic_type type,
-				       enum aarch64_insn_variant variant,
-				       enum aarch64_insn_register Rn,
-				       enum aarch64_insn_register Rd,
-				       u64 imm)
-{
-	u32 insn;
-
-	switch (type) {
-	case AARCH64_INSN_LOGIC_AND:
-		insn = aarch64_insn_get_and_imm_value();
-		break;
-	case AARCH64_INSN_LOGIC_ORR:
-		insn = aarch64_insn_get_orr_imm_value();
-		break;
-	case AARCH64_INSN_LOGIC_EOR:
-		insn = aarch64_insn_get_eor_imm_value();
-		break;
-	case AARCH64_INSN_LOGIC_AND_SETFLAGS:
-		insn = aarch64_insn_get_ands_imm_value();
-		break;
-	default:
-		pr_err("%s: unknown logical encoding %d\n", __func__, type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, Rd);
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, Rn);
-	return aarch64_encode_immediate(imm, variant, insn);
-}
-
 u32 aarch64_insn_gen_extr(enum aarch64_insn_variant variant,
 			  enum aarch64_insn_register Rm,
 			  enum aarch64_insn_register Rn,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-9-ada.coupriediaz%40arm.com.
