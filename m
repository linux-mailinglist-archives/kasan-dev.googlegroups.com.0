Return-Path: <kasan-dev+bncBDB3VRFH7QKRBR53ZPDAMGQEZITKUVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B925B971B3
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:01 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-277f0ea6fbasf32351165ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649800; cv=pass;
        d=google.com; s=arc-20240605;
        b=XF1fWBLlE2UUZh0szVB76wPNZsBX+ueLUNuKwuFVMfY0OuXte1klV6guekdl0jqKqh
         U+XcInyMNhk9TdDgPjXoHWXY+8Cxf+l6PB4BA1T7qyIocW07viS12O/KEQh/jQcYtxMI
         Gg256Kz/i1EZkqDzVQL7nncINFJ5B9IS80Xh+sQrkS3EMUCFdwIIC44TjnDsJu2aJn8N
         zfCZ4iBPYAUPlJliPRo8azNEWRAg2Rx5gLusoVXzt5Jr+l9til5SU02lC3W3JKdDriEa
         k2kFh4ZS4bPJ4bUk2dy1bNyB39ox82zCobwXBaGsCRQaUY9XrAninM2KGTinLVQqjX/T
         J/Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mzq2LZ/9h2WOTThqpPlz4SabKNCm+2RE0cEN6UfpTxs=;
        fh=0mhaOvuHdfpYXci7nYSX29JQErUDLgnXSuYTQ5UKtMA=;
        b=iC9bKQ79MAN/JlSV4jeRTU4YTKglD712nNd6AK6SO/KFVgfZx0bYojCVyfmcx3s6nh
         OJ+U6u5pwoJfH18/7mJx5t0jZrHV8/Xl31+oJOVpJrJESg7DZEZliNJusnfCuQivzOKw
         f0fcuv2KiXWCPfzFBgvVW8Ftl/ttsb/a8/9b8PV7mo01GMKnM8L/NXQzzA4KrnEHPevG
         sJ8GSBYUY86dBkhHCTuSZKX5Wk8NNiHxDqzGCQZ4q6KoAsZO0jCmo1z1EYNp9CN6H58k
         EewLSYuaDilYL7C8CQYwnW3Ctxyog6Dt2fcz1M9aiRTBbKUluXJ1LfILN46/zRmBHXfC
         zE3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649800; x=1759254600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mzq2LZ/9h2WOTThqpPlz4SabKNCm+2RE0cEN6UfpTxs=;
        b=uIlphZcE88sMdPG0RpmfRq9Cu4N5204EmuLFq+T/WSR0iaKBawSyOn+9GG7tLbhCGW
         fz16fkxvRCBCAjTMa95S+Ikq/pDajqXjhJ4cnwIR16JtLYCrXMd89sWFSI2Fwm0VtIxY
         V95r/ubgbWSoKVI1HXMqP3keo5B/GsgA64nRpldvN1bgZKhUhdNSXUMKVTufPZJI0uXq
         vIOgJYlZNw24Qlj0gep6CRCGhjpWpYQLbWBMesazAhI505YJGeJIDIdjHeqvOaGWPAeF
         YDDItKV6XfuBoxiK+FYH+jtsF/zI3a2CLMn/hYlcmCT4GulRm7MP7pZD6zF98dB1/Wrr
         aI8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649800; x=1759254600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Mzq2LZ/9h2WOTThqpPlz4SabKNCm+2RE0cEN6UfpTxs=;
        b=lKL6Qfye5AtK0jwBV/yKcwRdRwChwSd/szLhubbDtFdHgcVc6hvLgoHPt+a73yD3lz
         /vnHg3AnqJnA8GqH3F0DryNCMR5a7TEVRuI8jzAv8RDc8tU8uu51DPsC5Dgtlk6e8H2f
         bI8Ocmd0Rhuzk/T3650xJ04rsJXLey9PG9tUt3+HkQWsOgMEn9PYADQxZwH2lIBNziGL
         QrOC0PN/9DxYahPTQ5K/d7Ht9t9i1bgi+DJowIFkpnFV+VVrFYbOS4yz+FZzr9Syb5eM
         Ayi3z2DFhLPbVIVUkY4Ao5YMSPwELPGe1sApAge3yi5AJKq2X+uUJy9tzhg7ZWyFhwx8
         +rZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSuOkbyz4ZJ3Noho0qf7vDxd2iRGsnEI2BUEhEtel6L7uShUF6d0HlgN3kl+9Tf9mwM+AGgg==@lfdr.de
X-Gm-Message-State: AOJu0YxMgvR9VYbySnE5FYxann8NtEf3QUrrDMscahhm7LEJiSMmRHft
	ihUT3zX9t9alCtamuiGaKoS5SIEyTJ+T3QnGDgTTS5lfWS9m7m7P9K9t
X-Google-Smtp-Source: AGHT+IEGrikD3yfa65Pfbnn+8kc6qjvL3W0527DTSv28YAwqaUY41h/REsF78np0kCiNHpU7nwI2gA==
X-Received: by 2002:a17:902:c94a:b0:261:6d61:f28d with SMTP id d9443c01a7336-27cc76e1f82mr41166745ad.50.1758649799652;
        Tue, 23 Sep 2025 10:49:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6vVtNVrANIRzkNU5BANGA+7TfH0YkBsLN12hJ3pNdGIw==
Received: by 2002:a17:902:cf48:b0:264:22a1:54dd with SMTP id
 d9443c01a7336-26983ecf087ls37216825ad.0.-pod-prod-05-us; Tue, 23 Sep 2025
 10:49:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+WBlNARBrgSmCpm5Ih0aoyAis0ToGaIFMFgIrvlC65KvzRIsFzh6X5bm2b1laobVqS+OQPXGqVEM=@googlegroups.com
X-Received: by 2002:a17:902:db0e:b0:265:57dc:977b with SMTP id d9443c01a7336-27cc893ccfdmr38614915ad.61.1758649796762;
        Tue, 23 Sep 2025 10:49:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649796; cv=none;
        d=google.com; s=arc-20240605;
        b=DQr3TLOsjXiBE/y4r+sTiblA3tYavRTTVlLQUlSY7IDIJRlF6bPRM8gTIHDdjNJ1Sz
         A7B5vS9L90yP4qU38si2WHgsSn/crRB2MWvKJItN0V05jD78cdjLjIB9u4WQovaIIkoc
         2z9oosNJY0hMRquqsBeLsq2PGVOvAch7vCkg5DPgKVCwSegMyLy3HGThyD6/aHFAnyvE
         NqZCsu8kbRM3B1P8R/CPex6znRDhLxXn3ITzNNJaWmnB0K+7Ufw9I7haeoyJuwQsHVuO
         5g6ooNx2W6AK/Z2+nNH30ajt9jdgO9ySmOPG26dtZ+97okULQMnS3/oQeU/O8gmERiZ9
         JkrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=G7798F5nvon41Gu2d4tw9US7KiO03/UTTHZY2BNPbcU=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=CiSySTCw630qVZ/2/YEj1149zQWMNzgK+YnTCdG5OIETbV9Ihfev4tbzVW4jYS8AT2
         jnKiK+cec6yIU8c4QPpefU2Vllqgqf2StlPzjMAHdwHncplpRNtvHDrYD0TXmIPgU67G
         gVbyIU8jndg16t83xouFA/Z/eKecEx3YhKdbCGvXxDmOpi9iDWXw7l6fs++FQN5H7TEQ
         MiwGkX2gW1kUDU9dp8k+Xw7NAsUd89HuQ4nxh8Xft5OvISURZHCCn6yC5W+BV7fTphgy
         Ivotsh63HXKr7OF1Q3D8Rs4rH10q2HFgtof5EWUapwttl+YybE39kWLa4JeZ7+JdLiRa
         QnIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-2698028069esi6607245ad.7.2025.09.23.10.49.56
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CDDE8497;
	Tue, 23 Sep 2025 10:49:47 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 333583F5A1;
	Tue, 23 Sep 2025 10:49:51 -0700 (PDT)
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
Subject: [RFC PATCH 10/16] arm64/insn: always inline aarch64_insn_gen_branch_reg()
Date: Tue, 23 Sep 2025 18:48:57 +0100
Message-ID: <20250923174903.76283-11-ada.coupriediaz@arm.com>
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

As it is always called with an explicit instruction branch type, we can
check for its validity at compile time and remove the runtime error print.

This makes `aarch64_insn_gen_branch_reg()` safe for inlining
and usage from patching callbacks, as `aarch64_insn_encode_register()`
has been made safe in a previous commit.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 28 ++++++++++++++++++++++++++--
 arch/arm64/lib/insn.c         | 23 -----------------------
 2 files changed, 26 insertions(+), 25 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index a7caafd6f02b..6e6a53d4d750 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -760,8 +760,32 @@ static __always_inline bool aarch64_insn_is_nop(u32 insn)
 	return insn == aarch64_insn_gen_nop();
 }
 
-u32 aarch64_insn_gen_branch_reg(enum aarch64_insn_register reg,
-				enum aarch64_insn_branch_type type);
+static __always_inline u32 aarch64_insn_gen_branch_reg(
+			 enum aarch64_insn_register reg,
+			 enum aarch64_insn_branch_type type)
+{
+	compiletime_assert(type >= AARCH64_INSN_BRANCH_NOLINK &&
+		type <= AARCH64_INSN_BRANCH_RETURN,
+		"unknown branch encoding");
+	u32 insn;
+
+	switch (type) {
+	case AARCH64_INSN_BRANCH_NOLINK:
+		insn = aarch64_insn_get_br_value();
+		break;
+	case AARCH64_INSN_BRANCH_LINK:
+		insn = aarch64_insn_get_blr_value();
+		break;
+	case AARCH64_INSN_BRANCH_RETURN:
+		insn = aarch64_insn_get_ret_value();
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg);
+}
+
 u32 aarch64_insn_gen_load_store_reg(enum aarch64_insn_register reg,
 				    enum aarch64_insn_register base,
 				    enum aarch64_insn_register offset,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 34b6f1c692b4..8d38bf4bf203 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -178,29 +178,6 @@ u32 aarch64_insn_gen_cond_branch_imm(unsigned long pc, unsigned long addr,
 					     offset >> 2);
 }
 
-u32 aarch64_insn_gen_branch_reg(enum aarch64_insn_register reg,
-				enum aarch64_insn_branch_type type)
-{
-	u32 insn;
-
-	switch (type) {
-	case AARCH64_INSN_BRANCH_NOLINK:
-		insn = aarch64_insn_get_br_value();
-		break;
-	case AARCH64_INSN_BRANCH_LINK:
-		insn = aarch64_insn_get_blr_value();
-		break;
-	case AARCH64_INSN_BRANCH_RETURN:
-		insn = aarch64_insn_get_ret_value();
-		break;
-	default:
-		pr_err("%s: unknown branch encoding %d\n", __func__, type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg);
-}
-
 u32 aarch64_insn_gen_load_store_reg(enum aarch64_insn_register reg,
 				    enum aarch64_insn_register base,
 				    enum aarch64_insn_register offset,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-11-ada.coupriediaz%40arm.com.
