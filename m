Return-Path: <kasan-dev+bncBDB3VRFH7QKRBLV3ZPDAMGQEPDOMH5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id DFBFDB97198
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:35 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-73934dd7a22sf73095547b3.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649774; cv=pass;
        d=google.com; s=arc-20240605;
        b=W7351CfIaY3NHGGtUC+EjayRQNIoIhVYAB40Sh0IVcf8Qf5Q99sYqx3aTO1j9pSj36
         ClAcJg8SEgMxRcl3l5kDMm60/AZHoCNbRJAy5Lz6v2auB5PCaTEb3DQj5Xj/bvZELQKu
         X4rOGGX/O36up6DIOOzIBWrZy/bcnXRkJeCG/X1PwVWA/HBnCkkXxW/LVh8/X1tLZ1Xo
         hQZjejPkFHYZjXFkEYQf6Dbuiaddl7r2Qvgusv8JWZrAxsXOAGU9xqYc/BYboPplPkE/
         q1ZO1hFn04v1aliXjSCkfWc7Yl/up5q10PYmVJKh55BhEUU53qpeGZdbfw35VJocAOJ9
         FrSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7xqkYX1CD0IdUG3na+iYYbWhiXXRQyfmkX3llCCTrJE=;
        fh=13p/QkZsN0fPBy0jqxgR0o9dax19yi/MI5M6LCb9ikw=;
        b=K7Tr23v9w0rr0q0FcP8klV5DqYI42Mly6pfBXUgXR4toSoRGvx4mUdrmxBu2RCIpVC
         s/lduWJA1ywMJGoXJCVBS50uN4WCT8m1Mni3GB4jzORRmxLMYEmCwq5ibg4X6dOm3noj
         OqBaszhEHvq1jHCSAhtlL80ypoVeEXE8ETjVoqvqSAQgmh/A+FlcSX6sSHZXlc42Yba2
         zYF/n6wg5COd883OCAuA8HJQg7HEPXiYH+Yx+29VYzoP7dyxd3RM0yPoJ+Bxg0gYErX9
         KMnHwcTPk8pTzWfXN6+TnOFpgZTRNOPqYloBV5+C8VYhy6t/ZU2nHQTBvDZgCb2+54A0
         ziTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649774; x=1759254574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7xqkYX1CD0IdUG3na+iYYbWhiXXRQyfmkX3llCCTrJE=;
        b=oTVRQ1aGXVmtWAkPmuZildg0r3VkRpNJQDPM1/AIPXMXYzDjw6vMlo6bfFjnVpHfq2
         HgIdipgxiD8xuOiN4NkZmstG9jrvfun0govgxkOaBBMb4Ok8QMZPatcPr4632c8i/nvO
         fFHjNf/mkqb4GprfcExbZSh2mnnt6sHsuoTz7/kRViqUJZ72IugLf10SiA7w8NEJHFxN
         1shNIxL6Mb02wZBAx8Vdcj/oqwflyFpXxC0UgXu01+nTKWyydJcg9PCbalk+gKa6MOCF
         QRV9QmamLCw5PTJM/7LogTc+CGCOOYTcka5xzXGkJW7IPi3We9lLopO0dCUPIHdBomLJ
         +82Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649774; x=1759254574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7xqkYX1CD0IdUG3na+iYYbWhiXXRQyfmkX3llCCTrJE=;
        b=JKAZ4es4WKAckOJ2gKaMmcmO4v+SWKREZwf+mIIP+NCmZSh8+icizLHGAV8K8zQCZ1
         g138tuUlV6xrNi78SLQ+DX/oRRadyLzm3ogY8EYEPkmbC6b+6v1NhV8GVW/u3wbF1O5V
         XWcCtElPykCSfA1KuB9A4Ag7vX70geF+NeRIVNB9kdcZe4VxcurxaB2Z7gCJBKOodWba
         Xji3iDDjQ/Mcf4cgej98qpLvZ4fPDGW8TVd1mWypKLHly3/xy1X0N5sa3ZWYmK0OhWzE
         3tm7u/rZtvIRzGtEB831Q5447Z5VNxUAJ6BBOmv4Cx9jLIni38Pdr7BjOvpGMb+HxNTh
         dFyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLse0/GxiyFRXUvLAAlcB4uF3bu2pn34KyAilsZMu42f2INaIZNDt8WBma714zkWhh8aGoXA==@lfdr.de
X-Gm-Message-State: AOJu0YxTKZO1lM4ZdrkcGwXv/2GKhxVNmR8Dh3t32HK52cu3zSHwPb6K
	WpLhjJjgqavJw9XWEEwxzIx1ET22ri+Cbjkm4z0UjDO60M0V6r3n6hAw
X-Google-Smtp-Source: AGHT+IH3hqB5xDpTyLFTvSN64gW4igPyo9m2QRb3NCHFkE+lInqL2IEnyfCrwLzGPmJmj7uNHYsXRA==
X-Received: by 2002:a05:690c:6281:b0:723:bf47:96f8 with SMTP id 00721157ae682-758a7b2ed88mr30209207b3.53.1758649774645;
        Tue, 23 Sep 2025 10:49:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6EXVSMkBAXWyB8HorTW/Oh/CYwDZ8FMrZjFtdVE0FQpA==
Received: by 2002:a05:690e:1489:b0:5f3:b6f7:81b5 with SMTP id
 956f58d0204a3-633be0fde53ls3916285d50.2.-pod-prod-05-us; Tue, 23 Sep 2025
 10:49:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWV81e2J4VzLg6Fdsmy4P4YPsCOsB1Zrl6UQk09oZz9oIosZ1KnONKyM0zczgXagdvU5bHt+SMi+oA=@googlegroups.com
X-Received: by 2002:a05:690e:424f:b0:62c:70de:7c9a with SMTP id 956f58d0204a3-636046a8e0emr1889779d50.11.1758649772402;
        Tue, 23 Sep 2025 10:49:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649772; cv=none;
        d=google.com; s=arc-20240605;
        b=R11Q2nZGdT5jM989qCVbUArXlK4llhwmAlfPiHwp3Ux9keS+4iwmX8FuHsSH8rYqCB
         m8kO8I+PJTUC1mEYr7u2IqOUaiWWZghJzQbwytTdiS2Kezuyo51KWMf8hEvDUT+oZ/VI
         H+QQ3fuT2n79XO3vv36hqvjZAg3EG4nUcmzWqF6vW05sM0dfz2wSfyQIZ7u7SkSfwb67
         Su/phDG6FVaDeO0ZhLVWU0MfuSEVySQe4dcRNjXEYPjDfbtISoYofUjr8renB+jP3rOk
         LE8MTjos2Qp/QQ+RnqqhbA5vi9/e3K8Hx9msvCZTV6ECDMEPwj+3l18FznQzhhUbsXGl
         WwaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=nRwif9QX4NLPVrTQf/mDPVPyZw6QavAhED2K4dJ9XcQ=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=ZFnkzvRWOoo6Mr2uXp5GCsiXWLkHh3mcgf+PQvHwqq2iAfE41Xvha49AOpzVajzBX3
         aKbausLSQfwr8y5czp6L2sOKQTJ2LVyRw7gXZQ2tEj4IbRXhBV2ppu8LmLVhu2x1vwl6
         UAIqFRdXOGj5NFsLGSFQR2f88CZBl+e5k0gF2Yc69aEYWO879kEi+OD7c5GOyrDYtSzH
         BfN98sWXq8Sv3X9LebtNFT7Ew8oUHTkaadKoQCe6jCCq/IDAz6+zbsqALy0vT8a3NN5u
         C9NS4fUWkOctYlYey/i2rK25uUm8lb/Pvf18RjnhsCm//F69SLBDExd6lB+mlemDcleq
         rkTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 956f58d0204a3-635290619edsi449540d50.0.2025.09.23.10.49.32
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 72CBAFEC;
	Tue, 23 Sep 2025 10:49:23 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 4AA563F5A1;
	Tue, 23 Sep 2025 10:49:28 -0700 (PDT)
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
Subject: [RFC PATCH 04/16] arm64/insn: always inline aarch64_insn_encode_register()
Date: Tue, 23 Sep 2025 18:48:51 +0100
Message-ID: <20250923174903.76283-5-ada.coupriediaz@arm.com>
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

As it is always called with an explicit register type, we can
check for its validity at compile time and remove the runtime error print.
The register and instruction checks cannot be made at compile time,
as they are dynamically created. However, we can remove the error print
as it should never appear in normal operation and will still lead to
a fault BRK.

This makes `aarch64_insn_encode_register()` self-contained and safe
for inlining and usage from patching callbacks.

This is a change of visiblity, as previously the function was private to
lib/insn.c.
However, in order to inline more `aarch64_insn_...` functions and make
patching callbacks safe, it needs to be accessible by those functions.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 42 +++++++++++++++++++++++++++++++++++
 arch/arm64/lib/insn.c         | 42 -----------------------------------
 2 files changed, 42 insertions(+), 42 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index f6bce1a62dda..90f271483e5b 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -559,6 +559,48 @@ enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
 u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
 				  u32 insn, u64 imm);
+static __always_inline u32 aarch64_insn_encode_register(
+				 enum aarch64_insn_register_type type,
+				 u32 insn,
+				 enum aarch64_insn_register reg)
+{
+	compiletime_assert(type >= AARCH64_INSN_REGTYPE_RT &&
+		type <= AARCH64_INSN_REGTYPE_RS, "unknown register type encoding");
+	int shift;
+
+	if (insn == AARCH64_BREAK_FAULT)
+		return AARCH64_BREAK_FAULT;
+
+	if (reg < AARCH64_INSN_REG_0 || reg > AARCH64_INSN_REG_SP) {
+		return AARCH64_BREAK_FAULT;
+	}
+
+	switch (type) {
+	case AARCH64_INSN_REGTYPE_RT:
+	case AARCH64_INSN_REGTYPE_RD:
+		shift = 0;
+		break;
+	case AARCH64_INSN_REGTYPE_RN:
+		shift = 5;
+		break;
+	case AARCH64_INSN_REGTYPE_RT2:
+	case AARCH64_INSN_REGTYPE_RA:
+		shift = 10;
+		break;
+	case AARCH64_INSN_REGTYPE_RM:
+	case AARCH64_INSN_REGTYPE_RS:
+		shift = 16;
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	insn &= ~(GENMASK(4, 0) << shift);
+	insn |= reg << shift;
+
+	return insn;
+}
+
 static __always_inline u32 aarch64_insn_decode_register(
 				 enum aarch64_insn_register_type type, u32 insn)
 {
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 0fac78e542cf..1810e1ea64a7 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -144,48 +144,6 @@ u32 __kprobes aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
 	return insn;
 }
 
-static u32 aarch64_insn_encode_register(enum aarch64_insn_register_type type,
-					u32 insn,
-					enum aarch64_insn_register reg)
-{
-	int shift;
-
-	if (insn == AARCH64_BREAK_FAULT)
-		return AARCH64_BREAK_FAULT;
-
-	if (reg < AARCH64_INSN_REG_0 || reg > AARCH64_INSN_REG_SP) {
-		pr_err("%s: unknown register encoding %d\n", __func__, reg);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	switch (type) {
-	case AARCH64_INSN_REGTYPE_RT:
-	case AARCH64_INSN_REGTYPE_RD:
-		shift = 0;
-		break;
-	case AARCH64_INSN_REGTYPE_RN:
-		shift = 5;
-		break;
-	case AARCH64_INSN_REGTYPE_RT2:
-	case AARCH64_INSN_REGTYPE_RA:
-		shift = 10;
-		break;
-	case AARCH64_INSN_REGTYPE_RM:
-	case AARCH64_INSN_REGTYPE_RS:
-		shift = 16;
-		break;
-	default:
-		pr_err("%s: unknown register type encoding %d\n", __func__,
-		       type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	insn &= ~(GENMASK(4, 0) << shift);
-	insn |= reg << shift;
-
-	return insn;
-}
-
 static const u32 aarch64_insn_ldst_size[] = {
 	[AARCH64_INSN_SIZE_8] = 0,
 	[AARCH64_INSN_SIZE_16] = 1,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-5-ada.coupriediaz%40arm.com.
