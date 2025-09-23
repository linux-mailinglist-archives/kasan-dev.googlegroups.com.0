Return-Path: <kasan-dev+bncBDB3VRFH7QKRBMF3ZPDAMGQE6T2VWDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 42804B9719E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:38 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b5f6eeb20esf202216351cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649777; cv=pass;
        d=google.com; s=arc-20240605;
        b=k0Ot9Bp73BJ7wwsSPEdwLKNc7GrNwJkQJIme6DbSjSjlyZFmdkZsj4QQdCz9LGgxF0
         o8UiRLYHNvI/HUpbawDxSvJXBAxOJgLAg1TLOf2JgvTREgQMGLeB4r4DC7wznaprrazm
         Vt1qK6FkBn3SCVDofPtQ8pLHFK9tjO10FEZ5PFQHZDRXsJMrKBfTgpjqeD9D4Kp+WadS
         Al8Fn8s8qGueKqjUBdbi1pwpEtAE7BUP/Ph1sgWjqTpJe3/xB3AAiKYHfg0Ig0z+VnQm
         /tPudpv1OHCIMoWenz/4RrUDxqOIn2lRGCOQr3Kylj6UPl+PIR7eq/ytzSlEfrtOWWQW
         ivQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=huS/oVfGv9dUWjF6eXYhQ+71TQqSI8keTHD0BVymvCU=;
        fh=T04zxiPKWZkjZc9iuWYyq3VzsT4BAbCMCEocHvH+ETE=;
        b=Dy3XF5/B5PVJApE2hhWwut91hpIxG4VOE/ZRTSg8cE7ZkDwifv/SxRlG8vpFJ3zPdK
         NkxnX98beiWXdGGj9gofylQZHjqc8aujAIWLHKZgpr7PjDasb/At0rWkLmxLYzA5XZAy
         mxhhItysCCvofNO7Lnn75OmINkBbd9UABET0t5CSXNZNibirGukLRh7FaNPi2gXtsTsI
         wnRw8UcpAeeHgWu1LZdSLIgxCOpjr1BpzePPEDtzGQ+/jrN0frANRuQSv8m15cJW0fza
         QQEwjHXttyZeI4Lunfk+ki3/Nu44Fma3p2fNmxTRMlAtIP9mYESKSwzpYspKOv01qsF3
         ApfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649777; x=1759254577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=huS/oVfGv9dUWjF6eXYhQ+71TQqSI8keTHD0BVymvCU=;
        b=rXmQjYj7adU9P1J5pgOsp1UsphEaAMA3gynHPWIAgzmeq0iBnURhyKafXkK96jTPqk
         vTQF5S7jB6HqINg1k+rW0/BDnDPNGf546Lzf/9t9PXAwIDtL9CSEKXAnyViEpxKcE8uy
         95VG+10C+UUeSHC0MydTYUy4gUU/yqb3wLIU/qLfKWOvugwdJ0154V5QnW7lbVqb/F2i
         3U8Hpkk9VDMXmAOADV9apB1cwRtobZza0Osc0tB07RsrIht7DD8bLIZkkp+GqX750RH5
         mPhCiJWTtiRLLZGCGLHaatBCGNf+GsGIY1MdB85brqrIfF/bkBj7wssUFbPD58ajm2xb
         ds7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649777; x=1759254577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=huS/oVfGv9dUWjF6eXYhQ+71TQqSI8keTHD0BVymvCU=;
        b=rhlQ1X+jQzTAgXNJS5ePecFS+H+syFOKW2bV68BDX2ftCacmQA/uOM5Ymppawj0lrF
         /c8fBjtFShBp6BuAkw8Rg85Iv8i0N109VUYfPtBIR1l9FVrkfjW61ocq2+3fg8clTc60
         nsbZC0ZnQmAC8cCAQ4YKVgZ0hPBIsf/YpH1twuk/KfCX0UeY3jx2gmaDaDDJAIpecKvy
         av6l3YD8PwGYiTm/9dqDEqCn/k2h4mt25gwTsFr81uHghjoJ+Zh+IKUJh0Y6ujTk7dqN
         NKUjr7+WyigeHaNecmn1UoNfuX//VIalAaHKSnqJHufS7tyuGFh0zsBQzc/N3w7WTE7Z
         2pRQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+DXmRcSSowK5ajl8cDDFPY8Ol2c9OqPNEpxInVVMksbJNTn5Cc0EC7FQ9obuJRE3z+6tuzQ==@lfdr.de
X-Gm-Message-State: AOJu0YzqUcknFEQk09L9IFG07cWgRhy9QjpzHzUgqm+RWdR49wKvy59C
	wxksOQsDjDxIR4VukGBBmWKfwtzb29HLbEjU5bD3PSBWl1FnjjXllHnV
X-Google-Smtp-Source: AGHT+IHUIqhsU1ST99VTZ54T/JoqD39Et94160vJ0IM+6qzgqYWp+WdqO4TU+1marvI1kqWPGDaunw==
X-Received: by 2002:a05:622a:a94a:20b0:4d3:e20b:78c6 with SMTP id d75a77b69052e-4d3e20b8515mr29623551cf.80.1758649776850;
        Tue, 23 Sep 2025 10:49:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6oCBxI1vE+jgLJf9gHLijHfGlbbQI1halZ0Wn4X/fmqA==
Received: by 2002:a05:622a:2b4c:b0:4d6:c3a2:e1bd with SMTP id
 d75a77b69052e-4d6c3a2e86als8353161cf.0.-pod-prod-04-us; Tue, 23 Sep 2025
 10:49:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRVX57t6JlXixI2vuRiyW/c93YPUXIOFjtIknsg+P2fti2bpQKjmJOY7kGym3MhZa3L9E2ZehvOFE=@googlegroups.com
X-Received: by 2002:a05:620a:4149:b0:811:76d4:6d4c with SMTP id af79cd13be357-851694f4448mr366659685a.10.1758649775914;
        Tue, 23 Sep 2025 10:49:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649775; cv=none;
        d=google.com; s=arc-20240605;
        b=lXhiHDoZUFuRmh2UOie7JcQdcM7VEjqbIkzcizkqz8XK0544865KOa7uhz+CQxcjI8
         wp+4VqXCEPLXeFjnszw54j3t0x1pZSegExiZp9Hv9oK0DHLHPYPTw9o+Gf/wmZgrZ2c7
         BIIUtcZ44ZlexvLRIFcG9C8qymYrAr+0mVx7Viwpaxv1Htgr9NVqAGmjTgGEGuWPmbjE
         Y5XZyPHuMt6N8N4yeYPPKkxZO17g2YvRurKpS7Gjiq5gCE0tYpOU7JbkvyjUlYA/gbSe
         XKVrPcc9KW60CHEAliTD4VTeHKO5JtWXtZqlNxEN8DFyulH1FgtF0WtqjByvFi7GL9nf
         Tbaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=bZ2uzXtl6lqNAinf/Y3wQdYQbNd4yFTmZ87eTrWeF7E=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=Azu8hPtSFWhaM6y2GNheRZfIfyaaXRUMWAS9ghovsa9PdF2iCw/KUCbkrc0JrV+Uc9
         AyFH/KbkBJwDCm46DBwKCsH2O8dmJvW59OSBoR0gpd5qOEmUOsXM3sqHJPfmr0fTriT5
         YdBdTGNn+lMigKL45f4g1kV8m28f8/Mg07YdsD8kZKCdF+EqPQgZ/O64mqYiJdG7mtzD
         qb2EzWN6rZAFy38B91t+stfBtb9emq0QLus/HCy7SM3fJMpnhGM6djHJ7djOgUG/kK7t
         bDTcCBD9E9M8gaFw3elvVxu0/Qf4HVhxoxTtCKbY///8OXQ0i1AuIxUnDKl/oY867LWJ
         JQwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-855c2950442si1934785a.4.2025.09.23.10.49.35
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5738B25E0;
	Tue, 23 Sep 2025 10:49:27 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id DB98A3F5A1;
	Tue, 23 Sep 2025 10:49:31 -0700 (PDT)
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
Subject: [RFC PATCH 05/16] arm64/insn: always inline aarch64_insn_encode_immediate()
Date: Tue, 23 Sep 2025 18:48:52 +0100
Message-ID: <20250923174903.76283-6-ada.coupriediaz@arm.com>
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

As type is passed dynamically at runtime we cannot check at compile time
that is valid.
However, in practice this should not happen and will still result in a
fault BRK, so remove the error print.

Pull `aarch64_get_imm_shift_mask()` in the header as well and make it
`__always_inline` as it is needed for `aarch64_insn_encode_immediate()`
and is already safe to inline.
This is a change of visibility, so make sure to check the input pointers
in case it is used in other places.
Current callers do not care about -EINVAL, they just check for an error,
so change the return to a boolean.

This makes `aarch64_insn_encode_immediate()` safe for inlining and
usage from patching callbacks.

As both functions are now `__always_inline`, they do not need
their `__kprobes` annotation anymore.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 103 +++++++++++++++++++++++++++++++++-
 arch/arm64/lib/insn.c         | 102 +--------------------------------
 2 files changed, 102 insertions(+), 103 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 90f271483e5b..5f5f6a125b4e 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -9,6 +9,7 @@
 #define	__ASM_INSN_H
 #include <linux/bits.h>
 #include <linux/build_bug.h>
+#include <linux/sizes.h>
 #include <linux/types.h>
 
 #include <asm/insn-def.h>
@@ -555,10 +556,108 @@ static __always_inline bool aarch64_insn_uses_literal(u32 insn)
 	       aarch64_insn_is_prfm_lit(insn);
 }
 
+static __always_inline bool aarch64_get_imm_shift_mask(
+				 enum aarch64_insn_imm_type type, u32 *maskp, int *shiftp)
+{
+	u32 mask;
+	int shift;
+
+	if (maskp == NULL || shiftp == NULL)
+		return false;
+
+	switch (type) {
+	case AARCH64_INSN_IMM_26:
+		mask = BIT(26) - 1;
+		shift = 0;
+		break;
+	case AARCH64_INSN_IMM_19:
+		mask = BIT(19) - 1;
+		shift = 5;
+		break;
+	case AARCH64_INSN_IMM_16:
+		mask = BIT(16) - 1;
+		shift = 5;
+		break;
+	case AARCH64_INSN_IMM_14:
+		mask = BIT(14) - 1;
+		shift = 5;
+		break;
+	case AARCH64_INSN_IMM_12:
+		mask = BIT(12) - 1;
+		shift = 10;
+		break;
+	case AARCH64_INSN_IMM_9:
+		mask = BIT(9) - 1;
+		shift = 12;
+		break;
+	case AARCH64_INSN_IMM_7:
+		mask = BIT(7) - 1;
+		shift = 15;
+		break;
+	case AARCH64_INSN_IMM_6:
+	case AARCH64_INSN_IMM_S:
+		mask = BIT(6) - 1;
+		shift = 10;
+		break;
+	case AARCH64_INSN_IMM_R:
+		mask = BIT(6) - 1;
+		shift = 16;
+		break;
+	case AARCH64_INSN_IMM_N:
+		mask = 1;
+		shift = 22;
+		break;
+	default:
+		return false;
+	}
+
+	*maskp = mask;
+	*shiftp = shift;
+
+	return true;
+}
+
+#define ADR_IMM_HILOSPLIT	2
+#define ADR_IMM_SIZE		SZ_2M
+#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
+#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
+#define ADR_IMM_LOSHIFT		29
+#define ADR_IMM_HISHIFT		5
+
 enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
-u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
-				  u32 insn, u64 imm);
+
+static __always_inline u32 aarch64_insn_encode_immediate(
+				 enum aarch64_insn_imm_type type, u32 insn, u64 imm)
+{
+	u32 immlo, immhi, mask;
+	int shift;
+
+	if (insn == AARCH64_BREAK_FAULT)
+		return AARCH64_BREAK_FAULT;
+
+	switch (type) {
+	case AARCH64_INSN_IMM_ADR:
+		shift = 0;
+		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
+		imm >>= ADR_IMM_HILOSPLIT;
+		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
+		imm = immlo | immhi;
+		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
+			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
+		break;
+	default:
+		if (aarch64_get_imm_shift_mask(type, &mask, &shift) == false) {
+			return AARCH64_BREAK_FAULT;
+		}
+	}
+
+	/* Update the immediate field. */
+	insn &= ~(mask << shift);
+	insn |= (imm & mask) << shift;
+
+	return insn;
+}
 static __always_inline u32 aarch64_insn_encode_register(
 				 enum aarch64_insn_register_type type,
 				 u32 insn,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 1810e1ea64a7..d77aef7f84f1 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -13,7 +13,6 @@
 #include <linux/types.h>
 
 #include <asm/debug-monitors.h>
-#include <asm/errno.h>
 #include <asm/insn.h>
 #include <asm/kprobes.h>
 
@@ -21,71 +20,6 @@
 #define AARCH64_INSN_N_BIT	BIT(22)
 #define AARCH64_INSN_LSL_12	BIT(22)
 
-static int __kprobes aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
-						u32 *maskp, int *shiftp)
-{
-	u32 mask;
-	int shift;
-
-	switch (type) {
-	case AARCH64_INSN_IMM_26:
-		mask = BIT(26) - 1;
-		shift = 0;
-		break;
-	case AARCH64_INSN_IMM_19:
-		mask = BIT(19) - 1;
-		shift = 5;
-		break;
-	case AARCH64_INSN_IMM_16:
-		mask = BIT(16) - 1;
-		shift = 5;
-		break;
-	case AARCH64_INSN_IMM_14:
-		mask = BIT(14) - 1;
-		shift = 5;
-		break;
-	case AARCH64_INSN_IMM_12:
-		mask = BIT(12) - 1;
-		shift = 10;
-		break;
-	case AARCH64_INSN_IMM_9:
-		mask = BIT(9) - 1;
-		shift = 12;
-		break;
-	case AARCH64_INSN_IMM_7:
-		mask = BIT(7) - 1;
-		shift = 15;
-		break;
-	case AARCH64_INSN_IMM_6:
-	case AARCH64_INSN_IMM_S:
-		mask = BIT(6) - 1;
-		shift = 10;
-		break;
-	case AARCH64_INSN_IMM_R:
-		mask = BIT(6) - 1;
-		shift = 16;
-		break;
-	case AARCH64_INSN_IMM_N:
-		mask = 1;
-		shift = 22;
-		break;
-	default:
-		return -EINVAL;
-	}
-
-	*maskp = mask;
-	*shiftp = shift;
-
-	return 0;
-}
-
-#define ADR_IMM_HILOSPLIT	2
-#define ADR_IMM_SIZE		SZ_2M
-#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
-#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
-#define ADR_IMM_LOSHIFT		29
-#define ADR_IMM_HISHIFT		5
-
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
 {
 	u32 immlo, immhi, mask;
@@ -100,7 +34,7 @@ u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
 		mask = ADR_IMM_SIZE - 1;
 		break;
 	default:
-		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
+		if (aarch64_get_imm_shift_mask(type, &mask, &shift) == false) {
 			pr_err("%s: unknown immediate encoding %d\n", __func__,
 			       type);
 			return 0;
@@ -110,40 +44,6 @@ u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
 	return (insn >> shift) & mask;
 }
 
-u32 __kprobes aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
-				  u32 insn, u64 imm)
-{
-	u32 immlo, immhi, mask;
-	int shift;
-
-	if (insn == AARCH64_BREAK_FAULT)
-		return AARCH64_BREAK_FAULT;
-
-	switch (type) {
-	case AARCH64_INSN_IMM_ADR:
-		shift = 0;
-		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
-		imm >>= ADR_IMM_HILOSPLIT;
-		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
-		imm = immlo | immhi;
-		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
-			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
-		break;
-	default:
-		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
-			pr_err("%s: unknown immediate encoding %d\n", __func__,
-			       type);
-			return AARCH64_BREAK_FAULT;
-		}
-	}
-
-	/* Update the immediate field. */
-	insn &= ~(mask << shift);
-	insn |= (imm & mask) << shift;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-6-ada.coupriediaz%40arm.com.
