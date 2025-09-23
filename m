Return-Path: <kasan-dev+bncBDB3VRFH7QKRBQN3ZPDAMGQET7EETOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D30D9B971AD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:55 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-4248c63531esf2289655ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649794; cv=pass;
        d=google.com; s=arc-20240605;
        b=T352pHKFC3/K3Z7LuNOvVPo8HQCF7YT54jThAso3tgIxZxcET0cSV5exGfUkdhe6Lt
         Qnwu8w7u2XMTrsEs0VXoDftnbhThwLh2xy4miRbkUg7RXPHDZrJ4pcHzOAlam1Ee9fT0
         wmMUA3KPy2fzux+34sTojl/thQqz7QCJ3hGJ54jW6WglMvXKX08F+suEfEOG3jR3DVAY
         5ivtOfQd6SJZI+FWt35cl6gmtrRQf/udx4nLb82fz5zIIVUchCEmb4sqd4i1uWK9kS/8
         FwYMaYkaZAmTsj41XMGyX7DaZwZg5m8tkeHoWvC5aW1OqiLB095wccdNQVr66/PytoXo
         Fqow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/Qkb5mBAcZL/Izugo+KeDdnKEfSlx2mGj4F6l5m2QhU=;
        fh=wqVpgYl8oAZImfbvR0BagoWbQfxljRD7ODB/VoMM/Mk=;
        b=Lh7e9xKaJDojotjbJGn5LZECjkekClZnLc5Llqu5XB9TY4XPUDAM+yehIYAXHZzhc5
         zbC6JO6pXglq3LseVrzRJMv1Poigvd3lxDdS8jnEY1Ayw3xhMt1dEVRlroGQX+Qv2xRW
         B8CDkSkZX3NmSlsdD+cdoRWxdHGyOUAT/1ie0MC0aBM9LJ9rNwK7MeTYu6wl5bdHVYFC
         Hi6+88uY0H/8cls1YuRjUJrl0Fj+y58+P7iAXHSkIdFUYZymVmCUA26QHb7uFpnDF8jp
         UrVT9H/4A8D0amlriaWYYcQOvWW2eL6t8BzgtzMUGyO5dX4hdunzQTSL3rFJ5EW99SGc
         1caw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649794; x=1759254594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/Qkb5mBAcZL/Izugo+KeDdnKEfSlx2mGj4F6l5m2QhU=;
        b=c6841VFgGPsyRd46UVLIjCJ9L7uKosw6BxF9BXuN2lixtzY/wzPiqVVf5qxTgMPpU/
         dRW/TL2arwS+Gx6pm5P2NvM9FjYAQ9sjMyKNpwlqlIpJdBdL79b3BAYzq4KFt5EWHFnP
         m9u5lAwU7o+5uPYpSVNKkeLxlIgu1onulYshTmqzI4Sy1UOEOVioH6NSzMQ22xqoJsv3
         fwA10A8S58UQh22u6uPNOiCPiPm1DxnXnsSqs+JtOX9B/5knplBl4tyLs3O457ccyC9M
         uV1MWzJ9rCW+OmpoYGYm5R00DZapZkd5z9P8ZNm4luHJt+nIesG9lQB9cCKi9vA0R6H6
         vdCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649794; x=1759254594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/Qkb5mBAcZL/Izugo+KeDdnKEfSlx2mGj4F6l5m2QhU=;
        b=AOCTw/1czXFZdJeDJ/WzsVgjOK9k9J0eujcVHYBfoOPbX1j1l39tHoKbVB5EdkE22a
         1P8/oCf0Tz1bipiOIQH0nlBU6Xh1z3AD3BSbmpVBieZrPsKGi10QflZenMRSvtvxTIhJ
         ZqgJPDfo17RSzcj46Ugykyw1oYX2j+d4jKCX8EaDth2NBOFjoCWFLrnGPZ6wPwQTd8c5
         de8sE5aopqt8o9shwaqZwgdDxP+KxUXFWPLU020gqmTm6QiZdN5deUy8XZ0wlOegnP7w
         pwij8cPgRdYYkBmbtXlD7ClmTD5jPaSagLWxNSiGCR1YOTT9iPvK0w+IRPjVN4XpgbRK
         DcHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXV2UYpxNFPNpZFDSgrjLK46XW4xj3vfjANJ2h2CSfCOufI26i7k5UHKeWK7lb3z6TezEmRdw==@lfdr.de
X-Gm-Message-State: AOJu0YwSe13xEIoatN3ZxJvjh52cnLdXkqthLLuJ76Ksttehxnas1m0c
	Ehla/6DNgD7OMAtixoir9Hemy5WAuJrh/rUN3lxtUNrIe882n9lPtrLX
X-Google-Smtp-Source: AGHT+IFOC9sYubGNmJ9DAsga+qUPXv0ArCQQ0Wi//7c1NmcfGK0dkwn5x8uU5ea8xvQYeCRLIFj+Ug==
X-Received: by 2002:a05:6e02:b48:b0:425:70ad:799e with SMTP id e9e14a558f8ab-42582315dcemr62973535ab.10.1758649794108;
        Tue, 23 Sep 2025 10:49:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5JsCTM8DEFBdjkYq5UYnrin+5YKDPbNTOYrWr+dPzRcw==
Received: by 2002:a05:6e02:4816:b0:423:f9d3:8389 with SMTP id
 e9e14a558f8ab-4258b477fb7ls359745ab.2.-pod-prod-00-us; Tue, 23 Sep 2025
 10:49:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPN2691GVtV8iAIGWPAaOWuUS5zx+1MEMKYAfhn2do5LpUrx4t7f05qWHYPoSTnDmw4MOjvADEf9E=@googlegroups.com
X-Received: by 2002:a92:d9d0:0:b0:423:4ff6:aad3 with SMTP id e9e14a558f8ab-425822cafacmr46305805ab.7.1758649792772;
        Tue, 23 Sep 2025 10:49:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649792; cv=none;
        d=google.com; s=arc-20240605;
        b=fDqrSYO4oCdHfH8Gv5f7qIDuDgiWyFr8PCz358FzJZj4XQkzeWnWzWMrqLIz1f5IKq
         I54HTpcQwjR4HEe8YnT8jPtrxRdGvGg/QY5H7OF4xQoJ5lP4bgo4hiG+BjGsSMzV2who
         Wpkr9oxoxO0CLrBr5diFMeOmI0Jduqk2fOS+BdgToqeHuw6eIh2YgolbU3/RipaFqBbS
         vcEOGQTQJGQk7ttWwAgKGAGgyf+29+HuLQejaB1a3jSR74A79E2w/200JN6LVW2ro3pt
         Pfe8IggMl2sDCkgHiJE7ExAoFDzgHxZtkhJJ/xWyCX0VSrLLldqXbYdLRu7OFzP05+zU
         XFbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=nqNV/UFwypdIEpJKRCZL0w0/uWdDcXO5z3KDapN25dQ=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=CAEuIfZ3uDN3Ed92nwqZB1JGfeXweERCxdeortuO7jqTICRmCB0KpF8B6CQDLQyM+f
         7q1JOMnqpxS9hDhygDINjVFIR1kulmTvxi/zbJ8RvZu3bBVhvVs0FiCqH59NmP1MHmPk
         Um+xhnMXYWdYhffQXuXQa5u1z06Co0wVGp4T1UaXYzz8nVVZYShJE761uoOP8vtn+lxD
         FoFXzrFEWCmNtM310MMun9odH8jPqakJnurfHRWmZziNiYlxIGiLntYW6/fNvGK7atCC
         3GX+8J+ErWP7irm9fEAMCWRp41KvYDU1B18vk/B0XHIxgE729UQ/BzqYJ7GWtvzfBNY4
         rUAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 8926c6da1cb9f-53d4a031160si332141173.4.2025.09.23.10.49.52
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A8739497;
	Tue, 23 Sep 2025 10:49:43 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 1AE8B3F5A1;
	Tue, 23 Sep 2025 10:49:47 -0700 (PDT)
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
Subject: [RFC PATCH 09/16] arm64/insn: always inline aarch64_insn_gen_add_sub_imm()
Date: Tue, 23 Sep 2025 18:48:56 +0100
Message-ID: <20250923174903.76283-10-ada.coupriediaz@arm.com>
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

As it is always called with an explicit instruction adsb type and variant,
we can check for their validity at compile time and remove
the runtime error print.

This is not the case for the immediate error print, as it checks
dynamically. However, it should not occur in practice and will still
generate a fault BRK, so remove it.

This makes `aarch64_insn_gen_add_sub_imm()` safe for inlining
and usage from patching callbacks, as both
`aarch64_insn_encode_register()` and `aarch64_insn_encode_immediate()`
have been made safe in previous commits.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 68 +++++++++++++++++++++++++++++++++--
 arch/arm64/lib/insn.c         | 62 --------------------------------
 2 files changed, 66 insertions(+), 64 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index a94ecc9140f1..a7caafd6f02b 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -627,6 +627,8 @@ static __always_inline bool aarch64_get_imm_shift_mask(
 #define ADR_IMM_HISHIFT		5
 
 #define AARCH64_INSN_SF_BIT	BIT(31)
+#define AARCH64_INSN_LSL_12	BIT(22)
+
 
 enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
@@ -788,10 +790,72 @@ u32 aarch64_insn_gen_load_store_ex(enum aarch64_insn_register reg,
 				   enum aarch64_insn_register state,
 				   enum aarch64_insn_size_type size,
 				   enum aarch64_insn_ldst_type type);
-u32 aarch64_insn_gen_add_sub_imm(enum aarch64_insn_register dst,
+
+static __always_inline u32 aarch64_insn_gen_add_sub_imm(
+				 enum aarch64_insn_register dst,
 				 enum aarch64_insn_register src,
 				 int imm, enum aarch64_insn_variant variant,
-				 enum aarch64_insn_adsb_type type);
+				 enum aarch64_insn_adsb_type type)
+{
+	compiletime_assert(type >= AARCH64_INSN_ADSB_ADD &&
+		type <= AARCH64_INSN_ADSB_SUB_SETFLAGS,
+		"unknown add/sub encoding");
+	compiletime_assert(variant == AARCH64_INSN_VARIANT_32BIT ||
+		variant == AARCH64_INSN_VARIANT_64BIT,
+		"unknown variant encoding");
+	u32 insn;
+
+	switch (type) {
+	case AARCH64_INSN_ADSB_ADD:
+		insn = aarch64_insn_get_add_imm_value();
+		break;
+	case AARCH64_INSN_ADSB_SUB:
+		insn = aarch64_insn_get_sub_imm_value();
+		break;
+	case AARCH64_INSN_ADSB_ADD_SETFLAGS:
+		insn = aarch64_insn_get_adds_imm_value();
+		break;
+	case AARCH64_INSN_ADSB_SUB_SETFLAGS:
+		insn = aarch64_insn_get_subs_imm_value();
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	switch (variant) {
+	case AARCH64_INSN_VARIANT_32BIT:
+		break;
+	case AARCH64_INSN_VARIANT_64BIT:
+		insn |= AARCH64_INSN_SF_BIT;
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	/* We can't encode more than a 24bit value (12bit + 12bit shift) */
+	if (imm & ~(BIT(24) - 1))
+		goto out;
+
+	/* If we have something in the top 12 bits... */
+	if (imm & ~(SZ_4K - 1)) {
+		/* ... and in the low 12 bits -> error */
+		if (imm & (SZ_4K - 1))
+			goto out;
+
+		imm >>= 12;
+		insn |= AARCH64_INSN_LSL_12;
+	}
+
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
+
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
+
+	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_12, insn, imm);
+
+out:
+	return AARCH64_BREAK_FAULT;
+}
+
 u32 aarch64_insn_gen_adr(unsigned long pc, unsigned long addr,
 			 enum aarch64_insn_register reg,
 			 enum aarch64_insn_adr_type type);
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 15634094de05..34b6f1c692b4 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -17,7 +17,6 @@
 #include <asm/kprobes.h>
 
 #define AARCH64_INSN_N_BIT	BIT(22)
-#define AARCH64_INSN_LSL_12	BIT(22)
 
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
 {
@@ -585,67 +584,6 @@ u32 aarch64_insn_gen_cas(enum aarch64_insn_register result,
 }
 #endif
 
-u32 aarch64_insn_gen_add_sub_imm(enum aarch64_insn_register dst,
-				 enum aarch64_insn_register src,
-				 int imm, enum aarch64_insn_variant variant,
-				 enum aarch64_insn_adsb_type type)
-{
-	u32 insn;
-
-	switch (type) {
-	case AARCH64_INSN_ADSB_ADD:
-		insn = aarch64_insn_get_add_imm_value();
-		break;
-	case AARCH64_INSN_ADSB_SUB:
-		insn = aarch64_insn_get_sub_imm_value();
-		break;
-	case AARCH64_INSN_ADSB_ADD_SETFLAGS:
-		insn = aarch64_insn_get_adds_imm_value();
-		break;
-	case AARCH64_INSN_ADSB_SUB_SETFLAGS:
-		insn = aarch64_insn_get_subs_imm_value();
-		break;
-	default:
-		pr_err("%s: unknown add/sub encoding %d\n", __func__, type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	switch (variant) {
-	case AARCH64_INSN_VARIANT_32BIT:
-		break;
-	case AARCH64_INSN_VARIANT_64BIT:
-		insn |= AARCH64_INSN_SF_BIT;
-		break;
-	default:
-		pr_err("%s: unknown variant encoding %d\n", __func__, variant);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	/* We can't encode more than a 24bit value (12bit + 12bit shift) */
-	if (imm & ~(BIT(24) - 1))
-		goto out;
-
-	/* If we have something in the top 12 bits... */
-	if (imm & ~(SZ_4K - 1)) {
-		/* ... and in the low 12 bits -> error */
-		if (imm & (SZ_4K - 1))
-			goto out;
-
-		imm >>= 12;
-		insn |= AARCH64_INSN_LSL_12;
-	}
-
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
-
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
-
-	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_12, insn, imm);
-
-out:
-	pr_err("%s: invalid immediate encoding %d\n", __func__, imm);
-	return AARCH64_BREAK_FAULT;
-}
-
 u32 aarch64_insn_gen_bitfield(enum aarch64_insn_register dst,
 			      enum aarch64_insn_register src,
 			      int immr, int imms,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-10-ada.coupriediaz%40arm.com.
