Return-Path: <kasan-dev+bncBDB3VRFH7QKRBSF3ZPDAMGQEEV3DO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id CE8ACB971B6
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:02 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-78f3a8ee4d8sf96935716d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649801; cv=pass;
        d=google.com; s=arc-20240605;
        b=cZQgqOajNRv0KPY5ddVssofwCDsxkrn8DMRbRJ/+dvY34VIzjj6Ds2cWtbu8zu54Sr
         U3ZYl30w2NBja8+7x4EhBbEH6eXfEJAA6FZyP7OGoCo1onI+y9L/HbmffgoozKInPRd/
         VY+8ovw/GvDgZ+vMIMbImYMlvDrgP2gKRqhXKqzFBOGCP8pNN5RFzG91JKItXHE5CxBY
         HESuLy3pcTkx0DPyNFpsD89p8p8sth2txD/cUfDAQ4WoUgJvesd9623ATeRgtdKizjTA
         L08DO0qzDzuPyajD9JWNEUVBbuPnMsq41x6cpUNnJXbAo1ZyyntoqQA59/sfis3fJIx4
         7LAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nnDKI5dyysYhloUZtjjxHGEVYRzXrMwj8IhoD8NO3Hc=;
        fh=Nceoo9UcDa68Ih0SoqEWQLQkJC0o3X7mgHXhdEyCP9k=;
        b=jaFw79+3lUQ7wdkyplMH+ah5cMTzpKHqfXwN40BbZJwCX9Ch18bmHu701iG0LB4lBl
         f8Oz9O9xGBZ8fj7eyxJwptI/Mff1tt1b+6Gua/xwmF7BpFBvDCDToztb77nAQ7uuC2oK
         bl64nuLqAkLP6TiOiiBJjpsueEf73L/9KRg75rkge8N4CuB399HXjhWjtfZxMTEZBAsT
         RUoUaAfIupW7KPrV1pXZk8SAYqQskJpf6kC6bSChWBQmEaSDj6GfteG6JcQDBI0do+s5
         aFAyNNcL0deHGMYOz9vcgNMdFJGHKGBvMlqRK3+nSLIlKg93BMcBwirdQICarwepimUq
         3OCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649801; x=1759254601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nnDKI5dyysYhloUZtjjxHGEVYRzXrMwj8IhoD8NO3Hc=;
        b=ua0pkJqhiPqgIe7QFTUBe2oZCYd/tCy1+MvaKJRYwEkEphBixLoY9TwDKc15hQzTD2
         J2RhNPf5uCIoUEFx2t9WpTaxwPU2Ho2ICP+aTMbS54SJ9oI2kjOftYKXefbSmO777ZcO
         YOfHHIeUGEqhSvdaZnUIMK4e0THdYjSB3LsBQoHl1tT1gaUYpMF1P/dwycK45EmU09X1
         bpnXPRhjnG6JfiFaRo4r5rK6EVg3SqM7RyhTK3JzxrspJNOwWQGFLqizCui835zT9eU+
         MDTN+yGfcUJE79+PJsSwOT3Po1khruU9n+vf4ie3g/M1oGS1PKxAdsALDXBvjDi5wGE6
         FA+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649801; x=1759254601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nnDKI5dyysYhloUZtjjxHGEVYRzXrMwj8IhoD8NO3Hc=;
        b=Qg5MYcs5RrZxQpZSCRhTQm0hqUHDSUjM6gTJ9aHMd9E1L1TQfVN/BAqoBs74L5Ha/k
         yeITjoo+d8Gn28CWcyUhKkDSJf46pW1HPfVml9bkOjzmR5oOLNbU9GGt6djlMMF2SQ0m
         JQAQJ4pyU/ODXMYOZ9PkYku3IU5tfdGkpgAsFGfnoRo0lnxWh0MVX+ukTieEZehcePXv
         VUcMlrfHP545xbG7QrkNi4pDd9NjDSNpPkGfLvq69VrzFDNAJ5lNMCIQB8384TFh+BBe
         FS5Omz7lSoznvlweB0/Do+8r6nwQf5Kg1bcsmyO6ghYIbHzxLJzIE+MfmW+Hhf1derie
         NSyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX413dKYQAR+B06K9HavWkhErsIjeSEMQUXJuKGI9SR23FKeq8Lbj5GB/TO6xOeMPJWI8mbMQ==@lfdr.de
X-Gm-Message-State: AOJu0YwMAKEvgXk4HS8nS7EmEgN1SOIcTFJDT5cmguFeRyDMXEDdugI7
	ydnc7ShfaUWizbw7c7cUXF/YazIbwxZX6p5pjwLSXgPsIQ/Tj+pDQ81l
X-Google-Smtp-Source: AGHT+IG0b7Hvf/F7eOEZGccYko78EoaxieCls41Bp9QL7VuRGR8ggqJRWAZyyX2gEDMXHalU1B3nAQ==
X-Received: by 2002:a05:6214:c44:b0:7d0:29c8:23e2 with SMTP id 6a1803df08f44-7e7132cb5d8mr35061726d6.35.1758649801172;
        Tue, 23 Sep 2025 10:50:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5S1OmZklmsZRmJ3I8cMveBrcn7YNmdpsuILZDFQcyFlQ==
Received: by 2002:ad4:5c8e:0:b0:78e:136c:b6d8 with SMTP id 6a1803df08f44-7934eab1f02ls105304656d6.2.-pod-prod-07-us;
 Tue, 23 Sep 2025 10:50:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSbXQ+8DJzjtUjEq6yifuwREG/Ve9ZnBEw17xJvpA3hGnQy9u/W8p355kvJKOUlC0gxqjvkPiLkto=@googlegroups.com
X-Received: by 2002:ad4:5aac:0:b0:799:60cd:9a51 with SMTP id 6a1803df08f44-7e703728351mr34628466d6.24.1758649800323;
        Tue, 23 Sep 2025 10:50:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649800; cv=none;
        d=google.com; s=arc-20240605;
        b=NYxlp/nrmfr+ZergyaJw146WQVX0FaDBentvnx0302SUDLuTwDDz9vpVcG9KG6nXuk
         j4/+SjvnElPEe/2c4vyWMhthNZu4InaArMRLQXfC8chWOqOpZj/LS8evc8oasL2NWq6f
         jLgRnlHsR3cUJFTeB6nWukwUI3/pcoTgqfepjG/FlVfgIpxpqrSw/LL0RkGZXbBeP8/B
         043vhGl2uE9MQBVXphFcpksGOoASNnYUeau1JpOGEK8yQrZk1cHwX4xyyh/jEkUXcIzz
         5Q+afq0DHl9nchf3VSxse3+/QQHsIafPC/rhfTMQiTGwNyZJzEvwziWqxFniS/n11Qc8
         V0Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1ss/saKnMryxkFtQ4hFKcdP0V3JDpdbG7iyhetNvF7o=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=YGohzTPkn9BvseBZUM4LA/j0g9jzlYYS2RTD9OkyYG94QKqrbwy49W+lzZCxvEbhIG
         28lFxM9rng5OS0L4/ERWnMA9PZwXq2r9Q8srDXbAq0FamDuSzz7QAZJ2Dug2zZ3PvgNB
         bXghZptdvfKE2efWED4Bb8WY/zRB/INmBmnZ7g4AA1VJhR3rXK013Zv/HnPYxbh6B2n/
         nhZzMTdzDOqDURYjHCr8MWzw/7uoH9D3hwuhmLsQJNcbpZDz9myBGWASyJBwlc7+yMVl
         W9njD4o0+36F+px64l5oanTMNXBgUr14En3YHPFhYpdnBK6QmdZLDnwtLqmhzRv2D0Lc
         iBdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-79342226ad8si6605246d6.1.2025.09.23.10.50.00
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:50:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9AB86497;
	Tue, 23 Sep 2025 10:49:51 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 62B403F5A1;
	Tue, 23 Sep 2025 10:49:56 -0700 (PDT)
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
Subject: [RFC PATCH 11/16] arm64/insn: always inline aarch64_insn_gen_extr()
Date: Tue, 23 Sep 2025 18:48:58 +0100
Message-ID: <20250923174903.76283-12-ada.coupriediaz@arm.com>
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

As it is always called with an explicit variant, we can check for
its validity at compile time and remove the runtime error print.

This makes `aarch64_insn_gen_extr()` safe for inlining
and usage from patching callbacks, as both
`aarch64_insn_encode_immediate()` and `aarch64_insn_encode_register()`
have been made safe in previous commits.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 39 ++++++++++++++++++++++++++++++-----
 arch/arm64/lib/insn.c         | 32 ----------------------------
 2 files changed, 34 insertions(+), 37 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 6e6a53d4d750..4ba4d5c50137 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -1111,12 +1111,41 @@ static __always_inline u32 aarch64_insn_gen_logical_immediate(
 	return aarch64_encode_immediate(imm, variant, insn);
 }
 
+static __always_inline u32 aarch64_insn_gen_extr(
+			 enum aarch64_insn_variant variant,
+			 enum aarch64_insn_register Rm,
+			 enum aarch64_insn_register Rn,
+			 enum aarch64_insn_register Rd,
+			 u8 lsb)
+{
+	compiletime_assert(variant == AARCH64_INSN_VARIANT_32BIT ||
+		variant == AARCH64_INSN_VARIANT_64BIT,
+		"unknown variant encoding");
+	u32 insn;
+
+	insn = aarch64_insn_get_extr_value();
+
+	switch (variant) {
+	case AARCH64_INSN_VARIANT_32BIT:
+		if (lsb > 31)
+			return AARCH64_BREAK_FAULT;
+		break;
+	case AARCH64_INSN_VARIANT_64BIT:
+		if (lsb > 63)
+			return AARCH64_BREAK_FAULT;
+		insn |= AARCH64_INSN_SF_BIT;
+		insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_N, insn, 1);
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, lsb);
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, Rd);
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, Rn);
+	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, Rm);
+}
 
-u32 aarch64_insn_gen_extr(enum aarch64_insn_variant variant,
-			  enum aarch64_insn_register Rm,
-			  enum aarch64_insn_register Rn,
-			  enum aarch64_insn_register Rd,
-			  u8 lsb);
 #ifdef CONFIG_ARM64_LSE_ATOMICS
 u32 aarch64_insn_gen_atomic_ld_op(enum aarch64_insn_register result,
 				  enum aarch64_insn_register address,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 8d38bf4bf203..71df4d72ac81 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -1021,38 +1021,6 @@ u32 aarch32_insn_mcr_extract_crm(u32 insn)
 	return insn & CRM_MASK;
 }
 
-u32 aarch64_insn_gen_extr(enum aarch64_insn_variant variant,
-			  enum aarch64_insn_register Rm,
-			  enum aarch64_insn_register Rn,
-			  enum aarch64_insn_register Rd,
-			  u8 lsb)
-{
-	u32 insn;
-
-	insn = aarch64_insn_get_extr_value();
-
-	switch (variant) {
-	case AARCH64_INSN_VARIANT_32BIT:
-		if (lsb > 31)
-			return AARCH64_BREAK_FAULT;
-		break;
-	case AARCH64_INSN_VARIANT_64BIT:
-		if (lsb > 63)
-			return AARCH64_BREAK_FAULT;
-		insn |= AARCH64_INSN_SF_BIT;
-		insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_N, insn, 1);
-		break;
-	default:
-		pr_err("%s: unknown variant encoding %d\n", __func__, variant);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, lsb);
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, Rd);
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, Rn);
-	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, Rm);
-}
-
 static u32 __get_barrier_crm_val(enum aarch64_insn_mb_type type)
 {
 	switch (type) {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-12-ada.coupriediaz%40arm.com.
