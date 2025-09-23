Return-Path: <kasan-dev+bncBDB3VRFH7QKRBWN3ZPDAMGQEFUFSS5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 10239B971BF
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:33 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-7e90f268f62sf14677846d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649817; cv=pass;
        d=google.com; s=arc-20240605;
        b=lwEy8kaPEXa8lDD+LuhXLfsa3hluWJ9Nwftbq0KVGgDZB/17YsS65F7nyJV3+teyst
         u+OYdaUQS/xC7eX6FwqJrdKOT4aqEQfBzuHnjbjpbzwNPLY4hXin4lFYrBEYGKsQM5ko
         52zGsVZmV+xG6U72BuNH+BDwHGHwi4uaQI2xsdLt/dgf0hRE3niYq6e4btV/wtCSDExD
         +3S6Uq15fwNQaCBUimf533hK1fp07FdquIZieSn9+8Uwr2ENSjHNGid1Dpgc+OjijwkT
         VLKCwqVioISXvyxuFgk/Xmpoj+TDFwDQ2GokfftagPJv6rQWirlAAIZ8tDztYRyfN42o
         lJlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=s5CyQF5FN+QQMbcOKZXyKKAIXhRiEGpkopcc3dHQv1M=;
        fh=Sf7/+2yjo0X51jDPEWdoDmn0btx3zMFumuAPVyw6ILw=;
        b=EBQAwZ/VB/Fb37zp5Km39t4J3I/U7q/w87/IIarDbGORGowHVBPzuz8T0SpyJXP2Dd
         4rZXb55/smZbwfF9M+jDjTh/kzc5q9mJBtoQPMnNyVgjCYxvYoDPy3YiMDJiWhEIboda
         ZParmLOl5owSybcUhfFr9ogeA2BEDVfQxjteuc1Qiy6YuR9tMTjTIf65K6U1uOhZX+Kt
         iH+rwEbg653zogvNKE4nnDg7uBiQuZ+zWq0mmzBpkfSF3w95RqX9wXeVLNQ/fgjPOuxv
         5LyvZUICVulqczVsQHrFRmyI/aKsHlsFInkvk83gYSdghq0WtnvajAlgI3t0E+/WHvx4
         4t+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649817; x=1759254617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s5CyQF5FN+QQMbcOKZXyKKAIXhRiEGpkopcc3dHQv1M=;
        b=ligsBY62GkXkiW4NHOnSnDVoePtl5W2Mx28xrhoFuKY++p/BkMPEZPrMGsMK1xtxp7
         U3uJ1jMn11mLcveOy1sTYKfxqeW/ye99SfRJOFAV2EDbIFM6PB4CvREgRYkcxeNGeQgg
         GzXaOKcoeWTly5PPrsjb3NtQ7Tl1XTMXLrDhN7HCzcWg2H206gZVc5jPPQUq5xlb1488
         7lE/AFotMkXjpLZLvjnePp1vHla8J6YvUYpuQFr4Yfd1SlSfj+AehKK5GO2qPE23yVk3
         AlGbMHP36vnBFHA2mrPduiaUQArAw9tJqeI4DRgEtT7MvgqBt90P+dVp2IQ2nZXSkTMo
         2wag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649817; x=1759254617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s5CyQF5FN+QQMbcOKZXyKKAIXhRiEGpkopcc3dHQv1M=;
        b=FqulTX6MkRQvRAJqVv9zNg8y/YolSuSsZ2R4OyqG6O6DsFeFdWHH2SVCUItgDSXw3T
         NqhIeY2omo1GJmQwESdrVov2pKsP0mdkG+15dhufAudk0wxzqUYa8zyRgxlcnOeaxc8Z
         gTjO4pTubMdIpApWcV9ZInRa3sfKruICyQxnAd6slrQ/DNS/naLDBP05atKAFrL0GJ9b
         nyV+X3BVVG8UZkzW54s3nuP7m9GVyFW9VNPWiQNzYRBsxkzEXAmfdFrLyyzmmD83pUzK
         iS6JriTssBMAjNkPx7y2uPUtQ0Wdw7zdFhq38sDU4QdiNhRNzw03BHh5QZowgUqIrmLa
         NmPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuwxBQsfh9LqIGN+ZuQHfzPm/mY2urJ7HqKjpXnFEqtQqVccYxsD26CBfK1M2yqj+2jQmTiw==@lfdr.de
X-Gm-Message-State: AOJu0YxOYUadKopuaLX1y+NHDLH1dLdvyI8/CuOsr52O+GJSZcR1APnE
	Dcvv0pa+8UyPg4K8acGN56J2K6jTw10wlSt/EF+6A/4gHwaZyfr4v+7V
X-Google-Smtp-Source: AGHT+IE7oCQM0GxGAkxMNlbpJeMBN654F1NhAvb9XbqrmZq5eyoDYSAMU7Y6krN4x1iwaktNrkbKcA==
X-Received: by 2002:ad4:5f49:0:b0:79a:6b59:5ee7 with SMTP id 6a1803df08f44-7e70381d7d7mr42433546d6.18.1758649817418;
        Tue, 23 Sep 2025 10:50:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd71LR9jaXJ+nI3RyevEbnUGR0lk7rXkczDstFeRAblJVA==
Received: by 2002:a05:6214:2526:b0:781:a8de:e82e with SMTP id
 6a1803df08f44-7934a0cf9acls10509476d6.1.-pod-prod-02-us; Tue, 23 Sep 2025
 10:50:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeMFel6YfG7zH8nWIqGNztQH7ayxLVefaj+ItQckSg4fzaZG34U/pBUTmT+hjwxn/bhzxB90IbwZw=@googlegroups.com
X-Received: by 2002:a05:6214:2529:b0:792:d0c5:715d with SMTP id 6a1803df08f44-7e6ffbc531cmr40116516d6.1.1758649816237;
        Tue, 23 Sep 2025 10:50:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649816; cv=none;
        d=google.com; s=arc-20240605;
        b=gGmOIgmeEFi6Secaff2kV0Eze1aUCMAVrXQgWMOVJX/Ei2eUeFg252hZLgF7FgE3Zf
         QPaOg+VJzUvnwh+nYckvhtnBZEkA1m0UKz5RYNDOOCh1Hz/8iHh2erRmHmj3AdRw76rL
         Bdj1qJCg0AyS/XzO12OWJyt1VCMVtYB68YqhPnIl9LARFKFyVy/YbPJlGJeYQUUE1aOo
         VKG7NwEGj7KPESPWjeCuhLGrVhqv/b7Vx344qiSovajN5wYVObt3T3qCxhufeVxNrm41
         Y9BHKjbdt4d6aZYrzbDSlmHq1d6gUhq91z2rAniphoXpkWOcNQPlHGZyF9YHOKE0wZX8
         xZ+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=/h3GryW2ugWYvXKu7+Axpgl6L5jNnr93ft50tZXJ/tA=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=aNO1d13eXB7skzcj2BeLSwI4jg/ZMscTmWXVFDEwm/XWjMvFTQkxiVR95zHA4aEIKu
         F7tWvQ2hMa/e6TAnZcBbGoAp2NbGCrKv46MZTcd6Xa2Bv2oK5vA2yvtsdnQjc45CUvJD
         WaOtSQ7tj5YS7G2hlNs3uL1nXoXlj57C167guAgGD2PVzKEEXnB+gxmEICrHvW12kcwb
         VHcVCqcTNhDhHieipvpAiCLoaspJzoNk2tR+je2vnTMFSaFw/DSUXF3no3vd2mTDUWd6
         sBNE2I5GHN67Ma6IdO2hDJkspo0ABog4Lx7SfxQUVxH8HJNCUpO42Rp6o5kt6JECl9bV
         1LKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-7b0b65e03aesi50676d6.7.2025.09.23.10.50.16
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:50:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8E640497;
	Tue, 23 Sep 2025 10:50:07 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id EC8333F5A1;
	Tue, 23 Sep 2025 10:50:11 -0700 (PDT)
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
Subject: [RFC PATCH 15/16] arm64/insn: always inline aarch64_insn_gen_load_acq_store_rel()
Date: Tue, 23 Sep 2025 18:49:02 +0100
Message-ID: <20250923174903.76283-16-ada.coupriediaz@arm.com>
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

As it is always called with an explicit instruction type, we can
check for its validity at compile time and remove the runtime error print.

This makes `aarch64_insn_gen_load_acq_store_rel()` safe for inlining
and usage from patching callbacks, as both
`aarch64_insn_encode_ldst_size()` and `aarch64_insn_encode_register()`
have been made safe in previous commits.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 36 +++++++++++++++++++++++++++++++----
 arch/arm64/lib/insn.c         | 29 ----------------------------
 2 files changed, 32 insertions(+), 33 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 46d4d452e2e2..b7abc9b3e74c 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -882,10 +882,38 @@ u32 aarch64_insn_gen_load_store_pair(enum aarch64_insn_register reg1,
 				     int offset,
 				     enum aarch64_insn_variant variant,
 				     enum aarch64_insn_ldst_type type);
-u32 aarch64_insn_gen_load_acq_store_rel(enum aarch64_insn_register reg,
-					enum aarch64_insn_register base,
-					enum aarch64_insn_size_type size,
-					enum aarch64_insn_ldst_type type);
+
+static __always_inline u32 aarch64_insn_gen_load_acq_store_rel(
+					 enum aarch64_insn_register reg,
+					 enum aarch64_insn_register base,
+					 enum aarch64_insn_size_type size,
+					 enum aarch64_insn_ldst_type type)
+{
+	compiletime_assert(type == AARCH64_INSN_LDST_LOAD_ACQ ||
+					type == AARCH64_INSN_LDST_STORE_REL,
+		"unknown load-acquire/store-release encoding");
+	u32 insn;
+
+	switch (type) {
+	case AARCH64_INSN_LDST_LOAD_ACQ:
+		insn = aarch64_insn_get_load_acq_value();
+		break;
+	case AARCH64_INSN_LDST_STORE_REL:
+		insn = aarch64_insn_get_store_rel_value();
+		break;
+	default:
+		return AARCH64_BREAK_FAULT;
+	}
+
+	insn = aarch64_insn_encode_ldst_size(size, insn);
+
+	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn,
+					    reg);
+
+	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn,
+					    base);
+}
+
 u32 aarch64_insn_gen_load_store_ex(enum aarch64_insn_register reg,
 				   enum aarch64_insn_register base,
 				   enum aarch64_insn_register state,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 63564d236235..6ee298f96d47 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -328,35 +328,6 @@ u32 aarch64_insn_gen_load_store_pair(enum aarch64_insn_register reg1,
 					     offset >> shift);
 }
 
-u32 aarch64_insn_gen_load_acq_store_rel(enum aarch64_insn_register reg,
-					enum aarch64_insn_register base,
-					enum aarch64_insn_size_type size,
-					enum aarch64_insn_ldst_type type)
-{
-	u32 insn;
-
-	switch (type) {
-	case AARCH64_INSN_LDST_LOAD_ACQ:
-		insn = aarch64_insn_get_load_acq_value();
-		break;
-	case AARCH64_INSN_LDST_STORE_REL:
-		insn = aarch64_insn_get_store_rel_value();
-		break;
-	default:
-		pr_err("%s: unknown load-acquire/store-release encoding %d\n",
-		       __func__, type);
-		return AARCH64_BREAK_FAULT;
-	}
-
-	insn = aarch64_insn_encode_ldst_size(size, insn);
-
-	insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn,
-					    reg);
-
-	return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn,
-					    base);
-}
-
 u32 aarch64_insn_gen_load_store_ex(enum aarch64_insn_register reg,
 				   enum aarch64_insn_register base,
 				   enum aarch64_insn_register state,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-16-ada.coupriediaz%40arm.com.
