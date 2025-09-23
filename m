Return-Path: <kasan-dev+bncBDB3VRFH7QKRBUF3ZPDAMGQEZFM4SGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1748CB971C0
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:33 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-74c987789d2sf42828477b3.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649809; cv=pass;
        d=google.com; s=arc-20240605;
        b=iMK9+SlXaFgpXf2L6cBBjQMrxnGjVD7p9DWAXC2l249sUKF7AoQPuFEvrcD9UNkLcn
         HxpkjaKKABVgJ/qeXU6CreLyYjq0L7eWfx+HFLKZfu4w/3fC6dS4Va+oPCOBPvCvOlmS
         Q7wLiJBS+1lfYdihMhoVf1cBH8smJK15LhNOxjefsULFArRPwEQA1Z0KzdbFa0K0FkKb
         TNJBQH4fB4NVPEZzt2Wot+g5StWvZiMJ+oaxhJgJAXXlnd0AslEjqi7BdED5cOd94iKg
         /x6f7hwuKHZy2r/f4mqr0VPpipzgoY0yMka565i5Ken88CVP9Cyh8rUDAi5p97ugi3CE
         /w2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pnRqNosrtvEN2lR5ubKMfKSN/NC8JOUULMqWMTu/SZI=;
        fh=y9QTFE0hkDyKN+MN7t/hWk3E4GsQsELupW5RwtyYIV8=;
        b=Jz3wE9z8W+UX+VdrsnMWjjIOld1nPEyeY5M1UhpTFKQHN3AjN7u8rPy7mFfHH0KWyK
         aVdsp+oO8l0G6n+x+ju3NoM2k0ocbDiUJ3lWdBbpHFQQt5St9eEngtYRaWF3IxrKye0s
         AYKbTrHA23ZB0n+r2b+N6MYUjvGTdwNUKMVR6i5LXB4x+ZH9FkUpLKHg9PGqJs2zMs5J
         yFJR0rYH3jlsrE1BHvDS3cmJkbXsCLuXTQ2mjnz4DvhQg10JOwkYYUt3Bqg8nsNjHB28
         ahzEs/vJ7vAPXKZYRFPdCVMnJ/tJNBMu3Fd/sf+VXAqjNaLEY2017voOsPJAeuM8hbT2
         8SyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649809; x=1759254609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pnRqNosrtvEN2lR5ubKMfKSN/NC8JOUULMqWMTu/SZI=;
        b=NFYoAGgwbJwQLz7R0OZBV90txwjE4Pe6RIuVI98prS5xDIWjorfx8ab+3CbH5EYOd+
         Qoz9PYDEVlSpuG90oDRd8o+6pnivyyjplstETLtJ4Ld/lj48Kl3+J1Wlwd0zTCs+DAJn
         Ue1/d+LhcyDa8g6gQFVQqLm+VqnGGzUjKZQ+9BkKbiW6lRkt0/voWMi1OO5fwa2E+fW/
         kp607BDsz77OgW1iMQQuCjuZ1frzvtSgsUTFP1gXlRRtb01kKDBrNljXkG/PWqhXPqqP
         avBwTY4J8dFHrAYfxQF57iy1WrfDJr5dyDYi+0TRHZQpiLA5qyNTEqqllDtTEyAw28dW
         mo9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649809; x=1759254609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pnRqNosrtvEN2lR5ubKMfKSN/NC8JOUULMqWMTu/SZI=;
        b=gNRcbs4nsIDfW/Oy9uoFYe/SavCK0WggozzIXc+NcbvxKU+l/vRXnWpEUH3JDtUz2E
         gHNi4VFrF4+Hxo+TkncsG2Ezunnui1w6xGGRXRggvliSgouYTZZqCfCdYQ4dMPVeLnul
         EMY/zg8D4r3ss9H2Fewwr648DGP+SZaJaO1Lp3GFBCy27gwRLIroAoKJbCdnqp0Pe50S
         2QiBSEWRl8Mh1ounkdRfsWvrUYRF2JFICzTnZWeALeMm1JXVGdA1K8LJ9Vq3bkeU3G66
         RZ98A1y2jFedJIB8q1NScyzqs5nSvGZ7MDhaLlMKvoy0WeFE/MP4/a2CcSHEEOoebAGE
         EsnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWd/SJyFJDk8mDMpkihgBY3gh/v6lEyVyNxzpt4kfvWg2ZpPbFP3dwNSquRQvUq5DCC58ii7w==@lfdr.de
X-Gm-Message-State: AOJu0YyIMO6T+xoLkof3Sle0EF61+skrWxt22+hfsF3uUqbwnADGK25D
	pZMIS0Eitce9ZoEWMqXvW/LrtdFzS2pPW1Cets3CDsdApaIHsxk8sdjN
X-Google-Smtp-Source: AGHT+IEnJAM7fZxEVM9H4zK3m6kJJYE+0AMNOi4a1xZHfv+cXUNGn03B6pBjQznxy/EGQl0I+siwHg==
X-Received: by 2002:a05:690c:6908:b0:724:2cad:8df0 with SMTP id 00721157ae682-758a1e968ffmr27285077b3.29.1758649809236;
        Tue, 23 Sep 2025 10:50:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6pmVXno89Hxt7Ow4zRiUwOzw/q0zemEQtzOgdb8qb0Lw==
Received: by 2002:a05:690e:408f:b0:630:9c0d:2f94 with SMTP id
 956f58d0204a3-633be21dc44ls3671237d50.1.-pod-prod-04-us; Tue, 23 Sep 2025
 10:50:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTN32nmxgUCC1ZSUH/GvxRALA9brt/dWnwJP6f8AaZt/L5Rz2VZ6gpI/1wcZb5WCB7lpqCxERS98g=@googlegroups.com
X-Received: by 2002:a05:690e:1609:b0:633:a2e8:5489 with SMTP id 956f58d0204a3-63604701ce9mr2243957d50.33.1758649808322;
        Tue, 23 Sep 2025 10:50:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649808; cv=none;
        d=google.com; s=arc-20240605;
        b=WrO6AocebLFtyJhG6NOuxDNeIJGWzJ5zLjJoHslaD/DbkFDz5LAEkqp4SsAcoRexee
         BD2xFeDu2vD5Og+DbHbU4NmKtfp1egDqy8UfCNNdOnyTazz+CbRfTqZcE0na44qV54eI
         kYFg5YPNlmcBohBLQocU/14LK4Dd+Ajb1PcWBUCAZHI6o5i9DTzeMDcAYO3j6RuJGQOT
         Tg4Cf6GR4YfVrV9KR4qGE5dI5WC8cO0apRpaaGF9omNb1u2OyCkLpG0uEvRHjMuGlWa8
         UbmIYwzOi3Deje7/pkKgtdJS5oF5LNfEHvj4Vvaom9eKI7IMcO3q4vHpsqxvogMoNT+D
         5TbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=og+DP0OpgQMx1Vo1aDv2fAVsSm3Pe/LirWAaXqKKDW0=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=KNLWeOln7qGHxhDBstbgPdTZDWx6knEELkNvakc1QTuPjcKC2L+MPaFXwrmZPB0nfY
         MxshmpMgJuxl3Zdtjy0JyzCKEX4c3ULBR+wZHBmUCqru39YHL6c5xRwjp8Uo6SYVPalH
         35DOYh+GUHR6+phth6db50daI6GD9+0Lugv62nOTLLPZKhIVRgtUy7FhQ8/v867AamaS
         7ull6ivulIeCKSvQv7mJnxm8J5reM4hN8pVkoZKkfIikmnkgvynf+W+HeKR4jKMVGras
         RBDGJseQn5VsSCYDansRKoIKieKpZ/rsduRbc4U5KP1BKQ9rn0VePUfQoIFVw3W5E7GT
         1VPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 00721157ae682-7397146ea02si5368587b3.0.2025.09.23.10.50.08
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:50:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 65F85FEC;
	Tue, 23 Sep 2025 10:49:59 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id D6C233F5A1;
	Tue, 23 Sep 2025 10:50:03 -0700 (PDT)
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
Subject: [RFC PATCH 13/16] arm64/insn: introduce missing is_store/is_load helpers
Date: Tue, 23 Sep 2025 18:49:00 +0100
Message-ID: <20250923174903.76283-14-ada.coupriediaz@arm.com>
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

The current helpers only cover single and pair load/stores.
Introduce new helpers to cover exclusive, load acquire, store release
and the LSE atomics, as they both load and store.

To gather all of them in one call : introduce `aarch64_insn_is_load()`,
`aarch64_insn_is_store()`, and `aarch64_insn_is_ldst()` helpers which
check if the instruction is a load, store or either.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
Note: I made the LSE atomics part of the is_{load,store} helpers
as they are used as such by `aarch64_insn_encode_ldst_size()`,
but it could make sense to not have them in the helpers and just
call them together where neeeded.
---
 arch/arm64/include/asm/insn.h | 53 +++++++++++++++++++++++++++++++++++
 1 file changed, 53 insertions(+)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 4ba4d5c50137..44435eede1f3 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -520,6 +520,23 @@ static __always_inline bool aarch64_insn_is_barrier(u32 insn)
 	       aarch64_insn_is_pssbb(insn);
 }
 
+#ifdef CONFIG_ARM64_LSE_ATOMICS
+static __always_inline bool aarch64_insn_is_lse_atomic(u32 insn)
+{
+	return aarch64_insn_is_ldadd(insn) ||
+	       aarch64_insn_is_ldclr(insn) ||
+	       aarch64_insn_is_ldeor(insn) ||
+		   aarch64_insn_is_ldset(insn) ||
+		   aarch64_insn_is_swp(insn) ||
+		   aarch64_insn_is_cas(insn);
+}
+#else /* CONFIG_ARM64_LSE_ATOMICS */
+static __always_inline bool aarch64_insn_is_lse_atomic(u32 insn)
+{
+	return false;
+}
+#endif /* CONFIG_ARM64_LSE_ATOMICS */
+
 static __always_inline bool aarch64_insn_is_store_single(u32 insn)
 {
 	return aarch64_insn_is_store_imm(insn) ||
@@ -534,6 +551,21 @@ static __always_inline bool aarch64_insn_is_store_pair(u32 insn)
 	       aarch64_insn_is_stp_post(insn);
 }
 
+static __always_inline bool aarch64_insn_is_store_ex_or_rel(u32 insn)
+{
+	return aarch64_insn_is_store_ex(insn) ||
+	       aarch64_insn_is_store_ex(insn & (~BIT(15))) ||
+		   aarch64_insn_is_store_rel(insn);
+}
+
+static __always_inline bool aarch64_insn_is_store(u32 insn)
+{
+	return aarch64_insn_is_store_single(insn) ||
+	       aarch64_insn_is_store_pair(insn) ||
+		   aarch64_insn_is_store_ex_or_rel(insn) ||
+		   aarch64_insn_is_lse_atomic(insn);
+}
+
 static __always_inline bool aarch64_insn_is_load_single(u32 insn)
 {
 	return aarch64_insn_is_load_imm(insn) ||
@@ -548,6 +580,27 @@ static __always_inline bool aarch64_insn_is_load_pair(u32 insn)
 	       aarch64_insn_is_ldp_post(insn);
 }
 
+static __always_inline bool aarch64_insn_is_load_ex_or_acq(u32 insn)
+{
+	return aarch64_insn_is_load_ex(insn) ||
+	       aarch64_insn_is_load_ex(insn & (~BIT(15))) ||
+		   aarch64_insn_is_load_acq(insn);
+}
+
+static __always_inline bool aarch64_insn_is_load(u32 insn)
+{
+	return aarch64_insn_is_load_single(insn) ||
+	       aarch64_insn_is_load_pair(insn) ||
+		   aarch64_insn_is_load_ex_or_acq(insn) ||
+		   aarch64_insn_is_lse_atomic(insn);
+}
+
+static __always_inline bool aarch64_insn_is_ldst(u32 insn)
+{
+	return aarch64_insn_is_load(insn) ||
+		   aarch64_insn_is_store(insn);
+}
+
 static __always_inline bool aarch64_insn_uses_literal(u32 insn)
 {
 	/* ldr/ldrsw (literal), prfm */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-14-ada.coupriediaz%40arm.com.
