Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWELXT6QKGQELFXJBDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D1272B280D
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:57 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id d20sf4413899lfn.16
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305817; cv=pass;
        d=google.com; s=arc-20160816;
        b=lwP4JipvebhnbGjX6qAdngmj2xiNMbIPqiiGCcHILOvTSmdcGXc7sJdVgvYjeIMRov
         /EiyVdsYj/vJ5NJq54ee6ndmwDHwSq/Jz8r796tCilh7zebORDjfwfjVh5SU1/5oaQSv
         gz5v8OR7Oo72E3n2USaSR1S0NlGHAqEPWhxh9ggAH7GCMhcboGoJJi+cbyhQuXW9gNcF
         Y9uIlKXc06m+p+E2XTTX7WZZjEJvKgyluqHxYpn73sEKDxyPNXSIaQVBx+Esg+FxGNUD
         kS48lzL/Mk0XKbJXyZ/ya60NIuVSj7L3DZUIy4/VSgj1JcveTZmIUyrAmUJ9Ixh5rOzs
         TWHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Z9q+mFSVja3PrpzYp7fqdSZ/uMyzu14Ujd5V9caBTlg=;
        b=J1uBanzFxe0A+M7MR7GfDLfimO9sYQ1E0Z0WFL75J+bOJaZC+Gj8yQU9uKS6u+d02N
         NjGgauTccjcQdXdlLAZK/OI1jPeMnMa7J0MKRmO7zL+2qUYO0HCCEW1IBk+RJOtbPPQL
         QlBD9jCacY2JNXI7Q7NL1OPpRz5Zo4ErBfAPRcukrjXIhfE7odKuFhsVd17V3/ySmpxS
         2eejAPQX5XMQCWJR749/XYLnnAltGFh/MsXC2VpYUoQ2vQBRgopx/oBPQUuyW/MFnii+
         znNrd98qnraUttISBq8AF1MIwuKdcTZFxDpcpjLDSN2sg7uky5D4Gs+csIoWd5pShwwa
         5EKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i4IRzr7+;
       spf=pass (google.com: domain of 31wwvxwokcaicpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31wWvXwoKCaICPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z9q+mFSVja3PrpzYp7fqdSZ/uMyzu14Ujd5V9caBTlg=;
        b=UA5n6rvdks8nOV9C8PxIUUz2vUmDgNhc/sI/hysTlaujbfbOaxLSSM1YUetJTk8t4N
         9XDLrauAB571uLJWzIdCygOnv3zenC50aIoc+kD84gp8M3FxUQaFbLJZxrXxd2tmqzBL
         DdWhEKivojvM6umqNQOzs2EPMzg5y3fw2dx8wmTmAcPWkK8XPOyKBDuLQNlQj9roUqIr
         iMyjAO79rJo2pz1JdkBOhUKuau41ABYMzPIO/RtZ3K95sWM90aK2vPZ7MtYXzN2t7XSv
         S0Vvo0fStXGaE8KoE52SsYJuLJhoxAFfpaoj5+HRwkDr2R3vBKupC+KppFGtJ4kU33vj
         P89Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z9q+mFSVja3PrpzYp7fqdSZ/uMyzu14Ujd5V9caBTlg=;
        b=SPezS5WefM9N3qIFHZ8qHA2FFioP6Ai9XEuK7v4Dl/TcpbJFs4ylwHZSywJCfPMjBb
         JxfadckDQv3JqjJ/2wt/BlfmSePWFkx79BIEqgz7rM3rEl32QdDhXcjTQyISsFJ6VFaz
         BeWA8NkcDJ8oWsmFvpysErxJA48bKj9MHTEujwxUIkAFR1g2dseHos+vFO+9En9YGhD3
         Eh3Gy6tlhwydxKPcfXcgmcWiPLIfNcrERQbP5URRi1cbBB7nEVxs6+DRLbBTWTPH4PXM
         RQhvr7Rq456OvBzC35cgWs4XeqT7Lt0dSOjXaAumq4CLI3OMTYHQsTP8U+mKuaMDBRkj
         JeRg==
X-Gm-Message-State: AOAM532iPYL1JE6/N1x7BfB+TPQHDKlKW/7M6uo+zk5bMumZKENQwFJX
	p+/Bt8FaatHrrC0iNagXcxw=
X-Google-Smtp-Source: ABdhPJyQkY1lyqkc9M8D+Qc9QFC9TkD/3oNBXxKKhI7jeZSr5X1z/UZHWuVzeQTEZMpAuuCsl762lw==
X-Received: by 2002:a2e:b0ec:: with SMTP id h12mr1953465ljl.379.1605305817210;
        Fri, 13 Nov 2020 14:16:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90b:: with SMTP id 11ls1496700ljj.0.gmail; Fri, 13 Nov
 2020 14:16:56 -0800 (PST)
X-Received: by 2002:a2e:b0ec:: with SMTP id h12mr1953455ljl.379.1605305816325;
        Fri, 13 Nov 2020 14:16:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305816; cv=none;
        d=google.com; s=arc-20160816;
        b=0cULqkYuQT/xWw7Zb3zYXLmdkNeesTwqPuDX3SDxjRDlF663YrsC18oto5XY+jrpmu
         /RsQyl/fqSKe/7Do/3B8NU3Vv2E28n4NZGREq/kvT/krhtyrTEtcpTBz+RUNbMbVzAE0
         zJwDitSy3sLRGHiCGbK9me78By38eD0cJeOW2o24K/H5qoWB0TVkv0ZxZyOjkNjLMcZD
         0Azpjb/75Ah+bFJJiZnrbgj83sM0FPkXKAKCTbUxAnWun/xY5cQIcHyRYW7Nrvyv0zgW
         kQeSXTUN/6BRuCVolcXczuOJDE1hsRRcAiQf42GU+PhKeD3dW2GQFgtZauCBWjDXU4U5
         D18g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=AllKQJimzn7hLgi4RPYa1jCIh9marG6fXAU7bboN0mo=;
        b=NC5SNZuvGj7BFb1AOer3JJ67mkXP7mi53ul6FDgU/QmvgB/blSGUeAkeiufaXvVujk
         qnpGpuhoc87LOoSHlme30/iX/2QjQlOak4D11UEn2+5skW0PB0FS1X938NaJuxtftyb6
         muDWuRC/ouJ30vg5q6d/NhBuhIIKnIlIM3mty41iz0f0sVQCbjXcYHCXrQBSumgArJsC
         U+e9KI+tX9tPRKy9HrwUzoAUzgakJHfKtX29mr0jxlwMOfs+SZd9snvzr/8y3/XAHLgv
         9U/dh0RG9jiimMeLm/8pjPmW4rj66wboWCUbmzBbINTBzhNUeuSTAZcMemg55BtMe0tp
         mtBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i4IRzr7+;
       spf=pass (google.com: domain of 31wwvxwokcaicpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31wWvXwoKCaICPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f5si137731ljc.0.2020.11.13.14.16.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 31wwvxwokcaicpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u123so3998380wmu.5
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:56 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6a0b:: with SMTP id
 m11mr5863665wru.190.1605305815704; Fri, 13 Nov 2020 14:16:55 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:45 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <6182fdbdc372e9e4888cc7b73c47f85d21d1827f.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 17/42] kasan, arm64: rename kasan_init_tags and mark as __init
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i4IRzr7+;       spf=pass
 (google.com: domain of 31wwvxwokcaicpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31wWvXwoKCaICPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Rename kasan_init_tags() to kasan_init_sw_tags() as the upcoming hardware
tag-based KASAN mode will have its own initialization routine.
Also similarly to kasan_init() mark kasan_init_tags() as __init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I99aa2f7115d38a34ed85b329dadab6c7d6952416
---
 arch/arm64/kernel/setup.c  | 2 +-
 arch/arm64/mm/kasan_init.c | 2 +-
 include/linux/kasan.h      | 4 ++--
 mm/kasan/sw_tags.c         | 2 +-
 4 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index c28a9ec76b11..75e511211eb4 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -358,7 +358,7 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 	smp_build_mpidr_hash();
 
 	/* Init percpu seeds for random tags after cpus are set up. */
-	kasan_init_tags();
+	kasan_init_sw_tags();
 
 #ifdef CONFIG_ARM64_SW_TTBR0_PAN
 	/*
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index e35ce04beed1..d8e66c78440e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -283,7 +283,7 @@ void __init kasan_init(void)
 	kasan_init_shadow();
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
-	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
+	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
 #endif
 }
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 58567a672c5c..8b8babab852c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -191,7 +191,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-void kasan_init_tags(void);
+void __init kasan_init_sw_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
@@ -200,7 +200,7 @@ bool kasan_report(unsigned long addr, size_t size,
 
 #else /* CONFIG_KASAN_SW_TAGS */
 
-static inline void kasan_init_tags(void) { }
+static inline void kasan_init_sw_tags(void) { }
 
 static inline void *kasan_reset_tag(const void *addr)
 {
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 9445cf4ccdc8..7317d5229b2b 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -35,7 +35,7 @@
 
 static DEFINE_PER_CPU(u32, prng_state);
 
-void kasan_init_tags(void)
+void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6182fdbdc372e9e4888cc7b73c47f85d21d1827f.1605305705.git.andreyknvl%40google.com.
