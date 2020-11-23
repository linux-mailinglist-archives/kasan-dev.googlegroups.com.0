Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXFN6D6QKGQEDVNSMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D05C12C1549
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:01 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id i7sf8130132pgn.22
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162140; cv=pass;
        d=google.com; s=arc-20160816;
        b=E9wVJ5CxPH+01jAxcfaYF/iocatIw8/ITC00dJkXSDoz12p+8v7mQheXQNSvb1U/En
         hI0Cy6kiP/2rXxQfQGiqPrIyR5USewy+bAfVBXn7lTi+fszVTrIMwSRn2rqO7rpomvkz
         jojYitiUX/kyPbsygP4FFefkkIxqT7vCxhrBOR5HHDFltkeXgSdytD5nbB3ub5TN7pnL
         UEeUUZZ4hYP1NzWK+TSY/H1fHANKgssSPXSw6BcEm9V0LO2qjE/yEVygs0GnlhXdnGuE
         1JnZjbRs7Hvgeur9qDwBz382O3+fp7DsM/O+g0JgjE0vjqWiYgsQ1CB6dj20Y4AX3HFb
         VUKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=9MoyEQLi43i51Bx98sB4GfrnBhf9UjC8EbFXB1iWDU8=;
        b=YrZb0u8X2PWzcJ7uF8B/6P4cLUGaXoVyiwZpkEb3qokPm91xx2fBjEu1Ektboo2ru5
         VLlTKjS0banain+ABzVpREYKk5zPNa4jrym0zbjpui3VO1XCs4ejLBqgobGm1SrZp/K/
         MOnyBo0Iv8pcdA0uKwRspWFNA5vs0mgxmOFJBjtp9NAxQHhcdykaL30o3snmdVh/9g8+
         zKrzzsBR4dspFKsmASNFdkPHn+1XNxWA4Oxp3fN1sioLRckazJ5pZMBqo5SWR/KeGGcD
         ylk5bG/zG6UWd45MSaNT1zPu0RAAp/R+ktJqUro90Q9nVNt7n4NFZAyFNS0G14OlbpXR
         N76w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=srZKa6aH;
       spf=pass (google.com: domain of 32xa8xwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=32xa8XwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9MoyEQLi43i51Bx98sB4GfrnBhf9UjC8EbFXB1iWDU8=;
        b=pb0ySq5LUm5l2iaxuIh8wOB3Fk9VygVAFbPvEiEGCEsQqZqNg1hTjSrrReKaUa5LJc
         DZCuk9a02u+deWvrAVqNeabbfM+jF1/kvQgsb9auEyx/uukNE8KL4iXhNDvgTTaIxbvN
         WqeMs1KK3jZLWAZnAPxC/e1SCbLd9ekX0Jiuk123XwjCfA7zVYn0/b8St1HPGqI6gNMP
         kc42nzPqWhFlBpscPOuXGKcQYOWys9Icr5Av0Ku4/Pqr99MybRGp05FFiAiWTZZWpaMI
         s5jqH0FMS0ilxSacKCSMF85+NOHi9SiA/U7pYbeFRbrzVArfGGw3kXD+bhy3GTqVG1rh
         VnLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MoyEQLi43i51Bx98sB4GfrnBhf9UjC8EbFXB1iWDU8=;
        b=Vj1g+RER97pWSfpXMlsT6V4HbKUYZXmMy3qo4ea9wfGLHCYB0tuL/zUA2TtArxsfyx
         ijQ2XN6OFHbjIdu23NzDqW+fOlNSzDfzI2h56tPi9HJgeaYEldGUlksXlQ5njfHwBu2S
         s8nHM5Scw2WREASF/5ihi/2XHFOj+A8Ebyiwyrtvz6gnwbYmkheHnnl8yIULMfJI1xJz
         Up81nppEQee9ef2utUrmlaKMjjesMk3QgOqWi91k1ipWQm3BMDQGNlz1zcb5KAujf4YH
         H0yFYMUEihSI/pPMEo3SlkhKD5YpC25ZMmG/aVMB1qA1eDLEYF6z4jtV5sIPcg60FEVR
         kRow==
X-Gm-Message-State: AOAM532w1N4xWGDdJYpEd+iW6vjXB83a6HF7OsSXssPNelTb63//JIIb
	HfP5MpdjfIzlsFBM1+Nw7/g=
X-Google-Smtp-Source: ABdhPJxs+0B0g4z/Vurod7e4Y5I/G5zaCbpEHxeCCi90p/+V8rkn9wVJur/ZE7qvrPXvO5/cfqo93Q==
X-Received: by 2002:aa7:90ce:0:b029:18b:3686:c10c with SMTP id k14-20020aa790ce0000b029018b3686c10cmr930171pfk.66.1606162140592;
        Mon, 23 Nov 2020 12:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2a8:: with SMTP id q8ls5430792pfs.9.gmail; Mon, 23
 Nov 2020 12:09:00 -0800 (PST)
X-Received: by 2002:a63:83:: with SMTP id 125mr923652pga.423.1606162140046;
        Mon, 23 Nov 2020 12:09:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162140; cv=none;
        d=google.com; s=arc-20160816;
        b=LQkAydZ1LDgwDp972iRvJEVJTIkngpieMsZu4E5znoNIqvZM0zF7QK1voo4CJgjgHS
         RcQy1CNTBXITGqcrHPcw/I80VhIs6lnPwfTzMsummO1KgrWMNyHG/30wDLwCGPUMoDRW
         IYn7fz35zQD8aoZBjpIYF+HHRO1xjmfiZatmTXwG2h3Q0mIjD7VR7wcTX8T+sB3MIOWm
         dW/X2iltAMD7wlOe/xDKPbKf0FG+6XPRvJ9H9xrH/0cr/fpCkm7BniCwYadGbT62JeJ/
         rPXBhyI/s2XByp+iKYxEWPu8nCKF395jGsVkZDjzMGWwda1obvsaGFkp9RNOok+lFCAj
         JyzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=kG65aVx5WJn/kF7F81b/rehD2S5LbswJneuDpixnu58=;
        b=Ojk8noGwLw+JOkOqcjfAlHm0jMkEU6JNSPEjVAQX75+3pLvOpfQhMGwIVaI/I/d/KM
         U7aNyND6X2n6fjgyHrJ7WsvDjvhBuO56JA9c4xdZXXLPU+/G4haaQ1CzMnnnQTn2egM1
         A8SRvnsZjGMO7xxeNKcIlHu9WgoCjZxc90vJYxGoJVFsuv7CsOZezCtntq3Zc7CUghqc
         nbI3iOOW3MVlhpqCGPiaA3T+qE+dVe3URrS77O9+Ll+DVfaNTZthWrA2zsFRnA0xSspa
         5VCAn7u60iV5r13kn84r85kPKyOxJYk/H7Cu/AI9XJOBCrU68gV+9NX091HmRkRI0a6+
         CzUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=srZKa6aH;
       spf=pass (google.com: domain of 32xa8xwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=32xa8XwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 80si870016pga.5.2020.11.23.12.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 32xa8xwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d206so15436803qkc.23
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5587:: with SMTP id
 e7mr1239239qvx.33.1606162139104; Mon, 23 Nov 2020 12:08:59 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:41 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <71e52af72a09f4b50c8042f16101c60e50649fbb.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 17/42] kasan, arm64: rename kasan_init_tags and mark as __init
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
 header.i=@google.com header.s=20161025 header.b=srZKa6aH;       spf=pass
 (google.com: domain of 32xa8xwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=32xa8XwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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
index 1a57a76e1cc2..a950d5bc1ba5 100644
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71e52af72a09f4b50c8042f16101c60e50649fbb.1606161801.git.andreyknvl%40google.com.
