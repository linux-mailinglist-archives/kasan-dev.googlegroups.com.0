Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF7ORT6QKGQEBJG2KAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B90C2A712A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:52 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id s10sf102005lfi.15
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531992; cv=pass;
        d=google.com; s=arc-20160816;
        b=p0EC17D7JuQa2tIiReg5CKrejCN6v81caQlriWwQDM4TsXOSF2ercVnYF08+aeOgOy
         NjcOVr+nUg1HjBjwwFglgzxsLm37Cm7PRrGRZHmoxoQanLSAmGvAcPTXhatV3hsTFCUd
         z/xmKMbt4zuWh5x7ECQ5T+LxkhFPP20pZs7sN5r9jo9kpzwUVI7cVKkLGjHrkfGepGfP
         tfR+X1i3nCe/75gqYzQQCfxIftkGsEbmCVNjRxJN5RK6WopYUiCYp05G1LAkj1JX8mOb
         IuMmS7i0Mj99ZgveKP8Wv0UVC1gXz/+41JbX+UU1zjOzCZo8iHKT7JN7iplUx/10dOrw
         hu1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=q4gj5hmqiNMve3Syxm+wtazoxcbz5fAoIsjXjdLW6Nc=;
        b=00vFlw2hSBGuI7W0a1InbhLuuBT2LPS5VyZ/Iq4W5afCkF0FGV7Gl4dh/aDrld83MF
         rYehcFBkAO9mKnTqz2QpL1iOmJqnl9sdj0EOHw0VjOq3TOqhYpJuR+S67FGvYyupVuar
         IP+Gx4ORpTrlisGl6RN9m9XFOcV2F+po0kWn93UOaFle3Unvd3Zocp4ZEok63pUbbDO7
         pu1fniCD5WBwcWkEt+8gP0KWiPuU55zx7zc8nMPM0nMbV3wlrY2WYGMY5Pg+eN2NN/FU
         QJgBqycwcJeG4zgcF1/jGPOe5sn82ePcN6Iaq28vAwYCyh2F9Y5To7G2A9TNYOI+HXia
         trZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KrghbXMM;
       spf=pass (google.com: domain of 3fjejxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FjejXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q4gj5hmqiNMve3Syxm+wtazoxcbz5fAoIsjXjdLW6Nc=;
        b=FGeF+6qddkzsrb/mmj/KfbuZHiAhfADfUBZ4B2z6Jg3ypVVJbfw+9avkZQMYDrrS9F
         6ME5cOccNyLVY0+L6TQH4pNOallYli3wz/f0zDyJKAXKly6UUUclhDo6Oa6Hdg+Zd7vC
         xzKznbG8sAUEvjDlNXXJVOPqaDVdevGLTVUUuJGj8rG/MMfIZsiJ+G7a6ms3wDT0Sw4N
         TT2IsQayRRNvB+SScsYQZ/oj8JymK6KlXoCyWAPb9uybuLUwEVSu3ZqyZljMZWeigxAq
         xH+epKL5uz21+H0okHjivS9EVy1NdzHcUE+6XLJafnw2IjKYFd97JvFPuMqSIMUUydEk
         g7RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4gj5hmqiNMve3Syxm+wtazoxcbz5fAoIsjXjdLW6Nc=;
        b=RDcsB3Lb7P6Y3rKqe3nN1axTZkUr6vhLyutdG33sQUCyTLcXi5vrkkOdicRmxQd/6j
         M9wtMO4stSiDnvoezFut5JoKN8v2x1z94GRIANZs4ChsdqG2g/mLMv2GAjy/dhaMdxSy
         KANQ3H26QvYA7qotW9ZmBL/fbzG8yR3qTjxWMJWTCUnsGhZ0SKy9wuW3mwM5xXzcloLo
         /lqdjn2/NmBBJIZVaZTpYAWHESkVoJhPdD4Z1+UEao86nZFRAkEz75BET+bMm0VSrdY/
         JpBcgxPDZof5EHjLmCW0o4kvWMPL4CT34rpg24F9dYaAJV+7Et6ty4Nl3mvBJiy7xRPt
         AQMA==
X-Gm-Message-State: AOAM533dU2hdPrEbE27GDQpNsgUkxlzo0mt4f1GnfXCDx9/pC84ZOiK1
	sroBJ25rMEyVRVAzmPfssHs=
X-Google-Smtp-Source: ABdhPJwPL3fWcTBEWDK/0liF/BIUaNjwBig9rk0AVQOnb7uAJqLxESKTEQ+DK/FblzvOR4DOhdLp0w==
X-Received: by 2002:a19:7418:: with SMTP id v24mr24876lfe.440.1604531992082;
        Wed, 04 Nov 2020 15:19:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91d8:: with SMTP id u24ls106430ljg.7.gmail; Wed, 04 Nov
 2020 15:19:51 -0800 (PST)
X-Received: by 2002:a05:651c:1253:: with SMTP id h19mr116277ljh.414.1604531991044;
        Wed, 04 Nov 2020 15:19:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531991; cv=none;
        d=google.com; s=arc-20160816;
        b=q/r7zId27lLdFTCL18Z76lzZuIsn92w5FMoJc75bPMhyXxm/lqKOguQmrVE8ovRje3
         m+wPQGkybzt0YHXtrmLRtKGGyLkFa3Oy3/wVLgjXDD+xxXj7TIPl4zUOtw7DisNeY7F5
         ZKxxK0MqG8FLTMugL/oyG2rxjEQzDRM6DpP6+67wf2+JuememqlvNi253O8ybrlydG9O
         7Oyuly/OoiVVNlyrIIY6ReutrUua7qju5PesCywyWvkby0+D7W3lXHa112Fhq81FYcDk
         mBSL/OZutVyNSzCQc5EE/tWenWOtY2dcppmBCXVZfYevJmbZXFFtKnxfzk1JRmKFuBfe
         6Eyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ojj9e6SeGShn+CqBq2chujClVFvSwMkEAD8uQAmerxw=;
        b=lfAnfAwNRqK/vE9n5mUr4XzP6SmyTpjRceeui37bwf8jj45vkpekCuTfbNZg0xRdQx
         9ViHGGlEvpPyoJcyT6YZxaKwymkFkx9JOt/YH7AgNRwERiZTerRMEr3DOVcNszvKVq4r
         0yI4gXbJDGKfbqxxrougzBsz03T5lNxtH3lQYhz5zAIMZvdlPSyvxncqXhlzKV2eHVb+
         AVq9qsL79dI9cegFk3Kik0pp+/9bVEKQ452YeKNtujSRnz0hiKkvUj2P865JYpgkHoy/
         B0rMwDgmlWKTl52tV/yy5txSAwAfIEdHB8zS1ZK8G9AoabMi3zLa38vF1E+3O7jTqYM2
         h6lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KrghbXMM;
       spf=pass (google.com: domain of 3fjejxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FjejXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a1si130851lff.2.2020.11.04.15.19.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fjejxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t17so40585wrm.13
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e903:: with SMTP id
 q3mr97119wmc.42.1604531990350; Wed, 04 Nov 2020 15:19:50 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:33 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <f931d074bccbdf96ad91a34392d009fece081f59.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 18/43] kasan, arm64: rename kasan_init_tags and mark as __init
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KrghbXMM;       spf=pass
 (google.com: domain of 3fjejxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FjejXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I99aa2f7115d38a34ed85b329dadab6c7d6952416
---
 arch/arm64/kernel/setup.c  | 2 +-
 arch/arm64/mm/kasan_init.c | 2 +-
 include/linux/kasan.h      | 4 ++--
 mm/kasan/sw_tags.c         | 2 +-
 4 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 133257ffd859..bb79b09f73c8 100644
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
index 8d3d3c21340d..32b9d283e0a0 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -189,7 +189,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-void kasan_init_tags(void);
+void __init kasan_init_sw_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
@@ -198,7 +198,7 @@ bool kasan_report(unsigned long addr, size_t size,
 
 #else /* CONFIG_KASAN_SW_TAGS */
 
-static inline void kasan_init_tags(void) { }
+static inline void kasan_init_sw_tags(void) { }
 
 static inline void *kasan_reset_tag(const void *addr)
 {
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index d25f8641b7cd..b09a2c06abad 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -35,7 +35,7 @@
 
 static DEFINE_PER_CPU(u32, prng_state);
 
-void kasan_init_tags(void)
+void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f931d074bccbdf96ad91a34392d009fece081f59.1604531793.git.andreyknvl%40google.com.
