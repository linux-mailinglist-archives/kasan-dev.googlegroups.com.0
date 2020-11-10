Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH5AVT6QKGQENUBD25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D7A92AE2BE
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:44 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 4sf5415761ooc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046303; cv=pass;
        d=google.com; s=arc-20160816;
        b=FvO5OGqctBGh4ntliWgJ6Fi0bS82m33KTBi/Fwm3Gl9dFhy4JJPUUeVDwiuXZapMVx
         tTj6CTQEiKsLMWUAa3IDlLTVhSVyfOy5DHQcmNmjkh+hrAh8kn13PPkhBXAFH/UOCmdf
         gMHa6RmV8jlL+MbhKV36D4w+0K5uiko9YZ3w2KPGhn5tPDNQ0Xn8rrFzVpYbPjLvbCK7
         YbpYOhGrtDmBhR69qvcdxP1kKdgvzX+2VXt3H7CrWsw+G2F3yulMEAatiSGU2EFfSKmx
         X3OWGL+Yl0+8wCc0rO3sfxvC1oKi+ILQQXzl6tPpu2Zuo10W5ne6+waXe/gcBVAenPz5
         eFiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VLqo2wT4+BINNlsRu8j8dkCSonJadskdFdXjpaNU2kM=;
        b=JMfVAsy7n0EavxYdxU2VYMMWqZaewfo2MoaBNxSyxgpmF2qTyy885BX4sS8qUTYoSd
         ZlrqqzW3CYXupgRZhadbX93ovdlfuffbdtZMaGufpTR7TI7gFPatdkptYHzkeNFFZxHo
         I4VIt1qpzyTo1tnxUjiSQ0Klt1DdY9zwle8pT3g4yCrPN/tr732V8J0YbsAFzkkZfIi9
         hGriigyZI6UmjfGCJJq81Ks2icVq0DY37piwrOJ0YXS2r86DRvqvNJAF13R9+QytpD9L
         lg6uLDytFUf7L0lJDjS52FoB75bfDLm2VmpcowtnJfB/eyqjLKd84cefIvLnRnhKw7dX
         A4kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Seki+Rjk;
       spf=pass (google.com: domain of 3hhcrxwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3HhCrXwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VLqo2wT4+BINNlsRu8j8dkCSonJadskdFdXjpaNU2kM=;
        b=HyXssceI/l+bpdzcfhjTqhdH7uHiftk+AJq6cm+2O2sv08deX5pTOQNhkYoR1PuJss
         KiyjdJn2dSWuvKZcYOFdqF0oxU38oY9JKEV1MmUElZR0AXk0EekfdlVZUyD8SoYhBarU
         neTU0OlRMP1LM6/26AZUIrOji3XgtEv/mdwcMq9Rq/iWSqI9SdnZVD55825rPXl8F5sP
         GlRTraVL4CyvM7cX4DTjEO5Zub8POdvkadt9yhnW/oNSAYud9UR3d1M+ZfRFVrap65wn
         bThKHQeEpeCIDAUaliclzeD7cDyqO/zW7W1ceS9qkW74WZ9RZ1zf9QXHMp5QtyFl/Gj/
         ofYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VLqo2wT4+BINNlsRu8j8dkCSonJadskdFdXjpaNU2kM=;
        b=EG+7pWkSyU9VtuIaA+P9CgblEDW8xnneVvdV2araLtQtL6rNJx6jkZFTVj8Z44y5yg
         hRtKIIX884qcsOK0Ln8HPukZ5IyCvf8gzqWW1HANgo6JbAb/mnTYICGDna65GTfWjhwa
         wVMYK54EPmrthdAt6+NAeXB29USn+KrJTFPOQVDBtjIl15/m0WKldfH3ITNnEKQ2OcLT
         NlmEVYlni0mnKBGseXkLcXGkUuDN5eIw5V3X5pET+t0thpjg2ocIv8m440YQNPdHGTwo
         GSPYLNfRQiebhExYZL6hlukv/vrXhD7uBWgKcVWNGZ4d2seSc9OxTunKYjMc1eFIFfdA
         kFIQ==
X-Gm-Message-State: AOAM530vxMNoheuJ8xbV8mbl3Ur3wcqoR3/MOt1w1olY7ycL1/9X/EFg
	nxEnvmp+Zk4dUzatlNazyW0=
X-Google-Smtp-Source: ABdhPJweGY7Q7Qw/dsn/hv9ddqsr8DWgLfQvk5E8mK0EVRSqDCac53SJS5S25I6+OYr3otW1JpE8pg==
X-Received: by 2002:aca:fc97:: with SMTP id a145mr170262oii.178.1605046303255;
        Tue, 10 Nov 2020 14:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls3422147oib.5.gmail; Tue, 10
 Nov 2020 14:11:42 -0800 (PST)
X-Received: by 2002:aca:cdcb:: with SMTP id d194mr178199oig.142.1605046302917;
        Tue, 10 Nov 2020 14:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046302; cv=none;
        d=google.com; s=arc-20160816;
        b=KIqwJLFg5dTyr8Kj7X6SDh4ITDODprOsvUTxGJHib1MKqvSpoFc+p9/eFsomxJEVkZ
         IIpnICNJ+PSRM85HKPvNEz9uyWamVzuQm1t6suaGNnIQjgp+TkL46Kdgh8xgV8ctseSa
         B5YXfbT6WuTcMrv1lE/c1LoTubO2WL1ARa+km8FjOB8MnGGV/qYTVGYc2ZtR9aFx806+
         LnCaEwiC3pxvUXFw1bSecGE3kpcGdCbJG5GWWCY/GOyseHDNXauPCnVfhGaD7GS2snme
         NHYZS7HOmX7Y7BwDfjSUUxkJiIKKF4cHrVmWsWzwjizOXjBU5NxvqVmnR8G2Zxq/y7Nh
         mapA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=g1D3QU7M8sz0sof3NdcHUc7FXuL+sBstwF4DigTeK5Y=;
        b=gQu2+ffkhRQtSL0/imF5KIcvhdUM3QTmwhqdd4d9mwpVwykMaxlT3+ZvCQVISF8t+g
         3YZB60UfEnVm14KtswNLY5My6DkNh81m5gTKeWvOAE9edxX9IdCx5Zwj63ZR17c6vxNB
         k8Edz1e6kd6RKf30ZblKOSewzRy514OLr+HafmmqEw59gebArtMhqnGHG9nQ9vx5WV8z
         qMrsapM9YklbRdnOQRUE5SZozYlLrcNsx/TziC/PfkVuyLBelNmKskdR5s7BygTBKzSg
         PBA9aYnJvZsF7ezuS/2Qn4ugYOIcNOJrJ0s5oc9LmLYlW5q5h4zDvjrLETPlrCTSjnEu
         C+lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Seki+Rjk;
       spf=pass (google.com: domain of 3hhcrxwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3HhCrXwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id f16si12229otc.0.2020.11.10.14.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hhcrxwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x2so163532qkd.23
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:aa8f:: with SMTP id
 f15mr20400649qvb.46.1605046302266; Tue, 10 Nov 2020 14:11:42 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:12 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <3aae3b3f931618b4418af7992bff1e258e4eb1ad.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 15/44] kasan, arm64: only init shadow for software modes
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
 header.i=@google.com header.s=20161025 header.b=Seki+Rjk;       spf=pass
 (google.com: domain of 3hhcrxwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3HhCrXwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory. Only initialize
it when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I055e0651369b14d3e54cdaa8c48e6329b2e8952d
---
 arch/arm64/include/asm/kasan.h |  8 ++++++--
 arch/arm64/mm/kasan_init.c     | 15 ++++++++++++++-
 2 files changed, 20 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b0dc4abc3589..f7ea70d02cab 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -13,6 +13,12 @@
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+void kasan_init(void);
+#else
+static inline void kasan_init(void) { }
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
@@ -33,12 +39,10 @@
 #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (1UL << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
 #define KASAN_SHADOW_START      _KASAN_SHADOW_START(vabits_actual)
 
-void kasan_init(void);
 void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
-static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b24e43d20667..ffeb80d5aa8d 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -21,6 +21,8 @@
 #include <asm/sections.h>
 #include <asm/tlbflush.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
 
 /*
@@ -208,7 +210,7 @@ static void __init clear_pgds(unsigned long start,
 		set_pgd(pgd_offset_k(start), __pgd(0));
 }
 
-void __init kasan_init(void)
+static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
@@ -269,6 +271,17 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+}
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
+
+static inline void __init kasan_init_shadow(void) { }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+void __init kasan_init(void)
+{
+	kasan_init_shadow();
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3aae3b3f931618b4418af7992bff1e258e4eb1ad.1605046192.git.andreyknvl%40google.com.
