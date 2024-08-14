Return-Path: <kasan-dev+bncBCMIFTP47IJBBPHC6G2QMGQETABGX5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id CDA17951720
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:30 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2cb6b642c49sf633426a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625789; cv=pass;
        d=google.com; s=arc-20160816;
        b=zeIOCfuXLxMYzdvtYj7iTAGy8DFUPVjGZdmDZS7NG0zCPY9iLXRVUI1mmxpfe9KCfG
         fLUtJbJJmdft0ZmIh//SL+jEFJnZAp2gQH11BU6UTjRBPRbZg/HjvzOjtYg06wDlFgnm
         i0Q+aegISFfWBQp5kSydqEhlXPdVzq6tQlldXS9v0DSPREfOyvmKhy6P3nkvwWZSfnBb
         C++D4bSCPXWF6HY6iTUQfjsNi/kvjjILv3U5/qQs4wEU7kQPtbnDgAjkFuMLrc46RgYJ
         LIUyH+D3oQrhT2t1a+1tYTrHeI+6UnTwlJfb6y13FYqDm0NibuYLr1DqHKvxyZ2+YV8U
         vlFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jeQqwcNNOni4zfpNSjsLo8RSmTPZ31c7JK/BzKCgbYg=;
        fh=m1OB1THAT0ugg/V2xs8gWvTOm008eJHOazc68lA1LZk=;
        b=DfSggbpYO2WqM3nn1XjmUmzI1d+kVy9QCL5XCO8Piyuw3pzLTeXSTRXMECpF5KZMDd
         OBexKTJ8Sa8xT5haHwY+l8R5SdSbJ4PYZkKYYFM3qMNpj2a89JPKPu5lWcepRH4qsri+
         a7Ms9m3cH8m2tx5+3/hL34yOwM6qhLs+eRGcDKMd3zRvukl3FSZTXv2EGv6+PmKPnhrq
         PVLV5yfDzksq6vvZWada90am7t+AeD/MPPqam/GwUeUcWLR/orXM5lDwMSdT7EbL0+pf
         hzYoSgvfXwQ0iiASDcPK6rrqDOz3rllydMpMQ2zHf6LXtufhW9sKFpYx+BRmTEJtPiVY
         YwFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=SbTyK18H;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625789; x=1724230589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jeQqwcNNOni4zfpNSjsLo8RSmTPZ31c7JK/BzKCgbYg=;
        b=MpcJv9Sxcu08L4XBA8nvdBfdHZI5A9pj/ZxzVG3hxLNEn3SMWTUc4MCDoHjiIqok2H
         Vrhv8fyvtFrN3vn8DdiQekVOWTEffhrxMGHxDYZ3X3IVuUHsRMKf/kjGvng90E2LPucd
         ESqjrjFyQzftuyRsFjrigGjuB2Lu2TuGRQZgvc4grz5w9/E9Qc7lVHNQoiI607pXtPA1
         iuQMeA9s00TtXiYw+ASLO52pjGME5VPQglYWuEllERJ6frmAyCjRz5CZaHy8O5ViUuRG
         H46kIEsiPs+wrDl/wOCw1QZPDz6VJXbyBC7UvqTjTBrgHxDa8lEz2lToPXLeI1qpFIz3
         QCHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625789; x=1724230589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jeQqwcNNOni4zfpNSjsLo8RSmTPZ31c7JK/BzKCgbYg=;
        b=lr2x74qIiI4MOQxTWCLdSF8uhF7fnpv6Ygo2W5C4s9LeNdBMv+fyeq5402rz/jfJef
         QLS1fzPJMw9AXLs9Q7dPVVm9T+jVkPROvrJM/CqaTXLS4J5EPrFI0H/GWh2idrq5/TBs
         XlBOwNqm4/n7LplpKFhy6q6PqmbC9RswRGfY7WB9HiUWwtHH9meLLMD9VCr/+QGatGoT
         rvlqORJySKw7XSfwnlZkgnwcngxbma6n5hiAxNJu8lNEgvZFeeDdlWJnf9jfHxKeFdA7
         GCy6dup3YqFU7UvHez7MjRxPjLyCll6kYklagDAGwf65pZsUkaCVnpxVw3BBTtCGY4kB
         rHKQ==
X-Forwarded-Encrypted: i=2; AJvYcCWxIJyDSBZsO3aPd9Zkhep6woW2Lh3wHZPBMh+I/2b9RSdfDEHqPwm5kojVAkGYEwDVPY31GqI9QXzdslM05fHfrklxeDC5dQ==
X-Gm-Message-State: AOJu0YxUHO62RJiiNri5wVl48VHgcxjRLcoAndyMTW7CDx3dpsXVlwEr
	B7n8F+z0T51LdbvsxszRtkdxKe46zCno2pcZF23ipl2tJzqDYO8u
X-Google-Smtp-Source: AGHT+IFGPqMF6hGB70XMAJlZgy4WiQKWnUDcrQPHLIQukQhkugTmhXEHkyKXKjYSa/UylUGMei9KJQ==
X-Received: by 2002:a17:90a:5a84:b0:2cf:dd3c:9b0d with SMTP id 98e67ed59e1d1-2d3942228e7mr8814084a91.2.1723625789070;
        Wed, 14 Aug 2024 01:56:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1010:b0:2c9:321:1c17 with SMTP id
 98e67ed59e1d1-2d3aa8da9eals408094a91.1.-pod-prod-00-us; Wed, 14 Aug 2024
 01:56:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDQTkCpOYl+nH3ICLe0evaqfGB8Jhv6M870888Ly0xRNjxw8/jUwGiztzj3eaXtdRUhW+N5JefYmbzDGKULj005987p6PEpdJanQ==
X-Received: by 2002:a17:90a:7448:b0:2cb:5883:8fb0 with SMTP id 98e67ed59e1d1-2d3942ed12fmr8589001a91.14.1723625787896;
        Wed, 14 Aug 2024 01:56:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625784; cv=none;
        d=google.com; s=arc-20160816;
        b=IzXRayyYe7wMayub2JnTguK70weL088bwMAKCP3daCEEjJZKFLFreOOZZHbm7xsoI5
         XH/DzRckaeQ4BzlN5o9M1JwdMjTmxB+Sii/5e/xzsUCF4ak5YCY41buOwi2AcTRjL4sv
         Qlla9TFfXwFZgy9WwGXVPS/rs/i2OzXe+lbvH6wGKVVh8JoYdCZT/Gu9h3m2LA7O1oNk
         ZVVzsdixrYiPCA3x5RLMDPUSdFaNGlNuTKhTe2EXJNzGl++QKqjsz/gXx2x3Nmn1Vlqx
         Bzgv1OvHIjO5ADKtPx15jSSSIJQUyfPWNSS1/x8RpjjOjsXKBKJFUcafUjiJR05OpU8s
         vFIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FOU7P9jn4wor6Rdt5JEa4HOxmny7NogNXhx9YRYE+tY=;
        fh=IvxtfuvYlOOAhnMtZQpHRgMPQnfeT+jJT822IeWOJj4=;
        b=EVijP6chQo/YBzowb0DYbMX5gi101zT5rwOEHIxf6oIIlYtNxr4Em7IXpi1pjBzqEp
         Bnzqj+ZRH7Wrt82BOTircgzE9BEBEb82Ul9NU9rLThCnh5W5b+59ZZ/3NzR/HbPRMU3l
         jadSXY+njYdw7V7KdY7e/cjjTZJDFO+aNtZjEM9qOLB9leK7R+LVw/LkQcG/RHW8ypMg
         9O4SYt426o3j9Lbn0XGF/eYM+jN+B5EJ4UaGQCE5efaknu+Hd/C/jAF0OWHkRvDdWnQE
         Zj9MhivUOqAkQrx8jx22MRNJjlmJkorZobYN1Y9o4UhrnXOmoPbCJ+1Jp3eDaQhYxxI6
         kcZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=SbTyK18H;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d3ac728c31si46682a91.0.2024.08.14.01.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1fc66fc35f2so5183255ad.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpBEXo0hGyO958Pj9IgkVORnDnhl5O110Hdq8GGOJLUNBMtJJy1F6eLdg2vur/7t3N6riHZsmqYPUGOEi5NAXeqYo9r+ilkZhCFg==
X-Received: by 2002:a17:902:e741:b0:201:dc7b:a88f with SMTP id d9443c01a7336-201dc7bae70mr15567155ad.25.1723625783955;
        Wed, 14 Aug 2024 01:56:23 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:23 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 2/7] kasan: sw_tags: Check kasan_flag_enabled at runtime
Date: Wed, 14 Aug 2024 01:55:30 -0700
Message-ID: <20240814085618.968833-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=SbTyK18H;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

On RISC-V, the ISA extension required to dereference tagged pointers is
optional, and the interface to enable pointer masking requires firmware
support. Therefore, we must detect at runtime if sw_tags is usable on a
given machine. Reuse the logic from hw_tags to dynamically enable KASAN.

This commit makes no functional change to the KASAN_HW_TAGS code path.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 include/linux/kasan-enabled.h | 15 +++++----------
 mm/kasan/hw_tags.c            | 10 ----------
 mm/kasan/tags.c               | 10 ++++++++++
 3 files changed, 15 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0c..648bda9495b7 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,7 +4,7 @@
 
 #include <linux/static_key.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
@@ -13,23 +13,18 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
-{
-	return kasan_enabled();
-}
-
-#else /* CONFIG_KASAN_HW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
 {
 	return IS_ENABLED(CONFIG_KASAN);
 }
 
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_hw_tags_enabled(void)
 {
-	return false;
+	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) && kasan_enabled();
 }
 
-#endif /* CONFIG_KASAN_HW_TAGS */
-
 #endif /* LINUX_KASAN_ENABLED_H */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9958ebc15d38..c3beeb94efa5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -43,13 +43,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tags().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
@@ -257,9 +250,6 @@ void __init kasan_init_hw_tags(void)
 
 	kasan_init_tags();
 
-	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
-
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
 		kasan_vmalloc_enabled() ? "on" : "off",
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index d65d48b85f90..c111d98961ed 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -32,6 +32,13 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized by kasan_init_tags().
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
@@ -92,6 +99,9 @@ void __init kasan_init_tags(void)
 		if (WARN_ON(!stack_ring.entries))
 			static_branch_disable(&kasan_flag_stacktrace);
 	}
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
 }
 
 static void save_stack_info(struct kmem_cache *cache, void *object,
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-3-samuel.holland%40sifive.com.
