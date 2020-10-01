Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF6E3H5QKGQEEF55L7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 652A0280B00
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:21 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 26sf58110ljp.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593880; cv=pass;
        d=google.com; s=arc-20160816;
        b=gOkh6BAjY3KwCLCdH2wqCRCuYPygqL5hLL10zH1Wk6awuzk4cxV4WZwhEuTAN7YeWz
         oNCS7RhBSExtTGV8YuQwQArIAAi/0LlQ5QV5dZOH5u7qlzsu1pZeIkMiF2kY54Yz3mrB
         ++J6q0qLlTpkcmX1iUBguboj9s/VoTIchVBJZxZD1XVWRM/biz/E6ZLgGEhjOmb1SJ5a
         82GdA8cct8BMuV2goLX3CSdaX0tj1h8VGkuwdWJdb/8DPEiOUAU7abyaSMynaGbF6Sun
         BWzHsaMZ5BYG9VkwTNKd6xzBtsFYa8ITgAmoE1rSDKwdCDxI2H9emSsSvL93Qe2ncAIc
         v4Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ovUHEi59Z8ZagzMqQw/8nFNv4D+iSLldAY+JfmlJNSc=;
        b=0MCoD0dYr8MEk8CByjLIPFJPbKsx+6BfwPBi0o4X2Peon6u4AVKb1JqJWTh3xgfCsu
         iIkK+TRiqjSlN5EMgz5uTesjyM9JtH+vz12VgLg83lDQ95fMAXmcOQEt+5aniJzqPIAT
         46V+QvL1094K+OAWida38jZ5ZtMov/0QS98r3+S0vGa9znGM+dl+wfXtEoPXDi/s9JRn
         qMdf3LQWccA8pjhbsPp9t0Fblarvy4cMYEamP+Y8M8m5AaYqEVN8A7o+L70Dj0KhHrI9
         LHPMvPWFPQOGYkoavbPb9aEePVi3xfosme0PoopoGB5tdsvorkuVpyfnu5JJ5jQp5EGR
         oBbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MhEOyfxK;
       spf=pass (google.com: domain of 3fmj2xwokcbuviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3FmJ2XwoKCbUViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ovUHEi59Z8ZagzMqQw/8nFNv4D+iSLldAY+JfmlJNSc=;
        b=Yqf/bngQJhIv40Aajr7dc7Qu3CtTPFGEZcDT8/8EuCqTS6gqyKbufXBg1LtASYBkB8
         9tBCUX8GOeM5CcmYmDrdMCE1Gs67QRit1PQmIfOZm3k9C3Ifz5WjwS/wUT+lzQyLjhh6
         gMpmLVh+H6/IDOyjvQQFHD2r576aoZUsnjK0uvBh+4GKwAeVsZ2QBgrJQn9PPd/81f9f
         VPtywn4lPiyNmQNwG9z9Gw0hCGUMHFdp5oETPc3qSaRaPMdNEV/xaU9rJohYqv/xLcO3
         J+DvxcLpoRLPKuZXs5KkAJRCvQ1zEI86KGuLq5V8MYv0zVp8Bov9MwOpGqHgAYzZj1F5
         Wl4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ovUHEi59Z8ZagzMqQw/8nFNv4D+iSLldAY+JfmlJNSc=;
        b=X49FXbjU13BEymNZYgLDhmxjjMcHOK4t/GX7ZvSq3NoDuXuGECQawktWSq/QbBOYQb
         iUIOJM778faPAXMV1Vt2BIZUZACuesQfriZKyT1ORmqATTf7iHAUH/hrFNJ4nzj/hbm7
         Y6ETznIgAP0fQ9Lp9mZiQDr3guiM+zkR3w/g+jHQakElkV80m9y0TAzNb5n1cTLrQ9iq
         PkkWGqhwpQpdUVZRClXH5u3xBjufjKwxPeJJWr9SMGWborj4LougHgIes4ZqYrbcs8nz
         m773mRZro2x3XrzMe73TDyun600ZHUjJmEkFOYyPl0nmi418BM6K566upc1yoc6vOgbZ
         2Meg==
X-Gm-Message-State: AOAM532Dn97uK7AgcfcPV2GjEbUoWa9uar6DJMa8Hg9ArWNoF6PL7MtD
	cVOzDBbdWEl02c5UCHSRj3A=
X-Google-Smtp-Source: ABdhPJwKp6r52qwpZOsor1G0mdsUW0HU+UOEUNC3xVL1nnB69NkGk2hChBucK6228hpugNyWHts9Lg==
X-Received: by 2002:ac2:5dd3:: with SMTP id x19mr3865011lfq.340.1601593879928;
        Thu, 01 Oct 2020 16:11:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls2140461lfn.2.gmail; Thu, 01 Oct
 2020 16:11:19 -0700 (PDT)
X-Received: by 2002:a19:494b:: with SMTP id l11mr3801743lfj.462.1601593879056;
        Thu, 01 Oct 2020 16:11:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593879; cv=none;
        d=google.com; s=arc-20160816;
        b=jdUzvKYaOs/3vlowby2S426EYz08N9HVIvOcb4GVmclFHTuxF99fVerNIMKluWU20X
         82ipI+2jCrWeAMyzr4X7O1MN7cWU3mdjNrqnIcVM0o1GOFaEtiiFEhjACBetwrotWffO
         U8rdXV/Nv+/gBF+BFSFO8Xwon2m11txm1Pms7VV0jAPERmp5zs/S85d3HEMHHCGVdksv
         TKCGV4caVYHsUlgSqfSTB6MFSgEaogciHVLhbPqTi7uYPmtCpbPd8bFVHASO+770UxG8
         J96lKJi4CB08nMIcerWdOWVio04TeIPx5idRtS31FJkqrqQKBGm752wskcDGAhahKtps
         EJBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=CEk0EFBZADwM2R3bxadynAWU1zHiLtW/CrSHzr2Y4Kk=;
        b=VYWwvimFNzQo0NoI/4mMecd4L/TYnsuJNIQnwe/8ro1YRR1vmd/SJ3I2KiCoL7EUEy
         iwcC56OQO+xNaHtiqwxIxC+HWI1eR6zxPwPsdvhwNfJK0EYoJuJBi8ibvUE07AhY2fIF
         lRERpVyeFwabie7+GN17IXhkCAQSbm+VThOaBZR3EFbD48zkPPu7qVaMJBbwvUnSCa9B
         vBZS77VHdX6usQjizcf+fqq0afDALyluL3W7LxiqHOgbvM8t7zixsFWpaRkHgb2A9mc/
         fzldV6z/jPJuwu6BTLpj/pWk+nR0Xh5+esSYe0OHbH+VYdeQw+D+ESaiEIyxjzvEOnuB
         03iQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MhEOyfxK;
       spf=pass (google.com: domain of 3fmj2xwokcbuviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3FmJ2XwoKCbUViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id f12si206145lfs.1.2020.10.01.16.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fmj2xwokcbuviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id w17so111730eja.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:19 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:5509:: with SMTP id
 r9mr10806797ejp.12.1601593878339; Thu, 01 Oct 2020 16:11:18 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:15 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <e940b95aa82b2976ecf7fcfa18627038b6f7fb47.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 14/39] kasan, arm64: only init shadow for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MhEOyfxK;       spf=pass
 (google.com: domain of 3fmj2xwokcbuviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3FmJ2XwoKCbUViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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
index 7291b26ce788..4d35eaf3ec97 100644
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e940b95aa82b2976ecf7fcfa18627038b6f7fb47.1601593784.git.andreyknvl%40google.com.
