Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5FN6D6QKGQEHHTN4YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 96D432C1551
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:24 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id a134sf97051wmd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162164; cv=pass;
        d=google.com; s=arc-20160816;
        b=n1MCPAnKvS4aACrLlRF6+lCH7l1/ufN4HISjqHttSnCjNMnszoDQOhLJobW9zrCoSe
         tEu1Xamzugbz53Pww3O2yCYFdfhyAfZ8G07gbLRhG/jpXN20h0OMOaeZ3VyJe6G3Q+Gc
         6TLb2MFy0Maqg+oWUKYJRZpso2KMODRqDyjQ/ES8wPnC+ya074CGmQUjf8AbDf4aTlbl
         qKdbCWDiJtzIT6jhMYG/NsCQ1LYTkogM1hRf3Fs+9q1ri0PfXxXf9QHdNVdGNr6vjxRd
         AhsgLfhc5tgvEyQrhtEm4BLumvZDwFB/Z17eFgG0VoQi3T1nB5GfT0uiKc/vCoTAaef1
         /sRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=/x4xQdHrT9fysC8gG36pGvXFzbBV3cM8dsyjbxL9sXc=;
        b=qC4iHIBvbvOo7gwRmK+cBkCHofq19KvY2nK+cXmno6HavR2keaFvvfTYaJA45aNJ2a
         qQ0rxZcUtltT1VhcyiZSyXNxO1tFbJd7G4hQ4rXXOz/HKGmItfyEyHpCJkRKi7MpJs0U
         EI73uFs2jasnkqRQ6hxl8RGv8VGORHD0sQurXzQ8xsrJDYcaWukYXPXLtJDFLabVu8HL
         oevUD5my0kmLRsB5qOO5n/SOpzrzKk7u/YFTl+wndAKnI8bBNXYHbti34VgscGJCEDoA
         DkDETZXxuR0twHlIY8Me4tme46k4tNhxI4f2zf2xmfS2mp03GHUOgEKLEWCTQ3q1E9BS
         2/sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bzRUk7lH;
       spf=pass (google.com: domain of 38xa8xwokcryw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38xa8XwoKCRYw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/x4xQdHrT9fysC8gG36pGvXFzbBV3cM8dsyjbxL9sXc=;
        b=OV/10gEQpNofE92fzmX3urL838YJ9qiN603UmBM00SvAXGvZZxykMRvnvp/kL9c+bE
         KVuAiBcxR5AfmbVBve5HcfC1reFYGlotFiKjrqvl7064pei0XAglviXXd4K6ybGfFgiT
         iFq8QqKww0vDNnzIPCWIKjhpXVQ9BAi7Afo3ISvvtTDb/2mZNjw+FJoSboNAP92FHkFb
         ZJLAogQJ9fOQKJqai6ZBczXTxUe2yd0uXXendt2K+o1QluBabg4f5yvuHkPOiNoOt5ip
         i6jgsPFCXrzZjU+ifJQp8o56b+2Ba5wu1XOvc03a7iyf6HgLv9iFAWZibdKcWtxJVDx2
         3Y0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/x4xQdHrT9fysC8gG36pGvXFzbBV3cM8dsyjbxL9sXc=;
        b=oULeoznqA7OpctPY+8hW3vCC31OGDzYyMBRJUijmFfnHQkY3g9eGfTZz9f8FPR2eb+
         V2wf4AEbXhHdD54+7qnywvQvIvOdUgwSxCqV1rs7WjAomoyKnAQDz/syl+8HgTBWlYyQ
         3kFy4y6E0m0wCD91MjLxzLOjvmG7j1vmkYMN1UpdppoMjEUMGjRv46p6c9Y6Wl/c7RCZ
         n8GM7Wqr+mRy8jnHIlA9O7GqATpB+Pa6gC8I60WL7UTTFIivtxmsjGPvCFRjvS4o3zHN
         2QhayTgp9zlBU5Isx4Fiqxq3lPVha7H/t9Y0tk14yVdNPl6kJypCNr/O6DLNKLyb9Frd
         IoOQ==
X-Gm-Message-State: AOAM532Nm3K44uavn+RLTyBHchuTx2qzamFjD2wqUZgHl2c+pLwW+WGG
	i0sYJPXcdpWUQyvFHF/1P/s=
X-Google-Smtp-Source: ABdhPJyvi/+/oWZ41dElkjyrl9HmKoFmh7cC4TLqMPHHho+FL9iMyQwMdRtupIKxutLP9ygTPpNGBw==
X-Received: by 2002:a1c:f612:: with SMTP id w18mr610061wmc.11.1606162164412;
        Mon, 23 Nov 2020 12:09:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c354:: with SMTP id l20ls168703wmj.0.canary-gmail; Mon,
 23 Nov 2020 12:09:23 -0800 (PST)
X-Received: by 2002:a1c:a986:: with SMTP id s128mr604060wme.94.1606162163501;
        Mon, 23 Nov 2020 12:09:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162163; cv=none;
        d=google.com; s=arc-20160816;
        b=exSaQzjM7V8PIjPOrILOhokxYbuSQvN1kfItfuW1gRJK3pzzlRnVL2yxpPqec6J6eh
         ltzkCvBEtiKr6mvrve60gs4mD0GNr5Osb07heMet8C17VFbARpRk6r4YWRjRLAl72fjo
         p2baym9M2/BKjDbyf9bfBI1Lk8jW/3cmiOxAB76mPIV7CllFnzzF4aSY3eSmr5VLE3Fb
         eKJTjlbG3zgujq5hDp/jRwUk1dQhOeJBtBq5jHgmiG0USXHo0+aQUwfbdLo3ntSZOPGR
         V0L19wkvc70Y/V/V/BjCrB83iOtvgPWvWssavw7Ni/vWSzP/9g/a5j8Ila34tjHarzf+
         9JCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=KVSJXJK3L8qTAj65/VfUWb47G8JUT1DB2NysMQkgqU4=;
        b=FDwyRzz568BEyWm5YIbjqZGbn3C4rjaOkJ+q91ZtkbbgQ1wjSld89UNiyQ/8X2pCXS
         6E+7+Lucd3qdSqRS1bW+w948pSuSs9QXzl9OnXcCgarS8XFN2cProvhVZDai64/GO0cR
         AM7eyJsuDu3lG75tBRgUxUdC+H7TPylHCAPLLicu+aYzXjnR8BoKTHHLPGfuwTpODNzW
         Vt0HK3x21nc16mbfZ4NJ3siOP3t4ZyPkRP3a2N6ktQRaEiccgCVSuIONf8PAK9Yg0ZYb
         mG7wgc4+NaWJhuArUxcewfzsbLlaKVTeUwXIFro0UFDOtCPMSXWA/+w05pQ1XE8Gou5Z
         a9LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bzRUk7lH;
       spf=pass (google.com: domain of 38xa8xwokcryw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38xa8XwoKCRYw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y187si29301wmd.1.2020.11.23.12.09.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 38xa8xwokcryw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id l5so6217687wrn.18
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e3d4:: with SMTP id
 a203mr566406wmh.177.1606162163180; Mon, 23 Nov 2020 12:09:23 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:48 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <d03d1157124ea3532eaeb77507988733f5734986.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 24/42] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=bzRUk7lH;       spf=pass
 (google.com: domain of 38xa8xwokcryw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38xa8XwoKCRYw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) which
is an armv8.5-a architecture extension.

Enable the correct asm option when the compiler supports it in order to
allow the usage of ALTERNATIVE()s with MTE instructions.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I172e15e4c189f073e4c14a10276b276092e76536
---
 arch/arm64/Kconfig  | 4 ++++
 arch/arm64/Makefile | 5 +++++
 2 files changed, 9 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 026aaa64a7e0..b641bb6cbc73 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1591,6 +1591,9 @@ endmenu
 
 menu "ARMv8.5 architectural features"
 
+config AS_HAS_ARMV8_5
+	def_bool $(cc-option,-Wa$(comma)-march=armv8.5-a)
+
 config ARM64_BTI
 	bool "Branch Target Identification support"
 	default y
@@ -1665,6 +1668,7 @@ config ARM64_MTE
 	bool "Memory Tagging Extension support"
 	default y
 	depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
+	depends on AS_HAS_ARMV8_5
 	select ARCH_USES_HIGH_VMA_FLAGS
 	help
 	  Memory Tagging (part of the ARMv8.5 Extensions) provides
diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
index 5789c2d18d43..50ad9cbccb51 100644
--- a/arch/arm64/Makefile
+++ b/arch/arm64/Makefile
@@ -100,6 +100,11 @@ ifeq ($(CONFIG_AS_HAS_ARMV8_4), y)
 asm-arch := armv8.4-a
 endif
 
+ifeq ($(CONFIG_AS_HAS_ARMV8_5), y)
+# make sure to pass the newest target architecture to -march.
+asm-arch := armv8.5-a
+endif
+
 ifdef asm-arch
 KBUILD_CFLAGS	+= -Wa,-march=$(asm-arch) \
 		   -DARM64_ASM_ARCH='"$(asm-arch)"'
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d03d1157124ea3532eaeb77507988733f5734986.1606161801.git.andreyknvl%40google.com.
