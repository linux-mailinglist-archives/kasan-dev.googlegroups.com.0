Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKGF3H5QKGQE4LW356Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 62F8A280B3C
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:13:45 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id m203sf38642qke.16
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:13:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601594024; cv=pass;
        d=google.com; s=arc-20160816;
        b=F5iaUk7Ac5LZA+9TgEEQNPC4qOb2blr0SoLO6A+G1HMJCSa13k2TjuKqMlGr+O3wUY
         tuhCFl1s0t/DsGgzbvu4ER39QzthBUvF/XDBvUfR5WByOYH1W/RzbiyJ7NNbYDryoFGV
         92mzsGErVzO63dh4e1uSvn9AqF92RVGQZCA4aMe4e8Yk5Bmuk/WEXKRDz8ToORJFlopA
         n/nnj3p4Cm0pSs1cjYL6oz65yku4q4FI8lVZ2xicjLyoTkXz7PW1zqSTjClf5tIBkxGH
         1Un9pISJCPWrN1i/oaI8jn/Y6NxR1uqFswA5AAw5rBO+Y0+7j8slTcl1xfl0e33Nte8z
         GGPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FdhuW4k7G5OmCGfO5QX8Q4V0zXXXH3d5E9DQ+taDC2g=;
        b=ImVgo1ZCrMj6Oo0UGp1hcfTLCgNLI1Uotkc4JzdIevlLyzHnQdH8iN+pOdjjzYo58c
         ryapc9BNslRTL5ZHoUCm3aEFJj+3vn5Yl0cjuYdXFBnQ403Ypz8ltWQXfQWAEPdjV5K/
         gfiqM5ut/hmUB1joTytF8BhWzDJaSlG0/i6mT9Rye4b2ucxEruAlxAmwISZSYkuj+XCU
         VUYomwu/PqbQqKAzRFw0iHLmvP0hW5TL/apcSjOypMKYvJajiGhkgYve6xgBxIkSeX7H
         P2ORlRBLt73NdU88cTn2dSsWuqI06qBsbz0N3BtzYWOX/XFaA+kI7uf+jba1bj0Y+cgn
         nU6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hxySTHTf;
       spf=pass (google.com: domain of 3lgj2xwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3LGJ2XwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FdhuW4k7G5OmCGfO5QX8Q4V0zXXXH3d5E9DQ+taDC2g=;
        b=E3dhu8MROfDVezIzetCI953LvkTtOslzYWIuIq23A49NtHcLiijPkOQLf/4VJm1jW3
         0aF53KwMcllCeSk8pBz+2d1PDGmnFyKrHsT1sTXqRRLOPUYFEGwSJSUGdTTyIlNrYk6T
         2ctDHdTxcC30yFK+Bv89BYzxzSwkV6RUlM5rjAOFomCyLupMJR2Ya6FAyGHWJHSFs2QE
         r30xyYE4IyWSRr7w8OpPjr5rbzqTLNs/ifkXEOxrMkObFPbN6595G/NFxumcI/0YV/5N
         3Rgdl2eMYMJbMTR5WXB3rpmg9/8WRO3yQm5X+8hH0ACgNNxCoLWG4fUFBN2AA3DmqpOf
         /9jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FdhuW4k7G5OmCGfO5QX8Q4V0zXXXH3d5E9DQ+taDC2g=;
        b=gIy1oqMF4Ig6MR0JQtHofxiyEEI3TTEUz1bP0JxHUiqUJDjCxb5yyYowUOSj9rMSBO
         ymDxEVNrbgewKFiqepyLPEKV/S4zTqXSXCH1VfgkJBe1LDuWKmWIgmjFGOOjWddINyH+
         dB6Ks0V4j8yY++5hYDr2BGfuxCelZqrGgk2qZ3NpBpmtxkPvy0+HXtsWFZPn6oe6yoiW
         aN1tIfFrO7pfHbIJ/7JnZLnjBuAr/+wOiychiJDVWSZxI9ryl0pMO/EJ5ZSD2/CLfezZ
         gF225oKQvKdA7CLCHl0+jhMe2/axPRuCdKPqOfN0m7ISBtjnCJY7sczPSRHNO1TAJYfZ
         tEWw==
X-Gm-Message-State: AOAM5303JlQvsgSiH5FKQ+ZsS590TviG5nKqgDOt+gaa4cFLDFgZnJb0
	8t3JPePjg8SzaP3bIRsFYWk=
X-Google-Smtp-Source: ABdhPJydTt/+nT3LJmn7wOZ9pk/bFv8+O9L5sgc4h+UOfsyIvQUnw0J5JRoRyPZcq9WiyrogakxZkw==
X-Received: by 2002:ac8:47cf:: with SMTP id d15mr10259120qtr.197.1601594024496;
        Thu, 01 Oct 2020 16:13:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:59cf:: with SMTP id f15ls1124315qtf.1.gmail; Thu, 01 Oct
 2020 16:13:44 -0700 (PDT)
X-Received: by 2002:a37:9e8d:: with SMTP id h135mr10047472qke.493.1601593900477;
        Thu, 01 Oct 2020 16:11:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593900; cv=none;
        d=google.com; s=arc-20160816;
        b=YXPZjA22Mp3U0YuW9OH/gkp3c+oUBV+NeS5kwwc62Mqt5gXMwET6R/hC/iZ9yezam1
         rzk9eOBr+jbYylMrb9SqY3ppuGsNzoPKA26BxkbTB716h2WC8GCYz2bUEc2PQJKfZAw3
         GgmrCFzDg83B6jAe3vWGa4dQDMwW/+8nsN8Lc2TryXWqbVsoVPufIlT+vK9xJi83zsie
         qnRz+jyYmbpzDUKPfnvLSQ2SSa6Fs9nH8fMog2q/McpXaIGztMjU+Yyn0Y51BcDeNxgY
         D5JcWc4RLxaGWMg8pKJzCjSnV1JA7bFxGpDFVE+3hbtaaOfphf1DneZ4orfKiho28wWO
         8zWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/i/oGMXlxoli6h4O+lMoZppzKevwNPdee32h25HwaEc=;
        b=ykTQySjIEX6VOS9EV/PM+m10pJD4OhJRAJrMECw8Pt/MqR0u5sjN5urmp3bMw07tKi
         F2yb4hF2qrD31XlhOICPV3eVevdgUD4wExtES0VgK+bTC6kgCLHk2B6t8sOwVZThLGNu
         dHJ/X8Snzc/0O+Zs4uo2DKEMCcgLpJ7rp4Mt3etxE0lcN4QvTxZFiYWhFGUm6z60QWLn
         gw9vGCzSrDNbPtIhSXChpv8u2Gf2ijBzWSQr+Qd23328OFWrMG44645tjMwemJoaHCFE
         RkAs2lsfGai6tloBRRGhG2BCuah51m/IewTroyhMAMrteuPaRR47Vgih0nX/3Ecy9hFm
         2pog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hxySTHTf;
       spf=pass (google.com: domain of 3lgj2xwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3LGJ2XwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id a27si497311qtw.4.2020.10.01.16.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lgj2xwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id y2so236549qvs.14
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:40 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4d52:: with SMTP id
 m18mr10006770qvm.55.1601593900111; Thu, 01 Oct 2020 16:11:40 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:24 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <0215863872e20c790d7a17bf5f283512a06ab9ff.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 23/39] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=hxySTHTf;       spf=pass
 (google.com: domain of 3lgj2xwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3LGJ2XwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I172e15e4c189f073e4c14a10276b276092e76536
---
 arch/arm64/Kconfig  | 4 ++++
 arch/arm64/Makefile | 5 +++++
 2 files changed, 9 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e875db8e1c86..192544fcd1a5 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1600,6 +1600,9 @@ endmenu
 
 menu "ARMv8.5 architectural features"
 
+config AS_HAS_ARMV8_5
+	def_bool $(cc-option,-Wa$(comma)-march=armv8.5-a)
+
 config ARM64_BTI
 	bool "Branch Target Identification support"
 	default y
@@ -1676,6 +1679,7 @@ config ARM64_MTE
 	bool "Memory Tagging Extension support"
 	default y
 	depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
+	depends on AS_HAS_ARMV8_5
 	select ARCH_USES_HIGH_VMA_FLAGS
 	help
 	  Memory Tagging (part of the ARMv8.5 Extensions) provides
diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
index 130569f90c54..afcd61f7d2b0 100644
--- a/arch/arm64/Makefile
+++ b/arch/arm64/Makefile
@@ -94,6 +94,11 @@ ifeq ($(CONFIG_AS_HAS_ARMV8_4), y)
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0215863872e20c790d7a17bf5f283512a06ab9ff.1601593784.git.andreyknvl%40google.com.
