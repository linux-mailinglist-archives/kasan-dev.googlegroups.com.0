Return-Path: <kasan-dev+bncBC5JXFXXVEGRBHGX66BQMGQEQYA4GKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 06BA7364B60
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 22:44:14 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id o24-20020a17090ad258b029014e8a92bbeesf12870035pjw.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 13:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618865052; cv=pass;
        d=google.com; s=arc-20160816;
        b=vx9LgufG7FxHyASWXAyaaMerAlyxZSg5+6F5TX8xBzVMALlJAcJGGvaGdSk9r7mnRN
         xex9k4Tvm/08hI6Fmz5IJK4jJvEiMA9zUhfgpescSdxoaKamFKPA56wDZYXPnoSfGcbc
         buLyFv63EokbTuccvgBRnXWIsQVi18O3QL8yNTsMtPXBgFoCBTA5Tlg3+0xDC/G9FTgY
         u//qKBtNK5CH/yMloyL1o74BhH6JQUDhHKUzsWPKyUcXAvfm2cd8SSmJa/TAtHVuVrye
         Cu4aH6L2z1QTPrTRe5mUO33Uj140Ou4VacLUDhZRZ+0of+aVWGwgezL6gsQdT5Ijd+e6
         8/Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0khyGCFev7s0S8WwEQirF89ewywLMSBZvqxDYk/LiB4=;
        b=k5vPpxj0R5tQHa1KKWCVEqsJPGpVCuIgBglOUvSYJNRtsHwREPx1uXiEYtZWWS/SUd
         rJOqopiG8DFR9ZA6Ny+kxSIgv0MKDvoHtcmJA8TKTHOmj5ARByNL+NMhQ2Ea4ecwIFqY
         WhF82TxhpsQNDvNsTU6/oYHW8eplZFkx3dihxhObMRPJhJDjCMUxglv03q2gUSlnFL9f
         TKPvEfQc3ySpUZVZ9rE7LXh4/fHw4WjV1SiHLU9DZLVDpMSvmejlsAcWclZ5n2et3x4V
         w2dM5R3d4KptVsFCaRaQH1OGoXsAr0IDWUoRorgK/s8SvKvigOyioCBYS4nVWiSE3mpD
         vVbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="sm/u6upV";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0khyGCFev7s0S8WwEQirF89ewywLMSBZvqxDYk/LiB4=;
        b=OV2zP3MO7rVmlNrP/Lrk2qqP8knuBDCpDAmgvAYfHDUDSU4iYK9KPKsf6tw0NoRuLE
         c+J1y2mehiJQ8O6SYDIEP+8jZTskkY2cNPHacUIVzZBi71M3DXfczW4nMJ/HcMAfXk5i
         TrZ6f2r4vCejNv3sLpN1wYssIVovB0F/qlD+hA0caeeHwjuK9xE9XET/AA3CGDIKp6+h
         YFwyNxD/r4mwgo5kNLQ2mDLhsU+8oC3R/zkIqL6LnBzQLw1iA8ZXZY3MLjzt2vcqUrVD
         3562Ss9NMYLEEXhPpf8ElfovOdP+1C0jmxwMmpnQSKXq1GLZbDUW5OEcow2mjgMqj/hW
         37lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0khyGCFev7s0S8WwEQirF89ewywLMSBZvqxDYk/LiB4=;
        b=nFG/sc0T9lu7ORLYuiE0MtZT3CcOPj2rZqaaqFGSlQr10isly1y2F/esEMYN9w6teY
         IDoZ0NRBxKqpeg0jxSOfed8eaxpfWm1dDuLMCrvd12uQnXQTRoQ8Hi+7agTJrzu5/ZAq
         86FzvWX/YI7GLP0FDOSUgeZtS+xbK0r04Mro2uYWLSdlJUCdVIS1wuR0BmmGEqv7z3TD
         5tmeYg5WU3Cwvs/d+dE7HCZSeB+dbsbDzI9F98bn0QX9oA/c/kzEwhSGOYKhwP+o7I3j
         1mg4GGlW2tUp5u6SFt8L3IxhwD/hPQ+WrpptNA1n5NHt6/8E3eV7b2iW1GMdWuS/3CiU
         eTVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lT+rxWwX6lazeHMDlOgx4cf9y52WFjSiZZlnSXdiPxv/6FwMx
	rsMB+FWIul72Hp+8G8zM+qI=
X-Google-Smtp-Source: ABdhPJzMNYp3fXGKrO1wdn6fA/skvJ3R+IaFwFaAH0HvRfDQFlIRqcsLB6FMIl1cQCh4NdF8+5fOlw==
X-Received: by 2002:a17:90a:cb85:: with SMTP id a5mr1043431pju.124.1618865052697;
        Mon, 19 Apr 2021 13:44:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1492:: with SMTP id v18ls6999952pfu.0.gmail; Mon,
 19 Apr 2021 13:44:12 -0700 (PDT)
X-Received: by 2002:a05:6a00:1709:b029:25c:f974:e0b4 with SMTP id h9-20020a056a001709b029025cf974e0b4mr10890506pfc.81.1618865051929;
        Mon, 19 Apr 2021 13:44:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618865051; cv=none;
        d=google.com; s=arc-20160816;
        b=0SBsMzWaMPiJNuHXciT0HAklp6rdhk6Fi7vB0rodapDg2gd3frFGwqOvGdx4RokJgY
         PmXNzs9cDmOTf49wcHU5G/zWBLFDk0cu3a/ScPi0aAdtg+opE+g9Q+E0gIEVNZRfeKkZ
         RWGDAOvYW01M6Gj60sQDUQTzw6p6VV+JuUOyNiKQNz803LoVYGu9Y91wvGxrdjH/aFTk
         wA42PY9r0awSp0fLeLkCo9NF2n7jadwK345KB4+fiqrI6POTZHwRBlwQMauFpsDorwwc
         h04Y4gi47SKoyynxVuHUmgeH2P4PGveL/eiyTTQZtc/iWe7So5p2ulXRtBUWwp3Ip2y3
         FiqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TvQSC5X9vTcZkOP66NgOg7owX0RHKHn1QOU7Yzx0kPQ=;
        b=JDyla1B7P317bZeouE/JBaaL238lBRdRh/8GwcGh5BS8Vns0x0SpmtYKxJnolgJT/5
         bNsXU5gQel5/jkQKczH6QUtMu1xb9rS/rqcFEwtd1zwGGIctZxVAOwnCEwUTnrWpE9rc
         cMvm53sT3PbAv7uGxASeoshvKueeSYyzLFN4GjGybNXRuXv0yiVnr8q1md94kDFgCxWi
         XsKxaBs2A2OuUgTCNqz3CJAxOt7LGdA7J3HEZyoAkEtaNjOGjo9LJoqLOTjH1GPAiznJ
         vYpuCedT/tsBoiVofdgT0sFZq72WhLLsAhcteMIkTuLbW8Msk5gftuqfAGmxrv+rQglo
         q96g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="sm/u6upV";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i18si149427pju.2.2021.04.19.13.44.11
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Apr 2021 13:44:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 61DE161369;
	Mon, 19 Apr 2021 20:44:09 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	clang-built-linux@googlegroups.com
Subject: [PATCH AUTOSEL 5.11 18/23] kasan: fix hwasan build for gcc
Date: Mon, 19 Apr 2021 16:43:37 -0400
Message-Id: <20210419204343.6134-18-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210419204343.6134-1-sashal@kernel.org>
References: <20210419204343.6134-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="sm/u6upV";       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

[ Upstream commit 5c595ac4c776c44b5c59de22ab43b3fe256d9fbb ]

gcc-11 adds support for -fsanitize=kernel-hwaddress, so it becomes
possible to enable CONFIG_KASAN_SW_TAGS.

Unfortunately this fails to build at the moment, because the
corresponding command line arguments use llvm specific syntax.

Change it to use the cc-param macro instead, which works on both clang
and gcc.

[elver@google.com: fixup for "kasan: fix hwasan build for gcc"]
  Link: https://lkml.kernel.org/r/YHQZVfVVLE/LDK2v@elver.google.com

Link: https://lkml.kernel.org/r/20210323124112.1229772-1-arnd@kernel.org
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Michal Marek <michal.lkml@markovi.net>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 scripts/Makefile.kasan | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 1e000cc2e7b4..127012f45166 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -2,6 +2,8 @@
 CFLAGS_KASAN_NOSANITIZE := -fno-builtin
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
 
+cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
+
 ifdef CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_INLINE
@@ -12,8 +14,6 @@ endif
 
 CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
 
-cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
-
 # -fasan-shadow-offset fails without -fsanitize
 CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
 			-fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
@@ -36,14 +36,14 @@ endif # CONFIG_KASAN_GENERIC
 ifdef CONFIG_KASAN_SW_TAGS
 
 ifdef CONFIG_KASAN_INLINE
-    instrumentation_flags := -mllvm -hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
 else
-    instrumentation_flags := -mllvm -hwasan-instrument-with-calls=1
+    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
-		-mllvm -hwasan-use-short-granules=0 \
+		$(call cc-param,hwasan-instrument-stack=$(CONFIG_KASAN_STACK)) \
+		$(call cc-param,hwasan-use-short-granules=0) \
 		$(instrumentation_flags)
 
 endif # CONFIG_KASAN_SW_TAGS
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210419204343.6134-18-sashal%40kernel.org.
