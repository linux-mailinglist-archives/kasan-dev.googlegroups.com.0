Return-Path: <kasan-dev+bncBC5JXFXXVEGRBH4R4S4AMGQEBJA27FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 397BE9ACC57
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 16:30:58 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-288c77e33a4sf4679362fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 07:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729693857; cv=pass;
        d=google.com; s=arc-20240605;
        b=hx8qW2gSjqiXAwah8QXw+VvoUkb+/fLuGMV6knGIeEygoHXEIbuRnwszvz1jY1PvNb
         3JoIttZTGOZsBHTTbBcmidqjIZQh5DQLtPcBUW3oYTsG98/VHovkEoJt1u8zsXEjLBZF
         rFXq1JoQWlUsKU5L7aVlu/28AS1iT7+2tUfaCEySu5fhgmRFco1DHJd03xjYmfM3+19s
         TzrQoO3NqDZi7xXPRILiEaop8SnDD4SgEOJ4OQ2rk1SMGefagiDNDi8YXOUQxVWXMnfd
         SoHpZ5heftPIkSLMLe8RC6SFIExM0bcx6sn/c5AOxaW9TSs2ZVgfU4UM6QQFp98QXNQG
         Hbbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=mqkLy0zEaXPRs+IkEWBODgTVZGXHhrdX70o4K9Aw1MU=;
        fh=YdYNLhqTjMvMEpm8WTxIbTqR20Pvqljq4sTww6TqGLs=;
        b=fb2w7/Q+OAWQmcs+6/X88VeCTLgQEYo7C3FmLZNmEK7+Sf9pXFrvDodm77wWm8kHpJ
         kCBcp7AJfwjJRfhtp2Stib6vm4ITDbPbFvUvdbQnhKU2Ecxfz53Dg00pvT1M1j0kkaDM
         f8MMusbFNUCCq7rcFrwr6/Mo98xzYBWA9sQh6v6+wOkcKQxfJe/aI6efHCU4maglQSqs
         jF6/BbDrWoNEhCFZsuHBBsoyuR+vX3GidNshS8Q97QDeJls3bQBcGHB5z2ru/QN8z8VR
         DFKpYBKnpHEF/VFnXZZPsxfVaRK/KshXvoFOqiKEWEIb+wrj/qQfmEpag4pmavF6Iqdn
         f09w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j4CX1yg/";
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729693857; x=1730298657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mqkLy0zEaXPRs+IkEWBODgTVZGXHhrdX70o4K9Aw1MU=;
        b=eaRPmFs+hs9uoMqqAlfXHKiaI++NxkWyByoGL93KIuq/Nc/UOhnKGN331/hqashNq5
         mb6Yh/19l9QAjYrza/tJKqVYks83qDuikagP6bp6wSFCi2PdHCu1Q56pqcR2NPnTlXFq
         GsD7+VzRbUil0DNNW3ie9bfi5Ho/EbqIQ20zrohM8po2SljtIp1zzFRbN/r8w286oO1E
         W8Wnf5BZCYArNbYcoX1El4wAKlXJX0N5xlgCkHp1S7Gph7IKkP8kRu8w477rwo5SBfel
         jBeK5NQ4lJxZI8bSfgq/59+u4u/vrB1ahsD4dCDcWnN3Yg+7kIiwBrIUZxTsZ3S7IYRD
         46Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729693857; x=1730298657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mqkLy0zEaXPRs+IkEWBODgTVZGXHhrdX70o4K9Aw1MU=;
        b=gl7A/Asi1QHc2X22uulmH95hdePWXOsLfR6st2Vj2DgtILXYmq4gzNUe0hawC/LlSe
         lk2LNSpx+M3Q11FGl21M4WquIb5nVw3+yN1zacmQuJBbFPeRSYFNZGLQSYzpFGo6sKyG
         s3pI4J5hByH5H6GqSOqii58xsGJiAR2fYQdKr9G6lwAM0YnLbCkH2pT0p+7Jd77ZofAG
         /WLJuRMX/6tqig0CfUZ6NuY6YnvjBnoikfoxOOqPlB2LPp5MiOJaYI62pAE15VRh0VT0
         fMOQl6KShF9uRTHWpduOOfP+bg2gXeYVfKBTyBiyOSIaLItv6RbRh54kdU7fecLVOH4p
         U2DA==
X-Forwarded-Encrypted: i=2; AJvYcCVP/Soy3VAtl5Z82OoYRFzjo7eSKJOjqFv9QOv55ecQudqCP1kjIcnaj8OhJPA8VPH0YHx4WA==@lfdr.de
X-Gm-Message-State: AOJu0Yx946Pj+RGQUnCG4yv/ihQurEsj4KrviISzqwmVo/uQLSzlo7CX
	ybRBoyH3Ip0NHLz7yQR4InAkMb2Zx/K5cLtev4afPiZ4+1ZqUjs3
X-Google-Smtp-Source: AGHT+IFK+SkyPNkqMiyq2xBsv2no8o7fcS6Kot9qsezgX6hpAuhvfzqN/XxIogokCE8Xu2fuyx9R8g==
X-Received: by 2002:a05:6870:40c5:b0:287:3d2f:468c with SMTP id 586e51a60fabf-28ccb5dca59mr2921864fac.30.1729693856129;
        Wed, 23 Oct 2024 07:30:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e98:b0:278:2606:8489 with SMTP id
 586e51a60fabf-2890c820956ls5301664fac.0.-pod-prod-09-us; Wed, 23 Oct 2024
 07:30:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVgVrChM7lRdzYjxdMI+W51ztobCXiMcCm3ah+2HtRyeuSWLaNkrBWlVAZxoToA9sSJnQf0iztKHiQ=@googlegroups.com
X-Received: by 2002:a05:6808:654b:b0:3e6:2894:28a with SMTP id 5614622812f47-3e62894028dmr1027801b6e.39.1729693854860;
        Wed, 23 Oct 2024 07:30:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729693854; cv=none;
        d=google.com; s=arc-20240605;
        b=chKrkVh42L7c+5/1+wEOQ2VMKOFiGzCLxU8yTD0RoWunhIhKnouTbiw5178FARm5CC
         v8ggQ6qSKxaIk8GUDuVTrtR8JLCZF2DoIdPzoV8fwwMY7KbVU6P2vGuaown9JJBhccDD
         FYJsgCrUi7ilcuToLF62YfcQ03qU7PDwi6cFH57BIvY9rpCRCIykzsIT5jjwQWHQpPZi
         V5vK4+D/WcDd/CUgQ5LYt8ybXtDUcwqy+ZnXSxBQlledR2vX/8jv5U8tyXtqgFtHjrP1
         yyoKs2Iv370AgpBT3IRMCsTmui+JyQG5gH+1UZDuMEtJ3lI5jy5t+qQygueQmZzpQ4KQ
         hZYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wXvB12KBsNJDD89HU9DeSDzk6HNgm2DOBHESxK9mU80=;
        fh=2zoRfZ3GqwaOB86OT+ogluMCAewlKKw5Tb+NnXhkKI8=;
        b=C506K+KJwf8h501eQDNxlbnwnN+k8hnna88r30HZ0f/qPIXEBq3rK781OVDsCbGsde
         NUqx7w1J9evMAG8e9sAXbhTTRRXx8/JTCWXRtuM5YzD08YcdqF9oBXMn77E/iJ98P5+B
         JGFnVxFiJwY8LkYi2gm5xI0t0fbXf6sdKQIkVog/38Am4/tWP00iNxahYu+I4Td8+CAQ
         n0y7ibzKAfiXP9fc16vzJ2e5fcy1C3HaZkGbtvcV8D7PRrHi02EbtMWr00MuKRU7Xa7x
         GU6wszaljLOQcDHQIG7Mks5+5TIT3ol1ADXrfvJfxaVSVX/aHX0ET4SDf3J7bA6SpwwC
         Qt2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j4CX1yg/";
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e6103b43d9si362701b6e.3.2024.10.23.07.30.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 07:30:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id F3B1BA44C29;
	Wed, 23 Oct 2024 14:30:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AA69AC4CEC6;
	Wed, 23 Oct 2024 14:30:52 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	Sasha Levin <sashal@kernel.org>,
	ryabinin.a.a@gmail.com,
	nathan@kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH AUTOSEL 6.11 23/30] kasan: Disable Software Tag-Based KASAN with GCC
Date: Wed, 23 Oct 2024 10:29:48 -0400
Message-ID: <20241023143012.2980728-23-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20241023143012.2980728-1-sashal@kernel.org>
References: <20241023143012.2980728-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.11.5
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="j4CX1yg/";       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Sasha Levin <sashal@kernel.org>
Reply-To: Sasha Levin <sashal@kernel.org>
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

From: Will Deacon <will@kernel.org>

[ Upstream commit 7aed6a2c51ffc97a126e0ea0c270fab7af97ae18 ]

Syzbot reports a KASAN failure early during boot on arm64 when building
with GCC 12.2.0 and using the Software Tag-Based KASAN mode:

  | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
  | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
  | Write of size 4 at addr 03ff800086867e00 by task swapper/0
  | Pointer tag: [03], memory tag: [fe]

Initial triage indicates that the report is a false positive and a
thorough investigation of the crash by Mark Rutland revealed the root
cause to be a bug in GCC:

  > When GCC is passed `-fsanitize=hwaddress` or
  > `-fsanitize=kernel-hwaddress` it ignores
  > `__attribute__((no_sanitize_address))`, and instruments functions
  > we require are not instrumented.
  >
  > [...]
  >
  > All versions [of GCC] I tried were broken, from 11.3.0 to 14.2.0
  > inclusive.
  >
  > I think we have to disable KASAN_SW_TAGS with GCC until this is
  > fixed

Disable Software Tag-Based KASAN when building with GCC by making
CC_HAS_KASAN_SW_TAGS depend on !CC_IS_GCC.

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Link: https://lore.kernel.org/r/20241014161100.18034-1-will@kernel.org
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/Kconfig.kasan | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 98016e137b7f0..233ab20969242 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -22,8 +22,11 @@ config ARCH_DISABLE_KASAN_INLINE
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
+# GCC appears to ignore no_sanitize_address when -fsanitize=kernel-hwaddress
+# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=218854 (and
+# the linked LKML thread) for more details.
 config CC_HAS_KASAN_SW_TAGS
-	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
+	def_bool !CC_IS_GCC && $(cc-option, -fsanitize=kernel-hwaddress)
 
 # This option is only required for software KASAN modes.
 # Old GCC versions do not have proper support for no_sanitize_address.
@@ -98,7 +101,7 @@ config KASAN_SW_TAGS
 	help
 	  Enables Software Tag-Based KASAN.
 
-	  Requires GCC 11+ or Clang.
+	  Requires Clang.
 
 	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241023143012.2980728-23-sashal%40kernel.org.
