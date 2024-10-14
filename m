Return-Path: <kasan-dev+bncBDAZZCVNSYPBBHUFWW4AMGQEIB5TKQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 7303D99D44F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:11:12 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3a3c4554d29sf8124225ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 09:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728922271; cv=pass;
        d=google.com; s=arc-20240605;
        b=HPOURP+sQkUpZ3aLnsj8bE8mxONfOFKKoHucjRtjl3YUCbfaSScpmB2aCszFMqWS2w
         pisLql3ASrdQmFlWxIO56GMukIaJxFpnsZRn57Vlp9KZC157YCMB/Ma/dqsUf/drdRD/
         VoiMozh6HnacldIUrrq9kGi4setPgyMjceFguyAwO3KTisRF10tbDULfJC1HEsFuEDA8
         0nmuWu0quRRFfGZBdcmHE27uGiwFsODyrjmn4QX+RS/g+MAz1f+tkEDp3vOEja74Juwo
         d9LIImI7MrFfx9OFuG7L2e3tHJNdAgKdly9dMnOtvr8dkBx2aVwYpoMV8IVFf0fPSC7n
         iRyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=UGuH1jcILdMj8DRHtNgUdL92Up/a1vlYcaQo/YnHnFA=;
        fh=Vdh7zhnQ2X33AyBUjUjYVVIhPYFl8HoFEwbJYQAyUXQ=;
        b=I6p4IO4IkfuENXHm7wkdMH61OUeX8RAXvY7UiBEbxBNx6sEoUOElF4xx+F44Tdai0X
         mcHQKCmoMKMoUgFXQcmHF6gYkjlodiujBTwiHfYYZM3TxNWQXy63Tiu6/S117lOa9G5s
         gsYMFyEdUpkeW1xJSGX4UfHcb7FZ4UxK81US+xrllXhFZIAS6KOWlfSlotqtkoo3Y76K
         DXFrDsJNAUsLENsy3IL/jh01h22DNGNe0izgav0h5qSB+36KMjaZtchh0B6KsUvDnyMY
         bqrUR7MC9YhQ4pGnnMk1b5Rhzc9w4hQqOvXr0dQDQoLD2ZlPTumQQhqxmgl9suVyPRhw
         yEJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="D/Adz256";
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728922271; x=1729527071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UGuH1jcILdMj8DRHtNgUdL92Up/a1vlYcaQo/YnHnFA=;
        b=rd9W5raeY8PYqIUVlNkJIDdRgC8D/wMMkFe8EKSkhCXzXac9Dq1dTeGGSjPV3e3vkV
         Itc2kIaW8RRPizwpLXeJCo/b57qqwR7kJygP6qBc9qKc2QVZDpmAEolqxGdvz78ZTByI
         ouHjzLvg09fL0gdaM96CDBE91zYWKMIuQfZgWLqpO0BmpTFXujM5ntvM8i9xi1yGd8Pg
         q4i9q7KmCPAiw5Txu2Tb6E9O3SPGXpZMOIn1Kq38uQ8PJyMS6ThpojXgKhlPKwpFREVs
         CtKde2CStAuVNmBYzMttLYi8CPTIXkMTFox+SINRKHIONGaVBWQ+V1ApiRKdUrbOm8zf
         rsvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728922271; x=1729527071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UGuH1jcILdMj8DRHtNgUdL92Up/a1vlYcaQo/YnHnFA=;
        b=MCvHJ/rU0LQOXaaHXlfdXEKB4DuUu1FS/h8N6l9+H3GNXp/Z4BgJREMNx7IDHpQ9Po
         ZZ1XKRCTvrF1z+anhUPLg9vy+WcqwPx282yaK87A8U/Tw6YTsAsnwETcfv6Ni+x6adMy
         VNjMmG4yL5JRJB8oOECUBHYDJAStHANnPC68TEYeDNsavlhKYs5+0RxoP8BnsUELL1k7
         arZQmJ+BbcKscS3c1TKO3V2uN8Y7ENHXfrTxU70ZW/NQXt+s69OfZ/jsUVyPZIFTF201
         QGHMODXn8n7cbQH4GBlthaoa7ITjc1nIhqYbvKt/LGRA6F9MxOkKdsywuwYDD/1LNzvI
         xMUQ==
X-Forwarded-Encrypted: i=2; AJvYcCX7POglN02xWF5/3trG8U51mf8LFO0YveA3D1mul+hNNW9vGOLpWHh8DN/HGNRwA+CC9PRfxw==@lfdr.de
X-Gm-Message-State: AOJu0YygOcr/r2d9KWCOAlYnD6nWMslkhk92EnqYg0xTHP8HjJ7uCRJj
	cYkxAY24P3HtymD+6XtH4ODwwE3VaLpA4pU7ehF1KxGGgzB5NtPo
X-Google-Smtp-Source: AGHT+IEbjuwykw3SnkkzW9cWGAeapzF15okMmAoRF15ZC8lFoRh+6FOdwVXFClfUcXmceYITjjpcpA==
X-Received: by 2002:a05:6e02:1d9a:b0:3a0:9cd5:92f7 with SMTP id e9e14a558f8ab-3a3bcdeef37mr60238275ab.17.1728922270823;
        Mon, 14 Oct 2024 09:11:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1568:b0:3a1:94ba:d618 with SMTP id
 e9e14a558f8ab-3a3a73702f4ls3188725ab.0.-pod-prod-06-us; Mon, 14 Oct 2024
 09:11:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfk9u+BoR6tqSGqrZ7+q7qbQXd7vdfHgRXg/fVvjDlQ0vCafQ3nuD20pWYIA0dutmXJmk8HI4/4Vs=@googlegroups.com
X-Received: by 2002:a05:6602:6407:b0:82c:dbf1:700c with SMTP id ca18e2360f4ac-83a64db132cmr703449239f.12.1728922269946;
        Mon, 14 Oct 2024 09:11:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728922269; cv=none;
        d=google.com; s=arc-20240605;
        b=J0pA6kaTXFmPR+XvPM7fC7ftdLCZywkMzmvH9ucItNH6+UFpvnikKMw8vJTspRKKOl
         zBe8jq9c5KIxdIIhH2kvAQtQmkeG1X6YidMMMogf96ms962ojxJpyzZvDnJ4UNeY8RnE
         Gq+LyPORsIn+gAilvzcjls3JADtyiEC3E9e4qdJND1wXxTYfpV2KzowZBo5046HYuVYb
         D4wvyWYirsAGuSJm4gZQ3m31nwg5CnkaGx0hEp5OLxmQCtCJsXdU8qL+Bv0FK/o84Oby
         zyF9LAoCnNLPdkxHDJ5wl1T2pSyLR7kDT0sPFs2IULBrO9ffpScCQh64bGpIaRBciTnX
         9liw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=llp5ytVzB4Ph0+/8a8EaRdT3yelYdQ+lkHdacYEmEGg=;
        fh=vnb5S2etyzxcpza6w+bAdqIfHs+EVGw961jW89IwqJY=;
        b=NKSBFHYBG5n6AcixT7xeN+RoJ7IftIu66a6rQysyL3tOBukiU3HhVJRRKSf88aM4Hv
         hxaVmlUOluuR9tjk8eagx9HPSCuRrvEu/6N0DMufGxHesfQ06aMKeFAtj14UiCw0qOZr
         lFvCXNVlnylFX7yO6CKslJb/9INVMJKXF/Nx+KROrBDics654NNDUAxbCD4QV4fskvnB
         O88ZmdJ0v80EXyEdeRg6l0C7Iks8CNP+vf3ZIM5AA80zBQlLC71Vzai1Ixv43B0HBPfp
         qFKa7bd6PwoEXSNFC8kfsItQDgH7VfQfnftl5GvsR9vkw3TDMlCHLG1BVARhTl5T7kEV
         y7jQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="D/Adz256";
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dbd6259374si103782173.1.2024.10.14.09.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 09:11:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 174665C4BEB;
	Mon, 14 Oct 2024 16:11:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5CA5DC4CEC3;
	Mon, 14 Oct 2024 16:11:07 +0000 (UTC)
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-arm-kernel@lists.infradead.org
Cc: linux-kernel@vger.kernel.org,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com
Subject: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
Date: Mon, 14 Oct 2024 17:11:00 +0100
Message-Id: <20241014161100.18034-1-will@kernel.org>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="D/Adz256";       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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
Signed-off-by: Will Deacon <will@kernel.org>
---
 lib/Kconfig.kasan | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

While sweeping up pending fixes and open bug reports, I noticed this one
had slipped through the cracks...

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 98016e137b7f..233ab2096924 100644
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
2.47.0.rc1.288.g06298d1525-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014161100.18034-1-will%40kernel.org.
