Return-Path: <kasan-dev+bncBCJZRXGY5YJBBP4Z4KDQMGQEXRKB3KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E5A653D18A9
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:16 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id f5-20020a92b5050000b02901ff388acf98sf2298010ile.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901695; cv=pass;
        d=google.com; s=arc-20160816;
        b=xrCkPJoIYqNMdZHCA0wlUC7qYVrcCkvwKgqgxSr50JZbaQGXZWz3C4kMHKYsCYbWzx
         +iS81q0OG+UexkjqMaXNZD/wtEcYqnDiSmaC7I5KkhcZY2Lv/wrMxyUk1OgF5Je9Ekj2
         aPo/KWq+eOsWmP6GOnn8oqEdhTQOJjv6xFTws9R+b1snoTLuczWK+ja/6AEo69a1U9UJ
         gEvZMEHIHUqPZGmTlbTCk4yw8Q8OXrw1AuliUKoLlmCydkUd0a6f5hRCkWGu45B7l0XI
         LRc8pgKaMZLRDS7YZhFKWug9XJOv8sq5whFehJ0aCfaw/Np2W3rfqhho18fBYkKccUeo
         /7cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6ir8aZyicZwhdJPjc80tKsP31MIWoFHbsDyuwTEKDKc=;
        b=Bu4xK4PwCthvSIXLQuDCWxkTDV9NcsnZoRFMpmAxFwhbSTZ1Roq/u972LW1RcxPH/8
         UJFpt+fdLHdZ0qj0T+xSn5EWcv3sYl5miY0GQjciBdO3rR+8gw+MFs2k78pUS0+bEN6l
         Xr+x8wPg3kP9stElTEflajtwNh23eWI/dFW3f5+M4lwCdnFnZLOa2aoxOJWxbXDZcSp6
         jMTltULBqN58uYAUYWgi6G3tn5V4jxTg+WzEmeAfU1cx9bYeWSZco+HRSimMLeLpvyv0
         f3ktEBLv1kGzSzZzS1u6QYk05LmYyWBMxDs+3eyYUrvB0PfBEd0i76cjXjUu1j84jGgw
         QE7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mv0cjSVM;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ir8aZyicZwhdJPjc80tKsP31MIWoFHbsDyuwTEKDKc=;
        b=V9rogNeZxEPr5uai8arl4/Nm09vgilb61vDWK6KSQ9f63E0g+aO49/uVM7Z7HwkPy9
         n2gP8dMQRorTMbysJTwwOgxynF7mR2BIb8y8+ykrvfIKeukHmfisWIyleRdlAgUaAj+q
         YlMoOKiGUHOdihsKPSxRN35rJqb9FeyTITd/CbFpbiybiR/yEp+CxClWbG1eFEhUmhOy
         8Cooe5KX3U78ly8xCnqql6RwSs/TTdiPRhDDpP/nJLnWDZAa9IdscQdijKeC1jDAPvkx
         8bJeaZDBs5bkeKQGXsp5jFA1ePd9gwHpjRykZpFrR1+dexYdVjJCWml3B5q1x5XQafSL
         rSAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ir8aZyicZwhdJPjc80tKsP31MIWoFHbsDyuwTEKDKc=;
        b=Hye0x08YB/M4Y95NFx6BEdPdpY/UkBrrWclAfywhyAxxfeXAfA8vHSi6txwgO7PbEU
         Ym3Xxx7vRj0NQZlRKBov0gSFXbwVEWOcI7wT2y5ZoTppk193TvDNWVjiHnozM9FHPnFu
         dHfrpSJSsVq0J/MNjvl6pTySeR2CzIYQfpvdhKRTVWhwWfJ110SZiQuH4ZX4tdKf0z3R
         4wP4Y0CFMmZb7PAhxzacbwoXVHx5rwGINfa9s1BtRRG1zI38HUI+M2JUpQD7FGoD4Pf0
         NIcPHewd65T5fqzxYrVi0Wl1DiVutMGEjdhhylRRiuMZUTSAr1gdeRC9KWcaDwP4xnH3
         aR1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326YRoP6lsN/05+jt1MmeRfIrfMgQ/Wpx+V/9NfFh742W6JREnc
	D1Z9L0q/0jdV59ISny7RBQM=
X-Google-Smtp-Source: ABdhPJysF1m6PrZaUaHAKjzGglkfF7i4k4pobWXaGcThD9UQIbLu0ybYUY7V+BrkXTlsE+M1uDiPZQ==
X-Received: by 2002:a5d:8453:: with SMTP id w19mr27725419ior.105.1626901695709;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3b69:: with SMTP id i41ls650637jaf.3.gmail; Wed, 21 Jul
 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:a05:6638:6a6:: with SMTP id d6mr32086548jad.118.1626901695432;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=sBxiUqxO6pyv7pChvxbxMxAEgcP140juBsY25+unk/u44mv7LR+spq85PTF2hdayvW
         WYag62/I2rLRSioTqO9luIwjXp4kDKA6Ne3gCPTzjBHobsCLUZ+SW+iYAyzog4zJtFG8
         pwMhx4wznn3RCZeuu4ZwfnmVdVoP1lmm7fq4o0X64pZiwMny2MUsBlcuj+OQxlq3RTcC
         h5ZPefVsD3g4JwOIlJ2dQPmt7xpTm3WZXuE/9ryMfgAzcFc0aKvUcbC52lpiYOJwLDlO
         jZCktRj0ZBfS68znTrWytbsRz+YdTUAm3OHaCOvFbZ3vU50OqIpYG/2MaruGNRa0on4Z
         nGsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lCvSyqjYBxr3+OYNcxFarqV0Hyn3+kW4W1PBjKZbUkQ=;
        b=usrcEefYl8eR7ldaV958yCkqVTibMLP+FW5OLWGtWtWkkh7kp0s+4ivzPblaaGIdka
         c4FjTa1kSr2oL0rhOIaBuQNwr3CrOCdZZntIBjpVyX4vZb2dSLi4f4CzPDZTTn6E7Cmp
         5+ysNEWmDYdbbAse4rmQuJiAvwih84RH+B6yAmRoGKORQLvmxTF5CBx+Eir5xb/J3K0u
         nULmRVgdJUG9fJQ3AY6UxbdbKW+KCLqHWT+ZfU/srGgrafY3zkBftWMbiyh/cHYsU4J0
         Amf6xBEFE4lmPaYo2L1R6U9X1d2YAM+q0y/e0zzLPjWN93kFTV3x/RlvTYT2mSf7eXGJ
         z88w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mv0cjSVM;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e12si1731183ile.4.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A0849613FD;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 51EC25C09A4; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/8] kcsan: Improve some Kconfig comments
Date: Wed, 21 Jul 2021 14:08:05 -0700
Message-Id: <20210721210812.844740-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Mv0cjSVM;       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Improve comment for CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE. Also shorten
the comment above the "strictness" configuration options.

Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/Kconfig.kcsan | 16 ++++++++--------
 1 file changed, 8 insertions(+), 8 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 0440f373248eb..6152fbd5cbb43 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -40,10 +40,14 @@ menuconfig KCSAN
 
 if KCSAN
 
-# Compiler capabilities that should not fail the test if they are unavailable.
 config CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
 	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-compound-read-before-write=1)) || \
 		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param tsan-compound-read-before-write=1))
+	help
+	  The compiler instruments plain compound read-write operations
+	  differently (++, --, +=, -=, |=, &=, etc.), which allows KCSAN to
+	  distinguish them from other plain accesses. This is currently
+	  supported by Clang 12 or later.
 
 config KCSAN_VERBOSE
 	bool "Show verbose reports with more information about system state"
@@ -169,13 +173,9 @@ config KCSAN_REPORT_ONCE_IN_MS
 	  reporting to avoid flooding the console with reports.  Setting this
 	  to 0 disables rate limiting.
 
-# The main purpose of the below options is to control reported data races (e.g.
-# in fuzzer configs), and are not expected to be switched frequently by other
-# users. We could turn some of them into boot parameters, but given they should
-# not be switched normally, let's keep them here to simplify configuration.
-#
-# The defaults below are chosen to be very conservative, and may miss certain
-# bugs.
+# The main purpose of the below options is to control reported data races, and
+# are not expected to be switched frequently by non-testers or at runtime.
+# The defaults are chosen to be conservative, and can miss certain bugs.
 
 config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
 	bool "Report races of unknown origin"
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-1-paulmck%40kernel.org.
