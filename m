Return-Path: <kasan-dev+bncBDEZDPVRZMARB6NC4HDQMGQESQTYEBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DC95BF9D84
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 05:37:31 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-3c9a6b6caa8sf6167047fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Oct 2025 20:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761104250; cv=pass;
        d=google.com; s=arc-20240605;
        b=WLM8UXP9ZhwY3/eKrhU7zHlT/kwVGR9VuPK+29nRsPu0nG8GlHQmicCoC+P0MMYfkJ
         q5dmwLpgB++LA0MKsb/sZHrrta3DHf5yMNyQUa2FIp1Yla7HnBDWxko/FQ3swmyPmjMX
         X4SZjWriDXy1DisHmh7z9EaKo6mmdAkd5eNVs8KQQHfWq2EWvhXLR8seUjTLQpeB3s2V
         loNkeYaPU+y9YUFxD9hrgVqtwHcGuQ7vyfMIDj1q2Q+4rGMoQEqA9PN9ht1uJTYb49Rc
         TuKP99N6VXyxpfRlU1vUwCxzHtrI8MzhCMgNvU4mIwC45qwap61wtZIvkJTalwkXuTFF
         QLyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=FN0rb3CAKFKWC2e8CImPRTwVobsGHg1SXtr62YEI8bs=;
        fh=nES6+Yne+/HB/bKGzaWI31vnKMjrgnOptTDwbI+ZW1c=;
        b=Oei9EYecDjSDDvrLiYLeHArGSk3K6DwDfOEHnCr0vigCMIJ63s+dCqPTa8HIICMfpf
         P2vhZHImW8kNXO9IKEBUzrE4ThoTpFQdBCytw7dDZsS/nrDsGjtgHEne/7QwLdcYZ9ue
         mQ2Lki8xzXJPV6emC4neRmgea5fZoQrpVJNjtNzN9bNxhS2NtSfSRI7pjbv5ocsUR3sC
         ez6s2KgMuIJG8Byp3g1KdCcU69Bt+NeP9diLeNgMVXUXYhdX6WZ+0le9VOv8k4Wh5hi0
         vPre4IvojDO2nitzOgldqzIbq5aQ8rCvzgEOVjOoVOs+3hoBJ3VCuUVoRJQByqhZv5lg
         xqww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HqjjRdZf;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761104250; x=1761709050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FN0rb3CAKFKWC2e8CImPRTwVobsGHg1SXtr62YEI8bs=;
        b=K2x5Zd7JSC2lNYwpacMsNoYBYXpV/tCy3MGPXe1W6/4u2eM0ayVZFbiZ5MqUZJlsJ1
         aRgtipaAPSOupTHA766iq8zJtaKxgtWiST09sq9eOJrrjWiJmJsbDOi5BTCa/mXyog2z
         wpK5sz4wDtFO3M9A+ZXsw1Iq46TZm0Iuu35wgWenjRb3ZMOvyFZ8x/2NOaM+YHlh/ODm
         6wEmoSN9yk34TMmHhyeS4/3/FJ7otcfVL8VUk+UaYgOzOQc4JaBCZznHHBhvaZI6mEa+
         9chUrWt/3O0E5DaYnRIqdibx3gBlHAmL+DCtJz/7eGfVBU7mMPw2AT1nS8pKjd0fFnk4
         VgGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761104250; x=1761709050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FN0rb3CAKFKWC2e8CImPRTwVobsGHg1SXtr62YEI8bs=;
        b=RY4GaVYt1hp5Vak4zOPh8Q/8E1ZrAGtNjyEx6+92b08CKJV75BKf1sMM2K+gPIprC3
         ciLfn/Ul3ZQN8JMidh49tvK9YE+yYs76Wy6NfJCzKZ0yw/G2KbCiz2UIx0O+XXt/KIHI
         oISVpq15ioO/PBF5moxZpFEuQEbPugDjDWmJJZc/3CpdXxcvdEh7Jihqx1+SyN8UDH/W
         tKTLX2Gt0cdV1MQ40yEtXji57D0MOT/0cDRKcCUkl4XnEWka9u78INVrCawuZFv3zOv+
         NM5j8OkVZDEFkxPBe62ogr8GJYvsxcPWrmyZbDo6Ke6h/cgH80w4eoAGZktj400x2m3h
         N9SA==
X-Forwarded-Encrypted: i=2; AJvYcCU6PDeomUgv3owln9pR7SVJHz0H7sES13myFEHf2KtC0+2zt5RcX5e50+oOFq75sjROIgSBhw==@lfdr.de
X-Gm-Message-State: AOJu0YyPVH9opfHFWO2tAzy6Gq2yvNw+XgcoatD2YCADI4vV1fd3klA1
	18ejE/2y04EhHa18/wWsqvIPMp+yze3sh5O2paQcci+VZ+C2SVy0ZA45
X-Google-Smtp-Source: AGHT+IEXd1wCYUSWmLOCzMKAdrtWpOX1fnzrssTRzZe7zVYBSM+XnUVi/A6AQmQR0M/lq5N4Vychlg==
X-Received: by 2002:a05:6870:a995:b0:3c9:86d7:6d03 with SMTP id 586e51a60fabf-3c98d145ca5mr8958526fac.51.1761104249771;
        Tue, 21 Oct 2025 20:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7RmvFemXmuEKOH7bJu66DVyo0cK6rbAGSHv5Ozrp0HUg=="
Received: by 2002:a05:6871:7c0c:b0:3a9:7d42:2984 with SMTP id
 586e51a60fabf-3c975220d77ls4499249fac.1.-pod-prod-05-us; Tue, 21 Oct 2025
 20:37:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVknzjHidMoaXyfAiCrsSqtotqRy0nKWocGZODtpS4clkc5qEZWJ9mRu8Y0W2vc+w1FI2mNRG+7os8=@googlegroups.com
X-Received: by 2002:a05:6808:21a7:b0:441:8f74:f27 with SMTP id 5614622812f47-443a31e1b33mr8048706b6e.65.1761104248997;
        Tue, 21 Oct 2025 20:37:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761104248; cv=none;
        d=google.com; s=arc-20240605;
        b=e96OHbm1GtGiYl4sKsYh/JJOaXG+ZQZV4ZYX4uY91meOiHVOC6rrO54eu/01gFS+AT
         emA1xgkzjTMQ+xBYVcv9ET1F0RgKZriaj74OdxMnHZf7TpFjYo2l6nrkDKojZ+MUFu4c
         4odR9SU7sH1DzXl8U35wUoMMiKyFuXmwVCBkb/T5bn8QFgQvbpEyV3jEAvcs53nbycpG
         gKFhkzIyUZNPaXn+3XrSHJtsKhQUDOtjp9+YN74QhBXhE5fCdVmpWLStZtk8URDe4qZA
         3kfpQSu4WdEhVBJm/H3hTw7jmovi3u+rRuYPNtaI2tuWFst1QBm1ehCxWyp2MtPKrsyr
         czSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=0+7zP7sb/uUV1jRB9h+eYHxPoVIAWVug9/RfnSjiTss=;
        fh=An8bt1wDl0UlxFj2PSBGCcVX3Im305i2cyfHZ8X5aks=;
        b=c6YuP3gjTz54ri/x6cKlm1PPn3PWiCPdwS4OefXGzgIrmMJkP1EdXjCwUKJTBXKTv8
         RLGpi9zrNnQNxdpEw3tjSrHnTjIHrkmh4za32ADFtR3piwCxkRDQE+ktiR7DwdNquRfh
         NAHUBPeZPoNFjlpdEoYG2DsOWI+WNDVQ7mopnQJgalYVKePPZS7MTHEzz50Ixs+0ZMFn
         jRPKFE5+pSdVSuxEUc6v3vvNLwmftfWKy6Et/hHbbcgNQ5NYNzXelDqFhLTnjwRqky90
         bErG4HWqfyv1iqjjq0nGkNoK/1XS5LHhl4XyMEp6N6uej+VOcex1fQvbdWZBDZ3R1rc3
         NN/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HqjjRdZf;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-651d3ac479asi839063eaf.1.2025.10.21.20.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Oct 2025 20:37:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 4F792602BF;
	Wed, 22 Oct 2025 03:37:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9DE6CC4CEE7;
	Wed, 22 Oct 2025 03:37:27 +0000 (UTC)
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-crypto@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Ard Biesheuvel <ardb@kernel.org>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Pei Xiao <xiaopei01@kylinos.cn>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Eric Biggers <ebiggers@kernel.org>,
	syzbot+01fcd39a0d90cdb0e3df@syzkaller.appspotmail.com
Subject: [PATCH] lib/crypto: poly1305: Restore dependency of arch code on !KMSAN
Date: Tue, 21 Oct 2025 20:34:05 -0700
Message-ID: <20251022033405.64761-1-ebiggers@kernel.org>
X-Mailer: git-send-email 2.51.1.dirty
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HqjjRdZf;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

Restore the dependency of the architecture-optimized Poly1305 code on
!KMSAN.  It was dropped by commit b646b782e522 ("lib/crypto: poly1305:
Consolidate into single module").

Unlike the other hash algorithms in lib/crypto/ (e.g., SHA-512), the way
the architecture-optimized Poly1305 code is integrated results in
assembly code initializing memory, for several different architectures.
Thus, it generates false positive KMSAN warnings.  These could be
suppressed with kmsan_unpoison_memory(), but it would be needed in quite
a few places.  For now let's just restore the dependency on !KMSAN.

Note: this should have been caught by running poly1305_kunit with
CONFIG_KMSAN=y, which I did.  However, due to an unrelated KMSAN bug
(https://lore.kernel.org/r/20251022030213.GA35717@sol/), KMSAN currently
isn't working reliably.  Thus, the warning wasn't noticed until later.

Fixes: b646b782e522 ("lib/crypto: poly1305: Consolidate into single module")
Reported-by: syzbot+01fcd39a0d90cdb0e3df@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/r/68f6a48f.050a0220.91a22.0452.GAE@google.com/
Reported-by: Pei Xiao <xiaopei01@kylinos.cn>
Closes: https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.1761026343.git.xiaopei01@kylinos.cn/
Signed-off-by: Eric Biggers <ebiggers@kernel.org>
---
 lib/crypto/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/crypto/Kconfig b/lib/crypto/Kconfig
index eea17e36a22be..8886055e938f2 100644
--- a/lib/crypto/Kconfig
+++ b/lib/crypto/Kconfig
@@ -95,11 +95,11 @@ config CRYPTO_LIB_POLY1305
 	  The Poly1305 library functions.  Select this if your module uses any
 	  of the functions from <crypto/poly1305.h>.
 
 config CRYPTO_LIB_POLY1305_ARCH
 	bool
-	depends on CRYPTO_LIB_POLY1305 && !UML
+	depends on CRYPTO_LIB_POLY1305 && !UML && !KMSAN
 	default y if ARM
 	default y if ARM64 && KERNEL_MODE_NEON
 	default y if MIPS
 	# The PPC64 code needs to be fixed to work in softirq context.
 	default y if PPC64 && CPU_LITTLE_ENDIAN && VSX && BROKEN

base-commit: 552c50713f273b494ac6c77052032a49bc9255e2
-- 
2.51.1.dirty

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251022033405.64761-1-ebiggers%40kernel.org.
