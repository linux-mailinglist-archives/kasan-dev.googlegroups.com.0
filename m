Return-Path: <kasan-dev+bncBCS4VDMYRUNBB75J4SGQMGQE3NDIFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1516D474D91
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:48 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id i14-20020a2e864e000000b00218a2c57df8sf5955445ljj.20
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=uVMI62VKpkAVjLC/+q/pzMSTmq/D0VW8ADIWfD6dEHs7sCKV2LqhJVjaPXZ9vVQbmG
         QHP10NzskHOR42T7kgEuU6i6TjwWMGKjM0fRaWPVwG8qXRw/VyvZbDJGTVj2rucZJ6gg
         vSOwBNCNXiCWdMLlXuAqbtadOHz/zPybGmyjkKWcxdvFw/Njx1dOOEpCBQIfHQWA9EGs
         DmuWaiLd2TK/Xm9cx0g4rHU9hR0bgqN4kWEVLT5VGaHe8pbxG0Q8s7pFGrHHvbkvNvuK
         ptY6c5sgX3wjOxEx8AyMdnMccEI0gxkvFbRalRoHPuYzyMis+5C0i2G6Ermr+K6ggBpG
         hdxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z2PEECvQlw1J24cDOb0L7fDSnGUMjBpmSVkNq2EFoPQ=;
        b=EgMc+tnBAv/Men6Cn1P/VsTargiQ2j/MX9z/AOYqNSSG/WCRZkLm1E8mFULkBGVIYS
         XCKZqtGSb37Ord4XiQOPeJrDeCxRuCu34902ua9Nnkl1PEvluPHSyMxmduochQ7MsbC/
         bTUD8A9yXNwaMD/ZQnz1KdsvgjmRb11wZVG9FxzOqQc+faUSf3Ji3LUzQQsdZgKrd18R
         t2AiXSSag1kSPREBt9D+fWmNimPISvuPc5i7NY+HmQXkyLt6lM70MZWKvChh7nmok4TL
         z+pFDyzp1gpfamkVSY5otpTBXAAcKmUi8Ya4aOMyitnlCSVqDpJ+0iEK9lRnEJ5VzeGc
         AHbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i/Y1eBra";
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z2PEECvQlw1J24cDOb0L7fDSnGUMjBpmSVkNq2EFoPQ=;
        b=BdKsm9s/lOjGXESQKBctqQ3eVM69DAI0UOBhR18eYqm7MpWfpePPWKvlUr81WNsocy
         x2Hwl60L/upiKbIs839gHO/ozzMsb3plEQbFItxi38OUQCSG5vglvwDJ33QsMNCTD6LC
         RXs0dwaL1GknBExCLU+5L5oeQELncfHScCwk/0tOYyCwhhZ+3C/DPy5CgrNdjI4+hXJp
         loiLgIc0QIZcSnwyp6mq2MS5YCs/m7cKMGOCghi32r8TJlNr6BWUxwhAsLUHMPlN9XNw
         LEKf29VZHuYdWXIw9z21nxkeBBEcG/+dl7euoH49VJa/fDPfzgdCYO5e6mP1D2PCJ5qp
         Mv9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z2PEECvQlw1J24cDOb0L7fDSnGUMjBpmSVkNq2EFoPQ=;
        b=nF8RunfdIa0YN9oFOH2yF/XD1g9BFjtkuQzThISjZzE7XYhZ38D2ldL6+vjBWBdeYW
         6gcwD5QGeHaW3D7FBgYFRP+L58BXUllvSpOH3pISYu/cRm631bM2dTjigH34VMJh90BC
         vMICNeExFZqiKTZsKk490ZcfYeYNYmqUX3Kl+191NW48AA5XtWmpomKpxIS1DvfcWxT5
         BriAZ9x+FSJXe2DV6ClYXf2Di+X3e2Lw054/1GZPIQYwDl1E4F6gFRkw6dh9nE1DEnhZ
         soze0idOn/Euauc5nskgNKnokUFMqSMj25hHtd7qar8tGwra5pT01vQSPbyqrQLw7BaR
         SQMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+XEm9+eJBK3jO4ZnVeWjp2UuK3C/EYqE53dTZbSpbLUjt5gcZ
	GpuNv/LJpPsSFFnVAxHAY+g=
X-Google-Smtp-Source: ABdhPJxaY3hHn4sh4BfIaZUMiLwr76HSQHcLVVCbCHp0h4avXe77yeKGmSgcod9VKRpyxE/aRZy5iw==
X-Received: by 2002:a2e:9456:: with SMTP id o22mr7467102ljh.129.1639519487282;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b9c:: with SMTP id g28ls93856lfv.3.gmail; Tue, 14
 Dec 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a05:6512:ace:: with SMTP id n14mr7026867lfu.53.1639519486118;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=fpfifm3LP9f0yj1lGdZat+uwWysz6xnr41pERUJP58DGufzbU5sKAnOgQcn6g3Ff3J
         WjizTTR5B4Kuy/w1edqnEGZ0h4FBLsLW09lHdE3vZ1NEx/9Gt7F5wIs2gH+R/KorqOHY
         Tzw3fFou2DlSV+X2JuLh5ZS4vv6HeXG3GHvMIgz+Yia2kgSAKF1Jzl4pQrVSJ2YyEguQ
         /ZiiH4V+K3cypEs29QqnqiA5ZugCx7nR3OOeOD2viEAdVoJq/pJ26GYV0/yJQjDPgvvD
         9SfozQO7jCVOUSPPHNpjbeTIf/ya/hgkDdel3DxluDv02C1ZmEjBrUMmAjyB5VZSh58I
         id1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C6f+hZy4b6h5AdAZPoAVALJTmZKxOZbe0ifmg+DOHfY=;
        b=CKj/oI1eHhKicYH00ArIBeia6DTYcaO4oTAdINsnpq5BVJwS3CSaMfx5BUlDuFB7WY
         sPiB+oGdj6rg8vQe6ti3QOqlq5s6zt06jRqxbqbZ5uXj8IyO7n/MGrZ+NnyLy73C5moG
         oaFHfFAylpVYzHLX/4NEmMe/p3yrwSq0EaVXKYZ3EPpmOK0IBLCOtjXaHvkUIU42ObJy
         nDsQYE8V5mo1+OdOGoZvohtgTg5cA1oy+KbhOWD41UBnVuZH01BGogmfO9jBW6zM2ROQ
         Uffy42c9AqEhNdJYmMnCySj2Zn0GRftxju94yIzO1Jrq7v85lNOAmTipqgQ0Whd9BLYn
         36zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i/Y1eBra";
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id h12si5648lfv.4.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D8F1061744;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2476AC34631;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7B37F5C1C3C; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 17/29] asm-generic/bitops, kcsan: Add instrumentation for barriers
Date: Tue, 14 Dec 2021 14:04:27 -0800
Message-Id: <20211214220439.2236564-17-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="i/Y1eBra";       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Adds the required KCSAN instrumentation for barriers of atomic bitops.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/asm-generic/bitops/instrumented-atomic.h | 3 +++
 include/asm-generic/bitops/instrumented-lock.h   | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 81915dcd4b4e8..c90192b1c7552 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -67,6 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
@@ -80,6 +81,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
@@ -93,6 +95,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index 75ef606f71452..eb64bd4f11f3c 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -22,6 +22,7 @@
  */
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
@@ -37,6 +38,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
@@ -71,6 +73,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-17-paulmck%40kernel.org.
