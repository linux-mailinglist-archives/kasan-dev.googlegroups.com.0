Return-Path: <kasan-dev+bncBCJZRXGY5YJBBP4Z4KDQMGQEXRKB3KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D5D93D18AA
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id p142-20020a4a2f940000b0290263980f2b45sf1647810oop.8
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=aSdk3/kspcAMs1TvOvUKgF7vC4CBjz1iddWKiR1GySh+6tk9XYGTQx2HCXLxN4PwIt
         AtIcuR8oYPuRzLJjadjAG/dIHSMssw2ExMgG90r32yAMEXPDDyPrf7t2+AP6L6R9EuND
         kc6BsWTtvzQdd7j+Za/FL/zWxY+J05PDH1Am6mTzaDofLvWhkn+VcMl3Kibd2ofXfl0Q
         OR6Pk1ixsJTH3ew8E/CBGHrDHZPc2x/fe/QLRiWXV0LEu6SMP2zyEKshQF7eBq3AUBp3
         wEhpG9ZSldPyEzp/qSGfUgx6dBOhELLXiSq8BMPOeytNcYxaRN7Izi606Yzu7+Ce9wJN
         2Dzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8J1zm4iuru9cEM7lF7tdGLPMKMga4QYL7/1Bted820U=;
        b=wjIWZcoWdPL1N/bdAdaT6lz85tstucVCFW6ewc7m8UI33G+5p0PW4ZYsiWie1fcKF/
         HzK+rigGu66GWzv0VZN6Qj9ob86mOAI05tyrUbYS5tqZpmZCu/r2st4GmpoFDrNZBSLK
         zQZITXt91HGLPD9cSMxkCsbJmdRkpidqM3SErpqSqtX4JF/xGuo+za+u4ya6MSnoBi0O
         kd0sD7dGgM7SZT/7RJ2MQycZD3KmJQ8LPfYVFfP5uvPBvqEx58lAiKnqf6Zc78TgOSTP
         ahpHbbCdKD7AG9l01YHzBiuxXFAMB11KXjAg981PMo1slrsjZtx9pKH+YsTjLPrbNp5X
         6lBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HLV8wcCD;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8J1zm4iuru9cEM7lF7tdGLPMKMga4QYL7/1Bted820U=;
        b=FpufBqSRzKUTvglSnHc7DG66SKNlMbBkAQ4jlqdFXuGDnbpcm4z8JHe4dTuFfDnTZL
         UPcwtLSg8jMZYws/Uby24YToKmuw2HDxCDbT7QOGJ6yt3tFftLP2UCth8A7tDJMtzDjo
         UbhWyJJ7wFjgnqLNDLQQnmOqrw+GXoxnW3/A/M9Kv9Ryd+U1ZBRLQdp2bREeGH01S+sB
         zELeLutYtiUDTCIlVNXo/GB2uq8OAgKa+zi4b3X34kLRCNW2wt/8mq4V3DhZBYN7C/m2
         zvhi3A1AN9OUj06TNSfubr0lFaj6kbrqEHN8PRdgMbRwF8AxiRJHT+Uarru3b021nr9i
         HdNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8J1zm4iuru9cEM7lF7tdGLPMKMga4QYL7/1Bted820U=;
        b=nesuYGfN+dbbeghgW/XJUEA2ocyu1NNMgD7cumn7KA9pJ6rc3mG+LLKGIYmua919CN
         mZ0w8eqBQbZiV2fY31obaLV87YRKJtbQSDSwPLG9/KcZPd2pt7zTfHHlJAAt/zpaYine
         R6HG/1uQ7aQ3nAJHy6v/BTKqSkIW9W+qwNCBLOP4ob4w6bQ0HDhz1vsQS5vpLr0IANfR
         UYqpzWENDNqItZA4JDYyvFyEebgA6ZK6Ahti1oUszAA3Vfna+FzaiY+hhM+YGLrrK/YW
         dCmBkEtePIbToMskN421PUq5TXky/JVoQLy+bKgPb4e1IWPuCTfeHTY/tLa3MLh7BYFw
         2C7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rfwIAmhV1rzqH+VwmOSVtZWJOpDrb3izBVq8DWsQU9DblUkfQ
	Am+j5U//YAk6cydPfAoQoKY=
X-Google-Smtp-Source: ABdhPJwqRuwKbdhZrshQwoton4Pkd0lgQPd+dCL+eGaTaWDuX0ZgXPOF5idP31iDTJan1gaB8Ddrog==
X-Received: by 2002:aca:3e55:: with SMTP id l82mr6761847oia.34.1626901695806;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b443:: with SMTP id h3ls267335ooo.4.gmail; Wed, 21 Jul
 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:a4a:d2c9:: with SMTP id j9mr25788663oos.88.1626901695438;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=XV3s1OXDi7PmCd8C05Sx6jbzpyMQQuSY076XDpgtGHb2f0yD/AYI7uZlYv9Dn9qVKI
         8FVDh3+wHRHfgDawLt66K1VrTAr5FB72aikEtF0+d+EQnE5TWiWA5F9puh1lbhf2Lujt
         FyDqb105ZgocoSRpsucLjjknTSoXGqxCZ8SlAtkhdvsFEkQM0NkWetDrC2BQfwbZBDWO
         3UYvuxd7tXpR2UUSyY0LgfD0pS89OkCuzYwVD6EubTiBgXwXu0lUu7cTf3kw1bnsaP7r
         12fd4gK4azOQRDgodOu10drt536oE4Iev2GkIt8V5jCwANChcDwuHelMGKLJ55t0AbOj
         gWXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=92pQbpc8FuIZzqfiG1qKDt8AtzvU/xGMXAY202W45lA=;
        b=KpyPlu3DxYvVBR8o8k+aB/+Jyuqstu9BP1IGgKwmJMScIO3vMLv4GinJu0gbt5BsuS
         LlRzhFyLyBl0PWMSUvsGI1/pOdBwgK/GlKnRH+l0x/w4W+2Udfi7SewtCF2xyPJ72xxm
         XTHBNycyLGKksMrkZnUs6rA4phLXSXITMKNYyVTGRrfL7VukzdV1V3hyAtjZN7UuXlxt
         7S8MaazhqO6wX3Q+Us+3y3RSB4cr2TFwiGX4z3wIiLihNoU3fjm40TV9ukpg2QPFaeja
         3zxCKGpmesul9P8GJPH32KNB/CdcoMfoXZ9zQenW1UVqD4B0YPxN3B62bDimBC3dJCvr
         /+4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HLV8wcCD;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b9si3527058ooq.1.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9E2BC613F8;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 570D85C0A03; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
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
Subject: [PATCH kcsan 2/8] kcsan: Remove CONFIG_KCSAN_DEBUG
Date: Wed, 21 Jul 2021 14:08:06 -0700
Message-Id: <20210721210812.844740-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HLV8wcCD;       spf=pass
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

By this point CONFIG_KCSAN_DEBUG is pretty useless, as the system just
isn't usable with it due to spamming console (I imagine a randconfig
test robot will run into this sooner or later). Remove it.

Back in 2019 I used it occasionally to record traces of watchpoints and
verify the encoding is correct, but these days we have proper tests. If
something similar is needed in future, just add it back ad-hoc.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 9 ---------
 lib/Kconfig.kcsan   | 3 ---
 2 files changed, 12 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 26709ea65c715..d92977ede7e17 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -479,15 +479,6 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		break; /* ignore; we do not diff the values */
 	}
 
-	if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
-		kcsan_disable_current();
-		pr_err("watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
-		       is_write ? "write" : "read", size, ptr,
-		       watchpoint_slot((unsigned long)ptr),
-		       encode_watchpoint((unsigned long)ptr, size, is_write));
-		kcsan_enable_current();
-	}
-
 	/*
 	 * Delay this thread, to increase probability of observing a racy
 	 * conflicting access.
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 6152fbd5cbb43..5304f211f81f1 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -62,9 +62,6 @@ config KCSAN_VERBOSE
 	  generated from any one of them, system stability may suffer due to
 	  deadlocks or recursion.  If in doubt, say N.
 
-config KCSAN_DEBUG
-	bool "Debugging of KCSAN internals"
-
 config KCSAN_SELFTEST
 	bool "Perform short selftests on boot"
 	default y
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-2-paulmck%40kernel.org.
