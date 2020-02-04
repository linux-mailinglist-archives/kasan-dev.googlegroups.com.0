Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI6Q43YQKGQECFV3VQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D158A151F41
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 18:21:39 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id y15sf5505941lji.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 09:21:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580836899; cv=pass;
        d=google.com; s=arc-20160816;
        b=TmO9+6PBOh4aVvlIF4Sms1HXPWhHQFkBgaoNZQ3SUvq3EK1lujTcgvpQ0iaxnkIITx
         m5M/p9VlRbQU9r91uQSASfwhA14eZ7S7q+FM3Q6D73GVDPjWJ8sNtJ5TpwgipuXcg4/B
         vEaQqbjqyoMP4cysNH3AsOc3pFoLCZxrLkzmRlbIJ+R5sR2EnVVWn8oQm0NpO2Lj4JuR
         p2auq5BxS5rjOtNIn5qOPk0GrGdtQic7T2GnxPShUxbsPNjgdtk5JEnpb562HClBMGsC
         IaOFdbnkVaKxUKrJvO+alWcX2Lq15TcFdSM1xwsCWHRkl0VBP5yBnsobMP+XxOlBh/D9
         TdSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ybP2fOX4pGQdfukkL9baq0MXJ4styA8bBGhDU8wVxBQ=;
        b=L5WlYiKslJwxfiu9IfYwe2+JvYOseBFxlVil/VjUev2Rx9YEQvrrivtjfw7VAtxp8X
         kVEPnGbKSw3AFkXa7V1wO/Jo8wXG2D6Hs+/tN+ryMZjYivUCpQorQX3/56C14zVwHCyO
         wYmSjcQVEC5+tH55+cs22rSoVgHuFUhBqoVB+NXtl/hsOUQc+s9fYu8nvrWPTkuuRaX2
         KCE5+d5E4j31VviCrGziX/Xazskb0oNMHr6TijawpjeNqJF+BHoYxoutCtvJDhXI7rAu
         NSme4xKyDruEGTSModCtYa0Z4NR2DigK2KPb1KXZTqx74j3/V0130072SPPvCqgckj/r
         P/OA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kOwoRCDo;
       spf=pass (google.com: domain of 3iag5xgukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Iag5XgUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ybP2fOX4pGQdfukkL9baq0MXJ4styA8bBGhDU8wVxBQ=;
        b=EuNfygIKwLUz/wflmgdF8NBPEkmwIgDPqDO3keZHuaZfdauN36ECVwwA0jbfQzhFUH
         q5xO0MMCCpe1QeNLlEzExSBB+n12YlMCM2IFdfR0PpGyOPOMxzG56y+YS7WTiJ2MGBxE
         T1Fpm6xcUXHh9juJDpp++W1rIg8yeRGqMNcypABq32Zb1U4aOei9dFThYFvA3oXFDcZk
         a571W4vwkrIWuWlwC4SldJvtq8vV1jgYbfIlDtvSg20wn3z0G+9SFLehu87aKKzi7ha7
         0ScELTT9/VMv/EkwvzDuDPMP5ib14QsoFr+EBuBcOuKXtTYOzdlG2xkLJGnUAImxq/Hg
         himw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ybP2fOX4pGQdfukkL9baq0MXJ4styA8bBGhDU8wVxBQ=;
        b=RXW87rgV5oEQ4u1mpPFvsoN2rILPpMcvFPEhvhA2n+kbIHLzhgW+tTwz/eFDHw1m2u
         wLUBwcmcm2TuwHnt+va8nXIJZMzC89VnApFnm7eHm/FaMTsHKMUOnLjhiOgHvBbIYXAj
         erXJzTe/vTlZenTNwzKkUTRAlEVIYN0FHKz7pRpZY/nRYL+OCuXCbIITKyIOP2z31LOx
         Tm3pHxJbFJvpHxYI4eCJTZGS003tskoV9pRUYlOoXevfLFx+Fgx+KFrHvbT5XofmfxsN
         19yIJ0Sg8xiiehzUv2LNBdhruaK7vem7GbevOXSRjQG+AxVd/eaYaBGgZLQaEGMuvab3
         VHzA==
X-Gm-Message-State: APjAAAUDKg3+x647HMAuiqso0H5I7U0LCVfsOVB/PkXH55bBEwN2iZtS
	bs0UVH7fvq+9eb7zCagUGz0=
X-Google-Smtp-Source: APXvYqzGNpobETG4umYV68mFxChmvFyXkSTUij3EdsPojKxrv6gSTTvpI0IYiLL94se8YieIf9RvKw==
X-Received: by 2002:a05:6512:284:: with SMTP id j4mr15441982lfp.109.1580836899185;
        Tue, 04 Feb 2020 09:21:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1051:: with SMTP id x17ls2633873ljm.8.gmail; Tue,
 04 Feb 2020 09:21:38 -0800 (PST)
X-Received: by 2002:a2e:97cc:: with SMTP id m12mr17763984ljj.241.1580836898409;
        Tue, 04 Feb 2020 09:21:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580836898; cv=none;
        d=google.com; s=arc-20160816;
        b=iL+ZiO6zSxOzcZJC4ArXoF0yWt5pmhox3BbW+xyKmLgrKoobRUbOmBzUwLmn9xeUse
         nhOcMWSc0rApkIwnNj7Bd8xq9M+5JwXC09EC8CSKF/NTJV53GduIZxWaYcljnT8v7wvN
         fQOkYp+qIARuGCF6SI2ppmqHrhLpJ6RuX0+YOWsx5NukmfIV2a55uq0Ow9D1HVRH1w3F
         E92vOueHlkQ8b/Np4+BzVy+yLGLUtSd3vAzo+6qIBVXc067RxpYbHw8GaKQ38K2NH7YP
         PhV3JFwTjeUiYR1W79t1F7H07XJBAGGZ/ktfMhEhPiEPh/JKrVZQd8tcnvS44j5suckW
         aUEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/EdK19HAv7xXcKBEepm7DrM633ZSHTkUWpJ8Lb/HPBw=;
        b=CUhKEdr9D6SPS92oGxNHe8iEtOlhQjBDSCYi/OfuA+zLqphEVqKP/LZH52s8aJ5i+9
         7hlgskmU4ldTuv/QnIoTtVSVVrA4mei4FXPrQkgyIKpVz1bPEc6shh0zJfgvBoV4S5Qp
         Pb3tkyvyrkziILc7MTSV+9y9vNz5yEWuuwsj6XXeAFs0jLeVtww3HVHL6E3lcufMFuNN
         S/7n4+NdZDCWUCibf03/8crVX/ZbJ0fTJAL6atfFHpfhr4VgQpPJx0uJI5gmvqz/l/BS
         2tZmxO8rEq29G5kIimqZ7Ke8s/8hWE61RtkBeUVAgIZRZa7ndkLY/0jd+yPQEF0uIXfi
         NVfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kOwoRCDo;
       spf=pass (google.com: domain of 3iag5xgukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Iag5XgUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o193si610308lff.4.2020.02.04.09.21.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 09:21:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3iag5xgukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so1569687wmi.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 09:21:38 -0800 (PST)
X-Received: by 2002:adf:9b87:: with SMTP id d7mr24109403wrc.64.1580836897715;
 Tue, 04 Feb 2020 09:21:37 -0800 (PST)
Date: Tue,  4 Feb 2020 18:21:12 +0100
In-Reply-To: <20200204172112.234455-1-elver@google.com>
Message-Id: <20200204172112.234455-3-elver@google.com>
Mime-Version: 1.0
References: <20200204172112.234455-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 3/3] kcsan: Cleanup of main KCSAN Kconfig option
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kOwoRCDo;       spf=pass
 (google.com: domain of 3iag5xgukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Iag5XgUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This patch cleans up the rules of the 'KCSAN' Kconfig option by:
  1. implicitly selecting 'STACKTRACE' instead of depending on it;
  2. depending on DEBUG_KERNEL, to avoid accidentally turning KCSAN on if
     the kernel is not meant to be a debug kernel;
  3. updating the short and long summaries.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kcsan | 13 ++++++++-----
 1 file changed, 8 insertions(+), 5 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 020ac63e43617..9785bbf9a1d11 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -4,12 +4,15 @@ config HAVE_ARCH_KCSAN
 	bool
 
 menuconfig KCSAN
-	bool "KCSAN: watchpoint-based dynamic data race detector"
-	depends on HAVE_ARCH_KCSAN && !KASAN && STACKTRACE
+	bool "KCSAN: dynamic data race detector"
+	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	select STACKTRACE
 	help
-	  Kernel Concurrency Sanitizer is a dynamic data race detector, which
-	  uses a watchpoint-based sampling approach to detect races. See
-	  <file:Documentation/dev-tools/kcsan.rst> for more details.
+	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic data race
+	  detector, which relies on compile-time instrumentation, and uses a
+	  watchpoint-based sampling approach to detect data races.
+
+	  See <file:Documentation/dev-tools/kcsan.rst> for more details.
 
 if KCSAN
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204172112.234455-3-elver%40google.com.
