Return-Path: <kasan-dev+bncBD4NDKWHQYDRBS5QV2FAMGQEIPF7M4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 75611415201
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 22:55:41 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 1-20020a630e41000000b002528846c9f2sf2454059pgo.12
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 13:55:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632344140; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJUeadQmPKinnYUDEdFkD7AyPQ/T7ibUvGIFxDPTWJ/rtAShFGKutxfCYLX1nDdRHt
         xUpHoXk9uSWD1gzUeHDGbVEboIHy0xBjWZ3d37TK8caTafFRRSoLMNQodBu9fHwBsRxo
         BIl/iy6mLdMFmfZ2Am+fbrcNzC8yGy7uiw03DoohPE4TLwP+W8VPYjg0dRRZDNOE5nEj
         D620ncGItedGfKdH4ugVp3DdoGcrYP4MgoJrWWvwHzmQcqzop/6nBcxx/hFA6wgueu0c
         IDC3gGcxdJBlZcI2FEkXHKqZPHRyrCiaBDAs9kqwqHGGpLv27qAPIQA25zQRmtPWdWcT
         jvXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=f05nySEmk+725n/Notsw8bQMzp6pYOsyQQpYkCiUDO0=;
        b=VwmfN2tE+QHqLQ+g2zD/iYRVpQU3dj0E27bw+srwt56Ppn8HaPHIx7e+vpJMaIFgWw
         RLj4cnWqqYVJCr88b2i4jGx1VL2BASMfI9ArYYacWotnmq85IuV2hfJQCdueGwhlWPRM
         T0u2dpZiHgx5bKc9OCtWJR1WFji01UlRnr3CFaxYuUHzc9KRckaBuAT3OE8GA2/seyw5
         vIbtNlx7Rd4fzQkvqxAV+vTEk7cBKpxDP4F1IC5w1pvVU2o3X9P9lsoHYz6Cbw4Xewwo
         T7qN/OzRGGxMpGziSvtEGFTUuZ6dsm0PxnjLzD1lUMyGwkmP6ikUTQ5M6nvM2RvO7zEb
         fGWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="JoazlHT/";
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f05nySEmk+725n/Notsw8bQMzp6pYOsyQQpYkCiUDO0=;
        b=sa1GVI++8OUG11U1CA0wlVvS79DIoK1q1XIY0GdVwhO8j1+vkNG/+7wItH4Z1JsbwZ
         izZPv6MR1Rq2nDk19tErpFKR492+uF46AlLjURgFqdJbPdbs0WwBbsPvoGYdTvrmZITG
         h1cfk4r06NeQfHmMz5oHWIkeemtFXHi7k5gwJHY6+slk0+ihmgxOgiWOVcOHi0qa2r5E
         J2Dd1S+XiBcphsXotUsaMUVwoay+/K1oE2yRu+SVhh/dxftWD47M+ouZl9V5dMWtQBud
         b/LBael5yNuEdlvsQeNMLNhYwYPwQEAzNgKzI1Ou0QIm72axYnKf7NeNOhpyOP2zUkNN
         23iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f05nySEmk+725n/Notsw8bQMzp6pYOsyQQpYkCiUDO0=;
        b=rT3FQevm25buodJL9UR0hacZ7Crj4mxltHTK531tQU5ICasTsfFFK6dNk86S7N3HV0
         PGup3fi8sBuXez8Nm81/XzuEfjgGg8xUTaqNToFxkXrmDQortBneeKmfBz9sMVAwR5pj
         kA0ylKYG59/CkqXjzkc8U/7SnsXMU1msXzU3SQ1BhJamEK9ijsAsRadq75N+uWuhHwHD
         C+4edbfXYxwGhbSJU01t6YjUZB+8RT3vpQIAmk+AWe8Ax8frQO7WWrIq6bLcTbSW5PZU
         LEDPwZ7w5jaPGwRaYkuAy+3Fp9c7Y9SnahDp6O3UxYsHNcoadFUcEdBYJKbY4I9a3eQ0
         4VRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324Lu4DWEXQNHzCnHDcvjaM2e4vLZSsvVARCZG+Y950F7qUI9WU
	XqLnSG66wD8vF4K/2ePMSjk=
X-Google-Smtp-Source: ABdhPJwrlWf7eG0b3h6726wZ2mnT3j+B3ImSTa19mxdBtKuXLSPgZpmMnnmO68ipcArOuzgAAx8cnw==
X-Received: by 2002:a63:b94d:: with SMTP id v13mr802637pgo.361.1632344139717;
        Wed, 22 Sep 2021 13:55:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6252:: with SMTP id q18ls1467226pgv.0.gmail; Wed, 22 Sep
 2021 13:55:39 -0700 (PDT)
X-Received: by 2002:a05:6a00:1390:b0:447:961d:39b9 with SMTP id t16-20020a056a00139000b00447961d39b9mr1010861pfg.83.1632344139148;
        Wed, 22 Sep 2021 13:55:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632344139; cv=none;
        d=google.com; s=arc-20160816;
        b=Xlfq2m3Oj/ZqYFVhEzAkbRmKAPBFZVcLMCQjZdtypG7TsAPuc7owpHrMqyjfdx/GIo
         khGecWx1LfJ61eNcbfWZFXd/AnRmyrMFDeCpCDKFCichubsVNgqZvdmHWBjmid7YTSZB
         xHxIzOu0M2T2vVIUhCziN70QgQFuCxV3rICuyW6VwLV/9nV9MPj1sJHDVmmO7XExh0AI
         LYKlBQSPbMebuLfoWf0CfGA37ujrRIBx5dWfFfTZ5T3v4H3a43O1zdvaNW4ZOAFzNcLb
         M/6yQ9n1kF0j1x2uJmxYtW4LrLaJLL0L92tMcmzFf8CVwina6cgwMdZ8GhV0KFYipJr7
         yVAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=N5R33lCeEAR23h6ryuDeUX0kwHjUUeOVtRNqvTTh+tQ=;
        b=y9TDilZxxNi/lbt0TXABso9cf/Y+jNbOnNhdn0s8GZCfyEMdgHemIs/Sf4jiC0nP+R
         914Gy0P+U+0qxMIrN6+4W0xCC2SnayR4nedAiTFdkAKeMTJ5XwcpkX7bi538YAQBpoxv
         wHRZE+iVyx7XKSZl2UB4UlcWQJP3fm1A4xJIfyaC5LaPEa/5a2fYa6+1N/05n6l52I/P
         O/ld5x98YWc5UomaOOPFZVpTyQTURq1WbPjtd2QdybWQANtqd0hTSsOMDqtLqyur/Jqi
         vxs0A3Mkia8uw8+3Lh2tEvlNxzp77/9fC4KtzFIRsBq3/DfIDhwDKe8FUEHUfk5sgtHZ
         G/lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="JoazlHT/";
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y2si723429pjp.2.2021.09.22.13.55.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Sep 2021 13:55:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DB41261353;
	Wed, 22 Sep 2021 20:55:36 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Nathan Chancellor <nathan@kernel.org>
Subject: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
Date: Wed, 22 Sep 2021 13:55:25 -0700
Message-Id: <20210922205525.570068-1-nathan@kernel.org>
X-Mailer: git-send-email 2.33.0.514.g99c99ed825
MIME-Version: 1.0
X-Patchwork-Bot: notify
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="JoazlHT/";       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
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

Currently, the asan-stack parameter is only passed along if
CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET to
be defined in Kconfig so that the value can be checked. In RISC-V's
case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
asan-stack does not get disabled with clang even when CONFIG_KASAN_STACK
is disabled, resulting in large stack warnings with allmodconfig:

drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:117:12:
error: stack frame size (14400) exceeds limit (2048) in function
'lb035q02_connect' [-Werror,-Wframe-larger-than]
static int lb035q02_connect(struct omap_dss_device *dssdev)
           ^
1 error generated.

Ensure that the value of CONFIG_KASAN_STACK is always passed along to
the compiler so that these warnings do not happen when
CONFIG_KASAN_STACK is disabled.

Link: https://github.com/ClangBuiltLinux/linux/issues/1453
References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and earlier")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
 scripts/Makefile.kasan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 801c415bac59..b9e94c5e7097 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -33,10 +33,11 @@ else
 	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
 	 $(call cc-param,asan-globals=1) \
 	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-stack=$(stack_enable)) \
 	 $(call cc-param,asan-instrument-allocas=1)
 endif
 
+CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS

base-commit: 4057525736b159bd456732d11270af2cc49ec21f
-- 
2.33.0.514.g99c99ed825

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210922205525.570068-1-nathan%40kernel.org.
