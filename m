Return-Path: <kasan-dev+bncBDOILZ6ZXABBB45BSKOAMGQED3VQKWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A953F63A64B
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 11:44:04 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id c187-20020a1c35c4000000b003cfee3c91cdsf6126068wma.6
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 02:44:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669632244; cv=pass;
        d=google.com; s=arc-20160816;
        b=B27ux2JiQpz5xGCd9mNX8Aa6F+S2mfD4NDJ6NpvJLQ2cDhkVriGeuGwtn4x/Pb0VC4
         xBJQDxZtxUZGXf06DCravoIciWAdWkYoIWTP6qkXsQnU+beDGGCa3SXcZ+wZnCTza4SM
         cmv5DJlhNjuE2H2pyN8nQbFNAtgd0bCPAEljzfeRYjBAfQOYVwH34mVeIVxrEbXKsitr
         4K/VWAj1IFCORuXkwuC55W7SbyD/MVwepj7K6gthh7t85VJcKB2fGTISvtsmm5UmXNG1
         dUdroPgRpyEU/LaCcC52H2Q+si5XSLm42RheHkGAJf7FZoXLc7IhrsxxDTZim/UEK3xY
         M83A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZAidbPofXUxJmnRIO8FlFifx4joZ9BUw6HPT3jola3A=;
        b=W2UzUArqwN6YHRK2y5qC9I/VTa8vH8BE01J14Y2EP3DDLT07TyYxbt7SKruSrDUXNb
         ds2LmVOU5fQSRz7XsdF0YiX6rW3ZINhyufavhGaRFAX8vYkEIeBLS2RaFnIoRiil/6r5
         pVNT+Dy3Cgb03WI8uS5XHiJdxoPH43TI0Rip76UZpnsWsQ0XL5nBnAjfstw4xbT0Pl0c
         EdeCQgQG+JpX9uNxH+BbMY1exLLqR8dlqYSekGaaDWzSZj6j+QN/ymnGse8LI3VL2hoZ
         1XmP27enRCtyQyPUh0m55KrFC+rV0TatkaRr5trcKNlUQye6jbaX3HHN93G7lbghDkHU
         YmTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Ws0PVJEK;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZAidbPofXUxJmnRIO8FlFifx4joZ9BUw6HPT3jola3A=;
        b=EuXxzqKSk6ZXy+hmkLSxnYEDYguSpcAgteIVnzAAZZMjaDknNV6uUcQKWnsyc6lC1L
         sx2PEJlTN5PrBl0rLkpJgGUoA2g9Cps0Y6djMefq2Ts+K5KH49ncUp11HdI1QeLawbsx
         tel5yj30Vi0rfiszw3MGE+KejmHUDqtXhq5sEPwiNgVQddWGJbfy/swUSfCJaofGA4JE
         KOJYH24e5PlZWbEX8jX3uUb4SDbtdvdDcNL5rcVlwSBaXh11E5hvm401GFg+EdmgdHih
         r5ipphUnoYeYysBhVyAIEB+KlpyTC848hYCgq0rhYNWlm7bwHrqWmFIAPU7XPuWHI8ZR
         RILg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ZAidbPofXUxJmnRIO8FlFifx4joZ9BUw6HPT3jola3A=;
        b=7abeQDPYuiMzY+1OqOwWNHHxIMuE1KN3AJ2YOQn+s4qMDpenbNcczUbCQ2U6lgO0Ia
         JKG6jzHqtFepC0Hf+H0m+wYt9lh91VCLVfbVFPmX/jGJ61T2Gw2BV36Mric0OUAIHX1N
         Oa0+e4an8MuC2S2Fed8vfbQY0wmOKIzLU8dnsnur/lJZE0IM1D9lH9xjuvL8HNkGk65q
         VhvsNVTTQHplKIpe5QjgnqSJ7849GEPHn5jH9znvuysTIqSndmkTC70SPvulcFmxel2Q
         KVdYwbv2AdccWWR21KXfKadX6xG5YloQ4giaVSfwXIw4k3zOEMGY9xEBlcRP2GkFMZMs
         CRYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkCWRr7Fxbm5CUr7teXjvj79c5VTmWjmbHYIsYRI6vW+lOWhzdr
	pPWlHXTSQAljeGvKaCalGho=
X-Google-Smtp-Source: AA0mqf4vRWnszyE6xDYaWau7oPBrlVckBVb2y+TqnOmmv5CIM8YToP6c1d+Gm4WHemFYYMtK6/Bkng==
X-Received: by 2002:a05:600c:511b:b0:3d0:128a:6d1e with SMTP id o27-20020a05600c511b00b003d0128a6d1emr22634229wms.108.1669632244176;
        Mon, 28 Nov 2022 02:44:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20b:0:b0:228:ddd7:f40e with SMTP id j11-20020adfd20b000000b00228ddd7f40els10717359wrh.3.-pod-prod-gmail;
 Mon, 28 Nov 2022 02:44:03 -0800 (PST)
X-Received: by 2002:a05:6000:114f:b0:241:c80c:5f54 with SMTP id d15-20020a056000114f00b00241c80c5f54mr26407563wrx.15.1669632243145;
        Mon, 28 Nov 2022 02:44:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669632243; cv=none;
        d=google.com; s=arc-20160816;
        b=OWA6Coyd9QHjwh5xbJECorKfX7IDg2H9v8scxFxOSG7uRLPUEuyAcwiA3Xe2KHvvPO
         /oi0cWgIY8J+TZOYi/gP9prd6NjjGcM6W2yE4QBPgIbW4jSgHMk0m/Mflmxcv2xphKbV
         EKxjkxmC0umJ4d5Yc0JnfnJlkjfVBCSTHKCUB/Pm7NDItImVblNXnan+PCUy/Ays1RtE
         HTUi/OCmPUv42hY9ZoxUDDISYvygssYyg4ROEgzXsIxkq0N6XCmWuk1ux3J3Pg/wduqB
         N1KAfHq779PHQV/iLkSXeQgSjxE4k3CNt/tPankadXOzlHmjR9xkAR5uKN7YDkXw7Ixf
         ij7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wEdrYKs1l92oDoYXxk/BBvzoFFgUAzw23QwIrQ7Ayls=;
        b=rzHMxFuI1NDcEJme96ALVyflWysE1BAqogaeefP2dR9JX35u6GuJS/xFRY3PzhAJKp
         qX3Vl5ACh2yNXsUADvIJO+Dfvm21LFBRHoXbc8/qTqREfjOM3t5LuFVdqQ3C8jE+Lh7/
         roSJBfjcThOk0u8TuZd68nde+gFWeOjelfIMWCtN2lqQg0gCk2rRblgrztDmFJW1XOW3
         ZwUicbegx1eIfyx2q2JMktkz8qw+LYcIhmw8hYFztvau+9iFsNdfL9q2dPrPlfAiZxBj
         ioRzLWrwulrzsVjS/SoBs9eTDqb8c/siPV5k8Y1K79ElSvEh1gLhgXM0UqZ4YxScAJqo
         S5pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Ws0PVJEK;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id v6-20020a1cf706000000b003c4ecff4e2bsi606527wmh.1.2022.11.28.02.44.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Nov 2022 02:44:03 -0800 (PST)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id q7so12616037ljp.9
        for <kasan-dev@googlegroups.com>; Mon, 28 Nov 2022 02:44:03 -0800 (PST)
X-Received: by 2002:a05:651c:b26:b0:277:9847:286a with SMTP id b38-20020a05651c0b2600b002779847286amr10427471ljr.309.1669632242561;
        Mon, 28 Nov 2022 02:44:02 -0800 (PST)
Received: from localhost (c-e429e555.07-21-73746f28.bbcust.telenor.se. [85.229.41.228])
        by smtp.gmail.com with ESMTPSA id i15-20020a056512340f00b004afc1607130sm1667108lfr.8.2022.11.28.02.44.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Nov 2022 02:44:01 -0800 (PST)
From: Anders Roxell <anders.roxell@linaro.org>
To: elver@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	akpm@linux-foundation.org,
	keescook@chromium.org,
	davidgow@google.com,
	Jason@zx2c4.com,
	Anders Roxell <anders.roxell@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>
Subject: [PATCH 1/2] kernel: kcsan: kcsan_test: build without structleak plugin
Date: Mon, 28 Nov 2022 11:43:58 +0100
Message-Id: <20221128104358.2660634-1-anders.roxell@linaro.org>
X-Mailer: git-send-email 2.35.1
MIME-Version: 1.0
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=Ws0PVJEK;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Building kcsan_test with strucleak plugin enabled makes the stack frame
size to grow.

kernel/kcsan/kcsan_test.c:704:1: error: the frame size of 3296 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]

Turn off the structleak plugin checks for kcsan_test.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
---
 kernel/kcsan/Makefile | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 4f35d1bced6a..8cf70f068d92 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -17,4 +17,5 @@ KCSAN_INSTRUMENT_BARRIERS_selftest.o := y
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
 CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
+CFLAGS_kcsan_test.o += $(DISABLE_STRUCTLEAK_PLUGIN)
 obj-$(CONFIG_KCSAN_KUNIT_TEST) += kcsan_test.o
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221128104358.2660634-1-anders.roxell%40linaro.org.
