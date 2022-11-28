Return-Path: <kasan-dev+bncBDOILZ6ZXABBB6FBSKOAMGQEKDJJD6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 84EB663A64D
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 11:44:10 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id z9-20020a2ebe09000000b002796f022c63sf2302929ljq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 02:44:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669632250; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJx4AZtaqWXjH/En3KV+WZQKbeoRz6X2/L/EgCgqUOQMhCQrXEkEi/sKLuRccUn98G
         PozNqD4g9BCrXOE3ycR1LK0znVuAbFVBtMz39f3hPzPbS01imNOBG7mPpU9gbXmD6SPI
         wJP5c0MT5Mk2kr7xxszTI1aL13FlWKpzgyqfalUU+fKXCuTAS/k9vmpc22MjiqOJQGGi
         8dipPS5NoLpPZ+HgjxJzvH4VOI0WBUS33NpsqtWkeWciqDi6bN+6d8Za6j076wl86sDb
         bJEgO8+fzzuF9mjJBHCOxiW2vJgpWQ7MfXxqztLhG3WKMM9wH08HNb2Frts1vfDHLhRq
         Ph6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=r3RE++0wKKf21Rw9M2uTf+RchTNpKd70QAZ5br/6dZI=;
        b=bcYCCiQjMIXnsZWd+u1J94ONGTlrD4uVwkJ+l1M1MRkEV9blutOm7oiXye0Kv4gPSg
         T/b0GukPjYrKEYWv1w3LN5XaJX8qMUF89ZhAutKrsYDndoOze98ZtaGMzVAMKE1ax07I
         rlba65lCQTn9S6Ur2+y3niD0C4ekjPeouHnGty5myai4In48Lz5tzB/NdDBDje4mS1NV
         CGbIfIOfS+xdB2EoeMqLCudu/9FNkdGH8H/o9XQEokTmR58xin3kOn97oeKasCyjuqh5
         LIqAmZHHdEHOhvDXxJk4drwvTep5ZoYbiNrDt5JK4WPUtidrtSBDg0K1q8UJdWqUc0EV
         iB4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=wzELQ8ja;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=r3RE++0wKKf21Rw9M2uTf+RchTNpKd70QAZ5br/6dZI=;
        b=c0bM5mF6EkfSrNTKl2aHPR+0ivv6XWX6zkpHc6/ID6FVT7WNiLSYJnrDon6G5+Dolq
         3ywy4P9TnnA+pZLQ+bOdbSFAvz+fkR6zn0O5ikrTkNRIK71bBeFgl71QKEOhVpkNt/sp
         sYi6j94GIe/j2x/AMopxH8pvgUMCj9HilvqO05QDO3DM5oBErNVNdYBYDfBxHoqAagNo
         2sY9W0i6WVog2te+5TohNrvXICMPDer4utIRRzFcAXDghvPax3IDz1s1D3Yk7YXD5Rr3
         SqlnuaRCY2vkvf4VHMO0UJcBcrTMU3BH2JbSNzKUSkstiwX9jPpelwHRzn2gcEKstruV
         Ym8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=r3RE++0wKKf21Rw9M2uTf+RchTNpKd70QAZ5br/6dZI=;
        b=lOytFKkx75Hgouh93N9znwz7kgR3LOWbdYUz2bZR9AHq2P75QLlRIbc40y6cwwufTh
         fSLxjX3F6oW7AgZ6nTv074VuEs7yZn9LjS7ToiTBNHdPOJkbEZ8upQjbPU8xCQe+iUN9
         v80Cf22fpjL9xRHL8fVsAV4mxdzXqePy+OdJRVBxajXh4CugON4h5IIIGgkoul/OegGa
         4UWD5E5n/IoLe1H5CtAYldZx3NaiV3oPMM/jBzz6nUPbvKPvz1npq0h1u5atHThuPsGu
         +sV8MloXIg08bYEb43dYfrLBxOaEwWny8aJgn1GlWGe7lzX1VqtaN6LPKF2WsuV+gu+1
         Sv/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plLhnTeAmyXatRXFk94anwGNwlA8C0KQS6N/EPzT30lkF/Zl2Oy
	nwYw9dSMpxDxHDACZWGz51o=
X-Google-Smtp-Source: AA0mqf73P/8XBOk5vfPFtJNEyyrcQwgq33bCCqMbz7C0fCRU/OFulxGsYKa+8PpN2B3aqWyjeoFSRw==
X-Received: by 2002:a05:651c:14d:b0:279:9f97:9f8d with SMTP id c13-20020a05651c014d00b002799f979f8dmr1860251ljd.391.1669632248381;
        Mon, 28 Nov 2022 02:44:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ec:0:b0:4a2:3951:eac8 with SMTP id v12-20020ac258ec000000b004a23951eac8ls564803lfo.0.-pod-prod-gmail;
 Mon, 28 Nov 2022 02:44:07 -0800 (PST)
X-Received: by 2002:a19:7403:0:b0:494:9f2a:ab31 with SMTP id v3-20020a197403000000b004949f2aab31mr19089397lfe.457.1669632247202;
        Mon, 28 Nov 2022 02:44:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669632247; cv=none;
        d=google.com; s=arc-20160816;
        b=ZVgAlr7fc05o1W9lp2k8PFvnJg1lxYuKJHcTjltVmHmqN5clxnFgnpHHfTBMzGqWxh
         bj8Kiqqyyh4bcAux3nHhKWRQzhhRMFkXU2XTsH0TP6VIJtkAQ5fJZeOyrlnUeXcsbIf/
         xl0e+ynW6jSMPw6cL0DYgFwFaBdPryNR0wUzISW+5suWCA/3WElnnqVGeKmYDUdZkRTs
         fet0Je/swYZ7oecRbdtfp7oBQdqcm9HfCi7nXTE7G1l2Qn5jzaDRTBX/JjhIwTH5BNTc
         zuqmkh4I7rIKix6TpsjsibB0+D4sqH4bS5KyJPfpdCXEt83hfIQtPTLbXsh/QrTmTd8Z
         /pxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Qrek+ZlPBIzYYnVWAWL9s79RP21Pt1wu3tLOil+ceCM=;
        b=UOWeVTqGN27Toq6JxCkQNce4c1Gjdp0G85ogEIe1Q/1SyEYikP8gQd32p4PDiDpm6A
         XxNDJxEVR8nqz3OiuWbQlMy6S2XCaIBKORKHlH1LTimTeTz1NBiTAOuWk/9/iFKynL6M
         xfaMxNq3VQ6gyBiduvuMSSnYx0PawD0IOsVDp0keOT339lVrci9hQDme6bsSKdF4wNtc
         qTuk7BiRfF6RAHWSJTshcpvvpsCmMAtKSbxDVOuiyawv8P27Upmv5c1aS1HcFcWJRUlk
         HivK/9kXr7BelgtZZQtvDOWFB9n2hMGrIOu+EwNVkylbezAKzQRW0tKoPPZnFgGxm3EZ
         dtOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=wzELQ8ja;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id f5-20020a056512360500b004a222ff195esi417815lfs.11.2022.11.28.02.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Nov 2022 02:44:07 -0800 (PST)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id j2so10105281ljg.10
        for <kasan-dev@googlegroups.com>; Mon, 28 Nov 2022 02:44:07 -0800 (PST)
X-Received: by 2002:a2e:9797:0:b0:279:ab91:e4aa with SMTP id y23-20020a2e9797000000b00279ab91e4aamr119973lji.267.1669632245446;
        Mon, 28 Nov 2022 02:44:05 -0800 (PST)
Received: from localhost (c-e429e555.07-21-73746f28.bbcust.telenor.se. [85.229.41.228])
        by smtp.gmail.com with ESMTPSA id v7-20020a2ea607000000b0026e0434eb1esm1153662ljp.67.2022.11.28.02.44.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Nov 2022 02:44:05 -0800 (PST)
From: Anders Roxell <anders.roxell@linaro.org>
To: akpm@linux-foundation.org
Cc: elver@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.or,
	keescook@chromium.org,
	davidgow@google.com,
	Jason@zx2c4.com,
	Anders Roxell <anders.roxell@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>
Subject: [PATCH 2/2] lib: fortify_kunit: build without structleak plugin
Date: Mon, 28 Nov 2022 11:44:03 +0100
Message-Id: <20221128104403.2660703-1-anders.roxell@linaro.org>
X-Mailer: git-send-email 2.35.1
MIME-Version: 1.0
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=wzELQ8ja;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
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

Building fortify_kunit with strucleak plugin enabled makes the stack
frame size to grow.

lib/fortify_kunit.c:140:1: error: the frame size of 2368 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]

Turn off the structleak plugin checks for fortify_kunit.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
---
 lib/Makefile | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Makefile b/lib/Makefile
index bdb1552cbe9c..aab32082564a 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -382,6 +382,7 @@ obj-$(CONFIG_OVERFLOW_KUNIT_TEST) += overflow_kunit.o
 CFLAGS_stackinit_kunit.o += $(call cc-disable-warning, switch-unreachable)
 obj-$(CONFIG_STACKINIT_KUNIT_TEST) += stackinit_kunit.o
 CFLAGS_fortify_kunit.o += $(call cc-disable-warning, unsequenced)
+CFLAGS_fortify_kunit.o += $(DISABLE_STRUCTLEAK_PLUGIN)
 obj-$(CONFIG_FORTIFY_KUNIT_TEST) += fortify_kunit.o
 obj-$(CONFIG_STRSCPY_KUNIT_TEST) += strscpy_kunit.o
 obj-$(CONFIG_SIPHASH_KUNIT_TEST) += siphash_kunit.o
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221128104403.2660703-1-anders.roxell%40linaro.org.
