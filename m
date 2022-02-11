Return-Path: <kasan-dev+bncBDHK3V5WYIERBVW6TCIAMGQEQRQMY7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id CE7994B223F
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 10:41:42 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id d13-20020adfa34d000000b001e33a1c56f3sf3641176wrb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 01:41:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644572502; cv=pass;
        d=google.com; s=arc-20160816;
        b=uTCZmjO2AKuhANpzTFyah28S3ocWZtbl6F/YXoYhyOSPtWL9IdvFMaq6lgHk7Wbhy4
         /YPUdYt2i0UrUklMAEkKia1Z6n6WVDPrtUBjx2Dw06zqpI6vODz4XNibRcIdfT9xjN2D
         O+ZCLSLLARvTFK38FGiLpXu5h9xgXt72HkVgaXm05+esyXfLWKKXD5YRGY8Ziif+wdMy
         O1UAs6UYIhexRLo7570a+shCxmez6H1aZqXZ3hZY7iT0zRiV3yXfQyD/0t+h3R/qeAm7
         MtlaTI6nsR08BTVWsuFZcy3GYQY4sxdlGYsNLKhmfCZLgtX7UICnaLC0LgvWsANRBJhj
         6QbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QFGeJMMlsJP2piUV4Wz1P8Q0A6Yj7TRLLOiz48s/kLQ=;
        b=oUqeoAAH+juIr+n296XOcikJdHvG8fshqAwty3eYxhTJzMDcyRiGTVc/cfsK5RpxSw
         cFQoyYo69ObnXUMQWRuGOlTn8/4RXoeeZ3d4sHlKOnWHK75ZajHKUHrmuRtisJJrDT0f
         1kdtg3MqUkP70Zc3c5etalaVb4IivUUPRuK1C8ca81pX9RYJQsgj5O1zlFhRs7RQxLdX
         mLE/k1Y54CGLgarRabn56bwJyacrOO+csP/mhT7PbNH7ABxI5KOR1Mo/KXDJ7G/GTezu
         qlQDw5A0Pfl7aNyaYMxpiJ7OPa7ijHqkd8ZF2b67g2AAtC5Nx2u3qvE2vzhfNgzIBEnO
         ednQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ax9bjuve;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QFGeJMMlsJP2piUV4Wz1P8Q0A6Yj7TRLLOiz48s/kLQ=;
        b=RFEOFKlFdO8p8EKNebF/FXYNVa3dBDvpaNnTxW/OU/tLsjK5Am2JJnNkRrzm0tTAgX
         t0Mo5fQxQpiqlPeQiw1DNv0ZwU5vprVSzvnRUlpWivpdMpvP89Frt4RTxzn3aNcgY8k4
         1HsQfMWcYsfHPWxt2YOFX3qisIWQtoxrxlShqubeFMLAQb7RsqjGERdgCmPCqgpsFN9r
         ov8AIU73Fmya27NiN9jvJeJrfEalogckuh26VntsKd3T816ruRuuAFxtKPKQ01RkNDUe
         9alMCDxzmt3Dmr/ACT972bBYLpCyR2UwM6DCQou78N4/Fw8KZihK7j6xoenTHlEhqDCu
         B2bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QFGeJMMlsJP2piUV4Wz1P8Q0A6Yj7TRLLOiz48s/kLQ=;
        b=JjNTEEupS53Sn8pzOE+jpIp+hPqVo5VT85C2QRPfRwNhyPjshAbjwRyifzN/TP9kcQ
         C2b9Eh2TuHujMc5hnpjkiHE1Bs2IjwzLG1AhLchqKWj5rT01ymWHetc2A6GdMLyVo6vu
         sH6rke21KNgzSvTPGZoOlUBgF5oRxzDscBMTn4JU5RQMhIPVTvvJaOWBM0E7Px+vmPAV
         1NiaQlVCN2XHXWDXfUJbrx1T0TmhK0A30O1Sn2Pdv39bEWbSMY4kf8SprNPp2j2lyZ9h
         DQBGcvCgvFzkuJxit6mOtraE9TO3oa80jQVeoIKhe5hg0tmGfVad3xoEWQPWrgsrQmKl
         LRzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y1fw/MyFED0PhJeVdXsrVDPr+wDm/ywb8VIbWDjXBWeCJozZ/
	r37JX83g7K9lVt18d4WnR3U=
X-Google-Smtp-Source: ABdhPJwmY6ubkjLZ+KedI7qBq9U00z9u6+e3zuZW5WGyA9ixLFkZ7rDGvENQB5EyROjh263M5mLIkA==
X-Received: by 2002:a05:6000:1886:: with SMTP id a6mr674252wri.565.1644572502507;
        Fri, 11 Feb 2022 01:41:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a45e:: with SMTP id e30ls126575wra.2.gmail; Fri, 11 Feb
 2022 01:41:41 -0800 (PST)
X-Received: by 2002:a05:6000:1568:: with SMTP id 8mr638535wrz.583.1644572501616;
        Fri, 11 Feb 2022 01:41:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644572501; cv=none;
        d=google.com; s=arc-20160816;
        b=DjqqtfPeCwqUdjnPNLMRX7Fv8TlhI+ECuQwACesW2110q7hJxVB4ORujuCWMQd2jjN
         L7VEq8v+vIBudQ+xtcNL9PNqsPq2JFhmbONunSeOif74t0xFWtCmlP/r0sLWYtCkdZth
         92d7XH/YlklVIONHUzPiQJRNcFUKVMl5GmkiLooRUoGy8tRBHmWVrL6XrQQp6ayqqxkg
         PzmCxqNlOi167MfZc4+9LVL+zqEsv+zMY10SjiMAXsAsVwnOuPgGjD4rlnIfDNojqEO4
         VNtQaKoxGyF9JVwEYApcjoym7/wZnMeSU0xtubiIQ1ku/IrJMKMqcUNQcWR1CvQ9XZix
         gjtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ne9bnxO4PK4jt9C/gSl+PDTM3EheSheXGE0rb10tDic=;
        b=Is3Vgoh6eGql88OydDlPfykCpdR/1JSC9SS4ETTuE7/AfM/ROQZXgk3/qe1oO/fBwF
         fu/DLU0RNL4tmaa9ADk8XJKgfW69ctnrKdJyPfnkCTjLeN3scFOV6HHnREVhZw8/bbTX
         aDRe7yPzhEMmg3syIeW0SlWiaqRC24m3ooLgYs8lSqC7n2EdGexDYT/nWfRzOULH1NtB
         MJ1v93N/aqnTtu+yRAKupjcQXE9HBPcsHA+G9oUO5/UgmMs5eK88xYTfkT1uWeOJoRmt
         es+0AROB5Cv7BKMO3BMaZ3GHxAdFJz7JZ1ceSTzwxmycC7QQC90pgb1vsL/QSIxuMRQf
         rlMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ax9bjuve;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id o19si359967wme.1.2022.02.11.01.41.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 01:41:41 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id h22so3517701ejl.12
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 01:41:41 -0800 (PST)
X-Received: by 2002:a17:906:1d0a:: with SMTP id n10mr656306ejh.143.1644572501424;
        Fri, 11 Feb 2022 01:41:41 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:83e3:abbd:d188:2cc5])
        by smtp.gmail.com with ESMTPSA id e8sm603196ejl.68.2022.02.11.01.41.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 01:41:40 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v5 2/6] kunit: use NULL macros
Date: Fri, 11 Feb 2022 10:41:29 +0100
Message-Id: <20220211094133.265066-2-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211094133.265066-1-ribalda@chromium.org>
References: <20220211094133.265066-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ax9bjuve;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace the NULL checks with the more specific and idiomatic NULL macros.

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Reviewed-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/kunit/kunit-example-test.c | 2 ++
 lib/kunit/kunit-test.c         | 2 +-
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 4bbf37c04eba..91b1df7f59ed 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -91,6 +91,8 @@ static void example_all_expect_macros_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, test);
 	KUNIT_EXPECT_PTR_EQ(test, NULL, NULL);
 	KUNIT_EXPECT_PTR_NE(test, test, NULL);
+	KUNIT_EXPECT_NULL(test, NULL);
+	KUNIT_EXPECT_NOT_NULL(test, test);
 
 	/* String assertions */
 	KUNIT_EXPECT_STREQ(test, "hi", "hi");
diff --git a/lib/kunit/kunit-test.c b/lib/kunit/kunit-test.c
index 555601d17f79..8e2fe083a549 100644
--- a/lib/kunit/kunit-test.c
+++ b/lib/kunit/kunit-test.c
@@ -435,7 +435,7 @@ static void kunit_log_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test,
 				     strstr(suite.log, "along with this."));
 #else
-	KUNIT_EXPECT_PTR_EQ(test, test->log, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, test->log);
 #endif
 }
 
-- 
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211094133.265066-2-ribalda%40chromium.org.
