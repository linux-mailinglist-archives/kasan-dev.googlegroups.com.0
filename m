Return-Path: <kasan-dev+bncBDHK3V5WYIERBC5ETKIAMGQEGONAEIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 653B04B2AAD
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:42:52 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id r2-20020adfa142000000b001e176ac1ec3sf4071430wrr.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:42:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597772; cv=pass;
        d=google.com; s=arc-20160816;
        b=PtNd2rYJ6aS0sjr5Epmx1r33e4zDytA2dxi0+uuZ6GSuukp7UBePzn/oOZB1qYstL5
         57uFjpmwIHY/2zSO/SAbZ9fDYZ02rWtEJX3sI4YNhlp/qkgT5ODmuRnfd3V6C1f/NabG
         bNm0iiaI+X97xNilPXMQN6E/3DQN3gTsDQXGv3IgFD0wLuyZEXKBbZNNv9P9htTg1uIV
         SIe8dTai0EYi4LXZ2IZDqKBlTsMuY7obC6T+tKwN6leWdxnHleRPTLwOee5UeCwBkbWy
         akhTznhJL11uubWKTUvZs4bdkdAuMwrPSzMdazeR36VEGWr0E1QejHckxrrzOIHFpJcc
         IZVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZRL/r4STEMMzfdeE3ZTAnUlCRi0msr2sSCunx6OeJAI=;
        b=jLZjFafl1L2Y1hHF3GTHPKyQoUEOzyfuMVhnfXcv4IEtmRVK1TmWw50mlPbUMhzklG
         fpqXwiV7zDvrjRmzzQI0/AsgjqhVf82pXGGbKsvUEmK3CWD49zK7etMpFWQv7XO52/B7
         e3XEVqgCkb6WnpGMU9WaYO9d+jHKnm0exrHVqf2Me0EtG7H/Hi0R+t3Q3jT1HEKSv/xF
         eA2GF1BglPdbwc3bdSBfIAB5QzcocB9nEfuiToeqhtx4t4h1lvEZ3/0E3BvYZ769Ey7o
         +Ktm33hNxfofTrRE0ndUwcV524wthzxzj7pe0szswMxPgXEHa1d/Ab1pJi/bHVehj4pV
         h1jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Apm/1Dcq";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZRL/r4STEMMzfdeE3ZTAnUlCRi0msr2sSCunx6OeJAI=;
        b=lRlwvcuRKlBpYX10QFq/qb0qVOyGAMbrjOjnxdz/6BMI9nCGnD1YM9IMwcFwhsgIgF
         siZyWM0l8atjMBf8XcI5+/0LQSlr5Fw9Dkd1PC7k/lQxCBWgm8RX+GgH8q/1dW/1iZhx
         oUAjQvi3Jt1YlOcjPWemPgo0ezz5gH/wa3cHlOcPIyNE+t4ZzSmRBpgXcQrECTOq0/au
         dTUIW2S2KRv8lDIuP6NOwOphW1G5SEzpGmeJTtk3TanY3sz7G/iFRGVeurHHUf59lsYV
         S4V3+4hOcdCL7PT9/PwRyndDEagmPvwa9KKk3YVAUhdojoafs5fSs7tLXIZjQx6UkiZt
         sHXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZRL/r4STEMMzfdeE3ZTAnUlCRi0msr2sSCunx6OeJAI=;
        b=nQV8Xz+ro6HIIZri/MZ5CI+0XcFgAdmXzcO8Tcl+fnWydvIyu+L1I8WSzTQ2tHx+HB
         gzMLyw/LPL7z3/2izXeQ+ry5J0+J56B4K8dN90hOVowmYlYQzU+DGed5dbqodfZS7sAG
         qiJB/QT58bUs714fwxjpYuyO0BTO/PJZ57tHe/GJARyhTLO4vHe5tfGJ9D/+Cy8vKTYg
         kH8Pn5YQ6RIlcKSteNguCF1L9aG+wS3xssA6YaONpDgv8HjfvhSG7eEqycuikInK/QhG
         3s0O2g/MpokVG8BFokAIcx26pyimwFc35URe913tv+oJmLn0JB99FIXHEMXT9+5dOMhq
         9gxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nCAHE20Oto4Q15ohcveHLFAbsyOrZm5iCSX+VrRD5rF6JmmJA
	iwZ8lJmh3BQcCeXiJErs4yQ=
X-Google-Smtp-Source: ABdhPJz82FwdWIyZjcNIPUwM1jPsYmuGgfQ1J0oZkRDZJSe7Ba5x+nMK4xEtl7BFxgVCwOi5ukqN4w==
X-Received: by 2002:a05:600c:1e8b:: with SMTP id be11mr1000363wmb.96.1644597772100;
        Fri, 11 Feb 2022 08:42:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a3d0:: with SMTP id m16ls1118wrb.3.gmail; Fri, 11 Feb
 2022 08:42:51 -0800 (PST)
X-Received: by 2002:a5d:64e5:: with SMTP id g5mr2056041wri.541.1644597771077;
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597771; cv=none;
        d=google.com; s=arc-20160816;
        b=nMEsPpl9dSz+u3YmI3MdqGcvNtB3SLrCKVOVAbgouxhjOecuQ0w7SzMin5+U4X236F
         Z8XwQrHT8LoGjOSRTmqTJ1tK3V3BUiRjMTpVTl/cyjzdCZdAG7BjSzy+nR0Zm63JnqXy
         BJztNZ1LM5+h7aHiv+0ivX4tueZnYpUXe1WFT7fbCaQlta1s8FWoPm6fY53iXcLlM0RO
         5f8TJ6eJrEGkJzPFPGJjV+p/6NQNDhmMsoX7JJvPMoeNe9RK3SWbR80gs4rfunjZMBci
         j5/kj2BjRWXPDvmJznYzUaaHzZTWXuXLS3SllQo6oH2bDlYc3y9PaZPL7C74YFpxO8Au
         SfXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rByTC1qdfOpqKBTw6wu+dL30l5MNIQcmECFcqJUWyKk=;
        b=e94/gp670YCX7dBLSERZRTTBxx1EYagCDAh69nNC1GNGmQIHX3KjHJPCV/h7kgb1wu
         rvIMZu44Vv0r9MyiZEd2p/0+9/WvWZvEnLf+2RHguZb3v8uDYrSsrwJdiJPI/XLVKPRG
         Is9/10xuX5Z4ocrLFKXqLZj1lINTT5hbhqLa8Ql4xVyIDYZBL1WU27GNCqjy8u7Uhj11
         sA+2L1RTrLzaTr9EJPGQTds+ZKnD7OREWxEPrM1TrWQMVq000m/vvSOiZUGpSprk8yvN
         3WKOulQ8dvUEX5ihiFFCAmbfGP+QHLQ10xtxYfU/n4a1is68CwPhOnHRY0+/m8oKpD4Q
         CW2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Apm/1Dcq";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id c4si292158wmq.1.2022.02.11.08.42.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:42:51 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id h22so6026042ejl.12
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:42:51 -0800 (PST)
X-Received: by 2002:a17:907:6e14:: with SMTP id sd20mr2085294ejc.749.1644597770859;
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id i24sm4981233edt.86.2022.02.11.08.42.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v6 5/6] mctp: test: Use NULL macros
Date: Fri, 11 Feb 2022 17:42:45 +0100
Message-Id: <20220211164246.410079-5-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211164246.410079-1-ribalda@chromium.org>
References: <20220211164246.410079-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="Apm/1Dcq";       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c
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

Replace the PTR_EQ NULL checks wit the NULL macros. More idiomatic and
specific.

Acked-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 net/mctp/test/route-test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/net/mctp/test/route-test.c b/net/mctp/test/route-test.c
index 750f9f9b4daf..eb70b524c78e 100644
--- a/net/mctp/test/route-test.c
+++ b/net/mctp/test/route-test.c
@@ -361,7 +361,7 @@ static void mctp_test_route_input_sk(struct kunit *test)
 	} else {
 		KUNIT_EXPECT_NE(test, rc, 0);
 		skb2 = skb_recv_datagram(sock->sk, 0, 1, &rc);
-		KUNIT_EXPECT_PTR_EQ(test, skb2, NULL);
+		KUNIT_EXPECT_NULL(test, skb2);
 	}
 
 	__mctp_route_test_fini(test, dev, rt, sock);
@@ -430,7 +430,7 @@ static void mctp_test_route_input_sk_reasm(struct kunit *test)
 		skb_free_datagram(sock->sk, skb2);
 
 	} else {
-		KUNIT_EXPECT_PTR_EQ(test, skb2, NULL);
+		KUNIT_EXPECT_NULL(test, skb2);
 	}
 
 	__mctp_route_test_fini(test, dev, rt, sock);
-- 
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211164246.410079-5-ribalda%40chromium.org.
