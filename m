Return-Path: <kasan-dev+bncBDHK3V5WYIERBKEBQ2IAMGQE6PJWLKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 828BC4ACA60
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:27:20 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id g17-20020adfa591000000b001da86c91c22sf4995682wrc.5
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:27:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265640; cv=pass;
        d=google.com; s=arc-20160816;
        b=vK6bHxj12/zCJ3OFqyEfJHaiTtdplw/UkHtwb3oUEMuIzmmzv3j4Jvz9GTkeDba5EN
         NAngolSFMNERpxkkxDzfNfpEGPQTrmc26L2QgfdtK0OtC8CWWfpZBAUXb3VjQIH7NCoN
         8kbG4Ai2J5vQkI/dJ24eK4KN4zPAsaduSk+S4xBEjSsZdOnylzRzLgOAhRImQ3RwWwZ8
         YOpcAPOEw7XPwZ+3g/eK0oWNRQOzy/S/W9pDlZTrAOnQX7q5oihuxKzh9T3wyZ8P66c4
         zfUTCte27Zf6EfDAVrOn6ekav7qItvff46wh0w0znltgqXlRREMsLkHENVubIWlh0vwA
         YnYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rJMkGMZkv6JL6t9RU96gXbjYm2jXSkSjpz6AuqPKZ4Y=;
        b=KbKDe7FcGyIMy9gxA1hYX2UJznQQjwXzWTyUOqzHVTBmxGxXy/cBF8JVMJCEg9u9sV
         kpEiPfGT72qqxMoYKBpOMrR/PUC572JszhcXgD3zQYLBjNjrME+Yo5lDWIk6uqfdjtig
         nMPUBwU4RJChpt6zl9MUwEiPQUAxzHiU4JZP6CDoISaS5B4aUSbZYNxJbYS5f5iYnfbK
         mJ4WZmnLkwpmMunIoDrCTzwnBwpZ7aA8SX9WMFtNLg6RkFhqObJa36x0EVKV+0btBWjl
         tPfCD+/seo9R7Lkvp+YoXqNfUu2wHeopvBLDWENxdhDMMl/6hxZixWaIKwZFUJ6cSqaR
         2FKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VSeSAlio;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rJMkGMZkv6JL6t9RU96gXbjYm2jXSkSjpz6AuqPKZ4Y=;
        b=MgMckz1fI7D4lQishMcU/5bb7OrMrpmc3aFjhSZ8jGcbVrsglDmRl5+vU7VgL/d16g
         gbiuZRXLFaU7NX8eNQkfFDnvt7q7R+d6mjSYWtbaCsHnMbAPM+naQEDPG+Zo9YnLppC9
         5XqCcEfj7TOLJOmraMwp/63uRhPDo5euCxvDDhT0XLjLv2ji5veLldFraOCBbI05Kqw6
         Ww7PvTN6AjGUqbx9H8SZtHu8q7ERLWaUzLS/p6BYa71qv5HwJ2FMzdMljTBRhhhB7lrO
         OKHmzL50VbNhshJb0B5uaX/PJTIc8710ogjzsHtZoUhHZkHcaf7OuMgw64tMovkNc3sW
         A/HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rJMkGMZkv6JL6t9RU96gXbjYm2jXSkSjpz6AuqPKZ4Y=;
        b=hqh3zjIo+hv3Ic0g6ko/+b1eUEDUbibT5Wjiz3HkUouN+ZelRlkY8apFXp9fLq6Jqx
         LCHPeHOmgKEDwr6MGmH5MYyS9dgBy04O1Xd53JrZCIB1JuqdYkbOMMrx3p6TVPqFHq3d
         AWHgiFEUvx0HQ1xlbCoAZh7nRaVw/RmfbrbzIVPwOP2VHJT4cIQ8/FkfSMLot4xx56q5
         71QNAaSTGYs8dVV8sMM4ZOngbLSTdjsSgOz32O436CBpGXa5e1wITQGKID/NxCtU7w5J
         GVpdCWu66026ERKkzk0KLFzbWiXJ09JvLlSCX9+QbOXk4EzpuHT28JWdmmfJ1rOko553
         etOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zffrphTWVKdcMLuI/wtUgFfqDb/p69afX2XXor/KAVVHshsTQ
	EJQGHGMAZnA1hSdZPHq0Q2g=
X-Google-Smtp-Source: ABdhPJzdKxisG4l3HznD47fkzTelI/0k27hwg7RU+VuydT9IyBLcL0PW9z79gftnbMtY1YiqHgDtlQ==
X-Received: by 2002:a05:600c:300b:: with SMTP id j11mr90050wmh.3.1644265640189;
        Mon, 07 Feb 2022 12:27:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a51b:: with SMTP id i27ls331514wrb.3.gmail; Mon, 07 Feb
 2022 12:27:19 -0800 (PST)
X-Received: by 2002:a5d:6443:: with SMTP id d3mr863098wrw.33.1644265639294;
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265639; cv=none;
        d=google.com; s=arc-20160816;
        b=F/hfzzk3EOQtbK5rS7RkHi9QcNFDt9ztkYlpxQfyrnab5uKqNgKZ/kkx4O/EYWe6Nq
         FyafGr6qGXkZfH0oe0n1bEcNSSy0KAZW6sKtJv8FNubbKsi20o+k3p7vnZvo/J4L9qrw
         MCxIrf4HwiqZbjRJTXL+fpOPdBCmLmSgITsUaa+JD4dHDTVKf/QY/rhfxtYWlK/Iaout
         b2eE7GfEKLhP/3fMbWQcMEk2G0kYVJAgPWL2kyYnPsFiRhtCSMjZvfzEKSHLd5Z5ZL9V
         aCQSp2ugITUFmC+l28MokOELW4syfdCj21Cf3uA2icXPFtAIx+6uMVuZfz62kBzAGus+
         yo1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=COoBb1joui25djaKHvMRbQv4Mt4Thb8VpuVozeRERCg=;
        b=ZWXHWDehZnXwrG0vEAc1cS2aaSglxkPbjgk3fEwfkcfhIOzY2CwPzno5NFxnvbadRQ
         CBwquwBPqBj/PgpgEHXBmCJO+N306Vz5gD0AFbcrLmtNzyFILypIKtYyVMCPPnzMk0l7
         BJj7rQ1OONi4QrgvXLYr95xSBigZx9TL4aILUrMuE7JEm8trcv5RiHjq8P+ahtOQWaTK
         a1Vxu9EcRH0dOdJxh5j8VQn9OZdy2ESSVgv55V8bKuFUnXimwvAu71r5uVeXig6ewG6q
         ffoe7GgM6JlqXKsCNrwrWLAt28UqR5ZoOc6VrSRnFL82MQYFyN3gqzZtaLn+oguyKk4V
         53HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VSeSAlio;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id d14si531550wrz.4.2022.02.07.12.27.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id a8so45527713ejc.8
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:27:19 -0800 (PST)
X-Received: by 2002:a17:907:9494:: with SMTP id dm20mr1097662ejc.148.1644265639140;
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id t8sm787893eji.94.2022.02.07.12.27.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 12:27:18 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v2 5/6] mctp: test: Use NULL macros
Date: Mon,  7 Feb 2022 21:27:13 +0100
Message-Id: <20220207202714.1890024-5-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207202714.1890024-1-ribalda@chromium.org>
References: <20220207202714.1890024-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=VSeSAlio;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::632
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
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207202714.1890024-5-ribalda%40chromium.org.
