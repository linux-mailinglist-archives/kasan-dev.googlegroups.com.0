Return-Path: <kasan-dev+bncBDHK3V5WYIERB3NPRGIAMGQECM7QXQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BEAB4AD7BC
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 12:45:50 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id w7-20020adfbac7000000b001d6f75e4faesf5975058wrg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 03:45:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644320749; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJUXX4KvoC/IW+rWErX2o9TKOJ4H/8muUGzb11LBlEIBFZdw4aIoEz3eVxTkMQu7SE
         ZeMHQ/cnPzSWP/P0AwFN8hlM4paGJB0XOoduVTX8Kg/kI79JnND/OsRTRhmgMMpI8U0k
         dQUdnXhW4Kexqq7V+jrdKgHbQ/I5PBrlFnEWV5OaQYMtFoOpe0xhMIm10RDo0uehrHco
         PJKiHYAfUQFC0vX6xu6Sy8pOqYVvz/hIByOWCtGsooRwcAcxIWcN3XgDE1/wTynphdV7
         kvwIWcIyiYGkaXj5Chtu1wMtTKVdHfolNqnJcKO2p9FJ/hJ+U88QvM3/xvKXC8XBUrGo
         i9tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=goqU2UtzCs3QIgMICD8+1nOSw42tD26ynY/T6sYt4Bk=;
        b=g3AAc/Gyb9lGI2hEQDrVlkZcuIAJkwd2dclwRVPVfbzzeqX6ZjkiMR/IEHV/k6xxFY
         BNEkswFoOmdvb8F9ercfX9xPr7yzULGl4Tsb9kdbJqoB4wDkL1FM7WC+zrsfh9ZI7g1s
         LVllvpCGjeyRbjV3Forb6o14o1EKV5ZjObrPwxOWYuV6UcxK0IHc2uHbM10krf6W9g0I
         jegKJe8ZQt6zZE/Spvn2NvvNjjc6TeGvof5OHn4S9QAM5xYjVH7IWhRrDL49MX7uw+ap
         sRjfFF40N78BFzV5xPyzuwk7PM03at4sr6mpkgs4IQUcs82Yt7lt14Lpcs1SCAGA9Lzz
         oLuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VWm2iwcQ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=goqU2UtzCs3QIgMICD8+1nOSw42tD26ynY/T6sYt4Bk=;
        b=HPg4yTi6pgK90ps8Nts4Cay/Hcb8V79bfbH3HL+bofge/brlrfVCCBLD7P9RXv+Q4A
         Ri5u1LiPgvRs2dP7CT58W6gsfRSVc6ObLC5xZkP7YrOiA6rjuLUadi1OiltvJzesswzh
         AqM5xE/tbTUgnMFyuUO/PdlfTeRztHAQBYIpGCiEAOzQ7PefrK3V5n4xtcSBflWtlyay
         E3JpBhnVXtDUnOYwA51QqhAQieAF73B1+5BJkpbzDGBNLJjKpVzJoQxrL59vUBdj53p6
         cv4GyysODKFH06qdOfQrhC5FKHkygCTQNq9PkCFDFsBfd0HuWg7maDHQjbyKLiwtNa9u
         gr1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=goqU2UtzCs3QIgMICD8+1nOSw42tD26ynY/T6sYt4Bk=;
        b=kTo6iSOq2gPncK5FXmvNVDsF0rx8q17MAY5c+3vuwbXNOvE8D7ZUuMxnYwU7ccd9As
         HtOO9KdFLSyd68b6EjeJZz+DoYe2Czjz5jktbfsHShpSRaB3vfY+Uc0C6MmCkcmfkhot
         JwcaYQO4xLmt4W2xuZOV2kwKiamh+xet7CYuHk/rVqT1VEU05e+XpUCGj9+yyFFNCJ21
         o55UNu9E0fmn3HR7Vtyohh9mBww+kcOKwC+eWlxxAQv9EuMhBJhZIPTNrBZKBaVCvwNv
         aV1zSFia9qzYtlNj50MiJsZVwr8lLipF9q9c3jdlTsjcu9uEC/MNxWbdPZ+vQm8Tead7
         VyLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532u7xSHP9/YZF2kAb4VbQX/4oYDwfCNgs5iipNZJjJw0vDJVTkn
	gyUfa5QkmiBvcu5KSUyfRiw=
X-Google-Smtp-Source: ABdhPJzE3qUGFCTRaV+HEO7sF5FHze7nTLubPEh+Rj1prFqhriPbvxQMaiuxRH1MMKADXusBveiN2g==
X-Received: by 2002:adf:ef10:: with SMTP id e16mr2983301wro.428.1644320749779;
        Tue, 08 Feb 2022 03:45:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7909:: with SMTP id l9ls56404wme.0.experimental-gmail;
 Tue, 08 Feb 2022 03:45:48 -0800 (PST)
X-Received: by 2002:a5d:4411:: with SMTP id z17mr1200972wrq.384.1644320748631;
        Tue, 08 Feb 2022 03:45:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644320748; cv=none;
        d=google.com; s=arc-20160816;
        b=Lqu1rK0cPOHQoPrZ10A7xf0Tda2CwxyVFLBhGVszeTN3yZyh9tFJ+sHfMUUhEWxqef
         Ba/qDoFUZTLWhmJamQoO3SCdfaXxZxZlbqtZFnmJPivBEzCAGu34VHsW0QC43OdA0rlB
         Rc1AkVm9qTldAIexaTGdoIxFDHOmGlCn2h6pYQSFY8ZvzUdCD/JYmm/oa646s7KfaAOM
         34AXktK24XNtzJTlJ7a7CxHV2Xyw+zWtWIAxBk+OxY7CmXmBMZPrLWmd8ojh6AMyl/Lx
         YsGyLX2kk9F6wN8i7DCTdWS7v9GV4nLn45rTihztTBZz0wEeMpvGOd1BtqhgGDfT9cYT
         cx2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=34ZmyfAhOEYAooNo/xPVmg8jgekAv0axuEgwIeZSupk=;
        b=VELU73qnv0E51IH5+Mf1IMrWp2vVl9nRSTH3nzYEaRIe/NfoZXooszXS1/1dZB+IE8
         bX4BKjOt0jbIhGRCX3HvU1IQzAm1vyLtSaECO8Uja82lNGHibAHTkd+dO6Ot0ziqeWwb
         0WZpB8/e7noY/cZ3P2e2Ik+SOU6+3E7UpRMojBHUfqQUuxGcmrDs1mgLA6ljUyrE9KLc
         9nP7FhKU8MU7Ki2auinqs0imyx9xl2xMg3bgw1M8pNv+ow2cZrCBnUSj1oo91WB+QUjV
         OwRUkBhzty8rEbfZSCk4gZMPMC0FL21RIsXSvEtyLN5R41yi9oIiGf0JnXKob7uyFJZt
         NVbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VWm2iwcQ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id l16si408343wrz.7.2022.02.08.03.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 03:45:48 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id m4so51552007ejb.9
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 03:45:48 -0800 (PST)
X-Received: by 2002:a17:907:961b:: with SMTP id gb27mr3185433ejc.444.1644320748441;
        Tue, 08 Feb 2022 03:45:48 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:5d0f:d242:ddbf:a8a6])
        by smtp.gmail.com with ESMTPSA id y2sm4151902edt.54.2022.02.08.03.45.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Feb 2022 03:45:48 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v4 5/6] mctp: test: Use NULL macros
Date: Tue,  8 Feb 2022 12:45:40 +0100
Message-Id: <20220208114541.2046909-5-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220208114541.2046909-1-ribalda@chromium.org>
References: <20220208114541.2046909-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=VWm2iwcQ;       spf=pass
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

Replace the PTR_EQ NULL checks wit the NULL macros. More idiomatic and
specific.

Reviewed-by: Daniel Latypov <dlatypov@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220208114541.2046909-5-ribalda%40chromium.org.
