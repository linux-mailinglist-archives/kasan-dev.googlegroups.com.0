Return-Path: <kasan-dev+bncBDHK3V5WYIERB2WLQWIAMGQE7GBPURI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 62EF64AC89E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 19:33:15 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id y19-20020a2e9793000000b0023f158d6cc0sf4819637lji.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 10:33:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644258795; cv=pass;
        d=google.com; s=arc-20160816;
        b=nfB5Xs+U/BEQ3pmUVgUDOedJy2MZ+E2ywT42DUl1E7B+H6qKudL1FOzTQi33vNdRAO
         Fmnhv9LqxZRJAtB2MNeTDgozuJ62XvIkLqIeZpOgewBF+wqU/bqgQRaUeB9OW6Oe2EJF
         l1gqUK7FyTx6Mp695Ed44D8z2D0dC6h85Sl0J4OZFEcsX+YyVfmp+KgaPZuGkOob6ZOy
         A4N6EibPSsNvdzeGQRy869+/Q3XV90aGiJS3QAQMMcDWsX9mZ8abo01LJb4X4BbsPwEL
         w6cCE1CnmjgU5Jl1hwpu9Bkpv58o5WOTHPoY5FPGLY/hFd3BCfiqxXPiXFc26lRqOmqj
         xd5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lJElTfpvsjT9mK8WTbvLrvdY+Uogq/UnnitC86K7Zwk=;
        b=IlaYcRaG6ARtwie9ScA62ZPMwUMnt+TKlbCNbrmaZ/u6P4frbv+6CMlylJ7wzhILe2
         yW6dhpzmbUVYX5ux12OrYv25IpKo9QC9DtGMi7sLFPCPCWKnlENlYu6cYjE/W/n8SBU9
         C095S2opRrA+OP8VK8SzsuAMSIlzXdf354beIcJMON9apoZErW+w4i35UAnxtnlm/tbm
         InByU9pXXKuDyDhzayZwrzoAJJMU+5h7r/4lAO+eKpyAGZSn+JX2DaCSYNgv66ugGqAn
         nk/QeOkW+XXy76GJRRFrdBn2HE9/iotR31QhcQNYVSjyngRimJB5QqvdVpe9RW8Zg3Um
         rYhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=LEDvpjbL;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lJElTfpvsjT9mK8WTbvLrvdY+Uogq/UnnitC86K7Zwk=;
        b=SVanwfbua5dIBs7gE65erG3nhUIHf0pibl0/XGg4zfT9ZWSmeHlgzunO1LpUlAcvkA
         hn1KzTgCRfHMgM7AXxY0G3jp4TbUuso3EDrhH6aIwLva8Kgr7nhqc/hMP0YnrmGUDlEe
         hltBdZ5JmORBF2yx506RJBXKVY7QM2lYZSEgR/n+rrdHdHRAY0PgTgA6nQxdc0+GgmBH
         rjm9UCo8mwlmLFsyaD5TQ0b9SBUjaKre9RklUckYF0pdAytULHgyCiCeWwloCz4yAidi
         GN6Zq6zQjzrwFzrngiPpTLZbP/o9Z2tolDEnRmAuKp3RMGn9/aefeEBWn6FPk600AzcP
         Ph9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lJElTfpvsjT9mK8WTbvLrvdY+Uogq/UnnitC86K7Zwk=;
        b=Rik2/3adBnNgnRKVNRhkx9gQlWdhMzyM9whTZ7w1h77v99L0V4kZwa5Nbkst4PPtHK
         fHXWFu5Yx5NJqkeOKmDTaSuQ5uEAXVDQROnyJp2k0jJVWIiE9l+y+KX/f9PyUAfG5Msv
         yMO9biM0XzpqjIt2vyx1Ba16GVL5JnbfrhWggKg1/5p+s2/bn3QGNiuV47DCw6Zynu63
         4X8xfxgHmAlve4b6vuLF+2x3m2lQk6KTgaIhak7IxiVnJCrVy+t9OdClKoQbS5t6i+5+
         rIHRNrWIkwiAaSyX9+FqZe1PQg345BVAsLQU1Xx8KBg6lHeutVpdjtA2LwixMX+2nLvN
         aXuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aC2fCDUY6wBNNUDJLAIg5FGuccopzq1M0xFmeTgIt80B+Kw2v
	Z2prGewkpNUjhUTyPWh2X9s=
X-Google-Smtp-Source: ABdhPJxvJTqENTPRCMaIJKD9sZYxosWTFUrrtV8ToKJUMPhxkVzrYzxZ91GuEUM3+6fOLNLHgx34OA==
X-Received: by 2002:a2e:9bd4:: with SMTP id w20mr484391ljj.324.1644258794962;
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:22d1:: with SMTP id g17ls6216321lfu.2.gmail; Mon,
 07 Feb 2022 10:33:14 -0800 (PST)
X-Received: by 2002:ac2:4f03:: with SMTP id k3mr530067lfr.127.1644258794029;
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644258794; cv=none;
        d=google.com; s=arc-20160816;
        b=hOfCfS80xyooeK29wSxzce9x7MXtiJAQ7V4fEOGJ9jN4ofLufHZWgbjxoNeyTHjKkE
         q6G9arUdE2qGcjk8W1yBF8M1H6rW85BcEHwYcPfxZuhMCpxraT/8YsmX65q35JcJVrVq
         ixnoN7meVBKHvp5r39AS1Zg+nQttGizROr05v+o+RKQTcTjzTHgiyA2lRW3EBFkSw5Cc
         G5Vmsr5YOTScjK7pZ9C8KFX73zkZdACPrw9X5HcWWLarN6/0nTtDSSpwTUWpDJaqV7+l
         jZfUEvSfJecHPUoDpBcyZ8HSXI5iO4kTuJarg11v1glTFYTMLEDldoTcevE/m2v9NkB/
         yYLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=COoBb1joui25djaKHvMRbQv4Mt4Thb8VpuVozeRERCg=;
        b=lEHo5kvXXPoT6QpRmwQpy59vFmOo6z7aLfe2gVL3GJjhRrArO/oZ2e5AxXggwGCG1x
         cSwIa/ftb4X8pul0UWI0+9yjOej92oyZnyHK+UmadOY+arFFsYCknRaiLXA1ep6Cq7rG
         uwfJHprLLrX3hk+meoVKzW0s6obqJBVF05f44kHI3WiAmAluScSwFaWvQpCUf8LobGIK
         Q3Du9lOY/kI7NjvluGimZ/JwjcnA0B8Yi/ql5tfuF9+Z/eXAhwM9JfsiNZt69JNUeMAv
         R3rIBRdyG0Svrj4fcYP1koAcVa5Dqm7INcm3Y3GTHme3RssSM1YAM68FE/+/hJbKDKE6
         WiJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=LEDvpjbL;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id l5si496881lfk.11.2022.02.07.10.33.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id b13so32041610edn.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 10:33:14 -0800 (PST)
X-Received: by 2002:a05:6402:2789:: with SMTP id b9mr784253ede.308.1644258793829;
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id k15sm3045173eji.64.2022.02.07.10.33.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH 5/6] mctp: test: Use NULL macros
Date: Mon,  7 Feb 2022 19:33:07 +0100
Message-Id: <20220207183308.1829495-5-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
References: <20220207183308.1829495-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=LEDvpjbL;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207183308.1829495-5-ribalda%40chromium.org.
