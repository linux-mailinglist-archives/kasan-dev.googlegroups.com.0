Return-Path: <kasan-dev+bncBDHK3V5WYIERBWW6TCIAMGQEZXGYP4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 97F434B2242
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 10:41:46 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id k5-20020a508ac5000000b00408dec8390asf4974765edk.13
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 01:41:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644572506; cv=pass;
        d=google.com; s=arc-20160816;
        b=I1Fi6/ldCEh8nId9rl9iIvEjvVdhk8YJESuTAgKcri5hP2zN9oXuNZ4gVnzp9D+pW3
         Q2OJEGYYwLhEHP17jdh8cmTK4XtNhZTieF6EyUtBt24XwBst+gH/iHVNhgWSS7+uYpsH
         HP/D/BLF2MbH8JiRE7VFbOQ8vrXOAwLz0SVi3HWIp5ZSv2ur+X0grB9yPhGYMRNKF0//
         9EUHqYwlPaHXVjwKp4fpQMFE9iKn/a3Ivc6RD/H9JaJ69CGMOjpfzivy0633+ivQ3FgM
         PMrMpFbsn+73M92d19eDtWtdfK1FSXmGdFqPmpAruH+nQ/HnWdpG9BkblBGE5YIIuHnN
         0jXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=37VYYtbsxV8qf7iuIcHG1/8XT84nccYJtXOiLMsgMs8=;
        b=ld479Hq4xMIfO8Zd228k1CObttvKXxGSclUrbPGdxgu3PZvwf4NZ70/AV6smgDMIx7
         HIv0FwiwZtCmIDhuaJa28a5xb/MydhcJX8+D9/2H2n2g9E0+kFVXCk4gbVViamH4NYww
         IaE+ykKmmLI8ujAyX53zsl33aZJvNQ//6h5ZH1IUmAH9ITOXNDF5FOastg6dtmpIQtQN
         XhmIjsyxwOre9duuabeRxhK/L1byOpRGFHc0oKy53ThJ1S+3qwtnvmC15JK0aIzfpnFW
         qixRE0iSAPNJevx6A2dGk1mtEsQSIhWccYztqnY77DSAQ4C+TMjXkTjtpMFthczSHc8Q
         Xj7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="VUF1ln/A";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=37VYYtbsxV8qf7iuIcHG1/8XT84nccYJtXOiLMsgMs8=;
        b=UlYes3riLSZkCsihAjOizl/rkXP6Qf9zJIakkOAqbw6N2jyiHg7/hWCZHGQ1ymFlvY
         LoDP3BOcJ3huIXGhYltL44+yCH/fX+pFOXKhv0QgV1isNlPk856tb5+NO3utu/iSRQGo
         Opro5LA9zaxW6P9OHNoZLEzHRkve92GO126sIAkcy3GkE89UMvI5pg8CumtUNhwYdIU1
         k2TsQcE/iRpHP04f/gTiTrA0PcGDcLD3UIcfXxgn9AY4KEGGjOvAlsjjCkGi7rLyCy7w
         50pfvMxfB/pTrK+7+9QAcg6FwxKnqtavYEbP/4MphVPGFOv4P2xlReRsEVcn3w5Yv4jO
         dZyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=37VYYtbsxV8qf7iuIcHG1/8XT84nccYJtXOiLMsgMs8=;
        b=UcQ7+ZBdUA/KTfPKxjjLmbtJKrSoZHAE4lHpLvpQL3bZLC7D+ELIcF8X05gPjIgXwt
         5QD6N/kxmZgJkZ5NtSwoH8o5HbarlIANKYAjLMkegSCK9g937CY65VbF9xZAPLjByaXq
         +t0p0t4XzMEXrugk7TeNltjQrM4V3MfwYBKUqYr8xnNVTqqUA2udNicAUOvbG5HPhBWR
         GLifb2AFOmSFmFf/A0Rm5m5nx7TZ7+SWJqfATHGZgZZkw3G0voEWI64/WrtvLn6T41CS
         Ch5QBIn0CtM0iumIUM0YiAGGF5WhxmTWB0hePwszTSfy+qztW0Ic8ak7iJgoY7AUqTt9
         FpuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iihMVF51JNn4vayueFpJnm2DFQkfqMjHU1o+JhI0Y3e595gDJ
	R73IR/lTkm8JwHz20hA0MAM=
X-Google-Smtp-Source: ABdhPJyeY5wu7Ai0ud8TeElhoYT28RRILfYD12P3qO3mmByPfucqq8oINiKsIYaDZV6KQgYqCqsepQ==
X-Received: by 2002:a17:907:94d4:: with SMTP id dn20mr674350ejc.208.1644572506280;
        Fri, 11 Feb 2022 01:41:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2547:: with SMTP id l7ls3455868edb.0.gmail; Fri, 11
 Feb 2022 01:41:45 -0800 (PST)
X-Received: by 2002:a50:fc86:: with SMTP id f6mr968748edq.176.1644572505349;
        Fri, 11 Feb 2022 01:41:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644572505; cv=none;
        d=google.com; s=arc-20160816;
        b=tvRh4Dn+ojs1RBz8lyWBxBPJORz6kdAxJlaMXYfoPnoZpZFpUlG7B42IHU/E+DPjJ9
         amtK4vptlh2sIRT8HzvORet6y1Y3NEBSXw3D+fImExaud/Hl/Y+MJVeu2mzk/ZeVh0Ew
         /ctbAoCFr5cjwdD/b6/3NxI1WdD+wqiywFrqpD1X6X35fytqpBZlksMoI67lH8eKLx5U
         zVuQMekkSogArCnfFISPOvf41jdBaUyRKKi7ZUDpmPXoleRVqbjm9iR8BJnYTUVEEvNl
         VbUmR4SR6or0zleTRX3oPOFDBkqgrvVhAGOuxuMogmXl932qjFhqtrtwkILiSKZiqpC1
         c91w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rByTC1qdfOpqKBTw6wu+dL30l5MNIQcmECFcqJUWyKk=;
        b=MOTRCvWm9ZYd9pDDzShnDjHxTJ8fX20EygPkYqlBDY1bj9QIEknG2mUEXtJpLqS0Bp
         WRH/XR0bHS0Y5tQ28rj+bWo4Oi0bCw9NjpgpddiAUGOvRq3vGS/dxmjSlNejXG5Oycvp
         yDnPMKPkcx9bOSLq3RcFsLfRZwWnknNZZS3akVKMV/w3hCT1xb4BPJIkGBsw7iVMpqcQ
         0H9tlDBUv9ZIlQEPFx8p+PYnm1VBFfXPYpXpafcPDCX1/oDSfwFfq8/l0WjpSrX4AeEJ
         cuVcaj+H7VFPj9k8RXqTqNjI+4Ej8dN4LCP6wmEFCjqfE68JdEWznXzyrsjigU/wi6DF
         djVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="VUF1ln/A";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id s15si991475eji.1.2022.02.11.01.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 01:41:45 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id f17so15636829edd.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 01:41:45 -0800 (PST)
X-Received: by 2002:a05:6402:14c5:: with SMTP id f5mr958178edx.122.1644572505144;
        Fri, 11 Feb 2022 01:41:45 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:83e3:abbd:d188:2cc5])
        by smtp.gmail.com with ESMTPSA id e8sm603196ejl.68.2022.02.11.01.41.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 01:41:44 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v5 5/6] mctp: test: Use NULL macros
Date: Fri, 11 Feb 2022 10:41:32 +0100
Message-Id: <20220211094133.265066-5-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211094133.265066-1-ribalda@chromium.org>
References: <20220211094133.265066-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="VUF1ln/A";       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::534
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211094133.265066-5-ribalda%40chromium.org.
