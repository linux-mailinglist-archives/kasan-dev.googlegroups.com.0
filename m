Return-Path: <kasan-dev+bncBDHK3V5WYIERBFUWQ2IAMGQED74SJCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20EEA4ACAF8
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:11:51 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 130-20020a1c0288000000b0037bc5cbd027sf146830wmc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:11:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644268311; cv=pass;
        d=google.com; s=arc-20160816;
        b=eZzNmFOIFwYq7noV+Bvpi3eSvujSkZh//kyCb8k4mDbdhTf2RR23VROOoaJchJP68m
         QPkqo/wtKudwRmOSRXiRKXs/30Nl2eWLB0mRfiW+dvMNujKqqCoNA/nasrKiiXfRlH3A
         NnK+ZR3I94AaWSlg/koVJnSSAKCJL+oiE9ven0offDO2r89cBs6ZNNSpGkZsVbqwzBfS
         J8K1uLZqvnq/ge7LOzo/2IX1ZR3QyBx0jrP93ID1BUiv0xe6A7DD2ZRoH/8jL4oB9jy5
         z9kLUcHfgjxD6ImSosReErk4TI+4Vzw8q7UgFxve/TjM6EQ6JD6/YJgoKs/tHUyqXvvB
         RPHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tSdDn79B95A8Ay4v6Rp8FUx8f/4JF5XpsdnZgI2uXdM=;
        b=jZw1g/pnbKOclLktdSiyOL++YYlP46w2bNT04/HZv2HORfxwI9xI080XeL1XVavCD6
         lBctqqTUizDPfOSfBRvnamVNh16fZjLh3Q2oAhToR9eMCCzL5YAY5sd1u8qABSQoJ+8b
         oMu6Q53Ntw26AdK/qD7uciUfSF4BC9L8/M+t3R7dbu3FW8I1CsEH6OkijZlfgajS3Q35
         cPogUz/1wkTFg3PU3eL2lbsAkIMH25RUEwmwlIVkG49OdH4eszO5j3Wr9zzf2A7+ORK5
         qzLKOfFHk0OKZ2C427OFD0xDB9fYX9PIr6LQB4CTQS+AlOdqAIwGQ6nnLN/n6+a1j91C
         rnnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lWY1yE5w;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tSdDn79B95A8Ay4v6Rp8FUx8f/4JF5XpsdnZgI2uXdM=;
        b=brzjBnazRZ7VK7Pz4v7ViuQkNDph+IJ8xHTK89TlnOuJciyLKSPRCcfZaRaeXOJIYA
         vPu0suNV/t8w2MLOAdIY39wAg7IjA8TS0CcM9ak4eX5R3bIvfmfKgBAdtb50lHf9joDh
         3Ca5j7I+kaElZClRMPTpmsH/B6z4m6rMy0EocLvt0DCR4ARMZazkww6c9rfmkvUNNqeG
         nKvqDUnrlRwFruUTAyZpupB1s9UDgxMPpHG2cseMfBUHVUxRQ33cAP6fuMs+j4aYzump
         6md8UZ859A9ikWmPuACQZpI0FQj9Njvtj2Bprr6jJ7E1eJrRzrEfgtQazjNIVXNfiIUE
         xrow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tSdDn79B95A8Ay4v6Rp8FUx8f/4JF5XpsdnZgI2uXdM=;
        b=7HcJdfTwWMkK7XSZUDtwPxin+tNnlugVhi4OpV4g9jKyFkoZpdEuf15f+I8jUs7U9I
         meBOU5el25GMI/xnS/ssWtcpOMzT8/uUB5EXFRsi6wrMO+DmL6+Tnbji9JL69r+U0QUE
         7DTODd+1ttUyXzNfbctA30eLPja3rWihfhJtyGufxOJ4bwIH+xZkS5jziXaiMxzVxqzr
         0l8wo+XQV8dbtf7KN2o5h3IV9clHMZ4ruMhdE5djxsMbejUMuFh2Y55n+csWAMJJtg+d
         mPpKVqyNZsAbacPk3P8+DyVX+UKI/cFbEvQvj3I1dQwUpTOtMt0riuDmS/rVC2QLblhI
         vNqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AcgKYJJqNHqc4IPtVd9pizczYjQzGtWtAceXUX1NnRRWqgT1X
	DmL9maakBikEmFP9cmKkB9Y=
X-Google-Smtp-Source: ABdhPJxA+T8uACw4Er1L78M9ynCs1BTqJtg3qQFSeq2xdaby+BnOvqblcsR3usK4SXS/m8V0zuooWg==
X-Received: by 2002:a5d:6d09:: with SMTP id e9mr1036388wrq.253.1644268310745;
        Mon, 07 Feb 2022 13:11:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c20:: with SMTP id j32ls200186wms.1.gmail; Mon, 07
 Feb 2022 13:11:49 -0800 (PST)
X-Received: by 2002:a05:600c:4ed3:: with SMTP id g19mr612069wmq.186.1644268309771;
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644268309; cv=none;
        d=google.com; s=arc-20160816;
        b=synu5KSQ4Kn5BLlv60dHWAYhSdfcqp4WLPOks63ww3Urs1HnzmISfndEOp/tsGb1b0
         s5wm9lGjrKguJ4UeikVHwl7Jf3d4FvDP4/7omzYthtFsPW5CKidQqDqnocZThG6Jf16W
         6IJIVomoRZOtDs7cO2rZWK5+faKhdXG/WPLkxqGxh0NOuJ6uRBSuNzNyePrDHAW1mDva
         9WSdHvNCk9Qub2lPk5UXgEJGuYMyMFe5QVNK6wgD8G/x3IoksuNuI9ZDGbknnUqAo8nn
         npmlkz2Oi7gUwzdL9gd1tPxadaeS2uDtbh9nwYaXSOYfg1UuupOZEocOmvra4NxHT+Qv
         i1gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=COoBb1joui25djaKHvMRbQv4Mt4Thb8VpuVozeRERCg=;
        b=cwqmmtKtuggaOuc+ilAQk5xffj84DVg8O8zpBjqYUCM45V/Zy79A0GcE7qq6004vLR
         JZNxlPTJ1FoMopn+JS8XYGMcwuRrowVyYw3GiQOZ6qraj4Gy8iLt45Tzc8PDXv+DaFmw
         1Clh5l0s1h/9MXWjFOPfhcHCMXRlbHY6G7rTcQ00Eph+bb2YWbw5TK5ubnnWoe9Zz4JJ
         twGN6tMt8ePHXcJ7ybFtoXgFTVO90QhKTAJcRv0m4FnsAlSTM2JrZtFQHk2u7odGVRiV
         XjqlbdIlbeIoC0D2C0LVJnY8NnuVM5dHkx/hoW90BFlgC095IIP6+P5/hLwBgwb9UF3I
         b89A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lWY1yE5w;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ay37si22379wmb.2.2022.02.07.13.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id cn6so10236842edb.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:11:49 -0800 (PST)
X-Received: by 2002:a05:6402:1651:: with SMTP id s17mr1370551edx.0.1644268309509;
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id z4sm4047239ejd.39.2022.02.07.13.11.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v3 5/6] mctp: test: Use NULL macros
Date: Mon,  7 Feb 2022 22:11:43 +0100
Message-Id: <20220207211144.1948690-5-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207211144.1948690-1-ribalda@chromium.org>
References: <20220207211144.1948690-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lWY1yE5w;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207211144.1948690-5-ribalda%40chromium.org.
