Return-Path: <kasan-dev+bncBC5JXFXXVEGRBCNTSWPAMGQEA33HNTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 58C8B66C0D3
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 15:04:58 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id x7-20020ac24887000000b004cb10694f9bsf10410522lfc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 06:04:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673877898; cv=pass;
        d=google.com; s=arc-20160816;
        b=inPLYp7kVJK/vWc01J4LMPdCadktQFuGLsaqFcO+8ARDod5D6dkmr4RiAZf8bZqXd3
         +bWdAvmvmJIrYkeMlI7PbePq9P77lMH3/Ua7oJSDC24rFBiVHauNkSXeZQn+1hXDiYw6
         RNGHpPWyajSrEZkEVswc8JESUC3UTsXLYyNZCVJb+YtZvkDHhqez9J92Fa1n8/DnOzXA
         TQlJyJMOPynQbZkWSE+wqYwoxl9MwLzGRZJLxe8hZFPBJD+ldXY/OdbdKZL7AKx1b9VT
         MRyBSNGITpwl+7chPX+K87hZDJw68NZtU3FuZH6s829yG1ocXLbrUen3ff4r3Z/P3Bxp
         uXaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=k/3Uv4N2R+MpDa1kQvqXRjjsdGhf6ngDx6YDrUqDr70=;
        b=t0QaDN90oUqtNYTNyLi23Vsoc4SuzRHFzGZ2wPT7wdU7n8ywvv6FxUx9haSpdShKe+
         o8VgTuBmgcv66gzcLlVFfWskkmx0XoM9fuvEJ7XtW1e94g9DIm6wG8HSQ6r2PMYF1wL+
         xgGyru1H9CP84EkXXVsuxfKCv1M7gtlALOglpFHKlOnL5lNdmgAaKd07M1kiu8WDJWpV
         lFyr9BuTj9wUNaC3FUNPeeYuGYV0P9/13X9KAUru1wIjkgvXshkD3hJeSAu7QnlJMI49
         6Ing3vMypm/p6qJROolnPSsBiGR0KqBbGpM4gIApjzSwN3qMRpT9hYZsdhXgdhKeBisF
         cX7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QuL4XYmU;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k/3Uv4N2R+MpDa1kQvqXRjjsdGhf6ngDx6YDrUqDr70=;
        b=j5G+yRPRhdIwu2Dq/nBgnB7tiU6GUTmLls/rAIL351jT5WKfvjio5YgkzcDIfUpQ8b
         SSXZBeiXco3e8/Bbwb1rOMp1ZV4IXTNQauL6O420eq/yW7f1kjEWwPKIv3JlOvmHYN8c
         +Ukl3o0RHyahPFiQVqgI724qQ4cvlD00OpgKJS5QqESgiJPEcsUg3xmYgXIBpHR4C4vT
         zJgfhgFsiYOUm7HaYUr4fYI9fZyboau3q7mn3oBJtHnVROdwGMQVWslkUntWBrpvlcVT
         954rF6vKXHkdew70gyn3SUMtdoEVrTnQWRWHLicXM5n4tzyiCPF9BHT2pnrzh5HVc0BK
         FP4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k/3Uv4N2R+MpDa1kQvqXRjjsdGhf6ngDx6YDrUqDr70=;
        b=ea/7dZANQLDaNTG9fbbCuumdq0/I1PbYLOZfIsPTL7x7/6KvdEYPD1tizZDHD2Wtnm
         1QVktbdhPwJ/+8z3qr1PBPZ4o/0RwiT/6MoJwjn7S5VC4pvnBXej/ypTPpWXMofNUjKi
         TOFrgduDSlTIuEF0Rce5Mi9eoNMc2pGvxwsQ98ZLLumCNcZVMtW/ps6+9Yxr/00BJGT6
         ug+Uq8023E+Mi4iFNuQGX1yWeyGYjQ+IJxAJ3ZQzIoo7BQgAifHBGi7uswGpd3ZsKA+0
         ve8nM8lj/CnKkaYQjT5T+3ZmzUedzmqWXJuMu3mGvzbCbvWdzTDh7GnW+x9bhQIrawwq
         /BKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpxlaEnapTLbqINIV1RSvouqB9hkWk+P3E5xlTxPBxMvN2ghmki
	CTyz7R4F1dTA1AZ3PoJtw70=
X-Google-Smtp-Source: AMrXdXuV74arU3Y6AfQA4K7ej4PI08FwM57MqRXV/GbyMua7oFSXbI4zg06GtYHIiwxxfw+8QcF2Bw==
X-Received: by 2002:a05:6512:689:b0:4b5:8c94:dbd0 with SMTP id t9-20020a056512068900b004b58c94dbd0mr5023041lfe.523.1673877897682;
        Mon, 16 Jan 2023 06:04:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1018025lfr.3.-pod-prod-gmail; Mon, 16
 Jan 2023 06:04:56 -0800 (PST)
X-Received: by 2002:a05:6512:2390:b0:4b5:649a:9105 with SMTP id c16-20020a056512239000b004b5649a9105mr32646231lfv.65.1673877896138;
        Mon, 16 Jan 2023 06:04:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673877896; cv=none;
        d=google.com; s=arc-20160816;
        b=aW7URqdTy8Sab/lol3exW07DRefktQvXwPrZbf9CZFGViufrKfTLulgKseVH2KmRoP
         MznCMEokAEzz+tgz0M72Cu0ij/xLhDE1GYSET51r+T63MEgU+UItJMcj4kSgcRzVzYoS
         3V3a9U1c0xpeHyPvjEbewD6mQ3Hf0FO9cGSJDusQGzA4aYCVY1hKI/QBSJ9anYdBoc1x
         6Y7pKesdmb+xMQNrRwXcCNIHLtzyGJjENaYHakaU7Z3bfT/SoHaF0J1MHewxVkD/KMif
         G/kncSnONbI8XbASvuX2OmsTQK0j35OIxqiozeC97mFu+9Js71tAW7l21mGdHDTcQu7V
         trPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uK09Y32rCZQZyhYZiOoIBv1MyR85yJcZuZahsOXopeE=;
        b=aokKrWPY5Z1R12ZkNfZ9UkaQs+MAD3hOOsECGORmSqw+www1j7ZxM038RndvHVjbCD
         cAAh0f5bp2tDUQIDq3E6QTcsv4ZgZidOtzi8CJz8ekN/mqwNVbrXyr/wlHpxNtyrri4l
         vijsMpRpV/fd3/3h3OiUGp0sEdDHqS1QsdCxB7VW1J3euek4Lvm5B4ewHUcJRUHjxvnX
         nTAfGff+9d34/ls1HqL8jEbZ1ux5TuDtrpKFEhf78/lgmCbvWHZp7Of8JljfCsksRJMa
         0J7OzvhoC21WmIvYXN4Tk7uBf8+bExgnrqnhYlOjXsrwcqI/JKm3yeEIpwsgkZJD0xN1
         u4jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QuL4XYmU;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id m3-20020a056512114300b004d57ca1c967si76568lfg.0.2023.01.16.06.04.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Jan 2023 06:04:56 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B475DB80F9E;
	Mon, 16 Jan 2023 14:04:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A7E25C433F0;
	Mon, 16 Jan 2023 14:04:53 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Max Filippov <jcmvbkbc@gmail.com>,
	Marco Elver <elver@google.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.10 03/17] kcsan: test: don't put the expect array on the stack
Date: Mon, 16 Jan 2023 09:04:34 -0500
Message-Id: <20230116140448.116034-3-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20230116140448.116034-1-sashal@kernel.org>
References: <20230116140448.116034-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QuL4XYmU;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Max Filippov <jcmvbkbc@gmail.com>

[ Upstream commit 5b24ac2dfd3eb3e36f794af3aa7f2828b19035bd ]

Size of the 'expect' array in the __report_matches is 1536 bytes, which
is exactly the default frame size warning limit of the xtensa
architecture.
As a result allmodconfig xtensa kernel builds with the gcc that does not
support the compiler plugins (which otherwise would push the said
warning limit to 2K) fail with the following message:

  kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
    is larger than 1536 bytes

Fix it by dynamically allocating the 'expect' array.

Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/kcsan/kcsan-test.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index ebe7fd245104..8a8ccaf4f38f 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -149,7 +149,7 @@ static bool report_matches(const struct expect_report *r)
 	const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
 	bool ret = false;
 	unsigned long flags;
-	typeof(observed.lines) expect;
+	typeof(*observed.lines) *expect;
 	const char *end;
 	char *cur;
 	int i;
@@ -158,6 +158,10 @@ static bool report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
+	expect = kmalloc(sizeof(observed.lines), GFP_KERNEL);
+	if (WARN_ON(!expect))
+		return false;
+
 	/* Generate expected report contents. */
 
 	/* Title */
@@ -241,6 +245,7 @@ static bool report_matches(const struct expect_report *r)
 		strstr(observed.lines[2], expect[1])));
 out:
 	spin_unlock_irqrestore(&observed.lock, flags);
+	kfree(expect);
 	return ret;
 }
 
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230116140448.116034-3-sashal%40kernel.org.
