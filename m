Return-Path: <kasan-dev+bncBC5JXFXXVEGRBV5SSWPAMGQEE5YZUEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FF6C66C0BD
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 15:04:08 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id jg2-20020a170907970200b0086ee94381fbsf2860700ejc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 06:04:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673877848; cv=pass;
        d=google.com; s=arc-20160816;
        b=SXCDysTK3zisBhY348v4yUOMSL9YuVyCVSOMwoO1B+eLDY8liD2Dx/NRf6HrCQ1DzW
         PThp/s22mzfuHdVLE/gTCrbWDZ6oXL0iOyKCV/AL2kAhKWjG7+BnK/LI6yVd9WZtYLrd
         vJ0C+ZHNHcuaofMkNVrDwlQD34U5A0/iNL7W+bss2xQuCw1JYRg0TUx6nTFtJtZ1l0Sq
         ZNIQJQkuVxHRFpaxGFjnOgEuH3KoqKpB4TG02TFHpJR4lQe/xHvgcxelkHqzbE3JDtIg
         9r7kIaHGZdYzkWHbQ4KQCzi8U5LEw3R0Nj1Ra86ZaacNnFfnht3HOu4x/tTjor8y/OAv
         +UvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CaX+P3eMm4V2yjQSxoW0GyUwfN491pq24qGuHCDYdH0=;
        b=FlqFRmHfuUqsk0sw/pvbBWk1HPbPBZjyHnudTLqgqHcSbvdOtkBfMcBvz9OMfEuur5
         o2KMfrXhNWp96V72/PyfFUsOQXzjTqTk7Plv2E+CI9elAwzeWZBkd2ziniILl50r6Utp
         mhwrSe7ahXaoDdWACA4jY8yPmwcK4K9e07YFmjI6ZyVexQdK4qP/0gVn1X7o8fWbxYpN
         VNd9sPAlvbqRI/Y5VSVBYKwirc96CQEByl+sFD9PfshjQlQbL64yF9Px2Vdu9Uw0X2LJ
         52RdqPVNTiCfBrthxZyS7EWU3EsGaCGi/tIWnpaSZRcyqo4PJPnSpSvUT/rgOr9MFEmx
         vfuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cAYoxC/d";
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CaX+P3eMm4V2yjQSxoW0GyUwfN491pq24qGuHCDYdH0=;
        b=aOlakQSTHHmjIZ5LJdkqOv++VcMok0EcJlzKa2EG0aSrnmFZA86eXyCX6JSzoyyoxY
         yT4qgxrAquQO1cM/eLzyz2Pe4QI7UiaBb4OuSn6gLzjZ4hsFtmQ1atEKn1KzZykVk6Jj
         Nc7RY3+jlpuNVRDEHEd2mvfv82PFXFo11pNy0EvEzkZEvHYiOkIq/xAKNfDPUp+Fzns0
         xr7Fqgbhi9Idw7KysMF1MlXWpeuZQlCnUgLdm+T0NbPxlrDVVdkOkHg7Q+ENOeHhTKXM
         Bqt6Sdfjjih7iwkkdAUzKSdsCTfMcxZ5h1S1pi0K364oUthCEZBrff0f1WfKz0ivL5ab
         O+6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CaX+P3eMm4V2yjQSxoW0GyUwfN491pq24qGuHCDYdH0=;
        b=raxbcFLGOzAnlCirdsilI6f0hVjG9k2h31V/bMh7b2ZFSRXCwt/74+U3xnD9KhzH0E
         JmXdLC3xaYT2oaeiAXGvZom64O5yBG93CpTjl7yEzCgA/KSO+qvMctvDVu8oH21G45jL
         qcVXWJm4Tw716jYV9dNHD3SzX2JVq2I+IA3korAinQ3EEjNDTBECWpIjDxQWZCHymP9M
         yHDSrkt2umILPOniskEO+oLVLD5JsTmoHzJVVSfhyno3G8re7E0bQ7KyUBYEXJnIF2P/
         QV8LEswW73UOnfr0Jln3Dg0XUZVWoLRsHhpqbrXILOhgu6bckcPhCTXFqX6cyLd9iEP1
         MCGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq7Zpwbm35UV74YfixA7BAW4Se22QP54iDLX4qkhLb5LtZWoIYR
	ITtFWUXASumXxh/rbKfrON0=
X-Google-Smtp-Source: AMrXdXsWQ2GpUDh8+90h8Yt4D4mkKV66c3cUxqHU3VGmkVymKSwcbFThOivUtav9Nm2DpL1fmoQ5YQ==
X-Received: by 2002:a17:906:48f:b0:870:c5e2:e9b0 with SMTP id f15-20020a170906048f00b00870c5e2e9b0mr274121eja.698.1673877848137;
        Mon, 16 Jan 2023 06:04:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520a:b0:43d:b3c4:cd21 with SMTP id
 s10-20020a056402520a00b0043db3c4cd21ls439041edd.2.-pod-prod-gmail; Mon, 16
 Jan 2023 06:04:06 -0800 (PST)
X-Received: by 2002:aa7:cd69:0:b0:499:bffb:7e58 with SMTP id ca9-20020aa7cd69000000b00499bffb7e58mr10260992edb.20.1673877846719;
        Mon, 16 Jan 2023 06:04:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673877846; cv=none;
        d=google.com; s=arc-20160816;
        b=HITfImLGjwKqRKxkSbDFoXsR4c9rPu79GqWnOyT5K6Y5fVOZAOoDDfII/CIUF6q8gd
         ZJt6PzH511UT7nYIyJl3uzUdmOpez/iDond9+kj200u3Ic0capF285qN3Za76R+GFXdc
         oCT7mBFydY4r1mlyNGkimx/ywkya/TZO1S9zXpz2isE0u21kntzhqM5wTBQLX+Ks8X10
         ChQO7J2lVu81C7spIQmy+d2fj1eTWJQ5YFs6nd7H2okQA1FyqsECi2FRa0RsjPdTEwEM
         jyX6JhpHVCTAXpVkkR9Tbn+hMhCJjiZAEtU7pQjfBpkq+1maGWjGfHuaY5pX+BlOagy8
         S9VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ttnsOsbSVhRZjY+NiLGy1gxpRCePSleYFyj1Ag0UoZo=;
        b=LX86q7rEnuKsKOYv0GnVIrnN64LC2UQALBBmQqJ5bKSXBYjVx9CVIkrWpSpnoWHpvS
         wFYyhlx0JXptKOLm9ZKlUmy7R8kbQ8TClVtRwbnUjHhIkJ1PtzOz+XptOdNYCf5jNpau
         dtfIcWxmEPj1r2mlc1avfoCxrfgoohaz9fezs/qCEG+n6fQlNAQECpkJCekwUwsy/TMW
         351hkhmoZZ1HgDzBt8aXJVKDeiNxg/+x9kHJNdXYO5/L+3bO8jwucGcE10c/KkaOiR4c
         ZYINepJtKM6HvYH5JMXA8ipMiRGwY/o86OFX7xInpg8TKMG2TBdKbTJ9aXnZXiqAajZP
         cmdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cAYoxC/d";
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u9-20020aa7d889000000b0048ebe118a43si1284001edq.1.2023.01.16.06.04.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Jan 2023 06:04:06 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 73739B80F62;
	Mon, 16 Jan 2023 14:04:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 78EA9C433F0;
	Mon, 16 Jan 2023 14:04:04 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Max Filippov <jcmvbkbc@gmail.com>,
	Marco Elver <elver@google.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.15 03/24] kcsan: test: don't put the expect array on the stack
Date: Mon, 16 Jan 2023 09:03:38 -0500
Message-Id: <20230116140359.115716-3-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20230116140359.115716-1-sashal@kernel.org>
References: <20230116140359.115716-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="cAYoxC/d";       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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
 kernel/kcsan/kcsan_test.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dc55fd5a36fc..8b176aeab91b 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -151,7 +151,7 @@ static bool report_matches(const struct expect_report *r)
 	const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
 	bool ret = false;
 	unsigned long flags;
-	typeof(observed.lines) expect;
+	typeof(*observed.lines) *expect;
 	const char *end;
 	char *cur;
 	int i;
@@ -160,6 +160,10 @@ static bool report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
+	expect = kmalloc(sizeof(observed.lines), GFP_KERNEL);
+	if (WARN_ON(!expect))
+		return false;
+
 	/* Generate expected report contents. */
 
 	/* Title */
@@ -243,6 +247,7 @@ static bool report_matches(const struct expect_report *r)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230116140359.115716-3-sashal%40kernel.org.
