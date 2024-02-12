Return-Path: <kasan-dev+bncBCXO5E6EQQFBBA74U6XAMGQEBWWRE6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CE4D8511F5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 12:16:21 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2190667f9bcsf3259460fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 03:16:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707736580; cv=pass;
        d=google.com; s=arc-20160816;
        b=pENYAd692sXNHcP6ETvRcHHhJSeoJTQq024h8rOBAv/OW81IXiz0TBmQqA0t2uv3Jq
         Kvs01hfKNt0DOoUo/UhbEJtJxi97f2HfcjGAJC8qltqaBbRu9Li0w8gAX6/gv1Rl8tQd
         TjGLbRbVmzJrZ19X35WgZY7vpmAOsahW+aqLIhsq2AAlp61TabOueGoz3sroaOmTUz6r
         6fDx3E3UraxIDYln6chgQ7Y4Ocaq/7xpyY9wP8Zuj0miSU4mzl25tHhY4DMq2HWdpQa4
         vjMRBU3conrSj9picvquxKuvQWUR94FRPNF699kdBxlbT30q/JFZh/frDzPaPIoEYiN/
         IEwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=MI9fcn//GAyBg3idDctgjRtwmehWKfArKaf/0oqS/cs=;
        fh=rZaMSN9N+PrbnGXk9K781KydqggFI1bLQCbJUTakQFo=;
        b=pR93SXhutNNs6fpkMxkGJEI9V56aYjhl270JebFBpPCaoJxS6Qfdqk2kmbQrFNh579
         JojVldogdrRw4+4WdnfJart/r/HM+SC0MY1+TT11yVgmjydSvve16ISGwT0af1nPWFx8
         im+sG9BBmw3pAlTMFe8TKCWth1bzMTfRp1O1ALaYyklT80++qF+31zxFVH+S4TFt+NKl
         4VxR55fRUhbn/xpSuGqj43FUNzQ340/Oo/vaVO7y5n4Sx0xLAoSplzu8FHvjKtg7rpmv
         af7+Gy1cBrVKOvh5X77QWQZygwqktD3WsnD6IdL8ZTl4KwZWbyKBwgDNwyu7Vv7roudA
         Hvcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Uat5jhPa;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707736580; x=1708341380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MI9fcn//GAyBg3idDctgjRtwmehWKfArKaf/0oqS/cs=;
        b=KTOj2hL4gdw+JjvqybEIJluBh1OFxsSF+BUX8XrmjbyPxPo1m3dakEbb49SnWtxJT7
         +Ya9ZjSdaEMYPzCBScwYZUEMfJezRikPywvnX6lR9q5OY+AuOYN3OULs0FpuSt1Sl5vR
         hAMwqGz30PcqNFhihzLUA2VagwVjJRbA8M6TwlBsx7PqAbktHBP4vdo971tJb+Z4GzCZ
         KFcZyrpXaUE/3yfcF7GeuIgSfVzpgpEm++NKLAJdr7Wwzc2FdyUnAqvceAvEE33u2B87
         HdYKgq6b+8QCS48OaDp+IxGz7XY7iwxqo3wznzwuW0h+2rVKnud2tKa/BtBTZ+clolSU
         ccSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707736580; x=1708341380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MI9fcn//GAyBg3idDctgjRtwmehWKfArKaf/0oqS/cs=;
        b=ksA+KQQhKGuhr59JfyOfPrDXu8QXrRKFLVEYP5Me0ng/ILeWK96TDqw1xNpMJwga5f
         6qvffxcAE5muzWA98X2ZptKL3G7xLuuChSh3sU3Jjd/+bjifOoSdgt9LiMobPzJOj0t4
         EmbmT8AWqK1CfUfXnS5I0sqrNTrfAPbrwUMsXbwvHwyfVm0KFMq7036K+/ZR86TKinXq
         Gsr1ZfzFxIHguqKzRZVfbkeTb2fqghl/mXW/0fy0rZaeN4/mmSE0vPOSKxtCasYXjSMA
         9AadJqziy3CH0KZ8BnvU+xKFNaetiZ+PK6zyskRmCcNYoWO489gbQfbjNmpxzhyQN+zM
         8rQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzmzWrohzuVLwQ8kBGaZTJBqsbbY37ovwdRTVqIcblHx282e7fb
	F1LKqEpk9IK6V7xy+cxs1ixVZpS5VAJOD4BXAMsvb36RBoNFcL2F
X-Google-Smtp-Source: AGHT+IFlwedFCbQW7MTg0m4Av3snYVNWoy8bqU5hvjwCIa4apXiangfu80OiyRllSDKNXk3R3P83Lg==
X-Received: by 2002:a05:6871:3a1f:b0:219:700b:cb2c with SMTP id pu31-20020a0568713a1f00b00219700bcb2cmr8096672oac.55.1707736579836;
        Mon, 12 Feb 2024 03:16:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4d18:b0:21a:7f05:b413 with SMTP id
 pn24-20020a0568704d1800b0021a7f05b413ls7003oab.1.-pod-prod-04-us; Mon, 12 Feb
 2024 03:16:19 -0800 (PST)
X-Received: by 2002:a05:6870:468a:b0:21a:2691:12cf with SMTP id a10-20020a056870468a00b0021a269112cfmr8757071oap.19.1707736578957;
        Mon, 12 Feb 2024 03:16:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707736578; cv=none;
        d=google.com; s=arc-20160816;
        b=WB7IQ0DES5PB7cz5Yam5fPVj0GEVlL1UhhdLOqWv7obu5r2x4JOZGiEYn87syuzoRF
         Y1AFrkZaFHTZe7H+Hb99Rus54A4zYbhROYfELhNbQJY3PhYvf0K7FZ/UE9iWNH6aCLEN
         N3BjtxY7In6SpBVd4JjfIg62FBQ8Is2jj8FfPZLVL430DKMzfkG6eC+9LAI1DbKgO7sK
         vJaOi1LaCvabdqvWjZn7/P8WK4xoOdPuvZTBtoKQq9gnrg7sxsvLXGu0VgfD3uTjtwUP
         QJTX528P8D9/0iLyJVDSAVzlwkSs0+Qe6JuaQX4aLzvq1457P1ZuadOz3bQEa1QnsK0J
         Tdew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CamwcnDtE7Zyewx1uYQjtN0DOfd5vYuD5XVgyaMVNbU=;
        fh=rZaMSN9N+PrbnGXk9K781KydqggFI1bLQCbJUTakQFo=;
        b=WqfZ9C8GJTEZ+yEZGs+LVNrdJnfmmIKmIQNomoREjXKgwDVpgJaSIxvqW2YX3EOAsS
         yQRXsSU7aR2+i8o4lH7C4Yp8cHUwrPMI+j7AWJzz7F3DcuNttqlfpuwn812f/D5ES8IT
         gwpftti+l05ZQuVWXdGZrHdFtREihdk9V84vlmykquaE9Q8oeH/CNMiXToCSlALZea1B
         RFexkYMlICRBijndjYKfBOrfr/ZQmd8oQgjDZ3HC9+6LhkrWlIsgyvSb1jb5z0dAAsZN
         gDLPRcCBWuR4kspSYFXs2Ayet935wN5hlIqReAImPjihiIrxhBAQ44+3SCzWulRnAtIc
         OsUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Uat5jhPa;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCWQjTX7l3JWtUHRyFxUDJuGP3v3IVjDqE6WeEaw4Ho4b7bkzWvwWA3AW+dw88Y7MqDi5zVB6F7nLXbNRuz18EOhVDp/y3tGksJcGg==
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id he22-20020a056870799600b0021a0d307f23si566778oab.3.2024.02.12.03.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 03:16:18 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 7B56FCE1152;
	Mon, 12 Feb 2024 11:16:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C9ADC433C7;
	Mon, 12 Feb 2024 11:16:12 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <adech.fo@gmail.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan/test: avoid gcc warning for intentional overflow
Date: Mon, 12 Feb 2024 12:15:52 +0100
Message-Id: <20240212111609.869266-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Uat5jhPa;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

From: Arnd Bergmann <arnd@arndb.de>

The out-of-bounds test allocates an object that is three bytes too
short in order to validate the bounds checking. Starting with gcc-14,
this causes a compile-time warning as gcc has grown smart enough to
understand the sizeof() logic:

mm/kasan/kasan_test.c: In function 'kmalloc_oob_16':
mm/kasan/kasan_test.c:443:14: error: allocation of insufficient size '13' for type 'struct <anonymous>' with size '16' [-Werror=alloc-size]
  443 |         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
      |              ^

Hide the actual computation behind a RELOC_HIDE() that ensures
the compiler misses the intentional bug.

Fixes: 3f15801cdc23 ("lib: add kasan test module")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/kasan_test.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 318d9cec111a..2d8ae4fbe63b 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -440,7 +440,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	/* This test is specifically crafted for the generic mode. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
-	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
+	/* RELOC_HIDE to prevent gcc from warning about short alloc */
+	ptr1 = RELOC_HIDE(kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL), 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212111609.869266-1-arnd%40kernel.org.
