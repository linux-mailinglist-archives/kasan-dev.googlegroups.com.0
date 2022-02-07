Return-Path: <kasan-dev+bncBDHK3V5WYIERBKEBQ2IAMGQE6PJWLKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 748BF4ACA62
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:27:21 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 184-20020a2e05c1000000b0023a30a97e36sf4915138ljf.14
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:27:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265641; cv=pass;
        d=google.com; s=arc-20160816;
        b=T6vxFD31Q/Jff1GiyHnwFYGq8DuwOr0rpYaoc7ooS6rrhAtQcM5Uhy3YGIquBDq53k
         vIZN/z4T5GImaNralnDf5xjm37oxDpZG8eoBlUX19fy8yDqIPRTvLbYKLZIIVJTH7Hdf
         TdgfQX1phtyc2xQ2IYSb0osOyUnLtoLI/POjzTooEakOOrkq4daA2zRZU9fVZ/5WX+vn
         QUPJNNy9z84wzPNPcT9vM5Agn/uNOhA93O0AGTYOBEL97p2vWy97/OY2YQwYvB6C31RH
         E46cToFfHIJQzJffUoZdOdiVxUkldd5vhjwBhPc+klCe+n0qObAEpVfy7Jf7AnGaDmMJ
         lZ3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PM9IotOiBZ5wyVuEnuZwR7nj2lym9gkm/DPUtrvpm8A=;
        b=Y0TqhoPXDV7QQn1NdUWXBjH+dTlZAyVJxMjFao0szoR9uAcoFObLLOdsPmDHI1dSrB
         Qh7VfRfA5Bu/s5m6bVLaKDeg/31j3PasDDyMECXIfFMwu3qwh/kQTp5+Sh8QGiZu+VY3
         mAkvgwRv8dZwcLK4djzdky6ciGzQ27uPesl2HuBMCFjiBVfAXyFgvCoHjzrHVWNu5W+F
         u/Yh4v/4am+I5TtRb2eN1YsXsBl79Mo2j2+LsQqD15+1k6GNP5kzaMRrpNIx1JqGGvMm
         XOloNGQXMnEc9DyFRD9D9WIX3ftVad5sjaQkQOojN4eI53Didtik5cnLPS1jPam+KzVK
         1UvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jaLc531L;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PM9IotOiBZ5wyVuEnuZwR7nj2lym9gkm/DPUtrvpm8A=;
        b=AkeXcU/cCSnyu4UQyjUxUsbDOz/c9UUmFYzhcSQAO9/RKtsonDd6ktadTqGEqNdSFg
         bwNtBlsdaCFJURCyp9r3y2uFzWkM5a37+zha1TpBHXji5RTQC1ddbGVJWS6+iRYFt+ja
         oqCAwphZs3/Or39UVeHui9PlQ453Y0wrk6L7m+o/OyubwPCtDN4nNApN0zNKKdtCuWn2
         UeV8M6dmzNBZfzfj6w19KAkj+s/SKh3crndp7CHkMM+lCHxZCWckaLUmqptO251txNFN
         MzbR0QlqLZXRm5qP0q3awStG2tI9wErkym1w368jZ1MpUlE9TAGlZ+cpUpBntyZU96jD
         tFZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PM9IotOiBZ5wyVuEnuZwR7nj2lym9gkm/DPUtrvpm8A=;
        b=W8aB8FVrN9DU6U3Yf3a5o7TsccJA5gMqnkEg1EYe4aJy7SyYfd4TTq6lemw1ond9rM
         20o6Ur+k1koArmAF44cN4b87Vhaq4FY0WzGg/SEUtUkbtpwQtwOgTMVtsK1S2pWeEwSN
         pvzs1ru5gwVenxeLLLPwcJRKfF+OQ12JTtJXt6VDtyOY8V9BBcarSe2pNf50zBd6545d
         Ul7xfHwwLYR4PhuGRqN2lkS3Tv9JPUCCMu9JAJZvb8+V9+n36rK2rF2Zv0Y70oxYLaaO
         L1bM3rnuCYwJ+vcQHsNtsQ1MsGrtYE6K98cCT5p3v5hmNsYkasEMJx7nY8qqf4hWtCh4
         WB5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IdQy9G05KteskrKelfND3TU0JV9Gt+JFlOF8kWEioLghqaZQz
	SvFx7dZftNCBMbGQfxmuvuQ=
X-Google-Smtp-Source: ABdhPJyGG/0oby9BPaSZ/0sVwAYvVrm0FdKlSNRt/d5QSKD2GWB3yEuRyG8KL8XN9lMM/NJ3aDgZeQ==
X-Received: by 2002:a2e:b042:: with SMTP id d2mr711602ljl.147.1644265641046;
        Mon, 07 Feb 2022 12:27:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:198d:: with SMTP id bx13ls1587754ljb.2.gmail; Mon,
 07 Feb 2022 12:27:19 -0800 (PST)
X-Received: by 2002:a2e:5d3:: with SMTP id 202mr734298ljf.330.1644265639896;
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265639; cv=none;
        d=google.com; s=arc-20160816;
        b=nK8Sl8X58p+6wswXLsTu7Xyg00I53RkmyiDg/XmHqjDZyaqIh/1al0MSBUEbVr46ke
         OCwBqZGnyl60FffxiLOixOxVP6rluLcUGydizZGVaLixOTt+PiYcl4z5pqx7DPRMXgYP
         fShmnYGellMw/4q60PN7pwKcEhm0WKYevO8YSnuWeV8QO3ZGsHAgncw0cIvKiDOzGH2H
         QyDPQOg2Jxako6pFuZVTo7xzUIZNHTsVtcNgWhTXJQpmxlnn91XaJBBzg4mBnhIAuyUQ
         xwKKhnX6IDSEGTUNx7tx+9YLTMd02U2gQkE8jaUt3Lq65IPaNlDcrrQJdz1pxdTQbyWu
         iClg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sQV3FF5mFgBVe7Tg/aDZitfy1ByGgWInZOonbxaNvNg=;
        b=Globz+9Vzqifs3LdY8pq4GJ0QhH0Ipmn7nwnWVQ2WoRnEDgpT8AbB4zbS4nFrMsBNb
         Emb74CyqwqRnbZ+ESBcwig4qXLO2twmusCVWNt5SGpD3r0F/ag+9urOsEBcP0cnsz1Rq
         K7uY5597Oa56xwk60A4umblRVA1jJK0Syws6hGnobbkkgZcU62klejaOKIBorYIFuKkS
         8JoKrjRQz19e+6gtyqOZUEX0CHKjNLFlhDqzxlJPiJI7g1HG4fvIr+DwXqbbHMiiiIX8
         26Xb5jfFiLdzBjEb0TNt2vZu2gel1FvY2gzllIHTSsR7JyJbAWuTflSW3fKAi5j9AB51
         ATqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jaLc531L;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id k18si348962lfe.8.2022.02.07.12.27.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id bx2so16374060edb.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:27:19 -0800 (PST)
X-Received: by 2002:a05:6402:2022:: with SMTP id ay2mr1198884edb.273.1644265639653;
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id t8sm787893eji.94.2022.02.07.12.27.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 12:27:19 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v2 6/6] apparmor: test: Use NULL macros
Date: Mon,  7 Feb 2022 21:27:14 +0100
Message-Id: <20220207202714.1890024-6-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207202714.1890024-1-ribalda@chromium.org>
References: <20220207202714.1890024-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=jaLc531L;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c
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

Replace the PTR_EQ NULL checks with the more idiomatic and specific NULL
macros.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 security/apparmor/policy_unpack_test.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/security/apparmor/policy_unpack_test.c b/security/apparmor/policy_unpack_test.c
index 533137f45361..5c18d2f19862 100644
--- a/security/apparmor/policy_unpack_test.c
+++ b/security/apparmor/policy_unpack_test.c
@@ -313,7 +313,7 @@ static void policy_unpack_test_unpack_strdup_out_of_bounds(struct kunit *test)
 	size = unpack_strdup(puf->e, &string, TEST_STRING_NAME);
 
 	KUNIT_EXPECT_EQ(test, size, 0);
-	KUNIT_EXPECT_PTR_EQ(test, string, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, string);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);
 }
 
@@ -409,7 +409,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_1(
 	size = unpack_u16_chunk(puf->e, &chunk);
 
 	KUNIT_EXPECT_EQ(test, size, (size_t)0);
-	KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, chunk);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->end - 1);
 }
 
@@ -431,7 +431,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_2(
 	size = unpack_u16_chunk(puf->e, &chunk);
 
 	KUNIT_EXPECT_EQ(test, size, (size_t)0);
-	KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, chunk);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->start + TEST_U16_OFFSET);
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207202714.1890024-6-ribalda%40chromium.org.
