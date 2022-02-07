Return-Path: <kasan-dev+bncBDHK3V5WYIERB2OLQWIAMGQE6NLAVSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id EFE3C4AC89C
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 19:33:13 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id dn20-20020a05640222f400b0040f8cdfb542sf860346edb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 10:33:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644258793; cv=pass;
        d=google.com; s=arc-20160816;
        b=JR9L395bNFX9bavfiiKhSAyQChgOzigbs4owxijLcB1mz2o1zAL1Qq7thXZ+fbz2Y8
         XN/N0fXyG2UJQ2RZrNTUZ9FWbxxdAhUq+YFfEr1fF+wDVaZUQCv3WAg4d9kSPPj4kffy
         kAN/wJSavEKCYaXOfHHTjh7ei3NVq+9BBjkrvlO7b+glGUhpK/xe2bVZ+ykPQb/pdqcC
         hReCQF4lH1YZM3fF4npzEkhnLaxgzc3uvUu9Pc6RLK6KzjHZjZWa8FxHQwvvkgWIFeWH
         c3jGhnVifIiJDY2keoRnySQUQMdAaV+gJki+SrHB4j0o8kreWoFV/JaBvlnFVD+YZyNH
         1BUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5tOqyf4t2K/1QpX5Hqtm3KHnPtH/U4JaUwQDZzaZCn0=;
        b=RxNVlKyDgWx9OgSxQQopT2WUgV+Mplttt5bMlt7w52PahYS8kpMpmlslu2fzzs15bU
         ZPGggpaCSvrStXOc131qJgqpETuiwJrT+IhpnL3EVhzl7Ia6O+wiarTwVmrZY31mJ2+f
         CcC5K/hm4R2SXWkxFCgad9OTBPxTy1ummIzexSCMaggZDQjl/bdwC+xR616U5DaWSff2
         n0fEk+clSODaLwIRZf8yGc1sXpFnosYUDVbvoAHiFkHhIzLO/tKKAxl5+HCsOc/kRRHa
         ehLtHXqLvAd9XAdikDNND8Fqk+VenqoMhz9DTcYixBYp12bi02LU6Gsu8qbAE0wv0AIH
         9Aeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Y04HjLPs;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5tOqyf4t2K/1QpX5Hqtm3KHnPtH/U4JaUwQDZzaZCn0=;
        b=JnGYKUVSLRQst7Q/Sklk6XBIoDqvqC4Bs99HWj3sFRn9WJH3qPcpOZaUEX4zquer0w
         3+4BtUdCblw0oeG6O3bR21HfP1DqMj99ZX3McS+aaJfnAqoQPJ6jgJro2ti1SJVjP49h
         9O5EBVJHHCrlVifW9bLJsHb/uqPXg4ocV9sMv4ZAvXHZjjQ6sTFevlVjjJB9EKMYlf9G
         3UAP7vD14fiPIy8MAkWQfa1dZPvW/FGZPwP/jrbcqUlLpTWVemlnpxyAsU/JqohxTwSe
         8ZdSVERp5AQFK3yLk8t8C2G7MbgmZouY3+hqgCn8Mc538wh44wkchkXfjww5CjvvcSEv
         jBxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5tOqyf4t2K/1QpX5Hqtm3KHnPtH/U4JaUwQDZzaZCn0=;
        b=ALnTe1QEE29N5zF62w67t1n8KZFtLGYVvLvipC2GGs8L2MPEcg7mFWYrLkHwrPX07m
         Jqi9QlekcRHUsk4zcrmjdDsP/EYQyFiL6jctvIhx9S05GvZxlxq4+D3HWUHKLu1aEJhA
         jY/LyynKo37KlDLIj1Te6wKvd9OfNZtTFXhqPC/2S/VfylJqAKbc7H/QaB+Ek554Hdtb
         bP8/iY932ZJKLD75eVRwUU/0gSI4bC8yehqGmk9Yp+An4a3r8gUinLNmNzxi8/4mzmXL
         HJLUG8QocpFzHoiw5w9xqWhSyVx+uZXCgDPCuvCToQk+2Ez38GJkq7usX8ZHC8f5f+OK
         KqPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532VcKxpksiY9THgdahl2VMC7nklZ9eV8GXcuUlvihU90JsJK+Fw
	RaSDWOaxCFobwJjdj13GVlQ=
X-Google-Smtp-Source: ABdhPJwkAMSgjJL60RJcZXazIpvFxngytl+7OYhiYJ1K/23erPyd8A4valnCpf7CiEFt0HjBkaVCHQ==
X-Received: by 2002:a17:906:99c5:: with SMTP id s5mr775196ejn.373.1644258793660;
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:d0b:: with SMTP id eb11ls2384860edb.1.gmail; Mon,
 07 Feb 2022 10:33:12 -0800 (PST)
X-Received: by 2002:a05:6402:84f:: with SMTP id b15mr811374edz.206.1644258792821;
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644258792; cv=none;
        d=google.com; s=arc-20160816;
        b=vmId2YlHWRxmGZFVy75pHrfbvmpuISay2hh1UI0JeO9S/Vv/Y5v8T4OMFbEUoNLCJn
         ERB3uVF7MmNBmIdy92KdZPjD9wQjmbPKkf7q22pJa9L2yi8BeUCV0lR9gICHXZ/O6i25
         72hRKtIqqlsGlYUcoqpafJd1OoMnOz68BN0pgqZDN8qdXtcX6hqzMxxJ377dsTlTYp9x
         FUmsABJzSIijdkFRhFEoE7sRmwXet80NtVcMDH8P3ly/5LQFuOZ8RuERaNfIGkeQF1C4
         X2okvj9UH2FQogkH2a2VASqDqiHIaHI3hinzKCbHE5VD+wyZfmS5FT/lnFAL6HkJka3y
         xSHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ssHaNiY3LReYl3MVuJ+ePd9JHdf9OG1Dd7zZJ3nge2k=;
        b=gHuU428F6yvB66uCMmYcuhSOmdi5KprOH4Lb1ZB0lkCR9SBDDvXV8bR3QBH4Okg1qr
         fCi3osikOvETyKRp/5D5/7Dwh/5MLk81FNftASaszzgTyfcyKSDqHwfUGRennnkYUaXz
         iSYv9XGCEcqpyQ4Z/V/96hp4CZvomEeZzMknz4EbRrGJHFil0vSHZKfsrhBMhCcS1dI7
         5EttAIa8OVmKpX5Z6LdVKw1uNpgFI8awVdQTfB3txsxLS0iIdvWv8AUpDjXomZAKTTcp
         UL15opSa1X7WGL7g9zE0HeeUiEcxOlyk+2MyXkw6QiUzncO1h9m1DMgXTb/hlDDUVECe
         xI4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Y04HjLPs;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id s15si421892eji.1.2022.02.07.10.33.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id da4so10044730edb.4
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 10:33:12 -0800 (PST)
X-Received: by 2002:aa7:c043:: with SMTP id k3mr790601edo.184.1644258792671;
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id k15sm3045173eji.64.2022.02.07.10.33.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH 3/6] kunit: use NULL macros
Date: Mon,  7 Feb 2022 19:33:05 +0100
Message-Id: <20220207183308.1829495-3-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
References: <20220207183308.1829495-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Y04HjLPs;       spf=pass
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

Replace the NULL checks with the more specific and idiomatic NULL macros.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/kunit/kunit-test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/kunit/kunit-test.c b/lib/kunit/kunit-test.c
index 555601d17f79..8e2fe083a549 100644
--- a/lib/kunit/kunit-test.c
+++ b/lib/kunit/kunit-test.c
@@ -435,7 +435,7 @@ static void kunit_log_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test,
 				     strstr(suite.log, "along with this."));
 #else
-	KUNIT_EXPECT_PTR_EQ(test, test->log, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, test->log);
 #endif
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207183308.1829495-3-ribalda%40chromium.org.
