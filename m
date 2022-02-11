Return-Path: <kasan-dev+bncBDHK3V5WYIERBCVETKIAMGQED5F7QRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 790334B2AA9
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:42:50 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id r2-20020adfa142000000b001e176ac1ec3sf4071393wrr.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:42:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597770; cv=pass;
        d=google.com; s=arc-20160816;
        b=BlM9tQParniQWcozYpoVzeSWDOoSQlWuSMCQj9saT/zgm5lRGaNpYLlOVcEDeEkNnD
         0RO+i3bJzKxodqi2hbjC7omApKVTvh1eDWJQezNa/67a1OHJs3a20i4oiSuwRfkDupao
         5wqNlnAJxzJydee+rNvhk6Cxi6qvbwneTdi5H/w72yUPKWlg2kfvoXXGD9qiHqSFCLur
         Ah3KM1xS07ahoPqxScioC9hizjr5/0btU4uzwedVYMDpCWKifexyQZ4/OucfHGXEnTol
         1wHlVpU/MIijE1hm0H6hW7XNZAvLRCrhih7P+Z+hJZZotM2uNmIZny52ZEc3b7Clg/HT
         dmMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7bqMDdMF8NueQZKXLw6yez4Wj/701N5/xsHNtwWvNGk=;
        b=Vj/gmNvkVNm3TNaA3RdtBff9H/zY4miilISh6ogBuE6i+Wn/JjRddEDHiKm799tEp2
         cHYHB+7pL3CXPuoIlTlRvxVzE0gU2cdJuz5yd7emvhgH2KwCR3z4WO6mD+SSFFWu5T8D
         Azyz3yja0o8Z8yeJYP/DIbLTi1oE1ciJ6jcSZFljBSGbp/wTH8B3BTwBS4MUiA47tf4H
         jfu5do1rlEyko8UA8ZJA1Obsl5OeF6dxFbK/q3BXRYALBblgYsiQ2/Q3tDmFFVmoqYpQ
         jcmZAmlZq7WVsW7UaXQU54/eSlWtri8JlkqdGmRjmcgCd4DS3S+LQVgdJ92itlTsh5c6
         8sIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eJVH8qaw;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7bqMDdMF8NueQZKXLw6yez4Wj/701N5/xsHNtwWvNGk=;
        b=knJ8TCh7FszssWt33gQSjfv9LAyGC0x/LdLEcOy9PuiMO0iHZBGjP641hrabk3WRM2
         9b5YjFEed3OXjPCiAqbY0lv1YH+8ye0z+T/sKVjAhxKJaj0RPPQGl3pvCbSRCYpfii2w
         YdXG3kvHuuN/wHI3NTTDml2ByCQKFcwZMKl3CQP3xnLMVPTEefihR62iPBMMYn0j2mxo
         isVMPethWZvlYmGVKyCkFc8KVozKm2uwyz7OoQZwM//miC2tTrXG75MWMAAK02JnaIp3
         8XgmFBA5SVfXnyhICO/pKi51OGU4I4QKgj+6QiRWNEZyztHom4MCcAZkPdMVMHpB/a3K
         5LMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7bqMDdMF8NueQZKXLw6yez4Wj/701N5/xsHNtwWvNGk=;
        b=FumIjVIwBr1llZiQ1ka6JAcYDT1I5f9GQT8xJgj0AW/5X5sw9UYvr/C0PFm60/9n32
         /t8Abwq4XP8/duxZbj+dJQ/+oPKRiJU2R8Rk55PEkd1y6mEsjLlB00Rlm/XDu34E057k
         EAgG9WuVE24QTTAnKxlClf45hyoBXNuQNGl0oLCgaMeh0MaS7Qt2MuhVGG1RjJRUs/7q
         QqHuEHKiK2iP/7oWYtsLbm/ooqtxqcxWk6V1A7lTJB7rSIXyduUVf0ulUuFnuTzeGKAK
         OQswZyzvwrZqZdJiIOydYGpclvGNRzHlJcSQuwv/+c+CRXuykhBLIzrLeRnlpp2wXE71
         BGuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xWux+0gasP3uc4woJ4B8QcNb1VVXus8rbFI5Po8F+zpXL6CER
	4/cdgImrAdYVi6YwRfV5XXw=
X-Google-Smtp-Source: ABdhPJyHrbbQXD9pSGDTYeoOJhXl8o1QSlHagZaqUmBMF1M4SBHDEWQx3IqwwuoWE69KjzbAiFZVFg==
X-Received: by 2002:adf:dc44:: with SMTP id m4mr2018967wrj.355.1644597770176;
        Fri, 11 Feb 2022 08:42:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9f:: with SMTP id bg31ls2851523wmb.1.canary-gmail;
 Fri, 11 Feb 2022 08:42:49 -0800 (PST)
X-Received: by 2002:a5d:588e:: with SMTP id n14mr2159730wrf.45.1644597769297;
        Fri, 11 Feb 2022 08:42:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597769; cv=none;
        d=google.com; s=arc-20160816;
        b=EuSLdOuukXPwJqbXod90O3LT9FJSwAtXTXlvVZkzeT789P0Vdj0QpT4VSIw8UItyk7
         hwFsLqUBBGnR3CZDOzWX+pvhUH6P8G95PqsZebupNq+U4QQx+sTB3VMjJBNIbaqK5Zec
         YMsCIV7XeMFqj9MJzX/0QTkf3aRiiv7cXiG/I19eKfSAYoCiw1dX+4FY8uqArWm7Jtjc
         /f+IynBO2A41dSqVtfYnpINNStgg1l++F3msoxJo0lyvaiu01/KNiKHQFPRKgCleoJQ0
         O0F/2ajevNQQO9tyIWsBIo9t01iGx4iSD2HDu3w0KfzMsfN/YX9tq3JL7VlIPQ2tQdBD
         hAUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ne9bnxO4PK4jt9C/gSl+PDTM3EheSheXGE0rb10tDic=;
        b=KdnWv6lqVOGFoF/a1jgiFBT6ECpbxEk4N+/sPkSIklSUNPlQQyG/H+k3M2yoX9MbkB
         u8hnT8J83DuI/cYQ9GyeUp4mpWrv8qr5VCMntWpT/M54ptbcjJWQvQAnCoOn/lFx0WQ7
         HX4wh8yUskNa/9oq2xLbDNQ7ENbvTcZbntIXbM+U2qs0VEZ39Lpe3r3HPGFRjm6ttfnj
         Dv/IhiViKaFhS16gqE2995JURnFeSo3RfhJp0cn+Dnlujw+KJ9MQssQCFeVLz+0PdR5w
         XR2kDIBDWOE/MypGo1kkPvIpKg9RJ/iDABgUTqdrkH/MH4IaHgQt+IWQ1AlNjCi7+myh
         oRcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eJVH8qaw;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id h81si373146wmh.2.2022.02.11.08.42.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:42:49 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id y17so15420732edd.10
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:42:49 -0800 (PST)
X-Received: by 2002:a05:6402:34c7:: with SMTP id w7mr2808333edc.397.1644597769058;
        Fri, 11 Feb 2022 08:42:49 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id i24sm4981233edt.86.2022.02.11.08.42.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 08:42:48 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v6 2/6] kunit: use NULL macros
Date: Fri, 11 Feb 2022 17:42:42 +0100
Message-Id: <20220211164246.410079-2-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211164246.410079-1-ribalda@chromium.org>
References: <20220211164246.410079-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eJVH8qaw;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::530
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

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Reviewed-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/kunit/kunit-example-test.c | 2 ++
 lib/kunit/kunit-test.c         | 2 +-
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 4bbf37c04eba..91b1df7f59ed 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -91,6 +91,8 @@ static void example_all_expect_macros_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, test);
 	KUNIT_EXPECT_PTR_EQ(test, NULL, NULL);
 	KUNIT_EXPECT_PTR_NE(test, test, NULL);
+	KUNIT_EXPECT_NULL(test, NULL);
+	KUNIT_EXPECT_NOT_NULL(test, test);
 
 	/* String assertions */
 	KUNIT_EXPECT_STREQ(test, "hi", "hi");
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
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211164246.410079-2-ribalda%40chromium.org.
