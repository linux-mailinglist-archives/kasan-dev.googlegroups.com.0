Return-Path: <kasan-dev+bncBDX4HWEMTEBRB55T4GAAMGQEKW3T3RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 68D8030B09B
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:51 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id q11sf8799741ejd.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208631; cv=pass;
        d=google.com; s=arc-20160816;
        b=yy4lfpX465WNV0PwihJwRLQEMi7Dv8flXLP4Izs6i7P+MvAtLpkeQdsMB3PM5rAlvc
         pThdq3VvYd2xAiSHrVsKC5q4Kr+RjKhOuGTwQEaMTF9LA+58BMyBrn0UpFZeQOLMO7YW
         UieCYBqx7NKpnbeyZndiGN8HKq0dtt1Zlkn6Dg94RyALEOYBz9O/Kr9D3JqADhBGIiB7
         UrgSUc3ZrT9TPWU/Ndjp5z/F67XW8kmWiNHFuq5QVEX8LliYxmSi9LsolZu4yu6hYGod
         1mtzLF1dOE1AQZYAsmLE0xvxb58xR4PlVnG7Ki/EhUdOqS5bKiiJdnMmmcP4bWcm000N
         BkIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=gH5Z0kVzGVqjn7Ht0iTN1YU4h+fRq3np2fE/PgiK5sY=;
        b=wqRxfB/0+LMTZ3Z6ocrDK/lXdHHYG64QLjLkyOTk2rsMUV3te9UzYpJRB+ASf0cglc
         IakNB6yup4Th7ROghVcZ3fIEn2MhVzWIdOvZcM/MCumvHzJi14mxFqYS3fFtEnrEi7Mh
         4RH2mjoDBjMGUf+VuGhSng4JpwQGzVRcMXs34hG6g5wd09AzHbdDKGOss15cLKyNVqJD
         /am7XkwZvr5l/dadrYvPgwN8mBCgpqJFReoyyIovhKqbn2YQlmhzajd9q1tm0jyPnKHo
         ffg6nL5/dMgmNPP9xFMdo/RilWnai//gdPfKhKxN0xU4+kS7ypvxC2Z5NlA78q2i7f+s
         2hjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Phj+HIZS;
       spf=pass (google.com: domain of 39vkyyaokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=39VkYYAoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gH5Z0kVzGVqjn7Ht0iTN1YU4h+fRq3np2fE/PgiK5sY=;
        b=rsN9OYX0wf2i3UFhxRJ1DCyj2+725sKy100nwT1CCw/4za82Dupm1BQkdiE+WtsPg4
         dkzXlOxdipvhwwfJ6k4Sx4Ca3bjMR/aMTYdBQyWv90KSwcGS7xqpJQ+cXjgl3hsTS+mD
         INxIjWrRWHfbADJyabucSGJ2cFiVSOTruKzIwB+zfgSFXKM+5olI+KtFUpNuJI7Q4Htp
         1TYhP0Di+7+7w+YKA/1JM1O+7F8muljl7wkQTt4gi5XzOQStWESw06jjeXzu5lyOrXH4
         ZR4WXNbZ19bd6ahe7NfOZDQZWPCYRJjRJuRiii+bQo6tJ1IoVss7PlTosIAuZMkUtZz4
         msKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gH5Z0kVzGVqjn7Ht0iTN1YU4h+fRq3np2fE/PgiK5sY=;
        b=klqv8rsNzB0qJOEhTe2ZKuTz0QD7NAo9UUFrnxMdAX1pAd/sSdSCyMbdKh65xe9hSe
         0ZaLX6G0w5xam/MYlIzARLdjH+MS9uG8qJEPldrEk4KW0m3wLO+3yjXbfp6s44bYTOcS
         ywwiw6xwfP7mAb1Zv3hJds83KlSNvAtuc74Y7v7IgwyN1NEh36/howZgqYRALwnZiOfY
         KebYssbJ7mg9R2UjLfp+p+dxYpRchM6SmhRaJRSJ1I3njgOxTWKovPB6bAHQ1xLRWgZi
         x+jfRbZSV3GMUpBazjIn2vmYQPjd0CbXvOlbpWi+qENZyyjVaUegHtGrbj8c8xYn8RPJ
         OWPg==
X-Gm-Message-State: AOAM530MYXxUN7maGocR9986v9eqsw54vpOzjnuFfTg4Azhvn5dD+iWz
	HLXWOTWCND6vh3OSnjMW/Wc=
X-Google-Smtp-Source: ABdhPJzA0gmRR3+rWSuUfTmAFMAys13zkhZxq7h1T+9EUFMrLFz67GOnJ49SfOdl1MN//00/2HIvgA==
X-Received: by 2002:a17:906:11d3:: with SMTP id o19mr19807904eja.256.1612208631205;
        Mon, 01 Feb 2021 11:43:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls3403708edx.0.gmail; Mon,
 01 Feb 2021 11:43:50 -0800 (PST)
X-Received: by 2002:a05:6402:151:: with SMTP id s17mr19947941edu.107.1612208630444;
        Mon, 01 Feb 2021 11:43:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208630; cv=none;
        d=google.com; s=arc-20160816;
        b=sJkVHABxa63ZfR/jItGRFfHKdisQLEIT3IJWxspfsw/EdK5oVACyWuXqo/O+p35KC2
         bhZ4vGas8S90zHnA+N7MKpm1ZDkKOHzwDL9NDp/XvMI0QmWnwHhA88cNzAPzWjydLLMp
         QpybAkVBV8btBiJg5WWyBu9My5mf7F/4hmBYbUaqShfOiHsp+kPtJOC8DAtYU6H581ye
         cj+dOD+NHOBcEho5sGYKTaHAPEHSPdRyc+Pw4DV9C2kkrceOZyzGttuHLyTSGb8UUtRB
         EJA7ofXkM/GhrgbkcDM78qo+msgYU6ElEX0sYkDiBtnHNPdgwQ7DNTn72suGFAm2MIp0
         +RwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=vdSQ7N299ttJfkAji9JrIXHPqKuzBqRIB40yh5wvGsM=;
        b=WqaRHY+VU0zRsDuTf+vTfjsWjk7pWeI7UA7saDUKrVZi2eEJNsyusC09ediXOuLZkw
         4jvNbbQZimqGwtxnQ9mgV3JYN+Ci5w5M4gk8AwOvWt4UujXZRRtnltjK7e6YPhF7OYvp
         GUBA06JCLUz33ZkbeJy8aLkpmI0moZVXgEbqwp7lknJSz/DtSNMlWo7Lbk+asAgZwBRo
         4wbN8vVF/+XIvGAjSzpjGpTWYHF4si/iRnnHnKSiI+Vw8nTtENFlhpU9NrVLBAAqSjt6
         uhGocXP/IV3CevcvvQrf+cRJ7JEF6HCvhVmXzwnzEaQshVbj/bwkTvCN64Vf3pI5Xgy4
         04qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Phj+HIZS;
       spf=pass (google.com: domain of 39vkyyaokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=39VkYYAoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x14a.google.com (mail-lf1-x14a.google.com. [2a00:1450:4864:20::14a])
        by gmr-mx.google.com with ESMTPS id m5si718003edr.1.2021.02.01.11.43.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 39vkyyaokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) client-ip=2a00:1450:4864:20::14a;
Received: by mail-lf1-x14a.google.com with SMTP id v25so3150288lfp.18
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ac2:44b8:: with SMTP id
 c24mr9569637lfm.155.1612208629709; Mon, 01 Feb 2021 11:43:49 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:28 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <e762958db74587308514341a18622ff350a75d8a.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 04/12] kasan: clean up setting free info in kasan_slab_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Phj+HIZS;       spf=pass
 (google.com: domain of 39vkyyaokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=39VkYYAoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Put kasan_stack_collection_enabled() check and kasan_set_free_info()
calls next to each other.

The way this was previously implemented was a minor optimization that
relied of the the fact that kasan_stack_collection_enabled() is always
true for generic KASAN. The confusion that this brings outweights saving
a few instructions.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a7eb553c8e91..086bb77292b6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -350,13 +350,11 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_poison(object, cache->object_size, KASAN_KMALLOC_FREE);
 
-	if (!kasan_stack_collection_enabled())
-		return false;
-
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
 
-	kasan_set_free_info(cache, object, tag);
+	if (kasan_stack_collection_enabled())
+		kasan_set_free_info(cache, object, tag);
 
 	return kasan_quarantine_put(cache, object);
 }
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e762958db74587308514341a18622ff350a75d8a.1612208222.git.andreyknvl%40google.com.
