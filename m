Return-Path: <kasan-dev+bncBAABBNFK2CFAMGQEOLFDJUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B0A0341BFD8
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 09:26:44 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id f11-20020adfc98b000000b0015fedc2a8d4sf330475wrh.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 00:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632900404; cv=pass;
        d=google.com; s=arc-20160816;
        b=hqm2XK8IRY79Deb7Ax8XTFQ9luzrHoMPtwycdyATTYTts8c+y7w1fPVz2nVSE4ffAT
         DJpqWmYAN0SUJnheqByYzZPLvdUr/pBb7yquuakyYpMB82Ll6nV0gPjUEtoYGiITutUH
         ZAirT7IesX9+gmSW1ERfj2hNJitmXNzCt84wE0O653KoR1uT9FTguOf1rotivYzIRKxL
         7mMYV5r/3NakqiCb8xbcteb8+lUm+OBBmiQ0pEyOnzYNM0E/6zi4SMNdnUP+aiLuQZ6R
         UcRX4zOBUCcpMkJN+9AYdspNfTu8cP9yfAinl35VrYZgmSfJJR7kri6yP1Nk1kunuTYY
         AVAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9l5QRK85b+x0FsyWxPEOocce1Y++lbe9/xyoEGufGtA=;
        b=wgR2+adcUyjw+tqGmcpPD1BbhqBoWOmo/2s1OEJTv4Hu8BfyYLA5pI6YskZMZNRr3j
         Jv5c85PUx2ZQW/Df3JxSsSzDKZm0YT+BOX9SltAVbi9Yf9v4uQK1QlYWiW34ulM+1uZ3
         72pkINpM5c6elc0Frcyi0ko7hj9x44NoZCUbnHCZhHRPG76nHu3A54T8g3TtVOJNa230
         VpqlsAwqfqwQuwpALlkqRTKqRbw27ou6uDC6e8eZamoh6wcOYepmVjLdZfSNhTZL7ujG
         OtBSyRmy0mtLYK/IR3oeZ5J51KqrpepVwo8MfFYCCyQsaBqH/F74WaoiaiPwVHawlLdp
         M4QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=fail (google.com: domain of yanjun.zhu@linux.dev does not designate 134.134.136.126 as permitted sender) smtp.mailfrom=yanjun.zhu@linux.dev;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9l5QRK85b+x0FsyWxPEOocce1Y++lbe9/xyoEGufGtA=;
        b=DhEuPPBvEsPNfwjHTUE6AovXV1r10JOiKSbvw4e3yiQo9EX6gBL8DEB8149rVFfKEc
         lFT1KWVW/wEQcYtAMeqjzgQoEJN8v02jmJPsdyaNf/gY7WgR1vXN9rTXmymmMkCDG02e
         nWnWgZ7ZNjigJSKYNS02QYFj0mXjbQL88vvd70qTX/iL5uUipXszELHoMjZro1Zqwok9
         8IFANQUGXj88Q7PW5ERc8vBZ46TRiP0DTEuJv7qHA9jfM+9d+bKc+WZCoexeYp0sxLoA
         waUb0Dk9dVFVySItsrGC6s1ifM+qOdJCem/b6Ac8BD8d2MbmMWwutoU+xt5X1y827IXA
         IBRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9l5QRK85b+x0FsyWxPEOocce1Y++lbe9/xyoEGufGtA=;
        b=WviI2n1k+icEXgEEu0kqXYK2kAsBQ/eKg+8CqYrO51hKcv0xXGnsQCSt05nx2jUaXK
         3y814wXes3o7ThSZ5axf7gp6UbeE5WRh7H7mbqnUpAUMgGIty8HGYsMf4tzgoSnMXwbf
         MBxB15v149KjOCir8tosPn+Cx0HmfQ9OX5gMrdZngGpTzf4jfJREpHSODFbDoZNUYCCY
         qieyPHcXPnhPtMW5ZNWpw5/OtIA9Gv188WABr8ztwQlAb1HCRY69mFWikrimbz1BpGJh
         ArpQJc5/P5ainc7xa90J86O2lkbkZO65neNRo9noYg9kIADxg8c5JEnalB8J7s9HmIcN
         9LQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QW3X9q2sscG88aRZtEIX4HrWwsso7edMIpQXTXyrUfgqMgP4i
	KTDh5jX8cfkmC9GApC6FsDE=
X-Google-Smtp-Source: ABdhPJzr+3garOYSTQ2kKZSnF3D4QAhYVfCsoZEcImQUV03Y0PcTFqSsUrzcYMvbP9PnS29u05LMNA==
X-Received: by 2002:adf:e643:: with SMTP id b3mr5035230wrn.67.1632900404457;
        Wed, 29 Sep 2021 00:26:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b92:: with SMTP id o18ls1683273wra.0.gmail; Wed, 29 Sep
 2021 00:26:43 -0700 (PDT)
X-Received: by 2002:adf:d1c8:: with SMTP id b8mr1092976wrd.104.1632900403734;
        Wed, 29 Sep 2021 00:26:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632900403; cv=none;
        d=google.com; s=arc-20160816;
        b=EWyECQog2ZjN0C6u5AE9DOorDkQRXvYiSChM0zWmdTkQ1VzdNTY7i0FZnVhM2DRQUY
         jqdAvMEgwvxz2WzlRpkA2l5Atsyu/FydsX5Iov2pexQnlpDzv0kAp8L/YTJx9oNx0rh5
         k0H4BujsamheZ8BSf20D9PP/SOB7u8aDFK5cLYTnb3JRCdnaABdVlXkXD8tjrbZQvKRL
         NLp+SmnMic1NYpEyJsM/b4ssb5QXhiXaqV4+9eDjiV3/Af/Ox9TivmcGa/Rmdm6cAaR6
         36QpkHt43vNCg3nNa0e9tFOxl2Zwuge9sRJSBz1m8VOuv2htttPYc/BvJSDRe+KnnbFU
         EegQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=4kIrlSGa7ZdJmDoL1vBCrY8vjWdmqFqj4K6IUVi4d+E=;
        b=GpTnj68Hj+8rJHVJ71IJkmhkuMWnAv0f6lcj8iHsaN7jXXQyTx27selHCarNeI0XsA
         BPP9PKiYyUF1FRe8NsH+uUmhi2hjejJEpqe6B4EB09z0s2dYDtnaq+1q5xLFDJI/57m6
         fwOdhDR6xgRiQVOSd8nMJKNheDqJktR8khXMG4mF+3rRNM0kYLAf+YZ3wTWJpSzz8edK
         xlSuvSP2W/W90dEpuAEyVvB0mwUEmeKb9WFFQ2o3kekY4RU1+dur79BedwYxgZO6H3lk
         tvAfEOBHrXezQSm9WiGouahFyRousT6qvVyQ4K71kMAICgHiyr/iV57bAr+Q3w2GOFs5
         sQVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=fail (google.com: domain of yanjun.zhu@linux.dev does not designate 134.134.136.126 as permitted sender) smtp.mailfrom=yanjun.zhu@linux.dev;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id s127si112681wme.2.2021.09.29.00.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Sep 2021 00:26:43 -0700 (PDT)
Received-SPF: fail (google.com: domain of yanjun.zhu@linux.dev does not designate 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6200,9189,10121"; a="211964220"
X-IronPort-AV: E=Sophos;i="5.85,331,1624345200"; 
   d="scan'208";a="211964220"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Sep 2021 00:26:30 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.85,331,1624345200"; 
   d="scan'208";a="554522886"
Received: from unknown (HELO intel-173.bj.intel.com) ([10.238.154.173])
  by FMSMGA003.fm.intel.com with ESMTP; 29 Sep 2021 00:26:28 -0700
From: yanjun.zhu@linux.dev
To: ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Zhu Yanjun <yanjun.zhu@linux.dev>
Subject: [PATCH 1/1] mm/kasan: avoid export __kasan_kmalloc
Date: Wed, 29 Sep 2021 19:49:29 -0400
Message-Id: <20210929234929.857611-1-yanjun.zhu@linux.dev>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: yanjun.zhu@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       spf=fail
 (google.com: domain of yanjun.zhu@linux.dev does not designate
 134.134.136.126 as permitted sender) smtp.mailfrom=yanjun.zhu@linux.dev;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Zhu Yanjun <yanjun.zhu@linux.dev>

Since the function __kasan_kmalloc is only used in kasan module,
remove EXPORT_SYMBOL to this function.

Signed-off-by: Zhu Yanjun <yanjun.zhu@linux.dev>
---
 mm/kasan/common.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2baf121fb8c5..714535291ec6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -521,7 +521,6 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
 {
 	return ____kasan_kmalloc(cache, object, size, flags);
 }
-EXPORT_SYMBOL(__kasan_kmalloc);
 
 void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 						gfp_t flags)
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929234929.857611-1-yanjun.zhu%40linux.dev.
