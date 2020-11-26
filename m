Return-Path: <kasan-dev+bncBC6Z3ANQSIPBBAUG776QKGQECRAM7CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-f58.google.com (mail-qv1-f58.google.com [209.85.219.58])
	by mail.lfdr.de (Postfix) with ESMTPS id CFF282C57B8
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 16:00:19 +0100 (CET)
Received: by mail-qv1-f58.google.com with SMTP id e13sf1402257qvl.19
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 07:00:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606402818; cv=pass;
        d=google.com; s=arc-20160816;
        b=M3X4d4PdixaVUORBCcP8I2ISyBwRIKnVVjBpdVsSiIhrsZ/ERbzwhuV/vT/cRUup5M
         2VhVO05LWlO9a6Lz4Odmtuenad2xWL2ZcW+hs1+DAHNH4pzcavHKmIQlNfcu7uRzwGN7
         B220Bczin+FB+Xt8oorfg9ZfQ605YoxuupbFuyj5cqHdst6h2tcRRU0J9HiyV5ubpf4M
         LVdlh5b3OL45sJb7BuXw9CwItglYVxhRVn//rtc0nZ5Hp2H5REug2486upYisCkBDRzs
         MXvv08kBX8BPH05NRKcUt4pY5hiax8rIMKiFuVLMVRzOL4UGrvVLuy9CB2h57WDGc++Q
         MhsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:mime-version
         :subject:cc:to:from:sender;
        bh=mrk7kfyA81UFDX6HFGJjTk0X9je2G5jwTzr66KpFMB0=;
        b=s2cv4k3k4XCrShKKYSc9LYEQmLjfBWQ/TFohZnBbZ56Tfmg1KYoxv7UHbnml0Kty4r
         0dGRzm9qpPG1M0Hs9vjtFOqOCMpiQ+Cj325GGyS07bdmA6WRtWSVJW7vf4GORlyScTcV
         e726Vgoi6i91PprHqhQ/R4d9UOaLc6SWmGZ7glqbGP0XGQ/Z88YfVczy8mTvGBMY+IC8
         +eiNWEPuUNeUdP0hvAW9AU+gH7rgJW8GfUPG9MilhhJe+Twnh87oNz6yiheLb9ecifas
         6aPiAGWIWiPVDVPEFnTdXv3S+PO88aOXmXowRjZfPPOF4PjQqBy3AdYaHjg21t+OBZLt
         K+IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b=MsCriKm4;
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:to:cc:subject:mime-version:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mrk7kfyA81UFDX6HFGJjTk0X9je2G5jwTzr66KpFMB0=;
        b=pz6q/pFY9v9lf7M1SRccPg7vRUxbumTVp7lWTXkvI3fBMM1bk/AmkrxpoYImIvD5kR
         O22k2bQJ/mBSLH5vDWeS+vyBrED7vH+bi6dCpdgH9l5ywYdwV9yIzOdnzqIBXpXX8I6f
         mnsMMsN0ReXFDotzGpjm8KpIiEAtL0eThsYQ3eUGlJ4b7m16h3vj6OtaWDGI0trleX0d
         1gekpgZDVyhIg6misy+o05kYtME2HIY4j0SAvtoSBYalj4JwuPUqR6ZCloYRoLUwaUK0
         /uqgDESgo4QfqrybXtj3YH3flMdnji/pQ8Vkp6WGjFNvyWZxvsaCaggOgbvknShL+2JT
         2Xig==
X-Gm-Message-State: AOAM532SAny9Z0cWUpkheWTS3Cvf56RSYs0iXVT9m5pmLBPYw9RgZoJ/
	dSwzOcf0aMAnFVS+rSdhMz8=
X-Google-Smtp-Source: ABdhPJw9aO8O34HVpROmMSKd8/x7h89uCzjUKPCUBBCyq+P+9WOp4dny51/8J40n7o4QiAR5+Om3HQ==
X-Received: by 2002:ac8:5d53:: with SMTP id g19mr3507336qtx.354.1606402818332;
        Thu, 26 Nov 2020 07:00:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a2d1:: with SMTP id l200ls1166627qke.3.gmail; Thu, 26
 Nov 2020 07:00:17 -0800 (PST)
X-Received: by 2002:a37:44d6:: with SMTP id r205mr3594978qka.450.1606402817734;
        Thu, 26 Nov 2020 07:00:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606402817; cv=none;
        d=google.com; s=arc-20160816;
        b=s+Mt8oLTBokXEdMjo824kGYfhf7AnZ0fl2uulJxjc/xPF0cEEhB1Ie/oGW3B8oCcUj
         xgEY6TM4EbhnvqxjCQDjj0/u07b+ICCz5ZU7wp1WOATH6MtU9Ei2HuN32+cvr1F8Inwc
         vky0Kxyh0DDLLQ9cJy8EwS6VY72vbLLv0cpSdXNyhb1uB8EvGt0J+gBeTlqVan0HUy8I
         VMcN4+fd5AoGr7g0tRlmhpji9wz+Y5mS6KHP0WxjxHZTMAfdZbjI8GMxvtxMe0gqggBK
         H8NcDArGibVB5Y5oAT//PfhjZ7hmlnLQ6Ivqom81WB9jwlnhx2xEjYygeWpMgi2opTLW
         X+3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:mime-version:subject:cc:to:from:sender
         :dkim-signature;
        bh=qfMwSqnk0RUEJvnAIRSVXuZ7QDhIr4/4UMmKVwRvU1s=;
        b=Z6tEMdf6YRJHMTUJC4Q+aNs9JxJDsCTZr1rhUNZwa0hEKK/2oWEdk/a/hmr1cspvEn
         kOVJH3n1Z/4ttAEK4MHRv6ejwSk/0MMYy5bvldRFmbqvHsvqiH939b1aP2SOAeYib+6a
         5bc/Zwh3PCdNcPKpd+zjJo5ZwUOtk4wgNqV8D6E44fEfxU8SDE2Xf6rME7Dz/6B2O+h/
         M2u8Sav2Gh502KAguPC/CBBPdZs9x9yYH+dYGhoPRVg/R0isn6zgMjsSpFsNmlFxaIe+
         ds/VRlsU9KLcdCcJLHvb3v6u8j5ZzEYOYW7vVHAi55SnkbFu9uBT0BX5QiIkYkM+22zN
         5BsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b=MsCriKm4;
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id n20si100884qta.1.2020.11.26.07.00.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Nov 2020 07:00:17 -0800 (PST)
Received-SPF: pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id dm12so1037197qvb.3
        for <kasan-dev@googlegroups.com>; Thu, 26 Nov 2020 07:00:17 -0800 (PST)
X-Received: by 2002:a0c:fc52:: with SMTP id w18mr3578801qvp.48.1606402817425;
        Thu, 26 Nov 2020 07:00:17 -0800 (PST)
Received: from turing-police ([2601:5c0:c380:d61::359])
        by smtp.gmail.com with ESMTPSA id z20sm2978067qtb.31.2020.11.26.07.00.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Nov 2020 07:00:16 -0800 (PST)
Sender: Valdis Kletnieks <valdis@vt.edu>
From: "Valdis =?utf-8?Q?Kl=c4=93tnieks?=" <valdis.kletnieks@vt.edu>
X-Mailer: exmh version 2.9.0 11/07/2018 with nmh-1.7+dev
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>,
    Andrey Ryabinin <aryabinin@virtuozzo.com>
cc: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
    linux-kernel@vger.kernel.org
Subject: [PATCH] kasan, mm: fix build issue with asmlinkage
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Thu, 26 Nov 2020 10:00:15 -0500
Message-ID: <35126.1606402815@turing-police>
X-Original-Sender: valdis.kletnieks@vt.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b=MsCriKm4;
       spf=pass (google.com: domain of valdis@vt.edu designates
 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
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

commit 2df573d2ca4c1ce6ea33cb7849222f771e759211
Author: Andrey Konovalov <andreyknvl@google.com>
Date:   Tue Nov 24 16:45:08 2020 +1100

    kasan: shadow declarations only for software modes

introduces a build failure when it removed an include for linux/pgtable.h
It actually only needs linux/linkage.h

Test builds on both x86_64 and arm build cleanly

Fixes:   2df573d2ca4c ("kasan: shadow declarations only for software modes")
Signed-off-by: Valdis Kletnieks <valdis.kletnieks@vt.edu>

---
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 83860aa4e89c..5e0655fb2a6f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -12,6 +12,7 @@ struct task_struct;
 
 #ifdef CONFIG_KASAN
 
+#include <linux/linkage.h>
 #include <asm/kasan.h>
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35126.1606402815%40turing-police.
