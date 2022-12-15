Return-Path: <kasan-dev+bncBCXO5E6EQQFBBPMX5WOAMGQEKWGSFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0808164DEAA
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 17:30:56 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id v16-20020a62a510000000b005745a58c197sf6388568pfm.23
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 08:30:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671121854; cv=pass;
        d=google.com; s=arc-20160816;
        b=GEboAVJ1HZ0snFuIlIyum3NXN0W3TxFjyGjPm44WB868l8HO/G3prXcBGOl0+Bef/4
         vACg7NAI1re4ACWuKTr0bEbPCVp6FsY37Qvw/M6NbuTO9mmyIrWFee9cHPed9JVyMMvJ
         EWl1EX++1HiAptLaek13bBsf42qMRA1eHsXsWrB5oEbyJeE3K74/7vDqvtlUMQav0+tg
         rMELRIJgeXUwBubpQUAqToSi+ayqHE74K8mZBiR6I9wKtJkDzAaWa4j70G+3WzxOSZGP
         xu7RH5Q0zgqYlkr9Mh0/drWV7zNz+VFdbRLgy3yO/44UR1fIO+Z3K8g/tGG8GLdMvYS/
         wy2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7n0ufVWZ7YpzzWVSum1l/x6uTbqx/mWRRE+nD6hv/hU=;
        b=TeWZBZT5e5zXmxJh2tjd9BM2WWWUyYIowMxOznXTxZJ+lZOkFWlJOUf6L071rJh2jv
         ypGNjnMXa5vOHLHMqt5Abx8hVtu4uOoE+yWF6KBylmilaMR3soWiS1R7o/6JeUIKOkiV
         uVbdu8PiMHpTd981VMGAo4311trhRDFmZjOYHh23QmvT5niDL26Yz2pMKd2XTwq/o6kz
         SxOFNsZbdHBpF+WPZ97j1AS+dzPhE/USR/nA+IYyIV6BZGbhMm/xhw/3KSQ4yvg1yp70
         8Oz/AUPZ9hfWwb+KdYvcquc8MwuC2kXhCuzHbL8c63xql0DbK6JgqotCc0FJxapq3Qkc
         U7RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UKS4eIKs;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7n0ufVWZ7YpzzWVSum1l/x6uTbqx/mWRRE+nD6hv/hU=;
        b=NcjZOjXcwCWTankaLIUxVJgzGBHm4ppNqn68LONCt5SSmhMksQJcdII6ywP3Zr/SOJ
         q8AZ0ron3J7WjLYM9N8OFyII+LlwzXRebIQ18Q3hCWBo3SJH+7c8Ujvvwfg71TtcMlXg
         qtV42jrFUMMVC3+RXIl8mElj/em6A27rApc7BHZV6nhQYQcEj+KRFzzbNfIF6MEZOAhB
         iAoJDeJyIdKRMmmSdP1KHvjQbUmEoFoMbJdoG4WB48q3wKfZ19V2YEIdBK/z6Aly12Ti
         9ZfKDzhdsVr4ypD80YbiWcJcpZ00BbHSPIh8Zmba8fjvb/456uZbg5E8ndz8hzue7pjA
         MC4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7n0ufVWZ7YpzzWVSum1l/x6uTbqx/mWRRE+nD6hv/hU=;
        b=RpCduLmJSH8jBLsztBpGZnjBdPuu+e+dCrWUFJGlom2DgK8WDx9VOQua3ChZp20YYR
         OiBi7UmlmVji9+j14u6MX07t9XTIFJmps4sLBU2fxZpo6wsNDtNfY8LWUPrgShQ9OZPR
         kFCtbH6vdJRDQEtNQHVeBQZ3fpVeGfEcFsnbcjIhGg5PXXVEkeNhfyaetRrLPJGPSEvR
         IxuHyKlGfrnaFRg5ozoiX2eMS1k8Yf+80fMsYqAzTu86aBZrswoUm55wMQf1LpLrsgrG
         /DhuMW1vcKZVMs0Ob2VFBNscMpOQNM6DCoLyGYFaMSZszKEnX+kjlTdJMd00YFGgXWCK
         AC9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmX5cg8efBAziybS2D9ZCwCSqms7U/ct3BGaj5pIXskTjMlZGq/
	4V7+DscqonPKdM1j58Jhvmk=
X-Google-Smtp-Source: AA0mqf7gmlpHNbylITdn9SqG5gDKMIknW4Yk8OVnP90l8sxq+xHR7FcoRiJHINNarysurHENlXxu3A==
X-Received: by 2002:a63:cd52:0:b0:42a:9ba8:8c6b with SMTP id a18-20020a63cd52000000b0042a9ba88c6bmr89001397pgj.407.1671121854033;
        Thu, 15 Dec 2022 08:30:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2cc:0:b0:46e:9da4:e038 with SMTP id 195-20020a6302cc000000b0046e9da4e038ls7184641pgc.7.-pod-prod-gmail;
 Thu, 15 Dec 2022 08:30:53 -0800 (PST)
X-Received: by 2002:aa7:8f2d:0:b0:576:8027:a2fc with SMTP id y13-20020aa78f2d000000b005768027a2fcmr28366359pfr.12.1671121853307;
        Thu, 15 Dec 2022 08:30:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671121853; cv=none;
        d=google.com; s=arc-20160816;
        b=TSe4HRKjhXJIi3v9JSGAsCeLf+a2oj6P23JCDdYSNbferUJhFYOvAm4DL8m86Y6m/8
         mW1PckbwKwPrA/UEA0waZ56kTtVZO07R7Ym0SoUBKJG4Ie67ExINLzSU3UeHa+m1uJYq
         OxmE+ICqdHoUD1j50T0adPWD2oRjaq37MsYGU0uiB60/4ffztsMU+PaEzeDrbyIRj1ka
         u0FkJSl6H0Xb/XeR2hxYuEguecgHbaakf9lVarSgGRiYENCd9/xT7aRfc4R6PnF6I+Jo
         kTQSlIaADdyuWajjsETuX2DzDD82tn8V2otD8Fy8wIuwZyyMiJ2jcqe47xE7BPJ364qP
         2ZOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5sl1wEUyMqaCF2n4/rV+AWgLprf7UO3N74dC8Bu6j90=;
        b=mYVwpwCvs31eSk4FOsPPf51Mf7XXliQhyT8rn+8QKryGbjxhca88ppZFfIhJUgil1o
         zVSHUZV3jvvOPzIZ1eyOPWExo6qo0cTJpmqI8eS/PouHM+HSVluxU6MVDEhflQ4Qb/BF
         f35CBi7lQ2xU43GFbGNxL5UnUSET48LL8/0wIImNAVyhrwO6LZ1LMHfh1DF3c1X0dvUd
         Hub88guyNjyhkk4ZzRtGAI8VXX3lUsxlmsI2sw7nHuu4aJW0ZFouUQopoJwaK0/KqPrx
         D1TM6NZPfsp0ezv61ChBoAsGSD38IQORgnRyrism4DTkdtatYacDawcvdDl23hr1TA5d
         pf2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UKS4eIKs;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a64-20020a624d43000000b00576b2ab3999si197132pfb.2.2022.12.15.08.30.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Dec 2022 08:30:53 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A3F0361E41;
	Thu, 15 Dec 2022 16:30:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43A96C433EF;
	Thu, 15 Dec 2022 16:30:50 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kmsan: include linux/vmalloc.h
Date: Thu, 15 Dec 2022 17:30:17 +0100
Message-Id: <20221215163046.4079767-1-arnd@kernel.org>
X-Mailer: git-send-email 2.35.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UKS4eIKs;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE
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

From: Arnd Bergmann <arnd@arndb.de>

This is needed for the vmap/vunmap declarations:

mm/kmsan/kmsan_test.c:316:9: error: implicit declaration of function 'vmap' is invalid in C99 [-Werror,-Wimplicit-function-declaration]
        vbuf = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
               ^
mm/kmsan/kmsan_test.c:316:29: error: use of undeclared identifier 'VM_MAP'
        vbuf = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
                                   ^
mm/kmsan/kmsan_test.c:322:3: error: implicit declaration of function 'vunmap' is invalid in C99 [-Werror,-Wimplicit-function-declaration]
                vunmap(vbuf);
                ^

Fixes: 8ed691b02ade ("kmsan: add tests for KMSAN")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kmsan/kmsan_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index eb44ef3c5f29..088e21a48dc4 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -22,6 +22,7 @@
 #include <linux/spinlock.h>
 #include <linux/string.h>
 #include <linux/tracepoint.h>
+#include <linux/vmalloc.h>
 #include <trace/events/printk.h>
 
 static DEFINE_PER_CPU(int, per_cpu_var);
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221215163046.4079767-1-arnd%40kernel.org.
