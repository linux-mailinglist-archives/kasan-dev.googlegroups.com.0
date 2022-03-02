Return-Path: <kasan-dev+bncBAABBIF272IAMGQEX2NJIIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B1304CAA6D
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:36:49 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id j17-20020a2e8011000000b002463682ffd5sf670929ljg.6
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:36:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239008; cv=pass;
        d=google.com; s=arc-20160816;
        b=XZeQXEa99K4lHbIJzM0h7BcWlDE2TkpNGUjhfJ6rEhUK53XfIsRz7XGbfk5o9eOiz1
         5A5E/IyK8GI6yf5ebHUF08eWsKVkU+rJ6n964/5f9CUdqcu0iro+2iOCCxdG9TEDsQ9G
         +C7+/yILSvHFPrbSdr+f9jJCtistA0BplVjG2HEp+diXas4AvUZAIqVRcYhF4noEazYa
         XU+UfPnbn7GfcqcGDy6C8iLxj9z/tT+WmOnXBBOt/8tyh/VmQmEksI9RzyjvoGYzDf5S
         YyoGvslQjywepIOOqPCDyjwmLGsRUPlw2KmPiO5JPq6tuIiukPR4iOt/lawl/Wi8mRjS
         8xRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rC8F0HKiCmxtUkIKMVGeZ+rf7gdECTm4UG7+dw3KzaI=;
        b=VcdnygL8EvERBdOWc+mQgNzOEEcLBpYq7HNWMyHhpqOYLsWfULzHjNqjtqfLLl+bkC
         h/AYFMqfO8MlFJdEZEma30gTwpNak5fsEb2LTQLo5SCuv9UeOubmRUjLD4nWM1tP4CFQ
         E1jtnSZIDHw5qaGmf1SRcjWZqYTS9r0GCqQ7Z+RmE1Pqa+Fi8f66UjeSweM9DONSEg3l
         4oR9GujVZqkROO6SJMFCeghNiLgU/v2FnbN687A9NNMAdK06L7dbxQXR7WjYfB0H/OlK
         S6OWklxTR56UCuL9dZ1eSsBkguRz45smPRGg8U1btX/UzAGfm/21wKcVqCdJOUUEANTx
         LvFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Pw56LxQw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rC8F0HKiCmxtUkIKMVGeZ+rf7gdECTm4UG7+dw3KzaI=;
        b=OpyRIgSvoEsVo5zVxu6VjfmS/YHvlaZ0WMkoo6MUjwG4Xx/l+A864O4AdODxl4T5mg
         DsN6p0Fkqp9BoTuQJ7vpwCC4RezUn3Ghw4/NKd8SG6pDpPcFmmHjl00HN09q17qeMocd
         ZSX3x7SVJl39nxBG3Sn4jne2cJ7Jh4CFtYkDIWEu8QdYGlCFjwfdqKbwOHtBDWspbFHa
         4TGdxjwld/K9RrZYqLtIFwnKed/he9Y+iW+3b4s5f5fXYFk5pxBOlT04GFO6yliSuwGo
         Ex24ICa+pLgboRjmWPr1dPTSyyjjc9HxOgz0mv4kf6p5pjFyxzHkeDqme/9qNRpe+a3k
         WGDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rC8F0HKiCmxtUkIKMVGeZ+rf7gdECTm4UG7+dw3KzaI=;
        b=HiWggT0dx79HdYyA1e+X8AcOrf5FHbFnQG8wdPbOaho/bAizc7bmWFXoUpPlHOuYho
         IFvs6BhutcmShsKW2G5ihWAp4RAb2SDRj5Iq4lPUxmGyBXt6Hnyu/MVdgPnI1WWNOi8A
         2+YDW48rUvd3KQhmBfFelJ9XfukCl2LFLm36+dDYysuk+yEWoZZtavj4s/N3Wqyajbja
         7JIJX12JTNenJcW1Wf0Vvfu5YrvYvVNC2ACuYUiMemIBEprN7fWxkvBo5VeubzLu/xMj
         ei1ywg8ZbrLFjhlcK7EC2P8jPBYtUwtRHnyr1KWRnGEqAzoROZ52Ezg8/tYzjtO/v/VW
         XYZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EvhG/0S46UrQccUeoN62nakQrHJvbDiOx8XS7EwC65ZDhbwAy
	tc0PHD5lnc9dcnbE43XP0/4=
X-Google-Smtp-Source: ABdhPJyPZyGCZlt6rnSwDac0ipWLgtYjSgLm3nCMq5uYzu6ZeybRLxhUMNs8Ns1/F+GXqBKoPXGa7w==
X-Received: by 2002:a2e:8017:0:b0:246:3fb3:1618 with SMTP id j23-20020a2e8017000000b002463fb31618mr21439702ljg.427.1646239008611;
        Wed, 02 Mar 2022 08:36:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8e:b0:443:9610:6a0c with SMTP id
 g14-20020a0565123b8e00b0044396106a0cls483998lfv.1.gmail; Wed, 02 Mar 2022
 08:36:47 -0800 (PST)
X-Received: by 2002:ac2:4d5a:0:b0:445:b878:9b0 with SMTP id 26-20020ac24d5a000000b00445b87809b0mr3182661lfp.17.1646239007626;
        Wed, 02 Mar 2022 08:36:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239007; cv=none;
        d=google.com; s=arc-20160816;
        b=ZqkIfx593ZD24rso4EnepEu46D1WUUUGSAaZHVjbpP7V3yHBIOcSOMZ9tWjsjf9Bda
         VleGsDLCedfhFeUkxafA1EmEExppgPqVpxsM0jv1JSmOPWQW8E78BTu5zhKk/TpXxnma
         fVWnPXzqrZbnRzLKzuKHpb1gPCNn6/zVFXwObFyz1BEtrfCyYXZpZzsvxuPBNcwZbnXI
         Ovs7dg9xx9LwHnug8qKLO/5i3HcTNSqF7RUXYXobO1f/mnMlh6/EliEU6lkzpMsQxx1L
         jj2JwkYjTrGkHK8PFip0KhqaBTvNqZh41poY5OznmhYlo9/OqtUCRqJH08Sq+nj/wXb7
         BLVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yCGVn7r00QMuSI8V6gqxIK+E2Lf9e3kHr+j6afAS6Vw=;
        b=PUj4D56kpVP1YXSWjzPwKXTEbdz7Ui5h6vtLkhxzOsJ9YgyFNGJW6hbYTiZfQZ/CTo
         H6RnckYzRC8I5jIPwBSyAdzM1ABzlZhb3n1vNrJF+qV7Ld1wYltT6B7QF0KgGRqF7xi2
         SBWI0aDKQdISv0OGlUwcbk8nO20HDAhnsBmu4xZ41VWNinJFddz9x7O18ZlawOCgf/nH
         hhIl03JbX8Qg4rb7Z9w9aZjqL3Lobw3MmW4prIc9U9euuYmujfcK25HC9XfequSXpoqM
         aq5mGpqdgQZ3yGh21Pfk6TgG3M/+8AWqAGKIEIxvHvH05SML7v4yG68rLsWwnDLw4HNT
         BsLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Pw56LxQw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id s2-20020a2e81c2000000b002462ab45e78si1030168ljg.4.2022.03.02.08.36.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:36:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 01/22] kasan: drop addr check from describe_object_addr
Date: Wed,  2 Mar 2022 17:36:21 +0100
Message-Id: <761f8e5a6ee040d665934d916a90afe9f322f745.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Pw56LxQw;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

describe_object_addr() used to be called with NULL addr in the early
days of KASAN. This no longer happens, so drop the check.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f64352008bb8..607a8c2e4674 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -162,9 +162,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 	       " which belongs to the cache %s of size %d\n",
 		object, cache->name, cache->object_size);
 
-	if (!addr)
-		return;
-
 	if (access_addr < object_addr) {
 		rel_type = "to the left";
 		rel_bytes = object_addr - access_addr;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/761f8e5a6ee040d665934d916a90afe9f322f745.1646237226.git.andreyknvl%40google.com.
