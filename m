Return-Path: <kasan-dev+bncBAABB5NX52VAMGQEVJHBMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B62D37F1B6D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:48:38 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-50aa861dcf7sf2003735e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:48:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502518; cv=pass;
        d=google.com; s=arc-20160816;
        b=dBXJPs2UK07JhwgdC0Ll3vjiSbpxX0i62/4avzRDlfR2i30pl53yJgkDi6fr2EadTs
         FJUC//43yCpH00xDRj9DEsNEBCbuTim3V0iuRpY2F72p7n18LLMD1AOK0EUnkcD6DkPA
         MXYdScBJlINRV6/4byc4wCjXtgsHVHyevs2i0Z0cGweOnPzqYcHBoBB1eT8udRWV4NZh
         J6GPYsHxG5wMhuQw/SsAg/t1JxUxErFWSNykcIlIQ9RdwlhYqwFXsv7+AuQZPMCvfeq9
         cp8CnSnzJH/iVjEkp75khnMssTF9cmq3DMuqOkoQVPb2BgiCjGFvuYvG1pOxRyMiuV5Q
         KGkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1AOcyH2o+1beakU8gPkxH9mqsNdGunaA03XcJYLloaI=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=dYbThh3EN0xiOtpwxIPzAM+jrxiy+whAofW1qvmC/rl3dqltNMh+3fDE5VrxJpcRYk
         /3Xceo21pfKXJtu2dluofPhXoKv9wC78shiRgJfR1Dj84UQKgSMR7hCzf0BRq6PVM3C+
         V/0guP7A7XRuF24p+2uT76mdk+kgrR72YkRXyjfI7ovQN7MDbX44HB9g3ag81aeHRtmK
         kcZEJhtD2nkk/YV5P1HbaDo75VlLVi6DrkrjqnpfKVVlaNggxQhmRujV9OksbfS0g24V
         jEdwE39GkO2ZxVMJ7WhodwM/zFMHrsXF63ra6/orgtR42jWuX1b45B9hRKMxVpNCjROS
         DvDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mVlXzudg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502518; x=1701107318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1AOcyH2o+1beakU8gPkxH9mqsNdGunaA03XcJYLloaI=;
        b=sGq7H1x5xN1tjZ1povjk2oOzSEEfmxRbeoILabSXiyj+tDaqLbcbxfQ2nmOy/iO2FH
         lxB3eR/1zBaE66AqkN4BZ/6lCmLhmaVv+X+JvcuxDaiIO8aDVD9TFTwefMVeE/OsTUG3
         NnVSmONbliUghfuaLk+2mUZlFPph9SBmRB30TKQ75YA88i5txns4BGggYxE0WmFGscPl
         ttulUOJi8MOq54MflutzlT6pkq7vKr39umXX5bimVyz+RZdJzeZ+0fr/h7gVjQbZf67y
         Uvme0ZjN6RiGGXJ5KJxiv4KkIB774owK38JKPF8i4iPq/FU/TGGLdYaqff/TtMTamDzs
         swrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502518; x=1701107318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1AOcyH2o+1beakU8gPkxH9mqsNdGunaA03XcJYLloaI=;
        b=qZE/x7tR7pFCe/GOBC2FRExYXAwvsJGuiBJLlnsBZMZ3UPlvcqPHZvyEEDeYx7IAnz
         xPffj14lHMmKh2r8ftFOdBq2xsoN9watWM5jsFRkybWLzhK+9R80GZ8p7PVKyDxB5WLO
         DFo0YZo2DOWwmrxNIvl2IHnfNraUrUusEfN5NT/6sSDQigRVGD+R/REE9y3uNUNW720l
         gVAwqq2Ak2ugaAIBepHCjNoyW3KffgX0MQW54M4CaLxDaCPtwoKkGLI3J6wMnQp31Mok
         TJolPwthCOBn0SBPDUsOZ1b6Muk+3GrxOWGB4pd1txU72emDQpvnhUH8xEXvJzwISthw
         sJCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YytIJS54T7HVGPEjyhzMr9Yq/k5asgKEidG+XJPrBv9XNmeIdWi
	2omtoHQNJSDeSHw4sh7gok4=
X-Google-Smtp-Source: AGHT+IFuu+sLAIupfFSScseGR0lvj7H4Ty/4EVAufCxIqRpxK8Fd2IPFUY+2uMs4IKlcpqhZtkmVBA==
X-Received: by 2002:a05:6512:4898:b0:509:2b82:385c with SMTP id eq24-20020a056512489800b005092b82385cmr5763968lfb.61.1700502517331;
        Mon, 20 Nov 2023 09:48:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e9e:b0:50a:a999:f190 with SMTP id
 bi30-20020a0565120e9e00b0050aa999f190ls91501lfb.1.-pod-prod-06-eu; Mon, 20
 Nov 2023 09:48:36 -0800 (PST)
X-Received: by 2002:ac2:5110:0:b0:50a:3c38:778c with SMTP id q16-20020ac25110000000b0050a3c38778cmr6246935lfb.12.1700502515819;
        Mon, 20 Nov 2023 09:48:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502515; cv=none;
        d=google.com; s=arc-20160816;
        b=Gnw/yS1Wpo1Pa7O0cdM+8rzv0clqzkW5CBwgxUDLY4tXTPo/hqNxmzQIdniDOSOyMt
         c5x/g2UOxdPKs12ruI1vs9qtCpE9Wqae/RIptVB4vUdKD35KIq2LvBRPpI2a0FoT516R
         lkzkYJ4cJnhVbvKKeOq5zzJ9q2CMx8XISaqH2fiRm1afiFa60HgLymTn5BZeqOkQ9GgT
         CNHh19mpgYOvHln+/TlWUrdEG6FJEsTSn3jeEZvCXQyg5eI03rk1yGqNZnWT9rY/1on1
         aVdh6oxckVv52m272/zLSXcQEnOYUbGdCm/XYdtkivd2i3rAmOUr11h0peXysNRvE2C9
         jOVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Wo0lOk4QF0V4/CSryrBtBcTGMr2NPIzDQs2c2iiME6Q=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=hqY6b1zTbFf4b/VPMD4wDzCe2vmXcn6sv+FiYaY/3dpQy9+ruPjCwECth/THHP0U9Y
         7RVnIkTStU2nmIhwNaG9F4ZD/xf/kmUwTUPzUhjWPnqIfSPBfMjWd8P33qjB4VQF6Zq/
         tHBaMNlwbxnQjRWRTAI1zzJUVMJBerFrpLvNFMVDNTlKmD1Wl+F0Q/p/v+Rh7MfsKt0U
         rzewmBlX4tdXju3fZsmvfb4RTpDTsegy/cOgga6oQwzFBugLPA9LUwb8yDwr9EofmLAD
         R44o5rl9MelwI7p0YPU1d3tmuAztk3VyZc3HP9L/VH5kp2AsSPUlsqeJ+3MxJkEOFhsH
         YqdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mVlXzudg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta0.migadu.com (out-180.mta0.migadu.com. [2001:41d0:1004:224b::b4])
        by gmr-mx.google.com with ESMTPS id i20-20020a0565123e1400b005098ece8aa9si348213lfv.12.2023.11.20.09.48.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:48:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b4 as permitted sender) client-ip=2001:41d0:1004:224b::b4;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 10/22] lib/stackdepot: store next pool pointer in new_pool
Date: Mon, 20 Nov 2023 18:47:08 +0100
Message-Id: <448bc18296c16bef95cb3167697be6583dcc8ce3.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mVlXzudg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Instead of using the last pointer in stack_pools for storing the pointer
to a new pool (which does not yet store any stack records), use a new
new_pool variable.

This a purely code readability change: it seems more logical to store
the pointer to a pool with a special meaning in a dedicated variable.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index a38661beab97..68c1ac9aa916 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -85,6 +85,8 @@ static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
 static void *stack_pools[DEPOT_MAX_POOLS];
+/* Newly allocated pool that is not yet added to stack_pools. */
+static void *new_pool;
 /* Currently used pool in stack_pools. */
 static int pool_index;
 /* Offset to the unused space in the currently used pool. */
@@ -241,7 +243,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
-		stack_pools[pool_index + 1] = *prealloc;
+		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
 
@@ -272,6 +274,8 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		 * stack_depot_fetch().
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
+		stack_pools[pool_index] = new_pool;
+		new_pool = NULL;
 		pool_offset = 0;
 
 		/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/448bc18296c16bef95cb3167697be6583dcc8ce3.1700502145.git.andreyknvl%40google.com.
