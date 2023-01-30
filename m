Return-Path: <kasan-dev+bncBAABB3G24CPAMGQEJN7XXGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BDC1F681BBA
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:49:48 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id bg24-20020a05600c3c9800b003db0ddddb6fsf7802804wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:49:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111788; cv=pass;
        d=google.com; s=arc-20160816;
        b=tSCx9nWVu5eB4SDyVqU1by8pP6Ad6MrfgYQiLz+1De4I4h8Q8lRhLARv1WlBJ3DAaW
         Uf57EfSE8LQiMoW9GAtX47+cala8cfAcTQnN2P3aV5JFMXoMO2bWwi2IS0oN9WaffWOF
         kapQe8sLSGwAxfA+OmfDWr1r9YuMxy3qtfPqms/V8j6wc8n5viRjQc7GenNPLlF4RQZa
         lgzWQKQ45rfw9o4yEU0TYV83Bi/emjkE4HODEevJ22RNtzLhRv77XhH+hd39fAQPQ8rL
         Sl1oc6U6aN8pAajvndVdQ3jrk7V7//OcZkjmFnuzJGNQIYu4WfJhC+xVTDD9OMhzFT+0
         zBqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9vWVvbKVOw5mdOERy78HgInfcTABSe5rlAiel6lqAVg=;
        b=rrMDnhKHg4KTyU29+ePTwclJ53nRwuEhHsZu4iV3xMAjkXAfeZ/yo0FovRT0//3zic
         xUaNzRC8RO1JEoaI1WVI6D+sd+hm1T+3Pz6Ai4KNZzA7a/RQuFqVLEdBzkKnYzALtvNt
         2YaNmUpiQxZeSzRosPdiOy4VFNgZ9hALk4aRhJqTZxC9NMr6lTf7Sh02KefacegEu0Qc
         /9FZYReaeVTV4xGMPRq0PtLAhzEL1fzK1U2zKR8ETn7vRrsuTOxqKDbKgXaPC3y6KEKa
         HSMxJjGv0Ov85pJRM+atBW9FirOQWuelVijA9cfA7/zI+dwVFmQUm4gGHP9QWD8OkAsE
         ZdOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="l/E56Ec3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::87 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9vWVvbKVOw5mdOERy78HgInfcTABSe5rlAiel6lqAVg=;
        b=rVGtl1Y6o3fnhZ1v1NZFWdpeNMwQ9X4a1Kqza22Ifkdiv7oLE3xx2jmTZH+0lXH/MH
         zLJnBp/sXWCKkWua39+MUx2vRIzDaYJB5Xgdb5HQM856PXOi3qMTzdNpC13HJI3TuuA8
         3/EecxZt7pZsxeafSaDlJF150fa8+KJ/meeC3szWS03yHGrOV7oqZlf2frnMb2g/WXbr
         VN+5vdJHlxf5aRUkd9tl6O7zq1XsW+45+ozFnPIsFH3J2P5oS/zTG5pmdb899xliqaVt
         tdisNaPB1bV3e5H9tchZKNhLBTm8+hz8EaizaI9x9rwVvzAcsTwDhb16iz5zJiAt4PYt
         S1HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9vWVvbKVOw5mdOERy78HgInfcTABSe5rlAiel6lqAVg=;
        b=AaT945P+ddMyXcIcpq1+JYLsWmhGeUycCQK8rRMbaXiqerhL/Vwt1GrBkbAkRYPMDE
         30gAS1TEUvEa6IRGBEoDpl34oKICEIgRIHQPIC/ixo2SaLBVQ9xIyq+gnvGFVtsEdIhD
         gIKZcrvxHbkwCD90LRVNmwIh6C906wTlj2PsB6ReBiBXIhL/NSRyCkUnGv07JhLA6OMp
         IAJ5U7WZRwzvzpOBtvlvsFvLEsWvHbl1yOY5u+DpGXoF8lrsYt8WuZSgHVm0HV4sbwuD
         XfVi+qxUtYapOlIayxitZWd5gfMk1DQTbGn+WcX7+bWq/cRI/oWS1OMt21YgCWmRW1ya
         vGkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUzWwmHCJvDT0HFoqq4zTiABGHo6DTUu9yHFQ1F/vxfOrn0wBaU
	+Zp7OReoNXCyS/XW8KuIhSM=
X-Google-Smtp-Source: AK7set82Waoc4J7OQx6m2eToqOeTYZUJbVoP0ipmU54tOFWlb54hckhPHuPgvMHIgGVngCSPKKMu6A==
X-Received: by 2002:a05:600c:5025:b0:3dc:5e16:37ee with SMTP id n37-20020a05600c502500b003dc5e1637eemr240789wmr.37.1675111788272;
        Mon, 30 Jan 2023 12:49:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c20:b0:3dc:4bb4:7c6b with SMTP id
 j32-20020a05600c1c2000b003dc4bb47c6bls3361737wms.1.-pod-canary-gmail; Mon, 30
 Jan 2023 12:49:47 -0800 (PST)
X-Received: by 2002:a05:600c:4f08:b0:3db:9e3:3bf1 with SMTP id l8-20020a05600c4f0800b003db09e33bf1mr49571955wmq.31.1675111787296;
        Mon, 30 Jan 2023 12:49:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111787; cv=none;
        d=google.com; s=arc-20160816;
        b=u68a4QsEdJWoRDKBDtZcBznLhWo9OwZ/F3Zzh3kVwjvzOjZXfx+TFAq30bpHHLma1B
         ZJ89jw4Xby4SKIvc46tRhM7FhFc/RKZ/6LIDLrar0mW+HIa0usD2cxUTh+fPSiRxTQ2O
         7+RrBd4rn7dqDZORVXY2YdgOYCnnXDHZATSAKurUcjGtZIKxH+vz+DZUaKHZi/wDlZ+b
         xNHvSJM2cfrvO0BfTMOLvJLdjsmVMn61O1gRzaLdQNvtq4jwSLEsHIHT5QmtpkE5uM+H
         jcKnzgymvpnFJv2ixHw2ZOHN1l6RMIkv/hg3E9RE61NgslWXtXt2RoXy6CgwoCSbXtCk
         5DVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vpL8/NdYX1/weZXFrNrkU0jpgSm404fZwOGAfIO2ueo=;
        b=UdoqeomSvxByrrd7xEuBnraw+EtwjTHff8+fz9Ei1VWLLAse2yWpzQ/tKoIOk97dw4
         BmTLnoUTIZAoVlJq9itdMU/N5PV+pcYjNQClE/Gsnngb49pey5YDO00E4yL2YwhT9uto
         YvHTGix+/4VzgTop6iIShWmLtZlP6t01N/B89cegk6iHed55VUCSYfFv3KjorCxeX2xT
         3rrClAEajxDtUeJI23ATyeIDn/8PFm0DrtyPXeKubBdGBt3RBULE1sYcdO2Jgi5qnuUT
         HKGhLPxs2rXyMV9MH0ZxPrBCBZlZXFnTluiexte/Ez8RG7mhcjSqUKALI5dyph6D4LnG
         wNnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="l/E56Ec3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::87 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-135.mta1.migadu.com (out-135.mta1.migadu.com. [2001:41d0:203:375::87])
        by gmr-mx.google.com with ESMTPS id ay10-20020a05600c1e0a00b003dc537184cfsi328816wmb.1.2023.01.30.12.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:49:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::87 as permitted sender) client-ip=2001:41d0:203:375::87;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in init_stack_slab
Date: Mon, 30 Jan 2023 21:49:25 +0100
Message-Id: <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="l/E56Ec3";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::87 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

In commit 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in
stack_slabs"), init_stack_slab was changed to only use preallocated
memory for the next slab if the slab number limit is not reached.
However, setting next_slab_inited was not moved together with updating
stack_slabs.

Set next_slab_inited only if the preallocated memory was used for the
next slab.

Fixes: 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in stack_slabs")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 11 ++++++-----
 1 file changed, 6 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 79e894cf8406..0eed9bbcf23e 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -105,12 +105,13 @@ static bool init_stack_slab(void **prealloc)
 		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
 			stack_slabs[depot_index + 1] = *prealloc;
 			*prealloc = NULL;
+			/*
+			 * This smp_store_release pairs with smp_load_acquire()
+			 * from |next_slab_inited| above and in
+			 * stack_depot_save().
+			 */
+			smp_store_release(&next_slab_inited, 1);
 		}
-		/*
-		 * This smp_store_release pairs with smp_load_acquire() from
-		 * |next_slab_inited| above and in stack_depot_save().
-		 */
-		smp_store_release(&next_slab_inited, 1);
 	}
 	return true;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl%40google.com.
