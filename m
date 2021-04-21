Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWMHQCCAMGQEKSXCOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 08B5536697E
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 12:52:10 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id l18-20020a0560000232b02901026f4b8548sf12497968wrz.10
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 03:52:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619002329; cv=pass;
        d=google.com; s=arc-20160816;
        b=mW8mogBwnG2EKZF5OEy3TpIoeDvIHlKOxP2i8CdTdquXhZuXw5WlHgwkvkIhB836jn
         hzf68yRYkRq183CpYdW6YlfChzuFpNYDgdICEbjOHO96TbIW8K4Eb5s/ar/CRJZ8wQ75
         LRwqLosbXgsLjWfYxX4HQSOUm0+jsEWJmLgsmuwUaTTJn72PuJixaajRQCY4HGLSv+Io
         /AuOxGMEiLRrdpjIHHnzGvM/+eFOsTCckT5RQZzBojiSYwKKm+qimzMeDdDHAPffuO04
         lZlg8BVKfThwdpFyBiWBK8hEO3nO/qa5pEgjujr5B3I5Shl6icbIJt13yNBREikTMkGU
         EAXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=2c6F/T8Ac4/ntloflAKMBjXjp7XMDqxi8VjUUvGRnn4=;
        b=bIVSGGZC4mlRDeRxY7YW2tm26ZJN9I/mzs5ZbvvUi5nv0I8ThYSnHjqBNupnmpn9gU
         fuWPLkmW8kxXaJNhvlK4wLQ9IY2f2yfr8yzREFEuxn8EXLuLsu7/eQbQt466B9Z94b/1
         FXus7aK/2c+tbzDoch7Qg0Wz2rtKP7wLcevsBYjprRkZdftLCeBubH0jkVo8lCxxpoI+
         a5a5Pw4us/wFixeWP9sZlrzsIutqQo9KhbrRirDy9sViK/buzUBRoO64YFqAAtlQXyzA
         nxBWc/uk+8sfYTK3KGUSE1agwkprROKRT1Pp0j4wRi9JiTVf89VVZbqpSSFQr5fyN4ow
         RfQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="e4RwU/x5";
       spf=pass (google.com: domain of 32aoayaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32AOAYAUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2c6F/T8Ac4/ntloflAKMBjXjp7XMDqxi8VjUUvGRnn4=;
        b=adH6gf+gP33sjlVKo7ecXE4SWDsAGI622w0fNmtDZSCue/yiXBRSEguD4pgoseVVLC
         RmpcPx2b6xZ7XX8rCPEDGCB33O+7KeArE7lPWKeljC2Lo7TiZKgpApOdvNKq0NJnxuS7
         Y3v7RG6MALqAF2KGt8bukNBj19cdtTR7nSVqboabtjWSMOxGgsZKgG2eOSFULaeUGlKk
         nZxASL/YDIIKUSuIsrFdgSaXZF2DWthvRmRAG3TH5q7rCYttznQaZtVLSdLz4u9Mavyn
         pXARG6UZphG1z9gDA1SQ2JdMdZpVElunTiM/jyi5HIXi4UZgy5JL0CkYMyHiDpH87FGC
         96jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2c6F/T8Ac4/ntloflAKMBjXjp7XMDqxi8VjUUvGRnn4=;
        b=Z6oqAQ/2nWUaKNo+k/y7bI7Oc4cZzDXPESwLx1WAY2yzTODuZ/eiFYpN+A43f0kh5r
         U7etGby+DtswEyeunTNmwqZM8W0gTH7y9UfoPfr1xHS68HRS2XR40hkaYgxpQSr0rYaZ
         yjgGCV/x3RP73pbdbeNt7ohBbsT7HIOQXTk9/CK4W8STEGjJPffxBbkpj4OKgv6OOIpf
         +7gjZIv1lY7WOYGYphc3yO33JeSUWUu831+QoJaa+fEOhn6iq4gXzEcS1aeO4VoxrOH2
         LP7Wp1/TpglWWDGyxGp/m3JefU3/JbwMbuBZ88D22AqRF4a72vqTFYjAsimygiU43mB5
         sRYQ==
X-Gm-Message-State: AOAM5333pSYm1BSl/uitJQW7LgR6eXooJlQU5dcqpDuQcySis7vXq3d5
	Rc//z6LLa7+omLO0jxHt/nc=
X-Google-Smtp-Source: ABdhPJxnO6vQ0GoE2AYhN7qlwVM4lUPf5t8UXoyOpBLsH6+HiKjHbu4xJihkXHBXeEyrgzn8JWWmBA==
X-Received: by 2002:a5d:47c1:: with SMTP id o1mr24728109wrc.216.1619002329793;
        Wed, 21 Apr 2021 03:52:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e5:: with SMTP id g5ls2438802wrd.1.gmail; Wed, 21 Apr
 2021 03:52:09 -0700 (PDT)
X-Received: by 2002:adf:de08:: with SMTP id b8mr25688973wrm.279.1619002329014;
        Wed, 21 Apr 2021 03:52:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619002329; cv=none;
        d=google.com; s=arc-20160816;
        b=dRFJkZEaYL8RHpDXsuALzkGDwax2rrJWcC0Akc6VmWGHd5xc39tAr/UNfg+y8/LHIT
         1ADKU4GwEc3PBwv6p4zSSR2uLV/MIdt7+udrBGuibRlYK3BoBjdGW7xjXM8NEABRORLc
         lVFNZgX6TyobwOzhI+pEPrtwtO8ugtVHadzwaIf3js0neuXKQGbX2WQ7zclZRQQNesXJ
         DR1bLs1GA35m5iImMTm0+ZXwc6PM5woH8t44wfGoxGtp47vntA2SOM90ps74mLvL2PxG
         o0F3SX/WiV+/Zv0NUfiZtCkaTlVWWTF1I6bBNFBaEKEARiwqClLFjZGMpNF0wiC8nDfs
         PUJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=958qgNOMMQHBKiudXbOhYcKipML0hl7ML/vSp0CTCqA=;
        b=mDawop12vCXCXP20QbhhKzRVqEfsHPtoeC0Whj478I25jpVQROwL24ZWls/8WGV+F5
         xFB03e2AmPhqSOLRIFe+WQJEQiKXqv8Q44Xyc9Vnz9UHaBoX/Zm5P6OLOCzWkOFJO/MX
         4a2UD1kK2Ekm/LtmjHyEEN2QVf3wXXeumGbh6vW02I0tJ55oG36ye83Zba1ms2rCPNHK
         DnzEr/nrPcmanDhhwb5+8IdBWl0Ynf4qwdYbq1E+d4wXQ3ZtFvCPsDiAQ46dhkgz3qyw
         PcfNqB3RZJKUJes+fPmd1uk2+/X5gtiyag+Wc+0ip4xmOectHb1yOaMLDClu7sb5KwCA
         6waw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="e4RwU/x5";
       spf=pass (google.com: domain of 32aoayaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32AOAYAUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p65si1158298wmp.0.2021.04.21.03.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 03:52:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32aoayaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t14-20020a5d6a4e0000b029010277dcae0fso12423874wrw.22
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 03:52:08 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:c552:ee7c:6a14:80cc])
 (user=elver job=sendgmr) by 2002:a05:600c:4fd4:: with SMTP id
 o20mr9476694wmq.166.1619002328581; Wed, 21 Apr 2021 03:52:08 -0700 (PDT)
Date: Wed, 21 Apr 2021 12:51:32 +0200
In-Reply-To: <20210421105132.3965998-1-elver@google.com>
Message-Id: <20210421105132.3965998-4-elver@google.com>
Mime-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH v2 3/3] kfence: use power-efficient work queue to run delayed work
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="e4RwU/x5";       spf=pass
 (google.com: domain of 32aoayaukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32AOAYAUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the power-efficient work queue, to avoid the pathological case where
we keep pinning ourselves on the same possibly idle CPU on systems that
want to be power-efficient [1].
[1] https://lwn.net/Articles/731052/

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9742649f3f88..e18fbbd5d9b4 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -636,7 +636,8 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
 #endif
-	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_interval));
+	queue_delayed_work(system_power_efficient_wq, &kfence_timer,
+			   msecs_to_jiffies(kfence_sample_interval));
 }
 static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
 
@@ -665,7 +666,7 @@ void __init kfence_init(void)
 	}
 
 	WRITE_ONCE(kfence_enabled, true);
-	schedule_delayed_work(&kfence_timer, 0);
+	queue_delayed_work(system_power_efficient_wq, &kfence_timer, 0);
 	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
 		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
 		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421105132.3965998-4-elver%40google.com.
