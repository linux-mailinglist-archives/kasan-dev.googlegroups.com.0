Return-Path: <kasan-dev+bncBAABBQFB5GVQMGQEOHOFKYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F355812413
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:48:02 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2c9f80d8d0bsf61644001fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:48:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514881; cv=pass;
        d=google.com; s=arc-20160816;
        b=iOUDjWE8lnnduQweKOogXKATV9s054XmCKWuZrQUOOMhuWPA8zV2FYmbSwvUHprFvz
         0PYvk9BlSmst7dnMi83Iy7h4GEsG/Vq2R3OPmpr5f4j2zdu1NrOYNHK43SBQkmldttJP
         +Dp8r1Juumtnh8HpJMwqhWuSsM0SzNlAyqg8MHc+/+7Rvv1qUKb6M7ER4HWDpEx4VDo1
         /Gp+HRRV/FYx1fpl6hIG1qsuBllfiuHvgbQ4SzXSsaz7K+KdOkVLCQTv6KJaD4ADXCim
         eff1QVCp+k+ewvf0b/PFHZAy++SBXvz1nN3mtToj/nk8NXMiD3QSFlFUpHVixkX1pRKB
         fDlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=lq2UHxTQ7idP857sCX2tm591QlgjGPmp2ueURUWpDxA=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=H0K3OvJx/ByYRnaN+A/h76zsxUBwekp2FCXp2mDCJGyue52neDum3f91kVBx/7yaOV
         P5JUcXVJEIQ3GMiAK9PluULDRYOGWtfNoxZ22tQQZUExTwIbH4bqvqB5xtVZiRZ8rsxb
         VlbJkZoa0dng6cPju63h9EWqGoynCGLMVLaFnnvZcuOXk5DIenLpg4snzbFlGe7rCeK7
         1OtmmUgWRlkSBcRKjBLPWz8n7ESc3zftC9Z6rXu0xNVdmG51aguWEsxNKSLB0JBF+Yk8
         NnviZcdIXgFA4erHuL6b93tKnflLrAWHi4P6ogtNHbsHuqfnwwPOSrWaQ1RptXp564pb
         ZPRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=f+afQX0w;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514881; x=1703119681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lq2UHxTQ7idP857sCX2tm591QlgjGPmp2ueURUWpDxA=;
        b=lOhP2zCCDeJ3KvxNAPb6QD31X5TJWnk38cteDNNUyz3sM7qcqcSWiOSrpqDdQqjmQb
         gxhoy7cqwbExgYDD4LFzfZRu1m7Hz2njq9tdKhFGOzF4/t5LoDEY5jiIdkTVb6dMkSTS
         YLYX1K1u4R8YG+gTvEctdSwJXbE+/+ZuLT+/IVRlCo7EH2TiyquF0fS/G8xjCLPM7oHa
         6nyVDikq6H/edA8xGGlrJcwsGV2zgkZ++BHANAmjZ5mBbQHArAhlyEvDEIVqfxAaFLG1
         QkN2fJ7HEm+16XxbzT2en5NClWCPOd10k+B0s7TrMeUCn2HOmvscz0WVG+PlO0HsAeyX
         /4+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514881; x=1703119681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lq2UHxTQ7idP857sCX2tm591QlgjGPmp2ueURUWpDxA=;
        b=BAA6jI+J1azRXahAkqU9PiCg5Mh9vqvRLcEwCNot4r8HZGl06MiD3WL/O66LtLqspu
         j0XRnwfKDld+swEDZvcFzOEVq7LPWMgpuBiSSy8TeUV/lIWq0KrqnKyl7ubXBtTRO208
         xiIzwLyC/cC8nip22XRGMIAzsWneHULvhGnR+zcSAoUXnUDD3T1Jf3w4F4TjMud4m+gr
         Srchfr5+knAGEh1zH8oBXA3X3kW6eOk6oHmWjnS4i0Olp/9oz610jwHcDcAxqWRLj6NJ
         AuC9mHNsx3NFHkVNuYFmRbzMycRGV0Kgqs6M96OZsJW6fvz8nEres2iXC0a+40pqB0cy
         dTgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyXw0N/64JBVQOiEkNsXRslv0nimwf7D5tHBXP+Ogjf+CvWh6Gy
	/0ab2eocTdR150/mBWEfgGE=
X-Google-Smtp-Source: AGHT+IFvrwOSqUDj2LDZVIMaKiA5cA3GuXoptnki0rPFrfXcwL3prFSLAXLqwlNKZIajqkxaiQIiNg==
X-Received: by 2002:a05:651c:1145:b0:2cc:1dc9:2ea1 with SMTP id h5-20020a05651c114500b002cc1dc92ea1mr5006216ljo.87.1702514880877;
        Wed, 13 Dec 2023 16:48:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f95:b0:54f:45e7:eb04 with SMTP id
 eh21-20020a0564020f9500b0054f45e7eb04ls272138edb.0.-pod-prod-04-eu; Wed, 13
 Dec 2023 16:47:59 -0800 (PST)
X-Received: by 2002:a17:906:10c7:b0:a1d:2e32:d284 with SMTP id v7-20020a17090610c700b00a1d2e32d284mr3958954ejv.23.1702514879194;
        Wed, 13 Dec 2023 16:47:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514879; cv=none;
        d=google.com; s=arc-20160816;
        b=cXcIldN77RBerF4P3eWQro4mfwD6MYvgigHEjulZrSjcb0kN2TbbN6vPZMRxIlbj9x
         sP9M8av287HUMze2PemiYAeAsjTf8zMoriaVewuCu3m8ei1UTscMojihGS+81x7d0r8x
         S4ncELVi4ujwRcMMLn461YRG19+gCzfcxYTL9Gf6ECYAgtP3MdgJZ64lSQAxUBBOnzYc
         Ls5NYdUqDeP2b2GAV0gM+RqIMJFo+sTHKYHekuobxZY9ELpTIq8iJcvgpxOfFRPL+2mt
         wnbDTl7tehPEKxdKwY0bgYXZ3ibMdLVOJQNyiXtAnmMPcJhmYHURWA66dABSVCf7P3Ff
         mDYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cJEulgYn/h7q3QFVAp5zsWImEtvD0ben3q7crmppy9w=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=QbmqSRt96JdYyILOiA4o1LObORiwyGRn394RJDgjHj3XJq9uBBdADOWPAsQIIvg7yQ
         f8QHcptQ9gCZB0Fgp0ycKf0I3tNH/7EX1FFkGJNlowPPIa+gyosdrsZL22KqCNVOWCXp
         WkVigbAGIYt3wXyGnPMn5uMo89I+7l+qATTRY9dnJtc6yIZruweGYxyzDGIYBBfpM+3r
         hFjrIjtWpc9XiGo5P92C31g5yrh9x1oNQ4ITYS2/b5fSuGxFP3a8+LZB8XkmivmxUZRy
         DQBzL/IqkSfNFaxk72ethQv5oc+E2z2mnA22l0ohV1BtCqz+5CyeKht9V47VX6IwFgcl
         530Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=f+afQX0w;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id hs28-20020a1709073e9c00b009e2c2a65c8asi877871ejc.0.2023.12.13.16.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 16:47:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
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
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH -v2 mm 0/4] lib/stackdepot, kasan: fixes for stack eviction series
Date: Thu, 14 Dec 2023 01:47:50 +0100
Message-Id: <cover.1702514411.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=f+afQX0w;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

A few fixes for the stack depot eviction series.

Changes v1->v2:
- Add Fixes tags.
- Use per-object spinlock for protecting aux stack handles instead of a
  global one.

Andrey Konovalov (4):
  lib/stackdepot: add printk_deferred_enter/exit guards
  kasan: handle concurrent kasan_record_aux_stack calls
  kasan: memset free track in qlink_free
  lib/stackdepot: fix comment in include/linux/stackdepot.h

 include/linux/stackdepot.h |  2 --
 lib/stackdepot.c           |  9 +++++++++
 mm/kasan/generic.c         | 32 +++++++++++++++++++++++++++++---
 mm/kasan/kasan.h           |  2 ++
 mm/kasan/quarantine.c      |  2 +-
 5 files changed, 41 insertions(+), 6 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1702514411.git.andreyknvl%40google.com.
