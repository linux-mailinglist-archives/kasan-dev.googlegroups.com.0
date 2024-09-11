Return-Path: <kasan-dev+bncBDN7L7O25EIBBGPZQS3QMGQEM2NPC5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC433974A87
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2024 08:45:50 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-7d50c3d0f1asf5381977a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 23:45:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726037146; cv=pass;
        d=google.com; s=arc-20240605;
        b=CyfFPg/SNAEya74DeVY0Dw5FYZkDs+FWwWerwnHFAmX+hUAe9fvsEflB+FToFDFmCA
         Xu5D2grZ4y7pvlj0TlrEc8lmh65SJZupUIK+6kgOcOEDo2LO6NcVZsdTHgBq5EL8WtiS
         0t36fW6Hs+w+pNCXsPk/UAcnPpsvPoYVFoC6copzH+vCCj+Ij3l1kqT9idR5+K8Rgdpy
         6OEcLM4DjqXW8LPeltMn9X6GKf/7bWzLwLTq2zDLmsGCgCsxreXl7yRDwjUduK9uz1Il
         o5fKu8QA/pV2lxO/McfpxMl9opD/Fmd7zngZ3FE6xgYKir8zyGcoz+tRmwZu7soNH5hR
         nq/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bVP37iqvNOpJ2C4azkrWMhWHlyw3amrbbhDMwVKwFZo=;
        fh=GSMuHPIFjcxV2kpi6BbUqMEp9MKS//w/cEHvMO/hNB8=;
        b=h5tbT8H5j+VmlrsvT9W7IqO2N5J4ynmmEkgKK8q7ABf6OkvAOea8R/mtQrsYA7TDRQ
         G5+9VldT9C3c490YX0ZJVVUwVyA6A3np98pJQGRCD1NSYqQYL1kPj0inWVpkmCt+F4dp
         cPEr0OMTCctj4HjfYYRAtjSPdpfcxHtkb54ShMPYBT83+u7zz21ulIt30gsAhsALcNf2
         railO2RQl5HLJQ7WcU3XQlUjH5mh8hQcz0JEOU6INmaDRW//DmbcvDEJ/ne3Tq5iZvHz
         TRJJZcv/qWFEoq+zSQNBpm1A+Dh03PGhdNp//47J0oi8o3o1ZbEfJQTJgfhQssJm6Xjo
         C5ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XR35QEpx;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726037146; x=1726641946; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bVP37iqvNOpJ2C4azkrWMhWHlyw3amrbbhDMwVKwFZo=;
        b=nHYOuRqhUgCKvE/yF1MpXuzrT+k5IXMtHAbrxBCdhUlLsWVsyUEeRZU8yw+OTgMiAf
         LUVYnsU6vhgR+r4gRjrU4z9vh2N9wBgaxmRubXlrLn+7DPz2X8iOz2Uu4SnTWkenCKeH
         BW2WO62ZOqlUSFzLfSdoyrfNgNUBuRoQUxgrluqUxPXHDocGa8y5LLkvfVoekUMrl/uJ
         DFjKHJr68E3vd8iWPexEQLrsIJT4cZlZ8uSnl4LC026aLTDytRM6nCWcQwG4rvFQFB9y
         ROyj9qch83/FLBoUCYf8UWcuZcc2SV9cIFLHCs/tLwG71rF5HXmijidk5pXdc1Uu0LCi
         CG9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726037146; x=1726641946;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bVP37iqvNOpJ2C4azkrWMhWHlyw3amrbbhDMwVKwFZo=;
        b=KSo65igH/53logCadslkqphHb7JnyDE81yN7kmdGmYcETEtYgVKpJwiirJfZe46VI7
         dIe7Ae2J2qgId+PVA/fWmQhcd/cv2eg15R9y2qc8ghokVoyKVqGTqd7Z8FePIrZ3mgE5
         ueKCroLySIRFt0vDNk26h5rWJGMO//DLGOi641FYRvnHwUYeCvUgqtrJTrcEIXudHsoj
         mN3+biinNQNSpjJ87Abn7alEWuEADwDZTLZLx24UMZGvN8vtUpv2yDfsggxqEm1U1Ykl
         +8ysUSWmI9pZfj7bXTXls6Cx0Hl/ePrixHFdM+Z/pzLanyhlMtU3m37vu17WfLI0jC+7
         uYsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhmIa2wlu1codt6j/LdAwjxgEaKVXIvgP9N8Pih6bOm3rxKfefJarML5MaSUKntS6TJaJXQA==@lfdr.de
X-Gm-Message-State: AOJu0YxThFcHxr+goeA5x4vMalcDZxniyqPNfIA77uea5FgNq1O62RH9
	D2CNIblP3mnraNcPvhgXricOL6HxjUzHMo1dXUmRSwAPFh9gCWKf
X-Google-Smtp-Source: AGHT+IENW9unRt3rOGBW1bra+keaF25t+aLNY6okF9wsFoTMUhH6Iz02+JpNG/jvxXtjR3vHCypFIQ==
X-Received: by 2002:a17:90a:12ce:b0:2d3:c6dd:4383 with SMTP id 98e67ed59e1d1-2dad5019a89mr15968497a91.16.1726037145607;
        Tue, 10 Sep 2024 23:45:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c705:b0:2d8:d2c6:e0b8 with SMTP id
 98e67ed59e1d1-2dad2ef8278ls2690106a91.2.-pod-prod-04-us; Tue, 10 Sep 2024
 23:45:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYK9MZSU7ZEkkISBe4ydTLfKwdZux9jyLvQPp0iWjJs+a+MxC0MD4Po24GCrnzNQlTyhpvgDtMYAo=@googlegroups.com
X-Received: by 2002:a17:90a:77ca:b0:2d8:8ead:f013 with SMTP id 98e67ed59e1d1-2dad4efdfa9mr16596137a91.7.1726037144336;
        Tue, 10 Sep 2024 23:45:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726037144; cv=none;
        d=google.com; s=arc-20240605;
        b=TqgY141osiLTjgGLnRVs0jZVSg39mrbDVVVJaG7k584oWcGR50L18hVMBa6nRydtsn
         SyvVvO+fgIau+6HaNmHk+5xLJPwfEYhT+jhK3BqAF1O6qRkumnOIFUv7wjL2OCromQ0B
         HzXhIjzh73xHpG/6o2vHe3WQ5T65mBxMqylskZn8PwKwg5SMdYJrUT3e33wlXd20vEce
         xMz6VFuGEdK8utKT8H1at2tVhzMeBFNuPIXnw+W4ZgX8yjnADNKM9Sw/nqtk2Q1gxHCn
         3m6nNyM8wRQevbzODfFR2wSzpNNfX5QIha/wGeq2pWj6Ds6hXX9zrYzkjNaNJ8jaPh7R
         g7Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ygW2h7ODlwmBx5yTCoi5Gmf0Sb0T4upnchiSqJUdeTg=;
        fh=Xs830Dl/dg7cBD7Cjxi4zgG6B28PocXmmZIfDH/IGEM=;
        b=aGvA+Dz/WoZbWuv7/LAK6vVGfom2hDAWIpk14FiSDYz41akPdrVlGVd1hbLkO/QuUy
         uC0R5y/Ui87bUSIj+Bqp3F2koG0xdWy9IVZWlpJK/h5DqKW+UUuHhacbN9oLcnyUEGUI
         THUMjgevS0hE1FG15IhEeUy4k/uxGKdcf0h9FzvigCiwrH9UmISGIs/6N1YiF46/bNDF
         wPn/qGoB/viUy+nycGhbLuPMcRAGN5fAZfydabYTThvh+PekjBXn2koBy6Kq3O8sIjpk
         9Ld9avk4G5v8mFv0Dfh7gPgYk4Bw4qMB3FfhSKdRITkPpR4+2JCfYP/em81o32N9pcj0
         8K9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XR35QEpx;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2db6c1a8676si151045a91.0.2024.09.10.23.45.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 23:45:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: TBfl5tgJQe6TDHyKmxSAeg==
X-CSE-MsgGUID: p4YFUs6eSYOofz79+hbKHQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="36172956"
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="36172956"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 23:45:40 -0700
X-CSE-ConnectionGUID: 7FRSoTDrQNOS2pFrzeWgDA==
X-CSE-MsgGUID: dO/k+wvZRJCKQ0Bk9A0CJQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="67771470"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa007.jf.intel.com with ESMTP; 10 Sep 2024 23:45:36 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when orig_size is enabled
Date: Wed, 11 Sep 2024 14:45:30 +0800
Message-Id: <20240911064535.557650-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=XR35QEpx;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Danilo Krummrich's patch [1] raised one problem about krealloc() that
its caller doesn't pass the old request size, say the object is 64
bytes kmalloc one, but caller originally only requested 48 bytes. Then
when krealloc() shrinks or grows in the same object, or allocate a new
bigger object, it lacks this 'original size' information to do accurate
data preserving or zeroing (when __GFP_ZERO is set).

Thus with slub debug redzone and object tracking enabled, parts of the
object after krealloc() might contain redzone data instead of zeroes,
which is violating the __GFP_ZERO guarantees. Good thing is in this
case, kmalloc caches do have this 'orig_size' feature, which could be
used to improve the situation here.

To make the 'orig_size' accurate, we adjust some kasan/slub meta data
handling. Also add a slub kunit test case for krealloc().

This patchset has dependency over patches in both -mm tree and -slab
trees, so it is written based on linux-next tree '20240910' version.

[1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/

Thanks,
Feng

Changelog:

  Since v1:
  * Drop the patch changing generic kunit code from this patchset,
    and will send it separately.
  * Separate the krealloc moving form slab_common.c to slub.c to a 
    new patch for better review (Danilo/Vlastimil)
  * Improve commit log and comments (Vlastimil/Danilo) 
  * Rework the kunit test case to remove its dependency over
    slub_debug (which is incomplete in v1) (Vlastimil)
  * Add ack and review tag from developers.

Feng Tang (5):
  mm/kasan: Don't store metadata inside kmalloc object when
    slub_debug_orig_size is on
  mm/slub: Consider kfence case for get_orig_size()
  mm/slub: Move krealloc() and related code to slub.c
  mm/slub: Improve redzone check and zeroing for krealloc()
  mm/slub, kunit: Add testcase for krealloc redzone and zeroing

 lib/slub_kunit.c   |  42 +++++++++++++++
 mm/kasan/generic.c |   7 ++-
 mm/slab.h          |   6 +++
 mm/slab_common.c   |  84 ------------------------------
 mm/slub.c          | 125 ++++++++++++++++++++++++++++++++++++++-------
 5 files changed, 160 insertions(+), 104 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240911064535.557650-1-feng.tang%40intel.com.
