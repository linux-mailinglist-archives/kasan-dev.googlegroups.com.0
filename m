Return-Path: <kasan-dev+bncBAABB3G24CPAMGQEJN7XXGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F823681BBB
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:49:49 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id o26-20020a2e9b5a000000b0028e4072ac58sf2682349ljj.15
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:49:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111788; cv=pass;
        d=google.com; s=arc-20160816;
        b=njuu39ggBeQxa9BFV1iYf94+OlBtTiy8QqVtZ3Te6tQlVQQOUqNNIwQqebQzxjNw+I
         y3RaWQw4CLFmNvMMCQaEqVyjIH67ulQYHA1W0dkWfcMT0Z+zaui+Hec5EGwrpr72SiO4
         +skViWDZq/pr8PZW5sShQOTu3Xa8Cz4ZTj2LlhOPAxmoASElSOCGbxujIFIBqOMSzKls
         f63I0pj1Cv77mrI8zDCkcbdHSQT86MtUO+1GB+uux3QhqP90wNTvLMziJDOP5w9JOmIk
         IutDdnLzDvr7GEeeTMfqnHTq+4gBKUxZTpg8r22ZFuF/KeDTdqCveWZYk68oXp9PlNTo
         C9zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/EqgSQ643YM7ZRZvZDG52xHdYM6qF0VKrzjrypYetno=;
        b=o+lrtTm+/ohajm3Jo904RQkVlRPaUHcTDHUAR/iSKfLG1lLKou/P3Z5kxho/OAuEpr
         4X/vvMEmNvMV3NiBhzNN7y75c7nLKO15ed28gbB/Y8jPo15WIDvcXhxQU85z7qdKItUH
         oK+xcR0rArgaf6US8cTV269UyyN4gLOTaVqKX/5rTpulvwL2leeuwLuV4klon4YNf9JU
         221hUgBIgmCrVrkKMM+VfPAbzeidLysiKC0SunmYn04a3BaYybggpwLMkqGQN1Scs4+Z
         yNBV3cg2oF3bkDxqx4Xdln4CseeDiTlJkZo6bs+Ri96AthuTRVUg99ySlkQbmFsj7fY5
         f6Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IjSdtAT7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.40 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/EqgSQ643YM7ZRZvZDG52xHdYM6qF0VKrzjrypYetno=;
        b=bvo5hdIAgSg3e1E0dzS8O7RcMq7OrVgGOZkEqb3Xyen5N15A++GsRdZykRB6oy9r4J
         +wIgzahAF/y6AsnTQ7vxDmoee8eLZLNzCPcDmnpIg5QarPNXYpIz0nnEOPZTCwCoAh7i
         yE7wzKEep/w4SBWajbGJ15/oOolem04MKKoYjG7Pm3iOZtUiXhYfe3UIITTBe6an0/VF
         jKxApjOW82zyaBMnI5KecPtYA7xkefakUAx7yPdGQ3FhzTvvPqSrcPTtd2oobAhOfH3N
         9ItuuAC99myyf7DacuQcz2vFIaO/11Hw4pZcV8pkjCURBJoQWBAyIchX8qGrzPxVbT1G
         YNVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/EqgSQ643YM7ZRZvZDG52xHdYM6qF0VKrzjrypYetno=;
        b=dfbkGBNtBSJU9fu0TI6NNVKbcY9yMmFnKWJX8zr7QA1AjRBb5P9p0IVGZClcadzLj1
         cQZF8WDwpImtUye4kjS4PVUyjVILdYhr0Nv3rTuGPif/sTzItJeZByTpp8GKnoC2VlF4
         22kBs8I7bvhS8TqPU8Rt7NjEV6oW0CnU1Cy8e+36dyIFSkjNjaim6S31tfpCPTpUaYad
         u527sMYWh9FcbfkYUfzmZkIaGF15wcAjLTqf0O6p9MqkuYMsGA9pkGfNTD/QVAwPVKFJ
         TD8Tyn/XuLT6nWBUYGdt3Kaj6VS44KS4Rv4RB3U/Qg3lApYTkU9fmSwhnWo/u79OkGZd
         jH5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpN73InOrOAkAZOmbZdg5dS6HKgKDU9NXDaNoW9R3J4Raip3Fl7
	wFYdz02nsq5/ty7m9jD3QSg=
X-Google-Smtp-Source: AMrXdXtR48+z48pw/wK0S3GYTQYGSlsPIkVG199XfpgCf7ndOtSgchk1GBHnpegK76tRpO/3eXK25w==
X-Received: by 2002:ac2:4ade:0:b0:4d0:7b7:65dc with SMTP id m30-20020ac24ade000000b004d007b765dcmr4047842lfp.122.1675111788515;
        Mon, 30 Jan 2023 12:49:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2117:b0:290:6f32:2e13 with SMTP id
 a23-20020a05651c211700b002906f322e13ls142429ljq.7.-pod-prod-gmail; Mon, 30
 Jan 2023 12:49:47 -0800 (PST)
X-Received: by 2002:a05:651c:203:b0:290:6150:4aee with SMTP id y3-20020a05651c020300b0029061504aeemr1488308ljn.22.1675111787285;
        Mon, 30 Jan 2023 12:49:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111787; cv=none;
        d=google.com; s=arc-20160816;
        b=VDepAw6U7RJSSIRqjkBQsVE9ksZbr+bI0bi38wLTjzgrGVjyiA2Wh6FzOsw4mCumGy
         eH1/DN3+984aVxQsiOt9XwDIBaBaTWYvr9FQNbya94BSBIyPyWmFzinrWrN2rkP+xPVi
         Ro2lUtH8/J8vZJr4RAttGK+vFSQFMPcU5veL5neZmRmB3qU6Ss0Lz1SItyX8tm3e7rC1
         PtIGXSeIKk7767Xf9ZYXzJ9DqwQs7vkuRCZUi+fnLPpJa7qy2G4M7Pta52JboTIqrJgC
         dkTr78CYPnJypRrIz2fGTPoy5z+9qa/FHqp4ppbjJHGPAL2Gy2AfWz0Tir1sXinldadU
         JUuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hkOxFb3yEq6h7w40h7f3LyAdThOsJZHxCl/P/Sxc7oQ=;
        b=gHbV7S9aJm+7CqPMF0tW3nBM+lH04KjAKgslgjuU9xEKEoI2x/+JzKDvkUeF+fQwTA
         XvI9HOuisUe7YP7MZNTGIZCWBiSIR/tl85unkoiRp8Qh20pXMuMeq5hk/bWitCLpYWHt
         124Enu+ifKM3t+XlNSCZtjTOdBbY4N170tAOBnMzvBHM0i3CxYN6kvdCe0LD+DG1SqQN
         HYPBVZXfJrHp5mTTH8mPjfPi8LVE8zJ1AVMH2SMkJ3jFcy2V8K1y4t0EufQuB2o1bsmJ
         in7AMC6lZ0oPzjElSKJ1kPL8CSiXjZrn/i14qMlCqyYVDpLT0KPN7byjpgTs07yP9+al
         5y3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IjSdtAT7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.40 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-40.mta1.migadu.com (out-40.mta1.migadu.com. [95.215.58.40])
        by gmr-mx.google.com with ESMTPS id f17-20020a2ea0d1000000b0028b731e8e20si715931ljm.1.2023.01.30.12.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:49:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.40 as permitted sender) client-ip=95.215.58.40;
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
Subject: [PATCH 00/18] lib/stackdepot: fixes and clean-ups
Date: Mon, 30 Jan 2023 21:49:24 +0100
Message-Id: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IjSdtAT7;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.40 as
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

A set of fixes, comments, and clean-ups I came up with while reading
the stack depot code.

The only fix that might be worth backporting to stable kernels is
in the first patch.

Andrey Konovalov (18):
  lib/stackdepot: fix setting next_slab_inited in init_stack_slab
  lib/stackdepot: put functions in logical order
  lib/stackdepot: use pr_fmt to define message format
  lib/stackdepot, mm: rename stack_depot_want_early_init
  lib/stackdepot: rename stack_depot_disable
  lib/stackdepot: annotate init and early init functions
  lib/stackdepot: lower the indentation in stack_depot_init
  lib/stackdepot: reorder and annotate global variables
  lib/stackdepot: rename hash table constants and variables
  lib/stackdepot: rename init_stack_slab
  lib/stackdepot: rename slab variables
  lib/stackdepot: rename handle and slab constants
  lib/stacktrace: drop impossible WARN_ON for depot_init_slab
  lib/stackdepot: annotate depot_init_slab and depot_alloc_stack
  lib/stacktrace, kasan, kmsan: rework extra_bits interface
  lib/stackdepot: annotate racy slab_index accesses
  lib/stackdepot: various comments clean-ups
  lib/stackdepot: move documentation comments to stackdepot.h

 include/linux/stackdepot.h | 152 +++++++--
 lib/stackdepot.c           | 628 ++++++++++++++++++-------------------
 mm/kasan/common.c          |   2 +-
 mm/kmsan/core.c            |  10 +-
 mm/page_owner.c            |   2 +-
 mm/slub.c                  |   4 +-
 6 files changed, 435 insertions(+), 363 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1675111415.git.andreyknvl%40google.com.
