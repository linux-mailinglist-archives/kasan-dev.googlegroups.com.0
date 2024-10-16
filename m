Return-Path: <kasan-dev+bncBDN7L7O25EIBBR55X64AMGQEGTJZL7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id D7D4C9A0EB3
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:42:00 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-46089122a64sf20341381cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 08:42:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729093319; cv=pass;
        d=google.com; s=arc-20240605;
        b=EBCrMUVWFPq2RXQkS8zHM9xG4XC89G8MKwyAWGTqHRkkJ3+b0j66EByiwGfC8ZEzlU
         WZm078zZuVsLsjy2zNvbJ5p9r4F1N2ia0ndtpuOweLBmyKNa9XGSogaBwkpfnUT55HI+
         s/IbtrSx3ygY6tcS4fNuH9+DjPqXkbgIPxNFfdlMEvIklt6/Dr6k8F28Cs2Uyqi13zSW
         1TUauGvdrjgOU6xxi+RU35nL7cTW/j7OIlBkdAifUxbHXsQpSpe7QE7zK8sa2cda7nxU
         RWQMbVNHyyxQD8DVbKfIB+aVmlpMqLt+wIryNEB2D8uX0O/BzjRjY1uM4D0wdxhHvROS
         qkSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XSgYNlVs1fAtO9Jl1zcKJdz1/i2212jXZkUD2tOEEN4=;
        fh=Vr9SRFbY4hDwj+VVD3DbeDYM/MOM9R6vO9tSKqwCgSY=;
        b=c2vETzPd27Sq8QuYsGjNo+uXQWeTfU2jZSgs39Z9tEaqiY2zShGmFmIPcQ0DzB701H
         S5YD2QBBrB0fK0uLsTtEatBwDI4hqxf2o7Pm+MYuxzBtSPhI2ZCpCfaaE3ZBQOfQcNQ4
         PZC9B7M/ylx4PYKLkFOQBH3D/IQvHQqtgd5l0UshS4SZXUf+XrptfeQP03YIEIojSON0
         Qcynamgc2wfqgjl9NSCNHNm3CR/pxbHMavFth/MDVVL4DHPKdtaEQs91maqBOyQIK9FA
         Fn4tl5BVEW2bR6WjwgSYCq7D3B6NVv3wSaLeAyqa+wN/B69K6Py3zGRNN6DEHwW/t2q/
         c40A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="daQwXQP/";
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729093319; x=1729698119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XSgYNlVs1fAtO9Jl1zcKJdz1/i2212jXZkUD2tOEEN4=;
        b=wPpkHXlJlq53Sevc3fg0dr/GPCDUEbk8oOj3oeZEvuaIDvGuq0ivG3rvd7pPCZGjSO
         cmR/w0xuSy+wcVN0aVSmZMWxATl0uPQAwwFsHaZT5FNeqOl7hpwGnDd1Cb+SNmQ/UgLP
         BRLcXZGEnqFSsLcsuCSGpDJ3COmcgGSvCfFnwPxldAXcs3qRP3ZV0m1gAW18Ck4fcO86
         HhbKYKNpbcITU6AZHZr2ZfhwnrD3sfIpHszmeM8m3EPyoe9xWTUpDt/PijerFGRCghYa
         MNDWeiFHSImA+UREQbZRkkCmXNlB484Hd3o8wpTAvApoZzdHwBuD3wfmifUEESYe+/RI
         62jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729093319; x=1729698119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XSgYNlVs1fAtO9Jl1zcKJdz1/i2212jXZkUD2tOEEN4=;
        b=A1L8gbnkIhWzE1aLQPf9fDIiaWZlMV9E132IdEv3GaTkNlo33wKDH6l24bGZVscthp
         Tm/TC4rIiISj3VleM94Q4tSyt9oBuA1YBXCrKhyQGcYthIZ551pWtc6q43lLud9VBMGu
         TvsodqaFHj9AAzkp4FvMTMOmNLvynIPd8ek4J/aCJq2vEY/fO9n4wn2Ohw6p8V1t4QQR
         u2FHTam/dXMBrC+oo4I5PYhREPklpCudlr+WnlAmCioeE20yYTiscYdFpUEitFG0HR4c
         OeIhGJrfWNCFHEekrxN+s7OU3qdhd7gIg7QZoCFkBUA+LpnJCV+A51Egv4BqWhDSKfm5
         4jmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFBh2CdmFDGPmVeQ2NkpQ0wrn61Hu1Rn3GpAiVrhczqnyxvnpjkKKoQj9opo65JnDCka66hQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzw5rowU1pFzcKWuPyC+C+Y6CxoFiOCwb7ktRy23rZRvZWqrPkz
	Z/mLzO/Xt0QgiqHdCbMlCaZvHrZoroFW8Fsqmdsga2f3HXSUUlV0
X-Google-Smtp-Source: AGHT+IFpxQ63R135LmGZ7+HqshUjQbT2cltFmxGJDK/h1OKpLP5zerQFZdU2Baa3SrXjoeLva3yxZw==
X-Received: by 2002:ac8:7f93:0:b0:45f:67c:1eba with SMTP id d75a77b69052e-4604bb95f9bmr278333431cf.11.1729093319333;
        Wed, 16 Oct 2024 08:41:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c53:0:b0:458:2aac:e50d with SMTP id d75a77b69052e-4609b47ac91ls33381cf.0.-pod-prod-01-us;
 Wed, 16 Oct 2024 08:41:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVh3jeU8Lr5S6dH8EnhipBLFeSG/NOeBLqgxd4YdtAeNXTMCG4I3JQg0bDBpoK6ZG2Ro3O3vAs0RKA=@googlegroups.com
X-Received: by 2002:a05:6102:d8c:b0:4a4:8a29:a8f8 with SMTP id ada2fe7eead31-4a48a29ae3amr10894587137.2.1729093318633;
        Wed, 16 Oct 2024 08:41:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729093318; cv=none;
        d=google.com; s=arc-20240605;
        b=P+CGp+ua+8iNyh2xdP4ZyrNKcnFdSdYM9ZlCq4R3RuAmno4s3ITqFVwUPmBekPymDk
         7Zzy7BaC70skafy4L+x6aEYrC9EbMpVc/eP3YFqtPN35naifhV8Sd1/Q0IQXhBfBh9lh
         eq9njDP27/4R/7WLHjddednHCA5ErRskQg1cKy2McUtJ2X7o9oMJlpyBK+ImuhbupvUr
         at9Zsx/3JuKQTN5lP3ZDZI0t2wJIG957FG5wT5Ls8MCNxrN0IyFNN7k/BP46GOb3xlK+
         3YN5DMx6zXLZPTRJO9HF+j2Js08n3Q30pQ9b6jWWldGMw6DL07O/6XYG91mMMfLQ5ZRH
         x4Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dgmN9NQot3rIqBZ76hf4jeaZaZSf/C6kNIIS6FtSwZY=;
        fh=7lbPjXPBrR8dSgG7ysvKWnMIE29dr8yWrocKYwe0ENg=;
        b=P78L835JYzkR48c+G6+VkSW9tUsPRUZUs73DkVpiIIm7zb8CRMJhusRvvgkc8E/jHV
         CURODWx+2XzRpo3X6MIeomvVzIp8H4PWeMOkRy8hMsMrYza2YsDlgKOFwxsyPS3BmCFV
         DhfGXs8Uj/RvagxVR3lNfG75T2xFSDzC4LPMFBvl8vhGEY47G1CajiHgV6565ROzJ1rB
         xsJ5eeNjctd1DVD9NkOeVOICxQLg4RBVDt37zp7SmGSz2+GnQF3JS0nxNO9/owedSuLj
         HlU599xlQ+YfUfsYcThRx+2bxPN52t1EDqOyEnWljxWSKQzyw79fFPSddp77mQfw+mub
         o6Ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="daQwXQP/";
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a5acc321fbsi175313137.2.2024.10.16.08.41.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Oct 2024 08:41:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: TAFPmyN9QxOMxIyEMsLgow==
X-CSE-MsgGUID: hxp4Dyq/S3S5oSGzKkHLyQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11222"; a="46021331"
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="46021331"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Oct 2024 08:41:57 -0700
X-CSE-ConnectionGUID: Hg18HRddRDSTDV4mNZenXA==
X-CSE-MsgGUID: Ej/vS7TOQlqpQHn2zNunUQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,208,1725346800"; 
   d="scan'208";a="109018894"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by fmviesa001.fm.intel.com with ESMTP; 16 Oct 2024 08:41:53 -0700
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
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Narasimhan.V@amd.com
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v3 0/3] mm/slub: Improve data handling of krealloc() when orig_size is enabled
Date: Wed, 16 Oct 2024 23:41:49 +0800
Message-Id: <20241016154152.1376492-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="daQwXQP/";       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as
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

Many thanks to syzbot and V, Narasimhan for detecting issues of the
v2 patches.

This is again linux-slab tree's 'for-6.13/fixes' branch

[1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/

Thanks,
Feng

Changelog:

  Since v2:
  * Fix NULL pointer issue related to big kmalloc object which has
    no associated slab (V, Narasimhan, syzbot)
  * Fix issue related handling for kfence allocated object (syzbot,
    Marco Elver)
  * drop the 0001 and 0003 patch whch have been merged to slab tree

  Since v1:
  * Drop the patch changing generic kunit code from this patchset,
    and will send it separately.
  * Separate the krealloc moving form slab_common.c to slub.c to a 
    new patch for better review (Danilo/Vlastimil)
  * Improve commit log and comments (Vlastimil/Danilo) 
  * Rework the kunit test case to remove its dependency over
    slub_debug (which is incomplete in v1) (Vlastimil)
  * Add ack and review tag from developers.



Feng Tang (3):
  mm/slub: Consider kfence case for get_orig_size()
  mm/slub: Improve redzone check and zeroing for krealloc()
  mm/slub, kunit: Add testcase for krealloc redzone and zeroing

 lib/slub_kunit.c | 42 +++++++++++++++++++++++
 mm/slub.c        | 87 +++++++++++++++++++++++++++++++++++-------------
 2 files changed, 105 insertions(+), 24 deletions(-)

-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016154152.1376492-1-feng.tang%40intel.com.
