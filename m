Return-Path: <kasan-dev+bncBDN7L7O25EIBBHM77G3AMGQETS6VRDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE24C970B31
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 03:30:06 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e1cefe6afc4sf7704841276.2
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 18:30:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725845405; cv=pass;
        d=google.com; s=arc-20240605;
        b=Prgyx/La1xCYm0G3viPWCFDRmLA7vcy/++R4sycdBmz2VDwVdwPgoNLQ0IMgDBXHEX
         HuLizqNiznDXHamHqdNjXwvQjgVMx3+Kh+yMDg78xCfBjXHQ5TDKNCdZY0ctYZnVXwG9
         Z8ax0mllorzg2Vr8tMKHuGWILpi0tfqPMYJCLnatJrfRFjlS2CPokdkILL9IJrJ4WJTv
         YRrvlXagmQlb9xP6manhhy4AefQHRWK5c3iZXBFAfAI41e6qST5BYOIpMGwNDxmaPTy+
         kz4Efhb5Y8nmVAzFPKW3DjlseQn5Rn9KOeYHAPJNxDPeY1LKZ9ikxhby4ad4aeg2JjLF
         nIBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YOgPt5zYPniLzu/w3tSPDxteOA5qPpfkLlMPKGS6GwQ=;
        fh=eGADPJRmqpvfFgnKPNk2hb9dgENW7N314zygCoDQ+98=;
        b=j8o1hUEgEIECWahQ0r3vHC9UOUEwq7uKa7M6sO0375rTPjzghDS2lnf3yAWMovVDFU
         ruzllM/O2vQ+B2huD3cLO1UYoFFkz26WV882+n1bmFbs2QXMKUQHcXNiGQoupDj3Fxt+
         FLTJ6f1jCOBzZ84Qg/YVSUIA4eHH2EKGVpPqIfKJqqlQOnDpX58Huqn1KX369u0CL+Cz
         3+z9pXjO3KNq+W7p9VGqWRpqRFNMJtlpNaUujWQ9qQpoLwr8izeikwALq28jJPJ4hKTu
         h9WhBrg1RKqbDyaRpxxr8x+UQGwOl9Y+C0PBwGmjlVr7uzh80CNH6U6o1wYdAgZfmhSJ
         YIkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="J4zH6Ck/";
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725845405; x=1726450205; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YOgPt5zYPniLzu/w3tSPDxteOA5qPpfkLlMPKGS6GwQ=;
        b=RhPNVP6D5gnZB/4zI7LrxImvNFMdTLUefOP7SD0NxwsxntQTeMbjlJTbzfpKTAHB/b
         4DRNwM0FXWmGXSyPBRx9r81k4RpSWTFQvm59ycxqTEYx3to4MvqMd0AbOKzSu+IC79PC
         rHhLJUaSdxMGpIWkn7bENF6hJAJrnNUiCkQgg2/Qu5GJZ8yOMnR8V2t1aXc7OK07zWJO
         QqgIehiWoAJaYthcPhV1Kx8J3Sgy1BiX9nbdqbP7+/kHz+Bgr+pK4c3A5YXUG/rvJysw
         ZeQ+Y7ZLT0yFia0wq4uw/wiIXUZ3NxBDPrvd62xXMODu7HLmWS13cnGPLwkjWfNsqzvH
         ICZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725845405; x=1726450205;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YOgPt5zYPniLzu/w3tSPDxteOA5qPpfkLlMPKGS6GwQ=;
        b=mg38cJypxjChru2SrOWR87a44EsxxXcbN2yAgE39UYYgELvcRKuUQktPXiQTW3h9fT
         clGH2hmwg7VHKfgqC+ORlCfTmGnxVUey5m1XY2Bq+Anszupzb4Jeo6LGmBk5zszoiVPD
         nTiLO/0CxWjFbtjJ2zT7X/qWnRE3HBJw5QpXfkhBgfJ7EysYtIL0TLO2D/OIf/sf7Ufn
         IFsS1sTv7haX5bIUk3JEk1wWl4I6QlMN3FhKwb02olpoXiJH3fCyEN/GLf9WrrvwdR0q
         5yCigKPfEN/QXT9FSC4Bj2lAXLN4NsxGDafEtSSPGLXynwQ/LmpaGQgDhLlx9IbhD1Fl
         q32w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqJnhRI1kx+8cpcNr4z4vazRtvXpzMqhQmKiuDLL0JewY9WfcUKmPOf4PlXPTrQVFayTrRow==@lfdr.de
X-Gm-Message-State: AOJu0YwTy5Q2tVoW8eI6GEmt29STuAQxXHaWCs73KshrDB/onV69SgsM
	U0Zw/9sjzCtmH8frwruGcX2mK3oTqT7taMysOvnGaBNKak2IO7PO
X-Google-Smtp-Source: AGHT+IG6QBc0an30sK2FpiQQatzyM9V+ZUuAfpRAcFinedqZ6L/mbT3HpB8BJ2Bl0BWTrkHZVLlzOQ==
X-Received: by 2002:a05:6902:274a:b0:e0b:ea37:9c1e with SMTP id 3f1490d57ef6-e1d3487f125mr10980743276.21.1725845405431;
        Sun, 08 Sep 2024 18:30:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f0c:0:b0:458:a6c:8071 with SMTP id d75a77b69052e-45814bfb77cls32193871cf.1.-pod-prod-04-us;
 Sun, 08 Sep 2024 18:30:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZv15ln4l+ZiyzZYbcMZh/Nsc+MiPOdMaKNxU2EpfNJ9HgK9v1Lht3iVnoEpd8HT/2IBiwgXTNA3I=@googlegroups.com
X-Received: by 2002:a05:620a:198a:b0:7a9:b308:64f with SMTP id af79cd13be357-7a9b3080a6emr434830285a.46.1725845404713;
        Sun, 08 Sep 2024 18:30:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725845404; cv=none;
        d=google.com; s=arc-20240605;
        b=YWsyMhT1ALPPpJTpN5nCSryXYDRTXQhMiw8k5bzr8IbyMt28+I9GGEuxq+fQgdRriI
         oOGWc2O0H2l2moFe+/UDtSA5BnXBfaskzPOfPd4xz6XmmKH9dRanphSE5r1hhXcSQDWr
         7CVVU9m5Z8zk5mVyEZZLIZpHv+yJqiPs4gXQPpdjvkpZk62n4+rKD86pLK1Nj9L0Uo0k
         RNo4clb/ajB6grMRij0jIU29TLSGtteD5n02PRuK8ffoA2TjPpXkZDaFlBiRBzlqxQ3b
         fryVAo+EmYcGQdabLZFkMUDkAJeX/LMlOyU8ZSR6X5STVkXAOA8cjxE/lB/ng2/fSMH5
         dgOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jKEXCRS/7Hh33W61G56jRGbQA05xRUYbsN8ZemhdwTI=;
        fh=DOrQZqwZ3gYiN8TxsTSOKms3YTEHds3R/56bZbzlpuk=;
        b=On8yYuv9C1uPmOzMMiGtXozf28BQLPkATyHZYTjKdxQKL+Mo2fYD8ao2KkVtRDYZs1
         CHTvIldmGU6+Xzkw1lwdZixOCfyAyCQuh1Ujrm7CjuPNewbR4GKX4C76IcAcXstbNIQ4
         roNnG4Gt+R9NDVZEljWalsbZIIP1Ec864U0b8HIPo4/jvGSbYuEREKZ8N0T9tnIzy9L7
         0OjAcHdfUX7aEkc9nhd1D55qOW0srrI846J8jQU0sa2uEjaNSLx3lO4TJGnX60a7Z/FI
         9gbsyqsWByhiJDm3KQkH4+Z9hVSu57KfgbTvW4N4DS5tDh2mLEdXnFVZJExyRrLfyWCL
         pOSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="J4zH6Ck/";
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a07571si13098485a.4.2024.09.08.18.30.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 08 Sep 2024 18:30:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: 8sq0YfqBTt6NIHWkYgEScQ==
X-CSE-MsgGUID: k9cRKdJURVm6iUpikbUmkA==
X-IronPort-AV: E=McAfee;i="6700,10204,11189"; a="28258085"
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="28258085"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2024 18:30:03 -0700
X-CSE-ConnectionGUID: SV4/OxYHS6GhuvQL9jNidA==
X-CSE-MsgGUID: WgxXmmB/SiuN1T0gsJyu7w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="66486421"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa009.jf.intel.com with ESMTP; 08 Sep 2024 18:29:59 -0700
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
	Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH 0/5] mm/slub: Improve data handling of krealloc() when orig_size is enabled
Date: Mon,  9 Sep 2024 09:29:53 +0800
Message-Id: <20240909012958.913438-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="J4zH6Ck/";       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as
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
its caller doesn't know what's the actual request size, say the object
is 64 bytes kmalloc one, but the original caller may only requested 48
bytes. And when krealloc() shrinks or grows in the same object, or
allocate a new bigger object, it lacks this 'original size' information
to do accurate data preserving or zeroing (when __GFP_ZERO is set).

And when some slub debug option is enabled, kmalloc caches do have this
'orig_size' feature. As suggested by Vlastimil, utilize it to do more
accurate data handling, as well as enforce the kmalloc-redzone sanity check.

To make the 'orig_size' accurate, we adjust some kasan/slub meta data
handling. Also add a slub kunit test case for krealloc().

This patchset has dependency over patches in both -mm tree and -slab
trees, so it is written based on linux-next tree '20240905' version.

[1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/

Thanks,
Feng

Feng Tang (5):
  mm/kasan: Don't store metadata inside kmalloc object when
    slub_debug_orig_size is on
  mm/slub: Consider kfence case for get_orig_size()
  mm/slub: Improve redzone check and zeroing for krealloc()
  kunit: kfence: Make KFENCE_TEST_REQUIRES macro available for all kunit
    case
  mm/slub, kunit: Add testcase for krealloc redzone and zeroing

 include/kunit/test.h    |   6 ++
 lib/slub_kunit.c        |  46 +++++++++++++++
 mm/kasan/generic.c      |   5 +-
 mm/kfence/kfence_test.c |   9 +--
 mm/slab.h               |   6 ++
 mm/slab_common.c        |  84 ---------------------------
 mm/slub.c               | 125 ++++++++++++++++++++++++++++++++++------
 7 files changed, 171 insertions(+), 110 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240909012958.913438-1-feng.tang%40intel.com.
