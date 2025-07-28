Return-Path: <kasan-dev+bncBC4LXIPCY4NRBUW6T7CAMGQEMLFULBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C38FB14401
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 23:44:52 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3b604541741sf3192414f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 14:44:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753739092; cv=pass;
        d=google.com; s=arc-20240605;
        b=QPUO08yLGN4f17wOZ8qazkUomB0Lagi+WRjgGkIMmJKdim+xaflh0LMQ4Dp1pv925c
         ye2b86O8y4sk01tiCBY3PtQeN8u4db4nmXOjIiF4BzC/YVhwoaDPEapJiL6CQVhkFVDk
         Pj1Rb3/LeaqW4cSDLtoX8VVDNi4WsKCyP23kj9Jrk0x49VE4jO6hJABOaqKKsLyhDha4
         1mAuUWp9hAP02R4a5GTtxNskMfDCCNpTboIrgONyh+tonHImBa+eJ60SHUybIYmC6Nzb
         RrFAH8obvcSAhUVNe9IK7ge0MDXLvWnmsNqMTE63eyRXH+5vRLtEPUlnA7ghLrtuO3p9
         ATug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zbFWOCF09iDizSHXfxD2ZD9DJsfQxGrat3hbjDC2In8=;
        fh=/gmKOJO3A6e47bpSD8NOTE0aJbfeP9usakcb3gpevaE=;
        b=U5DGH3u0Fh595XONI4+5Ti8Y9mKxm6JQfdP3Pmoyyvwd92atAMcfxR222bkb29Eyjt
         LYjWJuw0NuK31rsGoYZHXVA3tuEoEJfVy1H6bz/4y5VCl3U1OarDxxd+gDcVs0B1hE/0
         90Ju3XXHyQIX8Xr21JLYx0WcS+t866MwtZI0NFsVZku+/RBcmVq6gVgTzsX4VVfH8Ccj
         hQqeVLJYyVydyPHyoOFT6eDTK6OtjI4OxZ76lzibK5xQKORgH7R1puz6U4Q3tmw/k8Ac
         vDPVtKGxOTlCSsTD/zQINt5VtQ8qS6VL2u/6t1eel/AkEIHr8uZakjWqGLac4ZWHp+DF
         +ucQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lCNW0qRW;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753739092; x=1754343892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zbFWOCF09iDizSHXfxD2ZD9DJsfQxGrat3hbjDC2In8=;
        b=dqPGP0CC2jv1KIIAfBxrsMfQQlxbUwoiP9HAG6A2eexZZBlD9ywhHqurkl3UJ9UdQh
         TjiSvv1Hk+e52o0+cwMhbgU3gZrpxYEtXM3eVZyoogQQ2cQa0FQ0MTv0XO6bvOf20VDq
         70PhbpzcX71J09/0rUgFhJDhfmR2hY1nCD95DT83EvHjq4/IqK9wLKgUuSdcbyWzpkjI
         e9D8cG66L3I+eCo6i2xosMSzxxciYxEwGENQbpJtAu1DDVHNtdEn+jUHMPDk6nTHYgLk
         7ctz7unBshR0KhyvOI+Ir6vtrTAzYH2kEE2aPO8OVD3pwS5wkYkOU8tbDaMTEfkaIihw
         ZEDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753739092; x=1754343892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zbFWOCF09iDizSHXfxD2ZD9DJsfQxGrat3hbjDC2In8=;
        b=qmEl6g82BHAUMiegVr6vrBASSbpt0hcscgokMXuuZufnTPoaT0L0ERCy1EtnX7hRG+
         FBAwWee/66FsAk4VvVkPMvOITtAJmkosWnl58YQsoxwtfi3LXO55rvXkbn3xIdxaHoUL
         ckhVCrRouDZA7cMeyWET2NUxuPByTWjFGJbdSmIRPkJn3O7sRMxG5K3Z6nSrthYmpjKV
         rqsiWlJJ6tNxeY9oRiWAcgw9Av3OSrCfbaCoHpj/WFWch+IOtr+JO8UK9E9fExy1X31M
         CA+9dAcWOYVbGyKWKXmjLP6q4vsixfmwZe1JEgSmGflmw810t8Pwq/XOv8WLxV+/lDyc
         Kxfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGG/G5B/bEzstXu+9X91dEFYWtrDhxnfGd5IQAzX3IFE2g1y4ofppNI+t7+K4nP0Vcn/wNRw==@lfdr.de
X-Gm-Message-State: AOJu0Yyi8hd3O3vT4BHY1Qe/1n+pkachHnSkrVKAd74yoWlbA5DzwcaR
	8Ey+ePeinG/ErCrn6Zl8uzyby29ANu5Vz5DoxKNFPbqGEYQDSjXeimu2
X-Google-Smtp-Source: AGHT+IH+9ZfKentT83tOTBHr6pHpKGkjzvARzEeBg5pNrW0dWMZrjNzrPiHicc7l4u7S/z7wTz9gGQ==
X-Received: by 2002:a5d:64ef:0:b0:3b7:817e:489d with SMTP id ffacd0b85a97d-3b7817e4a3cmr7397789f8f.21.1753739091194;
        Mon, 28 Jul 2025 14:44:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf3VO4XGnD+hhVtm+aqjAeTD2mguQ/GGCh1CUljfO7GMA==
Received: by 2002:a05:6000:430d:b0:3a5:89d7:ce0d with SMTP id
 ffacd0b85a97d-3b76e357270ls2057151f8f.0.-pod-prod-09-eu; Mon, 28 Jul 2025
 14:44:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtaZSPk2QHt6QN4bksBxrTCUTZRsvByYj2J3i1/vQyu5zo8PIlacetMCf59+s2qY2F56rHo8BKEls=@googlegroups.com
X-Received: by 2002:a05:6000:2912:b0:3b7:8abc:eba2 with SMTP id ffacd0b85a97d-3b78abcec94mr2937046f8f.20.1753739088350;
        Mon, 28 Jul 2025 14:44:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753739088; cv=none;
        d=google.com; s=arc-20240605;
        b=lKlO8A6iXNJ9nrwszRgkkON76sMzASgvbPZD9/1iHL5CvGGDRXo7k/JNrSEXHHSuO1
         HAlY0IYizF9Cxd/w/Vz29+VKeYHQnGp9oOuVRRkWxD5ihnYycXP846FGYLsWnv4OJ4gh
         iO7G0vAqt3Tars+kE4L2lBG/MODl9r4l/rQMfGm5I27yqfKq/CkgrwXMwYffl7I2YhC3
         LW5bvj+0TVLdVSprM3iIg2wZu1iA43ckLJxevkAu5HkwyIApAoGuOWjvHBbt2S4Fz2Y9
         XTiuwThoA+9w5djYI9dia2MuT/DumNjjjT7fheB8dighQri+pVPBoRDcQ5fzC3MqBHB3
         ad4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=g+Vx1WIV1p7F/AJ5QOgtYYg75xDa+1YjXfDcHgk+9Og=;
        fh=++CctvY9Az6vAmU7ll8eijH7dmu13rfHxEObLf/3+3M=;
        b=kqV9HlxUusterysJckFl9lLjIac4vCvPSKRfzX6/vuXfuVcp7GnPAAveokGpc2rfLd
         WEW+VbhfuUGNtu0Y+F0SYU6e2bLa5Gtul1oAuU/lEjqCfoayqKLOQpf+DwKDNeRdrU3q
         gguwafJFjQJM2qTbo4g+FGVWTMvai7Il+W5a2Yp4Al/yJ2AJ8uxGIY3cUPs6Wd4f2JoR
         +csX8ZHVLaemdyFyoSk3Yr5P7S68z4zH9Ycs8gwqzZ/jVop1qVxf7VDUlCzND2J6Ojly
         w5c+D/Jf3KrJxzd9gSUpR+xVxPgaxRmX+FR4Uuv8uALPBCFJu5rb7+N3TDta3aaVXdLF
         erjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lCNW0qRW;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588dd3fe52si37445e9.1.2025.07.28.14.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 28 Jul 2025 14:44:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 4gsSTKIfRyGF2gscqPYkVA==
X-CSE-MsgGUID: O1wisKx2TVG1FZCoFwNYUQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11505"; a="43606625"
X-IronPort-AV: E=Sophos;i="6.16,339,1744095600"; 
   d="scan'208";a="43606625"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Jul 2025 14:44:45 -0700
X-CSE-ConnectionGUID: apQAazL7Qom6OVLQX+vKoA==
X-CSE-MsgGUID: oSDJo8H4SXSN+NFJl2n3sA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,339,1744095600"; 
   d="scan'208";a="186170375"
Received: from lkp-server01.sh.intel.com (HELO 160750d4a34c) ([10.239.97.150])
  by fmviesa002.fm.intel.com with ESMTP; 28 Jul 2025 14:44:43 -0700
Received: from kbuild by 160750d4a34c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1ugVeC-0000mR-1S;
	Mon, 28 Jul 2025 21:44:40 +0000
Date: Tue, 29 Jul 2025 05:44:19 +0800
From: kernel test robot <lkp@intel.com>
To: Dishank Jogi <jogidishank503@gmail.com>, elver@google.com
Cc: oe-kbuild-all@lists.linux.dev, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	rathod.darshan.0896@gmail.com,
	Dishank Jogi <jogidishank503@gmail.com>
Subject: Re: [PATCH] kcsan: clean up redundant empty macro arguments in
 atomic ops.
Message-ID: <202507290502.vaOga5pZ-lkp@intel.com>
References: <20250728104327.48469-1-jogidishank503@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250728104327.48469-1-jogidishank503@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lCNW0qRW;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.16 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

Hi Dishank,

kernel test robot noticed the following build errors:

[auto build test ERROR on linus/master]
[also build test ERROR on v6.16 next-20250728]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Dishank-Jogi/kcsan-clean-up-redundant-empty-macro-arguments-in-atomic-ops/20250728-184659
base:   linus/master
patch link:    https://lore.kernel.org/r/20250728104327.48469-1-jogidishank503%40gmail.com
patch subject: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
config: x86_64-buildonly-randconfig-002-20250729 (https://download.01.org/0day-ci/archive/20250729/202507290502.vaOga5pZ-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250729/202507290502.vaOga5pZ-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202507290502.vaOga5pZ-lkp@intel.com/

All errors (new ones prefixed by >>):

>> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1270 | DEFINE_TSAN_ATOMIC_OPS(8);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1271 | DEFINE_TSAN_ATOMIC_OPS(16);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1272 | DEFINE_TSAN_ATOMIC_OPS(32);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
>> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~             
   kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
    1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
         | 
   kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
    1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
         |         ^~~~~~~~~~~~~~~~~~~~~~
   kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
    1274 | DEFINE_TSAN_ATOMIC_OPS(64);
         | ^~~~~~~~~~~~~~~~~~~~~~
   cc1: some warnings being treated as errors


vim +/DEFINE_TSAN_ATOMIC_RMW +1270 kernel/kcsan/core.c

0b8b0830ac1419 Marco Elver      2021-11-30  1169  
0f8ad5f2e93425 Marco Elver      2020-07-03  1170  #define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
0f8ad5f2e93425 Marco Elver      2020-07-03  1171  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
0f8ad5f2e93425 Marco Elver      2020-07-03  1172  	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
0f8ad5f2e93425 Marco Elver      2020-07-03  1173  	{                                                                                          \
0b8b0830ac1419 Marco Elver      2021-11-30  1174  		kcsan_atomic_builtin_memorder(memorder);                                           \
9d1335cc1e97cc Marco Elver      2020-07-24  1175  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
55a55fec5015b3 Marco Elver      2021-08-09  1176  			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
9d1335cc1e97cc Marco Elver      2020-07-24  1177  		}                                                                                  \
0f8ad5f2e93425 Marco Elver      2020-07-03  1178  		return __atomic_load_n(ptr, memorder);                                             \
0f8ad5f2e93425 Marco Elver      2020-07-03  1179  	}                                                                                          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1180  	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
0f8ad5f2e93425 Marco Elver      2020-07-03  1181  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
0f8ad5f2e93425 Marco Elver      2020-07-03  1182  	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
0f8ad5f2e93425 Marco Elver      2020-07-03  1183  	{                                                                                          \
0b8b0830ac1419 Marco Elver      2021-11-30  1184  		kcsan_atomic_builtin_memorder(memorder);                                           \
9d1335cc1e97cc Marco Elver      2020-07-24  1185  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
9d1335cc1e97cc Marco Elver      2020-07-24  1186  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
55a55fec5015b3 Marco Elver      2021-08-09  1187  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
9d1335cc1e97cc Marco Elver      2020-07-24  1188  		}                                                                                  \
0f8ad5f2e93425 Marco Elver      2020-07-03  1189  		__atomic_store_n(ptr, v, memorder);                                                \
0f8ad5f2e93425 Marco Elver      2020-07-03  1190  	}                                                                                          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1191  	EXPORT_SYMBOL(__tsan_atomic##bits##_store)
0f8ad5f2e93425 Marco Elver      2020-07-03  1192  
0f8ad5f2e93425 Marco Elver      2020-07-03  1193  #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
0f8ad5f2e93425 Marco Elver      2020-07-03  1194  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
0f8ad5f2e93425 Marco Elver      2020-07-03  1195  	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
0f8ad5f2e93425 Marco Elver      2020-07-03  1196  	{                                                                                          \
0b8b0830ac1419 Marco Elver      2021-11-30  1197  		kcsan_atomic_builtin_memorder(memorder);                                           \
9d1335cc1e97cc Marco Elver      2020-07-24  1198  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
14e2ac8de0f91f Marco Elver      2020-07-24  1199  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
9d1335cc1e97cc Marco Elver      2020-07-24  1200  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
55a55fec5015b3 Marco Elver      2021-08-09  1201  					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
9d1335cc1e97cc Marco Elver      2020-07-24  1202  		}                                                                                  \
0f8ad5f2e93425 Marco Elver      2020-07-03  1203  		return __atomic_##op##suffix(ptr, v, memorder);                                    \
0f8ad5f2e93425 Marco Elver      2020-07-03  1204  	}                                                                                          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1205  	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
0f8ad5f2e93425 Marco Elver      2020-07-03  1206  
0f8ad5f2e93425 Marco Elver      2020-07-03  1207  /*
0f8ad5f2e93425 Marco Elver      2020-07-03  1208   * Note: CAS operations are always classified as write, even in case they
0f8ad5f2e93425 Marco Elver      2020-07-03  1209   * fail. We cannot perform check_access() after a write, as it might lead to
0f8ad5f2e93425 Marco Elver      2020-07-03  1210   * false positives, in cases such as:
0f8ad5f2e93425 Marco Elver      2020-07-03  1211   *
0f8ad5f2e93425 Marco Elver      2020-07-03  1212   *	T0: __atomic_compare_exchange_n(&p->flag, &old, 1, ...)
0f8ad5f2e93425 Marco Elver      2020-07-03  1213   *
0f8ad5f2e93425 Marco Elver      2020-07-03  1214   *	T1: if (__atomic_load_n(&p->flag, ...)) {
0f8ad5f2e93425 Marco Elver      2020-07-03  1215   *		modify *p;
0f8ad5f2e93425 Marco Elver      2020-07-03  1216   *		p->flag = 0;
0f8ad5f2e93425 Marco Elver      2020-07-03  1217   *	    }
0f8ad5f2e93425 Marco Elver      2020-07-03  1218   *
0f8ad5f2e93425 Marco Elver      2020-07-03  1219   * The only downside is that, if there are 3 threads, with one CAS that
0f8ad5f2e93425 Marco Elver      2020-07-03  1220   * succeeds, another CAS that fails, and an unmarked racing operation, we may
0f8ad5f2e93425 Marco Elver      2020-07-03  1221   * point at the wrong CAS as the source of the race. However, if we assume that
0f8ad5f2e93425 Marco Elver      2020-07-03  1222   * all CAS can succeed in some other execution, the data race is still valid.
0f8ad5f2e93425 Marco Elver      2020-07-03  1223   */
0f8ad5f2e93425 Marco Elver      2020-07-03  1224  #define DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strength, weak)                                           \
0f8ad5f2e93425 Marco Elver      2020-07-03  1225  	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1226  							      u##bits val, int mo, int fail_mo);   \
0f8ad5f2e93425 Marco Elver      2020-07-03  1227  	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1228  							      u##bits val, int mo, int fail_mo)    \
0f8ad5f2e93425 Marco Elver      2020-07-03  1229  	{                                                                                          \
0b8b0830ac1419 Marco Elver      2021-11-30  1230  		kcsan_atomic_builtin_memorder(mo);                                                 \
9d1335cc1e97cc Marco Elver      2020-07-24  1231  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
14e2ac8de0f91f Marco Elver      2020-07-24  1232  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
9d1335cc1e97cc Marco Elver      2020-07-24  1233  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
55a55fec5015b3 Marco Elver      2021-08-09  1234  					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
9d1335cc1e97cc Marco Elver      2020-07-24  1235  		}                                                                                  \
0f8ad5f2e93425 Marco Elver      2020-07-03  1236  		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
0f8ad5f2e93425 Marco Elver      2020-07-03  1237  	}                                                                                          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1238  	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
0f8ad5f2e93425 Marco Elver      2020-07-03  1239  
0f8ad5f2e93425 Marco Elver      2020-07-03  1240  #define DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)                                                       \
0f8ad5f2e93425 Marco Elver      2020-07-03  1241  	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
0f8ad5f2e93425 Marco Elver      2020-07-03  1242  							   int mo, int fail_mo);                   \
0f8ad5f2e93425 Marco Elver      2020-07-03  1243  	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
0f8ad5f2e93425 Marco Elver      2020-07-03  1244  							   int mo, int fail_mo)                    \
0f8ad5f2e93425 Marco Elver      2020-07-03  1245  	{                                                                                          \
0b8b0830ac1419 Marco Elver      2021-11-30  1246  		kcsan_atomic_builtin_memorder(mo);                                                 \
9d1335cc1e97cc Marco Elver      2020-07-24  1247  		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
14e2ac8de0f91f Marco Elver      2020-07-24  1248  			check_access(ptr, bits / BITS_PER_BYTE,                                    \
9d1335cc1e97cc Marco Elver      2020-07-24  1249  				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
55a55fec5015b3 Marco Elver      2021-08-09  1250  					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
9d1335cc1e97cc Marco Elver      2020-07-24  1251  		}                                                                                  \
0f8ad5f2e93425 Marco Elver      2020-07-03  1252  		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
0f8ad5f2e93425 Marco Elver      2020-07-03  1253  		return exp;                                                                        \
0f8ad5f2e93425 Marco Elver      2020-07-03  1254  	}                                                                                          \
0f8ad5f2e93425 Marco Elver      2020-07-03  1255  	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_val)
0f8ad5f2e93425 Marco Elver      2020-07-03  1256  
0f8ad5f2e93425 Marco Elver      2020-07-03  1257  #define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
0f8ad5f2e93425 Marco Elver      2020-07-03  1258  	DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
0f8ad5f2e93425 Marco Elver      2020-07-03  1259  	DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
c843b93f690ae6 Dishank Jogi     2025-07-28 @1260  	DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
c843b93f690ae6 Dishank Jogi     2025-07-28  1261  	DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
c843b93f690ae6 Dishank Jogi     2025-07-28  1262  	DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
c843b93f690ae6 Dishank Jogi     2025-07-28  1263  	DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
c843b93f690ae6 Dishank Jogi     2025-07-28  1264  	DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
c843b93f690ae6 Dishank Jogi     2025-07-28  1265  	DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
0f8ad5f2e93425 Marco Elver      2020-07-03  1266  	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
0f8ad5f2e93425 Marco Elver      2020-07-03  1267  	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
0f8ad5f2e93425 Marco Elver      2020-07-03  1268  	DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
0f8ad5f2e93425 Marco Elver      2020-07-03  1269  
0f8ad5f2e93425 Marco Elver      2020-07-03 @1270  DEFINE_TSAN_ATOMIC_OPS(8);
0f8ad5f2e93425 Marco Elver      2020-07-03  1271  DEFINE_TSAN_ATOMIC_OPS(16);
0f8ad5f2e93425 Marco Elver      2020-07-03  1272  DEFINE_TSAN_ATOMIC_OPS(32);
353e7300a1db92 Christophe Leroy 2023-05-12  1273  #ifdef CONFIG_64BIT
0f8ad5f2e93425 Marco Elver      2020-07-03  1274  DEFINE_TSAN_ATOMIC_OPS(64);
353e7300a1db92 Christophe Leroy 2023-05-12  1275  #endif
0f8ad5f2e93425 Marco Elver      2020-07-03  1276  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507290502.vaOga5pZ-lkp%40intel.com.
