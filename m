Return-Path: <kasan-dev+bncBC4LXIPCY4NRB3XARHCQMGQE7L7ASGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 04087B295CE
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 02:14:40 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2445806eab4sf34109135ad.1
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 17:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755476079; cv=pass;
        d=google.com; s=arc-20240605;
        b=YAupRKesdmtB8XvndjO5/UsG2+2jzt+12MLPTLIjQfoCMl+19urqvZ0IPdcvdjxFbT
         ui3n2s8lgwdgCmFy2FwOU4fbfFyG1sBNqCmT2PyhRuGEew0CAO1spBxwhhlJtxvorIXP
         dGrRasd/EK+5WWjrU008jcAg48Q7R7BAUS3JRD8thEF0QIYP5A8CpH5Y+M+83bwvZYa7
         XMX4+NC2qKWdhnLR7WLJg/CMlZ+zHymwQT35MTexMCrqMTrSZqMXIQM2cqjWi54ylfmz
         L45A/og8GCayKEu3Xpf8Q//rk0fvIVzB/uYra6jFOcgyu7nI7110rW+MzhX3EQ9k9GKw
         IVpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KZq5vmvryayptn3HWrq5amrTtkCBSebJsvUoIOKF97g=;
        fh=tKGuRFmP46TQNNdAOdskj7J043XApTp4DWp1SKytTMQ=;
        b=iBfsFmg2X4X4uqv74Sa25okv0ASvuPLyFZnJC4EoXwiyppIN+yJdK2J5J7jynHqzOt
         yfdgS8g2bOnDrhB4hP6+0WL2I6O/K9elEYK8EOliLbs98/PCX0eIXgx2ItF6XGJ35xN9
         7XN2wD0wt1J/ujr49+Tz4QTclbELyv2mgVJbU0NbYdn4KPyXvHQT0Oa9IorvptgguIX2
         rKnOyJMNvOOM+5EKkfdTCD6OO5pzTEK19KELbEvpO94AEUhFquA50IbLhYl2c4U8orOw
         UF6/WdnTz8krge6HBEK0jFm/PRkN19vPnYvPqsxhEA68OSmbosMHaA9C1N6+rRrCwY4X
         alXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PMpXrweJ;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755476079; x=1756080879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KZq5vmvryayptn3HWrq5amrTtkCBSebJsvUoIOKF97g=;
        b=IzcRHydBEUIhdBjtgzK7tbRopwxrswSeDOiZ03z864kQhJQaasbs5yYP9ZLeKu94bm
         sCaWLsRlzifel4uCTZqsTxtjmySEbP88tz5YRB4c6Jdc3llvtWtTnP0XQUV63Jz47Xj9
         p5PQKbLkicg23eShcBh/1J4S3AdRSN95a8EP9JYHjmLzeDVjJVbRA9XHTPrBCWMXMSi7
         rHDPzC2nCVWSObXMh6nhlOWrXNRYUnTPbkRs60zHtxyAEaGzeVtJIAeKFAG3zetThfVN
         klXv2FVQzNbLDEW3cBvUcjBNndolXZ7yEdt60lr0tZ2X4Nh9dN/NnahDHV/B8q3DM5Xh
         QcEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755476079; x=1756080879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KZq5vmvryayptn3HWrq5amrTtkCBSebJsvUoIOKF97g=;
        b=QHb5yyJobolFn5+cl+fI0ktZF3/V6TvLMERbtPoAneU/nLQyzQum/8TjfOsRR3A5t0
         X14B1xDCi/9aHsJKOzXm4t9iA+MJe6UdqiYoDFK/J943iC5Zr5ijm7YfA7bFMEmvaKBh
         LuLiJdFNKv2WHIHTPzI3oM3rLER4dhzDzeDJEZunk61E5Xjy48gO0WT4Ar/spfo6G+7r
         Qb088LG4rKugasmjQWEyOhIdXiB6HVhOLCeDAljvSWeKkqhCO/EEN8sgYbZWd8+nZJ+t
         lI5FqXvNvTkhH7VKmU6ysjCHA17lBMdQj/K3X2CQC3onL6kdfk0GGZtRmaK5r/c8oyB4
         WrGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzkKhE/pHGztyIXCcBi+IDmv+pNO/2FI/dYUuO021iJLBRN9ukWyYjJJ+LsMpivhHPKjPX2Q==@lfdr.de
X-Gm-Message-State: AOJu0YydLN8Yu8jxTB40ajsmMK3dkQEJ/RS4uKcAprvBdltafGHlq982
	FkeDCVzxmOk5jTmcpHFMK4XUPHTrThdbmbT6LHqX83Bt7TUDQBDbhtyi
X-Google-Smtp-Source: AGHT+IGljFnQ45T5+R6MyIZcMltGvh8xEOAtBAlKP0V8jPYvvFmRp8oSSWj7rYaqg9Y60OfEmFS21w==
X-Received: by 2002:a17:902:cec7:b0:23f:cf96:3071 with SMTP id d9443c01a7336-2446d95aad2mr164437455ad.49.1755476078973;
        Sun, 17 Aug 2025 17:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZWoBdOu5C73rInvhtAjF3BhHN7A+LqBL8Rg44yNGTHQ==
Received: by 2002:a17:90b:3e4e:b0:31f:7cc:aa74 with SMTP id
 98e67ed59e1d1-3232669d0d7ls3690001a91.2.-pod-prod-02-us; Sun, 17 Aug 2025
 17:14:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcgfRnZk+w6VEsEY8g3tEP/DeN0Ad3Ou6zuFVaREm9rPwzLyl/LiSQ2yMwrZxOCy8NibCrpGKceco=@googlegroups.com
X-Received: by 2002:a05:6a21:6d86:b0:215:efed:acfc with SMTP id adf61e73a8af0-240d2de6a68mr15890540637.7.1755476077271;
        Sun, 17 Aug 2025 17:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755476077; cv=none;
        d=google.com; s=arc-20240605;
        b=LlxyNNJ04zoSAZjjEj5eKhQezrE4F7otsWDEMP+EtFXyZ+mrmO+SZN+4LH92XSmNbm
         GoQawv+z90wji+0MPTAJREZcbsZstmWjsk2mcg/8GEienC8eygCntMDEm0Z6r3qAjijp
         U4y7EMMOud059BL5MmBEzo1LK2yEayq6YhQqoJEv/aV+tEdvkpFZWyCFeed2ghU3c/ve
         /yPrgjCNgVnMbfRlgtJ1FsnpwmLpz4FD7s6jNarwgBJy26oO5KVPXxzm3MGOI8ABsZUD
         zIqZ9sjMQocqIZH9vlExbkWje4orvMhbw9eaxCQAvzD803Fn/bZ+yKjiS28akodNc+Io
         rOPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PJghPZDANcUiW5wXtsrqlleYuYJUnUmNG7Z7BobLTXA=;
        fh=Pypkfy11tsJxngxiQkOKIrvL9S0+C3FbL0pNI2luhOc=;
        b=hkBEKBRrkl45sjEgk095t8UvZomC3FgwxnZHiBUz+dtulZ6y/ypnjcuxZD2ovmd3Pf
         kVR6W638GuS7miuTBMFvF5jUWWhKMBoWxc2nD2kCNqj33+sc2UaMvxJDlh4rj5kJZCn2
         BCFbYQ0RDRvLGjHcC2Wr6oHqEUI+AJWcNQQGsH0Smt0jLPpRfeZ/B+HiMF7DV/i29MFj
         WvHOfikVwc4HAuL7vJzI0m2cZoS+Pdcq9+iNoqLhb2UAmLYB0nq7yIbfj8N6nNFllPt1
         I9TfDdey9dgkO0gAIYN6T5Owz9vkDsXYkhFDxd4Rwan/8OzkJatO/ObFWO+glyermUcA
         qXWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PMpXrweJ;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32328ae0dc0si389997a91.0.2025.08.17.17.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 17 Aug 2025 17:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: 25BFdEnSTbaydtOrPZwmhg==
X-CSE-MsgGUID: bePvXFS+RYCQqphS20j5ZA==
X-IronPort-AV: E=McAfee;i="6800,10657,11524"; a="68409211"
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="68409211"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 17:14:34 -0700
X-CSE-ConnectionGUID: rPkKLnjSQ5CNumytd/zTcA==
X-CSE-MsgGUID: Yli3IW/hTpGQPtHWPRWhLA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="168250450"
Received: from lkp-server02.sh.intel.com (HELO 4ea60e6ab079) ([10.239.97.151])
  by fmviesa010.fm.intel.com with ESMTP; 17 Aug 2025 17:14:28 -0700
Received: from kbuild by 4ea60e6ab079 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1unnW6-000DnH-1M;
	Mon, 18 Aug 2025 00:14:26 +0000
Date: Mon, 18 Aug 2025 08:13:56 +0800
From: kernel test robot <lkp@intel.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com
Cc: oe-kbuild-all@lists.linux.dev, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, Yeoreum Yun <yeoreum.yun@arm.com>
Subject: Re: [PATCH v3 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <202508180747.PxkbPnyA-lkp@intel.com>
References: <20250816110018.4055617-2-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250816110018.4055617-2-yeoreum.yun@arm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=PMpXrweJ;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted
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

Hi Yeoreum,

kernel test robot noticed the following build warnings:

[auto build test WARNING on 8f5ae30d69d7543eee0d70083daf4de8fe15d585]

url:    https://github.com/intel-lab-lkp/linux/commits/Yeoreum-Yun/kasan-hw-tags-introduce-kasan-write_only-option/20250816-190300
base:   8f5ae30d69d7543eee0d70083daf4de8fe15d585
patch link:    https://lore.kernel.org/r/20250816110018.4055617-2-yeoreum.yun%40arm.com
patch subject: [PATCH v3 1/2] kasan/hw-tags: introduce kasan.write_only option
config: arm64-randconfig-r053-20250818 (https://download.01.org/0day-ci/archive/20250818/202508180747.PxkbPnyA-lkp@intel.com/config)
compiler: aarch64-linux-gcc (GCC) 10.5.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250818/202508180747.PxkbPnyA-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202508180747.PxkbPnyA-lkp@intel.com/

All warnings (new ones prefixed by >>):

   mm/kasan/hw_tags.c: In function 'kasan_enable_hw_tags':
>> mm/kasan/hw_tags.c:433:21: warning: comparison between 'enum kasan_arg_mode' and 'enum kasan_arg_write_only' [-Wenum-compare]
     433 |  if (kasan_arg_mode == KASAN_ARG_WRITE_ONLY_ON &&
         |                     ^~
   mm/kasan/hw_tags.c:435:18: warning: comparison between 'enum kasan_arg_mode' and 'enum kasan_arg_write_only' [-Wenum-compare]
     435 |   kasan_arg_mode == KASAN_ARG_WRITE_ONLY_OFF;
         |                  ^~
>> mm/kasan/hw_tags.c:435:18: warning: statement with no effect [-Wunused-value]
     435 |   kasan_arg_mode == KASAN_ARG_WRITE_ONLY_OFF;
         |   ~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~


vim +433 mm/kasan/hw_tags.c

   423	
   424	void kasan_enable_hw_tags(void)
   425	{
   426		if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
   427			hw_enable_tag_checks_async();
   428		else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
   429			hw_enable_tag_checks_asymm();
   430		else
   431			hw_enable_tag_checks_sync();
   432	
 > 433		if (kasan_arg_mode == KASAN_ARG_WRITE_ONLY_ON &&
   434		    hw_enable_tag_checks_write_only()) {
 > 435			kasan_arg_mode == KASAN_ARG_WRITE_ONLY_OFF;
   436			kasan_flag_write_only = false;
   437			pr_warn_once("System doesn't support write-only option. Disable it\n");
   438		}
   439	}
   440	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202508180747.PxkbPnyA-lkp%40intel.com.
