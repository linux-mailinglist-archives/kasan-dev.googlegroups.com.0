Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKX2V7EAMGQENVV23NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9219EC38B9F
	for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 02:43:08 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-3da61d7a0d3sf240365fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 17:43:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762393387; cv=pass;
        d=google.com; s=arc-20240605;
        b=E3bmBMgw22Fs/+SyDDG2NFNu8ltYNRU71r/7ufadI7qNIcX4ozQN4H+XCo6rqNVKuU
         RL6yMGeHh8H/jGrVRjzh639F3aR7Hswg0XM5hVXvwGKOqq25u0BZ1UKjbTIB0KtTWMKa
         x3Vxs3a03hZinpTh3LLhSRK/oOQPjSk3O+vGF/kgz5rjkbZS0MtgrQAxxoTH37+Pswfy
         iyclDA4ru11+jIRup2tsiMgHrN9+iTmkWSRVVkpJ/qSVOam5iebDbgka5JqXuJLsAurL
         L8Bu/CIFCFE2xSCCjgKHtPre2hkgula815P8H4Mq7mJwSiAF7di5Hiw1wwrHFf4MiMoI
         YIDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EdubjGtQNSON6gKO3Wmv5Pg3e7ilTipZjBv1LPQ3vbw=;
        fh=WgFlTpoNjEpg8EwEFB0uKdIeqEz7LKQ6wnvghmQcwUI=;
        b=BNdLVQ+8MxczzOZ/LiUwLp8OiEVnYm/7jE1lSyyopbcZsfmVVRFaBvw0cJQRqjysYN
         2FsOd1GHFXTITimTlTA2eFbq4QFQCzsQ6H+9HHqtWiNHsXfg8XC5AZbVemw03i90lBFP
         q0ESJvjeAVy9zmSJ/wZ4/7baDFlx2NSmG+kTVsGtdgvUG5Em18IRm9RwdGrwOsbc2GDN
         XcQaf5uZr5RAw4uPUkdyTX7RjFD5YP8ADTv9ocxUoCkZ1iROY5uuuav4qMxczHyH6q5s
         5ROOOA6WiHtptmspr3PWkMuW3TpLzVaPv0vnY2APSuzdbIw4ZkiPbum58aN/+N++S9i8
         Q6fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SbrAmcbq;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762393387; x=1762998187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EdubjGtQNSON6gKO3Wmv5Pg3e7ilTipZjBv1LPQ3vbw=;
        b=Yoj0HePrFHJ7gjsu3MMUpXy1k8nubUz12/AslqhO8A3bS2yfFeoyhFpMsHCGFo+9B9
         MpOFYLO5M3NGD9NZxqQKrZw8WfI7zvYF4xRL72ZPlDY2/LUoZJPKp2lJ/Q7SLGOOKNRJ
         jE3PQzYZ6hzZtKkZQNVkXU6owWhFR5Q7l7XPRyyzRWt9/3YV4kTz/cw4QvUhrvANj6ta
         ZImQFxoGniJv82qjey3t+hWCLR2JpUmnKIWBQE5oZH0ZO/2XeaUH+H8vzvnp29EZUHiS
         6CVmwH3O4BgQtRrWL72ajzOkqEDrZ/Zw/sDxym3aXuByYiPIJpGWXD1PKRG3xKrxZvrK
         Iebg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762393387; x=1762998187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EdubjGtQNSON6gKO3Wmv5Pg3e7ilTipZjBv1LPQ3vbw=;
        b=M3rhGqPBn1Mf4gmTPVeHahWEXZK03g3xIJCFDg2VuODOjV2rx7Y0Df6bdVgbS4d9tB
         /O/gFKACwVn+mY4fW1RQXH9YCMc2u1KmBSOfSkWzSPzdnZ5suLsJqNVtAqIhpUo4j1As
         RrDgC1E9aw4mY1MGf4bl8EJVoa+8+mc9BBIiWczt3KjeRbhJ41jkT3GPPnRwOh30kjgq
         UeJAN9oPKjYqJTj7zpkL/fG3WdGMc5FYRJdthnOmRazZXUr3Dupn5uRRA49nzEv1eLCC
         pLnIqcvmZ7UZkZer6m4A3oEk9t4Y3AOMXi8pLoJGXL+HlQfsdrdv43NZBOoTvhpURtqK
         t34Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKTYwqcpvd5B6ZIQJELMVXf7i9eDUumO17YM90tFJezd3jWFtUk23BCbSWisPfmXWS+akvLw==@lfdr.de
X-Gm-Message-State: AOJu0YzD42M9P1/t+4IKI+jOV4+i1Q/Bgryd/IOuPi09mXEXFGemW6Mo
	eLZbI4KgD0yjQU70tOd7cA/rs+AkZm1v6bUG7K5xWD4xr6WI0/wGsZZj
X-Google-Smtp-Source: AGHT+IHVBxdMOhxw4YTsaAJgvuXpZuBPFS4/dDcSDVtTtu3piokxq3JsEJ0IDNo7W12Do1lrzD7SyQ==
X-Received: by 2002:a05:6870:e312:b0:315:8b80:aa4a with SMTP id 586e51a60fabf-3e19bb4b1femr3166041fac.48.1762393386678;
        Wed, 05 Nov 2025 17:43:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bW1qzQQxXrT86APp/CY5x9n28BRf8CsbGwfurnTVTfOw=="
Received: by 2002:a05:6870:320f:b0:3dc:b022:7efa with SMTP id
 586e51a60fabf-3e2f5daabe9ls167687fac.2.-pod-prod-06-us; Wed, 05 Nov 2025
 17:43:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXru9N91IJE2mdqxMmsuzG3nBshbI/WO/q5FKDcuwOIt6waeo+NzEW3br5lbD61uDDgtk7+h7cNA1c=@googlegroups.com
X-Received: by 2002:a05:6870:238e:b0:3dc:b701:c9b3 with SMTP id 586e51a60fabf-3e19bb47cc0mr3599392fac.45.1762393385763;
        Wed, 05 Nov 2025 17:43:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762393385; cv=none;
        d=google.com; s=arc-20240605;
        b=QFJLdFXUP9w3pRer95/Lm7XmyLzSwwYZriUvRzpYflgGoIxm5w6+rcwmGBySjDc4hU
         sWmmxoCTX5pUsjSkeKMyV/J0+nMSAI7p5i7cFgpeZMMzzXdGKnpQiRNz/jLrOlqR1qZK
         UkiudZZG7Z6rrvhcOjcbg/I3BmZ+xUyZJE5ipobp8mnbxTRRBOHj64abNHp0VnNDls5H
         omrQm2p/z2C7MpwmrfOXWgX3ZExKeooRbBheRX4UHcPyTZErR3uuOjlvdgfNmwhHpk03
         RIcTmJ1akf0t8YnqZlABC06sYeeSeNOR5RljwEklUfogJJq8Hcvx+XlVLR5149j1YFu9
         dZIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wGjalGWK+vwk9dPNtD22Weoh/gUOm9JIVNkXFSUGeqA=;
        fh=6GZ6QhcJbHHeQbew7PP4P4RAAJ6Z2vpf/yj2iVSn11Y=;
        b=I5ymvcrV1w1He6N00qO0a2qNlINCr75gVpp2mYPqwlre72bd/vs0bm5WjTyfLck7Uk
         /ZewksnXCD5GcETOmgm868l5VxCWxlpkNDBvYumVgwBxWwBsl9tH/hTiH3FSAG+MqFBP
         I2xhbOXcEyz567BL1PqLCB8nKVwzbo/ebv9YkJbI3rZQmbwQDs2ZzB/NBWh9c0ph1AKe
         yrA0Uc2cT/f9/sXiZi8ODUfbQqYJ1C5qX4Hy/SK2wYfRsaUZu+SJsFeRFEJFgG6p9wA3
         /Md+VVMeHryvgnZ/Fi0rmmOpabgAKTpk9XCG2e8GPfMQWZ4fqtFbg87nRgsUcfWyDV8l
         rZWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SbrAmcbq;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3e30823ff58si45549fac.1.2025.11.05.17.43.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 05 Nov 2025 17:43:05 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-CSE-ConnectionGUID: ftmWWTthR3SI4UxdLTQpcQ==
X-CSE-MsgGUID: J5NLG404TiKOXmfFNJMwEQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11604"; a="64404388"
X-IronPort-AV: E=Sophos;i="6.19,283,1754982000"; 
   d="scan'208";a="64404388"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Nov 2025 17:43:03 -0800
X-CSE-ConnectionGUID: CJWimRuKSDGhm1KNZzS0Ug==
X-CSE-MsgGUID: iOJKe8OyRfez6UZyGvb2Pg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.19,283,1754982000"; 
   d="scan'208";a="191976026"
Received: from lkp-server02.sh.intel.com (HELO 66d7546c76b2) ([10.239.97.151])
  by orviesa004.jf.intel.com with ESMTP; 05 Nov 2025 17:43:00 -0800
Received: from kbuild by 66d7546c76b2 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1vGp1e-000TL2-02;
	Thu, 06 Nov 2025 01:42:58 +0000
Date: Thu, 6 Nov 2025 09:42:22 +0800
From: kernel test robot <lkp@intel.com>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	m.wieczorretman@pm.me, stable@vger.kernel.org,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <202511060927.eg2dcKpK-lkp@intel.com>
References: <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SbrAmcbq;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.19 as permitted
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

Hi Maciej,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on linus/master v6.18-rc4 next-20251105]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Maciej-Wieczor-Retman/kasan-Unpoison-pcpu-chunks-with-base-address-tag/20251104-225204
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman%40pm.me
patch subject: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
config: loongarch-allyesconfig (https://download.01.org/0day-ci/archive/20251106/202511060927.eg2dcKpK-lkp@intel.com/config)
compiler: clang version 22.0.0git (https://github.com/llvm/llvm-project d2625a438020ad35330cda29c3def102c1687b1b)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20251106/202511060927.eg2dcKpK-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202511060927.eg2dcKpK-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/kasan/common.c:584:6: warning: no previous prototype for function '__kasan_unpoison_vmap_areas' [-Wmissing-prototypes]
     584 | void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
         |      ^
   mm/kasan/common.c:584:1: note: declare 'static' if the function is not intended to be used outside of this translation unit
     584 | void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
         | ^
         | static 
   1 warning generated.


vim +/__kasan_unpoison_vmap_areas +584 mm/kasan/common.c

   583	
 > 584	void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202511060927.eg2dcKpK-lkp%40intel.com.
