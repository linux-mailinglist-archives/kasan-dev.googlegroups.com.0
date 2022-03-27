Return-Path: <kasan-dev+bncBC4LXIPCY4NRBZFWQCJAMGQEW5WQDXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 661F94E86D3
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 10:08:05 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 20-20020a05651c009400b002462f08f8d2sf4460476ljq.2
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 01:08:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648368485; cv=pass;
        d=google.com; s=arc-20160816;
        b=tojPqra++gmMC2fxJ2331uLWkEfPfWQHlrbNoPpURV2w86I5W0KbkiCTHEKlwAq500
         nGN9VVq0uO7pGlt2cFBII10Pj1+71PzHhFRIQTroNeEtcAakELv7IeCGe9bgsPSOLrtt
         EKedw4kvyHxbc0jnkZlA8Qcx8k9KcPmcGqXaPW/poqkj7zI0zirklIhRxCAJKXS6pis5
         oQq3ys/TOddSPp1PTqL7WOj7NSJInnvFwFepU1RQfRWcfD/601tHfXUAtf+22IIamU2T
         xe0NC0qr6WL810PcQLp9z1t/fEDGdZWn+n6Q0iWtzK/IxPqHV3R28BHPMAwk5cNjwtCf
         /73Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9bUXwMjo4dGPEGgc3Gt5hXVbwE2ZHTHMGP9oVem6EFQ=;
        b=WMVL9fjGp0kPXY5iENnFyDkF/HoZlY6xRXgRpXuOonLJtRSm5LmqBJrmkfUy81G2wG
         +H8jT1dti45w62iuQdM4Q/zCniW5/+m3J0jEFs3whnMSwGz/2Fp6qGN9Tw/RkcfHrn1h
         y0uNPhdcYp7rigvj8YFc1PZt6qPktJEb4K1WGFQUcLp3oDii2hrU2N7wT7RdjWNJlx7S
         +w1cZOSs1wAV+aTQIwgPMXyMI+gICeAbw6lhj8jJLZspbeqFnYSkFjGm9fbTm26OQa6U
         pdG/0WxhGPEZzbDXAfCyuoYf86snI6jh9MKlazviAaGYKiGQ7e1Y2nW+F6w38FArHDWD
         nxQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YDv62Ozk;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9bUXwMjo4dGPEGgc3Gt5hXVbwE2ZHTHMGP9oVem6EFQ=;
        b=Itque2NztPVqqcatOFxMMUXT7ayQxEy2GzpaImU7ir2dufN/1h85+0CH/B/FFkSi2P
         SvXooilBGBK7gekFdY9seeSvlBl2rFKYuGmfU/X2J210/xqax2ONdezNdyeF8obDMOIH
         cdlx9/r67dSKtAviITDr6wQ0PByoaqY33C7pyjHttJ7sa//2P30jwW/u/Yl61vZv5hzT
         ni9WILr5oryCoIxzEl7AUJ123UFZK9LFT48oXqUpebONqaQ2/Q8daQRVcuTN/mACXiQD
         29SmLLEFKJ8j9M90ktfTv6fNKFqg81hlL71ueLZdYD0emvKOUx0qx8+uwsBBO+e5f36w
         g9Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9bUXwMjo4dGPEGgc3Gt5hXVbwE2ZHTHMGP9oVem6EFQ=;
        b=oi2wZ39iBp9CMWLQSxRotlGCVQrg4YDKsFwib0wn8UoGjOeQtvucAv9BrHFfkUWO9K
         fWrOIyeajQwwKxTFW1ygUWHE1r3peWfAukPP7ENkP9z+04suRH0UnuWz1rkKAO0qo+14
         ku5x94ZHza8KJ7WPlvEsQk3Y7+n/U8ZTMYQ++vb5eIfs8evJ2UmQTJAN2RuAcWRWGe7x
         MjpTtOohOf/glUrOM+kj9ms/ACfQDQNfuFyP1qwdYMEezo5YsNnJSjRmVAQogj/SBQf1
         4XFEIDVMIZzR74EATmAPobkHxEFkJRZIzC+WF0cbbCfciEVeGvo47cv9ZjjikzpoZ2eI
         Q7Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rMFFLLoCQFT6yx80v+7BHVTB62EvUWr4Lo3hH5A5xLNDbKpgZ
	2XKSiXYroCrAgwzaP1KDvF8=
X-Google-Smtp-Source: ABdhPJzoX7Ds0wWVDKwwAGkkktIu2qiZzyBtAcnYP286XTOqDRYTH/+OexazZUMwzaBG3b8jnZOSUg==
X-Received: by 2002:a2e:5cc:0:b0:249:13bc:1685 with SMTP id 195-20020a2e05cc000000b0024913bc1685mr15251609ljf.254.1648368484793;
        Sun, 27 Mar 2022 01:08:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d04:0:b0:249:324d:ebb2 with SMTP id y4-20020a2e7d04000000b00249324debb2ls630006ljc.1.gmail;
 Sun, 27 Mar 2022 01:08:03 -0700 (PDT)
X-Received: by 2002:a05:651c:20f:b0:249:6026:f0f6 with SMTP id y15-20020a05651c020f00b002496026f0f6mr15075606ljn.169.1648368483786;
        Sun, 27 Mar 2022 01:08:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648368483; cv=none;
        d=google.com; s=arc-20160816;
        b=iIQ1fyCy4qx0jcOgbm0b4COh9NdLL2mdTaliQq1jfyvD+sXmLy0f2BfZC8DSmNyHoi
         eb++4F0DPL73d8h4EUIkOv262fuE5i3IsCZhiLtyxPPMUIMNXwETAooaSzKSiNVT+4F6
         8Ab0gIq60B55JBBef4ulOR8phz1jmB/uhpdDXBOk+wbuYYB3U+eLVlduqyliShsQQ8u+
         IzHd+3Ect9VYvoEUURyzf26QOGHb/a3tbLJ11eGyfKLt47lhRPTFOie9jHIBoWORA6js
         SRSEvyBgFr7hQV/1Vb+31NXF+8EYpE29AfrcnELTqotnVVc/vjNDpaTZ9yEKztslVe13
         w+Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HgTYb5UDi0mCjCdm199HSUjPHhajhdc4It2AyfwHTWk=;
        b=c3yaT4onGjByf+RXwwXSNe+4DANPb34XSQmFrCBSBTF2Dfi+hRGLcdVPvHjUqFr7B3
         96hKd/+8glhZew3DatzoCQBl9TOBWMF4gGgSy/Db0hFVSs/+1NP7leuD8zH8YK5o5geZ
         8rKNbrn0Y1a0WOma6/E/zvexbqHO3Lly4zfdPwnLa8KmBhBb7rPHRYe+mpX/5AAi3CgD
         HNzGGpWiRkbM/ly6pbAORuq4ANMrZitBS67g928XxJgZF+Z9PPC87ALWLqJY+zMjlVBI
         HfBjwLpK3XlWrm2gsY9tcPzJKqzDKcqxNb8rDCMb0xvvoxSarHnVrF6W9Zg4vqzg64o3
         I0xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YDv62Ozk;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id x40-20020a0565123fa800b004487bb2d452si545432lfa.0.2022.03.27.01.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 01:08:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6200,9189,10298"; a="345270037"
X-IronPort-AV: E=Sophos;i="5.90,214,1643702400"; 
   d="scan'208";a="345270037"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Mar 2022 01:08:01 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,214,1643702400"; 
   d="scan'208";a="826400443"
Received: from lkp-server02.sh.intel.com (HELO 89b41b6ae01c) ([10.239.97.151])
  by fmsmga005.fm.intel.com with ESMTP; 27 Mar 2022 01:07:57 -0700
Received: from kbuild by 89b41b6ae01c with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nYNwK-0000qh-Tr; Sun, 27 Mar 2022 08:07:56 +0000
Date: Sun, 27 Mar 2022 16:07:30 +0800
From: kernel test robot <lkp@intel.com>
To: Muchun Song <songmuchun@bytedance.com>, torvalds@linux-foundation.org,
	glider@google.com, elver@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, cl@linux.com, penberg@kernel.org,
	rientjes@google.com, iamjoonsoo.kim@lge.com, vbabka@suse.cz,
	roman.gushchin@linux.dev
Cc: kbuild-all@lists.01.org, kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: Re: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
Message-ID: <202203271619.Ni4lY7Mc-lkp@intel.com>
References: <20220327051853.57647-2-songmuchun@bytedance.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220327051853.57647-2-songmuchun@bytedance.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=YDv62Ozk;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.43 as permitted
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

Hi Muchun,

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on hnaz-mm/master]

url:    https://github.com/intel-lab-lkp/linux/commits/Muchun-Song/mm-kfence-fix-missing-objcg-housekeeping-for-SLAB/20220327-132038
base:   https://github.com/hnaz/linux-mm master
config: x86_64-randconfig-c022 (https://download.01.org/0day-ci/archive/20220327/202203271619.Ni4lY7Mc-lkp@intel.com/config)
compiler: gcc-9 (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
reproduce (this is a W=1 build):
        # https://github.com/intel-lab-lkp/linux/commit/a33cf78311711db98d9f77541d0a4b50bc466875
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Muchun-Song/mm-kfence-fix-missing-objcg-housekeeping-for-SLAB/20220327-132038
        git checkout a33cf78311711db98d9f77541d0a4b50bc466875
        # save the config file to linux build tree
        mkdir build_dir
        make W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash mm/kfence/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

   mm/kfence/core.c: In function 'kfence_init_pool':
>> mm/kfence/core.c:593:36: warning: passing argument 1 of 'virt_to_slab' makes pointer from integer without a cast [-Wint-conversion]
     593 |   struct slab *slab = virt_to_slab(addr);
         |                                    ^~~~
         |                                    |
         |                                    long unsigned int
   In file included from mm/kfence/kfence.h:17,
                    from mm/kfence/core.c:35:
   mm/kfence/../slab.h:173:53: note: expected 'const void *' but argument is of type 'long unsigned int'
     173 | static inline struct slab *virt_to_slab(const void *addr)
         |                                         ~~~~~~~~~~~~^~~~
   mm/kfence/core.c:597:7: error: 'struct slab' has no member named 'memcg_data'
     597 |   slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
         |       ^~
   mm/kfence/core.c:597:52: error: 'MEMCG_DATA_OBJCGS' undeclared (first use in this function)
     597 |   slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
         |                                                    ^~~~~~~~~~~~~~~~~
   mm/kfence/core.c:597:52: note: each undeclared identifier is reported only once for each function it appears in


vim +/virt_to_slab +593 mm/kfence/core.c

   543	
   544	/*
   545	 * Initialization of the KFENCE pool after its allocation.
   546	 * Returns 0 on success; otherwise returns the address up to
   547	 * which partial initialization succeeded.
   548	 */
   549	static unsigned long kfence_init_pool(void)
   550	{
   551		unsigned long addr = (unsigned long)__kfence_pool;
   552		struct page *pages;
   553		int i;
   554	
   555		if (!arch_kfence_init_pool())
   556			return addr;
   557	
   558		pages = virt_to_page(addr);
   559	
   560		/*
   561		 * Set up object pages: they must have PG_slab set, to avoid freeing
   562		 * these as real pages.
   563		 *
   564		 * We also want to avoid inserting kfence_free() in the kfree()
   565		 * fast-path in SLUB, and therefore need to ensure kfree() correctly
   566		 * enters __slab_free() slow-path.
   567		 */
   568		for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
   569			if (!i || (i % 2))
   570				continue;
   571	
   572			/* Verify we do not have a compound head page. */
   573			if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
   574				return addr;
   575	
   576			__SetPageSlab(&pages[i]);
   577		}
   578	
   579		/*
   580		 * Protect the first 2 pages. The first page is mostly unnecessary, and
   581		 * merely serves as an extended guard page. However, adding one
   582		 * additional page in the beginning gives us an even number of pages,
   583		 * which simplifies the mapping of address to metadata index.
   584		 */
   585		for (i = 0; i < 2; i++) {
   586			if (unlikely(!kfence_protect(addr)))
   587				return addr;
   588	
   589			addr += PAGE_SIZE;
   590		}
   591	
   592		for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
 > 593			struct slab *slab = virt_to_slab(addr);
   594			struct kfence_metadata *meta = &kfence_metadata[i];
   595	
   596			/* Initialize metadata. */
   597			slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
   598			INIT_LIST_HEAD(&meta->list);
   599			raw_spin_lock_init(&meta->lock);
   600			meta->state = KFENCE_OBJECT_UNUSED;
   601			meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
   602			list_add_tail(&meta->list, &kfence_freelist);
   603	
   604			/* Protect the right redzone. */
   605			if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
   606				return addr;
   607	
   608			addr += 2 * PAGE_SIZE;
   609		}
   610	
   611		/*
   612		 * The pool is live and will never be deallocated from this point on.
   613		 * Remove the pool object from the kmemleak object tree, as it would
   614		 * otherwise overlap with allocations returned by kfence_alloc(), which
   615		 * are registered with kmemleak through the slab post-alloc hook.
   616		 */
   617		kmemleak_free(__kfence_pool);
   618	
   619		return 0;
   620	}
   621	

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202203271619.Ni4lY7Mc-lkp%40intel.com.
