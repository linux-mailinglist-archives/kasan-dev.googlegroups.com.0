Return-Path: <kasan-dev+bncBC4LXIPCY4NRBZFWQCJAMGQEW5WQDXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B282A4E86D4
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 10:08:05 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 20-20020a05651c009400b002462f08f8d2sf4460480ljq.2
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 01:08:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648368485; cv=pass;
        d=google.com; s=arc-20160816;
        b=gW702lRlzgWAqqdceB/xSk8c7+hPg2OLu5p44drcgYKNYNGLUuI6tyLHzfqaV9th6h
         9eYVY1MkqZzOs102BnNxwpn8HM6+DN6taDGxAX04qG+CHcXcP6uDqoW6mholM6S9CRaE
         W97elkk3967O8XfWDk8trmQQ8iteDNj0TdiqV4VWe7W1uYnqarQKdioe4p3BfbHzNs10
         TuRaYJXhs8zY7vbL4hIEzRJQCRO08TpQmQjpbYqPCOKHGZK5lLJWMHafNlStBC4bgN7I
         qGpNPFftHmVgXOIm/ZtNfmHp1q7WRGf2Nu/oBb/AYpxOUT0mWHWk8cdXKOgo6nDzvdh5
         UQww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=h3+wqqrzcb5Cx1muW8XxAhszJaHRilhDSBddfSuOuUo=;
        b=ZVpeVrTOfaZxgPA0PDvztoLJipp0VIIw9AH64biMbOkKqe9VuR0rOYGKJmd3CYnWqi
         ko9wdL75xtaUzRr8xA13lcupKRA60f+VSDKI9B3QwO30X795TcEV2txlynTZI+RRoax9
         Y0a1NslZSrfcZDQfjjfW2AmsvTfQo+74Zee+y6iMpOL0nNWQg43URzjIZhpZgNmT4p+I
         h1qmKoT/0Evc6OdIqQQ8/Yim1mw9egc7Bpucp7Q+VeDljUngpvOBDC47BxEAW5ZcuT5L
         x2S/EMZKCfYTdVkgK8F/SxBWaxlFHYNlfjdoEXJrCwwdkwiQe6jpLgb3d+s08j53VH/k
         9nYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cmG+T9st;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h3+wqqrzcb5Cx1muW8XxAhszJaHRilhDSBddfSuOuUo=;
        b=MsudA7UQNUYJLC3ciMJiehC8y5vo0qjZ5sIHgjCdLtrIPRe/IDEsuSS1LtuM5DBqle
         sqEZh6uIi6utkvotpPK/lkp+q2PMVpZovnTbExhRNbLx9VosTM6cIuoGc8EnwrnuU2iM
         rOst3ru0ROUmL6Ylq7WjWRwGEyQh74kpz1K29h8nPpEoEAMhIpjDU9aqml+k6EY6fR8z
         6JHGQ+SfXl4EASlbDafq5UgqOzTFhMEHCMf35zTeo8eoXSWKFG6dbHiTtJ+pmw5bLe/D
         wiRIGim6ojwwxOwBTkONO0sh90W/28n6fyjo89QPePJpnDaO0rBqWryKihqU7hJ1KrH+
         rfUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=h3+wqqrzcb5Cx1muW8XxAhszJaHRilhDSBddfSuOuUo=;
        b=a8HaeLGWoUD6kIhxGvPhEj61//nSftkbixkeKQlWjKraovq5dEQE5G34dLcO1yPduN
         Xyum/8G3MSReg7Xs+ztkEyh2Fum8tlIbd5VVdJQDoBN8v5s/lMsQpArGURVLg+sBn5p2
         d268iYqRvgqNmVmoYZ6TNg/r9/XZM2SmHUbTJ0dv2gJucjmdpdQAF9IJrZEtlJnZ4UCr
         O47caOnaLdVIgf+Wd0vxDwL95XVYVTW/CcicRA9OYJNemY7ROacDO6q8vQaGUPzDl3rz
         GDj0FvY+3V/GPz27CNCCNoATEQrtkAbVoG7dK6emnWSRFS/hf7Mg20XeEDXp8YKM7Lue
         fDZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530j2xleqOu5hiUNjKH4OqyUPRRBwQ53Hp4jrA3p3Gt28vnczvfY
	hCuR/C5+j1SqXWAm7sF34+E=
X-Google-Smtp-Source: ABdhPJxKsfWxM2tjyG3LIpFCuH9HRQO6Riorv0ggXZOkBFNSj/jHMe8vfO4+T+JO2c471OVGVyuC7w==
X-Received: by 2002:a05:651c:198b:b0:249:8bf4:498b with SMTP id bx11-20020a05651c198b00b002498bf4498bmr15516748ljb.441.1648368485164;
        Sun, 27 Mar 2022 01:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9983:0:b0:249:7c7a:28d8 with SMTP id w3-20020a2e9983000000b002497c7a28d8ls631154lji.3.gmail;
 Sun, 27 Mar 2022 01:08:04 -0700 (PDT)
X-Received: by 2002:a2e:9b10:0:b0:247:f28c:ffd3 with SMTP id u16-20020a2e9b10000000b00247f28cffd3mr14824501lji.152.1648368484226;
        Sun, 27 Mar 2022 01:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648368484; cv=none;
        d=google.com; s=arc-20160816;
        b=r6r2J4Q7Lfx1+2romzY0d4l56v9uUHnr+72yK2CZgFs2wdLw/KyydxS3BWwjZU8THM
         14kBYgKq5kfjSWfIgEhnx02QiXliJxoyTzyf9Rbrc9dnBP3ZeVNArQlSpnkUC4YUtc+G
         dFl3ccy4Vw7Wn1kknFx+xmS2Iws0/jGCTSShg/gDOiPQXmnDZBKPRFwhR0GjuMZT8KE/
         g65UvGQR9NHwi6VGhas2+p1GHEZj4UeEUyylnig4cmOCPcPNfWYFmXeZIhrwlgQYRARt
         k822eRt8XZq3Lo6tlsBwju0+mG7x3irSi4IJX19VJW/RsCkErlpqSejKm9iAhX8mhH8O
         cVRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SkZcigKACXc5wycflPxyx0jd6pe/l5SkCNwjEbjzdKc=;
        b=rXNXd3uZld2C9SlPf3kfMDb/1NJU5/C9ibKJVdsj5cJJ9Qifg9DkcwwdMyb1d4LSnZ
         h8f3YP5zSwTLYEtLgDN5F0rvEPd7ro25r7fkCQVpsYrfuDND8to5WbE7yCPvLHroQLys
         bfErFpry7BKIAx75R1sMfX5bMquRKm5zE+P5iCet1UAjh/mpxd6LCLlj4h1iAooeCSt3
         L75HEStBoiQUO4kVSWoXQEVDdHTs5RQbNPU1OqdVbBHqtHaHQspu3odJZMVUAOa/ETMi
         8oMRfcawiZSGdjZj4JlxEpzSOIhkqsBW3FmHbjUSjLrvF2C8Bx1itJO3UcXJd2v4XzJL
         k72w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cmG+T9st;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id b19-20020a2ebc13000000b00249b9662730si263083ljf.3.2022.03.27.01.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 01:08:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6200,9189,10298"; a="283717313"
X-IronPort-AV: E=Sophos;i="5.90,214,1643702400"; 
   d="scan'208";a="283717313"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Mar 2022 01:08:01 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,214,1643702400"; 
   d="scan'208";a="617500213"
Received: from lkp-server02.sh.intel.com (HELO 89b41b6ae01c) ([10.239.97.151])
  by fmsmga004.fm.intel.com with ESMTP; 27 Mar 2022 01:07:57 -0700
Received: from kbuild by 89b41b6ae01c with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1nYNwK-0000qj-UH; Sun, 27 Mar 2022 08:07:56 +0000
Date: Sun, 27 Mar 2022 16:07:27 +0800
From: kernel test robot <lkp@intel.com>
To: Muchun Song <songmuchun@bytedance.com>, torvalds@linux-foundation.org,
	glider@google.com, elver@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, cl@linux.com, penberg@kernel.org,
	rientjes@google.com, iamjoonsoo.kim@lge.com, vbabka@suse.cz,
	roman.gushchin@linux.dev
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: Re: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
Message-ID: <202203271634.QymsHESG-lkp@intel.com>
References: <20220327051853.57647-2-songmuchun@bytedance.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220327051853.57647-2-songmuchun@bytedance.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cmG+T9st;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted
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
config: x86_64-randconfig-a012 (https://download.01.org/0day-ci/archive/20220327/202203271634.QymsHESG-lkp@intel.com/config)
compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 0f6d9501cf49ce02937099350d08f20c4af86f3d)
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/a33cf78311711db98d9f77541d0a4b50bc466875
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Muchun-Song/mm-kfence-fix-missing-objcg-housekeeping-for-SLAB/20220327-132038
        git checkout a33cf78311711db98d9f77541d0a4b50bc466875
        # save the config file to linux build tree
        mkdir build_dir
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash mm/kfence/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

>> mm/kfence/core.c:593:36: warning: incompatible integer to pointer conversion passing 'unsigned long' to parameter of type 'const void *' [-Wint-conversion]
                   struct slab *slab = virt_to_slab(addr);
                                                    ^~~~
   mm/kfence/../slab.h:173:53: note: passing argument to parameter 'addr' here
   static inline struct slab *virt_to_slab(const void *addr)
                                                       ^
   mm/kfence/core.c:597:9: error: no member named 'memcg_data' in 'struct slab'
                   slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
                   ~~~~  ^
   mm/kfence/core.c:597:52: error: use of undeclared identifier 'MEMCG_DATA_OBJCGS'
                   slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
                                                                    ^
   1 warning and 2 errors generated.


vim +593 mm/kfence/core.c

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202203271634.QymsHESG-lkp%40intel.com.
