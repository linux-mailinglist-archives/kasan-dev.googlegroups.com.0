Return-Path: <kasan-dev+bncBC4LXIPCY4NRBKOKWKWAMGQEPT564KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8058C81F275
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 23:28:59 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-6d9b6701404sf2858167b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 14:28:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703716138; cv=pass;
        d=google.com; s=arc-20160816;
        b=wcSzD0HnX2Wefii+Fd/B/hxKsoBNeDIaPwWEP2pKzEfWMBGjxFsGPs4BCr+k4IO0H8
         vsCJTl4lu3LwMnqK/BdVfpNmF9jrr/mI4tdMA+LsIzqXPLzVLEgbhDSAOAw6kYaPgIFy
         itV1vYWM7vGtrzxXgfsUmum5ICisbaf1p19vDWnjkTuu8dUYYYi+q1VBHYXWPsJ0B4Yr
         lveQYGklBS5bCbiwkHBGAwq0fZKBBRoVCFmu5tRFvz9lYcGPkPrZYzO3yjR/av/9nsvH
         PrUd2PzaDVHj3ESQlrBZuvDojcY9rg9eLGDm9HwEiTrKSb7A7bl4IUzexZmlvO2J5H9u
         qhiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RvsKC8v9L2Jwckq3Nk6SdO9mfxgAoQj6yCztOHsC+98=;
        fh=s+ToP9nh56v32dLSCB/BqCwGI8MlAADG+gaIAoTWN1c=;
        b=H1kotsdvzlAiSrg0VUxCgl+pZFRn6Fl8D2y5oxIzlEBvL2rNsibcVBKqeBOOEHaA/O
         WcT7B9eMfSBb5WY5as/pmX1/xcFXfJzb+f3nR9AICeRqDovU+NsYD76x8sWAMicNDt1H
         RT7rKytNZXo4Dq4DCEghlBOReoW8O37Cw2kcfpwI6CHKGxi8SxCu3SrM8hypu37UF2Ra
         AhDc/hP6d2h3cuVfEHBpXw7i9rCGNQcwit5EAQ0WLkuxx/DPIlHuFuV/t9XRmgkPM2oC
         t7H122dR/TXlxuT2sIGDCtPTUqDOetGMpvZ4esdgDxYyUo8f4O7UGwJr/jjEZrsNjbNp
         B+jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QSAjSRnA;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703716138; x=1704320938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RvsKC8v9L2Jwckq3Nk6SdO9mfxgAoQj6yCztOHsC+98=;
        b=a9dNGG6KAtjR8LyFoY5dAhGKUcowjgIefJhdao8f8f/0T1rRjWWcWAT3wWJpQrQR/q
         P0EFN0ZxE+BjphAul0ZEEjixD8EDE4HmCDnoLkSrGHFmwumCOm6jo2DcaGFM4nU46hGT
         Vz54Z5BZekTab/bzLrdiJ7lwvXNMq4QNrP0YaoK7guf5P+VhmzTaJF3uWA+n6+YmF1rB
         df2QAYbg2avQDEIPY06AUK9JBlaw+DbwEnNZ0E6PXEjkI6Q77TrzF2XWoHv/tdgUhTET
         Y5bwItgrvBvbiDookl5ZICtdZYsaZrvVb8nGjzPULTlpBd7FeFuLlZvURjz7EroFn/MZ
         EVWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703716138; x=1704320938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RvsKC8v9L2Jwckq3Nk6SdO9mfxgAoQj6yCztOHsC+98=;
        b=chEs+fmTbRvnPJ3sl8EAk4QeQkOXUyCuVGymnr6rS5NcZibdnKBnt1cRUGDkCnYths
         2pQ1qqPCytE22QyVXMwFwouPvWWTY4SbvHVwXbfMHR7E6bDG5cKLygDvoUWuelVEQf2a
         CYIAD7iGLx5xJiFAA1OYcmA3da8b1mfry7S/7gfGgm7o4sFKfbhgCFFVYdNA4ZJH4Hxy
         KEYePILTHFnnCocuF063cBQJ5iMTcYT8/SW1nFiQ5lom1sTJpn/Csu6KM9ZJgCcjIVxd
         5C8wPBW/ygkzicKU2n6gS3TibvITInxjvQbAjc1xPuYo8kpJXeG0NOLHKVKzGaHjaSgQ
         gWgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwU1xf0PGlMRrYzbgxNP2hyGew6o6YoC7cujMEIb2BRCTzxn+m6
	LUmcbG5SuR7MNjsO1C8XLJw=
X-Google-Smtp-Source: AGHT+IFVlNwQwPk6iORFeV68zSP5fQX7SVYsQGEVXM7PuYAaVdbxZKs/brJz7jPvZqu+uYtw4E1iMw==
X-Received: by 2002:a05:6a00:90a0:b0:6d9:d249:84dc with SMTP id jo32-20020a056a0090a000b006d9d24984dcmr4462436pfb.28.1703716137905;
        Wed, 27 Dec 2023 14:28:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:179a:b0:6d9:9783:3c99 with SMTP id
 s26-20020a056a00179a00b006d997833c99ls1289731pfg.2.-pod-prod-03-us; Wed, 27
 Dec 2023 14:28:57 -0800 (PST)
X-Received: by 2002:a05:6a20:8825:b0:195:bda4:4b2d with SMTP id c37-20020a056a20882500b00195bda44b2dmr4048621pzf.102.1703716136495;
        Wed, 27 Dec 2023 14:28:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703716136; cv=none;
        d=google.com; s=arc-20160816;
        b=Tb/m5oHl0kzvVvUK0FAYF7rC5pEDXTDY8Zh7ojNwdSJpYL7FJTK1D+mb3+CYd467DG
         7Jpxm3AWhtb8n4biWMCcve9OiFXe/IRkgvCZiHmM5DaehCRWKNXw3xDk9NjG2IEIau27
         ixpElriEWwRPIRa/pAW5+1TOlDjGTV+/tpxSEcQWA3y8OQrBi9EzWbNao7k4exxmrsNg
         DhWq/KXgKrj3PgKotHVHl08hIfjVKxU6pJ1n4jLAur8uTBHlIGKROjBqI2Mm2Z6z/CXk
         Dv4oPWlyKsaCPO6+WszDgD25tgnqSTfhr91hhiDOXYVElcdfwPZYLKtcXiiiSigNn49d
         /W7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4Da+Fmb1Vvcxbep30ZUBOmDDGIjSH58Psmv2LEZR3p4=;
        fh=s+ToP9nh56v32dLSCB/BqCwGI8MlAADG+gaIAoTWN1c=;
        b=ep2Nvdqbdq2ZdaP6f3OfcsXUTUkiqFJeh4BRsoGFaWTqzmg0wqE9f2nZGmRZjH4hzT
         MK1QDZLyoRGSaaFA1IB2Bs3DzIeG0s/n+25cb9IcwikbkjMqxQt99lUwNUp52QY6y6zY
         z2Ksc2H2bXcC0I6xH/IqikzVGC+PSiia5DoS+tgvqR0t36iK8T9JKOXH+lZ6+sEkyh9t
         EDu270Bp1ntjF4xbC4ME3J6O9CV5AUTe+n8zcovXp/BRrw1J7yNc9hkH5I6H11b2crwm
         E2/QRhUOg1wu5O1YHkU+5zZD8VPBnJXGW/hrWQb6P2Hymr8UOvvTD3b+3YSSZbSD9JpY
         W5ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QSAjSRnA;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id bx9-20020a17090af48900b0028bcdd1725fsi1139009pjb.1.2023.12.27.14.28.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Dec 2023 14:28:56 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-IronPort-AV: E=McAfee;i="6600,9927,10936"; a="3335456"
X-IronPort-AV: E=Sophos;i="6.04,310,1695711600"; 
   d="scan'208";a="3335456"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Dec 2023 14:28:54 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10936"; a="778340767"
X-IronPort-AV: E=Sophos;i="6.04,310,1695711600"; 
   d="scan'208";a="778340767"
Received: from lkp-server02.sh.intel.com (HELO b07ab15da5fe) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 27 Dec 2023 14:28:50 -0800
Received: from kbuild by b07ab15da5fe with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rIcOO-000FnF-1P;
	Wed, 27 Dec 2023 22:28:48 +0000
Date: Thu, 28 Dec 2023 06:28:32 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] kasan: stop leaking stack trace handles
Message-ID: <202312280603.WqS3sWfa-lkp@intel.com>
References: <20231226225121.235865-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231226225121.235865-1-andrey.konovalov@linux.dev>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QSAjSRnA;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted
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

Hi,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[cannot apply to linus/master v6.7-rc7 next-20231222]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kasan-stop-leaking-stack-trace-handles/20231227-065314
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20231226225121.235865-1-andrey.konovalov%40linux.dev
patch subject: [PATCH mm] kasan: stop leaking stack trace handles
config: arm-randconfig-002-20231227 (https://download.01.org/0day-ci/archive/20231228/202312280603.WqS3sWfa-lkp@intel.com/config)
compiler: ClangBuiltLinux clang version 17.0.6 (https://github.com/llvm/llvm-project 6009708b4367171ccdbf4b5905cb6a803753fe18)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20231228/202312280603.WqS3sWfa-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202312280603.WqS3sWfa-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/kasan/generic.c:506:6: warning: no previous prototype for function 'release_alloc_meta' [-Wmissing-prototypes]
     506 | void release_alloc_meta(struct kasan_alloc_meta *meta)
         |      ^
   mm/kasan/generic.c:506:1: note: declare 'static' if the function is not intended to be used outside of this translation unit
     506 | void release_alloc_meta(struct kasan_alloc_meta *meta)
         | ^
         | static 
>> mm/kasan/generic.c:517:6: warning: no previous prototype for function 'release_free_meta' [-Wmissing-prototypes]
     517 | void release_free_meta(const void *object, struct kasan_free_meta *meta)
         |      ^
   mm/kasan/generic.c:517:1: note: declare 'static' if the function is not intended to be used outside of this translation unit
     517 | void release_free_meta(const void *object, struct kasan_free_meta *meta)
         | ^
         | static 
   2 warnings generated.


vim +/release_alloc_meta +506 mm/kasan/generic.c

   505	
 > 506	void release_alloc_meta(struct kasan_alloc_meta *meta)
   507	{
   508		/* Evict the stack traces from stack depot. */
   509		stack_depot_put(meta->alloc_track.stack);
   510		stack_depot_put(meta->aux_stack[0]);
   511		stack_depot_put(meta->aux_stack[1]);
   512	
   513		/* Zero out alloc meta to mark it as invalid. */
   514		__memset(meta, 0, sizeof(*meta));
   515	}
   516	
 > 517	void release_free_meta(const void *object, struct kasan_free_meta *meta)
   518	{
   519		/* Check if free meta is valid. */
   520		if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
   521			return;
   522	
   523		/* Evict the stack trace from the stack depot. */
   524		stack_depot_put(meta->free_track.stack);
   525	
   526		/* Mark free meta as invalid. */
   527		*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
   528	}
   529	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202312280603.WqS3sWfa-lkp%40intel.com.
