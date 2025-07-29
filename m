Return-Path: <kasan-dev+bncBC4LXIPCY4NRBFHIULCAMGQEN3FWSBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B3175B14D22
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:44:21 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3b785aee904sf1340863f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:44:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753789461; cv=pass;
        d=google.com; s=arc-20240605;
        b=kINqhxFrCh2r1Gpcd2X/mKsvWl8WxhJPIE+yR+zrFK1nBm7jBzLZe2EcJ08BjVjX8Y
         NPMpt7FDRiIbiRuydLEn1FKrSurGf1w8uO55tjiAfOwkoDuQoe+2faalaX82xY9j6w3b
         YjClDUS8r6uJtJS2X6ra9UAM1vhN+esq6eBrU49ascBq+eZJKopY2QI0RGYKP8JxsyE3
         inPDJXx/qRLw50KjlFEhVRzBbt599QVpYuoQ6ArELhMwWMax5HT86XyJGwtE6ld+M3km
         vO5Ytjoo+DSMFf2CEJ6FkW4iA9+GCUU7wAqQFWnHarnh7zfXFbmictTMc3SF5LlkyXqF
         KJoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oFhZqOxhbPVRfj0LhfHup2ICD1DjGQGRZVzl/9jedfI=;
        fh=9iHRQly6KBnFbYBU/Ji0StrsgoeQzBvNLYm9MbLUxFs=;
        b=PMGRN/TDxnmHMARzj62YfnxaxkzDN1qthSyh60x7bBrgh2xPNK7aubeSFWlpoDeIi7
         K21EL7YzLH0UlWNZEGsxvHXD0XQ3pAlqSbUkJj2g785NQ1jxLjsntvTHHOvRsfqJsxWs
         lDDXQ2VsSw+DrETTYFqT6t7kM+0kvJpKm0K4PDds57b5gqE+dPCE+WDCohhntuND8GxV
         5CVikYS2AAdooT0jkIq6+GGvsELQMaTKAsxLOIsyizwcdqH59xnUzf8utGDGy3LwIo8Q
         F3tFGu/mRhmFxGy7r8X8znbvQoQ+bpM9mSrXSSCukXr5PqTjVz5wMPNZ1Vcx5G0gcEvD
         ZbLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=maJDoNCn;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753789461; x=1754394261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oFhZqOxhbPVRfj0LhfHup2ICD1DjGQGRZVzl/9jedfI=;
        b=kr7Ltu8ZupjhqN7m6LvGLMuYST0WNDI+WSJ6t+icMBCCd8RxNELZpP7qj4naocIRfM
         U9xnDxkGZ7YGXyM8I7sqv3mXHqlG3cxjMvvewe9GMPmLeMMCvJmzk9w+sELVgubQubMs
         K3fYbS6pFm5gXM/3087btOv5ZW6EGEnYfBvikgpz9gLo5L+Y+9aEMEHqITZqvzUadq/o
         r7Pbl/Cudb2frCUekDCmy/vhtaOMtVc8IVVZBS6GylnXT6gINpOPt5AbCZiowe9ZPV6F
         z75Tc3AMYtVKNHy8+nf78DqMnh5AUFoFtEihcXxmXkZYrbMnT/QXY8XWYamXMHK49HJF
         EsAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753789461; x=1754394261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oFhZqOxhbPVRfj0LhfHup2ICD1DjGQGRZVzl/9jedfI=;
        b=t8QqDqC9e4Ih9hxPMpG0Q+KU9AOkJxNCCbCNWWiIYtXZaQsnC+b2tZBSNph8UmZ9FQ
         Q12bB6yE0wnxcBVRxlE9CuaEquEy7WZaf1p9GXZ5TOiqZz1mDfe+mDWMXJWui2pbo54m
         VWMtuJo2/9tQHiEN43fsaw4FtK1TRbTiN6tGpJ8nbqvtCz5KWjACVy6xcQXfsIydVflu
         iRiLZ776QtA29eX0v1AuRnHlPCYaGFQVWIFMATi+LNBknhGGtmxXhITuS1vcD55F5Q+j
         /9IWmZRpRiriLmQGIMwuTSwZWzaqA7D+j0gvFcW2/rjotTfWmHof6wNVlX1/NC18gKhk
         kMcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUy+1ZEGa6zzTmfAn8diZoC2Yk9lJqCqNvpSmAhFPMZ8DZirWUmt/oogErIco8w5AtVkcM33w==@lfdr.de
X-Gm-Message-State: AOJu0YyRHZuyZJDLhtuNW9pXUyMiRSIuQvrEm/NGuhR3UDotdQj7L5u+
	gxnCbnU0YL00tn3MQspDtmQscnaQqdLL505aBlcgTLCOoJXBXL0lh0jJ
X-Google-Smtp-Source: AGHT+IHGP+wbq5OGoxzxi7u1t1Hs3aCHH7fbSHDaGQHX+44G9AcVwdTSf3MaYFomN+8Oh2LyNF/sdg==
X-Received: by 2002:adf:a115:0:b0:3b7:942c:5450 with SMTP id ffacd0b85a97d-3b7942c574bmr327947f8f.9.1753789460899;
        Tue, 29 Jul 2025 04:44:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfBTo4ZuARtxCUmao9CYTkW0bLMtNkWouK6438Qg4alwQ==
Received: by 2002:a5d:5f84:0:b0:3b7:89fd:a28d with SMTP id ffacd0b85a97d-3b7925def9bls207148f8f.0.-pod-prod-01-eu;
 Tue, 29 Jul 2025 04:44:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0OzcHy0rKBoafvrggcRZBrFLXzx6/UJhnC8QuNuGfdgngfH02NBkg8y8uJgUtmEU74Ja8ixrgz3Y=@googlegroups.com
X-Received: by 2002:a5d:5d07:0:b0:3a3:67bb:8f3f with SMTP id ffacd0b85a97d-3b77677f94dmr11635671f8f.53.1753789458214;
        Tue, 29 Jul 2025 04:44:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753789458; cv=none;
        d=google.com; s=arc-20240605;
        b=I/4c1QoMOpk1GPdrq5CFPsteegLL4cSeU7BYD/p8XXmhQuBsalpMYtDG+p1vmB8zdp
         rSoPgFRkVpXM38nFT7F7WUXf0jfGCw99+4uSn7NxW/EzCeFDmXG+U5IjVSqSc/GDInRX
         +hjKz+y7YbMvlNCXRcFc1z1Bzphig3BBZLR1cAWQ90Ga1qNQqa1VqDKZIGKcQhN6wr3J
         oZ0L9rBZnvkK6h1rJHke+7gS3tRIVvQ2q7+KfYrfXtbJHYSmoWlvjx3NicHbFEhWDCr0
         0gXSaggRyj/wEb2IXZLVkgBYd4kVLPePIsnSeans731PNeVONdmt84DEBNLUFCX5ucyB
         l2ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=V4dPaG/39G97pEpZSzmGhT6o1P1jz8CI976QVhXhvVk=;
        fh=MnY2yHmUtVG56QfH9IVBZCnsTctFtylwu+FReEVZ+00=;
        b=AkaQ5gwtoR4lZcMNgGCqrFf6bqIGPeqWxnKipdXVlyfX0pDTXO4vyfzxDydhLvrx1U
         A1sRR/Vedbzf/1A58G/lUGmd5mdx1Q3n0OQ0HvL7HC5YZuDcKvHa1+mJTaD21Xu1te/O
         zvCVY+6WpbNgY5GNfAIdqmciJ3X4heOGM8HCeuHhv3YuahQdVE6j56R1cx5e/3/EMNrz
         A5wW8nHkT8qCveLkPyVaBA0dssRPIq1a/gNOmL30lUfusg+bjIqvL595r3CLt2Sq5uNH
         nbF8QV4rGB7++cJXUWUkHDkTH/VxLvyMRYyxcdciKZULWPrrl8UncT9YI/iLqI5hxFby
         Zc/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=maJDoNCn;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.15])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b787dc0640si111169f8f.7.2025.07.29.04.44.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 29 Jul 2025 04:44:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted sender) client-ip=192.198.163.15;
X-CSE-ConnectionGUID: q+gDHGYaSGy6vp6Hvbo+Pw==
X-CSE-MsgGUID: gRZOpU/UQOOBgxd5JnsXgg==
X-IronPort-AV: E=McAfee;i="6800,10657,11505"; a="56201178"
X-IronPort-AV: E=Sophos;i="6.16,348,1744095600"; 
   d="scan'208";a="56201178"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa109.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Jul 2025 04:44:15 -0700
X-CSE-ConnectionGUID: 4+hpF88NTZyzNYZafdPOGg==
X-CSE-MsgGUID: TN+w/QwzRluX085lDlwpLw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,348,1744095600"; 
   d="scan'208";a="163126446"
Received: from lkp-server01.sh.intel.com (HELO 160750d4a34c) ([10.239.97.150])
  by fmviesa008.fm.intel.com with ESMTP; 29 Jul 2025 04:44:12 -0700
Received: from kbuild by 160750d4a34c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1ugikc-0001FH-1Q;
	Tue, 29 Jul 2025 11:44:10 +0000
Date: Tue, 29 Jul 2025 19:43:11 +0800
From: kernel test robot <lkp@intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: oe-kbuild-all@lists.linux.dev, quic_jiangenj@quicinc.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v3 04/10] mm/kasan: define __asan_before_dynamic_init,
 __asan_after_dynamic_init
Message-ID: <202507291913.UMbUQv95-lkp@intel.com>
References: <20250728152548.3969143-5-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250728152548.3969143-5-glider@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=maJDoNCn;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted
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

Hi Alexander,

kernel test robot noticed the following build warnings:

[auto build test WARNING on tip/x86/core]
[also build test WARNING on akpm-mm/mm-everything shuah-kselftest/next shuah-kselftest/fixes linus/master v6.16 next-20250729]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Potapenko/x86-kcov-disable-instrumentation-of-arch-x86-kernel-tsc-c/20250728-232935
base:   tip/x86/core
patch link:    https://lore.kernel.org/r/20250728152548.3969143-5-glider%40google.com
patch subject: [PATCH v3 04/10] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
config: powerpc-allmodconfig (https://download.01.org/0day-ci/archive/20250729/202507291913.UMbUQv95-lkp@intel.com/config)
compiler: powerpc64-linux-gcc (GCC) 15.1.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250729/202507291913.UMbUQv95-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202507291913.UMbUQv95-lkp@intel.com/

All warnings (new ones prefixed by >>):

   In file included from mm/kasan/kasan_test_c.c:32:
>> mm/kasan/kasan.h:585:6: warning: conflicting types for built-in function '__asan_before_dynamic_init'; expected 'void(const void *)' [-Wbuiltin-declaration-mismatch]
     585 | void __asan_before_dynamic_init(const char *module_name);
         |      ^~~~~~~~~~~~~~~~~~~~~~~~~~


vim +585 mm/kasan/kasan.h

   577	
   578	/*
   579	 * Exported functions for interfaces called from assembly or from generated
   580	 * code. Declared here to avoid warnings about missing declarations.
   581	 */
   582	
   583	void __asan_register_globals(void *globals, ssize_t size);
   584	void __asan_unregister_globals(void *globals, ssize_t size);
 > 585	void __asan_before_dynamic_init(const char *module_name);
   586	void __asan_after_dynamic_init(void);
   587	void __asan_handle_no_return(void);
   588	void __asan_alloca_poison(void *, ssize_t size);
   589	void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
   590	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507291913.UMbUQv95-lkp%40intel.com.
