Return-Path: <kasan-dev+bncBC4LXIPCY4NRB6E77LBAMGQEU4BFT3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id B4341AEB7CE
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 14:35:14 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2ea7f2993d4sf2162921fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 05:35:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751027705; cv=pass;
        d=google.com; s=arc-20240605;
        b=XnKAorEABHtbIZXovL2zdLexOIM3whz3K6MTblNkyqGRvSQfSCACXRpRFZ/zpFzbU7
         mfxg9IHN11fAFfuKXL1q3P+TNKiBauB2uJgDtzwUt+PdK20EHjV70+eh4pH2hnvp6/p0
         6ZTBo0mPO7CZIgCJsV3RBSrUJ+hyug4WoMq6ryOU53Dj5hNVEYVNARQ3bwzPDcXXRtWi
         5M3AiOyJc9JGPwuyyg2i6WmGUkSO1GZmuNxwuVhCfK14uelS3almVm+mWOc7uWzFfj6O
         PsQHbFW00x4tLojFwhNFmULnibRkG8jwTRyhBVCVvQ2i7SnkV5xsGDYDUbIfgRPMHi+T
         NGEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ENn2CnTWd4VSCiKZDF64sghN5ES7RQ/aqWn4SnwmmBM=;
        fh=iGQ6BvO05LHeZyraZvtNkgixlKp4onKccCzGV4yfqEA=;
        b=cOodaK3kBIefms5YnYq5u5O35HC8z/uT1jBQj1XEx2vVKM3sSIaMYHP6fh8cS1TzcJ
         ThulyaLvX6Dpg4xsCOVGzCrJ7XgMRduIJd8YdBwO2w3PvlVP9dM6rBgiquswKQUh9DOZ
         Fzoa30t1vqRkQH/7YzV+DCs7z3wYh3JfY5hC7r9YrxLN3bdMAxYUwyMbdvNxDN0h576A
         FBeo1QBcRPHS/dlL7X0OLtAR2bWy65dUvv8N9dYBK4ksaVT1AclV7+krlg88AblUj6/5
         xdH3CX4GHqMTV5Qp0gTCbbw7JJQwyrROZNTsI4ncBQ9lol2PoR2GZimzqDSWO6Tq0wXC
         BCUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="OA4U/vcF";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751027705; x=1751632505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ENn2CnTWd4VSCiKZDF64sghN5ES7RQ/aqWn4SnwmmBM=;
        b=mkwKaJ+U3RxXUE7W9lhaa3AfWIlwicvrlr38zs9pon7zC/9JbirCma4vng6Ih1hW3+
         ldF0Y7R5Z1M9ho76aCOiE3mdxstjMW/xJEFcQtHeaPqw2w5P7gmMSSs+k43G5/iDGBl7
         zyAH0L1xpYCfFaGcekOhlrxayMo2tkHJVSrwDeDVfE9ZsgoEoMa+Bra/MKbl9JGWovo0
         riKBrCUksJb+txMV/igN8X7EaUChnMfqWUL3vYBPqf7F6j0w8dLxIY5ocwtV009e+NMu
         b+f5huol4QA/QJO9MmptlANuBmdbD5udiWsUK5V6hJgRUzhb2q9PPFzgw6nbkZdWiEre
         j35w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751027705; x=1751632505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ENn2CnTWd4VSCiKZDF64sghN5ES7RQ/aqWn4SnwmmBM=;
        b=VTELAVG7hfsKFiJ7QKQb0z8Su6k53pTN7twuWvUdu+l37xDJi3MMz67ct1IxKj57ny
         QrkOksDgfLmKPRnSENdxiYF33/kPz1qgb3kIiLFChw+KRWbGXo1FGFO+gnZ7Klf3v+G/
         JPlpm+ccwi5CKBlCKHORIRnGaxiRZTyMF6noeXlIVnF5QeRU73AmVluCM+IhbbuozLW8
         tEM3BTlLiwaYe7RczKr6+69Fg2OEWfMq4DvykXZTXLs0mqOjaotrQgPenBIKFvpCdzfM
         dR5NEQ+YGs1uUWeAZdvq6CXxPdOeUYDCF4koNyo3JKXRGIl7NzxV6XS6Yr+2xodWWE0d
         A2VQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhrGR9OUaJgCkqoy6+cuEsZbHPTocLzVSBSynBaWaPN5CbplvdFeb3oEsqp/RoZGSAoo9yeg==@lfdr.de
X-Gm-Message-State: AOJu0YzclhGk84Vc4fZWFsExfXJ6s9xJMcxilFA5zQnENWS2y68OBvof
	0V7UTxvsNxDiSLwpONqSuUh1brbmn4ZQS7FlL6IDhV4XC6tSgNyLptfe
X-Google-Smtp-Source: AGHT+IHHGB8ju1h8dMPJ6MpPkBZ2p/ox2y9cMmK+k8FvaoY4ggKanrPyPtIhg1y7cHR4qg0sJPyhUg==
X-Received: by 2002:a05:6870:356:b0:2e4:c5be:8e6c with SMTP id 586e51a60fabf-2efed415a1fmr1933568fac.1.1751027704901;
        Fri, 27 Jun 2025 05:35:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeqPsM6OqgwSn8afLC3YFd0oEa3tMDiAJ74gqRELeDEXg==
Received: by 2002:a05:6870:89a1:b0:2ef:2f93:9710 with SMTP id
 586e51a60fabf-2efcf2d1adels1217737fac.2.-pod-prod-01-us; Fri, 27 Jun 2025
 05:35:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWx9uxXM8AiFDyYceyL4nIMcB1pmPchJqTLeRk+OKpsP7OGwfoIjjNsygB0JluwcH9Kc+yCuDikxHk=@googlegroups.com
X-Received: by 2002:a05:6870:9694:b0:2d5:2534:ac19 with SMTP id 586e51a60fabf-2efed415194mr1881405fac.4.1751027702434;
        Fri, 27 Jun 2025 05:35:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751027702; cv=none;
        d=google.com; s=arc-20240605;
        b=cltZwDKD/en7yP73Llsd/XG43nNmNg0pcU/NxANaLM/TLJIIZTWYMpITi2e0fOz5wT
         1daEghPrDUMiXt1QK9d4nhxidgXVg5uZLVwPHEId9vah3LorXa1DNStGvEIRXky7cTlh
         aqkd3uSAGeRUQjh6EC1vVRiHVXMD8dt7sr0D+H/pX5sjYZJtYevrcHQ1m4AnJyozTMqC
         Im7QO5ir1jjHZorpJ4uzf/3dJvnQfvvPmymnFZtYF5jfi3hFVkCDzcCA78qU76x+p+/j
         eSKdc5CYRJyiI19ntL+ViRUY4wX7LvKnHd860p4MoQ9mHiJmu5YcEGzrEGGGuk+CXQZU
         gaCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hXrujbNg5bhHDsUyb4B74YRGVzKarTmGpgphbVQ6H5I=;
        fh=7tKbdrXp7qOPlSXPe91S9k1qU5AWkBYfjm+Id4Zw+8o=;
        b=DIvB1Ji5xhhUzdOOYDIRCKsyemRYhySguzc/YxC+H7/KuWFmEh6X24YmkQqZ3tO53P
         xwRnJrl/oqRZR8/gR/3ZGa7IPFFNueNtV1IMQ0kvwdDb4AxKP/3XiZexva5yAJcRCLtR
         MrseRfjF4hybvgQR7ncNHmwWKwGoUwKdAhsIsgpb1A0f6qqiRcfK1Omk4onPz+Ozt7JP
         apCqcu84CAKXV7v0EUTwaukfOKypmaTUMZhNadKjIl1eiKLwKLO9XNuwCG94wn1jDGZ0
         7OCYKO7HsD1kJZ3C8tqXXcWyRflZijK1R5EYrfuJYMddglb246iiETEGlckfX81iReZ6
         hDVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="OA4U/vcF";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73afb0c97a3si95386a34.3.2025.06.27.05.35.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 27 Jun 2025 05:35:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: hYHA8ciCRrGk/lboMvEB8A==
X-CSE-MsgGUID: xgmxk/LhQwi3TxaYJFL/Ww==
X-IronPort-AV: E=McAfee;i="6800,10657,11476"; a="52458925"
X-IronPort-AV: E=Sophos;i="6.16,270,1744095600"; 
   d="scan'208";a="52458925"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Jun 2025 05:35:01 -0700
X-CSE-ConnectionGUID: Ecej+RiLT062BvHRv6nqPA==
X-CSE-MsgGUID: TygrQ0gfTjeljWcCgm8jFw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,270,1744095600"; 
   d="scan'208";a="157176713"
Received: from lkp-server01.sh.intel.com (HELO e8142ee1dce2) ([10.239.97.150])
  by orviesa003.jf.intel.com with ESMTP; 27 Jun 2025 05:34:58 -0700
Received: from kbuild by e8142ee1dce2 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uV8IB-000WA8-1F;
	Fri, 27 Jun 2025 12:34:55 +0000
Date: Fri, 27 Jun 2025 20:34:24 +0800
From: kernel test robot <lkp@intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 07/11] kcov: add trace and trace_size to struct
 kcov_state
Message-ID: <202506271946.HACEE9U0-lkp@intel.com>
References: <20250626134158.3385080-8-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250626134158.3385080-8-glider@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="OA4U/vcF";       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted
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
[cannot apply to akpm-mm/mm-everything tip/sched/core arnd-asm-generic/master akpm-mm/mm-nonmm-unstable masahiroy-kbuild/for-next masahiroy-kbuild/fixes shuah-kselftest/next shuah-kselftest/fixes linus/master mcgrof/modules-next v6.16-rc3 next-20250627]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Alexander-Potapenko/x86-kcov-disable-instrumentation-of-arch-x86-kernel-tsc-c/20250626-214703
base:   tip/x86/core
patch link:    https://lore.kernel.org/r/20250626134158.3385080-8-glider%40google.com
patch subject: [PATCH v2 07/11] kcov: add trace and trace_size to struct kcov_state
config: x86_64-buildonly-randconfig-004-20250627 (https://download.01.org/0day-ci/archive/20250627/202506271946.HACEE9U0-lkp@intel.com/config)
compiler: clang version 20.1.7 (https://github.com/llvm/llvm-project 6146a88f60492b520a36f8f8f3231e15f3cc6082)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250627/202506271946.HACEE9U0-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202506271946.HACEE9U0-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> kernel/kcov.c:1013:15: warning: variable 'trace' set but not used [-Wunused-but-set-variable]
    1013 |         void *area, *trace;
         |                      ^
>> kernel/kcov.c:1014:21: warning: variable 'trace_size' set but not used [-Wunused-but-set-variable]
    1014 |         unsigned int size, trace_size;
         |                            ^
   2 warnings generated.


vim +/trace +1013 kernel/kcov.c

  1006	
  1007	/* See the comment before kcov_remote_start() for usage details. */
  1008	void kcov_remote_stop(void)
  1009	{
  1010		struct task_struct *t = current;
  1011		struct kcov *kcov;
  1012		unsigned int mode;
> 1013		void *area, *trace;
> 1014		unsigned int size, trace_size;
  1015		int sequence;
  1016		unsigned long flags;
  1017	
  1018		if (!in_task() && !in_softirq_really())
  1019			return;
  1020	
  1021		local_lock_irqsave(&kcov_percpu_data.lock, flags);
  1022	
  1023		mode = READ_ONCE(t->kcov_mode);
  1024		barrier();
  1025		if (!kcov_mode_enabled(mode)) {
  1026			local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
  1027			return;
  1028		}
  1029		/*
  1030		 * When in softirq, check if the corresponding kcov_remote_start()
  1031		 * actually found the remote handle and started collecting coverage.
  1032		 */
  1033		if (in_serving_softirq() && !t->kcov_softirq) {
  1034			local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
  1035			return;
  1036		}
  1037		/* Make sure that kcov_softirq is only set when in softirq. */
  1038		if (WARN_ON(!in_serving_softirq() && t->kcov_softirq)) {
  1039			local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
  1040			return;
  1041		}
  1042	
  1043		kcov = t->kcov;
  1044		area = t->kcov_state.area;
  1045		size = t->kcov_state.size;
  1046		trace = t->kcov_state.trace;
  1047		trace_size = t->kcov_state.trace_size;
  1048		sequence = t->kcov_state.sequence;
  1049	
  1050		kcov_stop(t);
  1051		if (in_serving_softirq()) {
  1052			t->kcov_softirq = 0;
  1053			kcov_remote_softirq_stop(t);
  1054		}
  1055	
  1056		spin_lock(&kcov->lock);
  1057		/*
  1058		 * KCOV_DISABLE could have been called between kcov_remote_start()
  1059		 * and kcov_remote_stop(), hence the sequence check.
  1060		 */
  1061		if (sequence == kcov->state.sequence && kcov->remote)
  1062			kcov_move_area(kcov->mode, kcov->state.area, kcov->state.size,
  1063				       area);
  1064		spin_unlock(&kcov->lock);
  1065	
  1066		if (in_task()) {
  1067			spin_lock(&kcov_remote_lock);
  1068			kcov_remote_area_put(area, size);
  1069			spin_unlock(&kcov_remote_lock);
  1070		}
  1071	
  1072		local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
  1073	
  1074		/* Get in kcov_remote_start(). */
  1075		kcov_put(kcov);
  1076	}
  1077	EXPORT_SYMBOL(kcov_remote_stop);
  1078	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202506271946.HACEE9U0-lkp%40intel.com.
