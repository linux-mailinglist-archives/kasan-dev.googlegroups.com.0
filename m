Return-Path: <kasan-dev+bncBC4LXIPCY4NRBMWGVDCAMGQE4JNVWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 21646B161CA
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 15:50:44 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-3322db3e985sf2693971fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 06:50:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753883443; cv=pass;
        d=google.com; s=arc-20240605;
        b=LkBVh0DsRFLTP1rprUPr4HnqdFDMvyGnrV6TNWe/VOlb342tE5lb8VOfOxIEjfUrNd
         QQjyVuicFDmiJPTQqzt9Btk+paCuTU1EBmOhM0/zCoq2Nbp/3lwhP1/qYeD8CgVRunUN
         hS1r5bYlCYZu8ARMHTz7BsgT8KfBR1e/MzSety4tTAVBjSkQ52PIb/uSra3JGjj+xCBm
         Rbx5vIhH9n9Bs/B8thTGGAgq9b8lTdskulHIWQEwmlSvlvZbW2x2s90myphWNd6w3FWx
         yWa7+2gG57j/RA+dqgybogsfzcrBAt7KqCSWgibaC7wITxiSrDBopRY8TtVaBfGK4sHc
         3+uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=T58r9RbWvNsOWDtKBnKSMhsXpg0Drm990yBc/WWDwb4=;
        fh=tV907Tvt93azqr5zokbZQM05qWJB3rY4IrDafHUh2gM=;
        b=kN8oE/uTEynMlcrVJiSQUsRe2DaLjHSvRiSXWQrQ1Mr3Y6OfEjEmy4lbUu5qijLduh
         ikgcNpWml7NCH19AWLm/gnh2Vs2nnYfGJZvx1NoOhQJ4r5PnD5FNnGaXwriHYl1Aobxm
         14/OyVqerCstxnZIvgLMpX7HYgI0G0rFabIMjvWyGwc1fJOggRIyB8+qe8OTS4Qpi/xm
         ba1Mmydqlmg1kcDyHkX5fkA4tEvyF6Q+J4T9u27yEkXACVJdnsPvsu9qXKMVBPcIS+p1
         8cVLBeqGZw6rahJXnap3DY2rWcASoQBlU1vbd0QDJCU74WvOeAjCMLf5u1vv8aKxNfWo
         zilA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="TmyiJ/9A";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753883443; x=1754488243; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=T58r9RbWvNsOWDtKBnKSMhsXpg0Drm990yBc/WWDwb4=;
        b=g8dPxKTWa0cs9uHu/NdGV9Qz+OzJoJrv0UYA6saGNqxersc8qdcRuVJpGo1+YUfqnE
         /Aaetgl+EjTutDe4xnQm6mJC7WplZQjoGyNXHVV3hbzDwVNgY9LUeTtNSto4Oy58qEyZ
         CgrZm1JLmQ79N7brbxTpGJCTA9xYVm3vuU41Q+Bcbs5ZO/pkf8e3cjUCv8mZCE8g6r1d
         wfkwzyp3zT4jcWN8uGaewGu1ZgdsSj3kWWaB8d77JbopDUySJDWGWkCByP3IoG9MUz8n
         uzXxcaJWcFgoxm/m2dhznwCg6B09hS0XJjCQqoango2Zru4bdP5999JiM7+0igbnNEbE
         1dTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753883443; x=1754488243;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=T58r9RbWvNsOWDtKBnKSMhsXpg0Drm990yBc/WWDwb4=;
        b=vQaJRxekKioY4yr1sgKUyJfkK3rKwFd0OIN24EKBqqtKh1OSDFZ/DBbt5XG7mi5RYI
         8cSIlLQ65ZPvMOnSwIPr3SxKpIXdcouAlgynSWJ0Jn4U2QdhNBh7r7IoWYyMfoS+/lP6
         OqaBcbiFjNU8M+S16G6F3JdmK9+o6KK05T8vRuFUhWxmehIFUeC4Q6UC77nXBirM5rvI
         J9BG43QMKd0KN/s/bpb+J4zcJEmKsuLYavbQZvTFuybjUU3DkHzA0mI+I/okv0j9J0LN
         GVkfs19PySV/GtzFZOlpuVad69gKUDfZq919QhipCLdoBLY2jylsjQmGXreQX8j0qOGX
         AqOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6Q8KekUCFlPUGZUXGywR1FPmGI0yf+yNY4YVFUvOniT+NmgTodvgb01PqH+aXe3im69nPnQ==@lfdr.de
X-Gm-Message-State: AOJu0YzZOEtygJwlaRg0hQhHwW4yIXCLR4THOFakVhXzo5ZY8h1eiVlx
	LQRErz6SevUZmJtpOmbzF76Tox/ktcUY2kSQa0OtQfzZoscYFrB0BxvG
X-Google-Smtp-Source: AGHT+IEouyk3KPk/UFHtBed35tV4vQ+yFm7wR9NJ6WV8DrEwmulnWpXaBPWmahGQA8wLwNfr4LQVRA==
X-Received: by 2002:a05:651c:e01:b0:32b:3c11:5177 with SMTP id 38308e7fff4ca-33224b8ea53mr6805251fa.21.1753883443036;
        Wed, 30 Jul 2025 06:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYMNXI4hNmd3njOeOJohzIEjFzlxXCqt7sfYTRzgiNVg==
Received: by 2002:a05:651c:31d2:b0:32b:800e:a2ed with SMTP id
 38308e7fff4ca-331ddabeb30ls11652621fa.1.-pod-prod-09-eu; Wed, 30 Jul 2025
 06:50:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTPnGUca8P5pyi/o7k24LFJeRNQDa9Fk6rRMGTidk+07DZSBx/DLSqSAcppcs5iI4M9a3gFQ5wo2E=@googlegroups.com
X-Received: by 2002:a05:6512:2306:b0:553:2cc1:2bb2 with SMTP id 2adb3069b0e04-55b7c01275fmr1154300e87.6.1753883440004;
        Wed, 30 Jul 2025 06:50:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753883439; cv=none;
        d=google.com; s=arc-20240605;
        b=XdoKYaKExvhziQlXvijiP/EP4T90x3Lgv2kyeWCt/bvT1wL71+PZUCUFi/vlNPwPoz
         /DzcGWj4M5b6FwErAntfJawpJfM4KLAskx1M7XQKVoqSJLKuM+uIVBDzPSHMC0MlKKKu
         bYVyYb2eg+UUWUO0IdAGM4kX5rz3RXa3lHY1CII8BottazMBoMBQ1TUWEKCHKU/SQTH0
         hPHTppXXJo58Pz1LD9C2h3RmXUvFBSmEy/j8kJmRcRzBl8nER0u/bLe8m7G0ZBHZ8XE2
         6BZT8D7sjHcyF/NqFYByXx/nfNUvWrWkkZ7Kkw6LbxNZzmqvXbLTkj2m0tyxWprJDILN
         WVSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4FLIOVPVaNxXzhqT6xfvPiIDjctvIZxcWxUZsUX7taw=;
        fh=I4sR73IDP66RYPHpdM8/ub26JNYtFDs/K1MHev7CqEs=;
        b=TwZesHAZCdVv0SCUy0rAJlBU9feF4H9eOt8Tc1tVDWEh0vAbYhgRx0+JgxWR0Ztd9a
         xc9Gv7pdNbJiasIJ6i0OFgCZvMFBHxdBiaNOC5pt04GdK5ubDrf0kDEZPrmyozwa29N+
         vF0F/3HxnZdbQjL5SxxDE4kjZc9/itvZ6l/eXQhvHnKpbDCKHQ/XUFt2LCBa+FFsnXFc
         KCrpQJjr6kfX9/W/ALcI8+JrW2qTDnpTXnx3E5AncGbnwkHpFOBj5ui71miTPfE4vzQo
         a8ve46vTfn0wWQG1XNLc4Kwv5UO1r7jrw7ExYvj5u58hBK2nowqb2xhOgD4NOhc/JAz8
         ps0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="TmyiJ/9A";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.15])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b63316f74si354891e87.6.2025.07.30.06.50.38
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 30 Jul 2025 06:50:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.15 as permitted sender) client-ip=192.198.163.15;
X-CSE-ConnectionGUID: h591qS5jQAWzuxrR4t0Gvw==
X-CSE-MsgGUID: CXzuIQlITy23JkfQd3grgg==
X-IronPort-AV: E=McAfee;i="6800,10657,11507"; a="56331424"
X-IronPort-AV: E=Sophos;i="6.16,350,1744095600"; 
   d="scan'208";a="56331424"
Received: from orviesa002.jf.intel.com ([10.64.159.142])
  by fmvoesa109.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Jul 2025 06:50:32 -0700
X-CSE-ConnectionGUID: 43tHoqJqSGyDw3huzPrupQ==
X-CSE-MsgGUID: 4qJf4K0QTxGvRBFc0JAQkg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,350,1744095600"; 
   d="scan'208";a="193978560"
Received: from lkp-server01.sh.intel.com (HELO 160750d4a34c) ([10.239.97.150])
  by orviesa002.jf.intel.com with ESMTP; 30 Jul 2025 06:50:28 -0700
Received: from kbuild by 160750d4a34c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uh7CL-0002nY-2G;
	Wed, 30 Jul 2025 13:50:25 +0000
Date: Wed, 30 Jul 2025 21:50:12 +0800
From: kernel test robot <lkp@intel.com>
To: Marie Zhussupova <marievic@google.com>, rmoar@google.com,
	davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, elver@google.com,
	dvyukov@google.com, lucas.demarchi@intel.com,
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com,
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
	Marie Zhussupova <marievic@google.com>
Subject: Re: [PATCH 2/9] kunit: Introduce param_init/exit for parameterized
 test shared context management
Message-ID: <202507302114.xQU4zmX5-lkp@intel.com>
References: <20250729193647.3410634-3-marievic@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250729193647.3410634-3-marievic@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="TmyiJ/9A";       spf=pass
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

Hi Marie,

kernel test robot noticed the following build errors:

[auto build test ERROR on shuah-kselftest/kunit]
[also build test ERROR on shuah-kselftest/kunit-fixes drm-xe/drm-xe-next linus/master v6.16 next-20250730]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Marie-Zhussupova/kunit-Add-parent-kunit-for-parameterized-test-context/20250730-033818
base:   https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git kunit
patch link:    https://lore.kernel.org/r/20250729193647.3410634-3-marievic%40google.com
patch subject: [PATCH 2/9] kunit: Introduce param_init/exit for parameterized test shared context management
config: x86_64-rhel-9.4-rust (https://download.01.org/0day-ci/archive/20250730/202507302114.xQU4zmX5-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f0227cb60147a26a1eeb4fb06e3b505e9c7261)
rustc: rustc 1.88.0 (6b00bc388 2025-06-23)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250730/202507302114.xQU4zmX5-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202507302114.xQU4zmX5-lkp@intel.com/

All errors (new ones prefixed by >>):

>> error[E0063]: missing fields `param_exit` and `param_init` in initializer of `kunit_case`
   --> rust/kernel/kunit.rs:200:5
   |
   200 |     kernel::bindings::kunit_case {
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing `param_exit` and `param_init`
--
>> error[E0063]: missing fields `param_exit` and `param_init` in initializer of `kunit_case`
   --> rust/kernel/kunit.rs:219:5
   |
   219 |     kernel::bindings::kunit_case {
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing `param_exit` and `param_init`

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507302114.xQU4zmX5-lkp%40intel.com.
