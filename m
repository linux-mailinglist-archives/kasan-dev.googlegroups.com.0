Return-Path: <kasan-dev+bncBC4LXIPCY4NRBRW2VDCAMGQEBVFGY2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F9B7B162E5
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 16:33:44 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-332121eabd7sf14343501fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 07:33:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753886024; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nodcp8gMS/McGoUlqbEiyGPdp0dlrBTmCChqPxcs/bNAYEvUbIZ5/KDw+vyOjWo0Dx
         QiPqb6JilI8hjD5jrlV5O4lgnXSUqVNQhe9+iHz8yjoTSPRM4FWKHXg6FZO5g8oYkuRK
         EqUCCAzbyFryfG6vj0VbDIkunB9R/vDoBeMce/2cUHcme8m/ppENJrZw+N7iv5h2wJ6Q
         TWS+jKYcF15ZRObRl5DDeq+YscouQZfyge+uKHQIiPRscY2PBtUPCn8r+Oa+3bwPmdOv
         vU+8dHm9CJ7FcLtaeK3hXwC6vDAObtRFtBwFx9V/iQn57K0HpmmhdKACpcwQLpxRmXRy
         2i8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=cRYFVNTpxe9l/M5yrLGtMOmIFCVYR7e3PTWpBiKiwBU=;
        fh=xDiTfS9fs8UMtSqgJOSq9mIFWmmpe5qQESHPz7JNiXU=;
        b=cqy6uH0f9umOG7fhvJHscPfkyW0PPsvjsfkJaLeUlr3LKjdfHpHdcPSp9Pa0+zRFC8
         hZFADIafYLzw+/ghnVNbw5GLH1bONKNjyKlnqscU0w0+flxd1HFJSxmDJnFfQperdaRz
         W6k/gjTyZYB5dtOYiJlf+MguVAP+f+0R99glXsBL164wQWzm+0Tq7fT01iPLSqpmEZuA
         o9xV6ldMpWzbaamlEGzsBc8umYrEePpNy6oIT3pdnqm78Y3G+StISZvWsNIK9NN7o35K
         BAtmw2HfMNILKH4+sutcy6paBxdNvLpCsXljgWj0+5VgIApeDCw8DBaBfOi7Se6AmKJY
         qnow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kCl7TQpi;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753886024; x=1754490824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cRYFVNTpxe9l/M5yrLGtMOmIFCVYR7e3PTWpBiKiwBU=;
        b=w+vhW5vzlLbsDfA4YS40TNhIx0NZbqY4hPjFuG6wgXNVa8MSKZPvSDz79tpao06ZPT
         hJwH0wqQzp+i1azatdX2FqtOQrOZhbQqIPEQoMknOPQjoJ2y0QtEyjzhn16S71ud7BY8
         jO+W0Kmz86hZV0ug5syBmVwhATcpY5CL3s3etw8RHS1fFHcbQTtZIgPFSQI0aVtJK3OT
         QFioKPFsRXk72iAVMyHpYwcGL3cs6g2+n1jFdIJCn38KGsC3+4dps316lF5LwwgjWCRR
         nnNEhZ0J6N7+QzmW96AwwTuRuxzdOCcXXkKvwwZD3yRM1e2+klYwDaBlL3IOKsQHl+ck
         UL0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753886024; x=1754490824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cRYFVNTpxe9l/M5yrLGtMOmIFCVYR7e3PTWpBiKiwBU=;
        b=S3Q9hrqhfXWxu9nC57Rzj1qqIcMgwMh9PlBFd7zlpcawiKtIeBzF7efRccrmoWnnb7
         96pcy8QFaK4czf19ViS3uIXxVcpsdv7bInG0y8l/CTMbQ1KI6hl1t3te074/Zo6ia+6u
         X2X8KyHrMwg5BfbbqO4ul9CoR8r+/KVytnf7J9iJV5XahFMSyn3BcqB+ZX6LYAOyOd94
         hZYLKyjDDTsxbud0YtzwyeEnqvhdlhfbZfRLXK09Hz7P++gByh02+S0gMY0RWGK6p6/F
         2LLzeSL6JzU9eUkGwnmf2LaH0y6tZKS5CH3tGW/D5JINsxZ+1OwiR6xaQu1EzQHWJCGG
         4D7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVla2uP006XE1/FslmCSjmUsJJIrp/xQOQxQ872ek60s50ukmxKx1DfUvP0wDKA4Yenc5//gw==@lfdr.de
X-Gm-Message-State: AOJu0Yx+bGUgKQHIQx4Ger741+9DYJDkIpAPg2QRKvMfYN4Hn+QWWTtc
	4uU2+yTxsTDGc5uqtGf852DZ+e8k2kuwWVsoMYV5bhvKjxi12S5bnPii
X-Google-Smtp-Source: AGHT+IH6v4VUsVTzkP52uAU9AuZZgnbQj4FA0RyP4/HNssOEmt0U4BEW4b74HI89L/YqDBC6qW9i4w==
X-Received: by 2002:a2e:a584:0:b0:32b:a8f7:9176 with SMTP id 38308e7fff4ca-33224a72637mr11292131fa.3.1753886023511;
        Wed, 30 Jul 2025 07:33:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdCoUGl2PM4jOrp8KIJoFdY6VznZRbXzkmBLrAXgmMkqg==
Received: by 2002:a05:651c:f13:b0:32a:6413:a9e with SMTP id
 38308e7fff4ca-331ddaab453ls16549641fa.1.-pod-prod-08-eu; Wed, 30 Jul 2025
 07:33:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4HY27dBr14n3NMYaCSp6SR4L6z5S8Ig0n4xyj03lGq0utxn+rGros/Jo29fxWC5IeNXJxLsxnLc0=@googlegroups.com
X-Received: by 2002:a05:651c:31d9:b0:32a:88ca:ec18 with SMTP id 38308e7fff4ca-33224aaacbfmr11066821fa.10.1753886020587;
        Wed, 30 Jul 2025 07:33:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753886020; cv=none;
        d=google.com; s=arc-20240605;
        b=P6/ETyCvhV3I221xfuv0xI/yZf1x4kxVpJwONSwdjIz7yzBXConbbOdOnMWOCT/q2m
         x1wLL6Q8MHItH7KoBE+uEbAyw/nwOHgEs1wZDWszEzCwaoa1bBse4E6Q9I/nIuHBbXll
         4iztADsW45YizC+iW6NdtuPUqYCmSLKJNL0j4Wdt+ED1but+Wy/oQpRKYsVLBM9mD0yj
         c1rfLRz6cVG5dByirw/S7A2sGJoIBepzifbJqIbOb+TA90KQJuOm8JiwSk1YWLicxeRP
         tTvnF2cuiAGw6nKJbz0OnQN+k+++W8Tz2dcYyg8q+E3VRtjtklLI5Na2Gd74spuveD5a
         eFjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tQgLjpBRTo21GnJkpm5db97pdL7+pJL8b5gqsOwD7nk=;
        fh=I4sR73IDP66RYPHpdM8/ub26JNYtFDs/K1MHev7CqEs=;
        b=bhUPDDbnVWJQmaiaOfIbC0KMRqwhhxKaKUSY97Q8qPD4xKMQiybxOfeUiz440q8A3O
         QQbv7I7pqimka8EQO+pnGfPXhXR9mQhwkf4LV8LOA3hVVlXX6B0BttJTffpyXy2QxAej
         2rdSSNd2lgV8w/5tdatcIMFULlTNC3eKl5yDJ2GebW9gq4DlpDNBXUgBBHy8TNQsjokq
         jskZr1E0ApVNQHHSeCb4QTlwAHszCinr9wOwKewMAhwWc0sgSMOOoKMogAOzcLDzkmLE
         diVy8tdk9FuUkhaWbFBmqvr+qIhJf3N5lNy/EHnc3M+uXeVbZng2Q0fo/a98tDrleN4u
         vJ/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kCl7TQpi;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f41ce796si3236521fa.3.2025.07.30.07.33.38
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 30 Jul 2025 07:33:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: grfDnen8QMOVdXzIKu5Tww==
X-CSE-MsgGUID: SqfHwHWKQW2yzn/0j0hwFQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11507"; a="60013799"
X-IronPort-AV: E=Sophos;i="6.16,350,1744095600"; 
   d="scan'208";a="60013799"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Jul 2025 07:33:37 -0700
X-CSE-ConnectionGUID: hkTixScCTg6cwK/DCkLisA==
X-CSE-MsgGUID: zW5cvb46RTmWg/nwgXfSFQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,350,1744095600"; 
   d="scan'208";a="167492737"
Received: from lkp-server01.sh.intel.com (HELO 160750d4a34c) ([10.239.97.150])
  by orviesa004.jf.intel.com with ESMTP; 30 Jul 2025 07:33:33 -0700
Received: from kbuild by 160750d4a34c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1uh7s2-0002pg-1A;
	Wed, 30 Jul 2025 14:33:30 +0000
Date: Wed, 30 Jul 2025 22:32:46 +0800
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
Subject: Re: [PATCH 3/9] kunit: Pass additional context to generate_params
 for parameterized testing
Message-ID: <202507302223.BTl33Nvo-lkp@intel.com>
References: <20250729193647.3410634-4-marievic@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250729193647.3410634-4-marievic@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=kCl7TQpi;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.12 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
Content-Transfer-Encoding: quoted-printable
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
[also build test ERROR on shuah-kselftest/kunit-fixes drm-xe/drm-xe-next li=
nus/master v6.16 next-20250730]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Marie-Zhussupova/kun=
it-Add-parent-kunit-for-parameterized-test-context/20250730-033818
base:   https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselfte=
st.git kunit
patch link:    https://lore.kernel.org/r/20250729193647.3410634-4-marievic%=
40google.com
patch subject: [PATCH 3/9] kunit: Pass additional context to generate_param=
s for parameterized testing
config: arm64-randconfig-002-20250730 (https://download.01.org/0day-ci/arch=
ive/20250730/202507302223.BTl33Nvo-lkp@intel.com/config)
compiler: clang version 20.1.8 (https://github.com/llvm/llvm-project 87f022=
7cb60147a26a1eeb4fb06e3b505e9c7261)
reproduce (this is a W=3D1 build): (https://download.01.org/0day-ci/archive=
/20250730/202507302223.BTl33Nvo-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new versio=
n of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202507302223.BTl33Nvo-lkp@i=
ntel.com/

All errors (new ones prefixed by >>):

   In file included from drivers/gpu/drm/xe/xe_migrate.c:1917:
>> drivers/gpu/drm/xe/tests/xe_migrate.c:772:44: error: incompatible functi=
on pointer types initializing 'const void *(*)(struct kunit *, const void *=
, char *)' with an expression of type 'const void *(const void *, char *)' =
[-Wincompatible-function-pointer-types]
     772 |         KUNIT_CASE_PARAM(xe_migrate_sanity_kunit, xe_pci_live_de=
vice_gen_param),
         |                                                   ^~~~~~~~~~~~~~=
~~~~~~~~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   In file included from drivers/gpu/drm/xe/xe_migrate.c:1917:
   drivers/gpu/drm/xe/tests/xe_migrate.c:773:42: error: incompatible functi=
on pointer types initializing 'const void *(*)(struct kunit *, const void *=
, char *)' with an expression of type 'const void *(const void *, char *)' =
[-Wincompatible-function-pointer-types]
     773 |         KUNIT_CASE_PARAM(xe_validate_ccs_kunit, xe_pci_live_devi=
ce_gen_param),
         |                                                 ^~~~~~~~~~~~~~~~=
~~~~~~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   2 errors generated.
--
   In file included from drivers/gpu/drm/xe/xe_dma_buf.c:319:
>> drivers/gpu/drm/xe/tests/xe_dma_buf.c:285:37: error: incompatible functi=
on pointer types initializing 'const void *(*)(struct kunit *, const void *=
, char *)' with an expression of type 'const void *(const void *, char *)' =
[-Wincompatible-function-pointer-types]
     285 |         KUNIT_CASE_PARAM(xe_dma_buf_kunit, xe_pci_live_device_ge=
n_param),
         |                                            ^~~~~~~~~~~~~~~~~~~~~=
~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   1 error generated.
--
   In file included from drivers/gpu/drm/xe/xe_bo.c:3128:
>> drivers/gpu/drm/xe/tests/xe_bo.c:610:41: error: incompatible function po=
inter types initializing 'const void *(*)(struct kunit *, const void *, cha=
r *)' with an expression of type 'const void *(const void *, char *)' [-Win=
compatible-function-pointer-types]
     610 |         KUNIT_CASE_PARAM(xe_ccs_migrate_kunit, xe_pci_live_devic=
e_gen_param),
         |                                                ^~~~~~~~~~~~~~~~~=
~~~~~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   In file included from drivers/gpu/drm/xe/xe_bo.c:3128:
   drivers/gpu/drm/xe/tests/xe_bo.c:611:38: error: incompatible function po=
inter types initializing 'const void *(*)(struct kunit *, const void *, cha=
r *)' with an expression of type 'const void *(const void *, char *)' [-Win=
compatible-function-pointer-types]
     611 |         KUNIT_CASE_PARAM(xe_bo_evict_kunit, xe_pci_live_device_g=
en_param),
         |                                             ^~~~~~~~~~~~~~~~~~~~=
~~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   In file included from drivers/gpu/drm/xe/xe_bo.c:3128:
   drivers/gpu/drm/xe/tests/xe_bo.c:624:44: error: incompatible function po=
inter types initializing 'const void *(*)(struct kunit *, const void *, cha=
r *)' with an expression of type 'const void *(const void *, char *)' [-Win=
compatible-function-pointer-types]
     624 |         KUNIT_CASE_PARAM_ATTR(xe_bo_shrink_kunit, xe_pci_live_de=
vice_gen_param,
         |                                                   ^~~~~~~~~~~~~~=
~~~~~~~~~~~~~~
   include/kunit/test.h:228:24: note: expanded from macro 'KUNIT_CASE_PARAM=
_ATTR'
     228 |                   .generate_params =3D gen_params,              =
                  \
         |                                      ^~~~~~~~~~
   3 errors generated.
--
   In file included from drivers/gpu/drm/xe/xe_mocs.c:799:
>> drivers/gpu/drm/xe/tests/xe_mocs.c:193:46: error: incompatible function =
pointer types initializing 'const void *(*)(struct kunit *, const void *, c=
har *)' with an expression of type 'const void *(const void *, char *)' [-W=
incompatible-function-pointer-types]
     193 |         KUNIT_CASE_PARAM(xe_live_mocs_kernel_kunit, xe_pci_live_=
device_gen_param),
         |                                                     ^~~~~~~~~~~~=
~~~~~~~~~~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   In file included from drivers/gpu/drm/xe/xe_mocs.c:799:
   drivers/gpu/drm/xe/tests/xe_mocs.c:194:45: error: incompatible function =
pointer types initializing 'const void *(*)(struct kunit *, const void *, c=
har *)' with an expression of type 'const void *(const void *, char *)' [-W=
incompatible-function-pointer-types]
     194 |         KUNIT_CASE_PARAM(xe_live_mocs_reset_kunit, xe_pci_live_d=
evice_gen_param),
         |                                                    ^~~~~~~~~~~~~=
~~~~~~~~~~~~~~~
   include/kunit/test.h:215:24: note: expanded from macro 'KUNIT_CASE_PARAM=
'
     215 |                   .generate_params =3D gen_params, .module_name =
=3D KBUILD_MODNAME}
         |                                      ^~~~~~~~~~
   2 errors generated.


vim +772 drivers/gpu/drm/xe/tests/xe_migrate.c

54f07cfc016226 Akshata Jahagirdar 2024-07-17  770 =20
0237368193e897 Michal Wajdeczko   2024-07-08  771  static struct kunit_case=
 xe_migrate_tests[] =3D {
37db1e77628551 Michal Wajdeczko   2024-07-20 @772  	KUNIT_CASE_PARAM(xe_mig=
rate_sanity_kunit, xe_pci_live_device_gen_param),
37db1e77628551 Michal Wajdeczko   2024-07-20  773  	KUNIT_CASE_PARAM(xe_val=
idate_ccs_kunit, xe_pci_live_device_gen_param),
0237368193e897 Michal Wajdeczko   2024-07-08  774  	{}
0237368193e897 Michal Wajdeczko   2024-07-08  775  };
0237368193e897 Michal Wajdeczko   2024-07-08  776 =20

--=20
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02507302223.BTl33Nvo-lkp%40intel.com.
