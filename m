Return-Path: <kasan-dev+bncBC4LXIPCY4NRB2EE4C4AMGQE5ERYKTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B65E9AB72C
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 21:52:10 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-7d4f9974c64sf4077319a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 12:52:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729626728; cv=pass;
        d=google.com; s=arc-20240605;
        b=D7QrWdOaAZdldazmWwWiJvdJ9BX8yL9Sn28wnGrZps3AkPLb6QMbg0/+DvbUTsVtc8
         498+1zF3Miax26lxa/j1psh8cOVfcNYPS7MqwHG9bdZhRZEHPP6AHXeoczFQI0ZIKX9h
         utDW4+eB4X+UPB9HEx5vcATHxaZRoBVI039C4AOYpq8Jl0VivIt1uXMfF6mA+6d0XgbV
         g4hp2YLVOnWIon4Iqk83mZ1lPgXFhWG0cYDIqtvWH3B5oeSdtLsk4gipKtmDghQKW3s4
         w9a2gdQ3PfvurHe2Pa9VBrmI+8rS/clYx/VdnEercD5fAT4HegGDMwHqiUkT5jHt8mTu
         e1Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QV66CYxC7s7BBEvxhJbxTc6KtQ0v/0K9P4Rab8u+klI=;
        fh=n67DXXGqlYQ5e3RFFn944X4GmcA8yKEP+FFrtS8FTjc=;
        b=J8y3XFXNUfjQU7f1TrOb89dzEuZ6fUzhpjalyRC9JmNLY3pKuEaUdt5SlkwGXpirXr
         2DeWO2bVkBHlL3yVC7MjQQGNhdSrnEwYYXxJyR3z+K6SFpED4ukdvA8JvDxaKPvPARZq
         d9th24db/OC6L8o/hRKp+pw7qkg+lz7iUTrWz98KQD0EzFtpay7VAuzqf4uASkZodMo3
         IM5qY2w1pwUBzMsL8wjZKqWbLGWXzX9R6sj7hLLiOGr/1QPYu6BEkV8umagkfMbB2HeA
         7nFVSsXroGDmmua4MANz8+cznKKr6IC0dtG5ZN7TFN2ZkrmOo4oS7XoxK1yO58CIqjVC
         0TTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=O3eHJRCJ;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729626728; x=1730231528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QV66CYxC7s7BBEvxhJbxTc6KtQ0v/0K9P4Rab8u+klI=;
        b=kF6bA6a+v1zsnbvfC+tqRPs7akHnmZDJEDvKF+U0uBXe5C1AZtMELUo86eM8mVcNg7
         TeukbjM2fbduvK6ATatvOSgO1qDO2L7/ZPzVZrI13Q9BU9ZE5uBIs4oVbRGiYA+yQXfa
         HEQwcse8pkX6W7136Q1WbpO8hHIYbdzCV03sKwWDOoviSh3pbpMXX0Dz3tp87D1bnajO
         HP+WOjWAxYleFcAA+raeyfwuvgPkmomvQHpSjfW6xBb1Leyi3ntgqpd26wSmb9rltfuz
         UflSGgJRsUh1y3Lq4jVeswFgi9uUOZ2LvN73Cz+b5rird/dN0qcXLQG8lwE9uPVKDc1U
         lbXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729626728; x=1730231528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QV66CYxC7s7BBEvxhJbxTc6KtQ0v/0K9P4Rab8u+klI=;
        b=no53JMPnh51ffpymOUZkJ+2DMQ2JC++zf9VzJKVoqgOJWDYxB+SlSUsShJY28ur/t+
         dms6tnpejvFpw1B8vnCBCL7m2eWo8Zb/J1IFo8PRLUngS5hNz0uRnul64kyKJrHrC9Bh
         +mffeQ79UVzexYtjKtl+JbNoqIIf4iLiyOmDLHSAQVsb5LxW9N4W3Bhd9jK7Yy9oO/7x
         C/dXYxKrIfzaD7Of/SB9/Ya3G4wKKflk/4bU2pcyYzyIK0sc2qaZ0wrt9zseoZSWU21l
         OmpD2N2O6uvKiniPGWjmp4s8PHA9s7u+ZPGkOwwtNSkxedmoUrqmZkhK7ZljPLIck7bD
         SSwQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVn4piVG6EI6oAmJvf4xltQa+o/c6ALuLvbnPaXYQAcmXLv2mlzMan+R/srOreH8HLx4pPS5A==@lfdr.de
X-Gm-Message-State: AOJu0Yzq/3kI5KHuPzzYdHRJ4w/aqgzI+UtNzX1qct0w71WsYkFlBxJX
	VTcvaqiV5SyVVyVCvgEul9vNMmhWhNniNvan41C5vY4dzsltIbg0
X-Google-Smtp-Source: AGHT+IGpqPivI/ktmiYBHu0xl6tHPf6fNmERCtVllzykIV+2Tohf/MNxluVRTt1+2gzwVXa0+mzwVw==
X-Received: by 2002:a17:902:e546:b0:20c:a387:7dc9 with SMTP id d9443c01a7336-20fa9e5b457mr3471835ad.29.1729626728437;
        Tue, 22 Oct 2024 12:52:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:244d:b0:205:43b8:1aa7 with SMTP id
 d9443c01a7336-20d479249e6ls17118805ad.0.-pod-prod-07-us; Tue, 22 Oct 2024
 12:52:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFMl13bEaM7XlobuWOeP/K4ceRWsvZ8NPqJ1GlK3D21ILBMSbAf1vsQNG1oe4eMByBXL63pTMyy3M=@googlegroups.com
X-Received: by 2002:a17:90a:c584:b0:2e2:b204:90c5 with SMTP id 98e67ed59e1d1-2e76b70c2abmr69090a91.33.1729626727205;
        Tue, 22 Oct 2024 12:52:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729626727; cv=none;
        d=google.com; s=arc-20240605;
        b=IEX/xV5ThdExHZE8w77YgUj5U14kVyiCCrOCYyA1Ioe9o7Gj2bsFjYCdyQlg0qUTpR
         ezmrEzUHNNEXuJSY2aoCUMThqCnTYB7H5EiX7aeyP/vuc/uT20v2f82RFjPt0FFxqnw5
         rE6gbheAF9/rCXHYiDv4+37bO3rL7WN1BiRfE4Au26oywmyuAKv2kUeGN0BOWXtxGdRY
         MElqcTeMj9kdzV0+XE/5hYb68PUtkRBpH/kqRSyDIDG0UQmrhn6Ifh6PTKehteAJM4eY
         WEzKm+p5JHgOXEI2YxjgcLzfJ5fd8zT/UQ71t53GTxK/J4HCV7LMHpNBDVOYZR6GYXeg
         7z/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u1oZZkcevuAhRjuDX+kx+SC6oHguIG+OA/zgLHr2GKk=;
        fh=5mZuK4wtlLDi2EWD6X2CkVyM4Fn45lQfsPQg5hYHlwo=;
        b=Aw/FbuEHsQSN2qesCpxWFPmppdqtVMGCFpu8WAu5zmRaguh8pIKHmditvx0nywT3RU
         kqtGW5O+L1MZ2FbJxEgNmEjRhJR3Ybt10EwUpM9EGET62ja9xd1c/tFSyV5xmsdZHiKW
         WfqsUNAXMPX7mP5wRzGD57GQR2gkAzf4W0O+r6dHLOZPfnD+6X6S/CWly+63pVD1mtV7
         +ztQRvnhPoUOSpUSaOF3CCBEACwCj7qj6DWQfOaGoCa7No8uIbm8Y7U3hmlW25Ox8DQV
         iCVbOJrRZF+YcCy2+K+DHMzxYiAXHH2VbGSHzjzKdeeE5ubWlONbg4JvgfQH/naeLCMh
         o26Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=O3eHJRCJ;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e5ad4fcfbesi214970a91.2.2024.10.22.12.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 22 Oct 2024 12:52:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: 9aHoN9Y2RFWygYGoj8SQ7Q==
X-CSE-MsgGUID: euNdhzVcS5mI7oWItH6m/w==
X-IronPort-AV: E=McAfee;i="6700,10204,11222"; a="28965265"
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="28965265"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Oct 2024 12:52:05 -0700
X-CSE-ConnectionGUID: Hd7C0uazSJyFDhVm50mY0g==
X-CSE-MsgGUID: 5xrvzvoTRWWzZR0ykl21Mw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,223,1725346800"; 
   d="scan'208";a="79538027"
Received: from lkp-server01.sh.intel.com (HELO a48cf1aa22e8) ([10.239.97.150])
  by fmviesa006.fm.intel.com with ESMTP; 22 Oct 2024 12:52:01 -0700
Received: from kbuild by a48cf1aa22e8 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1t3Kv9-000U2M-0D;
	Tue, 22 Oct 2024 19:51:59 +0000
Date: Wed, 23 Oct 2024 03:51:25 +0800
From: kernel test robot <lkp@intel.com>
To: Samuel Holland <samuel.holland@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: Re: [PATCH v2 4/9] kasan: sw_tags: Support tag widths less than 8
 bits
Message-ID: <202410230319.eQozBGh7-lkp@intel.com>
References: <20241022015913.3524425-5-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241022015913.3524425-5-samuel.holland@sifive.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=O3eHJRCJ;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.20 as permitted
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

Hi Samuel,

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-everything]
[also build test ERROR on arm64/for-next/core masahiroy-kbuild/for-next masahiroy-kbuild/fixes linus/master v6.12-rc4 next-20241022]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Samuel-Holland/kasan-sw_tags-Use-arithmetic-shift-for-shadow-computation/20241022-100129
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20241022015913.3524425-5-samuel.holland%40sifive.com
patch subject: [PATCH v2 4/9] kasan: sw_tags: Support tag widths less than 8 bits
config: um-allnoconfig (https://download.01.org/0day-ci/archive/20241023/202410230319.eQozBGh7-lkp@intel.com/config)
compiler: clang version 17.0.6 (https://github.com/llvm/llvm-project 6009708b4367171ccdbf4b5905cb6a803753fe18)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20241023/202410230319.eQozBGh7-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202410230319.eQozBGh7-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from arch/um/kernel/asm-offsets.c:1:
   In file included from arch/x86/um/shared/sysdep/kernel-offsets.h:5:
   In file included from include/linux/crypto.h:17:
   In file included from include/linux/slab.h:234:
   In file included from include/linux/kasan.h:7:
   In file included from include/linux/kasan-tags.h:5:
>> arch/um/include/asm/kasan.h:19:2: error: "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
      19 | #error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
         |  ^
   1 error generated.
   make[3]: *** [scripts/Makefile.build:102: arch/um/kernel/asm-offsets.s] Error 1
   make[3]: Target 'prepare' not remade because of errors.
   make[2]: *** [Makefile:1203: prepare0] Error 2
   make[2]: Target 'prepare' not remade because of errors.
   make[1]: *** [Makefile:224: __sub-make] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:224: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +19 arch/um/include/asm/kasan.h

5b301409e8bc5d7 Patricia Alfonso 2022-07-01  12  
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  13  #ifdef CONFIG_X86_64
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  14  #define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  15  /* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  16  #define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  17  			KASAN_SHADOW_SCALE_SHIFT)
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  18  #else
5b301409e8bc5d7 Patricia Alfonso 2022-07-01 @19  #error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  20  #endif /* CONFIG_X86_64 */
5b301409e8bc5d7 Patricia Alfonso 2022-07-01  21  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202410230319.eQozBGh7-lkp%40intel.com.
