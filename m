Return-Path: <kasan-dev+bncBC4LXIPCY4NRBAXRVS3QMGQEUP6EPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C9AC97C0BE
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 22:31:00 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-20537e42b7asf3277775ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 13:31:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726691459; cv=pass;
        d=google.com; s=arc-20240605;
        b=NRFBNxcUo16kOaKFUPSFxxqkl/4e7QheW6uXBxrYhVqFWuNyGan68I1ftkRD3DS+I5
         EAJaFvzDRmHgsreIPnU3AL5CpoypFwkGEVgnkY2cuJqeH1ifySKMDiHlWNJt63rwI71e
         i6kSUX3O06qS7fsjJdR0n6wHQ0SMT/yrg+4rBzkGQEBblGq0ABGh/phVUDyOYSNBZ49N
         PqFnpUzjaDkf7bRstD6+NabHLmdb3PPrVPv7Hqi8laN35hKf2zoQU9GjXncpXG+KtY+4
         aKyvfvaAQXc70zyL+3g6dHsaEGYpgyWiC2O3fNBbPipmJ7baUo/3cJsZ6oALPonKdRzE
         Vmaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=M5PqsRTh23TczKkoL7W7VS7qv02g+BwGatG0hNFRRNM=;
        fh=sAsIDD9xgB5Zr4g1FViLu1ic9LLceCXl7+pjwPBjRok=;
        b=SKijEwvPK89y0gZbRX7njjrLSoJEh89/ImqFhzJ/YXRaRy4o0uow4E2jjIY2cN+cqB
         241vq9CGd8g5i1kvvwvV4xsvPxj/cG6PZrKMCsqLQ0/E+dJAarLl4RjmayXGFH2/je7A
         2H6m/B9QCMNihmnI3KBOAGfYJkVU5Sf5Gs7vhOnjaVMn/YrZXG82yapgbStqfxyk4Osi
         djm/jmOUmFzA25RATaLjtbqSQSxYZk+b1axTjm2BvBkl+3b1y8re8Top3mN/xtRZRTy2
         dgTRwcG7B8KiitOt0Rt1ClbRBiSJfR7WNeSxoJRVjg8dL/UKB5lFGWOL4OKCm1xHjdoo
         wjlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DKOvUFhr;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726691459; x=1727296259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=M5PqsRTh23TczKkoL7W7VS7qv02g+BwGatG0hNFRRNM=;
        b=OhdZwljXAFsBRVE+hPPR1ydsJoyTcVrllWEr/fT4PsRumfBLZDFlIJO2kYeE/v8ekx
         yltmX4zGfMtn+MPKkR2yz57HZS8rXOXKNF84LkOKKpCW5/VMcu1sv7Uj1T4/7pmziQyI
         TTf6eU5tJ+eYfxx7P2jkWTaYFIGU63wjhZFVekg8jn/h6mf1RhhJ0U0MnQgPZTjwya6N
         i4K9Sd22P83fVCDnQhC1F+Gccwcex+qDE+4UGSqHWl9bIr2RSuIQjR6EquGTHfwUkhVs
         OuHTjA1cFsR1XVnQtAd2l4iJZxvinXsaUGyD9q66qW8njhvFq+6t+TQn+uxfA/3aNsMn
         lQKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726691459; x=1727296259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=M5PqsRTh23TczKkoL7W7VS7qv02g+BwGatG0hNFRRNM=;
        b=qMDo+0QqVkWJriVPL1DkbMLp3Gj+WXebzU0qI0tRsM4SFNsPoqW4Sgnwt85fUk3otP
         YKVY3+OXtOU+J6pnTbmsqrl/+3GYf8wsf2aBJHgdKczIZOvQnSi9YUWweLONIkYZ7K0U
         vKgHn151aJrMaT4Cm93+UblimzLtmiqT/G3dDTiwqkhRoDG7cFVQrbQ0yoK8K3zsxm8G
         A+2oz3nlsm9zYAW+DOHqcwPBSz5P5gxepbPXAvSPOGRYxIJOn5DXgS9802X+UOO3ivhW
         zcX4QeZvmrW5pjyXqhQZMDLN68tp7HTmPJR8qNsUJWbyvdRvjsFd8xFE+0A+vednGJt+
         3qdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSbvmw9qfWGbfu7TM/kS6aA2kCaCLZqm51BG5CexHqM7yrSbCAZydT3oczerbqpDFsFZiZHg==@lfdr.de
X-Gm-Message-State: AOJu0YzbDJQbeH2g+P3z8YQKeyDxWKoo5ococgUpaDv/yjH+NjYf94Zc
	BfALU28Xw1vFVUNPYxIC5RIR4dyiVIOs9qdkJo6pmqVr1zDkYG/R
X-Google-Smtp-Source: AGHT+IGdgubYFruz4+48zQPBBefYVc9Y8AvmtUEJpdTqK8tCoFsaL9rpjNqBaSok7mvjs9sZaoCsrw==
X-Received: by 2002:a17:902:f681:b0:206:d8c2:4a79 with SMTP id d9443c01a7336-2076e3366c9mr392568225ad.15.1726691458612;
        Wed, 18 Sep 2024 13:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2283:b0:205:866d:1761 with SMTP id
 d9443c01a7336-208cc009b9dls1816265ad.1.-pod-prod-08-us; Wed, 18 Sep 2024
 13:30:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbCfXa/OIlIrWQKtbIcWBfEye15jH4TgLwk/Y8H8dJCPa3JkQi3nk8hehhQOW6p7SuTdYDLaCkHTI=@googlegroups.com
X-Received: by 2002:a05:6a21:e8d:b0:1cf:6c64:f5de with SMTP id adf61e73a8af0-1cf75f5af88mr34825415637.27.1726691457135;
        Wed, 18 Sep 2024 13:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726691457; cv=none;
        d=google.com; s=arc-20240605;
        b=De4+TvbNAU8Sqm7t1+k+7JUtFUwSZ/Ek7d3aRpBmY4LQUQ5PK4LJpJ2wZAVXQWYKPM
         tp2XJa3oh1bVB63Oo309y5C2tEzoXe7qqOBpeiGioZWvqGRt2z9LElRMW9zz3UKkYg1b
         dZ2Q56spIHgZ1uuurbkGb2oy0OLdjMIeEPUkUcaiAJmgh14G8+B+oneB6Yz004jGBBBO
         7E3ACtyoX9laAo99ifqnYDkhz8fh5xJ0xt9zALOylEtBDZgFBph3NoeIbgK/DnBp/hSx
         mXaw0R/rrZXBdjD3lJ2LwXrruefpVEog1I02yvwf8/unPQ8VFQddT452eJ/x8zKDE4Nd
         +sNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6y93hK9fJeEj8Dp8VzUu/cuJ9J287umls7haJSmnzfw=;
        fh=wOZxOwjH4qrmpqNVXsEBkp5sKLyvNgsUJf9SRZj0BV0=;
        b=BEidxLYAnTbLyX7C04xAurq6IJvmD7wJC8uvWYRGLxAMmgFjPlrxhTsPPT1k3OHuSc
         ie9x61Xi188QP4i0GgFVrhI5NfFB6K2gIgmK9rUWQISXFr3IF0wtxFfWq17Zff7YVEHd
         nVbL5T/+DZG6KLT735Aj1B6+uxemB6Hg/+3gWkUiPEXox9Gt3zb5xlICNugK6fDWIK/z
         1+MztaDx1QZkkVzLXVCMBES/f/zedHEf9jO+dnjsxfAI0b7n+4Bgri/wjjCkrF6gvdx/
         sYp7gjT6HMVELAjg5lLdcZVzJY621k8V5KcBpF5DMGJzJHRmzAtyLgDfejkdbeEHaxvP
         Qr3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DKOvUFhr;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7db499f7264si497982a12.4.2024.09.18.13.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 18 Sep 2024 13:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: Kh4NANyrRUOzAOSC1OL8Tg==
X-CSE-MsgGUID: S530lQXPQOO9wvdR5BPvQg==
X-IronPort-AV: E=McAfee;i="6700,10204,11199"; a="36211524"
X-IronPort-AV: E=Sophos;i="6.10,239,1719903600"; 
   d="scan'208";a="36211524"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Sep 2024 13:30:55 -0700
X-CSE-ConnectionGUID: G03l2KzpRg6lUZ1ybq6Pkw==
X-CSE-MsgGUID: KgXze0/ERmmsxsK33VvTNA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,239,1719903600"; 
   d="scan'208";a="107154632"
Received: from lkp-server01.sh.intel.com (HELO 53e96f405c61) ([10.239.97.150])
  by orviesa001.jf.intel.com with ESMTP; 18 Sep 2024 13:30:48 -0700
Received: from kbuild by 53e96f405c61 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1sr1K1-000Cc6-1d;
	Wed, 18 Sep 2024 20:30:45 +0000
Date: Thu, 19 Sep 2024 04:30:20 +0800
From: kernel test robot <lkp@intel.com>
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
	linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Dimitri Sivanich <dimitri.sivanich@hpe.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Miaohe Lin <linmiaohe@huawei.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Message-ID: <202409190310.ViHBRe12-lkp@intel.com>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240917073117.1531207-8-anshuman.khandual@arm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DKOvUFhr;       spf=pass
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

Hi Anshuman,

kernel test robot noticed the following build errors:

[auto build test ERROR on char-misc/char-misc-testing]
[also build test ERROR on char-misc/char-misc-next char-misc/char-misc-linus brauner-vfs/vfs.all dennis-percpu/for-next linus/master v6.11]
[cannot apply to akpm-mm/mm-everything next-20240918]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Anshuman-Khandual/m68k-mm-Change-pmd_val/20240917-153331
base:   char-misc/char-misc-testing
patch link:    https://lore.kernel.org/r/20240917073117.1531207-8-anshuman.khandual%40arm.com
patch subject: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
config: arm-footbridge_defconfig (https://download.01.org/0day-ci/archive/20240919/202409190310.ViHBRe12-lkp@intel.com/config)
compiler: clang version 20.0.0git (https://github.com/llvm/llvm-project 8663a75fa2f31299ab8d1d90288d9df92aadee88)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240919/202409190310.ViHBRe12-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202409190310.ViHBRe12-lkp@intel.com/

All errors (new ones prefixed by >>):

   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:30:
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |                         ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/pgtable.h:1243:48: note: 'pgd' declared here
    1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
         |                                                ^
>> include/linux/pgtable.h:1245:8: error: array initializer must be an initializer list or wide string literal
    1245 |         pgd_t old_pgd = pgdp_get(pgd);
         |               ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:98:11: warning: array index 3 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
      98 |                 return (set->sig[3] | set->sig[2] |
         |                         ^        ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:98:25: warning: array index 2 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
      98 |                 return (set->sig[3] | set->sig[2] |
         |                                       ^        ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:11: warning: array index 3 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     114 |                 return  (set1->sig[3] == set2->sig[3]) &&
         |                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:114:27: warning: array index 3 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     114 |                 return  (set1->sig[3] == set2->sig[3]) &&
         |                                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:115:5: warning: array index 2 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     115 |                         (set1->sig[2] == set2->sig[2]) &&
         |                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:115:21: warning: array index 2 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     115 |                         (set1->sig[2] == set2->sig[2]) &&
         |                                          ^         ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:157:1: warning: array index 3 is past the end of the array (that has type 'const unsigned long[2]') [-Warray-bounds]
     157 | _SIG_SET_BINOP(sigorsets, _sig_or)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:138:8: note: expanded from macro '_SIG_SET_BINOP'
     138 |                 a3 = a->sig[3]; a2 = a->sig[2];                         \
         |                      ^      ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
--
     163 | _SIG_SET_BINOP(sigandnsets, _sig_andn)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:140:3: note: expanded from macro '_SIG_SET_BINOP'
     140 |                 r->sig[3] = op(a3, b3);                                 \
         |                 ^      ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:163:1: warning: array index 2 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
     163 | _SIG_SET_BINOP(sigandnsets, _sig_andn)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:141:3: note: expanded from macro '_SIG_SET_BINOP'
     141 |                 r->sig[2] = op(a2, b2);                                 \
         |                 ^      ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:187:1: warning: array index 3 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
     187 | _SIG_SET_OP(signotset, _sig_not)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:174:27: note: expanded from macro '_SIG_SET_OP'
     174 |         case 4: set->sig[3] = op(set->sig[3]);                          \
         |                                  ^        ~
   include/linux/signal.h:186:24: note: expanded from macro '_sig_not'
     186 | #define _sig_not(x)     (~(x))
         |                            ^
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:187:1: warning: array index 3 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
     187 | _SIG_SET_OP(signotset, _sig_not)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:174:10: note: expanded from macro '_SIG_SET_OP'
     174 |         case 4: set->sig[3] = op(set->sig[3]);                          \
         |                 ^        ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:187:1: warning: array index 2 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
     187 | _SIG_SET_OP(signotset, _sig_not)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:175:20: note: expanded from macro '_SIG_SET_OP'
     175 |                 set->sig[2] = op(set->sig[2]);                          \
         |                                  ^        ~
   include/linux/signal.h:186:24: note: expanded from macro '_sig_not'
     186 | #define _sig_not(x)     (~(x))
         |                            ^
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:1131:
   In file included from include/linux/huge_mm.h:8:
   In file included from include/linux/fs.h:33:
   In file included from include/linux/percpu-rwsem.h:7:
   In file included from include/linux/rcuwait.h:6:
   In file included from include/linux/sched/signal.h:6:
   include/linux/signal.h:187:1: warning: array index 2 is past the end of the array (that has type 'unsigned long[2]') [-Warray-bounds]
     187 | _SIG_SET_OP(signotset, _sig_not)
         | ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   include/linux/signal.h:175:3: note: expanded from macro '_SIG_SET_OP'
     175 |                 set->sig[2] = op(set->sig[2]);                          \
         |                 ^        ~
   arch/arm/include/asm/signal.h:17:2: note: array 'sig' declared here
      17 |         unsigned long sig[_NSIG_WORDS];
         |         ^
   In file included from arch/arm/kernel/asm-offsets.c:12:
   In file included from include/linux/mm.h:2232:
   include/linux/vmstat.h:517:36: warning: arithmetic between different enumeration types ('enum node_stat_item' and 'enum lru_list') [-Wenum-enum-conversion]
     517 |         return node_stat_name(NR_LRU_BASE + lru) + 3; // skip "nr_"
         |                               ~~~~~~~~~~~ ^ ~~~
   In file included from arch/arm/kernel/asm-offsets.c:12:
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                                   ^
   arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                            ^
   include/linux/mm.h:2819:61: note: 'pgd' declared here
    2819 | static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
         |                                                             ^
>> include/linux/mm.h:2822:28: error: passing 'const volatile pmdval_t *' (aka 'const volatile unsigned int *') to parameter of type 'pmdval_t *' (aka 'unsigned int *') discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
    2822 |         return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
         |                 ~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~
   arch/arm/include/asm/pgtable.h:154:25: note: expanded from macro 'pgdp_get'
     154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
         |                                 ^
   include/asm-generic/rwonce.h:47:28: note: expanded from macro 'READ_ONCE'
      47 | #define READ_ONCE(x)                                                    \
         |                                                                         ^
   include/linux/compiler.h:77:42: note: expanded from macro 'unlikely'
      77 | # define unlikely(x)    __builtin_expect(!!(x), 0)
         |                                             ^
   include/asm-generic/pgtable-nop4d.h:21:34: note: passing argument to parameter 'pgd' here
      21 | static inline int pgd_none(pgd_t pgd)           { return 0; }
         |                                  ^
   29 warnings and 18 errors generated.
   make[3]: *** [scripts/Makefile.build:117: arch/arm/kernel/asm-offsets.s] Error 1
   make[3]: Target 'prepare' not remade because of errors.
   make[2]: *** [Makefile:1194: prepare0] Error 2
   make[2]: Target 'prepare' not remade because of errors.
   make[1]: *** [Makefile:224: __sub-make] Error 2
   make[1]: Target 'prepare' not remade because of errors.
   make: *** [Makefile:224: __sub-make] Error 2
   make: Target 'prepare' not remade because of errors.


vim +1245 include/linux/pgtable.h

  1242	
  1243	static inline int pgd_none_or_clear_bad(pgd_t *pgd)
  1244	{
> 1245		pgd_t old_pgd = pgdp_get(pgd);
  1246	
  1247		if (pgd_none(old_pgd))
  1248			return 1;
  1249		if (unlikely(pgd_bad(old_pgd))) {
  1250			pgd_clear_bad(pgd);
  1251			return 1;
  1252		}
  1253		return 0;
  1254	}
  1255	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202409190310.ViHBRe12-lkp%40intel.com.
