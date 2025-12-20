Return-Path: <kasan-dev+bncBC4LXIPCY4NRBIPITLFAMGQEEWV4JIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 563F0CD30D6
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 15:35:16 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-c0c7e0a8ac1sf3739136a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 06:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766241314; cv=pass;
        d=google.com; s=arc-20240605;
        b=KsQn+IXlndJB1K4k5kQUSokizo0LNbc6cX7YC/w5agZvsYoEj1rugFmY0NZP95Ksft
         cz5HKhdMUml3b2g47Yqvb2+suYEyChTDlLrbLFa4PQ7F+cnyh7pH86pMK4BN+eq//D87
         Eukgx26c8ReIIki2SQYJEigQzgiYRrgKjd0NNTeMeClYgRjzqJvnV63EoMADZo2uW9tI
         S/E0TlOsWd4OudwixSKMmevKl+Ibc8+qp4u2d6/EfcrHNf8rjoRPjxmy9XKl6tKuXgen
         /OnouZz6Wq/6uSNd4xy8ZK4nD35gm4St8Pcu0Va/CQQCjjIRki/CJTND1kmjlFd5uz0O
         HeaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9kehfqRCmAUm3oo6kBHhJ4wyS/S8vK6HdvSuF/1vcUs=;
        fh=xkilaxmKbYEMNt6E+04+ki2gj1NCPdALJLweY3gvH7E=;
        b=G2h3y6ZX/1RqIg+VDP6D42hw/OYWPlPB8Trg28yNBatmnUFtJE9qRJ75WzMd3Po9nm
         Kifh/ZOoqLNouJI8gb4Y0C6OzIVTp+PdsSI1Ran6qOfLPLQC5tC6R2v18cJ3oPU/NkAT
         qtxTJWCkxny310cp5VXlgDVYKzuKEN8M0PEIxdk35ZSqNE4nMAaNMJZDP2+EeBroTwYw
         vJi7aU1y8Ofik5xa0AP+zToiVhlESH1pU6Oqq0gdEQFsNlGl3v9S21xdNq5w4B3MApHI
         OUMX353BYD//pn6HGbsDfFyBmjwJgumAPuPCF4KSnppBchxHPyhWkhJKf8OjdMEICbQp
         4EiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aT4J8va5;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766241314; x=1766846114; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9kehfqRCmAUm3oo6kBHhJ4wyS/S8vK6HdvSuF/1vcUs=;
        b=uO7T8IfX6BVX7oegvg+mJOnTQiKCPizKgcAi7pgsIqEaQtdBrKR/FOxyBuqto7gsh5
         dhP+W8ddOghd/XOV7RlErhbGdm9VDnRyWdDTKwAxmfStdAsu70Su6anOgMSSguUkB5eR
         ndMnchhh1zfjtzMeMz8kWe7UEYY8iYdduA6Qz1Ci3fPoLgIkcxT4+38qpLv7yMU9ExV+
         fWWb7md0UhZIQ6fxi8MZTQjWLvKYI73JgFfTmuMt/D51lKqXLi5BNwq+NWlwlEWWecdv
         an9kmPCsBaGcaHX/YOEFFk38wfhUngP6bJVWlICadvFyPfp83YDgv6NQEB5xD1/gEKQX
         lQtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766241314; x=1766846114;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9kehfqRCmAUm3oo6kBHhJ4wyS/S8vK6HdvSuF/1vcUs=;
        b=NawqxHUbiV1P6inZFd3uvX2vqwLy9SmsKll7Q6bh3o0nODRZhF5AeVSQzRwdssVb8y
         CTFtmwumTPbKVGtsi8YEgajB7hBQXVs3EGZv7dTAP2zK79c4xo0SGgOFw/IaPJePFFEP
         AFZFBGSQi4a4k0A4RBoGPQFiWIMRHPasHgtVHLJbJuxIYCFW2zrGP4D5jlch8d9MiSRD
         hrrO5Cd2HDVfmiVr8KZFL5gZe6CyjsZmQ5YsI6DYDxjxGAbTGkloBWKAXIeAeUNzTjro
         wa6XvBUp45yqrnSaLhHZPVwWS5LlQcmLTIPIGSG8NDHA38XsoBstb8bfe7uByoFCKevt
         VCLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULRiqR1N5PP2TiAp7XuLFzmXy0jRPbp4LS9lmszt+govS/mD/WU/aoktZ0lDR8zWxdL+JN+A==@lfdr.de
X-Gm-Message-State: AOJu0Yz77yhb23XhRG6X7LTp1TtHHWzrmKjvEW/xrAF5LdbFj+6zxmoV
	gRQVk77hgC8GbWtjQEksTdQHJKHSu04oSKEYvtXxAx5yukaHM6pqI7b+
X-Google-Smtp-Source: AGHT+IGo5XDaEPS+rslcdgbp89Btr618ylvNLlg628GYlq7uRnllxbdR1PfGEJD5Y4LXwcWnzyAJww==
X-Received: by 2002:a05:7022:428b:b0:11a:44d1:533a with SMTP id a92af1059eb24-121722ab620mr6999126c88.12.1766241313990;
        Sat, 20 Dec 2025 06:35:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZgy96XgWFLDKKLVjffp1OL5niVIJhD2rBPqMJusxn8rg=="
Received: by 2002:a05:7022:438c:b0:11b:50a:6266 with SMTP id
 a92af1059eb24-120568db0d3ls2287095c88.2.-pod-prod-06-us; Sat, 20 Dec 2025
 06:35:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUlUN0QIjqz0VGpSHIk2YeVxrKW3DgtNOSC61ZLcjV7EKbYS5yY5b9ko5di9ROwumaGoyZU3fS79YU=@googlegroups.com
X-Received: by 2002:a05:7300:d113:b0:2ae:595e:83bc with SMTP id 5a478bee46e88-2b05ec32aa4mr5109807eec.28.1766241312343;
        Sat, 20 Dec 2025 06:35:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766241312; cv=none;
        d=google.com; s=arc-20240605;
        b=jZjAZT7R3AESlUrRbOplODdbeD0iJfhBbSpmGFSpNtbf8ILNMaxadS1/5UnDF+TSQH
         iUKZYFr5HDpVYK4YichL2tZei3jQ5cUHUeBARtMcx/cwG8tvMf1VvITlUehUstXtarTS
         fJhL7meRasf9M2Wn9TDpsmIy9yp55vWytS+t2YW4y3qd8tdbuwaT0QqGmH0TOvYR5SoR
         V/9sT+4I6/Og5PaQVEJ+7s2Dt8lO3AaEClymRa7fgPPy7yvcnk/paaSQWwBU322nj6bW
         J8I17JwujVxZlh4PIa0SPOLx9KSYkYsB5XTP3ik+BbGhGVNfy+UVH1341l5+1ohgVcCo
         hhyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3R1bH16DYUdshLY9YhGQKabw0mbK51Bw1imcDfmG+yg=;
        fh=RjKEoS3X8Ay1Mr09WBkqTQEqd2dgjz5J+0dbwFtdeI4=;
        b=TGbnThHpvuPeQ2Tg31HrFyxQ3CqiXrvXBYeqJYJAWhq3f1r+vZG2/c2C6O4/jTzhYT
         4iP/pGgaP7GYWDtr/LsnCtozkzo2eXzhFSkgIKJELZC5pWFPu9InVUp/NjgQZTW6Zdg/
         QpWvRvCiW4LpGTvS5yrAxEOV0Krcvv8A+lJdJcFqZe1fgrFhNxPCnk1X4Cjs7SEZxI3D
         Bc/pNB5yx0WNvr99h3/3c2ZSfo+hCbZgqZfjYOBt9UjN/WLaAAaxiiNwTjAlDCaGl443
         bjDqk105OeHCulnEtMah4Zl4gkWIj8ZebxcFUX6WIYmNR/qoODnGHK8euVSgsU4V4BDD
         D3rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aT4J8va5;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b05fcfc236si58683eec.0.2025.12.20.06.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 20 Dec 2025 06:35:12 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted sender) client-ip=192.198.163.7;
X-CSE-ConnectionGUID: gI4l/2ITTQuEt6i8ZxTWig==
X-CSE-MsgGUID: KdMCKPOyToWzduxpDumnMg==
X-IronPort-AV: E=McAfee;i="6800,10657,11648"; a="93650011"
X-IronPort-AV: E=Sophos;i="6.21,164,1763452800"; 
   d="scan'208";a="93650011"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Dec 2025 06:35:10 -0800
X-CSE-ConnectionGUID: peCcym8jRty19M+j/ABXVw==
X-CSE-MsgGUID: trLAWK7BTMOchQoMARnQSQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,164,1763452800"; 
   d="scan'208";a="199023544"
Received: from lkp-server01.sh.intel.com (HELO 0d09efa1b85f) ([10.239.97.150])
  by fmviesa006.fm.intel.com with ESMTP; 20 Dec 2025 06:35:07 -0800
Received: from kbuild by 0d09efa1b85f with local (Exim 4.98.2)
	(envelope-from <lkp@intel.com>)
	id 1vWy2z-000000004eN-0hbf;
	Sat, 20 Dec 2025 14:35:05 +0000
Date: Sat, 20 Dec 2025 22:34:10 +0800
From: kernel test robot <lkp@intel.com>
To: yuan linyu <yuanlinyu@honor.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>, kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org, yuan linyu <yuanlinyu@honor.com>
Subject: Re: [PATCH v2 1/2] LoongArch: kfence: avoid use
 CONFIG_KFENCE_NUM_OBJECTS
Message-ID: <202512202213.B6MRZ7tt-lkp@intel.com>
References: <20251218063916.1433615-2-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251218063916.1433615-2-yuanlinyu@honor.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=aT4J8va5;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.7 as permitted
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

Hi yuan,

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-everything]
[also build test ERROR on drm-misc/drm-misc-next linus/master v6.19-rc1 next-20251219]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/yuan-linyu/LoongArch-kfence-avoid-use-CONFIG_KFENCE_NUM_OBJECTS/20251218-144322
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20251218063916.1433615-2-yuanlinyu%40honor.com
patch subject: [PATCH v2 1/2] LoongArch: kfence: avoid use CONFIG_KFENCE_NUM_OBJECTS
config: loongarch-randconfig-002-20251220 (https://download.01.org/0day-ci/archive/20251220/202512202213.B6MRZ7tt-lkp@intel.com/config)
compiler: loongarch64-linux-gcc (GCC) 15.1.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20251220/202512202213.B6MRZ7tt-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202512202213.B6MRZ7tt-lkp@intel.com/

All error/warnings (new ones prefixed by >>):

   In file included from arch/loongarch/include/asm/pgtable.h:13,
                    from include/linux/pgtable.h:6,
                    from include/linux/mm.h:31,
                    from arch/loongarch/kernel/asm-offsets.c:11:
>> include/linux/kfence.h:231:49: warning: 'struct kmem_cache' declared inside parameter list will not be visible outside of this definition or declaration
     231 | static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
         |                                                 ^~~~~~~~~~
   include/linux/kfence.h:232:41: warning: 'struct kmem_cache' declared inside parameter list will not be visible outside of this definition or declaration
     232 | static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
         |                                         ^~~~~~~~~~
>> include/linux/kfence.h:245:86: warning: 'struct slab' declared inside parameter list will not be visible outside of this definition or declaration
     245 | static inline bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
         |                                                                                      ^~~~
   In file included from include/linux/pgtable.h:17,
                    from include/linux/mm.h:31,
                    from include/linux/kfence.h:12,
                    from arch/loongarch/include/asm/pgtable.h:13,
                    from arch/loongarch/include/asm/uaccess.h:17,
                    from include/linux/uaccess.h:13,
                    from include/linux/sched/task.h:13,
                    from include/linux/sched/signal.h:9,
                    from kernel/sched/sched.h:17,
                    from kernel/sched/rq-offsets.c:5:
   include/asm-generic/pgtable_uffd.h:27:40: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      27 | static __always_inline int pmd_uffd_wp(pmd_t pmd)
         |                                        ^~~~~
         |                                        pgd_t
   include/asm-generic/pgtable_uffd.h:37:24: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      37 | static __always_inline pmd_t pmd_mkuffd_wp(pmd_t pmd)
         |                        ^~~~~
         |                        pgd_t
   include/asm-generic/pgtable_uffd.h:37:44: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      37 | static __always_inline pmd_t pmd_mkuffd_wp(pmd_t pmd)
         |                                            ^~~~~
         |                                            pgd_t
   include/asm-generic/pgtable_uffd.h:47:24: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      47 | static __always_inline pmd_t pmd_clear_uffd_wp(pmd_t pmd)
         |                        ^~~~~
         |                        pgd_t
   include/asm-generic/pgtable_uffd.h:47:48: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      47 | static __always_inline pmd_t pmd_clear_uffd_wp(pmd_t pmd)
         |                                                ^~~~~
         |                                                pgd_t
   include/asm-generic/pgtable_uffd.h:67:15: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      67 | static inline pmd_t pmd_swp_mkuffd_wp(pmd_t pmd)
         |               ^~~~~
         |               pgd_t
   include/asm-generic/pgtable_uffd.h:67:39: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      67 | static inline pmd_t pmd_swp_mkuffd_wp(pmd_t pmd)
         |                                       ^~~~~
         |                                       pgd_t
   include/asm-generic/pgtable_uffd.h:72:35: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      72 | static inline int pmd_swp_uffd_wp(pmd_t pmd)
         |                                   ^~~~~
         |                                   pgd_t
   include/asm-generic/pgtable_uffd.h:77:15: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      77 | static inline pmd_t pmd_swp_clear_uffd_wp(pmd_t pmd)
         |               ^~~~~
         |               pgd_t
   include/asm-generic/pgtable_uffd.h:77:43: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
      77 | static inline pmd_t pmd_swp_clear_uffd_wp(pmd_t pmd)
         |                                           ^~~~~
         |                                           pgd_t
   In file included from include/linux/pgtable.h:18:
   include/linux/page_table_check.h:121:69: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     121 | static inline void page_table_check_pmd_clear(struct mm_struct *mm, pmd_t pmd)
         |                                                                     ^~~~~
         |                                                                     pgd_t
   include/linux/page_table_check.h:125:69: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     125 | static inline void page_table_check_pud_clear(struct mm_struct *mm, pud_t pud)
         |                                                                     ^~~~~
         |                                                                     pgd_t
   include/linux/page_table_check.h:135:17: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     135 |                 pmd_t *pmdp, pmd_t pmd, unsigned int nr)
         |                 ^~~~~
         |                 pgd_t
   include/linux/page_table_check.h:135:30: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     135 |                 pmd_t *pmdp, pmd_t pmd, unsigned int nr)
         |                              ^~~~~
         |                              pgd_t
   include/linux/page_table_check.h:140:17: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     140 |                 pud_t *pudp, pud_t pud, unsigned int nr)
         |                 ^~~~~
         |                 pgd_t
   include/linux/page_table_check.h:140:30: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     140 |                 pud_t *pudp, pud_t pud, unsigned int nr)
         |                              ^~~~~
         |                              pgd_t
   include/linux/page_table_check.h:146:53: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     146 |                                                     pmd_t pmd)
         |                                                     ^~~~~
         |                                                     pgd_t
>> include/linux/pgtable.h:22:2: error: #error CONFIG_PGTABLE_LEVELS is not consistent with __PAGETABLE_{P4D,PUD,PMD}_FOLDED
      22 | #error CONFIG_PGTABLE_LEVELS is not consistent with __PAGETABLE_{P4D,PUD,PMD}_FOLDED
         |  ^~~~~
   include/linux/pgtable.h: In function 'pte_index':
>> include/linux/pgtable.h:69:43: error: 'PTRS_PER_PTE' undeclared (first use in this function)
      69 |         return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
         |                                           ^~~~~~~~~~~~
   include/linux/pgtable.h:69:43: note: each undeclared identifier is reported only once for each function it appears in
   include/linux/pgtable.h: In function 'pmd_index':
>> include/linux/pgtable.h:75:28: error: 'PMD_SHIFT' undeclared (first use in this function); did you mean 'NMI_SHIFT'?
      75 |         return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
         |                            ^~~~~~~~~
         |                            NMI_SHIFT
>> include/linux/pgtable.h:75:42: error: 'PTRS_PER_PMD' undeclared (first use in this function)
      75 |         return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
         |                                          ^~~~~~~~~~~~
   include/linux/pgtable.h: In function 'pud_index':
>> include/linux/pgtable.h:83:28: error: 'PUD_SHIFT' undeclared (first use in this function); did you mean 'NMI_SHIFT'?
      83 |         return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
         |                            ^~~~~~~~~
         |                            NMI_SHIFT
>> include/linux/pgtable.h:83:42: error: 'PTRS_PER_PUD' undeclared (first use in this function)
      83 |         return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
         |                                          ^~~~~~~~~~~~
   include/linux/pgtable.h: At top level:
>> include/linux/pgtable.h:115:40: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     115 | static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
         |                                        ^~~~~
         |                                        pgd_t
   include/linux/pgtable.h:130:32: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     130 | static inline pte_t *__pte_map(pmd_t *pmd, unsigned long address)
         |                                ^~~~~
         |                                pgd_t
   include/linux/pgtable.h:144:15: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     144 | static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
         |               ^~~~~
         |               pgd_t
>> include/linux/pgtable.h:144:33: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     144 | static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
         |                                 ^~~~~
         |                                 pgd_t
   include/linux/pgtable.h:152:15: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     152 | static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
         |               ^~~~~
         |               pgd_t
>> include/linux/pgtable.h:152:33: error: unknown type name 'p4d_t'; did you mean 'pgd_t'?
     152 | static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
         |                                 ^~~~~
         |                                 pgd_t
   include/linux/pgtable.h: In function 'pgd_offset_pgd':
>> include/linux/pgtable.h:90:32: error: 'PGDIR_SHIFT' undeclared (first use in this function)
      90 | #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
         |                                ^~~~~~~~~~~
   include/linux/pgtable.h:161:23: note: in expansion of macro 'pgd_index'
     161 |         return (pgd + pgd_index(address));
         |                       ^~~~~~~~~
>> include/linux/pgtable.h:90:48: error: 'PTRS_PER_PGD' undeclared (first use in this function)
      90 | #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
         |                                                ^~~~~~~~~~~~
   include/linux/pgtable.h:161:23: note: in expansion of macro 'pgd_index'
     161 |         return (pgd + pgd_index(address));
         |                       ^~~~~~~~~
   include/linux/pgtable.h: At top level:
   include/linux/pgtable.h:184:15: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     184 | static inline pmd_t *pmd_off(struct mm_struct *mm, unsigned long va)
         |               ^~~~~
         |               pgd_t
   include/linux/pgtable.h: In function 'pmd_off':
>> include/linux/pgtable.h:148:20: error: implicit declaration of function 'pmd_offset'; did you mean 'pmd_off'? [-Wimplicit-function-declaration]
     148 | #define pmd_offset pmd_offset
         |                    ^~~~~~~~~~
   include/linux/pgtable.h:186:16: note: in expansion of macro 'pmd_offset'
     186 |         return pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, va), va), va), va);
         |                ^~~~~~~~~~
>> include/linux/pgtable.h:156:20: error: implicit declaration of function 'pud_offset'; did you mean 'pmd_off'? [-Wimplicit-function-declaration]
     156 | #define pud_offset pud_offset
         |                    ^~~~~~~~~~
   include/linux/pgtable.h:186:27: note: in expansion of macro 'pud_offset'
     186 |         return pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, va), va), va), va);
         |                           ^~~~~~~~~~
>> include/linux/pgtable.h:186:38: error: implicit declaration of function 'p4d_offset'; did you mean 'pmd_offset'? [-Wimplicit-function-declaration]
     186 |         return pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, va), va), va), va);
         |                                      ^~~~~~~~~~
         |                                      pmd_offset
>> include/linux/pgtable.h:148:20: error: returning 'int' from a function with return type 'int *' makes pointer from integer without a cast [-Wint-conversion]
     148 | #define pmd_offset pmd_offset
         |                    ^
   include/linux/pgtable.h:186:16: note: in expansion of macro 'pmd_offset'
     186 |         return pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, va), va), va), va);
         |                ^~~~~~~~~~
   include/linux/pgtable.h: At top level:
   include/linux/pgtable.h:189:15: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     189 | static inline pmd_t *pmd_off_k(unsigned long va)
         |               ^~~~~
         |               pgd_t
   include/linux/pgtable.h: In function 'pmd_off_k':
>> include/linux/pgtable.h:148:20: error: returning 'int' from a function with return type 'int *' makes pointer from integer without a cast [-Wint-conversion]
     148 | #define pmd_offset pmd_offset
         |                    ^
   include/linux/pgtable.h:191:16: note: in expansion of macro 'pmd_offset'
     191 |         return pmd_offset(pud_offset(p4d_offset(pgd_offset_k(va), va), va), va);
         |                ^~~~~~~~~~
   include/linux/pgtable.h: In function 'virt_to_kpte':
   include/linux/pgtable.h:196:9: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     196 |         pmd_t *pmd = pmd_off_k(vaddr);
         |         ^~~~~
         |         pgd_t
>> include/linux/pgtable.h:198:16: error: implicit declaration of function 'pmd_none' [-Wimplicit-function-declaration]
     198 |         return pmd_none(*pmd) ? NULL : pte_offset_kernel(pmd, vaddr);
         |                ^~~~~~~~
>> include/linux/pgtable.h:119:27: error: implicit declaration of function 'pte_offset_kernel' [-Wimplicit-function-declaration]
     119 | #define pte_offset_kernel pte_offset_kernel
         |                           ^~~~~~~~~~~~~~~~~
   include/linux/pgtable.h:198:40: note: in expansion of macro 'pte_offset_kernel'
     198 |         return pmd_none(*pmd) ? NULL : pte_offset_kernel(pmd, vaddr);
         |                                        ^~~~~~~~~~~~~~~~~
   include/linux/pgtable.h:198:38: error: pointer/integer type mismatch in conditional expression [-Wint-conversion]
     198 |         return pmd_none(*pmd) ? NULL : pte_offset_kernel(pmd, vaddr);
         |                                      ^
   include/linux/pgtable.h: At top level:
   include/linux/pgtable.h:202:29: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     202 | static inline int pmd_young(pmd_t pmd)
         |                             ^~~~~
         |                             pgd_t
   include/linux/pgtable.h:209:29: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     209 | static inline int pmd_dirty(pmd_t pmd)
         |                             ^~~~~
         |                             pgd_t
   In file included from include/linux/shm.h:6,
                    from include/linux/sched.h:23,
                    from include/linux/percpu.h:12,
                    from include/linux/prandom.h:13,
                    from kernel/sched/sched.h:8:
   include/linux/pgtable.h: In function 'pte_advance_pfn':
   include/linux/pgtable.h:404:44: error: 'PFN_PTE_SHIFT' undeclared (first use in this function)
     404 |         return __pte(pte_val(pte) + (nr << PFN_PTE_SHIFT));
         |                                            ^~~~~~~~~~~~~
   arch/loongarch/include/asm/page.h:46:37: note: in definition of macro '__pte'
      46 | #define __pte(x)        ((pte_t) { (x) })
         |                                     ^
   include/linux/pgtable.h: In function 'set_ptes':
   include/linux/pgtable.h:435:17: error: implicit declaration of function 'set_pte'; did you mean 'set_ptes'? [-Wimplicit-function-declaration]
     435 |                 set_pte(ptep, pte);
         |                 ^~~~~~~
         |                 set_ptes
   include/linux/pgtable.h: At top level:
   include/linux/pgtable.h:461:64: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     461 |                                         unsigned long address, pmd_t *pmdp,
         |                                                                ^~~~~
         |                                                                pgd_t
   include/linux/pgtable.h:462:41: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     462 |                                         pmd_t entry, int dirty)
         |                                         ^~~~~
         |                                         pgd_t
   include/linux/pgtable.h:468:64: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     468 |                                         unsigned long address, pud_t *pudp,
         |                                                                ^~~~~
         |                                                                pgd_t
   include/linux/pgtable.h:469:41: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     469 |                                         pud_t entry, int dirty)
         |                                         ^~~~~
         |                                         pgd_t
   include/linux/pgtable.h:485:15: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     485 | static inline pmd_t pmdp_get(pmd_t *pmdp)
         |               ^~~~~
         |               pgd_t
   include/linux/pgtable.h:485:30: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     485 | static inline pmd_t pmdp_get(pmd_t *pmdp)
         |                              ^~~~~
         |                              pgd_t
   include/linux/pgtable.h:492:15: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     492 | static inline pud_t pudp_get(pud_t *pudp)
         |               ^~~~~
         |               pgd_t
   include/linux/pgtable.h:492:30: error: unknown type name 'pud_t'; did you mean 'pgd_t'?
     492 | static inline pud_t pudp_get(pud_t *pudp)
         |                              ^~~~~
         |                              pgd_t
   include/linux/pgtable.h:499:15: error: unknown type name 'p4d_t'; did you mean 'pgd_t'?
     499 | static inline p4d_t p4dp_get(p4d_t *p4dp)
         |               ^~~~~
         |               pgd_t
   include/linux/pgtable.h:499:30: error: unknown type name 'p4d_t'; did you mean 'pgd_t'?
     499 | static inline p4d_t p4dp_get(p4d_t *p4dp)
         |                              ^~~~~
         |                              pgd_t
   include/linux/pgtable.h: In function 'ptep_test_and_clear_young':
   include/linux/pgtable.h:519:14: error: implicit declaration of function 'pte_young' [-Wimplicit-function-declaration]
     519 |         if (!pte_young(pte))
         |              ^~~~~~~~~
   include/linux/pgtable.h:522:55: error: implicit declaration of function 'pte_mkold' [-Wimplicit-function-declaration]
     522 |                 set_pte_at(vma->vm_mm, address, ptep, pte_mkold(pte));
         |                                                       ^~~~~~~~~
   include/linux/pgtable.h:443:66: note: in definition of macro 'set_pte_at'
     443 | #define set_pte_at(mm, addr, ptep, pte) set_ptes(mm, addr, ptep, pte, 1)
         |                                                                  ^~~
   include/linux/pgtable.h:522:55: error: incompatible type for argument 4 of 'set_ptes'
     522 |                 set_pte_at(vma->vm_mm, address, ptep, pte_mkold(pte));
         |                                                       ^~~~~~~~~~~~~~
         |                                                       |
         |                                                       int
   include/linux/pgtable.h:443:66: note: in definition of macro 'set_pte_at'
     443 | #define set_pte_at(mm, addr, ptep, pte) set_ptes(mm, addr, ptep, pte, 1)
         |                                                                  ^~~
   include/linux/pgtable.h:430:36: note: expected 'pte_t' but argument is of type 'int'
     430 |                 pte_t *ptep, pte_t pte, unsigned int nr)
         |                              ~~~~~~^~~
   include/linux/pgtable.h: At top level:
   include/linux/pgtable.h:544:45: error: unknown type name 'pmd_t'; did you mean 'pgd_t'?
     544 |                                             pmd_t *pmdp)
         |                                             ^~~~~


vim +22 include/linux/pgtable.h

fbd71844852c94 include/asm-generic/pgtable.h Ben Hutchings           2011-02-27   19  
c2febafc67734a include/asm-generic/pgtable.h Kiryl Shutsemau         2017-03-09   20  #if 5 - defined(__PAGETABLE_P4D_FOLDED) - defined(__PAGETABLE_PUD_FOLDED) - \
c2febafc67734a include/asm-generic/pgtable.h Kiryl Shutsemau         2017-03-09   21  	defined(__PAGETABLE_PMD_FOLDED) != CONFIG_PGTABLE_LEVELS
c2febafc67734a include/asm-generic/pgtable.h Kiryl Shutsemau         2017-03-09  @22  #error CONFIG_PGTABLE_LEVELS is not consistent with __PAGETABLE_{P4D,PUD,PMD}_FOLDED
235a8f0286d3de include/asm-generic/pgtable.h Kiryl Shutsemau         2015-04-14   23  #endif
235a8f0286d3de include/asm-generic/pgtable.h Kiryl Shutsemau         2015-04-14   24  
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   25  /*
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   26   * On almost all architectures and configurations, 0 can be used as the
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   27   * upper ceiling to free_pgtables(): on many architectures it has the same
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   28   * effect as using TASK_SIZE.  However, there is one configuration which
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   29   * must impose a more careful limit, to avoid freeing kernel pgtables.
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   30   */
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   31  #ifndef USER_PGTABLES_CEILING
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   32  #define USER_PGTABLES_CEILING	0UL
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   33  #endif
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   34  
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   35  /*
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   36   * This defines the first usable user address. Platforms
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   37   * can override its value with custom FIRST_USER_ADDRESS
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   38   * defined in their respective <asm/pgtable.h>.
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   39   */
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   40  #ifndef FIRST_USER_ADDRESS
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   41  #define FIRST_USER_ADDRESS	0UL
fac7757e1fb05b include/linux/pgtable.h       Anshuman Khandual       2021-06-30   42  #endif
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   43  
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   44  /*
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   45   * This defines the generic helper for accessing PMD page
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   46   * table page. Although platforms can still override this
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   47   * via their respective <asm/pgtable.h>.
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   48   */
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   49  #ifndef pmd_pgtable
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   50  #define pmd_pgtable(pmd) pmd_page(pmd)
1c2f7d14d84f76 include/linux/pgtable.h       Anshuman Khandual       2021-06-30   51  #endif
6ee8630e02be6d include/asm-generic/pgtable.h Hugh Dickins            2013-04-29   52  
e06d03d5590ae1 include/linux/pgtable.h       Matthew Wilcox (Oracle  2024-03-26   53) #define pmd_folio(pmd) page_folio(pmd_page(pmd))
e06d03d5590ae1 include/linux/pgtable.h       Matthew Wilcox (Oracle  2024-03-26   54) 
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   55  /*
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   56   * A page table page can be thought of an array like this: pXd_t[PTRS_PER_PxD]
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   57   *
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   58   * The pXx_index() functions return the index of the entry in the page
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   59   * table page which would control the given virtual address
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   60   *
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   61   * As these functions may be used by the same code for different levels of
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   62   * the page table folding, they are always available, regardless of
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   63   * CONFIG_PGTABLE_LEVELS value. For the folded levels they simply return 0
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   64   * because in such cases PTRS_PER_PxD equals 1.
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   65   */
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   66  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   67  static inline unsigned long pte_index(unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   68  {
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  @69  	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   70  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   71  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   72  #ifndef pmd_index
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   73  static inline unsigned long pmd_index(unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   74  {
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  @75  	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   76  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   77  #define pmd_index pmd_index
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   78  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   79  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   80  #ifndef pud_index
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   81  static inline unsigned long pud_index(unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   82  {
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  @83  	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   84  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   85  #define pud_index pud_index
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   86  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   87  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   88  #ifndef pgd_index
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   89  /* Must be a compile-time constant, so implement it as a macro */
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  @90  #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   91  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08   92  
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   93  #ifndef kernel_pte_init
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   94  static inline void kernel_pte_init(void *addr)
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   95  {
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   96  }
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   97  #define kernel_pte_init kernel_pte_init
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   98  #endif
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04   99  
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  100  #ifndef pmd_init
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  101  static inline void pmd_init(void *addr)
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  102  {
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  103  }
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  104  #define pmd_init pmd_init
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  105  #endif
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  106  
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  107  #ifndef pud_init
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  108  static inline void pud_init(void *addr)
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  109  {
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  110  }
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  111  #define pud_init pud_init
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  112  #endif
7269ed4af34418 include/linux/pgtable.h       Bibo Mao                2024-11-04  113  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  114  #ifndef pte_offset_kernel
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @115  static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  116  {
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  117  	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  118  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @119  #define pte_offset_kernel pte_offset_kernel
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  120  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  121  
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  122  #ifdef CONFIG_HIGHPTE
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  123  #define __pte_map(pmd, address) \
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  124  	((pte_t *)kmap_local_page(pmd_page(*(pmd))) + pte_index((address)))
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  125  #define pte_unmap(pte)	do {	\
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  126  	kunmap_local((pte));	\
a349d72fd9efc8 include/linux/pgtable.h       Hugh Dickins            2023-07-11  127  	rcu_read_unlock();	\
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  128  } while (0)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  129  #else
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  130  static inline pte_t *__pte_map(pmd_t *pmd, unsigned long address)
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  131  {
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  132  	return pte_offset_kernel(pmd, address);
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  133  }
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  134  static inline void pte_unmap(pte_t *pte)
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  135  {
a349d72fd9efc8 include/linux/pgtable.h       Hugh Dickins            2023-07-11  136  	rcu_read_unlock();
0d940a9b270b92 include/linux/pgtable.h       Hugh Dickins            2023-06-08  137  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  138  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  139  
13cf577e6b66a1 include/linux/pgtable.h       Hugh Dickins            2023-07-11  140  void pte_free_defer(struct mm_struct *mm, pgtable_t pgtable);
13cf577e6b66a1 include/linux/pgtable.h       Hugh Dickins            2023-07-11  141  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  142  /* Find an entry in the second-level page table.. */
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  143  #ifndef pmd_offset
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @144  static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  145  {
9cf6fa24584431 include/linux/pgtable.h       Aneesh Kumar K.V        2021-07-07  146  	return pud_pgtable(*pud) + pmd_index(address);
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  147  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @148  #define pmd_offset pmd_offset
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  149  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  150  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  151  #ifndef pud_offset
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @152  static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  153  {
dc4875f0e791de include/linux/pgtable.h       Aneesh Kumar K.V        2021-07-07  154  	return p4d_pgtable(*p4d) + pud_index(address);
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  155  }
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @156  #define pud_offset pud_offset
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  157  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  158  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  159  static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  160  {
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  161  	return (pgd + pgd_index(address));
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  162  };
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  163  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  164  /*
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  165   * a shortcut to get a pgd_t in a given mm
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  166   */
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  167  #ifndef pgd_offset
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  168  #define pgd_offset(mm, address)		pgd_offset_pgd((mm)->pgd, (address))
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  169  #endif
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  170  
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  171  /*
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  172   * a shortcut which implies the use of the kernel's pgd, instead
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  173   * of a process's
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  174   */
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  175  #define pgd_offset_k(address)		pgd_offset(&init_mm, (address))
974b9b2c68f3d3 include/linux/pgtable.h       Mike Rapoport           2020-06-08  176  
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  177  /*
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  178   * In many cases it is known that a virtual address is mapped at PMD or PTE
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  179   * level, so instead of traversing all the page table levels, we can get a
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  180   * pointer to the PMD entry in user or kernel page table or translate a virtual
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  181   * address to the pointer in the PTE in the kernel page tables with simple
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  182   * helpers.
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  183   */
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  184  static inline pmd_t *pmd_off(struct mm_struct *mm, unsigned long va)
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  185  {
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @186  	return pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, va), va), va), va);
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  187  }
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  188  
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  189  static inline pmd_t *pmd_off_k(unsigned long va)
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  190  {
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  191  	return pmd_offset(pud_offset(p4d_offset(pgd_offset_k(va), va), va), va);
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  192  }
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  193  
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  194  static inline pte_t *virt_to_kpte(unsigned long vaddr)
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  195  {
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  196  	pmd_t *pmd = pmd_off_k(vaddr);
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  197  
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08 @198  	return pmd_none(*pmd) ? NULL : pte_offset_kernel(pmd, vaddr);
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  199  }
e05c7b1f2bc4b7 include/linux/pgtable.h       Mike Rapoport           2020-06-08  200  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202512202213.B6MRZ7tt-lkp%40intel.com.
