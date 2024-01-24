Return-Path: <kasan-dev+bncBC4LXIPCY4NRBBMGYKWQMGQE2AXSTFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5768083A00A
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 04:24:55 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-599107a1934sf3314189eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 19:24:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706066694; cv=pass;
        d=google.com; s=arc-20160816;
        b=BiZNyQBkuzBNCvW+k+cp/y9RNJUfPfjIP1YGvhYWWUTHORqJ33QLfH8C6NUhvUzo1d
         nEw+imGGhJCwGe6K+/g+nhxX8Bb/Nq9iOyY0w7q4J8Ra+ZP3+SLI6l788xIK6WuGBhMD
         frCGKqxRtD0ep/S3ZeNenbxGEb2wxoBXUUlE5dAhwuVLsR9fQv/35TUX7GvxyBLhthL+
         DnyDqRiFnD9pMNBf7mTzClxpcJvDn/nHh9YJ+jVfmjnDx07kWNriTsre/1JcxKV+H30j
         12uDXMtDKNLoiItk5ZXVPIM+zv2yp9xKNfvDzGzgGC4GIo4sjazjNlSABpyA9TcEtsS2
         d1bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=Q0mfSBODsf+0eda/RgsVl4D4tsJxCa/vmGiLTtsG6Uw=;
        fh=TEa9BDYWAEiy3kLYr+VklIYowbdPs7q4oXxtdxodvqM=;
        b=gYahpFdNb7JjyGFl6mgr6ag3MJKf8Lm6dnAlP5pePKLqiwmXaHYzHbobvWEAV0r5Np
         RJBfVbxhEh1m2RPS7IuzvIDNgDRiyJxVymCn4Koedgiwt7JfGlUqoPwOH0k1t3jQX3Nf
         jeHN7TnR3pMnnaIktwV/rxmnshHwxMFDOCbrsq3i/rkYHav1OlxMvYVogfh73rZEI5C/
         UAxfLdwyXUxlBlonoP/zQ02hROQKGW2OgACBqxconsNPZTUFDdjxE36Uh53TKUAzqmzd
         r8B/XTe6o3VMfqeXOAoROcB3DlY+eL6H4ByjdgyEd9DC/1QnKSxWaaXeA+etQtID545b
         5KZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lLcyncgm;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706066694; x=1706671494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q0mfSBODsf+0eda/RgsVl4D4tsJxCa/vmGiLTtsG6Uw=;
        b=HNwwG0UdQKmP64yYO+nKzyYqVu9uZ/EuFmBSdzP2H5MpoYk3Eps19iN0VSFSzpV/t+
         fPETgOgpIufkoteQ32YMvYsiq5SRE2/o6IrM4s0CQQDSvRWWFexqUnMARNK3ZY/SX/jK
         K/VZk5c1vI40C4DY3X0jAInlvWkB/P05VwpJs7LbluzBdubILEhDnGQJ3ePkL4bHq64N
         zSwS0ay14PagxPQwRfRA/7IA9E9PxfEs9Am4jgdm2JkjO2c8kPOrjp88zrY0QPUBC41k
         QgANyzBRGi9H6fXZJuSveUwR434EPjFG49bS9PRgXeqGECLIvXRpSD62KyQKviC1DaRu
         XtHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706066694; x=1706671494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q0mfSBODsf+0eda/RgsVl4D4tsJxCa/vmGiLTtsG6Uw=;
        b=qhnplX4ntX6Sfv5K2MsF0JCHgl79AOnKAwc5OxSG3Vd06mz6JX2UHBsJrDHJ3Jm4NQ
         JdI8WUbUmlWUvGl+/XfO0ll0qlpEzAYZmb0DIweCK6Nb6t0lhVlEDAsVR0EQ0fkNVsdr
         1LPMuvDA4YnCkw7wr2H1zt/0Bf+BYcUr5hAduC48j96vi7Bxpl0sx7IBBFcAeTrVBdEz
         E8ZQD97EdEgj54F/DzZvxLjjMtFBQu0gQ0CK5MTJQQfZzL/+kgVIrh8TpvFR9qD1dKe7
         DV9FFkqlowZtMkn4AC8jO8r1di+QvCREMWR/lhpif1VRXpMnpEHVE+dj7WgC/egzwxti
         fTYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxVnJN8v8R5NjVMf81TrU6bE2dE0VhFxVICleElLORqxWSDND97
	DFHfVES9QWSp79bKpqpjDsi6nP7DKxipK04ci0sF9GtPMwBuxPU8
X-Google-Smtp-Source: AGHT+IGjR3/MmDMo0xJiIgRZeFJ9m51676S5TXthr1B6b+zLljQwqdA/+HTxknLPKcEIsCEOQWsrIw==
X-Received: by 2002:a05:6808:2f1a:b0:3bd:692d:b234 with SMTP id gu26-20020a0568082f1a00b003bd692db234mr1065909oib.46.1706066693870;
        Tue, 23 Jan 2024 19:24:53 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:331b:b0:210:e69e:e8b9 with SMTP id
 nf27-20020a056871331b00b00210e69ee8b9ls89563oac.0.-pod-prod-06-us; Tue, 23
 Jan 2024 19:24:53 -0800 (PST)
X-Received: by 2002:a05:6808:1599:b0:3bd:62e3:b448 with SMTP id t25-20020a056808159900b003bd62e3b448mr974943oiw.18.1706066693028;
        Tue, 23 Jan 2024 19:24:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706066693; cv=none;
        d=google.com; s=arc-20160816;
        b=Yj4BcMGlee5MqwHPRARA1lEdIvm5bt8Fd/RJ5iDbSyDwwuOqvhLVtJYhpVBjtZZ5Cf
         AtOFLvZ+mXhMDFY7HG+D3QdCjjfxCMxxyq10WdTI1NlYC5Cy5TmPEceKH14OblESFVKR
         wRnRoPvXs5BvMvd9Q+evi647URtAirwp3JsUCcfH6yp9t9kLYB/9/bko6MTJ+JP3KaHj
         V5ofEde4vNf6AFIx0+M8g4JiSIvtqKczqgMgwkMq/TJo0zULyL/BTDe9BI4P4aopMc6K
         oVwPHCWhs3CwQXnMpPjehXTOCejFcADYRJIulC1j23QRn1JfJ/xv47yTByAXV/kuftQp
         pf8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=2cqniZjnQwsVBbcTSAIfAuqG1HFqLacT9VZkTUNtoxg=;
        fh=TEa9BDYWAEiy3kLYr+VklIYowbdPs7q4oXxtdxodvqM=;
        b=dhqCIMyaI7gcPJZMeX2oN3cXH/XoalpcMOO+53L31QrCyo8dNvRbb1Rxj4IweWOk43
         88V/TuTxdL5pn9EycCx4slHTxqwCrW3q82P6BdnnNwEVwhHzGzI/7f90Dzcbt9vOgxEP
         N6awQoiJFjQhcU+P5XhMJeQDJkhP1NmfHnlxe03JfBT+XtaXiaB+ezWzxxoTk2eglKAk
         +OTBPRpEQpeX3tKuYGpvoJKtnIJ1YSFVn2eRt7seEJzm/2Iq17QXJucER+7NnUWrRe1r
         x2kTIUCCoJypgrgKtK2QLcHDqbhDM0eKa6obk1jrMKvckUDOu6bZbSTKhdczT4CAWUnk
         SwUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lLcyncgm;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id bg24-20020a056808179800b003bb7afbe66csi923266oib.4.2024.01.23.19.24.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jan 2024 19:24:52 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-IronPort-AV: E=McAfee;i="6600,9927,10962"; a="8381510"
X-IronPort-AV: E=Sophos;i="6.05,215,1701158400"; 
   d="scan'208";a="8381510"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Jan 2024 19:24:51 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10962"; a="959366456"
X-IronPort-AV: E=Sophos;i="6.05,215,1701158400"; 
   d="scan'208";a="959366456"
Received: from lkp-server01.sh.intel.com (HELO 961aaaa5b03c) ([10.239.97.150])
  by orsmga005.jf.intel.com with ESMTP; 23 Jan 2024 19:24:48 -0800
Received: from kbuild by 961aaaa5b03c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rSTsb-0007pR-27;
	Wed, 24 Jan 2024 03:24:45 +0000
Date: Wed, 24 Jan 2024 11:23:58 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 dmaengine@vger.kernel.org, dri-devel@lists.freedesktop.org,
 etnaviv@lists.freedesktop.org, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-arm-msm@vger.kernel.org,
 linux-bcachefs@vger.kernel.org, linux-usb@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 774551425799cb5bbac94e1768fd69eec4f78dd4
Message-ID: <202401241153.saaJ1jP1-lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lLcyncgm;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
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

tree/branch: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git master
branch HEAD: 774551425799cb5bbac94e1768fd69eec4f78dd4  Add linux-next specific files for 20240123

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202401231518.8q9LD8n7-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202401240123.wBsFom3Z-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

drivers/dma/at_hdmac.c:255: warning: Enum value 'ATC_IS_CYCLIC' not described in enum 'atc_status'
drivers/dma/at_hdmac.c:255: warning: Enum value 'ATC_IS_PAUSED' not described in enum 'atc_status'

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- arc-randconfig-r062-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- arm-multi_v5_defconfig
|   |-- drivers-dma-at_hdmac.c:warning:Enum-value-ATC_IS_CYCLIC-not-described-in-enum-atc_status
|   `-- drivers-dma-at_hdmac.c:warning:Enum-value-ATC_IS_PAUSED-not-described-in-enum-atc_status
|-- i386-randconfig-051-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- i386-randconfig-054-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- i386-randconfig-062-20240123
|   |-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|   `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-sum-got-unsigned-int-assigned-csum
|-- i386-randconfig-141-20240123
|   |-- fs-bcachefs-btree_locking.c-bch2_trans_relock()-warn:passing-zero-to-PTR_ERR
|   |-- fs-bcachefs-buckets.c-bch2_trans_account_disk_usage_change()-error:we-previously-assumed-trans-disk_res-could-be-null-(see-line-)
|   `-- mm-huge_memory.c-thpsize_create()-warn:Calling-kobject_put-get-with-state-initialized-unset-from-line:
|-- microblaze-randconfig-r064-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- microblaze-randconfig-r123-20240123
|   `-- drivers-regulator-qcom_smd-regulator.c:sparse:sparse:symbol-smd_vreg_rpm-was-not-declared.-Should-it-be-static
|-- mips-allyesconfig
|   |-- (.ref.text):relocation-truncated-to-fit:R_MIPS_26-against-start_secondary
|   `-- (.text):relocation-truncated-to-fit:R_MIPS_26-against-kernel_entry
|-- nios2-randconfig-r052-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- nios2-randconfig-r054-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- openrisc-randconfig-r131-20240123
|   `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-csum-got-unsigned-int-assigned-csum
|-- sh-randconfig-r133-20240123
|   `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-sum-got-unsigned-int-assigned-csum
|-- x86_64-randconfig-101-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
|-- x86_64-randconfig-102-20240123
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
`-- x86_64-randconfig-161-20240123
    |-- mm-huge_memory.c-thpsize_create()-warn:Calling-kobject_put-get-with-state-initialized-unset-from-line:
    |-- mm-kasan-kasan_test.c-mempool_double_free_helper()-error:double-free-of-elem
    `-- mm-kasan-kasan_test.c-mempool_uaf_helper()-warn:passing-freed-memory-elem
clang_recent_errors
|-- x86_64-randconfig-121-20240123
|   `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-csum-got-unsigned-int-assigned-csum
`-- x86_64-randconfig-r132-20240123
    `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-csum-got-unsigned-int-assigned-csum

elapsed time: 1483m

configs tested: 177
configs skipped: 3

tested configs:
alpha                             allnoconfig   gcc  
alpha                            allyesconfig   gcc  
alpha                               defconfig   gcc  
arc                              allmodconfig   gcc  
arc                               allnoconfig   gcc  
arc                              allyesconfig   gcc  
arc                                 defconfig   gcc  
arc                   randconfig-001-20240123   gcc  
arc                   randconfig-002-20240123   gcc  
arm                              allmodconfig   gcc  
arm                               allnoconfig   gcc  
arm                              allyesconfig   gcc  
arm                       aspeed_g5_defconfig   gcc  
arm                                 defconfig   clang
arm                          ixp4xx_defconfig   clang
arm                            mps2_defconfig   gcc  
arm                        mvebu_v7_defconfig   gcc  
arm                          pxa910_defconfig   gcc  
arm                   randconfig-001-20240123   gcc  
arm                   randconfig-002-20240123   gcc  
arm                   randconfig-003-20240123   gcc  
arm                   randconfig-004-20240123   gcc  
arm                       versatile_defconfig   clang
arm64                            allmodconfig   clang
arm64                             allnoconfig   gcc  
arm64                               defconfig   gcc  
arm64                 randconfig-001-20240123   gcc  
arm64                 randconfig-002-20240123   gcc  
arm64                 randconfig-003-20240123   gcc  
arm64                 randconfig-004-20240123   gcc  
csky                             allmodconfig   gcc  
csky                              allnoconfig   gcc  
csky                             allyesconfig   gcc  
csky                                defconfig   gcc  
csky                  randconfig-001-20240123   gcc  
csky                  randconfig-002-20240123   gcc  
hexagon                          allmodconfig   clang
hexagon                           allnoconfig   clang
hexagon                          allyesconfig   clang
hexagon                             defconfig   clang
hexagon               randconfig-001-20240123   clang
hexagon               randconfig-002-20240123   clang
i386                             allmodconfig   clang
i386                              allnoconfig   clang
i386                             allyesconfig   clang
i386         buildonly-randconfig-001-20240123   gcc  
i386         buildonly-randconfig-002-20240123   gcc  
i386         buildonly-randconfig-003-20240123   gcc  
i386         buildonly-randconfig-004-20240123   gcc  
i386         buildonly-randconfig-005-20240123   gcc  
i386         buildonly-randconfig-006-20240123   gcc  
i386                                defconfig   gcc  
i386                  randconfig-001-20240123   gcc  
i386                  randconfig-002-20240123   gcc  
i386                  randconfig-003-20240123   gcc  
i386                  randconfig-004-20240123   gcc  
i386                  randconfig-005-20240123   gcc  
i386                  randconfig-006-20240123   gcc  
i386                  randconfig-011-20240123   clang
i386                  randconfig-012-20240123   clang
i386                  randconfig-013-20240123   clang
i386                  randconfig-014-20240123   clang
i386                  randconfig-015-20240123   clang
i386                  randconfig-016-20240123   clang
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch             randconfig-001-20240123   gcc  
loongarch             randconfig-002-20240123   gcc  
m68k                             allmodconfig   gcc  
m68k                              allnoconfig   gcc  
m68k                             allyesconfig   gcc  
m68k                                defconfig   gcc  
microblaze                       allmodconfig   gcc  
microblaze                        allnoconfig   gcc  
microblaze                       allyesconfig   gcc  
microblaze                          defconfig   gcc  
mips                              allnoconfig   clang
mips                             allyesconfig   gcc  
mips                     cu1830-neo_defconfig   clang
mips                       lemote2f_defconfig   gcc  
mips                        omega2p_defconfig   clang
nios2                            allmodconfig   gcc  
nios2                             allnoconfig   gcc  
nios2                            allyesconfig   gcc  
nios2                               defconfig   gcc  
nios2                 randconfig-001-20240123   gcc  
nios2                 randconfig-002-20240123   gcc  
openrisc                          allnoconfig   gcc  
openrisc                         allyesconfig   gcc  
openrisc                            defconfig   gcc  
parisc                           allmodconfig   gcc  
parisc                            allnoconfig   gcc  
parisc                           allyesconfig   gcc  
parisc                              defconfig   gcc  
parisc                generic-64bit_defconfig   gcc  
parisc                randconfig-001-20240123   gcc  
parisc                randconfig-002-20240123   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   clang
powerpc                           allnoconfig   gcc  
powerpc                          allyesconfig   clang
powerpc                      katmai_defconfig   clang
powerpc                 mpc832x_rdb_defconfig   clang
powerpc               randconfig-001-20240123   gcc  
powerpc               randconfig-002-20240123   gcc  
powerpc               randconfig-003-20240123   gcc  
powerpc64             randconfig-001-20240123   gcc  
powerpc64             randconfig-002-20240123   gcc  
powerpc64             randconfig-003-20240123   gcc  
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   clang
riscv                            allyesconfig   gcc  
riscv                               defconfig   gcc  
riscv                 randconfig-001-20240123   gcc  
riscv                 randconfig-002-20240123   gcc  
s390                             allmodconfig   gcc  
s390                              allnoconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                  randconfig-001-20240123   clang
s390                  randconfig-002-20240123   clang
sh                               allmodconfig   gcc  
sh                                allnoconfig   gcc  
sh                               allyesconfig   gcc  
sh                                  defconfig   gcc  
sh                    randconfig-001-20240123   gcc  
sh                    randconfig-002-20240123   gcc  
sh                           se7206_defconfig   gcc  
sh                           sh2007_defconfig   gcc  
sh                   sh7724_generic_defconfig   gcc  
sparc                            allmodconfig   gcc  
sparc64                          allmodconfig   gcc  
sparc64                          allyesconfig   gcc  
sparc64                             defconfig   gcc  
sparc64               randconfig-001-20240123   gcc  
sparc64               randconfig-002-20240123   gcc  
um                               allmodconfig   clang
um                                allnoconfig   clang
um                               allyesconfig   clang
um                                  defconfig   gcc  
um                             i386_defconfig   gcc  
um                    randconfig-001-20240123   gcc  
um                    randconfig-002-20240123   gcc  
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   clang
x86_64       buildonly-randconfig-001-20240123   gcc  
x86_64       buildonly-randconfig-002-20240123   gcc  
x86_64       buildonly-randconfig-003-20240123   gcc  
x86_64       buildonly-randconfig-004-20240123   gcc  
x86_64       buildonly-randconfig-005-20240123   gcc  
x86_64       buildonly-randconfig-006-20240123   gcc  
x86_64                              defconfig   gcc  
x86_64                randconfig-001-20240123   clang
x86_64                randconfig-002-20240123   clang
x86_64                randconfig-003-20240123   clang
x86_64                randconfig-004-20240123   clang
x86_64                randconfig-005-20240123   clang
x86_64                randconfig-006-20240123   clang
x86_64                randconfig-011-20240123   gcc  
x86_64                randconfig-012-20240123   gcc  
x86_64                randconfig-013-20240123   gcc  
x86_64                randconfig-014-20240123   gcc  
x86_64                randconfig-015-20240123   gcc  
x86_64                randconfig-016-20240123   gcc  
x86_64                randconfig-071-20240123   gcc  
x86_64                randconfig-072-20240123   gcc  
x86_64                randconfig-073-20240123   gcc  
x86_64                randconfig-074-20240123   gcc  
x86_64                randconfig-075-20240123   gcc  
x86_64                randconfig-076-20240123   gcc  
x86_64                          rhel-8.3-rust   clang
xtensa                            allnoconfig   gcc  
xtensa                randconfig-001-20240123   gcc  
xtensa                randconfig-002-20240123   gcc  
xtensa                         virt_defconfig   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401241153.saaJ1jP1-lkp%40intel.com.
