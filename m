Return-Path: <kasan-dev+bncBC4LXIPCY4NRBLVEV2RQMGQEU472TSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 15A4B70C2E8
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 18:02:56 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-5128dcbdfc1sf2048049a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 09:02:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684771375; cv=pass;
        d=google.com; s=arc-20160816;
        b=MJF6eF4vVttKRrgxEcDuROtDDeXO6daxtqqHMZERf0XscUTtHoGb3OMVtT5Es6rE/B
         zBwmbTbaO+4GuMrGNVxseRhrQEiHLfT6Rm+tUiE9KoCAIHQnn0Z4qX7iRnZrzd2Tf/r1
         5p7YDDOdWZUmzjfWplandMxz6UaikNu3c4b36IVObgAhtLlcgIupUDFxTw12rPPF5dr+
         8HWatAuHaV6vwcgvJeppk102IQJdGkITiqd6re24qJHVJS+hdUfd/oH5uZo5fGqkMUfN
         Bcl2xDEyg2gLPjA6OZe+CV952gGDuDB4pIIHaybD4WjVdz2Jpb/mgyVOskQnCHz4bo0l
         1t0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=oNIwhL4AZ4brFKihvI6GWMbGwERZC4aNN1Qs8SMPNGY=;
        b=pmcR/+C9W5iIaxIcRFT4OHSNxx3wYjzt7TbkW2PxJdxJHmqMvWBw8oHW9sVjHRXvBO
         Ge3mZyoZhifJm1UUEjwe8ca6ShX7lpysSuR+rb/JhM+KPGGnDLZRrBzm0MvIFloCbLVr
         pSBcCRXXTCI0aPSdtlFdXfraLxoh1dOIWwIzqkZNxLl3wePyMtcYiatO1hP40+vsQSNb
         6wr+VwIqHjj8kvUHOMVXpooft8oy8nYhMyzIve3EEEXHJg+hkzySNkKDx7lSm6+cnaAW
         vB0rfUZZDUn0g8ZZ10ewvRO+sAX98RsrJ7Cw/TQ8xagVkrYlfk5kUXB5rGIZv3Lj8WeC
         YwlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ndvNs+oI;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684771375; x=1687363375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oNIwhL4AZ4brFKihvI6GWMbGwERZC4aNN1Qs8SMPNGY=;
        b=JSZ/Mbkqq56ptpxmz8febZCpUkL43jipKdvkWQQLJHjHOcaLe4YG5g8dltbhuuq9xr
         3qtzhRBt3Fm6fKVRPjwceXvXRhlJ8iNofC742mQPBAILctKVvJCvGsNFvj7PyWfLRtdB
         /IXNpXaJPfWVdVrZVaOdJRh5JcQeQK93FwL4QkLck1jre+asoXT9ktGlzd/tC8VKO0uq
         nGlCxANFAQsMSOFmj9vHsfc9mZZlHXuf3WUwJVcVBy6U0sBQfH+nTa3CZN/BRdrdwgHg
         j7xZFkEldjf0w875rvtPBU1mB/D8UVzxp8+dONoEz6jsNFXew+Z8iBeZc3Zt8fhgJ36A
         Lntw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684771375; x=1687363375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oNIwhL4AZ4brFKihvI6GWMbGwERZC4aNN1Qs8SMPNGY=;
        b=luj6Ze2QZ4djEsCFp6SvBtUfZLQZZ+tUGbdPAjF2wpNmZVC2FZkINoKP/DXDIJzS+X
         Zkjw7VkZyJbqvQarHV3g+LBNkQHo2a2z57Cz8wI5RTVqLH2aeE5nMxZ2eexajaz5M2so
         P+HYZ2HalCq5v5g9v7YWix2akWGuF4kJUpxihSyku/iomHjfookwGuf8uwDWVj0slZ83
         64FgwYaY6QGYIRMZmqwe2XvbmH29em29wCgN/BLbpubGmDv8mbRpGSb1SPMMaItEDRA6
         EdXdfgYGUhk7am2v1JIslzBHvRNWZes/xD8WSG3YGWJxYzJGuzBjY+HnrIKIR+Lq/A1L
         BZsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy34xP/VdpT3wTAIq5vf0sXBorvcxYnGLk2kHBK0UBKIDr2nVvC
	4ezprTDyDXrLEpGKP7ZsXhQ=
X-Google-Smtp-Source: ACHHUZ5BRUx/gabm8H957qFTx2agj5LaQTV+qsEkt2PABFVBdVcTwoWgXgikZ/6zSU0HUh9J4vjrFA==
X-Received: by 2002:a50:d65d:0:b0:50b:fc7b:de7f with SMTP id c29-20020a50d65d000000b0050bfc7bde7fmr4128158edj.2.1684771374980;
        Mon, 22 May 2023 09:02:54 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c78a:0:b0:513:ede5:64d4 with SMTP id n10-20020aa7c78a000000b00513ede564d4ls824158eds.0.-pod-prod-00-eu;
 Mon, 22 May 2023 09:02:53 -0700 (PDT)
X-Received: by 2002:a17:907:7f8c:b0:96a:f8ec:c311 with SMTP id qk12-20020a1709077f8c00b0096af8ecc311mr8963842ejc.36.1684771373583;
        Mon, 22 May 2023 09:02:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684771373; cv=none;
        d=google.com; s=arc-20160816;
        b=fooCpTdktw2gLCKMnLCb0TQL/0wBklM9hpZyadvHrSB4nUCI62TtMvRExoY5mO0FtD
         cbsuTLdUvL2H2c+SbhwA17NW0DUxbEpEPugnnUYnJVFHfX63GHedW3r3Vc+UBKK3yU3g
         pfcrLVJ1k6/1GXS4RsaI/uJea6m+u/eUC5+KBLfz9nKZmS347bxbFrQcsu20qtNCbxwn
         4jf/fcdq+6t5zXqvtxD3z1DvgBfIjtYImhBjdgR8fKt8tBpfaeWfsBXbEOwoKf65uDXr
         08TxG2ZvKIxAyivTZqcPMW07wg5QR0H724ZokbvwsyP/cRQDqveY74xRzRj/tJOhHiX0
         eTqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ebuw9B6502P0u5exBIt/HSk3zds23LABc9FCf0AlXaE=;
        b=ihvxayMHvIVJTHrb3tCZfaLGyCxL1/VaQ+Dng9Tx7ncgGcUQWaeqKqu9NPnExLjE45
         bWxlAvIpoC7hFV9HRNFQlr2K9NUk0zwcfo/mdDH5FgFibGHh/BzK7dUK4Tm0KEa3417r
         jtetPvmoH6DZowtPabr1mvwwRzR1xWWxU98E6nFZ6uO7UNkA7hMbqAZA4EaB0wwH3T5J
         34hJIsbhE+7R1tDCN5iGNX3h3paGAgCbJq6o98z/8t76SnrhlAcU9OHoMb2I++U/wZIz
         sZDAeShbQbPDgEA4CXoN864+m6Eo3cpExy8wHdBqVfz4fvIanyQJPEnEkd7a6vQfXIbj
         ZUXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ndvNs+oI;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id fl23-20020a1709072a9700b00965600719e4si435162ejc.1.2023.05.22.09.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 May 2023 09:02:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10718"; a="337548592"
X-IronPort-AV: E=Sophos;i="6.00,184,1681196400"; 
   d="scan'208";a="337548592"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 May 2023 09:02:51 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10718"; a="773427999"
X-IronPort-AV: E=Sophos;i="6.00,184,1681196400"; 
   d="scan'208";a="773427999"
Received: from lkp-server01.sh.intel.com (HELO dea6d5a4f140) ([10.239.97.150])
  by fmsmga004.fm.intel.com with ESMTP; 22 May 2023 09:02:48 -0700
Received: from kbuild by dea6d5a4f140 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1q17zk-000CyJ-0L;
	Mon, 22 May 2023 16:02:48 +0000
Date: Tue, 23 May 2023 00:01:55 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 amd-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
 kvmarm@lists.linux.dev, linux-arm-kernel@lists.infradead.org,
 linux-perf-users@vger.kernel.org, linux-xfs@vger.kernel.org
Subject: [linux-next:master] BUILD SUCCESS WITH WARNING
 9f258af06b6268be8e960f63c3f66e88bdbbbdb0
Message-ID: <20230522160155.au0hJ%lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ndvNs+oI;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted
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

tree/branch: INFO setup_repo_specs: /db/releases/20230522162832/lkp-src/repo/*/linux-next
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git master
branch HEAD: 9f258af06b6268be8e960f63c3f66e88bdbbbdb0  Add linux-next specific files for 20230522

Warning reports:

https://lore.kernel.org/oe-kbuild-all/202305132244.DwzBUcUd-lkp@intel.com

Warning: (recently discovered and may have been fixed)

drivers/base/regmap/regcache-maple.c:113:23: warning: 'lower_index' is used uninitialized [-Wuninitialized]
drivers/base/regmap/regcache-maple.c:113:36: warning: 'lower_last' is used uninitialized [-Wuninitialized]
drivers/gpu/drm/amd/amdgpu/../display/amdgpu_dm/amdgpu_dm.c:6396:21: warning: variable 'count' set but not used [-Wunused-but-set-variable]

Unverified Warning (likely false positive, please contact us if interested):

arch/arm64/kvm/mmu.c:147:3-9: preceding lock on line 140
fs/xfs/scrub/fscounters.c:459 xchk_fscounters() warn: ignoring unreachable code.
kernel/events/uprobes.c:478 uprobe_write_opcode() warn: passing zero to 'PTR_ERR'
kernel/watchdog.c:40:19: sparse: sparse: symbol 'watchdog_hardlockup_user_enabled' was not declared. Should it be static?
kernel/watchdog.c:41:19: sparse: sparse: symbol 'watchdog_softlockup_user_enabled' was not declared. Should it be static?

Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arc-allyesconfig
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_index-is-used-uninitialized
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_last-is-used-uninitialized
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arc-buildonly-randconfig-r001-20230522
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arm-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arm-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arm-randconfig-r036-20230521
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arm64-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- arm64-randconfig-c041-20230521
|   `-- arch-arm64-kvm-mmu.c:preceding-lock-on-line
|-- arm64-randconfig-s053-20230521
|   `-- mm-kfence-core.c:sparse:sparse:cast-to-restricted-__le64
|-- i386-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- i386-randconfig-m021
|   `-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
|-- ia64-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- ia64-randconfig-m041-20230521
|   `-- fs-xfs-scrub-fscounters.c-xchk_fscounters()-warn:ignoring-unreachable-code.
|-- loongarch-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- loongarch-defconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- loongarch-randconfig-r033-20230522
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- mips-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- mips-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- powerpc-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- riscv-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- riscv-randconfig-r042-20230521
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- s390-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- s390-randconfig-s042-20230521
|   `-- mm-kfence-core.c:sparse:sparse:cast-to-restricted-__le64
|-- sparc-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- sparc-randconfig-s052-20230521
|   |-- kernel-watchdog.c:sparse:sparse:symbol-watchdog_hardlockup_user_enabled-was-not-declared.-Should-it-be-static
|   `-- kernel-watchdog.c:sparse:sparse:symbol-watchdog_softlockup_user_enabled-was-not-declared.-Should-it-be-static
|-- sparc64-randconfig-r016-20230521
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- x86_64-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|-- x86_64-randconfig-m001
|   `-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
|-- x86_64-randconfig-s021
|   |-- kernel-watchdog.c:sparse:sparse:symbol-watchdog_hardlockup_user_enabled-was-not-declared.-Should-it-be-static
|   `-- kernel-watchdog.c:sparse:sparse:symbol-watchdog_softlockup_user_enabled-was-not-declared.-Should-it-be-static
`-- x86_64-randconfig-s022
    |-- kernel-watchdog.c:sparse:sparse:symbol-watchdog_hardlockup_user_enabled-was-not-declared.-Should-it-be-static
    `-- kernel-watchdog.c:sparse:sparse:symbol-watchdog_softlockup_user_enabled-was-not-declared.-Should-it-be-static

elapsed time: 722m

configs tested: 166
configs skipped: 12

tested configs:
alpha                            allyesconfig   gcc  
alpha                               defconfig   gcc  
alpha                randconfig-r006-20230522   gcc  
alpha                randconfig-r011-20230522   gcc  
alpha                randconfig-r024-20230522   gcc  
arc                              allyesconfig   gcc  
arc          buildonly-randconfig-r001-20230522   gcc  
arc          buildonly-randconfig-r003-20230522   gcc  
arc                                 defconfig   gcc  
arc                 nsimosci_hs_smp_defconfig   gcc  
arc                  randconfig-r023-20230522   gcc  
arc                  randconfig-r043-20230521   gcc  
arc                  randconfig-r043-20230522   gcc  
arm                              allmodconfig   gcc  
arm                              allyesconfig   gcc  
arm                                 defconfig   gcc  
arm                          gemini_defconfig   gcc  
arm                      integrator_defconfig   gcc  
arm                           omap1_defconfig   clang
arm                  randconfig-r035-20230521   gcc  
arm                  randconfig-r036-20230521   gcc  
arm                  randconfig-r046-20230521   clang
arm                  randconfig-r046-20230522   gcc  
arm                          sp7021_defconfig   clang
arm                    vt8500_v6_v7_defconfig   clang
arm64                            allyesconfig   gcc  
arm64        buildonly-randconfig-r006-20230522   gcc  
arm64                               defconfig   gcc  
arm64                randconfig-r016-20230522   clang
csky         buildonly-randconfig-r004-20230521   gcc  
csky                                defconfig   gcc  
csky                 randconfig-r012-20230521   gcc  
hexagon              randconfig-r002-20230522   clang
hexagon              randconfig-r006-20230521   clang
hexagon              randconfig-r024-20230521   clang
hexagon              randconfig-r041-20230521   clang
hexagon              randconfig-r041-20230522   clang
hexagon              randconfig-r045-20230521   clang
hexagon              randconfig-r045-20230522   clang
i386                              allnoconfig   clang
i386                             allyesconfig   gcc  
i386                              debian-10.3   gcc  
i386                                defconfig   gcc  
i386                 randconfig-a001-20230522   gcc  
i386                 randconfig-a002-20230522   gcc  
i386                 randconfig-a003-20230522   gcc  
i386                 randconfig-a004-20230522   gcc  
i386                 randconfig-a005-20230522   gcc  
i386                 randconfig-a006-20230522   gcc  
i386                 randconfig-a011-20230522   clang
i386                 randconfig-a012-20230522   clang
i386                 randconfig-a013-20230522   clang
i386                 randconfig-a014-20230522   clang
i386                 randconfig-a015-20230522   clang
i386                 randconfig-a016-20230522   clang
i386                 randconfig-r003-20230522   gcc  
i386                 randconfig-r026-20230522   clang
ia64                             allmodconfig   gcc  
ia64                                defconfig   gcc  
ia64                 randconfig-r005-20230522   gcc  
ia64                          tiger_defconfig   gcc  
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch            randconfig-r033-20230522   gcc  
m68k                             allmodconfig   gcc  
m68k                          atari_defconfig   gcc  
m68k                                defconfig   gcc  
m68k                 randconfig-r014-20230522   gcc  
m68k                 randconfig-r034-20230521   gcc  
mips                             allmodconfig   gcc  
mips                             allyesconfig   gcc  
mips                 decstation_r4k_defconfig   gcc  
mips                           jazz_defconfig   gcc  
mips                        qi_lb60_defconfig   clang
mips                 randconfig-r022-20230522   gcc  
nios2                               defconfig   gcc  
nios2                randconfig-r004-20230522   gcc  
nios2                randconfig-r031-20230522   gcc  
nios2                randconfig-r032-20230521   gcc  
openrisc     buildonly-randconfig-r002-20230521   gcc  
openrisc                  or1klitex_defconfig   gcc  
openrisc             randconfig-r002-20230521   gcc  
parisc       buildonly-randconfig-r002-20230522   gcc  
parisc       buildonly-randconfig-r004-20230522   gcc  
parisc       buildonly-randconfig-r006-20230521   gcc  
parisc                              defconfig   gcc  
parisc64                         alldefconfig   gcc  
parisc64                            defconfig   gcc  
powerpc                     akebono_defconfig   clang
powerpc                          allmodconfig   gcc  
powerpc                           allnoconfig   gcc  
powerpc                   bluestone_defconfig   clang
powerpc                      chrp32_defconfig   gcc  
powerpc                     ksi8560_defconfig   clang
powerpc                     mpc512x_defconfig   clang
powerpc                      pcm030_defconfig   gcc  
powerpc              randconfig-r033-20230521   clang
powerpc                     skiroot_defconfig   clang
powerpc                     tqm5200_defconfig   clang
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   gcc  
riscv                               defconfig   gcc  
riscv                randconfig-r005-20230521   clang
riscv                randconfig-r042-20230521   gcc  
riscv                randconfig-r042-20230522   clang
riscv                          rv32_defconfig   gcc  
s390                             allmodconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                 randconfig-r003-20230521   clang
s390                 randconfig-r004-20230521   clang
s390                 randconfig-r011-20230521   gcc  
s390                 randconfig-r013-20230521   gcc  
s390                 randconfig-r023-20230521   gcc  
s390                 randconfig-r034-20230522   gcc  
s390                 randconfig-r044-20230521   gcc  
s390                 randconfig-r044-20230522   clang
sh                               allmodconfig   gcc  
sh                         apsh4a3a_defconfig   gcc  
sh           buildonly-randconfig-r003-20230521   gcc  
sh                   randconfig-r015-20230521   gcc  
sh                   randconfig-r021-20230521   gcc  
sh                           se7722_defconfig   gcc  
sparc        buildonly-randconfig-r005-20230521   gcc  
sparc                               defconfig   gcc  
sparc                randconfig-r015-20230522   gcc  
sparc                randconfig-r026-20230521   gcc  
sparc                randconfig-r035-20230522   gcc  
sparc64              randconfig-r001-20230521   gcc  
sparc64              randconfig-r016-20230521   gcc  
sparc64              randconfig-r025-20230521   gcc  
sparc64              randconfig-r031-20230521   gcc  
um                             i386_defconfig   gcc  
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   gcc  
x86_64                              defconfig   gcc  
x86_64                                  kexec   gcc  
x86_64               randconfig-a001-20230522   gcc  
x86_64               randconfig-a002-20230522   gcc  
x86_64               randconfig-a003-20230522   gcc  
x86_64               randconfig-a004-20230522   gcc  
x86_64               randconfig-a005-20230522   gcc  
x86_64               randconfig-a006-20230522   gcc  
x86_64               randconfig-a011-20230522   clang
x86_64               randconfig-a012-20230522   clang
x86_64               randconfig-a013-20230522   clang
x86_64               randconfig-a014-20230522   clang
x86_64               randconfig-a015-20230522   clang
x86_64               randconfig-a016-20230522   clang
x86_64               randconfig-r013-20230522   clang
x86_64               randconfig-x051-20230522   clang
x86_64               randconfig-x052-20230522   clang
x86_64               randconfig-x053-20230522   clang
x86_64               randconfig-x054-20230522   clang
x86_64               randconfig-x055-20230522   clang
x86_64               randconfig-x056-20230522   clang
x86_64               randconfig-x061-20230522   clang
x86_64               randconfig-x062-20230522   clang
x86_64               randconfig-x063-20230522   clang
x86_64               randconfig-x064-20230522   clang
x86_64               randconfig-x065-20230522   clang
x86_64               randconfig-x066-20230522   clang
x86_64                               rhel-8.3   gcc  
xtensa               randconfig-r022-20230521   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230522160155.au0hJ%25lkp%40intel.com.
