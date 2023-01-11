Return-Path: <kasan-dev+bncBC4LXIPCY4NRBNVT7OOQMGQEQYMIKNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5F39665F8A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 16:45:59 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id q9-20020a05651c054900b0027f19ad3517sf4057938ljp.13
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 07:45:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673451959; cv=pass;
        d=google.com; s=arc-20160816;
        b=Skjn4AxqD5BZp6/WZY0t+a1V2kMTl+C3p6E/2lQ7fOpWL60tksuqJjjZeTa6b5LbhV
         jyz7WcehL5f1ROr6xCtqEQrP+E25O69+1hgWGcY5UCGxH4nKMZBcI52XsNeKqdYtOULH
         MANGjgru0TnTUtfwYfKMuBlOb7699P1WzAK0gx5ebSjvkSRjQFeSKkKr7P8ln4ZCVuM3
         6iu/q7p2gutcMlQTYNg5iON+cF3WnjDtSG5pv4+KnJf6oICVkfPEyHnd1bhroSvyaFkz
         YKpGr+5xGxBmAwR30FmAK9O3XED16F4L55qpnfgXv2HRzqbOctns+hN/YtFWlaLAiEf6
         S9Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+cUeohT0yV0wjGZC70KKrvEfUSdaPQ+dF4cvTxWoTPY=;
        b=gfzvywCoxhLfMcX1gLOYRS5I5cAzmND2VEShsDPdJDhOqez5+9ufE9oLRThpD5MB1O
         9DghbbfTQhHb5iaZ5MdYX3bTHGDFoX2JkSfxHli06kzUvKxdJHBzuKiXLHWgCT18v4jq
         NH/9BVoL1We3Bt/Ba6J2p1f/RdkE/o1ZnGxLjOAyd88CtrFSpB7i7BJiVB1eAg5GJtaL
         fDSLJksKT2FeNX3cgzq6hcdfTbwl74dLp1adP30XmsI09sO9Wp4H5GTk25n4Q7g8RSbb
         jc9saQp2lTM7fUBM3ApqcR17phFNVAEuosQA3qvWDqGvKojEDkY00SNCBnUzyIMUYvxZ
         LSwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lmcjUsHk;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:subject:cc:to
         :from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+cUeohT0yV0wjGZC70KKrvEfUSdaPQ+dF4cvTxWoTPY=;
        b=FcFzXoRuPtOqXbQ8ZdtRpZPfzsNacmaUKBbFfBvxJEH3kxPL2kYazUFMkTvldkrHCD
         MRmo+T9n2b6fXRSIZHBE5eIh94E8J5ZjxJj5lJOq7CHW6wWzMRdgHay1B+C8txLpsp0D
         6AzY6tyLQrobGW1d+icznyiqeud4OoGI6S/bQeaq6srU6yG2L3niRcY7agRo557mDiwg
         km4b/NZYAI1hNLegX9Z0mBxrjbvz2W4TdxO9Dg3msKslZAlPD/nBgz7EWibY1kKeqjT8
         nr+RBzpoE6ZQiRANhAP90g2/ZduqH/tV1BJ6tjh2yPz3L2CRMKBqXOa9xFt08xTxNSa+
         3OXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+cUeohT0yV0wjGZC70KKrvEfUSdaPQ+dF4cvTxWoTPY=;
        b=abGD9DQUgFcU7DWVCgBOb895LhCzRV6yeBxYUHMD5G6TOqkHdfI0GoTwDK+lgiAorP
         z0tFwrL2NRscWL/MoivyMlgfr+tGevblHpfzYHedoZmm2INe7xID5vICh3lo4px+RaJs
         8+CxkK6NCLUKds/GGaH9e/NDj6HnsSi8zOGcdRazkboBrQxPJ7iEMyU/NREdQQtXGAe2
         +Qj89Vwd34VzdHTvtT24FKLP6BrIoJvZofHn/RaIFLr3JSLruviCBTRKuUQuacmH4kDM
         U1aT7s3fafAj4giJb6tIizdnicVwTPjA7gA2hs6P7Wxw+f6QOKgK3LGECU0evuZXPDzH
         Zg0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko2qt3oQPD+PN+/c9jIC4Caywb97MXE61rlck4gNWURS8/9c+yr
	OwFoMStCPYelhAqlnAFtYpw=
X-Google-Smtp-Source: AMrXdXvHsuZ+3ecjCb6yU/bN6tGSAm39s37/Ce/WBixWEgcxVhZa/fbk7DdCA+OPNoRp+ZvG3Twyjg==
X-Received: by 2002:a05:651c:10ae:b0:288:d4ab:a323 with SMTP id k14-20020a05651c10ae00b00288d4aba323mr114363ljn.227.1673451959139;
        Wed, 11 Jan 2023 07:45:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls6419506lfr.3.-pod-prod-gmail; Wed, 11
 Jan 2023 07:45:58 -0800 (PST)
X-Received: by 2002:ac2:5f43:0:b0:4cb:2c19:ec26 with SMTP id 3-20020ac25f43000000b004cb2c19ec26mr10633888lfz.35.1673451957979;
        Wed, 11 Jan 2023 07:45:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673451957; cv=none;
        d=google.com; s=arc-20160816;
        b=TTSfFxIEFDEo5WW7co+k07c4w09kXSvRScqoeqy4246W4BEbHzbPbgEAdKVoIoQyNY
         ZPIU+19iNTGaEKwjVPKcn93SyfpQXRy2RZrrxRwr4ffeh1y2VXFuNildWGw3OkT3RwJT
         EXQYJhGEPuL21r5fTKjSi8SWNv8wT8hBSTwGNzawrQkyqb9vTh8K/N+zNVyiIK4LzmT7
         whVbG0h4FeGzhKs7lrkh1P9b6Lzll73OylTrWoaueKmKSP7ift9nLJbV+KjZDS7Jz6Qj
         t6PcjODL8b9KQdL3xouLTXOz6c55Svuv7fkpl+xCNQs7/TsHkYvBC1nY/Mq2Hfd+U0Cm
         OA1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rvNXLdPFstyySTkBu4bwpyR3D3yIfyGna5HOeRLPswQ=;
        b=rYhDPhI3iVyLbse0Bf6upt7yUqTRDYEepyE5vMqR9jDSt5uGRBUObotm6VgMCT8dlV
         5DZzGNDaK1/rXrbF11W78dWRj7pqUw9Ls1yq1eVpNo/v+YlApkeQkrrus9zkdLD6/0Ki
         NOd43Mco5+DKJEaVnQH7+D7taOWy3FSXYbyqPQXNZBgtZqViyBN11JZnWhbifnsgXopE
         ppa6lWn0gPX8KCTUOEGNaOvgOc4bKgzC1/QfdkYXyHJfsM/tDJCCAY6PvC6fgpDXTGmt
         /YAVtpOBguyQ8zv6R3gGRF0QbKvmxeDV7kN3CTLmDmk5eJJG7XhAFewtjITer1d3t50Z
         owzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lmcjUsHk;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id o16-20020ac24e90000000b004a222ff195esi631585lfr.11.2023.01.11.07.45.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Jan 2023 07:45:57 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6500,9779,10586"; a="303143359"
X-IronPort-AV: E=Sophos;i="5.96,317,1665471600"; 
   d="scan'208";a="303143359"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jan 2023 07:45:30 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10586"; a="799854649"
X-IronPort-AV: E=Sophos;i="5.96,317,1665471600"; 
   d="scan'208";a="799854649"
Received: from lkp-server02.sh.intel.com (HELO f1920e93ebb5) ([10.239.97.151])
  by fmsmga001.fm.intel.com with ESMTP; 11 Jan 2023 07:45:19 -0800
Received: from kbuild by f1920e93ebb5 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1pFdHx-0009Ix-2U;
	Wed, 11 Jan 2023 15:45:17 +0000
Date: Wed, 11 Jan 2023 23:44:08 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, dri-devel@lists.freedesktop.org,
 Linux Memory Management List <linux-mm@kvack.org>
Subject: [linux-next:master] BUILD REGRESSION
 c9e9cdd8bdcc3e1ea330d49ea587ec71884dd0f5
Message-ID: <63bed948.8r/cE1fIbWFrvOVL%lkp@intel.com>
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lmcjUsHk;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.136 as permitted
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

tree/branch: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git master
branch HEAD: c9e9cdd8bdcc3e1ea330d49ea587ec71884dd0f5  Add linux-next specific files for 20230111

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202301111803.2ypwa4GK-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

aarch64-linux-ld: ID map text too big or misaligned
cistpl.c:(.text+0xbc): undefined reference to `iounmap'
drivers/gpu/drm/ttm/ttm_bo_util.c:364:32: error: implicit declaration of function 'vmap'; did you mean 'kmap'? [-Werror=implicit-function-declaration]
drivers/gpu/drm/ttm/ttm_bo_util.c:429:17: error: implicit declaration of function 'vunmap'; did you mean 'kunmap'? [-Werror=implicit-function-declaration]
include/linux/kcsan-checks.h:220:28: warning: 'args32' may be used uninitialized [-Wmaybe-uninitialized]
s390x-linux-ld: cistpl.c:(.text+0x354): undefined reference to `ioremap'
s390x-linux-ld: cistpl.c:(.text+0x3f6): undefined reference to `iounmap'

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- arm64-allyesconfig
|   `-- aarch64-linux-ld:ID-map-text-too-big-or-misaligned
|-- mips-allyesconfig
|   |-- drivers-gpu-drm-ttm-ttm_bo_util.c:error:implicit-declaration-of-function-vmap
|   `-- drivers-gpu-drm-ttm-ttm_bo_util.c:error:implicit-declaration-of-function-vunmap
`-- s390-randconfig-r034-20230111
    `-- include-linux-kcsan-checks.h:warning:args32-may-be-used-uninitialized
clang_recent_errors
`-- s390-randconfig-r005-20230110
    |-- cistpl.c:(.text):undefined-reference-to-iounmap
    |-- s39-linux-ld:cistpl.c:(.text):undefined-reference-to-ioremap
    `-- s39-linux-ld:cistpl.c:(.text):undefined-reference-to-iounmap

elapsed time: 725m

configs tested: 61
configs skipped: 2

gcc tested configs:
x86_64                            allnoconfig
um                             i386_defconfig
um                           x86_64_defconfig
powerpc                           allnoconfig
x86_64                        randconfig-a004
i386                                defconfig
arc                                 defconfig
x86_64                        randconfig-a002
x86_64                          rhel-8.3-func
s390                             allmodconfig
x86_64                              defconfig
arm                                 defconfig
x86_64                    rhel-8.3-kselftests
alpha                               defconfig
i386                          randconfig-a014
x86_64                               rhel-8.3
m68k                             allyesconfig
s390                                defconfig
x86_64                           rhel-8.3-bpf
i386                          randconfig-a012
x86_64                           rhel-8.3-syz
i386                          randconfig-a001
x86_64                         rhel-8.3-kunit
i386                          randconfig-a003
x86_64                           rhel-8.3-kvm
i386                          randconfig-a016
x86_64                        randconfig-a013
s390                             allyesconfig
arc                  randconfig-r043-20230110
m68k                             allmodconfig
x86_64                        randconfig-a006
x86_64                        randconfig-a011
arc                              allyesconfig
sh                               allmodconfig
s390                 randconfig-r044-20230110
alpha                            allyesconfig
i386                          randconfig-a005
mips                             allyesconfig
riscv                randconfig-r042-20230110
x86_64                        randconfig-a015
x86_64                           allyesconfig
arm64                            allyesconfig
powerpc                          allmodconfig
arm                              allyesconfig
i386                             allyesconfig

clang tested configs:
x86_64                          rhel-8.3-rust
i386                          randconfig-a013
x86_64                        randconfig-a001
hexagon              randconfig-r041-20230110
i386                          randconfig-a015
i386                          randconfig-a002
i386                          randconfig-a011
arm                  randconfig-r046-20230110
x86_64                        randconfig-a003
x86_64                        randconfig-a012
x86_64                        randconfig-a005
hexagon              randconfig-r045-20230110
i386                          randconfig-a004
x86_64                        randconfig-a014
i386                          randconfig-a006
x86_64                        randconfig-a016

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/63bed948.8r/cE1fIbWFrvOVL%25lkp%40intel.com.
