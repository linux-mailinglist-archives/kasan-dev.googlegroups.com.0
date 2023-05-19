Return-Path: <kasan-dev+bncBC4LXIPCY4NRB45OT2RQMGQEZQYMG4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CB84709B67
	for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 17:36:21 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3064d0b726fsf1324573f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 08:36:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684510580; cv=pass;
        d=google.com; s=arc-20160816;
        b=HjG5vzmibrJeddnsdl+Zxh/KGPAluNJ9Wjv6QzamZxqPyy6BKx1sg6z6obGDlWlAHk
         UJSI8GQXe6QAUoKHHrF1sDjZnsbE8iwGluz0QVWM+mL651Bn5CADA0gCL+95muOBr5D8
         8zx5hq6ztGl4KEjGIi4RTIgQ2E9RcibGbTUCF9hX+B7DXuOjUeNLVAQ0hJFMZcNp7l/a
         cN81G6+zg2DZbdAjIOYlCBTF3kURHACJkCCbhj3bAAGyCO8ESBBRA20P4RwcDevC7tg0
         7wN1nsbuRjEwUZhaHREggS++6xtwW7X1HbJ62ZPnhOh75E2MhNkSR8euEb2Rldp+BJz8
         OHyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=BKMeJMfxRfylojiCmgjT7T1i2TAeGw+q41BIFVK1eJM=;
        b=FGTAfvX+1ne+6OAbWvJ6EwdA5H+X8lQlDkJrY2YZxiPg+AV0u01igNq4/6EVib2flk
         HiXCCud1+lwKw68PerXsRW4KK6jqsbuRU47NtpOWLoJTsbXLooHMtRvLfztYu6zQfif3
         L8+KXMFIhz6QelwmuXjlfnP40CE6DBLkD759lSfI5OTHSGIsFULzj/PDhA70IQu/crDt
         mlfW2rak7NkGjLbsGOX0quo915/qgPUEzJvKymq6gGgMhsmPLrmfWrAe+yb4ZROV/cVH
         wBCMhxei0L4RukzresQwRaGMtK276kNCzg13ALIQgjzsDNOAQonKMibbDNQm2ZfYMoHy
         2+rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VCVdxUSX;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684510580; x=1687102580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BKMeJMfxRfylojiCmgjT7T1i2TAeGw+q41BIFVK1eJM=;
        b=mLqZauVHWbDwkEo0kYVk+gQzTMdEWkZcaYzB37boW5/5JxtjExnUpC3RTs564Ts/r0
         Bmk/qeCFeiRBrHbJHkAuYPKe/V8c0NEK5P4tJum/4CwoLFqIK6N7BVLbLvuJxbw8hBSV
         kHWw6ZhOOYKJh8UTGUsNs1TQ9DlUPKnAsH96odmdnmuBZ7gOuz6E0PGFi7MDNmkrTn/G
         tNM/mFM+V34f7eauXj256VVSRIyaUR/0V6MMHNKOLJ/aa0P71cATykkuSqQvMx5E6Vl4
         E6ncaBX1pfLSTagiCQLYQr/V44oaKPDP0TK7ord+Yk7MI4f6QPFE+XomQqQQqfxA5fGM
         snDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684510580; x=1687102580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BKMeJMfxRfylojiCmgjT7T1i2TAeGw+q41BIFVK1eJM=;
        b=SLSGOGd8+YE4jCs6hN7h0XGxR83FkBkgjIXMMPqwrpUkKnCts2nuHDIsm5dqQOYc92
         +osIFN+H8Cg6B6+aOfHvfQeCSK3PWuItmI8z7L+ZaDxCrIJiUml1aRTHoTJQWFSOOTkt
         bVqfLFlzViLFDahOKAOOnv0QKJUee+9+GSrsRQBy+3QMPkEBXXpOF4PmQKHxaVetZix6
         V6BwTeqWhdB+6PHqjgbidoCkN283QNDYdEHgtMJdkWJ9GALBQyTtyHp3voivuUJwXHVA
         f2PurUQsoaFysFvl81RoowtMbcfM/L/4NzVEA2DuW3De5zAwvWRDehJFzGXbeRUal2cC
         9Pow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx3yIxFRMc9pyZ9E7/BFPpYBdqPEr4N3xYwrQbZWT8ZFEMryZUh
	XfiRcxrjdhO0NTWHkwARebM=
X-Google-Smtp-Source: ACHHUZ74aOD4dO2uo/G+1WP+fmb6GC9r38yRAxNR/N2V5J6XGziwle2BWfTUGYw8oNM3GVPXITGreg==
X-Received: by 2002:adf:f305:0:b0:306:2635:6b78 with SMTP id i5-20020adff305000000b0030626356b78mr363800wro.4.1684510579988;
        Fri, 19 May 2023 08:36:19 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c8a:b0:3f5:21c:95cf with SMTP id
 k10-20020a05600c1c8a00b003f5021c95cfls1548491wms.1.-pod-prod-05-eu; Fri, 19
 May 2023 08:36:18 -0700 (PDT)
X-Received: by 2002:a7b:c4d3:0:b0:3f5:170:30a7 with SMTP id g19-20020a7bc4d3000000b003f5017030a7mr1437807wmk.41.1684510578667;
        Fri, 19 May 2023 08:36:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684510578; cv=none;
        d=google.com; s=arc-20160816;
        b=0ftp9xOM20KRhPgPRxqKzB7yiPhMNRe5aQew1Hs7oMdCCSJnDX6988LJZYIbFh+/Il
         lswTivny5Gs92muw+8F8vfc1HT2zjJR+3b7L0r8/DYWaB35v3jSoMf0aF78liyTEU55O
         Kf517YpFI6Qkko6Xro1a5IdgfLeBIiQsYI44MIC569O94k2o6jo8Tm4R3IeeyXgUsV5s
         UagxwEKl7NMCQ5AqZVxdnIke2AfbGB5tJr08JRxABduz6eMHbTsEVsAQlpSJNxzFJjo3
         OEmK+pZlkIqkgFh2Flj32elbdTZCTNOKcvy2mu6syMiWGtj2VRPNPjd7dngPvfJezzyz
         H6HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=N/CmPGvMiuYINI35IreAR8jXStJTJjjMM4bDh1xLYnA=;
        b=p2yP5yVTOBYAXok47RrvmujOa/aLmplewYvl4Xf1ycGsM2FG/7EQpiBQlDHNx5yARn
         MNYeCTtbqmVYkhcwaC9xHig2rzNWUgqmeWwqt7GaqqyLIcuYATOQSUXC7mUgxTxH8UKO
         4gDpbj/xIM9AR0hC/fKjgCnZNT6JHZLQN+Z0rUotJjt0rdg/mFLpz4RFHJLuwXDZesBP
         VjIoIOVbYrRhvWkSMUWhrBnUc38RR2rc/qbONJPnUEVL6PpA4AAT547F2fmaXqZglocg
         O7wFcGxmRiHPArmuMUBDzd6xiO7GlJ1mg4MGxtjFdnHSpcC2EkMIE6iIM243UHBnjHXh
         +kHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=VCVdxUSX;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id bg26-20020a05600c3c9a00b003f42c1b8171si257728wmb.0.2023.05.19.08.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 May 2023 08:36:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10715"; a="336995501"
X-IronPort-AV: E=Sophos;i="6.00,177,1681196400"; 
   d="scan'208";a="336995501"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 May 2023 08:36:16 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10715"; a="814776549"
X-IronPort-AV: E=Sophos;i="6.00,177,1681196400"; 
   d="scan'208";a="814776549"
Received: from lkp-server01.sh.intel.com (HELO dea6d5a4f140) ([10.239.97.150])
  by fmsmga002.fm.intel.com with ESMTP; 19 May 2023 08:36:13 -0700
Received: from kbuild by dea6d5a4f140 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1q029M-000AuI-2J;
	Fri, 19 May 2023 15:36:12 +0000
Date: Fri, 19 May 2023 23:35:48 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 amd-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
 linux-ext4@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-xfs@vger.kernel.org, netdev@vger.kernel.org
Subject: [linux-next:master] BUILD SUCCESS WITH WARNING
 dbd91ef4e91c1ce3a24429f5fb3876b7a0306733
Message-ID: <20230519153548.XTWhe%lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=VCVdxUSX;       spf=pass
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

tree/branch: INFO setup_repo_specs: /db/releases/20230519164737/lkp-src/repo/*/linux-next
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git master
branch HEAD: dbd91ef4e91c1ce3a24429f5fb3876b7a0306733  Add linux-next specific files for 20230519

Warning reports:

https://lore.kernel.org/oe-kbuild-all/202304220118.NYuW8ip0-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202305132244.DwzBUcUd-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202305182345.LTMlWG84-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202305190358.IEfJNraU-lkp@intel.com

Warning: (recently discovered and may have been fixed)

drivers/base/regmap/regcache-maple.c:113:23: warning: 'lower_index' is used uninitialized [-Wuninitialized]
drivers/base/regmap/regcache-maple.c:113:36: warning: 'lower_last' is used uninitialized [-Wuninitialized]
drivers/gpu/drm/amd/amdgpu/../display/amdgpu_dm/amdgpu_dm.c:6396:21: warning: variable 'count' set but not used [-Wunused-but-set-variable]
drivers/gpu/drm/amd/amdgpu/amdgpu_gfx.c:499:13: warning: variable 'j' set but not used [-Wunused-but-set-variable]
drivers/net/arcnet/com20020.c:74:7: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]

Unverified Warning (likely false positive, please contact us if interested):

fs/ext4/verity.c:316 ext4_get_verity_descriptor_location() error: uninitialized symbol 'desc_size_disk'.
fs/xfs/scrub/fscounters.c:459 xchk_fscounters() warn: ignoring unreachable code.
kernel/events/uprobes.c:478 uprobe_write_opcode() warn: passing zero to 'PTR_ERR'

Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- alpha-randconfig-r036-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arc-allyesconfig
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_index-is-used-uninitialized
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_last-is-used-uninitialized
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arc-vdk_hs38_defconfig
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_index-is-used-uninitialized
|   `-- drivers-base-regmap-regcache-maple.c:warning:lower_last-is-used-uninitialized
|-- arm-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arm-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arm64-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arm64-randconfig-r015-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- i386-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- i386-randconfig-m021
|   |-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
|   `-- lib-stackdepot.c-stack_print()-warn:unsigned-stack-size-is-never-less-than-zero.
|-- i386-randconfig-s001
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- i386-randconfig-s002
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- i386-randconfig-s003
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- ia64-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- ia64-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- loongarch-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- loongarch-defconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- loongarch-randconfig-r034-20230517
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- microblaze-buildonly-randconfig-r002-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- microblaze-randconfig-s053-20230517
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- mips-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- mips-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- openrisc-randconfig-s051-20230517
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- parisc-randconfig-m041-20230519
|   |-- fs-ext4-verity.c-ext4_get_verity_descriptor_location()-error:uninitialized-symbol-desc_size_disk-.
|   |-- fs-xfs-scrub-fscounters.c-xchk_fscounters()-warn:ignoring-unreachable-code.
|   `-- lib-stackdepot.c-stack_print()-warn:unsigned-stack-size-is-never-less-than-zero.
|-- powerpc-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-randconfig-c034-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- riscv-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- riscv-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- riscv-randconfig-s031-20230517
|   |-- mm-kfence-core.c:sparse:sparse:cast-to-restricted-__le64
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- s390-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- sparc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- sparc64-buildonly-randconfig-r004-20230517
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- x86_64-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- x86_64-randconfig-m001
|   |-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
|   `-- lib-stackdepot.c-stack_print()-warn:unsigned-stack-size-is-never-less-than-zero.
|-- x86_64-randconfig-s021
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- x86_64-randconfig-s022
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
|-- x86_64-randconfig-s023
|   |-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_get-was-not-declared.-Should-it-be-static
|   `-- mm-page_owner.c:sparse:sparse:symbol-page_owner_threshold_set-was-not-declared.-Should-it-be-static
`-- xtensa-randconfig-r001-20230517
    |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
    `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
clang_recent_errors
`-- riscv-randconfig-r032-20230517
    `-- drivers-net-arcnet-com20020.c:warning:performing-pointer-arithmetic-on-a-null-pointer-has-undefined-behavior

elapsed time: 724m

configs tested: 142
configs skipped: 6

tested configs:
alpha                            allyesconfig   gcc  
alpha                               defconfig   gcc  
alpha                randconfig-r033-20230517   gcc  
alpha                randconfig-r036-20230517   gcc  
arc                              allyesconfig   gcc  
arc                                 defconfig   gcc  
arc                         haps_hs_defconfig   gcc  
arc                     haps_hs_smp_defconfig   gcc  
arc                  randconfig-r043-20230517   gcc  
arc                        vdk_hs38_defconfig   gcc  
arm                              allmodconfig   gcc  
arm                              allyesconfig   gcc  
arm          buildonly-randconfig-r005-20230517   clang
arm                                 defconfig   gcc  
arm                      integrator_defconfig   gcc  
arm                         lpc32xx_defconfig   clang
arm                        mvebu_v7_defconfig   gcc  
arm                         nhk8815_defconfig   gcc  
arm                            qcom_defconfig   gcc  
arm                  randconfig-r046-20230517   clang
arm64                            allyesconfig   gcc  
arm64                               defconfig   gcc  
arm64                randconfig-r015-20230517   gcc  
csky                                defconfig   gcc  
hexagon              randconfig-r022-20230517   clang
hexagon              randconfig-r035-20230517   clang
hexagon              randconfig-r041-20230517   clang
hexagon              randconfig-r045-20230517   clang
i386                             allyesconfig   clang
i386                             allyesconfig   gcc  
i386                              debian-10.3   gcc  
i386                                defconfig   gcc  
i386                          randconfig-a001   gcc  
i386                          randconfig-a002   clang
i386                          randconfig-a003   gcc  
i386                          randconfig-a004   clang
i386                          randconfig-a005   gcc  
i386                          randconfig-a006   clang
i386                          randconfig-a011   clang
i386                          randconfig-a012   gcc  
i386                          randconfig-a013   clang
i386                          randconfig-a014   gcc  
i386                          randconfig-a015   clang
i386                          randconfig-a016   gcc  
ia64                             allmodconfig   gcc  
ia64                             allyesconfig   gcc  
ia64                                defconfig   gcc  
ia64                        generic_defconfig   gcc  
ia64                          tiger_defconfig   gcc  
loongarch                        alldefconfig   gcc  
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch            randconfig-r034-20230517   gcc  
m68k                             allmodconfig   gcc  
m68k                                defconfig   gcc  
m68k                 randconfig-r014-20230517   gcc  
m68k                 randconfig-r023-20230517   gcc  
microblaze   buildonly-randconfig-r002-20230517   gcc  
microblaze                          defconfig   gcc  
mips                             allmodconfig   gcc  
mips                             allyesconfig   gcc  
mips                  cavium_octeon_defconfig   clang
mips                           gcw0_defconfig   gcc  
mips                       lemote2f_defconfig   clang
mips                     loongson1b_defconfig   gcc  
mips                     loongson1c_defconfig   clang
mips                     loongson2k_defconfig   clang
mips                  maltasmvp_eva_defconfig   gcc  
mips                        qi_lb60_defconfig   clang
mips                 randconfig-r025-20230517   clang
nios2                               defconfig   gcc  
nios2                randconfig-r002-20230517   gcc  
openrisc             randconfig-r026-20230517   gcc  
parisc                              defconfig   gcc  
parisc               randconfig-r011-20230517   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   gcc  
powerpc                           allnoconfig   gcc  
powerpc                     ep8248e_defconfig   gcc  
powerpc                      katmai_defconfig   clang
powerpc                     ksi8560_defconfig   clang
powerpc                      pcm030_defconfig   gcc  
powerpc                      pmac32_defconfig   clang
powerpc                    sam440ep_defconfig   gcc  
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   gcc  
riscv                            allyesconfig   gcc  
riscv                               defconfig   gcc  
riscv                randconfig-r003-20230517   clang
riscv                randconfig-r005-20230517   clang
riscv                randconfig-r032-20230517   clang
riscv                randconfig-r042-20230517   gcc  
riscv                          rv32_defconfig   gcc  
s390                             allmodconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                 randconfig-r004-20230517   clang
s390                 randconfig-r031-20230517   clang
s390                 randconfig-r044-20230517   gcc  
sh                               allmodconfig   gcc  
sh                           se7721_defconfig   gcc  
sh                           se7751_defconfig   gcc  
sparc                             allnoconfig   gcc  
sparc                               defconfig   gcc  
sparc                randconfig-r016-20230517   gcc  
sparc                randconfig-r024-20230517   gcc  
sparc64      buildonly-randconfig-r004-20230517   gcc  
sparc64              randconfig-r012-20230517   gcc  
um                             i386_defconfig   gcc  
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   gcc  
x86_64                              defconfig   gcc  
x86_64                                  kexec   gcc  
x86_64                        randconfig-a001   clang
x86_64                        randconfig-a002   gcc  
x86_64                        randconfig-a003   clang
x86_64                        randconfig-a004   gcc  
x86_64                        randconfig-a005   clang
x86_64                        randconfig-a006   gcc  
x86_64                        randconfig-a011   gcc  
x86_64                        randconfig-a012   clang
x86_64                        randconfig-a013   gcc  
x86_64                        randconfig-a014   clang
x86_64                        randconfig-a015   gcc  
x86_64                        randconfig-a016   clang
x86_64                        randconfig-x051   gcc  
x86_64                        randconfig-x052   clang
x86_64                        randconfig-x053   gcc  
x86_64                        randconfig-x054   clang
x86_64                        randconfig-x055   gcc  
x86_64                        randconfig-x056   clang
x86_64                        randconfig-x061   gcc  
x86_64                        randconfig-x062   clang
x86_64                        randconfig-x063   gcc  
x86_64                        randconfig-x064   clang
x86_64                        randconfig-x065   gcc  
x86_64                        randconfig-x066   clang
x86_64                               rhel-8.3   gcc  
xtensa       buildonly-randconfig-r003-20230517   gcc  
xtensa               randconfig-r001-20230517   gcc  
xtensa               randconfig-r021-20230517   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230519153548.XTWhe%25lkp%40intel.com.
