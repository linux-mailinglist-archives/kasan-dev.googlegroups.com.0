Return-Path: <kasan-dev+bncBC4LXIPCY4NRBAE6SSRQMGQEW67LDBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55F54706F73
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 19:29:37 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3f42bcef2acsf4861245e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 10:29:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684344577; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qc6P7zB2NP+Dz2MGCRG/5deiApYyvcgLV2KCYzpFU7l9a8ROeNumk8x1nRABbJBlE0
         9V4kyDUuoQYg5W3u2EnpkHpuHewPt6vwvAv0i+oJ39TxgWR4nlP00KXX1r0rno2aTJFP
         56ssyRh3Lblwy5pGf4TpfC3Pk4A+0FolBSD3a/M7QVomTHyWTxak9Vi8oriNvrOyt/IU
         iA+x0isV8yV/HRyFR7Eu1SEcpOB1zCid/31ERALdxqt4vncNbGN1vQma3jVPKL7J7O4l
         Dk604fQp3wd1xzfMKHDRoAYpBdJ8d+e0Kj4NdCa+O7jXIS6SiZppNn08Kja/VEMMHDSj
         zGvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=/hAyH5tuJ0cvohl1fXoDHhrNfUmfBn0dExwBQmQgZ6s=;
        b=xkn1e1b4qvHuPJr3yNZQ+z3U1V7STtnjZuhGg7KPFLpvYWMWWl4PGtRI2bqSc5AI5D
         AnljhKryMQM+CdZ93xjmfasMzYDXrZo8G/V6+JzXO2utEr5AFqmQfws8oNrUWuBB+0pA
         JIbsxQ2KCYH0xaU6NfaIxh5/EQGhsXTkWYwFCNB5IDDWZ704e7TXwFxcL4crmvny6UUS
         xZzfU2rWP+ijW7XgSPtOpAzmdKYS+h6rvhSeVsA7UvKcAuM1aAQegmiIj0WsA/ctzyyo
         1tqsK4GSJ8N1XxDbJLSObXk7TLohM3qCt2ai38rBMrYieYIS+nPxN3cyB3eR3a/f8/mM
         jyhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DZExsUfU;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684344577; x=1686936577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/hAyH5tuJ0cvohl1fXoDHhrNfUmfBn0dExwBQmQgZ6s=;
        b=n9CKzL9QY6Le3jZyXajgr2wUKtcEv+j/ZqRwVnK2Dt748h6hnJ3r1ORNjnVMrtjeuD
         mdKTQyGJC+sj+lqSIVcNM5OBzpgj64LBsOLEECWEeDC83VoMDDkczcJlVzdn7Jkec0MD
         iZ0Uwf4SraRxq7Qo/DWoL7IhC+GCGofRCI3HioODRD5C6lAARLRzIthBZKQ2/kA1wdXO
         jQAWXOyRqSa+6X2HAqP5Edw0SrTr8FAIH/T5fuAQ8V/Wz3SjfAvBwR8biOFUS7cft/43
         aHV9XJZSz83+D3UUuCO9xEWnvbFvlclv+KaljUT7eXS3GLBZkjh8GNl+Bj8mZI1SPvIp
         YczQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684344577; x=1686936577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/hAyH5tuJ0cvohl1fXoDHhrNfUmfBn0dExwBQmQgZ6s=;
        b=KKTM6WQJd7RtrzOkygrP1zHXgcEjNgGLy6PzPWfXMoOG/0QBmDXp/buuFoULwAjcPs
         qrwhpRToL5789sHX35/rks6mmkLO+Wx66Ljxq2K8KlXh7kPPWGjn2rJdLmJjqAIvUej9
         sBQFU5zR0cXT+0pXnF+p0SYEEnF9kQ8VUE6nsZnz7NB4LVfCCUWVkcrwPrwgG1rm3DQ5
         5+4eGQDUBRVaB39NHmmaaF1F6gRdbYrm9n/6qj2N367ARZglBoJCNGDlfJRh3im67fVy
         tGcTs30G1asqKEnsCeIPi9yNcMIP3KxQZK/UeIyJiNygg5/s3ykAOI5XZZyPcpypyK73
         O7LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDySikCqLEqGoRZ7E+f7AJTpG4sjp/4BJxaAIKNVEfeSahbpWVNH
	3Z2Ajhma2HpEVdZMB9xvGPo=
X-Google-Smtp-Source: ACHHUZ4PUwM7Dh+X85IVqPF16+kFWl2tiPRUTZZ12Ujkb5scyJZ13gLIxCDlH/oujNnEAG+1Kl4Pgw==
X-Received: by 2002:adf:e3c3:0:b0:2f7:40a:4bb3 with SMTP id k3-20020adfe3c3000000b002f7040a4bb3mr280751wrm.12.1684344576620;
        Wed, 17 May 2023 10:29:36 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1c0f:b0:2f4:1b04:ed8f with SMTP id
 ba15-20020a0560001c0f00b002f41b04ed8fls2636949wrb.1.-pod-prod-gmail; Wed, 17
 May 2023 10:29:34 -0700 (PDT)
X-Received: by 2002:a5d:5592:0:b0:309:418f:d52c with SMTP id i18-20020a5d5592000000b00309418fd52cmr1205443wrv.63.1684344574851;
        Wed, 17 May 2023 10:29:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684344574; cv=none;
        d=google.com; s=arc-20160816;
        b=LOOIueGM4WZ1GpMO9U4sEKFwsMQG2k0Jhw4X5StvJMWaukAWKt3MsODuV0mroN53Ks
         TfzlSJlVm+NX5Oa/h/xNtQdOHwIA4AEbhDCBYlLxsvy7Qnmm0VUu4iKo2WhukoGEzcBL
         bLwsTxGFbG2RtZMvbIlRGdE+d//j5QKn7IFt/VOxrmjwjncFcDqIP0ckbDAhBWJt3UP4
         d/+I3nVSAlVfRXlKLMpGuO8EbwVu+1i/maBmrNXeLUa6iy0+8ncCWr4niQzbTuEjuZ9y
         Mn6PWzeK/SOWrusPn/PZL0kzE7JBGYjt9VvJvvkIPbARk6BrtbeGCMCx6RMCVfiV+rhz
         skBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Dfhis7UN1xq8ZvItxLy7RmfnuwrLr2PTQ9KkWw0dxSw=;
        b=K7zWOwH8XitouK+GkmloaET6istCIl+X7Kj2SUR36ZmMiwgaTEmfC7Sq4XlAYgKWNj
         ZhDpcGEWv6LO+7OCOmDr3lnM3Yub5TiGtnqKOxxwtj4/n/c3bR03hTelmmuExQXy3RKe
         Tv5gvHyL2Rb+By36reesm4VpVZgCi4KHKhuOfzpVPvkaAiU/xeW/pW3UtayGgltLPMq9
         GgH4oy9jFbKFPe4NZ1/GfkhfCytzJhURCmx//Gs+OIR5F0718yfs6T3On9LHXv1baZLo
         ZlYRU8GEK5GNu8b8Hu/RnNEUTPqb7h2nK+on6te1j5AJi+obJhuui7I1PpcSg5r1/a6i
         xICg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DZExsUfU;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id u2-20020a056000038200b003062765f97esi225679wrf.6.2023.05.17.10.29.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 May 2023 10:29:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10713"; a="350660147"
X-IronPort-AV: E=Sophos;i="5.99,282,1677571200"; 
   d="scan'208";a="350660147"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 May 2023 10:29:32 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10713"; a="652314150"
X-IronPort-AV: E=Sophos;i="5.99,282,1677571200"; 
   d="scan'208";a="652314150"
Received: from lkp-server01.sh.intel.com (HELO dea6d5a4f140) ([10.239.97.150])
  by orsmga003.jf.intel.com with ESMTP; 17 May 2023 10:29:29 -0700
Received: from kbuild by dea6d5a4f140 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1pzKxs-00096K-1m;
	Wed, 17 May 2023 17:29:28 +0000
Date: Thu, 18 May 2023 01:28:42 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 amd-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
 linux-bluetooth@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-xfs@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 065efa589871e93b6610c70c1e9de274ef1f1ba2
Message-ID: <20230517172842.Ssf2F%lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DZExsUfU;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted
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

tree/branch: INFO setup_repo_specs: /db/releases/20230517200055/lkp-src/repo/*/linux-next
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git master
branch HEAD: 065efa589871e93b6610c70c1e9de274ef1f1ba2  Add linux-next specific files for 20230517

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202304200812.6UqNDVZy-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202304220119.94Pw6YsD-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202305132244.DwzBUcUd-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202305171622.jKTovBvy-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

drivers/base/regmap/regcache-maple.c:113:23: warning: 'lower_index' is used uninitialized [-Wuninitialized]
drivers/base/regmap/regcache-maple.c:113:36: warning: 'lower_last' is used uninitialized [-Wuninitialized]
drivers/bluetooth/btnxpuart.c:1332:34: warning: unused variable 'nxpuart_of_match_table' [-Wunused-const-variable]
drivers/gpu/drm/amd/amdgpu/../display/amdgpu_dm/amdgpu_dm.c:6396:21: warning: variable 'count' set but not used [-Wunused-but-set-variable]
drivers/gpu/drm/amd/amdgpu/../display/dc/dce/dmub_abm.c:138:15: warning: variable 'feature_support' set but not used [-Wunused-but-set-variable]
drivers/gpu/drm/amd/amdgpu/amdgpu_gfx.c:499:13: warning: variable 'j' set but not used [-Wunused-but-set-variable]
ld.lld: error: undefined symbol: __udivdi3

Unverified Error/Warning (likely false positive, please contact us if interested):

drivers/net/wireless/realtek/rtw88/mac.c:798 __rtw_download_firmware() warn: missing unwind goto?
fs/xfs/scrub/fscounters.c:459 xchk_fscounters() warn: ignoring unreachable code.
kernel/events/uprobes.c:478 uprobe_write_opcode() warn: passing zero to 'PTR_ERR'

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arc-allyesconfig
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_index-is-used-uninitialized
|   |-- drivers-base-regmap-regcache-maple.c:warning:lower_last-is-used-uninitialized
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arm-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arm-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- arm64-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- csky-randconfig-m041-20230517
|   |-- drivers-net-wireless-realtek-rtw88-mac.c-__rtw_download_firmware()-warn:missing-unwind-goto
|   `-- fs-xfs-scrub-fscounters.c-xchk_fscounters()-warn:ignoring-unreachable-code.
|-- csky-randconfig-r032-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- i386-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- i386-randconfig-m021
|   `-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
|-- ia64-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- ia64-buildonly-randconfig-r005-20230517
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- ia64-randconfig-r023-20230517
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- ia64-randconfig-r031-20230517
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- loongarch-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- loongarch-defconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- mips-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- mips-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-buildonly-randconfig-r004-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-randconfig-c023-20230517
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-randconfig-c034-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-randconfig-r012-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- powerpc-randconfig-s033-20230517
|   `-- mm-kfence-core.c:sparse:sparse:cast-to-restricted-__le64
|-- riscv-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- s390-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- sparc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- sparc-randconfig-r005-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
|-- x86_64-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c:warning:variable-count-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-amdgpu_gfx.c:warning:variable-j-set-but-not-used
`-- x86_64-randconfig-m001
    `-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
clang_recent_errors
|-- arm64-randconfig-r006-20230517
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dce-dmub_abm.c:warning:variable-feature_support-set-but-not-used
|-- i386-buildonly-randconfig-r001-20230515
|   `-- ld.lld:error:undefined-symbol:__udivdi3
`-- x86_64-randconfig-x052
    `-- drivers-bluetooth-btnxpuart.c:warning:unused-variable-nxpuart_of_match_table

elapsed time: 871m

configs tested: 127
configs skipped: 7

tested configs:
alpha                            allyesconfig   gcc  
alpha        buildonly-randconfig-r002-20230517   gcc  
alpha                               defconfig   gcc  
alpha                randconfig-r013-20230517   gcc  
arc                              allyesconfig   gcc  
arc                                 defconfig   gcc  
arc                  randconfig-r043-20230517   gcc  
arm                              allmodconfig   gcc  
arm                              allyesconfig   gcc  
arm                        clps711x_defconfig   gcc  
arm                                 defconfig   gcc  
arm                          exynos_defconfig   gcc  
arm                            hisi_defconfig   gcc  
arm                  randconfig-r004-20230517   gcc  
arm                  randconfig-r046-20230517   clang
arm                           sama7_defconfig   clang
arm                           tegra_defconfig   gcc  
arm                         vf610m4_defconfig   gcc  
arm64                            allyesconfig   gcc  
arm64                               defconfig   gcc  
arm64                randconfig-r006-20230517   clang
arm64                randconfig-r011-20230517   gcc  
csky                                defconfig   gcc  
csky                 randconfig-r024-20230517   gcc  
csky                 randconfig-r025-20230517   gcc  
csky                 randconfig-r032-20230517   gcc  
hexagon      buildonly-randconfig-r006-20230517   clang
hexagon                             defconfig   clang
hexagon              randconfig-r041-20230517   clang
hexagon              randconfig-r045-20230517   clang
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
ia64         buildonly-randconfig-r005-20230517   gcc  
ia64                                defconfig   gcc  
ia64                        generic_defconfig   gcc  
ia64                 randconfig-r023-20230517   gcc  
ia64                 randconfig-r031-20230517   gcc  
ia64                 randconfig-r036-20230517   gcc  
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
m68k                             allmodconfig   gcc  
m68k                         amcore_defconfig   gcc  
m68k                         apollo_defconfig   gcc  
m68k         buildonly-randconfig-r001-20230517   gcc  
m68k                                defconfig   gcc  
microblaze           randconfig-r034-20230517   gcc  
mips                             allmodconfig   gcc  
mips                             allyesconfig   gcc  
mips                      malta_kvm_defconfig   clang
mips                 randconfig-r015-20230517   clang
nios2                            allyesconfig   gcc  
nios2        buildonly-randconfig-r003-20230517   gcc  
nios2                               defconfig   gcc  
parisc                              defconfig   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   gcc  
powerpc                           allnoconfig   gcc  
powerpc      buildonly-randconfig-r004-20230517   gcc  
powerpc              randconfig-r001-20230517   clang
powerpc              randconfig-r012-20230517   gcc  
powerpc              randconfig-r014-20230517   gcc  
powerpc              randconfig-r035-20230517   clang
powerpc                  storcenter_defconfig   gcc  
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   gcc  
riscv                               defconfig   gcc  
riscv                randconfig-r042-20230517   gcc  
riscv                          rv32_defconfig   gcc  
s390                             allmodconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                 randconfig-r016-20230517   gcc  
s390                 randconfig-r044-20230517   gcc  
sh                               allmodconfig   gcc  
sh                 kfr2r09-romimage_defconfig   gcc  
sh                   randconfig-r003-20230517   gcc  
sh                   randconfig-r022-20230517   gcc  
sh                           se7751_defconfig   gcc  
sparc                               defconfig   gcc  
sparc                randconfig-r005-20230517   gcc  
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
xtensa                    smp_lx200_defconfig   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230517172842.Ssf2F%25lkp%40intel.com.
