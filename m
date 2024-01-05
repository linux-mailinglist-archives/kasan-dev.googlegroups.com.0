Return-Path: <kasan-dev+bncBC4LXIPCY4NRBROH32WAMGQEN7FO7VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E0F2824EB2
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jan 2024 07:37:59 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-781b990bbc8sf120214585a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 22:37:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704436678; cv=pass;
        d=google.com; s=arc-20160816;
        b=uxUODzXV8k2Z10w+ULrWDz8PshogH3Pjva2p3nf8kwR/yxG1IDzg75BDzG2WJtxNFy
         t4YrVyPTBPA5YbY/GGcnJ1/VGx+e7F2+tlmvchtQ9nIawyVnT2NhYkTQEophDrBa2vHU
         Rj4C5p4hoZhl15ixsd2xdzL3mSbkLefWh5m7fxHE/pbgtP/fi2VjQeLYtKafrC5hmelj
         qc2SDh9LBVD12ruqJXBORXWFfOtHeDptdDtrgDY/Zn7c40uHxXx6yLDK8pyQwHYSLJBp
         XJ1S0iZExizvkbNgqHjoySsvBf/aIi3M3SciBIuHXwma5A5cKfKB17qeq9HV3u7sVrdq
         X9mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=1zs5+ohKwEYsbPq6G4pptWr0+teb5AkcW4wXZj7IpzQ=;
        fh=pQ7baJMmWmGDYmbPBpVhXd6jL8tDZa5Hv8Oep7AKzqo=;
        b=GfPHJgy/e+YkZIOdWQXmsFXJE5NOFSVwKmswtM1gZpnVZBhR/swNerUapV9TLo4Dk/
         fleFBKYAIj6p4XDoRSdy3tXyVTbqV3kWa1dLS0eMonyZQPmidAilln/6JHkFytThukUE
         UH3hTEZr+qnEpg0HR1v8qpGOLxKqOVhTgsCphQ2nJvu2LkvOgvFZTfxbtIVUv5Drfbh/
         E76pz8x3GPIlCPXdK4DVmcqgACNr0MrjhAfd5kIS+J0CRUYCCopyJ2hsLspbp/U/WWm4
         YRrsnFXWd5LFVUH6XSMZ0FS7ThacwZBbHf4HHMmLKdlpI2bThGMbEQphlllScQYuQfpR
         DUQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UY9grEM8;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704436678; x=1705041478; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1zs5+ohKwEYsbPq6G4pptWr0+teb5AkcW4wXZj7IpzQ=;
        b=soiAoIJBNzgoOOStzhLx8Tv67vj9KSZTt/UEUYYvrrYWSnjAskSIJAKAQ95o85ECXu
         WNiWQCVoGTw4aH7UV+D64nOCnDbMlhiueNYsWw9CAxkk6SNusdlgsEiTkqDsL8a/cfhA
         D62owpOTdDA94BcgsW93yB/dZxY2tl9Uutg55ORVc6Jiw9+pAqK08mxPb22fFBfyXJiV
         gW0W7DB1xXDvGefig1RwknkCs3r1IaKuUTMjOI01KqSBGCbjiBwBdS8Ilg+f77xEELVq
         bA7nTauKOEeRrd4mk29xsAUr1A1h+IZQ3sFHIT9wIFOxTAx6foLChjcWTwaPBiSQrC3Q
         moww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704436678; x=1705041478;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1zs5+ohKwEYsbPq6G4pptWr0+teb5AkcW4wXZj7IpzQ=;
        b=lRGrbQzDB2CT8cVFeq1XXellvSx4H5dM3cpzCpQu6SDRstqtzC7/fjVFhlAhPqrNYb
         nuRIjuz8wFvWWR/RjqlJJ/vk3I5AFF4ikoeX6jzYFj4aGWvDvL/ZVqL8QmJnCUJRSN7H
         cqqyJ6QmGt9GAsxcdTFNgS0K1PUIdmLKf0COwD5rU9TugvXmn1RqEf4VS93e2iVPkc3i
         R6Dz7QxJhfpbbojs8scnjjeBVko0vMMXJQdVsR0M5kg8oy9T3/N5KnOc89B05BAhoLvC
         SG8eAJvyKvHakKEU96eIzt4N1VZyCRolUxVpjt5jNviXPCV+u4/ke8mf9DQLgzHSpBb/
         R9Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxtaLUQvq6RB168SPOG1EKkAIc/G2zPp+KFG+pal4fNV+DcPt2C
	jV8X1FWpabEsXeZqIHgHIlY=
X-Google-Smtp-Source: AGHT+IESVHkQ4HXv7L0i3yE2iwqyqCku0ibfDJFa5aupKmEXDo5e53zr1j1vBaq2pAArPabWtDZ44g==
X-Received: by 2002:a05:6214:2aac:b0:67c:cd09:9b93 with SMTP id js12-20020a0562142aac00b0067ccd099b93mr1721513qvb.7.1704436677998;
        Thu, 04 Jan 2024 22:37:57 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:411c:b0:67f:74d3:afb5 with SMTP id
 kc28-20020a056214411c00b0067f74d3afb5ls25352qvb.1.-pod-prod-01-us; Thu, 04
 Jan 2024 22:37:57 -0800 (PST)
X-Received: by 2002:a67:b605:0:b0:466:e150:cb with SMTP id d5-20020a67b605000000b00466e15000cbmr1438882vsm.31.1704436677028;
        Thu, 04 Jan 2024 22:37:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704436677; cv=none;
        d=google.com; s=arc-20160816;
        b=HZg5w4BuHfBEZaCY3NLiaav8ZBbbTFRSHnaiNJ9icJR7Gg9WOsWidqUWX6huhmUywb
         OXjVV7ZJ+tpchXuBKRANIQxTFKdfMRDmdFFVeDNLJBc7WAk33Q3aQZW3M6Hslvr8bGwc
         Ru4hctumkwGwxtpwoE1GO4ZuP0cHhz0mRo5z3lRFYk3CEMTONaQiv173aupDkrbQVw8e
         lBFp/yZV6Ky5X+4AfROir/K+sAIyVfMdoEC32g6aybQZKanaE9GINdtVL8pmaBNLiVZh
         bkovCabWzYrv1Cdpj3PIkTBFILGBijejQzSB6s6elx1jr8O/nfp8+q7pBOdbeYANzYgN
         a8lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=RkBIRcr+dDh18LSlka8dvJTdkWi5RHnkcdSXzORpFCc=;
        fh=pQ7baJMmWmGDYmbPBpVhXd6jL8tDZa5Hv8Oep7AKzqo=;
        b=y3RAi7lcdbtAGTADEXwos3KwVbO9DU++rF2Y/eVNR6YrPJQw3dX/dMXXiaMAXs+tRI
         MWXpOyuhJZBMoOnCAmefMEMaXKcg58PRKwKz4BzNnflg5C/a4Yf3Ii9OLZsfB05bUrmj
         3XJ0WnAinmpryJ04E/e+8/oYJyOT7CwkMdvAXdGTyYUbF/hBR/A8P1x7pXwnRSs283ti
         xeCV2bakG8TNVcGf7HZz8VTDFc902ckjiVQtv+qwOw6AMi94M9GHaQiMLgPgAVAMDLJc
         43ea6NfV3XOYmnVSEWJ1J/cbPQbiNH4jzTlYUh2/CkohlxomR4UKgw+SUtDotiLqGxKh
         MI2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UY9grEM8;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id s16-20020ab07650000000b007cb8c7adf99si158357uaq.0.2024.01.04.22.37.55
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jan 2024 22:37:56 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-IronPort-AV: E=McAfee;i="6600,9927,10943"; a="4215417"
X-IronPort-AV: E=Sophos;i="6.04,332,1695711600"; 
   d="scan'208";a="4215417"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Jan 2024 22:37:34 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10943"; a="780676124"
X-IronPort-AV: E=Sophos;i="6.04,332,1695711600"; 
   d="scan'208";a="780676124"
Received: from lkp-server02.sh.intel.com (HELO b07ab15da5fe) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 04 Jan 2024 22:37:29 -0800
Received: from kbuild by b07ab15da5fe with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rLdpe-0000sv-2q;
	Fri, 05 Jan 2024 06:37:26 +0000
Date: Fri, 05 Jan 2024 14:36:48 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 amd-gfx@lists.freedesktop.org, dmaengine@vger.kernel.org,
 dri-devel@lists.freedesktop.org, freedreno@lists.freedesktop.org,
 kasan-dev@googlegroups.com, kunit-dev@googlegroups.com,
 linux-arm-msm@vger.kernel.org, linux-bcachefs@vger.kernel.org,
 linux-hwmon@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-media@vger.kernel.org, netdev@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 d0b3c8aa5e37775cd7c3ac07b256218df0fd6678
Message-ID: <202401051437.ylHQ71JT-lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UY9grEM8;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.11 as permitted
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
branch HEAD: d0b3c8aa5e37775cd7c3ac07b256218df0fd6678  Add linux-next specific files for 20240104

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202401041942.qrB1amZM-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

tools/testing/selftests/net/tcp_ao/bench-lookups.c:202: undefined reference to `sqrt'

Unverified Error/Warning (likely false positive, please contact us if interested):

drivers/gpu/drm/amd/amdgpu/../display/amdgpu_dm/amdgpu_dm.c:9280 amdgpu_dm_atomic_commit_tail() error: we previously assumed 'acrtc' could be null (see line 9277)
drivers/media/i2c/st-mipid02.c:396:1-7: WARNING: do_div() does a 64-by-32 division, please consider using div64_s64 instead.
drivers/net/ethernet/broadcom/bnxt/bnxt.c:5333:6-25: WARNING: atomic_dec_and_test variation before object free at line 5336.
drivers/net/ethernet/marvell/octeon_ep/octep_pfvf_mbox.c:32:16-17: WARNING opportunity for min()
drivers/net/ethernet/marvell/octeontx2/af/rvu_npc_fs.c:575:9-32: duplicated argument to & or |
{standard input}:18305: Warning: overflow in branch to .L4391; converted into longer instruction sequence
{standard input}:20816: Warning: overflow in branch to .L4982; converted into longer instruction sequence
{standard input}:21171: Warning: overflow in branch to .L4853; converted into longer instruction sequence
{standard input}:27179: Warning: overflow in branch to .L4887; converted into longer instruction sequence

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- arc-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arc-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arc-randconfig-002-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- arc-randconfig-r133-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   `-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|-- arm-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm-randconfig-001-20240104
|   `-- :Error:selected-processor-does-not-support-requested-special-purpose-register-mrs-r1-cpsr
|-- arm-randconfig-003-20240104
|   `-- :Error:selected-processor-does-not-support-requested-special-purpose-register-mrs-r1-cpsr
|-- arm-randconfig-r131-20240104
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-int-usertype-size
|-- arm64-defconfig
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l0_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l0_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l1_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l1_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-pvr_dev-description-in-pvr_mmu_backing_page
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-sgt-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-sgt_offset-description-in-pvr_mmu_op_context
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm64-randconfig-r053-20240104
|   |-- drivers-net-ethernet-broadcom-bnxt-bnxt.c:Unneeded-variable:rc-Return-on-line
|   |-- drivers-net-ethernet-broadcom-bnxt-bnxt.c:WARNING:atomic_dec_and_test-variation-before-object-free-at-line-.
|   |-- drivers-net-ethernet-marvell-octeon_ep-octep_pfvf_mbox.c:WARNING-opportunity-for-min()
|   `-- drivers-net-ethernet-marvell-octeontx2-af-rvu_npc_fs.c:duplicated-argument-to-or
|-- csky-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- csky-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-buildonly-randconfig-004-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-buildonly-randconfig-006-20240104
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-001-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-002-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-003-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-051-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-062-20240104
|   `-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|-- i386-randconfig-141-20240104
|   `-- lib-kunit-device.c-kunit_device_register_with_driver()-warn:passing-zero-to-ERR_CAST
|-- loongarch-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- m68k-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- m68k-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- microblaze-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- microblaze-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- mips-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- nios2-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- nios2-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- openrisc-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- openrisc-randconfig-r062-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- parisc-allmodconfig
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-tty-serial-8250_parisc.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- parisc-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- powerpc-randconfig-001-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- powerpc-randconfig-002-20240104
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-fs-exportfs-exportfs.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- powerpc64-randconfig-001-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- powerpc64-randconfig-002-20240104
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- powerpc64-randconfig-003-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- riscv-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- riscv-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- riscv-randconfig-001-20240104
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- riscv-randconfig-002-20240104
|   `-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|-- riscv-randconfig-r121-20240104
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
|-- s390-allmodconfig
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-dasd_diag_mod.o
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-dasd_eckd_mod.o
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-dasd_fba_mod.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- s390-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- sh-allmodconfig
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   `-- standard-input:Error:pcrel-too-far
|-- sh-allnoconfig
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L1609-converted-into-longer-instruction-sequence
|-- sh-allyesconfig
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   `-- standard-input:Error:pcrel-too-far
|-- sh-buildonly-randconfig-r004-20220313
|   `-- standard-input:Warning:overflow-in-branch-to-.L4391-converted-into-longer-instruction-sequence
|-- sh-buildonly-randconfig-r005-20211027
|   `-- standard-input:Warning:overflow-in-branch-to-.L4982-converted-into-longer-instruction-sequence
|-- sh-buildonly-randconfig-r006-20220111
|   `-- standard-input:Warning:overflow-in-branch-to-.L4887-converted-into-longer-instruction-sequence
|-- sh-randconfig-001-20240104
|   `-- standard-input:Error:pcrel-too-far
|-- sh-randconfig-002-20240104
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   `-- standard-input:Error:pcrel-too-far
|-- sh-randconfig-002-20240105
|   `-- standard-input:Warning:overflow-in-branch-to-.L4853-converted-into-longer-instruction-sequence
|-- sh-rsk7203_defconfig
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L1642-converted-into-longer-instruction-sequence
|-- sparc-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- sparc-randconfig-001-20240104
|   `-- (.head.text):relocation-truncated-to-fit:R_SPARC_WDISP22-against-init.text
|-- sparc-randconfig-002-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- sparc64-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- sparc64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- sparc64-randconfig-r123-20240104
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   `-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|-- um-randconfig-002-20240104
|   `-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|-- x86_64-buildonly-randconfig-001-20240104
|   `-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|-- x86_64-buildonly-randconfig-002-20240104
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- x86_64-buildonly-randconfig-003-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-buildonly-randconfig-004-20240104
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- x86_64-randconfig-011-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-014-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-072-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-102-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-103-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-104-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-161-20231228
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm.c-amdgpu_dm_atomic_commit_tail()-error:we-previously-assumed-acrtc-could-be-null-(see-line-)
|-- x86_64-randconfig-161-20240104
|   |-- lib-kunit-device.c-kunit_device_register_with_driver()-warn:passing-zero-to-ERR_CAST
|   |-- mm-kasan-kasan_test.c-mempool_double_free_helper()-error:double-free-of-elem
|   `-- mm-kasan-kasan_test.c-mempool_uaf_helper()-warn:passing-freed-memory-elem
|-- x86_64-rhel-8.3-bpf
|   `-- tools-testing-selftests-net-tcp_ao-bench-lookups.c:undefined-reference-to-sqrt
|-- xtensa-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- xtensa-randconfig-001-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
`-- xtensa-randconfig-r111-20240104
    `-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
clang_recent_errors
|-- arm-defconfig
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm-randconfig-r113-20240104
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-int-usertype-size
|-- arm64-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l0_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l0_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l1_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l1_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-pvr_dev-description-in-pvr_mmu_backing_page
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-sgt-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-sgt_offset-description-in-pvr_mmu_op_context
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l0_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l0_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l1_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-l1_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-pvr_dev-description-in-pvr_mmu_backing_page
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-sgt-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-sgt_offset-description-in-pvr_mmu_op_context
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- hexagon-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- hexagon-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- hexagon-randconfig-r052-20231228
|   `-- drivers-media-i2c-st-mipid02.c:WARNING:do_div()-does-a-by-division-please-consider-using-div64_s64-instead.
|-- i386-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- i386-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- i386-randconfig-012-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- i386-randconfig-016-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- powerpc-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- powerpc-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- s390-randconfig-001-20240104
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-dasd_diag_mod.o
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-dasd_eckd_mod.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- x86_64-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- x86_64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- x86_64-randconfig-002-20240104
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- x86_64-randconfig-121-20240104
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
|-- x86_64-randconfig-122-20240104
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:sparse:sparse:Using-plain-integer-as-NULL-pointer
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
`-- x86_64-randconfig-123-20240104
    |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:sparse:sparse:Using-plain-integer-as-NULL-pointer
    `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size

elapsed time: 1461m

configs tested: 178
configs skipped: 2

tested configs:
alpha                             allnoconfig   gcc  
alpha                            allyesconfig   gcc  
alpha                               defconfig   gcc  
arc                              allmodconfig   gcc  
arc                               allnoconfig   gcc  
arc                              allyesconfig   gcc  
arc                          axs101_defconfig   gcc  
arc                                 defconfig   gcc  
arc                   randconfig-001-20240104   gcc  
arc                   randconfig-002-20240104   gcc  
arm                              allmodconfig   gcc  
arm                               allnoconfig   gcc  
arm                              allyesconfig   gcc  
arm                                 defconfig   clang
arm                        mvebu_v7_defconfig   gcc  
arm                   randconfig-001-20240104   gcc  
arm                   randconfig-002-20240104   gcc  
arm                   randconfig-003-20240104   gcc  
arm                   randconfig-004-20240104   gcc  
arm                           sama5_defconfig   gcc  
arm64                            allmodconfig   clang
arm64                             allnoconfig   gcc  
arm64                               defconfig   gcc  
arm64                 randconfig-001-20240104   gcc  
arm64                 randconfig-002-20240104   gcc  
arm64                 randconfig-003-20240104   gcc  
arm64                 randconfig-004-20240104   gcc  
csky                             alldefconfig   gcc  
csky                             allmodconfig   gcc  
csky                              allnoconfig   gcc  
csky                             allyesconfig   gcc  
csky                                defconfig   gcc  
csky                  randconfig-001-20240104   gcc  
csky                  randconfig-002-20240104   gcc  
hexagon                          allmodconfig   clang
hexagon                           allnoconfig   clang
hexagon                          allyesconfig   clang
hexagon                             defconfig   clang
hexagon               randconfig-001-20240104   clang
hexagon               randconfig-002-20240104   clang
i386                             allmodconfig   clang
i386                              allnoconfig   clang
i386                             allyesconfig   clang
i386         buildonly-randconfig-001-20240104   gcc  
i386         buildonly-randconfig-002-20240104   gcc  
i386         buildonly-randconfig-003-20240104   gcc  
i386         buildonly-randconfig-004-20240104   gcc  
i386         buildonly-randconfig-005-20240104   gcc  
i386         buildonly-randconfig-006-20240104   gcc  
i386                                defconfig   gcc  
i386                  randconfig-001-20240104   gcc  
i386                  randconfig-002-20240104   gcc  
i386                  randconfig-003-20240104   gcc  
i386                  randconfig-004-20240104   gcc  
i386                  randconfig-005-20240104   gcc  
i386                  randconfig-006-20240104   gcc  
i386                  randconfig-011-20240104   clang
i386                  randconfig-012-20240104   clang
i386                  randconfig-013-20240104   clang
i386                  randconfig-014-20240104   clang
i386                  randconfig-015-20240104   clang
i386                  randconfig-016-20240104   clang
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch             randconfig-001-20240104   gcc  
loongarch             randconfig-002-20240104   gcc  
m68k                             allmodconfig   gcc  
m68k                              allnoconfig   gcc  
m68k                             allyesconfig   gcc  
m68k                       bvme6000_defconfig   gcc  
m68k                                defconfig   gcc  
m68k                       m5275evb_defconfig   gcc  
m68k                           sun3_defconfig   gcc  
microblaze                       allmodconfig   gcc  
microblaze                        allnoconfig   gcc  
microblaze                       allyesconfig   gcc  
microblaze                          defconfig   gcc  
mips                              allnoconfig   clang
mips                             allyesconfig   gcc  
mips                           mtx1_defconfig   clang
mips                   sb1250_swarm_defconfig   gcc  
nios2                            allmodconfig   gcc  
nios2                             allnoconfig   gcc  
nios2                            allyesconfig   gcc  
nios2                               defconfig   gcc  
nios2                 randconfig-001-20240104   gcc  
nios2                 randconfig-002-20240104   gcc  
openrisc                          allnoconfig   gcc  
openrisc                         allyesconfig   gcc  
openrisc                            defconfig   gcc  
parisc                           allmodconfig   gcc  
parisc                            allnoconfig   gcc  
parisc                           allyesconfig   gcc  
parisc                              defconfig   gcc  
parisc                randconfig-001-20240104   gcc  
parisc                randconfig-002-20240104   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   clang
powerpc                           allnoconfig   gcc  
powerpc                          allyesconfig   clang
powerpc                    gamecube_defconfig   clang
powerpc                   microwatt_defconfig   clang
powerpc                      ppc64e_defconfig   clang
powerpc               randconfig-001-20240104   gcc  
powerpc               randconfig-002-20240104   gcc  
powerpc               randconfig-003-20240104   gcc  
powerpc64             randconfig-001-20240104   gcc  
powerpc64             randconfig-002-20240104   gcc  
powerpc64             randconfig-003-20240104   gcc  
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   clang
riscv                            allyesconfig   gcc  
riscv                               defconfig   gcc  
riscv                 randconfig-001-20240104   gcc  
riscv                 randconfig-002-20240104   gcc  
riscv                          rv32_defconfig   clang
s390                             allmodconfig   gcc  
s390                              allnoconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                  randconfig-001-20240104   clang
s390                  randconfig-002-20240104   clang
sh                               allmodconfig   gcc  
sh                                allnoconfig   gcc  
sh                               allyesconfig   gcc  
sh                         apsh4a3a_defconfig   gcc  
sh                                  defconfig   gcc  
sh                    randconfig-001-20240104   gcc  
sh                    randconfig-002-20240104   gcc  
sh                          rsk7203_defconfig   gcc  
sh                          sdk7780_defconfig   gcc  
sh                           se7750_defconfig   gcc  
sparc                            allmodconfig   gcc  
sparc64                          allmodconfig   gcc  
sparc64                          allyesconfig   gcc  
sparc64                             defconfig   gcc  
sparc64               randconfig-001-20240104   gcc  
sparc64               randconfig-002-20240104   gcc  
um                               allmodconfig   clang
um                                allnoconfig   clang
um                               allyesconfig   clang
um                                  defconfig   gcc  
um                             i386_defconfig   gcc  
um                    randconfig-001-20240104   gcc  
um                    randconfig-002-20240104   gcc  
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   clang
x86_64       buildonly-randconfig-001-20240104   gcc  
x86_64       buildonly-randconfig-002-20240104   gcc  
x86_64       buildonly-randconfig-003-20240104   gcc  
x86_64       buildonly-randconfig-004-20240104   gcc  
x86_64       buildonly-randconfig-005-20240104   gcc  
x86_64       buildonly-randconfig-006-20240104   gcc  
x86_64                              defconfig   gcc  
x86_64                randconfig-001-20240104   clang
x86_64                randconfig-002-20240104   clang
x86_64                randconfig-003-20240104   clang
x86_64                randconfig-004-20240104   clang
x86_64                randconfig-005-20240104   clang
x86_64                randconfig-006-20240104   clang
x86_64                randconfig-011-20240104   gcc  
x86_64                randconfig-012-20240104   gcc  
x86_64                randconfig-013-20240104   gcc  
x86_64                randconfig-014-20240104   gcc  
x86_64                randconfig-015-20240104   gcc  
x86_64                randconfig-016-20240104   gcc  
x86_64                randconfig-071-20240104   gcc  
x86_64                randconfig-072-20240104   gcc  
x86_64                randconfig-073-20240104   gcc  
x86_64                randconfig-074-20240104   gcc  
x86_64                randconfig-075-20240104   gcc  
x86_64                randconfig-076-20240104   gcc  
x86_64                          rhel-8.3-rust   clang
xtensa                            allnoconfig   gcc  
xtensa                randconfig-001-20240104   gcc  
xtensa                randconfig-002-20240104   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401051437.ylHQ71JT-lkp%40intel.com.
