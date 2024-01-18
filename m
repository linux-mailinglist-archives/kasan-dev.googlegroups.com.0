Return-Path: <kasan-dev+bncBC4LXIPCY4NRBXWYUKWQMGQECKRJZQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D5C283122F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 05:43:12 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1d707608a3asf1511135ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jan 2024 20:43:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705552991; cv=pass;
        d=google.com; s=arc-20160816;
        b=RWd2fCBu8uEY/XEhwVNRIL6WMpxFxnOB+mzTGzAtC9JO9I33Wpli/qxyXPzuSlJ4b1
         OuNQnj9iJ5xOGCZ46H3GTujfJ2jUsLmsZffyD3DPEZkjr+YPhxTzF1TGSy1hzHq/WCak
         9cpHeO/+zQGJMooXnAb1PKsG86BNt3gETYkn91p1hPLNDIBoi8ho3uZaQCIXiM2ES2Z0
         PqNqNFhzbMNp9bzWNKN3s3pkITSZXE8vfnWCIKaZ4jvZSNNtfwxDHjv0uP8jP6abSmr6
         r+xebN+U1osRBXpDNw1OVM/ZD8G6K3ZydrQQk5jRMRj0rU3Y3nloV4jBd+dbaqObiQ8i
         a15Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=F3VQt/qlf/zztltPpfJZi75ffxu0a1kGvKRLp1ePSGE=;
        fh=sCOTSLq1RrgeQwCevQrgzApMmEMLNUZ1BcdfdVVjhAk=;
        b=sX6sSGLAK8otsrg1gZCbnX7SZvWPc+zR4voCCGfdHxsJhAO8XL/B7B+FLALq0ZPV4e
         Cpmbuy6FRe3yHcxcGdZT70BJt6ErE06uT+0V96vNP2EKT/8PVKYqtcfOIQOvKsTd/m59
         RU1Buk8k4Q4x0w9vxP1HpHU4tJ2jvCpGcVlFF3d1W9Fk6KZbEmQu79b9x2hIiEJ8ltnN
         t3ysXQZ9YvqTBJqUmu/SMj+Alhpsq2/oCMnk8h5dcikypN+hpbDdvZ4EgtsaGPhB3+J4
         IW4NcIUejltRrgUUPGih2MCWX7mTHVaQfoMY7PDkSBkloKsi09PeIg+wPOOGoo2JhQ9S
         7HKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZKAC9iXk;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705552991; x=1706157791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F3VQt/qlf/zztltPpfJZi75ffxu0a1kGvKRLp1ePSGE=;
        b=mkh8g4GNQGAo6R1MfyTLxUN6ZEdvCcYGhikrGYhlJEo1tmKRkrvto4iYD7XiXOiOox
         H8ObOY450I3RBjEdnjm9lgpj0tGK5hbhfVhwrVmgM6tMGENKZW+V/op3+khhU+IkZKtg
         1pFULSHvpY+lfxHckhSjHpDbTNjlCjBH/5Hmst0cli04T9jiaRkXM8A21tsMz1gb1nZE
         D8tGEai3nB/13NtlBETH+yb1zBG2NllBA8ljmxvT7dqo8Fp5O2yep1++ZgAxYGvcuLGy
         cFHb84z8p7mAC6qKwKQopj5S9LH5fQc8To4WNvLIUugGS2igt1+N1wT39sOZz4MWVxrP
         Vdvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705552991; x=1706157791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F3VQt/qlf/zztltPpfJZi75ffxu0a1kGvKRLp1ePSGE=;
        b=ZrWXMcBCzjk6lwYSqp7cdlato5UllbvmeAjFy+CywhOuh9Qo33HQ0dsoconLtYPivN
         0mpi6VofyDv8yO6hhHd222vrBTnpmuQUG/Ta9ME42MC8l1uY4t1NMk5xo3rUakFaOKl8
         3u5qxBTZsAZqRk9x7qO17hWK4ef1VFtnL3Kj6TiUnmm45y/P6uG+fDChOrS35Z6mjzJm
         v1qZj0rF3A6KznTav8d5vfAuv21+sAqo+X+/hZMufVIwZkZ2Rc59yKm12mdAqzEGy0kt
         DIGoObc942qpz7Fo7cy8CHZAx+thg9JAbCo080nWI4veqf0ij6S6A6Y+XaXPgr+UuLEl
         ynjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yynp3aDUtczariqLBnr3CVM9h9rxfpLILsxp55YmzTegG2NEyga
	2nQfQa5AeBuS6ILPDS1Jkwz+gqT4C5yap9LsHgCYVM+pJLNCFoCw
X-Google-Smtp-Source: AGHT+IGuH59o/jgJS4RuFdot8DP59X4J2tiAVPlpZkApLx8QiI9E+9Vy6cDfduPib7hGNh8yI40t3A==
X-Received: by 2002:a17:903:1c5:b0:1d5:efcb:3cd1 with SMTP id e5-20020a17090301c500b001d5efcb3cd1mr428233plh.81.1705552990785;
        Wed, 17 Jan 2024 20:43:10 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e887:b0:1d6:ee8a:1b07 with SMTP id
 w7-20020a170902e88700b001d6ee8a1b07ls1062548plg.2.-pod-prod-08-us; Wed, 17
 Jan 2024 20:43:09 -0800 (PST)
X-Received: by 2002:a17:902:c711:b0:1d0:6ffe:a22 with SMTP id p17-20020a170902c71100b001d06ffe0a22mr292371plp.128.1705552989655;
        Wed, 17 Jan 2024 20:43:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705552989; cv=none;
        d=google.com; s=arc-20160816;
        b=nKJFlBslko9dTTHFa2qG+c/H32WqMxO74BCvSgRisEG7L4OX0eYFEAZH2aXvZVCrR6
         eRoGM74vMvuvXsFFLrx+FKcXxFp0RDF1FzvqR2YiURUOrIbHYRIqW13ZwrdBv/XvkU9e
         o5OtxnCsqJLbocc4ThXX7p5ecHxzoSqsI+mKB+0LcaQDa6GjtGPdi5rYtTochzyyuvPx
         xgzvYO9P5HvcBKMIzEM/fEbgb2ml2LTtsXMgIJxxhPcZ3ckzzAcHbsit+/cNtaLpETFJ
         suJrNSwaWiHlldgAt+1/R1WMvquEXrx7Su74ex/Uq8AXQ1DOx8AplQ0PtIOSkdkYyPpS
         O/uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=HaF6Onvz68AAsYkDELkMenmO8l4QfDqiQ/sFnylhWnI=;
        fh=sCOTSLq1RrgeQwCevQrgzApMmEMLNUZ1BcdfdVVjhAk=;
        b=Igi5o8UEOvOMCjV39RxdwybZ3QS9OZ44gjwJT4BCPoOQDe5vTUiSpYkrBpPiw6fWwd
         GrZ7CAjQA4Sz4GnKDrek16YuNQ0iMDhPpjcDQNL3Ipr+xLaBFjx19PKapg5j9GqPSGnr
         FOzAHoom6uoX6D5vuuDdIVmbpn7SsDTdpf5XxtcePWLPYCrHmXijBX3YT8djZTtfeAb9
         RTPVOuHgnsjpnxFswAlYFsmzb7KnASSFFTbh9MXBqt5pN9/nTLK4HNegJecz0Y303+J8
         iuXcq0MxNlETuf3aj45Vh4EHpDO7/OFNcB/w6p5a6wl1adudYASZx67YgoNi9nIKN0VR
         WQGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZKAC9iXk;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id g23-20020a1709029f9700b001d5f37d32dfsi56912plq.5.2024.01.17.20.43.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jan 2024 20:43:09 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-IronPort-AV: E=McAfee;i="6600,9927,10956"; a="13700991"
X-IronPort-AV: E=Sophos;i="6.05,201,1701158400"; 
   d="scan'208";a="13700991"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Jan 2024 20:43:07 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.05,201,1701158400"; 
   d="scan'208";a="26667192"
Received: from lkp-server01.sh.intel.com (HELO 961aaaa5b03c) ([10.239.97.150])
  by fmviesa001.fm.intel.com with ESMTP; 17 Jan 2024 20:43:04 -0800
Received: from kbuild by 961aaaa5b03c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rQKF4-0002eq-00;
	Thu, 18 Jan 2024 04:43:02 +0000
Date: Thu, 18 Jan 2024 12:42:38 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 amd-gfx@lists.freedesktop.org, dmaengine@vger.kernel.org,
 dri-devel@lists.freedesktop.org, freedreno@lists.freedesktop.org,
 kasan-dev@googlegroups.com, linux-arm-msm@vger.kernel.org,
 linux-bcachefs@vger.kernel.org, linux-usb@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 943b9f0ab2cfbaea148dd6ac279957eb08b96904
Message-ID: <202401181234.71rFxd9x-lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZKAC9iXk;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.10 as permitted
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
branch HEAD: 943b9f0ab2cfbaea148dd6ac279957eb08b96904  Add linux-next specific files for 20240117

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202401172119.Fc2Ic3l9-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202401172139.XSfsNhrJ-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

drivers/gpu/drm/amd/amdgpu/../display/amdgpu_dm/amdgpu_dm_crtc.c:100: warning: This comment starts with '/**', but isn't a kernel-doc comment. Refer Documentation/doc-guide/kernel-doc.rst
fs/bcachefs/btree_write_buffer.c:128:24: warning: unused variable 'c' [-Wunused-variable]

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
|-- arm-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm-randconfig-004-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- arm64-defconfig
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm64-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- arm64-randconfig-003-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- arm64-randconfig-r111-20240117
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
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
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- csky-randconfig-r123-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|-- i386-buildonly-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-buildonly-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-buildonly-randconfig-003-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-buildonly-randconfig-005-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-003-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-141-20240117
|   |-- drivers-gpu-drm-drm_gpuvm.c-drm_gpuvm_exec_lock_range()-error:uninitialized-symbol-ret-.
|   `-- mm-huge_memory.c-thpsize_create()-warn:Calling-kobject_put-get-with-state-initialized-unset-from-line:
|-- loongarch-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- loongarch-defconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- loongarch-randconfig-001-20240117
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- loongarch-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- loongarch-randconfig-r051-20240117
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
|-- m68k-randconfig-r113-20240117
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
|   |-- (.ref.text):relocation-truncated-to-fit:R_MIPS_26-against-start_secondary
|   |-- (.text):relocation-truncated-to-fit:R_MIPS_26-against-kernel_entry
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
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
|-- nios2-randconfig-002-20240117
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
|-- parisc-allmodconfig
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
|-- powerpc-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- powerpc-randconfig-003-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- powerpc-randconfig-r061-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- powerpc64-randconfig-001-20240117
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
|-- riscv-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- riscv-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- s390-allmodconfig
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
|   `-- standard-input:Error:pcrel-too-far
|-- sh-allyesconfig
|   `-- standard-input:Error:pcrel-too-far
|-- sh-randconfig-001-20240117
|   `-- standard-input:Error:pcrel-too-far
|-- sparc-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
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
|-- sparc64-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- sparc64-randconfig-r064-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-buildonly-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-buildonly-randconfig-003-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- fs-bcachefs-btree_write_buffer.c:warning:unused-variable-c
|-- x86_64-buildonly-randconfig-005-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- x86_64-randconfig-012-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
`-- x86_64-randconfig-016-20240117
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
    `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
clang_recent_errors
|-- arm-defconfig
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- arm64-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arm64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
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
|-- hexagon-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- hexagon-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
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
|-- i386-randconfig-012-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- i386-randconfig-014-20240117
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
|-- powerpc-randconfig-r132-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- s390-randconfig-001-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- s390-randconfig-002-20240117
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
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- x86_64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- x86_64-randconfig-002-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- x86_64-randconfig-004-20240117
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- x86_64-randconfig-121-20240117
|   |-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
|-- x86_64-randconfig-122-20240117
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
`-- x86_64-randconfig-123-20240117
    `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size

elapsed time: 1469m

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
arc                   randconfig-001-20240117   gcc  
arc                   randconfig-002-20240117   gcc  
arm                              allmodconfig   gcc  
arm                               allnoconfig   gcc  
arm                              allyesconfig   gcc  
arm                     am200epdkit_defconfig   clang
arm                                 defconfig   clang
arm                          gemini_defconfig   gcc  
arm                           h3600_defconfig   gcc  
arm                      integrator_defconfig   gcc  
arm                   randconfig-001-20240117   gcc  
arm                   randconfig-002-20240117   gcc  
arm                   randconfig-003-20240117   gcc  
arm                   randconfig-004-20240117   gcc  
arm                           sama7_defconfig   clang
arm                           spitz_defconfig   clang
arm                           tegra_defconfig   gcc  
arm64                            allmodconfig   clang
arm64                             allnoconfig   gcc  
arm64                               defconfig   gcc  
arm64                 randconfig-001-20240117   gcc  
arm64                 randconfig-002-20240117   gcc  
arm64                 randconfig-003-20240117   gcc  
arm64                 randconfig-004-20240117   gcc  
csky                             allmodconfig   gcc  
csky                              allnoconfig   gcc  
csky                             allyesconfig   gcc  
csky                                defconfig   gcc  
csky                  randconfig-001-20240117   gcc  
csky                  randconfig-002-20240117   gcc  
hexagon                          allmodconfig   clang
hexagon                           allnoconfig   clang
hexagon                          allyesconfig   clang
hexagon                             defconfig   clang
hexagon               randconfig-001-20240117   clang
hexagon               randconfig-002-20240117   clang
i386                             allmodconfig   clang
i386                              allnoconfig   clang
i386                             allyesconfig   clang
i386         buildonly-randconfig-001-20240117   gcc  
i386         buildonly-randconfig-002-20240117   gcc  
i386         buildonly-randconfig-003-20240117   gcc  
i386         buildonly-randconfig-004-20240117   gcc  
i386         buildonly-randconfig-005-20240117   gcc  
i386         buildonly-randconfig-006-20240117   gcc  
i386                                defconfig   gcc  
i386                  randconfig-001-20240117   gcc  
i386                  randconfig-002-20240117   gcc  
i386                  randconfig-003-20240117   gcc  
i386                  randconfig-004-20240117   gcc  
i386                  randconfig-005-20240117   gcc  
i386                  randconfig-006-20240117   gcc  
i386                  randconfig-011-20240117   clang
i386                  randconfig-012-20240117   clang
i386                  randconfig-013-20240117   clang
i386                  randconfig-014-20240117   clang
i386                  randconfig-015-20240117   clang
i386                  randconfig-016-20240117   clang
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch                 loongson3_defconfig   gcc  
loongarch             randconfig-001-20240117   gcc  
loongarch             randconfig-002-20240117   gcc  
m68k                             allmodconfig   gcc  
m68k                              allnoconfig   gcc  
m68k                             allyesconfig   gcc  
m68k                                defconfig   gcc  
m68k                        stmark2_defconfig   gcc  
m68k                           virt_defconfig   gcc  
microblaze                       allmodconfig   gcc  
microblaze                        allnoconfig   gcc  
microblaze                       allyesconfig   gcc  
microblaze                          defconfig   gcc  
mips                              allnoconfig   clang
mips                             allyesconfig   gcc  
nios2                            allmodconfig   gcc  
nios2                             allnoconfig   gcc  
nios2                            allyesconfig   gcc  
nios2                               defconfig   gcc  
nios2                 randconfig-001-20240117   gcc  
nios2                 randconfig-002-20240117   gcc  
openrisc                          allnoconfig   gcc  
openrisc                         allyesconfig   gcc  
openrisc                            defconfig   gcc  
parisc                           allmodconfig   gcc  
parisc                            allnoconfig   gcc  
parisc                           allyesconfig   gcc  
parisc                              defconfig   gcc  
parisc                randconfig-001-20240117   gcc  
parisc                randconfig-002-20240117   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   clang
powerpc                           allnoconfig   gcc  
powerpc                          allyesconfig   clang
powerpc                      makalu_defconfig   gcc  
powerpc                     mpc512x_defconfig   clang
powerpc               randconfig-001-20240117   gcc  
powerpc               randconfig-002-20240117   gcc  
powerpc               randconfig-003-20240117   gcc  
powerpc                     redwood_defconfig   gcc  
powerpc64             randconfig-001-20240117   gcc  
powerpc64             randconfig-002-20240117   gcc  
powerpc64             randconfig-003-20240117   gcc  
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   clang
riscv                            allyesconfig   gcc  
riscv                               defconfig   gcc  
riscv                    nommu_k210_defconfig   gcc  
riscv                 randconfig-001-20240117   gcc  
riscv                 randconfig-002-20240117   gcc  
s390                             alldefconfig   clang
s390                             allmodconfig   gcc  
s390                              allnoconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                  randconfig-001-20240117   clang
s390                  randconfig-002-20240117   clang
sh                               allmodconfig   gcc  
sh                                allnoconfig   gcc  
sh                               allyesconfig   gcc  
sh                                  defconfig   gcc  
sh                    randconfig-001-20240117   gcc  
sh                    randconfig-002-20240117   gcc  
sh                   secureedge5410_defconfig   gcc  
sparc                            allmodconfig   gcc  
sparc64                          allmodconfig   gcc  
sparc64                          allyesconfig   gcc  
sparc64                             defconfig   gcc  
sparc64               randconfig-001-20240117   gcc  
sparc64               randconfig-002-20240117   gcc  
um                               allmodconfig   clang
um                                allnoconfig   clang
um                               allyesconfig   clang
um                                  defconfig   gcc  
um                             i386_defconfig   gcc  
um                    randconfig-001-20240117   gcc  
um                    randconfig-002-20240117   gcc  
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   clang
x86_64       buildonly-randconfig-001-20240117   gcc  
x86_64       buildonly-randconfig-002-20240117   gcc  
x86_64       buildonly-randconfig-003-20240117   gcc  
x86_64       buildonly-randconfig-004-20240117   gcc  
x86_64       buildonly-randconfig-005-20240117   gcc  
x86_64       buildonly-randconfig-006-20240117   gcc  
x86_64                              defconfig   gcc  
x86_64                randconfig-001-20240117   clang
x86_64                randconfig-002-20240117   clang
x86_64                randconfig-003-20240117   clang
x86_64                randconfig-004-20240117   clang
x86_64                randconfig-005-20240117   clang
x86_64                randconfig-006-20240117   clang
x86_64                randconfig-011-20240117   gcc  
x86_64                randconfig-012-20240117   gcc  
x86_64                randconfig-013-20240117   gcc  
x86_64                randconfig-014-20240117   gcc  
x86_64                randconfig-015-20240117   gcc  
x86_64                randconfig-016-20240117   gcc  
x86_64                randconfig-071-20240117   gcc  
x86_64                randconfig-072-20240117   gcc  
x86_64                randconfig-073-20240117   gcc  
x86_64                randconfig-074-20240117   gcc  
x86_64                randconfig-075-20240117   gcc  
x86_64                randconfig-076-20240117   gcc  
x86_64                          rhel-8.3-rust   clang
xtensa                            allnoconfig   gcc  
xtensa                randconfig-001-20240117   gcc  
xtensa                randconfig-002-20240117   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401181234.71rFxd9x-lkp%40intel.com.
