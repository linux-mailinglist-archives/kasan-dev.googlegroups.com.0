Return-Path: <kasan-dev+bncBC4LXIPCY4NRBYMN4SWAMGQEGHLGBDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 0055F825EC6
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Jan 2024 08:53:06 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4297363e66bsf6407321cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jan 2024 23:53:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704527586; cv=pass;
        d=google.com; s=arc-20160816;
        b=otnLUDhZiCKR22QBjej4VEZrgpDvvU0309nLDSKuC8ptjf0eHa7FyFqNX2HgUENQfH
         bmW1CD15LqeXosS69d7qFhD0imqbZJeelS3S7n1BQM58CibpZ0d4Kz8M46KG8GQP6vVV
         SITD9qA7km5xwc02LaeakplYNncYCovOOyPPd1g5kEFPbzBSOX4oznGVCD0EUQVjCPJB
         a4ZkjfgaATa0NCIIKHIMD7ED+wO6GB+zo6OrTaJAi7el/R+sdD+wSxSwMmm7HBhoWoqo
         uR+VYS3MiS8hJJTHKFafSEzX8ylMRqqCwTxIov/Pr/nUXm2QnNEnJOr9mk3IakgHRJRc
         Dwzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=u0hNcuVZJuVeELeWuLF74vUboGVFFXPgaENQdMAKD7M=;
        fh=yvH+hc2oHUVDj5qK4Ov6lYftzKcgGFjXBRpAehqYlZY=;
        b=lIUG5xBcApc7P15JNgYhI6z0cCNeafWaIklo/zDaymi8OwzBJuih0K5nRxAQRratXX
         Pij8QkAnLJum080YewgMPcXhSRcOCHYHREB6oI1kGjVS3Uu3cctaREMHkodua7YRYckK
         GLvtV1C/62j05Rw6ce1Lu08d4aveSLHOZTsWaOrG4DmYxuRc0erlAxnniPWMB1CppjsI
         YznmoVrM2OD4m+mdMV6N/44rShTmHA2G08ULk+VnKIDJGJacjYRW9omUEM7RW7mFDI3v
         PKMdXPz2Ox/8adU7RqBfpQduafpCwEapPbuekLWqaZZYPLZP7iexCnPyWQT4j7BbUGnY
         qvvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Snu2kt4r;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704527586; x=1705132386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u0hNcuVZJuVeELeWuLF74vUboGVFFXPgaENQdMAKD7M=;
        b=F2/GD7h/8tz3P74NNUEU7pXmirhG9Qo9fljEvzl3owmzJt0CJgSlNA9+h0ll3DuN93
         PGAWwSAubY2TPVLZFqIje1fF4lgKc0M3hz6p0xYi1DtsZaqxueyjiZMFleB2xyPNdsfp
         v5iQ5jD+ZYBvjWWyo9NweOSSf0uOcJRFbZYwEZR4wHUWZj0nQQowzNu7mcT3ycQFh59P
         PsheNb5XwU4K7x3Sx75wTAubpGzyNWUqSgmFNRlyPSQALIFl3CpYXN5padV/Pa749N+j
         xJ/0n4SEcOUPQYMB0uiQxLKc1znkKyIqeG3JpOHgYPF4qxU4lHNH0F/YUdVKame27yGE
         sPxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704527586; x=1705132386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u0hNcuVZJuVeELeWuLF74vUboGVFFXPgaENQdMAKD7M=;
        b=CWBryxRRlQ25rZCLwXXnkO+b796oEMO0OlsBV/89iuNS3cYo6ORlVUBd4UdSgiDm1o
         ILVYH6KWQ8ys7M42mRfyenYwJLHpTd0wvdSuZMq4SMENAz/eEiO2le8SAvnhJlxz8byY
         RlZ7c9cVrKEzvQdaX6zu0iZIt6CHmIm9SihePZHJEUjViqcGRzNA+S8cZnKlzBNmiEKW
         dq2fjhTB8wM4HNSu+Savqh699cTrgcuPg8MV4819nL0IU/hm6AoxhMh2ZmqM+OTocdAo
         EGXjyt64OR0cwy/TOCqTMkheUZwrswSwvl2pjnuHmLhzU+T0wXH9tmrZ/IW8z+pogzpO
         Wamg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQx0DC1Q/nIjZRU0rHdrNPUFIrkO/UGwJw0283fnDTlCgRoAJz
	iU0nOFbt76p7pS2HnIRDRiAV/Q==
X-Google-Smtp-Source: AGHT+IF7D8v4Md8XQzq95oIGrz0TFksl1ddr/Jk9W1jDCALK+S23B9zoPIH221JM/OiJ1tOl0Vghig==
X-Received: by 2002:ac8:5fc4:0:b0:429:758e:f4ce with SMTP id k4-20020ac85fc4000000b00429758ef4cemr1030305qta.65.1704527585640;
        Fri, 05 Jan 2024 23:53:05 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:480c:0:b0:427:9ac7:4744 with SMTP id g12-20020ac8480c000000b004279ac74744ls37498qtq.0.-pod-prod-09-us;
 Fri, 05 Jan 2024 23:53:05 -0800 (PST)
X-Received: by 2002:a05:6102:c8c:b0:467:b351:4d21 with SMTP id f12-20020a0561020c8c00b00467b3514d21mr374386vst.6.1704527584876;
        Fri, 05 Jan 2024 23:53:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704527584; cv=none;
        d=google.com; s=arc-20160816;
        b=G+koQ1w9c/z4Dh+UGXkV8bCn9dKQ9LAfsj8Zfy10cmEbdl3QmkvA8OFmtPrnGiWHbj
         lckYwj6HXQJcYIvMcvC4glG39jGfQmJETUKzAtaqjqK7hLKTSFZWs5pa4l95QKgi/Ly6
         2UGuYpj/WVNfOXbhWLwseqtTTHda5FVJ/yUkTqmo9qp12fdLF3q1LtdHaAncOl+hQp9J
         2zK34SsbAuQOuKiSEeEWj5sou4xCCg2YDzljcgRGE5xEQO9X6snVownuZUvDqSUu/1KZ
         WcKVhBwdj9k4TXZldN7AUMeHzqiGUsAGU3Ytb0yd7Mfe5dQPLvVgZH6u7/doDZEbbinF
         wZ8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZHkShIOj0JkF5M9tGvVXMP4egHeqyHqbyXOfsnlYR9A=;
        fh=yvH+hc2oHUVDj5qK4Ov6lYftzKcgGFjXBRpAehqYlZY=;
        b=gZT5cP920c8VeXY6N3gKv0RM3rUsr0SbN/JxGcHiDfolLqjUEhMGFPBhEeywwD7teq
         tu8c76nTvUNQh9iCidQjP/dtop71FgE1jhPiJpBnSzFWmj1pf+f9IloUGWwbLLmqPEUK
         LshdUDsi4pIUuV03hK/8eaa8wGZdvJIozqOG5Or6zUfULtKQ+hA7XE2eywFNSre/jd5G
         WvErcPirpjRBuVsgDA3y27/Anw8QoJyIelW+FeUq6Dquj5Ueub0LCpM+ihxMj+A3Acji
         EhVQQWpMxLobYT9H1SPPfttxJnlg0mnb/pyquzGOLhsO759ojtE9EuRFTRgD1TlFq1CR
         G0CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Snu2kt4r;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id h2-20020a0561023d8200b00467c4b0b419si33221vsv.0.2024.01.05.23.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Jan 2024 23:53:04 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10944"; a="382611078"
X-IronPort-AV: E=Sophos;i="6.04,336,1695711600"; 
   d="scan'208";a="382611078"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Jan 2024 23:52:53 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10944"; a="1027960224"
X-IronPort-AV: E=Sophos;i="6.04,336,1695711600"; 
   d="scan'208";a="1027960224"
Received: from lkp-server02.sh.intel.com (HELO b07ab15da5fe) ([10.239.97.151])
  by fmsmga006.fm.intel.com with ESMTP; 05 Jan 2024 23:52:50 -0800
Received: from kbuild by b07ab15da5fe with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rM1U8-0002CH-1g;
	Sat, 06 Jan 2024 07:52:48 +0000
Date: Sat, 06 Jan 2024 15:52:19 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 dmaengine@vger.kernel.org, dri-devel@lists.freedesktop.org,
 freedreno@lists.freedesktop.org, kasan-dev@googlegroups.com,
 linux-arm-msm@vger.kernel.org, linux-bcachefs@vger.kernel.org,
 linux-hwmon@vger.kernel.org, netdev@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 e2425464bc87159274879ab30f9d4fe624b9fcd2
Message-ID: <202401061514.ukKN3xCH-lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Snu2kt4r;       spf=pass
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

tree/branch: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git master
branch HEAD: e2425464bc87159274879ab30f9d4fe624b9fcd2  Add linux-next specific files for 20240105

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202401061458.1ymPozGI-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

Warning: /sys/devices/.../hwmon/hwmon<i>/curr1_crit is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:35  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:52
Warning: /sys/devices/.../hwmon/hwmon<i>/energy1_input is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:54  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:65
Warning: /sys/devices/.../hwmon/hwmon<i>/in0_input is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:46  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:0
Warning: /sys/devices/.../hwmon/hwmon<i>/power1_crit is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:22  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:39
Warning: /sys/devices/.../hwmon/hwmon<i>/power1_max is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:0  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:8
Warning: /sys/devices/.../hwmon/hwmon<i>/power1_max_interval is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:62  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:30
Warning: /sys/devices/.../hwmon/hwmon<i>/power1_rated_max is defined 2 times:  Documentation/ABI/testing/sysfs-driver-intel-xe-hwmon:14  Documentation/ABI/testing/sysfs-driver-intel-i915-hwmon:22

Unverified Error/Warning (likely false positive, please contact us if interested):

drivers/net/ethernet/marvell/octeontx2/af/rvu_nix.c:6147:9-13: ERROR: invalid reference to the index variable of the iterator on line 6138
drivers/net/ethernet/marvell/octeontx2/af/rvu_nix.c:6357:1-7: preceding lock on line 6318
drivers/net/ethernet/marvell/octeontx2/af/rvu_npc_fs.c:575:9-32: duplicated argument to & or |
{standard input}:20841: Warning: overflow in branch to .L4773; converted into longer instruction sequence
{standard input}:52226: Warning: overflow in branch to .L4679; converted into longer instruction sequence
{standard input}:54153: Warning: overflow in branch to .L4936; converted into longer instruction sequence
{standard input}:5891: Warning: overflow in branch to .L1414; converted into longer instruction sequence

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- arm-randconfig-r062-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- arm64-randconfig-r053-20240104
|   |-- drivers-net-ethernet-marvell-octeontx2-af-rvu_nix.c:ERROR:invalid-reference-to-the-index-variable-of-the-iterator-on-line
|   |-- drivers-net-ethernet-marvell-octeontx2-af-rvu_nix.c:preceding-lock-on-line
|   `-- drivers-net-ethernet-marvell-octeontx2-af-rvu_npc_fs.c:duplicated-argument-to-or
|-- i386-randconfig-012-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- i386-randconfig-016-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- m68k-randconfig-r113-20240105
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-base-regmap-regmap-mmio.o
|   `-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|-- m68k-randconfig-r131-20240105
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   `-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|-- microblaze-randconfig-r121-20240105
|   `-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|-- microblaze-randconfig-r123-20240105
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
|-- nios2-randconfig-001-20240105
|   `-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-fs-exportfs-exportfs.o
|-- nios2-randconfig-r133-20240105
|   `-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|-- openrisc-randconfig-r053-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- openrisc-randconfig-r121-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|-- parisc-randconfig-002-20240105
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
|-- s390-randconfig-001-20240105
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-fs-exportfs-exportfs.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- s390-randconfig-r132-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
|-- sh-allmodconfig
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   `-- standard-input:Error:pcrel-too-far
|-- sh-allnoconfig
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L1609-converted-into-longer-instruction-sequence
|-- sh-randconfig-001-20240105
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   `-- standard-input:Error:pcrel-too-far
|-- sh-randconfig-002-20240105
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L4853-converted-into-longer-instruction-sequence
|-- sh-randconfig-r022-20221121
|   `-- standard-input:Warning:overflow-in-branch-to-.L4679-converted-into-longer-instruction-sequence
|-- sh-randconfig-r031-20220728
|   `-- standard-input:Warning:overflow-in-branch-to-.L4936-converted-into-longer-instruction-sequence
|-- sh-randconfig-r051-20240105
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   `-- standard-input:Error:pcrel-too-far
|-- sh-randconfig-r064-20240105
|   `-- standard-input:Error:pcrel-too-far
|-- sh-randconfig-r111-20240105
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L1414-converted-into-longer-instruction-sequence
|-- sh-randconfig-r112-20240105
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-comparison-expression-(different-address-spaces):
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_1-at-emit-rtl.cc
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L4773-converted-into-longer-instruction-sequence
|-- sparc-randconfig-001-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- sparc-randconfig-r132-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|-- sparc64-randconfig-001-20240105
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|   `-- fbcon.c:(.text):undefined-reference-to-fb_is_primary_device
|-- sparc64-randconfig-002-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
`-- x86_64-allnoconfig
    |-- Warning:sys-devices-...-hwmon-hwmon-i-curr1_crit-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
    |-- Warning:sys-devices-...-hwmon-hwmon-i-energy1_input-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
    |-- Warning:sys-devices-...-hwmon-hwmon-i-in0_input-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
    |-- Warning:sys-devices-...-hwmon-hwmon-i-power1_crit-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
    |-- Warning:sys-devices-...-hwmon-hwmon-i-power1_max-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
    |-- Warning:sys-devices-...-hwmon-hwmon-i-power1_max_interval-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
    `-- Warning:sys-devices-...-hwmon-hwmon-i-power1_rated_max-is-defined-times:Documentation-ABI-testing-sysfs-driver-intel-xe-hwmon-Documentation-ABI-testing-sysfs-driver-intel-i915-hwmon
clang_recent_errors
|-- arm-defconfig
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
|-- hexagon-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- i386-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- i386-randconfig-004-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- mips-maltaup_defconfig
|   `-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
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
|-- powerpc-randconfig-003-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-member-debugfs_root-description-in-dpu_encoder_virt
|-- powerpc64-randconfig-002-20240105
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zlib_inflate.o
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- powerpc64-randconfig-003-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
|-- riscv-randconfig-r113-20240105
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-usertype-size
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
|-- x86_64-buildonly-randconfig-001-20240105
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
|   `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here
`-- x86_64-randconfig-076-20240105
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-dst_addr-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-filled_descs_num-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-size-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-src_addr-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-member-sw_desc-not-described-in-xdma_fill_descs
    |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-than-will-be-evaluated-first
    `-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-when-used-here

elapsed time: 1449m

configs tested: 179
configs skipped: 2

tested configs:
alpha                             allnoconfig   gcc  
alpha                            allyesconfig   gcc  
alpha                               defconfig   gcc  
arc                              allmodconfig   gcc  
arc                               allnoconfig   gcc  
arc                              allyesconfig   gcc  
arc                      axs103_smp_defconfig   gcc  
arc                                 defconfig   gcc  
arc                   randconfig-001-20240105   gcc  
arc                   randconfig-002-20240105   gcc  
arm                              allmodconfig   gcc  
arm                               allnoconfig   gcc  
arm                              allyesconfig   gcc  
arm                                 defconfig   clang
arm                      integrator_defconfig   gcc  
arm                   randconfig-001-20240105   clang
arm                   randconfig-002-20240105   clang
arm                   randconfig-003-20240105   clang
arm                   randconfig-004-20240105   clang
arm                           sama5_defconfig   gcc  
arm                        shmobile_defconfig   gcc  
arm64                            allmodconfig   clang
arm64                             allnoconfig   gcc  
arm64                               defconfig   gcc  
arm64                 randconfig-001-20240105   clang
arm64                 randconfig-002-20240105   clang
arm64                 randconfig-003-20240105   clang
arm64                 randconfig-004-20240105   clang
csky                             allmodconfig   gcc  
csky                              allnoconfig   gcc  
csky                             allyesconfig   gcc  
csky                                defconfig   gcc  
csky                  randconfig-001-20240105   gcc  
csky                  randconfig-002-20240105   gcc  
hexagon                          allmodconfig   clang
hexagon                           allnoconfig   clang
hexagon                          allyesconfig   clang
hexagon                             defconfig   clang
hexagon               randconfig-001-20240105   clang
hexagon               randconfig-002-20240105   clang
i386                             allmodconfig   clang
i386                              allnoconfig   clang
i386                             allyesconfig   clang
i386         buildonly-randconfig-001-20240105   clang
i386         buildonly-randconfig-002-20240105   clang
i386         buildonly-randconfig-003-20240105   clang
i386         buildonly-randconfig-004-20240105   clang
i386         buildonly-randconfig-005-20240105   clang
i386         buildonly-randconfig-006-20240105   clang
i386                                defconfig   gcc  
i386                  randconfig-001-20240105   clang
i386                  randconfig-002-20240105   clang
i386                  randconfig-003-20240105   clang
i386                  randconfig-004-20240105   clang
i386                  randconfig-005-20240105   clang
i386                  randconfig-006-20240105   clang
i386                  randconfig-011-20240105   gcc  
i386                  randconfig-012-20240105   gcc  
i386                  randconfig-013-20240105   gcc  
i386                  randconfig-014-20240105   gcc  
i386                  randconfig-015-20240105   gcc  
i386                  randconfig-016-20240105   gcc  
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch             randconfig-001-20240105   gcc  
loongarch             randconfig-002-20240105   gcc  
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
mips                        maltaup_defconfig   clang
nios2                            allmodconfig   gcc  
nios2                             allnoconfig   gcc  
nios2                            allyesconfig   gcc  
nios2                               defconfig   gcc  
nios2                 randconfig-001-20240105   gcc  
nios2                 randconfig-002-20240105   gcc  
openrisc                          allnoconfig   gcc  
openrisc                         allyesconfig   gcc  
openrisc                            defconfig   gcc  
parisc                           allmodconfig   gcc  
parisc                            allnoconfig   gcc  
parisc                           allyesconfig   gcc  
parisc                              defconfig   gcc  
parisc                randconfig-001-20240105   gcc  
parisc                randconfig-002-20240105   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   clang
powerpc                           allnoconfig   gcc  
powerpc                          allyesconfig   clang
powerpc                       maple_defconfig   gcc  
powerpc                 mpc832x_rdb_defconfig   clang
powerpc                 mpc836x_rdk_defconfig   clang
powerpc                  mpc866_ads_defconfig   clang
powerpc                  mpc885_ads_defconfig   clang
powerpc               randconfig-001-20240105   clang
powerpc               randconfig-002-20240105   clang
powerpc               randconfig-003-20240105   clang
powerpc64                        alldefconfig   gcc  
powerpc64             randconfig-001-20240105   clang
powerpc64             randconfig-002-20240105   clang
powerpc64             randconfig-003-20240105   clang
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   clang
riscv                            allyesconfig   gcc  
riscv                               defconfig   gcc  
riscv                 randconfig-001-20240105   clang
riscv                 randconfig-002-20240105   clang
riscv                          rv32_defconfig   clang
s390                             allmodconfig   gcc  
s390                              allnoconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                  randconfig-001-20240105   gcc  
s390                  randconfig-002-20240105   gcc  
sh                               allmodconfig   gcc  
sh                                allnoconfig   gcc  
sh                               allyesconfig   gcc  
sh                         apsh4a3a_defconfig   gcc  
sh                                  defconfig   gcc  
sh                    randconfig-001-20240105   gcc  
sh                    randconfig-002-20240105   gcc  
sh                           se7750_defconfig   gcc  
sh                   sh7770_generic_defconfig   gcc  
sh                            titan_defconfig   gcc  
sparc                            allmodconfig   gcc  
sparc                       sparc32_defconfig   gcc  
sparc64                          allmodconfig   gcc  
sparc64                          allyesconfig   gcc  
sparc64                             defconfig   gcc  
sparc64               randconfig-001-20240105   gcc  
sparc64               randconfig-002-20240105   gcc  
um                               allmodconfig   clang
um                                allnoconfig   clang
um                               allyesconfig   clang
um                                  defconfig   gcc  
um                             i386_defconfig   gcc  
um                    randconfig-001-20240105   clang
um                    randconfig-002-20240105   clang
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   clang
x86_64       buildonly-randconfig-001-20240105   clang
x86_64       buildonly-randconfig-002-20240105   clang
x86_64       buildonly-randconfig-003-20240105   clang
x86_64       buildonly-randconfig-004-20240105   clang
x86_64       buildonly-randconfig-005-20240105   clang
x86_64       buildonly-randconfig-006-20240105   clang
x86_64                              defconfig   gcc  
x86_64                randconfig-001-20240105   gcc  
x86_64                randconfig-002-20240105   gcc  
x86_64                randconfig-003-20240105   gcc  
x86_64                randconfig-004-20240105   gcc  
x86_64                randconfig-005-20240105   gcc  
x86_64                randconfig-006-20240105   gcc  
x86_64                randconfig-011-20240105   clang
x86_64                randconfig-012-20240105   clang
x86_64                randconfig-013-20240105   clang
x86_64                randconfig-014-20240105   clang
x86_64                randconfig-015-20240105   clang
x86_64                randconfig-016-20240105   clang
x86_64                randconfig-071-20240105   clang
x86_64                randconfig-072-20240105   clang
x86_64                randconfig-073-20240105   clang
x86_64                randconfig-074-20240105   clang
x86_64                randconfig-075-20240105   clang
x86_64                randconfig-076-20240105   clang
x86_64                          rhel-8.3-rust   clang
xtensa                            allnoconfig   gcc  
xtensa                       common_defconfig   gcc  
xtensa                randconfig-001-20240105   gcc  
xtensa                randconfig-002-20240105   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401061514.ukKN3xCH-lkp%40intel.com.
