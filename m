Return-Path: <kasan-dev+bncBC4LXIPCY4NRBA7GQKSAMGQE3CBLRXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 35772726624
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Jun 2023 18:40:37 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-3f6f58e269esf43496675e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jun 2023 09:40:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686156036; cv=pass;
        d=google.com; s=arc-20160816;
        b=cHAKzQjTSnxttVwFolsOAFtnyu4Box3gK6/56uwUYMKbP6DydZ4uoZel7eKFbjFsZ+
         M/ac77rSvZkWi2rkoGY0y/jO+Zw3QtjUJVuQU+Uea3rl5r63QrOMyUaYrGa9fPakpWGR
         iGMGndQD5yJQ94VOk5uvqCorKm/2Xgqrtu2/VEd5NB9wnDFSvzYsF1xqVT9NaXRWfspn
         JAAWl+uSBvGvZyhThAnzOa8Vpjx3HT139tltTpzbZVYKU9Sb8hEoXrxfwEPDltchlvxj
         swIkudwN8pU/reZYKQkO0SlmZ2LaviiWm/QmU9CMC49BWDfFNqDYqifhFuKId2qEV9gO
         D9Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=sMe0QjmuRp2N6oKfIGFxSyGtlQ8dhmEOF60izBor1XA=;
        b=pk3DFRs44/bCY+J1hX6FQV/Nkux4PGODvxGRGjlIeOuRjDe7rr3zNLK+zjhVgX1Gvf
         UQjPhjbTvoIiDlUZrN/WtnjErjPxC4wldpu/G1WZ3nUqw+xUqQOru+H6LuE7nA1uMQ8k
         cQCzfINa/i2lt992WM91pCKDY9ge7v6IAUQPUqqrjBBPsVTX1JvBIPS1I1+gYr3ysZBW
         9gKrUuqjWP70RmHRm79oDkoG1wsVlRnSz/4zOFgOmNB21l67SLXc4pvfGnIPEf0nbGja
         I08zQaWR2QVZNr4U+x0lNjkhPZMcLfzX2ZbQ+y3WANQ5+9nhDyEx97IxRIxVKpPnsLjG
         qVNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mEFaAYsy;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686156036; x=1688748036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sMe0QjmuRp2N6oKfIGFxSyGtlQ8dhmEOF60izBor1XA=;
        b=UocBPLG6imdEUykFTvx5NygQtoM2TF3mywRTbXh7pSs2YD6oRMPUDth0KOcUI2qJZu
         tGP9H7Y1v5ohRM0gdrtYsch0rVjDlWAX6Gxi1gsynn9Of9yczvE8eoiVF+uP43kXwBPS
         5agJ2iJ8ysZLs5bqx+i/y5NhYmpTvjAfHluWDC49GZYd/gysWoHG7jycnd8srsKtt8q8
         FaYFDozPwRUCH6LwkCpycJrMlvWNqx12Lye9iy8TR3zap43Im6rfKgLzJLnQ5ybKJOlF
         GbEen8yKkf6gvFQlhK4PCHc5FDd637EN3wnX2m2EVOgeyfzCwiX0i0eqOnBiZleOXw/o
         V1XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686156036; x=1688748036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sMe0QjmuRp2N6oKfIGFxSyGtlQ8dhmEOF60izBor1XA=;
        b=Gr/yWZ1IRzMwRxPE+EZChiDrpTi6ELI2siD7ExIcSxr+fHliQZ1tLvhl1y8Hr2jjUj
         ihkT1Qt/astO+WdWMAvdOEYxy6UjTHsWAPfrt+DH0bTKvm3Cw6iCjvLeZTVQ3jpz5WKJ
         SbEgCuzo/dMRr11Shuo7+DPBf1djal2xQlIJB205GqGiIZV09g2qdgoRXa/j0PU2cGjE
         lNaBS0LRh77ZYvE4PToiKUQBSKkhqUurFR0gfdlz8aMeZBTRBS/uNbupjtjdonJSmjvd
         2WWM3d3snzLxaBoziRsHUst0+GyMbrYDnXq/q2OuN6a6FMH4cFuHhE8PyzJ7G5rU4DfX
         zrJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx75W1mvncO0KHsmSUWWKJBrWzdeL+Wms+JMAE+NehWWM8+rbIf
	risCELO+OWUB5dBchDdhKhQ=
X-Google-Smtp-Source: ACHHUZ42dcq0OAEL3Xtq0Uwe63UU7EkP00usBJ2ylRz1EVZvURssQ/a0hSP4b4YDDYWE9FE63Ua8sQ==
X-Received: by 2002:a1c:7213:0:b0:3f7:e809:f41d with SMTP id n19-20020a1c7213000000b003f7e809f41dmr5435745wmc.4.1686156035734;
        Wed, 07 Jun 2023 09:40:35 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d1b:b0:3f7:ecbb:40e7 with SMTP id
 l27-20020a05600c1d1b00b003f7ecbb40e7ls20555wms.0.-pod-prod-05-eu; Wed, 07 Jun
 2023 09:40:34 -0700 (PDT)
X-Received: by 2002:a5d:51c6:0:b0:307:88ff:ea26 with SMTP id n6-20020a5d51c6000000b0030788ffea26mr4584121wrv.25.1686156034220;
        Wed, 07 Jun 2023 09:40:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686156034; cv=none;
        d=google.com; s=arc-20160816;
        b=w1BiDBcqdkB69E/bhHZkGOgAQEWCl0p0uEQIGEiKRy3eZMeouAH2Wv3wC8mw3Te1qw
         wkg+KqMtybjZL0ckRavgWnkJf6HmFxZkrzsVvt003D6E7KaKfU8bq5A1Yk/wioiISHSf
         hD5NwON1LK/iayVsl10iz6mty421LSZi6iq4/BSZMsIFv7iHBgkAbfq2epiWuaB4Xc/W
         1Qzk1Cqm3uvnrJFZzMM7G7dz91prkq6X29YJ8n10IigrRE3aYrv1IKUGFCWmoSE8vlV+
         w1aSy7cH7/A/3oD/4qU5Wjx2zdGwPXDrCtgAqb0t7B0fqLDY6Tek9nPNrXZZixV4gASn
         v5KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=nLPjZMGZWT8JFGR+LDFv5MtzpSjzr0S8cYXGCf7cDXs=;
        b=eNXEth/BEAApUWIqsDYtRK+1r07Q7Oh8qyiAF2uussirq4vvM/i4AvbedOjzkf9f6G
         qJYgf5dCusj0+cb4KeiEDyfGLxBb9bDbdw+3Z/ecPRFTV9lkjaNpR8VhpnTLmXvUbRaE
         NhEMJz0n3oTKQgOPBon4qsUVNfgRDiJoYpgB4i0zen4Yvt7DJ8Kp/v8uKQ55+MIBmnZ9
         MWCLIGu9sp5NOQSj5v1yACInK8ur52W1GqHMIasa/5B0vHYqXIHXvnN9aBCAULrYi3sH
         +lW10afghXfJA7ESIimcbasRcqhN9IMgIF98pNRGHIpIGqjqfCKKN+q7YtS8WI20ssuO
         /Fnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mEFaAYsy;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id bj13-20020a0560001e0d00b00309385d6135si1006311wrb.1.2023.06.07.09.40.33
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Jun 2023 09:40:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10734"; a="341695968"
X-IronPort-AV: E=Sophos;i="6.00,224,1681196400"; 
   d="scan'208";a="341695968"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Jun 2023 09:40:29 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10734"; a="712726946"
X-IronPort-AV: E=Sophos;i="6.00,224,1681196400"; 
   d="scan'208";a="712726946"
Received: from lkp-server01.sh.intel.com (HELO 15ab08e44a81) ([10.239.97.150])
  by fmsmga007.fm.intel.com with ESMTP; 07 Jun 2023 09:40:24 -0700
Received: from kbuild by 15ab08e44a81 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1q6wCu-0006kl-0a;
	Wed, 07 Jun 2023 16:40:24 +0000
Date: Thu, 08 Jun 2023 00:39:37 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 bpf@vger.kernel.org, dri-devel@lists.freedesktop.org,
 kasan-dev@googlegroups.com, kunit-dev@googlegroups.com,
 kvmarm@lists.linux.dev, linux-arm-kernel@lists.infradead.org,
 linux-arm-msm@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-nvme@lists.infradead.org, linux-pci@vger.kernel.org,
 linux-perf-users@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-usb@vger.kernel.org, netdev@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 abbd8bb42915d9ed06df11b430bf4ecb3d8ac5ad
Message-ID: <20230607163937.ZTc-D%lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mEFaAYsy;       spf=pass
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
branch HEAD: abbd8bb42915d9ed06df11b430bf4ecb3d8ac5ad  Add linux-next specific files for 20230607

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202305132244.DwzBUcUd-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202306021936.OktTcMAT-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202306051812.1YdWyZca-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202306071513.vCmugxAi-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

ERROR: modpost: "lynx_pcs_destroy" [drivers/net/ethernet/stmicro/stmmac/stmmac.ko] undefined!
drivers/bus/fsl-mc/fsl-mc-allocator.c:108:12: warning: variable 'mc_bus_dev' is uninitialized when used here [-Wuninitialized]
drivers/cpufreq/cpufreq-dt-platdev.c:105:34: warning: 'blocklist' defined but not used [-Wunused-const-variable=]
drivers/cpufreq/cpufreq-dt-platdev.c:18:34: warning: 'allowlist' defined but not used [-Wunused-const-variable=]
drivers/net/ethernet/altera/altera_tse_main.c:1419: undefined reference to `lynx_pcs_create_mdiodev'
drivers/net/ethernet/altera/altera_tse_main.c:1473: undefined reference to `lynx_pcs_destroy'
include/drm/drm_print.h:456:39: error: format '%ld' expects argument of type 'long int', but argument 4 has type 'size_t' {aka 'unsigned int'} [-Werror=format=]
lib/kunit/executor_test.c:138:4: error: cast from 'void (*)(const void *)' to 'kunit_action_t *' (aka 'void (*)(void *)') converts to incompatible function type [-Werror,-Wcast-function-type-strict]
microblaze-linux-ld: (.text+0x14a4): undefined reference to `lynx_pcs_destroy'
nios2-linux-ld: drivers/net/ethernet/altera/altera_tse_main.c:1451: undefined reference to `lynx_pcs_destroy'
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:330:18: warning: no previous prototype for 'bpf_kfunc_call_test_offset' [-Wmissing-prototypes]
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:336:1: warning: no previous prototype for 'bpf_kfunc_call_memb_acquire' [-Wmissing-prototypes]
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:342:18: warning: no previous prototype for 'bpf_kfunc_call_memb1_release' [-Wmissing-prototypes]
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:394:18: warning: no previous prototype for 'bpf_kfunc_call_test_fail1' [-Wmissing-prototypes]
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:398:18: warning: no previous prototype for 'bpf_kfunc_call_test_fail2' [-Wmissing-prototypes]
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:402:18: warning: no previous prototype for 'bpf_kfunc_call_test_fail3' [-Wmissing-prototypes]
tools/testing/selftests/bpf/bpf_testmod/bpf_testmod.c:410:18: warning: no previous prototype for 'bpf_kfunc_call_test_mem_len_fail1' [-Wmissing-prototypes]

Unverified Error/Warning (likely false positive, please contact us if interested):

arch/arm64/kvm/mmu.c:147:3-9: preceding lock on line 140
drivers/clk/qcom/gpucc-sm8550.c:37:22: sparse: sparse: decimal constant 2300000000 is between LONG_MAX and ULONG_MAX. For C99 that means long long, C90 compilers are very likely to produce unsigned long (and a warning) here
drivers/clk/qcom/videocc-sm8550.c:34:22: sparse: sparse: decimal constant 2300000000 is between LONG_MAX and ULONG_MAX. For C99 that means long long, C90 compilers are very likely to produce unsigned long (and a warning) here
drivers/nvme/host/pr.c:268:23-26: ERROR: reference preceded by free on line 278
drivers/pci/endpoint/functions/pci-epf-mhi.c:362:2-9: line 362 is redundant because platform_get_irq() already prints an error
drivers/usb/cdns3/cdns3-starfive.c:23: warning: expecting prototype for cdns3(). Prototype was for USB_STRAP_HOST() instead
drivers/usb/typec/tcpm/qcom/qcom_pmic_typec_pdphy.c:217:30: sparse: sparse: incorrect type in argument 1 (different base types)
kernel/events/uprobes.c:478 uprobe_write_opcode() warn: passing zero to 'PTR_ERR'
lib/kunit/test.c:336 __kunit_abort() warn: ignoring unreachable code.

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- arc-allyesconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- arm-allmodconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- arm-allyesconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- arm64-allyesconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- arm64-randconfig-c004-20230607
|   `-- arch-arm64-kvm-mmu.c:preceding-lock-on-line
|-- csky-randconfig-s053-20230607
|   |-- drivers-clk-qcom-gpucc-sm8550.c:sparse:sparse:decimal-constant-is-between-LONG_MAX-and-ULONG_MAX.-For-C99-that-means-long-long-C90-compilers-are-very-likely-to-produce-unsigned-long-(and-a-warning)-he
|   `-- drivers-clk-qcom-videocc-sm8550.c:sparse:sparse:decimal-constant-is-between-LONG_MAX-and-ULONG_MAX.-For-C99-that-means-long-long-C90-compilers-are-very-likely-to-produce-unsigned-long-(and-a-warning)-
|-- i386-allyesconfig
|   |-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|   `-- include-drm-drm_print.h:error:format-ld-expects-argument-of-type-long-int-but-argument-has-type-size_t-aka-unsigned-int
|-- i386-randconfig-m021-20230607
|   `-- kernel-events-uprobes.c-uprobe_write_opcode()-warn:passing-zero-to-PTR_ERR
|-- m68k-allmodconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- microblaze-randconfig-c041-20230607
|   `-- drivers-nvme-host-pr.c:ERROR:reference-preceded-by-free-on-line
|-- microblaze-randconfig-c044-20230607
|   `-- microblaze-linux-ld:(.text):undefined-reference-to-lynx_pcs_destroy
|-- mips-allmodconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- nios2-defconfig
|   |-- drivers-net-ethernet-altera-altera_tse_main.c:undefined-reference-to-lynx_pcs_create_mdiodev
|   |-- drivers-net-ethernet-altera-altera_tse_main.c:undefined-reference-to-lynx_pcs_destroy
|   `-- nios2-linux-ld:drivers-net-ethernet-altera-altera_tse_main.c:undefined-reference-to-lynx_pcs_destroy
|-- openrisc-randconfig-s052-20230607
|   |-- drivers-clk-qcom-gpucc-sm8550.c:sparse:sparse:decimal-constant-is-between-LONG_MAX-and-ULONG_MAX.-For-C99-that-means-long-long-C90-compilers-are-very-likely-to-produce-unsigned-long-(and-a-warning)-he
|   |-- drivers-clk-qcom-videocc-sm8550.c:sparse:sparse:decimal-constant-is-between-LONG_MAX-and-ULONG_MAX.-For-C99-that-means-long-long-C90-compilers-are-very-likely-to-produce-unsigned-long-(and-a-warning)-
|   |-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|   `-- drivers-usb-typec-tcpm-qcom-qcom_pmic_typec_pdphy.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-unsigned-short-usertype-header-got-restricted-__le16-const-usertype-header
|-- parisc-randconfig-s042-20230607
|   |-- drivers-clk-qcom-videocc-sm8550.c:sparse:sparse:decimal-constant-is-between-LONG_MAX-and-ULONG_MAX.-For-C99-that-means-long-long-C90-compilers-are-very-likely-to-produce-unsigned-long-(and-a-warning)-
|   `-- mm-kfence-core.c:sparse:sparse:cast-to-restricted-__le64
|-- powerpc-allmodconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- powerpc-randconfig-c031-20230607
|   `-- drivers-pci-endpoint-functions-pci-epf-mhi.c:line-is-redundant-because-platform_get_irq()-already-prints-an-error
|-- riscv-allmodconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- riscv-defconfig
|   `-- ERROR:lynx_pcs_destroy-drivers-net-ethernet-stmicro-stmmac-stmmac.ko-undefined
|-- riscv-rv32_defconfig
|   `-- ERROR:lynx_pcs_destroy-drivers-net-ethernet-stmicro-stmmac-stmmac.ko-undefined
|-- s390-allmodconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- s390-allyesconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- sh-randconfig-m041-20230607
|   `-- lib-kunit-test.c-__kunit_abort()-warn:ignoring-unreachable-code.
|-- x86_64-allyesconfig
|   `-- drivers-usb-cdns3-cdns3-starfive.c:warning:expecting-prototype-for-cdns3().-Prototype-was-for-USB_STRAP_HOST()-instead
|-- x86_64-randconfig-c044-20230607
|   |-- drivers-cpufreq-cpufreq-dt-platdev.c:warning:allowlist-defined-but-not-used
|   `-- drivers-cpufreq-cpufreq-dt-platdev.c:warning:blocklist-defined-but-not-used
|-- x86_64-randconfig-k001-20230607
|   |-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_memb1_release
|   |-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_memb_acquire
|   |-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_test_fail1
|   |-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_test_fail2
|   |-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_test_fail3
|   |-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_test_mem_len_fail1
|   `-- tools-testing-selftests-bpf-bpf_testmod-bpf_testmod.c:warning:no-previous-prototype-for-bpf_kfunc_call_test_offset
|-- x86_64-randconfig-x062-20230607
|   `-- drivers-net-ethernet-altera-altera_tse_main.c:undefined-reference-to-lynx_pcs_destroy
`-- x86_64-randconfig-x066-20230607
    `-- ERROR:lynx_pcs_destroy-drivers-net-ethernet-stmicro-stmmac-stmmac.ko-undefined
clang_recent_errors
|-- arm64-randconfig-r036-20230607
|   `-- drivers-bus-fsl-mc-fsl-mc-allocator.c:warning:variable-mc_bus_dev-is-uninitialized-when-used-here
|-- i386-randconfig-i002-20230607
|   `-- drivers-bus-fsl-mc-fsl-mc-allocator.c:warning:variable-mc_bus_dev-is-uninitialized-when-used-here
|-- i386-randconfig-i061-20230607
|   `-- drivers-bus-fsl-mc-fsl-mc-allocator.c:warning:variable-mc_bus_dev-is-uninitialized-when-used-here
`-- riscv-randconfig-r032-20230607
    `-- lib-kunit-executor_test.c:error:cast-from-void-(-)(const-void-)-to-kunit_action_t-(aka-void-(-)(void-)-)-converts-to-incompatible-function-type-Werror-Wcast-function-type-strict

elapsed time: 721m

configs tested: 143
configs skipped: 6

tested configs:
alpha                            alldefconfig   gcc  
alpha                            allyesconfig   gcc  
alpha        buildonly-randconfig-r002-20230607   gcc  
alpha                               defconfig   gcc  
arc                              allyesconfig   gcc  
arc                                 defconfig   gcc  
arc                     haps_hs_smp_defconfig   gcc  
arc                  randconfig-r002-20230607   gcc  
arc                  randconfig-r016-20230607   gcc  
arc                  randconfig-r033-20230607   gcc  
arc                  randconfig-r043-20230607   gcc  
arm                              allmodconfig   gcc  
arm                              allyesconfig   gcc  
arm                         assabet_defconfig   gcc  
arm                                 defconfig   gcc  
arm                           h3600_defconfig   gcc  
arm                            hisi_defconfig   gcc  
arm                           imxrt_defconfig   gcc  
arm                  randconfig-r046-20230607   clang
arm                          sp7021_defconfig   clang
arm64                            allyesconfig   gcc  
arm64                               defconfig   gcc  
arm64                randconfig-r003-20230607   clang
arm64                randconfig-r036-20230607   clang
csky         buildonly-randconfig-r003-20230607   gcc  
csky                                defconfig   gcc  
hexagon              randconfig-r014-20230607   clang
hexagon              randconfig-r041-20230607   clang
hexagon              randconfig-r045-20230607   clang
i386                             allyesconfig   gcc  
i386         buildonly-randconfig-r005-20230607   clang
i386                              debian-10.3   gcc  
i386                                defconfig   gcc  
i386                 randconfig-i001-20230607   clang
i386                 randconfig-i002-20230607   clang
i386                 randconfig-i003-20230607   clang
i386                 randconfig-i004-20230607   clang
i386                 randconfig-i005-20230607   clang
i386                 randconfig-i006-20230607   clang
i386                 randconfig-i011-20230607   gcc  
i386                 randconfig-i012-20230607   gcc  
i386                 randconfig-i051-20230607   clang
i386                 randconfig-i052-20230607   clang
i386                 randconfig-i053-20230607   clang
i386                 randconfig-i054-20230607   clang
i386                 randconfig-i055-20230607   clang
i386                 randconfig-i056-20230607   clang
i386                 randconfig-i061-20230607   clang
i386                 randconfig-i062-20230607   clang
i386                 randconfig-i063-20230607   clang
i386                 randconfig-i064-20230607   clang
i386                 randconfig-i065-20230607   clang
i386                 randconfig-i066-20230607   clang
i386                 randconfig-r022-20230607   gcc  
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch    buildonly-randconfig-r004-20230607   gcc  
loongarch                           defconfig   gcc  
loongarch            randconfig-r021-20230607   gcc  
loongarch            randconfig-r024-20230607   gcc  
m68k                             allmodconfig   gcc  
m68k                                defconfig   gcc  
m68k                       m5275evb_defconfig   gcc  
m68k                            mac_defconfig   gcc  
mips                             allmodconfig   gcc  
mips                             allyesconfig   gcc  
mips                         bigsur_defconfig   gcc  
mips                 randconfig-r004-20230607   gcc  
mips                 randconfig-r031-20230607   gcc  
mips                        vocore2_defconfig   gcc  
nios2                               defconfig   gcc  
nios2                randconfig-r026-20230607   gcc  
openrisc             randconfig-r023-20230607   gcc  
openrisc             randconfig-r032-20230607   gcc  
parisc                              defconfig   gcc  
parisc64                            defconfig   gcc  
powerpc                          allmodconfig   gcc  
powerpc                           allnoconfig   gcc  
powerpc                     ksi8560_defconfig   clang
powerpc                      makalu_defconfig   gcc  
powerpc                       maple_defconfig   gcc  
powerpc                      ppc6xx_defconfig   gcc  
powerpc              randconfig-r005-20230607   clang
powerpc              randconfig-r023-20230607   gcc  
powerpc                 xes_mpc85xx_defconfig   clang
riscv                            alldefconfig   clang
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   gcc  
riscv                               defconfig   gcc  
riscv                randconfig-r022-20230607   gcc  
riscv                randconfig-r042-20230607   gcc  
riscv                          rv32_defconfig   gcc  
s390                             allmodconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                 randconfig-r006-20230607   clang
s390                 randconfig-r024-20230607   gcc  
s390                 randconfig-r044-20230607   gcc  
sh                               allmodconfig   gcc  
sh                         ap325rxa_defconfig   gcc  
sh                          sdk7780_defconfig   gcc  
sparc        buildonly-randconfig-r006-20230607   gcc  
sparc                               defconfig   gcc  
sparc                randconfig-r015-20230607   gcc  
sparc                randconfig-r026-20230607   gcc  
sparc                       sparc64_defconfig   gcc  
sparc64              randconfig-r021-20230607   gcc  
sparc64              randconfig-r034-20230607   gcc  
um                             i386_defconfig   gcc  
um                           x86_64_defconfig   gcc  
x86_64                           allyesconfig   gcc  
x86_64                              defconfig   gcc  
x86_64                                  kexec   gcc  
x86_64               randconfig-a001-20230607   clang
x86_64               randconfig-a002-20230607   clang
x86_64               randconfig-a003-20230607   clang
x86_64               randconfig-a004-20230607   clang
x86_64               randconfig-a005-20230607   clang
x86_64               randconfig-a006-20230607   clang
x86_64               randconfig-a011-20230607   gcc  
x86_64               randconfig-a012-20230607   gcc  
x86_64               randconfig-a013-20230607   gcc  
x86_64               randconfig-a014-20230607   gcc  
x86_64               randconfig-a015-20230607   gcc  
x86_64               randconfig-a016-20230607   gcc  
x86_64               randconfig-k001-20230607   gcc  
x86_64               randconfig-x051-20230607   gcc  
x86_64               randconfig-x052-20230607   gcc  
x86_64               randconfig-x053-20230607   gcc  
x86_64               randconfig-x054-20230607   gcc  
x86_64               randconfig-x055-20230607   gcc  
x86_64               randconfig-x056-20230607   gcc  
x86_64               randconfig-x061-20230607   gcc  
x86_64               randconfig-x062-20230607   gcc  
x86_64               randconfig-x063-20230607   gcc  
x86_64               randconfig-x064-20230607   gcc  
x86_64               randconfig-x065-20230607   gcc  
x86_64               randconfig-x066-20230607   gcc  
x86_64                               rhel-8.3   gcc  
xtensa                  nommu_kc705_defconfig   gcc  
xtensa               randconfig-r011-20230607   gcc  
xtensa               randconfig-r012-20230607   gcc  
xtensa               randconfig-r035-20230607   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230607163937.ZTc-D%25lkp%40intel.com.
