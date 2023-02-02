Return-Path: <kasan-dev+bncBC4LXIPCY4NRB2VO56PAMGQEXDPG5XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 25A8F688283
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 16:31:55 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id ev18-20020a056402541200b004a621e993a8sf1685985edb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 07:31:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675351914; cv=pass;
        d=google.com; s=arc-20160816;
        b=QwpWZ+i3WHooQCLGwxcd3zo4qWI4B2pBVPKpvdqM5vd8Vu5J3XRxuZ+kLYHugBrggt
         E6ByeKe3tSD7g59gPMeR/SqnOWfm3tXmuzdccNhcuwdUydHEtkbVv2LDjAx7SwFC6HCN
         q33A3FzHLg9C4h6E8euu4n9XbpKx2GgqAbHEBuPTZHQt0Mbk/cQKffG0Xm67WSER+SMu
         PgAynx7mKiEZnm2OgWY6CuPyqQ8ai+oTjR09zSU4L1fl4akhLAl8GVpt0XHv3nCXze7z
         ewKj8XBzvK+Tqc7su3/Fayo6KFqcFsYJ3MU5+nzvCP34G63XVbM6CfYgwyIH4LyjQccW
         9xMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=KitpIUQRr5U4xwc8gDJHtlxSvIYZoBfa5EjJ0vmDY5o=;
        b=BvDposAdm2sYVBJ5Os93MwqRkJeff0R3w5kdNwOZhXBbAToTH8Q0X20zwX/TfwqcJi
         eBEHd7T5lscPx36BmJQ/kC7ax/ezMRL1deD/0YIwv47m8lTDJGc2tiuVMl7Q1pPf3E1y
         3M+y7+X5dB1Wx+n1XufiWpXkdBxKqzkPsQo8BTFz9FNmEGHbDGS3KEfXz7UVAdapRetE
         RkPWfGvaF+c56HNGUQk91YTg1NVJCaQxrk08gK/b/tI4/RYELJG5jqtZ0DDOsDTWjIJq
         Jo6z3tMXjLP2Zw+q1/6541TDsqWOI74AWSEKTYhBVyA6YrG0ol7aHLVLFrkGR7pqJOw8
         aZ9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EACGJJ5D;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:subject:cc:to
         :from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KitpIUQRr5U4xwc8gDJHtlxSvIYZoBfa5EjJ0vmDY5o=;
        b=X5afe5wATkCJNuYQHhJ/j7v4amjh7kes0YjSQLzAAIgzTQNQGt34h9BQ1rRGTP0x+E
         wXl61qp49eZokGW3Tmq1TrahLgyTWGb9vpuUBybYs1bvRZtAy1B5WpaZlgttGzUvytiz
         lQSVg0aV+s/YNDZDXlb9FFq2TgMwsPX0xGtQg9XW3zulOwhAenl6TAcg2aPGKAngBCJf
         TfuAKajZi+CjR3dFOT8rR3eNLWnHCgGKdq3X8aF1vpUIRKpqLq9S581uZMsznuvtTIqt
         1zbjrjOLOhN3Jy16xuhIHAPc0VvksVHSA75Qha5ZoP6XYSY8lTEhtAyMBAO1WWACuzSw
         95+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KitpIUQRr5U4xwc8gDJHtlxSvIYZoBfa5EjJ0vmDY5o=;
        b=Z5DyzvGPXYKbKUWABqkZqnghtT+LKePzoDeT1MahE07nDfHKXEsIrjMHoKogXfpYdf
         m70/JaGICMrdJGKbto5yGkTTJbSkmMM4HFuZ3nijZLdXLNoAu+fTi6F9q6oRYjNXa1bd
         VGWvd5s9LMYYSc8gDYgwCb+yK/HkOR7DKwAxxJG7GNsleB8R+eP7+EtxfUUqf9Hy7aLm
         CtqVBpFqUhYKqwXPRsCwyEDurpUeo0E6CsuQ1B7+7m5AfeVoYimPyQBGGOp4wS4+3TxB
         +nG06QgT8L2Wnezi7WNJwIyguRYDyGg+j106/yyw/gT4DODloElwjMA74tAAQaxXTln6
         XWsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUhCwJY0GbbhYajgaTMoXb/0GRp0RNo6iuVTC49h8SMVWCntZmr
	wNtSIUiDC9vGy10OiWC1pjI=
X-Google-Smtp-Source: AK7set9PQl/P54/764OKOvEM73HRSY4SFKArP+IxgeKU83+yzyLzSS+FRhVp9DmnmKSLUvMWoWsfBw==
X-Received: by 2002:a17:907:7094:b0:88d:1c7:d3d7 with SMTP id yj20-20020a170907709400b0088d01c7d3d7mr2182638ejb.183.1675351914719;
        Thu, 02 Feb 2023 07:31:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2996:b0:49e:5b8c:71c4 with SMTP id
 eq22-20020a056402299600b0049e5b8c71c4ls2348953edb.3.-pod-prod-gmail; Thu, 02
 Feb 2023 07:31:53 -0800 (PST)
X-Received: by 2002:a50:ce47:0:b0:4a2:45e3:ede3 with SMTP id k7-20020a50ce47000000b004a245e3ede3mr6601132edj.14.1675351913376;
        Thu, 02 Feb 2023 07:31:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675351913; cv=none;
        d=google.com; s=arc-20160816;
        b=oYlhxpGogmtif1M8waKyIOF7nCoowhZAUaLnRQ9+fqWMcyWuzkuL33i+LgFiSN19Ey
         /b6EirDgQLV2dZp2gZWr1pzIL3zk0OoGFSbap2KTcW/qVnW7xSwvWnZjkwGaN3Ltuuv9
         AhSCkA0uUkHrX0WYOLx7FS+lQdPmERnkUCHDB2j7FCJsnbEowRSJrAM2liPWIBTM+Tdz
         3jiAF/dleRURoLbyXOKdkZ/jdbvCGhHiCSdWCqrVmNuTSEcGEHvlL7gQymWlPUwdoH7Q
         /ubmLNeWI6yUDU9IMtZRdxhoexGixet/TmUtEy5KHNlEGxmt491CJ8mh0LE32e5v/3Rt
         1sFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kPgO62OF7+YqHDdGBFp2XrLVe8px7HLkbHuY/l0vSZc=;
        b=OCbdnXC3KsJueDkQcZ1zQ7M+fp678A1bLGHWy7Cg5g/mYo7o6lxJ8VipEKiMQVOEzY
         OUzpygET7KnfWMQryr72iqo6Rgxgf5VPbMQ2Wy+5E8ZKIU8pVXflp/45bA9UrhhT3nmy
         5zERDhW0XvZCQ6nwvj9jzGiLGugfwB9ny9kD+v+8NtkgYSQwMqvZ6uRhOAIlo0G6v6XN
         16ku8YKbsNzsH1nF7D9couVVVyeQLUaNp190OE50CF7AnosqH9FavLnd1oGJ6RPsmi0a
         JXtHvJi7RL2jtG353R9g0YS6gC8O8aP3ieVwayaCeSFNc3E8hm59vgemnzx9sygDduHq
         f4ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=EACGJJ5D;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id ds16-20020a0564021cd000b0046c3ce626bdsi1045774edb.2.2023.02.02.07.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Feb 2023 07:31:53 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10608"; a="393055053"
X-IronPort-AV: E=Sophos;i="5.97,267,1669104000"; 
   d="scan'208";a="393055053"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Feb 2023 07:26:39 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10608"; a="667316707"
X-IronPort-AV: E=Sophos;i="5.97,267,1669104000"; 
   d="scan'208";a="667316707"
Received: from lkp-server01.sh.intel.com (HELO ffa7f14d1d0f) ([10.239.97.150])
  by fmsmga007.fm.intel.com with ESMTP; 02 Feb 2023 07:26:36 -0800
Received: from kbuild by ffa7f14d1d0f with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1pNbTv-0006cC-17;
	Thu, 02 Feb 2023 15:26:35 +0000
Date: Thu, 02 Feb 2023 23:25:45 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-trace-kernel@vger.kernel.org, linux-tegra@vger.kernel.org,
 linux-media@vger.kernel.org, linux-arm-msm@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
 kvmarm@lists.cs.columbia.edu, kasan-dev@googlegroups.com,
 dri-devel@lists.freedesktop.org, amd-gfx@lists.freedesktop.org,
 Linux Memory Management List <linux-mm@kvack.org>
Subject: [linux-next:master] BUILD REGRESSION
 ea4dabbb4ad7eb52632a2ca0b8f89f0ea7c55dcf
Message-ID: <63dbd5f9.EHwMUB1NksMSVh+v%lkp@intel.com>
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=EACGJJ5D;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted
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
branch HEAD: ea4dabbb4ad7eb52632a2ca0b8f89f0ea7c55dcf  Add linux-next specific files for 20230202

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202301301801.y5O08tQx-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202301302110.mEtNwkBD-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202301310227.SeMvYeta-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202301310939.TAgCOEZb-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202302021325.700zGa0M-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

ERROR: modpost: "devm_platform_ioremap_resource" [drivers/dma/fsl-edma.ko] undefined!
ERROR: modpost: "devm_platform_ioremap_resource" [drivers/dma/idma64.ko] undefined!
arch/arm64/kvm/arm.c:2206: warning: expecting prototype for Initialize Hyp(). Prototype was for kvm_arm_init() instead
drivers/gpu/drm/amd/amdgpu/../display/dc/link/accessories/link_dp_trace.c:148:6: warning: no previous prototype for 'link_dp_trace_set_edp_power_timestamp' [-Wmissing-prototypes]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/accessories/link_dp_trace.c:148:6: warning: no previous prototype for function 'link_dp_trace_set_edp_power_timestamp' [-Wmissing-prototypes]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/accessories/link_dp_trace.c:158:10: warning: no previous prototype for 'link_dp_trace_get_edp_poweron_timestamp' [-Wmissing-prototypes]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/accessories/link_dp_trace.c:158:10: warning: no previous prototype for function 'link_dp_trace_get_edp_poweron_timestamp' [-Wmissing-prototypes]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/accessories/link_dp_trace.c:163:10: warning: no previous prototype for 'link_dp_trace_get_edp_poweroff_timestamp' [-Wmissing-prototypes]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/accessories/link_dp_trace.c:163:10: warning: no previous prototype for function 'link_dp_trace_get_edp_poweroff_timestamp' [-Wmissing-prototypes]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/protocols/link_dp_capability.c:1295:32: warning: variable 'result_write_min_hblank' set but not used [-Wunused-but-set-variable]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/protocols/link_dp_capability.c:279:42: warning: variable 'ds_port' set but not used [-Wunused-but-set-variable]
drivers/gpu/drm/amd/amdgpu/../display/dc/link/protocols/link_dp_training.c:1585:38: warning: variable 'result' set but not used [-Wunused-but-set-variable]
drivers/gpu/host1x/dev.c:521:10: warning: variable 'syncpt_irq' is uninitialized when used here [-Wuninitialized]
ftrace-ops.c:(.init.text+0x2c3): undefined reference to `__udivdi3'
mm/kasan/report.c:272:44: warning: format specifies type 'unsigned long' but the argument has type 'size_t' (aka 'unsigned int') [-Wformat]

Unverified Error/Warning (likely false positive, please contact us if interested):

drivers/media/i2c/max9286.c:802 max9286_s_stream() error: buffer overflow 'priv->fmt' 4 <= 32
drivers/nvmem/imx-ocotp.c:599:21: sparse: sparse: symbol 'imx_ocotp_layout' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v0_1.c:106:40: sparse: sparse: symbol 'tsens_9607_nvmem' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v0_1.c:26:40: sparse: sparse: symbol 'tsens_8916_nvmem' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v0_1.c:42:40: sparse: sparse: symbol 'tsens_8939_nvmem' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v0_1.c:62:40: sparse: sparse: symbol 'tsens_8974_nvmem' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v0_1.c:84:40: sparse: sparse: symbol 'tsens_8974_backup_nvmem' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v1.c:24:40: sparse: sparse: symbol 'tsens_qcs404_nvmem' was not declared. Should it be static?
drivers/thermal/qcom/tsens-v1.c:45:40: sparse: sparse: symbol 'tsens_8976_nvmem' was not declared. Should it be static?

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweron_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_set_edp_power_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-ds_port-set-but-not-used
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-result_write_min_hblank-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_training.c:warning:variable-result-set-but-not-used
|-- alpha-randconfig-r026-20230129
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweron_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_set_edp_power_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-ds_port-set-but-not-used
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-result_write_min_hblank-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_training.c:warning:variable-result-set-but-not-used
|-- alpha-randconfig-s052-20230129
|   |-- drivers-nvmem-imx-ocotp.c:sparse:sparse:symbol-imx_ocotp_layout-was-not-declared.-Should-it-be-static
|   |-- drivers-thermal-qcom-tsens-v0_1.c:sparse:sparse:symbol-tsens_8916_nvmem-was-not-declared.-Should-it-be-static
|   |-- drivers-thermal-qcom-tsens-v0_1.c:sparse:sparse:symbol-tsens_8939_nvmem-was-not-declared.-Should-it-be-static
|   |-- drivers-thermal-qcom-tsens-v0_1.c:sparse:sparse:symbol-tsens_8974_backup_nvmem-was-not-declared.-Should-it-be-static
|   |-- drivers-thermal-qcom-tsens-v0_1.c:sparse:sparse:symbol-tsens_8974_nvmem-was-not-declared.-Should-it-be-static
|   |-- drivers-thermal-qcom-tsens-v0_1.c:sparse:sparse:symbol-tsens_9607_nvmem-was-not-declared.-Should-it-be-static
|   |-- drivers-thermal-qcom-tsens-v1.c:sparse:sparse:symbol-tsens_8976_nvmem-was-not-declared.-Should-it-be-static
|   `-- drivers-thermal-qcom-tsens-v1.c:sparse:sparse:symbol-tsens_qcs404_nvmem-was-not-declared.-Should-it-be-static
|-- arc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweron_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_set_edp_power_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-ds_port-set-but-not-used
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-result_write_min_hblank-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_training.c:warning:variable-result-set-but-not-used
|-- arm-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweron_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_set_edp_power_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-ds_port-set-but-not-used
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-result_write_min_hblank-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_training.c:warning:variable-result-set-but-not-used
|-- arm64-allyesconfig
|   |-- arch-arm64-kvm-arm.c:warning:expecting-prototype-for-Initialize-Hyp().-Prototype-was-for-kvm_arm_init()-instead
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweron_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_set_edp_power_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-ds_port-set-but-not-used
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_capability.c:warning:variable-result_write_min_hblank-set-but-not-used
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-protocols-link_dp_training.c:warning:variable-result-set-but-not-used
|-- arm64-buildonly-randconfig-r004-20230130
|   |-- arch-arm64-kvm-arm.c:warning:expecting-prototype-for-Initialize-Hyp().-Prototype-was-for-kvm_arm_init()-instead
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_get_edp_poweron_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-link_dp_trace_set_edp_power_timestamp
clang_recent_errors
|-- arm-randconfig-r033-20230129
|   |-- drivers-gpu-host1x-dev.c:warning:variable-syncpt_irq-is-uninitialized-when-used-here
|   `-- mm-kasan-report.c:warning:format-specifies-type-unsigned-long-but-the-argument-has-type-size_t-(aka-unsigned-int-)
|-- arm64-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-function-link_dp_trace_get_edp_poweroff_timestamp
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-function-link_dp_trace_get_edp_poweron_timestamp
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-link-accessories-link_dp_trace.c:warning:no-previous-prototype-for-function-link_dp_trace_set_edp_power_timestamp
`-- powerpc-randconfig-r015-20230130
    `-- mm-kasan-report.c:warning:format-specifies-type-unsigned-long-but-the-argument-has-type-size_t-(aka-unsigned-int-)

elapsed time: 723m

configs tested: 67
configs skipped: 3

gcc tested configs:
x86_64                            allnoconfig
x86_64               randconfig-a001-20230130
i386                 randconfig-a002-20230130
x86_64               randconfig-a003-20230130
i386                 randconfig-a001-20230130
x86_64               randconfig-a004-20230130
um                             i386_defconfig
x86_64               randconfig-a002-20230130
i386                 randconfig-a004-20230130
i386                 randconfig-a003-20230130
x86_64               randconfig-a006-20230130
um                           x86_64_defconfig
i386                 randconfig-a005-20230130
x86_64               randconfig-a005-20230130
i386                 randconfig-a006-20230130
arc                                 defconfig
m68k                             allmodconfig
alpha                            allyesconfig
s390                             allmodconfig
m68k                             allyesconfig
arc                              allyesconfig
x86_64                    rhel-8.3-kselftests
alpha                               defconfig
s390                                defconfig
x86_64                          rhel-8.3-func
powerpc                           allnoconfig
powerpc                          allmodconfig
s390                             allyesconfig
x86_64                              defconfig
mips                             allyesconfig
sh                               allmodconfig
arc                  randconfig-r043-20230129
arm                                 defconfig
arm                  randconfig-r046-20230129
i386                                defconfig
ia64                             allmodconfig
x86_64                               rhel-8.3
arm                  randconfig-r046-20230130
arc                  randconfig-r043-20230130
x86_64                           rhel-8.3-syz
x86_64                         rhel-8.3-kunit
x86_64                           rhel-8.3-kvm
arm64                            allyesconfig
x86_64                           rhel-8.3-bpf
arm                              allyesconfig
x86_64                           allyesconfig
i386                             allyesconfig

clang tested configs:
x86_64               randconfig-a012-20230130
x86_64               randconfig-a013-20230130
x86_64               randconfig-a011-20230130
x86_64               randconfig-a014-20230130
x86_64               randconfig-a015-20230130
x86_64                          rhel-8.3-rust
x86_64               randconfig-a016-20230130
i386                 randconfig-a013-20230130
i386                 randconfig-a012-20230130
i386                 randconfig-a014-20230130
hexagon              randconfig-r045-20230130
i386                 randconfig-a015-20230130
i386                 randconfig-a011-20230130
i386                 randconfig-a016-20230130
hexagon              randconfig-r041-20230130
hexagon              randconfig-r045-20230129
s390                 randconfig-r044-20230129
s390                 randconfig-r044-20230130
riscv                randconfig-r042-20230129
riscv                randconfig-r042-20230130

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/63dbd5f9.EHwMUB1NksMSVh%2Bv%25lkp%40intel.com.
