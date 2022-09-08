Return-Path: <kasan-dev+bncBC4LXIPCY4NRBNG55GMAMGQEAGSGD7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A35565B2966
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 00:37:41 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id r17-20020adfbb11000000b00228663f217fsf4499333wrg.20
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 15:37:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662676661; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThvR9aly3Y3a/Knf/sLghBto0t0xgqvWyMXDmUBNdGk5K4CqHvggdbMEukwvg6kbMR
         JKbe7DSHApFXFBwRAbYOiW4KQRVWnwzSWFkok9w8SXJeFVgn6eN5RTyrjd2F0IYKRMF2
         6BQfZaVnVgvA5B2deaUpDa++ZDB+rBWJSdatHu5gvvPc4+i++w8ZSq6IdB/R2MgK76KF
         VNs00Dqr3T6y0tP0wHVPShhUvkaIuv9KN7a46td09qMiAZLBfRTYvA+1KGKl0IBbhilB
         orgMkmd/zahMfSgeAnUz952p1eeZ/kpUgPuIheY9v0TRzFG+SRNXgQVly9Rj/1//ZbHw
         qWWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=B+evr4hU8uGRJRLzx9QSTyl3AqW7HA0SKbPJXNLNagM=;
        b=PgCYQdhs2GYNeWwOAUVgzZ0INM6n1CSuAvMAqeanev8ogZH7k3q2Z8ge4+w8pupFCH
         j0kd1f8oLB9gaN+GH/zqmzCtl2dFrhFcl0xvZXk0LAmDbGZlCkfs05ZfhvRzWbWO67QS
         LQpMjWAgpD7dl9Du5GqQbVqLwtf3ILfwXmNWj0cskszmc59dh0ZjQu71l/5WbFMfhKnp
         VFNWCfd+tl1rvCQTRc00/pUC+tab5Xgwm5YD9UOIqdhw9M6hlHaARnQ9dGyGN9kzMEfm
         c7HMv5PMXXPZU2tLHWfuEKUJk6lsMf4AVTMZaqyZG/aW4qkMp9CDz8+n2VCnpzGs2FXO
         /Jlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JNHGbAPY;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:subject:cc:to
         :from:date:sender:from:to:cc:subject:date;
        bh=B+evr4hU8uGRJRLzx9QSTyl3AqW7HA0SKbPJXNLNagM=;
        b=ITfpb0Jrib3mC/NSkKgbSXmUgdsDSVGynbWAV/3YTOAhxpu09SelhcQ9gGODOAosg+
         zUf0cIVCMP5nVH3PI6Iy0alWuFs+x663+gi6GYDFVPP8P5Wqq9P9e/ZruW2k8GREbl+l
         VeOZvweEY2VB89HswuBkCkEbgYshZY0cDYWWTN9T6+G4tqJ0UsJMuDO1TJNAkTC4F8ko
         M4UCsLyV9nRDQ6GsPT0n6gMM3CngE1T9z7T5sz3i775Rntpg08ZsLDB2ScXdf3EXAX/J
         L6BJyg7hsIsEupiuxijqt2gVhzCkLmrn1+LtTjW8WrjK14FX4ij7ju878SyNWw08mvNP
         ryVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=B+evr4hU8uGRJRLzx9QSTyl3AqW7HA0SKbPJXNLNagM=;
        b=70/0ET9oIFi842jg1bKsWKH/Qhbxh4TNZci4nv6hjEyQBeQMBMaHJzl6eVdT9KfGHW
         pgFyL/iPyquiP0wYnrM1jjhR+jucgHlZA4XnX/Bbd/2aBZfaVH8nKrLFuPDob/a/5mQh
         Lb017iZqiM0rIyZhbKL/GcQMSSdxDIzPv77CTOTgBuhKa7goUUUcliGj2kZtZIYjx4MN
         Bg1saDMc4+8n448tH9G9ldWRrXrQac0D7YMfCbSYxsLPtws1NOyc1SIOQTCJDxAS0r/F
         Pb3Sk92ft+0Jwc5Gy/P/FNr6ZmqHqgegkaMUGTxniMSYI2+GGxsDSjUunYnCLueLMj/8
         +fbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3lMVaxZJSjQ5PQ73oqwd84n6wPBSedu2QFm07it0KptPMIaaCA
	ZX2Q4o7JJnWiEaTv9QY5znc=
X-Google-Smtp-Source: AA6agR6GepsVVBFhSbXHvIwS8aGztjuJK7NSfdMAI+fmdXeRcj0zQGRE8y1UDkDcGFaKhgVJwr9NrQ==
X-Received: by 2002:a05:600c:310b:b0:3a6:8970:27fc with SMTP id g11-20020a05600c310b00b003a6897027fcmr3550804wmo.98.1662676661083;
        Thu, 08 Sep 2022 15:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d210:0:b0:228:ddd7:f40e with SMTP id j16-20020adfd210000000b00228ddd7f40els5199027wrh.3.-pod-prod-gmail;
 Thu, 08 Sep 2022 15:37:40 -0700 (PDT)
X-Received: by 2002:adf:ec03:0:b0:228:76bd:76fc with SMTP id x3-20020adfec03000000b0022876bd76fcmr6381362wrn.533.1662676660048;
        Thu, 08 Sep 2022 15:37:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662676660; cv=none;
        d=google.com; s=arc-20160816;
        b=CcO4XhiDyNOaQp7Y6f7N4kStcWE3vgt53ArxcoJ65QaZoTuoPBhbgXvkRVACQaXDZQ
         mNifvZV4LFMcr4/s2QHlptG36Gzc8L8XYUUgivBnrZAPwPOvmUxM4YiaNSwKJwFEvVoZ
         38GKdQYWmiqpDSWak7hsQ4ABytX/e+WXXkHizGVRyjnwwoYVYkk8EMdv84ZBiPJGYKHq
         46SlMooSBbIZRbId+sg25zc+drT/aTCMmlSO6DqfbMdaWVzGfM2JTvJBcKAfZoJM90PJ
         JXoqczhIkiPLUQlG+ZFKiIMojIDf08LCPqmygcClL3J0ZLt6F7+eFCT7SrazSOWnwned
         CZGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=m1+riH/8Cn2BkPzndsEPSTZ3Zenh8cw5pZqpnVPGNdo=;
        b=kY6ppp/MIbOOkMV86rj3zcmS/1HPwjbcKLrZEhgsP/1I/mjz8f9t14o6gfPECieUg/
         wi0RU1DkKlK3+uLr0kESmwKjGm8voH0bqpJAgpTsVrjB0mRDgh7TimBEI+vsiIut8eW6
         ZSBzqNW5qzNmh8HOlE2c/m+6K42NdylOhKrrniNVYyxg0aCt/xd/DKBTwaxgoF1k9xyT
         Wtzc0/VTyZonq7nN/dE24/mdBY8rYBPtNTT23pdaOsvUS3aa+Ntzt55jWuCSrq6GkWBL
         OhZvcerpQ8CX2vV7Y+lneSsdKrStoH5P+b93MUKywOSoPJrHYDMjOcmNkzj08aIbUp8d
         LTgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JNHGbAPY;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id bz1-20020a056000090100b0022707c1dfc8si17945wrb.6.2022.09.08.15.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Sep 2022 15:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6500,9779,10464"; a="323542153"
X-IronPort-AV: E=Sophos;i="5.93,300,1654585200"; 
   d="scan'208";a="323542153"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2022 15:37:37 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,300,1654585200"; 
   d="scan'208";a="615060039"
Received: from lkp-server02.sh.intel.com (HELO b2938d2e5c5a) ([10.239.97.151])
  by orsmga002.jf.intel.com with ESMTP; 08 Sep 2022 15:37:33 -0700
Received: from kbuild by b2938d2e5c5a with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1oWQ9N-0000Nt-0V;
	Thu, 08 Sep 2022 22:37:33 +0000
Date: Fri, 09 Sep 2022 06:37:16 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linuxppc-dev@lists.ozlabs.org, linux-scsi@vger.kernel.org,
 linux-gpio@vger.kernel.org, linux-btrfs@vger.kernel.org,
 linux-aspeed@lists.ozlabs.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, dri-devel@lists.freedesktop.org,
 bpf@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 alsa-devel@alsa-project.org,
 Linux Memory Management List <linux-mm@kvack.org>
Subject: [linux-next:master] BUILD REGRESSION
 47c191411b68a771261be3dc0bd6f68394cef358
Message-ID: <631a6e9c.D4HRv8SAAnTyu/QX%lkp@intel.com>
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JNHGbAPY;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.88 as permitted
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
branch HEAD: 47c191411b68a771261be3dc0bd6f68394cef358  Add linux-next specific files for 20220908

Error/Warning reports:

https://lore.kernel.org/linux-mm/202209042337.FQi69rLV-lkp@intel.com
https://lore.kernel.org/linux-mm/202209080718.y5QmlNKH-lkp@intel.com
https://lore.kernel.org/llvm/202209090343.JPAFJt74-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

ERROR: modpost: "__divdi3" [drivers/gpu/drm/vkms/vkms.ko] undefined!
ERROR: modpost: "__udivdi3" [drivers/gpu/drm/vkms/vkms.ko] undefined!
arm-linux-gnueabi-ld: vkms_formats.c:(.text+0x824): undefined reference to `__aeabi_ldivmod'
drivers/base/regmap/regmap-mmio.c:222:17: error: implicit declaration of function 'writesb'; did you mean 'writeb'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:225:17: error: implicit declaration of function 'writesw'; did you mean 'writew'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:228:17: error: implicit declaration of function 'writesl'; did you mean 'writel'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:232:17: error: implicit declaration of function 'writesq'; did you mean 'writeq'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:232:17: error: implicit declaration of function 'writesq'; did you mean 'writesl'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:358:17: error: implicit declaration of function 'readsb'; did you mean 'readb'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:361:17: error: implicit declaration of function 'readsw'; did you mean 'readw'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:364:17: error: implicit declaration of function 'readsl'; did you mean 'readl'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:368:17: error: implicit declaration of function 'readsq'; did you mean 'readq'? [-Werror=implicit-function-declaration]
drivers/base/regmap/regmap-mmio.c:368:17: error: implicit declaration of function 'readsq'; did you mean 'readsl'? [-Werror=implicit-function-declaration]
drivers/crypto/aspeed/aspeed-hace.c:133 aspeed_hace_probe() warn: platform_get_irq() does not return zero
drivers/gpu/drm/amd/amdgpu/imu_v11_0_3.c:139:6: warning: no previous prototype for 'imu_v11_0_3_program_rlc_ram' [-Wmissing-prototypes]
drivers/gpu/drm/drm_atomic_helper.c:802: warning: expecting prototype for drm_atomic_helper_check_wb_connector_state(). Prototype was for drm_atomic_helper_check_wb_encoder_state() instead
drivers/gpu/drm/vkms/vkms_formats.c:259: undefined reference to `__divdi3'
drivers/pinctrl/pinctrl-amd.c:288 amd_gpio_dbg_show() warn: format string contains non-ascii character '\x9a'
drivers/pinctrl/pinctrl-amd.c:288 amd_gpio_dbg_show() warn: format string contains non-ascii character '\xa1'
drivers/pinctrl/pinctrl-amd.c:370 amd_gpio_dbg_show() warn: format string contains non-ascii character '\x95'
drivers/scsi/qla2xxx/qla_os.c:2854:23: warning: assignment to 'struct trace_array *' from 'int' makes pointer from integer without a cast [-Wint-conversion]
drivers/scsi/qla2xxx/qla_os.c:2854:25: error: implicit declaration of function 'trace_array_get_by_name'; did you mean 'trace_array_set_clr_event'? [-Werror=implicit-function-declaration]
drivers/scsi/qla2xxx/qla_os.c:2869:9: error: implicit declaration of function 'trace_array_put' [-Werror=implicit-function-declaration]
fs/btrfs/volumes.c:6549 __btrfs_map_block() error: we previously assumed 'mirror_num_ret' could be null (see line 6376)
ld: drivers/gpu/drm/vkms/vkms_formats.c:260: undefined reference to `__divdi3'
ld: vkms_formats.c:(.text+0x362): undefined reference to `__divdi3'
ld: vkms_formats.c:(.text+0x3b2): undefined reference to `__divdi3'
ld: vkms_formats.c:(.text+0x3ba): undefined reference to `__divdi3'
ld: vkms_formats.c:(.text+0x47f): undefined reference to `__divdi3'
mips-linux-ld: vkms_formats.c:(.text.argb_u16_to_RGB565+0xd0): undefined reference to `__divdi3'
mm/kasan/kasan_test_module.c:90:26: sparse:    struct kasan_rcu_info *
mm/kasan/kasan_test_module.c:90:26: sparse:    struct kasan_rcu_info [noderef] __rcu *
sound/soc/codecs/tas2562.c:442:13: warning: variable 'ret' set but not used [-Wunused-but-set-variable]
vkms_formats.c:(.text+0x266): undefined reference to `__divdi3'
vkms_formats.c:(.text+0x338): undefined reference to `__divdi3'
vkms_formats.c:(.text+0x388): undefined reference to `__divdi3'
vkms_formats.c:(.text+0x390): undefined reference to `__divdi3'
vkms_formats.c:(.text+0x455): undefined reference to `__divdi3'
vkms_formats.c:(.text+0x804): undefined reference to `__aeabi_ldivmod'
vkms_formats.c:(.text.argb_u16_to_RGB565+0xb0): undefined reference to `__divdi3'

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsb
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsl
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsq
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsw
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesb
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesl
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesq
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesw
|   |-- drivers-gpu-drm-amd-amdgpu-imu_v11_0_3.c:warning:no-previous-prototype-for-imu_v11_0_3_program_rlc_ram
|   |-- drivers-gpu-drm-drm_atomic_helper.c:warning:expecting-prototype-for-drm_atomic_helper_check_wb_connector_state().-Prototype-was-for-drm_atomic_helper_check_wb_encoder_state()-instead
|   |-- drivers-scsi-qla2xxx-qla_os.c:error:implicit-declaration-of-function-trace_array_get_by_name
|   |-- drivers-scsi-qla2xxx-qla_os.c:error:implicit-declaration-of-function-trace_array_put
|   |-- drivers-scsi-qla2xxx-qla_os.c:warning:assignment-to-struct-trace_array-from-int-makes-pointer-from-integer-without-a-cast
|   `-- sound-soc-codecs-tas2562.c:warning:variable-ret-set-but-not-used
|-- alpha-randconfig-r013-20220907
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsb
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsl
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsq
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsw
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesb
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesl
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesq
|   `-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesw
|-- alpha-randconfig-r034-20220907
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsb
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsl
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsq
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-readsw
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesb
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesl
|   |-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesq
|   `-- drivers-base-regmap-regmap-mmio.c:error:implicit-declaration-of-function-writesw
|-- arc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-imu_v11_0_3.c:warning:no-previous-prototype-for-imu_v11_0_3_program_rlc_ram
|   |-- drivers-gpu-drm-drm_atomic_helper.c:warning:expecting-prototype-for-drm_atomic_helper_check_wb_connector_state().-Prototype-was-for-drm_atomic_helper_check_wb_encoder_state()-instead
|   `-- sound-soc-codecs-tas2562.c:warning:variable-ret-set-but-not-used
|-- arc-randconfig-r003-20220907
|   `-- drivers-gpu-drm-drm_atomic_helper.c:warning:expecting-prototype-for-drm_atomic_helper_check_wb_connector_state().-Prototype-was-for-drm_atomic_helper_check_wb_encoder_state()-instead
|-- arc-randconfig-r026-20220907
|   |-- drivers-gpu-drm-drm_atomic_helper.c:warning:expecting-prototype-for-drm_atomic_helper_check_wb_connector_state().-Prototype-was-for-drm_atomic_helper_check_wb_encoder_state()-instead
|   `-- sound-soc-codecs-tas2562.c:warning:variable-ret-set-but-not-used
|-- arc-randconfig-s033-20220907
|   |-- kernel-bpf-hashtab.c:sparse:sparse:cast-removes-address-space-__percpu-of-expression
|   |-- kernel-bpf-hashtab.c:sparse:sparse:incorrect-type-in-assignment-(different-address-spaces)-expected-void-noderef-__percpu-assigned-pptr-got-void
|   |-- kernel-bpf-hashtab.c:sparse:sparse:incorrect-type-in-assignment-(different-address-spaces)-expected-void-ptr_to_pptr-got-void-noderef-__percpu-assigned-pptr
|   |-- kernel-bpf-memalloc.c:sparse:sparse:incorrect-type-in-argument-(different-address-spaces)-expected-void-noderef-__percpu-__pdata-got-void
|   |-- kernel-bpf-memalloc.c:sparse:sparse:incorrect-type-in-argument-(different-address-spaces)-expected-void-noderef-__percpu-__pdata-got-void-pptr
|   |-- kernel-bpf-memalloc.c:sparse:sparse:incorrect-type-in-initializer-(different-address-spaces)-expected-void-pptr-got-void-noderef-__percpu
|   `-- kernel-exit.c:sparse:sparse:incorrect-type-in-initializer-(different-address-spaces)-expected-struct-sighand_struct-sighand-got-struct-sighand_struct-noderef-__rcu-sighand
clang_recent_errors
|-- i386-randconfig-a002
|   `-- drivers-extcon-extcon-usbc-tusb320.c:warning:expecting-prototype-for-drivers-extcon-extcon-tusb320c().-Prototype-was-for-TUSB320_REG8()-instead
|-- i386-randconfig-a006
|   `-- ld.lld:error:undefined-symbol:__udivdi3
|-- i386-randconfig-a013
|   `-- ld.lld:error:undefined-symbol:__udivdi3
|-- i386-randconfig-a015
|   `-- drivers-extcon-extcon-usbc-tusb320.c:warning:expecting-prototype-for-drivers-extcon-extcon-tusb320c().-Prototype-was-for-TUSB320_REG8()-instead
|-- powerpc-randconfig-r021-20220907
|   |-- arch-powerpc-math-emu-fre.c:warning:no-previous-prototype-for-function-fre
|   |-- arch-powerpc-math-emu-frsqrtes.c:warning:no-previous-prototype-for-function-frsqrtes
|   |-- arch-powerpc-math-emu-fsqrt.c:warning:no-previous-prototype-for-function-fsqrt
|   |-- arch-powerpc-math-emu-fsqrts.c:warning:no-previous-prototype-for-function-fsqrts
|   |-- arch-powerpc-math-emu-mtfsf.c:warning:no-previous-prototype-for-function-mtfsf
|   `-- arch-powerpc-math-emu-mtfsfi.c:warning:no-previous-prototype-for-function-mtfsfi
|-- x86_64-randconfig-a003
|   `-- drivers-extcon-extcon-usbc-tusb320.c:warning:expecting-prototype-for-drivers-extcon-extcon-tusb320c().-Prototype-was-for-TUSB320_REG8()-instead
|-- x86_64-randconfig-a012
|   `-- drivers-extcon-extcon-usbc-tusb320.c:warning:expecting-prototype-for-drivers-extcon-extcon-tusb320c().-Prototype-was-for-TUSB320_REG8()-instead
`-- x86_64-randconfig-a016
    `-- drivers-extcon-extcon-usbc-tusb320.c:warning:expecting-prototype-for-drivers-extcon-extcon-tusb320c().-Prototype-was-for-TUSB320_REG8()-instead

elapsed time: 734m

configs tested: 75
configs skipped: 4

gcc tested configs:
um                             i386_defconfig
um                           x86_64_defconfig
m68k                             allmodconfig
x86_64                        randconfig-a011
powerpc                           allnoconfig
arc                              allyesconfig
powerpc                          allmodconfig
alpha                            allyesconfig
mips                             allyesconfig
m68k                             allyesconfig
x86_64                        randconfig-a015
i386                          randconfig-a014
sh                               allmodconfig
x86_64                        randconfig-a002
x86_64                              defconfig
x86_64                        randconfig-a013
i386                                defconfig
i386                          randconfig-a001
x86_64                          rhel-8.3-func
i386                          randconfig-a003
x86_64                        randconfig-a006
arc                  randconfig-r043-20220908
x86_64                        randconfig-a004
i386                          randconfig-a005
arm                                 defconfig
i386                          randconfig-a012
i386                          randconfig-a016
x86_64                         rhel-8.3-kunit
x86_64                           rhel-8.3-kvm
arm                              allyesconfig
x86_64                    rhel-8.3-kselftests
x86_64                           rhel-8.3-syz
x86_64                               rhel-8.3
i386                             allyesconfig
arm64                            allyesconfig
arc                  randconfig-r043-20220907
i386                          randconfig-c001
s390                 randconfig-r044-20220908
riscv                randconfig-r042-20220908
x86_64                           allyesconfig
ia64                             allmodconfig
csky                              allnoconfig
arc                               allnoconfig
alpha                             allnoconfig
riscv                             allnoconfig
m68k                       m5275evb_defconfig
sh                         ap325rxa_defconfig
arm                        cerfcube_defconfig
powerpc                         wii_defconfig
xtensa                  cadence_csp_defconfig
arm                        mvebu_v7_defconfig

clang tested configs:
x86_64                        randconfig-a012
i386                          randconfig-a013
x86_64                        randconfig-a014
x86_64                        randconfig-a001
i386                          randconfig-a002
x86_64                        randconfig-a003
x86_64                        randconfig-a016
i386                          randconfig-a011
x86_64                        randconfig-a005
hexagon              randconfig-r041-20220907
i386                          randconfig-a015
hexagon              randconfig-r041-20220908
i386                          randconfig-a006
i386                          randconfig-a004
riscv                randconfig-r042-20220907
hexagon              randconfig-r045-20220908
hexagon              randconfig-r045-20220907
s390                 randconfig-r044-20220907
x86_64                          rhel-8.3-rust
powerpc                        icon_defconfig
arm                       spear13xx_defconfig
arm                         palmz72_defconfig
powerpc                 mpc832x_rdb_defconfig
x86_64                        randconfig-k001

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/631a6e9c.D4HRv8SAAnTyu/QX%25lkp%40intel.com.
