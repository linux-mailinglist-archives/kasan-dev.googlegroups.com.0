Return-Path: <kasan-dev+bncBC4LXIPCY4NRBF5QXSWQMGQEQIX6W4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 676CC837E2B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 02:36:24 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-429be5ecc87sf45459161cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 17:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705973783; cv=pass;
        d=google.com; s=arc-20160816;
        b=qn1FGREMZ1Q28aEnHhV3S4KcQOuGdqDkY4BhmRAcU8h0ApNOIHkocc1NufdP36X7g4
         s9hePy6NYTdPjPva5fYkgQMxIe4q3B6B36El+T99OPiW5z5EGtsTz4sv6gzD4EN0bube
         R3o3INmUCjHRXV0+6jRSb0OTVEF+2CDRe0wN8wJq2C0Qid5Hwl1CHP4LRdzpgMINvfeK
         FYEtTicGxBZ2zBNxDU3sYvIAd8C59XxWacr674RU/AOlpMUg6PxV2LyM2T4CyDloKMa6
         kNkxjkEhPB+Ho8HcudGSHwDSjwGW+E5nOKd3Nmlj1b2g3yS2+JDb3OA5I/p/IygMbKAw
         /CnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:subject:cc:to
         :from:date:mime-version:sender:dkim-signature;
        bh=w5/bpMte2+VKLnKXYEcHlgbPdWopaN7nSR5dm8BjBSM=;
        fh=H3gNuLWK5uC5LdW/EOvoaH6Ljs0gqAayG5dG0IHihHM=;
        b=pLTBvozhAGbUuuAQpZbzbIap5QTiqVsAf76V6ymwwr+80rxHrAnVHdMse9w+rynPpk
         ML1udYrkam5qYbrfjAX0rOSPuOVHHPdKLpM6RD7i0oUThsrgJcy7UTnaCNXykCTM+smR
         fMBLsWPOxfqZqQSOtxWP5oWkW+BlzikNm4RdWDDiN5jVQJMmXNvqvhrkeNrk1590TiJe
         anxr/A+wZm79vKdWSATgt/4/9FBDLjsBAxkKGKl8NM4Cku5eZo2vgwvi6QgZShJSLcfg
         1HCpL0sMZ3HruawnqfoPnsF4Pr1xGLD85CSf6w+IZVLUfqN6RR6glWe9ukPtTymDT4Zn
         7Ntw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IgVyfqd4;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705973783; x=1706578583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=w5/bpMte2+VKLnKXYEcHlgbPdWopaN7nSR5dm8BjBSM=;
        b=NB33N+zHIItN4Bun3aPJVHB44YUKZUEzxw7dgEwtFxfJwv6hK75oAUUw+xDjMu2XtW
         T6yv+/39rROnk36Kc0kmnGNARrwfiUNnc9zKL00z1Q7ANh3NZOEEciDfOcoICTN9kR6k
         ql0x/IQHzHvWnLqiStY0RBF88cnFo8x2vna08OHa0qY28E5FurZDptpk2uBGxzdaq08j
         0aKOH2ykjLT6+JlPzQg1CJLhv1PqWsnteiGWvPbZsqWY7X6D8CP5WF3eVjXIxf7v/1f7
         dyH6klN7xYUD5HVUXj/PBt2ZUKhbsB6/6nxpkuTQ1xB8O8KX//Z8VuFpMpAi0156gi7O
         eTtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705973783; x=1706578583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:x-beenthere:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w5/bpMte2+VKLnKXYEcHlgbPdWopaN7nSR5dm8BjBSM=;
        b=J4Mdxws+gcfFoQPY6zOwzMd+A4FNPoYZhVfj1nbvyucszy19BYPIkmtlHWrJfxwO7p
         kHF2/Wsct4Yx3f9uUmmMOnmZ7hIJDJ7Uw89ugN/tVK1nm6xwFBYQNBOWyB5g/JPDO7Z/
         ytTEddVhHv1aQQMqpNn61vxPZRkCspxipNg77z1T5VVeeKoUHslJ4LcS35U4uXBKsdGj
         ADPbNf8Aka3mm4AXmKyVg11WZ/8kZ9ESOnb2KOIANuwiT6jg4820G6cmWPJZACNyGfm/
         crLCFbd9xD6OTYIs+P42AJ2uAaJyCaCAAhI4dt0h8AaRTt1e/XvVkE9Tp02TYsyYvxUr
         Mgrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwOejCzZNK4una11S5uWlTRPr/QHP8XJ3QJaadm0/RCiWGOq83n
	tCropco9z1xiHZwUN7YdRwTpInm0t4Gj6IIMN11FnKW9GA+1AxWL
X-Google-Smtp-Source: AGHT+IGUmeZCpfvunXxw6AW//UcNED404IGKh6u530CG61aTZmtw/plq/GmXRC5U79mOJ0znmFaZUw==
X-Received: by 2002:a05:622a:1a15:b0:42a:4de9:4a94 with SMTP id f21-20020a05622a1a1500b0042a4de94a94mr116341qtb.52.1705973783183;
        Mon, 22 Jan 2024 17:36:23 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c41:0:b0:42a:4b71:9efc with SMTP id o1-20020ac87c41000000b0042a4b719efcls430237qtv.2.-pod-prod-08-us;
 Mon, 22 Jan 2024 17:36:22 -0800 (PST)
X-Received: by 2002:a05:620a:564c:b0:783:6ab2:4421 with SMTP id vw12-20020a05620a564c00b007836ab24421mr5080388qkn.11.1705973782306;
        Mon, 22 Jan 2024 17:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705973782; cv=none;
        d=google.com; s=arc-20160816;
        b=y514iWuoIRP5NZvRZVH9VpMq7piuspJNzBKAVLUf3DYrafz5zKqqEcNQFOmwtgapj2
         /7h3fUd+F6lR6gtklzWd4AB6R1mki3A/ucgph1Sy+2h+4rRj7cT0djxQobQJEdbQTqLq
         bSU+AukmY7Ev+KJ8wDdJyU09iNtj+BHnC6LTP+ReOr8cgr94ZK9Anp5803xu5FN2dEeh
         qfnoXB7fDlUN7mI2R7PqZSBSBQmtdbWya1RyCAVTmRoK254diIfdRBQu8lHtQeZzKfGB
         ALQqeKPZ14cUlo+dyOKXuOMgAXEieVU4tioH59SZo+1BgegrNLSCRdGI6HSOB0CIMcn6
         qhXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=1ayR4Uri6jmUl4FQ65of0XeUiY2nOhxNb6x4E6WfqX4=;
        fh=H3gNuLWK5uC5LdW/EOvoaH6Ljs0gqAayG5dG0IHihHM=;
        b=XL0qA5IldVybBKUlyNHmShEgalHaqN9ZxveHkfWTnxHn+n9V4p6X1b7+hmOi0NMzJ1
         WShyF2JHuIQ8Fm1czRPOmxnOtm5kQ05KZA3sYyp72xXauSm7Zm1uA7HrLVKtTmv4wSMw
         C3qJFAZpyKvVZgq0oNrQ+emcMhooQNvN1kLJ3bwL1KQEHxU52Lj5y2eao1cLxYt1VpFg
         vSKgDwlJBZB9stRlPSJSAAsN99Gef9xTOaygvZMQUp1MWyylT6YvFzH073khOxz+aLYY
         LEcV2CIT+wX38VNL6nBiU7ng8QkNECp4i2D2W1/AIsxU77a263l4E+F9gNM2KAnvSRQs
         HPcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IgVyfqd4;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id tn12-20020a05620a3c0c00b0078329d079ffsi414747qkn.5.2024.01.22.17.36.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jan 2024 17:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6600,9927,10961"; a="398531564"
X-IronPort-AV: E=Sophos;i="6.05,212,1701158400"; 
   d="scan'208";a="398531564"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Jan 2024 17:36:20 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10961"; a="856145765"
X-IronPort-AV: E=Sophos;i="6.05,212,1701158400"; 
   d="scan'208";a="856145765"
Received: from lkp-server01.sh.intel.com (HELO 961aaaa5b03c) ([10.239.97.150])
  by fmsmga004.fm.intel.com with ESMTP; 22 Jan 2024 17:36:17 -0800
Received: from kbuild by 961aaaa5b03c with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rS5i3-00074a-2k;
	Tue, 23 Jan 2024 01:36:15 +0000
Date: Tue, 23 Jan 2024 09:36:05 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 amd-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
 etnaviv@lists.freedesktop.org, kasan-dev@googlegroups.com,
 linux-bcachefs@vger.kernel.org, linux-usb@vger.kernel.org,
 netdev@vger.kernel.org
Subject: [linux-next:master] BUILD REGRESSION
 319fbd8fc6d339e0a1c7b067eed870c518a13a02
Message-ID: <202401230901.Q0DlNgAU-lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=IgVyfqd4;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted
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
branch HEAD: 319fbd8fc6d339e0a1c7b067eed870c518a13a02  Add linux-next specific files for 20240122

Unverified Error/Warning (likely false positive, please contact us if interested):

drivers/gpu/drm/etnaviv/etnaviv_drv.c:614:3-14: ERROR: probable double put.

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arc-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arc-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arm-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arm-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- csky-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- csky-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- csky-randconfig-002-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- loongarch-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- loongarch-defconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- loongarch-randconfig-r122-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- microblaze-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- microblaze-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- mips-allyesconfig
|   |-- (.ref.text):relocation-truncated-to-fit:R_MIPS_26-against-start_secondary
|   |-- (.text):relocation-truncated-to-fit:R_MIPS_26-against-kernel_entry
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- openrisc-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- parisc-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- parisc-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- riscv-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- riscv-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- s390-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- s390-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- sh-randconfig-r131-20240122
|   |-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|   `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-sum-got-unsigned-int-assigned-csum
|-- sparc-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- sparc64-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- sparc64-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- sparc64-randconfig-r123-20240122
|   `-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|-- um-randconfig-r111-20240122
|   `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-sum-got-unsigned-int-assigned-csum
|-- x86_64-randconfig-121-20240122
|   `-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
`-- x86_64-randconfig-r133-20240122
    `-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-csum-got-unsigned-int-assigned-csum
clang_recent_errors
|-- arm64-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arm64-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arm64-randconfig-002-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- arm64-randconfig-004-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- i386-randconfig-053-20240122
|   `-- drivers-net-ethernet-broadcom-bnxt-bnxt.c:WARNING:atomic_dec_and_test-variation-before-object-free-at-line-.
|-- i386-randconfig-061-20240122
|   `-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|-- i386-randconfig-062-20240122
|   `-- drivers-usb-gadget-function-f_ncm.c:sparse:sparse:incorrect-type-in-assignment-(different-base-types)-expected-unsigned-short-usertype-max_segment_size-got-restricted-__le16-usertype
|-- i386-randconfig-141-20240122
|   |-- fs-bcachefs-btree_locking.c-bch2_trans_relock()-warn:passing-zero-to-PTR_ERR
|   |-- fs-bcachefs-buckets.c-bch2_trans_account_disk_usage_change()-error:we-previously-assumed-trans-disk_res-could-be-null-(see-line-)
|   `-- mm-huge_memory.c-thpsize_create()-warn:Calling-kobject_put-get-with-state-initialized-unset-from-line:
|-- powerpc-randconfig-r113-20240122
|   |-- lib-checksum_kunit.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-__wsum-usertype-sum-got-unsigned-int-assigned-csum
|   `-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(different-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-int-usertype-size
|-- riscv-randconfig-001-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- x86_64-allmodconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- x86_64-allyesconfig
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- x86_64-buildonly-randconfig-001-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- x86_64-randconfig-014-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- x86_64-randconfig-074-20240122
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-amdgpu_dm-amdgpu_dm_crtc.c:warning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Documentation-doc-guide-kernel-doc.rst
|-- x86_64-randconfig-102-20240122
|   `-- drivers-gpu-drm-etnaviv-etnaviv_drv.c:ERROR:probable-double-put.
`-- x86_64-randconfig-161-20240122
    |-- mm-kasan-kasan_test.c-mempool_double_free_helper()-error:double-free-of-elem
    `-- mm-kasan-kasan_test.c-mempool_uaf_helper()-warn:passing-freed-memory-elem

elapsed time: 1454m

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
arc                   randconfig-001-20240122   gcc  
arc                   randconfig-002-20240122   gcc  
arm                              allmodconfig   gcc  
arm                               allnoconfig   gcc  
arm                              allyesconfig   gcc  
arm                                 defconfig   clang
arm                           h3600_defconfig   gcc  
arm                        neponset_defconfig   clang
arm                   randconfig-001-20240122   clang
arm                   randconfig-002-20240122   clang
arm                   randconfig-003-20240122   clang
arm                   randconfig-004-20240122   clang
arm                           stm32_defconfig   gcc  
arm                         vf610m4_defconfig   gcc  
arm64                            allmodconfig   clang
arm64                             allnoconfig   gcc  
arm64                               defconfig   gcc  
arm64                 randconfig-001-20240122   clang
arm64                 randconfig-002-20240122   clang
arm64                 randconfig-003-20240122   clang
arm64                 randconfig-004-20240122   clang
csky                             allmodconfig   gcc  
csky                              allnoconfig   gcc  
csky                             allyesconfig   gcc  
csky                                defconfig   gcc  
csky                  randconfig-001-20240122   gcc  
csky                  randconfig-002-20240122   gcc  
hexagon                          allmodconfig   clang
hexagon                           allnoconfig   clang
hexagon                          allyesconfig   clang
hexagon                             defconfig   clang
hexagon               randconfig-001-20240122   clang
hexagon               randconfig-002-20240122   clang
i386                             allmodconfig   clang
i386                              allnoconfig   clang
i386                             allyesconfig   clang
i386         buildonly-randconfig-001-20240122   clang
i386         buildonly-randconfig-002-20240122   clang
i386         buildonly-randconfig-003-20240122   clang
i386         buildonly-randconfig-004-20240122   clang
i386         buildonly-randconfig-005-20240122   clang
i386         buildonly-randconfig-006-20240122   clang
i386                                defconfig   gcc  
i386                  randconfig-001-20240122   clang
i386                  randconfig-002-20240122   clang
i386                  randconfig-003-20240122   clang
i386                  randconfig-004-20240122   clang
i386                  randconfig-005-20240122   clang
i386                  randconfig-006-20240122   clang
i386                  randconfig-011-20240122   gcc  
i386                  randconfig-012-20240122   gcc  
i386                  randconfig-013-20240122   gcc  
i386                  randconfig-014-20240122   gcc  
i386                  randconfig-015-20240122   gcc  
i386                  randconfig-016-20240122   gcc  
loongarch                        allmodconfig   gcc  
loongarch                         allnoconfig   gcc  
loongarch                           defconfig   gcc  
loongarch             randconfig-001-20240122   gcc  
loongarch             randconfig-002-20240122   gcc  
m68k                             allmodconfig   gcc  
m68k                              allnoconfig   gcc  
m68k                             allyesconfig   gcc  
m68k                                defconfig   gcc  
m68k                            mac_defconfig   gcc  
m68k                           virt_defconfig   gcc  
microblaze                       allmodconfig   gcc  
microblaze                        allnoconfig   gcc  
microblaze                       allyesconfig   gcc  
microblaze                          defconfig   gcc  
mips                              allnoconfig   clang
mips                             allyesconfig   gcc  
mips                        bcm63xx_defconfig   clang
mips                  decstation_64_defconfig   gcc  
mips                     decstation_defconfig   gcc  
mips                         rt305x_defconfig   gcc  
nios2                            allmodconfig   gcc  
nios2                             allnoconfig   gcc  
nios2                            allyesconfig   gcc  
nios2                               defconfig   gcc  
nios2                 randconfig-001-20240122   gcc  
nios2                 randconfig-002-20240122   gcc  
openrisc                          allnoconfig   gcc  
openrisc                         allyesconfig   gcc  
openrisc                            defconfig   gcc  
parisc                           allmodconfig   gcc  
parisc                            allnoconfig   gcc  
parisc                           allyesconfig   gcc  
parisc                              defconfig   gcc  
parisc                randconfig-001-20240122   gcc  
parisc                randconfig-002-20240122   gcc  
parisc64                            defconfig   gcc  
powerpc                     akebono_defconfig   clang
powerpc                          allmodconfig   clang
powerpc                           allnoconfig   gcc  
powerpc                          allyesconfig   clang
powerpc                      ppc64e_defconfig   clang
powerpc               randconfig-001-20240122   clang
powerpc               randconfig-002-20240122   clang
powerpc               randconfig-003-20240122   clang
powerpc64             randconfig-001-20240122   clang
powerpc64             randconfig-002-20240122   clang
powerpc64             randconfig-003-20240122   clang
riscv                            allmodconfig   gcc  
riscv                             allnoconfig   clang
riscv                            allyesconfig   gcc  
riscv                               defconfig   gcc  
riscv             nommu_k210_sdcard_defconfig   gcc  
riscv                 randconfig-001-20240122   clang
riscv                 randconfig-002-20240122   clang
s390                             allmodconfig   gcc  
s390                              allnoconfig   gcc  
s390                             allyesconfig   gcc  
s390                                defconfig   gcc  
s390                  randconfig-001-20240122   gcc  
s390                  randconfig-002-20240122   gcc  
sh                               alldefconfig   gcc  
sh                               allmodconfig   gcc  
sh                                allnoconfig   gcc  
sh                               allyesconfig   gcc  
sh                                  defconfig   gcc  
sh                    randconfig-001-20240122   gcc  
sh                    randconfig-002-20240122   gcc  
sh                           se7343_defconfig   gcc  
sparc                            allmodconfig   gcc  
sparc64                          allmodconfig   gcc  
sparc64                          allyesconfig   gcc  
sparc64                             defconfig   gcc  
sparc64               randconfig-001-20240122   gcc  
sparc64               randconfig-002-20240122   gcc  
um                               allmodconfig   clang
um                                allnoconfig   clang
um                               allyesconfig   clang
um                                  defconfig   gcc  
um                             i386_defconfig   gcc  
um                    randconfig-001-20240122   clang
um                    randconfig-002-20240122   clang
um                           x86_64_defconfig   gcc  
x86_64                            allnoconfig   gcc  
x86_64                           allyesconfig   clang
x86_64       buildonly-randconfig-001-20240122   clang
x86_64       buildonly-randconfig-002-20240122   clang
x86_64       buildonly-randconfig-003-20240122   clang
x86_64       buildonly-randconfig-004-20240122   clang
x86_64       buildonly-randconfig-005-20240122   clang
x86_64       buildonly-randconfig-006-20240122   clang
x86_64                              defconfig   gcc  
x86_64                randconfig-001-20240122   gcc  
x86_64                randconfig-002-20240122   gcc  
x86_64                randconfig-003-20240122   gcc  
x86_64                randconfig-004-20240122   gcc  
x86_64                randconfig-005-20240122   gcc  
x86_64                randconfig-006-20240122   gcc  
x86_64                randconfig-011-20240122   clang
x86_64                randconfig-012-20240122   clang
x86_64                randconfig-013-20240122   clang
x86_64                randconfig-014-20240122   clang
x86_64                randconfig-015-20240122   clang
x86_64                randconfig-016-20240122   clang
x86_64                randconfig-071-20240122   clang
x86_64                randconfig-072-20240122   clang
x86_64                randconfig-073-20240122   clang
x86_64                randconfig-074-20240122   clang
x86_64                randconfig-075-20240122   clang
x86_64                randconfig-076-20240122   clang
x86_64                          rhel-8.3-rust   clang
xtensa                            allnoconfig   gcc  
xtensa                randconfig-001-20240122   gcc  
xtensa                randconfig-002-20240122   gcc  
xtensa                    xip_kc705_defconfig   gcc  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401230901.Q0DlNgAU-lkp%40intel.com.
