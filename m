Return-Path: <kasan-dev+bncBC7OD3FKWUERBIOVYOPAMGQE3IAZ6ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E501267ABEA
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:38:58 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id w15-20020a056830144f00b00687ec8c75cdsf1330943otp.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:38:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635937; cv=pass;
        d=google.com; s=arc-20160816;
        b=b3YPMn+Y8htyQ0pb8fBfTbXKc/stihKwQ6Yen9EaDbdb6xZymuNq/W64AuSFNEm4gS
         FIHyqLt/LQ6YhqN1PuhdNPCi5rtSXKTByyiwnX8MrB6U96pTJLYGUVUhXRlylXItrjUb
         lpx2TNmJOgGjnkCeRx16bL0SF0klxunPGUrJ+E8Annnz5yWGMpZrO3fWNmS6TC4tic+h
         g+cE8i2+GZyrIhpR6ljryoTZVKs7W82WW3HQ7b0lE2km33Ji9jHogy4Hs5mh2+A3babQ
         C/DHLNLMzhe/KMkC17fKop5FHK5PVt5yhUlmPAWqAsji7HVaiFFhh8LZD8iLvRbBrqkg
         vi3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=aCj/qyOkLuMtFvIGhJm+MStsllY4Xj2CBnMp1xqI4Kg=;
        b=nEk3rZgLJWI9+24gBUO5HwqnDy8l4bOF/0CvQuALhPGnDlv4zqY/XshgURKiA/Cw1E
         uKigcTlBCKKmzbN3KUV70AO6pt4o7NFSvW9LT3fJAlkAiYLbHycY7XWGVRHWljBBOYLv
         rReykaWQ+OvYujMQtUNP+YX4Kpgh1Uz+Nc9FNra6s6PCRzgd79G8wkbyAXHTD2dkWAej
         NEnL0TujNsDeamf3Hz4HNxWIWP9NEfC2yfBJ/AgxHTEsORbQYf188h3ssiZWPi0OEVZR
         CdcupEA2s7ZCEJYhJ+ip/duGP9v8z51agWD1cZfaZhaYXTdlk2a47iN6NSAoVZO778Gl
         B7kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lB4btchv;
       spf=pass (google.com: domain of 3oorqywykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3oOrQYwYKCd0RTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aCj/qyOkLuMtFvIGhJm+MStsllY4Xj2CBnMp1xqI4Kg=;
        b=SlRgM4s47ZCUEHPZ9CwMHzRDCs6CsdmpCubQVp08CXuyq/T5e7lJLqebZdjK2HUYIG
         KIEXP4P6wnYmvbaZzP9fhDdnt+4tlTSjX1F47ZmBuYNmnPVxTENsUofl8/6ZQmb6tHIk
         fsDo6IUc7Gn+vGdXEREvT4rjYbl5HKIFkrhysc0RcGvwmh2GvfAomgI0ew66vEbHiyJ8
         cvUQV0QUhwP60z0eLWIxJ0V3ON8QlPs3c8Lkpto+NGuXLOPY713AUvYphorLu06BOn43
         zOytQFSwaDckqdkbsi4vCJHggOw43sEANC4i6R0V+iVEvRyjc+08a5ABSSk21gX2cxES
         37qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aCj/qyOkLuMtFvIGhJm+MStsllY4Xj2CBnMp1xqI4Kg=;
        b=5pMFMm8tl6z4xnt5c/Bp/x0QIcebKuFtgaIDw2FPrznWPOd3FRBarOQMGGi0p+L684
         24o/hrjYmO8DoHGh87ZgBFv3ujOipy2auQXWHjzjJYPRDRdR1M569hBUec94Jhct+PW1
         HakpZQO8yQlsD2Y+hIVqmGRGFdue7Hp0fSdulhZar0XI7IjnAlF5Zg+IE8lpCjG5Jnum
         0KNZdMzHOLCdix4d5C4VaAFEazEM2WQgFx7w7qcFI/dcwwTwtIFkwNGJKlYhMyjah8ci
         mMfJSPBRwHtq9AgMoAFkQTpXq/fZLiHCHGGjQ7DvMGLhjuHIFZCtheS4F1eCS5aH9tYj
         XBfA==
X-Gm-Message-State: AFqh2krOZqFCTgQf3zzoMyKFdw3zZv6zV4BfGSCIcsFFw6iv8IHj/VMn
	h9IcTkNQgt52k4Z+KLzcoF4=
X-Google-Smtp-Source: AMrXdXt4/5JzhtAp+/aiDT0zEiK6+/OVnVJKSsZwCYYJ8SEuv3Y+KilN5PV39RF+RIUzSLZJJvLx4Q==
X-Received: by 2002:a05:6870:5d93:b0:15e:ca6a:913 with SMTP id fu19-20020a0568705d9300b0015eca6a0913mr2689015oab.204.1674635937317;
        Wed, 25 Jan 2023 00:38:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:110f:0:b0:35b:2747:ee0f with SMTP id 15-20020aca110f000000b0035b2747ee0fls5456747oir.3.-pod-prod-gmail;
 Wed, 25 Jan 2023 00:38:57 -0800 (PST)
X-Received: by 2002:a05:6808:1825:b0:35e:401a:7824 with SMTP id bh37-20020a056808182500b0035e401a7824mr20221335oib.51.1674635936912;
        Wed, 25 Jan 2023 00:38:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635936; cv=none;
        d=google.com; s=arc-20160816;
        b=xysloz7+QxHWw9OuL7xPLvR841KZamF/W4132ShjXE68hj8BnBd6Z/I6XP7ala6ID6
         JzCnkLmq3ZNLANBYwkK1O47uVmK/OvyVwLyU5Ap9pAAqKE51zBznxnn1faRF/2kF5GP0
         +DkqM5Vs3PKdfxbJFaA+YnKEzd+W+4Jf3TJv7aMC7axtsupiqPB1XKbYWuKiYdp1g5AW
         oZ20n1wSIPP65QlQG7iwevNP4sqDk+6hhsDBQ8CWU1M71Udyy9/XeberoD385qTBXFCq
         Rox1ozTzbhlPwoAjaYMTIl0ZoeA0pnL/hjgh3sK7LAm3//IVa+2HtD2NXICO8CKPOb3o
         bEKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=gBh0+9Ej4fdZiBcL1FEtjjBddEyxpct0JkyXcSRf3Wg=;
        b=P4jRsj/jH41ZHTCfuF2xAbl5c7agALt10sj/r3XNZ8SPlrfR/SpEcKWHjNR5OibXf5
         N1oPLsM5Nd4hwxAQi6YRRueJKjLx4d54wGosxEzsF23I+9RN1gLJzOxppI71TXZbo7Ri
         5yVqgn8qgKxFhSX0WBWAcfgMRPCfN+UMKqNKjgFAuf20Uk/sioV3TUesDIFV8jBikPt2
         0HOIODse4fjvPpWsCJNJOJewEDc9/8+H3TxsTEmyGH7ktbMceGpPrMfx/gt5AszKJhxL
         lSkVl1LNC3Sf0VlQj49wBKEMMSdZyA8niC6/CEbQuezUSdKEvqU3X/KZZjL4f/RcRbgW
         ZFKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lB4btchv;
       spf=pass (google.com: domain of 3oorqywykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3oOrQYwYKCd0RTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id bu7-20020a0568300d0700b0066fe878940fsi821010otb.5.2023.01.25.00.38.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:38:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oorqywykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-4c8e781bc0aso183719437b3.22
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:38:56 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:f7b0:20e8:ce66:f98])
 (user=surenb job=sendgmr) by 2002:a05:6902:34f:b0:6f9:7bf9:8fc7 with SMTP id
 e15-20020a056902034f00b006f97bf98fc7mr3373858ybs.279.1674635936246; Wed, 25
 Jan 2023 00:38:56 -0800 (PST)
Date: Wed, 25 Jan 2023 00:38:45 -0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.405.gd4c25cc71f-goog
Message-ID: <20230125083851.27759-1-surenb@google.com>
Subject: [PATCH v2 0/6] introduce vm_flags modifier functions
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: michel@lespinasse.org, jglisse@google.com, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, mgorman@techsingularity.net, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, peterz@infradead.org, 
	ldufour@linux.ibm.com, paulmck@kernel.org, luto@kernel.org, 
	songliubraving@fb.com, peterx@redhat.com, david@redhat.com, 
	dhowells@redhat.com, hughd@google.com, bigeasy@linutronix.de, 
	kent.overstreet@linux.dev, punit.agrawal@bytedance.com, lstoakes@gmail.com, 
	peterjung1337@gmail.com, rientjes@google.com, axelrasmussen@google.com, 
	joelaf@google.com, minchan@google.com, jannh@google.com, shakeelb@google.com, 
	tatashin@google.com, edumazet@google.com, gthelen@google.com, 
	gurua@google.com, arjunroy@google.com, soheil@google.com, 
	hughlynch@google.com, leewalsh@google.com, posk@google.com, will@kernel.org, 
	aneesh.kumar@linux.ibm.com, npiggin@gmail.com, chenhuacai@kernel.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, qianweili@huawei.com, wangzhou1@hisilicon.com, 
	herbert@gondor.apana.org.au, davem@davemloft.net, vkoul@kernel.org, 
	airlied@gmail.com, daniel@ffwll.ch, maarten.lankhorst@linux.intel.com, 
	mripard@kernel.org, tzimmermann@suse.de, l.stach@pengutronix.de, 
	krzysztof.kozlowski@linaro.org, patrik.r.jakobsson@gmail.com, 
	matthias.bgg@gmail.com, robdclark@gmail.com, quic_abhinavk@quicinc.com, 
	dmitry.baryshkov@linaro.org, tomba@kernel.org, hjc@rock-chips.com, 
	heiko@sntech.de, ray.huang@amd.com, kraxel@redhat.com, sre@kernel.org, 
	mcoquelin.stm32@gmail.com, alexandre.torgue@foss.st.com, tfiga@chromium.org, 
	m.szyprowski@samsung.com, mchehab@kernel.org, dimitri.sivanich@hpe.com, 
	zhangfei.gao@linaro.org, jejb@linux.ibm.com, martin.petersen@oracle.com, 
	dgilbert@interlog.com, hdegoede@redhat.com, mst@redhat.com, 
	jasowang@redhat.com, alex.williamson@redhat.com, deller@gmx.de, 
	jayalk@intworks.biz, viro@zeniv.linux.org.uk, nico@fluxnic.net, 
	xiang@kernel.org, chao@kernel.org, tytso@mit.edu, adilger.kernel@dilger.ca, 
	miklos@szeredi.hu, mike.kravetz@oracle.com, muchun.song@linux.dev, 
	bhe@redhat.com, andrii@kernel.org, yoshfuji@linux-ipv6.org, 
	dsahern@kernel.org, kuba@kernel.org, pabeni@redhat.com, perex@perex.cz, 
	tiwai@suse.com, haojian.zhuang@gmail.com, robert.jarzmik@free.fr, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linuxppc-dev@lists.ozlabs.org, x86@kernel.org, linux-kernel@vger.kernel.org, 
	linux-graphics-maintainer@vmware.com, linux-ia64@vger.kernel.org, 
	linux-arch@vger.kernel.org, loongarch@lists.linux.dev, kvm@vger.kernel.org, 
	linux-s390@vger.kernel.org, linux-sgx@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org, 
	linux-crypto@vger.kernel.org, nvdimm@lists.linux.dev, 
	dmaengine@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, etnaviv@lists.freedesktop.org, 
	linux-samsung-soc@vger.kernel.org, intel-gfx@lists.freedesktop.org, 
	linux-mediatek@lists.infradead.org, linux-arm-msm@vger.kernel.org, 
	freedreno@lists.freedesktop.org, linux-rockchip@lists.infradead.org, 
	linux-tegra@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	xen-devel@lists.xenproject.org, linux-stm32@st-md-mailman.stormreply.com, 
	linux-rdma@vger.kernel.org, linux-media@vger.kernel.org, 
	linux-accelerators@lists.ozlabs.org, sparclinux@vger.kernel.org, 
	linux-scsi@vger.kernel.org, linux-staging@lists.linux.dev, 
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org, 
	netdev@vger.kernel.org, linux-fbdev@vger.kernel.org, linux-aio@kvack.org, 
	linux-fsdevel@vger.kernel.org, linux-erofs@lists.ozlabs.org, 
	linux-ext4@vger.kernel.org, devel@lists.orangefs.org, 
	kexec@lists.infradead.org, linux-xfs@vger.kernel.org, bpf@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	selinux@vger.kernel.org, alsa-devel@alsa-project.org, kernel-team@android.com, 
	surenb@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lB4btchv;       spf=pass
 (google.com: domain of 3oorqywykcd0rtqdmafnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3oOrQYwYKCd0RTQDMAFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

This patchset was originally published as a part of per-VMA locking [1] and
was split after suggestion that it's viable on its own and to facilitate
the review process. It is now a preprequisite for the next version of per-VMA
lock patchset, which reuses vm_flags modifier functions to lock the VMA when
vm_flags are being updated.

VMA vm_flags modifications are usually done under exclusive mmap_lock
protection because this attrubute affects other decisions like VMA merging
or splitting and races should be prevented. Introduce vm_flags modifier
functions to enforce correct locking.

[1] https://lore.kernel.org/all/20230109205336.3665937-1-surenb@google.com/

The patchset applies cleanly over mm-unstable branch of mm tree.

My apologies for an extremely large distribution list. The patch touches
lots of files and many are in arch/ and drivers/.

Suren Baghdasaryan (6):
  mm: introduce vma->vm_flags modifier functions
  mm: replace VM_LOCKED_CLEAR_MASK with VM_LOCKED_MASK
  mm: replace vma->vm_flags direct modifications with modifier calls
  mm: replace vma->vm_flags indirect modification in ksm_madvise
  mm: introduce mod_vm_flags_nolock and use it in untrack_pfn
  mm: export dump_mm()

 arch/arm/kernel/process.c                     |  2 +-
 arch/ia64/mm/init.c                           |  8 +--
 arch/loongarch/include/asm/tlb.h              |  2 +-
 arch/powerpc/kvm/book3s_hv_uvmem.c            |  5 +-
 arch/powerpc/kvm/book3s_xive_native.c         |  2 +-
 arch/powerpc/mm/book3s64/subpage_prot.c       |  2 +-
 arch/powerpc/platforms/book3s/vas-api.c       |  2 +-
 arch/powerpc/platforms/cell/spufs/file.c      | 14 ++---
 arch/s390/mm/gmap.c                           |  8 +--
 arch/x86/entry/vsyscall/vsyscall_64.c         |  2 +-
 arch/x86/kernel/cpu/sgx/driver.c              |  2 +-
 arch/x86/kernel/cpu/sgx/virt.c                |  2 +-
 arch/x86/mm/pat/memtype.c                     | 14 +++--
 arch/x86/um/mem_32.c                          |  2 +-
 drivers/acpi/pfr_telemetry.c                  |  2 +-
 drivers/android/binder.c                      |  3 +-
 drivers/char/mspec.c                          |  2 +-
 drivers/crypto/hisilicon/qm.c                 |  2 +-
 drivers/dax/device.c                          |  2 +-
 drivers/dma/idxd/cdev.c                       |  2 +-
 drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c       |  2 +-
 drivers/gpu/drm/amd/amdkfd/kfd_chardev.c      |  4 +-
 drivers/gpu/drm/amd/amdkfd/kfd_doorbell.c     |  4 +-
 drivers/gpu/drm/amd/amdkfd/kfd_events.c       |  4 +-
 drivers/gpu/drm/amd/amdkfd/kfd_process.c      |  4 +-
 drivers/gpu/drm/drm_gem.c                     |  2 +-
 drivers/gpu/drm/drm_gem_dma_helper.c          |  3 +-
 drivers/gpu/drm/drm_gem_shmem_helper.c        |  2 +-
 drivers/gpu/drm/drm_vm.c                      |  8 +--
 drivers/gpu/drm/etnaviv/etnaviv_gem.c         |  2 +-
 drivers/gpu/drm/exynos/exynos_drm_gem.c       |  4 +-
 drivers/gpu/drm/gma500/framebuffer.c          |  2 +-
 drivers/gpu/drm/i810/i810_dma.c               |  2 +-
 drivers/gpu/drm/i915/gem/i915_gem_mman.c      |  4 +-
 drivers/gpu/drm/mediatek/mtk_drm_gem.c        |  2 +-
 drivers/gpu/drm/msm/msm_gem.c                 |  2 +-
 drivers/gpu/drm/omapdrm/omap_gem.c            |  3 +-
 drivers/gpu/drm/rockchip/rockchip_drm_gem.c   |  3 +-
 drivers/gpu/drm/tegra/gem.c                   |  5 +-
 drivers/gpu/drm/ttm/ttm_bo_vm.c               |  3 +-
 drivers/gpu/drm/virtio/virtgpu_vram.c         |  2 +-
 drivers/gpu/drm/vmwgfx/vmwgfx_ttm_glue.c      |  2 +-
 drivers/gpu/drm/xen/xen_drm_front_gem.c       |  3 +-
 drivers/hsi/clients/cmt_speech.c              |  2 +-
 drivers/hwtracing/intel_th/msu.c              |  2 +-
 drivers/hwtracing/stm/core.c                  |  2 +-
 drivers/infiniband/hw/hfi1/file_ops.c         |  4 +-
 drivers/infiniband/hw/mlx5/main.c             |  4 +-
 drivers/infiniband/hw/qib/qib_file_ops.c      | 13 +++--
 drivers/infiniband/hw/usnic/usnic_ib_verbs.c  |  2 +-
 .../infiniband/hw/vmw_pvrdma/pvrdma_verbs.c   |  2 +-
 .../common/videobuf2/videobuf2-dma-contig.c   |  2 +-
 .../common/videobuf2/videobuf2-vmalloc.c      |  2 +-
 drivers/media/v4l2-core/videobuf-dma-contig.c |  2 +-
 drivers/media/v4l2-core/videobuf-dma-sg.c     |  4 +-
 drivers/media/v4l2-core/videobuf-vmalloc.c    |  2 +-
 drivers/misc/cxl/context.c                    |  2 +-
 drivers/misc/habanalabs/common/memory.c       |  2 +-
 drivers/misc/habanalabs/gaudi/gaudi.c         |  4 +-
 drivers/misc/habanalabs/gaudi2/gaudi2.c       |  8 +--
 drivers/misc/habanalabs/goya/goya.c           |  4 +-
 drivers/misc/ocxl/context.c                   |  4 +-
 drivers/misc/ocxl/sysfs.c                     |  2 +-
 drivers/misc/open-dice.c                      |  4 +-
 drivers/misc/sgi-gru/grufile.c                |  4 +-
 drivers/misc/uacce/uacce.c                    |  2 +-
 drivers/sbus/char/oradax.c                    |  2 +-
 drivers/scsi/cxlflash/ocxl_hw.c               |  2 +-
 drivers/scsi/sg.c                             |  2 +-
 .../staging/media/atomisp/pci/hmm/hmm_bo.c    |  2 +-
 drivers/staging/media/deprecated/meye/meye.c  |  4 +-
 .../media/deprecated/stkwebcam/stk-webcam.c   |  2 +-
 drivers/target/target_core_user.c             |  2 +-
 drivers/uio/uio.c                             |  2 +-
 drivers/usb/core/devio.c                      |  3 +-
 drivers/usb/mon/mon_bin.c                     |  3 +-
 drivers/vdpa/vdpa_user/iova_domain.c          |  2 +-
 drivers/vfio/pci/vfio_pci_core.c              |  2 +-
 drivers/vhost/vdpa.c                          |  2 +-
 drivers/video/fbdev/68328fb.c                 |  2 +-
 drivers/video/fbdev/core/fb_defio.c           |  4 +-
 drivers/xen/gntalloc.c                        |  2 +-
 drivers/xen/gntdev.c                          |  4 +-
 drivers/xen/privcmd-buf.c                     |  2 +-
 drivers/xen/privcmd.c                         |  4 +-
 fs/aio.c                                      |  2 +-
 fs/cramfs/inode.c                             |  2 +-
 fs/erofs/data.c                               |  2 +-
 fs/exec.c                                     |  4 +-
 fs/ext4/file.c                                |  2 +-
 fs/fuse/dax.c                                 |  2 +-
 fs/hugetlbfs/inode.c                          |  4 +-
 fs/orangefs/file.c                            |  3 +-
 fs/proc/task_mmu.c                            |  2 +-
 fs/proc/vmcore.c                              |  3 +-
 fs/userfaultfd.c                              |  2 +-
 fs/xfs/xfs_file.c                             |  2 +-
 include/linux/mm.h                            | 51 +++++++++++++++++--
 include/linux/mm_types.h                      |  8 ++-
 include/linux/pgtable.h                       |  5 +-
 kernel/bpf/ringbuf.c                          |  4 +-
 kernel/bpf/syscall.c                          |  4 +-
 kernel/events/core.c                          |  2 +-
 kernel/fork.c                                 |  2 +-
 kernel/kcov.c                                 |  2 +-
 kernel/relay.c                                |  2 +-
 mm/debug.c                                    |  1 +
 mm/hugetlb.c                                  |  4 +-
 mm/khugepaged.c                               |  2 +
 mm/ksm.c                                      |  2 +
 mm/madvise.c                                  |  2 +-
 mm/memory.c                                   | 19 +++----
 mm/memremap.c                                 |  4 +-
 mm/mlock.c                                    | 12 ++---
 mm/mmap.c                                     | 32 +++++++-----
 mm/mprotect.c                                 |  2 +-
 mm/mremap.c                                   |  8 +--
 mm/nommu.c                                    | 11 ++--
 mm/secretmem.c                                |  2 +-
 mm/shmem.c                                    |  2 +-
 mm/vmalloc.c                                  |  2 +-
 net/ipv4/tcp.c                                |  4 +-
 security/selinux/selinuxfs.c                  |  6 +--
 sound/core/oss/pcm_oss.c                      |  2 +-
 sound/core/pcm_native.c                       |  9 ++--
 sound/soc/pxa/mmp-sspa.c                      |  2 +-
 sound/usb/usx2y/us122l.c                      |  4 +-
 sound/usb/usx2y/usX2Yhwdep.c                  |  2 +-
 sound/usb/usx2y/usx2yhwdeppcm.c               |  2 +-
 129 files changed, 292 insertions(+), 233 deletions(-)

-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125083851.27759-1-surenb%40google.com.
