Return-Path: <kasan-dev+bncBDZJXP7F6YLRBYEW3CSAMGQE7ELMW5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 088A373C23A
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 23:15:14 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2b479d12b31sf10939061fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 14:15:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687554913; cv=pass;
        d=google.com; s=arc-20160816;
        b=CHVFM+TACENQJeUP6Cn7pVlZaaclX6CNJrz7xpzO6QqzFFIluyjuAZBNHRFYj0G0b9
         PZdp32gke7PYV/bb1DX3REtIE5CiohpPrUFRH3EGZwpnRlt1GVT36aNXFGgb7/QwMedM
         v1dLQWR5Qhs6TpLzU/8a2KWlOgv3Dez9tzgj95zqwfHutL/CzNVH7yCUMFarKEw7hJqw
         wmG4FmgeFzunJix/5rGhp+QN6GMtL+Ti+0HDLFoDm3G1QZEfTkaj28GYC8Oku+du6Tl7
         GapTGyOqkDTT7p5oilJH6K0lohALw2U9i20w/ViJxgtpDMevIDhDhRxuoljZjNL/uX1P
         AweA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=uF4TqofLHILq9gXtCqaH4njj+8LfkEpewu0BwB4H/mQ=;
        b=H7bkv2bU4fV1WLuRisdZnFHYmJh70SBcaFwzVYj7hVCK8jprEw/6kbPcmNcvCTaWOT
         GTTGRqhfF7CCeXBMhWNDT5sAg96d/LXIFqBU2GEVNpWagXHxCuB3NHIOhr2j+lQaczED
         RQKCKwE/bTTUGoQP5OyjEexHfgJ+moXSwrw/kYln+J49xmUfhbcWbONnzzAvpu4BblJA
         U/zIoNeEax+ixZw5HL+1+5Ay/j5lDYkJsJBfjv2mkavcSYuqaa7ieNGsHdN1KPqTYFrS
         zjvBNQD0QjTM7zJObhar96+oEOPeH9yH28gASc8Y8HyetLXRE0kt87Lp8JwO3HODzUgQ
         KP4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=PQ1b0Em2;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687554913; x=1690146913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uF4TqofLHILq9gXtCqaH4njj+8LfkEpewu0BwB4H/mQ=;
        b=CJ/NRzkBtwzSC7vvWI0Se56wgmENIhTxHc+iSOanYS/EH2DK1hfSywj2hkRs6iStQy
         14nlqeNhe2hjqqSLLK4oYYyq/TZu+X/HHVNCX7l8+xi+metY6vasKrWdqoemLySSX3rz
         1OPDdurqo9Shucu0ajftTYiGJYXcHxG6PrMNVBOBTjk0arF/96d0pukKDQqf3d3dhRA1
         69IlrmK53N0aqWuFaAi1xZuZukjwTMvDnDwzv4/GrOXeZgGGMmHr7VURAyNtYq2JRsqJ
         vWosw/7Zzz5tJxB5wFcRTubIVGdzPyJ5nawjaluPhDmi8BmBHTXjO0sR+gnm6RNpm31U
         OytA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687554913; x=1690146913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uF4TqofLHILq9gXtCqaH4njj+8LfkEpewu0BwB4H/mQ=;
        b=OnuW54uT1JB2But6ypW9upP7yshE6Yl2cvP6xYyY+lkon+RqgnVNLL7YKAyZEQE0SN
         fOG+Y6TNkivhLxb48wIT6R96i+v+RzgJrq8haHpjzLYMtiMzvkoeirD/2Q2x93fJYuBB
         EE3A7mTUN6WekoK4EhQyq9vy/4DfAciuqKucjIAda6eAjM7wd8yXcdA+x4y6NlG20HJM
         2QhQaB6PHHGGWnWX3NMfw22QvuU73Df8SMCsMWFiSeiLhb3nvvOtW8eY+/M0Uf+Q4JK8
         2Q6bljvkOBt8bQHMCdJr9Pa/opTmFgMmtl4MJg+VGwK/UmF5dyd2jopr2oVHPnkQSnXJ
         j3gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxNxbs36gBHGkENfEUvXEOmMixYHRtRrFX4+6lt8kM0pNQNRtAF
	nPRJc6o859wDUKIWFVHjFK0=
X-Google-Smtp-Source: ACHHUZ7zcBwXI0ld9xKIWi+x/VtXF7VXImlSnN+RmgCe+4DIGwrh4Q1WjstjVj7tPyTFgva/I97LFQ==
X-Received: by 2002:a2e:8004:0:b0:2b4:6b64:6863 with SMTP id j4-20020a2e8004000000b002b46b646863mr11260493ljg.16.1687554912706;
        Fri, 23 Jun 2023 14:15:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a2a:b0:2b4:85a7:4e0 with SMTP id
 by42-20020a05651c1a2a00b002b485a704e0ls548805ljb.0.-pod-prod-02-eu; Fri, 23
 Jun 2023 14:15:11 -0700 (PDT)
X-Received: by 2002:ac2:4d9a:0:b0:4f8:6e4e:6171 with SMTP id g26-20020ac24d9a000000b004f86e4e6171mr11685082lfe.1.1687554910967;
        Fri, 23 Jun 2023 14:15:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687554910; cv=none;
        d=google.com; s=arc-20160816;
        b=gpKynPqAPyJr2VIzLGXDGdml7v22GOycBgRURvGSde8jP6AxukOWTHwPJNNiv9rcId
         evQovLmNI4Jl4TkarSv9h4YI/C/Oiz1H9rVrUiLvNTYcCzwjk6zVRq1sO579Xriqps6/
         MFRpTQIZnuNmD9aVYD1XOyF9EV+XmytrdbSUuCLFAyJYYWUH8taw+BVzkKedt5X0nBc/
         QXTcAj5MDW/TXMeck3ln0elwBjwaE4a7DKcIpi8omgQ6xUU6KLUzzqWekBo/3B7Dey7R
         7roMyJ28XUYPYsPZecmOEZpvhSOa+0CUFo1gM+6FQOfF7kj70WQT6mInurApZlnSGlHu
         ozQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=yokMEiNdELJzyHFQdE73QSq1qzFaQMznhY0/hFJPXdI=;
        fh=EcgdAC2FuFrIj/KrOL6pppTJGrygJuPsGjT/Pp+RpwA=;
        b=b1HLxdkQrGpUcmREpRKfF/hgjyl31cDqGqCCbr1Lme2JajrdXADwK2Hx5EhWqVkh7h
         RHdePf9o3FSc54NMjmYCtJYJbZE+lUZb8GNApMFJejfziN+lji+6Mal055CJa+5vwlyX
         EtVhwQnOUMKQDv44HDL+wBmCxZgnxGmHVSmchwb5MgYOD1C2NrircPP7Hwd30qcDcleD
         J4D5qjqXZjOlfoDfCUe2ET55Hjba8+wHT4wp1uCm7D3IGrLE661jvGwJFgW5NCml+0KN
         DduJHxBa9OiM0yPa/rEPRwtn6SDdobFAMgiRMZBgaQlyXWHNQQaNtSNM/aYoE45RGJG9
         2cvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=PQ1b0Em2;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
Received: from mail3-relais-sop.national.inria.fr (mail3-relais-sop.national.inria.fr. [192.134.164.104])
        by gmr-mx.google.com with ESMTPS id c31-20020a056512239f00b004f76ab5e91asi9415lfv.10.2023.06.23.14.15.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Jun 2023 14:15:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) client-ip=192.134.164.104;
X-IronPort-AV: E=Sophos;i="6.01,153,1684792800"; 
   d="scan'208";a="59686157"
Received: from i80.paris.inria.fr (HELO i80.paris.inria.fr.) ([128.93.90.48])
  by mail3-relais-sop.national.inria.fr with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Jun 2023 23:15:09 +0200
From: Julia Lawall <Julia.Lawall@inria.fr>
To: linux-staging@lists.linux.dev
Cc: keescook@chromium.org,
	kernel-janitors@vger.kernel.org,
	Tianshu Qiu <tian.shu.qiu@intel.com>,
	Bingbu Cao <bingbu.cao@intel.com>,
	linux-sgx@vger.kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	iommu@lists.linux.dev,
	linux-tegra@vger.kernel.org,
	Robin Murphy <robin.murphy@arm.com>,
	Krishna Reddy <vdumpa@nvidia.com>,
	linux-scsi@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	linux-kernel@vger.kernel.org,
	netdev@vger.kernel.org,
	Shailend Chand <shailend@google.com>,
	Benjamin Gaignard <benjamin.gaignard@collabora.com>,
	Liam Mark <lmark@codeaurora.org>,
	Laura Abbott <labbott@redhat.com>,
	Brian Starkey <Brian.Starkey@arm.com>,
	John Stultz <jstultz@google.com>,
	linux-media@vger.kernel.org,
	linaro-mm-sig@lists.linaro.org,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	virtualization@lists.linux-foundation.org,
	mhi@lists.linux.dev,
	linux-arm-msm@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	intel-gvt-dev@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	VMware Graphics Reviewers <linux-graphics-maintainer@vmware.com>,
	linux-hyperv@vger.kernel.org
Subject: [PATCH 00/26] use array_size
Date: Fri, 23 Jun 2023 23:14:31 +0200
Message-Id: <20230623211457.102544-1-Julia.Lawall@inria.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: Julia.Lawall@inria.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@inria.fr header.s=dc header.b=PQ1b0Em2;       spf=pass (google.com:
 domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted
 sender) smtp.mailfrom=Julia.Lawall@inria.fr;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=inria.fr
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

Use array_size to protect against multiplication overflows.

This follows up on the following patches by Kees Cook from 2018.

42bc47b35320 ("treewide: Use array_size() in vmalloc()")
fad953ce0b22 ("treewide: Use array_size() in vzalloc()")

The changes were done using the following Coccinelle semantic patch,
adapted from the one posted by Kees.

// Drop single-byte sizes and redundant parens.
@@
    expression COUNT;
    typedef u8;
    typedef __u8;
    type t = {u8,__u8,char,unsigned char};
    identifier alloc = {vmalloc,vzalloc};
@@
      alloc(
-           (sizeof(t)) * (COUNT)
+           COUNT
      , ...)

// 3-factor product with 2 sizeof(variable), with redundant parens removed.
@@
    expression COUNT;
    size_t e1, e2, e3;
    identifier alloc = {vmalloc,vzalloc};
@@

(    
      alloc(
-           (e1) * (e2) * (e3)
+           array3_size(e1, e2, e3)
      ,...)
|
      alloc(
-           (e1) * (e2) * (COUNT)
+           array3_size(COUNT, e1, e2)
      ,...)
)

// 3-factor product with 1 sizeof(type) or sizeof(expression), with
// redundant parens removed.
@@
    expression STRIDE, COUNT;
    size_t e;
    identifier alloc = {vmalloc,vzalloc};
@@

      alloc(
-           (e) * (COUNT) * (STRIDE)
+           array3_size(COUNT, STRIDE, e)
      ,...)

// Any remaining multi-factor products, first at least 3-factor products
// when they're not all constants...
@@
    expression E1, E2, E3;
    constant C1, C2, C3;
    identifier alloc = {vmalloc,vzalloc};
@@
    
(
      alloc(C1 * C2 * C3,...)
|
      alloc(
-           (E1) * (E2) * (E3)
+           array3_size(E1, E2, E3)
      ,...)
)

// 2-factor product with sizeof(type/expression) and identifier or constant.
@@
    size_t e1,e2;
    expression COUNT;
    identifier alloc = {vmalloc,vzalloc};
@@

(
      alloc(
-           (e1) * (e2)
+           array_size(e1, e2)
      ,...)
|
      alloc(
-           (e1) * (COUNT)
+           array_size(COUNT, e1)
      ,...)
)
    
// And then all remaining 2 factors products when they're not all constants.
@@
    expression E1, E2;
    constant C1, C2;
    identifier alloc = {vmalloc,vzalloc};
@@
    
(
      alloc(C1 * C2,...)
|
      alloc(
-           (E1) * (E2)
+           array_size(E1, E2)
      ,...)
)


---

 arch/x86/kernel/cpu/sgx/main.c                    |    3 ++-
 drivers/accel/habanalabs/common/device.c          |    3 ++-
 drivers/accel/habanalabs/common/state_dump.c      |    6 +++---
 drivers/bus/mhi/host/init.c                       |    4 ++--
 drivers/comedi/comedi_buf.c                       |    4 ++--
 drivers/dma-buf/heaps/system_heap.c               |    2 +-
 drivers/gpu/drm/gud/gud_pipe.c                    |    2 +-
 drivers/gpu/drm/i915/gvt/gtt.c                    |    6 ++++--
 drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c           |    2 +-
 drivers/infiniband/hw/bnxt_re/qplib_res.c         |    4 ++--
 drivers/infiniband/hw/erdma/erdma_verbs.c         |    4 ++--
 drivers/infiniband/sw/siw/siw_qp.c                |    4 ++--
 drivers/infiniband/sw/siw/siw_verbs.c             |    6 +++---
 drivers/iommu/tegra-gart.c                        |    4 ++--
 drivers/net/ethernet/amd/pds_core/core.c          |    4 ++--
 drivers/net/ethernet/freescale/enetc/enetc.c      |    4 ++--
 drivers/net/ethernet/google/gve/gve_tx.c          |    2 +-
 drivers/net/ethernet/marvell/octeon_ep/octep_rx.c |    2 +-
 drivers/net/ethernet/microsoft/mana/hw_channel.c  |    2 +-
 drivers/net/ethernet/pensando/ionic/ionic_lif.c   |    4 ++--
 drivers/scsi/fnic/fnic_trace.c                    |    2 +-
 drivers/scsi/qla2xxx/qla_init.c                   |    4 ++--
 drivers/staging/media/ipu3/ipu3-mmu.c             |    2 +-
 drivers/vdpa/vdpa_user/iova_domain.c              |    3 +--
 drivers/virtio/virtio_mem.c                       |    6 +++---
 fs/btrfs/zoned.c                                  |    5 +++--
 kernel/kcov.c                                     |    2 +-
 lib/test_vmalloc.c                                |   12 ++++++------
 28 files changed, 56 insertions(+), 52 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230623211457.102544-1-Julia.Lawall%40inria.fr.
