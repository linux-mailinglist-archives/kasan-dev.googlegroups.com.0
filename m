Return-Path: <kasan-dev+bncBDZJXP7F6YLRBKXL5OSAMGQEIPY6NZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 03A3C73FE94
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jun 2023 16:43:56 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4fb7d06a7e6sf1591690e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jun 2023 07:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687877035; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBU/htzkUkkFCRvOxwa/7ps+ojemCXeoBGwzmUxhsWfl5z8ikXFaQXLOorW7H3+bAp
         2M2pefspLET1pHTB8mHKiOWn4n4OpE8f/FEecvlXYvHtE4ROuOAaSPJc1RuBJWCQ9yFE
         CX5NW3OuDQKNERTKxxKR+eWgJW5ffcI7iz8oyD2sH92X7LoCljX4pfi2hPkDSG9aDGHB
         fkkY+751lnN3CUGwHB9LjX2Zty+Hklxz7aW6qFMf0VQNNIkasHprFO86IYYH15MVp6Ss
         GhnpSHhsULj4xdH80I+x0Z0BFd75Z+rEp9vIagQVuYBCToaTVLpQ1Proj8PKwSjNqJyY
         0/LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+0uw9dO6uiqVSWvary6ydpF5bTxtqJ9uiZHifuLjLBU=;
        b=txCPehJrAGlaf5DkSQaKbSDq8KiwZ1VuCdw6GFXIqpQtvG2Bdz2QZgblNtjJT4XUYo
         9OSeGQowhDwVZZUkfoO8fkSbDIe+uTCb18wKsCorVQ+SlY4QkzqhiK0hfQsCSmELwnPd
         Pt2ha7RizeYRYf1y7dj7OenvcHMcbIXt/13IGGUuNuHXgITKDBwdFumD2OreKWvdu8jj
         nAr2730g+XOSyEbFrgr16bCuhz7J2Aide3xof6BTxu9v2aHNJMEYcCc6w4i5CbzKb8A/
         8NJh9oMAE+VMHMV2eA8ldSw7hGGwjl4FQuthrAvE8WGplT+ITuBftLdfpBPJB4rUi15l
         bmQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=YpuufV72;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687877035; x=1690469035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+0uw9dO6uiqVSWvary6ydpF5bTxtqJ9uiZHifuLjLBU=;
        b=PzRvkQhIAPW7RtAEg2EA4hBwY7eNR3AJu7wCuFpt1VMfFpljZE8T/trzGqkkYZvotC
         YvXfVoLKqQYxLoSMADPSFa2RAH9WUuadWxB323W/xTgvjmYlfAAmJPyQTvAx3ijv9WzD
         a5Joij3KcRQM3zAHlUdXBVicnI5eG/JlMybPKFtMdyYGYJiYoqcTfI4rMIySbs0oBE/s
         l2CgYRG2Dy8Q6q/ZP7/pPEAPW9QzZn3h+ma++nJS9uI4gsTtfob5PQxhCQVZ0OknM50L
         jajBqzqnGFmGp6vbTBmF3l3ZlU+GCMzaxkkl99xHqV9+0zgDFmuUx+OSKrTo4WIbbAXO
         4oSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687877035; x=1690469035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+0uw9dO6uiqVSWvary6ydpF5bTxtqJ9uiZHifuLjLBU=;
        b=Fffyo9kqZ+PO0VgS9KmBPayAZQFkqtiB8mCYsQ0hRfIA0F8aTGHGKCU62jXxFuZWA2
         pLar3mJZH6DtkDEPMYKmoOt1NE82wcPzrWasaDt7/eFJqFnw+wManZoH1aoaLrtOCufF
         yyp3KfY1/JQ4imflo2nZ1piiZb6gVvM3YS+16qfmZQWDHBpwlp7Lxwhf6dfoe+GVW4Lp
         OH3BDSY7A+Rz1BbNF9vsVRFGeO47wCZgfBRt/yEdtWPXXeoR+/n3oYWf5R/i1bzLXppe
         JyDnstHmMIxEM5C2/hYDRCBoZ7BRvkvCrsnT36n6EkwjCe96OZXlDfjlnIBDfIiGuiGF
         gk4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzoxHWqhtx3gX/fDerKoo9bVLK/CfdS5nqvq5Msi+1LnJisNqvR
	Ue5jcMXKWEbXEEhtXzXLQGY=
X-Google-Smtp-Source: ACHHUZ6npO1O9YsmIQb2cX4fI5yRWx4ZMnqhHOhPb0vhWzgx6SSxasZLqlUvp4TTn3RZmivGT06Tpw==
X-Received: by 2002:a05:6512:108d:b0:4f9:6842:afc with SMTP id j13-20020a056512108d00b004f968420afcmr11374103lfg.64.1687877034316;
        Tue, 27 Jun 2023 07:43:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:7114:0:b0:4f8:52a6:ee15 with SMTP id m20-20020a197114000000b004f852a6ee15ls105048lfc.1.-pod-prod-07-eu;
 Tue, 27 Jun 2023 07:43:52 -0700 (PDT)
X-Received: by 2002:a05:6512:ea7:b0:4f6:1433:fca0 with SMTP id bi39-20020a0565120ea700b004f61433fca0mr20514453lfb.0.1687877032174;
        Tue, 27 Jun 2023 07:43:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687877032; cv=none;
        d=google.com; s=arc-20160816;
        b=vS1rXVvw/1R9NkBDhoeSDIFjCXV/oGdHFg2t5SjqzwvUrV+LMGK++/YB3NJjelb8+k
         I2H02tiI9a4hdG6FXLrtMBVClYaC9aF3KCiAmbqKrCqqPOqzauv0g0xfTRS082l3TTK+
         /frfMS9JbxUQqxd0zNIDybRDdpgAda1T0eXnOh1U4Iswse+RINjLytZ+s+2z0SYuVcNz
         wZ2tjBHWsOTfI8olNk7nA4bqX4Y/Wq6XsUffMt9l208vluSvmKXJTf1WwHjpXOg6VY1W
         vbdgZoch8JSxWpEcRCsio0R8HcuZn2meFpIjWjMsZ4DlhvCDWwlmg9oPUvmA9SPlJjaf
         ZEVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lz+eaKXjltZfgC96+KOEH+DiV357kqzsKaP1ME9j9JM=;
        fh=G7yZoAXDVSoKYk/MV98bbQy4hqfCBj12o7NoburH1aI=;
        b=DZ+9zh4/iLgKsfCcxmbBhItdd5mMvswoXcuMPct3F+tqYc9t4IEmD3ZPhBmid4I8Ys
         WqYiq2y0xxaXLz6F3S2P6ATcvZW+sm/XZu4Y2KheyD+nL208zozRozTuSUCp9WIn/Nja
         V27vsL0Qo7HB9ijudwuhbjDcIXDxyU2r5LzG+o9tNxAqVezewQyIx5obZZ0Jvs35s4eG
         YMRrSVp/IM9ZN3j2yPdbs+XOsl5mjwSpRP98sVqfOJ6bNlvrkWttrNrFJVSglaxrAE6p
         aoUV3bgdw8rXx9IDfe+5qBt4HcDUR9ujzQbksmDnx8R0b/9Fqb/8VPhtP3K7ioFsVk1s
         hAcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=YpuufV72;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) smtp.mailfrom=Julia.Lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
Received: from mail2-relais-roc.national.inria.fr (mail2-relais-roc.national.inria.fr. [192.134.164.83])
        by gmr-mx.google.com with ESMTPS id bp21-20020a056512159500b004fb8167d7desi154510lfb.4.2023.06.27.07.43.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Jun 2023 07:43:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted sender) client-ip=192.134.164.83;
X-IronPort-AV: E=Sophos;i="6.01,162,1684792800"; 
   d="scan'208";a="114936315"
Received: from i80.paris.inria.fr (HELO i80.paris.inria.fr.) ([128.93.90.48])
  by mail2-relais-roc.national.inria.fr with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Jun 2023 16:43:51 +0200
From: Julia Lawall <Julia.Lawall@inria.fr>
To: linux-hyperv@vger.kernel.org
Cc: kernel-janitors@vger.kernel.org,
	keescook@chromium.org,
	christophe.jaillet@wanadoo.fr,
	kuba@kernel.org,
	kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	iommu@lists.linux.dev,
	linux-tegra@vger.kernel.org,
	Robin Murphy <robin.murphy@arm.com>,
	Krishna Reddy <vdumpa@nvidia.com>,
	virtualization@lists.linux-foundation.org,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	linux-scsi@vger.kernel.org,
	linaro-mm-sig@lists.linaro.org,
	linux-media@vger.kernel.org,
	John Stultz <jstultz@google.com>,
	Brian Starkey <Brian.Starkey@arm.com>,
	Laura Abbott <labbott@redhat.com>,
	Liam Mark <lmark@codeaurora.org>,
	Benjamin Gaignard <benjamin.gaignard@collabora.com>,
	dri-devel@lists.freedesktop.org,
	linux-kernel@vger.kernel.org,
	netdev@vger.kernel.org,
	Shailend Chand <shailend@google.com>,
	linux-rdma@vger.kernel.org,
	mhi@lists.linux.dev,
	linux-arm-msm@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	intel-gvt-dev@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-sgx@vger.kernel.org
Subject: [PATCH v2 00/24] use vmalloc_array and vcalloc
Date: Tue, 27 Jun 2023 16:43:15 +0200
Message-Id: <20230627144339.144478-1-Julia.Lawall@inria.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: Julia.Lawall@inria.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@inria.fr header.s=dc header.b=YpuufV72;       spf=pass (google.com:
 domain of julia.lawall@inria.fr designates 192.134.164.83 as permitted
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

The functions vmalloc_array and vcalloc were introduced in

commit a8749a35c399 ("mm: vmalloc: introduce array allocation functions")

but are not used much yet.  This series introduces uses of
these functions, to protect against multiplication overflows.

The changes were done using the following Coccinelle semantic
patch.

@initialize:ocaml@
@@

let rename alloc =
  match alloc with
    "vmalloc" -> "vmalloc_array"
  | "vzalloc" -> "vcalloc"
  | _ -> failwith "unknown"

@@
    size_t e1,e2;
    constant C1, C2;
    expression E1, E2, COUNT, x1, x2, x3;
    typedef u8;
    typedef __u8;
    type t = {u8,__u8,char,unsigned char};
    identifier alloc = {vmalloc,vzalloc};
    fresh identifier realloc = script:ocaml(alloc) { rename alloc };
@@

(
      alloc(x1*x2*x3)
|
      alloc(C1 * C2)
|
      alloc((sizeof(t)) * (COUNT), ...)
|
-     alloc((e1) * (e2))
+     realloc(e1, e2)
|
-     alloc((e1) * (COUNT))
+     realloc(COUNT, e1)
|
-     alloc((E1) * (E2))
+     realloc(E1, E2)
)

v2: This series uses vmalloc_array and vcalloc instead of
array_size.  It also leaves a multiplication of a constant by a
sizeof as is.  Two patches are thus dropped from the series.

---

 arch/x86/kernel/cpu/sgx/main.c                    |    2 +-
 drivers/accel/habanalabs/common/device.c          |    3 ++-
 drivers/accel/habanalabs/common/state_dump.c      |    7 ++++---
 drivers/bus/mhi/host/init.c                       |    2 +-
 drivers/comedi/comedi_buf.c                       |    4 ++--
 drivers/dma-buf/heaps/system_heap.c               |    2 +-
 drivers/gpu/drm/gud/gud_pipe.c                    |    2 +-
 drivers/gpu/drm/i915/gvt/gtt.c                    |    6 ++++--
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
 drivers/vdpa/vdpa_user/iova_domain.c              |    4 ++--
 drivers/virtio/virtio_mem.c                       |    6 +++---
 fs/btrfs/zoned.c                                  |    4 ++--
 kernel/kcov.c                                     |    2 +-
 lib/test_vmalloc.c                                |    9 +++++----
 26 files changed, 52 insertions(+), 47 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230627144339.144478-1-Julia.Lawall%40inria.fr.
