Return-Path: <kasan-dev+bncBDN3FGENWMIRB3NGUWLAMGQEMNX33CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2754556C8A1
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jul 2022 12:07:43 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id v13-20020a05622a014d00b0031ea4c5d35dsf977366qtw.9
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jul 2022 03:07:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657361262; cv=pass;
        d=google.com; s=arc-20160816;
        b=ia+e6TPXTw1MFTEnPlXq73WU4io+oNMDRKUUuMyJxfqjCcoQpc04RiwptK2WYSfnHB
         euEVApDzjc9pOlxT3U7nyn7lkncPFBdBSv/mPdyNZr9YBBOyUOw5WTGqOUhSbstXR8oJ
         u9tpwf97bT88QWZ5LyTcRPcfA3h5KyuWIKnVtra+Y+I9hg4rnGiaJMMnsiQ/Q2SBssqC
         w2ysCPCL+rQlezMtKN+cIubbFrZAJMdmCL8GT5tAvT8gYni4sP9SWQl056HEzLhMLji+
         RF9XcyVbzxnTNGUQSiiKE0L8QIy78Y8A2JNJJuweilUi8fhSPqokplRsbdpJy/KOCbHM
         k4Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=uSLJNaWqMn9wwrR4mwEo58GvwYbs5zF7N8ThyF9Nbto=;
        b=AnBywKYzZyH47w3VWTvf2Q6gKtnW946+9+Yu0htysXw0vdWSt5p1lzMI8CHuIcubmQ
         FUoUODkOy/dYGNX6ysosfaUndpDMZ0Fzdh5Q+3HFGSk1duMhH8y6gZMRTDLkKJOsV+d5
         kW3PMci2IIL4wM6wrOMZdjF+PQ9H3MuxyZKCGBVJrOjqY0NtF27Jpfdt1zVyZhm5clHG
         sXGV2DZY4aq5KHWiDaXoU44XkXVViLNym6BOoyhULw/K6RMB1WjvoP3cPWpJdlnDPnR+
         ctQY+cOBRKo+gQaxvQC/1xKT065dMF7KaZVwDm20CR9VbGgFFbe4Xv5HrjSqswAySLnS
         zB3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LnWbmh+e;
       spf=pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uSLJNaWqMn9wwrR4mwEo58GvwYbs5zF7N8ThyF9Nbto=;
        b=CfRq5EosDi9PEHnAC54F1p60ceVaBStS4EYbBzOb3xzdyF7BLrRMLQ54v6s0o7bpOC
         711sgCgQTyG6N4uNX3I2+ccvdM4luw+pFRDevD2D2tGye5ES9bbmfPNxuV8HV2Gb8beW
         UzoEQO1LaAeppvdTjGh/kmAi8Fe5elwA1Zo/C+KrAmJdlvb45vG7SIIJI1nd68EYGaO7
         coiy5fH7hHSoyeB15nO4WJo8p3RnwohoHdZz4J1M3TiSIjBM/GSP2EdP0P9jQ3M10GSO
         23FJS2qY1i6Uu+jVIzfHPXQCyq/Gf/ZYMRemSxi1VXxOAPcf3Mjk6Cgyg2w8E6HuiQNd
         5O2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uSLJNaWqMn9wwrR4mwEo58GvwYbs5zF7N8ThyF9Nbto=;
        b=nrGXcyYnoEPzW0KmWLKMx0GC5WERTuHWwRsgvR1L3MuF4HHbfQXChwpA/cw60SK8Ng
         oF3VpM2dLD0C1Lx+HjP9XVwKiofJlW+hdOwXFdwbTgHi+cIzyQL6Eot+t9TjvLPKuYmS
         7QFr2lcdj0baS9zpQuW0jPXGwlrZA1P/4YH9kSd7bBqSj7BCp3kBpULcAtPdMQWRH/pl
         Tk5ngS62gj5nk234AfoEtvVn0e0w07lTZ6bZfDGOuG/fXTmCsFp5088mFCHWA9ZvmwDH
         gy3LWXLy4TLjme8Bb4O2h1yVR/C66Z5PMG1K/zyk7CYwLSx07BBq5XpNaQLIIqs1FKIf
         ktEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+kfo8MSdK8kW16epr3MdXL3tG3A1MRTQTJL7YV9oP7JwQzbpSG
	K3cMOrVpFRj8tcu1HuQpqK8=
X-Google-Smtp-Source: AGRyM1uDJk8zcBdFL2qzrN4sXn7wKs88YFK3NGVsMqvzYpHU3IvYloKF3IHpUnreBZIguMfs13NVkw==
X-Received: by 2002:ac8:7d46:0:b0:31d:29fa:4b6c with SMTP id h6-20020ac87d46000000b0031d29fa4b6cmr6589412qtb.482.1657361262018;
        Sat, 09 Jul 2022 03:07:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:550:b0:319:4679:df1 with SMTP id
 m16-20020a05622a055000b0031946790df1ls22995646qtx.3.gmail; Sat, 09 Jul 2022
 03:07:41 -0700 (PDT)
X-Received: by 2002:ac8:5a0e:0:b0:31d:3055:b6d6 with SMTP id n14-20020ac85a0e000000b0031d3055b6d6mr6378414qta.205.1657361261594;
        Sat, 09 Jul 2022 03:07:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657361261; cv=none;
        d=google.com; s=arc-20160816;
        b=Xi8bXH9N7CqMrm7WCPIrPyXhaB1nSsFZLlRYx9ZOqz2YymBodXcpU4w6lhLDW8DRsS
         pqo2Qk1ebpacVUu9m1sWcAsi5++gDBtajnoaK1g1Oip4sm10CmWsBB71b0AOAYJOahzZ
         m+V81Tg8ot1Z1KcDtIiyC05V1o1b/gdnn3elOkTButHNN+R2pZGDKPhDvVkuqJpEn8nb
         xcsnTT067QEFqxmQUDAenbYdyrcBy9Ou9gWU0ITwcyK2XQQiwYLXEyvsTX5By1/DTyMw
         yE/zl3buDZu1IDskcpxjj2K8Ykc6U1uHEayBqb5CC1Az7tTH5ozev+nbMuf3GFIA0ITx
         A9LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lcf5CWji8PrjKchL1lNFxwIrBEb1votmpvxVcVc5nQE=;
        b=gGIdKD+y4ZxEasoZOVYbFqolrkohRDdrfKxsQI2E3tvG3CntOAGLWDDb1vBfFhPdAo
         3Z38U2iHGyqH563J7E8DLUxC2VD+2YAUq4b3h3s85LsqQFBjyYILpuC9p80jCYNPRhZ7
         KI4OBANU535eJaxFMXnvSkOb7ISFqYgKL0mqXrFm+AiZY8c2pLyCff14icu6wnktN/aQ
         rsKzZK6CG7lMK62BJBkmD6/6utJJkcNx424+fz5zD1QOYvjItCxmApa3hfMWBrQc58IC
         cqNwp+PNT0zkAFZl2I9BzrPT/Tbdu/XaRt04sS/Pht4rVY2eEpIyMbBjge1GtRrEPScX
         UkmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LnWbmh+e;
       spf=pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id h23-20020ae9ec17000000b006b56b2144ffsi46546qkg.5.2022.07.09.03.07.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 09 Jul 2022 03:07:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 16FDC60EFD;
	Sat,  9 Jul 2022 10:07:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EAE2C341C7;
	Sat,  9 Jul 2022 10:07:39 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.95)
	(envelope-from <mchehab@kernel.org>)
	id 1oA7N9-004EGQ-BD;
	Sat, 09 Jul 2022 11:07:35 +0100
From: Mauro Carvalho Chehab <mchehab@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab@kernel.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	"H. Peter Anvin" <hpa@zytor.com>,
	=?UTF-8?q?Krzysztof=20Wilczy=C5=84ski?= <kw@linux.com>,
	"Theodore Ts'o" <tytso@mit.edu>,
	Alex Shi <alexs@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Grodzovsky <andrey.grodzovsky@amd.com>,
	Borislav Petkov <bp@alien8.de>,
	Daniel Vetter <daniel@ffwll.ch>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Airlie <airlied@linux.ie>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Leo Yan <leo.yan@linaro.org>,
	Marc Kleine-Budde <mkl@pengutronix.de>,
	Marco Elver <elver@google.com>,
	Mathieu Poirier <mathieu.poirier@linaro.org>,
	Max Staudt <max@enpas.org>,
	Mike Kravetz <mike.kravetz@oracle.com>,
	Mike Leach <mike.leach@linaro.org>,
	Muchun Song <songmuchun@bytedance.com>,
	Paolo Abeni <pabeni@redhat.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Wolfgang Grandegger <wg@grandegger.com>,
	Yanteng Si <siyanteng@loongson.cn>,
	coresight@lists.linaro.org,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linaro-mm-sig@lists.linaro.org,
	linux-arm-kernel@lists.infradead.org,
	linux-cachefs@redhat.com,
	linux-can@vger.kernel.org,
	linux-ext4@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mm@kvack.org,
	linux-pci@vger.kernel.org,
	linux-sgx@vger.kernel.org,
	netdev@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v3 00/21] Update Documentation/ cross references and fix issues
Date: Sat,  9 Jul 2022 11:07:13 +0100
Message-Id: <cover.1657360984.git.mchehab@kernel.org>
X-Mailer: git-send-email 2.36.1
MIME-Version: 1.0
X-Original-Sender: mchehab@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LnWbmh+e;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

This series fix almost all fixable issues when building the html docs at
linux-next (next-20220608):

- Address some broken cross-references;
- Fix kernel-doc warnings;
- Fix bad tags on ReST files.

With this series applied, plus other pending patches that should hopefully
be merged in time for the next merge window, htmldocs build will produce
just 4 warnings with Sphinx 2.4.4.

Sphinx >=3 will produce some extra false-positive warnings due to conflicts
between structs and functions sharing the same name. Hopefully this will
be fixed either on a new Sphinx 5.x version or Sphinx 6.0.

Mauro Carvalho Chehab (21):
  docs: networking: update netdevices.rst reference
  docs: update vmalloced-kernel-stacks.rst reference
  docs: update vmemmap_dedup.rst reference
  docs: zh_CN: page_migration: fix reference to mm index.rst
  dt-bindings: arm: update arm,coresight-cpu-debug.yaml reference
  x86/sgx: fix kernel-doc markups
  fscache: fix kernel-doc documentation
  fs: namei: address some kernel-doc issues
  drm/scheduler: fix a kernel-doc warning
  drm/scheduler: add a missing kernel-doc parameter
  kfence: fix a kernel-doc parameter
  genalloc: add a description for start_addr parameter
  textsearch: document list inside struct ts_ops
  dcache: fix a kernel-doc warning
  docs: ext4: blockmap.rst: fix a broken table
  docs: PCI: pci-vntb-function.rst: Properly include ascii artwork
  docs: PCI: pci-vntb-howto.rst: fix a title markup
  docs: virt: kvm: fix a title markup at api.rst
  docs: ABI: sysfs-bus-nvdimm
  docs: leds: index.rst: add leds-qcom-lpg to it
  Documentation: coresight: fix binding wildcards

 Documentation/ABI/testing/sysfs-bus-nvdimm             |  2 ++
 Documentation/PCI/endpoint/pci-vntb-function.rst       |  2 +-
 Documentation/PCI/endpoint/pci-vntb-howto.rst          |  2 +-
 Documentation/filesystems/ext4/blockmap.rst            |  2 +-
 Documentation/leds/index.rst                           |  1 +
 Documentation/trace/coresight/coresight-cpu-debug.rst  |  2 +-
 Documentation/trace/coresight/coresight.rst            |  2 +-
 Documentation/translations/zh_CN/mm/page_migration.rst |  2 +-
 .../translations/zh_CN/mm/vmalloced-kernel-stacks.rst  |  2 +-
 Documentation/virt/kvm/api.rst                         |  6 +++---
 arch/x86/include/uapi/asm/sgx.h                        | 10 ++++++++--
 drivers/gpu/drm/scheduler/sched_main.c                 |  1 +
 drivers/net/can/can327.c                               |  2 +-
 fs/namei.c                                             |  3 +++
 include/drm/gpu_scheduler.h                            |  1 +
 include/linux/dcache.h                                 |  2 +-
 include/linux/fscache.h                                |  4 ++--
 include/linux/genalloc.h                               |  1 +
 include/linux/kfence.h                                 |  1 +
 include/linux/textsearch.h                             |  1 +
 mm/hugetlb_vmemmap.h                                   |  2 +-
 21 files changed, 34 insertions(+), 17 deletions(-)

-- 
2.36.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1657360984.git.mchehab%40kernel.org.
