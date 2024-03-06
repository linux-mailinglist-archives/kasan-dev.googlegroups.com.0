Return-Path: <kasan-dev+bncBC7OD3FKWUERBE7KUKXQMGQE7UBYYEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id CC808873E87
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:24 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-5dc4ffda13fsf965920a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749523; cv=pass;
        d=google.com; s=arc-20160816;
        b=Inaz1rcrn6jLxOIBrVYM/Kwpry+AUx1cz4cSOrHzNdBLlyBQ4DSInZhsbkDaFO6rv7
         q9ImPCMxqLma264FAQQqg4nSIAzqAIyz5z9YfsOk5aRjbIoLzdoKBUKM5EWMkMVsu3Mc
         yL+4JTP3v5f92MvRtvC+RwExj6rGTylqpHdamqq0eQpEAP2jZxEwJ0SRskfsAbpSSVRb
         JnhclfbcAVDzs+QBpwvxGw1SWcQnLAJL9uw64DFxtd2wYpHWQYPOndynrdC1YXcVGjQr
         Hy9/CQfQkrwWGNPzn8utnuNC6IaiSClVcBlGi3RbvNwEFq5ezfNqQFF8zBSqRTyTWeLt
         CKOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=N2n9wH9NINmMoBBvo84nLvCz5wIJgmOe440ddQy9f0E=;
        fh=D3D9IG3FaTt1IpaTEdgH+fHokrTa/Xh7Y4CW/drwF0s=;
        b=J/clbx5ER8yLTdNu2SYs5lODz9RZD+kzDqC1SXMMRRkDOeB5aOy/JoTQuVLJvl6I6F
         J7OMDXwpum+6x2NBVWj4P8nOMinXYNcqaahO1nSToAb0RQZx8IcFmuv1gYvaISPEESDE
         GusYvUcHBUjMPRYLuv4VOxo/O9VSwD2ouDzATI0Oqh2+5PZR8s2c3iKJZiiDBitLmmv9
         B+4SJcpbcwxIxhMjQDnMLyViXgUPrMt1eCqGVwUSr+U+cUoTX8d9SrlNaxnd8hd4SmDE
         na1WjFCiIXlpu6Rhc/c7gNGskflY7UnVrg58/K+AD6egRMSXYDdW+03L++XlddY22m3y
         aA9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TODmOPrs;
       spf=pass (google.com: domain of 3ebxozqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EbXoZQYKCVQEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749523; x=1710354323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=N2n9wH9NINmMoBBvo84nLvCz5wIJgmOe440ddQy9f0E=;
        b=Wii2QW1QU9s+89IdgVsOSvOSJZqOa3oo0uvMFtGN6S6sKDVi+xHrdLgDyNbHylUK5R
         KGChYbG9fpckXuTFPWCcX4YeeBnBrsoiOaEpyX9m+uI2nEam6NKMgug61yfJlJ9LCMZz
         +UWUFzm7YIMbIvgGbdhlvG1+9IyKcHVKhamgs/BH28ztjydu6spWPRgM4FkJOaMfraDF
         17HU3ptCGEufJQClZk6jMSEIB9iz3yUSQOV32x3zMou2iHLTs2JFmW2aUO7slzLVjLMK
         p0JRqmOErcAZz/25vq4gfQspEX3bItUwpNU6m73E8bdqzIpWtxm6p6S5OKiLGA/FAO+N
         dP7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749523; x=1710354323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N2n9wH9NINmMoBBvo84nLvCz5wIJgmOe440ddQy9f0E=;
        b=YkgHSpQepH7KXulgvE49ge0n+UbU2jCDNj03XaBDJQwC31ZVauaaVcAIIn+CpoaeUM
         ek2XS+USEw9DvngzjaGqKhzovAQ+bTFP5fL9ddtI396ZrO1qX3NPuEoaTk+R4Bi41b8J
         Ey+nqpYHK7UizcptEHMjOxl1FTl8i4qrP0YOybV64R6sspGCc0ocTjGf8yiyeSaptlpq
         VNE67bFroNsxWXQkuw2vULDhGPFnX8r2RbQQ1ePF/NS0Rrye7rlnVU07/lo2txWGPY/6
         e1YgZHetMjUt2DZBgVmZGTRmLTR/A4fb8Y39f/d7vgkLxyDBC2IPm+RDbWoBD7VBsZD+
         cAQA==
X-Forwarded-Encrypted: i=2; AJvYcCWZJVGJiBHuFTTUmDl9B6RAxiwc3hlfMYo8zSSD72txyL2A3mIagSp0ZUHdD4AI9f+DlHA8VWkDSD3RtrK/aLGfYvmGMo3X9A==
X-Gm-Message-State: AOJu0Yxxll04tact+1ggXwiqTbNJaLf4okqCtPvPFegnxcvb7sLiDNO7
	FoJBw9YDPOcLTOxLE465+tRerWKwuiVIu1DHLK2FFhwJJ8L4jiNG
X-Google-Smtp-Source: AGHT+IFcDbvmR9y334CBY7hKgujmNkzxhrzJneiZkJ4E15SFTP0E3Q/VrIj/j453RpJzIdFQfg5Bmw==
X-Received: by 2002:a05:6a20:2587:b0:1a1:6e20:424d with SMTP id k7-20020a056a20258700b001a16e20424dmr125024pzd.15.1709749523343;
        Wed, 06 Mar 2024 10:25:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1828:b0:6e5:4c77:a146 with SMTP id
 y40-20020a056a00182800b006e54c77a146ls71334pfa.2.-pod-prod-00-us; Wed, 06 Mar
 2024 10:25:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVe9jiK+fvWf2XhiN2LF5zLXf1FlAgipLRghuOePLhsfSyzHPOiyah/L8jKbQjGSNknpUrYDWv5xtyKqTHv4+hAjFWsi6qq3MHvIA==
X-Received: by 2002:a17:902:eccc:b0:1dc:b968:780e with SMTP id a12-20020a170902eccc00b001dcb968780emr1199265plh.33.1709749522235;
        Wed, 06 Mar 2024 10:25:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749522; cv=none;
        d=google.com; s=arc-20160816;
        b=awC0OmTkLNHdxepd9tTS4L89YLtc1KRovQ1fgbdhXTmH0Q7uB3O2bt1tMaboRl39po
         BAOlC1ubIOfj40GZIKNNRXq27DNt1zkXsohbz7gKdjEvRcf+xOIPel5Fj1dhv2JV+aTY
         EVLShg04XZHWKkPc8XT3WCipvMTkzsDufxe1hcu9OBxPSssL1fXk+InGoHC/jycqxdSs
         IjfG/sP7InukJ6b+NgP9+FcJxuSQZ4d7dkQFDslDjjCpJhdblg94Q35qI980YAs2Hgrx
         d9cfc3awtoJkOHwAK7gbMKTn0tCwEzu1d0CCGYA8LzL3IBubYJnodOD/GOAuVPzp/0Xq
         /uuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ce5q/5s2y8sTRUjXlJUoDQaDDC72MtCTDHZZLC1kTDU=;
        fh=epG+wY03H1kXcNinHxQWghRmlkEJiQ8Lap9tqRjuxrE=;
        b=NaBR4VgdgVFgQ19mCWQ9hZnKwpYFekovGU1mzTTbhVCiRwT3guV0vOTr814cLtYKuc
         8kFMQMAq+FG5VjuneDgY6B1cTySKCN33qu3my1QpxV3lBsFidsApKtn0gweslJrUjVHW
         sRRUwaSN+cTvpsWdplbxuVij7CbpZPLrGzoJTOGjUp5Iadl/T3gl45aUd5lnvEiyzyQN
         OofVS5RlwFy7VR0uQtPOz5lgMEgxOmkbQ3w6pbRmB0g55zxLTVTu7o8xYBknAbwtu/3r
         Dw0NVa5TpoqY6dV5GJ+lW7dus14oCCF1wWDDpTq5+LDGFxIYkvbvqaBQJQegLE93VTDG
         2Big==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TODmOPrs;
       spf=pass (google.com: domain of 3ebxozqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EbXoZQYKCVQEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id lg11-20020a170902fb8b00b001db63388676si985672plb.8.2024.03.06.10.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ebxozqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60971264c48so589047b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZSnB0NdGG01e26E96oshD8arVuf3VZj+PzVQ17wlsKptTU3IDJkPZayubV4vLS4RKiSjqR1Y4Iul/M9/UADEp2DdlmG3HJuey/g==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1821:b0:dc7:9218:df3b with SMTP id
 cf33-20020a056902182100b00dc79218df3bmr687403ybb.10.1709749521260; Wed, 06
 Mar 2024 10:25:21 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:15 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-18-surenb@google.com>
Subject: [PATCH v5 17/37] change alloc_pages name in dma_map_ops to avoid name conflicts
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TODmOPrs;       spf=pass
 (google.com: domain of 3ebxozqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3EbXoZQYKCVQEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
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

After redefining alloc_pages, all uses of that name are being replaced.
Change the conflicting names to prevent preprocessor from replacing them
when it's not intended.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/alpha/kernel/pci_iommu.c           | 2 +-
 arch/mips/jazz/jazzdma.c                | 2 +-
 arch/powerpc/kernel/dma-iommu.c         | 2 +-
 arch/powerpc/platforms/ps3/system-bus.c | 4 ++--
 arch/powerpc/platforms/pseries/vio.c    | 2 +-
 arch/x86/kernel/amd_gart_64.c           | 2 +-
 drivers/iommu/dma-iommu.c               | 2 +-
 drivers/parisc/ccio-dma.c               | 2 +-
 drivers/parisc/sba_iommu.c              | 2 +-
 drivers/xen/grant-dma-ops.c             | 2 +-
 drivers/xen/swiotlb-xen.c               | 2 +-
 include/linux/dma-map-ops.h             | 2 +-
 kernel/dma/mapping.c                    | 4 ++--
 13 files changed, 15 insertions(+), 15 deletions(-)

diff --git a/arch/alpha/kernel/pci_iommu.c b/arch/alpha/kernel/pci_iommu.c
index c81183935e97..7fcf3e9b7103 100644
--- a/arch/alpha/kernel/pci_iommu.c
+++ b/arch/alpha/kernel/pci_iommu.c
@@ -929,7 +929,7 @@ const struct dma_map_ops alpha_pci_ops = {
 	.dma_supported		= alpha_pci_supported,
 	.mmap			= dma_common_mmap,
 	.get_sgtable		= dma_common_get_sgtable,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 };
 EXPORT_SYMBOL(alpha_pci_ops);
diff --git a/arch/mips/jazz/jazzdma.c b/arch/mips/jazz/jazzdma.c
index eabddb89d221..c97b089b9902 100644
--- a/arch/mips/jazz/jazzdma.c
+++ b/arch/mips/jazz/jazzdma.c
@@ -617,7 +617,7 @@ const struct dma_map_ops jazz_dma_ops = {
 	.sync_sg_for_device	= jazz_dma_sync_sg_for_device,
 	.mmap			= dma_common_mmap,
 	.get_sgtable		= dma_common_get_sgtable,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 };
 EXPORT_SYMBOL(jazz_dma_ops);
diff --git a/arch/powerpc/kernel/dma-iommu.c b/arch/powerpc/kernel/dma-iommu.c
index 8920862ffd79..f0ae39e77e37 100644
--- a/arch/powerpc/kernel/dma-iommu.c
+++ b/arch/powerpc/kernel/dma-iommu.c
@@ -216,6 +216,6 @@ const struct dma_map_ops dma_iommu_ops = {
 	.get_required_mask	= dma_iommu_get_required_mask,
 	.mmap			= dma_common_mmap,
 	.get_sgtable		= dma_common_get_sgtable,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 };
diff --git a/arch/powerpc/platforms/ps3/system-bus.c b/arch/powerpc/platforms/ps3/system-bus.c
index d6b5f5ecd515..56dc6b29a3e7 100644
--- a/arch/powerpc/platforms/ps3/system-bus.c
+++ b/arch/powerpc/platforms/ps3/system-bus.c
@@ -695,7 +695,7 @@ static const struct dma_map_ops ps3_sb_dma_ops = {
 	.unmap_page = ps3_unmap_page,
 	.mmap = dma_common_mmap,
 	.get_sgtable = dma_common_get_sgtable,
-	.alloc_pages = dma_common_alloc_pages,
+	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 };
 
@@ -709,7 +709,7 @@ static const struct dma_map_ops ps3_ioc0_dma_ops = {
 	.unmap_page = ps3_unmap_page,
 	.mmap = dma_common_mmap,
 	.get_sgtable = dma_common_get_sgtable,
-	.alloc_pages = dma_common_alloc_pages,
+	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 };
 
diff --git a/arch/powerpc/platforms/pseries/vio.c b/arch/powerpc/platforms/pseries/vio.c
index 2dc9cbc4bcd8..0c90fc4c3796 100644
--- a/arch/powerpc/platforms/pseries/vio.c
+++ b/arch/powerpc/platforms/pseries/vio.c
@@ -611,7 +611,7 @@ static const struct dma_map_ops vio_dma_mapping_ops = {
 	.get_required_mask = dma_iommu_get_required_mask,
 	.mmap		   = dma_common_mmap,
 	.get_sgtable	   = dma_common_get_sgtable,
-	.alloc_pages	   = dma_common_alloc_pages,
+	.alloc_pages_op	   = dma_common_alloc_pages,
 	.free_pages	   = dma_common_free_pages,
 };
 
diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/amd_gart_64.c
index 2ae98f754e59..c884deca839b 100644
--- a/arch/x86/kernel/amd_gart_64.c
+++ b/arch/x86/kernel/amd_gart_64.c
@@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_ops = {
 	.get_sgtable			= dma_common_get_sgtable,
 	.dma_supported			= dma_direct_supported,
 	.get_required_mask		= dma_direct_get_required_mask,
-	.alloc_pages			= dma_direct_alloc_pages,
+	.alloc_pages_op			= dma_direct_alloc_pages,
 	.free_pages			= dma_direct_free_pages,
 };
 
diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 50ccc4f1ef81..8a1f7f5d1bca 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1710,7 +1710,7 @@ static const struct dma_map_ops iommu_dma_ops = {
 	.flags			= DMA_F_PCI_P2PDMA_SUPPORTED,
 	.alloc			= iommu_dma_alloc,
 	.free			= iommu_dma_free,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 	.alloc_noncontiguous	= iommu_dma_alloc_noncontiguous,
 	.free_noncontiguous	= iommu_dma_free_noncontiguous,
diff --git a/drivers/parisc/ccio-dma.c b/drivers/parisc/ccio-dma.c
index 9ce0d20a6c58..feef537257d0 100644
--- a/drivers/parisc/ccio-dma.c
+++ b/drivers/parisc/ccio-dma.c
@@ -1022,7 +1022,7 @@ static const struct dma_map_ops ccio_ops = {
 	.map_sg =		ccio_map_sg,
 	.unmap_sg =		ccio_unmap_sg,
 	.get_sgtable =		dma_common_get_sgtable,
-	.alloc_pages =		dma_common_alloc_pages,
+	.alloc_pages_op =	dma_common_alloc_pages,
 	.free_pages =		dma_common_free_pages,
 };
 
diff --git a/drivers/parisc/sba_iommu.c b/drivers/parisc/sba_iommu.c
index 784037837f65..fc3863c09f83 100644
--- a/drivers/parisc/sba_iommu.c
+++ b/drivers/parisc/sba_iommu.c
@@ -1090,7 +1090,7 @@ static const struct dma_map_ops sba_ops = {
 	.map_sg =		sba_map_sg,
 	.unmap_sg =		sba_unmap_sg,
 	.get_sgtable =		dma_common_get_sgtable,
-	.alloc_pages =		dma_common_alloc_pages,
+	.alloc_pages_op =	dma_common_alloc_pages,
 	.free_pages =		dma_common_free_pages,
 };
 
diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-ops.c
index 76f6f26265a3..29257d2639db 100644
--- a/drivers/xen/grant-dma-ops.c
+++ b/drivers/xen/grant-dma-ops.c
@@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct device *dev, u64 mask)
 static const struct dma_map_ops xen_grant_dma_ops = {
 	.alloc = xen_grant_dma_alloc,
 	.free = xen_grant_dma_free,
-	.alloc_pages = xen_grant_dma_alloc_pages,
+	.alloc_pages_op = xen_grant_dma_alloc_pages,
 	.free_pages = xen_grant_dma_free_pages,
 	.mmap = dma_common_mmap,
 	.get_sgtable = dma_common_get_sgtable,
diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
index 0e6c6c25d154..1c4ef5111651 100644
--- a/drivers/xen/swiotlb-xen.c
+++ b/drivers/xen/swiotlb-xen.c
@@ -403,7 +403,7 @@ const struct dma_map_ops xen_swiotlb_dma_ops = {
 	.dma_supported = xen_swiotlb_dma_supported,
 	.mmap = dma_common_mmap,
 	.get_sgtable = dma_common_get_sgtable,
-	.alloc_pages = dma_common_alloc_pages,
+	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 	.max_mapping_size = swiotlb_max_mapping_size,
 };
diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
index 4abc60f04209..9ee319851b5f 100644
--- a/include/linux/dma-map-ops.h
+++ b/include/linux/dma-map-ops.h
@@ -29,7 +29,7 @@ struct dma_map_ops {
 			unsigned long attrs);
 	void (*free)(struct device *dev, size_t size, void *vaddr,
 			dma_addr_t dma_handle, unsigned long attrs);
-	struct page *(*alloc_pages)(struct device *dev, size_t size,
+	struct page *(*alloc_pages_op)(struct device *dev, size_t size,
 			dma_addr_t *dma_handle, enum dma_data_direction dir,
 			gfp_t gfp);
 	void (*free_pages)(struct device *dev, size_t size, struct page *vaddr,
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 58db8fd70471..5e2d51e1cdf6 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struct device *dev, size_t size,
 	size = PAGE_ALIGN(size);
 	if (dma_alloc_direct(dev, ops))
 		return dma_direct_alloc_pages(dev, size, dma_handle, dir, gfp);
-	if (!ops->alloc_pages)
+	if (!ops->alloc_pages_op)
 		return NULL;
-	return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
+	return ops->alloc_pages_op(dev, size, dma_handle, dir, gfp);
 }
 
 struct page *dma_alloc_pages(struct device *dev, size_t size,
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-18-surenb%40google.com.
