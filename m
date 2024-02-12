Return-Path: <kasan-dev+bncBC7OD3FKWUERBOFAVKXAMGQEQYYNF2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id D6B66851FD8
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:09 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-5ee22efe5eesf62578677b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774009; cv=pass;
        d=google.com; s=arc-20160816;
        b=J94H5RR12PsRnTJEC4PrATu7zyMDB5YPENXhNgzBYZWh78yQlX1Id608UU5nWP/PUr
         X1j5SB8N53znj1qJiuXXdCykhNEfjTMZ0KJ2RWEfpHZZsBemy5GpCN+wONqPnWouPLbX
         uURktrVcM3L+SWeC6Fdu3znt+kO2wgP3pEBRWBvsZ/l6q27znLlJPXELKWZDK/sPgM7r
         Lvd/mTbUfKE7l0BzxIOKZ867t5JtKjK7F9Bdbn78qQ6MbGDZt9gL3oNtYmHZf4szs0oU
         u+pkHCWyz+LfEld/iNFIDvuhRjDYEhdzpgr/lIbaxL/g0mPV4TxXNIRrkN8oL+EXaeVi
         1qpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fAyqKTd8/tWwNMRw13rKQmGS0n1VEBQG9JAhQE5QHHM=;
        fh=o1zyUIKbTwp3KvaNvpZGXCwOZ5DKyQ34rw/3x6TTbmI=;
        b=VhAnv6Vm+aLSpZtdyibyKNr2xi34TsjtlGHKMwoVG95ycVK+glxyEgXrGD/IhpIOkb
         1RoHJzYlqf9TOBnZd7AAYAlq0qOIXJ0KaSqIYs30o0CV3QQ0xGmzN1+d4naKmDz0dhWx
         lismG7Vb+0o5AXNfnTU5Im83zKj7/nN6KsufxNBT1G1VNfrJsuJ5YnF5ln8G5moezR6c
         6t2z76WQTbfTzG5WPUQZ7PCaZYSOVwJqPE1JH00m/KYCzLhQ4VKWmKDGUt5EFT4lrXMI
         TDL9+zICfwky2Ez+t9S5XaUXyFf+rxFJhmmtwF9zUjbUOgSWkXKKKYYoEwA68zcR46b9
         5M2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EAQjCW9N;
       spf=pass (google.com: domain of 3n5dkzqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3N5DKZQYKCbYoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774008; x=1708378808; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fAyqKTd8/tWwNMRw13rKQmGS0n1VEBQG9JAhQE5QHHM=;
        b=fvGQrabmoYrQ4/VVL7rSv26Q+k7QhzS7V5DagsnliKKXGuZs9P8xdmfZSVPacqXel7
         6/N1DSmSjVY7hr/QrDUZIRRGJDuPQpgib/6xnruWngIy14BSSv/Xj2zHWnSGc12v1inw
         tZpSGho96/Aju6hNIM2qcYWHClVnHyIrRJuahXcu5z3VFsxqR8Ypmh3hAUX4tnuSOTIu
         96Yfqirk+Lhl7Rf9Xr1fZ06S2EB67GEdwiiEz/Wbh95i/aOd0dz/AmTABVz8Es9JPBUd
         WLXN20eluwpvJwcGMzx9EFhk0NGqYORsuJ7oSfU6TW/O3TLhcIx/BWMMuXv05B068L0N
         whzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774008; x=1708378808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fAyqKTd8/tWwNMRw13rKQmGS0n1VEBQG9JAhQE5QHHM=;
        b=DNH8r8eGG6hXb01ZDqbrNETFf06DabqPNO85xXhFEYECE/lpxcwiMnZplX2Kfnpy/1
         JBIlEd7YCplrOs+9BgZudhn0fGDrWM2TL1tn1GaFpa21EhwhTUh/ZlrEHjPxtcTOpz6L
         2T121fHHkpOM6kZTD/LmLGCT1Lz/UDl1QI88SrIfzaF8FWBL53rGA8S10wSVETugVgLt
         CNyn0CKhGeTgLrlvE//kVg/m/ze1Ea9RQlbfTMbJ8uuYvN5tc/xlPaRCB3xqL2hBu3Dc
         X0VmO/GFVVwm+tsWqj7srkIQBapRhNoHfTYyvjZ38O44ymrC/h6AceL8jr2OzF54zTBa
         oO4A==
X-Forwarded-Encrypted: i=2; AJvYcCWHEV82cxI8xPFwLh1RO1WTIvMubN7uL5qPpdGW7Js58TXlpkTzJr50bqSQ5hZfkJqT+kQGsXELmugt4qMEjnmaQsQfsEMuBQ==
X-Gm-Message-State: AOJu0YwzlRpK5u212R/IyOAXV+/GQrWt+mqVZyyDDuHoaBKrPs0sQAyf
	BuiiZUAd8Xs3NGqtvlulPZzn2MnuW5WlqsU7Xr0OSFxlQ+lGj8ij
X-Google-Smtp-Source: AGHT+IHLz88cRSDoS08w1FT8r88QwSHnJ0k3WEVXn48C6pnjJ8yRCL3obbNirAPhDLAnR/bzrtYgeg==
X-Received: by 2002:a25:8183:0:b0:dc2:1f48:ca14 with SMTP id p3-20020a258183000000b00dc21f48ca14mr4750114ybk.12.1707774008803;
        Mon, 12 Feb 2024 13:40:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa90:0:b0:dcc:4b24:c0df with SMTP id t16-20020a25aa90000000b00dcc4b24c0dfls184168ybi.0.-pod-prod-03-us;
 Mon, 12 Feb 2024 13:40:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbczacMNhbLEoHF6J0KVa24V6fViOWwtdZ3NhtJRvm8etFluvzZ36Hkcs8e8WzqhZ0gwx2qWOdZ1OaRTLx/YpoPSxiNG4ZIH5TCA==
X-Received: by 2002:a05:690c:f91:b0:607:839d:b8e6 with SMTP id df17-20020a05690c0f9100b00607839db8e6mr65956ywb.7.1707774007990;
        Mon, 12 Feb 2024 13:40:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774007; cv=none;
        d=google.com; s=arc-20160816;
        b=HLkwUvJ76AyzMws2ah/jTCU3AXy6i+H75rz8Ya/RVjtz/VqWI1aNE2VPUhcwftQg16
         b43x6yIf0JLcqV6kVpHO7u46kv5rGucUO3v7xS0Hz9ReOLooAdorMop/8jdtz0dPVfTZ
         QVwz2+kQjfE9WiF5Vc5b/5UFJswB0O+nnONQhCtVsAYRzdJ0xqSwJ4ucbVWBTAF314L1
         gIKFWTv9qZnn1CDXy/KBachyTSHfn2iKXVDgJ9sea1wtBQpmwOnI7yonY9ZYtCw5EOAu
         fuyfRUZ0Vma0FW3GBClvX0+cwsjSXWi/uZKpgrvCR2CMWqwtovoKitoL3hB68xdswH4C
         dzSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gyt+GmM2eMHRRKEe8/8uFf8EZSlg2sZI9NA/PbSxBWI=;
        fh=gcmK+CfxWv+5TJZyMST7xpMmQBGUTfLO/Ma5fH7c7Q8=;
        b=KHXBfny7DsCrz7acIfjw64SyKJoyK2Xb1IfMUXHh/ExkmQprcsVfjOBVhysMzuSXoE
         nitFDK6FBkpKVTyMRtEMV4OFwRohmzVX0Tfd1P9tn98JKuStYLbzZ2DoQ+SuDlwbhnU/
         1yEkZWLhF6zKoMuLj1uX+T07YQCFnWgMIfUNLV0NKjGvHmVcDyb5PK6o0MJLhZDFNhtk
         jz7HJ/uDmlT5/yUzlmrGLpE6cfi8E1Ptyw2V4OTuBkn5ThOzbs4OgkwVQQIerBl5oY7e
         x9b6JdUmFcq5uLOtzYZGlf5xG5nCZDO370KBhcQ/W8POsd4XXRQS9g7qzMLiEzDdR7Ws
         l37w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EAQjCW9N;
       spf=pass (google.com: domain of 3n5dkzqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3N5DKZQYKCbYoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCW6+jtp7Bh/egKJkd8AdYesLQziS9MxsNrxrAyVZAslO9Yv95pwf8b+Ub3lowunk88dYCxDYqzFROFKpk05MMcWjtL2mGl13hYobw==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id d6-20020a0ddb06000000b006040f84d90bsi717420ywe.4.2024.02.12.13.40.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3n5dkzqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-604ab15463aso4576647b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW4hEzI2rJGZXiYrfK3B5bTH/TtTJHwL5tSGjLrIxBP7ucI1e8qqPZzWs4SDJEhOPAMv5dI5seYVc3YUBGxUp+UZVfxRovRGnE1yA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a81:848a:0:b0:604:49a1:8da0 with SMTP id
 u132-20020a81848a000000b0060449a18da0mr1393758ywf.8.1707774007616; Mon, 12
 Feb 2024 13:40:07 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:02 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-17-surenb@google.com>
Subject: [PATCH v3 16/35] change alloc_pages name in dma_map_ops to avoid name conflicts
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EAQjCW9N;       spf=pass
 (google.com: domain of 3n5dkzqykcbyoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3N5DKZQYKCbYoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-17-surenb%40google.com.
