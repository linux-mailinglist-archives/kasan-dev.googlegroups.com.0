Return-Path: <kasan-dev+bncBC7OD3FKWUERB3VD3GXAMGQEI4PJSJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CFCAB85E782
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:35 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3655fa1722bsf1231875ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544494; cv=pass;
        d=google.com; s=arc-20160816;
        b=uR6xBvPPlFtNq6irOdQsOjH9wrz0pZm980b0mF+ymIMS4ZxX4wp3bImDluDy3DaX8X
         JJQsVnrlTrzDi6hPnVsf2nhRPdhRPvzGq/YrmTlUoabAyeiexGCoCr7sHlvLow0k8eel
         7DkLxmybBoKT+TcO8RcqJKIQqh0SVt9EoV1n3bksa2vEQDlzdErhd/VBA3sHQr+r2qBe
         eqJREmNax5MfiEl2DVkGjHtBJaUJyb3OQyHjvNH0PgfBUVflRhkz1UzR5lzfHpGJE0g8
         tioin/ltBX2lq8R8Bd4JCA9m6p9kDpOPd6F8uTla0hKwU+dQp553XaO+IoxLUgkjPIm0
         onEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=o2NL8E7ClUKV0u2DvvptnPJGE1kqvQl1I+Op/gR1pEs=;
        fh=nC/4wXNKKVbacni+l+6VbR0n5kJrnKPnnkYQLghJJs8=;
        b=u5oOd80baQ9S4reAU2CTG36yi9pVxK5p3E7TjBUFnANavkTN1CL65dnm0/Xgzxc8R+
         IsVMr/fbTl7BKPAyDJy0TsrSADC0a/V8Z/eaqn3mYGzr3J8q09eEIIm51F2enIU4p/EB
         0VFxhwXIlYFsMDxTidIdnNVOrMK8uzALaiVA885hylRM48FcydhVpmsfCmwx8GMMDVo0
         jz4arP7GMP3QxYC4kiWUuoHaaEIR92y1Y9XJ6exfgplb8CqJ95HNPSTKqKnu833crtpr
         PZWvBIWA217ccLhJPL6h2SplP93NppXodHqrzLfyTI+W/CY9yuBg1i1E8tM0h12+jEMt
         oJ0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tr8Mm+Sy;
       spf=pass (google.com: domain of 37vhwzqykcsaoqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=37VHWZQYKCSAOQNAJ7CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544494; x=1709149294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=o2NL8E7ClUKV0u2DvvptnPJGE1kqvQl1I+Op/gR1pEs=;
        b=VlEJDpygvbAAO/w5ylMrF2ZMm4u7PM4Du/8d/zllYZmXoHogpx0bj/7z0ZXcXhiDRK
         vlBsJjz0jtt5gzTp5wDIwlcGkUUfTBijqpW4rakFowwmt2ZbtfpBxCOeodLAK8d2CwcD
         5EQvo2X7CfrqnXN3hl+aopoAzsG1KklKmM+0kR06pudb6+JzRNzFQmIpXAWG0LlzwnBY
         oMcImi/eaxelzxmVktYY7dW9qP5UIs6UMbmsC4s3dtCvxsqryacj5S4ujtPCyaWBlMHn
         0EJlmgsoJEq447/yeF1Gv+fgfuT7VoaLDLaIxsxpKl8UtJErPdK5iU1jSCISpCEYhnCF
         hiOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544494; x=1709149294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o2NL8E7ClUKV0u2DvvptnPJGE1kqvQl1I+Op/gR1pEs=;
        b=FQqfDhmYk2ApqqXDCAgwstbd8sJYmOZHAdJs3+pbAHd10+6O4ZW+TS2eyToXFBEUfa
         FLhlF1RUnaLMEn+K7zW7c+S2prvcAmxJ87zy/rMY+9IF6NCOnz3JRaCviWf0SkTxVdMy
         gbkbEtBbBkAKIvX2lU82/WdVqhKU/R0JVvcMjxf0NckwKharnOHHp4PkHFM26eigxs7j
         aqQtxQrdchXYBWTDB+pYlQpEllc8cFarzYppQtxNuvU/yK0ZHWqkAWJBL2yP0/4CBsvg
         GbJU/BEYdqjh4fR0NnNqA7gJ6c9FO/cgT7UpVODd3tqIWgKY+Bbem47aagSM5O1z54Qm
         yBUQ==
X-Forwarded-Encrypted: i=2; AJvYcCUwYOhcaq/L5lhuaqMcB3QY9rOB4lDGyFizY/pf1Lv7HTcfV+uXu4pC1FNg3eCXilpEpHsMMyU1BzRvAXxDqQYWfQTVnNxK7A==
X-Gm-Message-State: AOJu0YwIye+NqjMOh4wIfRab/fm+zgCdPTBrTwUYwY1WklRLPfUEjvRT
	UbWR4bU3zBjr39hz0xil3EKVll5yZOfq3qddnOdmAJSh1b6yOfDO
X-Google-Smtp-Source: AGHT+IF/pQPP5kX2C7Ca/jZPaLSac5SfX3o81SyLBQSC2XtosFZsJ/z8Xe6iCKimB4HpKJX0VbF38Q==
X-Received: by 2002:a05:6e02:19cd:b0:365:bd3:790c with SMTP id r13-20020a056e0219cd00b003650bd3790cmr419920ill.2.1708544494698;
        Wed, 21 Feb 2024 11:41:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2806:0:b0:364:ff62:9c77 with SMTP id l6-20020a922806000000b00364ff629c77ls2094523ilf.2.-pod-prod-00-us;
 Wed, 21 Feb 2024 11:41:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVH9VZs29oFDMyxSgbHes9Dstg1SkcXSQGPps6DVy62UQCq6vby7t7Y3lQ3fuJ0Z2lkAvsHm3B8UtqiA2XzPPyYUoFIhY0TTfXK+w==
X-Received: by 2002:a5e:c24c:0:b0:7c7:7a28:9d2f with SMTP id w12-20020a5ec24c000000b007c77a289d2fmr368579iop.7.1708544493920;
        Wed, 21 Feb 2024 11:41:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544493; cv=none;
        d=google.com; s=arc-20160816;
        b=X/PAHbm/RlsVqSBnTt9htdidMleaQs+0M9XA+DSFBEEwGkC0/zXk7qFFmA/zf3nb/w
         4Vo33rmdY6UFMuP8x0hY7R3IQj8MMkLODLre3JkJ+MTtIcCd/lxqgz7EGDsFypF+DW57
         vCAP/gqgGoelAJ7RbflZHp4XokWktvKxl0rGYujeSIrQh9LyjDjK8YG+8UjijHNHCtSD
         Q+opBVaBLkxAkUjmNKVtioUL16LnsUXE6JFb+E1yyosPS6YBVuzvl29C2jPYvX/U+yZQ
         U9uDGzAnjAnAZmV0VdnmvNsZNJRi9pjCiGwSFej6si2ooOGMMR47HV100xUodOTnb9y7
         hJww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/ICmwOELDDa5gDiXJ0QfSPYNwNSjuLTkQBKISvcVpvE=;
        fh=ALdeE4bP1bgEsDfIlEM8hg5DGtOdtgZxC4LUQx8z2SY=;
        b=VHOfSHGRQO0qDzVc0n9UwMJ8tXcnKrx+kNGmPKBIgS6QokFGC0fCHFpweAEE8SRsLc
         lxTiWY65vq9966iUiICfE+B7KDuvgT1Ifq2+AKTdj1JJcKS1s/6x3qQ7Kko3bTxR8P9d
         b5O2jxL3GjkWDqks8NNDZwxLHu3nn/p5F5z1lUMwud48/EGMr09t5e9NZvmvwtJxpyP5
         lrCXpmadn5bjGUpsuUfJuiL5m598PxDsvIuhqhxbAmmzhZJJju0+aDbi0JkepjmGgWcg
         z3OHHMMpHV6SBXGnKvb14cfHSgSGv8PAcYXLKVpJ/LMKpxMYim9BZr1jZhyF9qX22lEg
         Iv0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tr8Mm+Sy;
       spf=pass (google.com: domain of 37vhwzqykcsaoqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=37VHWZQYKCSAOQNAJ7CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w17-20020a0566022c1100b007c769ed87a8si135632iov.1.2024.02.21.11.41.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 37vhwzqykcsaoqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-603c0e020a6so58051297b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXNpPidUqy0iRLdXDgIXtgKw70syVFMQGA1xk6yddaujDBc6uLf7fzrq3ivMSfxa9RgxjEuQYgqdwlVo4xtlywLcWUxQeFe+SJVXg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:ab4c:0:b0:608:2137:27f6 with SMTP id
 d12-20020a81ab4c000000b00608213727f6mr2122409ywk.5.1708544493446; Wed, 21 Feb
 2024 11:41:33 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:30 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-18-surenb@google.com>
Subject: [PATCH v4 17/36] change alloc_pages name in dma_map_ops to avoid name conflicts
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
 header.i=@google.com header.s=20230601 header.b=tr8Mm+Sy;       spf=pass
 (google.com: domain of 37vhwzqykcsaoqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=37VHWZQYKCSAOQNAJ7CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-18-surenb%40google.com.
