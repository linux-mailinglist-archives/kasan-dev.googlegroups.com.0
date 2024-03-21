Return-Path: <kasan-dev+bncBC7OD3FKWUERBXGE6GXQMGQE4DS6QDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id E3223885DB3
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:49 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-22233c4914dsf1079893fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039068; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jnlfn1pjvuM5chI0y6U8JShForZDm02PY3q/2SIWdtBh/Db37II6gJVCjbWXJJzFZw
         u3FxopBh1HstMad2u/GrECd5NIwt/r+4bu/dKsPdsumWtfB8l/9o28R0Xk7aHjA7abJr
         0zfHlk4a20VNtuGf7lUn9Y0WAbO3uGwRTAC+M+rO6op6aY/TdHlC6YxOAihpcERtpmX5
         ERwCyipwbZd3sobHTPusgqKfr6nDINkmXA/3Z7JZ9QfKtL0bKUxJi/RPqAo6Zzmv5eGy
         4GCBCkilMzU54EEY4b0DzCWbpyhKQU8Blh7XCD8wQturg7xiDgwKFQVu82NIiYKTg40h
         7SUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fufnf8DECjXSu694fq3HPVeiYLHWbBZGuQyxyTn38Fw=;
        fh=JNJpqUtlTvT38qeI1tkAXjDaKrnIubGP7oZrh7jpiNk=;
        b=p9yPRxQRkC4boJZhBmN2enDacekM89oen+vnhhwIDdoZE3Tu/c++bmQ/wQDCXgir5w
         arvSasGsN2oMDm4x6Covc0U+xEFC9pHissSB21RzuJW/thmNdk5mxOw/4BoIqw/0hE2E
         BjVlonb3LejPNJG0yX6H6NmfJiL8wTIlNqb/tFQ2rMLNhOa3M2j+WdQaG9OTM774Eb0m
         QHOLUybnMGVhWARQwanvLB0tSW3lIQE6R9Sou/o1NNIH0n6JvK45MEpgOgBISuHlsjM7
         0vPt1zMjfWYX1dluOBpzATWp8HLcy6LgDA9u0XUgG/HmRDn3cA4xbYat5fXbDmV2hsDu
         AKwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hsSuM1Me;
       spf=pass (google.com: domain of 3w2l8zqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3W2L8ZQYKCUg241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039068; x=1711643868; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fufnf8DECjXSu694fq3HPVeiYLHWbBZGuQyxyTn38Fw=;
        b=aHld9kxgzVSvMdVQi64v4GbU9H5NxYK+OWop5/pAQf3G2ajoUCE/avfdqOendWH80H
         VoQ4kZY40fXlWzvHlh4Vof0gCoiZc+WUrRbTgRp4tg5OVI2lJSB3HlHtnk/s0OupVsYK
         P8uBymhtuECdmhwAm0Y1GsCltvvSE3H+ZyeLzpgcL62KBqQlT2AtSziZjoe2t8E7U7W/
         dWf0iRuHrB4zEXHpOojiwFS+Z/wIMF+11WDUyOvO6dW0QIRwaCUYvZu3izdmL2zastV6
         Ix0BMRlYQaF8I8ema/mtQwXL9cC1dp4Y/c80HNbfKmmFKbOD3e9LpySQT42xrENQOxXT
         qcrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039068; x=1711643868;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fufnf8DECjXSu694fq3HPVeiYLHWbBZGuQyxyTn38Fw=;
        b=gX1stZdJhQxoLXjgKs/D/eWS3uWmL8InHbjXVVc9Ylna1pj9GRPZP3qDIY1UKhWp9r
         ctoaGjSRsO0E4MJjrDcDKZDFnaMZS+6PXoyCWhV+M9doUP124FuWbZSmTkzBeNxqsRlq
         attFuCrSh4I1LQzimYGmF3Js7FDZt4jwPlaeQJdyClhT0LaZPOtgAUkUNoJdApVR6IVO
         n5XGOQ8oEauw+hXs2iy4wywImXHLDS/P4tZrIND/enxNRaSQCwCbeqAK6H3xUESquAHy
         yt96pAC1HyRG6ih7RdA5NwnK4Lk8wQ06OM0zvLdg7VWt0OXnqkUajOcS7Som7oCqYpSe
         zyBA==
X-Forwarded-Encrypted: i=2; AJvYcCX2JLNlK0OILNDA+76vWshmCtAypLVViMkokjg4PySoMVaULli25w6QRCtyLN06MHhOlD2iLN/fYwKzbReKSZz90n/OLLdgSA==
X-Gm-Message-State: AOJu0YyHfQWQZ2qnBJKkx1g7lzy1dQ7g+3psi5FFiAdLz9NHwT9KSanm
	KhVSQrRktiapsT5A3F35hHC7hCKxGaGGX8hvdAQ3vJtLUcEhdpKP
X-Google-Smtp-Source: AGHT+IGVF1G9LAi6XIFEgFUdgMh9bFL/CtYM3skAadnoztTgad7JTw51fYsevA0OSkcNcK6hEpYrkA==
X-Received: by 2002:a05:6870:d251:b0:21f:7e35:8f4d with SMTP id h17-20020a056870d25100b0021f7e358f4dmr26798148oac.6.1711039068812;
        Thu, 21 Mar 2024 09:37:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1587:b0:222:5ca1:6a8b with SMTP id
 j7-20020a056870158700b002225ca16a8bls1362565oab.0.-pod-prod-02-us; Thu, 21
 Mar 2024 09:37:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIPGlogapSXM9LH3gFet+z3FJZLxc1xOrHdWWtQUtIXlPqaRoVbKP8rinSGOkjDbCLCgi0BLV0mEhPVfSBS/W6EdlPHBI+bcDSDw==
X-Received: by 2002:a05:6870:4342:b0:21e:8cdb:1030 with SMTP id x2-20020a056870434200b0021e8cdb1030mr25156379oah.24.1711039067586;
        Thu, 21 Mar 2024 09:37:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039067; cv=none;
        d=google.com; s=arc-20160816;
        b=VuhU7Cyb4Tab+Nz6+gOymczhSYElQIGtT37572ft2xUqq5ONGZxy021UsaffikdoTY
         I6dJKm5TrKoFpn+Wbbh31/K5diJ/gNEHTIGnKQo9mHqSErXgCYKUAm/c5JE6Ht3bUJr/
         QGsvZzARsvOsYY73FTpmvAheJ8SNn3gdu12qZOP1SOkDHMGP3AyKknRgymsi6Vk4b7yB
         TTcc/QLaLj1IpuBrhpxyLAz9X92pnbH+ZXcqLZhhnB/HzGHQCI+OeRpe1lKEwiEZOzwa
         W9NUJnnRzpfBN4QHXycQ9CpbRURXOa8GWoCsaYjdWnTXmuTittXVi30oDShK4nV9WaCf
         I+Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jp7kzC4k0D+sc/q1IPxvwe52UJDwCcNnw+Zbq+7qIDQ=;
        fh=m406xatat6YosWCYnpRJPiXvTadGAVgLX+enIkwZYy4=;
        b=qnTYPKUCAt3WMqaNBMMkq9sHtRV6y8Wg9EV/pcm0djGa6e/OySzaPLdt/sRLcD5y9H
         JmkdFm1Rk9xiuIC2BMgOZ4zbJT1JLFLn5iAvLqaSlPmTC1iyDwcklXt0OHHAjY5C36pU
         mHcHenOmbOVt74z+pmQh2CGlcrLZWW5GOb7C6uHbOdVemoeNbbrlU37ur57jcIVkw3g3
         SewU1R2LeboBDsdmRGs5xYE9wl4kSPEqYNHsp9umasajJuBfdKC0IDx4ReJj1JfCqJL+
         PFOMyCGifqxmcfimRVfzW8bzMrYgaifKQD9jwNDY3JPaLqFuws6NCvOKwbn2Rofb8gV9
         DQCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hsSuM1Me;
       spf=pass (google.com: domain of 3w2l8zqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3W2L8ZQYKCUg241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id hm14-20020a0568701b8e00b00221d905d771si34653oab.2.2024.03.21.09.37.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3w2l8zqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60a605154d0so14620167b3.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDirbaRTJOKahf9Uvy8ALkFHDQalmSQ+ye+oh2yAN03FhPt055m8W73RBBHHS+V4cN+d+P45lPmiKRTjc5yhpbBKkHHz4n6mlYKQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:690c:6f91:b0:60a:1844:74ef with SMTP id
 je17-20020a05690c6f9100b0060a184474efmr881713ywb.1.1711039067006; Thu, 21 Mar
 2024 09:37:47 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:39 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-18-surenb@google.com>
Subject: [PATCH v6 17/37] change alloc_pages name in dma_map_ops to avoid name conflicts
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=hsSuM1Me;       spf=pass
 (google.com: domain of 3w2l8zqykcug241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3W2L8ZQYKCUg241oxlqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--surenb.bounces.google.com;
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
index 90ff85c879bf..477c1d5e1737 100644
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
index b58f5a3311c3..6ba52481a1d7 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1715,7 +1715,7 @@ static const struct dma_map_ops iommu_dma_ops = {
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-18-surenb%40google.com.
