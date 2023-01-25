Return-Path: <kasan-dev+bncBC7OD3FKWUERBJOVYOPAMGQEEXVZ37Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5731867ABED
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:39:03 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id x9-20020a056e021ca900b0030f177273c3sf11955454ill.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:39:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635942; cv=pass;
        d=google.com; s=arc-20160816;
        b=0HGhizrQZv4J7g6PNPtkIne6eQIaBcwQbUjqruARFhy5AOZ1RIX+E0g2P3TmO3jKrq
         3GsbZxWyzAJx7QsjFVna44fT5eZ2l3hyve+n797DRlHpZOXYkmOP0f0QbgbCIK1EoGlN
         fH23mp4Z81acsYpD2Ssm7f76g63rm2eyOkGPk+mOseyIEc7qhtH6M2Ysxe2kKnbrFREV
         RiOrYIGlsHB9CLn0dwjdqDnJBmHA+LoJ36h+nJVmRk8KE8Vv4eopik3vfbK/7TJCABF0
         dC1tXYEVCo1HRxQxwVv0eqC/dJJIE1e6fIVIJteVSC1tvQOuvc2vh5WYNQmgx5LcSKjM
         3Vpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=06buinesBkj+VylUlmNXUCem3ypfBD6r+RdC2wNLbwY=;
        b=ZMBx/kVhtKP58IE6rHW/b76H25gBvUrrUsqIYXyM0Yelvur8gFfvruSebwk/GsA7m0
         UgvsmU/1jnxBQt1G3pxaDWbae3RRMl2e3jj817gHkRCMs8PbMwxcEu1Mze6C67ys7IdV
         +1SFPQtncor5iOZPrApC0QRgzGSX5yNiBIVW/p+jIAs6IgyIAgPLTS8/XOk6EdLh5Cky
         DbzphPy5511Z6SuYsTNYIiNrSEnilo1UHAAc2nCcWyOR3rAoo5jEHy8HH7l0YAZdERZb
         rEsFxdszyG2wqAyZdSiBk9WKPv5YdlM/p+5kCPDDIxUyLii+OuhFyhynz4dwDXJx8S7T
         WGog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n8rHaHJ5;
       spf=pass (google.com: domain of 3porqywykceevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3pOrQYwYKCeEVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=06buinesBkj+VylUlmNXUCem3ypfBD6r+RdC2wNLbwY=;
        b=A7qiK9lskFn3zykK5MhUK7zJualMEWlctIaIdFVPYmNx9LCrISDIK825u4Gsfhfkgk
         wtQb6YeuVek3QiDtDhYJ5H7TH4EPU7D8xqkVB6DGtuUM6HMvTMOQT3G/JD0RjYAKNIpe
         05/tpAQ1VHTNTQEECcV+fcKp6QJTOzet0jkAjGha1Q4rWB/HHXFMCggUFbDQbe5q4+vR
         lYWi2n+xbdk0O0RnvFxtZLFMn0QW9T75pYKGDHI88rLZyhGr0PezcoQJRM7fSbgg3NgW
         exzhAXjMkJQgunK0KN3+5onzAhoF8I7cmBvZ03wWURFTjeaamTZqrOgoEtk/lgTX2aVX
         W52Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=06buinesBkj+VylUlmNXUCem3ypfBD6r+RdC2wNLbwY=;
        b=qj7ROb9lcfiSwIZqF71WUREoQloXNXNAhF05Dl8uxtox9OhQZDF4qUoKvevVx2tydc
         v2FXfa8h1TmeujEhhZhC4O8/gUSiw/Ce4x/w3q8fVVYLeDDXmLV9LOncc1Lrh7FXkfxf
         NGRlKHpgVIf5hUkAgfuUthbvPAdGgZO6ZiY9RzfUgqNYTMiMmcv6kEUCU1pwFKuWBCfn
         t0UCJ6ZJ4xhQNoAP30yrVTNV4e10QDvi2b7rYvrG+WmGzps0sZt63GmOcvs+AYcE+UWN
         iDOLMcs/s/2P4D5TIUkBc1eqv89WaVM1K4aE0JY6ANitxMDCwCGtHdC7gzzZW2o6FzoC
         FrLw==
X-Gm-Message-State: AFqh2kot7icwHIjpBBq4a/yXrByEZIjLPX4fANsLSNnpSiGeuzWE2wGP
	IZJZsZECw5y+ZDwwRKPsVeU=
X-Google-Smtp-Source: AMrXdXsPz7ICv5icEpk2kEZlxBSENvwxZGXpnnGO0aSrStxXIanqQpysOzZjUsisuGc9D9hYOHl3ZQ==
X-Received: by 2002:a05:6638:36e9:b0:39e:6a9f:67d0 with SMTP id t41-20020a05663836e900b0039e6a9f67d0mr3135275jau.122.1674635941854;
        Wed, 25 Jan 2023 00:39:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d08:b0:30d:7b4a:439d with SMTP id
 g8-20020a056e020d0800b0030d7b4a439dls5928909ilj.9.-pod-prod-gmail; Wed, 25
 Jan 2023 00:39:01 -0800 (PST)
X-Received: by 2002:a92:d70e:0:b0:30d:aed2:20aa with SMTP id m14-20020a92d70e000000b0030daed220aamr22001804iln.29.1674635941436;
        Wed, 25 Jan 2023 00:39:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635941; cv=none;
        d=google.com; s=arc-20160816;
        b=cUZQ+///7dptZ5oYrjPdDWk4yzL71jiSqVv5JTITjL4WRZpp8KM0FwYBr59LFnz9wr
         5zNiDUXNr0Pr5iiScAA3pPsUZbdK5x/bpiFjzqHlsoURkXEfeh9XS0+dv2H+oN2GQSds
         OyzKhpPwB+qtu5UEhf0i7oX+MhQI5sfnyaPsDBo0AX6SR+p/E4/X7UUDz2EnY8lImE6t
         PTKd4nDHA5UkYIf4xrEfULi69HOSP35WguJLsRbgWHcFIyuIrhDT769LKALAFFoI3CQI
         xD9zAtUN27DNqXS5PQVQsuBSAgX/qTj9cFAndg5fZv7q2+Y/3EWIJnY5CD79pxM0JCOa
         yoiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lALTt0Cs0OJR7OUarHpyHJwBeXB89z2/3DAseSYxnFw=;
        b=cVIGbpFFTvizrdK/tCf5ykih4SNiJ4CnL3/KnJwY2Wd0In9uRQg99hkRjlEJPvmdJ9
         J/wCA3txsIgVqRnF7x8xCtiRx3gTgLQ4P5MdH0xwa9xdckhhTWz9DuFPE5IR9kODUudv
         4iEAmiogBkgRc1cfc+k1ZLD67j4b0bFKIUSpYXVnC6KyApyzXM3Nu1mSBahEmR2XVlg+
         52earduQ4lCNnltBLslHdbvG2HezqygDvAaUiYEncjDxNkD2zh1aiVgbJVmeN1v5mPGQ
         iFYRECcj/xx4he+B4qNzI1fW6SpDPo5gaWXEiBUFEdSxIe6GNemuwi+2FW6YipCjd/+Y
         DiLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n8rHaHJ5;
       spf=pass (google.com: domain of 3porqywykceevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3pOrQYwYKCeEVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id v10-20020a056638358a00b003a2f65364e7si473055jal.1.2023.01.25.00.39.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:39:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3porqywykceevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5066df312d7so9489297b3.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:39:01 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:f7b0:20e8:ce66:f98])
 (user=surenb job=sendgmr) by 2002:a25:c057:0:b0:802:898f:6e73 with SMTP id
 c84-20020a25c057000000b00802898f6e73mr2020239ybf.411.1674635940754; Wed, 25
 Jan 2023 00:39:00 -0800 (PST)
Date: Wed, 25 Jan 2023 00:38:47 -0800
In-Reply-To: <20230125083851.27759-1-surenb@google.com>
Mime-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com>
X-Mailer: git-send-email 2.39.1.405.gd4c25cc71f-goog
Message-ID: <20230125083851.27759-3-surenb@google.com>
Subject: [PATCH v2 2/6] mm: replace VM_LOCKED_CLEAR_MASK with VM_LOCKED_MASK
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
 header.i=@google.com header.s=20210112 header.b=n8rHaHJ5;       spf=pass
 (google.com: domain of 3porqywykceevxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3pOrQYwYKCeEVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
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

To simplify the usage of VM_LOCKED_CLEAR_MASK in clear_vm_flags(),
replace it with VM_LOCKED_MASK bitmask and convert all users.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/mm.h | 4 ++--
 kernel/fork.c      | 2 +-
 mm/hugetlb.c       | 4 ++--
 mm/mlock.c         | 6 +++---
 mm/mmap.c          | 6 +++---
 mm/mremap.c        | 2 +-
 6 files changed, 12 insertions(+), 12 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index b71f2809caac..da62bdd627bf 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -421,8 +421,8 @@ extern unsigned int kobjsize(const void *objp);
 /* This mask defines which mm->def_flags a process can inherit its parent */
 #define VM_INIT_DEF_MASK	VM_NOHUGEPAGE
 
-/* This mask is used to clear all the VMA flags used by mlock */
-#define VM_LOCKED_CLEAR_MASK	(~(VM_LOCKED | VM_LOCKONFAULT))
+/* This mask represents all the VMA flag bits used by mlock */
+#define VM_LOCKED_MASK	(VM_LOCKED | VM_LOCKONFAULT)
 
 /* Arch-specific flags to clear when updating VM flags on protection change */
 #ifndef VM_ARCH_CLEAR
diff --git a/kernel/fork.c b/kernel/fork.c
index 6683c1b0f460..03d472051236 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -669,7 +669,7 @@ static __latent_entropy int dup_mmap(struct mm_struct *mm,
 			tmp->anon_vma = NULL;
 		} else if (anon_vma_fork(tmp, mpnt))
 			goto fail_nomem_anon_vma_fork;
-		tmp->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
+		clear_vm_flags(tmp, VM_LOCKED_MASK);
 		file = tmp->vm_file;
 		if (file) {
 			struct address_space *mapping = file->f_mapping;
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index d20c8b09890e..4ecdbad9a451 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -6973,8 +6973,8 @@ static unsigned long page_table_shareable(struct vm_area_struct *svma,
 	unsigned long s_end = sbase + PUD_SIZE;
 
 	/* Allow segments to share if only one is marked locked */
-	unsigned long vm_flags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
-	unsigned long svm_flags = svma->vm_flags & VM_LOCKED_CLEAR_MASK;
+	unsigned long vm_flags = vma->vm_flags & ~VM_LOCKED_MASK;
+	unsigned long svm_flags = svma->vm_flags & ~VM_LOCKED_MASK;
 
 	/*
 	 * match the virtual addresses, permission and the alignment of the
diff --git a/mm/mlock.c b/mm/mlock.c
index 0336f52e03d7..5c4fff93cd6b 100644
--- a/mm/mlock.c
+++ b/mm/mlock.c
@@ -497,7 +497,7 @@ static int apply_vma_lock_flags(unsigned long start, size_t len,
 		if (vma->vm_start != tmp)
 			return -ENOMEM;
 
-		newflags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
+		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
 		newflags |= flags;
 		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
 		tmp = vma->vm_end;
@@ -661,7 +661,7 @@ static int apply_mlockall_flags(int flags)
 	struct vm_area_struct *vma, *prev = NULL;
 	vm_flags_t to_add = 0;
 
-	current->mm->def_flags &= VM_LOCKED_CLEAR_MASK;
+	current->mm->def_flags &= ~VM_LOCKED_MASK;
 	if (flags & MCL_FUTURE) {
 		current->mm->def_flags |= VM_LOCKED;
 
@@ -681,7 +681,7 @@ static int apply_mlockall_flags(int flags)
 	for_each_vma(vmi, vma) {
 		vm_flags_t newflags;
 
-		newflags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
+		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
 		newflags |= to_add;
 
 		/* Ignore errors */
diff --git a/mm/mmap.c b/mm/mmap.c
index d4abc6feced1..323bd253b25a 100644
--- a/mm/mmap.c
+++ b/mm/mmap.c
@@ -2671,7 +2671,7 @@ unsigned long mmap_region(struct file *file, unsigned long addr,
 		if ((vm_flags & VM_SPECIAL) || vma_is_dax(vma) ||
 					is_vm_hugetlb_page(vma) ||
 					vma == get_gate_vma(current->mm))
-			vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
+			clear_vm_flags(vma, VM_LOCKED_MASK);
 		else
 			mm->locked_vm += (len >> PAGE_SHIFT);
 	}
@@ -3340,8 +3340,8 @@ static struct vm_area_struct *__install_special_mapping(
 	vma->vm_start = addr;
 	vma->vm_end = addr + len;
 
-	vma->vm_flags = vm_flags | mm->def_flags | VM_DONTEXPAND | VM_SOFTDIRTY;
-	vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
+	init_vm_flags(vma, (vm_flags | mm->def_flags |
+		      VM_DONTEXPAND | VM_SOFTDIRTY) & ~VM_LOCKED_MASK);
 	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
 
 	vma->vm_ops = ops;
diff --git a/mm/mremap.c b/mm/mremap.c
index 1b3ee02bead7..35db9752cb6a 100644
--- a/mm/mremap.c
+++ b/mm/mremap.c
@@ -687,7 +687,7 @@ static unsigned long move_vma(struct vm_area_struct *vma,
 
 	if (unlikely(!err && (flags & MREMAP_DONTUNMAP))) {
 		/* We always clear VM_LOCKED[ONFAULT] on the old vma */
-		vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
+		clear_vm_flags(vma, VM_LOCKED_MASK);
 
 		/*
 		 * anon_vma links of the old vma is no longer needed after its page
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125083851.27759-3-surenb%40google.com.
