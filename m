Return-Path: <kasan-dev+bncBC7OD3FKWUERBLOVYOPAMGQEUH74XIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FF5C67ABF9
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:39:10 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-4c8e781bc0asf183724337b3.22
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:39:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635949; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkz6zJHikcrmc2ic61fV0X7kSEW4RXLkfNKpE8W5aerXND1prXqv665MlplIYiuCMv
         25EkQt6IPO0pluJvGcuXXkilCvtC525v3MNsR202B8szcGzTlPpu/KxvHzRj9diuC2kw
         WDRNQg7bxM/7wW10+FLiBD2NCOzfQbodszkXsFbfkqvD/I4PgPPROThLmwdQbEI5hepC
         cKDgd3LLlcK2cvZdjL86M7z9cws3AbdzshMlc/47V6P6VDVbpPBTN0nwvcZJ7gD67m5g
         Rv0Aob8405mnmj3Jv9RtBY8i/27CnRHn9fEKYe54IdoMBP03qE+P3tkOozsjGSUKw3R2
         T2rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VWh93l0m/UNYpbHQTv73BnMU+LYuhCwDPn8Ch5wRMxs=;
        b=XBksWoC+h98gaWBWcWlxzlYWyd06BbeLlggYvc3ki0hYqDA4NgBPsiK0a9BOcwjmPf
         ke/p47ePBNKSIgk4ZHZuesl5osIpHUCRcVoXFfVTn0H8S7nlay7WzH/QSr2uUh0LnVXc
         bD2lXQ43sDLB9kCI4KydcHPeH3wRNorNbi5q/QCxp23oZBHDGPJJhNUAyqHx6zZ6fwYf
         mT8F6vupVA4lnMJdh2rz5KmonZli3/8atdVfvqITOc2z6jvqj+XOXfiSJZBIrjbbsrZm
         fQs06qeyyEzGeTjEmclhqPIKjhtJif1GMSaET7Waj6t1c8J3LeUphzEA38pLOv4YG/44
         HfcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MF4o67HH;
       spf=pass (google.com: domain of 3rorqywykcekdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3rOrQYwYKCekdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VWh93l0m/UNYpbHQTv73BnMU+LYuhCwDPn8Ch5wRMxs=;
        b=GFbeMFEyB5L+P8hAGchiYred+Jtgu3JX6hAGNQ+QCP6vc/wIXgHQNUDd/Ghe7p4G69
         /dgipo7G99hT3FbwGpTeV8exuan6DpWRg+5E14ttw8JUPKOJ5tjzDhJ2/dPXiPdQmuam
         5GstR+bCRCi9XWBiGlIMTerlGCneKnTIt0od3bH/UIp8qsElSGd8A3R7uQ7XXewvlgML
         85o2wekLH3yHynfnO/hWNOlpLqEBFgBV5zhPxtFFHzAgp/SEErMCROeBF+dwxo3ZUQEk
         51UAKrwOvaYVhPqfBf3mTUxODwdbJrmPjizOPt/ZREwpAC0yvP3jButSdwCiNZUolrqJ
         WN2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=VWh93l0m/UNYpbHQTv73BnMU+LYuhCwDPn8Ch5wRMxs=;
        b=Z8sMhHCIJTvpGMANkydGnpEC+ayNndG5yTagvaD6GvzxEpvluvRwv2lswIhmxhsMWn
         +zrg+tv6nXOcj+RNhu0A7PPg82jPmRZo8nLNiU8xFla8dfDHBK9pp2YmbRGQEYCSs/T4
         2bwpO1AAoWC2fDWns866ugA/Hn6efWhgdnUQ4NS+D0syEiC7+KyUs0TeoT9FrW5FT6X5
         iXaiTVO+CCArfuOObZsrzWNGJRFSKigNn40pbO0aUjo+r54FX61fO0W4oM7+zoFwr2S5
         8SKwqv6quuoHJy2kE2Gg4JDC2iHeuGfdLIxRbp+bukNZoNCrO7tuQ87ennk9e8OoZuIH
         VO7Q==
X-Gm-Message-State: AFqh2kp2vLLzHmUHnyJkcSO9GtRzbXLONEKlU+LZTTVF5RaZbzzh5tKn
	d1onKSh6xhKEK2E/A/WJq6U=
X-Google-Smtp-Source: AMrXdXvyVShmGDd9OIB2+nKIOmdc5Z7wYrMVcvxqK9JGYhxVarNbpXPuKqaaKr3Iy2ED0oVp6S8hXA==
X-Received: by 2002:a0d:cbcc:0:b0:502:7d37:f626 with SMTP id n195-20020a0dcbcc000000b005027d37f626mr2177160ywd.58.1674635949317;
        Wed, 25 Jan 2023 00:39:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7711:0:b0:80b:66db:2f94 with SMTP id s17-20020a257711000000b0080b66db2f94ls2555645ybc.10.-pod-prod-gmail;
 Wed, 25 Jan 2023 00:39:08 -0800 (PST)
X-Received: by 2002:a5b:702:0:b0:80b:acef:7744 with SMTP id g2-20020a5b0702000000b0080bacef7744mr456129ybq.52.1674635948774;
        Wed, 25 Jan 2023 00:39:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635948; cv=none;
        d=google.com; s=arc-20160816;
        b=Ekl8mmXcWMr6X0RMEXWMoWleeybtVu45LX9RGCZIqntSUIYH5BkaRtvFwtaMywIYlc
         FmYsB9POFDKWSba6u3vcKvglXoBJ8NwXe+Q4puQil/fiT+kpmpD69HYUMMVBDQPo267L
         jGj97rMUO+5pxXDcuDu1dfxz+rG+GvT4cPsdn9weC7VbEqBZgF9OOse4jViS70uJJ95E
         RYVFE1C3bTkHwcPbFxRcfXsiQkgd65lsxdSMMMgGebVXTTLStBDWVYDPa4kDJIr1t0lA
         XW6bmJ3nJh0f4Zq1wFLCiKWbeFcpIZP7Hd4gZlNhikRsYeb5OrVOAM86xKA4EMFJ0caY
         deLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sj271avprjKe1me6H/esP7A1ES+jGLLWBsFdbdzx2Jg=;
        b=iRjeFAThHTTsMKQcxyM0ITFnI7y46N5P/iOfl4OBvLdvOvcdjNeVpXxGHjWvQHwixe
         DqbsnEkZg69fA0NFxOeVV7BbBcCCRye2+KbjWUL1PCbJVlsgzmh8zUeQb3ZPFnPNYgEi
         dFdUjCZV8VOrz5Fi+2uBLo1ZS+M1U2/lCdXvL+YdQKKNRPL+8M2WUjSxU3ubOvsBsO2e
         +4Sos2OoeXGS3wepBKT8ln5+DvJiOL59PRhWTnezKiIh0WK4tjmIt2Uje7EK9608BeRx
         89JQxESPBHNagSa91ImoB2FjpF3WwNpHq2a4P2dVtMlZuP830AhwB4r7LOpqZM8fZ9D6
         cxWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MF4o67HH;
       spf=pass (google.com: domain of 3rorqywykcekdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3rOrQYwYKCekdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id x142-20020a25e094000000b008015c6cea1csi523449ybg.3.2023.01.25.00.39.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:39:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rorqywykcekdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id n194-20020a2540cb000000b008038647d9ebso13553498yba.5
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:39:08 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:f7b0:20e8:ce66:f98])
 (user=surenb job=sendgmr) by 2002:a25:2bc1:0:b0:7fe:35ff:fddb with SMTP id
 r184-20020a252bc1000000b007fe35fffddbmr2303833ybr.466.1674635948201; Wed, 25
 Jan 2023 00:39:08 -0800 (PST)
Date: Wed, 25 Jan 2023 00:38:50 -0800
In-Reply-To: <20230125083851.27759-1-surenb@google.com>
Mime-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com>
X-Mailer: git-send-email 2.39.1.405.gd4c25cc71f-goog
Message-ID: <20230125083851.27759-6-surenb@google.com>
Subject: [PATCH v2 5/6] mm: introduce mod_vm_flags_nolock and use it in untrack_pfn
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
 header.i=@google.com header.s=20210112 header.b=MF4o67HH;       spf=pass
 (google.com: domain of 3rorqywykcekdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3rOrQYwYKCekdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
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

In cases when VMA flags are modified after VMA was isolated and mmap_lock
was downgraded, flags modifications would result in an assertion because
mmap write lock is not held.
Introduce mod_vm_flags_nolock to be used in such situation.
Pass a hint to untrack_pfn to conditionally use mod_vm_flags_nolock for
flags modification and to avoid assertion.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/x86/mm/pat/memtype.c | 10 +++++++---
 include/linux/mm.h        | 12 +++++++++---
 include/linux/pgtable.h   |  5 +++--
 mm/memory.c               | 13 +++++++------
 mm/memremap.c             |  4 ++--
 mm/mmap.c                 | 16 ++++++++++------
 6 files changed, 38 insertions(+), 22 deletions(-)

diff --git a/arch/x86/mm/pat/memtype.c b/arch/x86/mm/pat/memtype.c
index ae9645c900fa..d8adc0b42cf2 100644
--- a/arch/x86/mm/pat/memtype.c
+++ b/arch/x86/mm/pat/memtype.c
@@ -1046,7 +1046,7 @@ void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot, pfn_t pfn)
  * can be for the entire vma (in which case pfn, size are zero).
  */
 void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
-		 unsigned long size)
+		 unsigned long size, bool mm_wr_locked)
 {
 	resource_size_t paddr;
 	unsigned long prot;
@@ -1065,8 +1065,12 @@ void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
 		size = vma->vm_end - vma->vm_start;
 	}
 	free_pfn_range(paddr, size);
-	if (vma)
-		clear_vm_flags(vma, VM_PAT);
+	if (vma) {
+		if (mm_wr_locked)
+			clear_vm_flags(vma, VM_PAT);
+		else
+			mod_vm_flags_nolock(vma, 0, VM_PAT);
+	}
 }
 
 /*
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 55335edd1373..48d49930c411 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -656,12 +656,18 @@ static inline void clear_vm_flags(struct vm_area_struct *vma,
 	vma->vm_flags &= ~flags;
 }
 
+static inline void mod_vm_flags_nolock(struct vm_area_struct *vma,
+				       unsigned long set, unsigned long clear)
+{
+	vma->vm_flags |= set;
+	vma->vm_flags &= ~clear;
+}
+
 static inline void mod_vm_flags(struct vm_area_struct *vma,
 				unsigned long set, unsigned long clear)
 {
 	mmap_assert_write_locked(vma->vm_mm);
-	vma->vm_flags |= set;
-	vma->vm_flags &= ~clear;
+	mod_vm_flags_nolock(vma, set, clear);
 }
 
 static inline void vma_set_anonymous(struct vm_area_struct *vma)
@@ -2087,7 +2093,7 @@ static inline void zap_vma_pages(struct vm_area_struct *vma)
 }
 void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
 		struct vm_area_struct *start_vma, unsigned long start,
-		unsigned long end);
+		unsigned long end, bool mm_wr_locked);
 
 struct mmu_notifier_range;
 
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 5fd45454c073..c63cd44777ec 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1185,7 +1185,8 @@ static inline int track_pfn_copy(struct vm_area_struct *vma)
  * can be for the entire vma (in which case pfn, size are zero).
  */
 static inline void untrack_pfn(struct vm_area_struct *vma,
-			       unsigned long pfn, unsigned long size)
+			       unsigned long pfn, unsigned long size,
+			       bool mm_wr_locked)
 {
 }
 
@@ -1203,7 +1204,7 @@ extern void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot,
 			     pfn_t pfn);
 extern int track_pfn_copy(struct vm_area_struct *vma);
 extern void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
-			unsigned long size);
+			unsigned long size, bool mm_wr_locked);
 extern void untrack_pfn_moved(struct vm_area_struct *vma);
 #endif
 
diff --git a/mm/memory.c b/mm/memory.c
index d6902065e558..5b11b50e2c4a 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -1613,7 +1613,7 @@ void unmap_page_range(struct mmu_gather *tlb,
 static void unmap_single_vma(struct mmu_gather *tlb,
 		struct vm_area_struct *vma, unsigned long start_addr,
 		unsigned long end_addr,
-		struct zap_details *details)
+		struct zap_details *details, bool mm_wr_locked)
 {
 	unsigned long start = max(vma->vm_start, start_addr);
 	unsigned long end;
@@ -1628,7 +1628,7 @@ static void unmap_single_vma(struct mmu_gather *tlb,
 		uprobe_munmap(vma, start, end);
 
 	if (unlikely(vma->vm_flags & VM_PFNMAP))
-		untrack_pfn(vma, 0, 0);
+		untrack_pfn(vma, 0, 0, mm_wr_locked);
 
 	if (start != end) {
 		if (unlikely(is_vm_hugetlb_page(vma))) {
@@ -1675,7 +1675,7 @@ static void unmap_single_vma(struct mmu_gather *tlb,
  */
 void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
 		struct vm_area_struct *vma, unsigned long start_addr,
-		unsigned long end_addr)
+		unsigned long end_addr, bool mm_wr_locked)
 {
 	struct mmu_notifier_range range;
 	struct zap_details details = {
@@ -1689,7 +1689,8 @@ void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
 				start_addr, end_addr);
 	mmu_notifier_invalidate_range_start(&range);
 	do {
-		unmap_single_vma(tlb, vma, start_addr, end_addr, &details);
+		unmap_single_vma(tlb, vma, start_addr, end_addr, &details,
+				 mm_wr_locked);
 	} while ((vma = mas_find(&mas, end_addr - 1)) != NULL);
 	mmu_notifier_invalidate_range_end(&range);
 }
@@ -1723,7 +1724,7 @@ void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
 	 * unmap 'address-end' not 'range.start-range.end' as range
 	 * could have been expanded for hugetlb pmd sharing.
 	 */
-	unmap_single_vma(&tlb, vma, address, end, details);
+	unmap_single_vma(&tlb, vma, address, end, details, false);
 	mmu_notifier_invalidate_range_end(&range);
 	tlb_finish_mmu(&tlb);
 }
@@ -2492,7 +2493,7 @@ int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
 
 	err = remap_pfn_range_notrack(vma, addr, pfn, size, prot);
 	if (err)
-		untrack_pfn(vma, pfn, PAGE_ALIGN(size));
+		untrack_pfn(vma, pfn, PAGE_ALIGN(size), true);
 	return err;
 }
 EXPORT_SYMBOL(remap_pfn_range);
diff --git a/mm/memremap.c b/mm/memremap.c
index 08cbf54fe037..2f88f43d4a01 100644
--- a/mm/memremap.c
+++ b/mm/memremap.c
@@ -129,7 +129,7 @@ static void pageunmap_range(struct dev_pagemap *pgmap, int range_id)
 	}
 	mem_hotplug_done();
 
-	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range));
+	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range), true);
 	pgmap_array_delete(range);
 }
 
@@ -276,7 +276,7 @@ static int pagemap_range(struct dev_pagemap *pgmap, struct mhp_params *params,
 	if (!is_private)
 		kasan_remove_zero_shadow(__va(range->start), range_len(range));
 err_kasan:
-	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range));
+	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range), true);
 err_pfn_remap:
 	pgmap_array_delete(range);
 	return error;
diff --git a/mm/mmap.c b/mm/mmap.c
index 2c6e9072e6a8..69d440997648 100644
--- a/mm/mmap.c
+++ b/mm/mmap.c
@@ -78,7 +78,7 @@ core_param(ignore_rlimit_data, ignore_rlimit_data, bool, 0644);
 static void unmap_region(struct mm_struct *mm, struct maple_tree *mt,
 		struct vm_area_struct *vma, struct vm_area_struct *prev,
 		struct vm_area_struct *next, unsigned long start,
-		unsigned long end);
+		unsigned long end, bool mm_wr_locked);
 
 static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
 {
@@ -2136,14 +2136,14 @@ static inline void remove_mt(struct mm_struct *mm, struct ma_state *mas)
 static void unmap_region(struct mm_struct *mm, struct maple_tree *mt,
 		struct vm_area_struct *vma, struct vm_area_struct *prev,
 		struct vm_area_struct *next,
-		unsigned long start, unsigned long end)
+		unsigned long start, unsigned long end, bool mm_wr_locked)
 {
 	struct mmu_gather tlb;
 
 	lru_add_drain();
 	tlb_gather_mmu(&tlb, mm);
 	update_hiwater_rss(mm);
-	unmap_vmas(&tlb, mt, vma, start, end);
+	unmap_vmas(&tlb, mt, vma, start, end, mm_wr_locked);
 	free_pgtables(&tlb, mt, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
 				 next ? next->vm_start : USER_PGTABLES_CEILING);
 	tlb_finish_mmu(&tlb);
@@ -2391,7 +2391,11 @@ do_vmi_align_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
 			mmap_write_downgrade(mm);
 	}
 
-	unmap_region(mm, &mt_detach, vma, prev, next, start, end);
+	/*
+	 * We can free page tables without write-locking mmap_lock because VMAs
+	 * were isolated before we downgraded mmap_lock.
+	 */
+	unmap_region(mm, &mt_detach, vma, prev, next, start, end, !downgrade);
 	/* Statistics and freeing VMAs */
 	mas_set(&mas_detach, start);
 	remove_mt(mm, &mas_detach);
@@ -2704,7 +2708,7 @@ unsigned long mmap_region(struct file *file, unsigned long addr,
 
 		/* Undo any partial mapping done by a device driver. */
 		unmap_region(mm, &mm->mm_mt, vma, prev, next, vma->vm_start,
-			     vma->vm_end);
+			     vma->vm_end, true);
 	}
 	if (file && (vm_flags & VM_SHARED))
 		mapping_unmap_writable(file->f_mapping);
@@ -3031,7 +3035,7 @@ void exit_mmap(struct mm_struct *mm)
 	tlb_gather_mmu_fullmm(&tlb, mm);
 	/* update_hiwater_rss(mm) here? but nobody should be looking */
 	/* Use ULONG_MAX here to ensure all VMAs in the mm are unmapped */
-	unmap_vmas(&tlb, &mm->mm_mt, vma, 0, ULONG_MAX);
+	unmap_vmas(&tlb, &mm->mm_mt, vma, 0, ULONG_MAX, false);
 	mmap_read_unlock(mm);
 
 	/*
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125083851.27759-6-surenb%40google.com.
