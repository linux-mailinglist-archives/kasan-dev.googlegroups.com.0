Return-Path: <kasan-dev+bncBC7OD3FKWUERBI6VYOPAMGQENERKMSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id E048267ABEB
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:39:01 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id x10-20020a170902ec8a00b001949f64986bsf10377744plg.12
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:39:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635940; cv=pass;
        d=google.com; s=arc-20160816;
        b=U/RuoqgnQEiaVoMhFonF5XNgdi7q+DqGOfaPH0nC+DxJY3+pmZw7Rn3dd2lD1w+JAc
         lNmmtYwQf4T/lnXTrKW3XUTu7HbawxiLvtGslPiTzeUelRo1iRrIpTB+xYAz5qidWvF/
         S6/MV+Paa4vODbLrpRKJFEf2iG6yBk7mlCJM3izE2hDcKpLkZA/YLFhTufV+t/HIDL5j
         rCQQsf3uJHt0PDMd4i/VOQfmpDscwh/La14PIhUgr3qCClBGU+psnSqUXkLQzEMVYCZR
         jkd+9fdycXHIy6pUQ1PuDbPvSncVl5JbfMACxM9Sgi02z7vcuojfgE1C4bCDkI4YqR1S
         1MfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bP+b8RFCwrXf9ijiaefOsgSJbqyFhteXIJsyEqG7DPE=;
        b=cD0iBEWKLWMq1KTkb/6M95aDHncxMif3/RRBjJulIhV8CFSUHIENZ4cJEkLLpArMNA
         SSCx4eBNvCcmO5htVrT6KqsxjVPFht7viIp7+0KAWUqWZ/8oMAA5XEMFsAEtMyNu1ry+
         o9S8HX0MBS644dwlGpisuRP6aAMlO3lBxDtQM4ETdOqxHA3oG674tRwXcwczvMuKkjL4
         CDRtGr63Sm2Y9S8GfvJdPK+MUdiWBPMaeXKfiHuRHwMoI/P+Q6r5LjB3DtQ0w/T71RV/
         OflIgwOD4JUOBt+B0jlFk5yuZxok6nUWY1a3M7z7UhOJxmuCep5RVscMSOvVpIomUDuh
         HkMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FpW3Zfeo;
       spf=pass (google.com: domain of 3ourqywykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ourQYwYKCd8TVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bP+b8RFCwrXf9ijiaefOsgSJbqyFhteXIJsyEqG7DPE=;
        b=ZV2AH9cQM10GJlH+6CwZ2fYXlrrIIgKdVTb36pF+O2855QurLG+KPyCzA3qyr890Vn
         kDsRnc8JVCZmhdWdgJf03aRwo7BzGzhjM+1x9ZxfJnzSWC7DSG1oNOXZimzMxug3WedZ
         xk4BswcV5cCAnMvJxY1XgRbe0a0RdJQRmTfTr0p8yp2b+HwvArDFRM6GJZ+d/Cv7lcZW
         /G59g0t1Bu4waKzjcTy2RKF5K8gjNyI1a4hJkiBNAL9nV5nB7V2SVePhs2RHpwOeQwlJ
         w8t4uqDKzyiWTboqZbd5uX0kPy9cbKpmq8qgoM+6vz0+e+99Mv5UgYbIB7JYSdd/6COT
         TMgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bP+b8RFCwrXf9ijiaefOsgSJbqyFhteXIJsyEqG7DPE=;
        b=n07U3S2I+n9z0ga9eUvGVkjaO76wD67s/hy5Qe1AjHykfZ8c590ETwN1Fv+ZYfXzj+
         26WFWLiqnSp5RJSJruSsHHoOGn0E4+UIMwmFiHIC8bmy9ZOySUq1fEap3PSRb2xLATAc
         aidCsPSM2yObGxYM0jL6xsCoMwqaUHIWnRpz2HSkLRggDJ8/XSDWhfTpwj2jSVW8KTlF
         JHqEdV7CldTpAKMI6/T8eR9JEsLm+NV/OkDnZkIToJJ6l99v/btK14aIe6pwICfzJmD2
         NDNByUb0VPFjh/ev+EnZpjwy4RlSpiaSYO1yvapZ2VeSIaGVzmHyCNwuJT84naswHiUL
         qB2g==
X-Gm-Message-State: AFqh2krCdVbKbhVEzdF1r1K/qKPglEleTprp1GJ0TQui82+gW7omGaC9
	Sw/AwvFYmbuGsDYVptRrAF8=
X-Google-Smtp-Source: AMrXdXvyj3PdH4hcPMOQRvET2bO2owkOCx15cqs/WQEzlkyh3je4SiDSX5ytcPxGj+uiYNDMLpLFuA==
X-Received: by 2002:a17:90a:1a0c:b0:229:3d15:4148 with SMTP id 12-20020a17090a1a0c00b002293d154148mr4520614pjk.124.1674635940088;
        Wed, 25 Jan 2023 00:39:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2682:b0:196:2e27:844e with SMTP id
 jf2-20020a170903268200b001962e27844els740124plb.7.-pod-prod-gmail; Wed, 25
 Jan 2023 00:38:59 -0800 (PST)
X-Received: by 2002:a17:90a:6545:b0:229:9b0a:360e with SMTP id f5-20020a17090a654500b002299b0a360emr33546697pjs.12.1674635939350;
        Wed, 25 Jan 2023 00:38:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635939; cv=none;
        d=google.com; s=arc-20160816;
        b=tkl6PzbC4TfCFX9aAPUroZg5UuquDwFDd3yhMJ84gliegabJ1NzjfMWGN/WsvDMhS1
         Y19XfRrrs4d67C3WOT8ZO9PNYLTSaMIC7n1OgVLG4A3JcRkJYwgUnqbQaY1Xdwrsy2MU
         oXtiPCxPjO4Pw4MIfZrg0t6Gn+g+PZXQm+rY2MHJXKSdBk42Wjcev3FN+bmfWnl1ZiEZ
         NW+Um+y1Mq/VB1+vEukFnmYlAzGT+ezycXq4T+h66VGIWw3ceyB2BqhCKkQKIQPSY0FT
         GfXbEj6uwV0Di7qXagEZyJvUjcKI5vlClwCeto9jPsEGGXcr8WHM7g23A/7tVh2oN2pJ
         BeoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ralp0YsbeintaJ1+3rV0BJxcsbdnu/jVKuNhvnt0T5Y=;
        b=LeJuiLOORkNPF5tvvis/cfx5hm0umhAnTAXATeiK5Bgo4CXB0WY+0Z5OYkOdgcI0Fn
         i4utNAHREEHL92/Smhy/tlsGLSBIXail39ftrHCN7zQq4hZGBbSs3TIhH/onJOQ41zFp
         ao0fkD+uI6Q9dpo9SQXdKkPEhU1D0q8cRkKIa7udUp2T06+PTvG3Q4ZvDOxVDUE8qn/W
         z8XoLhFPGcu8rUYzRomL5OTXBNKi1O8xc5UJsG3ISLd5my6M98Eq3hEIDENIAN3/qEo0
         QB4/7B1DkTuN5fLozBq81CASibbzkCh+0PfSxB0WLFthzELd93WVxDjfSMaDwVEU2sEJ
         uRzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FpW3Zfeo;
       spf=pass (google.com: domain of 3ourqywykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ourQYwYKCd8TVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id br24-20020a17090b0f1800b00213290fa218si85453pjb.2.2023.01.25.00.38.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:38:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ourqywykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id t13-20020a056902018d00b0074747131938so19209194ybh.12
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:38:59 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:f7b0:20e8:ce66:f98])
 (user=surenb job=sendgmr) by 2002:a81:3e07:0:b0:506:6185:4fad with SMTP id
 l7-20020a813e07000000b0050661854fadmr450398ywa.451.1674635938431; Wed, 25 Jan
 2023 00:38:58 -0800 (PST)
Date: Wed, 25 Jan 2023 00:38:46 -0800
In-Reply-To: <20230125083851.27759-1-surenb@google.com>
Mime-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com>
X-Mailer: git-send-email 2.39.1.405.gd4c25cc71f-goog
Message-ID: <20230125083851.27759-2-surenb@google.com>
Subject: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
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
 header.i=@google.com header.s=20210112 header.b=FpW3Zfeo;       spf=pass
 (google.com: domain of 3ourqywykcd8tvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ourQYwYKCd8TVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
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

vm_flags are among VMA attributes which affect decisions like VMA merging
and splitting. Therefore all vm_flags modifications are performed after
taking exclusive mmap_lock to prevent vm_flags updates racing with such
operations. Introduce modifier functions for vm_flags to be used whenever
flags are updated. This way we can better check and control correct
locking behavior during these updates.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/mm.h       | 37 +++++++++++++++++++++++++++++++++++++
 include/linux/mm_types.h |  8 +++++++-
 2 files changed, 44 insertions(+), 1 deletion(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index c2f62bdce134..b71f2809caac 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -627,6 +627,43 @@ static inline void vma_init(struct vm_area_struct *vma, struct mm_struct *mm)
 	INIT_LIST_HEAD(&vma->anon_vma_chain);
 }
 
+/* Use when VMA is not part of the VMA tree and needs no locking */
+static inline void init_vm_flags(struct vm_area_struct *vma,
+				 unsigned long flags)
+{
+	vma->vm_flags = flags;
+}
+
+/* Use when VMA is part of the VMA tree and modifications need coordination */
+static inline void reset_vm_flags(struct vm_area_struct *vma,
+				  unsigned long flags)
+{
+	mmap_assert_write_locked(vma->vm_mm);
+	init_vm_flags(vma, flags);
+}
+
+static inline void set_vm_flags(struct vm_area_struct *vma,
+				unsigned long flags)
+{
+	mmap_assert_write_locked(vma->vm_mm);
+	vma->vm_flags |= flags;
+}
+
+static inline void clear_vm_flags(struct vm_area_struct *vma,
+				  unsigned long flags)
+{
+	mmap_assert_write_locked(vma->vm_mm);
+	vma->vm_flags &= ~flags;
+}
+
+static inline void mod_vm_flags(struct vm_area_struct *vma,
+				unsigned long set, unsigned long clear)
+{
+	mmap_assert_write_locked(vma->vm_mm);
+	vma->vm_flags |= set;
+	vma->vm_flags &= ~clear;
+}
+
 static inline void vma_set_anonymous(struct vm_area_struct *vma)
 {
 	vma->vm_ops = NULL;
diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
index 2d6d790d9bed..6c7c70bf50dd 100644
--- a/include/linux/mm_types.h
+++ b/include/linux/mm_types.h
@@ -491,7 +491,13 @@ struct vm_area_struct {
 	 * See vmf_insert_mixed_prot() for discussion.
 	 */
 	pgprot_t vm_page_prot;
-	unsigned long vm_flags;		/* Flags, see mm.h. */
+
+	/*
+	 * Flags, see mm.h.
+	 * WARNING! Do not modify directly.
+	 * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
+	 */
+	unsigned long vm_flags;
 
 	/*
 	 * For areas with an address space and backing store,
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125083851.27759-2-surenb%40google.com.
