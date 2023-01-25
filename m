Return-Path: <kasan-dev+bncBC7OD3FKWUERBKWVYOPAMGQELDHTRLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 8038467ABF7
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:39:08 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id k5-20020a170902c40500b001947b539123sf10378216plk.19
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:39:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635947; cv=pass;
        d=google.com; s=arc-20160816;
        b=zapssuMHh26EikMq0MTOVcGxB00oJ7Rj05/+wWysAXDU719G7WDfHqCXg3xruBf9hD
         2GXxtri6I3QcmGyCBm9kx9DXLyCds60NIJbxsrfJCjBqeManALigMMEnRumO2yAFyBR6
         AqURfNb1/HA1Y5ChCEc1o/2IHIBL4vjY7T+KwglB03PajRBW6TnLdttW8Sv9vYs31sPF
         ZZ0DXCuZRYIbBvBNmO+41iL0Azv8skzrwDYK+WuOAS10nP8dxx2pQRivkaYuktspKTct
         t6sdd/qbxHk4HXuM+Ro57zX1mlkJ/vQs6Ogl5F7UFb5QXRjezk3rthUx7BQ128YiOvI9
         Wi9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vMKh6ou7Z1D2cDuRFysihewHO+VDPxcQdi1Vf07PKTQ=;
        b=ycE8asJ2VY3fxfDklKlN1pK6tB44+ZfIwVZJ6+81p0P4R0ayeRJBbdqSDDgxZPvUo/
         wg+iKIZyGp9JB4gxVkD1IOAM1RSVTbOMmcocxN7H8i4ls0Hsws9JTBrZiYci6sJv3F0w
         opqyGG7SPG4TraHdn+1GcvJ4HII/gjyebCJiTYV40n99qX17S4FasnKLZ3X0YwHw1yhk
         AUESYJ33SXJPdo4tLV7NhkYSEo+pz8/mSYPf4yy7cHKE0a6f0A+/EFHWojoUlpxwb+LU
         hro7D7sFALzcugnoaALx1tUFLCxHL39wsrXpwuGr3lFt3hjCcCc5YyoHmpquuSoGO3ys
         oayQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VwtVZ3ff;
       spf=pass (google.com: domain of 3qerqywykceyaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3qerQYwYKCeYacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vMKh6ou7Z1D2cDuRFysihewHO+VDPxcQdi1Vf07PKTQ=;
        b=dPoWk9vpGhqjGtFVYG/SXEm/Z/q6XIBf1GFaSXn/eW79OuQEy0W6aJUgr7BnGzxe/J
         +qS1tjZB9/DUJJwVcPqMy4a4k3nzsVo0T4og/qdMva75n3mQhqV4X/TfA1+dTznKyJzL
         WDWD2ZEA3jC3vneNkRP1ObIA2n8Lox0dXVbjTri5oEeKvhAuprz+RbnFAQPuq4oEM3z/
         Xg2OaS2ZH4HHjjnrGnnaOn2QalzMbbH2RvdVHcBSnnmfaPSxul69ZPKibSzPUbEG3jc9
         u5kaozKLPyMb7dQQuUD6Pj+OBxx1jZE8rBA5+wOSyBvloWHkon5IzTDJRqVMctNsWWIq
         sDhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vMKh6ou7Z1D2cDuRFysihewHO+VDPxcQdi1Vf07PKTQ=;
        b=QK6dJAqQf4Q8S+fNdT8Idna0qO1SiNvMGtJsE2kGJz/qJe5xkCSaP5R2OSAG5Z0GZT
         UCWc5rqfLAkZeu3DTnFksnk6P8Fue/vWmkbI5kIT56rG1oH5AqskdBYy/c7fYkxV6oJs
         v7aEqdJgQRRyCtGgLztJUOeV22ISmo+/4yHBZ8Lbog61vhE9stvY686OsdEQzMQPgSgx
         R1Wo7B5fdxDyh4sRzLyeY1PtPms01+w1VmNNt05qcd4KD17sGgh2c6Jz8tIuzlh0H7my
         JsE/+9yfgsCnQ0nee+O9X8ftYQAUnewzc07H1VybumwE4uy52ZODKYsVjfUDPfoalD6Q
         D1hA==
X-Gm-Message-State: AO0yUKVW76z6oZWNSSSJrg6xPg1yE+1hrFGj947D99Me8/Ab0hCBvX7j
	RZqVxQqAkJ7jfDSHBnPpOLE=
X-Google-Smtp-Source: AK7set+9RhV7SQQdwi/Ve+R9EldWKFIhA6LqrbH0qfFKu/GCuF7Oib9sRcmwqUZ4PAZZ59QDz8rrLw==
X-Received: by 2002:a17:902:e74f:b0:196:238b:8cc9 with SMTP id p15-20020a170902e74f00b00196238b8cc9mr338195plf.8.1674635947098;
        Wed, 25 Jan 2023 00:39:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8697:b0:191:1e85:3329 with SMTP id
 g23-20020a170902869700b001911e853329ls1418866plo.3.-pod-prod-gmail; Wed, 25
 Jan 2023 00:39:06 -0800 (PST)
X-Received: by 2002:a17:90b:3506:b0:22c:b32:4806 with SMTP id ls6-20020a17090b350600b0022c0b324806mr884705pjb.27.1674635946398;
        Wed, 25 Jan 2023 00:39:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635946; cv=none;
        d=google.com; s=arc-20160816;
        b=tc+d51dHyheBzbIoRzzmeKctQVz5On1tRaWGjn3FpnDRa//Zv8xFPQl5zdHhnVnR8b
         OimxUyWDadVnqx8leoo2V5IkOYY/TG5OHT8XLk6J3o3KdGD4fOEY2OQ3voX+3oCxnq9f
         GpDAjNlb3kFHzJV9I4giL4gI5CxhQ8LC2UJnJbbGgQKxx7EqHhHkAHRFAsb8tt38Fa6j
         KIQyTj+Cfvmg+iMqMp4AfHkUs3j2NO1RLiLSqwzdfWvSOkffAIBnnSMTkSe3VctIYPGd
         1bhj2Sl256SQ8nuruwH904zO6rLdsWMz02DTLl9rgRS8ZKpGYRnHJNV+X8DvDAtink/i
         zu0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mVuGMhZwlEMXe0FAwC4rLE7OnnAfe6cAroxVvXklBMk=;
        b=CrZrkofaPScFMi+9P0DrkjOVZaxAsisuAoFnl6wot9tOuGys9ZO9T9eXvvQiFN/k9K
         0jdycHfaHPCXIOndWQA4OTTUDzGMvCbEI+XFlEZWxBRFFlWfiy6CJnY59S1AG/BQCOYj
         4IOhux6GP3IJ8+pTmSbGbxzSGYicoJP+81VYcPArcR07+u2ZdRuQzXx48KCHd0Ct7qcW
         JvnSqLfQsjW3tVo10haGjZpwqr5J087zyZ7bOoWb62et4kMSOAtFrieVelgy8+Lkxvjn
         1udF7A3PzJM0tuIOR03gUdWvsp0qHRjSs46yi7KKcYeoymGfkv5TcdRxnqG7bqXjjl1S
         j44g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VwtVZ3ff;
       spf=pass (google.com: domain of 3qerqywykceyaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3qerQYwYKCeYacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id br24-20020a17090b0f1800b00213290fa218si85453pjb.2.2023.01.25.00.39.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:39:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qerqywykceyaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id t13-20020a056902018d00b0074747131938so19209506ybh.12
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:39:06 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:f7b0:20e8:ce66:f98])
 (user=surenb job=sendgmr) by 2002:a25:c247:0:b0:80b:6201:bee7 with SMTP id
 s68-20020a25c247000000b0080b6201bee7mr702095ybf.340.1674635945821; Wed, 25
 Jan 2023 00:39:05 -0800 (PST)
Date: Wed, 25 Jan 2023 00:38:49 -0800
In-Reply-To: <20230125083851.27759-1-surenb@google.com>
Mime-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com>
X-Mailer: git-send-email 2.39.1.405.gd4c25cc71f-goog
Message-ID: <20230125083851.27759-5-surenb@google.com>
Subject: [PATCH v2 4/6] mm: replace vma->vm_flags indirect modification in ksm_madvise
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
 header.i=@google.com header.s=20210112 header.b=VwtVZ3ff;       spf=pass
 (google.com: domain of 3qerqywykceyaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3qerQYwYKCeYacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
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

Replace indirect modifications to vma->vm_flags with calls to modifier
functions to be able to track flag changes and to keep vma locking
correctness. Add a BUG_ON check in ksm_madvise() to catch indirect
vm_flags modification attempts.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/powerpc/kvm/book3s_hv_uvmem.c | 5 ++++-
 arch/s390/mm/gmap.c                | 5 ++++-
 mm/khugepaged.c                    | 2 ++
 mm/ksm.c                           | 2 ++
 4 files changed, 12 insertions(+), 2 deletions(-)

diff --git a/arch/powerpc/kvm/book3s_hv_uvmem.c b/arch/powerpc/kvm/book3s_hv_uvmem.c
index 1d67baa5557a..325a7a47d348 100644
--- a/arch/powerpc/kvm/book3s_hv_uvmem.c
+++ b/arch/powerpc/kvm/book3s_hv_uvmem.c
@@ -393,6 +393,7 @@ static int kvmppc_memslot_page_merge(struct kvm *kvm,
 {
 	unsigned long gfn = memslot->base_gfn;
 	unsigned long end, start = gfn_to_hva(kvm, gfn);
+	unsigned long vm_flags;
 	int ret = 0;
 	struct vm_area_struct *vma;
 	int merge_flag = (merge) ? MADV_MERGEABLE : MADV_UNMERGEABLE;
@@ -409,12 +410,14 @@ static int kvmppc_memslot_page_merge(struct kvm *kvm,
 			ret = H_STATE;
 			break;
 		}
+		vm_flags = vma->vm_flags;
 		ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
-			  merge_flag, &vma->vm_flags);
+			  merge_flag, &vm_flags);
 		if (ret) {
 			ret = H_STATE;
 			break;
 		}
+		reset_vm_flags(vma, vm_flags);
 		start = vma->vm_end;
 	} while (end > vma->vm_end);
 
diff --git a/arch/s390/mm/gmap.c b/arch/s390/mm/gmap.c
index 3a695b8a1e3c..d5eb47dcdacb 100644
--- a/arch/s390/mm/gmap.c
+++ b/arch/s390/mm/gmap.c
@@ -2587,14 +2587,17 @@ int gmap_mark_unmergeable(void)
 {
 	struct mm_struct *mm = current->mm;
 	struct vm_area_struct *vma;
+	unsigned long vm_flags;
 	int ret;
 	VMA_ITERATOR(vmi, mm, 0);
 
 	for_each_vma(vmi, vma) {
+		vm_flags = vma->vm_flags;
 		ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
-				  MADV_UNMERGEABLE, &vma->vm_flags);
+				  MADV_UNMERGEABLE, &vm_flags);
 		if (ret)
 			return ret;
+		reset_vm_flags(vma, vm_flags);
 	}
 	mm->def_flags &= ~VM_MERGEABLE;
 	return 0;
diff --git a/mm/khugepaged.c b/mm/khugepaged.c
index 8abc59345bf2..76b24cd0c179 100644
--- a/mm/khugepaged.c
+++ b/mm/khugepaged.c
@@ -354,6 +354,8 @@ struct attribute_group khugepaged_attr_group = {
 int hugepage_madvise(struct vm_area_struct *vma,
 		     unsigned long *vm_flags, int advice)
 {
+	/* vma->vm_flags can be changed only using modifier functions */
+	BUG_ON(vm_flags == &vma->vm_flags);
 	switch (advice) {
 	case MADV_HUGEPAGE:
 #ifdef CONFIG_S390
diff --git a/mm/ksm.c b/mm/ksm.c
index 04f1c8c2df11..992b2be9f5e6 100644
--- a/mm/ksm.c
+++ b/mm/ksm.c
@@ -2573,6 +2573,8 @@ int ksm_madvise(struct vm_area_struct *vma, unsigned long start,
 	struct mm_struct *mm = vma->vm_mm;
 	int err;
 
+	/* vma->vm_flags can be changed only using modifier functions */
+	BUG_ON(vm_flags == &vma->vm_flags);
 	switch (advice) {
 	case MADV_MERGEABLE:
 		/*
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125083851.27759-5-surenb%40google.com.
