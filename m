Return-Path: <kasan-dev+bncBDOY5FWKT4KRBG4PZGPAMGQESRJL4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AD5B067C72B
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 10:27:57 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1500bc69a97sf355560fac.7
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 01:27:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674725276; cv=pass;
        d=google.com; s=arc-20160816;
        b=A3eBswQPU3bZeeZyXW1o/OLENFmbIuZByZZAKxAm7N8QcrAiBbyN/JBoU1BUqqi5vG
         BhVyIyAuKvtb+zg2m+j1rOlGDsJ4VG//pmLnzpoElphOgmorJ/ZR8EZ6yY6wLekCQ4bp
         6jhD6wUYMKmrV0hPjwAtaYTREiHysCcJx+jCtwjEn2HcoO6TK2Y/rkSGBizoQMxM7wFz
         3axbahWh2L0d8fguQFbxChoJcByk4xiI4E4ZPSXK9X7ER1tK/QHJsW8Jbao1NgCZD1qp
         5/iljqvaXPfNBkM8I5+FhZPmbA1r5mf3PH72tv9cMakaQrY4/6F0Gk8toe8ZRHJFs2SA
         PoBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6QFGVdGZr+tfB3V131nmhSq4NFZjUwSa7dqb/l/10sA=;
        b=KHPdJmEQJVRlg8FFP7VyDDgXfkdHtxYdoL7hnDAMvOC24Jmg9zPfsyzEV1RJpdAKVK
         kOyjYsQuGH04qPRAiRS/yh5aHknB6hQHWpS79/c4uYHNic4/CO9o9FNf1jTarXL++wid
         HZTFgGbAZNYGp6MVAEOjFWENgKo+OOSfXjarj/j2Ii0Y3fZlQe1viAlcyXphWkRZTIHr
         dGLW//8qjFFLi8IKI5nzywRJVjtfOw69vPI5sUTqFSiHIL9mY2rdnfaaPjUabPfwyXct
         SIBWOcUHO97xgN7lYiehVN1cDnLajVlVVLoZZ/w75FvFFC6ebXWenxj0yjNk1cJfuBUv
         prcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j//Fl5kI";
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6QFGVdGZr+tfB3V131nmhSq4NFZjUwSa7dqb/l/10sA=;
        b=buF3/nJBNkcYZb4W7OuMM5OeAF3Daj/GvFaSxVVJ2b86bOLhJIV2lF/dzrxbHQNOHQ
         VPusbzrYkfeAPmUFiOeR1gOiyCfLDSBpYY9y6IN0dpTxZwoxk/MqOY+cdw+0Rf1diTA+
         h8udKmynF9ksBLyuYCTJqQnGKqCzmwTNmJnwtoHRRG9toU3OW9TCTNRAFTKo1Sdd1iO4
         LHW4inmOnkrsGJsltXltfrq8wdEZGuAf3hijk1RBEkjZfetOTpBZQx73KBxB5ERgfObX
         +BtIrsmEIwy5hgNReYJldw/9Uee8gA2S2WFmCVr+nZFBzUgCr9sl1SsSZZDBnXTa232v
         ig9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6QFGVdGZr+tfB3V131nmhSq4NFZjUwSa7dqb/l/10sA=;
        b=1KjFSXlvUBSWCLT+VH7UVdRUzm5G1Uv2Y9d7bH0hhob1QKk3dk1PfwElrGB0M/whZZ
         Z4aCDaipplITGJF20bJENHp9P+X6rrhjDwjXK5qb6/r9LebuMJfy5SluPRYEmtbMIodm
         P4BYfxeNx/A9fjVuKyevJRXIKu8j770G4hRN2eFBlujFDcivlUw0x7Jm41WyH6tOqZ5i
         AY9tJddXTN7k5arBhbb7Z15FX4sGS/VHv7F7HSch1MRkoUn/SXAmPUVIAlibQAK89X8S
         8Dt4gUzhYTkHozhYaWEFZlG3AwJedYs8yTgcKVLOgZ79hOv46TM4lY8psizlm6G1kP3M
         G9IQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqjez7tRk0+5RSI4QjQKKHBxGgy89+cVqExvDkwqPS+vXLH0dtN
	Ph58br5HChe+gWQsnHeM3ys=
X-Google-Smtp-Source: AMrXdXtauXh1+0BJtfO9DBVEU6PCeG1V934DvTKfpQv0FhOvOsaNSr91DeNsjb8qoh/CASdAb2L2eQ==
X-Received: by 2002:a54:4e83:0:b0:35e:2d5e:f617 with SMTP id c3-20020a544e83000000b0035e2d5ef617mr2296036oiy.25.1674725275995;
        Thu, 26 Jan 2023 01:27:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5785:0:b0:65a:941:6199 with SMTP id q5-20020a9d5785000000b0065a09416199ls202525oth.5.-pod-prod-gmail;
 Thu, 26 Jan 2023 01:27:55 -0800 (PST)
X-Received: by 2002:a05:6830:30af:b0:66e:6054:428d with SMTP id g47-20020a05683030af00b0066e6054428dmr18376752ots.23.1674725275610;
        Thu, 26 Jan 2023 01:27:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674725275; cv=none;
        d=google.com; s=arc-20160816;
        b=QQLicfV8dAnI6GVD03MHiNB0RMaNGm4M/QUwt6sceEqVQj7zOm49/UWI6Cqg+JYgnk
         283XW8M+sD1IrGm5x8POcqcZoiW2vEYgmUW++YMBzCDlJgsmJuW4wCEWssgNSi7Z79cH
         BPQiuMVX83Mvw1Ikh1l7RpMJ+K9n0RBy8lntuB5fZx4xqxHiJ8uguPvQXYgaBbHuxW7C
         dosAmolex83rJJBeWt/PQfDG4J2lLB5Xm+/Katv8ENaduNL95s4tG9rDkH6+khIlKmgK
         Ho8H6nFll3Wc1olhsxhs4Ou0F1NsP3c79n8EoqrntpIv9m92DweV9mTs1RBpMNWa09QK
         WhcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9O9Szc5bse9dUzN3k+CIlb0LPRxwHm2vh1Ton4i2RMY=;
        b=q1gymGzaISggBiLSwuZHtK33K9bW/Mff9pQYxTuRj69XIFNQTX2iP8x+JB9SiesBBV
         nX1z/TJhCVKbsluJoSCC+tsl6rTyr1EDEDUD2azgJ1yWW95exfGllczKj7JnZZ2xFJJ6
         Ph9eDSTVnBuHNr25uJV8EKFTLpYvb7d86FyLgAZKJxdRwKzaFc30RQkTUNVCanmcyQkY
         ju7Mkl5Vj4VKlzG+IdJXroMQD9qfMgHb+2Wju1GYC7gb9EQcJw0+sG1HJZY3BJjoIIKb
         /BwUlvj7NWe3pQh9iT/J937vLVZD6RACeq7NTngRQcXSgoHMBXRwptX4mPLZVZT66uxy
         yLdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j//Fl5kI";
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id cc9-20020a05683061c900b00686e40e1e0esi93769otb.1.2023.01.26.01.27.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 01:27:55 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2F13361769;
	Thu, 26 Jan 2023 09:27:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C3921C433EF;
	Thu, 26 Jan 2023 09:27:09 +0000 (UTC)
Date: Thu, 26 Jan 2023 11:26:58 +0200
From: Mike Rapoport <rppt@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	mgorman@techsingularity.net, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, peterz@infradead.org,
	ldufour@linux.ibm.com, paulmck@kernel.org, luto@kernel.org,
	songliubraving@fb.com, peterx@redhat.com, david@redhat.com,
	dhowells@redhat.com, hughd@google.com, bigeasy@linutronix.de,
	kent.overstreet@linux.dev, punit.agrawal@bytedance.com,
	lstoakes@gmail.com, peterjung1337@gmail.com, rientjes@google.com,
	axelrasmussen@google.com, joelaf@google.com, minchan@google.com,
	jannh@google.com, shakeelb@google.com, tatashin@google.com,
	edumazet@google.com, gthelen@google.com, gurua@google.com,
	arjunroy@google.com, soheil@google.com, hughlynch@google.com,
	leewalsh@google.com, posk@google.com, will@kernel.org,
	aneesh.kumar@linux.ibm.com, npiggin@gmail.com,
	chenhuacai@kernel.org, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, richard@nod.at,
	anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
	qianweili@huawei.com, wangzhou1@hisilicon.com,
	herbert@gondor.apana.org.au, davem@davemloft.net, vkoul@kernel.org,
	airlied@gmail.com, daniel@ffwll.ch,
	maarten.lankhorst@linux.intel.com, mripard@kernel.org,
	tzimmermann@suse.de, l.stach@pengutronix.de,
	krzysztof.kozlowski@linaro.org, patrik.r.jakobsson@gmail.com,
	matthias.bgg@gmail.com, robdclark@gmail.com,
	quic_abhinavk@quicinc.com, dmitry.baryshkov@linaro.org,
	tomba@kernel.org, hjc@rock-chips.com, heiko@sntech.de,
	ray.huang@amd.com, kraxel@redhat.com, sre@kernel.org,
	mcoquelin.stm32@gmail.com, alexandre.torgue@foss.st.com,
	tfiga@chromium.org, m.szyprowski@samsung.com, mchehab@kernel.org,
	dimitri.sivanich@hpe.com, zhangfei.gao@linaro.org,
	jejb@linux.ibm.com, martin.petersen@oracle.com,
	dgilbert@interlog.com, hdegoede@redhat.com, mst@redhat.com,
	jasowang@redhat.com, alex.williamson@redhat.com, deller@gmx.de,
	jayalk@intworks.biz, viro@zeniv.linux.org.uk, nico@fluxnic.net,
	xiang@kernel.org, chao@kernel.org, tytso@mit.edu,
	adilger.kernel@dilger.ca, miklos@szeredi.hu,
	mike.kravetz@oracle.com, muchun.song@linux.dev, bhe@redhat.com,
	andrii@kernel.org, yoshfuji@linux-ipv6.org, dsahern@kernel.org,
	kuba@kernel.org, pabeni@redhat.com, perex@perex.cz, tiwai@suse.com,
	haojian.zhuang@gmail.com, robert.jarzmik@free.fr,
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, linux-graphics-maintainer@vmware.com,
	linux-ia64@vger.kernel.org, linux-arch@vger.kernel.org,
	loongarch@lists.linux.dev, kvm@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-sgx@vger.kernel.org,
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org,
	linux-crypto@vger.kernel.org, nvdimm@lists.linux.dev,
	dmaengine@vger.kernel.org, amd-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, etnaviv@lists.freedesktop.org,
	linux-samsung-soc@vger.kernel.org, intel-gfx@lists.freedesktop.org,
	linux-mediatek@lists.infradead.org, linux-arm-msm@vger.kernel.org,
	freedreno@lists.freedesktop.org, linux-rockchip@lists.infradead.org,
	linux-tegra@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	xen-devel@lists.xenproject.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-rdma@vger.kernel.org, linux-media@vger.kernel.org,
	linux-accelerators@lists.ozlabs.org, sparclinux@vger.kernel.org,
	linux-scsi@vger.kernel.org, linux-staging@lists.linux.dev,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	netdev@vger.kernel.org, linux-fbdev@vger.kernel.org,
	linux-aio@kvack.org, linux-fsdevel@vger.kernel.org,
	linux-erofs@lists.ozlabs.org, linux-ext4@vger.kernel.org,
	devel@lists.orangefs.org, kexec@lists.infradead.org,
	linux-xfs@vger.kernel.org, bpf@vger.kernel.org,
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com,
	selinux@vger.kernel.org, alsa-devel@alsa-project.org,
	kernel-team@android.com
Subject: Re: [PATCH v2 4/6] mm: replace vma->vm_flags indirect modification
 in ksm_madvise
Message-ID: <Y9JHYvihjxGpAFPg@kernel.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-5-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-5-surenb@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="j//Fl5kI";       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Jan 25, 2023 at 12:38:49AM -0800, Suren Baghdasaryan wrote:
> Replace indirect modifications to vma->vm_flags with calls to modifier
> functions to be able to track flag changes and to keep vma locking
> correctness. Add a BUG_ON check in ksm_madvise() to catch indirect
> vm_flags modification attempts.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Mike Rapoport (IBM) <rppt@kernel.org>

> ---
>  arch/powerpc/kvm/book3s_hv_uvmem.c | 5 ++++-
>  arch/s390/mm/gmap.c                | 5 ++++-
>  mm/khugepaged.c                    | 2 ++
>  mm/ksm.c                           | 2 ++
>  4 files changed, 12 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/powerpc/kvm/book3s_hv_uvmem.c b/arch/powerpc/kvm/book3s_hv_uvmem.c
> index 1d67baa5557a..325a7a47d348 100644
> --- a/arch/powerpc/kvm/book3s_hv_uvmem.c
> +++ b/arch/powerpc/kvm/book3s_hv_uvmem.c
> @@ -393,6 +393,7 @@ static int kvmppc_memslot_page_merge(struct kvm *kvm,
>  {
>  	unsigned long gfn = memslot->base_gfn;
>  	unsigned long end, start = gfn_to_hva(kvm, gfn);
> +	unsigned long vm_flags;
>  	int ret = 0;
>  	struct vm_area_struct *vma;
>  	int merge_flag = (merge) ? MADV_MERGEABLE : MADV_UNMERGEABLE;
> @@ -409,12 +410,14 @@ static int kvmppc_memslot_page_merge(struct kvm *kvm,
>  			ret = H_STATE;
>  			break;
>  		}
> +		vm_flags = vma->vm_flags;
>  		ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
> -			  merge_flag, &vma->vm_flags);
> +			  merge_flag, &vm_flags);
>  		if (ret) {
>  			ret = H_STATE;
>  			break;
>  		}
> +		reset_vm_flags(vma, vm_flags);
>  		start = vma->vm_end;
>  	} while (end > vma->vm_end);
>  
> diff --git a/arch/s390/mm/gmap.c b/arch/s390/mm/gmap.c
> index 3a695b8a1e3c..d5eb47dcdacb 100644
> --- a/arch/s390/mm/gmap.c
> +++ b/arch/s390/mm/gmap.c
> @@ -2587,14 +2587,17 @@ int gmap_mark_unmergeable(void)
>  {
>  	struct mm_struct *mm = current->mm;
>  	struct vm_area_struct *vma;
> +	unsigned long vm_flags;
>  	int ret;
>  	VMA_ITERATOR(vmi, mm, 0);
>  
>  	for_each_vma(vmi, vma) {
> +		vm_flags = vma->vm_flags;
>  		ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
> -				  MADV_UNMERGEABLE, &vma->vm_flags);
> +				  MADV_UNMERGEABLE, &vm_flags);
>  		if (ret)
>  			return ret;
> +		reset_vm_flags(vma, vm_flags);
>  	}
>  	mm->def_flags &= ~VM_MERGEABLE;
>  	return 0;
> diff --git a/mm/khugepaged.c b/mm/khugepaged.c
> index 8abc59345bf2..76b24cd0c179 100644
> --- a/mm/khugepaged.c
> +++ b/mm/khugepaged.c
> @@ -354,6 +354,8 @@ struct attribute_group khugepaged_attr_group = {
>  int hugepage_madvise(struct vm_area_struct *vma,
>  		     unsigned long *vm_flags, int advice)
>  {
> +	/* vma->vm_flags can be changed only using modifier functions */
> +	BUG_ON(vm_flags == &vma->vm_flags);
>  	switch (advice) {
>  	case MADV_HUGEPAGE:
>  #ifdef CONFIG_S390
> diff --git a/mm/ksm.c b/mm/ksm.c
> index 04f1c8c2df11..992b2be9f5e6 100644
> --- a/mm/ksm.c
> +++ b/mm/ksm.c
> @@ -2573,6 +2573,8 @@ int ksm_madvise(struct vm_area_struct *vma, unsigned long start,
>  	struct mm_struct *mm = vma->vm_mm;
>  	int err;
>  
> +	/* vma->vm_flags can be changed only using modifier functions */
> +	BUG_ON(vm_flags == &vma->vm_flags);
>  	switch (advice) {
>  	case MADV_MERGEABLE:
>  		/*
> -- 
> 2.39.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9JHYvihjxGpAFPg%40kernel.org.
