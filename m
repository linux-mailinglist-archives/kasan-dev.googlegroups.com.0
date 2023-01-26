Return-Path: <kasan-dev+bncBDOY5FWKT4KRB7ESZGPAMGQEX5UIFEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9665367C769
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 10:35:57 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id n6-20020a0565120ac600b004d5a68b0f94sf686316lfu.14
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 01:35:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674725757; cv=pass;
        d=google.com; s=arc-20160816;
        b=ydD95h9xF+hyd9mMsopZIIt6GBWF/hDDTFNryEGmA4g7dT4Y/JzbN2gRVdJQF0JuVA
         vFi9z8gJpptuZvEYPHdzKFEkRx870gdZnaKPq+oG8+94n4KmBSIv+JKxtV86b45JP2x9
         CEu3wjIeZwRT091nq+zN2irUlegbz6Y4ub2wzMi2EG/NvAEABvYv97FwIlE+jNMGr8FN
         5IbqrJww6Yw58U2voUG2DD3mq8ZuBcV/huMnhwDbsN2TnP7fLfCk8IalxwDkDu1mSrat
         iK0gMFugP6vxGWAjiwKCvYL7ZSfW3Nfq0dI+wU1Qm18WgF7Iec1ywpXnePqd9F3t740I
         xlZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mskzgbdWmtlTq6lxkaVF0egI9UcLgQGZYpzZIfWW5+Q=;
        b=D24W3q4CZDeB1USlaArg0ff+lBUZ29kQE4krYzW+Dre6hjXXbhnwwY9OK0FfMunSzT
         053ZOyA82KhjIQbBIrQeou5ejmFm35ZvmtmAXYUK9QbpV2uVvdZNLAPZaiweJJoxWcJm
         2EahaPdSizvBz5pxBbNWR2VltD4bIaZPMZNF3elxlh2m/vR7kycYtjoSgLP3qMw0bxKb
         1o3QdT+7d6gV9LrXxXzGE8sxbdt6Ul3MO74j4obGUk7523WlzAaYhaWCdp2zELyaXaZ1
         uOAw5t/g+EntoQi4/favJtSXc8qsCtVriXsecb55bqEEzpBBaq5YVh26Gb1j7DWzNZXx
         8X4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DpDvg8hL;
       spf=pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mskzgbdWmtlTq6lxkaVF0egI9UcLgQGZYpzZIfWW5+Q=;
        b=Q0WJeCFI4yY73iRznbtkTXO7B4hIss4k5FJt526yIQK7eZQ/4NE97sDuxdqjXlTTSI
         9Eg6fk7nPdP9fllkfjID/EkSd4N0YlK1a5s2IX8DKJhuP9YY2DOpLjPYy3o5BtVXqW79
         I0YtNn5tntyiLcWjfcdP8Av47i+cFiBMNYe/3hxqvO14bKYHVvGIqMWD5c9+NYLPJPS2
         kGvwNLTZ50RFZ4AjKwVkTlYkFfo5fEjb2JRsabmVe418cOm/10O4E2elDAHbHHoLiMkn
         NSu5E4nfis7CCwCl0cAFIcgn8MHbZvfJDlYs4Nl/5N6NyxUVN8HZgCfb82ORTfGsKJgc
         6KPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mskzgbdWmtlTq6lxkaVF0egI9UcLgQGZYpzZIfWW5+Q=;
        b=zjEbomBUN46VN503JPn3sDWU+aN64zB5M7+JbQ6EDyCTx4pp7+Gz5khpJsxfvnYM0g
         0FDwYh9VFil+HHak0AY3rq/yBOqf60nqlmY9vqATvQyCw6eNWyXslcg7HAHdcsp/hWBI
         CyFb9vcz/uTf09b92gKW0Az9AZ+dJ8nZc+DUpRT1phtiSxaJp1sBNyyhbUePU4MiKEIc
         ZyJlzTE+JreK7DWzOZXSt7NW3gT1K/j5GcyZwjUo5bVrHwlpQd6yDi/bqMIEGHzl7f/w
         oXvdbbTi7mS7tUbvHd4RfRnKPjGuvQCW7G/x8/Z24AHbVDK/A589pxEJv98cY5PKRyQd
         h6Rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpgdeMoAlbUewKrWC6jrXSCzqngXhfn5mrSd4nPZn7nsKjWt0/T
	6eLPMtTcRmophV0+i6fGbVc=
X-Google-Smtp-Source: AMrXdXtUe7DwLvgEq/K1wHKthlag1KtCjDfPKP3pHxnReT/kGAVm9K9YxnYmXr8D0wxJqnKMMO7NZQ==
X-Received: by 2002:a2e:9591:0:b0:28b:68b4:f3b0 with SMTP id w17-20020a2e9591000000b0028b68b4f3b0mr1921651ljh.101.1674725756744;
        Thu, 26 Jan 2023 01:35:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9198:0:b0:27f:e626:ad40 with SMTP id f24-20020a2e9198000000b0027fe626ad40ls188694ljg.1.-pod-prod-gmail;
 Thu, 26 Jan 2023 01:35:55 -0800 (PST)
X-Received: by 2002:a2e:9e0d:0:b0:284:819:1f85 with SMTP id e13-20020a2e9e0d000000b0028408191f85mr8938413ljk.40.1674725755514;
        Thu, 26 Jan 2023 01:35:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674725755; cv=none;
        d=google.com; s=arc-20160816;
        b=WyQdVaZWn8fidwrAvSEsuh9AkYx20X84Rxc+ASnu0fBPjMfOzDj/M6jAiU67bqye5w
         p3dmxJe+RjyXN+fI83stf4VfIz5SMn/KGOlPR7ieNHLsOCGlo95GeLxBlivX6lY4OlU1
         TPp5zpZen8qDOPDCy3kFoSLU54O+U/NoM+MrzD1zutxwFnM/ApThLu2jSO5jtLCHtRVM
         9xQohdvDW/05dbPSH/Lk35Z26Yif2uucwulbjMbi8LkQ8a5IhmqLvhvKB3STL+HiPuhH
         VV0Rl3+UdEIH8HSOjk7nlop1lfR7LGJ5sQe9V28MNobkWWsvP2602LLDKOY7/kMcf7r1
         1tlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=V6+CIInquHBEpxji0ytsGppDJ+ls0B8YpThTHtnrLyE=;
        b=SGBteDpHVrR+4OxdZlkm9oPJEUB8Q0kjAT9Lu1XMIuqhp9pk395dYJMgiSIhKPgL7w
         /6ugT04wIG09tnnTQoLwZmitc7IckTRFO32a8ANLxExBWsVUZzXBKrWrwo643hAZOEq9
         JyHpQdV2ktMGEdcA6XJTJ16NUN5kAtkq/OlQsPBmUSBFdFx54mXCDrsNsbxOlkMaf46K
         mniXIy7tzav141L0x/2lRVsfCF1vbhttCuM2S2J8cQlc+8d27jQsQWY/xBNf9iDiu7rh
         oy7ldZASWaMAOcdrmFhFZG6rWl3pklrQfk2bNKREJBDS3bA8xMIGXvv2ocIN8uasYGW0
         wCzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DpDvg8hL;
       spf=pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id y5-20020a056512044500b004d579451cc2si39707lfk.12.2023.01.26.01.35.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 01:35:55 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 82E6DB81CB8;
	Thu, 26 Jan 2023 09:35:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40FC4C433EF;
	Thu, 26 Jan 2023 09:35:05 +0000 (UTC)
Date: Thu, 26 Jan 2023 11:34:54 +0200
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
Subject: Re: [PATCH v2 5/6] mm: introduce mod_vm_flags_nolock and use it in
 untrack_pfn
Message-ID: <Y9JJPvvuvSjQ+x9h@kernel.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-6-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-6-surenb@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DpDvg8hL;       spf=pass
 (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Jan 25, 2023 at 12:38:50AM -0800, Suren Baghdasaryan wrote:
> In cases when VMA flags are modified after VMA was isolated and mmap_lock
> was downgraded, flags modifications would result in an assertion because
> mmap write lock is not held.
> Introduce mod_vm_flags_nolock to be used in such situation.

vm_flags_mod_nolock?

> Pass a hint to untrack_pfn to conditionally use mod_vm_flags_nolock for
> flags modification and to avoid assertion.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  arch/x86/mm/pat/memtype.c | 10 +++++++---
>  include/linux/mm.h        | 12 +++++++++---
>  include/linux/pgtable.h   |  5 +++--
>  mm/memory.c               | 13 +++++++------
>  mm/memremap.c             |  4 ++--
>  mm/mmap.c                 | 16 ++++++++++------
>  6 files changed, 38 insertions(+), 22 deletions(-)
> 
> diff --git a/arch/x86/mm/pat/memtype.c b/arch/x86/mm/pat/memtype.c
> index ae9645c900fa..d8adc0b42cf2 100644
> --- a/arch/x86/mm/pat/memtype.c
> +++ b/arch/x86/mm/pat/memtype.c
> @@ -1046,7 +1046,7 @@ void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot, pfn_t pfn)
>   * can be for the entire vma (in which case pfn, size are zero).
>   */
>  void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
> -		 unsigned long size)
> +		 unsigned long size, bool mm_wr_locked)
>  {
>  	resource_size_t paddr;
>  	unsigned long prot;
> @@ -1065,8 +1065,12 @@ void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
>  		size = vma->vm_end - vma->vm_start;
>  	}
>  	free_pfn_range(paddr, size);
> -	if (vma)
> -		clear_vm_flags(vma, VM_PAT);
> +	if (vma) {
> +		if (mm_wr_locked)
> +			clear_vm_flags(vma, VM_PAT);
> +		else
> +			mod_vm_flags_nolock(vma, 0, VM_PAT);
> +	}
>  }
>  
>  /*
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 55335edd1373..48d49930c411 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -656,12 +656,18 @@ static inline void clear_vm_flags(struct vm_area_struct *vma,
>  	vma->vm_flags &= ~flags;
>  }
>  
> +static inline void mod_vm_flags_nolock(struct vm_area_struct *vma,
> +				       unsigned long set, unsigned long clear)
> +{
> +	vma->vm_flags |= set;
> +	vma->vm_flags &= ~clear;
> +}
> +
>  static inline void mod_vm_flags(struct vm_area_struct *vma,
>  				unsigned long set, unsigned long clear)
>  {
>  	mmap_assert_write_locked(vma->vm_mm);
> -	vma->vm_flags |= set;
> -	vma->vm_flags &= ~clear;
> +	mod_vm_flags_nolock(vma, set, clear);
>  }
>  
>  static inline void vma_set_anonymous(struct vm_area_struct *vma)
> @@ -2087,7 +2093,7 @@ static inline void zap_vma_pages(struct vm_area_struct *vma)
>  }
>  void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
>  		struct vm_area_struct *start_vma, unsigned long start,
> -		unsigned long end);
> +		unsigned long end, bool mm_wr_locked);
>  
>  struct mmu_notifier_range;
>  
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 5fd45454c073..c63cd44777ec 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1185,7 +1185,8 @@ static inline int track_pfn_copy(struct vm_area_struct *vma)
>   * can be for the entire vma (in which case pfn, size are zero).
>   */
>  static inline void untrack_pfn(struct vm_area_struct *vma,
> -			       unsigned long pfn, unsigned long size)
> +			       unsigned long pfn, unsigned long size,
> +			       bool mm_wr_locked)
>  {
>  }
>  
> @@ -1203,7 +1204,7 @@ extern void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot,
>  			     pfn_t pfn);
>  extern int track_pfn_copy(struct vm_area_struct *vma);
>  extern void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
> -			unsigned long size);
> +			unsigned long size, bool mm_wr_locked);
>  extern void untrack_pfn_moved(struct vm_area_struct *vma);
>  #endif
>  
> diff --git a/mm/memory.c b/mm/memory.c
> index d6902065e558..5b11b50e2c4a 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -1613,7 +1613,7 @@ void unmap_page_range(struct mmu_gather *tlb,
>  static void unmap_single_vma(struct mmu_gather *tlb,
>  		struct vm_area_struct *vma, unsigned long start_addr,
>  		unsigned long end_addr,
> -		struct zap_details *details)
> +		struct zap_details *details, bool mm_wr_locked)
>  {
>  	unsigned long start = max(vma->vm_start, start_addr);
>  	unsigned long end;
> @@ -1628,7 +1628,7 @@ static void unmap_single_vma(struct mmu_gather *tlb,
>  		uprobe_munmap(vma, start, end);
>  
>  	if (unlikely(vma->vm_flags & VM_PFNMAP))
> -		untrack_pfn(vma, 0, 0);
> +		untrack_pfn(vma, 0, 0, mm_wr_locked);
>  
>  	if (start != end) {
>  		if (unlikely(is_vm_hugetlb_page(vma))) {
> @@ -1675,7 +1675,7 @@ static void unmap_single_vma(struct mmu_gather *tlb,
>   */
>  void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
>  		struct vm_area_struct *vma, unsigned long start_addr,
> -		unsigned long end_addr)
> +		unsigned long end_addr, bool mm_wr_locked)
>  {
>  	struct mmu_notifier_range range;
>  	struct zap_details details = {
> @@ -1689,7 +1689,8 @@ void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
>  				start_addr, end_addr);
>  	mmu_notifier_invalidate_range_start(&range);
>  	do {
> -		unmap_single_vma(tlb, vma, start_addr, end_addr, &details);
> +		unmap_single_vma(tlb, vma, start_addr, end_addr, &details,
> +				 mm_wr_locked);
>  	} while ((vma = mas_find(&mas, end_addr - 1)) != NULL);
>  	mmu_notifier_invalidate_range_end(&range);
>  }
> @@ -1723,7 +1724,7 @@ void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
>  	 * unmap 'address-end' not 'range.start-range.end' as range
>  	 * could have been expanded for hugetlb pmd sharing.
>  	 */
> -	unmap_single_vma(&tlb, vma, address, end, details);
> +	unmap_single_vma(&tlb, vma, address, end, details, false);
>  	mmu_notifier_invalidate_range_end(&range);
>  	tlb_finish_mmu(&tlb);
>  }
> @@ -2492,7 +2493,7 @@ int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
>  
>  	err = remap_pfn_range_notrack(vma, addr, pfn, size, prot);
>  	if (err)
> -		untrack_pfn(vma, pfn, PAGE_ALIGN(size));
> +		untrack_pfn(vma, pfn, PAGE_ALIGN(size), true);
>  	return err;
>  }
>  EXPORT_SYMBOL(remap_pfn_range);
> diff --git a/mm/memremap.c b/mm/memremap.c
> index 08cbf54fe037..2f88f43d4a01 100644
> --- a/mm/memremap.c
> +++ b/mm/memremap.c
> @@ -129,7 +129,7 @@ static void pageunmap_range(struct dev_pagemap *pgmap, int range_id)
>  	}
>  	mem_hotplug_done();
>  
> -	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range));
> +	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range), true);
>  	pgmap_array_delete(range);
>  }
>  
> @@ -276,7 +276,7 @@ static int pagemap_range(struct dev_pagemap *pgmap, struct mhp_params *params,
>  	if (!is_private)
>  		kasan_remove_zero_shadow(__va(range->start), range_len(range));
>  err_kasan:
> -	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range));
> +	untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range), true);
>  err_pfn_remap:
>  	pgmap_array_delete(range);
>  	return error;
> diff --git a/mm/mmap.c b/mm/mmap.c
> index 2c6e9072e6a8..69d440997648 100644
> --- a/mm/mmap.c
> +++ b/mm/mmap.c
> @@ -78,7 +78,7 @@ core_param(ignore_rlimit_data, ignore_rlimit_data, bool, 0644);
>  static void unmap_region(struct mm_struct *mm, struct maple_tree *mt,
>  		struct vm_area_struct *vma, struct vm_area_struct *prev,
>  		struct vm_area_struct *next, unsigned long start,
> -		unsigned long end);
> +		unsigned long end, bool mm_wr_locked);
>  
>  static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
>  {
> @@ -2136,14 +2136,14 @@ static inline void remove_mt(struct mm_struct *mm, struct ma_state *mas)
>  static void unmap_region(struct mm_struct *mm, struct maple_tree *mt,
>  		struct vm_area_struct *vma, struct vm_area_struct *prev,
>  		struct vm_area_struct *next,
> -		unsigned long start, unsigned long end)
> +		unsigned long start, unsigned long end, bool mm_wr_locked)
>  {
>  	struct mmu_gather tlb;
>  
>  	lru_add_drain();
>  	tlb_gather_mmu(&tlb, mm);
>  	update_hiwater_rss(mm);
> -	unmap_vmas(&tlb, mt, vma, start, end);
> +	unmap_vmas(&tlb, mt, vma, start, end, mm_wr_locked);
>  	free_pgtables(&tlb, mt, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
>  				 next ? next->vm_start : USER_PGTABLES_CEILING);
>  	tlb_finish_mmu(&tlb);
> @@ -2391,7 +2391,11 @@ do_vmi_align_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
>  			mmap_write_downgrade(mm);
>  	}
>  
> -	unmap_region(mm, &mt_detach, vma, prev, next, start, end);
> +	/*
> +	 * We can free page tables without write-locking mmap_lock because VMAs
> +	 * were isolated before we downgraded mmap_lock.
> +	 */
> +	unmap_region(mm, &mt_detach, vma, prev, next, start, end, !downgrade);
>  	/* Statistics and freeing VMAs */
>  	mas_set(&mas_detach, start);
>  	remove_mt(mm, &mas_detach);
> @@ -2704,7 +2708,7 @@ unsigned long mmap_region(struct file *file, unsigned long addr,
>  
>  		/* Undo any partial mapping done by a device driver. */
>  		unmap_region(mm, &mm->mm_mt, vma, prev, next, vma->vm_start,
> -			     vma->vm_end);
> +			     vma->vm_end, true);
>  	}
>  	if (file && (vm_flags & VM_SHARED))
>  		mapping_unmap_writable(file->f_mapping);
> @@ -3031,7 +3035,7 @@ void exit_mmap(struct mm_struct *mm)
>  	tlb_gather_mmu_fullmm(&tlb, mm);
>  	/* update_hiwater_rss(mm) here? but nobody should be looking */
>  	/* Use ULONG_MAX here to ensure all VMAs in the mm are unmapped */
> -	unmap_vmas(&tlb, &mm->mm_mt, vma, 0, ULONG_MAX);
> +	unmap_vmas(&tlb, &mm->mm_mt, vma, 0, ULONG_MAX, false);
>  	mmap_read_unlock(mm);
>  
>  	/*
> -- 
> 2.39.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9JJPvvuvSjQ%2Bx9h%40kernel.org.
