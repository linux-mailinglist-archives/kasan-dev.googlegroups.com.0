Return-Path: <kasan-dev+bncBDOY5FWKT4KRBY4LZGPAMGQENC7P4GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id C32F067C6E3
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 10:20:36 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id xh12-20020a170906da8c00b007413144e87fsf898487ejb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 01:20:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674724835; cv=pass;
        d=google.com; s=arc-20160816;
        b=kXqZXUW0kx9cYzW8fg87EOCyqmFNoneaS1JGXlVClC4A6TDHjLyR65rcgmpIiUkCL6
         IHyCDhb0aPBmFmJH3HCslt6XNQGQmzizVEZmQlQ5KLUHManKBT5LcTMo1jfo4iB6lnWv
         Hjb/rVOqTzX5r518nRONQURZgCY6po651O2x3dwWW1/UT33s57fme00uxJxJMBc+Tjw1
         l6FBTCJMRy1iycmZ0FBDGFETIKZvElWBIzkYH9wjyPZGATzkjg4TRFon3fCEKkumCm35
         bXdw8SVSngATZVjIYbfPEruz8mRJVibB7T6RB3ikp6rHYR4dJVk9/mgraATHTAUu1kGx
         N9Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=W3EH2k2qHo8hwsans0PyZsy1B4OSdkNI1zqDGU8bDtk=;
        b=xSQov8lS38RMi7/We9ocjolZMBqXv6/qRIL6zR5h/up8V/8KFaENWZmVdsRqyHVRSE
         TLryT0VuFrwYVWbow0A0iZdaJX/3XNnbnQAPo+40RUsMkJfHhGDpmq9i9tCy68kt3PAy
         MZ603YN8HC3Af3382GrCAQ3MkqG5OMtu8hH+Ej0whN4VjzUm0x+XGfwcK71U1l6p53SJ
         TEOXV7ahZ6ZOHKRhKuRbLepeMzpJkoS2mbZr/im2P4MV+wMimRQvv6UTyRDTWv+efnMY
         wPlhEmHs03KOK5VfQpbubEuERl9rFrn2HCSeiwVIzzF/Mewzmx1seYGjSed9AfIhMKL5
         LSRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JmyjvNON;
       spf=pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W3EH2k2qHo8hwsans0PyZsy1B4OSdkNI1zqDGU8bDtk=;
        b=k74IAS4p/KZSEdXjUPihOLlXqvhyVeqwq/v/i1N6iMjIcNCG+jGR/SeNPBc1Nkojl1
         HaorYvC9lDpSOU+b7FlosbF8uQjaoCxGq5f1tApm0qtFcnxggpk5Wex7vqvceU3gVLAL
         mBeqWJkztz4g1flzkMdzcPysWEnYm0Jzt/fEItFy5o2w5hQgaqxlLfSnxpwoOCheXodz
         IaZjRmfPm53yWimOVr/oGdv8RN/ai+6MCOnUEoBi+82WJWgJgNvWxKRw6MEGrwEoCo2R
         6erUWHCr62Vs1tnPB0H7TbZvLQphoO3BdmLsr2fs0BvHeMHZxIG7yj+wT5jSY3BOHjuC
         6NPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W3EH2k2qHo8hwsans0PyZsy1B4OSdkNI1zqDGU8bDtk=;
        b=Aj8iHbAmoimK3TRPm2tXJ1T6g/wAKOxpxH1+vuWds/dZ0hgijMWDfi8pPEREJPQZ+L
         Py9uBkBcd1vwcZNcD0/rKFJoqoufRO+S92yWEaQSnduh2d0E3GgOgom16L2CQc44PHf5
         M+dIxhwvmAK7CkSXc5ZE8srebnrNUhjdFBDFo0kcRoJZnA+coEi3kZElBhkvxFnOkH1f
         x9I3qavko/pJSK2PwvgxtKAP5/2QkDsPsMFH9lRqEgvbTExxEkRVqioMG5dX9RVur0eE
         755WypBsViN5xaUBOJSDjVoWmiHJofoPO7uiinOGsP0ZsXsdYK6W5FuWUHYcTIptBbIx
         4Bzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koyGYqUv2k0NgTPhNvnGcR9HBKdunM5EvtZvgVAP64W6osQAqHp
	q5qx1ccEvnWU3onFBsG0qtY=
X-Google-Smtp-Source: AMrXdXsXYJr8t5yPWMBWRPmVBgIC6rtD++qv1MPPqmXyRlNRtg5AOIxkxAeeBwaVRraR6if44aSbeA==
X-Received: by 2002:a17:906:dfc1:b0:7bd:3a5c:4dea with SMTP id jt1-20020a170906dfc100b007bd3a5c4deamr4524213ejc.190.1674724835265;
        Thu, 26 Jan 2023 01:20:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d681:0:b0:49e:29ce:a2b with SMTP id r1-20020a50d681000000b0049e29ce0a2bls1477225edi.0.-pod-prod-gmail;
 Thu, 26 Jan 2023 01:20:34 -0800 (PST)
X-Received: by 2002:aa7:c619:0:b0:49e:6e34:c363 with SMTP id h25-20020aa7c619000000b0049e6e34c363mr28315128edq.35.1674724834258;
        Thu, 26 Jan 2023 01:20:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674724834; cv=none;
        d=google.com; s=arc-20160816;
        b=tbKFNRFbPLJWJYqycQKVq/2fZgcuwasVxTRB9m9e2Qh9KBXV20N6QwHtJuUTxf5oUz
         Xz6BxWX6Zt0uerORP/2WnNinQz9QX90dVRTBoEfo6rRmKfM77QXl/Ddxdo/Xt5Awu8Tk
         4hYUJGlh0549z9KJEn/SPx8o6bzSOxeO3wP/Ns0Lxyn8paJKkOZRP9vLr7egGg0LIby5
         Z0zMXDid8BjQYYmJug9cDk6jQrk0XUYbq6sV10Ha/mkaxH8b12OGDxeMgjC+k4TGFFqT
         f9Z9nSKyuFUhYQb3JANCqjf7tKEMELfj/x2VwNWyOQQpvMbma8nQZq2nvMpZe6kqJKd1
         Huww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Nw0s+iOGwE5ewwKvFJLNs9mGXGEq6YMBUPCHPhGK/Xg=;
        b=yIkiP8UdM8q1jXPuy2TFUx8x1g2UU/4lwDqLeDIWH4gN4QyPVpqcOKC5cieRJ2Jm3S
         Z6CGbC7jYHJvSpINUVTIOTOGHGrOaxVW+5NOvl9Vdm1xe0RMPVyMBel/zuMMHnlNwKsA
         ZhmvYMCtZHLNyNa8lQaQLsLzefLQSsz2GT16GYqi5aBSBH9jOQQE3s4iQGrcVm7Ulo4f
         ujUoxYroScUn0jgpRrv45hWqgwvSfe1IJOl74uc9TMo7TlbFS7L5pSgAWPox9Bu9c3vJ
         oUTCdwnoHGGg42YgWo+vYsOZwaaXA+eHQ6rvRyQMuMxZrIHgTmiGkOum1GTttd3BMnBz
         LThw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JmyjvNON;
       spf=pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id es12-20020a056402380c00b0047014e8771fsi40337edb.3.2023.01.26.01.20.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 01:20:34 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C04C8B81D19;
	Thu, 26 Jan 2023 09:20:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2F7DBC433D2;
	Thu, 26 Jan 2023 09:19:45 +0000 (UTC)
Date: Thu, 26 Jan 2023 11:19:37 +0200
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
Subject: Re: [PATCH v2 2/6] mm: replace VM_LOCKED_CLEAR_MASK with
 VM_LOCKED_MASK
Message-ID: <Y9JFqaE4n/eGoWWi@kernel.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-3-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-3-surenb@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JmyjvNON;       spf=pass
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

On Wed, Jan 25, 2023 at 12:38:47AM -0800, Suren Baghdasaryan wrote:
> To simplify the usage of VM_LOCKED_CLEAR_MASK in clear_vm_flags(),
> replace it with VM_LOCKED_MASK bitmask and convert all users.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Mike Rapoport (IBM) <rppt@kernel.org>

> ---
>  include/linux/mm.h | 4 ++--
>  kernel/fork.c      | 2 +-
>  mm/hugetlb.c       | 4 ++--
>  mm/mlock.c         | 6 +++---
>  mm/mmap.c          | 6 +++---
>  mm/mremap.c        | 2 +-
>  6 files changed, 12 insertions(+), 12 deletions(-)
> 
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index b71f2809caac..da62bdd627bf 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -421,8 +421,8 @@ extern unsigned int kobjsize(const void *objp);
>  /* This mask defines which mm->def_flags a process can inherit its parent */
>  #define VM_INIT_DEF_MASK	VM_NOHUGEPAGE
>  
> -/* This mask is used to clear all the VMA flags used by mlock */
> -#define VM_LOCKED_CLEAR_MASK	(~(VM_LOCKED | VM_LOCKONFAULT))
> +/* This mask represents all the VMA flag bits used by mlock */
> +#define VM_LOCKED_MASK	(VM_LOCKED | VM_LOCKONFAULT)
>  
>  /* Arch-specific flags to clear when updating VM flags on protection change */
>  #ifndef VM_ARCH_CLEAR
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 6683c1b0f460..03d472051236 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -669,7 +669,7 @@ static __latent_entropy int dup_mmap(struct mm_struct *mm,
>  			tmp->anon_vma = NULL;
>  		} else if (anon_vma_fork(tmp, mpnt))
>  			goto fail_nomem_anon_vma_fork;
> -		tmp->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
> +		clear_vm_flags(tmp, VM_LOCKED_MASK);
>  		file = tmp->vm_file;
>  		if (file) {
>  			struct address_space *mapping = file->f_mapping;
> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
> index d20c8b09890e..4ecdbad9a451 100644
> --- a/mm/hugetlb.c
> +++ b/mm/hugetlb.c
> @@ -6973,8 +6973,8 @@ static unsigned long page_table_shareable(struct vm_area_struct *svma,
>  	unsigned long s_end = sbase + PUD_SIZE;
>  
>  	/* Allow segments to share if only one is marked locked */
> -	unsigned long vm_flags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
> -	unsigned long svm_flags = svma->vm_flags & VM_LOCKED_CLEAR_MASK;
> +	unsigned long vm_flags = vma->vm_flags & ~VM_LOCKED_MASK;
> +	unsigned long svm_flags = svma->vm_flags & ~VM_LOCKED_MASK;
>  
>  	/*
>  	 * match the virtual addresses, permission and the alignment of the
> diff --git a/mm/mlock.c b/mm/mlock.c
> index 0336f52e03d7..5c4fff93cd6b 100644
> --- a/mm/mlock.c
> +++ b/mm/mlock.c
> @@ -497,7 +497,7 @@ static int apply_vma_lock_flags(unsigned long start, size_t len,
>  		if (vma->vm_start != tmp)
>  			return -ENOMEM;
>  
> -		newflags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
> +		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
>  		newflags |= flags;
>  		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
>  		tmp = vma->vm_end;
> @@ -661,7 +661,7 @@ static int apply_mlockall_flags(int flags)
>  	struct vm_area_struct *vma, *prev = NULL;
>  	vm_flags_t to_add = 0;
>  
> -	current->mm->def_flags &= VM_LOCKED_CLEAR_MASK;
> +	current->mm->def_flags &= ~VM_LOCKED_MASK;
>  	if (flags & MCL_FUTURE) {
>  		current->mm->def_flags |= VM_LOCKED;
>  
> @@ -681,7 +681,7 @@ static int apply_mlockall_flags(int flags)
>  	for_each_vma(vmi, vma) {
>  		vm_flags_t newflags;
>  
> -		newflags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
> +		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
>  		newflags |= to_add;
>  
>  		/* Ignore errors */
> diff --git a/mm/mmap.c b/mm/mmap.c
> index d4abc6feced1..323bd253b25a 100644
> --- a/mm/mmap.c
> +++ b/mm/mmap.c
> @@ -2671,7 +2671,7 @@ unsigned long mmap_region(struct file *file, unsigned long addr,
>  		if ((vm_flags & VM_SPECIAL) || vma_is_dax(vma) ||
>  					is_vm_hugetlb_page(vma) ||
>  					vma == get_gate_vma(current->mm))
> -			vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
> +			clear_vm_flags(vma, VM_LOCKED_MASK);
>  		else
>  			mm->locked_vm += (len >> PAGE_SHIFT);
>  	}
> @@ -3340,8 +3340,8 @@ static struct vm_area_struct *__install_special_mapping(
>  	vma->vm_start = addr;
>  	vma->vm_end = addr + len;
>  
> -	vma->vm_flags = vm_flags | mm->def_flags | VM_DONTEXPAND | VM_SOFTDIRTY;
> -	vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
> +	init_vm_flags(vma, (vm_flags | mm->def_flags |
> +		      VM_DONTEXPAND | VM_SOFTDIRTY) & ~VM_LOCKED_MASK);
>  	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
>  
>  	vma->vm_ops = ops;
> diff --git a/mm/mremap.c b/mm/mremap.c
> index 1b3ee02bead7..35db9752cb6a 100644
> --- a/mm/mremap.c
> +++ b/mm/mremap.c
> @@ -687,7 +687,7 @@ static unsigned long move_vma(struct vm_area_struct *vma,
>  
>  	if (unlikely(!err && (flags & MREMAP_DONTUNMAP))) {
>  		/* We always clear VM_LOCKED[ONFAULT] on the old vma */
> -		vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
> +		clear_vm_flags(vma, VM_LOCKED_MASK);
>  
>  		/*
>  		 * anon_vma links of the old vma is no longer needed after its page
> -- 
> 2.39.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9JFqaE4n/eGoWWi%40kernel.org.
