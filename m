Return-Path: <kasan-dev+bncBCKMR55PYIGBBFPAYOPAMGQEST42BOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C19A67AD1C
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:02:14 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id o22-20020a05600c511600b003db02b921f1sf754223wms.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:02:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674637334; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjYJfoClbKUTyY2cTj838YY6HzoAMipBav2TUunhASpbypRhzZ7CpCCy8k6pS52weY
         SjRqbv3qO/fkTWt1hCbj6OSBXcGiNHtmhk/lym3Gl5aGO/YdkwTgbYBaprD7b+fllUVb
         LFeLlQStCiY7ew5qyTwnSKQbWOvHqJN1HTXhOmSXO2+cvypxuvVZPA0EkJ8Z46Tz2uxb
         /+UFJ8ahIFBiS8Ej7vN8NOWgcPrFUDk/XmczV5+l2clPhIENudlp8r5WsVBmSDLc1HgO
         kkFKl/nKy6KhIA8tCif55P64LLgN/EHLrHIKumCjttadVhC6+7hPuD6UAtXbNqLRLVnv
         9UbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3EdevzxFVVnSNanU9D/7CKBtKn1YkBWLY5VdnRnuQSQ=;
        b=AGSdN8d0YvGmomQmYc8kyObpbegF642dpDgK69ic/wpwEYyRBLGlDuILILSiehxsfL
         EhLOpx+spr1WvSskU+DtonXMcBYbgbc/TKe/dLMH9sYNH59wm347tB8709gur31C3pQ7
         RsCRUiBa8JoGd8VO8baoJnCcTYpPBRLVwpPODd4zkdH5XS8Xo5/bgM2src6JdU5grtCY
         TgY20oLYEXOMJcvbHT3uYlfz5JB4S4tI+gcu35amK2pbDYyNKrAVMj0WDa+DET3PYyuW
         NLZb0DdbUWE1rA5ZSChntYnax+YX3GasDiBjGYicQ1OUwAWKFhQeB+hfCA5CmLJ1PvMK
         AtKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=CylERLDb;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3EdevzxFVVnSNanU9D/7CKBtKn1YkBWLY5VdnRnuQSQ=;
        b=XxTAiuWdt/KBVT8iXSHI2KlkNrqV44oOAWDxpGDMsfig2/vGo+FjJLhHZI5eFBoklw
         vcyglLmzfqKchfvT9clv1lBS6srDeuRufjNOap0wsk1gXcs55c3twfiBGaXv/uxS0ONG
         ikC3bOncldhM25ZI4C3hTW/uXMC1u+VjMt8v+uEkz/b/6VsAKczAEwVg7uyQ0u6kPSo6
         adFHvmXTL4bH2Kv0vDiCA55AgV6/tIKzvYJLdxh+tbMi4cHTNfgRuUk0xDj0IvZWluZ7
         PtzfKoDi/GZCbhNHs+HN007mYnyusG31Z/50K9+Kei9ndR6yuO+SOaoZe4fg8CgAzlVE
         RuXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3EdevzxFVVnSNanU9D/7CKBtKn1YkBWLY5VdnRnuQSQ=;
        b=u3C1tIVkWDb1vJ0AwQbBxsJc7KJG+gcAeAYHwQex4ufVN98XPIsX4en6EIa3HX95sk
         O7QWf/GD53xH94RDbTIJsyT0w8XmgSFcda64iBTKSuVPpBVCgpxzbFIdhJLiiHWhH3ej
         /LOJVeBJk47obXYl9A6z1JXcgLqZBIMze05/CFUH7AFl3YGYIf5wh/hQpODpQ99VjF3Q
         aLaSL2TyGjIczZDcaRmeqBBhk7UCkLj+loejI+Ixw3qZ9+Iory6jO/vI9os/MTWYo0Ah
         SrAKd1zEedPi/MxkrMlFpR7lqQzm9t5fZvx9O6cmyNxnpRZHixHrHMgvaqMtOg5K9wHm
         fy+A==
X-Gm-Message-State: AO0yUKVaGicKA3vcGXjfsdzc8xaV2ZOeypm4RvMIgQcWLkiOR8JO7LZ3
	RwHzEToKrQGr6thPIaioISE=
X-Google-Smtp-Source: AK7set9Mza0Bxnv9Qp68mz4l1fAdY1ivcXtRNgDzbkvczRPNygxSHhsAJXrZNvaIo2dBYnyIgPCTVA==
X-Received: by 2002:a5d:6247:0:b0:2bf:ae8e:c2de with SMTP id m7-20020a5d6247000000b002bfae8ec2demr255661wrv.588.1674637334096;
        Wed, 25 Jan 2023 01:02:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c7:b0:2be:34f5:ab03 with SMTP id
 b7-20020a05600003c700b002be34f5ab03ls488480wrg.3.-pod-prod-gmail; Wed, 25 Jan
 2023 01:02:12 -0800 (PST)
X-Received: by 2002:a05:6000:10c6:b0:2bd:e33e:c04b with SMTP id b6-20020a05600010c600b002bde33ec04bmr25819647wrx.22.1674637332805;
        Wed, 25 Jan 2023 01:02:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674637332; cv=none;
        d=google.com; s=arc-20160816;
        b=hfeMEprwc9Brtph9Y0aIcYfmPQ/77REyPe0w3PYxICNrhqV0otUK8aOFZ8ecewQ/Zr
         0iGuwvdBhdIBBtkDWprvt3efSahKPznZt1RQgFnbsx2VroADvCfd0Kol9QbohJ4HX9V1
         Gcv3ctmA09wWd/7fQKkE1aBxpTFOr2K8ouUtiYC9sdR4KMiF+GytQ4g4UR9WuMLLDQum
         RC0f1Z3XiNp0QpPpl+Mv3VhaeD5XkWOkbePw/n5gmQ2eZZYWUUIriSX5wnhYALBmxM7K
         Z2UQe56sWtGvEHXFW30toPl41GpehT02VjO9zJymc1Dpznhsv53irY1Lz3BnWO7HP6n4
         ZIFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SlRMHnKgl2ysMiG3ziDgQVqy0pZ2+RMTN2tEUkXl1oQ=;
        b=i0RJb8iWx1FrtPCsSPH3Nz1/FF5tpgzU7k3Nvx+0Gwe50+mqR9Z25il0nnIPrCnIPF
         BVGxaxy3MzIkwCKZMEpbfjaTj3j7QQ/y328OJZ05FTAM89bX6TDBgUTRLV2S23mCSVDq
         58m09Be8t7I+fjw/1WYy00Gx7UMmv6IaY+WB2094PngpDKJowpcBOn3umpBOSGFsgwyY
         QU3mEgHo8RguQ7yp5Tq5tPx6LwBk6/92pTeOvKwrTXtEtC2ramKCmFM2ZSzrYTvkLKNO
         UCG2R/bbYoxIZpT7daEmjXKVwoHa57JmqhDDVYtdYtUE70kN4cnW6cNKPVH6KkBK89MJ
         3ukQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=CylERLDb;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id co14-20020a0560000a0e00b002be378bf638si205505wrb.6.2023.01.25.01.02.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 01:02:12 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 705451FED6;
	Wed, 25 Jan 2023 09:02:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 224651339E;
	Wed, 25 Jan 2023 09:02:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id reRPCBTw0GOqDAAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 09:02:12 +0000
Date: Wed, 25 Jan 2023 10:02:11 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@techsingularity.net,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	peterz@infradead.org, ldufour@linux.ibm.com, paulmck@kernel.org,
	luto@kernel.org, songliubraving@fb.com, peterx@redhat.com,
	david@redhat.com, dhowells@redhat.com, hughd@google.com,
	bigeasy@linutronix.de, kent.overstreet@linux.dev,
	punit.agrawal@bytedance.com, lstoakes@gmail.com,
	peterjung1337@gmail.com, rientjes@google.com,
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
Message-ID: <Y9DwE4Z8hB38aX6X@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-3-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-3-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=CylERLDb;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 25-01-23 00:38:47, Suren Baghdasaryan wrote:
> To simplify the usage of VM_LOCKED_CLEAR_MASK in clear_vm_flags(),
> replace it with VM_LOCKED_MASK bitmask and convert all users.
>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Michal Hocko <mhocko@suse.com>

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

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9DwE4Z8hB38aX6X%40dhcp22.suse.cz.
