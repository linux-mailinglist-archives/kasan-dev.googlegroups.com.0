Return-Path: <kasan-dev+bncBCKMR55PYIGBBCHTYOPAMGQESAWI7UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 6135D67AE56
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:42:33 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id v15-20020adfe4cf000000b002bf9413bc50sf2248436wrm.16
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:42:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674639753; cv=pass;
        d=google.com; s=arc-20160816;
        b=qoZh2mHaXJuwc1lR9V9hsiiWfyQmxG+We0Wef2NNvpRNSLtZaJ4CKaSbGQqk8uciPL
         AD7EPdlVzSWmfwMgD0VTpIMTO4Dxm7toLb6wK6a0Fp7+U7Apuy8iChOojJRU2O21ZpBz
         zJuqtQwg2Djufo3sPDioBbTkHfDrPgsF4JjlKLSi1bD1tVuSlkbTYx+s/i0MMilgXxE8
         I+81KYid+mURH5p3XQKL2BAGl4BHOIQSKRyy6vjXpdhpx1vI2QENXqQDWy8Eqnc47+gD
         44QrtHC8zXrzZJnBXUgdLRPXlgFDcPbTFkqyLO5lpF52jaNM+LCtuZCfxl14gi30eXXh
         sdtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=wN7OlV7gxZwV6CvkgWoJTWUNWyn+/Ks8hFKSiZ6U778=;
        b=isYOVaTQoGgoXEchUxbxrTaOt9rjFIzgl/in+yD7lkoM+1FdHbUKcI/WhOJIRDpEX/
         nKl4/0enm0JLF+IVbQypsv4jF54HL6g9p4b2ZQFU2qgKjmdCyzVZ/zJj5/HrS6Br1RnG
         bViqyQKByCzqvpsgfSMKTGTuAl7aLhd7zbXmwU3S2iMVza3RSljdAVoRBOiWm3WBEcHX
         UlwMosxpdtCEx94ruuArlxo+nbJcQc6yPfgGghULJCXGQ68ISs0apE38Pnk1yIKSQau5
         dsUAV59rY99rFxahqJ2LEZgn3h3drlToQMbevHsepAeeWAJ+jkBYSd3RTHYrcRSaMWtn
         vzPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=clWvQxTx;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wN7OlV7gxZwV6CvkgWoJTWUNWyn+/Ks8hFKSiZ6U778=;
        b=r+jFqLCs9IuLKvsXbSkacQg3hglcpfeFxASEdfgrdMgMTSg2ciHQEUIg/jDx1Pteuo
         VPYnTXhQZKXXzfJVjS2jSYMYrEETzg3zC1zNu4QmhctrxDfM8rL2FQ70GISciOM0TXTV
         EmLdLN2rPXf0rq1/bQA/xOYBf1wREmFJujwXbjWJVt6nhO6zQ50IriJ90HV7RZ7p1bKB
         OQIzCJCcHYt0ef9Qb+oOaA0VM4NGv9HfmfT4F3rmVa9pNmakaqa0/HOKWtuM7w6Xwhm/
         dPsDRbmnXCSglwmrjLK/pI9lAvCpgJDsyq7AUFx/js0MiwFTthrL43LkxIylaXconWya
         KJtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wN7OlV7gxZwV6CvkgWoJTWUNWyn+/Ks8hFKSiZ6U778=;
        b=cT/CU0Bzv9zaVLN+5+BLZZpS6fekqGJI3KCALdMXEY9DRpsFWXGSzto2iQlya9kO2J
         d7yAD0nHd58aaJOYZK5I1jqQDhCU5gdhfKz54fVaODqUiZm59IQ+yW2Uca2liAsuoimP
         p2Q4QljmvvocSuIGoHChYiE80cF/UF6/KyJeHGDdj7B98hSFQEeg7YWrhbCuhkB0FMqW
         IkhUrqY38O+kd/LFPeo2y+pzJxt98N2rHQwEXQwQtMHI7IoYAa0PAUHWdxS7yJ4EGeDy
         ioya5k6SUL/NZRI4GQLSckmKsTiwQA8Z+USbqcQ0UwHD27wBlQtsZV9MPCFP7XSDHd1Q
         Mbdg==
X-Gm-Message-State: AO0yUKXz7s3Uo6dXO0D6ksunVdohm20oHdmQ0H71Tu/KL9xZy7JKmR05
	hkva8Bg6zUbLT69cuAJC8FM=
X-Google-Smtp-Source: AK7set+WnV8vzpeCGVOOKDhSc8LItakjoc0qqHlk9mtszTiBkPFt01Z5XafA+AlB/kBm4J/mU2HDKQ==
X-Received: by 2002:a5d:6e55:0:b0:2bf:b2f2:bf66 with SMTP id j21-20020a5d6e55000000b002bfb2f2bf66mr206366wrz.440.1674639752827;
        Wed, 25 Jan 2023 01:42:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e48f:0:b0:2bf:ae0c:669b with SMTP id i15-20020adfe48f000000b002bfae0c669bls658961wrm.2.-pod-prod-gmail;
 Wed, 25 Jan 2023 01:42:31 -0800 (PST)
X-Received: by 2002:adf:e908:0:b0:2bd:e8a8:80bf with SMTP id f8-20020adfe908000000b002bde8a880bfmr27138277wrm.55.1674639751537;
        Wed, 25 Jan 2023 01:42:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674639751; cv=none;
        d=google.com; s=arc-20160816;
        b=EQCw3cx26eCcNS+5VgJFnyqNqIMqOk6WPl8/qb7K63tFzXLBEH7irjyIqwvTEhAAV7
         WI9VWw6rBdpQvKqe/IQNGJ9l/Fn4CX5J0yYw+ybhWCM9sR4wY27/9/zXq5Wij14wWjYx
         0reKyYdYP1Ku7KdkOEVNDhcfqEMkrcw/MK1uTKyzt1mI6eUJOI9EMMPZTAPwyoQnRAf2
         JxSf1Xz7mTklGzokckjc6zERZSXhuv5vw72kpU12g2ZRs39O99CRZRhH/qT8LXIgPAaO
         rwXWR4RUoFszITPxAB698MCqdnFLwnr14Dx6FPQAIYVElArGXyVmp17CcBd0JQ63DDuD
         zxqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wTTa+i+nU+PdO+h/KcQj1hMAey36ZrEColPN1KlfYvE=;
        b=adbHaKgVb5f19t6XYGgXWlPudn48JY88mMcoIC9rIBGGUwrrwsObMC59k94eVdjhre
         2ifS23UlXlpbgx5t6Uca4CaAaZIKPZdIWZnMMSEUTTDzlaO5w5KZfwvWBfjm8VVH+Qo3
         Jwj7ARbePHXQJPZkGjo1qo9O3fmkA6uCICZW7FEg5udbFJ9ky5oIeD2DpHF6FiVmE2Gy
         ml/lRtSNCsnogsx9oofDtBDP0d4f69mS8GHyoVN7XjfHwXhTfYU26LheB5a2FYellhp6
         sn1x4az9pYo0HVkuqPeNF3t/VyvY1seY+tQBxJgtfFFwD1tQmiJh7xMbNy8+D5yOwmBk
         YjmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=clWvQxTx;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id h5-20020a05600016c500b002be29f05cdfsi221586wrf.0.2023.01.25.01.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 01:42:31 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4107E21C7E;
	Wed, 25 Jan 2023 09:42:31 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id EA4FB1358F;
	Wed, 25 Jan 2023 09:42:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yLixOIb50GN6IgAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 09:42:30 +0000
Date: Wed, 25 Jan 2023 10:42:30 +0100
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
Subject: Re: [PATCH v2 5/6] mm: introduce mod_vm_flags_nolock and use it in
 untrack_pfn
Message-ID: <Y9D5hjcprLI92VKf@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-6-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-6-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=clWvQxTx;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
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

On Wed 25-01-23 00:38:50, Suren Baghdasaryan wrote:
> In cases when VMA flags are modified after VMA was isolated and mmap_lock
> was downgraded, flags modifications would result in an assertion because
> mmap write lock is not held.
> Introduce mod_vm_flags_nolock to be used in such situation.
> Pass a hint to untrack_pfn to conditionally use mod_vm_flags_nolock for
> flags modification and to avoid assertion.

The changelog nor the documentation of mod_vm_flags_nolock 
really explain when it is safe to use it. This is really important for
future potential users.

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

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9D5hjcprLI92VKf%40dhcp22.suse.cz.
