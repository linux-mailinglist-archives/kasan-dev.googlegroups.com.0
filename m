Return-Path: <kasan-dev+bncBDOY5FWKT4KRBTEKZGPAMGQEYL6X3WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8308B67C6B3
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 10:18:06 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id 12-20020a62160c000000b005808c2cd0b6sf678253pfw.12
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 01:18:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674724684; cv=pass;
        d=google.com; s=arc-20160816;
        b=dIFS1+Xma7Ynliov++AQcgev4WvpJdrhxBefE+1lr/dfSSFRdzkASofmnfuQ+kFymd
         1CPkSst0cIWV30T30DlDCpjdBQTSZ9b3N4HgXyHQ3NfG99c/6idlXyTx6PLJsBwPz6to
         p2msSYgc26pqmB6cGuobPqBQ18mNIhkjEdoFyeagxDG4LzKw1y4NSw2eWCPD7ZAExWJ7
         Tw1isjLx/3qlxAwi0iKznGTmTpPNX2y3tZZAEaCtZODSNoIJLnSBUXmrHwg6HcJkmJjW
         BYRj9LLXgp9FR2EzQ4K4Rb5aSiYCeN8YJN1YxSpX7TglwGU/daYFI48jgH0cJdJs5tiT
         h4Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8lT99Lg4CldWHeedNAS2U5TpwUCVAZGzDYGW6GKdC5Y=;
        b=Ff9+yQQN63RkIGy2fOe9sTQb5v+tFeBrcqQmepM9yUL9YTwdYcTICccZPNcxFadvgw
         HqGTOT/Deb1beUiaF0l034FT9+ZnAwvoTChVoTPqtXKQ9xoegs8H66/sADBd6Xp1G2YL
         wakO5qpoLYKbzU69IMgFE/pkOCtgsdE9XdnX5NuOZYO2tlN/cAP6fH+bQxAAnGqQimzx
         iMvWbBTTWbwtTVF/Qmei1oSonNI3hlZdaVUUcGXWX+VRZeyj0zrJQetmrUHJvQrkpgtz
         6zhsDLcQ7oYj6i0cij5CYvjdawFp/olRLLTNOobyivuf3FhclJtNjU6yduH6pfiYpMV4
         gElA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sky5enLF;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8lT99Lg4CldWHeedNAS2U5TpwUCVAZGzDYGW6GKdC5Y=;
        b=Gf29K0M3GT1Glv/ANdu/MTzMqb6jCEhA/oolC+eMNxgIstpGCuBbm03pUWjVhGcPUp
         bd7ZI67Q0LrM9UqXYus0iphxBv06bCaXYRK4ZC/QIpU65dDenlJtQaqnXjDVblnaeccZ
         31rt3mtGauMII5yjGELWZxIkEvYwPkoL+0KO2wlOkC3DKgEnD+DSrxs4yWI/liDCMuUA
         m6QyTap/UOuOBcdxSC5N6zSIB+bWZsP1LRUcJimXVbizWa9sjoJHT88jhj1j5Q9YkQQt
         9F8Ci3rYtDzISPZ1M6w3S+ogPhDzNCt5pRlphdTlmRiai0/N3eyFo3BzefMdinvlXnbd
         +0Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8lT99Lg4CldWHeedNAS2U5TpwUCVAZGzDYGW6GKdC5Y=;
        b=YF0on6W2dfiVp3KHJs5O2bnhw167RboZMNiaUpKNL3WRFDkUwd5egulpr9q0Nt44FU
         3BITQtKRGcxACLy6D+GJ+BwzH5RRkPotpEC5/mkDuxzlwyRiJTqhd27YJhSPhs9t0VGM
         xNIomubn1oYN1GxbCIHiuUrw0z8IIJUUuCiUz364U4ym0Z1saW6vAazMLWHAhn8dLSG9
         gGHvAJcO3/eFZYkO2Ux2ElkFnjJ0v5+QP+m0o8nbdlyEyrEll9W6CptNnLZ0lS8gGseb
         JNHBWq7+iV/INJjxHadfmyeYPaFhC+GD9Fiq0CFnx2pI1Gdks7S3ehXqoIjWDIqY0SLk
         5WVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVihzmmMV8vRZnEUc9+tS78psy7m41kXZLPPA17TCHWQ7w+zlwr
	Wa3oevoE9Gk2FZaYTocRknw=
X-Google-Smtp-Source: AK7set/PEnMGgzK8zVXUyz4vVfnWxvlinkoBznnqT/AS8Cg4RvypszPodUBv2KabCy7rjjSp7E09eA==
X-Received: by 2002:a17:90a:6e4d:b0:22b:ee57:725b with SMTP id s13-20020a17090a6e4d00b0022bee57725bmr1771201pjm.159.1674724684663;
        Thu, 26 Jan 2023 01:18:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2312:b0:194:d87a:ffa6 with SMTP id
 d18-20020a170903231200b00194d87affa6ls1709612plh.1.-pod-prod-gmail; Thu, 26
 Jan 2023 01:18:04 -0800 (PST)
X-Received: by 2002:a17:90b:1bc7:b0:22b:bbe3:672b with SMTP id oa7-20020a17090b1bc700b0022bbbe3672bmr21453050pjb.9.1674724683911;
        Thu, 26 Jan 2023 01:18:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674724683; cv=none;
        d=google.com; s=arc-20160816;
        b=eMZga4jOCBPGb2vXka+jrNpdUW4rCfoMnPuhAPERIj2Bwoj5VPPRxra/eSDsD0DMXv
         vJKLPhx2InEqFFo4YxJrqmAjFTIL2SqGyzis/7dWFgd4PW7lPGac9M8J80Lfgxi7HHc1
         sIY1tZRg3bjC+BbGl59N4KVl+nomw0ywPZKnqrsJHRqoQDdw7DwID5+mqWiMRjzYokQn
         H+thJT9253Tm4lUajZYgFAqme5SSxgaSr3OIOoNBperTV0b+A3fNPCU0zJ0HpdEKVzbV
         7Z3LApARoUlrXBKNPxoFl2I9uM+RzfrnNwSYXZgexl9diIy/IVLV2m+gVnTAmvyUGMbr
         txog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=h2GT4+WZ8jGJqzdU7QXUBHwNvKESwP4EBaI52fm4yVY=;
        b=jrr6KB0up2cNUMnm/r/hm9TBuHtEXT6y9+3bKq/IUQ3MWa/RN+/5MYDILya+kFnmQm
         W8PYFnpAE2Fdk6tB1z06CTEKzBELpRyC1X7TuBvUHVWEsNas0x5N6VKOX9DUuAce9sIr
         /NpeaWFusXh4hNBa9jSXELGec5BS0/1+9l/FAQ77uhsky7VFY2FxlzpSmUZynQEznkYq
         TxQhyn74ZG8jZavyq9L77JLbtTYil6fEwZKAagPxNCL3vxjcVCfv1jSAC9yOSy9TGk/g
         Kpxm0xnfpcy82QCgjJcP2P60nbqPS9zoyNfb8FzHCnf+LeHUeiqQ9GVY7Qgl9KtucOy2
         cD3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sky5enLF;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id t14-20020a17090ad50e00b0022975f69761si67013pju.0.2023.01.26.01.18.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 01:18:03 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 148A86172A;
	Thu, 26 Jan 2023 09:18:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0B686C433EF;
	Thu, 26 Jan 2023 09:17:19 +0000 (UTC)
Date: Thu, 26 Jan 2023 11:17:09 +0200
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
Subject: Re: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
Message-ID: <Y9JFFYjfJf9uDijE@kernel.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-2-surenb@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sky5enLF;       spf=pass
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

On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
> vm_flags are among VMA attributes which affect decisions like VMA merging
> and splitting. Therefore all vm_flags modifications are performed after
> taking exclusive mmap_lock to prevent vm_flags updates racing with such
> operations. Introduce modifier functions for vm_flags to be used whenever
> flags are updated. This way we can better check and control correct
> locking behavior during these updates.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/mm.h       | 37 +++++++++++++++++++++++++++++++++++++
>  include/linux/mm_types.h |  8 +++++++-
>  2 files changed, 44 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index c2f62bdce134..b71f2809caac 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -627,6 +627,43 @@ static inline void vma_init(struct vm_area_struct *vma, struct mm_struct *mm)
>  	INIT_LIST_HEAD(&vma->anon_vma_chain);
>  }
>  
> +/* Use when VMA is not part of the VMA tree and needs no locking */
> +static inline void init_vm_flags(struct vm_area_struct *vma,
> +				 unsigned long flags)

I'd suggest to make it vm_flags_init() etc.
Except that

Acked-by: Mike Rapoport (IBM) <rppt@kernel.org>

> +{
> +	vma->vm_flags = flags;
> +}
> +
> +/* Use when VMA is part of the VMA tree and modifications need coordination */
> +static inline void reset_vm_flags(struct vm_area_struct *vma,
> +				  unsigned long flags)
> +{
> +	mmap_assert_write_locked(vma->vm_mm);
> +	init_vm_flags(vma, flags);
> +}
> +
> +static inline void set_vm_flags(struct vm_area_struct *vma,
> +				unsigned long flags)
> +{
> +	mmap_assert_write_locked(vma->vm_mm);
> +	vma->vm_flags |= flags;
> +}
> +
> +static inline void clear_vm_flags(struct vm_area_struct *vma,
> +				  unsigned long flags)
> +{
> +	mmap_assert_write_locked(vma->vm_mm);
> +	vma->vm_flags &= ~flags;
> +}
> +
> +static inline void mod_vm_flags(struct vm_area_struct *vma,
> +				unsigned long set, unsigned long clear)
> +{
> +	mmap_assert_write_locked(vma->vm_mm);
> +	vma->vm_flags |= set;
> +	vma->vm_flags &= ~clear;
> +}
> +
>  static inline void vma_set_anonymous(struct vm_area_struct *vma)
>  {
>  	vma->vm_ops = NULL;
> diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
> index 2d6d790d9bed..6c7c70bf50dd 100644
> --- a/include/linux/mm_types.h
> +++ b/include/linux/mm_types.h
> @@ -491,7 +491,13 @@ struct vm_area_struct {
>  	 * See vmf_insert_mixed_prot() for discussion.
>  	 */
>  	pgprot_t vm_page_prot;
> -	unsigned long vm_flags;		/* Flags, see mm.h. */
> +
> +	/*
> +	 * Flags, see mm.h.
> +	 * WARNING! Do not modify directly.
> +	 * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> +	 */
> +	unsigned long vm_flags;
>  
>  	/*
>  	 * For areas with an address space and backing store,
> -- 
> 2.39.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9JFFYjfJf9uDijE%40kernel.org.
