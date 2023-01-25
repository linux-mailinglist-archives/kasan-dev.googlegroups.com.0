Return-Path: <kasan-dev+bncBCKMR55PYIGBBOG5YOPAMGQEZAO234I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0528767ACEA
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:56:25 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id i8-20020a05600011c800b002bfb6712623sf369996wrx.6
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:56:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674636984; cv=pass;
        d=google.com; s=arc-20160816;
        b=n+Uoj5S1gh6KLwiUDBrItJqp0uJHQfCeo+tn3ruWByWSLGjkKsFUHmwg9h0KQNOLdS
         b5JAMLARRzbw79TpB9GtBnxuSdVMgpcpRKJ2iIQHxWJLTUuCuFgTU8h4GluqEZ0Z9KWl
         mQix0998E8vrv/aOsAzkNZVewLpyCaD+d5tlIRI/r5P2918cHHeWShml2GyAj+v7bWt+
         Iou8aLcsXJWydAg2ryzUfkmAV94MQjZc7gAemys9QJ5OkG46RPdXRkRxb5139EEITj9J
         Q9rlUDuDaYoZToJ0U4VSYNznwo2jdDL6Qc6xIznZy0DES4oP122wDF2Lc82YcXqMecVx
         Fk7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=H8HoL3s4ablVr8oWB7L6jfgxu2/WxcunZ290BSpXuwQ=;
        b=H/B9JZNMFiGfZ861/uFaZJvjotHMvDUo2BTl5Yn3syKF6kKo2EsBmCuYj97mU6vdny
         CqmhrGnrRhblLR99Gn9ztGICbmZAFwT/rDw0yz+pR63VDMaejcghsTHaB4nes3qzTd4E
         fDqznsA/S9u2GXWrR6M1r+mpFebpOp2bDCUyKEKCeV6WAkgPlJZA9fW2XEfAURm6ZCEs
         Mm3aDgjDWLPJZnZDF+DlEvOF4EhBcA3Vl7/fTtcuaZdRDG/3ajsQanwUy8U37oF0kWhQ
         MRihUcjKBJvC7EH3Hf25FtIncziIxU01h9eg+hJ4oKl8BhbDwsPqGPwNxp/p+QrXsz8c
         +3lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=sP3k2vbL;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=H8HoL3s4ablVr8oWB7L6jfgxu2/WxcunZ290BSpXuwQ=;
        b=GtdRDt3n4gdoXkWlK+ZcCaj5DWcLITpV32Qbol+QAgl0ZKqe1XBNy7RVp2rQbiSPjt
         owVuZsXwKuFA8VZd2YoYMyqykdgmJwjjRZFwiehwwPdzkHMFS5mLn7S5oa4R+dBivjus
         xAlbqKKNVOQVD71i6Dl5FJn5Eth2VVX3o0xHCFUCs4J71iZ/re6K5kcgPURVyvNmH152
         yKKABEqW0FKZ0sXP2b5Na5c4/ynyfeqTXB7i5OeewJkdPgxh5opq4qAoLKN214fSXSpA
         XYiFXLNlze2/LASUN5f+Hl7HrKpLIxKh45XQ6xtRcYpoaQ88LEEkB1OhT5e1AoFlwYj8
         AuqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H8HoL3s4ablVr8oWB7L6jfgxu2/WxcunZ290BSpXuwQ=;
        b=R7Gm5pQnbxmv92RgDoa9X6XIubqDgsyuSwW4fOM9wIo+KZ4ycJQGIKBEFnm71kGcKC
         MECQIrAkPYUe/SJHIvyLLdDaEjD91igogm52RUex/RG4GMTj4VYdd75UgNjWECOb3Hwb
         CnRMvWQqvKmk10oi6qH8Ah3c1ktfN5Xwgqdz5KzFlmrpAWsQkzriJVXd8mf47ucSrtLq
         kSd73PKgAUBhayM3ailLverNRf0xEGZgx8zGFHImLwa4Pc9csSlwiUf4KpguWFdHNLRq
         C+ukc+W+6edvb0mmqN6ilmACwp/5gZUEtEFDnWVsY69W+H7Dpp0b/0UOqJAO7EunExas
         Wl6w==
X-Gm-Message-State: AFqh2koG7/rTxKoOToRXlWs7r3GQ0PpBimYqCUp2C3XE7OvLbPHPuomM
	tUPVt0lyhiCmw/rnbThHYuM=
X-Google-Smtp-Source: AMrXdXsuBphnM7PL5ES+XBTSVUvqajlmiuJZB3cmhSVkdogDtepl6yyJa68O6Afg0XytyJsbGVNFHw==
X-Received: by 2002:a05:600c:4f41:b0:3db:14e1:d16e with SMTP id m1-20020a05600c4f4100b003db14e1d16emr2173674wmq.35.1674636984643;
        Wed, 25 Jan 2023 00:56:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd91:0:b0:2bf:adc3:9107 with SMTP id q17-20020adfcd91000000b002bfadc39107ls461127wrj.0.-pod-prod-gmail;
 Wed, 25 Jan 2023 00:56:23 -0800 (PST)
X-Received: by 2002:adf:ef4f:0:b0:2bc:7ff8:fb83 with SMTP id c15-20020adfef4f000000b002bc7ff8fb83mr27209729wrp.47.1674636983427;
        Wed, 25 Jan 2023 00:56:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674636983; cv=none;
        d=google.com; s=arc-20160816;
        b=HB9MhPdVb5O5YN6ouwPm5VFwG3LIt+t4Ntc/PqVSGBEGX/Po2LV30ADQskH019FerP
         A2qUb0FmrKV5A3HyM2tSFxqoZZgOF5Ng9PDGlh5ZSPNt71upVb+5kTYI4RC3dityudd5
         sYTihgZyqSwQP5qQ2exSuFz5fK60/gkTxz+JizorD7Akwaa13eniYVLiykl9TrcK6oiU
         p9QZKdEkOhSZvhixW7qGQyJa4O4mIW7jOnqa+YRrqsTysjWN6DxQDlHVig205AtLn60K
         TnMFZUjzDQxADPa+Z+NgdZcT2hRwQqFxTACDs811ceXUf4UJvtcnn9LxBjJV9IffSTfL
         w6gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HlfVezvAjFmKLztHMOaZ+yji8Nsqp9vLwu4LVliFLNo=;
        b=Wc+FICPAU6y49sW1je3WqvncggIIaaJL6hp0TBrDXuMUmy+jCj/5/BN6DnHLBiLR4/
         e2Muv+gMxcSMy2jITeAQNHbEmqLEU8lwd6ccfDPPFZMjhKwhuyvBV1bHC8fLZI2GcBla
         FjtBxsEIsZhKK5YAf112QMlLAXvMzv8nJh1jEWPJjU+x+OruQsdNK62+6DuD/iHvBcbR
         pFJjDv5V+JTbqtuyBt9bkHob+rg6bSUGAWSE9H//GBjP+vpEXljFu09JpsngDCVzIy52
         NH1OwbNW6r7Ebin1TKT5IogSWV7hAUWbjUOsfQuqZO42ImbIJi3zXaZ1cr2qW0UURMVA
         n/VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=sP3k2vbL;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id ba25-20020a0560001c1900b002be1052742esi208554wrb.4.2023.01.25.00.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:56:23 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0C21A1FED0;
	Wed, 25 Jan 2023 08:56:23 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id B78841339E;
	Wed, 25 Jan 2023 08:56:22 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ZJ2WLLbu0GN/CQAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 25 Jan 2023 08:56:22 +0000
Date: Wed, 25 Jan 2023 09:56:22 +0100
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
Subject: Re: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
Message-ID: <Y9DuttqjdKSRCVYh@dhcp22.suse.cz>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-2-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=sP3k2vbL;       spf=pass
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

On Wed 25-01-23 00:38:46, Suren Baghdasaryan wrote:
> vm_flags are among VMA attributes which affect decisions like VMA merging
> and splitting. Therefore all vm_flags modifications are performed after
> taking exclusive mmap_lock to prevent vm_flags updates racing with such
> operations. Introduce modifier functions for vm_flags to be used whenever
> flags are updated. This way we can better check and control correct
> locking behavior during these updates.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Michal Hocko <mhocko@suse.com>

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

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9DuttqjdKSRCVYh%40dhcp22.suse.cz.
