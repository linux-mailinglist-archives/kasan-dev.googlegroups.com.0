Return-Path: <kasan-dev+bncBCS5D2F7IUIMDMGKTYDBUBEMY72TC@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 408F567CF77
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 16:12:03 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id cr14-20020a056a000f0e00b0058da951c487sf1054849pfb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 07:12:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674745922; cv=pass;
        d=google.com; s=arc-20160816;
        b=RIFZuzTucBBk+KETpjdQiJ4Ni3lCHt9lrSv+GGv1KeVySQtU++EFdTkdf3rc0loJjK
         YDc5MG8DpnqAnx5UtkYfEvxFZXP5MwYv4sXLQy06jvsQBf4NePylEIUuHhzZ4hHENqOV
         k0omSpPWNXdAeYLO92YNVfokIEOHgeXngPGqCnjecuGKz9Zs5uGYqXGIZ56cAwnmg3qq
         RNw0UH9ETUGoE+PenaGWeM3YPbzHhIEsiDtMOBXlv02twSUtDYtRnCOBe9RoYnxgQ9IX
         8mMBbaOGgPC0ELYorwFfJz24HoA3E+Xz5TcEA21LUU0e26B464tgu8rpfYk9sXCzWQR6
         7QAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kozU7Vn9PVTJyE/zefiOyyNSZliC3MsZ3c/z1DFa9hE=;
        b=jIchb4f6G5SNN898MFTN+JDAbGmKb1weuLy7jGUReIgmFiFHdkT7raNT/Okb0HVDE4
         H46rUXUmpUTFT4Acd82UMqObNwSX7szcRyj4RWiAtWMqhl9qW33o44zWQ+xgwAto8BcZ
         aXMW7pylhVvtZtMd+xl/4/Mj4Bacid8u6Z66YIdT3D8Ora3+OQuLITCvp/RETElqEB4c
         S91Cjxs/bpDtsdd58BO830hK8Wpz+f3YUAk+HE2FFniNMZX3o5TVRyGpy2KZtCHkb7+p
         WgHI9KebsOZfE9biEXD/pnNbWkGJbfGPXAcU8mWy78tnGiL436mBsB67iUWuOD4ZK3zO
         GvQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=iqmwaHjx;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kozU7Vn9PVTJyE/zefiOyyNSZliC3MsZ3c/z1DFa9hE=;
        b=I0gsUWUUBa3XSRSHFjdiwUTpx14Y+zszUHPUA8POKIxOjfVIT90+OQyvd2Zgq28MWM
         s87lnrpWWlONnpVCZ9bVsoG6xzyOUv9k04E2J/yE6QyHqLWyH690Bo8kEOl7BHELY85K
         vbsiFsjHvILf5BO+y6WJvF+bnu5+xkwcbgBPFyw8uXFcXZO0vqV0oIgOiNYwrxNn68qz
         eBMYqTmJGpOxiTAc9OxeDnZaLSY5F/x3RoMlBpfXgtxWJ75OkkcCLjyMt98CVTB/oD+N
         +d/w1kyALKDk+28WW4cBJ1cQHfGtUjqYPF6fpwxnLOaHdr83fopTQhJ4K7v0SNcaswBw
         qxDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kozU7Vn9PVTJyE/zefiOyyNSZliC3MsZ3c/z1DFa9hE=;
        b=cB3v1LIBHm0S0s1cWy3F/kv3jTJh52mXr7Mn1qw51JxzEzTOhBooSZp/klydM52IdG
         +mVeUXCQmgcuwBsJ3Ks9VLdql34eixxEJQbvuGSwi1yQQhE5lqRriLVl5JJi+MvJV76Z
         GO3yLTvf3cnay+A1zcVgfRQLuN0S/eO2pj4bPnmCAJg1zIV9Gblju36VPfxLxbJQwTKi
         95FxnOyI8qsJgrRwdn3tB71RVmyO63xVTzjUsm2CWzFoLKi0e42k48OqQ3N+kOSd9yl2
         lu5eu+bCFPGx9bebw1awfKT3aOfHWbNuxaNkZYn6/VAK7CKdTVs8CNSyEKWiZRlOKlVu
         MF6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWUK2OLncodx22fNOXUyD+LNGvHVC+QHDImymWSYPaDVo4ClY/C
	Q4zjJBl2Gm7tm9rUUo/zSyE=
X-Google-Smtp-Source: AK7set/4qgF3EqZQekOSbEs6Xu0EPde1PhT51zGYSqhz2ZoM0XM/5qDWc/hBnX5l50Y/W/OZdyU1kg==
X-Received: by 2002:a17:90b:384:b0:22c:3a4:697d with SMTP id ga4-20020a17090b038400b0022c03a4697dmr1283142pjb.63.1674745921766;
        Thu, 26 Jan 2023 07:12:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d80e:b0:22b:eeb8:fd6a with SMTP id
 a14-20020a17090ad80e00b0022beeb8fd6als2726988pjv.1.-pod-control-gmail; Thu,
 26 Jan 2023 07:12:01 -0800 (PST)
X-Received: by 2002:a17:902:c94b:b0:194:acd1:6624 with SMTP id i11-20020a170902c94b00b00194acd16624mr48754914pla.61.1674745920938;
        Thu, 26 Jan 2023 07:12:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674745920; cv=none;
        d=google.com; s=arc-20160816;
        b=FY1oQKdsYdTPKsy78HuIcFiw6vnT5513u/POD8qak8Mpla6nElJUlNdYDX+Q8zW3HX
         X8k/1BygKo+7ZFY9+rpdaWPa1fd8njd7QuwXWG6x4eeQf6oNRYxngHFrmZKa8UOB/O1r
         Q4oDfdYs63zUy58qsSvnD3Rh6OCbWfXbbJFtbDwh71gYA7zcXjIF6dfcxxvwWjDfPIbI
         9848hHiG0jQlWgLbCpkfANpo52/CN9SLVOybOzoscqOb2PVAfoy50jmAGUSerqQp21H2
         BcqTdCuXX+FhAYvzoy86lh5wmBdUAfgMmhloVBJ6zinA90op8Nvy1EFwiNGeqxz3EZJl
         qaNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EH9adbDOpWNaGYEHl4xrAV40gwHDwqK76tq84Z0eyXc=;
        b=Q0/cm1ysbMPy+zOfMjpwGOCuNO/tdp3owS/HnXi5Zw7u+ZKwfI3KXOc1fkqMvMK414
         ENU0/0DLfGPdya7ASxhGQqIyXOCoDx9YBhERwwcoucuMO5fNN/HhSbB8FXcxw61y2h6a
         2pKG6I9+FQBGQZzteay1BXaUMeMiWQ/na+3YXPDGoXFP4XH/vPtIS5d13zEycl+zRrWH
         UI3YDM6D/qZzUVye+Mlo272idTdcQlvso5J4vMv+4Wd3vwjLIA2lbynGrtbLelJQ61EN
         1wKIC9pzq4uLsAZcgYjQUMXuF0HaPe7C/WqnVlguSQK56maO/j8aUibM0P8G2dKu38b5
         l8oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=iqmwaHjx;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id q8-20020a170902f78800b00178112d1196si126489pln.4.2023.01.26.07.12.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jan 2023 07:12:00 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pL3s4-006q4a-Hd; Thu, 26 Jan 2023 15:09:00 +0000
Date: Thu, 26 Jan 2023 15:09:00 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Mike Rapoport <rppt@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	michel@lespinasse.org, jglisse@google.com, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@techsingularity.net,
	dave@stgolabs.net, liam.howlett@oracle.com, peterz@infradead.org,
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
Message-ID: <Y9KXjLaFFUvqqdd4@casper.infradead.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
 <Y9JFFYjfJf9uDijE@kernel.org>
 <Y9KTUw/04FmBVplw@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y9KTUw/04FmBVplw@kernel.org>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=iqmwaHjx;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Thu, Jan 26, 2023 at 04:50:59PM +0200, Mike Rapoport wrote:
> On Thu, Jan 26, 2023 at 11:17:09AM +0200, Mike Rapoport wrote:
> > On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
> > > +/* Use when VMA is not part of the VMA tree and needs no locking */
> > > +static inline void init_vm_flags(struct vm_area_struct *vma,
> > > +				 unsigned long flags)
> > 
> > I'd suggest to make it vm_flags_init() etc.
> 
> Thinking more about it, it will be even clearer to name these vma_flags_xyz()

Perhaps vma_VERB_flags()?

vma_init_flags()
vma_reset_flags()
vma_set_flags()
vma_clear_flags()
vma_mod_flags()

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9KXjLaFFUvqqdd4%40casper.infradead.org.
