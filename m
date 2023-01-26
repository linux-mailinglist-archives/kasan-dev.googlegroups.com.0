Return-Path: <kasan-dev+bncBDOY5FWKT4KRBBNHZKPAMGQEDMYUGDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1319E67CED8
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 15:51:52 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id y19-20020a05651c221300b00279958f353fsf441396ljq.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 06:51:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674744710; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ufmm7CkJhdw29MnYRQnJ2SG9p5C8EqEzkBjyD5XqYj37ay32f7zVx8ue3o2oVZYgXZ
         cDIPK73FJnqQDhD0tk+nq0A2Jy1pFIIShl2KNl7Yg8a06TY8NwRGY528CgqHmHLwXVdc
         atTCBwEeP0h770AdFgBYYe1h+zk6i5KR3w0aye5FAlR2se/jaJRFSNQSRi2H5B3QP7nV
         4aTEAn6cSRl4Y/EQQosMZxXN1Xy9jJ2Av7Oti/bc2ytpKKpPF9OQs8tjRr5ow8Ry3oJH
         7oFm4tlfVjJdLD7gTJP9i4tQyHV5j6tA/NzGTf1LYmfmbCXIsQ2hvxejCUTf9Vs/6LP8
         MldQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AgzQJjXiB9O5IezDjFGFhF3lTsyY+6Zg3AH/bEahOms=;
        b=bEdUTNRIFr9ccTn5XA5iy5i/8ISEMWtH7O3zGEHdYgNkb1Bc1idPxMGtO/6NSDHsXs
         i1jSu4sH4H7asbFFJkYSpyKWtoRb66s6BsSRrUQtBTo1iujHPKKbtePcvDKlCblhAO6a
         bUUvFUUXWoJ5209JXlocPXKCn+jAVTfiWsmsdeP1gHv09J5Vc971wk1s7RUbw6ow24jw
         6JnA/ccoeRQ352MF5g1SE1eFiwtoAwHuNz45mRy+QRoEMfKOuSswjin1+SGuqbAy94w7
         hHVLoYWGziFV1nqFJNXwetqZei9DAx/b6gG4/BR45HIAingvDCVmc4f789AxH+ZEfMrV
         0LdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r54XDevq;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AgzQJjXiB9O5IezDjFGFhF3lTsyY+6Zg3AH/bEahOms=;
        b=dvUXpKs9Vavx9sr4lupRe2iKA+ZZP4s3gNzB6BhxOwlUj5Ow8EAIyIpobtuF1JKkBu
         0+vDlPu+IqNsHwOR64KF/EodmVzyFcFhJXkEJuPT8lPop1kXoOzW95Vk0xZW6d/0yOAd
         pG6s4d7nxN9/NAfjh/onv2IbwMmtnMa7+vdd4ql3PJlvZHJz62D1+Z4BiupjBdoOCoCw
         4NNB2kwvEFsDh1IXV03j5vXyKqk3RyRD1p/XHklR1qn6JVcSE9CfSpPgg6SamU7v0lvr
         C7xAhB6cIrpi3rvpb77odQr/aLxkFz/lBz0TCwr9SDs6eXj+Wn4hWRUuhlXQ4LS5zO2A
         Tg6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AgzQJjXiB9O5IezDjFGFhF3lTsyY+6Zg3AH/bEahOms=;
        b=0URUSocmEV/pBdOhP0/DJE8LwEV+0Kv1kcECaYBjOIluezUd24Mc5BBSRSpPgYW/4u
         zXwTASvohF6C6f8zLkF8oUsF3bYGc3t2WpEePfL/Xi/s5txgfA8T5cQxyKlFK9cvwL6D
         QKy9OFWBMjHQRPaHTQMlvL6van/xfPoIwMkdlyxehuEMhiEKKB4mROvtDM+x8UC4namI
         PFSSfZGOnGRxwWAKp3tsuhC2ksxrQn2L94Tm4EGulCLiHk+kjPeA3mDcqWE5UvvLk+Vg
         pY5ZdrWgxq/6LbC6L/Z4WLIzRdICYkgjona4b57CvtcIsqgR3OuOg0UB/Nqpx5iWB5Gz
         JcCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kotLp3jwR97LM8Vn8sDFbROPfYj5M2q8T2qrkg+LWO9j6ECyxGL
	m+jZhkR1Ety7hsHHcnnsENg=
X-Google-Smtp-Source: AMrXdXu38+m8g3nd/LKbFuRx+Vv4OzFO9p6jSq6POISCljz9467r//cgNkUwdvjtqt2P7Eg6oUFTxQ==
X-Received: by 2002:ac2:5ded:0:b0:4cc:84da:1ef6 with SMTP id z13-20020ac25ded000000b004cc84da1ef6mr1662448lfq.262.1674744710213;
        Thu, 26 Jan 2023 06:51:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1146:b0:4cf:ff9f:bbfd with SMTP id
 m6-20020a056512114600b004cfff9fbbfdls1502792lfg.1.-pod-prod-gmail; Thu, 26
 Jan 2023 06:51:48 -0800 (PST)
X-Received: by 2002:a05:6512:21e:b0:4b5:5da1:5225 with SMTP id a30-20020a056512021e00b004b55da15225mr10196530lfo.50.1674744708734;
        Thu, 26 Jan 2023 06:51:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674744708; cv=none;
        d=google.com; s=arc-20160816;
        b=P3od9SMFoWDFFwx18mBVgszqunVleHl5ItccK9kqEjtsNEbobX5XSKoZbhKgd/mz3n
         kmvMcX5xbEyjrmKi+L5/5xlXgygAzAsPKhHgnLKoLrdrW/r6U8lHRpszzCep67U02FWe
         PE+KOi15QoQp9dae0p3/1+k1It5yNgry0EilehrKWjkkBgGwB2G4TqXjj3OIrFFuhV2F
         v5JmKxp9efh9Vlib6ag9oF9lWfL3YxftFtGF/sumT6ioXmQW6/ADOTqdWPPkfnBazS8W
         O/AgUale3fWyTgl3+MRs6wq7eUas4hSp5whpe7F6ZX/+qrlq569TGl/6l0r1c5Oetbcd
         AxDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HrtUUguTsc3q4s7c4LcTF1DMLDGgIvDEx3lNG8Wbexc=;
        b=ckLp6KjgK1+gyGZBaZ2mKwhXwHNomXbjJ+Gd3AJIGgbNxF6pFa9KWYx9gF4c7p5Vp3
         N+GL2uTTrzTsCKT5NRlmCEwxhkR9fAzq8EqwBgVhpr9pmTQnOrEHaDhitGn52moSpWlS
         A9QaLdj4Tar6T4ajFcIMTDh4o8hxQlGSf/4aFL4H5x7zOGi8wz+xnOFReTrXoRxUng2Z
         WvYIgzUnDFlISSSiaHAduykXc74/vtapIV0baQAKLVhiok+pqJ39GIdpCAIvXKR4uI22
         zCwke27BuBbIdOW4QojoCWhjTLwk0WRYi7FQYJP28nhVSgfGSzIdQ/JPxLqh4Mo6Uen/
         nVgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r54XDevq;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id c39-20020a05651223a700b004d57ca1c967si76002lfv.0.2023.01.26.06.51.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 06:51:48 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1199FB81DC9;
	Thu, 26 Jan 2023 14:51:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3695EC433EF;
	Thu, 26 Jan 2023 14:51:09 +0000 (UTC)
Date: Thu, 26 Jan 2023 16:50:59 +0200
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
Message-ID: <Y9KTUw/04FmBVplw@kernel.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
 <Y9JFFYjfJf9uDijE@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y9JFFYjfJf9uDijE@kernel.org>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=r54XDevq;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as
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

On Thu, Jan 26, 2023 at 11:17:09AM +0200, Mike Rapoport wrote:
> On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
> > vm_flags are among VMA attributes which affect decisions like VMA merging
> > and splitting. Therefore all vm_flags modifications are performed after
> > taking exclusive mmap_lock to prevent vm_flags updates racing with such
> > operations. Introduce modifier functions for vm_flags to be used whenever
> > flags are updated. This way we can better check and control correct
> > locking behavior during these updates.
> > 
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/mm.h       | 37 +++++++++++++++++++++++++++++++++++++
> >  include/linux/mm_types.h |  8 +++++++-
> >  2 files changed, 44 insertions(+), 1 deletion(-)
> > 
> > diff --git a/include/linux/mm.h b/include/linux/mm.h
> > index c2f62bdce134..b71f2809caac 100644
> > --- a/include/linux/mm.h
> > +++ b/include/linux/mm.h
> > @@ -627,6 +627,43 @@ static inline void vma_init(struct vm_area_struct *vma, struct mm_struct *mm)
> >  	INIT_LIST_HEAD(&vma->anon_vma_chain);
> >  }
> >  
> > +/* Use when VMA is not part of the VMA tree and needs no locking */
> > +static inline void init_vm_flags(struct vm_area_struct *vma,
> > +				 unsigned long flags)
> 
> I'd suggest to make it vm_flags_init() etc.

Thinking more about it, it will be even clearer to name these vma_flags_xyz()

> Except that
> 
> Acked-by: Mike Rapoport (IBM) <rppt@kernel.org>
> 

--
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9KTUw/04FmBVplw%40kernel.org.
