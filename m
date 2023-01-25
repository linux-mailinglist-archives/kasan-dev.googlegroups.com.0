Return-Path: <kasan-dev+bncBC7OD3FKWUERBC4DY2PAMGQEQRN72ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A7B067BAB3
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 20:22:52 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id bn10-20020a056a02030a00b004da3651ff4csf941200pgb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 11:22:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674674571; cv=pass;
        d=google.com; s=arc-20160816;
        b=gQKhbBXgbg++eghWOFPdkTxPleXKnTudNtz/h+BLnffXuCl2HFVQvCPLKC4rBnIUgs
         1tYt76nWZIiPLSn6RJ+mKYwpcHpb+m6dFZTC+fII7l/e99c13BI6bDbk3wgWqedecB3d
         GmQlUmvn1NxEGkSRCs52yPyUrlfMeDMF86gAAskFpWWZ6o5EmOM8DgbMZc5o6ZcqQFFr
         FGMFs73yhsmhpYRrKECoNFT10kGtLZTK2iZdLfyTpXueC5xS3euvHTwixUOs9p6TeCKs
         Y/qyanLoQUwpEgX/8IMArRb5edoY+/ZlxFBX3CJpjgbTwtN59sHtcRF4iCSJfcIuAlFW
         g0mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pbv6WunGmNpZGDscDsASOM41MFcj+hewl/PNNom02D4=;
        b=T3VTrvXJVlErkUsLGk1CrMJLEygql19HZGECqOI2Ul2pBuiAyqS+KPjiNQKgvvWavE
         d5bLzuCsn1PJ5yRC3U1JAUf8uOlbduswJO8Y6siPFMKCT2pmkrN6N0DAbfX909hgaJHV
         93sDQKYx318fKL0LoU3O/mjxlnVuy5AuOR4A3NVT9wMYOM2bPJLqbifYO9MWay+05LOq
         6A/S77PXg4m8cR0Ixy8aJFDFE898QmvtkiKaUVOrTYn1Z8SUPEN5YSdxR/utmHzuTKw6
         i0SQoUyulHxrkAzlWYDBcpS0na5z2M0oReoVmNhLCEDExD3GMtikWVgjlCbalvLjPx5T
         UNUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hXTUs83q;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pbv6WunGmNpZGDscDsASOM41MFcj+hewl/PNNom02D4=;
        b=fRBeD5sEiT6ncnd1xdcRmYLERV1Xdx1SRAQUfluaQKX2DyvCHtWx3VzeE9iQRZI2B7
         ONNbwJAU28n7d0wd2pBTUlyFwAzdion4oY3ufvBE5QU7l13pcfeWP+gMLspeFCoqiBgm
         d6edSFBSoUGTKlfWCtgZrRScpiM3gw4k+rPC1YuGzqbrxLdt9D13sWVQcLjJbvePFPIH
         mNmUJKQU2sul/BALYOCtOxdH+UdF5AZUvu81JoFdHQrJVKosNpGMUiuYWQlpWgbZzZP4
         4OvwPbManS6IYKP9eY9ECFiv4ejUiYmjhNHjE/OT2K2AR7c2vDqMk1MjWM4hvYMPXvPD
         y1/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pbv6WunGmNpZGDscDsASOM41MFcj+hewl/PNNom02D4=;
        b=qH289GYYzzEW455rce1jFMS9cHkhRrzUo+rInftAs25Vq7dPhZyXsbM1DzlwKTWe/W
         v2F1GcanIQpMq8vGZKWTMWwBDQOgYWVb15qJKme8xSlKFAvhFSgQuygPm3wqBUik0Q0m
         LMNcHSz5j3l/DUCsxfx6/kHy3rMmxf/cHgdT00tVyNVQdUrtONe00y6lwDQEFFwSdec0
         M8cne2xy83/xlzWHA7KfApiqIAH7LwDupxwtiNhat73HN8/XWti1Jdkdgs6meEeigh0S
         d2zDNPS/sfKvUyx0GGqrlB5tDSOfyaEh+foMMvoH+zdxOpwOetjMc3q24IAJbI03OO3N
         ueug==
X-Gm-Message-State: AO0yUKVqLq9p+lvDPfeInQbptpH/h3vIY6fJZu8unxJ8MOegH8k1cBx6
	OJhGSnHmPVZtCVuNWzfpVcs=
X-Google-Smtp-Source: AK7set9N+oHqaBm8J9rJhGQXNN1NzLENDOLd6QzOJI4YC+KB3CZokKXWAVUJU2BlEfgBAvpdq7cMiw==
X-Received: by 2002:a17:90a:4048:b0:22c:5db:d2df with SMTP id k8-20020a17090a404800b0022c05dbd2dfmr741269pjg.234.1674674571233;
        Wed, 25 Jan 2023 11:22:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecc4:b0:194:d87a:ffa6 with SMTP id
 a4-20020a170902ecc400b00194d87affa6ls18545300plh.1.-pod-prod-gmail; Wed, 25
 Jan 2023 11:22:50 -0800 (PST)
X-Received: by 2002:a17:90b:1bd2:b0:22c:81d:f6b4 with SMTP id oa18-20020a17090b1bd200b0022c081df6b4mr3416170pjb.38.1674674570487;
        Wed, 25 Jan 2023 11:22:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674674570; cv=none;
        d=google.com; s=arc-20160816;
        b=L1oKGJSWLTvr6MZIIlqsUmzbOTs5lGQUytCstN7/EzC8ZkVUjR0iBMxwgPX5zdE/P4
         8RUdXzL2pdH0auCINYbG6uU4/xCjDyRNiMLel0Ou0PWVYp+TkqrbAjwX+v86m5DVjgXg
         qe2W7MhsO0jHO4bKohBIkA36plNiKg5ylFaI6vLEXltqfuE9jUvx19YSamf4liarHjhv
         yCO+OvZqVM2WmF11zuLjitGypO3CePzsA33OAzNV40DOoriHuZe3QVgLubzvjEpLqCEQ
         IBUA+dSDKhzdUEuPjHKiYtR4nI4n3sBYSYJ8o3cv9dGitY+b3PQRsMyjEc3sxnZMdU+3
         m07w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PCnMypYs8jymH6Ufuva+9r/69Y/DZs8kYxwQEYrzQFk=;
        b=ocdhL6vHOwpTkeMm83QtgNyCaV8CJhosgy0lXlkuJZFHgZzlGBM8fW7KoGqaampPH6
         R+7LGngBdigjfqEez1Hm75NNhxuds6fbzwhIV2bBUPYRPdC/0Ir6ohMZwZsUscDgwYa9
         RnHBDTa/isr5Md0DWANR/HAtpDXfVi9UrKYGtrk5VvCA9MEPL1YdrKC6krTZL2f99RIt
         G7yLIYD0fkfoTz/gGAhsJGXQ+XB4gsL0qjkZgdWz1o3SkW0N/3M2pOJyfXGiLgZ8haj7
         PP2kQf4y2kxO+O7U7O/zcrgmDKDt8BuFYRBgskrgx/PF/Y9zVJy2AQp74KmtUl4DgIQh
         6B4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hXTUs83q;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id g2-20020a17090a9b8200b002295c9ea1a8si234737pjp.1.2023.01.25.11.22.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 11:22:50 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-4a263c4ddbaso278952497b3.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 11:22:50 -0800 (PST)
X-Received: by 2002:a0d:d456:0:b0:507:26dc:ebd with SMTP id
 w83-20020a0dd456000000b0050726dc0ebdmr298632ywd.455.1674674569763; Wed, 25
 Jan 2023 11:22:49 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-2-surenb@google.com>
 <Y9F19QEDX5d/44EV@casper.infradead.org>
In-Reply-To: <Y9F19QEDX5d/44EV@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 11:22:38 -0800
Message-ID: <CAJuCfpH+LMFX=TT04gSMA05cz_-CXMum6fobRrduWvzm1HWPmQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
To: Matthew Wilcox <willy@infradead.org>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
	mgorman@techsingularity.net, dave@stgolabs.net, liam.howlett@oracle.com, 
	peterz@infradead.org, ldufour@linux.ibm.com, paulmck@kernel.org, 
	luto@kernel.org, songliubraving@fb.com, peterx@redhat.com, david@redhat.com, 
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
	selinux@vger.kernel.org, alsa-devel@alsa-project.org, kernel-team@android.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hXTUs83q;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jan 25, 2023 at 10:33 AM Matthew Wilcox <willy@infradead.org> wrote:
>
> On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
> > +/* Use when VMA is not part of the VMA tree and needs no locking */
> > +static inline void init_vm_flags(struct vm_area_struct *vma,
> > +                              unsigned long flags)
> > +{
> > +     vma->vm_flags = flags;
>
> vm_flags are supposed to have type vm_flags_t.  That's not been
> fully realised yet, but perhaps we could avoid making it worse?
>
> >       pgprot_t vm_page_prot;
> > -     unsigned long vm_flags;         /* Flags, see mm.h. */
> > +
> > +     /*
> > +      * Flags, see mm.h.
> > +      * WARNING! Do not modify directly.
> > +      * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> > +      */
> > +     unsigned long vm_flags;
>
> Including changing this line to vm_flags_t

Good point. Will make the change. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpH%2BLMFX%3DTT04gSMA05cz_-CXMum6fobRrduWvzm1HWPmQ%40mail.gmail.com.
