Return-Path: <kasan-dev+bncBC7OD3FKWUERB3GSZKPAMGQEUSUJRII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B075A67D14C
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 17:25:17 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id bg13-20020a056808178d00b00364af0a66f9sf849831oib.14
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 08:25:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674750316; cv=pass;
        d=google.com; s=arc-20160816;
        b=C7vNe4YBvLKrf06qLprtyDav65wsgLRiSz5X5DmuYMXX9ZiTXW2zEffzLcwJ+4IkJg
         rGSpznjGz9W1DED2wXATuvZvCSKrqU4n1xzTl2GJzOpb9xMYzRh2URdqwOQHb8uUpckS
         nC92EwkEBsVDBzzYv9QESUEwrqOpK+aERyOl2ieQI6sFI0iqWKecAPsXWry/Obg4/qCZ
         mKvh1ryqtNlHCkbDtTE4xVMwocvxV8vh901tB1D8kdIBiG9+NjVENcah3xgEro7rcey+
         QUu1vLa7TuhuIcERC3SEapzBC9PEUx4e42oJTb1F1xzxYsz1DLhI9PmWgjx/Na1fHNoo
         KRCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6LOkYBru9xgO9rLsnjkU3qfDryUgYGhHMBJIGf+S3kw=;
        b=rVphKm0ydYmxoUtl99ZjEZWRwwSp+1m/v26/+pubQXt8XeSJ3Il6OugS/Qi/O/u/pT
         TRtZKOD0+Z7Mm50lkC3SeilIQahUx/iwKBUXq/iIjm5N28eX1wUVCuPfLRBUvdbCnwX6
         EwALQTHu1Me8taEdWnzE8suPc9gfOrrVF+CscWFpSn8x0n7BUVZnQ4CVrpUyJ896N0Tp
         YcM+u3+wDfCA3IpAibSxC6mq//psc9L5bnUXMqpayoAhXBjLiWSdf06y4R+olWy8YUfF
         wK64qdKWeln3sfPa3VZx0PBxS0IRaB8mFhie0P1Xrl66h3fNG0Y7RJGibvxo1f8fXTXa
         vfAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BrNExWGH;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6LOkYBru9xgO9rLsnjkU3qfDryUgYGhHMBJIGf+S3kw=;
        b=Aoy330aRdB0PDRChcer7mOZ1jqDSgxZoXrQhYJ4XlVRtKLLZVMEcvN0wduUnOl4dMY
         i6VYwNg+/BQZFG/U29YiBl+1HbXVw0kyMjK/2LLU7qFxD69QwWFrLRL2m5kjs1tq6iG3
         IQEvd1Wyf93T90RlDISeEI9305ejKTWke0YnXuJJPVjYKl8l34MF5rHv6z3sufEtUISf
         0daawta03mzde8wsIlRuz8hv5Fvfs9qIGGvgEdVlY73Q+2vXscPGMU5iDGLtfCctLjT9
         McoW36mzfARXkaOEAKZ2OHkCf1OxT7lW5DVYXQfvSsjWYU1h7cNLo30QJW4Ii638y8aN
         xtUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=6LOkYBru9xgO9rLsnjkU3qfDryUgYGhHMBJIGf+S3kw=;
        b=c4pcPR6k1+oWlRVddG1vqS5K4NZeke/7b46TuTCaMsU52gqyDopl+oKzm4lv7zOYok
         FxLOZbMvT7txKDDLIyK1KKJjpmUNnVxtD8dUt3P7mJauYyvg3Ot8YvUXdgUuPZauXt6R
         GV+/OsKMLrbmQDK+ZQqfXe0hzPX1qqi+rL/1LT+SQF/w2ApJWJzm/u/WEcrJaRiNUeVW
         1oQF0wVxfGKqT6EyyRia2Kmzs+C3+KoEs7u5hRuhQ4YfSsTJuPiSszOt/KA3W8nScE0F
         CYEWvp4ctxd2BseIgixm8HOU0nnKrolxFzMPX8XdYv3eZQih2tfCwNcAbye9XHtR4VDH
         ICug==
X-Gm-Message-State: AFqh2kpi6Z9m59AZ5iO4XizJCGSAGwNMYNXdiK//cNnXt+orStqF1x0q
	y70jIKEKKemWdI6rtm6adVc=
X-Google-Smtp-Source: AMrXdXuYbP/fmt+PkVi8ejqM0MuDzcnlY2d2nl9zZ9y6wNTesliqzH6vY6zFBAbAZclbi6w1YBlcdQ==
X-Received: by 2002:a05:6808:8c:b0:363:b19e:1138 with SMTP id s12-20020a056808008c00b00363b19e1138mr1867781oic.7.1674750316257;
        Thu, 26 Jan 2023 08:25:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:e82:b0:66d:a9f3:4e75 with SMTP id
 dp2-20020a0568300e8200b0066da9f34e75ls365596otb.9.-pod-prod-gmail; Thu, 26
 Jan 2023 08:25:15 -0800 (PST)
X-Received: by 2002:a05:6830:1e5b:b0:684:d7f8:dc46 with SMTP id e27-20020a0568301e5b00b00684d7f8dc46mr18443686otj.20.1674750315760;
        Thu, 26 Jan 2023 08:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674750315; cv=none;
        d=google.com; s=arc-20160816;
        b=ScyaK1Y2PpkkologNzAFGZqisvX/xHhcHTU5sxrQDhR1Pq0Kp80y+Pd9IKZS8CS4Wy
         /v7JOLpdk6V1CEVDZy+/k3iyLPWmSwud5e0jHf/pej3JLoHcRZ+GYrkOi9O602ZOGi5l
         MdAxRkaqgMl5tLNcBDRsUUlir829dRkKwUYlWdyAD/5zfnlNYL90GCit+RENPxyVXhqB
         bUuswm2+NwQ5yDn0uPq5GkRgdAp2vxPGUl/TAugL0bxoGVsuNPp33zmavWXQhj5zGUW5
         O637maWo9MWyaXGcZ42C9vyCqCCYhJGpYZtYhZL7AqWPzmAXrn3j5WJUwsPWUSVQ+zqF
         gixQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rUFKXit/Slxp5jNkRtm2qJfbudUdkwg/5ym9L9/2xFg=;
        b=dt5RKe6B+/CFK3nrCu5kyXZekA2FwaySEjYwLfE+4BT2jFrDFpb/7LnO+p/u73y4k+
         jhGWHFIIbDdUuVpNZWbQeoppl5vRML5sul2ZBKbPwFRTufMd7lNyO5AJ4BRcAghSR6Ca
         p2XzyrdnvAJ/OVfWc6hGQxav9vy/f8vk4bPC6/yDYD7bC2o/AnoXky24//qiEJf4nbzV
         B2Ckxfl7VKPL40e5laIqAppq1F8VgDwf4w2Ct40Ml75Q8Gp1Ldriy5F9ZNqZCHb7661f
         0nWNwzdljONLZzwzpDkrOb92+nnnjHcz7ZtIBGAxCBbZipg1Bdt7JUuh2lNEiXC9V/5P
         175A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BrNExWGH;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id bk6-20020a056830368600b0067054a075b7si245185otb.2.2023.01.26.08.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jan 2023 08:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-4b718cab0e4so29942647b3.9
        for <kasan-dev@googlegroups.com>; Thu, 26 Jan 2023 08:25:15 -0800 (PST)
X-Received: by 2002:a81:1b8b:0:b0:4ff:774b:7ffb with SMTP id
 b133-20020a811b8b000000b004ff774b7ffbmr3541685ywb.218.1674750315051; Thu, 26
 Jan 2023 08:25:15 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-2-surenb@google.com>
 <Y9JFFYjfJf9uDijE@kernel.org> <Y9KTUw/04FmBVplw@kernel.org> <Y9KXjLaFFUvqqdd4@casper.infradead.org>
In-Reply-To: <Y9KXjLaFFUvqqdd4@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Jan 2023 08:25:03 -0800
Message-ID: <CAJuCfpHs4wvQpitiAYc+PQX3LnitF=wvm=zVX7CzMozzmnbcnw@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
To: Matthew Wilcox <willy@infradead.org>
Cc: Mike Rapoport <rppt@kernel.org>, akpm@linux-foundation.org, michel@lespinasse.org, 
	jglisse@google.com, mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
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
 header.i=@google.com header.s=20210112 header.b=BrNExWGH;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1131
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

On Thu, Jan 26, 2023 at 7:09 AM Matthew Wilcox <willy@infradead.org> wrote:
>
> On Thu, Jan 26, 2023 at 04:50:59PM +0200, Mike Rapoport wrote:
> > On Thu, Jan 26, 2023 at 11:17:09AM +0200, Mike Rapoport wrote:
> > > On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
> > > > +/* Use when VMA is not part of the VMA tree and needs no locking */
> > > > +static inline void init_vm_flags(struct vm_area_struct *vma,
> > > > +                          unsigned long flags)
> > >
> > > I'd suggest to make it vm_flags_init() etc.
> >
> > Thinking more about it, it will be even clearer to name these vma_flags_xyz()
>
> Perhaps vma_VERB_flags()?
>
> vma_init_flags()
> vma_reset_flags()
> vma_set_flags()
> vma_clear_flags()
> vma_mod_flags()

Due to excessive email bouncing I posted the v3 of this patchset using
the original per-VMA patchset's distribution list. That might have
dropped Mike from the list. Sorry about that Mike, I'll add you to my
usual list of suspects :)
The v3 is here:
https://lore.kernel.org/all/20230125233554.153109-1-surenb@google.com/
and Andrew did suggest the same renames, so I'll be posting v4 with
those changes later today.
Thanks for the feedback!

>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHs4wvQpitiAYc%2BPQX3LnitF%3Dwvm%3DzVX7CzMozzmnbcnw%40mail.gmail.com.
