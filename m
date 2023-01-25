Return-Path: <kasan-dev+bncBC7OD3FKWUERBYECY2PAMGQES7L3ZZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4690267BA94
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 20:22:10 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id g4-20020ab01304000000b0060d5bfd73b5sf5917768uae.16
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 11:22:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674674529; cv=pass;
        d=google.com; s=arc-20160816;
        b=HDMXoADPjnTxpuX5jfE/QthdTYUAVVUc94jbkfG+kJi02rTrUeFBqZI7yiDVywN0Ah
         jUMYpJQ7iLBHiIq0Vp84T2I3de23IX2umUfRyAYu/jfYctfrzmCvV+8xkarUAa3HOyV+
         ZRBTuGjqtzfRefpOabcDyyc7Z8en0Jf1Fh8VMElerQ3xoHIOyr/XZ1eGlGH3ktlKqAZj
         Cf/jUz7YSqHIQMiQI85WFsiWBHckQgSSlRyTs4P5uajzLWR6xaCETX4B9hN+bwulyP4C
         oxn9Vj0I4UJ5rfKwNNbm/QZsF6pmLYB/KP5nkd0Gbhf1KB3XlHGuAT/JxpvSXMBbzQGM
         CqDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FrjsUYuty4fyr8FXJUthLL9QiW0H3NestOSRJB9CSuQ=;
        b=1Kw1xmejSgq/jO3gcNm0YM+NLeAzZVeXazamo0GOzLIhtaht+OSnrhhEMmRW+B1sQY
         oTWJpn34BYLERli2dQdaNb50sNCVaDBdB+rckOWTSLYuKn7dO7XopakWQpch4pGtCCy6
         40ZUTQ0jt3EKppH4/RXOED4xT13G20XgUOqHJDPSw1DogCi8KmXVolwcoxx221ZbYvWA
         tHI/6R3YMIZeca382IiIHKuUeHggOltMv5WNXXWQjYEXtwnxwguPT5iSoNM9oQQwcypv
         PzDIg2p8YcHKVyuIDOS/v6UTC0R6jNb9vE1kxYWIj3phdoUhOnOYB/wYBs+pVbQlgdBW
         ZsrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=idbJO946;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FrjsUYuty4fyr8FXJUthLL9QiW0H3NestOSRJB9CSuQ=;
        b=p2o2Hkv4Ax9XSWO4dppKAuPu2xVUmq+du0E3AefR33bWJoNak0Fmf8ALhX9T/4OzWC
         +wFs50ZURYh0+kR3Zu0s+Bh1JFnG+0srfy2iwd2TZlPc85Zuef/Dp1DbWap8d5wTLRGM
         0phDMglRQRT1nxU7nRvYY87QWrkisi4ndiHVCtB/hFn5h54g3MFCiBMsdh3OoVsg5yqE
         vqSWnbtRguGgIpxH6iL0UUJgUdPPUxk/Ehi3/wus/fVz+eUjbuispkIL7/7vbd7rejBm
         eyd8AbC0uYbnoJrem7R+vx0pK65CGH35aZ+yP1Dn5vABaP4A9TBWCLPZ+LmluH0a4a1A
         fqsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=FrjsUYuty4fyr8FXJUthLL9QiW0H3NestOSRJB9CSuQ=;
        b=pyR3Syl3l2tGUMZLaA1VgzunMBwtrFlroLxikLCO4sOPqfIXATDgQxIW3hl6tW4rxx
         3b0N+tXlhPKdzIAT3AWAAd/HQ3+2I5JIVdc0tN/is98osmvL1vMu0KtjADEUr3wq5X+M
         i8clF1x328Q7LEFhX04sVVNFZ+x6DD48QtKiuYP7dCOAMTKhodJ6+MvXw77ytMzU/NLQ
         tzVZL8L7Hj+ydG0y7WjK4KY84cTpA9UgjpKuvzqNDob1Ty0DVoFPlZZ5WAxhRbZEfyTB
         fkWDbN1NMYpZnkq4SE8ZA5QJRCVoVJ0IwCf4wGCBDpnf8rINcOBqtewFygpW6cMuDs4w
         dlbQ==
X-Gm-Message-State: AFqh2kpKHkFW2CifDsqXhHRjpX+i+PY82/HW0Z6P/KHpxVd1xYk0qs2g
	NyH332n8xdRxMEh56CUVXc0=
X-Google-Smtp-Source: AMrXdXuPT/b2oc1TUQKxewOANj5VI9945doJDY5xbVG9E312cJZQWPie1kS7FaD6Cr6aO1UdS+45kw==
X-Received: by 2002:a05:6102:370f:b0:3ce:dcbc:23a5 with SMTP id s15-20020a056102370f00b003cedcbc23a5mr4723927vst.71.1674674528958;
        Wed, 25 Jan 2023 11:22:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9801:0:b0:3d8:d251:63a5 with SMTP id a1-20020a1f9801000000b003d8d25163a5ls3528271vke.4.-pod-prod-gmail;
 Wed, 25 Jan 2023 11:22:08 -0800 (PST)
X-Received: by 2002:a1f:19c1:0:b0:3d5:91ea:4d0a with SMTP id 184-20020a1f19c1000000b003d591ea4d0amr31789793vkz.8.1674674528217;
        Wed, 25 Jan 2023 11:22:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674674528; cv=none;
        d=google.com; s=arc-20160816;
        b=zTxJrSxYo2c7ODyRRJbUJSXJv9wDdmYxULUpY+PJEtTLDxZSQ0J6x6lQMmHEGLxWkX
         rgZZfu7fjvrqkGBfHdaWCTNkbKtOaYXZSw6Kly1Ev53OFE/7Qt08Cy6lkLbosge6QUaZ
         FYSt7a2XSf/M0QPP6OHJJdDUweT4jHiCEijxhi6BcGBOO9hmwDoftc0qgKAQIyY7L4p7
         3oa8xoct+MlFLHDGKOvQ4e9MZfEgamseHJzrQmkpVoMVxRvp28s/naAhVuqXL66P0Pkf
         Mti8VJxnmGkrymwA1X/dJknqTFxpfvPmmmvOt1khBpT4BMhAk91LaiZK7BG8DgRZTOmj
         JRhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=azRxZ4iz/UmvW0JqPrqtZcKNmaFt9MhDUKzgc4KSKbs=;
        b=KJm3FlDdoG3Y/XmghIJGbeh92C6GfZL5X+ZbnB9eKPfoovl2jyLdMs7IxQE0HsUJnb
         qdQQxwgPXu3LPYqT03uXsTUYqF/KLxBqLPhq2k+t1eTV2Odx8DQhdNhzHfp3BR3ated8
         Gx4g9V+flH1i89cYliIagPkiIIasK8ik1cPxesYC7dvwXpeYhig5z7FglH0LBVvo3eMY
         0E5tE9TaF02VXK1d8ECIPKlg8z1CM2ZuGePWoywyubwblL8ibf452fYbJtzazCXRSGe0
         BOLvg+vNNM0tgCyWCdlj6khnEAgFUuNVT/Ww3EsAuTOdh+91snsXVl1P3sGV4mXCQPBY
         lGmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=idbJO946;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id d28-20020ac5c55c000000b003d53e3ed270si562932vkl.0.2023.01.25.11.22.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 11:22:08 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 123so24339633ybv.6
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 11:22:08 -0800 (PST)
X-Received: by 2002:a25:c247:0:b0:80b:6201:bee7 with SMTP id
 s68-20020a25c247000000b0080b6201bee7mr946541ybf.340.1674674527537; Wed, 25
 Jan 2023 11:22:07 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-2-surenb@google.com>
 <Y9Dx0cPXF2yoLwww@hirez.programming.kicks-ass.net> <CAJuCfpEcVCZaCGzc-Wim25eaV5e6YG1YJAAdKwZ6JHViB0z8aw@mail.gmail.com>
 <Y9F28J9njAtwifuL@casper.infradead.org>
In-Reply-To: <Y9F28J9njAtwifuL@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 11:21:56 -0800
Message-ID: <CAJuCfpHO7g-5GZep0e7r=dFTBhVHpN3R_pHMGOqetgrKyYzMFQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] mm: introduce vma->vm_flags modifier functions
To: Matthew Wilcox <willy@infradead.org>
Cc: Peter Zijlstra <peterz@infradead.org>, akpm@linux-foundation.org, michel@lespinasse.org, 
	jglisse@google.com, mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
	mgorman@techsingularity.net, dave@stgolabs.net, liam.howlett@oracle.com, 
	ldufour@linux.ibm.com, paulmck@kernel.org, luto@kernel.org, 
	songliubraving@fb.com, peterx@redhat.com, david@redhat.com, 
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
 header.i=@google.com header.s=20210112 header.b=idbJO946;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jan 25, 2023 at 10:37 AM Matthew Wilcox <willy@infradead.org> wrote:
>
> On Wed, Jan 25, 2023 at 08:49:50AM -0800, Suren Baghdasaryan wrote:
> > On Wed, Jan 25, 2023 at 1:10 AM Peter Zijlstra <peterz@infradead.org> wrote:
> > > > +     /*
> > > > +      * Flags, see mm.h.
> > > > +      * WARNING! Do not modify directly.
> > > > +      * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> > > > +      */
> > > > +     unsigned long vm_flags;
> > >
> > > We have __private and ACCESS_PRIVATE() to help with enforcing this.
> >
> > Thanks for pointing this out, Peter! I guess for that I'll need to
> > convert all read accesses and provide get_vm_flags() too? That will
> > cause some additional churt (a quick search shows 801 hits over 248
> > files) but maybe it's worth it? I think Michal suggested that too in
> > another patch. Should I do that while we are at it?
>
> Here's a trick I saw somewhere in the VFS:
>
>         union {
>                 const vm_flags_t vm_flags;
>                 vm_flags_t __private __vm_flags;
>         };
>
> Now it can be read by anybody but written only by those using
> ACCESS_PRIVATE.

Huh, this is quite nice! I think it does not save us from the cases
when vma->vm_flags is passed by a reference and modified indirectly,
like in ksm_madvise()? Though maybe such usecases are so rare (I found
only 2 cases) that we can ignore this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHO7g-5GZep0e7r%3DdFTBhVHpN3R_pHMGOqetgrKyYzMFQ%40mail.gmail.com.
