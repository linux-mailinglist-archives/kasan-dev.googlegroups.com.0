Return-Path: <kasan-dev+bncBC7OD3FKWUERBXGKYWPAMGQE4GREDSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7427267B859
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 18:22:37 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-16316ec053fsf2341195fac.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:22:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674667356; cv=pass;
        d=google.com; s=arc-20160816;
        b=JSePAU2QLcfDR8jowBGFn+o6ec1n3o+W5JOeFGK1TvEQvOmB7uURxJ6r5PzNmFDKaM
         Gy95MJw+Xuo6LfZy5OQzINp+AeaffUsG8Ij93PNf738Cm8lFreVOuYGwZqJd+geInc/b
         N9wfM6OLHQAHoxozCDCmJz0voCOvf/L99BqW+6FdVJh4+NoEX/gpvmYB2F42Begt8DOG
         sfkZ1ZfoVuHqRV2/3vEfgD5oktvzL70sZUUaieyvGMp8zjC1TKuNKkgvXARaBM8+cRQQ
         AkwRI7s/OcLSuo01K9r1stR3ZG2Hgs1MeZx0vn4JhJEhojUgih4W5XE3zeQu6Xrl1cA6
         P1QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wId94lqcfH3+H/aV+z+q3WYn1xqwdAhgEmHX6sA2Ui8=;
        b=jhbxl3zHkid/kJ6tqzniJdvFoGtPyDzZk9wHOvk0sYl4KQFaLygGdpNCbFnVNF36R+
         wGUKsHxPnvmSwxTW4yOI7b6wjlZAv/w1rMItWUQ6cO9l8+9h2GYZWRgwqshP0DDrsSoX
         IGPVHhT5Dx376pMzuXWMepnCHwafQLNFNFxU4W6vGR4tzXZDLJh4hoXmJKxKyIUTunWm
         EBHbkxN5A7scyaIxp6xlBfil22pvPiNvoojWE4CPpVKhhtff1dahV4iNh08ETpQlpwup
         VoQ6PyFpjl0782BFFKPhbYTe2jpiEGeggE5E9OMwzc55Z2nvhNqhT4EzDXHRw8gb/jVr
         7wnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QlZyecSv;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wId94lqcfH3+H/aV+z+q3WYn1xqwdAhgEmHX6sA2Ui8=;
        b=pteXKqDDkAe53zrigkvWlg3Obz0I3I+6Ah6cHz4y/4F7hErqmI2otq6x4dqvHzTUpy
         Md+of5EC/rJo0ItqFNQ78ITTR9YVSg4Kf2evNxLDJDBWc3wY5ewfiGbMGh8jl1srULoA
         3j4J8a9Z/TrcSOqmummrwLoMkSsfUDyqrClDtTDcd1w43PeQ5uzZ2hzkzq3RPPqphqNP
         NXz3nsZzjlUn9vARdGxwlAVqN+qqEsp3F1HoInIj1fQpmu9VdBMH4pHeKXO++vV38QUu
         6z2geEdzZfvytOBh8Hhc47s9rADX2lH9wCQ9zmNT1chevho8G0g+KgbdDZnQ0gwlpLQj
         fw3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=wId94lqcfH3+H/aV+z+q3WYn1xqwdAhgEmHX6sA2Ui8=;
        b=RrgHVkCm6TqsrrkxbIz8ppjlhBLII2mgZE3Nzz7ex37oWY+oSZ0xN89KBeZyMnXK/S
         6uDjaphJGMRBUgA/b3h0yKuTjBptoQ+9i+daJ10GiXG3lO9fGUMyYygE55vGNSNuWwX7
         LAwWx0OxzWDBb3yWGItbidK9CpDnw/K2v8YD7HmPqQXm7NxT4ZVvEXQMC5EWPhqILLBR
         NZ5hNA/4uzWmr0XXZsqc4NNntQBX+vF+1bUeUHyhdSzM8F0HGuOak8yAuVLoq44nCc7M
         NJ9Z3Ol5srkSmxt8jWspIYVUWOaZ/KYp8IRZFra30+AwWV6D9vp2sSjsWXflKnV4U18U
         v1qQ==
X-Gm-Message-State: AFqh2kptnJNBNe9Ez+yOZs0jSAxh84GeeWzYKsLIp4cL5Ph1ULlD1VAa
	UgtPqzen5O4PTW/zWTmgwmg=
X-Google-Smtp-Source: AMrXdXtP6t5Ol6tvB31h/brlheYiatJR56i2IgWwHVmii78geRQRpX20YMDomL//byZvijk65r3Epg==
X-Received: by 2002:a54:4785:0:b0:368:11f1:9eda with SMTP id o5-20020a544785000000b0036811f19edamr1681659oic.220.1674667356210;
        Wed, 25 Jan 2023 09:22:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:661c:b0:66e:aed3:654a with SMTP id
 cp28-20020a056830661c00b0066eaed3654als3805005otb.4.-pod-prod-gmail; Wed, 25
 Jan 2023 09:22:35 -0800 (PST)
X-Received: by 2002:a9d:371:0:b0:684:9ffa:bdbc with SMTP id 104-20020a9d0371000000b006849ffabdbcmr14614105otv.29.1674667355847;
        Wed, 25 Jan 2023 09:22:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674667355; cv=none;
        d=google.com; s=arc-20160816;
        b=H+zxYgclcl37AIYZVuqAOom4FnrCfl7lsszjtT90HE2FeaRvzAWPV2rEfbqESgBG1s
         m5w6Q9kD4k1wGFcZvvUqts5/PHGJtdD430CjJBPwt/sRnxWOIUZyhhDC9NieZCVO9+60
         wkPTqL90uMw2/Lz6l3eIhwfQ5AHV19BpFhAmj8mC856Wei18qHakryU4kuAApWDg072c
         +YqujjF7Pfu9wmEOP91GFirUspP3sBfalsOEznb63WWSug7VG4cdnf+/EV82H0HsttjO
         lDiv5diw4Xg7LUg87B6V/lczkeNDWeHWKJwz7p0ofWgsz5IVzbSuolKmBApzxCrExOGo
         jnuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IqJXv+IInDU1mKTOWecSjx46uIp9RhIiEah7PjvPLrg=;
        b=bnnu+mWSBBeXfPGcwwFCpVIBc38FmZMWdl54CrptvsOBdOjrKNKWbjgYZjEmFBEzE4
         mDHXn2tgKoKPCqBQF0N2/gPFuyozCpz10n1gGFvBm60m8n8ZTaB2baTPIkPaeLvmlCZw
         1mVm1oJuqhRFm8YgqG7VjAP9FNo/Yg5I/DcxlR2g/o9qZvTmd9DFVRO+/msqq6wy3TC0
         laJBNTP6a7D/338TD9qcmby5MvhLiUFFd/l26s2EWWnPaVtxXXz5TDhwsl8YpuOmwexm
         ePXBLzrtuZWjwc+CHXgPzVm7BzRZHR0OnubUVWBXeU3/l5hSfqFa9oHt1jELKu3IefQe
         Skmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QlZyecSv;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id ci10-20020a05683063ca00b00686566f6f48si1035689otb.0.2023.01.25.09.22.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 09:22:35 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id 188so23883589ybi.9
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 09:22:35 -0800 (PST)
X-Received: by 2002:a25:a408:0:b0:800:28d4:6936 with SMTP id
 f8-20020a25a408000000b0080028d46936mr2303639ybi.431.1674667354997; Wed, 25
 Jan 2023 09:22:34 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-5-surenb@google.com>
 <Y9D4rWEsajV/WfNx@dhcp22.suse.cz> <CAJuCfpGd2eG0RSMte9OVgsRVWPo+Sj7+t8EOo8o_iKzZoh1MXA@mail.gmail.com>
 <Y9Fh9joU3vTCwYbX@dhcp22.suse.cz>
In-Reply-To: <Y9Fh9joU3vTCwYbX@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 09:22:23 -0800
Message-ID: <CAJuCfpEJ1U2UHBNhLx4gggN3PLZKP5RejiZL_U5ZLxU_wdviVg@mail.gmail.com>
Subject: Re: [PATCH v2 4/6] mm: replace vma->vm_flags indirect modification in ksm_madvise
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@techsingularity.net, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
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
 header.i=@google.com header.s=20210112 header.b=QlZyecSv;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as
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

On Wed, Jan 25, 2023 at 9:08 AM Michal Hocko <mhocko@suse.com> wrote:
>
> On Wed 25-01-23 08:57:48, Suren Baghdasaryan wrote:
> > On Wed, Jan 25, 2023 at 1:38 AM 'Michal Hocko' via kernel-team
> > <kernel-team@android.com> wrote:
> > >
> > > On Wed 25-01-23 00:38:49, Suren Baghdasaryan wrote:
> > > > Replace indirect modifications to vma->vm_flags with calls to modifier
> > > > functions to be able to track flag changes and to keep vma locking
> > > > correctness. Add a BUG_ON check in ksm_madvise() to catch indirect
> > > > vm_flags modification attempts.
> > >
> > > Those BUG_ONs scream to much IMHO. KSM is an MM internal code so I
> > > gueess we should be willing to trust it.
> >
> > Yes, but I really want to prevent an indirect misuse since it was not
> > easy to find these. If you feel strongly about it I will remove them
> > or if you have a better suggestion I'm all for it.
>
> You can avoid that by making flags inaccesible directly, right?

Ah, you mean Peter's suggestion of using __private? I guess that would
cover it. I'll drop these BUG_ONs in the next version. Thanks!

>
> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpEJ1U2UHBNhLx4gggN3PLZKP5RejiZL_U5ZLxU_wdviVg%40mail.gmail.com.
