Return-Path: <kasan-dev+bncBC7OD3FKWUERBHWAYWPAMGQEGQRIVYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BE6067B7AD
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 18:00:16 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id v12-20020a9d4e8c000000b0068653f5e950sf9357593otk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:00:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674666015; cv=pass;
        d=google.com; s=arc-20160816;
        b=kwb+h0HHncr5MgLrJpyarbSUE/YklJoZXVqLCSso/BKcnianVN7reU8cBkQvtAM4jf
         wMnVVl7jAc9eo3oFM2aS7tlp+9kI0gnXhfbQ6mN1n17wB/Mi23wReBGmxlEE/mM3EsG6
         A99OGynlhP1nnUWV/JsMB4BhFdOQMpAuZOaBGbG0eVAFXoPhxba/qGOiYEB9x4liIKn1
         6UVgAQJuHwauJ2CZEyQCWiz6/NiWZRIeBOaiztJoFxhE8I7nqrkSZT6uiCq+rD89k5ve
         Vj57wf7fGVJxK9p2ttv0OhL71DEF4YMQCqbaLRx5L8u6LDw9It08SSgl4GONWZbhKKiu
         US3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J+Py0TUNSIthX5hMF1DqT4V4ZIxKbHKJnaOIc4UBQLM=;
        b=d0P5zA1WWgXid+pb7bbSlk7gKx/LZp7mgT++LxxN1OINVOj1yUVYpoQlaCDS5AALgq
         KaffVqlRYEZWRLiPyviBNywrgvLNRTJ65KEgrmjS1lPEnV/MrzOjLYuC327AXI2FcYTy
         9pr5ibPKKtMzh8LtCC/0PGklsl58loXuWOoH4eJRJ0f7eVPzoca00WbEihZ71x6iwW4B
         BNeybWOxmkP8zs//nPoTAz8EYDlfOG4EudiJXQTlw7v3OS4Vp7Ur2zVE4cY+zO+SkR3G
         OvjnotzgFmaU/m051J9sz0aRUp4zqvCiTYBoGqV+7UTfRacke+LAtGl/2ahJVfxMmKL4
         GgGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W2wM+2B2;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J+Py0TUNSIthX5hMF1DqT4V4ZIxKbHKJnaOIc4UBQLM=;
        b=oo+LuzxZtRM7kLYvzIUHUrAepNYk2UmbWnh9kANFBzMNBG4zfUKiuoFyzFcv6oC2R0
         IcGyF0in+GYTgH8Yeu02LXNM8ifAM+wHil2tp0Nu1zmcsns8d6JfxWaY2OHooeUtuJZb
         3vU8q1GWK9wHRTUkjV43K0uInmLRk2dHUaCjP1JRPkQoEBQ0Pr6J5sUhgT9CyAR0vBBz
         bJpj8yQUfE7exU577ntkdKdWFuxkwXFjhh+NA+VH9AfPo7mwAXffz6mvUiemzhmlhwjG
         yX+7OUJniDS8v5w29ZPBx6slVPXSejQmPKVD+WfLpVfoDqmrRI3lRMLTl8PLT5HIrt2a
         zKaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=J+Py0TUNSIthX5hMF1DqT4V4ZIxKbHKJnaOIc4UBQLM=;
        b=0a4CAa/e1H0bQC1r22eMCcXMLIwpNp0UvIQIyeJJUuuScTt0nBPIk+kAhjJmZGHkt1
         pSG1cLhX1IOu0uWI7ohHJPuAXRoQRVlD22F/vPLuq7ZHAqn+MHzptRbe5QSvDx7WdSkd
         WcnkH1laOQA5K+k2mOJqOfEdbNzf4LjuwGKl9gw9fTGLLl5NesRwFUxHqlAqqsx8Vn1o
         g3rd0jr0Jvve1qiiCxVcSfIk2Euy/ALmi8k9fIrXZ9rYrpZJzkGX1+cr9yMLXYGtsSJO
         l+LVlfx3zaR9HsaH0N1BGzT62mLQRfmFXCZAxe/E1INaP4qEFbFcb/M4C7Jrr4mL/4w3
         xGVw==
X-Gm-Message-State: AFqh2kqE4hBtlbJM90h8jGTL3DrQ/6GB7jvwPViHhwvyQ2S4aRTVZCb1
	GhMP9Y0U/oqzbvLMqcprst0=
X-Google-Smtp-Source: AMrXdXvqA89CYfdNt5/Gw1VAlwCZ+oU93y7bYBvQ4XRnk6y8H9bV7rwPka7g16izZks5n1wOHS0tjA==
X-Received: by 2002:a05:6870:c0c7:b0:15f:5131:3727 with SMTP id e7-20020a056870c0c700b0015f51313727mr2395372oad.223.1674666014742;
        Wed, 25 Jan 2023 09:00:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7dd8:0:b0:670:6b50:739d with SMTP id k24-20020a9d7dd8000000b006706b50739dls3789558otn.6.-pod-prod-gmail;
 Wed, 25 Jan 2023 09:00:14 -0800 (PST)
X-Received: by 2002:a9d:1b6c:0:b0:66c:4d30:b69f with SMTP id l99-20020a9d1b6c000000b0066c4d30b69fmr15799576otl.24.1674666014140;
        Wed, 25 Jan 2023 09:00:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674666014; cv=none;
        d=google.com; s=arc-20160816;
        b=ylv4DSPDJLN+3kFb0rSIeSIDpsa3csnQYTj6viZQwQb0tWBVb295/6bvsxZCuEE7pb
         +2DTTh2gnFBfKgdwXSVsW6Cwk5JyGo72BS17bj9z8diOZmvJtq5X61wbxcCuOdBUi9B9
         J1tkGXMBJ8+Q/i4OLciUs/vbqvsvl6kuJYPUtzhYXV/DWZouP58tWaRcH+avaMSjIgEd
         8+5eNcU6fOfthC7HzhnKv16lv/WUflYzHTLCq9kcUjGRI1kumuEFBIg+qh2gswM/jgeA
         6kpSxjVaQ/ZGwD/JscB3+Qrdapqrg6pqKyG260MrpPWnNBvqF6SQGdI+7H+NBi6C6U0q
         T5gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L4MXGiF0uBNS4YdEO04YxfSu/PH3d6GEYxinGGkJ0l0=;
        b=kBgeQ09KLTkm81LSNTiT1wo3PGi67RnouYz1Q3Uffvx5gszFHki3VZduqFgsTFTESy
         02IU30Lycs1dB/p84S5lo4fQSwpetdNVBG2cYKDW0eiuypo8SUN8PvGxjOJOnDK04X3z
         N4FmSkBCbUvHIr6vVYDRPxgGE6gk2AqC8sZmDS3F+s+0G8jpV3mzmIN/oNvY+6g2U7S0
         uEq8/uw1MABQ7Acep5RtYRX/eaEIaEnyfSLlj5iA+BF8326Y9Js//v4MfzZrWvlvbFzb
         EbLo+P+TmN2lqIdsrMDkAaxMnbyfLBJcUCp7RHS0stAVNlGb165HUS6teVCyevlWiyBE
         viIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W2wM+2B2;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id cy23-20020a056830699700b0067054a075b7si1101432otb.2.2023.01.25.09.00.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 09:00:14 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-4a263c4ddbaso273142387b3.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 09:00:14 -0800 (PST)
X-Received: by 2002:a0d:c0c7:0:b0:502:30d7:5fff with SMTP id
 b190-20020a0dc0c7000000b0050230d75fffmr2052050ywd.347.1674666013171; Wed, 25
 Jan 2023 09:00:13 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-6-surenb@google.com>
 <Y9D5hjcprLI92VKf@dhcp22.suse.cz>
In-Reply-To: <Y9D5hjcprLI92VKf@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 09:00:00 -0800
Message-ID: <CAJuCfpHHPB=VE7Q=hoxVj7GBF18rpSQ-O-5+S3EPxOB5rHOrDg@mail.gmail.com>
Subject: Re: [PATCH v2 5/6] mm: introduce mod_vm_flags_nolock and use it in untrack_pfn
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
 header.i=@google.com header.s=20210112 header.b=W2wM+2B2;       spf=pass
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

On Wed, Jan 25, 2023 at 1:42 AM Michal Hocko <mhocko@suse.com> wrote:
>
> On Wed 25-01-23 00:38:50, Suren Baghdasaryan wrote:
> > In cases when VMA flags are modified after VMA was isolated and mmap_lock
> > was downgraded, flags modifications would result in an assertion because
> > mmap write lock is not held.
> > Introduce mod_vm_flags_nolock to be used in such situation.
> > Pass a hint to untrack_pfn to conditionally use mod_vm_flags_nolock for
> > flags modification and to avoid assertion.
>
> The changelog nor the documentation of mod_vm_flags_nolock
> really explain when it is safe to use it. This is really important for
> future potential users.

True. I'll add clarification in the comments and in the changelog. Thanks!

>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  arch/x86/mm/pat/memtype.c | 10 +++++++---
> >  include/linux/mm.h        | 12 +++++++++---
> >  include/linux/pgtable.h   |  5 +++--
> >  mm/memory.c               | 13 +++++++------
> >  mm/memremap.c             |  4 ++--
> >  mm/mmap.c                 | 16 ++++++++++------
> >  6 files changed, 38 insertions(+), 22 deletions(-)
> >
> > diff --git a/arch/x86/mm/pat/memtype.c b/arch/x86/mm/pat/memtype.c
> > index ae9645c900fa..d8adc0b42cf2 100644
> > --- a/arch/x86/mm/pat/memtype.c
> > +++ b/arch/x86/mm/pat/memtype.c
> > @@ -1046,7 +1046,7 @@ void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot, pfn_t pfn)
> >   * can be for the entire vma (in which case pfn, size are zero).
> >   */
> >  void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
> > -              unsigned long size)
> > +              unsigned long size, bool mm_wr_locked)
> >  {
> >       resource_size_t paddr;
> >       unsigned long prot;
> > @@ -1065,8 +1065,12 @@ void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
> >               size = vma->vm_end - vma->vm_start;
> >       }
> >       free_pfn_range(paddr, size);
> > -     if (vma)
> > -             clear_vm_flags(vma, VM_PAT);
> > +     if (vma) {
> > +             if (mm_wr_locked)
> > +                     clear_vm_flags(vma, VM_PAT);
> > +             else
> > +                     mod_vm_flags_nolock(vma, 0, VM_PAT);
> > +     }
> >  }
> >
> >  /*
> > diff --git a/include/linux/mm.h b/include/linux/mm.h
> > index 55335edd1373..48d49930c411 100644
> > --- a/include/linux/mm.h
> > +++ b/include/linux/mm.h
> > @@ -656,12 +656,18 @@ static inline void clear_vm_flags(struct vm_area_struct *vma,
> >       vma->vm_flags &= ~flags;
> >  }
> >
> > +static inline void mod_vm_flags_nolock(struct vm_area_struct *vma,
> > +                                    unsigned long set, unsigned long clear)
> > +{
> > +     vma->vm_flags |= set;
> > +     vma->vm_flags &= ~clear;
> > +}
> > +
> >  static inline void mod_vm_flags(struct vm_area_struct *vma,
> >                               unsigned long set, unsigned long clear)
> >  {
> >       mmap_assert_write_locked(vma->vm_mm);
> > -     vma->vm_flags |= set;
> > -     vma->vm_flags &= ~clear;
> > +     mod_vm_flags_nolock(vma, set, clear);
> >  }
> >
> >  static inline void vma_set_anonymous(struct vm_area_struct *vma)
> > @@ -2087,7 +2093,7 @@ static inline void zap_vma_pages(struct vm_area_struct *vma)
> >  }
> >  void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
> >               struct vm_area_struct *start_vma, unsigned long start,
> > -             unsigned long end);
> > +             unsigned long end, bool mm_wr_locked);
> >
> >  struct mmu_notifier_range;
> >
> > diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> > index 5fd45454c073..c63cd44777ec 100644
> > --- a/include/linux/pgtable.h
> > +++ b/include/linux/pgtable.h
> > @@ -1185,7 +1185,8 @@ static inline int track_pfn_copy(struct vm_area_struct *vma)
> >   * can be for the entire vma (in which case pfn, size are zero).
> >   */
> >  static inline void untrack_pfn(struct vm_area_struct *vma,
> > -                            unsigned long pfn, unsigned long size)
> > +                            unsigned long pfn, unsigned long size,
> > +                            bool mm_wr_locked)
> >  {
> >  }
> >
> > @@ -1203,7 +1204,7 @@ extern void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot,
> >                            pfn_t pfn);
> >  extern int track_pfn_copy(struct vm_area_struct *vma);
> >  extern void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
> > -                     unsigned long size);
> > +                     unsigned long size, bool mm_wr_locked);
> >  extern void untrack_pfn_moved(struct vm_area_struct *vma);
> >  #endif
> >
> > diff --git a/mm/memory.c b/mm/memory.c
> > index d6902065e558..5b11b50e2c4a 100644
> > --- a/mm/memory.c
> > +++ b/mm/memory.c
> > @@ -1613,7 +1613,7 @@ void unmap_page_range(struct mmu_gather *tlb,
> >  static void unmap_single_vma(struct mmu_gather *tlb,
> >               struct vm_area_struct *vma, unsigned long start_addr,
> >               unsigned long end_addr,
> > -             struct zap_details *details)
> > +             struct zap_details *details, bool mm_wr_locked)
> >  {
> >       unsigned long start = max(vma->vm_start, start_addr);
> >       unsigned long end;
> > @@ -1628,7 +1628,7 @@ static void unmap_single_vma(struct mmu_gather *tlb,
> >               uprobe_munmap(vma, start, end);
> >
> >       if (unlikely(vma->vm_flags & VM_PFNMAP))
> > -             untrack_pfn(vma, 0, 0);
> > +             untrack_pfn(vma, 0, 0, mm_wr_locked);
> >
> >       if (start != end) {
> >               if (unlikely(is_vm_hugetlb_page(vma))) {
> > @@ -1675,7 +1675,7 @@ static void unmap_single_vma(struct mmu_gather *tlb,
> >   */
> >  void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
> >               struct vm_area_struct *vma, unsigned long start_addr,
> > -             unsigned long end_addr)
> > +             unsigned long end_addr, bool mm_wr_locked)
> >  {
> >       struct mmu_notifier_range range;
> >       struct zap_details details = {
> > @@ -1689,7 +1689,8 @@ void unmap_vmas(struct mmu_gather *tlb, struct maple_tree *mt,
> >                               start_addr, end_addr);
> >       mmu_notifier_invalidate_range_start(&range);
> >       do {
> > -             unmap_single_vma(tlb, vma, start_addr, end_addr, &details);
> > +             unmap_single_vma(tlb, vma, start_addr, end_addr, &details,
> > +                              mm_wr_locked);
> >       } while ((vma = mas_find(&mas, end_addr - 1)) != NULL);
> >       mmu_notifier_invalidate_range_end(&range);
> >  }
> > @@ -1723,7 +1724,7 @@ void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
> >        * unmap 'address-end' not 'range.start-range.end' as range
> >        * could have been expanded for hugetlb pmd sharing.
> >        */
> > -     unmap_single_vma(&tlb, vma, address, end, details);
> > +     unmap_single_vma(&tlb, vma, address, end, details, false);
> >       mmu_notifier_invalidate_range_end(&range);
> >       tlb_finish_mmu(&tlb);
> >  }
> > @@ -2492,7 +2493,7 @@ int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
> >
> >       err = remap_pfn_range_notrack(vma, addr, pfn, size, prot);
> >       if (err)
> > -             untrack_pfn(vma, pfn, PAGE_ALIGN(size));
> > +             untrack_pfn(vma, pfn, PAGE_ALIGN(size), true);
> >       return err;
> >  }
> >  EXPORT_SYMBOL(remap_pfn_range);
> > diff --git a/mm/memremap.c b/mm/memremap.c
> > index 08cbf54fe037..2f88f43d4a01 100644
> > --- a/mm/memremap.c
> > +++ b/mm/memremap.c
> > @@ -129,7 +129,7 @@ static void pageunmap_range(struct dev_pagemap *pgmap, int range_id)
> >       }
> >       mem_hotplug_done();
> >
> > -     untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range));
> > +     untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range), true);
> >       pgmap_array_delete(range);
> >  }
> >
> > @@ -276,7 +276,7 @@ static int pagemap_range(struct dev_pagemap *pgmap, struct mhp_params *params,
> >       if (!is_private)
> >               kasan_remove_zero_shadow(__va(range->start), range_len(range));
> >  err_kasan:
> > -     untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range));
> > +     untrack_pfn(NULL, PHYS_PFN(range->start), range_len(range), true);
> >  err_pfn_remap:
> >       pgmap_array_delete(range);
> >       return error;
> > diff --git a/mm/mmap.c b/mm/mmap.c
> > index 2c6e9072e6a8..69d440997648 100644
> > --- a/mm/mmap.c
> > +++ b/mm/mmap.c
> > @@ -78,7 +78,7 @@ core_param(ignore_rlimit_data, ignore_rlimit_data, bool, 0644);
> >  static void unmap_region(struct mm_struct *mm, struct maple_tree *mt,
> >               struct vm_area_struct *vma, struct vm_area_struct *prev,
> >               struct vm_area_struct *next, unsigned long start,
> > -             unsigned long end);
> > +             unsigned long end, bool mm_wr_locked);
> >
> >  static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
> >  {
> > @@ -2136,14 +2136,14 @@ static inline void remove_mt(struct mm_struct *mm, struct ma_state *mas)
> >  static void unmap_region(struct mm_struct *mm, struct maple_tree *mt,
> >               struct vm_area_struct *vma, struct vm_area_struct *prev,
> >               struct vm_area_struct *next,
> > -             unsigned long start, unsigned long end)
> > +             unsigned long start, unsigned long end, bool mm_wr_locked)
> >  {
> >       struct mmu_gather tlb;
> >
> >       lru_add_drain();
> >       tlb_gather_mmu(&tlb, mm);
> >       update_hiwater_rss(mm);
> > -     unmap_vmas(&tlb, mt, vma, start, end);
> > +     unmap_vmas(&tlb, mt, vma, start, end, mm_wr_locked);
> >       free_pgtables(&tlb, mt, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
> >                                next ? next->vm_start : USER_PGTABLES_CEILING);
> >       tlb_finish_mmu(&tlb);
> > @@ -2391,7 +2391,11 @@ do_vmi_align_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
> >                       mmap_write_downgrade(mm);
> >       }
> >
> > -     unmap_region(mm, &mt_detach, vma, prev, next, start, end);
> > +     /*
> > +      * We can free page tables without write-locking mmap_lock because VMAs
> > +      * were isolated before we downgraded mmap_lock.
> > +      */
> > +     unmap_region(mm, &mt_detach, vma, prev, next, start, end, !downgrade);
> >       /* Statistics and freeing VMAs */
> >       mas_set(&mas_detach, start);
> >       remove_mt(mm, &mas_detach);
> > @@ -2704,7 +2708,7 @@ unsigned long mmap_region(struct file *file, unsigned long addr,
> >
> >               /* Undo any partial mapping done by a device driver. */
> >               unmap_region(mm, &mm->mm_mt, vma, prev, next, vma->vm_start,
> > -                          vma->vm_end);
> > +                          vma->vm_end, true);
> >       }
> >       if (file && (vm_flags & VM_SHARED))
> >               mapping_unmap_writable(file->f_mapping);
> > @@ -3031,7 +3035,7 @@ void exit_mmap(struct mm_struct *mm)
> >       tlb_gather_mmu_fullmm(&tlb, mm);
> >       /* update_hiwater_rss(mm) here? but nobody should be looking */
> >       /* Use ULONG_MAX here to ensure all VMAs in the mm are unmapped */
> > -     unmap_vmas(&tlb, &mm->mm_mt, vma, 0, ULONG_MAX);
> > +     unmap_vmas(&tlb, &mm->mm_mt, vma, 0, ULONG_MAX, false);
> >       mmap_read_unlock(mm);
> >
> >       /*
> > --
> > 2.39.1
>
> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHHPB%3DVE7Q%3DhoxVj7GBF18rpSQ-O-5%2BS3EPxOB5rHOrDg%40mail.gmail.com.
