Return-Path: <kasan-dev+bncBC7OD3FKWUERBGN7YWPAMGQEVMGYAYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E52F67B78D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 17:58:03 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id y21-20020a5ec815000000b00707f2611335sf2459496iol.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 08:58:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674665882; cv=pass;
        d=google.com; s=arc-20160816;
        b=hMP2WnG+oHXiQDKPh+VQ417Vc8u3AA0VERq/qNHxcjQxXJKyl0cQV0w/FZx+e3H8Xh
         5rl8mcMiRwFXECFU65sLnKEAQpzMhlDGlXzSad7wCajamuGCXESVjg7qh6OhyW4uDG4S
         C/MKAl9EsoV3XL2uxE2jSHfMusuc7LjLzwujzLz6RFlYdy/rsS8x82o+5Ow5xFxTIhnI
         ds61K+AglP6GQ19QPeW6FlBVqxcUXc+PcGN51Pd9XAYbv921lbcChVybkTOa8FXLYCbR
         DS333jl8txNWG4Va3hxm7XqzYwyJeI3ANwG3PojPJey5wKsjk8LJzcKmo9GiFSanvkyz
         ROYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wgBfPBTqzLgcveQlWPwv8W12VGsMhhQg2DmG9TF7i5M=;
        b=NfNPxZyT6zQheIOc+gDMf0rvg39ZQxqHbVeHCT8ThdiV3NNf1LhD+9cpJQYgaPjTzV
         807cDKT09aomaj9v6WFN1rK1RP3euDg6wGyb9uRWV9FFkvRLkwwQdhV89POQyCU55q9g
         rW3yVZ2XVNYX/yyPl3nW3ld+uyEEM3VEGRWbcw6f1mnjC44M0sm0ul2OFsuC3QST41/r
         iO/uM3/wjHZN4g8xEA1ramBZiYrj04K0X4eEGoj9cVLCRadgCdHPrcv0bkT76BE5Al5q
         vxWQtVJwA0QIjkAXTKahFKggPxNihxHCqrMoxvtXzaSA+0QsqKxaPJDhrJX0XeH/tV8s
         2vwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ngnRJaht;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wgBfPBTqzLgcveQlWPwv8W12VGsMhhQg2DmG9TF7i5M=;
        b=EmMTMx01mphgy1mqKc6grg+AA7KQO4evxbfW0t8pYWwlb35y+4snmPC3AxpqXvCqfo
         zjLCqq0+RUDt7KLvkTCsMhJBJ/iHF0MfKMx0bcUxPXY5gZ3iRYOo33haFu8indX8xmC0
         +7yhyqLgtVw1OODOuqm/6n8Wy/bWfnUhqX+MhOG+0Wlf7IEsEPCtmnwGJnhrk6Hh0K3x
         mhNC24jKx9Nk1WRXbP3YTcQQl42uiu7Ni+zZPR/yKPVB5ElV/TfnTR6+m9lY1Sjj6Fgp
         R48l0aT7SNPDs2gOyTF79OTY8HHlQu93Wvg1lJ+/EPWePGpBvp4soZ+C1pdTeYWRUwNi
         4MvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=wgBfPBTqzLgcveQlWPwv8W12VGsMhhQg2DmG9TF7i5M=;
        b=OmtLzknj0LgZQGyDSE26UOllgvHl9nyHCeptyhSKrR0uJaO4oGfu2dqb7iXMEHaKDC
         M3Lm6nPBmU+ClNrjr0W5gA19/N6XG2T+JYjfVsEJd/PxVGAWQjTSyv61KFOAJ3PlLaTk
         FoE3UklNm/HcoGpEMmheV8u1mHHHag6XNE80Gwsvnxb2eo9twz2idxJX8F45CczV2L1J
         Po+FxCI96cAscncLL0b4Dr/y+EMXhAsU3CKI/XlO1ul0YoEfhxuBLaCIlipArCchT+3t
         9VuIA4dabXWNvwwJ2F+0EFel2HesdJOA+ms+nM0Iqkk2l0UgD4T9DVaxxrnDiJUu/F4B
         suEQ==
X-Gm-Message-State: AO0yUKXVy/3oEIB1FKRU2/ZVQ09vD1K+BfZ5OMxWmV2JJ8gjbTdpt2ky
	/7UjU6p7l3X50mU9WhCtK7Q=
X-Google-Smtp-Source: AK7set92Q45qlCNwZ/8tk6wEChUsH22Ijtt0XJg6C3Uziexxt/HfoTC7AYOp3O/cmRtGqZaF/QztcQ==
X-Received: by 2002:a92:8745:0:b0:310:9a62:2ba1 with SMTP id d5-20020a928745000000b003109a622ba1mr656014ilm.106.1674665882138;
        Wed, 25 Jan 2023 08:58:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:d708:0:b0:6de:9e24:a442 with SMTP id v8-20020a5ed708000000b006de9e24a442ls3891460iom.9.-pod-prod-gmail;
 Wed, 25 Jan 2023 08:58:01 -0800 (PST)
X-Received: by 2002:a5e:d90a:0:b0:707:ec16:1159 with SMTP id n10-20020a5ed90a000000b00707ec161159mr3648880iop.5.1674665881541;
        Wed, 25 Jan 2023 08:58:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674665881; cv=none;
        d=google.com; s=arc-20160816;
        b=e8AMt+kvZCXY7Ija+6QhJIbI0NAAX1w2w8dcf9wR+D3WSYzD7vwqeFKjOK2MzLyp1h
         jJ0qiEC1V8FIUJiSMx4Ivp6EXVsZQFrXq6kUqeLS0XAAbx4qKllF7St26KKEuSuVm5vo
         qYSl+Fqzkz6ZZ4VoVIWgyGMdWdySq53KVO5Gpyn8snTFn/cslOC/xMoK0AMrzffobdIS
         2UWwXqcW+FEQt/iGWWDVkKLtzx4R1KmTVDOkgd4ls04BwLJOxgfCqo+g2b6KS0J8thNi
         X93KrthA78goQ8dYXcAdDIJTWeBSaySUMcxCenmksDXXIxKX/l4JukMssFRk0Wy7a9U5
         U4yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G/HaQvIeifLKJJp6JsBUTA/Cu0PG4HCFXOBV2LCBpGc=;
        b=FjpSuUw6My/H07Y5PQZdBdnUltHstMDilGswZ+ZUifH0jCRbjw3mJLcDSZf9zRhQH7
         cRo7k99nP20itEj4dvb/Y0gTwajLSMv/BzLuoaM8JyufGKmh0dlJh3uWUYfyHLZOcjnd
         RoZJEI6cUxQbmtxqFzrgA8tzaz2HAF4G0mhh0ajeS94mmwupvzfzh5D4WIgxVdF8o8+i
         x8fvkxRxUY13LSzdYl8t87nOMw7io6J0OsIS++5uM5uYagmwkbRnbgBnXV2Ber9fusEE
         4Y/S3gwgwwkc07mzVWPNwMjqWY8E1LoB0RA8+qmqjxLEN7xJDWOmN9Vy0kpkHP7eXaTU
         sGAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ngnRJaht;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id e7-20020a5d85c7000000b00707a3e9f678si485306ios.3.2023.01.25.08.58.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 08:58:01 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id e15so1638664ybn.10
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 08:58:01 -0800 (PST)
X-Received: by 2002:a25:ad02:0:b0:80b:6fd3:84d3 with SMTP id
 y2-20020a25ad02000000b0080b6fd384d3mr714673ybi.316.1674665880846; Wed, 25 Jan
 2023 08:58:00 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-5-surenb@google.com>
 <Y9D4rWEsajV/WfNx@dhcp22.suse.cz>
In-Reply-To: <Y9D4rWEsajV/WfNx@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 08:57:48 -0800
Message-ID: <CAJuCfpGd2eG0RSMte9OVgsRVWPo+Sj7+t8EOo8o_iKzZoh1MXA@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=ngnRJaht;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
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

On Wed, Jan 25, 2023 at 1:38 AM 'Michal Hocko' via kernel-team
<kernel-team@android.com> wrote:
>
> On Wed 25-01-23 00:38:49, Suren Baghdasaryan wrote:
> > Replace indirect modifications to vma->vm_flags with calls to modifier
> > functions to be able to track flag changes and to keep vma locking
> > correctness. Add a BUG_ON check in ksm_madvise() to catch indirect
> > vm_flags modification attempts.
>
> Those BUG_ONs scream to much IMHO. KSM is an MM internal code so I
> gueess we should be willing to trust it.

Yes, but I really want to prevent an indirect misuse since it was not
easy to find these. If you feel strongly about it I will remove them
or if you have a better suggestion I'm all for it.

>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> Acked-by: Michal Hocko <mhocko@suse.com>
> --
> Michal Hocko
> SUSE Labs
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an email to kernel-team+unsubscribe@android.com.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGd2eG0RSMte9OVgsRVWPo%2BSj7%2Bt8EOo8o_iKzZoh1MXA%40mail.gmail.com.
