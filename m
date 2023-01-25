Return-Path: <kasan-dev+bncBC7OD3FKWUERB7N5YWPAMGQES5O6Z4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FF4067B768
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 17:55:27 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id w10-20020a056e021c8a00b0030efad632e0sf13039835ill.22
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 08:55:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674665725; cv=pass;
        d=google.com; s=arc-20160816;
        b=bKRtNBXijOaIyq8ouOGI+kI1G8itytDTlNfWaeN/7jg3T3d1LJpfsfqjB999aXJT2/
         M+gXEvGTVvb9wgkEPzhUiUyGddmkOrDanaOBIigW2yYi44cN44P2QZ0r0FdPlNN5slm4
         EvmHmu68yYxwfXkXETzgIHoYcokT0+W7LFVHywQWiOfERclvvzJmA8RtG9lYS6ooWx+9
         tDoANehhVHQObnfqfFRxnkXrR+ihowbDJ/3vuTJqOBPHfL19fv12rHxTNtRYsyljURqe
         3fwowaYeMq6/Hj18AsODNeUPDj5vi1zYsskU+p1vmmTxAd5Jj8g50EDYs6RY8PTRduL+
         m0NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LzXEDyz18b19rM6Kt9qiaaypioqXGqOCNgMpO+h16DU=;
        b=FHhFyldfHqg6OnhSMYQ1Oy9hs1LgpxguyBriVBMAu3MiACQjp7zm/XyzRZq37XWKvb
         U+6Lu7OkmjykSUMsYTvhcGvfLg/Evx+gDDKWUodxESuXAvU9LWuea5shwcMG7cUVLdDC
         w8aAghLI1L37FT26EV+249Klanlqh+8mVHvV0mI5AonLS/Pg3WeRyqMpSNEcQy/new8K
         Mw5Ew2oaZNVYQFrz46o5nithAn9yW8aKVXjw/k4JsXYbvC7bF33oWQQWla1Z3u4QvxUi
         VhTFfVskmAvJjV5Y/wncrr6X5bYOZehLuPGcz3Zq/IIKK/VmDo1e+HPB5igRr/fkRG0q
         KjLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="S433Z2p/";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LzXEDyz18b19rM6Kt9qiaaypioqXGqOCNgMpO+h16DU=;
        b=YbhlfXDzsvyYlKGRKKJBNx1h5cyuLcTuRkaaD8YL28l/duGFv9+gobneCiKpU2Dxnp
         8Hw01Zt1FO/GmemStHqtKvpA+jkLAxOIVzuSo0ZM1D0yE5dRj3TjlN0Czi2PaNcKsQ36
         NKL/Ua5kObsoQdWBRQ0Omf7VgPlaOd7G6x0VCaJ/KjdMYpKSi+UO0Z1+eXEFgjcXKrVT
         EoR5/wY7srgOdHyTsNWAh4WgztuKIc1fGAd1OMjFZeUeqr+6NpiNc0tStuoLai6EH7lJ
         X/acn4YHZmjp/jF2jiJLYmtQF0wxIjd4Il4tJmvHSh3R7a9JP+clnIFvS/EeXPS30UBc
         xpLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LzXEDyz18b19rM6Kt9qiaaypioqXGqOCNgMpO+h16DU=;
        b=rjLfeNd8c719T0DuzutISZzogUSzxa4qhnLHTPIDyoLC1m7FRfVX6PWKDRxDs8dblk
         EQTwHOCOBsX+DcmdvWGxtuYqYpKNVzfriUFeqUVXnVSGnL9POu+DIqeaAHpetYNwpL69
         1Cf6dIbhoZaU8M6ntYVuxoAQyiRl0lZZlX/zKmp3ANKEXM3hj0BZ6a1r7L8ndSQ/pNcv
         NKARQT5TcZeJ9foEH9ZmrVyqHA/jfmiDY6FPolcnLHqkWmy83swxLCN/upu3ReUKqCyj
         AGG30LNNOcoUmqjvzAGyjYsvtrlVfk+O/t7OGJsNFV/9RzsJipGym0EeD35wxbJDfBFw
         1afw==
X-Gm-Message-State: AFqh2koBcgyONo6k9ygkCV2Dve5M1NIe/c+oYBwFoGABe/DrVYv43RP0
	NyrzgSPUGD0bJSJF89BxQII=
X-Google-Smtp-Source: AMrXdXtYbOI7T3LNGWvhlRE0KnNEgxowUUaoBWGYAVLgkqZ1mYjaDUr8gtSh0jS8s9hggrktj/xs5w==
X-Received: by 2002:a92:7301:0:b0:30f:23b6:87c3 with SMTP id o1-20020a927301000000b0030f23b687c3mr3444627ilc.83.1674665725556;
        Wed, 25 Jan 2023 08:55:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c5b0:0:b0:30c:27a9:a355 with SMTP id r16-20020a92c5b0000000b0030c27a9a355ls6344040ilt.3.-pod-prod-gmail;
 Wed, 25 Jan 2023 08:55:25 -0800 (PST)
X-Received: by 2002:a05:6e02:1a09:b0:30f:5333:1a51 with SMTP id s9-20020a056e021a0900b0030f53331a51mr17996554ild.22.1674665725080;
        Wed, 25 Jan 2023 08:55:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674665725; cv=none;
        d=google.com; s=arc-20160816;
        b=GoLk7yfmKdwU8gsSPUmLKNasJAQtFD2/wOzWXv2n/v3MLbtrlDxKaHVpaGSd7J7EPN
         GE7fudbHGSu8Z9K9FPfUCl+BOzwP/jUZokkQWc1fC8O7JeH0bpqXW+BxHOQmZwAtrH0C
         9tc2ltROkbFmZZzbUp0RlT/QBUe8NS1ICBpStngbaVWv6nB0Qwat4PPU0uV+5XHfHQo2
         YJVX48Zg0Cmy1zoqq0+Y1IDzds+1H1hO7bCULxEl6tBIFSHQJQ/Y5USQ/hDYoAkEeyS4
         sqtoDPdMmAaE1xyJSJZi1X2IH+uOcEGVlfmrtJdNeCDtKuUzFVfbRgrc5raOiYqm293q
         M2GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=49H+5dcfdqsESvQ4qNxkOgTxyGkRYtaMvRra0jMgwoI=;
        b=tChzyIYYIrJkWoax0rFFqszZIY3PRMdYyjDEGb3TccGaNxAOWKhf69mNxXVjTdTwGP
         zmTBuYcyaz3TpAG3w2vxo5YfR8DlaI67jycuAmvkrLEVtyOyUGY+coZ8HPnZpMwWMmxj
         yVgQ7ar0KLcnyWsmAaVebblS39AsWcYFJ66OCSNdgZNLDf6kMoKvvpX5gKEinDTf2Io1
         Vjmx7QM6tKBRXjInsUSbyBjc026g7/TNbMDvVSwqbB+yn7Up9nJA3mNz7zaFBJNj5Swm
         Y+ZgIhuyIGNzucwh3Qjf8azdH/S/AYJG74BeU/6Vnsrun9fbvQcNmaKMaOq7fCn4LQbW
         ncew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="S433Z2p/";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id v10-20020a056638358a00b003a2f65364e7si568439jal.1.2023.01.25.08.55.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 08:55:25 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-4ff1fa82bbbso225687817b3.10
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 08:55:25 -0800 (PST)
X-Received: by 2002:a0d:d456:0:b0:507:26dc:ebd with SMTP id
 w83-20020a0dd456000000b0050726dc0ebdmr239978ywd.455.1674665724181; Wed, 25
 Jan 2023 08:55:24 -0800 (PST)
MIME-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com> <20230125083851.27759-4-surenb@google.com>
 <Y9D2zXpy+9iyZNun@dhcp22.suse.cz>
In-Reply-To: <Y9D2zXpy+9iyZNun@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 08:55:12 -0800
Message-ID: <CAJuCfpG7KWnj3J_t4nN1R4gfiM5jgjsiTfL55hNa=Uvz4E835g@mail.gmail.com>
Subject: Re: [PATCH v2 3/6] mm: replace vma->vm_flags direct modifications
 with modifier calls
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
 header.i=@google.com header.s=20210112 header.b="S433Z2p/";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133
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

On Wed, Jan 25, 2023 at 1:30 AM 'Michal Hocko' via kernel-team
<kernel-team@android.com> wrote:
>
> On Wed 25-01-23 00:38:48, Suren Baghdasaryan wrote:
> > Replace direct modifications to vma->vm_flags with calls to modifier
> > functions to be able to track flag changes and to keep vma locking
> > correctness.
>
> Is this a manual (git grep) based work or have you used Coccinele for
> the patch generation?

It was a manual "search and replace" and in the process I temporarily
renamed vm_flags to ensure I did not miss any usage.

>
> My potentially incomplete check
> $ git grep ">[[:space:]]*vm_flags[[:space:]]*[&|^]="
>
> shows that nothing should be left after this. There is still quite a lot
> of direct checks of the flags (more than 600). Maybe it would be good to
> make flags accessible only via accessors which would also prevent any
> future direct setting of those flags in uncontrolled way as well.

Yes, I think Peter's suggestion in the first patch would also require
that. Much more churn but probably worth it for the future
maintenance. I'll add a patch which converts all readers as well.

>
> Anyway
> Acked-by: Michal Hocko <mhocko@suse.com>

Thanks for all the reviews!

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpG7KWnj3J_t4nN1R4gfiM5jgjsiTfL55hNa%3DUvz4E835g%40mail.gmail.com.
