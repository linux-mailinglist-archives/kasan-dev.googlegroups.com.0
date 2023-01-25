Return-Path: <kasan-dev+bncBCS5D2F7IUIN73WFTYDBUBCJPV77O@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9147F67B993
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 19:39:28 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id cg18-20020a056830631200b0068646c482f8sf9459245otb.18
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:39:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674671967; cv=pass;
        d=google.com; s=arc-20160816;
        b=gILdwKLebi0gg4hFNp89WmH/J2HaTTWMcofnixVU3VyUmSrVVaPG6Agb/0Zchfelne
         v8ituZ749yY6Dp+yn7MUwjz2eV5v/zCwj28Z7RwqR5qou0f51RFRDEti9m0WgbV3x+0A
         CYVoPg4Z2Hx2MNKUoTE6UU4/xJrpxHp1Iztltzcb6MO/16kXfgsrB9OC7nPBSdwp/mn+
         /rXb/GnwiIPd9GuT6SLoN7zQSzVphOP2xLjPmCkfDeVnSvAsXAGbLj3EuWLlqV0gh/pl
         46VTGeafbowVvvNeB4Dosv+hXDVo+NtnH3kDS3YUkS3NOoviqIczM4GK6MkO3Rorg4Xn
         BUXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bZ/tWC6G2Ap6yH+3R4HRpNDiWUCFj2Ph1H6DFnoud8k=;
        b=IzBSd0SS8YBy7GKH8Z9wlTfOVpdQNmIxMrZVMntifiYOlzj0eq1S34H/bDokcEbx6x
         TE9FuWhvXtlWgxiTnxcer41bdq/3mXIW6bsDMXcevfDBlnee4UTINbowmHn1w8w5J4rE
         NTtpWEWdwWkgKloxaExiWqlrRspi7/qiheYlmkMFtbRsctz7Pe/fE4VA5+Q/q6zrp7hJ
         hBpzve7kBt/j3fR7l1p9VVqjQEN3nWCFvyBFDA/cKy0I+xYTFPVM62876dXF1pR6bVcm
         gNhLLf4aj4yPgvSFxoyNcBX1NYRYmnIWTUUz/je9ELQ+sQZXmtn9Ho9s2YEChegVJs/7
         wtLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uqNynxzu;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bZ/tWC6G2Ap6yH+3R4HRpNDiWUCFj2Ph1H6DFnoud8k=;
        b=ibj/RD10pdYYbxGmRxtTUtSmO75996q+XYeGOKO3euNsWXFkfnaUm9+B54nhC/hk9X
         hXYzfla6ma/w/lYBU7eYpQnQsMauO1/bUvQ3oCxluNl+WiVQrZjhAihVqvBLQydxbrK1
         SSwXD4Q/Ts8Vv7z1D69FhNONLqmnSAZlImq93vUGcJl2fkLbRp3503+MlbyV69NW6TiV
         iDI0t0PRA3s/gK6cCSRX/Yu7UU0v9MrgL4vhDYzrhcHqT02V09AcQLCarFvgsyg9f8L2
         Yxr42vjxRWcf4cLV9bOZNZZbMZYl10CYScoRl47OvyJUXBg1+OFg/wWCTVBLmNUqMC++
         4r7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bZ/tWC6G2Ap6yH+3R4HRpNDiWUCFj2Ph1H6DFnoud8k=;
        b=ajY2q+6BYl8fOrGZDe7UMm9XK2tk29i+hZWXTzwdHzDwkTTusxcvFnPffdrg67ktnG
         vXfy+p8Uj0VlTOZVfBvjO6hbuMpyF7xqpzacUTGvyuU9xIvnj+0tpT5IsoTDrVfhy/a7
         ROdeouBH/Ma9byMAG7idQsI/VjpRhA5rMYT83GXXc2tygtULfMpm498SP3XtEJUoQ2F3
         DI71P49CxJ8ubLmi0j19P2oyrMCoNhVsdOkSVQKnS4oJkzqa53xAUY6pREgXK9+DTVpW
         roC4UljKJvEyZNWL3wrRekcQYjrspIiFtYJt9n1D2dkPaVZvY913O7Ppf2SGOuLxT9e1
         HdMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krNGJVmPeF+kwvKcbDpklL1IP61D4KZPQFgMtpguXfuGVbVZZRp
	y3JEDc7n7BRaOWHDKaaGjcU=
X-Google-Smtp-Source: AMrXdXvQUqOmN3T+HGbDJft4oj0QbYlSJsG0cvHTGrIaYr45f5IExel9tzpOxbNih7LaHZjxZfdw4g==
X-Received: by 2002:a05:6808:2201:b0:363:976b:9305 with SMTP id bd1-20020a056808220100b00363976b9305mr1870844oib.274.1674671967465;
        Wed, 25 Jan 2023 10:39:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:785:0:b0:359:ca69:f473 with SMTP id 127-20020aca0785000000b00359ca69f473ls5997297oih.10.-pod-prod-gmail;
 Wed, 25 Jan 2023 10:39:27 -0800 (PST)
X-Received: by 2002:a05:6808:2222:b0:364:5a39:ec53 with SMTP id bd34-20020a056808222200b003645a39ec53mr19511482oib.22.1674671966999;
        Wed, 25 Jan 2023 10:39:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674671966; cv=none;
        d=google.com; s=arc-20160816;
        b=vJJ47VHAQN7h5T5hYvT1sg6H9qFUlUsAhVyEdQ7ZLDv0AQvSzHYAoPeBBac8Q9p6jY
         niNTlV9EWPqg8s3OUtlmv8rmBErDiqyWVGaNtyerOVtKFP88PuA4JeJJsCw+GAlXcXN5
         EspXzoumQQ9cI8xIAwtoZSO3SsBWq1GlI3sl6hVqtmmnM6dKA0byrLfI2+tDxMhYqDFL
         rm6grtjrJuty0FS6aECbnHDpbN8SaSzNA7GqJDp/Bn8QLE0ALzyurMDiuc0/FwoiE0U2
         q2vXM0KP9qkYa+izf/bxk6+nhicmyS3jICK8ySmow2y+PDwQjAYfg2d8Puf24QQ9w0X2
         3cJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j8xmcwaWWp8ClSuIcWbfPO9W4DI7+K1SIXYR1hupOAY=;
        b=HUy4MRxxXor/y8+/KvGdF5I5GNyMKrBcwlc4S6f4LOo3x+PjGjnjPvU9gQVAGgn+RP
         nC0xK8gMi7Lzcx/oAN4lzJzm8vj58mFY4FhyZZ4HHyWng57lK/dJugaWF8RXWuSt82nw
         270QAagDeG/58I64WC8iMVEeKEQth9P1OpZayHXa/DBrhIAfwXyp4qqLVFkocS1QZ3+T
         OHZfrxJqK/6bf5wOlF/WnuC/wCuBcrFVQgmE2mNKio1E67tH3I3mgp0K45KV3IpNajwI
         oWf8Ys9/5Z3/w+GEZNLMqSMhSN+Jsa1tUow2JMn2awKk4Kpfr4kz1+jkPT8VR+iTtewx
         LcBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uqNynxzu;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id cd27-20020a056830621b00b00684c98d3502si1056741otb.3.2023.01.25.10.39.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 10:39:26 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pKkeP-0066hH-0o; Wed, 25 Jan 2023 18:37:37 +0000
Date: Wed, 25 Jan 2023 18:37:36 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, akpm@linux-foundation.org,
	michel@lespinasse.org, jglisse@google.com, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@techsingularity.net,
	dave@stgolabs.net, liam.howlett@oracle.com, ldufour@linux.ibm.com,
	paulmck@kernel.org, luto@kernel.org, songliubraving@fb.com,
	peterx@redhat.com, david@redhat.com, dhowells@redhat.com,
	hughd@google.com, bigeasy@linutronix.de, kent.overstreet@linux.dev,
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
Message-ID: <Y9F28J9njAtwifuL@casper.infradead.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
 <Y9Dx0cPXF2yoLwww@hirez.programming.kicks-ass.net>
 <CAJuCfpEcVCZaCGzc-Wim25eaV5e6YG1YJAAdKwZ6JHViB0z8aw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpEcVCZaCGzc-Wim25eaV5e6YG1YJAAdKwZ6JHViB0z8aw@mail.gmail.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=uqNynxzu;
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

On Wed, Jan 25, 2023 at 08:49:50AM -0800, Suren Baghdasaryan wrote:
> On Wed, Jan 25, 2023 at 1:10 AM Peter Zijlstra <peterz@infradead.org> wrote:
> > > +     /*
> > > +      * Flags, see mm.h.
> > > +      * WARNING! Do not modify directly.
> > > +      * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> > > +      */
> > > +     unsigned long vm_flags;
> >
> > We have __private and ACCESS_PRIVATE() to help with enforcing this.
> 
> Thanks for pointing this out, Peter! I guess for that I'll need to
> convert all read accesses and provide get_vm_flags() too? That will
> cause some additional churt (a quick search shows 801 hits over 248
> files) but maybe it's worth it? I think Michal suggested that too in
> another patch. Should I do that while we are at it?

Here's a trick I saw somewhere in the VFS:

	union {
		const vm_flags_t vm_flags;
		vm_flags_t __private __vm_flags;
	};

Now it can be read by anybody but written only by those using
ACCESS_PRIVATE.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9F28J9njAtwifuL%40casper.infradead.org.
