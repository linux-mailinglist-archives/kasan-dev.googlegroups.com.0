Return-Path: <kasan-dev+bncBDBK55H2UQKRBF7EYOPAMGQECEKBM6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1304867AD60
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:10:49 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id j11-20020a05620a410b00b007066f45a99asf12567587qko.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:10:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674637848; cv=pass;
        d=google.com; s=arc-20160816;
        b=XEOBjVm1oFv599HIsfvQCHiMVYcu414Fk5S5MmtSbCoGQjGNa2XWYi6Y8KLBo1xjQA
         5r8FeALQUhcvgLnDj6Ied35h5Gz71L1iP3sV6kD15RIFqHErFEMLREHDtHjSj0hN7/lO
         xaatrSbINWYVvwP6Cq808fap4dqzLwKy2gRbCrZu5RkSckhcOyt39VZ79Ny1zmd8jRVM
         HYURgt45zzgZ9LhVq0geBXjzeVyPhTtF/ehnjDqRNynUikQMdlnIbKGxbx64lTkpZ8Pe
         LVYOCnuO+HnAZr0wM0J6UammJKhAx2uyQgei+3H7haC9iEEucVH6Xor31e29yGGBc2rs
         M1+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DUvBluytcZvkMlWDm5wpzEoZayWAhqiq/hFKmNm1Xxo=;
        b=cK+c7KFI22cqXzTVexv+qeqOLEgDilwj/f+Z2Oq0HhtdE+FOQIm2pEA+yHDObQ9co1
         Lz+8OKU8ul+gyhjx337aMEMoki7vzGgY1RDjfqWBmA72r4NYgxwQKxaX5GX0HvunEc1W
         eOFpzZoWQesFj/+dMqJaf11k2DolnlV22v6JUM31zWBmSbn1VJQoujTj3n3seStiPh0n
         UjI5193WAbcgHPGUS3zdaXK6dOpJAlRVn8ctTzK5T5xDHRYwiZ14pT58QkBzYgGeGM8G
         gsd7uzHUQGqcwkYUoWX0yP2bWJMEHgPPnnonH2n2sYkIFDas3oCLDOIVSh46ZrHXix61
         kYIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=qsa+lu0U;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DUvBluytcZvkMlWDm5wpzEoZayWAhqiq/hFKmNm1Xxo=;
        b=FXqbGXV/kUvbrPc7c2A27+qzxDLkOR7eEHUp4sZaasS3DerSV6dV+6ChPecSkwnLyy
         FsimUFUicVFu12388m52FmRmk2/x9I7VMAj7yorweGsLKR5wMkECM3SQLRbzl5q30joq
         BemB5ayScIR9E/PGc4l85ukzmBpWbtJMGQDS57TuNzaNJGyTvK91sBEfFoxY3IP1zMfB
         3pa0O95fJ9e2PJHXWM8o7bHDg3eWQpdfkQMhARpFQAJX+UUTmG1y3jqli8N7lEJC5cho
         eCzP9Ukf2KWBS7hVzChWtKoV+zKW4jGCjhociiClkFV4goRB31KSPNvW92KNHWsTp612
         fAjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DUvBluytcZvkMlWDm5wpzEoZayWAhqiq/hFKmNm1Xxo=;
        b=pX5lWn3cSdsAMCIbTYFHg9pbqcKrD2Qse/4ltnFeHB6RgK83lL4W+Ezid0607IkorY
         r1hUyOR6xAl/CVijiihGf1AxXfW9qbZ3Buqfg/m3VMkbUxTYSdTazuHaWgZThi+dS2/+
         cpEqPA7bwN1XFO/B55imy1NTAV801h+Holf+T8HrPVrxG+wgA93Z2CK26z652xuYQSZp
         1uO4tMeCqW2K5GK/BJl3Oz+8b43bE9VUdtSyuySMOA1qGBJ0AP8SyPcF+0mlzeIP9kGB
         TPQcXH8hev+N7UY963haRwmqxaokeAeJFVdo7GOfz0YzHf6aZ9QwLH6w0PhUUcF8neh9
         +Gxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kppsW8IpnOGzyg2LeOPS7JMnT+4sIkNhKEJ/NeUf3EaLsFhsfM8
	yNjqNFkk9WynLJM6TXOz9L8=
X-Google-Smtp-Source: AMrXdXt6ul1GyGZM95RPfvLnKjTW9xsr+zCQgPjeNoOLzFQV88krrbd+koCIJW4nX95ZA4zbF0PP7Q==
X-Received: by 2002:a05:620a:2238:b0:6fe:fa63:58d8 with SMTP id n24-20020a05620a223800b006fefa6358d8mr1803262qkh.662.1674637848078;
        Wed, 25 Jan 2023 01:10:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a914:0:b0:532:228d:cad5 with SMTP id y20-20020a0ca914000000b00532228dcad5ls11108617qva.2.-pod-prod-gmail;
 Wed, 25 Jan 2023 01:10:47 -0800 (PST)
X-Received: by 2002:a05:6214:3246:b0:534:afe8:f214 with SMTP id mt6-20020a056214324600b00534afe8f214mr48720864qvb.46.1674637847559;
        Wed, 25 Jan 2023 01:10:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674637847; cv=none;
        d=google.com; s=arc-20160816;
        b=gyXeKi18BkqvFR3zaSsJFTqmNbFtuZf+uMyzyh1WRSmipscz4/arWLdEv9TakWxdX8
         h3Z9f1djh64K2tqdHw4c5crLafjcX1RPyAgJANApvdGImbLwyI69uNXqcjX05l6XyZos
         G+BKWVHlBY2q4Blc9LmB2NlFLVczboc4fVygY0LL/MWL8oXwt8n+IgfgPW7JLKNdZpNc
         jj3c4HlAGrORyzRv/ahTEgSakwQT33BUexO96tb3Dee6QetZGjufS5Ha+a5YvuP+NPjs
         QHbtUJ8CbDOnovVrDEXes6cBkSHGizmY4I/WkM0s1Z1eSPsa0gmAt1knS3H97isBGYpV
         BYtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hk+0OseVD3OO+ksIzhtEU5LrZV8KXEqXC3zpbOGn/ls=;
        b=q2QxL0TlR1+1pwXSld7wAt4A+lvRtgSUf1wrNLFvZ8PEhu3teyTY0jPXgldi/OFFzL
         U4bz5pq+rP7CoROVTq77hNXIdkZkVr5FSB9EqD2I02g/A07yhRQJexBVdxS6Pc964isv
         rC6e3QjQzO0jfgTe76+rI8+JIMmqF8EjsYXjlNZiyp1a+rUkQYcybuB4/mdaAF47B7+R
         94IHReyafweWjPRuIdBSTUP6tjh+fcH7m85wX2hJqJwe7/2csO8ETVlr19Vmw4fa3Fvm
         u791TY6bvk+jDIDMkPgA2P/QCgvk2/oI1ZE/Xw3vlDoFXsJdbGcSQF2MZCvdK6LNSx9H
         oWDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=qsa+lu0U;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id b15-20020a05620a270f00b0070f2c8e7344si359667qkp.5.2023.01.25.01.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 01:10:47 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pKbmL-0026m7-1c;
	Wed, 25 Jan 2023 09:09:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 83601300137;
	Wed, 25 Jan 2023 10:09:37 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 673382C247607; Wed, 25 Jan 2023 10:09:37 +0100 (CET)
Date: Wed, 25 Jan 2023 10:09:37 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	mgorman@techsingularity.net, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, ldufour@linux.ibm.com, paulmck@kernel.org,
	luto@kernel.org, songliubraving@fb.com, peterx@redhat.com,
	david@redhat.com, dhowells@redhat.com, hughd@google.com,
	bigeasy@linutronix.de, kent.overstreet@linux.dev,
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
Message-ID: <Y9Dx0cPXF2yoLwww@hirez.programming.kicks-ass.net>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-2-surenb@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=qsa+lu0U;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:

> diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
> index 2d6d790d9bed..6c7c70bf50dd 100644
> --- a/include/linux/mm_types.h
> +++ b/include/linux/mm_types.h
> @@ -491,7 +491,13 @@ struct vm_area_struct {
>  	 * See vmf_insert_mixed_prot() for discussion.
>  	 */
>  	pgprot_t vm_page_prot;
> -	unsigned long vm_flags;		/* Flags, see mm.h. */
> +
> +	/*
> +	 * Flags, see mm.h.
> +	 * WARNING! Do not modify directly.
> +	 * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> +	 */
> +	unsigned long vm_flags;

We have __private and ACCESS_PRIVATE() to help with enforcing this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9Dx0cPXF2yoLwww%40hirez.programming.kicks-ass.net.
