Return-Path: <kasan-dev+bncBCS5D2F7IUIM53WFTYDBUBHBGZ7S6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 941A067B986
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 19:39:12 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id g31-20020a63111f000000b004bbc748ca63sf8637883pgl.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:39:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674671951; cv=pass;
        d=google.com; s=arc-20160816;
        b=RXjjXPWW+UF4sFSvmvDcRvr998cE4nnXqqomKKntiSZwXBMI6E6MyB073IXwyB4vwO
         GrwpBZFZ36ojy3Rbn72Cp8rKSP8gv9hM/IbX6TDFaEgOwBYcB8991r/W7XD/3uhdLmJu
         EA5z7U+97xUb3z4oBKmSUEB7HqSpRWOMuJaYfTPGm1jXJea7X5lqTLV75+yT4BZ6dh0f
         yLuwtzB/+FeFLVbwT7Qa/hT3YHXoAOx8IqDEDL3rNAnzCGf9Po165ryQuxSKLoVwKWUe
         c1giFbPgE5JG19MrxjVi/EFe6M3J8dxgJouRKMBvAALarziT1AdFfZrRBT/UTXWYOFJ/
         hm+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/2hJDQA/zRPfMXAuaiGRlPcHx2yZFoq7J4dSz2GnywU=;
        b=odDG21nYGWO5SnsEs5gdC91MfGeM+8ogALU/AxMkdwWOlnM69LncdDS/cXOQptx6Qp
         h3L/jwImONMar5UYjLjDLVDuQZpx8b6UlnW7l9HwtaeHwZqGA0CyqANHBcb+7URyP9d5
         l0b9P2o9N6XurpqVqxThaiNpZD5sZH6j3OcJ6B3Jjdx/qxd7vYo5Yb6lsmj7I9D5OlTc
         fWerBSWXRzoegVukBvDYIjcBfpcCTfmvJ+ZUCtlYnrnsAXMbv6mlLBhSqNB9BKj7QWtq
         MX8mS/xnL/QbhueJ5xXGv1Vq4usnf/TZNqvjTANZQPE0KArTfbmAgQHV3RlTg+Ajl0FE
         pjzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=mx74wVm8;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/2hJDQA/zRPfMXAuaiGRlPcHx2yZFoq7J4dSz2GnywU=;
        b=tHZzNaHu36rXvCxNhOtZEo9gu66njoJ2cGFwuLC9TW4vkfEk6TXW9p+nyMDAQ88iN0
         tE2K1oNIqn55TK71B/Rvd6ZkTMhEIIlrfY3/FGcGf+dXxU0WoV/+MdJlaLz8tYVMd8B1
         2OclmFnlWLNQz1dhyzRfkNjA72kdDpBNNWxf4ZTB3XMN7MUWa9YsbEcSOCzYNXgjzKSx
         SaL74RNbwoXeVqSMbzDoA5ocy2JzN7rj6WyUpvdlSKGfYEaL8gySZaEGwmKK8GWBVpnR
         /FVfFAYKa+raphDJAg8duRtJSL+EwBTYYIE+tEEK372sA1MK7soSPgt1SyoMoconW9Tt
         v60g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/2hJDQA/zRPfMXAuaiGRlPcHx2yZFoq7J4dSz2GnywU=;
        b=7pCc8KHaSMX0ChnCDGTrKpgHhUhwN4rN1JAQM2snfbX0/9bitJVOwHidc6HjUD7Djg
         l22/crxuJRvPP+lk8SxYHb2qefeIDvm8VqcNWNthi05n0D3g8rJ0tsWjztOnPcFzpBxt
         /fF66mN1GyDZ20o2+kfuG7s224ctBlIlMQ+lNJbfUDLkcB0RM7Ow7oX2w8rz5nVMYzvS
         pgGVSc3L/n24y3chqElmmD/P2gWU//8devDobvjch3s/Wo1BsXbrhozYQqyyce5R0crk
         4YRFouisHzDkpKJFpz06HJUH7965Y2RJIzD7l7H5gTFs0p6Pzc2m4/o/83lagsOrDi+9
         8Dgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVvjma3mKFH95ZHAeTKvF2J3FaxMdRdosdc31YI9D8V1TGlZ+l6
	o4dgFIzrVTz6wdq5i3Iy7+M=
X-Google-Smtp-Source: AK7set+By2HNgO3T8MGyABImWPM94lX/5sxLgtrmpqcKB718YkbbGJcb4UhFY9DMt9y9MIOthKk1BA==
X-Received: by 2002:a17:902:6b86:b0:196:3b96:6a1a with SMTP id p6-20020a1709026b8600b001963b966a1amr34623plk.28.1674671950597;
        Wed, 25 Jan 2023 10:39:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:744d:b0:214:246b:918a with SMTP id
 o13-20020a17090a744d00b00214246b918als3377455pjk.2.-pod-canary-gmail; Wed, 25
 Jan 2023 10:39:09 -0800 (PST)
X-Received: by 2002:a17:902:e194:b0:196:29ba:ee49 with SMTP id y20-20020a170902e19400b0019629baee49mr2542094pla.67.1674671949633;
        Wed, 25 Jan 2023 10:39:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674671949; cv=none;
        d=google.com; s=arc-20160816;
        b=vOwap4cbdi1vYflV8KD2x5yVi13DhY0gXoZjxtLhrQ4/BX6zhUwfPX//C+AD0yOakj
         yCMNIR5R6m3Yk89Ra9U8VhMiJF5OMx4DagLvuhTjg0OUfWvXcvsPIF6K3myax2Uh+fRI
         cREzX4OVTiRc6BY7qA7JIH9e1nknj5Rw/t0jnushQ/nYq69TFE/QI10nR5H8rlPQcBAv
         RDQnZObwaj0JcMjzC/4v52T6sfhuOc/wt+XbAqwAbX5byMFtsv9Fps4ema12Kn71JkzH
         J35n+UzDRcGFHfEjamxX6Dv8Vd5QT/wwwSIHv6qtHkwGg0naPGIckmtCjk6wZQ1yoypL
         2bPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WhE3p5nMlMDjaV/irGLArTSJUCL3MW0izpTScdbc1OU=;
        b=cZVS6TSEhe3zHS8dkKAdNvuV3IgnOpdyod2w7aP4fbYRoi3o1oAF6odF7n80kfEk0j
         xC+AGDtGZsEpg3RhLuTDZbFCq6J1N0K6K40MtK11+UzBcLBXcVRHpIjKbFNkfeHR1gNw
         70jPbGrcGlPODIdgZz8EpnkFBc7EmvbwLg0IM+iUx80TRYtXAHFh54CZRccigWQv1bxw
         0JDyWy028/DaAJfGKExT9PgJvc4yadDlkX6a92fI4sTABKAp822Ukkj67uE92a5xKduY
         0ZF0xJ99SPb0YuDfr7f8QQkGujO1xaXIHgvlGqMJKUovu9F2ANmiBmoFh9lwULC96XEq
         QoFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=mx74wVm8;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id n21-20020a170903405500b00178112d1196si479802pla.4.2023.01.25.10.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 10:39:09 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pKkaL-0066XZ-MG; Wed, 25 Jan 2023 18:33:25 +0000
Date: Wed, 25 Jan 2023 18:33:25 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	mgorman@techsingularity.net, dave@stgolabs.net,
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
Message-ID: <Y9F19QEDX5d/44EV@casper.infradead.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-2-surenb@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=mx74wVm8;
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

On Wed, Jan 25, 2023 at 12:38:46AM -0800, Suren Baghdasaryan wrote:
> +/* Use when VMA is not part of the VMA tree and needs no locking */
> +static inline void init_vm_flags(struct vm_area_struct *vma,
> +				 unsigned long flags)
> +{
> +	vma->vm_flags = flags;

vm_flags are supposed to have type vm_flags_t.  That's not been
fully realised yet, but perhaps we could avoid making it worse?

>  	pgprot_t vm_page_prot;
> -	unsigned long vm_flags;		/* Flags, see mm.h. */
> +
> +	/*
> +	 * Flags, see mm.h.
> +	 * WARNING! Do not modify directly.
> +	 * Use {init|reset|set|clear|mod}_vm_flags() functions instead.
> +	 */
> +	unsigned long vm_flags;

Including changing this line to vm_flags_t

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9F19QEDX5d/44EV%40casper.infradead.org.
