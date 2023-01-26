Return-Path: <kasan-dev+bncBDOY5FWKT4KRBVVFZKPAMGQE2LZJRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8D2967CEB9
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 15:48:55 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id h9-20020a1ccc09000000b003db1c488826sf2932288wmb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 06:48:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674744535; cv=pass;
        d=google.com; s=arc-20160816;
        b=A0Pzjr9p7Qk7LNEICBd70v9LXwV+rkg8nPhnxxtRKtTb2sKy2RY7b7MhpNEN02L8ET
         cMu9ZqZEqyko4mog6TbOgn7T9Ymi11wM3t4W2wdkhMW9Nk/TmpGlasiZsLd1aniFtpCa
         FHzyTXiKir9T1CctAJ8IA33/Q/W7IodQs28mhkP0oNkUOOsmS/Sxz6xmWT+V3TU/oJ5Y
         j6KgdNQ8cedoUxQEgEkNpI9Az21MziWzFSVY/T/6LaXQiCGwELqAi/5e/PxYrR1wou8g
         HK/vsYHznRAdQs2gqIHu57NJ+4xO3feWi2mtEx69dILtbqleq7zA2Ska9zWeQ1f/hAyl
         yj1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GEhnQTfQu+BCCqAyxBSHhe75QA5ODi1NiALbAuoHG1Q=;
        b=Z0mEdWskfwBHfbETHBEtFMgQB9vzu/j58pM1tRFbNHvVzMcXo+5CtuBtsA52TVCuct
         Hi0y3paABpUef6qewizP/FtRNqoCemyCguXmpKCzTghxXAnX7+k8KFvU/9o/z0TSRNjt
         W/j2LzE6uYtlpdsMvEfxaBZ/p6IiCwN8TJOz3F1F1nWFnaMKCmgTJr0l1rws7pQXbTWG
         EnqEMuNzJZR7ROIc7qO57MZ8Yom9/SfEvFpGS1TP7lpPCUiO4M6wngNabs/kHCS3Tip8
         5MWsNESp9idwX1FYmlv641PNaXES82tOgkwxHNUG03/le3nLymw7RJ75h7j/7kDdIDJk
         Us+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OyaVsT5e;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GEhnQTfQu+BCCqAyxBSHhe75QA5ODi1NiALbAuoHG1Q=;
        b=ZCO4ehfjEe9O3+bEixxcVazdpnB88vr8mgR+UD9uN9FsVNPRmaVqbvtQNnZRfCzagq
         jAjRGPbVEsu6dJDwYqygKY80zQdhFB7l8I1xXnNIMGGkJzQjtnv+4gSqkH/DabSt8YM6
         OE/2SLVLXHBNzqIbHBxVdljAnYCAvQqa8CrFNEhNtlwuOEDw6taVF/tdCzd+MyMWJmlL
         4462bO57yArEA4JRfQXAEszsX5KB0Ng2l/sBaJlSJ84mzV0jEXPrEN9AGZ1q85LpG6Ta
         6HgISVqNFuWsDXdhkCH5RLIoXIfvws1itntbMbiEB6qyawo/+rdVQK2ly2j+a927UpcK
         kaJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GEhnQTfQu+BCCqAyxBSHhe75QA5ODi1NiALbAuoHG1Q=;
        b=PtcF3oKRQwIMEllmNObl7O+LY8cQhyR3VkQ1fiHmTBvVlO2bN1z93sADkjxY6KfLAb
         iihYL4PsI9HUn/gEG6h924SfD2ivdANsVGpcV7ph90j7eZd0BfTyw0c82ZVhxapZGN0D
         VcNKVgzzJBuC/li4EDHncSa26LLLd/a9SA91m1ShEFDSSGBWj93dYlEDKBrqOaCva9Me
         ZGzRyZfjWyiU4a7aj92QuuL6R8jP7D3fvIKv/hQMxesweDjWI/awHfRI6z8fxaMbm5tY
         0kp8rcqX9b9pVn+ck4Uqp7JQST2hXk+zSz6adD5tQfrQcOJLjFMstzIjpRjjv+iQscex
         wUQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq+nG1FlxE5y5wENOT72sf34lD+u3i7gUrjqy/Ssr/YVAw5G0QI
	A2viBLwnvRF10AxIvkNDSMQ=
X-Google-Smtp-Source: AMrXdXtMhpO710y1/HsGwK1CGi2rtT70gQYOOfmp/Iwo+LY7dWCzpg6AmoPElvDM5/FLFi7Vk66DIg==
X-Received: by 2002:a05:6000:136b:b0:2bb:e864:7a2a with SMTP id q11-20020a056000136b00b002bbe8647a2amr1237582wrz.218.1674744535119;
        Thu, 26 Jan 2023 06:48:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da5:b0:3cd:d7d0:14b6 with SMTP id
 p37-20020a05600c1da500b003cdd7d014b6ls1217118wms.1.-pod-control-gmail; Thu,
 26 Jan 2023 06:48:54 -0800 (PST)
X-Received: by 2002:a05:600c:4fd3:b0:3cf:7197:e68a with SMTP id o19-20020a05600c4fd300b003cf7197e68amr33380959wmq.18.1674744534160;
        Thu, 26 Jan 2023 06:48:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674744534; cv=none;
        d=google.com; s=arc-20160816;
        b=sH/L6pVga1c9uGk7JVb2eiKWvdClKY/+g4Lo+fMpQjDLXGLjDCQB7fuWtPvmgqxcqI
         imFZopBILkT2KlwrTgX1OYAvNDMQb8lNM+UPDjpYPUku4aq4xb9ftiKjyh2HA/nClGoC
         uvrr5AtZ1yGm1JC3em8yls6tbNprnPdGX3AVOcP0CwPUITAz3+Aj0bpYYpsFa3YMSAny
         TwmFq2Aav6q4Zco4QDxtskH53zOxSJVK/gEimEc+zOriercaCw+4b+k+F4Xm57Dg61uR
         uL3qBbrBdMFDad8pFiYj9QH7agrdDGemasNCCSTXESWGHOxJKvKMGoouNEBwZv3YIM3y
         i9Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fK+Z6q5CCrbSGUGA/VU77diV1gJjJKFGcQC7IYueLvo=;
        b=tV5T7TQ7gdSohzvdaWs3kCCeLz8CacjaHGE0whzvWDpdKwDFyQ6MwZGYMf132HGhV7
         uqLqSCegNqZqpgoxwC8vhkEPeMcNMngh4Ye6V4NwiHY4VApTTuIQySi26USZeMf82NWV
         CCPQPb5Vh7TOqfYqwkS1zFVUcGO4rNzu31WIpvIwd83N/LJjnkYsJwXPhDAZEFAxeKzq
         DS1yB3J3R+U5XSNEUbglpMCDaxVQtpfTvhjTkD/nVI+nLfAdojeHwdW+pHMtsM8tYVMr
         /6P5hMHKOeYT6CfMuaZK7Bpu/mLiu55ubYylatSLq1cWrNoKMVUOeScvoqkm0sLkd902
         TOFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OyaVsT5e;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id az13-20020a05600c600d00b003db0037852esi594616wmb.0.2023.01.26.06.48.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 06:48:54 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A5903B81D69;
	Thu, 26 Jan 2023 14:48:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 05241C4339B;
	Thu, 26 Jan 2023 14:48:14 +0000 (UTC)
Date: Thu, 26 Jan 2023 16:48:04 +0200
From: Mike Rapoport <rppt@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, michel@lespinasse.org, jglisse@google.com,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	mgorman@techsingularity.net, dave@stgolabs.net, willy@infradead.org,
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
Subject: Re: [PATCH v2 6/6] mm: export dump_mm()
Message-ID: <Y9KSpNJ4y0GMwkrW@kernel.org>
References: <20230125083851.27759-1-surenb@google.com>
 <20230125083851.27759-7-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230125083851.27759-7-surenb@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OyaVsT5e;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Jan 25, 2023 at 12:38:51AM -0800, Suren Baghdasaryan wrote:
> mmap_assert_write_locked() is used in vm_flags modifiers. Because
> mmap_assert_write_locked() uses dump_mm() and vm_flags are sometimes
> modified from from inside a module, it's necessary to export
> dump_mm() function.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Acked-by: Mike Rapoport (IBM) <rppt@kernel.org>

> ---
>  mm/debug.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/debug.c b/mm/debug.c
> index 9d3d893dc7f4..96d594e16292 100644
> --- a/mm/debug.c
> +++ b/mm/debug.c
> @@ -215,6 +215,7 @@ void dump_mm(const struct mm_struct *mm)
>  		mm->def_flags, &mm->def_flags
>  	);
>  }
> +EXPORT_SYMBOL(dump_mm);
>  
>  static bool page_init_poisoning __read_mostly = true;
>  
> -- 
> 2.39.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9KSpNJ4y0GMwkrW%40kernel.org.
