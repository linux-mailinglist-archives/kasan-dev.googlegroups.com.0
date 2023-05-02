Return-Path: <kasan-dev+bncBCLL3W4IUEDRBYPCYSRAMGQECOVN24Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1CE6F479F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 17:50:58 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-4ef455ba61csf2480193e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 08:50:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683042658; cv=pass;
        d=google.com; s=arc-20160816;
        b=OZaL49aD/Qbo+0xo2rFodpMXGqdWNtWbgO4UksZ07jyU3fkv7CMyyk2Et+XylV04uv
         LJJKTk3rJKOXdGDhAlKrMNb4UweQ9+/ID8wUKM/YyeN3NN6HrgdKIpypr/r93xnIAvi4
         mKiKOoXKaApgSILrXq+PIk9jIrcHdqUjDcLnq6vFY72cmfwf5LbJSdZLBAjod1rnTEj4
         SQLTNT6ocDyhYBeH35dzJRfVVlKSY5jwBwVbPGdq6+TByH3W0nTElRGXLuyDHNUrnvVz
         DEPhHUHdQFUya9K9ztgPUokLeE+Hiz/hVZBMcSuiRKdcX2CvHiWoKhyF48VBIGb1z3OL
         JdUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kBeJQBkHckGBZzBA6KhzPdtVSTa4uqBSasKioNTcOH8=;
        b=FWQLK2JayV6dQhh7YgY0/KJGDGqwD6ebJ6PDF35S4alT4UvcFckQG7R45yVRbP5fyS
         FbbhtGF5A5EET/b65CpL9UIc2dm3UABIZxxswxTK9HJFUu0DsoJv5Qw4zKLKaC0QsQyS
         X3n+l/t1ObfmB+UZz/U/z0ZRI9KxHjNAdX7FlgjzoypxPTqDod4LpLVp76lxyiaL7wOX
         DzuBOhHCWDinc65W88zS4kevuLFQXCeQUQOvoAfqrjFV52e8EepaEfr6Q+SW0Xz62PhH
         ms5V6Jox884OiNEkcqHpA1POuWyED6qEDai+MyfUKjjkMacokA50d8I0HI0CTuzZ5PCo
         0N8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=hpCWoQk8;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683042658; x=1685634658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kBeJQBkHckGBZzBA6KhzPdtVSTa4uqBSasKioNTcOH8=;
        b=jtBKYYffz6SIN55rBTyZr7mucmSdsP620+VcZGUJ5zq+lQ7qk5aRuqGuULhXUXS9em
         9FwAR1nx4kFNmnASb9aNViC7Osn48e1Q2EqTCUquDwOzedscZ/GWe7axq9ZMHCnr6Gl4
         tJ3bBNMvTRs/vdO0gz5NZ0yVMIWl9cy3+iVrrXdvOSRGUnTTioSlJLJ+6EJi2SJFBZAe
         EP2bLAVcCnH8UX+Rn/XFfUiQ1qaHl2xJbdzDgpncDwlz/TW57rU8OE/y7wYrBsKJ4WKg
         w8iKyhOd+p40wH+Thzbr/iAEcsCCopzCZE/4pNY0tdHvf/eysscwa4Ppy9vMFFzUyFlW
         RPNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683042658; x=1685634658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kBeJQBkHckGBZzBA6KhzPdtVSTa4uqBSasKioNTcOH8=;
        b=jvtHOuv27hRC46K8vv+svIbDpyGGwTRI3xbvRLS/n7r687ia87lMY/nwmqCAkpiJ3b
         Tn+U5g6bI5OHdVaN8lQkBLgce6TG0YIBd3BSpyRLxMcmwMCXkYRkaEHnDMb9El7i5ZGT
         mE/RMHeSaZa2KDIzeg/ABFqxZTbOjzGSeKFnYxTNlQdVLIpHz0tX4Hc5TB3EN3POo2YV
         3WScwfrzqc+Rwv/Hun1qnZkq+p/l5cbAwLa4FAxV10lk5JEZygf00PA8if6x0f8S5KAK
         cXH8HiplL9YLUEH5QWMutoOutkP8nvUxexX227ooPGfas9a0Ufi2dyersybD5AZ/MxPR
         brOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwCmS/1Ow9vgW+2yUScSRMHPMt2E2cF8lX+YuuZEDcU2KC/HKcn
	G5RiAyBFbtE3SHhEtUSiLJQ=
X-Google-Smtp-Source: ACHHUZ4KMFXC7KM99rGEnoHme1hToAUJp7nW+znUAj1sVweB+57uKeyDA3hUGYiX2wCPbGhaOJtMXA==
X-Received: by 2002:ac2:5990:0:b0:4e0:39f3:5b9a with SMTP id w16-20020ac25990000000b004e039f35b9amr92176lfn.13.1683042657785;
        Tue, 02 May 2023 08:50:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b15:b0:4e8:c8b4:347a with SMTP id
 w21-20020a0565120b1500b004e8c8b4347als778173lfu.1.-pod-prod-gmail; Tue, 02
 May 2023 08:50:56 -0700 (PDT)
X-Received: by 2002:ac2:5612:0:b0:4ef:e97b:46ae with SMTP id v18-20020ac25612000000b004efe97b46aemr105536lfd.43.1683042656433;
        Tue, 02 May 2023 08:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683042656; cv=none;
        d=google.com; s=arc-20160816;
        b=TQY0/QeKQtCYWM1FX+CK5qWpjTsbfsQwUKMhl/kjfMD2E+Ryc3CvcoscHQwHC7MuQg
         cX1vmzqos9jNKKnrZj/2G7aR+pvBRG53j63OXyDqQSCzYXTNDH8CROgIcIDiFHIjId5H
         8sNG6exc7V3ddIAKgaESNF0yXiX52XVZ8rvIzoUnjWT0EbuTKqvKlcvCVJF38W6+OMKe
         WnnNMvyVTh55fTrrcfrIounBQrFQTq3MoNPd8mlQhvyEOyf3hgI+YfQeXJ17L5ibQVjT
         ugNnK/Db/2QEzW5CMb+qR8A4RSnwEDusYJcPSuutsRdlPnnb0VULvFV+tXlZAuo+1MAL
         wV5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=gA8QupUtMGX0BAGjUh9A20qUx/lBJYF50Tf/D+3/ix8=;
        b=F4cJ/UpOlNE2UQitcQL87QjhCTjH8gJO3hWXR74VmEoAXkmUFiZzBD+2DzhrMrREFD
         292KTAOkG/ganDxZ2AFFGig305vNhZ7Vrhpcc0Pd1GDM0sW8S9EhoTnALt4dbaILMAdV
         pqvoiG4YYTvaQDO7x3GqTTvywMWamUbtTUNaLIZHBJgbQtHpuEM/7qemc7rjiDBckFeN
         I4nYqVshB/ZPbCLNhmFw5cY8R9xyQJCxhgCz3Ih66CJWgovUT3PPbGhY1aVYtiuJOikW
         9yVeLIfuUEfmgVxICwtOuSXmhdRXKzvDI4vzVKS5wxtbgThoFEhYE43403c6AUNEOGB3
         z/TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=hpCWoQk8;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id c35-20020a05651223a300b004efeb1773ebsi1685033lfv.11.2023.05.02.08.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 08:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id E369D149DFD;
	Tue,  2 May 2023 17:50:53 +0200 (CEST)
Date: Tue, 2 May 2023 17:50:52 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid
 name conflicts
Message-ID: <20230502175052.43814202@meshulam.tesarici.cz>
In-Reply-To: <20230501165450.15352-20-surenb@google.com>
References: <20230501165450.15352-1-surenb@google.com>
	<20230501165450.15352-20-surenb@google.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=hpCWoQk8;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=tesarici.cz
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

On Mon,  1 May 2023 09:54:29 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> After redefining alloc_pages, all uses of that name are being replaced.
> Change the conflicting names to prevent preprocessor from replacing them
> when it's not intended.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  arch/x86/kernel/amd_gart_64.c | 2 +-
>  drivers/iommu/dma-iommu.c     | 2 +-
>  drivers/xen/grant-dma-ops.c   | 2 +-
>  drivers/xen/swiotlb-xen.c     | 2 +-
>  include/linux/dma-map-ops.h   | 2 +-
>  kernel/dma/mapping.c          | 4 ++--
>  6 files changed, 7 insertions(+), 7 deletions(-)
> 
> diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/amd_gart_64.c
> index 56a917df410d..842a0ec5eaa9 100644
> --- a/arch/x86/kernel/amd_gart_64.c
> +++ b/arch/x86/kernel/amd_gart_64.c
> @@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_ops = {
>  	.get_sgtable			= dma_common_get_sgtable,
>  	.dma_supported			= dma_direct_supported,
>  	.get_required_mask		= dma_direct_get_required_mask,
> -	.alloc_pages			= dma_direct_alloc_pages,
> +	.alloc_pages_op			= dma_direct_alloc_pages,
>  	.free_pages			= dma_direct_free_pages,
>  };
>  
> diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
> index 7a9f0b0bddbd..76a9d5ca4eee 100644
> --- a/drivers/iommu/dma-iommu.c
> +++ b/drivers/iommu/dma-iommu.c
> @@ -1556,7 +1556,7 @@ static const struct dma_map_ops iommu_dma_ops = {
>  	.flags			= DMA_F_PCI_P2PDMA_SUPPORTED,
>  	.alloc			= iommu_dma_alloc,
>  	.free			= iommu_dma_free,
> -	.alloc_pages		= dma_common_alloc_pages,
> +	.alloc_pages_op		= dma_common_alloc_pages,
>  	.free_pages		= dma_common_free_pages,
>  	.alloc_noncontiguous	= iommu_dma_alloc_noncontiguous,
>  	.free_noncontiguous	= iommu_dma_free_noncontiguous,
> diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-ops.c
> index 9784a77fa3c9..6c7d984f164d 100644
> --- a/drivers/xen/grant-dma-ops.c
> +++ b/drivers/xen/grant-dma-ops.c
> @@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct device *dev, u64 mask)
>  static const struct dma_map_ops xen_grant_dma_ops = {
>  	.alloc = xen_grant_dma_alloc,
>  	.free = xen_grant_dma_free,
> -	.alloc_pages = xen_grant_dma_alloc_pages,
> +	.alloc_pages_op = xen_grant_dma_alloc_pages,
>  	.free_pages = xen_grant_dma_free_pages,
>  	.mmap = dma_common_mmap,
>  	.get_sgtable = dma_common_get_sgtable,
> diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
> index 67aa74d20162..5ab2616153f0 100644
> --- a/drivers/xen/swiotlb-xen.c
> +++ b/drivers/xen/swiotlb-xen.c
> @@ -403,6 +403,6 @@ const struct dma_map_ops xen_swiotlb_dma_ops = {
>  	.dma_supported = xen_swiotlb_dma_supported,
>  	.mmap = dma_common_mmap,
>  	.get_sgtable = dma_common_get_sgtable,
> -	.alloc_pages = dma_common_alloc_pages,
> +	.alloc_pages_op = dma_common_alloc_pages,
>  	.free_pages = dma_common_free_pages,
>  };
> diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
> index 31f114f486c4..d741940dcb3b 100644
> --- a/include/linux/dma-map-ops.h
> +++ b/include/linux/dma-map-ops.h
> @@ -27,7 +27,7 @@ struct dma_map_ops {
>  			unsigned long attrs);
>  	void (*free)(struct device *dev, size_t size, void *vaddr,
>  			dma_addr_t dma_handle, unsigned long attrs);
> -	struct page *(*alloc_pages)(struct device *dev, size_t size,
> +	struct page *(*alloc_pages_op)(struct device *dev, size_t size,
>  			dma_addr_t *dma_handle, enum dma_data_direction dir,
>  			gfp_t gfp);
>  	void (*free_pages)(struct device *dev, size_t size, struct page *vaddr,
> diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> index 9a4db5cce600..fc42930af14b 100644
> --- a/kernel/dma/mapping.c
> +++ b/kernel/dma/mapping.c
> @@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struct device *dev, size_t size,
>  	size = PAGE_ALIGN(size);
>  	if (dma_alloc_direct(dev, ops))
>  		return dma_direct_alloc_pages(dev, size, dma_handle, dir, gfp);
> -	if (!ops->alloc_pages)
> +	if (!ops->alloc_pages_op)
>  		return NULL;
> -	return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
> +	return ops->alloc_pages_op(dev, size, dma_handle, dir, gfp);
>  }
>  
>  struct page *dma_alloc_pages(struct device *dev, size_t size,

I'm not impressed. This patch increases churn for code which does not
(directly) benefit from the change, and that for limitations in your
tooling?

Why not just rename the conflicting uses in your local tree, but then
remove the rename from the final patch series?

Just my two cents,
Petr T

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230502175052.43814202%40meshulam.tesarici.cz.
