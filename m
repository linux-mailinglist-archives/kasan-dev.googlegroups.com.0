Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLVCS6FQMGQEMB6ZUPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id D2BC342ABB9
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 20:17:19 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id l10-20020a17090ac58a00b001a04b92a5d4sf154568pjt.8
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 11:17:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634062638; cv=pass;
        d=google.com; s=arc-20160816;
        b=wBksU4VHLlU2TLz7AccLCz7IRezsHPDGNBA3j/LJM6IWcu7cVVqYylTjwcWhArMJte
         9eq6b8dbh9a1FfjJK1EW0VkJ+2MVnmE1O+roSGlXjI8T7p8jcSpMvG6OdrPcAK4p1/xT
         VAYLrV6jEGgaH6qqoG/EpBxPIalCevhE6FQB84U9Yao1dddF03mEtlckxPXQMvhppblm
         Kn2XbIOoDMxymkpyLWnIX2VN3zJjJzBiy46Vsce78H/Vju2npZz5h+8KofrWyPDRTO8I
         krBjHpUlQHrbW/TfKmrUsYRR+hE1TUSl8mUwJbES5RQXZmPf/mfYYJdmFBaxUCuoBv5I
         ixug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rWL+kODa5tGcMd2PrcXgJbP+vXZvSvWjhIFHRkVZhNk=;
        b=KsIL4NX4LkG69k74+Yz5wiSbPgQIjSbpTpzMt4e9E/dTZi5HzYBY6JJDHA4sNf6Qaz
         th2qORPo92TSy6j2WzAFEde3kBkOBM21Lq+YPGxsbHW9pdljdEAwgYLJl12jQTZU1aLG
         A+LC17NJPbhW7tuqyircyRqafnvWeftlv3VuU179PnzuCZckrMI5MF44G1/8VDM5iFRa
         viF0YYPm98ET3RNzJSbQWtjzIEOBgucoqYHI9v/9mnS/1HLWXuldwIrenY9zGVfl8reI
         XTT3a0cYnGtBgn7BcAFtKDJo7rJ598WmNW53iIIq7XAziEt+1o8cbrK93JFYORDuHFt6
         Z2jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rWL+kODa5tGcMd2PrcXgJbP+vXZvSvWjhIFHRkVZhNk=;
        b=i/+F5Fx/cpLit1zurX2ATqCOsphIumYs22Ko2q1EjoHO11qwDR6IodqEKxU+GdplKW
         iOEI0N4Zevg37niWudRJGQF4Eon4eQ9eZVfq9U0NJE7Lrews6T8LcatbMKlGLbMVPasV
         xtmz3Zk3EhKeJJPbTa/CsDrJYSsmfOWCZ5cLtAjkFOTHdYoDNl/m4giJ7qO9t36dIXJk
         RY+AhStrRuNHwiPDyAH2N07R9YQHI4E2UJqsEMTLOA8AcqAAXJrUrix40UvMFrwLm5Ef
         SN/qUS+y/Y/A0nMMP23VdENMZohuoZsDhTJG+aXgCwEgurNVYNlae2XQs89n5Wq5KUK3
         0Q/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rWL+kODa5tGcMd2PrcXgJbP+vXZvSvWjhIFHRkVZhNk=;
        b=rstJ6Ilysx3Bo/o1qE2MLQTU3MNU7LsPLd3NwbANrld1kW8nSj8+OVNdpEFovZ1+V/
         DluJjaD/YvDPYHcBSjrhEApH8YviFWz7CPLeMibI14dANkAcug6ZobwXPh7xeis6TLZW
         CfKqA5tEHxK7dEP5dA1PEDj3OjKZuf/onkiZMx3feccs5wLO9lOGGxrljsCYcZurOv4v
         d/lwkFdCHJUgBZNUKP5qtORukMYGJZaHUcqSRNx7Ip8XS/QdQdr7Ol/noV5gS9qyETtH
         TiGNyuZAXfG9zBb/Usa1AXlhNtYLsvTlEbKzkc/m6Ar3qDoa+GINmE1E8nKn9pwSGQ1b
         Qmcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gPOQkG006QN7wdF32kNEueJ2sP60Y+Qj/+XLjvqXcM5YNWTKm
	cpA3pICyJc8V8nbJ5k3FlFg=
X-Google-Smtp-Source: ABdhPJwHMzYeb28cK9UZUAIi6pAttllITsjMMnQ0leQ32Eg0bCxldou+CDIqavSORQkUGbu+d1/KOQ==
X-Received: by 2002:a17:902:d2cd:b0:13f:14dd:aeff with SMTP id n13-20020a170902d2cd00b0013f14ddaeffmr26107466plc.67.1634062638325;
        Tue, 12 Oct 2021 11:17:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:815:: with SMTP id m21ls1088509pfk.9.gmail; Tue, 12
 Oct 2021 11:17:17 -0700 (PDT)
X-Received: by 2002:a62:3893:0:b0:44b:9369:5de5 with SMTP id f141-20020a623893000000b0044b93695de5mr32946026pfa.40.1634062637650;
        Tue, 12 Oct 2021 11:17:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634062637; cv=none;
        d=google.com; s=arc-20160816;
        b=p7aaph4IgxNoZKK0b9OTCZpXh03EyVZxNUjrz0FGXyFZ5JF8JXUlgsN/U7RvyYzKNx
         nuPohFLdmh08tVooEQZrncPO7FTBtaeXfwuXj7538cXMZOgUesH1RsYWf/K9/QQsU9hg
         SMnlpcHb615mUjobAQFOSkviWsdSPBWMPbilJ5m6nevXxQOquxT3OUmoAWsq2eQVHNvl
         dJzllDosBv3SuHx9SuBXhtR6aKjQrArtsTNtEK5rib1dfguvCYZeNMlhXhueL9cDHXTs
         CmGlxV6FUwPpAFihAxiq4/XQU+CcVPYg6VxTSxbWtfZl1nfjHnw5GHxuonqv5AXkHK2U
         lAmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=dqyN+Jpe1k7+rgHzXetmi/PPcnOIT5dkEihb0HVp+yk=;
        b=kpXZk9Mw3r+6qj7aFQXgsaABQsghB2HBZGcbA3soG+ysBhOYSAoMGEFCjVEhDXBsED
         qbbk/VjV7AO5aRWqFfuocgpL5hJx+WOPPi7of//co8kWlRfxaYiWIvbAniBKFYGwUL2g
         xdaIsXwlO8ZnoqVdTg/UKc0FMrzQ/e70SfLMt0tORMQ0jerm7FHFQEebNLv6nBsw1yPo
         X1LoCg/IJjGqNFp/2wXklh0Ym0RkyFQJaYqhEjhRpMR2ijwq6ADgxfei5GoB8EM3YaDj
         Xr1kMu/gYaZ8AnJyNEA6K6mHwlv86e6kvT6fNynzLiwha6zq4Ea8HDosyw29siqsJfWt
         Orqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y12si814940pfc.1.2021.10.12.11.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Oct 2021 11:17:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7A93560462;
	Tue, 12 Oct 2021 18:17:15 +0000 (UTC)
Date: Tue, 12 Oct 2021 19:17:12 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	dvyukov@google.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, elver@google.com,
	akpm@linux-foundation.org, gregkh@linuxfoundation.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
Message-ID: <YWXRKFrGSkgLXNvt@arm.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-4-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210910053354.26721-4-wangkefeng.wang@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Sep 10, 2021 at 01:33:54PM +0800, Kefeng Wang wrote:
> With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
> 
> Unable to handle kernel paging request at virtual address ffff7000028f2000
> ...
> swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
> [ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
> Internal error: Oops: 96000007 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
> Hardware name: linux,dummy-virt (DT)
> pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
> pc : kasan_check_range+0x90/0x1a0
> lr : memcpy+0x88/0xf4
> sp : ffff80001378fe20
> ...
> Call trace:
>  kasan_check_range+0x90/0x1a0
>  pcpu_page_first_chunk+0x3f0/0x568
>  setup_per_cpu_areas+0xb8/0x184
>  start_kernel+0x8c/0x328
> 
> The vm area used in vm_area_register_early() has no kasan shadow memory,
> Let's add a new kasan_populate_early_vm_area_shadow() function to populate
> the vm area shadow memory to fix the issue.
> 
> Acked-by: Marco Elver <elver@google.com> (for KASAN parts)
> Acked-by: Andrey Konovalov <andreyknvl@gmail.com> (for KASAN parts)
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>

It looks like I only acked patch 2 previously, so here it is:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWXRKFrGSkgLXNvt%40arm.com.
