Return-Path: <kasan-dev+bncBDV6LP4FXIHRBOOV4KGQMGQESZC47EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 42627474517
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 15:31:23 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id lt10-20020a17090b354a00b001a649326aedsf15243799pjb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 06:31:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639492281; cv=pass;
        d=google.com; s=arc-20160816;
        b=egePxJs8YEx3riVZ1KieWTp1FVSR5PVxIeOZOhX/qpfCRLOZnEzB1yf58wkX1YlEMa
         N7DOco3fUGVE5XlQ0YG+y438Sk4qktcecbcM2Uh68/1ql/7B3D3F72xiat5b6dp26Vi1
         BkIDBIiQ3Isfo+WsZPqRS8fU6puxD2DybUu5h9xr8QRyHDfnOL4rRqzbEe8x0ZDmFqTR
         1ylT2Kbtm/XuhbW6y58SIKesgU7T1q2lHkigWki4UDx1IrjSbGx9A9mLYNrFLDw9taXY
         oyodSG2clgPidNyAHAP/fEMVip65iRwEBtMfYSJQhDfcIi3i2UrprL1q6xs7SgzH/n3c
         hz6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GIkSkxPOD60g0KF6e4wwY+zzOYJj//d3Qct+ch6G8qM=;
        b=ec03MgRzJJ8YQw2ssttkwbp4aRo1TCqxQcNrzJxg5ZI8kNvrZqjkz5Z9ILSso8sydU
         8IbcgIao80muOHPZ7gtL6YyTdDXf0IovSlItUxi8PxmoaLHuPdPVdavCxefhuOu/tiLK
         TzFHbGXaQgNFQm8n+DfjR9fo28UTEcHW8k/UJ+/0okAe3nXr+9Bwgsy3tJ3WDZ7B0xLc
         TbyWTuUfEqy8yCHMfrnEOct1lKe5aYRyUKMuujuJD51ZYrzQrE6A2P3UbKyfAZwce8pe
         xdk7IeAxpqNpAZ7Yflo1QCUviiiFF97kqimQs6jw71MN0lCC0a17MOLUAe0OPNNMG4ct
         qsGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20210112.gappssmtp.com header.s=20210112 header.b=wZQgz4iU;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GIkSkxPOD60g0KF6e4wwY+zzOYJj//d3Qct+ch6G8qM=;
        b=BpiO5b4rXOyQgSABxYxv2ydJukxqYHpIwdD+sANIXFqxcQ78B602EuHA/Kh0Nqxwid
         tl6LN+OMlvRCE0CFLYdkLag05m8GSRcLxtNVVD2xHYI945quGd8upzzT5oi96A+0Xtk+
         JHNjtotttpGH1ZZK52Xrr6NxNwW2NfzF0fQIMAr7HIGNk0eObjNb6pNltZtg90/9JxVw
         eOH8zTLroCf0ye4vkQuIu4CSiScgEd2jKlxRur0XDwG291+PJGgsdLK6MR98vQki+ra5
         //uaMt+li0tsteXaeA6bET3rX9hBY3X4L+YGm3qazC+LV43FE03fD1xgM3h2NF4J0wQz
         xDUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GIkSkxPOD60g0KF6e4wwY+zzOYJj//d3Qct+ch6G8qM=;
        b=IK2f95dJBvgtncmYWOvTQHThi5pkTY1UIpEkkmtXGZMArrwbkUOPUgOXhkesBsuRgR
         xEvSogKzN2MpUWK2E5z5fZX/TvdQMUmQxiZ9my8dpqcWqGOD1y10lL9iFyp+qLYz86tX
         d+LEahn+q1paRjpHa5YXJrD1ZaUARNYCtq7XzY0hb0YHJW3WhmiDLNxkfB+oel8np6AR
         OyUYfp/UXHRziY6N6tsylxRROoiDTzlQNZP++OgMhF/1pLNQyqipfTSSllIgkuKje1wn
         +W0N723+hCEw9ebVdxDc9a9jPpK8EH9o72dOo8cqDKMKyqeCv2KiKaHK4mAkrBxaP6NX
         0sGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qmgSrB21eahTq+MH+ONhxdM+vzKrnxPDdi9Plq8WUyqk+G6Kk
	s5yLrjla3IoryjX7+o8mF4A=
X-Google-Smtp-Source: ABdhPJzPaawxO+h2a1q9VCzd/KPMOoGuvgxNqGrl9lySrKqRIvq4lxSNft4lAwu25Fj2HrvOIjA5eQ==
X-Received: by 2002:a63:8a4b:: with SMTP id y72mr3932017pgd.1.1639492281432;
        Tue, 14 Dec 2021 06:31:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3ece:: with SMTP id rm14ls904519pjb.2.canary-gmail;
 Tue, 14 Dec 2021 06:31:20 -0800 (PST)
X-Received: by 2002:a17:90b:384a:: with SMTP id nl10mr6064414pjb.234.1639492280799;
        Tue, 14 Dec 2021 06:31:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639492280; cv=none;
        d=google.com; s=arc-20160816;
        b=AexSVgZnaSSeCqEXq+I77bvFuCBBRTTkVeAdw1THjGY0h6lDPh9z7JGndmBmAL2T3F
         Hqg2960dKmfo0mJW6/xkv2cctj4kB6DhN8xPsXS6envq5p39YUgeMQcaUqO0cgPqUZ7Z
         CC63DoLcDO2VpPiMejOSZDqfSzP33X9Sx9RsNCRMfclaaY9s63xOAeEEyQ+I7i2l+c6k
         jr9nM3RlCO+nUC53XFU7Ip7M3wmTd7J9HHr9uAPMxIOqr+1o90jnVBXtMbo7iCxloN8/
         9x+fcFWFf0Fy0DDgE1WDxvt50xT6872Mdy0a3+FC0FmU5pU2j9t6ZchIR7Ionq90puWw
         Y66w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PnyBX2cL3sw5aLNMKdlSdA2yt3vqpypZzbVoHtQrrVM=;
        b=VFVOqokBTe0vcWXMa3WnyBc+/37Wy4wZ+TcvE2zNUf44SsWjPQ3WgGn/+Trm+/Fl3W
         /knqV1KzhhF5iUWfuhRpupKP5f+RQNQ0VNWIKKqfPgNV9kYxa1NqgaRHQLUBiDAeD0U5
         LxMaDjEsbpwWFECoKBHNk9OSYa/t81BgD/vbQIJ5JHG5C61DWukHc8t1Nu/EGm2RDJXf
         jdkAhR1Q7Au+OoVK2A9b8+e6N+wlLYaycwEYvXDXKCR3bvMzHfk2FKMdDJ0h9ql+8Ebl
         sDsMxBgrC244W472sleJstp6oUlule8x+2vPVWXcS0xWI/qC56aA3IdfRbd+tiQ31v8d
         P2PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20210112.gappssmtp.com header.s=20210112 header.b=wZQgz4iU;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id w1si167643pjn.1.2021.12.14.06.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 06:31:20 -0800 (PST)
Received-SPF: pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id b67so16872880qkg.6
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 06:31:20 -0800 (PST)
X-Received: by 2002:a37:654f:: with SMTP id z76mr4207368qkb.224.1639492276068;
        Tue, 14 Dec 2021 06:31:16 -0800 (PST)
Received: from localhost ([2620:10d:c091:480::1:e1e4])
        by smtp.gmail.com with ESMTPSA id o9sm16361qtk.81.2021.12.14.06.31.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 06:31:15 -0800 (PST)
Date: Tue, 14 Dec 2021 15:31:13 +0100
From: Johannes Weiner <hannes@cmpxchg.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Julia Lawall <julia.lawall@inria.fr>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Michal Hocko <mhocko@kernel.org>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v2 22/33] mm: Convert struct page to struct slab in
 functions used by other subsystems
Message-ID: <YbiqseeMBeqbn5CR@cmpxchg.org>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-23-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211201181510.18784-23-vbabka@suse.cz>
X-Original-Sender: hannes@cmpxchg.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cmpxchg-org.20210112.gappssmtp.com header.s=20210112
 header.b=wZQgz4iU;       spf=pass (google.com: domain of hannes@cmpxchg.org
 designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
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

On Wed, Dec 01, 2021 at 07:14:59PM +0100, Vlastimil Babka wrote:
> KASAN, KFENCE and memcg interact with SLAB or SLUB internals through functions
> nearest_obj(), obj_to_index() and objs_per_slab() that use struct page as
> parameter. This patch converts it to struct slab including all callers, through
> a coccinelle semantic patch.
> 
> // Options: --include-headers --no-includes --smpl-spacing include/linux/slab_def.h include/linux/slub_def.h mm/slab.h mm/kasan/*.c mm/kfence/kfence_test.c mm/memcontrol.c mm/slab.c mm/slub.c
> // Note: needs coccinelle 1.1.1 to avoid breaking whitespace
> 
> @@
> @@
> 
> -objs_per_slab_page(
> +objs_per_slab(
>  ...
>  )
>  { ... }
> 
> @@
> @@
> 
> -objs_per_slab_page(
> +objs_per_slab(
>  ...
>  )
> 
> @@
> identifier fn =~ "obj_to_index|objs_per_slab";
> @@
> 
>  fn(...,
> -   const struct page *page
> +   const struct slab *slab
>     ,...)
>  {
> <...
> (
> - page_address(page)
> + slab_address(slab)
> |
> - page
> + slab
> )
> ...>
>  }
> 
> @@
> identifier fn =~ "nearest_obj";
> @@
> 
>  fn(...,
> -   struct page *page
> +   const struct slab *slab
>     ,...)
>  {
> <...
> (
> - page_address(page)
> + slab_address(slab)
> |
> - page
> + slab
> )
> ...>
>  }
> 
> @@
> identifier fn =~ "nearest_obj|obj_to_index|objs_per_slab";
> expression E;
> @@
> 
>  fn(...,
> (
> - slab_page(E)
> + E
> |
> - virt_to_page(E)
> + virt_to_slab(E)
> |
> - virt_to_head_page(E)
> + virt_to_slab(E)
> |
> - page
> + page_slab(page)
> )
>   ,...)
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Julia Lawall <julia.lawall@inria.fr>
> Cc: Luis Chamberlain <mcgrof@kernel.org>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Johannes Weiner <hannes@cmpxchg.org>
> Cc: Michal Hocko <mhocko@kernel.org>
> Cc: Vladimir Davydov <vdavydov.dev@gmail.com>
> Cc: <kasan-dev@googlegroups.com>
> Cc: <cgroups@vger.kernel.org>

LGTM.

Acked-by: Johannes Weiner <hannes@cmpxchg.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbiqseeMBeqbn5CR%40cmpxchg.org.
