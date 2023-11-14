Return-Path: <kasan-dev+bncBCF5XGNWYQBRBKPZZOVAMGQE3PDQMQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F7727EA9D2
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:50:50 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-41cc6c43cdfsf63959951cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:50:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699937449; cv=pass;
        d=google.com; s=arc-20160816;
        b=rfUUmOWoSI9YYTx1ELAqKjpbZN6itFyYT27+IT75DUYQsrhFOg3EwyzF37EpnId5+/
         aK04bkXkzx8JC2ikSVRrNjQQEg0wUO8274E4aicanHVGPWqzubHEbdvsUH1spFX0/Rz7
         0jRJrYm85i1+bvxpC2iLodEVN66cgRbKxVPNqqVGd7zNQS4qTn2Nfsx5co16jLhT3M0Q
         QPJ+DD3hrXOfGsL7V7x6lMOGUd0mChDYXG8AhFYXznw4KTsXxHCwnx1beees80RSCTNx
         RLzehpxJq42wNc2CPtIKWnAOAH/I4ckf/jsRGnjpDvO3kZLA9Crzdtno715UEKgVU7Y/
         +XAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WtLBqxjOO4scsqR30ALCc5UnGXsgyDi9fjDptgyOCMM=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=lpQ+SwboYz1WCB369wCIjVbXBvNDxMr/pVVgcIsWZ/zx1nuv0Qk9YrZECjtnKU0Hzc
         5giN6OWhSUJ61oBPzgHyVAKSg7uzJ8y0qBmNTBhanRekCA33kV27UTGsX1K2K16Pq20u
         Zj/Da+4drKhN/5nLzsOKTy8Vr8O4CBP/5V1B00YBgocWxQVr9LFiSxwVZFP3YWqJhU7V
         BhYV9iesD7P+izOlyszkZvQXuxWqMUpc/lcjhWnYG469VdvH5Z1ImgAqMrDjgenwGycX
         5bK1Kds+6sJunTiWfNHbqXuok6UpvX4glcUt5zDRIO+riLy1lYtHyqaxLCHCaXtQYDCh
         4UtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=djztyBnk;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699937449; x=1700542249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WtLBqxjOO4scsqR30ALCc5UnGXsgyDi9fjDptgyOCMM=;
        b=A9i8z39gvSHgzOAwe/rm2vIH2X0JkIflwdE2G9n6RhJ9FEh7iEVmx1uMcyhYK6w+0E
         Rem0+9NWqcgCpIrGdYe5CUUnu+OkctI9jzvGHvXbjTPCq25bqMrY00p0zcVJ9sCinfr+
         yCTzvkD3MhHOSJnefGPpoFVvgCANejWB9Q4ocEBZJ56jMAtVhrcIqxfcmV+L1U07cnPR
         +HxHS7jCawY2NfcMQKtsL52sL9YA29gI2eNRhHRUrJ9xZlIPLeTsyYdCYc7hTciLEi8o
         SX07A4nxAKuko9c4+IG1Hbh84HaJEXxtgbwP6r6YPkG4OJuCvit5/LJvcpYtu7133NW9
         CBNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699937449; x=1700542249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WtLBqxjOO4scsqR30ALCc5UnGXsgyDi9fjDptgyOCMM=;
        b=sDZxhF8k1kLYn2YGJtIqjHvk21cxUPxNMW+1n0KWIqvMB+3eW2zI3V4b66cFwCVafF
         50G8bRKxyN3o2a1vu9wbztaw3nv+mS50ThHMiQSkAKMWLBYv3Gt4MVuP2agQ/Q4/Vw0S
         Q9pSBsLnDBHbtF8zTRSwNhX722mefQuN9+glxAFEy1plMqS0p0Fm9CSR2LUo+ZGwnjru
         G41w4XuJUcXev9KPwxKW34sNZYddaTgxoUWELfN9aCfMk2S+i11tZX5AMaWlxsnDISL3
         A7GK8kSfXE5cLpyA6Q9Vk4OygVrUGog5xBw/JMfA4tGLVo2vdybx9JiKgVdJ63y0qe6M
         RLSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx7ct3/magGH1eyES7/JhTGDNOGqkx3QZZwr3+Nz4Zi/2nfJJTJ
	FM/w/buXZiASYzn4Hvv4WaU=
X-Google-Smtp-Source: AGHT+IFo52WZDhn1ACJmYD6xR92EvY965jziFJrc295C9bdJmB65Elvi44qEUwhhKDu2LNFe3kFjNA==
X-Received: by 2002:ac8:570e:0:b0:41c:d916:75d9 with SMTP id 14-20020ac8570e000000b0041cd91675d9mr1490646qtw.32.1699937449138;
        Mon, 13 Nov 2023 20:50:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1190:b0:41c:b879:6082 with SMTP id
 m16-20020a05622a119000b0041cb8796082ls1086508qtk.2.-pod-prod-09-us; Mon, 13
 Nov 2023 20:50:48 -0800 (PST)
X-Received: by 2002:a05:6102:2c07:b0:45f:101c:16d5 with SMTP id ie7-20020a0561022c0700b0045f101c16d5mr10026126vsb.19.1699937448461;
        Mon, 13 Nov 2023 20:50:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699937448; cv=none;
        d=google.com; s=arc-20160816;
        b=B//6fkV3ZpPWbJF8yHntpsShAzx9DLTCvIJ7Jlc+mIiaNla/TKuFIzpScthA84b1Bx
         k2+pyP4JXwOj16he0lRVfGmshoMKlo3LiPZRnmNFnU2dNpyuWlj8lUygs+EaBkd20+tK
         VqqwdQfWCijpTAK8FCAao0Ftx8e9kZR1bGZndk/mNarEIAYY77pBD5wl2sizv2hQad1j
         C+BidhsP5UtNofE0r6tB+TsNJa2MMOq4nPF3FwlXDIPJEDGPSwU/cIABmNoYvd9cjGBj
         15kzJf1iGN3KQOzZF1ItgmKAoRRFicDHxlKUjEDVpASbOdCjTfPh18NZJ5zNql6nYYjR
         CFoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gSHaE/1GVg9mC1SVDtWharYt7nYPJBYXesltql5ggN0=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=a6ErLlDUK7PqXeKpjZjvKb8i2YD4++Y9sYTqRuWj32kTDEjFUlZGrQoaW42wCQz8o5
         i/DuenEtSKhoKFFP4H7aNV9sus9tKDmYW1zVyfaOSKByBDeJwr68PTgRebYhyBMxf7mC
         FrnTjobqtHM0Re3vTqZy9ZBGKUtcc1rmUa8lZujfsgf5fWaRpuD/8zow4bwAt69E8kLp
         UuoRCFLMPbm9e/7fk/PlyT5ZbvTCq9kx/uTvgtN7JvUmkU/kWNR/P19BXTmW6zRNTw18
         Sc7bKWKYZVevfRI6XM7P58xY41OCtLroS0o6ZSkuNRtreEof9rZwhaZboKXr+P5et0SN
         Kf6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=djztyBnk;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id cd12-20020a056130108c00b007b5fcda34aesi870385uab.0.2023.11.13.20.50.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:50:48 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1cc29f39e7aso33002485ad.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:50:48 -0800 (PST)
X-Received: by 2002:a17:902:8b85:b0:1cc:474d:bdf9 with SMTP id ay5-20020a1709028b8500b001cc474dbdf9mr1243778plb.36.1699937447538;
        Mon, 13 Nov 2023 20:50:47 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id a13-20020a170902b58d00b001c9db5e2929sm4875757pls.93.2023.11.13.20.50.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:50:47 -0800 (PST)
Date: Mon, 13 Nov 2023 20:50:46 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 18/20] mm/slub: remove slab_alloc() and
 __kmem_cache_alloc_lru() wrappers
Message-ID: <202311132048.B3AADC400@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-40-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-40-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=djztyBnk;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Nov 13, 2023 at 08:13:59PM +0100, Vlastimil Babka wrote:
> slab_alloc() is a thin wrapper around slab_alloc_node() with only one
> caller.  Replace with direct call of slab_alloc_node().
> __kmem_cache_alloc_lru() itself is a thin wrapper with two callers,
> so replace it with direct calls of slab_alloc_node() and
> trace_kmem_cache_alloc().

I'd have a sense that with 2 callers a wrapper is still useful?

> 
> This also makes sure _RET_IP_ has always the expected value and not
> depending on inlining decisions.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> [...]
>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
>  {
> -	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
> +	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_,
> +				    s->object_size);
>  

Whitespace change here isn't mentioned in the commit log.

Regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132048.B3AADC400%40keescook.
