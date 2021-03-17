Return-Path: <kasan-dev+bncBDDL3KWR4EBRBT4GY6BAMGQEHEA447Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id EB53933EBD8
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 09:52:32 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id k19sf19043930ook.13
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 01:52:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615971152; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGsL9pxKbGuGfEQpGvKiOziyuEJ//5u8GU9G+Z3Y64UNetWBMF7j3NT9vdbC6+Tacs
         ieQhfjBjg3exqPsvrIsOHBT34jZlIDRCSWdlQgrMVpUJu5KrpQq0b9PMFHfmipKvsO6M
         72wc/GWxmqXA2/yp6sPr9Upwx3qwMc2Zt36H9HhZQN7QPcniaFf20Kn5xNJ6xC3sXuo5
         yoDeqwphX4MncYvbhEui+6taDoufw9K8tcgaDWeSoBaccuXQ1b9oag6QztAcGA3hYjy+
         veVU8YY/uoQNMHhbumuXJW+i+KEqBWstlHUy2ji64+lNL2qTY/n0qjx/x95ilWOBQxDY
         KCbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=X+1Nn86c7Gh6dDHwP2rNVZgJvbchBdFHYICEG4g7BCY=;
        b=eNIjS9s/tnRpxmqTEgSdq1xEnHvTo6C29yrHXg5Ke3760lA6bs5mNwwrK6BM6kr+mm
         e7OGzXRDzGUzOunSlSfcPq7+fNyYBG02jWc58STNxKgfUoBueeP9ioX2j24mpvTY0gJh
         iEgVGk6P1S9HKGGAQGTcNZYKdNskHvQr4XCKp6VnWRr/RjozC3VwAZPw49yeeSGaCX5g
         OMaM+YzNwP7w9/9bzt70PbgPfA93NjbNMWuCd09G6Kofq4Mya8ljjb2ew76BKEY6N4xy
         9dfTeVFyUzv2y4wv7Kw7HF04EXTKunvYy1xwFQpbFHZ5NZKd0drgAKGCBfFg2cP5sG1c
         b3mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X+1Nn86c7Gh6dDHwP2rNVZgJvbchBdFHYICEG4g7BCY=;
        b=n2EVbCX1uO6bYbITYOFd/G/FJebey3km/50itlhVJowB3ojnt7ZbX34heLFvrJZ0Fc
         QTec3JsaEWow9fa6fDC08ZyqffREDM5KIRombC4nBfPStBRtHBIkVSq1SKp0S8Hc5DQH
         kKRtTxevlXr6pbdix5rg+e6nkHkzAzYZzOC0syGeoz35NBENXmOsmEgtuOJX6IMNeVB1
         nJCQo6u30G7sva4NeSoHaBV5lWbCyhNaG5ZvwShBlkCGhEtHaOCH6lS7e6T+gqlN9wkU
         TEFikNBzZB9CMBejAo1zv/sL+iSl6Lk1D8wVZdWEdxmpE0R9t8Ryjh8ckf6JVEoeGOf/
         at6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X+1Nn86c7Gh6dDHwP2rNVZgJvbchBdFHYICEG4g7BCY=;
        b=uJ6jLYZyWMR9rCHcqqlbuzO3Lac6f1Ppn+HqXajLgFY0hWCX3qlK7g0DS1o3WGvFSE
         0ThNbjzKGIE6uZTgbeYo7325rqRUQNZOj++aqlJ/0PH6ERohcgbVSE47IGSKxx6CDw3v
         7wkWWCZesxF2nqW0RdaMWeNWeIrL/hWJWNqOu6ujpOUrPshusaBkFvvDel+yUKuCxlTk
         dCA8AmJC2S2tct66bYXTARCj7vg/EacCVelbs9MPojo50yEbpt9SsIw82xQOwLusbsSR
         N5XIOUSOzPez80/3vFE6xR7c5C5uCW3vJz3UU5ncDCMTdjj3WYvm1H2UiD2HXq/Eq4CZ
         D62w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sOyBDvfdWH7AzgLjBvmq+uK+js0UvQFVNVvhdMR4g7dq596zz
	20OMbnTP8383iUxm+oB4eRU=
X-Google-Smtp-Source: ABdhPJz3Vpkkqx6BPR45c82WQE4IQ5hRl5mN2aHmp24/X4GnTqzowqr3cADb6Xb2eiMppcf0DF5POg==
X-Received: by 2002:a4a:d48b:: with SMTP id o11mr2503737oos.2.1615971151950;
        Wed, 17 Mar 2021 01:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4996:: with SMTP id w144ls5494871oia.3.gmail; Wed, 17
 Mar 2021 01:52:31 -0700 (PDT)
X-Received: by 2002:a54:4494:: with SMTP id v20mr2049479oiv.147.1615971151532;
        Wed, 17 Mar 2021 01:52:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615971151; cv=none;
        d=google.com; s=arc-20160816;
        b=yLspRVeDmsi6rYLSZoj7YMg16bsgBLZpiZyDZ4dNmS2e2/sQAed/hWUg4Tjry+07zX
         AgoNUqVhRGQmwi+q6Cx535yuM23BG1/KVQoJP+hW6tFZVrLgyxveyA4E1bhNp/ii0Jhc
         V0lL7yKPXrFnGyLsqrzvdUWMxSzxFQ6h9cBM6lgzGbBWfDJQobC/sGeAzz5ClgXuabjU
         esolWEBaAbkh7z2pp3yjtaDM0KxVsqnsBvPsS49FgZuol2Cg5vOWLBuAO9P+Z1zJIke2
         b24a6ZPkvaUacDZSTK6+ehx0Y7gbVzR4sJJPZDlr1iWCB4maX4pZEns+eljCsekAf+Tm
         jvPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/qW/VElwaqVTeHlKYyk2v3D3oBW97+vbqzwRAaAhJbI=;
        b=KcSFnWRxZD5ARv+11kCFk9EsVL8oOsNmNOyZi1VrCAYq1Fk6xIjOMpSv1k6rM83uDv
         osGFWOk+EtAyeY1KmT+sbREJfS3V2YXYag8m3RBD413OcpA6+ryWZUyzEeVzE8BNO7vs
         Lxnt5LFQaxiwZ/I6sBCJBvhA3fZ8WwutZ7wpXUzehWBm2YnZEQUoWuc1TFENJYrOG1/u
         U5yxOYcneW0iycRTvMvB9n4BB72AsWnyi6fKnPYVH6cqxclGYJ53sEjqsFdqMpOSxLhl
         K6VWhUsNZdZNJmj6PZcJJTjexwRUkTv7amwUvkzGAd0/a0gfxw301mo3rEZAandO6sf1
         pyIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h187si1172453oib.1.2021.03.17.01.52.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Mar 2021 01:52:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0ECE364E27;
	Wed, 17 Mar 2021 08:52:28 +0000 (UTC)
Date: Wed, 17 Mar 2021 08:52:26 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	andreyknvl@google.com, jannh@google.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Luis Henriques <lhenriques@suse.de>
Subject: Re: [PATCH mm] kfence: make compatible with kmemleak
Message-ID: <20210317085225.GA12269@arm.com>
References: <20210317084740.3099921-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210317084740.3099921-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
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

On Wed, Mar 17, 2021 at 09:47:40AM +0100, Marco Elver wrote:
> Because memblock allocations are registered with kmemleak, the KFENCE
> pool was seen by kmemleak as one large object. Later allocations through
> kfence_alloc() that were registered with kmemleak via
> slab_post_alloc_hook() would then overlap and trigger a warning.
> Therefore, once the pool is initialized, we can remove (free) it from
> kmemleak again, since it should be treated as allocator-internal and be
> seen as "free memory".
> 
> The second problem is that kmemleak is passed the rounded size, and not
> the originally requested size, which is also the size of KFENCE objects.
> To avoid kmemleak scanning past the end of an object and trigger a
> KFENCE out-of-bounds error, fix the size if it is a KFENCE object.
> 
> For simplicity, to avoid a call to kfence_ksize() in
> slab_post_alloc_hook() (and avoid new IS_ENABLED(CONFIG_DEBUG_KMEMLEAK)
> guard), just call kfence_ksize() in mm/kmemleak.c:create_object().
> 
> Reported-by: Luis Henriques <lhenriques@suse.de>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210317085225.GA12269%40arm.com.
