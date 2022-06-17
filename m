Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4UWGKQMGQENZGYLNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6191554F453
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 11:33:00 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id k34-20020a05600c1ca200b0039c7db490c8sf1972933wms.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 02:33:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655458380; cv=pass;
        d=google.com; s=arc-20160816;
        b=rqUCLtZofEFKbH3Ub313FchV8RC+THJHzd08XJDvXs46BlUFwiFaNqZU5n1NRUtpey
         sY2hjgXL8vY30Ul7I/FlhJ9X+Z34GJT9tTlw6az0wRuiTGP/vI79brSoVe7OnUj4rowp
         m6DVwOgx3h1HWj49rnldBFAgyIOC+X113nZqd1nb3Zse/yHoyCT2l9B47hCvNPkMAwcj
         wCSdCi3+Z5Ay1Vl8ALS9MkZuW9wRT5p11njMqDqjmjqyUfK9uingsEzA0PD+tEznvoHu
         C0XRuCjQLJeaLY9t3SEllmkC5n8rD2IDQ5AnL3XMPldq8BJ73VWROZnkJ+dkUHfsE87s
         psKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0uMaVxQfPMXB6myffnCiBe9RqXwJl5w2kXpNz67uTv4=;
        b=YMmHi0NmSVAgtuSMT9tU2JsI6Z4AJ1Qk+IOVHOASJqNjKsXcCVGjJQKCDxnc7koi+t
         4FvBbR4Q4/RAWusGD+YhCjMlZdKzO9+adgoYoxNangTb1sy3AL934OlNJbg18AXxuHBg
         jnTb0BZXxeMrHLhoLrJgj1XVwvWZ34yb1tMsWJ8Rr/KcfDFta5Yzr556qlEQiiFqyDXO
         tKiQzS23f3Kf4S6vNsZ4M/QScuL8nQjK8fMmNSe+GhopCZ7MspE4qqAPKBI1AjtpDFj+
         GeKRSW0JWerEbOFleE7FgODdTyTxxA5dR1WDarULpxzR28UAKGhcZjvDApoGFOaInrBa
         TEuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BIPKJRz2;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0uMaVxQfPMXB6myffnCiBe9RqXwJl5w2kXpNz67uTv4=;
        b=lkzUSzJX1uybS0ncO4qxZNSH4fibbbgLz4PACPf7bhlFPmJJ0YwuCQMyVq6+VIuJUn
         /eMxbkeBFVmNL2bwuK5SMMd+m62cana4evj9IrzfMG7vBevGgRHWnCfbR+RXQ8l3LGhW
         7VMrk6vEMp3Edj/yV2e2HEt5NM/tYW7nH9Q6/CmaIDRTmZtOtdIT8zFQrKf+JNAqIoGQ
         hkjnR8G/dgxWewCejbWFKqPoI1hm1yOvBAx7XapajXT7IFdviPnQz7D/bpki615xDGg8
         7AF1P7JVUgZeUFJfpTRWyij1+AY4wBlFIGzn+6Qr0rN9XQ2UqTjhgymQWaJ+86TkgO3D
         QpGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0uMaVxQfPMXB6myffnCiBe9RqXwJl5w2kXpNz67uTv4=;
        b=Bcvk7Up/FGtKoLPReenFHKTdCUe5Dct7PAlYQLG/5iOppICIgO+lHK9cYxdKSiZIKM
         RfxdPPJQc3IQy/YJh99g0bXfa0cTjajBrNA0H8vcC4yZfC3FYFihOtlJ0BeBkN3MhlLM
         u/FGoKA1go4JeR9A1OMhJNTbXPbdqEFxThei18RGwH5baUok5beGU+98YzDfpGFpCafT
         eAlrshfqKOU3nSDtb2fSyMGJC+bRErjDOTt6F/WYIjYkuwfQ4qSIWHKz4WCND3cpmMcm
         7pya8tmbO3lTRiQMyku0qeiQJQC/x7dHoPWIH4EVE+l3yOpuOtKuzQYhBIpuQUxGY8/u
         uh3Q==
X-Gm-Message-State: AJIora+v5VHPRSR0GvcyHu+o37e3/J/najTAitEXYw5QeuonVbH7QLyk
	Q8OAk8v3iKuXX1tR++rrBrY=
X-Google-Smtp-Source: AGRyM1tFfRw2ut1CdX9RTec2hGNJvdPpLv5wfAN6qRXU+Hd7ryfCfTQ9F8DSPTXfvj1f2PJNLhkaFw==
X-Received: by 2002:adf:d1ea:0:b0:210:3e1f:3ea7 with SMTP id g10-20020adfd1ea000000b002103e1f3ea7mr8560200wrd.595.1655458379817;
        Fri, 17 Jun 2022 02:32:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls500169wri.0.gmail; Fri, 17 Jun 2022
 02:32:58 -0700 (PDT)
X-Received: by 2002:a05:6000:1f86:b0:210:20ed:e2c4 with SMTP id bw6-20020a0560001f8600b0021020ede2c4mr8421938wrb.200.1655458378544;
        Fri, 17 Jun 2022 02:32:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655458378; cv=none;
        d=google.com; s=arc-20160816;
        b=OkISMoafSKlLgjB+HA0YRA5WzSie0b7EQZpB2QPDTg0ZNC8ecPZHre6BW01T0w12PB
         lMO3e0EY2zPf9ee2AyQFySFNp2+GInjebx1NaCTNwwvxcnh4tNajAXRnKKZB368mes/D
         TGZngFIA32j3Ktkmdt+Pl2I6M4VXt4E8Q8D7gJSXy93aBCeoLq/qI4dGe79TKiGxM2DL
         7GBZk8uh9JO+gbA6M1XVAP2F6PjHq6l01AnJ++VWwTFSqNFt0JhSkd+7dV327rwTbjNc
         Q+imyqwgMlyEtK4Z/nv68QtU9ellnqx7PLTGicJysbqqo20Xud65WYAPodOLYWvDo9CQ
         AjYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8tIgYOlZc8Rzi7NZd/7vIlN3v4vuKLtpWjp+gizjnUo=;
        b=r/3lXzvuoF0ZDYsyfDuItBa+4EfU5ZJ5qUEzHot4gQdkEVEIiu7H7K/Hnd7BeeN9mz
         7qRAmeHXc1gqv8YM0gunDkw9jEOvOjpSEBa1c5NoaD3nuQzYSUNqdsxHf2nlExl2rNyb
         wEGXvcL6ltD6Y5JIk2GNnkkYIwZHaY9Mv3jGNA5j7v6oR0ob3lZ77NzzUjWxX5IK2huP
         c2Glp9/JG/ccXixLZ1YoINGqOaHcLVEi2GsNks2S267qc+aTZZP5FUTmd8US29BNKQzj
         8QL2j/mjyY+MG9faC2H6r2ks6LXwTqI1DhnaMlD7GAHg3OJKgyHmfmd7exux4gyeo8e1
         ju4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BIPKJRz2;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id f15-20020a7bc8cf000000b00397320af7e9si393186wml.4.2022.06.17.02.32.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jun 2022 02:32:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id s1so4993974wra.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Jun 2022 02:32:58 -0700 (PDT)
X-Received: by 2002:a05:6000:2ab:b0:211:7fef:7730 with SMTP id l11-20020a05600002ab00b002117fef7730mr8132727wry.533.1655458377918;
        Fri, 17 Jun 2022 02:32:57 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:17af:cc9a:8d7c:f5cd])
        by smtp.gmail.com with ESMTPSA id r17-20020a05600c35d100b0039c8d181ac6sm9266582wmq.26.2022.06.17.02.32.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jun 2022 02:32:57 -0700 (PDT)
Date: Fri, 17 Jun 2022 11:32:50 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 00/32] kasan: switch tag-based modes to stack ring from
 per-object metadata
Message-ID: <YqxKQpjJMwUCpbTt@elver.google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.3 (2022-04-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BIPKJRz2;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Jun 13, 2022 at 10:13PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> This series makes the tag-based KASAN modes use a ring buffer for storing
> stack depot handles for alloc/free stack traces for slab objects instead
> of per-object metadata. This ring buffer is referred to as the stack ring.
> 
> On each alloc/free of a slab object, the tagged address of the object and
> the current stack trace are recorded in the stack ring.
> 
> On each bug report, if the accessed address belongs to a slab object, the
> stack ring is scanned for matching entries. The newest entries are used to
> print the alloc/free stack traces in the report: one entry for alloc and
> one for free.
> 
> The ring buffer is lock-free.
> 
> The advantages of this approach over storing stack trace handles in
> per-object metadata with the tag-based KASAN modes:
> 
> - Allows to find relevant stack traces for use-after-free bugs without
>   using quarantine for freed memory. (Currently, if the object was
>   reallocated multiple times, the report contains the latest alloc/free
>   stack traces, not necessarily the ones relevant to the buggy allocation.)
> - Allows to better identify and mark use-after-free bugs, effectively
>   making the CONFIG_KASAN_TAGS_IDENTIFY functionality always-on.
> - Has fixed memory overhead.
> 
> The disadvantage:
> 
> - If the affected object was allocated/freed long before the bug happened
>   and the stack trace events were purged from the stack ring, the report
>   will have no stack traces.

Do you have statistics on how how likely this is? Maybe through
identifying what the average lifetime of an entry in the stack ring is?

How bad is this for very long lived objects (e.g. pagecache)?

> Discussion
> ==========
> 
> The current implementation of the stack ring uses a single ring buffer for
> the whole kernel. This might lead to contention due to atomic accesses to
> the ring buffer index on multicore systems.
> 
> It is unclear to me whether the performance impact from this contention
> is significant compared to the slowdown introduced by collecting stack
> traces.

I agree, but once stack trace collection becomes faster (per your future
plans below), this might need to be revisited.

> While these patches are being reviewed, I will do some tests on the arm64
> hardware that I have. However, I do not have a large multicore arm64
> system to do proper measurements.
> 
> A considered alternative is to keep a separate ring buffer for each CPU
> and then iterate over all of them when printing a bug report. This approach
> requires somehow figuring out which of the stack rings has the freshest
> stack traces for an object if multiple stack rings have them.
> 
> Further plans
> =============
> 
> This series is a part of an effort to make KASAN stack trace collection
> suitable for production. This requires stack trace collection to be fast
> and memory-bounded.
> 
> The planned steps are:
> 
> 1. Speed up stack trace collection (potentially, by using SCS;
>    patches on-hold until steps #2 and #3 are completed).
> 2. Keep stack trace handles in the stack ring (this series).
> 3. Add a memory-bounded mode to stack depot or provide an alternative
>    memory-bounded stack storage.
> 4. Potentially, implement stack trace collection sampling to minimize
>    the performance impact.
> 
> Thanks!
> 
> Andrey Konovalov (32):
>   kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
>   kasan: rename kasan_set_*_info to kasan_save_*_info
>   kasan: move is_kmalloc check out of save_alloc_info
>   kasan: split save_alloc_info implementations
>   kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
>   kasan: introduce kasan_print_aux_stacks
>   kasan: introduce kasan_get_alloc_track
>   kasan: introduce kasan_init_object_meta
>   kasan: clear metadata functions for tag-based modes
>   kasan: move kasan_get_*_meta to generic.c
>   kasan: introduce kasan_requires_meta
>   kasan: introduce kasan_init_cache_meta
>   kasan: drop CONFIG_KASAN_GENERIC check from kasan_init_cache_meta
>   kasan: only define kasan_metadata_size for Generic mode
>   kasan: only define kasan_never_merge for Generic mode
>   kasan: only define metadata offsets for Generic mode
>   kasan: only define metadata structs for Generic mode
>   kasan: only define kasan_cache_create for Generic mode
>   kasan: pass tagged pointers to kasan_save_alloc/free_info
>   kasan: move kasan_get_alloc/free_track definitions
>   kasan: simplify invalid-free reporting
>   kasan: cosmetic changes in report.c
>   kasan: use kasan_addr_to_slab in print_address_description
>   kasan: move kasan_addr_to_slab to common.c
>   kasan: make kasan_addr_to_page static
>   kasan: simplify print_report
>   kasan: introduce complete_report_info
>   kasan: fill in cache and object in complete_report_info
>   kasan: rework function arguments in report.c
>   kasan: introduce kasan_complete_mode_report_info
>   kasan: implement stack ring for tag-based modes
>   kasan: better identify bug types for tag-based modes

Let me go and review the patches now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqxKQpjJMwUCpbTt%40elver.google.com.
