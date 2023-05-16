Return-Path: <kasan-dev+bncBCF5XGNWYQBRBNVVR6RQMGQEMFCJTXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id CA780705727
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 21:34:15 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-ba237aec108sf15086381276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 12:34:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684265654; cv=pass;
        d=google.com; s=arc-20160816;
        b=C6W5qyGV6zNtK2A0kneHwK7dTJwvlRCD1iZhwwWLAYRIc1+cTL90hbH822SUerDQbW
         gYkzSZnbDFXUI4JrhoIuEAxwmmc87INKevnCQHn7oazTluHbEwyKL/birGIqGq9UX+jW
         tYoS7LibTGDfMvWhCbrmwEIvhuTeNOWJIcp7klVWsFjr3U9oIlYPEmLmYwYc5KM13ePf
         YWlz8MjW1Hd0yF15EgKp7RtjdeyF98XmdF6EE38BzwqoV1ShUKNo6hWzmykQY7ZKS/Xn
         qVZZ9SSjFThl4cUsvcmo81Z+uNoqWqQLgdbjJgQgU2Z5Olw/C7srs85UxhWXD4DYWqEf
         Ukkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=thf03gVfmtOw7iNqic6ml4HqceIoVjK7E2Eqg0N/6mg=;
        b=YSuJVPiVszFA54VD99h1vppVTg2AZ8X6qvcbRdTIeBUHKTwj70e650Y7mfM+bAZ2qL
         DS6yhsDQVxKAnJqOOA1z3+MacPpHfLjVjOPkcY1DtaQhjetVJCxEgK+hSSOMyC5bsp9D
         j49OuGgwd538akVdrMKErmqe5JNxXkjf9hIXO+b8EDYjRfzV1icXqbZAG7tVrwK9GCVc
         LxupMB0nC+Fm0Op5D7nABLoQb9rXHQVOkoAYX4OdE9XyozoN4P62nI53nlGUxUUAebsI
         ZmvPqoVTj2dNjhjJwo7g0lc5wvIjdbPZfCz8oagyATJnQcHPHo5ntzyBnGpvwsgFWml4
         7GzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bNHc1U0C;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684265654; x=1686857654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=thf03gVfmtOw7iNqic6ml4HqceIoVjK7E2Eqg0N/6mg=;
        b=qFB7rxnhIqjbIml1VdP9prkf80PWpioZwGArPWyQizuHEZ7SBXqUqoxUKg5YQvIVtf
         W9SxSQ95t0iEV13GNwoDzr6Uy0MtaQRHFp+BmZppELRKp3A8Or6G3rI37Hsv0/3Wmv+U
         gARrJXpsX5vaqLLR7N7MRSXnNyHlPcbUVzqrsfC0PsMw1QDBAaH9lTgprxxh5cmlYYr1
         eG8FAT7HeLmK1vUk9Uf8oPRdrtQkipuk1I1NKJNJjEtAQwRRlT9R+vOLnSC3e5i0eqCX
         pOmLPIQpZyjXZ18A3V/tByFfNbofeyO3Vfs0BTdindqSAkg1P8CdmeoCz3WAMc50cuMf
         XO1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684265654; x=1686857654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=thf03gVfmtOw7iNqic6ml4HqceIoVjK7E2Eqg0N/6mg=;
        b=GplV6625uQFjD5DztwzMyMeQU+xEp9bdS4wD/GjRYIqG4EZqo+nj2UavHgPUtBXu9v
         6v/KBVn/bE/UODS3FRrbsZSbs27+TIrylqarE3czzlM4mkFwTgUhc/0PhqRacXKymoyK
         q6nsHB1yF3WP+yia1fKYAFu0N6csY8kmlLCzkQRmBznVBujueSh5UFQOT3FMIQBLxOOv
         JyxvKXp8mPvYLGqP/NSAOyWlrxoVM+I+zkXzgZgUxNpuYzDGiTXXq/GixcWU1S0sxBWK
         36cTv5oE93QFRij4bfJ5m7VpedAOV9zXY8OZkbRQ9vL+e5emQuObB3vBwOKOjkqXLC4z
         BoSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxpBsVWz5aBE4wXsGY4K4xDF6l7+CAejW+627j+e2vS47iqJGxq
	KdHaqFy3MZEcp6N5KxDHlLo=
X-Google-Smtp-Source: ACHHUZ5B3d1pWVZcsf7esPu7xqYYq6KHGR/YTL6E2q/NGKBjYMBxBbrS/ajjOdPbY30AOLclh/wNaw==
X-Received: by 2002:a25:8407:0:b0:ba8:4b22:4e8a with SMTP id u7-20020a258407000000b00ba84b224e8amr482504ybk.0.1684265654494;
        Tue, 16 May 2023 12:34:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:2a0a:b0:55d:a2e0:32da with SMTP id
 ei10-20020a05690c2a0a00b0055da2e032dals10504264ywb.1.-pod-prod-gmail; Tue, 16
 May 2023 12:34:13 -0700 (PDT)
X-Received: by 2002:a0d:ca8b:0:b0:561:1de8:26cc with SMTP id m133-20020a0dca8b000000b005611de826ccmr12203411ywd.30.1684265653820;
        Tue, 16 May 2023 12:34:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684265653; cv=none;
        d=google.com; s=arc-20160816;
        b=QsoKTjhBGk/ccZGGS84VPAAstK7g/MFd0VQHejOUCuHl8bKEGoW++ZqO1iDClZyd1+
         ZJUi/OAbmd31QZJk0/rhUT34l1XnHDhXMGeb3WYzImcDioMMl8DclknpwN8tYmVQsKKs
         2tDiZlaUs70HSHsYKAtFgndM7R+43rPULdW0hwlmnkN2rA2tJP2Yk1qkWB/+8kTZ9SSm
         RXsEp80SV/vEp5VXVi8Y1enwL/7I+Dm3MzIzwgk15fL7em9xQVlaWJN1boe3I0Ry7wUy
         s1iS9tiyo4OoGHgdlXjYFEXBX/uy86ABrsVf/3kR6Sct4W/WGYghy34irlVYSw9GGcHz
         dmmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NjomB45/tUXiCEV6Zx/tTP1f+pkWwWrPq8cCPi1RJqc=;
        b=HfK/BPyVAUGQ+8r4aOFRVNlaeIQJzg6ZavUaOMePItAJklMnXW3HsbsGbtNPbr1FGZ
         MPI1jZOxmoeDnkRiFSCqeqtnovVNDRgtmONODMDYsZjwmg9lm/sY6ylwg+JaUvRp3ZHU
         xalfbazA+9/O/vHbDSCBiH66/z3E5RW1pQGT1Eysk8zBoRotlRBmdgGEc6Gln0yagpEp
         KG9KIlcvqcXOEN3aElFkPhi6iwKPaCIBHXFtmx+g1oqH/Fzr/3rXHDA9gxR1OdHV/9ae
         58vJB7Jm7GBVQHPLLFKu/X0R9rxAl04S/vPNNYY+wk6ONazN3HukPq0TtCNbdJWdcQUd
         UPtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bNHc1U0C;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id cj4-20020a05690c0b0400b0055a905c06bbsi23791ywb.2.2023.05.16.12.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 12:34:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6439df6c268so9591120b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 12:34:13 -0700 (PDT)
X-Received: by 2002:a05:6a00:1141:b0:64a:ff32:7349 with SMTP id b1-20020a056a00114100b0064aff327349mr16158832pfm.32.1684265652878;
        Tue, 16 May 2023 12:34:12 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id g19-20020aa78753000000b00634b91326a9sm14259716pfo.143.2023.05.16.12.34.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 May 2023 12:34:12 -0700 (PDT)
Date: Tue, 16 May 2023 12:34:11 -0700
From: Kees Cook <keescook@chromium.org>
To: "GONG, Ruiqi" <gongruiqi1@huawei.com>, Jann Horn <jannh@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Alexander Lobakin <aleksander.lobakin@intel.com>,
	kasan-dev@googlegroups.com, Wang Weiyang <wangweiyang2@huawei.com>,
	Xiu Jianfeng <xiujianfeng@huawei.com>
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Message-ID: <202305161204.CB4A87C13@keescook>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230508075507.1720950-1-gongruiqi1@huawei.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=bNHc1U0C;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
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

For new CCs, the start of this thread is here[0].

On Mon, May 08, 2023 at 03:55:07PM +0800, GONG, Ruiqi wrote:
> When exploiting memory vulnerabilities, "heap spraying" is a common
> technique targeting those related to dynamic memory allocation (i.e. the
> "heap"), and it plays an important role in a successful exploitation.
> Basically, it is to overwrite the memory area of vulnerable object by
> triggering allocation in other subsystems or modules and therefore
> getting a reference to the targeted memory location. It's usable on
> various types of vulnerablity including use after free (UAF), heap out-
> of-bound write and etc.

I heartily agree we need some better approaches to deal with UAF, and
by extension, heap spraying.

> There are (at least) two reasons why the heap can be sprayed: 1) generic
> slab caches are shared among different subsystems and modules, and
> 2) dedicated slab caches could be merged with the generic ones.
> Currently these two factors cannot be prevented at a low cost: the first
> one is a widely used memory allocation mechanism, and shutting down slab
> merging completely via `slub_nomerge` would be overkill.
> 
> To efficiently prevent heap spraying, we propose the following approach:
> to create multiple copies of generic slab caches that will never be
> merged, and random one of them will be used at allocation. The random
> selection is based on the address of code that calls `kmalloc()`, which
> means it is static at runtime (rather than dynamically determined at
> each time of allocation, which could be bypassed by repeatedly spraying
> in brute force). In this way, the vulnerable object and memory allocated
> in other subsystems and modules will (most probably) be on different
> slab caches, which prevents the object from being sprayed.

This is a nice balance between the best option we have now
("slub_nomerge") and most invasive changes (type-based allocation
segregation, which requires at least extensive compiler support),
forcing some caches to be "out of reach".

> 
> The overhead of performance has been tested on a 40-core x86 server by
> comparing the results of `perf bench all` between the kernels with and
> without this patch based on the latest linux-next kernel, which shows
> minor difference. A subset of benchmarks are listed below:
> 
> 			control		experiment (avg of 3 samples)
> sched/messaging (sec)	0.019		0.019
> sched/pipe (sec)	5.253		5.340
> syscall/basic (sec)	0.741		0.742
> mem/memcpy (GB/sec)	15.258789	14.860495
> mem/memset (GB/sec)	48.828125	50.431069
> 
> The overhead of memory usage was measured by executing `free` after boot
> on a QEMU VM with 1GB total memory, and as expected, it's positively
> correlated with # of cache copies:
> 
> 		control		4 copies	8 copies	16 copies
> total		969.8M		968.2M		968.2M		968.2M
> used		20.0M		21.9M		24.1M		26.7M
> free		936.9M		933.6M		931.4M		928.6M
> available	932.2M		928.8M		926.6M		923.9M

Great to see the impact: it's relatively tiny. Nice!

Back when we looked at cache quarantines, Jann pointed out that it
was still possible to perform heap spraying -- it just needed more
allocations. In this case, I think that's addressed (probabilistically)
by making it less likely that a cache where a UAF is reachable is merged
with something with strong exploitation primitives (e.g. msgsnd).

In light of all the UAF attack/defense breakdowns in Jann's blog
post[1], I'm curious where this defense lands. It seems like it would
keep the primitives described there (i.e. "upgrading" the heap spray
into a page table "type confusion") would be addressed probabilistically
just like any other style of attack. Jann, what do you think, and how
does it compare to the KCTF work[2] you've been doing?

In addition to this work, I'd like to see something like the kmalloc
caches, but for kmem_cache_alloc(), where a dedicated cache of
variably-sized allocations can be managed. With that, we can split off
_dedicated_ caches where we know there are strong exploitation
primitives (i.e. msgsnd, etc). Then we can carve off known weak heap
allocation caches as well as make merging probabilistically harder.

I imagine it would be possible to then split this series into two
halves: one that creates the "make arbitrary-sized caches" API, and the
second that applies that to kmalloc globally (as done here).

> 
> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
> ---
> 
> v2:
>   - Use hash_64() and a per-boot random seed to select kmalloc() caches.

This is good: I was hoping there would be something to make it per-boot
randomized beyond just compile-time.

So, yes, I think this is worth it, but I'd like to see what design holes
Jann can poke in it first. :)

-Kees

[0] https://lore.kernel.org/lkml/20230508075507.1720950-1-gongruiqi1@huawei.com/
[1] https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html
[2] https://github.com/thejh/linux/commit/a87ad16046f6f7fd61080ebfb93753366466b761

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202305161204.CB4A87C13%40keescook.
