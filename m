Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF4P2CWAMGQEC67POLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 396A9821C14
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 13:54:49 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-3bb936e6ee9sf6145942b6e.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 04:54:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704200088; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OUuKjB2VnZ8pSze/CmN1SVOLkV94+rAD4HeIByPND1RwwKi1LVeNg2unE36He1f6g
         kZkfQw6w7bFl8MGPlbpf1gt/wXI7PtxABveWFPmX5BqxJJ68rgggpsTK8J/tukU/HcNH
         aJeCLAKV4iY+1wR0XOQDYbjxBVtnvduBOtpgjObJo8jDf9rgJJK6i5L6WMQypRRZWfqo
         4t3XLCBlNWceeV+lBWyh4V7MXPiSeX3lNI1qfaVp8G1W0E9yaxoItQoUkj9AxewYRjCF
         JTbPkUxK3/x0KtOpTDstQfXoYWKWYHn4i9GSMmJUWxHuaO5/QC4zOwJgbzoJ14HWCxkg
         Kxqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8Vx55e4TyJETGkaU3RhCcQPaTdVgms94HhjwTrHH5mw=;
        fh=FyCHTDws/5IrfNgPWVFTAAhk8MeJh+BMbJgBeQ8Nmrg=;
        b=h+zSCh0/8Y7j7BfbMpWjTckB0d8OdLn0repszT2LE7I3D04/AkMpokMet+d4xlfYGZ
         LGqM2GlTm/VG5bS+2l9b0IzE6yFMkINjrTixk0hAhrLMutNSZtlSjUFO1pc1Eqo7gY4y
         KDRF9X+vW0EHN6liNmrl7SKub2QE/PbH3B5H6jZp4+E3DgJ+bmG0yjKPEd1lfer/Cxgv
         1qdLPUY8e/K3BV/vObcqiImuP0vvCr8WBN3qPEJYCCfG1s4rZUpuOc8KFz/dtmCAKjIt
         qMK4HdGO6jibUZjmBJl4qREMAdj6XfZjdHKE1mUm0HC0URYPdM4nn3oaACBpFdO/BwEE
         QZKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vWMQuLGm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704200088; x=1704804888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Vx55e4TyJETGkaU3RhCcQPaTdVgms94HhjwTrHH5mw=;
        b=N5pCQAKAHfsnNQ4D26xs2w+cgZ4rbRp0tVSdMUYojV89jjgOiylmskpO6QAe0XR84b
         urgasOrqfNU/K29mB8tLDrvQC/jHrWRCrFIYA01/3aNLLiUJWaitggn0LcDuXCLLLMAQ
         eONers6RbM5jyGdeF1pzv63RQ1lV8b82b5RDw8rGwEzuvmto4HACbS2bwmdICCcKw1JG
         oLWYaUaxZJSn1S0T0VEZPsSQrYWZ6ypO5NN2csncEny67ffNkPZTlnMdAZYH+3ZAQjwN
         ydJx3PITQx/clR6WhnKb7ZCAnsyyNvkkasla77xrXxAKkUYPbD+bXoafZFSy2M6HD/TZ
         mAPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704200088; x=1704804888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8Vx55e4TyJETGkaU3RhCcQPaTdVgms94HhjwTrHH5mw=;
        b=FBP988efQvPiRS49dyPHR+Ls+KYtNao6LfGb9VmbRk17mGcRsmN8Iqh8/T0kBhQRzK
         k4MfQ6L/KMG0+JWFWvBiIuBxrxsbRT/WdKIYm8VCQM15Xsrz+42q4L8ps4XG8slOsYxl
         qDmyhUAEBpSKtJxlHI6lxW/3nU2ZpgRCofJT5J2hPeNy6RRNk/fW/8i/HNNMB4OoPSmD
         13kFr7Ybq43LZbp9Z7pJ9VP0a6DbRJaReVg0gQLA7FEDmDcDOSol+IStbA1Lc5QUKyLn
         FV1F/C+O7mA3uPwPlhIQ+cvI3mMmBFAqOPE/uQlkbFMjNRHEOi9eTJACBbxf4dDtn6II
         Ybeg==
X-Gm-Message-State: AOJu0YyriHXzU/3hH/O2QJQCNLKx36IPsONn4O7BtRCi3kjVN276k+Iu
	MESZO0mZsVb5XEIjXT/+Xy8=
X-Google-Smtp-Source: AGHT+IHhJP7ZmBv5rUbLzFhA0RpRA2rOTGrCSQ/h7+UydL/l4zonEm8juQWGby6wpbNegT07fymHXA==
X-Received: by 2002:a05:6808:208d:b0:3bc:2095:c054 with SMTP id s13-20020a056808208d00b003bc2095c054mr55983oiw.7.1704200087707;
        Tue, 02 Jan 2024 04:54:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a111:b0:203:c4c1:bc5e with SMTP id
 m17-20020a056870a11100b00203c4c1bc5els3854128oae.0.-pod-prod-00-us; Tue, 02
 Jan 2024 04:54:47 -0800 (PST)
X-Received: by 2002:a05:6870:fbac:b0:204:219d:7db5 with SMTP id kv44-20020a056870fbac00b00204219d7db5mr7252273oab.33.1704200086968;
        Tue, 02 Jan 2024 04:54:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704200086; cv=none;
        d=google.com; s=arc-20160816;
        b=EkzOpsYtkZARrhfcVNnW2pNJYMuOSb1PZKs8hOPVy9IZZ9qWr47BtDnMTZE69PFWFY
         KSwbkHHt+4ygkVE0vlb5nuIxJLc4nup9B1s8FDjaKIzat+fcCgxPmoNXC6Pod2UBsHF4
         BCvtz1YR2tIDaRwO6l0jHjZTnKsZKvAoDycXDXdB+O38nrKLXHopyw4lAu9lp+u9XZPY
         jhjVmSF/9WH6q9Wn+VXW1j1wW/sGk1U1ZEK4nX/nHPXyJaqr6VSHf6sypho6AuvkqoiN
         QlL/jBJXRFxAPSJ7hFF5QHTKfRrlRd0VqlsKgM798/dR9bb4UJpxFZELZruwTSSW26Vw
         lHKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rzpHQecmeH/R/ZNceK/OpsKzmGzn/z2pMokFTKQkVW8=;
        fh=FyCHTDws/5IrfNgPWVFTAAhk8MeJh+BMbJgBeQ8Nmrg=;
        b=tZszdyIB9B21ZUFMccq4d4JpYOZjO7489FjvcCHDYU/slVNl/bNkgBjNojvL6p7Zm7
         4ZUJnNQQYdqRVWxa9Ryg3GhtfzA1EbVvK4S/1NRF8JHEIi4fHiFQbzNF2YBkugE7MDhY
         +m5tNkgW86Nk1YZWeFJ2MAqjSPIGW4XhxkU/jQCpGIbUgdf0YBHJEUk/fkIwbYa3Qjss
         7/GVbRXOL7hV0Dh58Qzbh8fQVE7HQlq2UCiXcy4fToATDCi2YoGglBDi3B1zlP/G6/IK
         +1Wa8rTDVC7zJt3aECGmqlVehgBE0hIDUSX05dodmesm0uei1Nqkl8bQBkLCpRkWnaC2
         d0OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vWMQuLGm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id hl8-20020a0568701b0800b00204853d91eesi1537849oab.4.2024.01.02.04.54.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jan 2024 04:54:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id 71dfb90a1353d-4b739b29686so3511490e0c.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Jan 2024 04:54:46 -0800 (PST)
X-Received: by 2002:a05:6122:9a0:b0:4b6:c780:ac90 with SMTP id
 g32-20020a05612209a000b004b6c780ac90mr10538276vkd.0.1704200086271; Tue, 02
 Jan 2024 04:54:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jan 2024 13:54:08 +0100
Message-ID: <CANpmjNOaeKRZKtJusQu9Ag2=ifwPS+L9-ZGL77dRzDFPGu_DOQ@mail.gmail.com>
Subject: Re: [PATCH mm 00/21] kasan: save mempool stack traces
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Breno Leitao <leitao@debian.org>, 
	Alexander Lobakin <alobakin@pm.me>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vWMQuLGm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as
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

On Tue, 19 Dec 2023 at 23:29, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> This series updates KASAN to save alloc and free stack traces for
> secondary-level allocators that cache and reuse allocations internally
> instead of giving them back to the underlying allocator (e.g. mempool).
>
> As a part of this change, introduce and document a set of KASAN hooks:
>
> bool kasan_mempool_poison_pages(struct page *page, unsigned int order);
> void kasan_mempool_unpoison_pages(struct page *page, unsigned int order);
> bool kasan_mempool_poison_object(void *ptr);
> void kasan_mempool_unpoison_object(void *ptr, size_t size);
>
> and use them in the mempool code.
>
> Besides mempool, skbuff and io_uring also cache allocations and already
> use KASAN hooks to poison those. Their code is updated to use the new
> mempool hooks.
>
> The new hooks save alloc and free stack traces (for normal kmalloc and
> slab objects; stack traces for large kmalloc objects and page_alloc are
> not supported by KASAN yet), improve the readability of the users' code,
> and also allow the users to prevent double-free and invalid-free bugs;
> see the patches for the details.
>
> There doesn't appear to be any conflicts with the KASAN patches that are
> currently in mm, but I rebased the patchset on top just in case.
>
> Changes RFC->v1:
> - New patch "mempool: skip slub_debug poisoning when KASAN is enabled".
> - Replace mempool_use_prealloc_only API with mempool_alloc_preallocated.
> - Avoid triggering slub_debug-detected corruptions in mempool tests.
>
> Andrey Konovalov (21):
>   kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_object
>   kasan: move kasan_mempool_poison_object
>   kasan: document kasan_mempool_poison_object
>   kasan: add return value for kasan_mempool_poison_object
>   kasan: introduce kasan_mempool_unpoison_object
>   kasan: introduce kasan_mempool_poison_pages
>   kasan: introduce kasan_mempool_unpoison_pages
>   kasan: clean up __kasan_mempool_poison_object
>   kasan: save free stack traces for slab mempools
>   kasan: clean up and rename ____kasan_kmalloc
>   kasan: introduce poison_kmalloc_large_redzone
>   kasan: save alloc stack traces for mempool
>   mempool: skip slub_debug poisoning when KASAN is enabled
>   mempool: use new mempool KASAN hooks
>   mempool: introduce mempool_use_prealloc_only
>   kasan: add mempool tests
>   kasan: rename pagealloc tests
>   kasan: reorder tests
>   kasan: rename and document kasan_(un)poison_object_data
>   skbuff: use mempool KASAN hooks
>   io_uring: use mempool KASAN hook
>
>  include/linux/kasan.h   | 161 +++++++-
>  include/linux/mempool.h |   1 +
>  io_uring/alloc_cache.h  |   5 +-
>  mm/kasan/common.c       | 221 ++++++----
>  mm/kasan/kasan_test.c   | 870 +++++++++++++++++++++++++++-------------
>  mm/mempool.c            |  67 +++-
>  mm/slab.c               |  10 +-
>  mm/slub.c               |   4 +-
>  net/core/skbuff.c       |  10 +-
>  9 files changed, 954 insertions(+), 395 deletions(-)

Acked-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOaeKRZKtJusQu9Ag2%3DifwPS%2BL9-ZGL77dRzDFPGu_DOQ%40mail.gmail.com.
