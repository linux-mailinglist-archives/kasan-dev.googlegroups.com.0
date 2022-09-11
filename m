Return-Path: <kasan-dev+bncBDW2JDUY5AORB5UW66MAMGQEJWPW7MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 013035B4E8F
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 13:50:16 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id z26-20020a05683020da00b00655d8590ed3sf860229otq.7
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 04:50:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662897014; cv=pass;
        d=google.com; s=arc-20160816;
        b=QxPNcf1KE/PeVu1fZasWU8i8BzGXufAfY8OmODaPRB5XAUG02S5Axq64LLTYhc+cqc
         o/NWl/F64iGx+ckIOq85ZDzQ8Gf88idr7vHlf6N0kQgSgO9+wVNLhZjUSOVWF3rxbYDI
         3w3RiI7hZlvhHiKnBsGs7W+nELn5JN6JMmmsdoh+5+GVOTgk9pz6D1BnMtXWc5RqE/CF
         T2UuEbcpn0Dzy7F4XKQfh3ZJ6edVUszCYfm5OMBFJvbOmbyCYVcvs5VqUWRuBAWub+Yf
         kCVdN0J/WidEqNRM75lsszf3zdGOdJxFsPIugeKGyHAUYKI5OkUYE8U6GqlLRhY1UV/j
         pkmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=HkYB0N1ru1gRdOSKWkIXHQ3ghAlyOId4e4etwKEiY8g=;
        b=a4ymi0kW9xuBdVpjzz7V6hMOohYPPBMHKpGEKRDjj9ydG4HV1qiCqXk9DtdKhKhyWW
         TzN/x/zCuMN4xPQe1mzPNFpZMoscmfnVWwS3vLAgzqIGpnM7EwKwG4tooKKTMLbu07PJ
         C7zVRgOLayRJ54cPfth5A5/dPe/mcIJOHnmP1y/JSjbwH1yigj2yJRkViVAkGoZfD3YR
         cLULY3WFP5KI6j+PNKoY2ynY+xaEkCWR3h0u2iav+kRBrWJFq4u3PKv6zWIVOBcXcv+J
         wFqzLhtLhPhiPHjGB6lXlBThfYqbEFEDk2mecHmuhIuy50mOldGJ6/6hFzpctNWSl7cR
         4GXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Pp9lyLfW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=HkYB0N1ru1gRdOSKWkIXHQ3ghAlyOId4e4etwKEiY8g=;
        b=VKy1jFw6FTdHdIXCURPYPynBjP0KJFBfD06bkA3dR5kZqAjlh+kGmZrVru3k/d6S+t
         6mkkIZpOA4nC/jY2VGQiigA39dGdUs9bUsq+6nZxDfOv83f/0dXsOpUfLDNzx10djyZP
         l3THn0IOkKIHDC4xssgXNDW3S+ZiREc9KzfxfW2KJ8sDtn/5ysQuk9/VBJh4rwYjuc2l
         7WjZtWleKq7/GV2mduhMZR0kAY23lGpwruuhNxZFRX12WzBedmbs61n6yYXg/2RaFssM
         dmSI+znflSP/i3MOs8SOtS3xAnQIyfvg+GzTmdVGUnTU4qy69PYXKHRnPkpBZ5dCxMtp
         hN+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=HkYB0N1ru1gRdOSKWkIXHQ3ghAlyOId4e4etwKEiY8g=;
        b=GwFKENe4Yg3SBal5UJg/an/Vcn7srQ8JhN6WRcuEeECj8w6TdDNPP/XAH8VVroPVAP
         9YeCGmaQCkLI2u4IWMMcMtoeX7LFQNOZJXI0x3BO/dNnSEaOBAk5FvGljZoDUXtrNiA1
         xs1ztDU731uoMsl4bxTfocNLaDwRTYCq7mLds3q37ph9BmXSdskORqiZ+2y6LbGtnBY4
         le3971LvBM/HYhc5YQSOt4gwGCzFgSUqY3pBioKkYmfXkZZREWN4NxMf2Xr0Sb4Gn1tS
         hMi9YT1ZSz4uRdndA4GZw1Gho2q03Bz/Hv9RHtaXopJASQjMoOCHgILLvGA4ntORyxUU
         sGHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=HkYB0N1ru1gRdOSKWkIXHQ3ghAlyOId4e4etwKEiY8g=;
        b=0pi/3G1NR10HMgXcCOvCDClcYVwTF1gMVjKO9thqV1hNUxIPXCk56hFxZgEQ6NCq22
         PVm2uR277ccr3g7b/JHOf2louHbV5putf6j18fVOOxauKKD+vn1v5vgLSDpOLKzfQ6YZ
         /Dz3vrAvQ8s/lcXIn3PxZbdHkCsUJjucbrDiaNQpQxodBD3lUNb5/TzzrTdgZ3N7oZ48
         csRTuQ9B0dJa7h/7Je9WRXgbGBu0VK7syGae8m9KTnqPskdiKJxSOHD59P/XvHTgnA/B
         kcgMv40ggin3JLmsdzimO6pdViY6CAvjjtGaVwP73kzqD8Z1vzc7oSyzvrtTTbeBUXzS
         BAAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3ekfpWglBTjDTpoy75EEqexQ/Q1lEagWp51zgBYrEVCg9dxrZB
	Ql/0HocR5ijSLLTLS/crNQ8=
X-Google-Smtp-Source: AA6agR4jRaF/BYsPkflSx2EUReNMVXtO+394rFw0gSlairJ7u/c/9oN9aW/9S6CzDX/1m36O8/gkWQ==
X-Received: by 2002:a9d:4816:0:b0:655:cae1:ab7d with SMTP id c22-20020a9d4816000000b00655cae1ab7dmr1864522otf.269.1662897014579;
        Sun, 11 Sep 2022 04:50:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2cc3:0:b0:475:4c60:e0f1 with SMTP id o186-20020a4a2cc3000000b004754c60e0f1ls135478ooo.8.-pod-prod-gmail;
 Sun, 11 Sep 2022 04:50:14 -0700 (PDT)
X-Received: by 2002:a4a:ae85:0:b0:44b:4ac7:9e10 with SMTP id u5-20020a4aae85000000b0044b4ac79e10mr7694397oon.24.1662897014198;
        Sun, 11 Sep 2022 04:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662897014; cv=none;
        d=google.com; s=arc-20160816;
        b=a//u7dkK0ZKb2QOdgaGJXRNjzWtQ3EcWlwnGukV3+KTCAbn8oUNRPuB38JgBIip+QZ
         QO6lsOBDyLizsTKJi88KNvRWhTKbtuCgMyloiUm7IEgnbHmxwwQPs7isF46CWjpLCHy5
         HMQ1iKNI2vAQ2ZZPLvCP24aUXfsCxGwB6Pwe/3rm8H5Zy+OfDuqgjJrfxSM8YlAVo+P1
         3frQCt6D4xciQH5rqGCYuH6TNEbV4E1/ydaKnNa0thsoAkUqtGKFe28Hss1Q+jflvVDI
         8F39OESGmY+U89sOLKBNza9MEqB8mCaSUwBXcw8oFSeXfPJkzZeWBTjT0YUkPlA8Tpjt
         m1EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o0NomSJrd+We+cA0E2POE4mJvtyH0veoDgu14xHBABY=;
        b=vns04FB3Ay+uuhkNN/q8A4dmcMkG1353xr9X9mT1yU7GIv6UuHDXyP5STSofMHRZwk
         hAOxo1Vje6D/IXexaEaDym22fCf+SHUxVJAu5i73AncmRub4Il/SN5pjip8t2fEt4jh/
         0bQebd68AA1olJOdJ11vGPs/jpw1clb3cILZsAzfDTw6Kg5HTw0/qaKKTYV/MMuVLZWN
         udxtdahReGy2Fwfvpq0XnKDoIxrrKw2ndk6qth9dShsimZy3gPpJeKgEXYPdmN9YYFII
         b9/FmerusVxyyEI4jpOk7iwUF5WOkDfDwVqgm6rKU83OADxrP6p680BO2KO0q9hMLOju
         l/hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Pp9lyLfW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id k67-20020aca3d46000000b0034480be185csi187189oia.4.2022.09.11.04.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 11 Sep 2022 04:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id m9so4829738qvv.7
        for <kasan-dev@googlegroups.com>; Sun, 11 Sep 2022 04:50:14 -0700 (PDT)
X-Received: by 2002:a05:6214:c48:b0:4ac:b18d:c101 with SMTP id
 r8-20020a0562140c4800b004acb18dc101mr849569qvj.107.1662897013746; Sun, 11 Sep
 2022 04:50:13 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 13:50:03 +0200
Message-ID: <CA+fCnZdok0KzOfYmXHQMNFmiuU1H26y8=PaRZ+F0YqTbgxH1Ww@mail.gmail.com>
Subject: Re: [PATCH mm v3 00/34] kasan: switch tag-based modes to stack ring
 from per-object metadata
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Pp9lyLfW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f36
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Sep 5, 2022 at 11:05 PM <andrey.konovalov@linux.dev> wrote:
>
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
>
> Discussion
> ==========
>
> The proposed implementation of the stack ring uses a single ring buffer for
> the whole kernel. This might lead to contention due to atomic accesses to
> the ring buffer index on multicore systems.
>
> At this point, it is unknown whether the performance impact from this
> contention would be significant compared to the slowdown introduced by
> collecting stack traces due to the planned changes to the latter part,
> see the section below.
>
> For now, the proposed implementation is deemed to be good enough, but this
> might need to be revisited once the stack collection becomes faster.
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

Hi Andrew,

Could you consider picking up this series into mm?

Most of the patches have a Reviewed-by tag from Marco, and I've
addressed the last few comments he had in v3.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdok0KzOfYmXHQMNFmiuU1H26y8%3DPaRZ%2BF0YqTbgxH1Ww%40mail.gmail.com.
