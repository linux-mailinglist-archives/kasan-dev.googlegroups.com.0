Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYP47OMAMGQEFF2EUYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FE555B5748
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 11:39:47 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id k19-20020a056a00135300b0054096343fc6sf5258552pfu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 02:39:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662975585; cv=pass;
        d=google.com; s=arc-20160816;
        b=w0f5SiVTrGYdvxu+eUxxk78QVyRvHeAeypWm0QozhTJwiAldNnscbpI6TyTOu/Y47q
         s3NOkTX+x87LZpOkC+YHmqMPoecyyFH+eyN75Q0wnNrauATf/YXoDmZYNZUy/GanJI3o
         DB/S9B7HyICLDkR2MmTcJshbfPvhQJyP89m+dnMGUSRAHakhxBGmXqQETSJ5JDUJ3lYv
         RNbGbu5KXV8u6e7ov9Ig6uVloMdNNY26FCBmTzpDAIC8R99g/XxQWAtaUwZOQvdW7GYZ
         bHBPTkak3MDRSf1P8nujDqTj52dl5O6wcfByuRPWz009L+t4aSzLEYpBVV2dO2xHiJEG
         i1Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZxURNOo+jIF13MpNk1DuwVjJkHEzIgJVB5IQDp7Ww0U=;
        b=arK+Y43clMLcgVzx86yKab9NGzXs4bHui3FKdgrrGYx0DaofvksT7seYXc3nhLx62C
         wgxwALAjP94sir0DP/85LivS5WfjFN+sa3B6fiXq7UUhcbpwRmOx620FF2nq5yzhS+1t
         Ms+nU/nRADRF7dqcfLEx0egvENON6qW9uHmgKfEcGV0mQ+CrGrGOuS+u+7yL9vQ0nCz0
         aPfw1m0obUaDOV5EFxRuSaql+YxXBdgQ9uua4tiuKRR4cGfBoSyrmL3uWGPj3EMdiZCM
         V8+fyZ0HVY/YF4GievJYPqVqxGRgml5lBrQXuoezdY3CQn7qK2KOHKmY6ZbneRfrLlO6
         485w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pThsu5An;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=ZxURNOo+jIF13MpNk1DuwVjJkHEzIgJVB5IQDp7Ww0U=;
        b=FaWF/sPiogYXPc0LKOEljDcCSfl1ZEGL9kQfxWjpbd0iwnJssvmGyKWdnlb09SgxE+
         vGrqq0rE6DzbMDAkV9GVKS0Ypj8jdEUbR8s5ApjsbB+Myw9BWiox4+SZ6AtNmKTA6UZn
         an0UidyTfwSpdjFX1ZVJhjOMNA5alQNpxTTo2jFP/j3QMsCaNaCwkBOCl93q4aQtTg+X
         D5idahEBpZj8zsK26Fk+XcQTF71vDDDYBbOU9hxUnMwPiPl8aTQZGfzpJa7XeQRdcoXJ
         5RGC3YlcV0IYEJoMNx0UVH50WwWFD5NSDdRrnEimPo13ejnASsSFAf0UIPlE6CPpV9H/
         xmHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=ZxURNOo+jIF13MpNk1DuwVjJkHEzIgJVB5IQDp7Ww0U=;
        b=SJx1RQ6gMQcTwosTmPGTgCocIFK79fz0kgmTtACojwjUbaKTB9SHIRkIKGNUZN8x2v
         Ng9rmiB9O1XYhLXseQESniYLov42VcblHTiOCRmeuvuqf88/8DhkLwTiv88iJXRWoDEE
         SkmlZZrFkrC56huWVAvrY0yXqoSsNr5VWRrHbJW+EI5x67oq7fPnRoyey9rifu+0iQbJ
         U2/BQxN3Tl/YQ30YuIYgCep9zAaUFuKH7oj5cuy7CU/h4182uwnbKRVviuIRgCprw6j2
         CQAAKCwkwG+ybWE2z62eI12GxCSGeYPcDoXwjBPT8dA/tWvL6DeCRWum33N7Q4UGRXKa
         Q9yA==
X-Gm-Message-State: ACgBeo3O67g7PYG2L5E1YJce/wLl9UJxnzQe6goKm0XOzd7+bTTzWZTC
	tWTNVtGm04yoa2tm96lvWf4=
X-Google-Smtp-Source: AA6agR4sDdv0HKwqCDqu57p/SnvVPwDDrinxqkma5o/fepZDRWrMfjPwAkZ4k+rdsL79mBvwnNS52Q==
X-Received: by 2002:aa7:8d08:0:b0:538:105a:eb6a with SMTP id j8-20020aa78d08000000b00538105aeb6amr26869893pfe.42.1662975585326;
        Mon, 12 Sep 2022 02:39:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:215:0:b0:438:e83a:1620 with SMTP id 21-20020a630215000000b00438e83a1620ls1445290pgc.6.-pod-prod-gmail;
 Mon, 12 Sep 2022 02:39:44 -0700 (PDT)
X-Received: by 2002:a65:58cd:0:b0:433:fc80:bb88 with SMTP id e13-20020a6558cd000000b00433fc80bb88mr22294691pgu.521.1662975584310;
        Mon, 12 Sep 2022 02:39:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662975584; cv=none;
        d=google.com; s=arc-20160816;
        b=FuxWB4hhtxqvd1TfUIThs0frJkJCcaa5w93wfW6ARKL+zFn3qQSqZ4w0y6NZOXLh1a
         h4sgMyGDjF1Z6JbplWLmDgqyQsnIu5Tf1CvLTRQM+HkiTEHkp3aGi5bzzeKsaOjE03TA
         189enrgxrFWr0HW+DGP64HUHZeNh+B1dUGBo5R1dzBcsGikw6BcxUYudUy5X3fGF/F7/
         k+LPQKH3MnyF6fRRoD2ScaoWD/fjnCoomKkygVr3BA5QD7/1ZeU3FvmDh9QqiF7J/ANb
         flL9aULfPlKUDe/oaG7TMeFOc30b8rDBrCQIo0ryUTr3mzHKEBvT898V4lc4UA3Te4zA
         H6Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/locK1nMU2wTDSjtK8T7mBpx0lWcB3ffdE7tyuNnsYs=;
        b=EEdo6uGnUsSgx22RE4r+YvmCXHrBEuVrX60CkeQnBLynbGvf1ig26u0ROpt0uxLGdN
         JL/XrwqEQ70LJ7bTxqy+FwM17MmbDtqBouStWG28HKParRSES69sjJdZKyr0I0t0YsmX
         1SX6h1B+G4MOpuNefcFMzQAsk+Au8oxWdzJulpvVyCd5xqkBCwcYaF9FDqYNXTRAtCh1
         A0O8/q3XMqY5z0YFhHhBdx6BopH9L7/+SuIvJDKDPdQwIhE9kfWHFMYVCMEq95kDLHvQ
         VeTXC60hn0uou1xN1zU10e7PVEYh5e2y3NM2KuMip+etT9Zhs9SRRHwn+DEVte/duv9x
         rJ1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pThsu5An;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id j2-20020a625502000000b00537a63cf17dsi208314pfb.3.2022.09.12.02.39.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Sep 2022 02:39:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 202so11796285ybe.13
        for <kasan-dev@googlegroups.com>; Mon, 12 Sep 2022 02:39:44 -0700 (PDT)
X-Received: by 2002:a25:1e86:0:b0:68d:549a:e4c2 with SMTP id
 e128-20020a251e86000000b0068d549ae4c2mr20782284ybe.93.1662975583465; Mon, 12
 Sep 2022 02:39:43 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1662411799.git.andreyknvl@google.com> <CA+fCnZdok0KzOfYmXHQMNFmiuU1H26y8=PaRZ+F0YqTbgxH1Ww@mail.gmail.com>
In-Reply-To: <CA+fCnZdok0KzOfYmXHQMNFmiuU1H26y8=PaRZ+F0YqTbgxH1Ww@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Sep 2022 11:39:07 +0200
Message-ID: <CANpmjNM3RqQpvxvZ4+J9DYvMjcZwWjwEGakQb8U4DL+Eu=6K5A@mail.gmail.com>
Subject: Re: [PATCH mm v3 00/34] kasan: switch tag-based modes to stack ring
 from per-object metadata
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pThsu5An;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
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

On Sun, 11 Sept 2022 at 13:50, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Mon, Sep 5, 2022 at 11:05 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > This series makes the tag-based KASAN modes use a ring buffer for storing
> > stack depot handles for alloc/free stack traces for slab objects instead
> > of per-object metadata. This ring buffer is referred to as the stack ring.
> >
> > On each alloc/free of a slab object, the tagged address of the object and
> > the current stack trace are recorded in the stack ring.
> >
> > On each bug report, if the accessed address belongs to a slab object, the
> > stack ring is scanned for matching entries. The newest entries are used to
> > print the alloc/free stack traces in the report: one entry for alloc and
> > one for free.
> >
> > The advantages of this approach over storing stack trace handles in
> > per-object metadata with the tag-based KASAN modes:
> >
> > - Allows to find relevant stack traces for use-after-free bugs without
> >   using quarantine for freed memory. (Currently, if the object was
> >   reallocated multiple times, the report contains the latest alloc/free
> >   stack traces, not necessarily the ones relevant to the buggy allocation.)
> > - Allows to better identify and mark use-after-free bugs, effectively
> >   making the CONFIG_KASAN_TAGS_IDENTIFY functionality always-on.
> > - Has fixed memory overhead.
> >
> > The disadvantage:
> >
> > - If the affected object was allocated/freed long before the bug happened
> >   and the stack trace events were purged from the stack ring, the report
> >   will have no stack traces.
> >
> > Discussion
> > ==========
> >
> > The proposed implementation of the stack ring uses a single ring buffer for
> > the whole kernel. This might lead to contention due to atomic accesses to
> > the ring buffer index on multicore systems.
> >
> > At this point, it is unknown whether the performance impact from this
> > contention would be significant compared to the slowdown introduced by
> > collecting stack traces due to the planned changes to the latter part,
> > see the section below.
> >
> > For now, the proposed implementation is deemed to be good enough, but this
> > might need to be revisited once the stack collection becomes faster.
> >
> > A considered alternative is to keep a separate ring buffer for each CPU
> > and then iterate over all of them when printing a bug report. This approach
> > requires somehow figuring out which of the stack rings has the freshest
> > stack traces for an object if multiple stack rings have them.
> >
> > Further plans
> > =============
> >
> > This series is a part of an effort to make KASAN stack trace collection
> > suitable for production. This requires stack trace collection to be fast
> > and memory-bounded.
> >
> > The planned steps are:
> >
> > 1. Speed up stack trace collection (potentially, by using SCS;
> >    patches on-hold until steps #2 and #3 are completed).
> > 2. Keep stack trace handles in the stack ring (this series).
> > 3. Add a memory-bounded mode to stack depot or provide an alternative
> >    memory-bounded stack storage.
> > 4. Potentially, implement stack trace collection sampling to minimize
> >    the performance impact.
> >
> > Thanks!
>
> Hi Andrew,
>
> Could you consider picking up this series into mm?
>
> Most of the patches have a Reviewed-by tag from Marco, and I've
> addressed the last few comments he had in v3.
>
> Thanks!

I see them in -next, so they've been picked up?

FWIW, my concerns have been addressed, so for patches that don't yet
have my Reviewed:


Acked-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM3RqQpvxvZ4%2BJ9DYvMjcZwWjwEGakQb8U4DL%2BEu%3D6K5A%40mail.gmail.com.
