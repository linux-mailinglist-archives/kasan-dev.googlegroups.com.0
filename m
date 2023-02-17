Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2MCXWPQMGQEMWUY32I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 894F069A791
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 09:57:15 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id s12-20020a170903200c00b0019a8df175b2sf584665pla.23
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 00:57:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676624234; cv=pass;
        d=google.com; s=arc-20160816;
        b=zk59K9MTois/4IfWyUbd/8TqXaxKWteu8nljByKnvVqPTPSKbPrBXzNf5ue1C9xOKL
         Kep+pcyeo+Z4w5shj00FjotY2OPNrizSCuYn/ZfpUmL/CPzTc1COZnzMhBvmy02IJkyG
         qmd1foxBQXSjUynEhDE/T4DJGSskgoq06E72PqlqSFq9QMmLX/OloazRwkpAumukj7Jl
         I+WFCx3XRvmNAORcjuyvV85qIQJ01yB9MeI/cu3AJ5gbL3AxfbUJ7dXRIMG0EyNXas0+
         3b4L1wEEX1JlZc5vpTdS1Kb/9CSo+LlSnqQ7SGaXOU559qJv9Cg9Qr1thJ0/S4cQDc2/
         XcKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0w/Bgc4hYSjUxRN+QSZ7kuvm/HW4xMH+0xIaBaBaS2s=;
        b=MrARsoWCC+qPsjzrunnKB3OjnAeuGqQ8QARbqR1y/b50aUTrj7SPW43z4MAb+GUTCK
         AZQSs1K769v4JsLxPqcBzgk6xGKw1OnvdOwbYGhQBwaBA+XZ72fkMGbB9ppKhYjKLIW6
         AfVJLVMGcBbyhJ1vC+PG6VsA+jkgXaoUIv7lfFO0LBjUhTG9XML2+rcGvSoZXFX1tnLa
         wS9AntqUr9p/Wf92L4sDBN/U2b6P15xMsZxBxwqr6gMSUTU2VTkei3MFuVNUjwgChTuB
         c+LLbLnbvx/XlHPNs8tG5CCHRMw0RpJ0Ypz8h5jzXB9ZCPDmVEQ6lI2emw+7lWzdT/3E
         z4uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gh6VjHO7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0w/Bgc4hYSjUxRN+QSZ7kuvm/HW4xMH+0xIaBaBaS2s=;
        b=CwNoYmOkjE+TcGs57fkYM2E8CX4GihRUn2SWTHYpAnK6IFtEI1XCJS49hRFpcKA/ow
         CaqqEV3BNXPpeb77Nz28LK1qqtvsvPsDBzY9HzAp9V2i25hpsPCcpqbiX3FkfGMR8V4o
         gZk6M3zgMOzva/jUYzqi/9ZVgIkoYR9dw6k4Hxo04yF27IyC8CBJTaPr2sqNxck15oNc
         QJzV9Y0VV5XwBX+b6mXNCRlpssmuC3f7VG9RdRQAykG9iSyApccwh8iam/jBYy+EAAg9
         tnOKQZIokrxQn2BcN9h4c9bCl9oZmmIowDBa1hQqx8/qtrlZJpWXfVf8YRsJk2HQoRBQ
         eI1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=0w/Bgc4hYSjUxRN+QSZ7kuvm/HW4xMH+0xIaBaBaS2s=;
        b=P0LQ3TKNnZLl9tKGE7a3DHOkl+MBO/fslMftM1fJOm2wtqweD9WZZvLc8V7qFPsIRM
         p6Uv9NsJUHFgkvyJnrmDpVPNw2XgzyL/ucLNbfk0AZbZKNdaUPdiNtOB53JGMyxcjLl+
         bdwq6jkOhvtkMY6fTFQ2cknNTag4n/Kxl7k/gx3lCEqvfAjWVGj7UieJU2UtHAe157uI
         cUPTyfGbGDvyzlhRDbNC+FIiz2GheU+pOnkbo5UZGZpuX0gDcigrHnZYZ1csfzQFdwpD
         C3tHQ+o5u1+Uf2F3NfxI04X6tE1PvVTIZyHZ5cRDhB4gCodvloe6xWhXOFz8FHEQ+tDi
         /u6g==
X-Gm-Message-State: AO0yUKVDqvxMJfvTXNOay+wUUYzxwhVCyVziOGypG4OAspCRrrs18q5I
	XKHu7OWI05U+Hq8IRvF7MxA=
X-Google-Smtp-Source: AK7set+AN2fLjSJAcJhqszOxLrW14YGmR9n4wqifn3VgEmfRXyCTfFLBzIXWej3+ODLNKXcFpifYTQ==
X-Received: by 2002:a17:90b:3a8f:b0:233:d38d:dcf3 with SMTP id om15-20020a17090b3a8f00b00233d38ddcf3mr1377601pjb.52.1676624233819;
        Fri, 17 Feb 2023 00:57:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:e82:b0:234:2ef4:2e9 with SMTP id fv2-20020a17090b0e8200b002342ef402e9ls934241pjb.0.-pod-control-gmail;
 Fri, 17 Feb 2023 00:57:13 -0800 (PST)
X-Received: by 2002:a17:903:41cc:b0:196:704e:2c97 with SMTP id u12-20020a17090341cc00b00196704e2c97mr680350ple.25.1676624232975;
        Fri, 17 Feb 2023 00:57:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676624232; cv=none;
        d=google.com; s=arc-20160816;
        b=zh5vo2AmQmzDUf2o7GLHWt8fq7UOsskHZst4dDROT5tQi3lm4YdDx+xzFqqjo8nGuC
         aktE3cuObvEkASGbTqHb9biUnW+acgx7fRedYUlvfruc0rukXJXDD1obUbX2eqtKDv8a
         nIMKQ3bDHb6lQh3bCaNoBNj0KHsTc2nz90mJnwqkQz4r1Rv6W/k2CyUasSfMMom74Blm
         BxA/f+0W3rr6Xc5Y2ICkFVRJiBltW/f5XSN9jBhZmtMyPlD7mzSiOw7d2MaRvbyUP/vv
         iIyMm/ar/MROr41FdVRnFCdFlt2KX0Ml5j/DcSIaVyE9MLoxi3d0pN9riGIc1Pg8Ydg/
         jN4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AdXhA+rr7rT3nbRAWr9dOcvlGGpbLeHVjZKaiCCs0e4=;
        b=S/p5uAL9+Jbw6J6QjhO6RX4ArKo4s+wzHIuUR5MJOdV00xNJewRv+qW/yXlop0ggK9
         4waQeTflXXVjq5Eb3rTeuS/BvQGD2asiVVdCHY0QVOyneVftiZVSh6AGjhr+MjkYFwCK
         UhgrmyvIjt/u78sgYDISQjI2pKmUwAw0kbYaa+UZE53hBSXNtLGiQ/LAW552wXfMkI5G
         H4wjn38RYoHqR1scuyvrTXRxnU4W6UeQG+CguonKTZ7MIttN5qpWM5p1u9CGXOQDjQTP
         JK8yKS2h3uvMpulrrMAdUKv5od8L6LLVlJtsg3jdnbq+31A3ynOrv2lFEd+d6yGVxQX4
         SMGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Gh6VjHO7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id la5-20020a170902fa0500b001990cb9ce78si229185plb.1.2023.02.17.00.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 00:57:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id p9so150274vki.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 00:57:12 -0800 (PST)
X-Received: by 2002:a1f:13d4:0:b0:3ea:78fc:6dd8 with SMTP id
 203-20020a1f13d4000000b003ea78fc6dd8mr1602508vkt.21.1676624232103; Fri, 17
 Feb 2023 00:57:12 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
 <CAG_fn=V3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf+fRw@mail.gmail.com>
 <CAG_fn=VuD+8GL_3-aSa9Y=zLqmroK11bqk48GBuPgTCpZMe-jw@mail.gmail.com>
 <CANpmjNOciiDNkWDrkQ+BEgAj=rSYGQAuHVS1DTDfvPHSbAndoA@mail.gmail.com> <CA+G9fYvLmhfw7dk_rhXBHd7YESGtAndmhdcW2=VGANfk0ho9Uw@mail.gmail.com>
In-Reply-To: <CA+G9fYvLmhfw7dk_rhXBHd7YESGtAndmhdcW2=VGANfk0ho9Uw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Feb 2023 09:56:34 +0100
Message-ID: <CANpmjNPLX-1JzSiFzxCyk=Y-zOupMjezeeEGa_wa7+-B5dtc5Q@mail.gmail.com>
Subject: Re: next: x86_64: kunit test crashed and kernel panic
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Alexander Potapenko <glider@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Jakub Jelinek <jakub@redhat.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev, Anders Roxell <anders.roxell@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Gh6VjHO7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as
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

On Fri, 17 Feb 2023 at 08:30, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> Hi Marco,
>
> On Fri, 17 Feb 2023 at 05:22, Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 16 Feb 2023 at 19:59, Alexander Potapenko <glider@google.com> wrote:
> > >
> > > >
> > > > > <4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
> > > > > <4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10
> > > >
> > > > Most certainly kmalloc_memmove_negative_size() is related.
> > > > Looks like we fail to intercept the call to memmove() in this test,
> > > > passing -2 to the actual __memmove().
> > >
> > > This was introduced by 69d4c0d321869 ("entry, kasan, x86: Disallow
> > > overriding mem*() functions")
> >
> > Ah, thanks!
> >
> > > There's Marco's "kasan: Emit different calls for instrumentable
> > > memintrinsics", but it doesn't fix the problem for me (looking
> > > closer...), and GCC support is still not there, right?
> >
> > Only Clang 15 supports it at this point. Some future GCC will support it.
> >
> > > Failing to intercept memcpy/memset/memmove should normally result in
> > > false negatives, but kmalloc_memmove_negative_size() makes a strong
> > > assumption that KASAN will catch and prevent memmove(dst, src, -2).
> >
> > Ouch - ok, so we need to skip these tests if we know memintrinsics
> > aren't instrumented.
> >
> > I've sent a series here:
> > https://lore.kernel.org/all/20230216234522.3757369-1-elver@google.com/
>
> Thanks for sending this patch series.
>
> I request you to share your Linux tree / branch / sha.
> I will rebuild it with clang-16 and run kunit tests and get back to
> you soon with results.

The series should apply against -next, where you observed the failure.

Otherwise I have them here:
https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=kasan/dev

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPLX-1JzSiFzxCyk%3DY-zOupMjezeeEGa_wa7%2B-B5dtc5Q%40mail.gmail.com.
