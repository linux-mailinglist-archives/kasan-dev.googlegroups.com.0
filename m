Return-Path: <kasan-dev+bncBCW2HNMCXUPRB4E6SHWQKGQE4CK7SEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id F36D9D6049
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:35:29 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id s14sf17517376qtn.4
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:35:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049328; cv=pass;
        d=google.com; s=arc-20160816;
        b=N4CQsmKflcR2KRKpHgkby8YcRQDTFpelhWvp8Mi4fR+rtUsvasD+5C8SgLKBUEF66B
         mdei9x/1udUn0/iyFyuVhzcPLVg9xc1uvTFPXTqzPOlyDxTQ+VINIjake38Ykglt/l8C
         RrxpfcTi5UlM5cDwGB4zUDUOcN2P56d8XY5+Eg1vPCieUSJDA2OT8jkT1kLFCnkiacCS
         MvTcaTDJxHv26n1by4HdX8/TU+qToVRVSuc7s062H/jJXOQ4AhlWyC63UfILIUpKymbq
         lAhfXre7s3qiqltWDxOds9kqkLvrddNaUC5iQPfc+X5hJ47M/Hw11PPMV7SWkzPf0Lhs
         /LzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=9xg6zDQ0PYkF/AUL/RFdi6KGBUmE5CWCTiLxdSJMB8s=;
        b=ndiqwOWKWUY2nOtZMmH7yk6b3DdyRvrM/+N48nhJI/0htiddbkLiQ6FvMVe9FGJE4c
         DAOS8qFzAd3tpezCJ3L48mXVCvHriAX36bCudndK/0GRrMyB9iXd3rdDPcCn18uTnzyD
         PXs+4Ja1DMU1KDAgD3eIfcXzsyeNPmWkM5X2Rr7a0hJgE5IDKlNTdoFh3Rlx35TCBTMr
         6yC8bhToBxMePXRC3pSx5JQPo+fLA741Y6Yfts1JHciqzbBf3zRAuLKINHp8Fu7gQMEA
         lU9jzvfR2H1YHazFzc6ChsVrR70Yl5V+e04oiKJ0w4rui2RNU4450xBbuHnmfkKZgzvL
         o3Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jBE2A2nj;
       spf=pass (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=parri.andrea@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9xg6zDQ0PYkF/AUL/RFdi6KGBUmE5CWCTiLxdSJMB8s=;
        b=VA6fDzIdA8BxhDPVqQ3y+oxt8Gba/UVsT/cCihcTVn4Emkv6fymf7ZJnm94aOmI/2A
         JcD3dGjTqlukg6ZoAyNLa4qgF13bDjd9JEoe+mVT0xRiLHBFM649ZEJ/bvNsdkUPV5JH
         /R/mc1hyMpqkPfef6zId6tQbCA6W7G2sQR6ZYUfVyF2X4yD7wr2mlJW1u9oNHEZyFCqs
         5+7sELRMarkeK1omBcOlJkGjHzyCnsY9e7PQHlORa1y9I6NoQCA+a2XUTnCkNsQL8VQr
         DywIIAkVfQya66hOaWCzuh37RHQ7K8EILwnkboEHR4vfpfmWTSbxlWH8ALDDJNY1izYx
         uf4w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9xg6zDQ0PYkF/AUL/RFdi6KGBUmE5CWCTiLxdSJMB8s=;
        b=r4zpmVdjvgNcuKYSNYYQD+27GtNmLt0H3MV9yZC2U5iDclIVb6BEd6a56mpmtSmYzn
         h0obZG/l6H2KA7uPOr5Y6Vn+3IbAmrojlhuzQSujd5TQVQkNHWPbijlBCJ9kqAoegJxh
         i89A2CIDYHIIjd0AVY8ANI7axCTZHxn2PHje7Gr3NPzu/r3mBPSpJ1v3LYPdC383+TVm
         j+A4IHwgOhYb6Pj/8f1TXakPZ1JwhF4+oNLbCIB6G6q+pIQxR5b3e31+h7/9PjQRrT9L
         2oSPN4Civd8xxyBftDE82V0SETE88K4/4ldxdtw8GZH6UHjVlzsT9dV1WJlT88stj1ts
         dFug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9xg6zDQ0PYkF/AUL/RFdi6KGBUmE5CWCTiLxdSJMB8s=;
        b=uWojgpSOHLJBXaE8IL0YApZJBHSvHqf182rKC/5KWTYY1dZ3L5BBl3MV9XDeVHheQY
         zOdYEA1U59M+mRVkKjyeIUx6ICXtZmjb2ma0f7XSDNhXJOt8YACmjce3poaFhtbTc9g5
         uhv5J3wo88uw9UT3JMrpi/5wf/H/C9+V3odk3k8Bzb3R3MGgO/MSfSkRN4+WO+t/jDU7
         13Udq9SktEQLMM3x2ErReJWtaGL/RyIZmJpGuW4mdQ5ZqlXsqC44XhBVCtEfKiaxJ6Hq
         cjW7Oet4VTcf9T8pii3AeU12SfVdPzxgEnNHdlyOrpmFiVv//36pcR44gtFN6j8hzS+K
         x1Sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWWEocchz7RfbFV5SS5iRYv4KGD+Ukif+ZaMWut1fn7LuPg0iy4
	O5Rs17PYmLMo0w36ZdqnI30=
X-Google-Smtp-Source: APXvYqxKG6+aVicVBtR4hGjQKLODWzkzbbX0ozObgwTB+SQ8dFuwpSoWgtHxGpb7t1+JjV8aLe8LtA==
X-Received: by 2002:ad4:4433:: with SMTP id e19mr30180856qvt.105.1571049328454;
        Mon, 14 Oct 2019 03:35:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a853:: with SMTP id r80ls4090612qke.0.gmail; Mon, 14 Oct
 2019 03:35:28 -0700 (PDT)
X-Received: by 2002:a05:620a:14b9:: with SMTP id x25mr29422509qkj.9.1571049328306;
        Mon, 14 Oct 2019 03:35:28 -0700 (PDT)
Received: by 2002:a37:6710:0:0:0:0:0 with SMTP id b16msqkc;
        Wed, 9 Oct 2019 13:17:15 -0700 (PDT)
X-Received: by 2002:a17:906:90d8:: with SMTP id v24mr4687038ejw.60.1570652234931;
        Wed, 09 Oct 2019 13:17:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570652234; cv=none;
        d=google.com; s=arc-20160816;
        b=uqCreO06EpXqQhIzriqN5J8Tme0r4T3gIECGHZ3Ell7+THKPtArOeYczezTh/XhOXc
         7q5Z4UsovpGQH/l5QSdlgfh7n0RfxS/HFhRDbzmXYnlJ2X7D/L5GqIpvjFLz1OowSi97
         64yL+j1RS13kR1XnDhdy4RPKJ3NLTLl0AIDBTpSDKUaiExOeudLrfk3CL9kgvebCmNEd
         hrPxgmYcQd09ydv+jMgjiP5Q5+JbRbzgDsrlJib1LrRgeCIUirgrMAieUgPbAN5bxjvo
         z7JQz68o3myliOIAgwvyngZzsWqUj1nWZesETBSq8nKzmFn+w4qTCW4+70iLY2Uugi2B
         u4jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6AEE8so4vqanvMnabGRUAj1QDKzo4+4N4D1c+Rl4nYM=;
        b=fLVwSL9a1EI2aUqHlbk+GYx0fyBWxDVbgqxyYbECoCH0NncI+sVo792iK9l0Anb3Zz
         6YQdH9wb7mQmq9dTO9wKc+VNFf/DRqNn0RiwREKMwJNsIWaGpWk4YwwcUyGJG2Z706X5
         se5jhcdtHzyfYIwt6kUuundsaMMgRoe23YCigLtdnMapla+udGcHmjibAGdvHH+/zpXV
         0QKqz2w27bjBCKzz3lBjAS1Lj/QixBaB0hFSFDhZSfLFu4LAmKIH+q8cozAeKs2TKNnP
         3KdYTgnsvvej5ambtvULx7In9RTx5ULYmPU3wDEO247DVr1rBwNHHL9zOHD7eOrz/cvL
         5OLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jBE2A2nj;
       spf=pass (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=parri.andrea@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id c31si152695edb.0.2019.10.09.13.17.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2019 13:17:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id m18so3985846wmc.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2019 13:17:14 -0700 (PDT)
X-Received: by 2002:a05:600c:da:: with SMTP id u26mr3801909wmm.122.1570652234274;
        Wed, 09 Oct 2019 13:17:14 -0700 (PDT)
Received: from andrea (ip-213-220-200-127.net.upcbroadband.cz. [213.220.200.127])
        by smtp.gmail.com with ESMTPSA id x5sm5190712wrg.69.2019.10.09.13.17.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Oct 2019 13:17:13 -0700 (PDT)
Date: Wed, 9 Oct 2019 22:17:06 +0200
From: Andrea Parri <parri.andrea@gmail.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Eric Dumazet <eric.dumazet@gmail.com>, Will Deacon <will@kernel.org>,
	Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Daniel Lustig <dlustig@nvidia.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191009201706.GA3755@andrea>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
 <0715d98b-12e9-fd81-31d1-67bcb752b0a1@gmail.com>
 <CACT4Y+bdPKQDGag1rZG6mCj2EKwEsgWdMuHZq_um2KuWOrog6Q@mail.gmail.com>
 <CACT4Y+Z+rX_cvDLwkzCvmudR6brCNM-8yA+hx9V6nXe159tf6A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z+rX_cvDLwkzCvmudR6brCNM-8yA+hx9V6nXe159tf6A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: parri.andrea@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=jBE2A2nj;       spf=pass
 (google.com: domain of parri.andrea@gmail.com designates 2a00:1450:4864:20::343
 as permitted sender) smtp.mailfrom=parri.andrea@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, Oct 09, 2019 at 09:45:50AM +0200, Dmitry Vyukov wrote:
> On Sat, Oct 5, 2019 at 6:16 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Sat, Oct 5, 2019 at 2:58 AM Eric Dumazet <eric.dumazet@gmail.com> wrote:
> > > > This one is tricky. What I think we need to avoid is an onslaught of
> > > > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > > > code being modified. My worry is that Joe Developer is eager to get their
> > > > first patch into the kernel, so runs this tool and starts spamming
> > > > maintainers with these things to the point that they start ignoring KCSAN
> > > > reports altogether because of the time they take up.
> > > >
> > > > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > > > to have a comment describing the racy access, a bit like we do for memory
> > > > barriers. Another possibility would be to use atomic_t more widely if
> > > > there is genuine concurrency involved.
> > > >
> > >
> > > About READ_ONCE() and WRITE_ONCE(), we will probably need
> > >
> > > ADD_ONCE(var, value)  for arches that can implement the RMW in a single instruction.
> > >
> > > WRITE_ONCE(var, var + value) does not look pretty, and increases register pressure.
> >
> > FWIW modern compilers can handle this if we tell them what we are trying to do:
> >
> > void foo(int *p, int x)
> > {
> >     x += __atomic_load_n(p, __ATOMIC_RELAXED);
> >     __atomic_store_n(p, x, __ATOMIC_RELAXED);
> > }
> >
> > $ clang test.c -c -O2 && objdump -d test.o
> >
> > 0000000000000000 <foo>:
> >    0: 01 37                add    %esi,(%rdi)
> >    2: c3                    retq
> >
> > We can have syntactic sugar on top of this of course.
> 
> An interesting precedent come up in another KCSAN bug report. Namely,
> it may be reasonable for a compiler to use different optimization
> heuristics for concurrent and non-concurrent code. Consider there are
> some legal code transformations, but it's unclear if they are
> profitable or not. It may be the case that for non-concurrent code the
> expectation is that it's a profitable transformation, but for
> concurrent code it is not. So that may be another reason to
> communicate to compiler what we want to do, rather than trying to
> trick and play against each other. I've added the concrete example
> here:
> https://github.com/google/ktsan/wiki/READ_ONCE-and-WRITE_ONCE#it-may-improve-performance

Unrelated, but maybe worth pointing out/for reference: I think that
the section discussing the LKMM,

  https://github.com/google/ktsan/wiki/READ_ONCE-and-WRITE_ONCE#it-is-required-for-kernel-memory-model ,

might benefit from a revision/an update, in particular, the statement
"The Kernel Memory Consistency Model requires marking of all shared
accesses" seems now quite inaccurate to me, c.f., e.g.,

  d1a84ab190137 ("tools/memory-model: Add definitions of plain and marked accesses")
  0031e38adf387 ("tools/memory-model: Add data-race detection")

and

  https://lkml.kernel.org/r/Pine.LNX.4.44L0.1910011338240.1991-100000@iolanthe.rowland.org .

Thanks,
  Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191009201706.GA3755%40andrea.
