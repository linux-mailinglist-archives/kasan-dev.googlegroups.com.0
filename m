Return-Path: <kasan-dev+bncBCA3DTHS4QLRBGNARK5QMGQE3KP56ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E3C59F60AD
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2024 10:04:27 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-6f2b3f1eb8csf28390427b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2024 01:04:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734512666; cv=pass;
        d=google.com; s=arc-20240605;
        b=FbycDL0VckbGTYvlrT2XWj8psp3HKU6pmxHNQUuD/ZxXZP8ThAfIFsqJRwyQaHYlgO
         dpGqMCzudTCepzGs/tEXvXHpc8UBqvXnEcxFiCY5T/PetJoEdR34b8LEM8bIkjICBSqN
         JiXsWfBnb8pVYPPGQS/3/TIx6Q2PIupOG3RpMwC/8oyi1H7wZYbHw/mBaZp5rtaaxoAq
         LVYktpljgXTEkwOxoFPunp4dDG0JExXNOxJlbK1ZaooGetnNjsLntZ7XI9TsQf7H9ES+
         BS0feOPUR2vzP4S/6WlczfL3Q1izsLG/IrJX3BhPQ1Bl/I9jFFlhMx6JifUvosVLX6v1
         bVJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=i7T1OuV8eA0YoFRvCikjEJOXlcHZxabzLV+o1v8eXr0=;
        fh=yXtntXUpdKq/ztTHiN+VUqMdHYQGktaO4R72Fs8/yuk=;
        b=K9KtgatbgqyH6fIqyzNLmaoclHYEVghQzIe3X7iugFIRDgJOtIesiJqqyLgQ2VTb/P
         Vjdb/UikSY0boTm+YXHCXfB3P+1Lio55fUuEM63Him+eTsRPcqgJF/2BHFxFswAiSpCA
         fzSyMDPImMdgEhE+4AsONQN/lERXowS4KKSqOcXf7NI2vIJFL/ZljSD3Cnac+bNGhrA1
         taDMBKEAXQgqWuiVMJkU19S/VdW1vRUVNtQWmLZYEXBa46g8YC8CWuNVLjN9AxJY7s/g
         0QmtgrWtil2EzAE959EEg73FVetXrIpuzWCCA6gmmp9TQ0AWJHCmDO5DPvbQM/F4WjBh
         K6PQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hz8pjgJq;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734512666; x=1735117466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=i7T1OuV8eA0YoFRvCikjEJOXlcHZxabzLV+o1v8eXr0=;
        b=atR3OL8fr2CXd66smfolng+U2y1WVlw6CldlD+utXCmlRGETMNcUZYo1fQ8knldlal
         E2rVqYKZUYy35HswuLi7AiBmZNz2iXF0ghuX6q7uWCLMcelSUa3CvstfUiYZCeQ0S6Uh
         t9v4AcwNF/DR42cYQkbJeYrApTCtZDbzOOjGnwKUUtfnpbmQxHygLBOFesFJC0WakKnV
         XE0tE5Cgi2C45V+j1lztfC2tAhhMuHA5Z7iuEKC6q3XyEJJ+ennizCa17yPO9NS9OMKp
         xicicG/9HAIBJ6yLkbymK9u6QyifJoH65vcozGthNo5rvQYbqQv2qdnLN3SDr5ScrvZM
         HkNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734512666; x=1735117466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i7T1OuV8eA0YoFRvCikjEJOXlcHZxabzLV+o1v8eXr0=;
        b=caJGuJHrs+CekR8J6DwkOIULXVv1ZEBX5QdfdccIHGYKE04yeFMl1oyKW3e+LFNcxA
         BXpiLdMMxJA9qLYzaPba/xX5Pu6dWcyT1hmru6CsylOSM+24GHsPaY6kv+2nNyLLuO9Z
         jJw3Rjt54cjcdtLcjdqfveLmPs9uUpgMKQGdUwWQgkk6WnugbHl31JmfYE91nxWLLQeS
         /f/M3VcKwpdyK28uH+QwH0EKselj2eqCz9LX/A/ttZusv/RE2lJ1meaHlMskp8PPyTuz
         BlvSB4ryNADKBpLA5Zkrgmn8JtBAQ474gdqE++jzhrNgk1CH6MDxrtzTemdIMyoveusu
         PV8A==
X-Forwarded-Encrypted: i=2; AJvYcCVChyiBMqxiqU3dE3Np5uGx4qUUcnCBcLyeVmpstuwctzPLRndyOpt1Oq0oy9IG0LrCr2VrKQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMBkawvk+ZeBlm6c6pgOLr/Puiw+o61KzEX6ja4J8QV11MozNi
	5LcsqMTxR218/pKsEeGZ8ia3umTxLDYDgCsXlKdeBT8KC+D0oNGn
X-Google-Smtp-Source: AGHT+IFOX7S4B2rfZAvGC4XUzhv30DDqDibxUT8IHsiEwRICVYqSxGuUytF5yO8ekvQJMptb9DKZHQ==
X-Received: by 2002:a05:6902:2008:b0:e47:f4e3:87f2 with SMTP id 3f1490d57ef6-e5362166889mr1362954276.31.1734512665995;
        Wed, 18 Dec 2024 01:04:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b298:0:b0:e48:25c2:a5d7 with SMTP id 3f1490d57ef6-e4825c2ae5bls859249276.0.-pod-prod-06-us;
 Wed, 18 Dec 2024 01:04:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW7YanZGnSeOPyDb6/nW2MJf0yX5voXYjtC5zdZn7BPqm2g0SoCaDvAjNvYbaM2fcXSO3C3HQRDfi4=@googlegroups.com
X-Received: by 2002:a05:690c:4b0f:b0:6ef:7036:3b57 with SMTP id 00721157ae682-6f3d26799dcmr15670947b3.28.1734512665146;
        Wed, 18 Dec 2024 01:04:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734512665; cv=none;
        d=google.com; s=arc-20240605;
        b=K0RHwlRDSYCtu9wEY1KWAXhk4pUXXj/u6pj5QODJnt1tqbv39vOZIQ2+xBNayfhLj+
         lrCDXZ7e1YmnmQswtMxjWldIjbwP86Tuz9steG3UKHsSVLXQxG9HkIZUEYX+XKunjqxZ
         rkk9OFWNRt5tYkCxeYCNKmovXTLTv7zL3ANBYsQzpjCds18p/dtWc/fn2i00kILb+XKe
         UywwUkP9awAQd2sA6Ki0tOc4bMvQu/zKkFxBtxtMclbkb3gMcJKyQmLyCXWLtoamSKBN
         Ycp2YKlHiwNOPTbMYin7YsazlyqMgOSWkRfhi8LAwFOz6Su5XDyMv6Iqbb6uF5uWOIXt
         IZhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CbSkSQe4R7SrfVQgqrkefXYWnBh3gDoYCa5LEb6lK5Q=;
        fh=smqNO/heR4s9rFq7UK6ANZ9L3Axc6mqfKi7hc5z+6O4=;
        b=cbBFbZmpCH+jKseP9Lz+0TnZBkoiaj9ieBF9nVK2H3rT3svclc/2om8X1WeJota2Bn
         XxdG+JTJXo3iqDJbJxjXX4nPEfLFYfWi3IdsZqcF3NjcsMufGo2tTvdZl0nGPx+mzaoy
         1ErimohjZUwdFn1FVLlKele3HnesyHDJ2WTpAYRiGcr1b4yE0aaxA785f7aiOyogCcdw
         NHICH35or/dVDObwvDPyH/w25grtCYUxsUscPQlOYuND3mu3GW3i7woVK1W3iu6pIp3J
         s0LrMH6njWZNFCSbyZ05+Omv4X3CaYldjXbYhHDqXuGdeo4YDBTdnTgeQIdqx5smCx31
         0xvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hz8pjgJq;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f2890c3b2bsi2536497b3.4.2024.12.18.01.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2024 01:04:25 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 0E72EA4208A;
	Wed, 18 Dec 2024 09:02:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 187FAC4CECE;
	Wed, 18 Dec 2024 09:04:24 +0000 (UTC)
Date: Wed, 18 Dec 2024 01:04:22 -0800
From: "'Josh Poimboeuf' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcov: mark in_softirq_really() as __always_inline
Message-ID: <20241218090422.c66wse2kswnazkou@jpoimboe>
References: <20241217071814.2261620-1-arnd@kernel.org>
 <CANpmjNOjY-XaJqGzQW7=EDWPuEfOSyGCSLUKLj++WAKRS2EmAQ@mail.gmail.com>
 <20241218084049.npa3zhkagbqp2khc@jpoimboe>
 <6df09ea5-1478-476c-8bc2-16217a4db3a3@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6df09ea5-1478-476c-8bc2-16217a4db3a3@app.fastmail.com>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hz8pjgJq;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 2604:1380:45d1:ec00::3
 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Josh Poimboeuf <jpoimboe@kernel.org>
Reply-To: Josh Poimboeuf <jpoimboe@kernel.org>
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

On Wed, Dec 18, 2024 at 09:49:46AM +0100, Arnd Bergmann wrote:
> On Wed, Dec 18, 2024, at 09:40, Josh Poimboeuf wrote:
> > On Tue, Dec 17, 2024 at 09:30:24AM +0100, Marco Elver wrote:
> >> On Tue, 17 Dec 2024 at 08:18, Arnd Bergmann <arnd@kernel.org> wrote:
> >> >
> >> > From: Arnd Bergmann <arnd@arndb.de>
> >> >
> >> > If gcc decides not to inline in_softirq_really(), objtool warns about
> >> > a function call with UACCESS enabled:
> >> >
> >> > kernel/kcov.o: warning: objtool: __sanitizer_cov_trace_pc+0x1e: call to in_softirq_really() with UACCESS enabled
> >> > kernel/kcov.o: warning: objtool: check_kcov_mode+0x11: call to in_softirq_really() with UACCESS enabled
> >> >
> >> > Mark this as __always_inline to avoid the problem.
> >> >
> >> > Fixes: 7d4df2dad312 ("kcov: properly check for softirq context")
> >> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> >> 
> >> __always_inline is the usual approach for code that can be
> >> instrumented - but I thought we explicitly never instrument
> >> kernel/kcov.c with anything. So I'm rather puzzled why gcc would not
> >> inline this function. In any case "inline" guarantees nothing, so:
> >
> > I'm guessing CONFIG_DEBUG_SECTION_MISMATCH was enabled, which enables
> > -fno-inline-functions-called-once which ends up being the cause of a lot
> > of these __always_inline patches.
> >
> > I had a patch to get rid of that at some point, guess it got lost...
> 
> It doesn't seem to be the cause here, I get the warning both with
> and without CONFIG_DEBUG_SECTION_MISMATCH in random configurations.
> I've attached one .config that shows the problem without this
> option in case you want to investigate further.

Guess I should have looked closer, that function is called more than
once, never mind...

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241218090422.c66wse2kswnazkou%40jpoimboe.
