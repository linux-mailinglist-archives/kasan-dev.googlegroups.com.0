Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB3GIT2MAMGQEGI7TMKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id A2F935A16BD
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Aug 2022 18:33:53 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id qb39-20020a1709077ea700b0073ddc845586sf404488ejc.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Aug 2022 09:33:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661445228; cv=pass;
        d=google.com; s=arc-20160816;
        b=V6XN3is78xB9TW+dEPUNw+3cITtADhZBWiDSMq3Lr91imE1VxEG3Ta7Nf50doKG63W
         Lr5nZmxlCTmLh3EKjPtrREFzYPijdgUi55YQ0963kYBkNL7YpN8o0v2V11xI+KpJQXUu
         +CLx1FEN764G14ajUT7mKPDiVFPWV5CuoePm7KkSJampYCBMuChM/k+Kx0ch19EL0lg0
         qsM8yX4cCRqPPP+y8mY28qEzbWvg4fM6vlnHmQ/gnf9jDTV0cWVvuyds+7DEVfdjKGpq
         tFZF4vtrpsJNg8wNfETWRETPa0KksJyOfuF1IG5NbH/dkPTXldbyVl1E2bPS/rEkYYIy
         FClA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=8/3oue9MpaiINhHW/Mh+2CN3IlrEcRsoF+KYGSDfonE=;
        b=gEs1paZKhlofjUMJqeo50jPQWRmpCwsb/n7G6P1d4ixy3fH5Juhgc0I/KBjL3896W1
         VGWJEeRBZHKabDXph8+Y1H7NQy7n6x9oOB/p9a30Eh8cVuX5RPZ1hjeJ3L4hnIInMpLL
         XRSHIJFXTbLqfKWQXqM8+Zg6LMoQ36mTXogBjt+88w8sRkEim//PyjRc9SwIlFlKfVMW
         ocZYOmgkrpRc0VDK0JmgZEgWoFuq9eLIes1QyhuBw3B5Om4CCL60+I8F+J5KvnIYz8Z0
         FCPUAtjv3Oywtf6gC9erJKPLM7GLL0OrXia851grKHxxy7VkMJe0XJiu+xS6lysC6beQ
         IBvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=NQdfXYry;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc;
        bh=8/3oue9MpaiINhHW/Mh+2CN3IlrEcRsoF+KYGSDfonE=;
        b=IW7B40pefi2k+2E88RLYDHYuyLXXHBGn2qB5ki8RCSnZOVZG1ENig2ThNTkd0UQMd7
         8b0NK5LJJOQ34OFOwfUfuTVuMjEHJ+7sREphZUgPz9AJ4IrW5DkNnCCNJoPi/GTlYfeI
         fJCsFK9aaQRRvk2bknb0KF++ATwcylSJf9kr8/euiScqvIZ+ap6Ohu5YxgF+PwapB5ln
         BIxZmviTYQlViytjMy5w9oANdTNywhZUGR04HMYchgwCoZdqo91loGuqQUdcNxKjvZ7X
         RbY9EpuS1wiI68n6+v4DHvNRUoBLxn/GwgZzWfOl8TGpYX9q3uJUIjcAb/Sd1ej9hPFr
         JXwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=8/3oue9MpaiINhHW/Mh+2CN3IlrEcRsoF+KYGSDfonE=;
        b=TOIgWwrEWN8ElbKhqiEsyIfB5KkIHQPbYpjAxxtRrkA2dFDzxuWfkZN31aXlJ3k6Ti
         UfKWZpcrDqZD867gzB3xS5dSZom5YcwpScRiDiQGJ6HunhhsJsKL7u06WJ/lztaf9dcM
         uvr2XGyYJZiSihrFvE8w65yzlbOoObXXX4yeT6vneWLvU32LmCCh7kKeBu6OyDqDhPx9
         1V3nvnCPRW8IwBaGRlo/oJlLQF/hO2cG7DLmLhAn5zSCd9j8mEKjyD50z7mNHb7vXJJU
         veCtQbY9bFIclLeIwrwsQolbRJOfNgmUgg6Y/JZK4uQ9T4Ol8LLKJ5NdOcVlKOHzgQhB
         7jhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1fe2RJr3xxPHsLQpDMTHK2hkfTCMMcb8nJI9VWhqn9V5Mn43ZD
	kwKh9TK4UPNGwhZolU7d83o=
X-Google-Smtp-Source: AA6agR6LtUIZ8ZQFeDxGPWHYlxRdIVsUdfElUSpfiGzLLo9QNYUa5IQP+NWwcb9G7yTo85Z0BxtuzA==
X-Received: by 2002:a17:906:ef8b:b0:730:e14f:d762 with SMTP id ze11-20020a170906ef8b00b00730e14fd762mr3058053ejb.519.1661445228310;
        Thu, 25 Aug 2022 09:33:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:76ad:b0:73c:b61c:65e3 with SMTP id
 jw13-20020a17090776ad00b0073cb61c65e3ls872868ejc.11.-pod-prod-gmail; Thu, 25
 Aug 2022 09:33:47 -0700 (PDT)
X-Received: by 2002:a17:907:7dac:b0:739:8df9:3c16 with SMTP id oz44-20020a1709077dac00b007398df93c16mr2935912ejc.9.1661445226913;
        Thu, 25 Aug 2022 09:33:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661445226; cv=none;
        d=google.com; s=arc-20160816;
        b=ijnNvFpNM01SWICl2eq/Wci8Ns5t4x70qM8nRI2EwYHBGa/Ul05Zq96oI3O7qsZGg2
         NcffXN3779svMdNhsezhX1OWmH1vs2PKw/R3nhehmYFzr5hA3Cc2mu+gPsPLg5FI1RSV
         83hgKDu3/PHOoCqNAL0qiB5kY/SkD38fVl9zPvpYAeFaUvfGGdrkHEP7I/WFflqdOTUR
         iR21M5zIgJrd5N52+4XV+CNPPbIXwMhPhP4ZcKxyrzvoaweOfoMx36yBo0nx7Cmf7yrt
         xqXx+PQojDR1zvB0FaG8BCt7rBvd5Comk+KKeaF7fqxgo2yWlFNpVpEkp2jIEf5H4yEh
         p3AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4kxSioqpPleGpZIZkkWOJIrDSHemVIWhFh1D4qTNMMk=;
        b=aHSTCEXVIPXDNcw6h1ep6CABudp5GlAiGSLzCY37bEkIJDtpVS/zepkAiMloEwXxlG
         zW3Lzf4+ZQLehGQDiTfrH+5iKlbhZuoRBXx0/E/EA2c43xROaUOeFQPD2SszYcTbUu8P
         S0US2zkxGVTKqhrQEXhGZeRbKJymiONcpNqpCOLJvGRGT/Xm2sJUL59V4mwS5DGcYdGG
         /4k4UdGdUbrwvthT3NbIVvx7cL/NB8T+z66QZ66VX51lgjowwp0H+r8MqfNhtkIdQJ5d
         OKqUbsYIvL9IxDzma+SfFjOI44v5Yb5YBZlpEUceZzk0tgOULUs5M07YYGTmqCkIoozZ
         BjAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=NQdfXYry;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id g13-20020aa7c84d000000b0044609bb9ed0si434973edt.1.2022.08.25.09.33.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Aug 2022 09:33:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id w22so5033412ljg.7
        for <kasan-dev@googlegroups.com>; Thu, 25 Aug 2022 09:33:46 -0700 (PDT)
X-Received: by 2002:a2e:a4d6:0:b0:261:e561:5bd6 with SMTP id p22-20020a2ea4d6000000b00261e5615bd6mr1256765ljm.464.1661445225946;
        Thu, 25 Aug 2022 09:33:45 -0700 (PDT)
Received: from mail-lj1-f180.google.com (mail-lj1-f180.google.com. [209.85.208.180])
        by smtp.gmail.com with ESMTPSA id p3-20020ac24ec3000000b0048aeafde9b8sm577254lfr.108.2022.08.25.09.33.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Aug 2022 09:33:45 -0700 (PDT)
Received: by mail-lj1-f180.google.com with SMTP id bn9so12437395ljb.6
        for <kasan-dev@googlegroups.com>; Thu, 25 Aug 2022 09:33:45 -0700 (PDT)
X-Received: by 2002:a05:6000:1888:b0:222:ca41:dc26 with SMTP id
 a8-20020a056000188800b00222ca41dc26mr2662375wri.442.1661445214833; Thu, 25
 Aug 2022 09:33:34 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-45-glider@google.com>
 <YsNIjwTw41y0Ij0n@casper.infradead.org> <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com>
In-Reply-To: <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 25 Aug 2022 09:33:18 -0700
X-Gmail-Original-Message-ID: <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
Message-ID: <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
To: Alexander Potapenko <glider@google.com>
Cc: Matthew Wilcox <willy@infradead.org>, Segher Boessenkool <segher@kernel.crashing.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=NQdfXYry;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Aug 25, 2022 at 8:40 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Jul 4, 2022 at 10:07 PM Matthew Wilcox <willy@infradead.org> wrote:
> >
> > ... wait, passing an uninitialised variable to a function *which doesn't
> > actually use it* is now UB?  What genius came up with that rule?  What
> > purpose does it serve?
> >
>
> There is a discussion at [1], with Segher pointing out a reason for
> this rule [2] and Linus requesting that we should be warning about the
> cases where uninitialized variables are passed by value.

I think Matthew was actually more wondering how that UB rule came to be.

Personally, I pretty much despise *all* cases of "undefined behavior",
but "uninitialized argument" across a function call is one of the more
understandable ones.

For one, it's a static sanity checking issue: if function call
arguments can be uninitialized random garbage on the assumption that
the callee doesn't necessarily _use_ them, then any static checker is
going to be unhappy because it means that it can never assume that
incoming arguments have been initialized either.

Of course, that's always true for any pointer passing, but hey, at
least then it's pretty much explicit. You're passing a pointer to some
memory to another function, it's always going to be a bit ambiguous
who is supposed to initialize it - the caller or the callee.

Because one very important "static checker" is the person reading the
code. When I read a function definition, I most definitely have the
expectation that the caller has initialized all the arguments.

So I actually think that "human static checker" is a really important
case. I do not think I'm the only one who expects incomping function
arguments to have values.

But I think the immediate cause of it on a compiler side was basically
things like poison bits. Which are a nice debugging feature, even
though (sadly) I don't think they are usually added the for debugging.
It's always for some other much more nefarious reason (eg ia64 and
speculative loads weren't for "hey, this will help people find bugs",
but for "hey, our architecture depends on static scheduling tricks
that aren't really valid, so we have to take faults late").

Now, imagine you're a compiler, and you see a random incoming integer
argument, and you can't even schedule simple arithmetic expressions on
it early because you don't know if the caller initialized it or not,
and it might cause some poison bit fault...

So you'd most certainly want to know that all incoming arguments are
actually valid, because otherwise you can't do even some really simple
and obvious optimziations.

Of course, on normal architectures, this only ever happens with FP
values, and it's often hard to trigger there too. But you most
definitely *could* see it.

I personally was actually surprised compilers didn't warn for "you are
using an uninitialized value" for a function call argument, because I
mentally consider function call arguments to *be* a use of a value.

Except when the function is inlined, and then it's all different - the
call itself goes away, and I *expect* the compiler to DTRT and not
"use" the argument except when it's used inside the inlined function.

Because hey, that's literally the whole point of inlining, and it
makes the "static checking" problem go away at least for a compiler.

                     Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw%40mail.gmail.com.
