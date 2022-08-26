Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBA6EUSMAMGQEXMNAI4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BCC805A301D
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 21:41:55 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id p19-20020a05600c1d9300b003a5c3141365sf4490340wms.9
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 12:41:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661542915; cv=pass;
        d=google.com; s=arc-20160816;
        b=go6cfIndFRJo6U/AY02zvgQOU/0u9aAkPzzG94WCRALYKMexEdKkUn+mwEeAAJKtQ2
         ShNa/ezuKUK32uu/gRcFdRMgvCVHxqhd1iVMi6r75tF6PL7mzKloMxtzngJ7Wk49OM5w
         zKa4aDO9cSra8gm/lV2uiOoSk81UR4YjD0ejqpNjcIxPnHHxo5HiMkmF/v+//xVp3SeP
         l9JhJzxNoaN3CTbeuUabCJ3V8c08eismH2apBC9rTmGgr8fKl60gBc9T5AvbXzwTOrJ6
         85u61ubArYx6yZbEax1NnhHuqTqRXoJ8Faz1s2x9gBLpR4LhRi5xgC7XxGXbhqB1mHM1
         eD5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=92MicaUg+CLxvy1UYm009fXJeAEd2pVQvCTzfw8KLxs=;
        b=S+up8I0DpU87HlwRy3EGv3qjJmZnTkd70mo6DA5nnCFHnvlT3VGcKXAxvLAzpB8fln
         hgA4n8KA3v4Ny4AffQOXb17OcWqCxg8AomEcZ+mqebu3IMAfEsqt8fDFi1B/v+K6Frxf
         C8dPzPO9KBrFvCEx5Hj1XXAnCEpMfvpzZGayVb1f0rlAf7ahQc7MssC+tXfBvOyrHZdQ
         TwWZ66y3oeTgI4QPEgWSob3IUgxh++YrkOSzNJqYfmGUGXIbn3qsNKSNVliV32bEldGP
         RJVdWXuLWYuJONHplooumIRfEDAFmywR/h3EAvQ/XQcmBG+PgH9Aj4DZAN+XsLyMkZCl
         B6lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=OpNlxqMQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc;
        bh=92MicaUg+CLxvy1UYm009fXJeAEd2pVQvCTzfw8KLxs=;
        b=TZlmkfJqncQHkExS6i1pPA/aVV2QW5rqYVoT/bFjpmTjh8aDK2bsx/r/TwFA8j3Ipw
         rR/VvSLbHchfBoi8QCcmyBdGVjBfxdKdizaLdRHBwS2PAFzdsqL8f9U9z41DrCpoB2z/
         NN4KNiTrOEoSWB/V2EdnU9DtNIbf9hW6vqcUez9PF/g0ZcVowPjvQO1Y3NUbnXrzlX4/
         XWOFHDHRca9Gk5SV6B76bgwUCJ/+P1zMM2LhEvmNKNWY3Hq6i/5c0EgaZA+RPE5uZc6D
         GaYctQjmmxXzQtM7wLCa5VdWnoc44nlrmtEfqPkYaCUmpPPPVWAn3uCS1w0zWo90Q9s0
         k/kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=92MicaUg+CLxvy1UYm009fXJeAEd2pVQvCTzfw8KLxs=;
        b=XsBdP/82W7Fc0HelEkdJp3wB3NbZlYtUV69sSzdMmAlucdAIDKB7pZ5IFGUaxOOe5+
         q+zg0EBmy06Wu5y+0DFbXRq5xZXoO7pVui9W30xxc1YQqu1vQH5MWaJHvQ+aMaxIrbEA
         AHBbQlnd+52b9kcuCh1Ewbqo6xOf3x1yMrMkEZZD9eFv1mbGlhlh3EMev7oszR9xKl9g
         zcXVspwXUQMTIafEV6KUIObcyaTCiPura5/qFt2sLvkjlOJKzfdxwqwHXepw0z/RZO3h
         ig3TMlF/Abimov6HHVr4dNI82W7IsM6KGoiltpp5qIMHzmT84uh2AEC+re1pYlvp3/7n
         4zTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1+f7M/Is30zp1psRZ8KfddstnkD8QhN2AvpnZ/bmrfpwERL9V4
	wWbsZXsoV77hDQUMFXCGFYU=
X-Google-Smtp-Source: AA6agR7Se/7FsJ63yWNmLCG7bYCHh1LSLREmXVgKzlryYtjdasC/bI6Ax9Q5X+XYSGy1R/NmOhhN3g==
X-Received: by 2002:a5d:64a9:0:b0:225:66ef:be9d with SMTP id m9-20020a5d64a9000000b0022566efbe9dmr625389wrp.604.1661542915343;
        Fri, 26 Aug 2022 12:41:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:225:26dd:8b59 with SMTP id k20-20020adfd234000000b0022526dd8b59ls1150135wrh.3.-pod-prod-gmail;
 Fri, 26 Aug 2022 12:41:54 -0700 (PDT)
X-Received: by 2002:a5d:434a:0:b0:21d:aa7e:b1bb with SMTP id u10-20020a5d434a000000b0021daa7eb1bbmr642929wrr.619.1661542914129;
        Fri, 26 Aug 2022 12:41:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661542914; cv=none;
        d=google.com; s=arc-20160816;
        b=yLbss91MefS8Oy/QrVMd/T4u7+HQQaoTjPZ6ECHjyauS4vF9zGEEIVk1razT52WsMK
         Mr7zl40xivwkKGbljFZSkOLO13yctEoE2UIZQIlWQE5Qw7h3zf4D5XO9NaMTV5CDHbwA
         LtVq4iT8aaTT0tzpvKtmsJRivQN2xSvM4sexQrkL0YDczKvKwyVjycMnHPL6iYnefrMf
         ED7EM27NxKgSa0Ab8ELu3Y7hi97OmpUJgJzaNGsELTojigHMHJOF34KI0cYOfO4LhaHT
         h29n83wArFAEBHrRMgtdWQh+Dr3v1kZjx+aL3K5vKDBYkle/mJnX6ktnJ/lE+Xo6KtIN
         KvnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qH9fXuLG/2N7XJd2Ax6mCY7hEPgeeICD6t/tT+e4ZA0=;
        b=Y++0uFxXRRGN2avihUukriH/8bmqs3olFY/ECgDrSNrxfsOTNKXYYozMTuXbtHOy5O
         +4lmcZyS3VzgNabLv5pXSjX3XERfCh6tqXm11K9GNfPOtUXmL1N/o+aaUxjnS7Ko17xG
         sMM96wj3bScs5thYLoMz31+Zlp3GgK7hXluf2B/3GPoRpKFK5uaxAL1lLzEt8vd5lvPA
         riGZ5VonhbzGfDYB8AjO/DvodTzWiSJZn5TvPPuwW38uuUyw/e5oA21XYKyZu2E0m3It
         OG2/zaenel8CDfV9NppNfFsBN+Tv6mrOxmQch9qZ/4h2BSr1iKIcpeE7HlGRCk1Tv7jM
         SBjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=OpNlxqMQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id ba13-20020a0560001c0d00b002206b4cd42fsi11434wrb.5.2022.08.26.12.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 12:41:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 2so3325677edx.2
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 12:41:54 -0700 (PDT)
X-Received: by 2002:a05:6402:b74:b0:447:d664:83f6 with SMTP id cb20-20020a0564020b7400b00447d66483f6mr4463045edb.303.1661542913551;
        Fri, 26 Aug 2022 12:41:53 -0700 (PDT)
Received: from mail-ej1-f41.google.com (mail-ej1-f41.google.com. [209.85.218.41])
        by smtp.gmail.com with ESMTPSA id ku13-20020a170907788d00b0073d53f4e053sm1240386ejc.104.2022.08.26.12.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 12:41:53 -0700 (PDT)
Received: by mail-ej1-f41.google.com with SMTP id p16so1864868ejb.9
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 12:41:53 -0700 (PDT)
X-Received: by 2002:a5d:4052:0:b0:225:8b55:67fd with SMTP id
 w18-20020a5d4052000000b002258b5567fdmr600450wrp.281.1661542902549; Fri, 26
 Aug 2022 12:41:42 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-45-glider@google.com>
 <YsNIjwTw41y0Ij0n@casper.infradead.org> <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com>
 <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com> <20220825215754.GI25951@gate.crashing.org>
In-Reply-To: <20220825215754.GI25951@gate.crashing.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 26 Aug 2022 12:41:25 -0700
X-Gmail-Original-Message-ID: <CAHk-=wj_nfiLk_bzjD8GWFFzm17syvOYqS=Y7BOarMSTkMiamQ@mail.gmail.com>
Message-ID: <CAHk-=wj_nfiLk_bzjD8GWFFzm17syvOYqS=Y7BOarMSTkMiamQ@mail.gmail.com>
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
To: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Alexander Potapenko <glider@google.com>, Matthew Wilcox <willy@infradead.org>, 
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
 header.i=@linux-foundation.org header.s=google header.b=OpNlxqMQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Aug 25, 2022 at 3:10 PM Segher Boessenkool
<segher@kernel.crashing.org> wrote:
>
> But UB is defined in terms of the abstract machine (like *all* of C),
> not in terms of the generated machine code.  Typically things will work
> fine if they "become invisible" by inlining, but this does not make the
> program a correct program ever.  Sorry :-(

Yeah, and the abstract machine model based on "abstract syntax" is
just wrong, wrong, wrong.

I really wish the C standard people had the guts to just fix it.  At
some point, relying on tradition when the tradition is bad is not a
great thing.

It's the same problem that made all the memory ordering discussions
completely untenable. The language to allow the whole data dependency
was completely ridiculous, because it became about the C language
syntax and theory, not about the actual code generation and actual
*meaning* that the whole thing was *about*.

Java may be a horrible language that a lot of people hate, but it
avoided a lot of problems by just making things about an actual
virtual machine and describing things within a more concrete model of
a virtual machine.

Then you can just say "this code sequence generates this set of
operations, and the compiler can optimize it any which way it likes as
long as the end result is equivalent".

Oh well.

I will repeat: a paper standard that doesn't take reality into account
is less useful than toilet paper. It's scratchy and not very
absorbent.

And the kernel will continue to care more about reality than about a C
standard that does bad things.

Inlining makes the use of the argument go away at the call site and
moves the code of the function into the body. That's how things
*work*. That's literally the meaning of inlining.

And inlining in C is so important because macros are weak, and other
facilities like templates don't exist.

But in the kernel, we also often use it because the actual semantics
of "not a function call" in terms of code generation is also important
(ie we have literal cases where "not generating the 'call'
instruction" is a correctness issue).

If the C standard thinks "undefined argument even for inlining use is
UB", then it's a case of that paperwork that doesn't reflect reality,
and we'll treat it with the deference it deserves - is less than
toilet paper.

We have decades of history of doing that in the kernel. Sometimes the
standards are just wrong, sometimes they are just too far removed from
reality to be relevant, and then it's just not worth worrying about
them.

          Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwj_nfiLk_bzjD8GWFFzm17syvOYqS%3DY7BOarMSTkMiamQ%40mail.gmail.com.
