Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUPFYP2QKGQE4V3YMLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DF4A1C4D84
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 07:00:01 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id s7sf720401eji.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 May 2020 22:00:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588654801; cv=pass;
        d=google.com; s=arc-20160816;
        b=zlEcE3AGNci/S6h9mPzkcZQnM5Spc9EFsxxEcY80D58RRLwjomXlSi/5rQt7MtDdhv
         AfHeVkPIFNIbV5TO3PPWRLptBEqiEuQ1VYrSHTouD+OoY5g3fcYZFKJf4iKXpJauE+nB
         Ghjzf7Fc9qUuQN4ADh7wgnyEykQPCmRdFoA/5JTJKzyTt+H6DXRQtZ4OtLhZh3KRh4S0
         KacZ2hvNURr74pXzSufEdRGf1qpNPTVuwlz/Ujfyxq7+CQn34CVfwDh4TMewl5LrKsia
         5vrkmky9bkz3MfrluYA/fkXOd2Vrvmh2Tft4NxT9KMfOzvvp2G86OLCeY7XWHKrdi1PE
         fsyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ksKN1KfOng0FyN5hg6EqvzIgF6UR4tzOmvAYodfN5g0=;
        b=PahvSQ6wWKv3xzh/pEZTba/0jiK3wK3iKkWuGZHTepPNkJWuEzCiyIB+Th0pNcwyoV
         Q/Gc1mbGXFkbP00u0nuqEs6nGJh75MewaE/elWRfLOblmXhNm0cfy7B8apZTrDf1zpfT
         LrI7MdhqopW5/jYTyUUaeqxTJDONijI/++p2qo6Ql4Bn9R0s2qWWk2u8XOqnjTyl65Xe
         Zs47P0/bL9TO4aDCohZjNsApCwj52gTi7w2DdcokAnhba3AcXPWEFqpZRqZkl9LIcEEj
         z5aFzTxcPgxGOKtjIHBd5J44ezy1srn5Ct+zKRGzXVZMFLVopp4tPlfKYKbQiN0lXrbf
         Irsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XGKXoYze;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ksKN1KfOng0FyN5hg6EqvzIgF6UR4tzOmvAYodfN5g0=;
        b=l8RaD+3f9HIOR3h9080SaMrGLiYC6W6JeHTYz/yUVL948FjxTfKMJ1LHE1ov2HW74b
         kV06g/2f3WVrPwFCC6Q7syE9S7B+Y8RuuER6wMX7oFO03QYFIjaa6fCzmrpI3BtOzR3+
         foqO4vmcFajEzCvbXJ+D/FBEhbZrxFfP8a6yQUCF+HxXAbtZYMvCBmYfBvGx1n8J5pvK
         ZT60oG/vk3JwL9n5yg/IC3ApZdYEhOWuJr2drZ9kFw1rHdPBSICnyWYkn+LfxNc18Khi
         MNlZN0z71Xigsc7s/v1gi483WrF3bL8oG0SA6moZfKvESwV5WUovsI9Mv3wKbxPV4I1r
         VWfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ksKN1KfOng0FyN5hg6EqvzIgF6UR4tzOmvAYodfN5g0=;
        b=evpQPec1oOU0O7FwFGzhqopna1s1nqND4+sSc0Wavf1KVHMe8uDL/vpbcgElWzvMTq
         fbbp72HqbVA3HZYqc8Ifo0cs5qBfMJZj3yKSJGIw9Y+rgdU+KXJyAQae3pRwQwZ7H9sN
         vL0DGmSWks2zPPwdEEcYquggb34Tl62ozRxMnATAKJZ1baxZf+lm0JiXGHTFQMdz27vw
         srv+xvUNP/BZHCmsLnovVna+kR6vycEdpHPTzhevw0C15w39GmiXNuIGqew+mYVWbQ/x
         5HKNnaxR9otocHF5evz2eCGYxb7ndi5mFFI4okJ2XuRVNSCyHSYyskQ3IPrmsv4V3Lgv
         zSGw==
X-Gm-Message-State: AGi0PuZjjMB79lZP14uPof8V0ldwoOEshpNV7lI55CMTVYxIa0f9o2W6
	uL0Je8ejM5zz1d1OuRkWzvA=
X-Google-Smtp-Source: APiQypJaBPuD2ph8LnJreUpGM7P9s1h3lYIEHhKGhka2AFeiEuX2FKYdd5iNW54dwKnVwAAsKDYaCQ==
X-Received: by 2002:a50:9dc9:: with SMTP id l9mr1047967edk.39.1588654801105;
        Mon, 04 May 2020 22:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1004:: with SMTP id ox4ls789527ejb.1.gmail; Mon, 04
 May 2020 22:00:00 -0700 (PDT)
X-Received: by 2002:a17:906:3da:: with SMTP id c26mr1087841eja.290.1588654800422;
        Mon, 04 May 2020 22:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588654800; cv=none;
        d=google.com; s=arc-20160816;
        b=xryAdmu8kU8pXNmXfn42ZonTzZkv+PrKZdaTdP7QkP3jL++SFOMUuw4TySperwQ0jE
         7jNIwjgUAKgIKTKNyQ8F1zAeadlM20JGbPLYjrt/EMwzPut4JvYPJSW5kLmvpo+CykOK
         tUxsegb0I0lmZQnXE4tgFvORLvru6aGv0ezonIs6p2dF4jCwiAI4/e+Go/9DlZQ57IRS
         PlpnTkyhBlnr7uTnURalHSmR47uZz2b7vBNq7n1BNqWEtgFYlHT3TdgzwWjGhmx90tU1
         ZY7+Q4ydB+rKjwm2HERFKRgLW2Ssud3LE3TL8xCzK7xRyfNisKvG4G2N/14G+YdRQX/8
         7uPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L/sAhNPIx0HscGRab45ItFmjRECKgd522Fp745ex8GE=;
        b=D/LOzSeEQ8TOKwDylrXVvs6CBXsC6hbjArJTbVtbI4ssRVfwbTtG4cpD+l2rW/DSIp
         SIniwlMYjGAzuXIkinq8VCDapbKH0UwIF0Xb+Sr/GmvvgM1oc9xvubGprhNB0chFOI11
         NE04TAKTklLtGWdRaCD3v727nao2mfYwAUoP7d27CpUnodAC+6/xTsUjwCgbxKjGjclJ
         af9iLDVP3ztrhk/7oybkL3Py5+RLCIDC2ZLqnXRwdZ8KBONHMQgy5Meg6UM9WZVvm69w
         Eo4QLIclUv021nEphGdE2v5bfwUxnNwAB424EQN+SeE6+rswz8DCZKtCipDcNW71RWDu
         LbfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XGKXoYze;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id i2si41453edn.2.2020.05.04.22.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 May 2020 22:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id v8so1539410wma.0
        for <kasan-dev@googlegroups.com>; Mon, 04 May 2020 22:00:00 -0700 (PDT)
X-Received: by 2002:a05:600c:4096:: with SMTP id k22mr987224wmh.99.1588654799821;
 Mon, 04 May 2020 21:59:59 -0700 (PDT)
MIME-Version: 1.0
References: <20200427143507.49654-1-elver@google.com> <CANpmjNOv7VXv9LtWHWBx1-an+1+WxjtzDNBF+rKsOm+ybmvwog@mail.gmail.com>
In-Reply-To: <CANpmjNOv7VXv9LtWHWBx1-an+1+WxjtzDNBF+rKsOm+ybmvwog@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 May 2020 12:59:47 +0800
Message-ID: <CABVgOSnr8CX5tN9u_wafxSiyyVcM9nL_nX2ufrSdRi=jdWjerg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add test suite
To: Marco Elver <elver@google.com>
Cc: KUnit Development <kunit-dev@googlegroups.com>, Brendan Higgins <brendanhiggins@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XGKXoYze;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Mon, Apr 27, 2020 at 11:23 PM 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Mon, 27 Apr 2020 at 16:35, Marco Elver <elver@google.com> wrote:
> >
> > This adds KCSAN test focusing on behaviour of the integrated runtime.
> > Tests various race scenarios, and verifies the reports generated to
> > console. Makes use of KUnit for test organization, and the Torture
> > framework for test thread control.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
>
> +KUnit devs
> We had some discussions on how to best test sanitizer runtimes, and we
> believe that this test is what testing sanitizer runtimes should
> roughly look like. Note that, for KCSAN there are various additional
> complexities like multiple threads, and report generation isn't
> entirely deterministic (need to run some number of iterations to get
> reports, may get multiple reports, etc.).

Thanks very much for writing the test. I do think that it goes a
little outside what we'd normally expect of a unit test (notably with
the issues around determinism and threading), but it's good to see
KUnit being pushed in new directions a bit.

The biggest issue in my mind is the possibility that the
non-determinism of the tests could cause false positives. If we're
trying to run as many KUnit tests as possible as part of continuous
integration systems or as a condition for accepting patches, having
flaky tests could be annoying. The KCSAN tests seem to break/fail
as-is when run on single-core machines (at least, under qemu), so some
way of documenting this as a requirement would probably be necessary,
too.

One possibility would be to add support for "skipped" tests to KUnit
(the TAP specification allows for it), so that the KCSAN test could
detect cases where it's not reliable, and skip itself (leaving a note
as to why). In the short term, though, we'd absolutely need some
documentation around the dependencies for the test.

(For the record, the failures I saw were all due to running under qemu
emulating as a uniprocessor/single-core machine: with
CONFIG_PREEMPT_VOLUNTARY, it would just hang after creating the first
couple of threads. With CONFIG_PREEMPT, the tests completed, but the
majority of them failed.)

> The main thing, however, is that we want to verify the actual output
> (or absence of it) to console. This is what the KCSAN test does using
> the 'console' tracepoint. Could KUnit provide some generic
> infrastructure to check console output, like is done in the test here?
> Right now I couldn't say what the most useful generalization of this
> would be (without it just being a wrapper around the console
> tracepoint), because the way I've decided to capture and then match
> console output is quite test-specific. For now we can replicate this
> logic on a per-test basis, but it would be extremely useful if there
> was a generic interface that KUnit could provide in future.

This is something we've discussed here a couple of times as well.
While I'll confess to being a little bit wary of having tests rely too
heavily on console output: it risks being a bit fragile if the exact
contents or formatting of messages change, or ends up having a lot of
string formatting and/or parsing code in the tests. I do agree,
though, that it probably needs to be at least a part of testing things
like sanitizers where the ultimate goal is to produce console output.
I'm not exactly sure how we'd implement it yet, so it's probably not
going to happen extremely soon, but what you have here looks to me
like a good example we can generalise as needed.

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnr8CX5tN9u_wafxSiyyVcM9nL_nX2ufrSdRi%3DjdWjerg%40mail.gmail.com.
