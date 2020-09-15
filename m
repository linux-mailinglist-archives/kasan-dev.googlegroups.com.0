Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEVAQL5QKGQEDD6FRLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id BA17C26A295
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 11:57:39 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id p6sf1245787ooo.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 02:57:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600163858; cv=pass;
        d=google.com; s=arc-20160816;
        b=mGwcnzTNqH7ARYapg8AeNdyQap7ucNtHj1TzZozPBifHOUyk+225xKQGY/AxZpA5aN
         ZxVc+CwUVdYTZkDSdEmEWSp6FD3HFktF0UTutnefk+2+VszBbkUbbkTR2+77tpQRoU2z
         Nz8WmEW9lGYOppT6SYDeGwxWZ0PpYzosiGk9RACrcDFmaTvBqnu6to1MGH0XlCjysMLQ
         oUWzL86vPKDPRIDZ2WLOTiKLmpWPQEdm4Kyy0XYhP5a1xbDAys0k2ZupC/eCNUShvdYz
         DRSDlrtNfWUvb08v3vHRBKIHEzZym7ngK932CrSt4rhGjT6IbVPY01xiIhhrHw31ZTdC
         KS7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Br47SLIDdxCtnuxNBx6uLAoZSlZZ83TcMHKzllFj1O4=;
        b=PeLDaz0m6+N3cCXo7nXqFW+AKnwLgwnESNYEir239RXTpI30MPix3hdz4rfjbWSrZE
         +izXY/Vun5lLipWmkVxw/qfL78s2phmu2uSb7WYaa/yCvliBV76OJwKxcYQzgnXMgZ2S
         c8TujmmZFnwJJ/hSF+qb5ehkcVUtBWfhWds73QwQsGE1QiuXf3WubwZBp891HSvZ5gbK
         Sw6O341obUEXmRHxZOEha4ekYBQBKgog7sBYs6hV2b3vA5onAO7pU6mWKBZS9QUZ5O3Z
         7nyfW7X8CrpgsgcgDuHZL9/iJzwQZjwhar6fC9EfGzO6H3oWEJNpiuXY93mi9eUH4697
         K7Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ASeidofS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Br47SLIDdxCtnuxNBx6uLAoZSlZZ83TcMHKzllFj1O4=;
        b=o4C5WHJ/x/WNVIY6qM7k9LeEyKQQZavBjv52YL9xo8/ChWQlIX5bv0YvGNdBXeWyGY
         Er2Ahx85Ok4myEvqZe81nYzzKcGGIqNHfNCJyi7mDjsMHr/c+VFyFiueJ3/hRkTdRHBY
         NXRllvtV1HeS2MA2XuRSBQqQRUg6QF3CNIudt3dAFXGd09R0j6gpQ0PXUZqjLwyHnw21
         UC285geGFwI4UUnWYMdWOUwaRMBoXwU7da6+NMlVdVSGlcmim/6hLhxjO3GXzCAGEQKs
         du4Ip9p9X9Mt0Cj8qxEp84Kmqpqch1M2Ocyxg/PssCB9rN3k4yp4RuQFCjdTl/e6MaXN
         xbvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Br47SLIDdxCtnuxNBx6uLAoZSlZZ83TcMHKzllFj1O4=;
        b=r4ad9iWSth+pf+t0TUV6FN/GtPuN02wX1PX0ZWM5Avr2CZ4uXyLQn2N/J/DbYWE3kW
         Bfeyhlq6X9WezdbklkS12oBq7r86XiBGkzo26PXKXUuCa5Da+PIuirY4a/J5kyznUQ4K
         T9iKOSRds9Jw0B9i02tRUxB2mvjB7lw6ZPw+mleQLb5YgAabT+3wzvvtJ3Enxzbjn54g
         sK+31vTf5bbO9UKDOL33TNMRlr0p+Dv/pUAneMoe+iy3VL596FX84azmnqaAAR0hWFCB
         AL+IkpsfO0C9IdkG+XehD86leMWPWRQ55xRzmf0lZ7j6mCO0ZYccj61X+Vu4ahl78PgR
         SjRg==
X-Gm-Message-State: AOAM530bQ4ETR9HFZIIYqLHNVYT2uBTlYVhrsqaRKSZpSh7G6C0ORz4G
	bnbd61jdm/hAzSU3QEiBqvE=
X-Google-Smtp-Source: ABdhPJy3Y/YMH7/Lk2/v8dr6jzuSP8kaicXlnmRwVOyY/inE+z2Thb/cLeoJopdUbfVyvmSMF/efGA==
X-Received: by 2002:a9d:7459:: with SMTP id p25mr11693545otk.234.1600163858708;
        Tue, 15 Sep 2020 02:57:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7ad8:: with SMTP id m24ls2711918otn.8.gmail; Tue, 15 Sep
 2020 02:57:38 -0700 (PDT)
X-Received: by 2002:a05:6830:1c4:: with SMTP id r4mr795459ota.67.1600163858357;
        Tue, 15 Sep 2020 02:57:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600163858; cv=none;
        d=google.com; s=arc-20160816;
        b=K6R2c4Gl02pwpx7ygoyYIb1J0TzX/eo97lYMQVpgf591XoKTpEq+uMFBr1V7pchS+m
         /0tWJeS1Pr+LfCOG2cILDo3OrHY9/49tZ2OoHMtWSX5niCn0QVgdJoaO5owEk8Ydj+hw
         0IPiErOFO/W9y3GRgGB71CJjnXhVpM2gCbbtR1zYw8n9sTUAJIWslH7CFvfUeaokhpDg
         emI1pqEsi4O73O0qaEcc3cFP2n1Z2TY0tkuJ1s3jKM9SeLHhww2t/NgpWBUb0krOMDLv
         iq+36vMKUEwIWNrJO0ZaK9kw7B9bncGHN//4IC6FGkUFsF+bzTQRN2IYcJrrpIbd/E9D
         kpZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JzT2ZqDHda+Wc2x3+EDcqLa2oAGwHZvtm9Os6CPbsUs=;
        b=JzQvlNc0nGnpTOfVGciSVvymggbS4qCAFe7XD/NN5KK7c8qoTNFI7YL7kRuDWPI22e
         xKhYhp3SQbfxPDi7tZq02tVmsUR6TWIJtZQG2ltXoq7TA+npHgSDN4tQZu2j/hYal0BS
         +/4bOgLbonmlIhDf1BcGEgYZ3K60rBDRbICQOlFgSeM+H+oFNUHGYq06BagtEFRki91V
         gmUGjmxL6O9zXZR3FwcwzIqcwi33+egV3+LP7xsDJ2KsSFz6UTEtEZ+wIhC0clwvczPz
         ApmFn0qVxr8o5cMzi9C15KwKLxIOegaC+kiBEoSJGbMwcfOa6yC+QrH5nh/2pD42Sv2T
         st0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ASeidofS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id m3si1174803otk.4.2020.09.15.02.57.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 02:57:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id x14so3162184oic.9
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 02:57:38 -0700 (PDT)
X-Received: by 2002:a05:6808:20c:: with SMTP id l12mr2813900oie.70.1600163857893;
 Tue, 15 Sep 2020 02:57:37 -0700 (PDT)
MIME-Version: 1.0
References: <20200914170055.45a02b55@canb.auug.org.au> <CABVgOSko2FDCgEhCBD4Nm5ExEa9vLQrRiHMh+89nPYjqGjegFw@mail.gmail.com>
In-Reply-To: <CABVgOSko2FDCgEhCBD4Nm5ExEa9vLQrRiHMh+89nPYjqGjegFw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Sep 2020 11:57:26 +0200
Message-ID: <CANpmjNM0nRdzRfWocwxEoT2x-qM0NBNU5cfgrQ4k3fdjtxot4Q@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm-current tree
To: David Gow <davidgow@google.com>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, Andrew Morton <akpm@linux-foundation.org>, 
	Patricia Alfonso <trishalfonso@google.com>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ASeidofS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Tue, 15 Sep 2020 at 06:03, 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> [+kasan-dev, +kunit-dev]
>
> On Mon, Sep 14, 2020 at 3:01 PM Stephen Rothwell <sfr@canb.auug.org.au> wrote:
> >
> > Hi all,
> >
> > After merging the akpm-current tree, today's linux-next build (x86_64
> > allmodconfig) produced this warning:
> >
> > In file included from lib/test_kasan_module.c:16:
> > lib/../mm/kasan/kasan.h:232:6: warning: conflicting types for built-in function '__asan_register_globals'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
> >   232 | void __asan_register_globals(struct kasan_global *globals, size_t size);
> >       |      ^~~~~~~~~~~~~~~~~~~~~~~
> > lib/../mm/kasan/kasan.h:233:6: warning: conflicting types for built-in function '__asan_unregister_globals'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
> >   233 | void __asan_unregister_globals(struct kasan_global *globals, size_t size);
> >       |      ^~~~~~~~~~~~~~~~~~~~~~~~~
> > lib/../mm/kasan/kasan.h:235:6: warning: conflicting types for built-in function '__asan_alloca_poison'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
> >   235 | void __asan_alloca_poison(unsigned long addr, size_t size);
> >       |      ^~~~~~~~~~~~~~~~~~~~
> > lib/../mm/kasan/kasan.h:236:6: warning: conflicting types for built-in function '__asan_allocas_unpoison'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
> >   236 | void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom);
> >       |      ^~~~~~~~~~~~~~~~~~~~~~~
> > lib/../mm/kasan/kasan.h:238:6: warning: conflicting types for built-in function '__asan_load1'; expected 'void(void *)' [-Wbuiltin-declaration-mismatch]
> >   238 | void __asan_load1(unsigned long addr);
> >       |      ^~~~~~~~~~~~
> [...some more similar warnings truncated...]
>
> Whoops -- these are an issue with the patch: the test_kasan_module.c
> file should be built with -fno-builtin. I've out a new version of the
> series which fixes this:
> https://lore.kernel.org/linux-mm/20200915035828.570483-1-davidgow@google.com/T/#t
>
> Basically, the fix is just:
>
> diff --git a/lib/Makefile b/lib/Makefile
> index 8c94cad26db7..d4af75136c54 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -69,6 +69,7 @@ obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
>  CFLAGS_test_kasan.o += -fno-builtin
>  CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
>  obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
> +CFLAGS_test_kasan_module.o += -fno-builtin
>  obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
>  CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
>  UBSAN_SANITIZE_test_ubsan.o := y

That's reasonable, given it's already done for test_kasan.o.

Although the warnings only occur because it's including
"../mm/kasan/kasan.h", which include declarations for the
instrumentation functions. AFAIK, those declarations only exist to
avoid missing-declaration warnings; in which case all of them could
just be moved above their definitions in generic.c (which would also
avoid some repetition for the ones defined with macros). But given the
various other KASAN patches in-flight, to avoid conflicts let's leave
this as-is, but it's something to improve in case we wanted to get rid
of the fno-builtin.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM0nRdzRfWocwxEoT2x-qM0NBNU5cfgrQ4k3fdjtxot4Q%40mail.gmail.com.
