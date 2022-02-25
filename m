Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB36D4OIAMGQEK7TLF2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id BFA924C4710
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 15:04:32 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id k33-20020a05651c062100b002460b0e948dsf2413698lje.13
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 06:04:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645797872; cv=pass;
        d=google.com; s=arc-20160816;
        b=0mnMCUSpjuwhrS30kckB05gC7MLBAGv35bL4xEftcVcbSbdFO/n/A4ciD5aLWfEy3t
         94cVzBctGx4/cIAXJvPAj2ocg3K7rnL5dKAkTj2y7tJz6h2iOavvgpLo88MK9flWhufH
         141lVROxshRxliniG8TGF0/TfoiShFO8plC62dQ3B7yQv+nxLs1mmONKftT+xSFiJFOF
         Wb+74cWxSaK0fk4qLnkDJj2COa9yLqwCnDWiSsMK+YbaeS4X57oWyMnm7gO5oipjLLQd
         A9sGFLzUxa7NVBUeUR0PsVtHZ1CyNlS4WLtkPowdYfKvwaHUBqKh0UTnNFTBiAsGYBJj
         Yylw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4q29H11+oFVfc0Qy3XOevLM4qvGhNAu4djmfWLH+eO4=;
        b=Tln52jfBg3GIgo9Bwmq1n/JDwUKxS+QwfK0SeQAnRk5Kz+xplVjGmFy6RRrfQKJ/o+
         zYKLkF3CsBX385PygT1wDhR7birpyVD/eKVKJN67oAOMAiSidfiaiO26LfHBXq0hI+Kt
         8Z9EwYb7PRheHEZ3xQPkxNFiJ2mHjWlftLOv7n9uVtozVrYQVzJVHlHXki6yhekuL5QW
         apG12rCGAr2fxSGvnIuMFiO+G6iz7gQfraq/sImXy2qMdGO0zc+VWfwnQqSPmZV0JJrq
         8+puH0EsqvtwkTrDzf022/XA+sPCJi7/0EqCgqzpwXq3tPnqkZSsEWhS+HzRVyVNZq+O
         YRCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=m1l0dzVf;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4q29H11+oFVfc0Qy3XOevLM4qvGhNAu4djmfWLH+eO4=;
        b=PGhHD69GibjSAI9VaH6OHwC+FgevrCfR9ii1ZPgLgU/anl5sT06OvuQ+KhOyPK6uvf
         LvjEGBsormU+yytwjaPhmSdBsJiOrL/G3kZ1mSsv8AHn4zjGuLxy7E3c2Zr2cf4Jx8u4
         YLnl81Sh5ccIO0U4dA6E1zzy59i/lfM1JY1UvDHNJk3sYF1iwZgAUv5zyHrSXfW1zy9k
         +Pb5Q7b/izCLyz3ib+F5/zq3TgyKrjKHjE1wKZ5Nnn5jWxkoi4023saReA+q01jDAegG
         JHeWT6YksGQyeG0WfRicLAiQFhR8nGryW5E7wgXIvUeyBhA2smQ/o+ZSvQpLCZk1Z3u+
         C58A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4q29H11+oFVfc0Qy3XOevLM4qvGhNAu4djmfWLH+eO4=;
        b=KFGh5hV0FEhi8KtunXZCL+oZvwjNudrF8E99VmH7O3zqvxhTvGycGvORo1vkHrIWXQ
         hkD5lVchzKsd+gv7T5EVUdtXfMN/rGIfUU4SPiswQ9WoPLqYCt4EcSM9aWwb38o6sfD5
         RExGV+S4Xj7YOo/DWQvr177l8ZEgA03LA/CxSRf01YToTQU7TH62wvPKgw8BbHPunaOD
         L2HKmwUk4Lkub1BYUhi4f9KYPAGD/O+dOMya5Fwew9KVlFOgLIrwrNpKTWpmeoaNikZa
         G4YQxGc/kwRyaLw9Skxbu+wfwmI4HvdJsah+U/SG3C4JPUXNp6in6mtQa/1S7Fg7OwgT
         Oxhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RgGavmAiF+0BYkvJHbi8GJo0j+KP9cQpGwux5JxEfXI7IbPaN
	tXzR4KPsjRlzOOeA4BMnTeQ=
X-Google-Smtp-Source: ABdhPJzK9imLTcNE0giJTkQOrTB6jbTdVjvBm1EIeM9I29vecP+dssl89Az46erGJzmqIliQ3lkUwQ==
X-Received: by 2002:a19:a404:0:b0:443:2ef6:1ae7 with SMTP id q4-20020a19a404000000b004432ef61ae7mr5220844lfc.554.1645797872200;
        Fri, 25 Feb 2022 06:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8e:b0:443:9610:6a0c with SMTP id
 g14-20020a0565123b8e00b0044396106a0cls2537414lfv.1.gmail; Fri, 25 Feb 2022
 06:04:31 -0800 (PST)
X-Received: by 2002:a05:6512:3c9b:b0:440:10a2:dc11 with SMTP id h27-20020a0565123c9b00b0044010a2dc11mr4976908lfv.584.1645797871133;
        Fri, 25 Feb 2022 06:04:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645797871; cv=none;
        d=google.com; s=arc-20160816;
        b=pvls9fpgihQrpsOFz+u3ppgZep/1+DmyYxNF1pVCvi9PXl+XshextedMXE7/OEYvl0
         76fXv1BiNGwAAtzqh2kG2cWvgQ5begXwbH02TjAwIs+ApglGYT04MGzOU3ho/X00Wk/0
         EO/UIF7oKP0NRlEdWnx8T7b3BkAQJJBJhtd2OaWMorIl+PRC1IUVe4R5qhI8Vqmd/uhp
         x5WvfyzYt/cEAMmIBTjU9LO7w2RrbOVSUIhgNxN5TBvHEY5Mbn18gqyVZ3fMk/DqHkhQ
         YrayGyjS1856p8RByXIjd0BZNsIMIBAWCbEdTpEsL+QGN0rJBif+bX9MEPRgMDRTRnWo
         syhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EdlAiChWlSjnHqMEl5+rYYw1D6uhL90FBdNameorEkY=;
        b=CswcSDpr4eOeTYDQCJY11FIHBQlF6tohoJC4XEzlfonT7zP4iI6dt6jolDjog23269
         6rx1rizu0iP5ORx4GDABbY4+Jk+rdxu/rjGK9ye8hwXbqBEDN2HpDpi45pNEbqLRMYA7
         ZNXt818+t9nA5pq0DyZi0nEVBFfPJvej+bW7lwm46gVF0JqbOmSaUceYLhRtwWpJyfSo
         B+gT8SHIjk1tXyKkuG9UAvYAFVptYIVSpSEE9GK9aT1/Hh9TugPkr9/71w+hhfkvodN6
         1yKXiGT6kFPX1uZtfZgFbcz9/Z629Od13afBKc8/ZiBec1Fht07+pvM/jYiLmfqVjpXC
         N/DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=m1l0dzVf;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id m15-20020a2e910f000000b00246477237ccsi154240ljg.8.2022.02.25.06.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 06:04:30 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ej1-f70.google.com (mail-ej1-f70.google.com [209.85.218.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 2AD7B3F1F3
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 14:04:30 +0000 (UTC)
Received: by mail-ej1-f70.google.com with SMTP id o22-20020a1709061d5600b006d1aa593787so2726899ejh.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 06:04:30 -0800 (PST)
X-Received: by 2002:a17:906:80c7:b0:6cf:9c76:1404 with SMTP id a7-20020a17090680c700b006cf9c761404mr6139739ejx.207.1645797869862;
        Fri, 25 Feb 2022 06:04:29 -0800 (PST)
X-Received: by 2002:a17:906:80c7:b0:6cf:9c76:1404 with SMTP id
 a7-20020a17090680c700b006cf9c761404mr6139716ejx.207.1645797869620; Fri, 25
 Feb 2022 06:04:29 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com> <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
In-Reply-To: <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 25 Feb 2022 15:04:18 +0100
Message-ID: <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Marco Elver <elver@google.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=m1l0dzVf;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > As reported by Aleksandr, syzbot riscv is broken since commit
> > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit actually
> > breaks KASAN_INLINE which is not fixed in this series, that will come later
> > when found.
> >
> > Nevertheless, this series fixes small things that made the syzbot
> > configuration + KASAN_OUTLINE fail to boot.
> >
> > Note that even though the config at [1] boots fine with this series, I
> > was not able to boot the small config at [2] which fails because
> > kasan_poison receives a really weird address 0x4075706301000000 (maybe a
> > kasan person could provide some hint about what happens below in
> > do_ctors -> __asan_register_globals):
>
> asan_register_globals is responsible for poisoning redzones around
> globals. As hinted by 'do_ctors', it calls constructors, and in this
> case a compiler-generated constructor that calls
> __asan_register_globals with metadata generated by the compiler. That
> metadata contains information about global variables. Note, these
> constructors are called on initial boot, but also every time a kernel
> module (that has globals) is loaded.
>
> It may also be a toolchain issue, but it's hard to say. If you're
> using GCC to test, try Clang (11 or later), and vice-versa.

I tried 3 different gcc toolchains already, but that did not fix the
issue. The only thing that worked was setting asan-globals=0 in
scripts/Makefile.kasan, but ok, that's not a fix.
I tried to bisect this issue but our kasan implementation has been
broken quite a few times, so it failed.

I keep digging!

Thanks for the tips,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo%2BC1Nq%2BDw%40mail.gmail.com.
