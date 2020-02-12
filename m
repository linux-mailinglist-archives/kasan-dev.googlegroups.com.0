Return-Path: <kasan-dev+bncBCMIZB7QWENRBM5UR3ZAKGQENYMN45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BC6515A140
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 07:24:53 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id i11sf711602qki.12
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 22:24:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581488692; cv=pass;
        d=google.com; s=arc-20160816;
        b=VDlrWN6gBzDScB4VxOlQaRYYuMQQ4uJ5T8h+rxqUFvn4tjB3YLFeCrAqt3ww48ltY9
         wjIjcBQVsc6wbxrXKCWTWxWiv0e4GnyuNQmTUNJFlKDPMQQXxegJBd8kh0xBC1vFFUQp
         HoEloi6R4NNiM4MKU5hNq4NsO+hFEN6HSLFAVSTWAwnaADqD5rMhYZNn/bd5ICEx97UD
         4dSCiIkNZNcp8O2buVUJYmJE/vLZkmnPOC0u6xugb0saou9XAqFB4eQck2kniqGi0X+9
         CoTZYW7eDxJQP2PXv6zu42xl4bQk15zWsCK+riKrBb94CSaXYhFxqGJyyRI+DPrlJJsD
         N6tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0shKv6u7HacqOhoI5lHfpM1ytvKqlgBPsOPo0OWqFm8=;
        b=VviyNRfSh+rEzcf8CXMUgvCD2BX/yQTgUx7vdywdihsUrD3K05EYnV8teyEOhl3Yza
         2yJ/g2MnJ0y/3DSzAPmzdqn+bwMtMfblTkhzALj6d6coosYAOTSUVL0Bkho3/GdZCWwz
         HOlhCz3Oil2j/7F2XfIIxi0o/+zg0LNVfdLPIgnPJp1JcgwTPUSYNe/zBbMvDss6IAMU
         9PAgEGvOkwKJOI+rUzHZ4IshBLi0u7vSv5Qj5xJQHfKL8jvep/NFmhqXplZ3IcnXKIZl
         knX2tjIgtrE12IYAdch5Mw35SK3VKI3aG/iUr1oPvlUXCZjrZNsaZ7POZD3vRtVy1w+B
         ld0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BfOuOrPL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0shKv6u7HacqOhoI5lHfpM1ytvKqlgBPsOPo0OWqFm8=;
        b=L7M30z2QWsIWd6v2tAR0/WfTYIbVt8l3WXaG7uZpCgEMBgY9H/QnLg5C4gtLZ3FML6
         7+lZq7aWJTza18+D5/ObwQD2X+MeVJcI15Wtq8eycKc0GQHRk5rwMPiA3cxhxJLQAXSq
         2BY8WeSwimUXF5xs7yhAaHGK2tYRch5TIXgh6a/i3gODgw6koE6X2Xc9HVQwCzBlaVbx
         1Mnij2Axmn0QkpfCpT6tqWqdTlvm5uK7SupU4f1xT54Ok8gugLNgGhJxNVsb79oaWtYk
         wsCGOQjaAMIulW24s4jZzJJ4oIVkfnmlpmCxohmH00cKbH2lUkPRjcB0QvmfInFTUB/s
         8eUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0shKv6u7HacqOhoI5lHfpM1ytvKqlgBPsOPo0OWqFm8=;
        b=J4KjzOon6fcp6axYR1UA213c018Z0bOXLsXwiZ/jNJX29BvntmKNz4wkc+aWIFGGJI
         r5cpyA9fSl8m3QQhXqj7Q8/3RpSS3cgbXN77fYxbA1GW03Pqfnufuj7M4eK2yQ5cwcV5
         od3ttiDbk4/cydIlU8l9DAMBsuWCUoollDAFcYIDvYGdBXclT88eCKvol8rjxW/5lDcy
         nqnPl0fInadENlxDx7KndMegSg1K/0a9Clsdi8xjMe1lTlPzTLvB2fnWds7LhV3YG3/U
         tMxM0eR6Py8ymerkVDnhcL8JkoTyGx7URvlTKz94cZfrpcROh3ZmCuEpELFHHEnywW6U
         7i2g==
X-Gm-Message-State: APjAAAWOm1FsIKNhpCwG6kQAhQL8CLSjxP0alkqwLQ0vouTUJumzXOXn
	RFMEghjITUkSHJJ9gjOplg8=
X-Google-Smtp-Source: APXvYqy/TEzkaBDqZXaLtwob5qsP6dIEk89dptnNchWXHVhEp0bcckUYcdOtbHsGAsRXMR0VjQ2UVg==
X-Received: by 2002:aed:2284:: with SMTP id p4mr5589908qtc.329.1581488691849;
        Tue, 11 Feb 2020 22:24:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6116:: with SMTP id v22ls1353553qkb.8.gmail; Tue, 11 Feb
 2020 22:24:51 -0800 (PST)
X-Received: by 2002:a37:4997:: with SMTP id w145mr7111250qka.30.1581488691541;
        Tue, 11 Feb 2020 22:24:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581488691; cv=none;
        d=google.com; s=arc-20160816;
        b=s//D9NeXcpr963VGyPEZQeNU4EDHbCGTE7EuXurSItq3hIicilJtQSNgnMbqk3BacC
         PDNZfM7LJAyxp5F7wA85udYLVOaHZpONugMeJkpkmsqykhIvUYzskDjoaMjRirTiAjEL
         suanSSj5yWnnMsjw1uLhDe/sDJDHZeUihUEAQatOEEiV1KI9NV6iApEct1aKZAd/uNYg
         FQ3VlyGDBy/ukb/rsn6Km86Ex7ToAh0V7/LsVxc+cmh101oelYECHjV3GyoUtRlaTHa+
         lqkhiWXrN1XTRjUqZTzTwdC5HVm1UOaD+oZUO+HAkK3Ymt56Ap2OAOal8ptZumF2oqSo
         3zAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2OOHsjtYMgDYJvlYtd6T0hN9gxm/R2JJYyhVvz7S9ig=;
        b=mBhgDeXpzbtRLgfvIw+0K1roy2Dj1AILZXYWQOxVeGLe9/EGWGnOgsiZY/R6z2lprh
         18XAxp0e8QYMTpKoAK1Rv3y9WGxhM9rGhU5lFClFd5lgE9P9mKlLSoV7vjIS4BVRRQdG
         0yv2ehqR9vsYf1lruADIVm8zhfa8F0En32igHkMKSlCOj/2PKe7RDDCN/rHdqg4UQm4d
         glJ88Y6ewNw5sQCwO+QRQeJ16stAOi2WAGC/Kl0ZX4nh1WwgIwTWcVJdJqyei4UIf31O
         ZzKbLL3shpwupJlEZpuMS7uDAkjaN/augDVnNAKqC7yXZVK0m/azOjqrHm09tKmPmNTP
         DNQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BfOuOrPL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id c19si367994qtk.5.2020.02.11.22.24.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 22:24:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id b7so1023279qkl.7
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 22:24:51 -0800 (PST)
X-Received: by 2002:a37:9d95:: with SMTP id g143mr9264374qke.256.1581488690981;
 Tue, 11 Feb 2020 22:24:50 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com> <CAKFsvU+zaY6B_+g=UTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA@mail.gmail.com>
In-Reply-To: <CAKFsvU+zaY6B_+g=UTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2020 07:24:39 +0100
Message-ID: <CACT4Y+aHRiR_7hiRE0DmaCQV2NzaqL0-kbMoVPJU=5-pcOBxJA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BfOuOrPL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Feb 12, 2020 at 1:19 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> On Thu, Jan 16, 2020 at 12:53 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > > +void kasan_init(void)
> > > +{
> > > +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> > > +
> > > +       // unpoison the kernel text which is form uml_physmem -> uml_reserved
> > > +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> > > +
> > > +       // unpoison the vmalloc region, which is start_vm -> end_vm
> > > +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> > > +
> > > +       init_task.kasan_depth = 0;
> > > +       pr_info("KernelAddressSanitizer initialized\n");
> > > +}
> >
> > Was this tested with stack instrumentation? Stack instrumentation
> > changes what shadow is being read/written and when. We don't need to
> > get it working right now, but if it does not work it would be nice to
> > restrict the setting and leave some comment traces for future
> > generations.
> If you are referring to KASAN_STACK_ENABLE, I just tested it and it
> seems to work fine.


I mean stack instrumentation which is enabled with CONFIG_KASAN_STACK.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaHRiR_7hiRE0DmaCQV2NzaqL0-kbMoVPJU%3D5-pcOBxJA%40mail.gmail.com.
