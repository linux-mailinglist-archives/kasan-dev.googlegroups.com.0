Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQN37GCAMGQEUQGQWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 73D72380868
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 13:23:46 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id c20-20020a0cf2d40000b02901e8759f1f5esf12974403qvm.10
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 04:23:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620991425; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yijsd/R1pwBN9+sVAhpKBR5OQPX/2OawrkUz5luDpZ3r7vpqf2pP0KSsWkEnDulf0f
         wc3qSnHVgbHBu0zomqrHoo4sfPxbjLa++lW3bQzh4IwFKA6RWFB+jv5bBtqp6SWTphVQ
         sJsdynN37QzVW3Ypps40uOl3g/IrYdua0GloKof1K32w3lD78HzmQFl8GXuSDDsoSWCK
         5SmMj49f6hxjO+JkYvWOuo0s2FP5rHJhvDihwzz4nutkzISBQyB2VOdaNFvzPM9Vt50H
         ftRSGDoOg/YMWdj8Q84TCyCHF4WWHEB0iAlCWjOSuccbsuUUiU+lEUB4fScagaQJyG6p
         ec4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6bwykRv8T8hOg71Mbpyk+NS2AWCtjBXMmMdtbzGHc+w=;
        b=QD6N6fohcyf7xRmqh0h6xUXXJWAxJug4aZDr/DE+2x1n7C7LzKfJnPLaS6UbFMPVoQ
         CizkiTGNN9//Eo4s4EdYnvXw/OnfMLEF6tom7gEwqMH8TGgwWCRSgrxDhzsGl6oic8j2
         +Q5WcZ/4G2sLSOiq2EK6DgYxFP6xpbq2+KYRAt5Np5fBdUHJKHQBLWgNxgBdwZd8dYdv
         RgGm0jbc9ErIQTE7fiL4geGB+EUGIFByC4+RE77fKmgmpbdPhpCQm3o2uL/xDxOGQjyZ
         OBhHM687DJ8nRAPaZzk09KbTW9LgE2DQt2YbabshPFIBnQf6lor1FCyacZ+AVVC6AdQG
         yoSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=byJy0nDw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6bwykRv8T8hOg71Mbpyk+NS2AWCtjBXMmMdtbzGHc+w=;
        b=dv5+CAHCY9MMUF28LnMQOjhgKwo6oel16WfhQMrTFXglcM4uOQpwMpJ2MTirjO/6Zt
         4ofXFLd+WXXENvyjaHGblrEHtdAbYZpqxc/e/XwzThDeJxPot6YT2X1B5n2BgSMYo0ZB
         jcWLefLPs0rfYQaZLlSY+vCdR4JNM+9v/ldF/ApLc/Yeua1JyzAU9R8dIqP+1IikfXPU
         8XdKpcO1J8pVtWNrbNfWEfMGgrghpWLNUzLfryJqAR0P4jnumYRWDiNpwuHqgACdY8W/
         v8wxg4W/HLSfCRtzKdAwiuGc5gG5zv259j1FaC6M99Un4UJzC77XX5uj3Iokon9+1DcO
         rYJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6bwykRv8T8hOg71Mbpyk+NS2AWCtjBXMmMdtbzGHc+w=;
        b=I8LXnJY4bJfVdeOp6cVPgwCw2L4zoQC09Rb+y+/mMA6PuTlVqGtUblsp43vfE7bvY8
         kRFf8LyWHrn296MJ4ncQZPvog5E9YbojjY5IWfTnJhrJOGJCxJJe0ohwsCrGxzVYC3JS
         45UErOwFz003a0adra9RkCn02PCMPI3Dk8ONLASxR2cvzrxrY3kzrgTWglLTgEc1wDxn
         r15nko7yBZCUKZCkmmm2wpVbKwbHks02m5nFFHWfV7I5UaNyeMWRWtaAuGSuFjX1uRwc
         zpn+rjhy8wwGPSWXq7dZIvPUtRACLmUfUXnijEhXRYel4wIIxQQKvOZfYgyJqF8FKg/b
         XMvA==
X-Gm-Message-State: AOAM531oLuQHihgNTZUtJnD4rPnjPoDTJRMGOBSkJiZBBYYN1/3xrN7i
	QOube9fHdPuvSlcDDieLRQU=
X-Google-Smtp-Source: ABdhPJwBFBxDvchszhpAYgJzggYxg6ynq97ha5ldKxWD/ua9xOrvsUo2XueJkfCgrA0PNmxmhHizPQ==
X-Received: by 2002:ac8:7f13:: with SMTP id f19mr16869096qtk.237.1620991425515;
        Fri, 14 May 2021 04:23:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ad0d:: with SMTP id f13ls5766843qkm.1.gmail; Fri, 14 May
 2021 04:23:45 -0700 (PDT)
X-Received: by 2002:a37:9c84:: with SMTP id f126mr43067519qke.240.1620991425086;
        Fri, 14 May 2021 04:23:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620991425; cv=none;
        d=google.com; s=arc-20160816;
        b=VOViL/67uiCS/7gm28B9WFuoeN0Dso5VIsgPOhrOd1TFhCWTEAJCuKJSQxdOls/oNv
         Qe36wAwn8rmXjcmfBZJPcLSvWC6qbuwXfNkH357IwmO2bZEwD1xjtToD7CLXM3B+4dSx
         3mkZVr2GsNI+6BIFgMSC0aVbS8hWBXfehG3L6SGqYUEnUx/DnuA6NltKmv4cW22jdAZo
         8YGjIRXgxsSmOGSLqRYsz8hsjXhHvUj+OPKAL6D55HrZ0my81yhCI55/U/NBwQRBjCF8
         rBhSA8JHK8ITohDnJ1lk9uXhNV24S/GCXAgkG2Sl1Fdhr/9kPetb+Uo0zGOJxJi3oJPW
         HUjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nrX7Y1hC+nFf54KNExFqPzRBO4yUoXGtLaJKecZ8/sc=;
        b=NXMSe269RraC7paKdTpovJ4Ir7Rbq0vhOnylhUhdGbf19lQ+e1bkkrnpUYPTz7bQta
         S5S2Fm/b31ybk/SjYu4CRcqfiMUrfS9E8Li+G7UDeHr/YeK9Hoz6U7sdjVbclj6eoyNZ
         geJN8WZCu5/6rZDHDTkYy95hizcK2RzPt5QJ6PqcDaqTY+KPOvQmtJGn1IFMC9PwhCxm
         VYlIuIOZIyV3lfgM8v+tW1D13dKhCwAcyh2o/X9mhWvUxz7ZC5Y3CWfX0lYye5VxzkIs
         LEslw9THnYmouVRu7C5xKOgQytfOq9Q6fLXbY15Py2VEjy+qOLDb59kMoCDXIf8dZbRs
         nUpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=byJy0nDw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2a.google.com (mail-oo1-xc2a.google.com. [2607:f8b0:4864:20::c2a])
        by gmr-mx.google.com with ESMTPS id 142si557357qko.4.2021.05.14.04.23.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 04:23:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2a as permitted sender) client-ip=2607:f8b0:4864:20::c2a;
Received: by mail-oo1-xc2a.google.com with SMTP id i8-20020a4aa1080000b0290201edd785e7so6282438ool.1
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 04:23:45 -0700 (PDT)
X-Received: by 2002:a4a:6202:: with SMTP id x2mr35903358ooc.36.1620991424458;
 Fri, 14 May 2021 04:23:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210514092139.3225509-1-svens@linux.ibm.com> <20210514092139.3225509-2-svens@linux.ibm.com>
 <CANpmjNNB=KTDBb65qtNwrPbwnbD2ThAFchA1HSCg9HKETkQvCg@mail.gmail.com> <yt9dfsypinlk.fsf@linux.ibm.com>
In-Reply-To: <yt9dfsypinlk.fsf@linux.ibm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 May 2021 13:23:33 +0200
Message-ID: <CANpmjNPAS5kDsADb-DwvdFR9nRnX47-mFuEG2vmMPn5U3i3sGQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kfence: add function to mask address bits
To: Sven Schnelle <svens@linux.ibm.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=byJy0nDw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2a as
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

On Fri, 14 May 2021 at 13:03, Sven Schnelle <svens@linux.ibm.com> wrote:
>
> Marco Elver <elver@google.com> writes:
>
> >> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> >> index e18fbbd5d9b4..bc15e3cb71d5 100644
> >> --- a/mm/kfence/core.c
> >> +++ b/mm/kfence/core.c
> >> @@ -50,6 +50,11 @@ static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE
> >>  #endif
> >>  #define MODULE_PARAM_PREFIX "kfence."
> >>
> >> +unsigned long __weak kfence_arch_mask_addr(unsigned long addr)
> >> +{
> >> +       return addr;
> >> +}
> >
> > I don't think this belongs here, because it's test-specific,
> > furthermore if possible we'd like to put all arch-specific code into
> > <asm/kfence.h> (whether or not your arch will have 'static inline'
> > functions only, like x86 and arm64, or not is up to you).
> >
> > Because I don't see this function being terribly complex, also let's
> > just make it a macro.
> >
> > Then in kfence_test.c, we can have:
> >
> > #ifndef kfence_test_mask_address
> > #define kfence_test_mask_address(addr) (addr)
> > #endif
> >
> > and then have it include <asm/kfence.h>. And in your <asm/kfence.h>
> > you can simply say:
> >
> > #define kfence_test_mask_address(addr) (.........)
> >
> > It also avoids having to export kfence_test_mask_address, because
> > kfence_test can be built as a module.
>
> Ok, i'll change my patch accordingly. Thanks!

Sounds good. Also please add a brief comment on top of the
"kfence_test_mask_address" part in kfence_test, like "/* May be
overridden by <asm/kfence.h>. */" -- we have something similar in
mm/kfence/report.c. Also, I think we want to call the macro
"arch_kfence_test_address" -- the "mask" part is very much
arch-dependent, and might not even be a mask on some other weird
hypothetical architecture.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPAS5kDsADb-DwvdFR9nRnX47-mFuEG2vmMPn5U3i3sGQ%40mail.gmail.com.
