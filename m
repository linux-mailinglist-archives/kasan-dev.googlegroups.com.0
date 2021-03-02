Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7466AQMGQE5NAMURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D022432970D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 09:58:32 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id z81sf6003105oiz.13
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 00:58:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614675511; cv=pass;
        d=google.com; s=arc-20160816;
        b=ymxitKrbhU9XjGQlZixPaTEuPnNBYpPa5bDmNKKj7NXn80T8tOUdw9KZmiQgplfLvy
         GdLtWEFxKbB2M2Tc0+wpwyARXGBwbZye3uraURbwCXh3yzasrXVQIoqMUUaBAYA+T7hY
         qXX1FzwdNE15q9qI8sEAc+fTJbvd3v7bu9E+8pKa6wwcNbHbwcSc8Y2+H4nOjiOW9KZQ
         7dl+I8oi03etLfHnmKh1xicMFUoK9t5n0q2yohvoASvcAdWxAHqOCfusJCR44NeY6NF0
         FWiEuQksIlmz1W0ZJb4UoRZnF7K11PBSCWZwRhAH5i88ZBAL+Xuko3OBsU8G5ysfvbIH
         enkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E58IUyS5jL3zVfUhYKLgwy17zgGKiw+aOX2StGHhRVg=;
        b=mSDLR8BLjZ9FhqLRpkaz4ux8GaakX4aPX/9aycevk/hjpxO80bzNvHK0+cMQfir871
         u2OxAnPD/hzP7Ew1dvMZefnosqEBhpYQ+oJ7Ni4gwlL5hnus5E0hXLXmvCFG4SNrDaqV
         rBpBCSxyujjF8P5A/av12s9SBR0oMNWtCIGez451i2U9c79yvMKtSc9srY2yjJWN7Leq
         a4Bt1M/N3tWaYRrIwI7sa+PsYuK8rwYFL0Llnmkcu35xrByt9CCGgOBmSVA1G7dvJ3EB
         9V4qgsljTDZwSagVSnmlq9y+1cWchXZo0X1mBC/LZHYkrjN11bqEzrh2Jgke7VJ0j5++
         c3dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VuJezB0t;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E58IUyS5jL3zVfUhYKLgwy17zgGKiw+aOX2StGHhRVg=;
        b=C5WsaxkAU2QK9gm+K0nK2O1Q/Fhra+LY/uoTlt5d1PTycS2AjRMOIPDlntSz2uVKQG
         tKGAfks/X25KJfZCqCdGCFkd1JjUAoATJ1s+MhQem2ZuQthRdc5FoEViv+XEqTAX1lFu
         6JtQTgw6GJ/u4HMQkqKwSGPUt/eZAhPZ0wFFTYKfRuGTbwwLjltwuxh5HtBbX+olzsh9
         WEXMdtgmMvEdtWjs9EjuJrznKod1/9EWLqd500Pv4v6RR+tH+jsgxwQFuYrfLeubXnSw
         p8rnpkIPh569Ri3RDBjPWn5B7eQXndkLo4nooRYtoCR5+wrcBSq+Nhyw5Wk2xGYQ2tcB
         UO8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E58IUyS5jL3zVfUhYKLgwy17zgGKiw+aOX2StGHhRVg=;
        b=eTS0HisXTommO+Hc75kEY4qFNXvUrrJpZsjVTIOhPYfY1lBLWsQufr4acf1I0cT1Ox
         3Xei50U7F/iwmjAtFY0bMXrTfHc5qw7EpeaGKzX1thxm0u4Uw21Y/dcSgrr5cEsyVq3G
         MACO+x/ZHDuSQ6RNqpg9y855rxWSy/tca+h3Jvt6wgsP9KOOQ5kA/ZWhgDEuivu19r6N
         fFSgLGMvhfzbzB96Nvdl0wlv1yzAmnZZ9R3IjpslZoH0vCscYiOC/ZFtanD+iWdsJalZ
         eCEQRtY+D9GuLTOw2s9xintvB7IW+0FBZP2bQSxdht10mAvgSateJYIxt5x9sSIdmXQ9
         T2vA==
X-Gm-Message-State: AOAM532K4f7RhEIztreT2z4MgTME5+a+rWlHepzhEW2t5tsRE5a2596x
	ecrxA1qxYzcTPQj5oF0VyYs=
X-Google-Smtp-Source: ABdhPJyDSkig8FSeaxf3cE1oskqoPc0hYHUeXawTlnRnEmwwCCn+f0EsmAMIXHVRHmOzNnzrrAPSlw==
X-Received: by 2002:a05:6808:2d7:: with SMTP id a23mr2434593oid.144.1614675511872;
        Tue, 02 Mar 2021 00:58:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8189:: with SMTP id c9ls414696oog.10.gmail; Tue, 02 Mar
 2021 00:58:31 -0800 (PST)
X-Received: by 2002:a4a:e70a:: with SMTP id y10mr15982094oou.75.1614675511517;
        Tue, 02 Mar 2021 00:58:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614675511; cv=none;
        d=google.com; s=arc-20160816;
        b=M3TAr/I06KqgwqKp8eoWooMpibu8pnhJrKOJ/ZpfwMyXAekMBOKiooCa3XDU2ayfOO
         nFL4kzlFA+G3yxL/kG33QrBpVilMs2vYbDFRr4CR2Tz9Ku8krZmPyPx5fAaVV6+Qjly1
         sjanQBqEuq2zPYPWGNii2LsG0/ArJ0voJVbPEj3eijvUUN6BfaqoT+EvUgsXmAMVY2g4
         iSeNCKxnuMAuyJ9uo+rX+C9ZxHF6RKvQm/vYmce7D8xT4YbpiTPLSEbs8db5fdpbsuVz
         XjE0m8UQSSfkGjwkhdhPnw8amWgCz0DNoypwvli+MF7WY/DRCoaR+F82qNV7Wzd0NZcq
         mp1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZedzYRAADqpCRUEjxpUyyJbfTq4kXSXEtgpjDsYUTaM=;
        b=fxJy4triHnraWf9lqv83puil86SEXMzPys2JGv+uT2JHarYMeV7gjMu8J5zDvBmQY0
         2yOL+kg/yS+TiPoGqoxrCd3ezt1YQMCI2crihgrfYaKLsZbCBV4y9sVGGm0WiV+1Vo2+
         NP+oWWzRc9fTko6EYQcJW+7GpqLDnDjvE5JAXjR9HKnWGF/xcGgpOo6/D6waBnqVNID2
         CG6VAgdsnCt5CdMMIUonqogTrbiSZAyhoQrK5qC2NS9O4xc2XSH47khF0WjgGVnlfIw9
         VjDHgElAw/jfGI8Qbwtm77zAYq1rOvSeuxv6eXKURpHYk5I0T0NArmsr8+y23JCzGuO+
         87dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VuJezB0t;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id v4si324594oiv.4.2021.03.02.00.58.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Mar 2021 00:58:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id h22so19293314otr.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Mar 2021 00:58:31 -0800 (PST)
X-Received: by 2002:a9d:644a:: with SMTP id m10mr17387529otl.233.1614675511068;
 Tue, 02 Mar 2021 00:58:31 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
In-Reply-To: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Mar 2021 09:58:19 +0100
Message-ID: <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VuJezB0t;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Tue, 2 Mar 2021 at 09:37, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the ppc32 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.

Nice!

> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the Read/Write linear map to be
> mapped at page granularity.
>
> Unit tests succeed on all tests but one:
>
>         [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfence/kfence_test.c:636
>         [   15.053324]     Expected report_matches(&expect) to be true, but is false
>         [   15.068359]     not ok 21 - test_invalid_access

This is strange, given all the other tests passed. Do you mind sharing
the full test log?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA%40mail.gmail.com.
