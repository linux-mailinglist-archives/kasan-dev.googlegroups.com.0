Return-Path: <kasan-dev+bncBCAKHU6U2ENBBR5MR3UQKGQEM4H56IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 23FA262923
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 21:15:21 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id t19sf11078054pgh.6
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 12:15:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562613320; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mc6O0QkwVFH5+DEK012nYMBjKmULjPT77Y0L27X9fAYDyCvIzZYkjjIaTU11/gYDXN
         JYjL4g+Ps3Rrc/OcwQkcb/krhcGkFOi5SQ7s7RVWdYz0xg1py1N1NNl2BGnlw3KNMULT
         vx3bws+LP+X+dAC4rbRN18xusXLoRdvFIzmij7y75j+PJ25pTI21WaVysVKtgAwkYNS5
         a5uZqAjMuch7ePd5rpFBFtWq62ZHV1wcxuhl8Jvg4BqccDkptggpwL9bgd0OK3gKcD2l
         ETuv5Bc/piLVOrJyKB6aNf2kSm3Uv59NNRhCRIZ4d4V74uOuaxr3uWNkxQ84rm8TOAOk
         IcqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=3Pl3ROO7MyfWOXqEtVoB1qSEODgCdM7XS2okBUFJkLA=;
        b=zkBTtNq4zf4a1OVNAEK3CMpIRjEnTvtJy8JD+NkqTVr9wG5TebXvDlBagR/eabh2z0
         LRel3G15RHwv9djt8iJTTC1HS8QEecoXWG0pELXN49+xHzYy4Lao+F7Fc9eQaYn4gFrr
         rWIXZ6LfdV+yraiDIKC4LSRBliifTzptJNXGQ+1enxJfNkzWe/VIPoM3Wd2HZW+ed2uf
         8jBKGjIJ+AsNCMqeMVr1r6vauCopaIWl0JJjipO/CsQk/4S1ueSWn8P+nkCKMWo79Kcq
         UsQMHWvEPU8C25o/Gfp1+e6lE6jl6C5NtSv8KqZqCZAGKHKFnrL7MAOlOitRBOgn4hAH
         htXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nFHru7Us;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Pl3ROO7MyfWOXqEtVoB1qSEODgCdM7XS2okBUFJkLA=;
        b=camx9XL/GuDI2kqfJRRrf9yD3PufqEjLPReW2XXb5pfq5upM2e6dt+okFzZoMfqA4D
         b9vEwUxbAzGg9BgZf8qFRk+wKUiMYpmQsDf8XoWPT8D8FNbPY3yD9d/jQJDTBs35BzD7
         skcpyRUD2ylQ/VjH9akbBf37gHavU3zthqA+/Ci8eISKZGg2+N+s4pFHQUh5bZKutfLT
         ebCojib78AXJ37xdPxaGaYF4F/llF7yGi2u3q189xXomtSeW548b0fl/2wzACVVP+Cn+
         4UEBHuFN2L9XpVm8inYOopdHywaxEdf/+8kaPW+eWncnHtv2zFuKm1wcvIXbEb9YiSqF
         2MiQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Pl3ROO7MyfWOXqEtVoB1qSEODgCdM7XS2okBUFJkLA=;
        b=C0EMvrQAkNy4NfoMi7D9BSM1NT4bv4LQ6s+U3Ar+zFKVUlsrlwjlSq5U9PgjD/yfEK
         om2l34l7GNI9rS5z5MWlvMJDT6Fdtt3VG3MOl7HEgrtBrkWPVpjGKJbqEq/evsmU120w
         SYNRPYTBjpDUxQkwv8Zn1iiGjoz60JTrUSz5ex+zsq6Ow4k4YZ3TTVQwKAMtAwTpQV0+
         a4ZhYCQ+4sQYBBpNnhCoNlSHAbOISWm4/GA1V8lj8MfwXTEW3kan5V+faDY/im8Ap2Gc
         UAFwDoVWU+jMtptwTNsV/kmgCtR0pPfcSmhgRzpEpKQobfZ3E2rEzK9uWDs5LQnMlKnE
         hnQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Pl3ROO7MyfWOXqEtVoB1qSEODgCdM7XS2okBUFJkLA=;
        b=WarMCXzVfcbAYGv5finypK4wUmhrc6kq6Roiq7ijeblVRsswM6Q8/jXgxx1sow5nGO
         eMdmMuUzMFcGMYKKEUlvEjRSsB2Th1Bz677DZBclDsnD8+PR5FF3gfz9owWZbbikB28D
         b8BEvIOdX1qd9vQf5fJUesa1y1pyKYdoKOR2vGS2vL2kkR02OWhkBm3uMy+TVaezE6Y8
         auSK5sriU2b6NrbbkYMPMpn+6Pw1td+lzGJmrG49RC5qqjK8m1dr2lCefHHASeGvhnl9
         aFsqJ9kVF5rgfB617zqrzosf8Qqb71F+DgSV542D7DP0CwpSXqY8lcShNz0yNiGbaziK
         pccA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXYY06Y8zYeok2sHenR0rXCukB6+P3W+fsOTBYcE5pv+4CVIN4p
	e4UUHukSFBPdiaR+4hbIp8g=
X-Google-Smtp-Source: APXvYqw/XIPZhFKrkJLA1K27cO87ArNm6ZKe4WoGVNVw4d23GFHlANNeWhY7HH+W1daoDh+29FP5cQ==
X-Received: by 2002:a65:6114:: with SMTP id z20mr26186898pgu.141.1562613319817;
        Mon, 08 Jul 2019 12:15:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:372f:: with SMTP id u44ls155924pjb.5.canary-gmail;
 Mon, 08 Jul 2019 12:15:19 -0700 (PDT)
X-Received: by 2002:a17:90a:7787:: with SMTP id v7mr27721150pjk.143.1562613319474;
        Mon, 08 Jul 2019 12:15:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562613319; cv=none;
        d=google.com; s=arc-20160816;
        b=06KW7sURzXfKfUjSIoeGfySHQsSepbZqaa/bC6g7ArXYfOTNoR3EC7a7LEhNkXgjzS
         NnjznnKvGTmwbaz5PZCH3IvExeOCDz4Tctb7AsZC/sE4rW8tjV5Z4grLXt7YuyudEsnx
         jspZGR+W9/AA16Nzk+OIKJZauLDcftMBEqJf7swIBzr+pLGuBGPSam9Oizh1tRH74SOb
         inkXez1j5GJlB1SQdck4efmeeXjVnY3MJW1Vfg5jKs8bVSmT2KKDbbB4cUnieYZO37/k
         ygRgiKe0lgGBhZ7EmFt5g2bQqG2lpKgE46ACUM597PIB+0x6FtXIX0sXmZidp7c7POEo
         mtMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WRouqp2Jr2IUErTR0qCJ9n0SpIEbdq6dJAYcthpZfJY=;
        b=QI2HeJz8P0hzCS/DMncZ0+Q72L6SLItZWYlyjiQdDdXrSOoz20jmIDH8TzOLNqIofU
         WBj2JEWdvAx7UN4A/TH7Omb3AzcxavsmznUzNBgOhT7qGed9bCantG1EvVlfUgc9LCaL
         /IvIjoMHdQ/Kgw348R8Cru0aPYUindYw+eNWoJ4xX6tJ06i26DssOKZDgQjPzgQtt0hL
         0IIjeSsX4XIzERK05LGnq8rw5I2WjlDpDQ0wzvoOY/GJ9LgsYi0nrCdUcqn6UYiO+lkv
         dakYH6ki9ohpfxDKTAnMfY3OxxZhznBy5tH4v9xiNzomwyqaFdjI81Q3l0+xjjsiA6yO
         XoPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nFHru7Us;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe44.google.com (mail-vs1-xe44.google.com. [2607:f8b0:4864:20::e44])
        by gmr-mx.google.com with ESMTPS id h14si415462plr.2.2019.07.08.12.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 12:15:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of anatol.pomozov@gmail.com designates 2607:f8b0:4864:20::e44 as permitted sender) client-ip=2607:f8b0:4864:20::e44;
Received: by mail-vs1-xe44.google.com with SMTP id a186so8951445vsd.7
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 12:15:19 -0700 (PDT)
X-Received: by 2002:a67:7cd0:: with SMTP id x199mr11500012vsc.233.1562613319042;
 Mon, 08 Jul 2019 12:15:19 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
 <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
 <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com>
 <CACT4Y+ZJcp9fTsnvc+S3mG5qUJwvdPfgyi3O5=u_+=LGrbTzdg@mail.gmail.com>
 <CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA@mail.gmail.com> <CACT4Y+YO8d6xQvjDFNKn83+JWms=75VWL5CASC8F974x7obM4Q@mail.gmail.com>
In-Reply-To: <CACT4Y+YO8d6xQvjDFNKn83+JWms=75VWL5CASC8F974x7obM4Q@mail.gmail.com>
From: Anatol Pomozov <anatol.pomozov@gmail.com>
Date: Mon, 8 Jul 2019 12:15:07 -0700
Message-ID: <CAOMFOmU2_oAmgBSVxQ3wbfQk42Y1AN7BSE4izuSctieX=bDwFw@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anatol.pomozov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nFHru7Us;       spf=pass
 (google.com: domain of anatol.pomozov@gmail.com designates
 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hello folks

On Thu, Jul 4, 2019 at 11:17 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jul 3, 2019 at 5:45 PM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
> > > > And btw semaphores do not use atomics. It is a non-atomic counter
> > > > guared by a spinlock.
> > >
> > >
> > > Ah, ok, then I guess spinlocks provided the necessary synchronization
> > > for tsan (consider semaphores as applied code that uses spinlocks,
> > > such code should not need any explicit annotations). And that may be
> > > the right way to handle it, esp. taking into account that it's rarely
> > > used.
> >
> > The spinlock provides a critical section for the internal counter only
> >
> > https://github.com/google/ktsan/blob/ktsan-master/kernel/locking/semaphore.c#L61
>
> But this may be already enough.
> Any down on the semaphore decrements the counter, consequently it
> acquires the spinlock, consequently it synchronizes with whoever
> executed up on the semaphore via the spinlock.
> 1. KTSAN understands raw_spin_lock_irqsave, right?

Yes, KTSAN understands raw_spin_lock_irqsave through __raw_spin_lock_irqsave.

> 2. Have you seen false positives? Could you post an example?

I did not go into testing this functionality. We need stress tests for
the codepath that utilizes the semaphores (like test for console
code).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOMFOmU2_oAmgBSVxQ3wbfQk42Y1AN7BSE4izuSctieX%3DbDwFw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
