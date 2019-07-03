Return-Path: <kasan-dev+bncBCMIZB7QWENRBN4Q6HUAKGQEDRJIPOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 15CAD5DDF3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 08:16:25 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id h67sf752094ybg.22
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 23:16:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562134584; cv=pass;
        d=google.com; s=arc-20160816;
        b=tFoFBL2BuSzJxQEPYt2X3QwwxZh6vUz/v+bjwAxSaAym+z3g6IrIn2/vM3fnm0ZOyG
         obIRJWodU0eqpE4d265qxUAZzld4VoAOBj8sqpJqEtqVkOij1nJ62xBXYQ5n5NmU5Q5h
         YP/d0ylH1CgQFb9E3G7l/bksXJLybTTgFsWvI6CTQamm9WdQm6S24bRe3D0olA/yfcj5
         UJDTV+DQy1ucqVGO3CrNT+o1V6U3WF3xfzvqy8i4ZJeajElcmwqZmM9txuMC+7g7Tt76
         1Q+Ti4cf1WGbEak7hBhDKXx2Y9LnBbHLrFOhnNMLYZFwo0V3tpgYClrxsbT5mE6Bb2AN
         kzHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dZ4T7DEL1tdSH5i64pcFlQtuJ13Z9629GznFcH5QeSQ=;
        b=VsAt8P7GsTUndBtv5RBSZfPRXojmNRGFGPTfFIZdwexWytusvOsdCVfQ/cvsi8QEkB
         ZJovgFBaSa6Lv0S25LhKlXVFcR2djJCfqVDnq0Jg708H9jJ0WN+UGP2h0xanu5sgZCZv
         ndwtU73WlRU7JExbqYzkrPGxezz1HDg5dH0QDzeHXa++yaOmEGAVkeiwE5IIf9ZFvK37
         E0Gk9lTTk8ctNvTrFqJdjN3SMuqXRuD+D0U6JaQe+A+qfLYPxGkyJnYUmQg05w5Ky7EF
         4OQBFjFTc9rXxnzwI9godbBL0gNhEGsi0ifeQpMCdt+9TCC4gGuNxaUnFNwMdMYcM9iR
         B7UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=su0RwBuz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dZ4T7DEL1tdSH5i64pcFlQtuJ13Z9629GznFcH5QeSQ=;
        b=c2m3oPfuZxgD9OE2+IA5ABw/KymMnC6nC3LGEgt7tU5rWufxd6Wp0wVHV8RQT/XmS/
         yOxtaHmz6Z1HhG/8RpMuNw7qFxNfxdnu5+5iVcrhfk+OxYDeFa10w8d5jguFddQVkkfT
         TFQfEUO0tBGjtrJrjoyiHKt2nfSjVlZDkt6PIc1fPD3DEVOTY5By5Z/J9+CpRPC5NYsQ
         u4Od+St4/ZwU0d4/3N44QBoGwRWPNFyRsevfYQdbJQOOoHvUFCAbX8ExtBPt3yLSIGRl
         Q2utcccjsdSpPP6NL3rTzCuU5a2TU9n04a76pm5TP8re20M7Tq2gq1z3+MWZRihDKkpC
         syvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dZ4T7DEL1tdSH5i64pcFlQtuJ13Z9629GznFcH5QeSQ=;
        b=nt0WdNvyF56KV2McW/EU/D0So05loc/RHWlq3hxmQr0mzZSg6aAb9bsnXF2Kl4sF9T
         BIQruMBR35Kmq5Iy42PzLkX1Qo+vnA5yPvgZfgkdKkxT8DbtD7FoVgEu5jIhNMSExKDE
         2XL5hgu4HX95vH0e0wM9HJ2ZFgO726oxDDd1fu75y8pGKQq61MCmm0Odgrc/wuEbv8LZ
         MozWE+R1TOC3pUY8t9Wd0IiPo95GVTpw118rfajS0OjX4+Y8FRFT7sQoDpxJh+PE0xyE
         cQkEbHOGp2G/d12pKNdTUeFyWt0DuVChDc8zCrudPdW61gs4k8F7thU0mlH4Op30BtiE
         ttoQ==
X-Gm-Message-State: APjAAAUKDSn5WppVrsq2XWZ5MktpusmA+ntMn8lfvyX+EpGu/DY9+7Wt
	eay9LKXgueWveRqGb2jIhJg=
X-Google-Smtp-Source: APXvYqxF6o4AuhcNyrvZWDa1XXiLH8kgkScxo+0TG++0G03rNqKyRVoUlQRKYi6vlgbJzeS9NocNGA==
X-Received: by 2002:a81:1090:: with SMTP id 138mr21165324ywq.422.1562134583729;
        Tue, 02 Jul 2019 23:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7805:: with SMTP id t5ls182705ywc.8.gmail; Tue, 02 Jul
 2019 23:16:23 -0700 (PDT)
X-Received: by 2002:a81:bd54:: with SMTP id n20mr22296259ywk.507.1562134583476;
        Tue, 02 Jul 2019 23:16:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562134583; cv=none;
        d=google.com; s=arc-20160816;
        b=qzcg0rxUox4LtD+hlzGXI0QSodeVoGidM8EiFSMOvJA09FJ6eYmr8U/THvWoW9wola
         +JX+gwCAOJ4jJqqfjhiVJQh7W90m+IuSmUzWDaE1U5QY1UlNyy5pIVJDZnkOTcKDWKip
         zeqrkVcWRLxoUr6zaZCrUa7YpUc/dmDruWWHDMFqgZyzAY5SHeeeZrfGdVUULvqgdpt+
         j8h/c+4vUiULMlc2/REpesVankcMCSq+b8OrIjgnyAuNdpqksxfM8srwFT2wdJeHx2WR
         UkV8Gapzh7YGb0TmoFAMN7D3A9MHA/rvpNhJAFoEWrColXQOn36tAiGu77csNZaRYTtO
         FKPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R2THxZg0veVh6DR370OvD8iZuhQVrJiyUKil60y1Wkw=;
        b=bMfG87JhwEwdwBhyPJDRgZekxa7MZOihJZsNTjFjcSyUOR1fcf7vKk3p0Oqoo+ZbxV
         oYVH7SHeL4i/ef07qJJMyf+gj7NtygKBnufxleE0iJiXtiF+gGIANKhI2iPlJxkkAsO6
         9doT7WZD0FC6coF1YA5bbT1n7y1Zli7AhP95TL9qeUh8dWuoPfyiuZzLZxacpK4zT44g
         ix9+j/a3l+vqeFk8T27wXy7NcAG41X9zKEbfx/ezo4Whrcnc+mjksrTjb0CblI/v9Dlv
         XdVuD9yNpe9Nj9IU1GQnRjBONAmWjDAZEO2IbOmrhxizHHam8EApzmCIGL4sxIEmEr/d
         SwxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=su0RwBuz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id g15si50562ybq.0.2019.07.02.23.16.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 23:16:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id i10so1974832iol.13
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 23:16:23 -0700 (PDT)
X-Received: by 2002:a02:3308:: with SMTP id c8mr39858892jae.103.1562134582699;
 Tue, 02 Jul 2019 23:16:22 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
 <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com> <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com>
In-Reply-To: <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jul 2019 08:16:09 +0200
Message-ID: <CACT4Y+ZJcp9fTsnvc+S3mG5qUJwvdPfgyi3O5=u_+=LGrbTzdg@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Anatol Pomozov <anatol.pomozov@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=su0RwBuz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43
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

On Wed, Jul 3, 2019 at 7:56 AM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
>
> Hello
>
> On Tue, Jul 2, 2019 at 10:15 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, Jul 3, 2019 at 7:01 AM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
> > >
> > > Hi
> > >
> > > I am working on getting KernelThreadSanitizer into better shape.
> > > Trying to make it more stable and to report racy accesses a bit more
> > > accurately.
> > >
> > > The issue with Linux kernel is that it has a plenty of synchronization
> > > primitives. And KTSAN needs to take care of them.
> > >
> > > One such interesting primitive is semaphore
> > > (kernel/locking/semaphore.c). I am not sure what is the use-case for
> > > semaphores and why other primitives do not work instead. I checked
> > > some examples (e.g. console case -
> > > console_trylock/down_console_sem/up_console_sem) and it looks like a
> > > typical mutex to me.
> > >
> > > So I tried to add KTSAN interceptors to semaphore implementation and
> > > found that down() and up() for semaphores can be called by different
> > > threads. It confuses KTSAN that expects mutex ownership.
> > >
> > > So now I wonder what would be the best way for KTSAN to handle semaphores.
> >
> > Yes, that is the official meaning of a semaphore -- it can be "locked"
> > and "unlocked" in different threads, it does not have a notion of
> > ownership and critical sections, only the counter. The counter for a
> > non-binary semaphore can also go above 1, i.e. can be "locked" several
> > times.
> >
> > For such primitive I think we should just add release annotation in up
> > and acquire in down.
> > But how did it work before? Did we already have these annotations? Or
> > it's a new primitive? Or it is used rarely enough that we never
> > noticed? Or maybe it is already indirectly annotated via the
> > implementation primitives (e.g. atomics)?
>
> Semaphores has never been annotated with KTSAN. I guess they are rare
> and problems never been noticed. Currently ~30 of semaphore uses in
> the whole Linux tree.
>
> And btw semaphores do not use atomics. It is a non-atomic counter
> guared by a spinlock.


Ah, ok, then I guess spinlocks provided the necessary synchronization
for tsan (consider semaphores as applied code that uses spinlocks,
such code should not need any explicit annotations). And that may be
the right way to handle it, esp. taking into account that it's rarely
used.


> > We now need tighter synchronization on KTSAN as +Marco will start
> > actively working on KTSAN soon too. Need to avoid duplicated work and
> > stepping on each other. I think we planned the following as first
> > steps: rebasing to HEAD, rebasing fixes for benign races, fixing any
> > new benign races during boot/ssh.
>
> That's great to hear.
>
> I've already rebased KTSAN to current Torvald's HEAD and fixed some
> issues that crashed KTSAN. Now KTSAN works more stable for me. Will
> share the tree once I clean it up.

This is great!
Marco, please keep this in mind.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZJcp9fTsnvc%2BS3mG5qUJwvdPfgyi3O5%3Du_%2B%3DLGrbTzdg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
