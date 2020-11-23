Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA4L6D6QKGQE5472WMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id E212F2C1359
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 19:55:00 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id r29sf14242970qtu.21
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 10:55:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606157699; cv=pass;
        d=google.com; s=arc-20160816;
        b=rY33uXVGx06bJSxlQu7ddSTio7UqYv9+DhAtw0Fl5lxyV+SMzU0dkHxmvV3OV3qkUR
         6dDbuLg98KeBJRAW8058LCqv92kkw1Zfo4BLgw9JQmeRIHK5Am4FukjaClCY9oDVAgNn
         A9NaamuzoQOpHUTIwrzKZq+pjuLsIGP8G03vvnGOgbH+T88b0aYktpuhNZ4t4LURIzyH
         BvoJZ0AdeSoFC3m/N6NitpwQ/4VYFHccbhalT4MNQl1OvGp6XCcVjVajzLKuYQhdeL0u
         pPdge0Hu4hR7lD/GaaQUFsAilA1WWLxtHG/UyJKJj10Jjid6A2GY6I30RvmEFC26lBkJ
         Jl7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Qfd3pvZqQD1OJ+5It+b/PV6j1tBa+Li3Ls7hI2SGtIA=;
        b=eGalc3RFHz4pJtin60eYTL+WlKE2YfCZFLi6a0Bzisvwsb1n/Pk/nIEwadanLazQHh
         fnapPP8OAfuTEECyR3ciLYoIyvgEddGlwpVnEkGekscTUn1Rbr2zBZu0Z8hTfg2ta07T
         tgcfZJuIv5J83XT4SLURiU9ui8WnEdpPDsWp2QKW75rXTZF5ALphs8RmJ7q49zjHrqSQ
         P3qVhyRJsfpP+O7IXdua5CzN38aG+Wpde3htI6Ycc9tE24TcGLT5/l7AerSLdhrH6xK9
         y9Cr5NRPyILwPX+FPjqcVHXSBD4wEB6/nlOL0wCHOHxkI8VKtXeyamE3tH508L1xFVH4
         TgkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SB0bFKQC;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qfd3pvZqQD1OJ+5It+b/PV6j1tBa+Li3Ls7hI2SGtIA=;
        b=dV3tGt4gzMmhyuka75ogQJcmMYwlV0TA1CFM8vQd1PaTpIh7gJsXsZaLFUji4zHpFp
         q3Tb25FctZCqLIvZmG6Rx8KMaJp65Kdy2i3IPX/dtu5RRMaRCOBuWup8gkNTJ2hKFzM/
         fzOPnTN/lBNCry6EU0lFZ9B/m5rtcihEknbvrxrQC74o7uomFXy7FLAW/IT3IUNyYMBQ
         kudwNGRItTLgfx4sDIKNlpv6AvPLtKxGz0WveyH0qY8QYqZy5U0bDnPVJrDP5zPuotZq
         y2oQe6C+2J1fzCfAvTqOTVMbkkEAF1LROosNDm/HSvkPOJXwlFB9FQbmV5pGyu5xtDnU
         QW+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qfd3pvZqQD1OJ+5It+b/PV6j1tBa+Li3Ls7hI2SGtIA=;
        b=rmp+Ao4xRDY3lZMCti7iNqQ8ZRyUe67wOZwPKiVOqsUrhDpjTDgK/AXIWg0ZChanOk
         8ROF4nEfzCZHNXTN/8ds+O0UduWNpGJmgs5dTNZFqQo6m/24dc3y2YdpkWDGVxqF2eEj
         wS7uooe9XUdYhp5Q7DTpiYqQ8x/XvJmOA6AjSHnyCJvOE5QojDRQGF8LOY9JjnLSlnGS
         B9jA5OgqgZNcJgwDw072JcxNKOfI2JqtWiaMM1QZmqMRowx63Zn1CTTcnKSIm4LK74su
         an/aRS4DOdF3CgnH911hFff+dywFsJUC15dreDM9zEUe9EAIfDy7GWP6qVLpa45qNkOk
         YXMA==
X-Gm-Message-State: AOAM532CKsdaz2jlN+cNBnA3PWNDVrTzhxndOZIpzEzhffREL3ZSf5Me
	LtXpGnNtGl0xYPhAKPOgbw4=
X-Google-Smtp-Source: ABdhPJz2jo77SnpRR72IesloNz9wT2JLbt+Y5KXQpQHcSWNgbgBZHwWjApIpHjgyKebJz3AVmoU1Zw==
X-Received: by 2002:ae9:f204:: with SMTP id m4mr914942qkg.227.1606157699666;
        Mon, 23 Nov 2020 10:54:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7dc5:: with SMTP id y188ls6973453qkc.6.gmail; Mon, 23
 Nov 2020 10:54:59 -0800 (PST)
X-Received: by 2002:a37:4796:: with SMTP id u144mr908689qka.235.1606157699223;
        Mon, 23 Nov 2020 10:54:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606157699; cv=none;
        d=google.com; s=arc-20160816;
        b=BwgYHZn7pIMUnAbptR4XMg5sLv/XjuTbbXOabmD5U8DNc/MQwJGy2ExNklj+L4S+V2
         mFa96Bs63DmWAWz9Syc6rtMiIwlWZ0N+EX/5CSOEx9n31OhZ3ZzeJgcwgJNVfx80XaKj
         /cWbx7yyRFrb0qtNo57Q0aVV9ce0PcHa9HF3rXdyAX6mgbWGZUXw1WwMshZ+NJF/03tx
         VbrEVI9vnvGqhsXR+C5+pQ1k+YRFbr/CTLPqyloI6bxtgSQ+aOy3L5yQNTgZ5MqKDDiJ
         T2jPrKUgTuy69tGd4o7OG2RdRHA3hm/wi2Z6QYpM9mK8q5SI3jg+IOV80KUldYjYAgDC
         +Xag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X9Zd5o6/t2zXpVPXOIa1lwnDSa6wxu3aYly3YlPdS4M=;
        b=oV3ZpuYFIicN1+ABK7edSi/fO+8k6xAPUP1Ki0rSbykwNsmZHg/SSATMOqJeEqBp1A
         jcuBqkNjQtqXbeaaV9ksMV8zdi2NwWKHeu5QUnxAg7yFmq5+82Tgg0GSqphlaHOYn0Tl
         UtNJI6rqSNVWTVygUnIaGdcVif2pAcpP7BZ6NekrSkgf35butK+KL/qNs5lHEJUZqL9U
         KoDaU86j4C/nh0FyrTI4g98NJDG7Lqui1bBXJwjMfqDruOAcR63tw7/9U4wJk49VU8LR
         34/Bj9Ix+0k7FPIl/VedtzxR2wUJhbc8Rs3s4Y9onh2cuBB9PGQ+Um8V3OAQ4n1Fk332
         8qnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SB0bFKQC;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id a8si40131qto.0.2020.11.23.10.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 10:54:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id f17so6565436pge.6
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 10:54:59 -0800 (PST)
X-Received: by 2002:a17:90a:4215:: with SMTP id o21mr326674pjg.166.1606157698246;
 Mon, 23 Nov 2020 10:54:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <52518837b34d607abbf30855b3ac4cb1a9486946.1605305978.git.andreyknvl@google.com>
 <CACT4Y+ZaRgqpgPRe5k5fVrhd_He5_6N55715YzwWcQyvxYUNRQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZaRgqpgPRe5k5fVrhd_He5_6N55715YzwWcQyvxYUNRQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 19:54:47 +0100
Message-ID: <CAAeHK+xv2UQyD1MtAiu8d=cRbJDNXQaaA-Qh+Eut3gRnLbJEMA@mail.gmail.com>
Subject: Re: [PATCH mm v3 17/19] kasan: clean up metadata allocation and usage
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SB0bFKQC;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Nov 17, 2020 at 2:12 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> >  void __kasan_poison_slab(struct page *page)
> >  {
> > @@ -272,11 +305,9 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> >         struct kasan_alloc_meta *alloc_meta;
> >
> >         if (kasan_stack_collection_enabled()) {
> > -               if (!(cache->flags & SLAB_KASAN))
> > -                       return (void *)object;
>
> Is it a subtle change in behavior?
> Previously we had an early return and also did not set tag, now we
> only skip memset but set tag... was it a bug before?...

This is a change in behavior, see the patch description. We now always
sanitize an object's contents, but only store/update the metadata when
it fits. I'll update the patch title, as it might sound confusing, as
it kind of implies we're not changing the behavior.

> > @@ -135,7 +135,12 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
> >         if (IS_ENABLED(CONFIG_SLAB))
> >                 local_irq_save(flags);
> >
> > +       /*
> > +        * As the object now gets freed from the quaratine, assume that its
> > +        * free track is now longer valid.
>
> typo: _no_ longer valid

Will fix!

>
> > +        */
> >         *(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
> > +
> >         ___cache_free(cache, object, _THIS_IP_);
> >
> >         if (IS_ENABLED(CONFIG_SLAB))
> > @@ -168,6 +173,9 @@ void quarantine_put(struct kmem_cache *cache, void *object)
> >         struct qlist_head temp = QLIST_INIT;
> >         struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> >
> > +       if (!meta)
> > +               return;
>
> Humm... is this possible? If yes, we would be leaking the object here...
> Perhaps BUG_ON with a comment instead.

No, this isn't possible. Will turn this into a warning and add a comment.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxv2UQyD1MtAiu8d%3DcRbJDNXQaaA-Qh%2BEut3gRnLbJEMA%40mail.gmail.com.
