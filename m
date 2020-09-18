Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWU2SP5QKGQE4R2YTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B89FF270088
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:08:11 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id z22sf1717987otq.14
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:08:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600441690; cv=pass;
        d=google.com; s=arc-20160816;
        b=SCqZ57c2GaK1BTAxqt8bzTUCFkN1bPIo3liSyLs06Bj1/g5Ax2eTAmBPA0yShqb/ow
         9G9TT9yx3VglfoPYZFVtcgyApvBWQYynC00RN/jVo6etmyfAo3A7beNvp5F3heq8tN3B
         7Sy0v/spM54fyOd9QFU5F06GjpwXrdpAQBmMkBTJow4ANC+39aEwE5gjl7gnPgWMV7HB
         /zNqbQp420qicUtVOyfJ4/BabAXuPGFC938tG6sLspokGxa35Lmn6+uLLnheURqn1fYD
         gp7RLkPMdu4lId6L99hL2tNsQqBFcAkDBwUtwCaUi3w3vokCSNXSlylLiefJV/wpmdTq
         xWGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PjIBVzrScr+PnRjUWRnQrUQ3myLYzbYpcLhnlegqIEk=;
        b=TojjASxK31ZlmwSSoVAKGoAKdV5b9werrjf37sp8Tif3HDa91pllUULKQdTXTfpa3n
         Lm+G7bjn5wHbZaWCEZGWHbRAmAgWK1RY5ucXldtZisychYDmgPzQesGYOYUgeFV434Cx
         SRm48EqX2T75UxUJeslK5TIIQazs4/QPOXnBnWalZlIQmdcFTRMZsY6MoMa8LXKu984f
         /C07ouwxAQxdVLKS95LvcGGj7QABJGeeXxp6tbCyduRaePqvdMh3fdn7vxaVvavQs47B
         eEQRDRGGq00Cu9vHe40lkMnN0F04eKNvk0ozzhbDfzRj8/LxahXiQiPQRha/49jRPu19
         5b1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="a/D8P1Jo";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PjIBVzrScr+PnRjUWRnQrUQ3myLYzbYpcLhnlegqIEk=;
        b=KgWGMckBo/Bjh1b79BPuN8RPdrxQyzdw+GhWqCFaaS4FIuBTien9xO6sdU6T1i0RqR
         7gLZt0m9QmLvBN57mAs+sW8luT/Urx0vSMJXJirKaYA+wDubSbK/gQtV45LWXUCjcaL/
         mp1yOdvH77XPTHIZSv/mrmIMJfNlsCcCFpztqw6WRImAHCcsoTNWxG3eQgeOhjc5PrUi
         jkZsM5YDYOc098qlYSbC2E37CkcR/PgRnuF+bpnwxhtDzbnRkDHlPIOZy4R2O0/gxZfy
         LHLY+ZyEQO5U1WxD2IXlzFDCMnQvBMhoBF8I7B+eXQ9CU9yOElz3GGjqPMlMrEf+44A0
         PEnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PjIBVzrScr+PnRjUWRnQrUQ3myLYzbYpcLhnlegqIEk=;
        b=Y/PggciVvQWtZpqWIErKjOY+MjidClCjfntD2CiTiMxiRnTPkiaP5FY7of7qVtVSKT
         OAlktYoK0NoHHXe2GkzHjdF8GFfIRb7i1vvkvOauZxii1cuTaf7xS9c8RM6Kk1LVe0nt
         O5uLaLuDDhylw867dIR7+371AXSPWjq7xtsqps194e0NpgOvRMk+Pd2tEae+gK69yWdG
         ACg8OEfXd9USNWTPNTEUrZ4UUw9kDG2hL8LHCZO5QBCVCMMhOzYN5gJSvFwKCK17yPs4
         cdIPKFf6aB+XcZBe6/HGc+w622PbQMwn9kkdTkcz3C3ZzEwCTSygALoMGp5/Ug7Day9D
         bDLQ==
X-Gm-Message-State: AOAM532gSGCWLIrKgCVw8XDm0ReHBdKc6er6ezrUBoRwMilMmgfbak87
	Py32Eauvp9D6moYjGx0BRv8=
X-Google-Smtp-Source: ABdhPJyw6nEf8qB1VGw0SB34Vh0Mn0tA4MJSAcuWwmD3rST4wB8W2ojh50SzmgKFnEB6xOFXx5tMqQ==
X-Received: by 2002:a05:6830:4a4:: with SMTP id l4mr22148159otd.212.1600441690650;
        Fri, 18 Sep 2020 08:08:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e547:: with SMTP id s7ls345266oot.11.gmail; Fri, 18 Sep
 2020 08:08:10 -0700 (PDT)
X-Received: by 2002:a4a:e862:: with SMTP id m2mr24574109oom.33.1600441690233;
        Fri, 18 Sep 2020 08:08:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600441690; cv=none;
        d=google.com; s=arc-20160816;
        b=hktSK1ZOg5J3t9vGpwp/q3E8s/mUXYJFlc09BukJJ794sx71nJ10C89rA4VC5Q03we
         K4Ay1NPD+Iit0Zo74cJUR7qYFtaCxgc4osGj9UomiVIvMX39pj3n5aqwjJAdjq5qTxbg
         5XCh/a5OLTnxi83mHWt4/vyqoQep/x0/6dtUxf82ceiUILxJcENm38jY0jVlHnNsz0iV
         07CM5FFSV58IEc4dgT502FrG4Dj9yDfVApyNjYsbdrdqQpUjmwWWD9ablMF0sxof9Ir3
         U3z7RhRj3I6jMfYXSKmIGJ3oYjfOKrypmJ8qnREaI6h2uZukYY98OQaZif+ilNCXW8aJ
         hSJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hGGCKEp4K9GjwoPVxOOO2axTbNb8r7W1/g/yQhmQlPs=;
        b=u67epTR4dX0PLqWh4YsN3+iKGXA/dULE4iid6l1G+4LhklZyjuCzV5Tpu/b6gIhmLQ
         22E5ERSHZeGiMRUvC7R7Ifjw1rE13JmLcEn70ZZxg4+hMmjkRqG5Lzir0zPg2OdncJVr
         2c3fwj2KRvnYYXf9vk7KP/zT90SeBrnSywBeBRqnhTfzD21CZCCPsGYDEehUAMoWOzRn
         0n6glhkIJ2+wcP04H4Nf7IdiK6kRkvXQvvZuwK2Qw+HFUJ+y9qWuEBDZOSZmyvABYbmN
         aKxPLCjIIX8+8LSlSq9l2CS9+O+nN2poH50sr1n9ITbnuIs9E4Szb7wt8fUlaxvBUIt2
         UWag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="a/D8P1Jo";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id k144si220661oih.5.2020.09.18.08.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:08:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id s65so3654198pgb.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:08:10 -0700 (PDT)
X-Received: by 2002:a63:5d07:: with SMTP id r7mr14529655pgb.440.1600441689365;
 Fri, 18 Sep 2020 08:08:09 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <0a35b29d161bf2559d6e16fbd903e49351c7f6b8.1600204505.git.andreyknvl@google.com>
 <20200918105206.GB2384246@elver.google.com>
In-Reply-To: <20200918105206.GB2384246@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 17:07:58 +0200
Message-ID: <CAAeHK+wqzZJWWh+u3HaLvSAt=4SxaFT4JUgTqzMYcPNGhBFFBg@mail.gmail.com>
Subject: Re: [PATCH v2 31/37] kasan, x86, s390: update undef CONFIG_KASAN
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="a/D8P1Jo";       spf=pass
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

On Fri, Sep 18, 2020 at 12:52 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> [...]
> >  arch/s390/boot/string.c         | 1 +
> >  arch/x86/boot/compressed/misc.h | 1 +
> >  2 files changed, 2 insertions(+)
> >
> > diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
> > index b11e8108773a..faccb33b462c 100644
> > --- a/arch/s390/boot/string.c
> > +++ b/arch/s390/boot/string.c
> > @@ -3,6 +3,7 @@
> >  #include <linux/kernel.h>
> >  #include <linux/errno.h>
> >  #undef CONFIG_KASAN
> > +#undef CONFIG_KASAN_GENERIC
>
> Is CONFIG_KASAN still used to guard instrumented versions of functions?
>
> It looks like #undef CONFIG_KASAN is no longer needed -- at least
> <linux/string.h> no longer mentions it.

I'm pretty sure this is still necessary (something didn't work when I
forgot to make this change), but I'll check again.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwqzZJWWh%2Bu3HaLvSAt%3D4SxaFT4JUgTqzMYcPNGhBFFBg%40mail.gmail.com.
