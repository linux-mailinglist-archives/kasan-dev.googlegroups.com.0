Return-Path: <kasan-dev+bncBCMIZB7QWENRBPNS4DWAKGQED6ZEI3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id D267ACC7A6
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Oct 2019 06:17:02 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id b67sf8708049qkc.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 21:17:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570249021; cv=pass;
        d=google.com; s=arc-20160816;
        b=l8kgGYE/bhWH2emJjKRDBEWbGV4x6cuKnrQ9XjpbNPYoRPapob0a5SLhrj8/g77OJ5
         YEGIX5ubpEaoScTVlbTauJ2XvUxFVYjGGjWeP6eOg2QKAuW5SQNAyXZXQI0oCF9+KzYt
         UvYJN6I5OnQnwegfcaRKMUxsr4W0dbjh6dj1kIuz4hz8Kpz5cTPAqR2tCoJM/hh1UYiC
         japPvj8Ewiz+Z+9hfBgKk6Yeq3tf5YqMKNFuGG630hAjy/J474+GUdPW7V+vhyXc1PLG
         B+2rVNXAJVWidXEkUiByvAEqOk8exlt1dP3IV6GjltRHTMFkMlDKkrr/SWBPsniwQiLA
         oUZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DXEaNtq4T3qWPDNOZ5dmqkil/2FfZ+AApzJCOznkNe4=;
        b=k9AmyIHNc8IGHI91ZvuuTdipsKgtoYGnkt4TwvzXP7A42be+OB1xEC1Ve9BnXRR+rY
         9a0umyqOqlZbCqKqyHCHq50x73OQckb3NJ+XFttm9PxftVtCLeMJbWjGY4Y5JtN5a8+V
         D5WtN8ZJgw99DcQCPTgKo1H7FffPoHngKe+QTSy7bK0YtGCqgJiqfqzZG91RTqnF8M/I
         NYbza2+UiMr6G1F10uFhUlOc7YvtyG/R0NEayRTcmAT2zN+/TGNJZB/Jm3BR5/Luvhg8
         bzPEjfCg+c3dGbzYG/GfIMghTbf3BxrG+hWPdVJtJurhTL62SrZ/5H8TgbZyJf2EVhKh
         sgMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PFX3TwRa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DXEaNtq4T3qWPDNOZ5dmqkil/2FfZ+AApzJCOznkNe4=;
        b=NYaGFS/3pB764ugvzLVbkAw0sZ03sbW4wUt3sbbXeplv17htEICp75YHlLZp50yiOo
         Xyb/8/ZlERCVxGU/OZNZVokpVNxVxQgjO2k2MMAywtjGhG3PvvoN0BkwdQovC/pwQdmC
         vCAzi3m9pg0EnFs0mH/6NNvEoIAQk9DjvnY2O1wsy0OGsfz6MJ0619r77e9L0R8Zrw5q
         wh7mY3thwgz8oAD1fFe7bNKhuLRT1Ww7mD7tPixi9XlpLX5PO60aP8zuXYfJZtlBCvGg
         oDZQt0cTDnrxVepSp/DU4RSEJxeEHfJOdRSL7Ph5hjcE4L7bc3/VeIshX4E4WsMe8RDo
         zDNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DXEaNtq4T3qWPDNOZ5dmqkil/2FfZ+AApzJCOznkNe4=;
        b=iUHjk7bAtTzEuFRWHlsSEpozBW9OOYaF0mRYYpnstsOuoJAkFXkftfsP90skH//yx+
         enS8epNYyHrUvPKOFRdmEFFaraOZPcbtRbFGILos5ceydYgl99ksTyTkAiwefSkaQevg
         wJescrXKD0ZaQAaW5hk9gvX3WQ0052N4fHMQK5VDxhFGCXbfEqSlE1Ww8bbJ9JXTsjBx
         WIXLQ/qQDqsbaXpprxTzGiROHLEu0lxIVYT32krJRIR8MWdPTxdg66+y2oVqjh5FZcLy
         5trtZyCzqQFg0eYl07aWdsk1f96OPuxC5IweRFI1GWosQkrMKS30jUq0qsuRZOx5V502
         U7PQ==
X-Gm-Message-State: APjAAAVqvDwsk6TXzmMIAc2bW42MPLmAzMJMi3Vm9InjxQ4GrkkVJQJX
	O7q4EUpxTFxEwMZbbRlb9n0=
X-Google-Smtp-Source: APXvYqwuYDVflBaAPeryjNOBpcqi0UXZomNkskvDdakuEf/sQZcMCuS+GTZX6rCDv5S2fPhYbjEowQ==
X-Received: by 2002:aed:216a:: with SMTP id 97mr20154780qtc.114.1570249021395;
        Fri, 04 Oct 2019 21:17:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d246:: with SMTP id o6ls1966609qvh.9.gmail; Fri, 04 Oct
 2019 21:17:01 -0700 (PDT)
X-Received: by 2002:a05:6214:1449:: with SMTP id b9mr17876237qvy.139.1570249020995;
        Fri, 04 Oct 2019 21:17:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570249020; cv=none;
        d=google.com; s=arc-20160816;
        b=KH+F3WUxdtYNTKj0cFcNiVjr49jzHDYD8tK88i2Br+VPAvOZAUjIvqk0QVldnjqQCG
         8FkniF9GjMqRfE2S7ynV97mOZvrrRWuPOsAQiaNytUNSLieQU4lTRtCWluht+PeTaKq9
         tgzfP+6vJAQK2MylMNUs3h064ya1vA3nS+j34NvV4FDUK0qLhR3+j9Jn5M0fUrJ8fBlU
         qQHWyFd6Q7YJ6Vhr6Tws1czqiZQj0RJG3Hv12lFq/rDWBDQvr8OxEK98uZNedM2S6dVo
         /BDl46TSBIDOrfo834JxUw+JgAOIoR2UgwyGq6ljxohCc5Nt8ro9irPGJwQiroIm191D
         4TaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gR2Z2jLC/Tqbl5OOfY8ysoZnhqlSC5suivknCtmSIx4=;
        b=a5l5ynFkxkUiDux2zua4Ntjs/j1k4ULK/5TFBj2tTXaDY8Mi8Pk4zZisz9uTUYqJoo
         k6QS3Mw79tZwm/VZCDxvlobRkCBANF71Ou5j/2gZ5d4/rBtubKODfajvZZpucOl7xCst
         ie5u7hZkEPIJuhxThMQRP33u+D3vPbwK4nKjuthkAqyLS4SLpVIR7GXXyuHCbONcW9nm
         m2Ub9wK+3XZChQpr3qDyto1oZG+QKf6djmb+GM5os6fjpcAlePhAvdcloKxwiB6GfFED
         ytJ+YYQp+CwH5GSUqQta0WMoS5f6mGA6lPyvflXV5DDoaFxhKFWmj+/Cs+ZHju0Qrzx3
         Sowg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PFX3TwRa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id l4si440814qtl.1.2019.10.04.21.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 21:17:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id w2so7810131qkf.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 21:17:00 -0700 (PDT)
X-Received: by 2002:a37:9202:: with SMTP id u2mr13849869qkd.8.1570249020168;
 Fri, 04 Oct 2019 21:17:00 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck> <0715d98b-12e9-fd81-31d1-67bcb752b0a1@gmail.com>
In-Reply-To: <0715d98b-12e9-fd81-31d1-67bcb752b0a1@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 5 Oct 2019 06:16:48 +0200
Message-ID: <CACT4Y+bdPKQDGag1rZG6mCj2EKwEsgWdMuHZq_um2KuWOrog6Q@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Eric Dumazet <eric.dumazet@gmail.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>, 
	Anatol Pomazau <anatol@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PFX3TwRa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Sat, Oct 5, 2019 at 2:58 AM Eric Dumazet <eric.dumazet@gmail.com> wrote:
> > This one is tricky. What I think we need to avoid is an onslaught of
> > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > code being modified. My worry is that Joe Developer is eager to get their
> > first patch into the kernel, so runs this tool and starts spamming
> > maintainers with these things to the point that they start ignoring KCSAN
> > reports altogether because of the time they take up.
> >
> > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > to have a comment describing the racy access, a bit like we do for memory
> > barriers. Another possibility would be to use atomic_t more widely if
> > there is genuine concurrency involved.
> >
>
> About READ_ONCE() and WRITE_ONCE(), we will probably need
>
> ADD_ONCE(var, value)  for arches that can implement the RMW in a single instruction.
>
> WRITE_ONCE(var, var + value) does not look pretty, and increases register pressure.

FWIW modern compilers can handle this if we tell them what we are trying to do:

void foo(int *p, int x)
{
    x += __atomic_load_n(p, __ATOMIC_RELAXED);
    __atomic_store_n(p, x, __ATOMIC_RELAXED);
}

$ clang test.c -c -O2 && objdump -d test.o

0000000000000000 <foo>:
   0: 01 37                add    %esi,(%rdi)
   2: c3                    retq

We can have syntactic sugar on top of this of course.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbdPKQDGag1rZG6mCj2EKwEsgWdMuHZq_um2KuWOrog6Q%40mail.gmail.com.
