Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNF333AKGQEZH7K4YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B0441ECF70
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 14:09:11 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id j16sf1422732qka.11
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 05:09:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591186150; cv=pass;
        d=google.com; s=arc-20160816;
        b=s+JMxPyhh49FKmqMVaFBlEysHlsUfDMUdX8HAni0z2FiXTJF3AWXCwJ9eDM7SFwSog
         G2X0Q8Q+adWhDJrEMcg2NZrTR0Dvm3V9qLAxYaIYpQKUGKiyCQ/29MSaHlnL3DEo3ikX
         je+Z+NrdpsjO9Xb9qttp4qMwkdguX9DwxTYKQ0H8hdy6vs5Fwuiloof5/M9EmDSTmwul
         hc4rwdb9L08dThDPKvJzhVJooYQ/9Kt4w75OWgq9RMliRYpnzM/RlDcMr6faxGPCG997
         kuDjKa54MddGZ6bPDYwamgqmik8FooRf/sdtv3DYVoLA98NrOk0VTqulTEIbXBmUSaVL
         Vgfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DpEERN/S9/nqaFHEqwckihuQmZ9s4p95lNrmw2s5Yto=;
        b=uw22DCAKeWXBgzVNSnoJ5y9syfUPCny5I7mX3m+z7RjYPbFd5hbYRjog914pg4ZLNk
         GeFa7zGRHQ/phY0LMZFm0GKOo6vg3He6dNILYMBmOwfqFpFOYqW4bKxaGiFhOWttu1CH
         zx6M8yAxo/nSy2967gs/45bxEeokdy/yiAGMQEF9FPkoU3d59NwUFaYxlI6fLkJQDVGw
         k1ysiVtS57RITih6Ai+Lk0MRq53Kn+Js7HEnRmCyTdw8DADNrgqBNHdIo74jyxsFankj
         i4bXybfWdG0WbptZdFfXn4cpTgDpFFYnkvTpFrDr/wW/LM7IIgekib78nYCV9/Bll5Yb
         gblA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G1QU3vuR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DpEERN/S9/nqaFHEqwckihuQmZ9s4p95lNrmw2s5Yto=;
        b=hY1LOS9AULS5srbEGSS/Ske3skVaF5wnltQUUf/ZJJVvXYjLoNc+n9bPrL23ehLDI6
         LoSavHStR6FoN8KQ+/8E0udTiGHEc5uw3wQ4V+8pqMnRX7jDCo+K0WoJCmGWAcDz3t//
         q0JPshQJnOqcQgHDPukHoCvoFE5dgQdS1Q+0C46da99aKrsoaIj1FaNz7jkWw8rPW1pu
         /B9VJ9eAYltOPINQ4BITSuHXI+7ivl/WS+nLqImlDf+Av4thincbg3rKn/lAI4vmoyq1
         LJ5aszxS5IofkQhCqt+Hc5fExoygCyZz07EUMVy7odmWz0yzZB8+lvfqHOAWuWfSBybu
         gXqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DpEERN/S9/nqaFHEqwckihuQmZ9s4p95lNrmw2s5Yto=;
        b=E8bCc4HTwJfDGBl+qpTznt32TInVCnQqK4b8RTJYTQRtXG4b1ztkx8FmDcpyYkBzYg
         ZXyfwyqoC0/WsjJrESvmYAX+WmCMpwzvfxovpvqtoroOjEK048kf4thJ9e0Sma/4DXLE
         xoKTHnnNYqU4FNPLh8L0sUL1JqpZBodXjC9MbavBD8jntgj7Ln/+cL3iUAtucx71mN24
         aWbDs/qpMOsxz68Ckolzb5AW7BjURHIKupASSTqfHxjm96k4zJ4BMuwW4NldxsRSkOY8
         g25fy5xyvqvZBP4yfvllyvIWKen+EkHTq37ITpdtgAGZsBD7//akIrJXExYfUpM/iIBV
         eckg==
X-Gm-Message-State: AOAM531ECDvETutNHuFnQ2aPLp2NQNsmVlMyU4iJPj9bTPk/mJnYIiXs
	0vk1HhCgbMqhn0rTbOKTkV4=
X-Google-Smtp-Source: ABdhPJydy5xflQdRMru2NpqAog0M6cGEzAWOEOJb6RwsVFWZtbpR2Z5wkMJKIw8+s2/Fnpx3/XVZFA==
X-Received: by 2002:aed:26c2:: with SMTP id q60mr1059502qtd.206.1591186149928;
        Wed, 03 Jun 2020 05:09:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ac7:: with SMTP id 190ls861129qkk.0.gmail; Wed, 03 Jun
 2020 05:09:09 -0700 (PDT)
X-Received: by 2002:a37:48c8:: with SMTP id v191mr30652866qka.268.1591186149569;
        Wed, 03 Jun 2020 05:09:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591186149; cv=none;
        d=google.com; s=arc-20160816;
        b=akenDTVor/tRDpoQ5/41/zGEP35DcIdeqzgH5ahMMk+OBKjea2DklPYAFHZa8gGiVd
         oNGFn49Z+jIW+wiS+qMeL+VZ9FeHDLN1FTk5imzECRV+3f7uMLHH4BcUoiI0cVcpX7G9
         qKvLwq3GqQgq5evCwonFDR9tZC9Iu4NOBJvdZnNyzXGtlhUARycGQ7oJxOjwpdq20x2z
         SPWzSPTz2jmrsQHz0g+gZVrAC7uE2eY5thDzr5Jm5Sn7bD2ErC9bSYitj5Jwqlbbbu+y
         BdRavayd8JrjEjBNoWasSsZVWlKLz9tyBdij2dAAT+h8tvokKM/qTLRGUlPsQhXikMiy
         xZRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CrQWsWD5f9oeeT83eEC6g4ZTyQnFkgomgZ4RHURPls8=;
        b=kPfW5v3kH76FjCKiH+F8+8uvDpY3505oeHAJ+orHiLzqIfLa9R6T59aNnMX6ofrq1C
         JZQWyKoMGJc73OzFeTmLyMCursNFQN7nPrMjoctsKjQxzJghwtr8fCAdBNaeFKiWiaYK
         bycsGt7aRbZbsdV9PeWmA+i5VXuMroZ/1fPwWktCEKBvbTN6nMei8EiNR+FG3zUYMiNe
         WktlIocjsgFdxYZvJFxsrnVqBr+gXeE8T7Glz64umymMmMph5BLRFQ4s0o77n7imUOyr
         wag9q+jlC4uXSazPp8XAyMp71z5d/5MG2y+8h2uXQcB9h2kgDiaRPa7rIf9aslB5Jj0+
         ToZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G1QU3vuR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id v64si144120qka.5.2020.06.03.05.09.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 05:09:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b8so1592420oic.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 05:09:09 -0700 (PDT)
X-Received: by 2002:a05:6808:3ac:: with SMTP id n12mr4385422oie.172.1591186148832;
 Wed, 03 Jun 2020 05:09:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net>
In-Reply-To: <20200603120818.GC2627@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 14:08:57 +0200
Message-ID: <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G1QU3vuR;       spf=pass
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

On Wed, 3 Jun 2020 at 14:08, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jun 03, 2020 at 02:00:37PM +0200, Peter Zijlstra wrote:
> > On Wed, Jun 03, 2020 at 01:40:14PM +0200, Peter Zijlstra wrote:
> > > The first patch is a fix for x86/entry, I'm quicky runing out of brown paper bags again :/
> > >
> > > The rest goes on top of these:
> > >
> > >   https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
> > >   https://lkml.kernel.org/r/20200602184409.22142-1-elver@google.com
> > >
> > > patches from myself and Marco that enable *SAN builds. So far GCC-KASAN seen to
> > > behave quite well, I've yet to try UBSAN.
> >
> > GCC10 + UBSAN:
> >
> > vmlinux.o: warning: objtool: match_held_lock()+0x1b2: call to __ubsan_handle_type_mismatch_v1() leaves .noinstr.text section
> > vmlinux.o: warning: objtool: rcu_nmi_enter()+0x234: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
> > vmlinux.o: warning: objtool: __rcu_is_watching()+0x59: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
> >
> > All of them are marked noinstr. So I suppose UBSAN is just buggered in
> > GCC :-/
>
> CLANG11 + UBSAN:
>
> vmlinux.o: warning: objtool: exc_nmi()+0x1c3: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
> vmlinux.o: warning: objtool: poke_int3_handler()+0x72: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
> vmlinux.o: warning: objtool: mce_check_crashing_cpu()+0x71: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
> vmlinux.o: warning: objtool: lock_is_held_type()+0x95: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0xba: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x2c: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
>
> IOW, UBSAN appears to be completely hosed.

What is the .config you used? I somehow can't reproduce. I've applied
the patches on top of -tip/master.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOxLkqh%3DqpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA%40mail.gmail.com.
