Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRVVY7WQKGQECSJEYLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CA9EE395D
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 19:09:27 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id u131sf18778573ywa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 10:09:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571936966; cv=pass;
        d=google.com; s=arc-20160816;
        b=A703vDSxIAVM2WaMc2TlGFNn4PhbolSc4w/33qHJmXteVHEe81deH6IW3l27CkRLc2
         pUhQ6nrQ+hwrgVMdomvK55ZnL8DRIWBzxk+JX+45Y95C/CPvxxkMjA3NsKaqMjI8+v+4
         XwBR6a8iZ2BkWD4qTfADPVlhFiIq0/1Bgnx1ycjW/8tlow1pkW24oCAZpYcH6ecdKJaq
         D0WD09yfeeov5f4pJTAPzTJSnrQyFjQG1hGbTw1IaHxaOhiRro8cMOy+NPnWKKNrKkz2
         H2JwaAcWXmFBY1tjtIYgghkHytGXH7Z2tzmS9ztkclvTA/E2itAWwROz5du6lAw5LP0e
         Q9ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s25pUYdAuvc75ll98vlDHBRtIO425a95GSppQbXHfrM=;
        b=Efdcl5cv9WLimLw6UQkhUCrWhVAn91mVa86lq5J2IGyAO7BxwqsEvaeM7U2VMGgJLJ
         WnFIppXgywSNCcYh1mk8FoLSTUsSZmabqC/BWeoWl1ZxXkev7/h8X0R44FRPGhSYt658
         YLn0nptKmJCm3Amazv9iyXHf3vpWM9r6ViX+gryo8Gi+fuGozjQJzUdCwfGwmEsg3Z5D
         qzAWOoUPbJbh5T33hwlfIVRbDRvCAtGUO9UZ+WDr9oJD6bXMylChjWN9PzPvW6B1e3kN
         Sknlj1+ZmJ58I32KHm1/WN49MOqNbJQ0ESZ+Bp44gh/qQ2lvLJOSOruBPP4UmUUYQ0ZE
         95Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NDkinmJa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s25pUYdAuvc75ll98vlDHBRtIO425a95GSppQbXHfrM=;
        b=hsGCjN52/lesSStXf/36EA3NwUatP6Hk/8h9nSFdomBVEUk5XdqChSwoM9jCCyw/pY
         dLyoogGl1X5/AVazxIRFKUYLfh9G1OzPdCv47H+ipcgSAJi6hzPHIdh1ewkUwPiU5hA5
         VF5K8t0ZhOZEvg4DB0ad53FG5+i3AK5pQ88F8SPptPNgNbtPSXPVft8tcU3U2qlV71JH
         01J/RKqj/DBSo8YH42TI265j1GLHKpSAphdHGqFir9BzKPvmJjPk7P8JMgTF4cQau4Be
         ONGk68hFTHBAv+jkUKHRiiEQvdx/pxFamg6JxeoLcbEqFtCvPnUi/pebN7W4w99BMTlw
         Hqig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s25pUYdAuvc75ll98vlDHBRtIO425a95GSppQbXHfrM=;
        b=HLDeF6Zdzhddt5TI6UbSjp2WIByJp5TXRl4s7ZKTrnnl3qwbDL6UcOWY7ep0vWrK+u
         JciOXa4VB1mhRW0AC7bUwR2Mr+jmEI8KZKYnlagsWZX7NPoy4N6pwmoUfY/cz5+XQox1
         jgVcygq+E7wcLAS9A1vFiPPQ4Okhn+fj8VtFx6n32/2hVhhm9LoR3OPx9lgjhOu8WpKR
         gD3E0UK1T8PgjH1ast/LYzdXXZJbAVT4CAVdtrdT2i8Yhj7XH0kieZI2YFweAo0mc8MP
         Oje+oIQLxqA5LiLoiG1QJ1G7uNwhtfphuKLOTGDiGDA6/36O6nJj9pzjp+x0s3NGTJ4z
         97xQ==
X-Gm-Message-State: APjAAAXzYVFWAsf2u12giOoNriOQefxAsqiuu7v6wsoPQswqnFOUzw2T
	ztoxWBt7UXmWm2ihl+7Ka9w=
X-Google-Smtp-Source: APXvYqzTJU0/hmkoyIdSpO/370sDuR9v/4KDzbA2jnupunCSAA2sTmVSH68FbTcrpZF2scelKaDnUA==
X-Received: by 2002:a25:58d5:: with SMTP id m204mr11218473ybb.325.1571936966447;
        Thu, 24 Oct 2019 10:09:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9788:: with SMTP id i8ls1056494ybo.7.gmail; Thu, 24 Oct
 2019 10:09:26 -0700 (PDT)
X-Received: by 2002:a5b:c44:: with SMTP id d4mr11843620ybr.206.1571936966023;
        Thu, 24 Oct 2019 10:09:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571936966; cv=none;
        d=google.com; s=arc-20160816;
        b=f2fyKpLsxjmz8VF88r/XiGK3UU5DHWZI43wMu8t8osGZ18aWCfbYOw7FD/Rw6lCtp7
         FApECMdJKZA/xZ1RcAetBt8uhABo+vJdNJCum1gDtMK0OIR2RYM4RtbCDIBx5uk1TdIE
         17eNF8vnNGlkGM+YqDeR1eU8bahcrb2zDQQMOZSWbMI+NYFyNJtYbbeel6fynYS2/OGc
         PPtgsX2mz6R53cTu1qK7Md9cOAnpXC33xt9pW0XDx0x+Zo/QgkHHyF6w1oVsIc3fLSwe
         ssoZ180f7oSpxCnNWRqhd8wLqtakWjK2vlwaVRJy2D+b+vidD6JkWFB8FAc8p0s0LRtm
         L2rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LW4UeTeDzuNPqIV02zMQFN/K1Ur44NII9oOTDJRv/K0=;
        b=qWsbxJvd4WP71zfeftSu/dEiQDAdxM8wOa6XHJnMmJHFDWtOAZEzPVfq0/yildeKy4
         baC4+Gu+/uhRgQJtMKZwnyxuwjR0Y1jX0xvYciTbpLLLuHQysAxWt5YzRESwgZXhOK8o
         5N8Wnc2YNt7vTebSnIHzY5nDVCtewO3WSXQGFTlcwH2ZCw1kT617xFJStddYAxVOBOc5
         NbzYfYaN5miF+WN+Cdr9GoBBihjYYm2dkG7d9X8hreOmkzKNLOfLZQaY/lX4NtuswMTS
         joWa6IqllBWIkZ5yZRNGAMB419UcI7Nn1ml6qsxzFzpPWnaRQVENcYaPuAlJqWlcSBCu
         w7rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NDkinmJa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id r9si1682727ybc.0.2019.10.24.10.09.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Oct 2019 10:09:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id c7so10565426otm.3
        for <kasan-dev@googlegroups.com>; Thu, 24 Oct 2019 10:09:25 -0700 (PDT)
X-Received: by 2002:a05:6830:1693:: with SMTP id k19mr12897876otr.233.1571936964760;
 Thu, 24 Oct 2019 10:09:24 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-5-elver@google.com>
 <20191024122801.GD4300@lakrids.cambridge.arm.com> <CANpmjNPFkqOSEcEP475-NeeJnY5pZ44m+bEhtOs8E_xkRKr-TQ@mail.gmail.com>
 <20191024163545.GI4300@lakrids.cambridge.arm.com>
In-Reply-To: <20191024163545.GI4300@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Oct 2019 19:09:12 +0200
Message-ID: <CANpmjNOg8wK71_PnQ03UhsY0H212bXWj+4keT0dDK18F4UNPHw@mail.gmail.com>
Subject: Re: [PATCH v2 4/8] seqlock, kcsan: Add annotations for KCSAN
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NDkinmJa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Thu, 24 Oct 2019 at 18:35, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Thu, Oct 24, 2019 at 04:17:11PM +0200, Marco Elver wrote:
> > On Thu, 24 Oct 2019 at 14:28, Mark Rutland <mark.rutland@arm.com> wrote:
> > >
> > > On Thu, Oct 17, 2019 at 04:13:01PM +0200, Marco Elver wrote:
> > > > Since seqlocks in the Linux kernel do not require the use of marked
> > > > atomic accesses in critical sections, we teach KCSAN to assume such
> > > > accesses are atomic. KCSAN currently also pretends that writes to
> > > > `sequence` are atomic, although currently plain writes are used (their
> > > > corresponding reads are READ_ONCE).
> > > >
> > > > Further, to avoid false positives in the absence of clear ending of a
> > > > seqlock reader critical section (only when using the raw interface),
> > > > KCSAN assumes a fixed number of accesses after start of a seqlock
> > > > critical section are atomic.
> > >
> > > Do we have many examples where there's not a clear end to a seqlock
> > > sequence? Or are there just a handful?
> > >
> > > If there aren't that many, I wonder if we can make it mandatory to have
> > > an explicit end, or to add some helper for those patterns so that we can
> > > reliably hook them.
> >
> > In an ideal world, all usage of seqlocks would be via seqlock_t, which
> > follows a somewhat saner usage, where we already do normal begin/end
> > markings -- with subtle exception to readers needing to be flat atomic
> > regions, e.g. because usage like this:
> > - fs/namespace.c:__legitimize_mnt - unbalanced read_seqretry
> > - fs/dcache.c:d_walk - unbalanced need_seqretry
> >
> > But anything directly accessing seqcount_t seems to be unpredictable.
> > Filtering for usage of read_seqcount_retry not following 'do { .. }
> > while (read_seqcount_retry(..));' (although even the ones in while
> > loops aren't necessarily predictable):
> >
> > $ git grep 'read_seqcount_retry' | grep -Ev 'seqlock.h|Doc|\* ' | grep
> > -v 'while ('
> > => about 1/3 of the total read_seqcount_retry usage.
> >
> > Just looking at fs/namei.c, I would conclude that it'd be a pretty
> > daunting task to prescribe and migrate to an interface that forces
> > clear begin/end.
> >
> > Which is why I concluded that for now, it is probably better to make
> > KCSAN play well with the existing code.
>
> Thanks for the detailed explanation, it's very helpful.
>
> That all sounds reasonable to me -- could you fold some of that into the
> commit message?

Thanks, will do. (I hope to have v3 ready by some time next week.)

-- Marco

> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOg8wK71_PnQ03UhsY0H212bXWj%2B4keT0dDK18F4UNPHw%40mail.gmail.com.
