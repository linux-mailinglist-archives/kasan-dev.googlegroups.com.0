Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBDEDSX2AKGQEBJPPWKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8148A19B9F5
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 03:36:12 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id b12sf1467626edy.7
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 18:36:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585791372; cv=pass;
        d=google.com; s=arc-20160816;
        b=LNM/+AbXCaQsT4WipCyAVIetcqXVq6m5APwbvQXecM9MstW01NqC06llzvxi40ANzN
         L5LjlpPY4gzKJ3encYZv6IU6/owsqUv9z27MZr+lOnYy8oI1yrnM11Bj9k6ZFSrgJI8A
         b31gXKX7pk7gjWUjoltLHZmus83m7yQ6YlyxTP6lHGm61C/xp3rhLyBbpLZd5Y4anQ7l
         ZLMc5b9CNVZx7+Xe5rRttN906wnYDycgP/CbU2XFk8P+4Q7d6uUsKc+BwNW7e+nJFJvb
         XqNYVuWg9peEEUq2SHXxJo5Qx2Yxq3Mc+S+MrGoMx2+L0+iwAfBzrssmbRUlUj2d59+r
         k/mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9fz/G5Jdz+Tc3dfnInce+66Kk4B4GVxe1iwGHHa6DZo=;
        b=EVrGmDjwKApB+2G/QVVRdfedWZs764dcG4nkDoIMClizW7WE4AR98GSpLW8/MCffAZ
         pNO7HzFbVuZdCvWLK97H3vyPT7kwId83L2PCIvroDDwJlLdrkHpRISdXq+UZE7Hl1Ybe
         wr55sQoiukY7GtIxho3HydHHQD7fVKePFPROVG/VseCK8jhWrdFX7oZR1ZjkUPBn1QA0
         Kq4ir4bC1tcPofs9SKxY7aZURn4rSXgAR/xdeVh+jXUxBXhiOTVG+2vGoMKRLjXcIOs5
         uSfzKDMMrPEKJDpNUCDgqYe0QGN6iTnZf25GCaMuKnabwJ5HgWv7wiHhlz9LjX+opA3O
         n2Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Iy/+QP+K";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9fz/G5Jdz+Tc3dfnInce+66Kk4B4GVxe1iwGHHa6DZo=;
        b=iZtyw5my/G2jJPXJzijTkQWXqIDij9Qq27gZDxfgJLIQIxvdrEi1L8VJDcdMLSGY4l
         6xajxHW9WtW1bZkMIufnyoUm0Al1SHAal19pTtod0qFbaymBUF0F4IHRySNhW3MQPQkx
         RnQFW3mRJfsnd+N+GLHYuE55aaaPNz6O8lOj9w9+bV66MPB444cwaorr3/Yqt15OpZtN
         hiE/aTEp64xfYQbsw5yg45+SCaI1CJrRWR2rJRLRFThO4iT7qF6eGg+jk6C6T6Xznfru
         Ig1cJmUuiWW6tCTGfD32vni3sIQ39ZXCan7AiAYSFSJkhpdCmPVvVVojlFP9TFQY7CYS
         Ih/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9fz/G5Jdz+Tc3dfnInce+66Kk4B4GVxe1iwGHHa6DZo=;
        b=LwCcuxXApm7OWD0eFaNHQ1ayrl/gDIuIExFrU79tj0WuSJ5dkT+3mQMR3nBKKdIQtt
         K/jcvFl7GGlO9/rh4H310Wcikww29vrN/KI/ja42Gc0aCzmtXiXrirDhzKV2qsI0nfES
         JulMno9tmYCZBHMQQ4OuHmQyIrkW5mf3xuFVvN0MILpb0Nrcs7fv2tgrJRvCY7yKP6Am
         07I33CSSE4DrnWmO5ou+7pFvM8yqC3MSuZBHaP1GhTG8T82ctMRywdt9llBJfNttlslv
         Tbz5VzBwS2RF2XJl5GKo/sSYBKXZ8ChA4EZxLeiW4XEjjtni6+7T7BCMZ0ETgw7IHsyb
         YdVQ==
X-Gm-Message-State: AGi0PuY3zIIkGhrorsiIddQf0A5SEaS+F4zNP0Z1ijr+6bfjqWKDLp1a
	OZ0wdDASMC047ksrya/hUiU=
X-Google-Smtp-Source: APiQypINOxanguIAA7+ia8AALNlrTmyUQxk2n1jjXogDYnkMGbHPdLjXiXbBELkw1ZXwb8Oj7y4wcg==
X-Received: by 2002:a17:906:455:: with SMTP id e21mr948910eja.128.1585791372277;
        Wed, 01 Apr 2020 18:36:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:aad0:: with SMTP id kt16ls770719ejb.2.gmail; Wed, 01
 Apr 2020 18:36:11 -0700 (PDT)
X-Received: by 2002:a17:906:a391:: with SMTP id k17mr940865ejz.25.1585791371787;
        Wed, 01 Apr 2020 18:36:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585791371; cv=none;
        d=google.com; s=arc-20160816;
        b=CrPyKx7tMLhol03MdLVBcfXVJoJfIxUjZy1/Dmxpeqer0O1D12fvZeAKcoY0OCln7G
         +g07wN+WD93dNzbn7MU/d4EnGXu2jqC50OfgENMmGd96LV5jFPzohfpBq8SlO+2WG4vv
         o7DUxE9BvUJ2RjsTfDoJUz3hv5j2ujYsGY+XJAYWVnF36H1xRZL7xxK/tA7DIJoM89+Y
         UWPHdqo1SyxyaC0gH/tPK/XQy6bL3mjARE/yU+ejbFt+HCk7AJnwuDncKGksrhuVlm3Z
         4i17LqXuSSLCMNoD99zWdFCN8RAApj0WcXNCVK84nNnFBQZhg9GCvKksPqWuzJjARM9Z
         8JiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p4NjOGhfdlS01zHiaiGfeK4n/oNGr20mOQ6J0VtQZkU=;
        b=NXRRPmBVsGN3zXpjEdorTtjiTxr129EsJ/z90prNzK/ncmxtVBVhezqgD2qyjHzkRa
         i0u198L8VBl7hpebpC9HLTSUY5HJd0suZvtaCnI6IyL4MkoNF2vyMr0DktiatvVGuqKH
         G1dsudbWP68NxsV8cne0ikMedoxT2WA48r/7xYMQyvKBDH+X54CXO2JcduCiX38iUGTT
         L2qTr7Uf4W+wEPPdoIoRNagez8wS6tzwWKrY3C19V252WJg+G6KG2FR9BSR+Og+3dk/o
         a9Cg2vErZgUZyNm1Y1mh34nXUfQ5aOLBp5SCRHOboAZzKgcRvYKKZdo88J5QbEqjgPlt
         f0mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Iy/+QP+K";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id j9si271099ejx.0.2020.04.01.18.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 18:36:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id z23so1362974lfh.8
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 18:36:11 -0700 (PDT)
X-Received: by 2002:a05:6512:3127:: with SMTP id p7mr583281lfd.108.1585791371001;
 Wed, 01 Apr 2020 18:36:11 -0700 (PDT)
MIME-Version: 1.0
References: <20200324215049.GA3710@pi3.com.pl> <202003291528.730A329@keescook>
 <87zhbvlyq7.fsf_-_@x220.int.ebiederm.org> <CAG48ez3nYr7dj340Rk5-QbzhsFq0JTKPf2MvVJ1-oi1Zug1ftQ@mail.gmail.com>
 <CAHk-=wjz0LEi68oGJSQzZ--3JTFF+dX2yDaXDRKUpYxtBB=Zfw@mail.gmail.com> <CAHk-=wgM3qZeChs_1yFt8p8ye1pOaM_cX57BZ_0+qdEPcAiaCQ@mail.gmail.com>
In-Reply-To: <CAHk-=wgM3qZeChs_1yFt8p8ye1pOaM_cX57BZ_0+qdEPcAiaCQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Apr 2020 03:35:44 +0200
Message-ID: <CAG48ez1f82re_V=DzQuRHpy7wOWs1iixrah4GYYxngF1v-moZw@mail.gmail.com>
Subject: Re: [PATCH] signal: Extend exec_id to 64bits
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: "Eric W. Biederman" <ebiederm@xmission.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Andrea Parri <parri.andrea@gmail.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Nicholas Piggin <npiggin@gmail.com>, David Howells <dhowells@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Akira Yokosawa <akiyks@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Adam Zabrocki <pi3@pi3.com.pl>, 
	kernel list <linux-kernel@vger.kernel.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, Oleg Nesterov <oleg@redhat.com>, 
	Andy Lutomirski <luto@amacapital.net>, Bernd Edlinger <bernd.edlinger@hotmail.de>, 
	Kees Cook <keescook@chromium.org>, Andrew Morton <akpm@linux-foundation.org>, 
	stable <stable@vger.kernel.org>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Iy/+QP+K";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Apr 2, 2020 at 1:55 AM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
> On Wed, Apr 1, 2020 at 4:51 PM Linus Torvalds
> <torvalds@linux-foundation.org> wrote:
> >
> > It's literally testing a sequence counter for equality. If you get
> > tearing in the high bits on the write (or the read), you'd still need
> > to have the low bits turn around 4G times to get a matching value.
>
> Put another way: first you'd have to work however many weeks to do 4
> billion execve() calls, and then you need to hit basically a
> single-instruction race to take advantage of it.
>
> Good luck with that. If you have that kind of God-like capability,
> whoever you're attacking stands no chance in the first place.

I'm not really worried about someone being able to hit this in
practice, especially given that the only thing it lets you do is send
signals; I just think that the code is wrong in principle, and that we
should avoid having "technically wrong, but works in practice" code in
the kernel.

This kind of intentional race might also trip up testing tools like
the upcoming KCSAN instrumentation, unless it is specifically
annotated as an intentionally racing instruction. (For now, KCSAN is
64-bit only, so it won't actually be able to detect this though; and
the current KCSAN development branch actually incorrectly considers
WRITE_ONCE() to always be atomic; but still, in principle it's the
kind of issue KCSAN is supposed to detect, I think.)

But even without KCSAN, if we have tearing stores racing with loads, I
think that we ought to *at least* have a comment noting that we're
intentionally doing that so that people don't copy this kind of code
to a place where the high bits change more frequently and correctness
matters more.

Since the read is already protected by the tasklist_lock, an
alternative might be to let the execve path also take that lock to
protect the sequence number update, given that execve is not a
particularly hot path. Or we could hand-code the equality check and
increment operations to be properly race-free.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1f82re_V%3DDzQuRHpy7wOWs1iixrah4GYYxngF1v-moZw%40mail.gmail.com.
