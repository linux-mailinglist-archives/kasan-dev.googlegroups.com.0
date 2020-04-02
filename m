Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBAWWTD2AKGQEXZ4R7BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id E461C19C88C
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 20:12:18 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id n15sf3408493edq.6
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 11:12:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585851138; cv=pass;
        d=google.com; s=arc-20160816;
        b=rPCqv6eu4B7JUUb69zm6CNSw9BRgQ5z0I2zoVwF738/TdC9Pb8ZqJKZLmZ4EPrCPQh
         vbbymhsWua7wLYxXroTFmme9Mh2ha6YoHxewDAT5F4XBnElIkSEbx1/keA3E6t+Gr1e+
         j4GgB3ykHEhOoBd6qum7DdwLmR2AN/zETY16GzhDq6mKeQOkc9dzwVHBYtxTUNAP5h6/
         ISQnimzoQDwOJyyVD64O8H6Fgu0tDatRB6kI7dM+9XE2RgxWUNtAuIX5WR/7y4y9JYeA
         Z70eoE0jbhtqElcRYqTG5cHbhEDq1tDqQ7p6mt5TrLAMDnTAVsalTRRzdYDUFacNn8YQ
         saAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4b9mEtSBkOowuBEIxV4GGdgPwl79kJ/tNAigsFjKKuo=;
        b=ZQbY5twc+r36TiA4RPQaSk+rJ6slHcZaKgQjyIbjU4DxCjDAs548eXDo4lFeSIFfRY
         9IcMjAtljreQvk6VjX7UUZzcKjCPGUnhvbhCcfXjUxA955ojYdPfDGwj37y5Oj9mIobc
         t/kthVZu/taL1n4Q1CDRaGL+VIFweEX/x2/qInc/g0NTs6ClAap8Q5omgedSIpoOf/T9
         7/zqNQNTg6vKPY2MY9RNgbQhi40spRfweXCuSxTxrjAT/0JGpZZqF0l1cLie/qObbd/p
         fwXdJbOnEn7vYSg9SL9TbBXJuv5KAyg5nRAZe0Wjf6EawXDWHkr6KfbGOUNKUfUfkfx9
         wLuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=hvEITigZ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4b9mEtSBkOowuBEIxV4GGdgPwl79kJ/tNAigsFjKKuo=;
        b=NOH0VnlGe2Ba6fILMz67e+slqMIQUwdLA0DbrNCPln7BWasQ6Y2cT7KsVf6w2dBgy4
         hXaLakAQDQPO9DyTVXIHy0SxT/iwpu6pO6wTVFrgImO48PXDN9ZvKrpN3VV09C1E3FIh
         XUvGq7ZHR3c0Z+DhfbcvfVLBUazxoP9NPsGNTujQn9MzIJIMgZucwl3+bxBBo+fghW4m
         JEVf8lPfYYphyAqnq38TFvnZEGFfQANZfirrD+RFyeCCaTw9+D0Bp0xaCgqWY967Hugd
         VrJ47tpI8gJdcU8LiUn2/sR0WwuEabNbJFcXYmoRqeyIoaVYV07ttkwocefvf2H+0t4H
         DxWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4b9mEtSBkOowuBEIxV4GGdgPwl79kJ/tNAigsFjKKuo=;
        b=uJq7jTuCufzFSrBLnlNSQVNM8Fhz5jd7F+WBl8J0qaqRYLoa+bYYZwazzM6dbHedGr
         jzB4omRTILpHGMeSCpka3DsXyuSIUJ8c+zKdNOsxEu9WkOH2REy+5wawcLuOodGpO6Fg
         9UaDUl+EiUGXWwv/2SY/Q85kKCA6KBe6varIEUolWwFpYYkyiNzHltgKTB0tISkUVHxz
         Vwn6noqjS6s/BKdoXcAMlUItv3WRN+s3ENHXnTNu3zs4tABUBilzE5bEg7/8TzWJB0G1
         3LSh4hpz4HgcRAEKE9wkDQi4IGxkoEuXuMFiTqcRvsHRh61OELRM3fOhoT0EEOCTiDNC
         GN1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYkZm5+FzVNZcSepDnnG4A1p3VHGpOs0foBYKIVxKuucRNR6uMg
	G3zPeglM7IUrYqm5K9qZk4k=
X-Google-Smtp-Source: APiQypKD7fW3yHskqxNU3VgGSZyp1gi8p52hgfIYcnZSNMzhYYLUTCQcPvroKIEbXmiNw230uSVKIw==
X-Received: by 2002:a17:906:28cf:: with SMTP id p15mr4621798ejd.202.1585851138676;
        Thu, 02 Apr 2020 11:12:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8ad5:: with SMTP id k21ls2205163edk.0.gmail; Thu, 02 Apr
 2020 11:12:17 -0700 (PDT)
X-Received: by 2002:a50:d614:: with SMTP id x20mr4392471edi.186.1585851137766;
        Thu, 02 Apr 2020 11:12:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585851137; cv=none;
        d=google.com; s=arc-20160816;
        b=F6ceYdiGt/3dX44EfgA0+8pWmKgyIu5CGTwi6MQu0ArVwuqHTRFbZ6LU2ypv1Cf9DV
         kVQAgMKsJWQeG/DzWL5CZ7fF/ScBZ6DltgobezE0HXoxlg9jOGoU5xF+Kc5Xe2cpIMeF
         wyryMa5FTkRQ1QeXnKo3VPKz80X1cWVyw8bZp+rg9jCkJTloNzZ+U1Y6DrMalC2Pt9qa
         /rCqaODKrqKB3YP+jjF/Rg+9to06j31T5FUUjivBf7864N3MONpsVE/9jNqRm5yUAJlW
         YylFe+e8IvDjCxeIsCpgcwXrpoq2ayMAkNWXy+BSo6hzDWbieJO8eMYmUzHimaiwFm2Q
         boUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RlBOg0dum66ebZmfIZrWlU1IBkKC8efn4oYc6hOU1L0=;
        b=ShuRJW34h9POWJAkCcply02AewLIHYUHsvlIUQvMqnQzp8jzkYPdTx+GRV5JIIzJup
         FjudWXO9MguLxUffVQF3MK6JCI2KPSq8fzxUk3hL8uiALGtoLSkgIMZbpF+osdhJbuBE
         2fHou24EuqbNlUn8ozZs0UuqJ6cPXAt85myWP/Zi9O/aal+hz55bpbCw8wTAIcHr2LYy
         8UUBF7b4w/71C9WbX+1GBghdf9wDMn7OeX5l8sb07SJefSqEuhh7mcK+6DW3VUkgx9kx
         lclgdQwcpLzbVMsOwWpKeRgO3n/LtKb+TuioE2Na2p/7FPzPQnYHlyCXdnL5NlBYiadl
         Eo7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=hvEITigZ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id c21si286333edj.0.2020.04.02.11.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 11:12:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id a43so5496338edf.6
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 11:12:17 -0700 (PDT)
X-Received: by 2002:a50:c004:: with SMTP id r4mr4020066edb.110.1585851137117;
        Thu, 02 Apr 2020 11:12:17 -0700 (PDT)
Received: from mail-ed1-f49.google.com (mail-ed1-f49.google.com. [209.85.208.49])
        by smtp.gmail.com with ESMTPSA id m3sm1195451ejj.22.2020.04.02.11.12.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 11:12:16 -0700 (PDT)
Received: by mail-ed1-f49.google.com with SMTP id o1so5543045edv.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 11:12:16 -0700 (PDT)
X-Received: by 2002:a2e:8652:: with SMTP id i18mr2793744ljj.265.1585850802219;
 Thu, 02 Apr 2020 11:06:42 -0700 (PDT)
MIME-Version: 1.0
References: <20200324215049.GA3710@pi3.com.pl> <202003291528.730A329@keescook>
 <87zhbvlyq7.fsf_-_@x220.int.ebiederm.org> <CAG48ez3nYr7dj340Rk5-QbzhsFq0JTKPf2MvVJ1-oi1Zug1ftQ@mail.gmail.com>
 <CAHk-=wjz0LEi68oGJSQzZ--3JTFF+dX2yDaXDRKUpYxtBB=Zfw@mail.gmail.com>
 <CAHk-=wgM3qZeChs_1yFt8p8ye1pOaM_cX57BZ_0+qdEPcAiaCQ@mail.gmail.com>
 <CAG48ez1f82re_V=DzQuRHpy7wOWs1iixrah4GYYxngF1v-moZw@mail.gmail.com>
 <CAHk-=whks0iE1f=Ka0_vo2PYg774P7FA8Y30YrOdUBGRH-ch9A@mail.gmail.com> <877dyym3r0.fsf@x220.int.ebiederm.org>
In-Reply-To: <877dyym3r0.fsf@x220.int.ebiederm.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 2 Apr 2020 11:06:02 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiOS4Fi2tsXQrvLOiW69g4HiJYsqL6RPeTd14b4+2-Ykg@mail.gmail.com>
Message-ID: <CAHk-=wiOS4Fi2tsXQrvLOiW69g4HiJYsqL6RPeTd14b4+2-Ykg@mail.gmail.com>
Subject: Re: [PATCH] signal: Extend exec_id to 64bits
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Jann Horn <jannh@google.com>, Alan Stern <stern@rowland.harvard.edu>, 
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
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=hvEITigZ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Apr 2, 2020 at 6:14 AM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Linus Torvalds <torvalds@linux-foundation.org> writes:
>
> > tasklist_lock is aboue the hottest lock there is in all of the kernel.
>
> Do you know code paths you see tasklist_lock being hot?

It's generally not bad enough to show up on single-socket machines.

But the problem with tasklist_lock is that it's one of our remaining
completely global locks. So it scales like sh*t in some circumstances.

On single-socket machines, most of the truly nasty hot paths aren't a
huge problem, because they tend to be mostly readers. So you get the
cacheline bounce, but you don't (usually) get much busy looping. The
cacheline bounce is "almost free" on a single socket.

But because it's one of those completely global locks, on big
multi-socket machines people have reported it as a problem forever.
Even just readers can cause problems (because of the cacheline
bouncing even when you just do the reader increment), but you also end
up having more issues with writers scaling badly.

Don't get me wrong - you can get bad scaling on other locks too, even
when they aren't really global - we had that with just the reference
counter increment for the user signal accounting, after all. Neither
of the reference counts were actually global, but they were just
effectively single counters under that particular load (ie the count
was per-user, but the load ran as a single user).

The reason tasklist_lock probably doesn't come up very much is that
it's _always_ been expensive. It has also caused some fundamental
issues (I think it's the main reason we have that rule that
reader-writer locks are unfair to readers, because we have readers
from interrupt context too, but can't afford to make normal readers
disable interrupts).

A lot of the tasklist lock readers end up looping quite a bit inside
the lock (looping over threads etc), which is why it can then be a big
deal when the rare reader shows up.

We've improved a _lot_ of those loops. That has definitely helped for
the common cases. But we've never been able to really fix the lock
itself.

                 Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiOS4Fi2tsXQrvLOiW69g4HiJYsqL6RPeTd14b4%2B2-Ykg%40mail.gmail.com.
