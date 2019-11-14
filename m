Return-Path: <kasan-dev+bncBC7OBJGL2MHBB65OW3XAKGQEEHDZPWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id C7CE7FCCC2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:05:48 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id j134sf4729325ywb.11
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:05:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754747; cv=pass;
        d=google.com; s=arc-20160816;
        b=O5yDcHoEmL/cr2A9oCCsCtyxnbyC8GD82s0f+fkSpCuC8lVHFgbXXCir+loI8unwEj
         0N5vvw+7MwvegL2o3ni98aK4t77SGj12Ht8GK52+7P2M/FJavgXfJyWqyB4TNQrMS4Xo
         tJ94waaxnHQzbJgOC1sXneOOG3Je6sqqis153l0xEO7Qy0YM64oBIw2lo4+681je91P2
         KYdx8EZ8uiTh/jNPyCtehf6aLZFkxP/jIRLQiYWXYysYAgLLHMabRLHXecdUtGBB0Yv9
         IBb2oUe/OLHcDKvA4mhQbHeqxjBJfpaZtAD97zid3gCIahD9CLTXwPBs/IQ4B6RKq0sd
         MWUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xSPSfg4G2cAJxBOd6TT0BjR5CHpYA18Fy+zwJuO7WDs=;
        b=hIxAU4o2wW076zkyv36OJKhQgxV6hLvJqrTYSKnDc3tZDYlR54aX8ChuJsFMyz0I4D
         ksJ7JvtRJBYPTftV6QtyWhYCTUsufOzlWn3HcG5scQSLgeOzuJnP2rxQwdFZc7HEjb6r
         IDdEfK6v21nzFt6WFzNiHsxjUg/zDAj/NFG7IfC8S+Sbs7DHO2eF1IDEbIDRjN7Guwcg
         As6VnH4+NPhqeOJ0g8Innfs/nlgTWO2rGv/Vc940kE8+ChgnIiaz3PVjTiRUgJSfEOJr
         4PFsKUdCcbcqRjiUTIEmNHkDSyEBD+MLgdfaLGcCAmyC66ClTCt/J3DafZF885s1cvqs
         M5Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NxgoVXfs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xSPSfg4G2cAJxBOd6TT0BjR5CHpYA18Fy+zwJuO7WDs=;
        b=nQ5uSx2gQJ9QbZ1FnGRk9Mi/IbnxzUNi4Hnxhw1u9GLn7UY78mIBrAUYgQ/DMLB6WJ
         nOt9NysYBpjQpTomOhx+wV21z/roELSZRZ5z2vQtIeWoSo1uC2538WzS3RT6TJucG0yq
         zFPL/IT0Sv5Hu24zb/Zw0LQQXk847wbPO6eJc/UDZgtgM6VOsUee4yFxk2dRysVLpOVV
         VJ9scug38OL0WuGCL+tKCpZ/b44i7gUiiLGM8obd0/xiRaQK4OLh7dFgcOeRanjLbbXp
         kmY/bc4gUFvTSNO9rXzfUr1tphvHPxAEm5FYaBGWijqvgCCnQv927v6it5ugs6VUJIWF
         Ha4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xSPSfg4G2cAJxBOd6TT0BjR5CHpYA18Fy+zwJuO7WDs=;
        b=evolQFlhHJk+An7KlfrPbiiv5wcluea5wXmqfe0n51bwxqxAY7qnXq/Jm0DlwxLxZ2
         y4IfJVwDX/kUFvSoIPv1ltG0l4iv1H9vsC4On68D7Qfh/M6ZUv3ok8Wl03RAA4q65qvY
         NCkMKLF1Q4PTu/llP+Q3/EaLH+CvkGYhQlm+E/r2DAHKiif0HZU0xbgv8jWl9EDl8L+O
         vMf/oJ7uuyqBEZXzeF44v0mL+ga77FO+nsWkpH7mc9Reble9heL2zSdttlpsht29nz5s
         EoJdPR3zAfQTf4OXDLaPRGwxnyx58cFQc5fHy+mXaeqnuR3txP+5PqJPOk9iHJqXVyNX
         78QQ==
X-Gm-Message-State: APjAAAV9cfhULQ1YzNqXN1ej38LavsHZptEKbKd+31K28NR4dBtdVS8F
	LOatBdi5X3fBKIBOICEVgxk=
X-Google-Smtp-Source: APXvYqx5CgbafyVqAR/zCkvoSWpHjA16Ri1yrZ3kLYm7NKCXe2k009+SoMqKH8JusAbh1EWzeZkcvg==
X-Received: by 2002:a25:d84c:: with SMTP id p73mr7582465ybg.362.1573754747757;
        Thu, 14 Nov 2019 10:05:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6c89:: with SMTP id h131ls554867ybc.16.gmail; Thu, 14
 Nov 2019 10:05:47 -0800 (PST)
X-Received: by 2002:a25:4a43:: with SMTP id x64mr8286230yba.37.1573754747409;
        Thu, 14 Nov 2019 10:05:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754747; cv=none;
        d=google.com; s=arc-20160816;
        b=nsfYB53EoQsmwPlm2I3BNbBcff7Ksb4kdOv8RDr94cKWQzO+HbiR4TYbNvY/dT+P2i
         IJpNXrswXhb0w4ZI1ZJqs/Hg8QDDtIiEFTiosTXZ1nSRkZdPntw+MP5Bxl33lO3CUfWx
         MsaH00EXuDza7X8QkwPo3l6YCkwTr5Jf/2YUNVJcX32WaNNlCRLVSBxAcLZfC2dCT+Vr
         ZNOCKf5ZL2Zc0yyUt4RBpeUncYJQ50I2u/9LXIo7XqgPHjl0efW2N8dp6ITCu5XFGuMv
         e9Kb27HgojeVt+/REfd1HX6WxwwlZH+y3QhvSKnJd7Lm1KQYyHoAme8ue77nkVR2UOxE
         J5hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IlVs0WMHnCQFEwWjunTfC44Tofp8nrm/CewGUjfwrsU=;
        b=sGKm53o+c1sXLbd5oU+DSnz5jm0g80zKGurUhPJeAAFe/s9O0hjHPvvvHFBWry/Sk+
         ZErsEvHWSAGR7s5oXRGJLXN85TxqiWnsQBNcCcjheW0IlteSh5QVZhUVYTDPbsxCXQXG
         vdPPsy9dNEjjdCUKGSUGX4HNXhttHD1FH8l6ERmXwgerQLw8+fTxTFveJQwgrKGfXNU4
         jGEc19+WwJKOv7QuTsjvpnw6irJhCQUXQagl5UblOsV7tQukgbnAINDzwjfIxiWKJ11L
         fYTljIKNKaILoTbFdBPTnlgqo5XjOYATAMyYKd2XapdMP2XVYAqswt8Bk/VWUu9GF4X8
         lSdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NxgoVXfs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id g82si166931ywc.0.2019.11.14.10.05.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:05:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id n19so1863649otk.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:05:47 -0800 (PST)
X-Received: by 2002:a9d:8d2:: with SMTP id 76mr8943242otf.17.1573754746598;
 Thu, 14 Nov 2019 10:05:46 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-1-elver@google.com> <20191104164717.GE20975@paulmck-ThinkPad-P72>
 <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
 <20191104194658.GK20975@paulmck-ThinkPad-P72> <CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno+o-Fe+7OYKmPvCboQ@mail.gmail.com>
 <20191105142035.GR20975@paulmck-ThinkPad-P72> <CANpmjNPEukbQtD5BGpHdxqMvnq7Uyqr9o3QCByjCKxtPboEJtA@mail.gmail.com>
In-Reply-To: <CANpmjNPEukbQtD5BGpHdxqMvnq7Uyqr9o3QCByjCKxtPboEJtA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 19:05:34 +0100
Message-ID: <CANpmjNPTMjx4TSr+LEwV-xm8jFtATOym=h416j5rLK1V4kOYCg@mail.gmail.com>
Subject: Re: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
To: "Paul E. McKenney" <paulmck@kernel.org>
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
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NxgoVXfs;       spf=pass
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

On Tue, 5 Nov 2019 at 16:25, Marco Elver <elver@google.com> wrote:
>
> On Tue, 5 Nov 2019 at 15:20, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Tue, Nov 05, 2019 at 12:10:56PM +0100, Marco Elver wrote:
> > > On Mon, 4 Nov 2019 at 20:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Mon, Nov 04, 2019 at 07:41:30PM +0100, Marco Elver wrote:
> > > > > On Mon, 4 Nov 2019 at 17:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > >
> > > > > > On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> > > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > > KCSAN is a sampling watchpoint-based data-race detector. More details
> > > > > > > are included in Documentation/dev-tools/kcsan.rst. This patch-series
> > > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > > architectures is relatively straightforward (we are aware of
> > > > > > > experimental ARM64 and POWER support).
> > > > > > >
> > > > > > > To gather early feedback, we announced KCSAN back in September, and
> > > > > > > have integrated the feedback where possible:
> > > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > > >
> > > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > > including several articles that motivate why data-races are dangerous
> > > > > > > [1, 2], justifying a data-race detector such as KCSAN.
> > > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > > [2] https://lwn.net/Articles/799218/
> > > > > > >
> > > > > > > The current list of known upstream fixes for data-races found by KCSAN
> > > > > > > can be found here:
> > > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > > >
> > > > > > Making this more accessible to more people seems like a good thing.
> > > > > > So, for the series:
> > > > > >
> > > > > > Acked-by: Paul E. McKenney <paulmck@kernel.org>
> > > > >
> > > > > Much appreciated. Thanks, Paul!
> > > > >
> > > > > Any suggestions which tree this could eventually land in?
> > > >
> > > > I would guess that Dmitry might have some suggestions.
> > >
> > > I checked and we're both unclear what the most obvious tree to land in
> > > is (the other sanitizers are mm related, which KCSAN is not).
> > >
> > > One suggestion that comes to my mind is for KCSAN to go through the
> > > same tree (rcu?) as the LKMM due to their inherent relationship. Would
> > > that make most sense?
> >
> > It works for me, though you guys have to continue to be the main
> > developers.  ;-)
>
> Great, thanks. We did add an entry to MAINTAINERS, so yes of course. :-)
>
> > I will go through the patches more carefully, and please look into the
> > kbuild test robot complaint.
>
> I just responded to that, it seems to be a sparse problem.
>
> Thanks,
> -- Marco

v4 was sent out:
http://lkml.kernel.org/r/20191114180303.66955-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPTMjx4TSr%2BLEwV-xm8jFtATOym%3Dh416j5rLK1V4kOYCg%40mail.gmail.com.
