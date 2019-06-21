Return-Path: <kasan-dev+bncBDEKVJM7XAHRBO56WPUAKGQESFSSDFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C0C2A4E9B7
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 15:44:28 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id p13sf6400151ywm.20
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 06:44:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561124667; cv=pass;
        d=google.com; s=arc-20160816;
        b=C55KZETleCl3/lOZwaQaExD1U/KDN+LybRB3R1hTCP1E3TMCcLhSzKbzAdFWTqnsDr
         p0QOHB0I7Kx8lDnhHqbNoKpuTLiofb8e7b4MODlOJwcTyidV6VRuhXQ7PJ3T7gkckw1g
         Px4QOBbYltPFvw3AHet5KDOmS6ACWdMVFXSEDFqZhCCJwhRYkONQ4oWwJ6N2xQMXZSAn
         l5fIP/Ui9kIHjdx0YV7/YUd412CacbojJJ9nn+f8Fkn/d3Shlhf+l7gQuAdjRunsISeB
         pQnOXE8JQJUZ5P3MU1zFaOZrMidI80m3QM8uwFVLsbWVcBmuzeM8kAuoDpc0htO4Dl1y
         NbiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=COW+c/RTU9VoBecd2qXw2nBTELv6Boucazfub5NblKY=;
        b=I4KUC67jNYaEfEvmS1P0ag6AN+FzYr2ifpuFkUcT0v0eHmXEveQhlCA0UdXoenoB7V
         CfbyqDLFJAaEpynGacfHK4rjanHtOEeYz4Ek771IRneFsQQYNMO1vbNuF6Y30m9IkPkm
         adaoRXgb2gSOOH4GI4K4cR1QAY5F7Vp1lIoh1H3JvqhqcoJtLaPIGRCXzZUZAVPJ7tU+
         BOnK97OlnZfU5aYKVxXJdgM4rcn7whB35lCSrwqG8vQpG/b7g44E+wD+Eonj9pzg4J1L
         Fdtpci/UVYaehFV1y2AmwczmVg/VW+FRALy2x9Lu0k0RUicFOPqFwp/ErqfmI6vZpvmH
         h1Gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=COW+c/RTU9VoBecd2qXw2nBTELv6Boucazfub5NblKY=;
        b=JSP33/fmxia9gvI56j+G6d70loKgJjcj5k2KTWdaMeKwdBFDUOkQDexil9Zo4JI0er
         Jiu6kW8ZBMlFO0D2+WYzZ72Q1ojCvSqYJMfqfR9CGfAtdITNVG7Kmb5ebXPfWTEZE3ft
         JjNJLAWjwAXHwJ0K/+k55k4ZmX6mwEb2/B2sAw9oHBBEnOeklewzIqa2ArsNhu21y9u/
         yimrsX5ePRCN6MDkvulkR/hqNnGKTthZ1ywfF8tYQigMTDoWKwYhp/9oOtvtmWALqtvf
         VH7OS+ngfIB0zx2I42Kn7ijACL0/DJ1GKJ8U0dXo6O5IBEXabUKFkvMUSKvK5guG8C9j
         gdyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=COW+c/RTU9VoBecd2qXw2nBTELv6Boucazfub5NblKY=;
        b=B65F+7pEr+msOCvldhAR5BVhgc2Sw6gxsXForWvZY5W8+fZkCI7NPkfD/pC/nVq+qF
         rsCXRvbiRj4FHoH1UioqJdVZMcAi83F+2r7AZmQ4LEad4NmiI9gCNkww3XyF1/OWYqE9
         QNlT0lTvkWDBJXXuMzLLxSDXs6Mm9akyx5Pw9JqZqcGtEQg1oUe3W1la2z0Ulgu+SzEu
         I7gD410aQt2HOWjxdurP9r8PFr3wBH052kbCW/zeVBUjnSJgfF4XP+nGFvXBwjekNVGs
         ZsQT3eaXwDtfmwBskBitAg9qPY/htUS3wQVGp2Bckgm8exzWQbH2AhmeLKPL7U4BtSnE
         oGFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW8W035+of0sS57QSr+ihuprEoGg7MWUi0mbAficxjtfCQ7aG0I
	JIq9Ze3odoiuVUHnpJNxso8=
X-Google-Smtp-Source: APXvYqyev0iXfuWvNc+wIbhfM1lnWJbokkBqJIpi5gS4f1tK9igxdLwFt64Sw+tVn7x4XzLtGj13rg==
X-Received: by 2002:a25:84cd:: with SMTP id x13mr72345091ybm.349.1561124667490;
        Fri, 21 Jun 2019 06:44:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:108b:: with SMTP id 133ls797680ywq.0.gmail; Fri, 21 Jun
 2019 06:44:27 -0700 (PDT)
X-Received: by 2002:a81:924a:: with SMTP id j71mr19991892ywg.5.1561124667138;
        Fri, 21 Jun 2019 06:44:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561124667; cv=none;
        d=google.com; s=arc-20160816;
        b=XlnVNgsL3+3rspEGZYYqK+lHxw9cTBbRRF8zAiWA7lKI0KWmz/dXFYPxnShH5STYTV
         N6FmKomYRM69oSTUx/VwtF9IdttBRmn4sJ6ih1b8lCfGJrBrH47TspZ7AwN4paIUAed2
         cWhisq4tzBdXjKAvpHP6holZ0QB3tklEE7iMcV4mW/2byTphRWDAleCZVTm6BAreOsuR
         dK+zZAu4U2Xqp+kN8iJi3OhieFtIPkvdOlcCIlsMyzAWaR4IFlVZabHeLUZIQY9yRMEq
         J4kObkXPyOoI/hbZM6eurqW1heSZ+19+xp9PvLCSmNoP5k/KOeecsp42P47S9TFtQ+Z8
         8iwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=1VRloZAnkBM20C0VMUxA/xb315UbiGomahozxwvH1Z8=;
        b=Fs2FE4FH2jUbpjFHiUGZStwpL5b8eEd2mFseetYVFka4HHXAdVK+7TrYPBXv/ZQwbn
         XW4anpzKylkMm8y0a5BY+bY0H4ZQxjxQAFfSyOlAYXzQEdQPzztn4eTtYR0DimTtmmYY
         owA8trT9MJnLZr5trTBiq7iMdS7yDMqi20wy6GJWzRGsnSbaLELdxEqtbxfjJPH7Gf2A
         kRdoWsjD6qXHdO+Q1ZahPtU8ZHXc8YeR+jTnVwZs5PeX1w4UJNM4WDGkpCMjFyizqX1T
         aXcy/X5+B9o/+K7JzrTbLdePg0BRVBP+8x2/plAWLO6goCTowSS81eyaUZ/FsPvohcNQ
         cDxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
Received: from mail-qt1-f194.google.com (mail-qt1-f194.google.com. [209.85.160.194])
        by gmr-mx.google.com with ESMTPS id o62si203125yba.0.2019.06.21.06.44.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2019 06:44:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as permitted sender) client-ip=209.85.160.194;
Received: by mail-qt1-f194.google.com with SMTP id j19so6892716qtr.12
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2019 06:44:27 -0700 (PDT)
X-Received: by 2002:aed:2bc1:: with SMTP id e59mr96965363qtd.7.1561124666614;
 Fri, 21 Jun 2019 06:44:26 -0700 (PDT)
MIME-Version: 1.0
References: <20190618094731.3677294-1-arnd@arndb.de> <201906201034.9E44D8A2A8@keescook>
 <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com> <CAKv+Gu-A_OWUQ_neUAprmQOotPA=LoUGQHvFkZ2tqQAg=us1jA@mail.gmail.com>
In-Reply-To: <CAKv+Gu-A_OWUQ_neUAprmQOotPA=LoUGQHvFkZ2tqQAg=us1jA@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Fri, 21 Jun 2019 15:44:08 +0200
Message-ID: <CAK8P3a2d3H-pdiLX_8aA4LNLOVTSyPW_jvwZQkv0Ey3SJS87Bg@mail.gmail.com>
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with KASAN_STACK
To: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Cc: Kees Cook <keescook@chromium.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Popov <alex.popov@linux.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, 
	LSM List <linux-security-module@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of arndbergmann@gmail.com designates 209.85.160.194 as
 permitted sender) smtp.mailfrom=arndbergmann@gmail.com
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

On Fri, Jun 21, 2019 at 3:32 PM Ard Biesheuvel
<ard.biesheuvel@linaro.org> wrote:
> On Fri, 21 Jun 2019 at 11:44, Arnd Bergmann <arnd@arndb.de> wrote:
> > On Thu, Jun 20, 2019 at 7:36 PM Kees Cook <keescook@chromium.org> wrote:
> > > On Tue, Jun 18, 2019 at 11:47:13AM +0200, Arnd Bergmann wrote:
> > > > The combination of KASAN_STACK and GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
> > > > leads to much larger kernel stack usage, as seen from the warnings
> > > > about functions that now exceed the 2048 byte limit:
> > >
> > > Is the preference that this go into v5.2 (there's not much time left),
> > > or should this be v5.3? (You didn't mark it as Cc: stable?)
> >
> > Having it in 5.2 would be great. I had not done much build testing in the last
> > months, so I didn't actually realize that your patch was merged a while ago
> > rather than only in linux-next.
> >
> > BTW, I have now run into a small number of files that are still affected
> > by a stack overflow warning from STRUCTLEAK_BYREF_ALL. I'm trying
> > to come up with patches for those as well, we can probably do it in a way
> > that also improves the affected drivers. I'll put you on Cc when I
> > find another one.
> >
>
> There is something fundamentally wrong here, though. BYREF_ALL only
> initializes variables that have their address taken, which does not
> explain why the size of the stack frame should increase (since in
> order to have an address in the first place, the variable must already
> have a stack slot assigned)
>
> So I suspect that BYREF_ALL is defeating some optimizations where.
> e.g., the call involving the address of the variable is optimized
> away, but the the initialization remains, thus forcing the variable to
> be allocated in the stack frame even though the initializer is the
> only thing that references it.

One pattern I have seen here is temporary variables from macros or
inline functions whose lifetime now extends over the entire function
rather than just the basic block in which they are defined, see e.g.
lpfc_debug_dump_qe() being inlined multiple times into
lpfc_debug_dump_all_queues(). Each instance of the local
"char line_buf[LPFC_LBUF_SZ];" seems to add on to the previous
one now, where the behavior without the structleak plugin is that
they don't.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2d3H-pdiLX_8aA4LNLOVTSyPW_jvwZQkv0Ey3SJS87Bg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
