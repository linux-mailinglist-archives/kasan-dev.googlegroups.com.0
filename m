Return-Path: <kasan-dev+bncBDYJPJO25UGBBPO73L3AKGQEYY7W6YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BDC491EC34A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:59:58 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id q24sf9144480pfs.7
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:59:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591127997; cv=pass;
        d=google.com; s=arc-20160816;
        b=CpdLHAl9S1zHdMxNhhj6cUgjmO2EN/aFyDhLFfUXI9noc3iE7G2W5/oKYxrFdYt3IO
         IDawK+5Y7J1UgXWuSlY7/aqCJmHf+We58dZD6bNdYLGZyIzdgQETsfvpZhVXTQO8ACkj
         EbThf11IGJc2MmgAAai4GpJh+edYoygj9RhcKzGcNMnl2J4GXXvZAywleyjKNouLQXKi
         mWBeGpsHl/I4EQl5Q3MiYhHQI0XGI+y5AjwCxhXQ6m4nqEkemmxoyssUo7LvPH1j2wPo
         leCxzdlx9IZP7YvJxoGh4719uUyHTHc7oz9SRqlx35v4QZTbCSRpFk6JbqiQhes+Zrll
         rnFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yTCBz8qWX3Wu3dz4qM2UCCxRIs+A4udraIeASaGyFjk=;
        b=IHac+K7mK8x7xqe3G+Mgaj7ELbVG+PJVS7Vwkc+wAwOeHJCXXexL+h6FvJc9TBFSvv
         jals5mpf3yCLtYxQT8vNWC6tbsC+tUENTQgO2GmMGwjVJqA7RRoVn0GeJ3HLG4e8E9SK
         lEIyzbrJFQJy9QcyTuvGYyL1pERz3b3wqVPsN2JuW18luBJz2JQGY089GP7fRrkw8hzU
         i1JwqqjWrONL9X8MNxzIMG5RgoUvO0tfJD35Yz4cuOexE2ggmMPDmafaznxVsXiE/WV8
         /khxT96xRJlMdd41msyKQkdj82AdJjWQ+J9yRgrxZjWWH+IhcxoxLdNzKlnz5N0icmvV
         KmjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dM8oqfer;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yTCBz8qWX3Wu3dz4qM2UCCxRIs+A4udraIeASaGyFjk=;
        b=eM4vncsPFDYdALMCPsqs3w6BP6W6PgMiAJ4wXAtZd7CV4Y3ApcHNY2zAjVWZPNC5c+
         40ir8BcYU2nykQ9uZT5+bynfsRYuWr1CPZrio6onC8AkSqcAx+/KNiDfBeNvFXkUzWNH
         L3l87hk2V17+fv8yRtANsIzN3wrA7O1tYekO97z9USqH+RZ1uHMs37FddmWcHCJKp0mh
         lRzSqkJLjj/KqdzPZ+GAXX+xiCapeTN02ffrEZDGh9s7J5JMLyKH+YCwplMF0iBi5RLA
         qUSxWIDURYOWa4zIXi/p3aVvKxm9HKnGFVucF9pkGIGRybDKZHDG4Pz1RaXDcJNp69XG
         33bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yTCBz8qWX3Wu3dz4qM2UCCxRIs+A4udraIeASaGyFjk=;
        b=mn0d97ztiNuSKBTfqFRIPaXerpKG3xeE1xoYFlderlk9MVKsm50CXQzqXJLnOwKa2G
         wYoqpAdEZJY9I7L4modpLNbxOtjTy/rADp4mmHj3ggKzmPCknPpYHD9gW5SQl/uaaJuo
         PL9tJsvpAZJ4n/IKWoma+wASVzhuLPDAbYWZaSlrleahqLD7zyA60Nm12Nb+dDWepVmK
         WQBnxeMXi5AaUEmmPpbdm30UUUWExwnrGQkWlBO5i56ht1Q8AZzcAUYsFD/bHqE52kx9
         PVL9Xtkrmwbjs5B6xiEVISq1mQDqSNkore4VV+OV1Co2yf/GpXY9zw8wwTQClabRqg/8
         YvcA==
X-Gm-Message-State: AOAM533PwzfvM2s0S5bzLuHSW9MrVoMThFQBhxyZGi/WKvvpuz6sXfCB
	SJHsXDraRvBJrqtr1t3KvEw=
X-Google-Smtp-Source: ABdhPJxTkNKSBlLNve3bPUUmdwdimfJqecy+akV4OsNwcytNIfLEM3nBVgXpvsb6CbWAGLmm6/0LjQ==
X-Received: by 2002:a17:90a:9307:: with SMTP id p7mr890115pjo.182.1591127997418;
        Tue, 02 Jun 2020 12:59:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8548:: with SMTP id d8ls3262002plo.11.gmail; Tue, 02
 Jun 2020 12:59:56 -0700 (PDT)
X-Received: by 2002:a17:90a:2070:: with SMTP id n103mr923024pjc.109.1591127996789;
        Tue, 02 Jun 2020 12:59:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591127996; cv=none;
        d=google.com; s=arc-20160816;
        b=hKvPzFZRHZRYXn3KNu64SfRmBf8/KzMpx/cIoFhuj9nHgojz2siKY5Sp9YLicxK8tQ
         2nc+3M3r6frl59USCLvUIffA0Kzg5f/7BkMuYiFnzI+ksA6qRkYCXAl+qvk/CuoV6VLp
         vXvLM+iUsgSjyNJiz9TxB/90OTEyNkoTSH+8HesuJtmTuNytq552IlxqeXBrPO+GXWn8
         g7wrQiisrW63WwWUGR9XpzddE14Q0VT587N3rB0vn7RckyQQ2inQLoujn4Jwa9eMvDH5
         rQ/lz3AquWk+S3dFclJE5X3U2Am1udwk5PN+g3xNBIAXSmG0mfOxhu6lBeM+DWz9NFxA
         COaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pDJvPNaeJdVNz7jP499BIJ/LDFB76CjtukHr7y52odE=;
        b=gYb9DDoW/U4g9ZvOclOYyttswUSCWajc5mCy3BIOrZXG+ibvn1YlHbhufvFSabUDj7
         fOApXqlZOpBlM0nq65MwtTOsUgoFpCRt6WJVHTztcDWUN32KE/3RiZri5g7chDUQUzZ+
         D6AtXLSER4NLFgygEYlP+NTRHm0yquolVYYdfHNg43Gk+XqfsaCQtuVHzpcSi3LNsukb
         9sYMAxVLyxAUasBDZNVyIEaMbFxUGFcUmBEGsXaEiyndi69zPYcDvLNCzjvVS1cHcert
         C7QQsTfQ7eZegX3KGx+qP5beTSvllw/HZPmkZZvAvOndno26pZ2n6X3uLapUQ/0TvlUc
         1A6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dM8oqfer;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id q12si153647pfu.4.2020.06.02.12.59.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 12:59:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id a4so5722971pfo.4
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 12:59:56 -0700 (PDT)
X-Received: by 2002:a17:90a:4e8c:: with SMTP id o12mr856663pjh.25.1591127996304;
 Tue, 02 Jun 2020 12:59:56 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
 <20200602191936.GE2604@hirez.programming.kicks-ass.net> <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
 <20200602193853.GF2604@hirez.programming.kicks-ass.net>
In-Reply-To: <20200602193853.GF2604@hirez.programming.kicks-ass.net>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 12:59:44 -0700
Message-ID: <CAKwvOd=TZsioqoUU+xZSUMooqux6Meu54PBCxP2mbtRb3Yp5pg@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dM8oqfer;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Jun 2, 2020 at 12:38 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Jun 02, 2020 at 09:25:47PM +0200, Marco Elver wrote:
> > On Tue, 2 Jun 2020 at 21:19, Peter Zijlstra <peterz@infradead.org> wrote:
>
> > > Currently x86 only, but I know other arch maintainers are planning to
> > > have a hard look at their code based on our findings.
> >
> > I've already spotted a bunch of 'noinstr' outside arch/x86 e.g. in
> > kernel/{locking,rcu}, and a bunch of these functions use atomic_*, all
> > of which are __always_inline. The noinstr uses outside arch/x86 would
> > break builds on all architecture with GCC <= 7 when using sanitizers.
> > At least that's what led me to conclude we need this for all
> > architectures.
>
> True; but !x86 could, probably, get away with not fully respecting
> noinstr at this time. But that'd make a mess of things again, so my
> preference is as you did, unilaterally raise the min version for *SAN.

Fair, thought I'd ask.  (I prefer people use newer
hopefully-less-buggier-but-maybe-not-really-suprise-they're-actually-worse
tools anyways)

Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
---
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3DTZsioqoUU%2BxZSUMooqux6Meu54PBCxP2mbtRb3Yp5pg%40mail.gmail.com.
