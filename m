Return-Path: <kasan-dev+bncBDHYDDNWVUNRBGG2XH3AKGQEPS3IUIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C7BB1E43E0
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 15:37:29 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id h26sf11607124otl.17
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 06:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590586648; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/XB8B8E8oljx4UYZ+dvLDYcUTN1MYE0GKh+egzL7ePpG38nn6IcbUa0BFUsXaE+o4
         8SVpppbKl8L3nCP/20nd0DIZ6bUqYWIHhm5ZoWHlzu74rTtBK5KbXahb7axprTChjPYe
         7lej8bn5gjJ8os9dfWtazrJnirtAcjMhHvLpDgiziQ8+GlSwxXXHeCbeGRFEMe6nfD8h
         ay4a/KNGnnhYrHliVuIFBQPZ2LKmdt8c8gxilrZCkaj+xWNQOyA7MLnhMlwgpTvx+bSf
         kvbaRN8NgaOCIdqsHWmgs2s+rZjMn+TDJamodoC91EPg4xH8bZu/RWVfLJvrlw4skvkD
         vlSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=btN2Wu9f9LJj80Tms4YnEJtI09A8xbzT/FUM3hZZBsU=;
        b=bZ+SC2DM83Urr8htsB2cQY4TK+37F/5j8rMrh3gH6/kjlLrUsdOi4aplT0r5ann8v1
         bYoWEYfqmJetoOuv7SzAK7bpp6/0sxZpCYvBsF4gIeimiwqj8mubMPpvnIFu9IuTg+R8
         RcCkVkBhTN7HQHy2QLiKy/U//Ml64RUSTV8a9QVztx7/1kt/BCtynDhVaLmKs8LGBdBq
         SaY6/cwoZDtMnbg2DgmVm+HnQeP1pMLYuDOISVpvgAI+27Zs69yndIt/vDJ3A2rBrII4
         yy1CTmiA6yeb2dnFkWVcyHKFy3bvMayDHhuXFNKMYuMziUnrT9vW8Rd4slhGVcj0mjjd
         /i8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=C6l+HeyB;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=btN2Wu9f9LJj80Tms4YnEJtI09A8xbzT/FUM3hZZBsU=;
        b=iZatizikS94YGpv2nrjs56/2/YssF2lK9lqwyHEPf1a9xiEk+Iv/6YTRvWh+cXigZj
         h/rW+C6AAP4u3XaY0Mo9fbdWHH+3Z+kQVIrUK1QTLk/gLDAS18inf0dW8qalNU2dImrn
         v857I0Bp+UJN2X3KIKHvhzMTy5edA+E2WjGCkHjbfZ0gQQoXzGqylY0EobmNVVnxWyEQ
         LLoIVcy4CZUoYITRP6IR78+WY0jLlX12j8Mm9dlHie3FGHxJlD67n4l31LFKYPFcCrfa
         a6VGLo0/Oah/ktg2i+T9I+TW/unOsxqtVTlttlDu56FVOgfF/nlEtfa8mytE08t8mdTb
         wfLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=btN2Wu9f9LJj80Tms4YnEJtI09A8xbzT/FUM3hZZBsU=;
        b=jzt2EOdBEO5jR8V6gd1e3suYEXki+2p7JkU0yw1c0TAqboT8V47oATpKNlnOiRDxUm
         K3/p5wirLPOg+9/s2AOX3Jha+ClQwHS6mPH129STvmAk7GPwKNCcn03c+zQbqQVhtWYd
         LfJ0JTzchvMsykNCIARlGjwJN/t0XRxI5XcpU1wUlgjhPjNAeG82macZYcVZT/BhI1OT
         QLTgg/R5XFmH8+1LyCnI6z/jy2IS0GI+8bkiRoOiFafdlWeyZyfcvUI4v4nRWRxphVoG
         UV42hJsSyEBuiupI/2SmG/l/HEjgFnEkx3NdvszIu0rcMzZTt0AV+lgoWYNbyihy7LWh
         wU0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=btN2Wu9f9LJj80Tms4YnEJtI09A8xbzT/FUM3hZZBsU=;
        b=tpmoq7l63y3jhVOZXg3AsypD9Tbtmih03rFQIA8CYw2qdeKynAiPusGQPjzbw4kR3B
         KK/LBH/eBx3lhKYqMvXXVg0Q0M1YBDw4UzZ4iXNmpLEhazBdGilhGTCDqznNZUJYjiCV
         gV0LD+z1Pij0CYwLWgJR35ejxJcpK5V9QM5LOxQv0rITWYTSQfgOsQeOFbZRNACrIap3
         RUTk70MZV86tkLFxblGZdQE99S1eP0uePhqjcsxGqRKEghlUZhlee0kCLP9/y13wSH1j
         NW91hiXRDqMFEguHlKmn18VohhttuW1n5BkIt4tCRWX136X4eP9NjpeI4oEyddpJFvPu
         ldtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fWl2ipTNCt505hbFoBQ6NSh8/o9eVMT3+Hg3O1/dXY4Fh6E6S
	wONJLAe2ORr74xQV9fZKVMY=
X-Google-Smtp-Source: ABdhPJwKocv7adGlYBrGZnQNitgV0vsHXz02Rz8HpHUcVxI85kI18mlomsX6ODGO/g4+2CReuHaF7A==
X-Received: by 2002:a9d:6b8e:: with SMTP id b14mr4638408otq.347.1590586648307;
        Wed, 27 May 2020 06:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2d81:: with SMTP id g1ls3107713otb.6.gmail; Wed, 27 May
 2020 06:37:28 -0700 (PDT)
X-Received: by 2002:a05:6830:61b:: with SMTP id w27mr5122464oti.154.1590586647972;
        Wed, 27 May 2020 06:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590586647; cv=none;
        d=google.com; s=arc-20160816;
        b=NGTecBDYWjbubMgxXcvtyC70HfDrGGkXBqlDlIwYvJ5k+i77iZRa3TPRE6Ix5gpx7B
         Z3XlrVzZascD5DMijamXWQfGbQ2tmOnDhiKpiF3ySwNWWHa9VXAdvkACfwiVTOWp3EkR
         evmM4CsG1qB5EunZs2CS3f4ndYnJ/Ky3SiirgxGn4g0NQEarYbFZhG2Xa/oYARnktMlL
         qhLn3ypgANgCa9uqq9t7oY0QEIs3sJZR5OnLhA/+O9UXVAXd0DxHYRliC7FNwFeeDmDt
         B1x355pYN/IoaP0Ex0IHVwM5SeUBUCIsK6FtHAQkrQanHFgEY1ODnZd0mWxo9179nY22
         /r1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=98asfAGM0k82DbjTjDjy1krArq/Ou3skB4zttUQk7aU=;
        b=a8LUO0prtgm6dU8MpL2PI/xeJn73N8WxsW9K2Tg+5uwqLoB5vQlmzZ0F8O6QUm3V5K
         1ixi8nyY3OAa450Bem30QfS2nixchDG9cLd6ssJOQOsex+nMHedXy8QMK7vzoXItVWBZ
         lV3C0sM7GiRxpCyMuico2SxwFXCz/PIZri17jSXjt9QbhDmHKNZbMQO60j1vG9ggw0mW
         B6jrkZWyEYQ/uFcxtyoAaXnItpq8yXxP7NqHIGYhqGyLpUqcbAs2A0yY+GSLdoGw+cgn
         mjOBnU2c/9GzIPzjzciXZP6XJ587fqkPyfcKKbBk+3J+e0q7cdwH6nPmiCdmmbaTVohD
         UhKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=C6l+HeyB;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id k65si305605oib.2.2020.05.27.06.37.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 06:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id q8so24534532iow.7;
        Wed, 27 May 2020 06:37:27 -0700 (PDT)
X-Received: by 2002:a02:b0d1:: with SMTP id w17mr5599803jah.75.1590586647220;
 Wed, 27 May 2020 06:37:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
 <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com> <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
In-Reply-To: <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Wed, 27 May 2020 15:37:19 +0200
Message-ID: <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sedat.dilek@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=C6l+HeyB;       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41
 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 27, 2020 at 3:30 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 27 May 2020 at 15:11, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> >
> > On Wed, May 27, 2020 at 2:50 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > >
> > > On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > > > > >
> > > > > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > > > > of the drop I saw with gcc, compared to current mainline.
> > > > > > >
> > > > > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > >
> > > > > >
> > > > > > Hi Arnd,
> > > > > >
> > > > > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> > > > >
> > > > > I meant v5.7.
> > > > >
> > > > > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > > > > >
> > > > > > Is there a speedup benefit also for Linux v5.7?
> > > > > > Which patches do I need?
> > > > >
> > > > > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > > > > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > > > > linux-next
> > > > > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > > > > almost back to the speed of linux-5.7.
> > > > >
> > > >
> > > > Which clang version did you use - and have you set KCSAN kconfigs -
> > > > AFAICS this needs clang-11?
> > >
> > > I'm currently using clang-11, but I see the same problem with older
> > > versions, and both with and without KCSAN enabled. I think the issue
> > > is mostly the deep nesting of macros that leads to code bloat.
> > >
> >
> > Thanks.
> >
> > With clang-10:
> >
> > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > +HAVE_ARCH_KCSAN y
>
> Clang 10 doesn't support KCSAN (HAVE_KCSAN_COMPILER unset).
>
> > With clang-11:
> >
> > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> >  CLANG_VERSION 100001 -> 110000
> > +CC_HAS_ASM_INLINE y
> > +HAVE_ARCH_KCSAN y
> > +HAVE_KCSAN_COMPILER y
> > +KCSAN n
> >
> > Which KCSAN kconfigs did you enable?
>
> To clarify: as said in [1], KCSAN (or any other instrumentation) is no
> longer relevant to the issue here, and the compile-time regression is
> observable with most configs. The problem is due to pre-processing and
> parsing, which came about due to new READ_ONCE() and the
> __unqual_scalar_typeof() macro (which this patch optimizes).
>
> KCSAN and new ONCEs got tangled up because we first attempted to
> annotate {READ,WRITE}_ONCE() with data_race(), but that turned out to
> have all kinds of other issues (explanation in [2]). So we decided to
> drop all the KCSAN-specific bits from ONCE, and require KCSAN to be
> Clang 11. Those fixes were applied to the first version of new
> {READ,WRITE}_ONCE() in -tip, which actually restored the new ONCEs to
> the pre-KCSAN version (now that KCSAN can deal with them without
> annotations).
>
> Hope this makes more sense now.
>
> [1] https://lore.kernel.org/lkml/CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com/
> [2] https://lore.kernel.org/lkml/20200521142047.169334-1-elver@google.com/
>

Thanks, Marco.

I pulled tip.git#locking/kcsan on top of Linux v5.7-rc7 and applied this patch.
Just wanted to try KCSAN for the first time and it will also be my
first building with clang-11.
That's why I asked.

- Sedat -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUWzPMOj%2BqsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg%2B2Nw%40mail.gmail.com.
