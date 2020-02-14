Return-Path: <kasan-dev+bncBCMIZB7QWENRBG4TTLZAKGQEKMKYO4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 07AD815D6DC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 12:50:53 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id e11sf5920707qkl.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 03:50:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581681052; cv=pass;
        d=google.com; s=arc-20160816;
        b=jZ1Q0/kogvpwyE+wAjPX2ZQ/cOTnMblClYsmhW1vQk7SCcBZ5K3bi9SAGF0aLCtaN2
         pcNRuOiuCR82x23P+hhnQVjaLeYrKluC5ay8ParZce/ye/uhtmdZ0Vp2RQitw8jSsY66
         5GUVTc2ewgBqvXGS5EZtU27TKGpMQyMJB0Gtk02kYiELMmkw3Pj8D8E3/0UOQCfCXMDh
         PY5iTCabMVxPmluSeep5IcXHlKbr4YI76s0U2v/aYL2wvYpzfoeUVWQ1lDo/AqvBEi/b
         hl6x2NVP6mUBD0mPLFeYYh3gIn9QwC8VGAM/Wt8b/IlCFyGZmqu23XBcFV+21epiD3mS
         Fx3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LvgzXD5/XB+luF0QBcfmLHiY0N9UgP9e3addajj1FhI=;
        b=JcHdF9h2xYQWqwjeng0WuIwBJBJ4w6ZrTVkwCwqIRvpGBG1gNdYYNjZxHYf/KSt1aO
         REycFpdqpjQcizw5pO/3XkxjIZfALtklqGQng5CER3O4ce6tiBv3KbBmupullxvMOPfq
         jmRMpBi2feUb2erQtlvbQ0Y0YapGYdl5VbeRVXYztRTec2v6Pv+8pIf6n4GZHykzegpN
         GX8veVNZAb4KP+/J+JkRXhPGvw39b/Kjjp8duc8ng/d8/YAoGkDfVlZZPkOVoJ4JmflC
         +ZHG8HkjpA1OvJfk1POXX7Kk7FMsqH0bu1ru3+KfT+fjj32cBB8UsOigPHfE2x2pq+3s
         I24A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gHABD3av;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LvgzXD5/XB+luF0QBcfmLHiY0N9UgP9e3addajj1FhI=;
        b=cXvJCRMxFJiw/VFHf7jZ+6pzgcozzdm4HyKjeTZsXj9WkCB/lrTSlh4e2m7QG8a/41
         h0GQhVi1CNn8oKzIuj+OyZim2M2WTSrXgGV0PqqNtlnkhlFvdCtL2SVEBxTnhXVDaPoa
         ZtkHundj7t3qmpb4+JG+lSQlhobok0W+SpBCiYwy6y8M+39E/fXYtoTFFS1g6pnlnt5y
         Q5ubZIPdDEfE4HQrPI2xCptgkoMxc3w1HPzJmc8bku8BB6yAX6C+sC205/7En2o6BcmM
         iV3MT0ZtNUH9hTxPrbnSUt+X4ezqHJ29pa0OdS0rv4Xx3NyHmNsIoEZIUJ3JeufETX1a
         1GFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LvgzXD5/XB+luF0QBcfmLHiY0N9UgP9e3addajj1FhI=;
        b=k457mDokOi9YmhwUAtpGNGnyD8YnwYCDBsRP+wkl5iIM1lgInIaFSxu1NUvZqvjgvX
         R/QxaV8jbE5yTh1YSiUDwE6gorJD7+MIeYI5X4R/plEr/bzSG6ooDRx8xZ7J5Wux8qTp
         N74S535/KsIdim/PhbjVFVbbAUdXF9Im0XTkqCXi3Jf17VleoKmmBHbxDtoH8cY7PJt7
         JSzo/HPIr1Vd8DWNNLCI78C/G5Vx0H//+M0S2P3jikjwWlGV6QDYBo7zNd6TMdB/5WI7
         KTR1I921+VuVYZcEqYcvjRe2893ctDutsKqujoLx860NSpBXZGefqjo/TS1OLhJkdB2R
         Hh+Q==
X-Gm-Message-State: APjAAAUtWgXEIvygNVq0iDepxLFTiBX8I/JPSLOkUaKnRN5p51t/MFvE
	SF1C0asMqIKGI8J+On8jdd4=
X-Google-Smtp-Source: APXvYqzKO/EH/1BCJ5olQO9SHaWvH8vPVHWMRTsx1TIV9KduoS08MosxVMTkFNMdeeWNBQ4xS5SSfQ==
X-Received: by 2002:a37:5fc2:: with SMTP id t185mr2031994qkb.271.1581681051960;
        Fri, 14 Feb 2020 03:50:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:72c4:: with SMTP id o4ls662512qtp.10.gmail; Fri, 14 Feb
 2020 03:50:51 -0800 (PST)
X-Received: by 2002:ac8:730c:: with SMTP id x12mr2176148qto.179.1581681051518;
        Fri, 14 Feb 2020 03:50:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581681051; cv=none;
        d=google.com; s=arc-20160816;
        b=psLA/pbT7q3S3VXCekYTd7/ZFjVyfOky/ppibDVFVhYvIGRGqtDYexI/AggGk4pRle
         ILnz1ZYAUaLNZ5TnWfG+m+EZiCEAN7CJrz8zTykecm2GsX2P9hHgWsRRb9r2zGRI6mOJ
         9xCD2dgQQml7elucYbvafZyi7D0yJZ1i7Ytq8GfLwhc9O6gPBwudCiaDs9398O2DESRn
         rvx6dgkZomVaZnBcPBXla5mNwvPnSk1dMWhsbWn6xqayqw5HQUpzYjmwHmMvhNUBNdCg
         CFKD80Pni0hMTD+q77VOetu9ZKBOhUFpjADamtFm9oik7gVDBTwhPYDuggZ0pXL3Fgwt
         B7Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HzQoy05Af67alr+vpKQsT3UpCBuAqj1D3z8JYtOyJCA=;
        b=YxTnt7qhCidsHj489CyYg+PENRKSZeK2+5ots7BPv89bn4dL60FNMYwMDwMZA7Klmp
         6CJxWDICguJQ7h085TrsEsTrOFDud7CXzTasoE55O1mYNofOOreSgHNQqPCPO+P0AbWM
         wumJiqBSAhQr4wDGXdejxa+YViaENzaVw5c7UEwCTJ1MNQp4U52EcEr3noMQq9ojlUSt
         dZ2WF/O/pUp7EsqD5SPcJuM1Utjqs2QVq4FBqWA49cdZswdImKwWTU1De+hTSY9u3ZfI
         +IbAbNm3Ktx6nDQzNjX3KgpjrBOR8SMtNM/E2b6avgC90p4N/c9SEci5bnqqvRrAqSHC
         EdMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gHABD3av;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id g23si274951qki.4.2020.02.14.03.50.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 03:50:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id e21so6714279qtp.13
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 03:50:51 -0800 (PST)
X-Received: by 2002:ac8:340c:: with SMTP id u12mr2134179qtb.257.1581681050484;
 Fri, 14 Feb 2020 03:50:50 -0800 (PST)
MIME-Version: 1.0
References: <20200207120859.GA22345@paulmck-ThinkPad-P72> <1581088731.7365.16.camel@lca.pw>
 <CANpmjNPbT+2s+V+Ra3C-4ahtCxyHZzOLzCDp9u7c339vN6u7Fg@mail.gmail.com>
 <CANpmjNOXma=Px-EMMp-F5dij2BaF8iZFj-3WGCXf+bXrdtdU5Q@mail.gmail.com>
 <CANpmjNOdUZJz9N1ydecFrOgpqOMgwOT576dxo97XooPwwED3Hg@mail.gmail.com>
 <2C38E1DE-647E-4B90-98B8-D7F3C0512ADA@lca.pw> <20200214094423.GP2935@paulmck-ThinkPad-P72>
 <CANpmjNN17WCK=4=ZUfcKEARarYEheZ+L88JAKm-qG_zXM9DauQ@mail.gmail.com>
In-Reply-To: <CANpmjNN17WCK=4=ZUfcKEARarYEheZ+L88JAKm-qG_zXM9DauQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2020 12:50:38 +0100
Message-ID: <CACT4Y+Z-m9djWoTMne8WPffDiW=v5NE0vrqrD8O+oXUfYr+KHw@mail.gmail.com>
Subject: Re: KCSAN pull request content
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Qian Cai <cai@lca.pw>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gHABD3av;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Fri, Feb 14, 2020 at 12:03 PM Marco Elver <elver@google.com> wrote:
> > > >>>>> Hello!
> > > >>>>>
> > > >>>>> I just got a private email from Ingo suggesting that KCSAN migh=
t make
> > > >>>>> not this (now ending) merge window but the next one.  However, =
he would
> > > >>>>> like a nicely curated pull request very soon, like today or tom=
orrow.
> > > >>>>> Something about KCSAN having had an incompatibility or two with=
 KASAN
> > > >>>>> and lockdep, I would guess, plus it being new, thus Ingo wantin=
g more
> > > >>>>> test time in -tip and -next than usual, I would guess.  Me, I w=
ould feel
> > > >>>>> more comfortable getting a round of -next testing in before sen=
ding such
> > > >>>>> a pull request, but I don't get to do that until the end of the=
 current
> > > >>>>> merge window.  Can't have everything!
> > > >>>>>
> > > >>>>> Left to myself, I would rebase the following commits on top of =
the
> > > >>>>> current KCSAN group in -tip.  Please let me know if I should ch=
ange
> > > >>>>> this list.  Are any too risky?  Did I miss any?
> > > >>>>>
> > > >>>>> My testing needs to include the following:
> > > >>>>>
> > > >>>>> o     Run the stack in rcutorture testing.
> > > >>>>>
> > > >>>>> o     Above, but introduce a lockdep splat.
> > > >>>>>
> > > >>>>> o     Test attempts to do KCSAN and KASAN concurrently.
> > > >>>>>
> > > >>>>> o     Use ASSERT_EXCLUSIVE_* in RCU, and verify with injected r=
aces.
> > > >>>>>
> > > >>>>> o     Above, but merging latest mainline.
> > > >>>>>
> > > >>>>> Anything else?
> > > >>>>
> > > >>>> Just to give some feedback after playing KCSAN for a few weeks w=
ith a hope that
> > > >>>> some of them might be addressed before merged into the mainline.
> > > >>>
> > > >>> Thank you for testing and feedback!
> > > >>>
> > > >>>> =3D=3D=3D Documentation =3D=3D=3D
> > > >>>> I am having a bit of hard time to explain to other developers (M=
arco did help me
> > > >>>> on this a lot though) once I had sent some patches to mark inten=
tional data
> > > >>>> races. People still have a lot of questions around data_race() m=
acro, and
> > > >>>> hesitate to see their code has been surrounded by such unfamilia=
r things. People
> > > >>>> also have a lot of questions on what KCSAN/compiler could be cha=
nged rather than
> > > >>>> using the macro in the kernel. For example, readers only care ab=
out a single bit
> > > >>>> that is immutable of load tearing (lots of those in kernel). Not=
 sure if it
> > > >>>> worth for Macro to write a FAQ if it does not exist today, so I =
could point it
> > > >>>> to developers rather than having to answer those questions (or i=
nvolve Marco)
> > > >>>> over and over again?
> > > >>>
> > > >>> We're writing an LWN article that should resolve part of this. If=
 you
> > > >>> have specific points for a FAQ-like section, please let us know!
> > > >>> Until that article is out, feel free to Cc me, so I can answer
> > > >>> questions and get more feedback.
> > > >>>
> > > >>> After the article is out, I'm planning to update
> > > >>> 'Documentation/dev-tools/kcsan.rst' with a shorter version of tha=
t
> > > >>> article. We're still figuring out what exactly to write.
> > > >>>
> > > >>> =3D=3D Bitmask problem =3D=3D
> > > >>> The bitmask problem I currently don't have an answer, other than =
to
> > > >>> use 'data_race()' or blacklist these files for now. Technically
> > > >>> they're data races, because the compiler still emits a load that =
is
> > > >>> between byte and word size, but clearly, most of the bits read ar=
e
> > > >>> "thrown away". There may also be other compiler optimizations tha=
t we
> > > >>> want to guard against, so load-tearing isn't the only thing to ke=
ep in
> > > >>> mind.
> > > >>>
> > > >>> Since KCSAN (as of recently) considers aligned writes up to word-=
size
> > > >>> as atomic, the flag writers won't need annotations. So 'flags |=
=3D (foo
> > > >>> << FOO_SHIFT)' won't need to be marked and can remain as-is. Howe=
ver,
> > > >>> if a concurrent '(flags & BAR_MASK) >> BAR_SHIFT' happens, where =
the
> > > >>> BAR bits are never changed even if FOO bits change, then KCSAN
> > > >>> currently still complains if flags is not READ_ONCE(flags).
> > > >>>
> > > >>> Because some of the flag operations are non-trivial and can do
> > > >>> arbitrary shifts, ands, ors, etc. it's pretty much impossible to =
infer
> > > >>> which bits we should look at. A macro like 'READ_BITS(var, start,
> > > >>> end)' might help, but arguably that's not great, since the existi=
ng
> > > >>> idioms are all over the kernel, and are quite readable as-is.
> > > >>>
> > > >>> I'm still thinking about this. It could be an extension to the
> > > >>> same-value stores are ignored option, but unsure how to get the b=
its
> > > >>> to look at due to reasons mentioned above.
> > > >>>
> > > >>>> =3D=3D=3D Performance =3D=3D=3D
> > > >>>> After switched from KASAN to KCSAN using the default KCSAN optio=
ns, the system
> > > >>>> is considerable slower. For example, systemd timeout probing LVM=
 rootfs that
> > > >>>> need a manual intervention, see dmesg [1]. Also, the kernel comp=
ilation is
> > > >>>> significantly slower. Yes, I am using KCSAN_REPORT_ONCE_IN_MS=3D=
1000000000 to rate
> > > >>>> limited. It might be just that there are some tunables I have no=
t had a chance
> > > >>>> to play much that could improve the performance like number of w=
atchpoints, but
> > > >>>> those tunables may need a more sensible default to begin with.
> > > >>>
> > > >>> KASAN and KCSAN are separate tools and their runtimes have nothin=
g in
> > > >>> common. They find different bug classes.
> > > >>>
> > > >>> Compilation speed is largely out of our control, since this is du=
e to
> > > >>> the instrumentation being inserted. I don't think it hurts the re=
st of
> > > >>> the kernel, since it's meant to be a debugging tool, and not enab=
led
> > > >>> by default.  To see if it is only GCC that is so slow, try the la=
test
> > > >>> Clang, which I think also generates better code in some cases!
> > > >>>
> > > >>> Runtime performance wise, one issue seems to be that you're enabl=
ing
> > > >>> as many debugging tools as possible all at once, running on a ver=
y
> > > >>> large system. I'd expect the number of data races for a large sys=
tem
> > > >>> to increase drastically. There are 2 ways to test this hypothesis=
.
> > > >>> First you can try to set 'maxcpus=3D8' or something, then try the
> > > >>> following.
> > > >>>
> > > >>> KCSAN_REPORT_ONCE_IN_MS only helps limiting output to console, bu=
t the
> > > >>> data races are still found, including all the slow-path overhead.=
 On a
> > > >>> large system this is probably problematic while the kernel still =
has
> > > >>> so many data races  (I imagine if the kernel had as many
> > > >>> user-after-free, out-of-bounds etc. as data races, you also would=
 have
> > > >>> a bad time with KASAN).
> > > >>>
> > > >>> For a very large system, we want to _reduce_ the per-CPU rate at =
which
> > > >>> we might detect data races:
> > > >>>
> > > >>> CONFIG_KCSAN_SKIP_WATCH=3D10000 # increased, to set up watchpoint=
s less often
> > > >>>
> > > >>> Essentially, because you have so many CPUs, the chances of detect=
ing a
> > > >>> race is amplified by default (compared to say the VMs we use syzb=
ot
> > > >>> in). If you still have problems, keep increasing
> > > >>> CONFIG_KCSAN_SKIP_WATCH.  Not sure why I didn't think of this ear=
lier.
> > > >>> :-/
> > > >>>
> > > >>> Probably not needed, but you can also try adding this to your con=
fig:
> > > >>> CONFIG_KCSAN_NUM_WATCHPOINTS=3D512  # increase to reduce overall =
contention
> > > >>> CONFIG_KCSAN_UDELAY_TASK=3D40  # decreased to reduce total delay =
across
> > > >>> the whole system
> > > >>> CONFIG_KCSAN_UDELAY_INTERRUPT=3D10 # decreased, same reason
> > > >>
> > > >> I think I can make these boot parameters easily, so you can also
> > > >> change some of them at runtime. Let me send a patch. I hope it's
> > > >> trivial enough of a patch to be able to be included in the pull
> > > >> request that Paul is preparing.
> > > >>
> > > >> I will send this in approx. 1.5 hours.
> > > >
> > > > I've just sent a patch to expose parameters which you can use to tu=
ne
> > > > your system's performance. Those parameters are the only ones that =
you
> > > > should need to touch at runtime to improve overall system performan=
ce.
> > > >
> > > > So in your case I'd try CONFIG_KCSAN_SKIP_WATCH=3D20000, and then o=
nce
> > > > you're booted decrease the value of
> > > > /sys/module/kcsan/parameters/skip_watch until KCSAN finds enough ra=
ces
> > > > and your system is still stable enough.
> > >
> > > Some more feedback,
> > >
> > > Lately, I have spent a few days reviewing the reports. There are stil=
l way too many
> > > likely false positives that really need ways to control them efficien=
tly other than sending
> > > hundreds of patches using the data_race() macro. There are many place=
s write and
> > > read only care about a single bit, i.e. page->flags that is safe from=
 a data race.
>
> The bit operations are tricky. Just sending 'data_race()' doesn't fix
> too much per-se, so let's think about this.
>
> For now, filtering the marked atomic bit writes (like you have below)
> and unmarked reads, you may use the following config:
>    CONFIG_KCSAN_IGNORE_ATOMICS=3Dy
>    CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=3Dn
> (The Kconfig defaults together with these 2 options should give you
> the most conservative reporting.)
>
> That would certainly get rid of all the marked flags writes (which I
> assume they should be) and unmarked read cases. Although I still don't
> fully agree that all the reads can be unmarked, for the time being
> let's assume that's the case.
>
> > Is it possible to post-process the KASAN reports using the symbol table
> > (with full DWARF information) to filter out accesses to specific struct=
ure
> > fields such as this one?  (In theory the answer must be "yes" given tha=
t
> > tools like gdb figure this out, but the only difference between theory
> > and practice is that in theory they are both the same.)
>
> Good question. I don't know right now and need to investigate.

+kasan-dev

This will significantly complicate the use of the tool.
It won't be possible to run it standalone anymore. It won't be
possible to use/trust console output, which is I guess the current way
to test kernel by all kernel developers today, somebody will need to
re-teach of all them for this more complex way of assessing output.
Somebody will need to integrate this special build, post processing
and making the debug binary available at the right location into all
kernel testing systems. Systems like KUnit won't be able to give
PASS/FAIL result anymore as well.
I would strongly advise against this path, kernel needs to decide if a
bug happened or not on its own.

As a more technical detail, it also won't work if a pointer to the
field is taken. For direct field accesses it may be possible to tie to
the field name, but for just any *ptr it's not feasible afterwards.
Think of:

if (get_random() % 2)
  ptr =3D &foo->bar;
else
  ptr =3D kmalloc();
*ptr =3D ...; // race detected here, is it access to bar field?



> > Or maybe it is possible to do this at build/run time, for example, by
> > marking the struct field somehow in a manner similar to how functions
> > can be marked as ignored by KCSAN?
>
> We already have an exception for 'jiffies', but that's easy because
> it's global. Let me look into it.
>
> > > For example,
> > >
> > > [  518.993276][ T3411] write (marked) to 0xffffe308bd79ae00 of 8 byte=
s by task 3330 on cpu 45:
> > > [  519.001718][ T3411]  mark_page_accessed+0xe3/0x3f0
> > > arch_set_bit at arch/x86/include/asm/bitops.h:55
> > > (inlined by) set_bit at include/asm-generic/bitops/instrumented-atomi=
c.h:29
> > > (inlined by) SetPageReferenced at include/linux/page-flags.h:315
> > > (inlined by) mark_page_accessed at mm/swap.c:378
> > > [  519.006616][ T3411]  generic_file_buffered_read+0x706/0xf00
> > > [  519.012256][ T3411]  generic_file_read_iter+0x199/0x200
> > > [  519.018227][ T3411]  xfs_file_buffered_aio_read+0x125/0x2f0 [xfs]
> > > [  519.024999][ T3411]  xfs_file_read_iter+0x1e4/0x430 [xfs]
> > > [  519.030472][ T3411]  new_sync_read+0x299/0x3a0
> > > [  519.034978][ T3411]  __vfs_read+0x92/0xa0
> > > [  519.039056][ T3411]  vfs_read+0xcf/0x1c0
> > > [  519.043045][ T3411]  kernel_read+0x89/0xd0
> > > [  519.047206][ T3411]  kernel_read_file+0x1fe/0x2b0
> > > [  519.051980][ T3411]  kernel_read_file_from_fd+0x56/0x90
> > > [  519.057283][ T3411]  __do_sys_finit_module+0xc7/0x190
> > > [  519.062412][ T3411]  __x64_sys_finit_module+0x4c/0x60
> > > [  519.067550][ T3411]  do_syscall_64+0x91/0xc44
> > > [  519.071974][ T3411]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > [  519.077776][ T3411]
> > > [  519.080021][ T3411] read to 0xffffe308bd79ae00 of 8 bytes by task =
3411 on cpu 72:
> > > [  519.087614][ T3411]  pagevec_lru_move_fn+0x112/0x190
> > > PagePoisoned at include/linux/page-flags.h:194
>
> PagePoisoned is not doing any bit operations, it's reading the entire wor=
d.
>
> > > (inlined by) page_to_nid at include/linux/mm.h:1080
>
> It's used here in a VM_BUG_ON_PGFLAGS.
>
> But if you use the option recommended above, this race would be
> filtered out. My recommendation is that you use the most conservative
> config for now (using the 2 options above), to avoid, as you pointed
> out, sending potentially unnecessary data_race() if we find a way to
> avoid them altogether.
>
> > > (inlined by) page_pgdat at include/linux/mm.h:1227
> > > (inlined by) pagevec_lru_move_fn at mm/swap.c:201
> > > [  519.092646][ T3411]  activate_page+0x1e2/0x250
> > > [  519.097170][ T3411]  mark_page_accessed+0x242/0x3f0
> > > [  519.102128][ T3411]  generic_file_buffered_read+0x706/0xf00
> > > [  519.107785][ T3411]  generic_file_read_iter+0x199/0x200
> > > [  519.113768][ T3411]  xfs_file_buffered_aio_read+0x125/0x2f0 [xfs]
> > > [  519.120550][ T3411]  xfs_file_read_iter+0x1e4/0x430 [xfs]
> > > [  519.126029][ T3411]  new_sync_read+0x299/0x3a0
> > > [  519.130525][ T3411]  __vfs_read+0x92/0xa0
> > > [  519.134590][ T3411]  vfs_read+0xcf/0x1c0
> > > [  519.138569][ T3411]  kernel_read+0x89/0xd0
> > > [  519.142732][ T3411]  kernel_read_file+0x1fe/0x2b0
> > > [  519.147512][ T3411]  kernel_read_file_from_fd+0x56/0x90
> > > [  519.152821][ T3411]  __do_sys_finit_module+0xc7/0x190
> > > [  519.157958][ T3411]  __x64_sys_finit_module+0x4c/0x60
> > > [  519.163095][ T3411]  do_syscall_64+0x91/0xc44
> > > [  519.167530][ T3411]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > >
> > > Also, there are writes only for a few bits or a few members in a stru=
cture, but reads
> > > don=E2=80=99t care about those bits or members. I suppose we could us=
e
> > > ASSERT_EXCUSIVE_BITS() for that by figuring out the member offsets or=
 it is better
> > > to have another helper ASSERT_EXCLUSIVE_MEMBERS()? For example,
> > >
> > > write to 0xffff9cf8bba08ad8 of 8 bytes by task 14263 on cpu 35:
> > > 28284.522789][T12120]  vma_interval_tree_insert+0x101/0x150
> > > vma_interval_tree_insert+0x101/0x150:
> > > rb_insert_augmented_cached at include/linux/rbtree_augmented.h:58 (di=
scriminator 13)
> > > (inlined by) vma_interval_tree_insert at mm/interval_tree.c:23 (discr=
iminator 13)
> > > [28284.528273][T12120]  __vma_link_file+0x6e/0xe0
> > > __vma_link_file at mm/mmap.c:629
> > > [28284.532806][T12120]  vma_link+0xa2/0x120
> > > [28284.536819][T12120]  mmap_region+0x753/0xb90
> > > [28284.541170][T12120]  do_mmap+0x45c/0x710
> > > [28284.545179][T12120]  vm_mmap_pgoff+0xc0/0x130
> > > [28284.549615][T12120]  ksys_mmap_pgoff+0x1d1/0x300
> > > [28284.554306][T12120]  __x64_sys_mmap+0x33/0x40
> > > [28284.558730][T12120]  do_syscall_64+0x91/0xc44
> > > [28284.563164][T12120]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > [28349.717158][T14262] read to 0xffff9cf8bba08a80 of 200 bytes by tas=
k 14262 on cpu 122:
> > > [28349.725059][T14262]  vm_area_dup+0x6a/0xe0
> > > vm_area_dup at kernel/fork.c:362
> > > [28349.729201][T14262]  __split_vma+0x72/0x2a0
> > > __split_vma at mm/mmap.c:2661
> > > [28349.733434][T14262]  split_vma+0x5a/0x80
> > > [28349.737409][T14262]  mprotect_fixup+0x368/0x3f0
> > > [28349.741992][T14262]  do_mprotect_pkey+0x263/0x420
> > > [28349.746750][T14262]  __x64_sys_mprotect+0x51/0x70
> > > [28349.751513][T14262]  do_syscall_64+0x91/0xc44
> > > [28349.755920][T14262]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > >
> > > The writer only changed struct vm_area_struct.shared.rb, but the read=
er does not
> > > care about it. Thus, no harm even if it has been shattered because it=
 will be inserted
> > > into a new place in the rbtree.
> >
> > So this is a race between a field update and a copy of the enclosing
> > structure?  I could imagine cases where I would want KCSAN to complain
> > about this.  Would marking specific fields as being forgiven for data
> > races help in this case?  Or are there other situations where data
> > races on these same fields would need to be detected?
>
> We discussed this before:
> https://lore.kernel.org/lkml/000000000000b49e190595aa39fe@google.com/
>
> We just can't infer it's safe, since the fact that the read value will
> be discarded/overwritten afterwards is nothing we know about, only
> whoever wrote the code.
>
> Something like ASSERT_EXCLUSIVE_MEMBERS seems will become unreadable
> quickly, e.g. for large structs such as this one It just wouldn't be
> ergonomic or readable. Let's try to keep it simple for now.
>
> This might actually be a fair place for __no_kcsan:
>
>   __no_kcsan  /* @orig may be modified concurrently, but we will
> reinitialize our copy. */
>   struct vm_area_struct *vm_area_dup(struct vm_area_struct *orig) {
>
> Thoughts?
>
> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZ-m9djWoTMne8WPffDiW%3Dv5NE0vrqrD8O%2BoXUfYr%2BKHw%40mai=
l.gmail.com.
