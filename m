Return-Path: <kasan-dev+bncBCT4XGV33UIBBB5FWSMAMGQEJX7R2CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 548B95A547E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 21:24:58 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id x9-20020a4a8009000000b0044a835beeddsf4015915oof.7
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 12:24:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661801097; cv=pass;
        d=google.com; s=arc-20160816;
        b=rS0DdiOV/b5PTWC9qsUDXOysxB2XXx6geW9cVxOidFcdTmch6kwi3vzMJuyZRMOIgH
         BmZ7rl01HBzqm/VuUfSEs/vQ4RWxtaiUCgkZPsg8WIKBcrT+YMrtbzdfo1YY1RNa2EYW
         jTsfX4MUYDxPNPDo1hBJIXeQkgs1RssnM9Q4f8WM/z7400crs7H6AxAjOZF8IMXDCJ08
         KFPBnojhErzLMJ3R1KLZUpNk6kLhaisCzkCMnGDI5xEb8451Ya6tRIpds27cBoaNw30S
         AsJ3wN9ELiseasdEcwqz2Mt7SpmOx4WwcW108i6WfQ+zb8l+G2QeHqIO6cfJ04PNrDZR
         PkZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=ZbRknFvLHzAt8q/rRsl4pJivJ+BRGcijRxEzHYMDRgg=;
        b=gLnJZOv1Us4NYCKPvAova+JVtGf5AQON37WAGjdPcvwempDvKvueWtDZwNhWN07Icx
         YgYns6rbFTwHcehBSa/JdvBfhkrxEOpqNHq8klJDifeGmbC+jaVcu97hv7tyaKoNrM/C
         3DNuCf/krLAawLqNwrFYwTlJU+3eWOwVNFlmVv3Tf7NDsQkvat5URYcgI9Cw7/oBeWUl
         zFjN8coWotU0F6AeDlRG2QAFCzUKdjBXbCzatZR7GEzj2m3R+sVc0QQwcFsKkD9E007S
         vhZiD7sTBf+b58Al+iMJh+P+F4rY9DuQPenOuYyIopDFB3wEG98fglMkDzfbhpxcinTR
         FeDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="e6GuB5/Z";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=ZbRknFvLHzAt8q/rRsl4pJivJ+BRGcijRxEzHYMDRgg=;
        b=C8Ds3YRkXUUWmuVWQqNKk9/Xs1Orb2TmCLh1MeTAaXW5nWi19eCgglif/SO7VJw6Mt
         dm69+7ZZKLWW1KCeANU9FehqVgL9zYSTHwBARuFyZV5hntcjeK1Ozeom6sEgoF5IRPQD
         q+tJqSfy9iEAGiuSNXd6WrpoCYvv5mbH5CU8SbiWwgjXMg5uh2kwavqLcyN8/xO3Pbtt
         7J/BjD5BUnxDeGlSrXcBZuxGKOLK4lnYLwni9ujORjPiU6RI86A7jEzADLkSQW5RTBO6
         6xp3SPeU5ITx2PG6tJEiqJtmUY/exJJIFE0ovcPNQ12kmhqvYqHZJ0blyMeNtiuE3+j8
         xaxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc;
        bh=ZbRknFvLHzAt8q/rRsl4pJivJ+BRGcijRxEzHYMDRgg=;
        b=Q9VONpIkgwFzQa+Vx2TfZxl+htP92B44mtnMnRir/BoatRi3MWOWepVxj9h9mvWbey
         SxGdfBcB70QtkeoYA0e1Gz5aCennGF/yl08V5oC9n9fODFyP8OQKUV4cG/XSUu7IO/N3
         YqRIDFD1ILF+pVQdLvlm05HrGxuaBeiOKo7NzlkFgXqN6So3V9qQ8IPNAGtbiPP75TKH
         xP5QjcA/4QTKNALplf6TlOGjPPp+SFOrpJo2hJt7lbLA/zPdGnLdgB1SbIoVipnLAM/7
         KTxC9r/gEr6yaYblLxZUpWLBj1JXaJTGS23JCUFECi7RK9+LZXv6vPQOjvOrvkTTbP0c
         iw8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3BtZUNPJ41BKL0uSch+6LW2x5e0EH8lswb6CueituObOrDsgFp
	Ja0en52q+t7CsEABvQHdfR0=
X-Google-Smtp-Source: AA6agR65U53Ruykt5m9m5UH/Q8PIDpNHtlIlTxyJf4+RZyI8Vx2pSsY1G9WBhz26i+yBcBfc1KvgHA==
X-Received: by 2002:a05:6870:6487:b0:11d:3f21:869a with SMTP id cz7-20020a056870648700b0011d3f21869amr7908745oab.164.1661801095643;
        Mon, 29 Aug 2022 12:24:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:91e:b0:638:adfe:6a17 with SMTP id
 v30-20020a056830091e00b00638adfe6a17ls1614776ott.3.-pod-prod-gmail; Mon, 29
 Aug 2022 12:24:55 -0700 (PDT)
X-Received: by 2002:a9d:6ac4:0:b0:639:3c4d:f99f with SMTP id m4-20020a9d6ac4000000b006393c4df99fmr6846900otq.188.1661801095095;
        Mon, 29 Aug 2022 12:24:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661801095; cv=none;
        d=google.com; s=arc-20160816;
        b=EcvNB0NJgiT7oqTmqdUM7eAcNpTO65ZIosyuhICZo4T/ahLu7/pq8PKVslQcGUczEC
         fbU+AxLfgDYrkMu0mmoqIgHz+SFH+HwQHBXKPvlJQU24mZQqI9SUJhae3VWxKdWIAkBk
         ZgTkY2qrRkVrMnkNgaUWOMN0Ebzqya+ilOnuiKR3o5DBMF0zzxum+mRWGml5U3vEd6bC
         6SnVWec9nWMiZhcRGVa4q2cFhh7m6VSGJFsWKo6S69ENiLtXFUA/LogaaqABgKuujDzA
         GviqJENWnGOXsPOabNRPQTDr9ZBTt3Y1vVXHr4LyMnO7SBHWPZefV5CuErokuPxjcHZ0
         tdhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/NTlFoZkG2bUm4RJ3DTKShJCWdzBXxO10ZwSGSS0Xho=;
        b=uCqnT6PI6TpZ4zs48bs3PGzZnmUW+NhDWFHPzpK+YSW/OBKbLkEOgtmmdhCdLrJOH9
         xjoikDDDQYWxqMhYQdwioJdQPpVAylytnVWy9cUu58x4tD2bihCrg6zS4dMHFR4a4Jdu
         yQ9GVSURj54CafBl8ExZD34mbkKjd+ybB2GbLYBWOOBgKPQk7nFje8S0YO5VTUXsynnp
         6TyiUOG2g/MSaFwlXCReg6ez2MOitp8Lh9Lvkhw/veswYf3BoFmGyGsaJK+QspfQ1NoQ
         tQJY+J0BqttpKv8xC3ppCdTdhrGn4pPQNZEYydooFoj1EccxE3txlkxmR1Nq619luGq5
         wdCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="e6GuB5/Z";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id u18-20020a056870f29200b0011ca4383bd6si987165oap.4.2022.08.29.12.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Aug 2022 12:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A47E66121E;
	Mon, 29 Aug 2022 19:24:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C5E72C433D6;
	Mon, 29 Aug 2022 19:24:52 +0000 (UTC)
Date: Mon, 29 Aug 2022 12:24:52 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski
 <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
 <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner
 <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum
 <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev
 <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, LKML
 <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user()
 and put_user()
Message-Id: <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
In-Reply-To: <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
References: <20220826150807.723137-1-glider@google.com>
	<20220826150807.723137-5-glider@google.com>
	<20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
	<CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="e6GuB5/Z";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 29 Aug 2022 16:57:31 +0200 Alexander Potapenko <glider@google.com> =
wrote:

> On Sat, Aug 27, 2022 at 6:17 AM Andrew Morton <akpm@linux-foundation.org>=
 wrote:
> >
> > On Fri, 26 Aug 2022 17:07:27 +0200 Alexander Potapenko <glider@google.c=
om> wrote:
> >
> > > Use hooks from instrumented.h to notify bug detection tools about
> > > usercopy events in variations of get_user() and put_user().
> >
> > And this one blows up x86_64 allmodconfig builds.
>=20
> How do I reproduce this?
> I tried running `make mrproper; make allmodconfig; make -j64` (or
> allyesconfig, allnoconfig) on both KMSAN tree
> (https://github.com/google/kmsan/commit/ac3859c02d7f40f59992737d63afcacda=
0a972ec,
> which is Linux v6.0-rc2 plus the 44 KMSAN patches) and
> linux-mm/mm-stable @ec6624452e36158d0813758d837f7a2263a4109d with
> KMSAN patches applied on top of it.
> All builds were successful.
>=20
> I then tried to cherry-pick just the first 4 commits to mm-stable and
> see if allmodconfig works - it resulted in numerous "implicit
> declaration of function =E2=80=98instrument_get_user=E2=80=99" errors (qu=
ite silly of
> me), but nothing looking like the errors you posted.
> I'll try to build-test every patch in the series after fixing the
> missing declarations, but so far I don't see other problems.
>=20
> Could you share the mmotm commit id which resulted in the failures?

I just pushed out a tree which exhibits this with gcc-12.1.1 and with
gcc-11.1.0.  Tag is mm-everything-2022-08-29-19-17.

The problem is introduced by d0d9a44d2210 ("kmsan: add KMSAN runtime core")

make mrproper
make allmodconfig
make init/do_mounts.o

In file included from ./include/linux/kernel.h:22,
                 from ./arch/x86/include/asm/percpu.h:27,
                 from ./arch/x86/include/asm/nospec-branch.h:14,
                 from ./arch/x86/include/asm/paravirt_types.h:40,
                 from ./arch/x86/include/asm/ptrace.h:97,
                 from ./arch/x86/include/asm/math_emu.h:5,
                 from ./arch/x86/include/asm/processor.h:13,
                 from ./arch/x86/include/asm/timex.h:5,
                 from ./include/linux/timex.h:67,
                 from ./include/linux/time32.h:13,
                 from ./include/linux/time.h:60,
                 from ./include/linux/stat.h:19,
                 from ./include/linux/module.h:13,
                 from init/do_mounts.c:2:
./include/linux/page-flags.h: In function =E2=80=98page_fixed_fake_head=E2=
=80=99:
./include/linux/page-flags.h:226:36: error: invalid use of undefined type =
=E2=80=98const struct page=E2=80=99
  226 |             test_bit(PG_head, &page->flags)) {
      |                                    ^~
./include/linux/bitops.h:50:44: note: in definition of macro =E2=80=98bitop=
=E2=80=99
   50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (uintptr_t)NU=
LL) && \
      |                                            ^~~~
./include/linux/page-flags.h:226:13: note: in expansion of macro =E2=80=98t=
est_bit=E2=80=99
  226 |             test_bit(PG_head, &page->flags)) {
      |             ^~~~~~~~
...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220829122452.cce41f2754c4e063f3ae8b75%40linux-foundation.org.
