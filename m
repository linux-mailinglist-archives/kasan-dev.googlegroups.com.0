Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEGWXCMAMGQE5WJ6MVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 37BDE5A6729
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 17:21:54 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id s13-20020a056a00194d00b005385093da2dsf2483012pfk.13
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 08:21:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661872912; cv=pass;
        d=google.com; s=arc-20160816;
        b=tL3a0AD1RK7gPKAiaiRjN9q3Y9eMBAswG9WPMSC6rpuY9irDRgWbyi876dEpNcsP/y
         NuKq5eb4wBmNZDlB3QaIalwiNJ1KLAV5VVN+UTXW9s9HGWiPu0b2B5OjPJgIHFnX+9pc
         yKd6mW/F3h/vXlsZsn4T3jw4xUne71ILRx0buUS9b+46rb8XbWKzRhsFxPrPBj93THzN
         /xoIjMIIi0XPnVq+CVsFB2wsUQqQvtGBZ0KjDft5st2+6Bg4+uQKbFFCn4+8470iLQQ+
         4002LfGlM1CVGVJ6wokv8mMZM/TfYoamE30sMxuGwJWTsiwmleUJ9kQOZ2+J4V2Lj7wu
         MgUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+MOYBj8fpvMFki1+iESmldmRwKLpq1LfN6BTYn1jrLs=;
        b=KqEBSgGizHHqcdAgFXhRDz78NmbNtff8QthQHKCatHM+jLCrrD7ffzwBdPhQspDZwc
         I+GU8Os73kJ5kGJaLRY92tXTGWWMsh1KuELfAaPnNYBJWvuR49JOAU1fNL9l05u4uLcU
         fHFoGzuU9i67UPlPkLmEVjpkIU+pel/JJ8gqMkmPhVK7OqW6xF2lJ9m23i3S8lgwrPUI
         iWEagCGfLqoesjCVUs9gdM6SjEwvRCVi6Fds++B0AxvU2gG2YE2GzFjBoqafm2H7nlkS
         xUko1XA3OiNE1B6URE4nSFrt/rompaOH7VhhzT96Xf8h8UwG0y6TS6AEoVt/NDuuFowH
         hkeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YBKdHJyH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=+MOYBj8fpvMFki1+iESmldmRwKLpq1LfN6BTYn1jrLs=;
        b=gdQiYN4WIJn3erhtQDVMMwqON7TkbLw1vpDiZmW1yhujHqtv8uTUNck/B0qnloSje7
         UNgN/N0aPUoiTa8f7TYSaoj0HOkq0m50HhW9/LO+6HRCWclYKpAUW1jWsfnf93PKU9eQ
         RlMkrzR3XG0R/28VkXpUhHjLwk6SIR+Cm4vAObo7or0KFRsJxKMk75ecaHtCcV3Mku+s
         r6MR34Xn/ykN8KWYZ3doPn1nr/vGUttmpCINp2pkPM0+tutyXC52hOL7f/Y0M+bY/2we
         wJY8xP1PxWKHY0c6aWSKJkYCnAlIyNsF3JSkNTz5C80F88Kj5KA/EtYeS8EwFJD5b7ei
         JYOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=+MOYBj8fpvMFki1+iESmldmRwKLpq1LfN6BTYn1jrLs=;
        b=L6ha5bF3PRv7kUbcuTgziXNj6VwLqZES/R9lwjTMj0iebZtBLYBKLSrUv7gg8VDgr3
         6YM86DEk3FzxRNB1sAYkIIHAyXV5tdX/k351tfKrrz6dnvqsc70sORh+T9krsqf5kcYs
         IEqWUbOPFu33zh+bd0bq1XqpCB5qbgUhW1EWr6RuyaSjCzsLNa8ZDmEoNWBx5H6OuLEB
         Ru8NhyXp5Xtj6RPFuB6NPuZA9j++MbKV/0TepcnqSYC1K1horvC5xLT9h3YFr0AizQM3
         9DsJ5b8/kQThGuPNK2TdDT4eyS8Ug0x+hH4//yjyY+52Au8IQ1Izp5GrLMZ4oOtUn5WM
         WLpg==
X-Gm-Message-State: ACgBeo37lMpqj2cF5iwGQ1vpqP66AOiKohOKd3cXWL3w2b6aqL+zYwO8
	u2N1l1lIoBm8xP2cBkaViLE=
X-Google-Smtp-Source: AA6agR5XRbbzgdPqrS+zF28Gm2hrpkFWlArmZ0oiARbP0x38+rhhh49pdI2cDnRTc7OUPodpdh3k9g==
X-Received: by 2002:a63:5d4e:0:b0:41d:dcc3:aa85 with SMTP id o14-20020a635d4e000000b0041ddcc3aa85mr18287665pgm.324.1661872912673;
        Tue, 30 Aug 2022 08:21:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2b4b:0:b0:429:ead7:6932 with SMTP id r72-20020a632b4b000000b00429ead76932ls6188230pgr.4.-pod-prod-gmail;
 Tue, 30 Aug 2022 08:21:51 -0700 (PDT)
X-Received: by 2002:a05:6a00:23c1:b0:53a:9381:2987 with SMTP id g1-20020a056a0023c100b0053a93812987mr1165478pfc.16.1661872911802;
        Tue, 30 Aug 2022 08:21:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661872911; cv=none;
        d=google.com; s=arc-20160816;
        b=V8dULM8QChcfE/zdE3mUkaxoarcXfUWu4RPdB6hH8Gi3MiC5As53YDxHR3clo73z6l
         +KV+Ap3cTI7eU2fdUjMIyy2P48jGMc35jqnD5houa2Wjm2n7lxldyCs5W8vUtO0sQMSc
         al4FUTOqh3z7ujFxIKLxgXA/j+epd0aNCnPilxlO2iOz5bQz1PnxSa2Dox3wVDaTy9TR
         KOgppuArOFhxrMWuqOW0kSocfDNxlY94qqRvsP9w3sK4qOgWJ2KKlA51VAsqUY8WJZA5
         e4nfkLRqFjUaBE88auxnc174ICDx5DtTORdtoNKOqE60i81qNhb7xBJB+EBf3ZpHdQF1
         bCzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uqfm/6R6fkKJnneVeLdLuiqY/mudrNlydjep/s3PwB8=;
        b=NjknR2X3UCra/Z0dikB7b2IDmjADmqGa06rIJUh6nSKSwUUdYWXMG0e9PEcBhc2R8z
         za8fWcMOan2naLgrGzwuHGUslALAPqq4h1U/Ape83b2kNOUZZ50ahfTrCryZLNFVXgLc
         u5UC0YTb+//CqwqWmRTSWZ1MwaxxCYaZq3lYrUoIimiPvb9L0aQ/NrCJl7FkqfbsPrs3
         n6aLPS/BoYzMDJ72DYr46XBw/WwnCSxVKvp6X5IYIFGXcW0CXf01VnwERw2sJ4jjkSPh
         0/Iq+ISwZWAleQ/9l8gr+uAT5MT82KeVRjjnRHCkoPKZbNT+uyrHWU9MZAB2LR1Gfu5a
         ddGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YBKdHJyH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id z198-20020a6333cf000000b0041e0e935246si120533pgz.3.2022.08.30.08.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 08:21:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-340f82c77baso165961687b3.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 08:21:51 -0700 (PDT)
X-Received: by 2002:a81:b71c:0:b0:340:bb98:fb38 with SMTP id
 v28-20020a81b71c000000b00340bb98fb38mr12971069ywh.428.1661872910913; Tue, 30
 Aug 2022 08:21:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <51077555-5341-cf53-78bb-842d2e39d1ec@csgroup.eu>
In-Reply-To: <51077555-5341-cf53-78bb-842d2e39d1ec@csgroup.eu>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Aug 2022 17:21:14 +0200
Message-ID: <CAG_fn=V6aQZGkq0HdhzXFCm1Qbn6GHdQd0dYESBup4Lz7hXV5Q@mail.gmail.com>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YBKdHJyH;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Aug 30, 2022 at 5:06 PM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 26/08/2022 =C3=A0 17:07, Alexander Potapenko a =C3=A9crit :
> > Use hooks from instrumented.h to notify bug detection tools about
> > usercopy events in variations of get_user() and put_user().
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > v5:
> >   -- handle put_user(), make sure to not evaluate pointer/value twice
> >
> > Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1=
859fdf5cc485a2fce
> > ---
> >   arch/x86/include/asm/uaccess.h | 22 +++++++++++++++-------
> >   1 file changed, 15 insertions(+), 7 deletions(-)
> >
> > diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uacc=
ess.h
> > index 913e593a3b45f..c1b8982899eca 100644
> > --- a/arch/x86/include/asm/uaccess.h
> > +++ b/arch/x86/include/asm/uaccess.h
> > @@ -5,6 +5,7 @@
> >    * User space memory access functions
> >    */
> >   #include <linux/compiler.h>
> > +#include <linux/instrumented.h>
> >   #include <linux/kasan-checks.h>
> >   #include <linux/string.h>
> >   #include <asm/asm.h>
> > @@ -103,6 +104,7 @@ extern int __get_user_bad(void);
> >                    : "=3Da" (__ret_gu), "=3Dr" (__val_gu),             =
   \
> >                       ASM_CALL_CONSTRAINT                             \
> >                    : "0" (ptr), "i" (sizeof(*(ptr))));                \
> > +     instrument_get_user(__val_gu);                                  \
>
> Where is that instrument_get_user() defined ? I can't find it neither in
> v6.0-rc3 nor in linux-next.
>
> >       (x) =3D (__force __typeof__(*(ptr))) __val_gu;                   =
 \
> >       __builtin_expect(__ret_gu, 0);                                  \
> >   })
>
> Christophe

Yeah, as mentioned above, I should've put an empty declaration of it
in include/linux/instrumented.h, but failed to. I'll fix this in v6.
The "real" implementation of instrument_get_user() will appear in
"instrumented.h: add KMSAN support"

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV6aQZGkq0HdhzXFCm1Qbn6GHdQd0dYESBup4Lz7hXV5Q%40mail.gmai=
l.com.
