Return-Path: <kasan-dev+bncBCMIZB7QWENRB3OQ7TYAKGQEZPICH7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 450A013C6BF
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 15:57:50 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id k16sf7256264vko.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 06:57:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579100269; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xpsx1BQ612t1IHaYF7OaaPrNRFb8wJGFztPysO1r8N2Xbv6RSY/RLIKR7xpkrjxngx
         OI5PaPwp/sddXMX7Rz+FDGJlBmINbAeat/b8ZS3EfRqUWqZUisZaLSF1RuSPDKd4Hx9W
         5AWr5rd0cVKAkyAnsTdrqzPEtE7sKQHvVSIktv5Ezvcih/kPYE/fvAHPxF7TqikbMxmc
         ozzLn7SBYbittpzEpHuIgZsBIrQGbGiHd/D3/hBqQiZBTVJUriHouFEjTfe9XCPkcBPg
         WZjNvq6ItA0Wqaigmy9T+aDmLntPEnnIIXD1Di6AFuGaU0TEnbh4DndL8Pf5pwrPZh89
         qAbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ob3McZT8Oc3WgtLjAEE22vBM6UZ6hYjqZCOKzqmdr7E=;
        b=lclsjlC1KFu5FS4uT5pflsSMUZP7Kw1LjAoBZWVQ41JbGAPfHdE33BqIabVrP/4t9M
         +fucbYVjhAGzfRbpDYoBxeRCsrb6+wjRY++kcAhZkDWdSjCqJhsNPYBsIOkZA/UUm/sI
         wTZ7OVdT7By1ZT69gxp6RGlGAVYY8mHp7cNRj97dpDgqrP834ZOCd/eDVx5+6ROmNKyx
         UCQoTHImdBfI3tkvOJ1utvYMLSQorO00V7PtEG0Dfor5XetHdNcV6iEPHkB/QUpairyg
         ISG3eMwylGDG6q87XMFHlBKfBaNugfpFdWu/r7F4ZVBzW8kOJdppn9iFTTm6J79fhTL8
         98Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qNEZxBFu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ob3McZT8Oc3WgtLjAEE22vBM6UZ6hYjqZCOKzqmdr7E=;
        b=oagKw4UZFQi57hI2uWods3SpeFiCTidwwPSXH8Yu8kKgmwcIL2+Axxb67OhxtB4TbW
         zJ24nSaWaqc9g0nVL6LX/e39FCBskRXRwAALg0kbHrDxyWV2LmQG4mXpZ5BH4+taexfo
         r5tRLQjs6c4tNmwNqecMrkev0Xx+G/Svm5crdCm63RNxR8G93rOA7I29vhjD2IiWvtZU
         Gcq8H5eAqi+yDR86RPqrvVjgRcyjlxEaLkamWbWflAc5eDRQ6IHXcZ1Hq7eZD7KNo1lF
         8x//M0W1ni8C4m2BUB8A0YBx076Rz3YaLO0JtyZVrmGUVKC5bX3PSRU0lwHL4urpE8+E
         IAcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ob3McZT8Oc3WgtLjAEE22vBM6UZ6hYjqZCOKzqmdr7E=;
        b=ElHsFIUf7uf24UPIydDDKWtLSyYw6VgGM44gPFPu9za45t4cccTZGT41xSA8iujAsI
         fFxgnIObdqta/ieqZTVOCzH2bVNVOEzDjtQCpo7r+OUtRhYyGlXiBq+vCNY7aSbjorPc
         rp58+WyPJhW7mk/j8UVP/zdjyqKykus6LomaQa3wUf8pzgEetSJ9KXrF9YoAztVFrCte
         YVcmAGUjuqOC0j8edHg3yHUvs/2Mnj8A9KlPg3vMurIuBHczDSPg01PWio7qAEw8O/+W
         KN/ufahOAFCNvJDt9SmqQxWdydM2a2vm204ZdelAuGV0A5t0SveeOjCW4BsktZ1RIVPc
         a95g==
X-Gm-Message-State: APjAAAUQsH6aX8dkY0Cy3I0Q+zo350is+mhn0enPGmWR9KANWd6pan7E
	rlDZubLQHl3RLSVIkABaZD4=
X-Google-Smtp-Source: APXvYqziUpJfu7ELVPcDyUI4KuDCVjMK5Tlbe6wbNqvszkp24x3CAi7hvB6IwOKQcYrw0v9bDiOUHg==
X-Received: by 2002:ab0:2644:: with SMTP id q4mr17276116uao.101.1579100269073;
        Wed, 15 Jan 2020 06:57:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f996:: with SMTP id b22ls1608146vsq.12.gmail; Wed, 15
 Jan 2020 06:57:48 -0800 (PST)
X-Received: by 2002:a67:f054:: with SMTP id q20mr4736571vsm.17.1579100268639;
        Wed, 15 Jan 2020 06:57:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579100268; cv=none;
        d=google.com; s=arc-20160816;
        b=OWCPPqfJ+CYZ4w+cw/4jZGUtsaH6Ha+aKIb4mWt4y7dx0ixclgRYKKJ4unC2SszBlM
         RoJ/1LnpUso6K0JJmx5qhmFnMrFXR5JwYO1+7SGrsvwPSfxuyxlbhdCnwTySmxAuPPb6
         ZVTi4LeEDYdbfDuvs0AyBz6nUJn0sv2y9fXydeK4JqcDl1ZImg5bRXy18clSWecOWnPH
         MWGhOx7HFAP00BhDdNe5sbA9uImguM9N2rtn7+0X4z1DWEVFCgl6QXFl5FfjsnWzXgtx
         u1+xKA3ouoeoNblNwjcqPVMXEJMVhC9zo1pKIwf6nFCjfqv4+aeGDugYtDSgM7FhXgIJ
         Q2zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NmZV6ZNor/aMnsybdf9Y2H14ROOnyA+MZIhvgXeb7nw=;
        b=WimtRyveQZdtTGxy0QacY6lgBKsuLqOqXxiroQAJ234CVBaXDYp2zqs2jhzEJXgh7G
         KHBwmLpwHHstU6jANIZhuTl+fhuoDc8CsPdbzTybvZK2sbhcNGx2rFV5Bd8hBU5h62zF
         3EwRj/HLE9dH3dSK9w/k/U8v6aFuQtq/15BjYGeMcnoINTmsqYXZnNaQgFPJEBo5Qyd2
         1jjHf7q9/ikmUJICTb0taZKvZKJC3HhT2ar9ilRghjmItlpwrd9HfrrcOCHdlggVVD/w
         K30tTSGpCX/P7t0vVepjR54rZMkccrf23o0cN7nPUgj93E8ECeFfyTcKWmE9sbhScRh0
         RyWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qNEZxBFu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id w4si772106vse.2.2020.01.15.06.57.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 06:57:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id dp13so7458743qvb.7
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 06:57:48 -0800 (PST)
X-Received: by 2002:ad4:4810:: with SMTP id g16mr25308035qvy.22.1579100267932;
 Wed, 15 Jan 2020 06:57:47 -0800 (PST)
MIME-Version: 1.0
References: <20200115063710.15796-1-dja@axtens.net> <20200115063710.15796-2-dja@axtens.net>
 <CACT4Y+bAuaeHOcTHqp-=ckOb58fRajpGYk4khNzpS7_OyBDQYQ@mail.gmail.com> <917cc571-a25c-3d3e-547c-c537149834d6@c-s.fr>
In-Reply-To: <917cc571-a25c-3d3e-547c-c537149834d6@c-s.fr>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 15:57:36 +0100
Message-ID: <CACT4Y+Y-qPLzn2sur5QnS2h4=Qb2B_5rFxwMKuzhe-hwsReGqg@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
To: Christophe Leroy <christophe.leroy@c-s.fr>
Cc: Daniel Axtens <dja@axtens.net>, linux-s390 <linux-s390@vger.kernel.org>, 
	linux-xtensa@linux-xtensa.org, "the arch/x86 maintainers" <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, Daniel Micay <danielmicay@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qNEZxBFu;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Wed, Jan 15, 2020 at 3:47 PM Christophe Leroy
<christophe.leroy@c-s.fr> wrote:
>
> Le 15/01/2020 =C3=A0 15:43, Dmitry Vyukov a =C3=A9crit :
> > On Wed, Jan 15, 2020 at 7:37 AM Daniel Axtens <dja@axtens.net> wrote:
> >>
> >> 3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE=
:
> >> memchr, memcmp and strlen.
> >>
> >> When FORTIFY_SOURCE is on, a number of functions are replaced with
> >> fortified versions, which attempt to check the sizes of the operands.
> >> However, these functions often directly invoke __builtin_foo() once th=
ey
> >> have performed the fortify check. The compiler can detect that the res=
ults
> >> of these functions are not used, and knows that they have no other sid=
e
> >> effects, and so can eliminate them as dead code.
> >>
> >> Why are only memchr, memcmp and strlen affected?
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >>
> >> Of string and string-like functions, kasan_test tests:
> >>
> >>   * strchr  ->  not affected, no fortified version
> >>   * strrchr ->  likewise
> >>   * strcmp  ->  likewise
> >>   * strncmp ->  likewise
> >>
> >>   * strnlen ->  not affected, the fortify source implementation calls =
the
> >>                 underlying strnlen implementation which is instrumente=
d, not
> >>                 a builtin
> >>
> >>   * strlen  ->  affected, the fortify souce implementation calls a __b=
uiltin
> >>                 version which the compiler can determine is dead.
> >>
> >>   * memchr  ->  likewise
> >>   * memcmp  ->  likewise
> >>
> >>   * memset ->   not affected, the compiler knows that memset writes to=
 its
> >>                 first argument and therefore is not dead.
> >>
> >> Why does this not affect the functions normally?
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >>
> >> In string.h, these functions are not marked as __pure, so the compiler
> >> cannot know that they do not have side effects. If relevant functions =
are
> >> marked as __pure in string.h, we see the following warnings and the
> >> functions are elided:
> >>
> >> lib/test_kasan.c: In function =E2=80=98kasan_memchr=E2=80=99:
> >> lib/test_kasan.c:606:2: warning: statement with no effect [-Wunused-va=
lue]
> >>    memchr(ptr, '1', size + 1);
> >>    ^~~~~~~~~~~~~~~~~~~~~~~~~~
> >> lib/test_kasan.c: In function =E2=80=98kasan_memcmp=E2=80=99:
> >> lib/test_kasan.c:622:2: warning: statement with no effect [-Wunused-va=
lue]
> >>    memcmp(ptr, arr, size+1);
> >>    ^~~~~~~~~~~~~~~~~~~~~~~~
> >> lib/test_kasan.c: In function =E2=80=98kasan_strings=E2=80=99:
> >> lib/test_kasan.c:645:2: warning: statement with no effect [-Wunused-va=
lue]
> >>    strchr(ptr, '1');
> >>    ^~~~~~~~~~~~~~~~
> >> ...
> >>
> >> This annotation would make sense to add and could be added at any poin=
t, so
> >> the behaviour of test_kasan.c should change.
> >>
> >> The fix
> >> =3D=3D=3D=3D=3D=3D=3D
> >>
> >> Make all the functions that are pure write their results to a global,
> >> which makes them live. The strlen and memchr tests now pass.
> >>
> >> The memcmp test still fails to trigger, which is addressed in the next
> >> patch.
> >>
> >> Cc: Daniel Micay <danielmicay@gmail.com>
> >> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> >> Cc: Alexander Potapenko <glider@google.com>
> >> Cc: Dmitry Vyukov <dvyukov@google.com>
> >> Fixes: 0c96350a2d2f ("lib/test_kasan.c: add tests for several string/m=
emory API functions")
> >> Signed-off-by: Daniel Axtens <dja@axtens.net>
> >> ---
> >>   lib/test_kasan.c | 30 +++++++++++++++++++-----------
> >>   1 file changed, 19 insertions(+), 11 deletions(-)
> >>
> >> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> >> index 328d33beae36..58a8cef0d7a2 100644
> >> --- a/lib/test_kasan.c
> >> +++ b/lib/test_kasan.c
> >> @@ -23,6 +23,14 @@
> >>
> >>   #include <asm/page.h>
> >>
> >> +/*
> >> + * We assign some test results to these globals to make sure the test=
s
> >> + * are not eliminated as dead code.
> >> + */
> >> +
> >> +int int_result;
> >> +void *ptr_result;
> >
> > These are globals, but are not static and don't have kasan_ prefix.
> > But I guess this does not matter for modules?
> > Otherwise:
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> >
>
> I think if you make them static, GCC will see they aren't used and will
> eliminate everything still ?

static volatile? :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BY-qPLzn2sur5QnS2h4%3DQb2B_5rFxwMKuzhe-hwsReGqg%40mail.gm=
ail.com.
