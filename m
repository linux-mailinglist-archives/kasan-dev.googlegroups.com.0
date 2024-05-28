Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCXA22ZAMGQE3PIFRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id CE6AA8D185C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 12:20:59 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-36da6da1d98sf6542315ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 03:20:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716891658; cv=pass;
        d=google.com; s=arc-20160816;
        b=fxpP88g6CbclOY3Ki9yFBTZjoaWkdq8MHV/ykRSKihZqdy9jf239PeZj7WCP1tceHz
         Rw6uQAme5Czf2ycgVh64xXt1yZGu6wpVL9K7EKEjlOpS+U7yY9XzmZQamWnBnUc/RDSi
         Fl2xnh4qQHHFrpbYM3uajNLrbtVR1nSvgAcH3tMpxe1pzQ9qkJPvXT4rPVhUwW9mW29e
         nQL8M9sGFw8GrJ563ntiYpdaYbd+ZhcIFnwNdWJfXB88TOwyWHEz3FFRZjpdtOgq66ES
         8mMIrtA58aDiVUANyoaCEQThXcnag/OOYz65b7xbXFPZgKWB6GJcFBMNa0c3rEZbJ9ac
         wvww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gxC/khZqshqhM54Qfl4cqWeIFzWhbDDTng/l4YAycZM=;
        fh=vfRJ2lBeD+UwEOT7siMbs7FbP1bO3tCssYvM+9CkFZY=;
        b=nW7WprT+MeVYY6WpQoC9ArCh3o50QHokJ+cFhul/ieHU6cBU2RbXjWPLPoE0Rl8fOa
         x+/GClFze8rtDum8XesJGadERUq4BfQpEvyycpoO4faiMdkoWLL/tgII2AjnuGEGncrH
         mSeaShyy6p/4oYYuelugUI8XV7v5GuTcpKecEUVDryrcNwKCGXXrpG4eGJdv27ygr1gy
         PGNp6jOqLHNmH8KRrCn/Ib4gDu33P39gktRfsYdxR75GMzQnUnDoPBf7Zb8+gu9rNLGK
         RSJp/Dbs7HrAUn6vZUB5/jikYCbuErfT+xzWFgtvWeqrOB250BpRxScTBMYl21DctJHw
         ykvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mDr0uYQ+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716891658; x=1717496458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gxC/khZqshqhM54Qfl4cqWeIFzWhbDDTng/l4YAycZM=;
        b=LDD55J6DoJ4OZp521ZWkCOQ7mrgMq6/V7QEg3YNLB18HH/e+CqPW/y/9uvr16CLcyD
         n/8Z6Up8UoOWd59srNG2zw/dMCOdskURIDlQnUaWCmrTJu031jPedV5FNWBPy6NwnqnS
         yqaPFx58QieVngjF97wbHyKHv27oq2cZidin801JTm4sZGH/YOGP6YUXaZ6xiPgf/Qg8
         qUk3QZHi2P8mKjHWWT3Fn1CtLB/kOqOdRHFEZtv9oKqCZMXdkD48xdSWew3tAON0dbNx
         x179C5leq4LBmxjjzCdFDtR93L4d7hoH1N3IKdXjvIQ/hzdbO8cKb4SUv2gxy5dQMnl1
         zlaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716891658; x=1717496458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gxC/khZqshqhM54Qfl4cqWeIFzWhbDDTng/l4YAycZM=;
        b=afCmrSLO5b59bEI+S9nSMXud3kuKa98cKboG9cTJ6hMKfEL8inrdxZJ91ZrhiB5Qdn
         wTZ/OyVz4lWrAmWxEIWPEwWiApb9iVQ5VS4CPZP8OnSKFLkySvxYh9sbCdrBfmx4BX9v
         lVDA2NgKwSNA7R8dFe5w/76LY6O7KK/dwkjq7Fy4NFrhSsSZ2xaXSCiocQV8CXULKZlu
         aFSIH3JWqyrXF9aiycu3QvOJJNoKuTiul6MseQz6ZuGXbSz8hP3UpTdK4g58ipuX3WhH
         XsSC2nfdlQbf6BQL9XnKyWtB7lpLuBTDzaUE2GQ7nugHUPshSbM2Cg1bl5rNH5zm6Kex
         vDSg==
X-Forwarded-Encrypted: i=2; AJvYcCV2EFLi3+0MJptkRb/c8w6RX8UMTdoh4Kvet5JPjhYhCfbd1jvDdLFFTms/lgw3sd9zgF3AUlgOutpj73W5iAfJcmE7JOcXyg==
X-Gm-Message-State: AOJu0YxfFVym840BxJmsrjV0qhCajCyTHf1csZ3BPy0/JmoaXYOR9ZwZ
	pMDuuUwb0Woo0cahBK1oB7l6UQpE9Vasuez4vLW9LS09BLYPicEp
X-Google-Smtp-Source: AGHT+IH+RY829lj++y9tTwLpjUQdg9MwCJrc/xWYb0I7DyUb1u9BzTdCKWyu3+wy92XCthS1AejlkQ==
X-Received: by 2002:a05:6e02:164a:b0:374:5c5d:ad0f with SMTP id e9e14a558f8ab-3745c5dd6a7mr42838995ab.25.1716891658391;
        Tue, 28 May 2024 03:20:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a09:b0:371:9e5c:5506 with SMTP id
 e9e14a558f8ab-3737c62e593ls23083505ab.2.-pod-prod-02-us; Tue, 28 May 2024
 03:20:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWN0v4dXP1JSq7sRsPNzprEbydnSdbveeDYNp4FEw5lI/jZ7FCvM8C4hBfEZurdKvpdwoi1AAnftlVRTW8GkYoa2ne78X98LbIm8w==
X-Received: by 2002:a5d:8702:0:b0:7e2:61ae:24dd with SMTP id ca18e2360f4ac-7e8c64622d2mr1247055139f.16.1716891657565;
        Tue, 28 May 2024 03:20:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716891657; cv=none;
        d=google.com; s=arc-20160816;
        b=H3jXDMWkYTVzS3kXQiDh2OPiEDW9rdg/3JPmuC4kjLWRfnE76UlcGsMYrEWPPpjkx9
         ln1yJs+KD+caH1LY005EoNZ0MhRXeFBJrb0hhkN2n6D5m2khp7UNSd7g1LewNSg1FAvj
         85Ao+4+fTCdMLMWgEu9cBVxFzZfJLspbctP6OQTrsI6B0UdaIF+nd7amkgPAQJ02cS5P
         Qixe+0T8Os4HLvihpAHdGu7gLaq8nntIQWh0U579FhHSrR/Ni83xF76XTz71R2IgVgrP
         VxBW4Rf4KL+huEGK56dQ9F4uETsP2Qphvj+2cN+lAKOsANKP/yWPYMrlf+3EBgeBMyST
         wqVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gL61El2MUvMXM1QO7xxPZA2/oELsPgEiA0VxGFI8MCw=;
        fh=VxtXOcXu4SfavTfrvKNAfufZ8nv6BZ+iRP/glR/74eg=;
        b=yGZ5QOA3Rrub5v+7gNDwsYc0g5yMBitVOZMJH0+BDEgHs+H2Q7lJoc/SwWz64IvqA2
         Mz21xsRzfX0nwUdWhsa4DcSnvT2zm4VutM/HxoNNJohg2uXn4i9p9Zaf9TuV8bfYfxw9
         6h5qKyCsXQevEyqAHjfqwK9Zy7AN40/x3SF05j/qEwARJubT0xsB27aNAtDVjoZJlRQz
         6fQCErhZ/lxfPo+4ZEDvsxpxvG+7DjPAR0YBI6u+Mwx8bgQOZ434chIcEEF1T0C3dvYg
         MJ+YK5O538SQIDbfZ5JeQUS+MceBcC2mwTb0QO10xqnM05gYfahWtpcUGXdXSztInywc
         SXiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mDr0uYQ+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b0dc4d23d1si101992173.1.2024.05.28.03.20.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 03:20:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-df4e346e36fso695099276.1
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 03:20:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU4nWYYjY088ZWMAP+rAFrMp6Ef3TJLyg87c/qNwFw60GHpIkmq8Nzb+KWzqXjWsWOhZpWVvsTgvFcKM9Lj1KSHEXiZd8/iprZ6rQ==
X-Received: by 2002:a25:ad0b:0:b0:df4:db5c:99f4 with SMTP id
 3f1490d57ef6-df77224071fmr10979349276.53.1716891656941; Tue, 28 May 2024
 03:20:56 -0700 (PDT)
MIME-Version: 1.0
References: <20240524232804.1984355-1-bjohannesmeyer@gmail.com>
In-Reply-To: <20240524232804.1984355-1-bjohannesmeyer@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 May 2024 12:20:15 +0200
Message-ID: <CAG_fn=U2U5j8VxrkKGHEOdbpheVXM08ExFwkqNhz4qv2EtTjWg@mail.gmail.com>
Subject: Re: [PATCH] kmsan: introduce test_unpoison_memory()
To: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mDr0uYQ+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2f as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Sat, May 25, 2024 at 1:28=E2=80=AFAM Brian Johannesmeyer
<bjohannesmeyer@gmail.com> wrote:
>
> Add a regression test to ensure that kmsan_unpoison_memory() works the sa=
me
> as an unpoisoning operation added by the instrumentation. (Of course,
> please correct me if I'm misunderstanding how these should work).
>
> The test has two subtests: one that checks the instrumentation, and one
> that checks kmsan_unpoison_memory(). Each subtest initializes the first
> byte of a 4-byte buffer, then checks that the other 3 bytes are
> uninitialized. Unfortunately, the test for kmsan_unpoison_memory() fails =
to
> identify the 3 bytes as uninitialized (i.e., the line with the comment
> "Fail: No UMR report").
>
> As to my guess why this is happening: From kmsan_unpoison_memory(), the
> backing shadow is indeed correctly overwritten in
> kmsan_internal_set_shadow_origin() via `__memset(shadow_start, b, size);`=
.
> Instead, the issue seems to stem from overwriting the backing origin, in
> the following `origin_start[i] =3D origin;` loop; if we return before tha=
t
> loop on this specific call to kmsan_unpoison_memory(), then the test
> passes.

Hi Brian,

You are right with your analysis.
KMSAN stores a single origin for every aligned four-byte granule of
memory, so we lose some information when more than one uninitialized
value is combined in that granule.
When writing an uninitialized value to memory, a viable strategy is to
always update the origin. But if we partially initialize the granule
with a store, it is better to preserve that granule's origin to
prevent false negatives, so we need to check the resulting shadow slot
before updating the origin.
This is what the compiler instrumentation does, so
kmsan_internal_set_shadow_origin() should behave in the same way.
I found a similar bug in kmsan_internal_memmove_metadata() last year,
but missed this one.

I am going to send a patch fixing this along with your test (with an
updated description), if you don't object.

> Signed-off-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
> ---
>  mm/kmsan/kmsan_test.c | 25 +++++++++++++++++++++++++
>  1 file changed, 25 insertions(+)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 07d3a3a5a9c5..c3ab90df0abf 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -614,6 +614,30 @@ static void test_stackdepot_roundtrip(struct kunit *=
test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +/*
> + * Test case: ensure that kmsan_unpoison_memory() and the instrumentatio=
n work
> + * the same
> + */
> +static void test_unpoison_memory(struct kunit *test)
> +{
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "test_unpoison_memory");
> +       volatile char a[4], b[4];
> +
> +       kunit_info(
> +               test,
> +               "unpoisoning via the instrumentation vs. kmsan_unpoison_m=
emory() (2 UMR reports)\n");
> +
> +       a[0] =3D 0;                                     // Initialize a[0=
]
> +       kmsan_check_memory((char *)&a[1], 3);         // Check a[1]--a[3]
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect)); // Pass: UMR re=
port
> +
> +       report_reset();
> +
> +       kmsan_unpoison_memory((char *)&b[0], 1);  // Initialize b[0]
> +       kmsan_check_memory((char *)&b[1], 3);     // Check b[1]--b[3]
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect)); // Fail: No UMR=
 report
> +}
> +
>  static struct kunit_case kmsan_test_cases[] =3D {
>         KUNIT_CASE(test_uninit_kmalloc),
>         KUNIT_CASE(test_init_kmalloc),
> @@ -637,6 +661,7 @@ static struct kunit_case kmsan_test_cases[] =3D {
>         KUNIT_CASE(test_memset64),
>         KUNIT_CASE(test_long_origin_chain),
>         KUNIT_CASE(test_stackdepot_roundtrip),
> +       KUNIT_CASE(test_unpoison_memory),
>         {},
>  };
>
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20240524232804.1984355-1-bjohannesmeyer%40gmail.com.



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
kasan-dev/CAG_fn%3DU2U5j8VxrkKGHEOdbpheVXM08ExFwkqNhz4qv2EtTjWg%40mail.gmai=
l.com.
