Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKGN5WWQMGQEUTNEQSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 71F2684542F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Feb 2024 10:38:50 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-59a18ecf836sf966982eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Feb 2024 01:38:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706780329; cv=pass;
        d=google.com; s=arc-20160816;
        b=dan2E06K7/ke9m8jBPrryPzIiZh8cOtWLh7EeJTRWiYqulfd542juvDYauCdImb4Ab
         9ysdZ8N9b935/FQnLm8wIjCaKvOZdXA25Xr1duMjx9DV+qfHEpT+zvrPucgaMCOVUgke
         EbxsCWbqnmpdZlWRQ094qx+hbj4TCkWv0b8F+PJCfPzymWXZBO/i8RrZkus37IJVTv93
         co6dlp9xslcKJ2Q831sJBtMREBdgeeATWc7j2jZ/ED2fglxpPdoNfagw02RpIARpoMDv
         +xXs+4it49APBL0zHCl90G7/QPBLyiazloa3op7S24KBpSNxdiMj0wd4z7GtmpyqUfQ2
         oPKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SncK0RWHvWzL+JRUMswoVKd7Ud+yD5KkjaarBOupVVk=;
        fh=sURhgRMI/NLnjnh4+wdgfgcBU6H9+1/x0r8uViQlrSo=;
        b=PADyRZ1bXLSd0WiAeLORANf9fY174JRl9QvLs9aioG3kjII8N2QEXoSAstqEqvflN/
         MUK+HmML+t0sVpYKEZiT0FLyYMATrDsJmMYCthcVC0PWXgVzx5KUA1SxENmzuVO77VMU
         WmOC0tBk/lD5s9y4UxzMV/O/6bBRXGpDFTZQ8K2sZX4d3cToFKnEx7L42w0syC53RtNi
         jigJO/KxgaysvJJnNMv4cyUFu6cWwT+CznNVHb6CARi4dW4C4GvOWdeaqGi18d70Us4b
         OZlK15hl8E6rb7Asy9JhG34qo8Yn/59nl698caNU3v1fB0c9U4tV3iUuyujGVvzSEMLV
         WuHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mLSiuZXX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706780329; x=1707385129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SncK0RWHvWzL+JRUMswoVKd7Ud+yD5KkjaarBOupVVk=;
        b=FG6vUD0ZWroiYWbvY7osj50HyThEkm0xAOlMzF6JY65+CsgW8NagAzp7h3I6C6eZSF
         1VLW53doPMKtZC2qrzngqGBE1eOwmqU2UC5FM6W5GK3ZzOjAPNjmR0VOcFQsb7DzDKrC
         OClKxXE/gLAJJHXdWrAsZXZe9GeDdH06lNQLx+oB4bUb9fDnD2Yxaw3jCl5P5Tx3+6SR
         75JbaXpVFoznzZgyq9wk3XVKvitjxKlGdMoQY0RA9I6KGOpkbunnCscB8HnvKIoMwiPB
         7YZBbwUtkqQeJHjpPrIGXiDFb6UOG7eXWsM/79RVRaVDZ9ihBO9Adel7lCH8YVUQIx3F
         cJHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706780329; x=1707385129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SncK0RWHvWzL+JRUMswoVKd7Ud+yD5KkjaarBOupVVk=;
        b=f82HGhI72W84h30FZ4SxGFOSMnJBMER/PEqJLn4dt7j6+Uh7honYu4elLRQngmbjYY
         vWlRFTgQmUco0oQ0prf0wBj8tWer55GrP4aOvnBiX2DkQVLm4UU0dD6P+c0LLmyX7cOY
         CL8RHxfnZbTUoAUUn+H0q8gvmLZCBkiRunROLfBriKeZjJRqJOyfihOJkIz3OEERQuYR
         5j4bT1YYXB7oUPkk9V4ImKugGqyVB8BPxByuB8yh/vtfO9QrsAUgErXoUmiEH4lgvQtK
         VNHBcWJHsRCTuM5ynnVAus5Gx5BihyeIcUFXjnuI3DWGrO1MwRr5SPqt6dSGicTp12sm
         Gunw==
X-Gm-Message-State: AOJu0Ywu7lxOHQk3N+MEJ/Yyhah8hE0An9P73/56zUqyXsfdqxWtlpoE
	l3R4aU/6VMadNVu+CVe2OJYeenAnjsbKXmIaVKl5XdBS4divS3LS
X-Google-Smtp-Source: AGHT+IHxRfLUd99VLCNZgVVc36quOUU2LEzTvRQqD8Cd7JM5LUyDHQMSyGopifSgMis8jX1KfTJuBA==
X-Received: by 2002:a4a:e0d0:0:b0:59c:8688:5a37 with SMTP id e16-20020a4ae0d0000000b0059c86885a37mr705462oot.0.1706780328888;
        Thu, 01 Feb 2024 01:38:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:60d:b0:599:1da6:a4d8 with SMTP id
 e13-20020a056820060d00b005991da6a4d8ls18895oow.1.-pod-prod-03-us; Thu, 01 Feb
 2024 01:38:47 -0800 (PST)
X-Received: by 2002:a9d:6b99:0:b0:6e1:1573:f99e with SMTP id b25-20020a9d6b99000000b006e11573f99emr1721635otq.33.1706780327225;
        Thu, 01 Feb 2024 01:38:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706780327; cv=none;
        d=google.com; s=arc-20160816;
        b=DuuI/dcvnzhLu8LipT/I7nZhDWj+IKmYB0VNE0/bDchv846htTMlQXwpXJgRyaeTXz
         8Z+imKn8aljdN6QBusb1YPvCfCDveiBeuA4jOvZUPSBLLkS38Bw6pe5S/wdgzJQbCCgo
         T4/Ih1PG+NeLQ+NJE0UadwKrqEIH0f/UOrpooRKh4E4kEBXHFBh0BT6mHtq1rmjuroaM
         w7l0p6Z7jpwbWiVoxsiF+aUmYOFp/qlpAnEDLXtDeKzI8X1S+R4MezTSkJCmmc70CofS
         LdJTW3miDTcIS3rtFuz7gnRAwYUY2vD16FjkGvFo9rUkQCTjOX6J2iZvYL8cpGPEHmpU
         wEmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XD0yQ/tI+tg2dm8uEuvvq9XaoXhsRoncokKKzr2jeMM=;
        fh=sURhgRMI/NLnjnh4+wdgfgcBU6H9+1/x0r8uViQlrSo=;
        b=EprPvuBydaGBwizfr99XEvaFqMnEGihZfHd3Kb7blcZj30E1nyIB5+pA9I8gKH+KlZ
         Dpmeb8HuRRqwXQUZiE3cqO3NNyQxwbiR61PUawn/bz6Ra/kYHfPmotVLAZfHlumS/WrA
         r7KR65ekvIOIHdpq10zlJQt0TjJYc3b7zEN7CBTzmj7wJo0DNton/HDKlFov/Z/WXsk/
         gMZcP9M3TSQtRI3MEJxTHrAgVnchWZfHqwj5Uz9DNWY605TlwVQRzon/PLfqKBf2gIFM
         GHSJTdbreTMGoJwgGYyuLCCm4q7r9SlzYDgSC3EEw/dT1f/zU2KHzE225LcI56ATfo6X
         j8sg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mLSiuZXX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCVpODGuaU3h+W+iAVgK3m4LSdzhECYuwiXIpMyT5ux6+YC8SoQO8w0Fg6mhwh6sOXXzTNbpJUUaNaNr9kIdE+1KR4KEogHDcbyagA==
Received: from mail-vk1-xa2e.google.com (mail-vk1-xa2e.google.com. [2607:f8b0:4864:20::a2e])
        by gmr-mx.google.com with ESMTPS id az15-20020a056830458f00b006e112c9aa65si1016392otb.0.2024.02.01.01.38.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Feb 2024 01:38:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) client-ip=2607:f8b0:4864:20::a2e;
Received: by mail-vk1-xa2e.google.com with SMTP id 71dfb90a1353d-4bd8977f1c5so278369e0c.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Feb 2024 01:38:47 -0800 (PST)
X-Received: by 2002:a05:6122:1d87:b0:4bd:7da1:a2ea with SMTP id
 gg7-20020a0561221d8700b004bd7da1a2eamr1519212vkb.14.1706780326396; Thu, 01
 Feb 2024 01:38:46 -0800 (PST)
MIME-Version: 1.0
References: <20240131210041.686657-1-paul.heidekrueger@tum.de>
In-Reply-To: <20240131210041.686657-1-paul.heidekrueger@tum.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Feb 2024 10:38:07 +0100
Message-ID: <CANpmjNPvQ16mrQOTzecN6ZpYe+N8dBw8V+Mci53CBgC2sx84Ew@mail.gmail.com>
Subject: Re: [PATCH RFC v2] kasan: add atomic tests
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mLSiuZXX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as
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

On Wed, 31 Jan 2024 at 22:01, Paul Heidekr=C3=BCger <paul.heidekrueger@tum.=
de> wrote:
>
> Hi!
>
> This RFC patch adds tests that detect whether KASan is able to catch
> unsafe atomic accesses.
>
> Since v1, which can be found on Bugzilla (see "Closes:" tag), I've made
> the following suggested changes:
>
> * Adjust size of allocations to make kasan_atomics() work with all KASan =
modes
> * Remove comments and move tests closer to the bitops tests
> * For functions taking two addresses as an input, test each address in a =
separate function call.
> * Rename variables for clarity
> * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_sto=
re_release()
>
> I'm still uncelar on which kinds of atomic accesses we should be testing
> though. The patch below only covers a subset, and I don't know if it
> would be feasible to just manually add all atomics of interest. Which
> ones would those be exactly?

The atomics wrappers are generated by a script. An exhaustive test
case would, if generated by hand, be difficult to keep in sync if some
variants are removed or renamed (although that's probably a relatively
rare occurrence).

I would probably just cover some of the most common ones that all
architectures (that support KASAN) provide. I think you are already
covering some of the most important ones, and I'd just say it's good
enough for the test.

> As Andrey pointed out on Bugzilla, if we
> were to include all of the atomic64_* ones, that would make a lot of
> function calls.

Just include a few atomic64_ cases, similar to the ones you already
include for atomic_. Although beware that the atomic64_t helpers are
likely not available on 32-bit architectures, so you need an #ifdef
CONFIG_64BIT.

Alternatively, there is also atomic_long_t, which (on 64-bit
architectures) just wraps atomic64_t helpers, and on 32-bit the
atomic_t ones. I'd probably opt for the atomic_long_t variants, just
to keep it simpler and get some additional coverage on 32-bit
architectures.

> Also, the availability of atomics varies between architectures; I did my
> testing on arm64. Is something like gen-atomic-instrumented.sh required?

I would not touch gen-atomic-instrumented.sh for the test.

> Many thanks,
> Paul
>
> CC: Marco Elver <elver@google.com>
> CC: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> ---
>  mm/kasan/kasan_test.c | 50 +++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 50 insertions(+)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..1ab4444fe4a0 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1150,6 +1150,55 @@ static void kasan_bitops_tags(struct kunit *test)
>         kfree(bits);
>  }
>
> +static void kasan_atomics_helper(struct kunit *test, void *unsafe, void =
*safe)
> +{
> +       int *i_safe =3D (int *)safe;
> +       int *i_unsafe =3D (int *)unsafe;
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe))=
;
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe))=
;
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> +}
> +
> +static void kasan_atomics(struct kunit *test)
> +{
> +       int *a1, *a2;

If you're casting it to void* below and never using as an int* in this
function, just make these void* (the sizeof can just be sizeof(int)).

> +       a1 =3D kzalloc(48, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +       a2 =3D kzalloc(sizeof(*a1), GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +
> +       kasan_atomics_helper(test, (void *)a1 + 48, (void *)a2);

We try to ensure (where possible) that the KASAN tests are not
destructive to the rest of the kernel. I think the size of "48" was
chosen to fall into the 64-byte size class, similar to the bitops. I
would just copy that comment, so nobody attempts to change it in
future. :-)

> +       kfree(a1);
> +       kfree(a2);

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPvQ16mrQOTzecN6ZpYe%2BN8dBw8V%2BMci53CBgC2sx84Ew%40mail.gm=
ail.com.
