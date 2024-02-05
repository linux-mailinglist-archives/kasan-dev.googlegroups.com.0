Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7OXQOXAMGQEUQWT3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 191AA849CA2
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 15:09:03 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-68c7e6ffdd3sf38293686d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 06:09:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707142142; cv=pass;
        d=google.com; s=arc-20160816;
        b=FMu8TllZ0orK1ZMjncf1PzUYTe97cPXsyT44CkzjSBdhJSeUoLflSVDz6XPNeSmUch
         v3wTNa4A20q/a1KHJCIhhdhxXu4xMAziyqcSWxJyJ3mNayN5m/ufGJM8kuvfZdKA6rJo
         ZCQ6RN6bYyvlgz14s21rGdeUAZ2tPUb6jPquXtYbX/em7yEbbYc6yFXiHDb92wnV+h20
         noQ5eQ6RpqNMHZi6j187yNAlTBq0DOM6FVM8iYSsYcfxADCJ38JBbBv3Ciz/cMNTF8bg
         sXgkjNm/+LInXdwJH0oOrDMWZTyAA4dYLZc6jVXSH2/eFJsd8dLZ3NxFiomC8Y3S2uQp
         nFJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AJlLHOSwaGkkrJ3dWCwMWu0b89PBLUAxm2xDx09SbtM=;
        fh=LBlP0YoqbqamsU6jwdOU03SVBwZEBSaB9Pt9PS8Idfo=;
        b=EEU6Ik/ZBNuBsjojmex758rrRPcK4NrD2Uv0hxlUmfQqsjYN+IDdIcjaGFJhUr5ErG
         JwoYtcEarppjDcAQFFbJuRDgkMnEqiPJ+0uiHaL2YGzOPGe2k8TvZyAFOgBQvDXXFv8t
         BosXAWdEdokfssnNxk97XfxoNFqeRuRHALGhx5huceSdSsubt485g4HAsoEH/JEAU0EO
         bwyJbxwmWEDK4yrTUDQx5BASAMoUMngt2GMH6Y8+TQtiEvW+Ax8ljRmjrC207FUa87NJ
         s66+jK/iQ8bwKwHuilSSsVy+ptfEXfsMJ/FdIu0b1Qx+tf8Z2OY1Zrp9nwT7JtdMs7y/
         TzMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="J/PKWO6I";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707142142; x=1707746942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AJlLHOSwaGkkrJ3dWCwMWu0b89PBLUAxm2xDx09SbtM=;
        b=mmSSKDXN8LqR9NEniW/Z5MFuPxp9T2IXjU5vw6V1cnD7Ua7+ebDXgmbT+kLdaKCpRW
         4ASO/3XXQVGsTMBFjvijNltYiL0mMKpobRSd5+qDTQYK3VgrQA9klIb64TqKVC83moBK
         PG12IXaNUGmou6uIh9rZ10OSLzycGcTV8xq077Znub5M0UA9AF8mQPIae5i3O/jIBdXT
         taPKd4HAMdk4Vh7nMItoXu5i7mQdEclTz4FJFhq22s9BtqSq5iGY+4rgugEuQbS7J42e
         ST31ifvlJFF8c3HIDwN4d0/1gMKC0NOTf/E6wVxJ1VJIjhNIuOB7Rrllajrn9PmqhAk2
         fIgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707142142; x=1707746942;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AJlLHOSwaGkkrJ3dWCwMWu0b89PBLUAxm2xDx09SbtM=;
        b=PWCG9L34K6aAcmIfy36EWRjDol8J3bU5nm8AypJFHtjmkrsv5FET8qpnmrbNK4gACz
         5ARrxRgtpOdvL0vS6xD154q1cK3HKUJ/JaPrMB8B2+x5IyuKQp2iPB0LOKL7C06WJb61
         tH/audZN1UnlNkT9r+cSDIZ+MLk2rGmuVQdmPg3yNI2D97oWPnfGXFsNxnMtuTT8c9wR
         Y8WkGY5ll1hUXCswsBThMlzPJeTa8i4axt0PsO724QvNtMBflywzostnktIfRALzYQp3
         Y0YYjWEM1N+ZnUTIaEc71d4+kh/d4UNM1sPAWTT2+jAx7elk+uPFdVjWZCoxu1WtAWFI
         +hLg==
X-Gm-Message-State: AOJu0Yy2gMDzfTFQzN1XMyvUwGEUnnbeHzPkJegE6rYTfBrmrMv9MMQk
	y6qfPuBohCtsRUQy0iosm5HgdcVRcHYifhAz4BrEYzh+Dz9PClhB
X-Google-Smtp-Source: AGHT+IHCojIZfAKjuv26f0KXPrueZxnbvykzJlsiq4tCVPXPPWlK1X8qmUX9AnTnHPpPp0aotkR6qg==
X-Received: by 2002:a0c:e14b:0:b0:68c:8525:a349 with SMTP id c11-20020a0ce14b000000b0068c8525a349mr6089916qvl.29.1707142141798;
        Mon, 05 Feb 2024 06:09:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ea22:0:b0:67f:74d3:afb5 with SMTP id t2-20020a0cea22000000b0067f74d3afb5ls3532973qvp.1.-pod-prod-01-us;
 Mon, 05 Feb 2024 06:09:01 -0800 (PST)
X-Received: by 2002:a05:6214:2248:b0:68c:88f9:6696 with SMTP id c8-20020a056214224800b0068c88f96696mr10131262qvc.23.1707142141009;
        Mon, 05 Feb 2024 06:09:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707142140; cv=none;
        d=google.com; s=arc-20160816;
        b=q7FkPT68b1+YRU20LAwzBEwQrO7S3kMNUrboYsUHBycg96hpZsssjjZHm5lla4n2S7
         ghhbkFQ7eD60ZaFZPy1HAkKhrcpEWgwpAOBGSskuXpW5Zo0F+WkbbjIZAtkgJg4icsaH
         H2mPx3Chc+GbJte33ULgngEFYiQhwe6KDc/7hWVrdChIWciPr0De68Z9kuhAels6u+Hz
         Z17TnkYpLp8lItzoNSopvAVCTk6wPoxko7hsUM6KCRKQJo/F/gGemAd4ILSeqWvTd6ut
         3FjIZPtgPm2ejArmcRmDAhfZx4DeFrwog7i7dxWc0na4jJ51wHEocP5ScbP2ERJaHgvY
         yhpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mzbh1UXzk14eXCXPK6xOaBGhFX+s/GQyOx72L7u65eE=;
        fh=LBlP0YoqbqamsU6jwdOU03SVBwZEBSaB9Pt9PS8Idfo=;
        b=M1/MyvAz5QLOsmIHZ2XUiGSxV2GBZeeY84SU+bkm+0zUYukVFPjf9a/dEMfx22kTSm
         ghtw856WOEMOUIUM4qsmwicephzX8L876gSTQMeICiZcgJN1VDFFgV7bP+9OCno2fBo9
         v1mrtcVY7W7wJJu4DEbB4u0PNZwQGAmp1BYKBesAf9S4MpKkYqubkzveeHWncIUhUIba
         fcw6bZTTgv/RhYzmfgqtAHqHx45T14I8McOdY8WJTvr0fbOYVUM2YEOD8FE0pXJrWjCT
         rlPVM6tobltpTsre5mQriZQaBH4tFSRcvTDitAVzRqytUQ5mQ9Juz2AcjfHOXohnmhES
         Rb7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="J/PKWO6I";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCWG7hqcH8xup4RxpwsjLpyEwCcAeEWYVWPHgvmMiAkJzjfb8QXvwdVs9hH+pAYBVb5O4d+H9RqJpgK1jXT7bYsuCtEFf9cIPR9xMA==
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id w20-20020a056214013400b0068183f0cc5dsi502752qvs.2.2024.02.05.06.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 06:09:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-7d317aafbd1so1968627241.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 06:09:00 -0800 (PST)
X-Received: by 2002:a05:6122:20a9:b0:4c0:3390:7abe with SMTP id
 i41-20020a05612220a900b004c033907abemr1619708vkd.12.1707142140414; Mon, 05
 Feb 2024 06:09:00 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
 <20240202113259.3045705-1-paul.heidekrueger@tum.de>
In-Reply-To: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Feb 2024 15:08:24 +0100
Message-ID: <CANpmjNN9zoMt-ahcu0MEGNH4OSO44H3BSqkOv+Drwg0TZP+g7Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: add atomic tests
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="J/PKWO6I";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
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

On Fri, 2 Feb 2024 at 12:33, Paul Heidekr=C3=BCger <paul.heidekrueger@tum.d=
e> wrote:
>
> Test that KASan can detect some unsafe atomic accesses.
>
> As discussed in the linked thread below, these tests attempt to cover
> the most common uses of atomics and, therefore, aren't exhaustive.
>
> CC: Marco Elver <elver@google.com>
> CC: Andrey Konovalov <andreyknvl@gmail.com>
> Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueg=
er@tum.de/T/#u
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>

Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>

Thank you.


> ---
> Changes PATCH RFC v2 -> PATCH v1:
> * Remove casts to void*
> * Remove i_safe variable
> * Add atomic_long_* test cases
> * Carry over comment from kasan_bitops_tags()
>
> Changes PATCH RFC v1 -> PATCH RFC v2:
> * Adjust size of allocations to make kasan_atomics() work with all KASan =
modes
> * Remove comments and move tests closer to the bitops tests
> * For functions taking two addresses as an input, test each address in a =
separate function call.
> * Rename variables for clarity
> * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_sto=
re_release()
>
>  mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 79 insertions(+)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..4ef2280c322c 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
>         kfree(bits);
>  }
>
> +static void kasan_atomics_helper(struct kunit *test, void *unsafe, void =
*safe)
> +{
> +       int *i_unsafe =3D (int *)unsafe;
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> +
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
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42)=
);
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, saf=
e, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsaf=
e, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, =
42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(uns=
afe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(uns=
afe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe)=
);
> +}
> +
> +static void kasan_atomics(struct kunit *test)
> +{
> +       void *a1, *a2;
> +
> +       /*
> +        * Just as with kasan_bitops_tags(), we allocate 48 bytes of memo=
ry such
> +        * that the following 16 bytes will make up the redzone.
> +        */
> +       a1 =3D kzalloc(48, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +       a2 =3D kzalloc(sizeof(int), GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +
> +       /* Use atomics to access the redzone. */
> +       kasan_atomics_helper(test, a1 + 48, a2);
> +
> +       kfree(a1);
> +       kfree(a2);
> +}
> +
>  static void kmalloc_double_kzfree(struct kunit *test)
>  {
>         char *ptr;
> @@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kasan_strings),
>         KUNIT_CASE(kasan_bitops_generic),
>         KUNIT_CASE(kasan_bitops_tags),
> +       KUNIT_CASE(kasan_atomics),
>         KUNIT_CASE(kmalloc_double_kzfree),
>         KUNIT_CASE(rcu_uaf),
>         KUNIT_CASE(workqueue_uaf),
> --
> 2.40.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNN9zoMt-ahcu0MEGNH4OSO44H3BSqkOv%2BDrwg0TZP%2Bg7Q%40mail.gm=
ail.com.
