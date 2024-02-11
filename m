Return-Path: <kasan-dev+bncBAABBTM6UKXAMGQE3JRLLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9483A850846
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Feb 2024 10:11:43 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d08eacba7asf22615701fa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Feb 2024 01:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707642703; cv=pass;
        d=google.com; s=arc-20160816;
        b=c96r9eYBId8MG0UHUCjrTrFOMC/xrsijeWt7mHOH4IFsfah9YBaDh2vX/thfWRx/XY
         VgsulPEmZmFkv5pq0ClErtToe4RgTjDf1rmDZKUmmiXQiUmT0LLZTezl9t6NmgKLNCN2
         qCHdC2StgmWqRoRknAj+pOqh9i5L1xurap/G7XhIIo+YQ0n0fz2ioorNSv2LrmJKQ2IE
         xHryT7Zhf85A/uDWqZJ5WX7P1At4XDOL9TceAxQii7ElUCWhyy/RE2xRE1zekdsts9qm
         GYIjq8kauF/MmG64UQkmGvuNyg6CdfrLP58j7Apw2bGVBJ0qhp34ZnquN0jlNHZtKE0J
         IorA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qBWeTzL0WViFEq+WY/T7tp9Sr5ZJJ3KbnQ9bkUYlmBA=;
        fh=IyCkpCHIxVUeCMw3vPBuyrAGODJCHPYc4ZTKer3k7Hg=;
        b=jrS8u0k7cnbz3mD7BIUjrfk4AF/a+dSq/6tWoz5awO/uK9a6kIUUrrG2/Be70ENzBQ
         /lw3Ehmo2AmKe5bV/7tuZ499pxYcWdZFKJVgqh7L6uctu185KWc3to+EuGmwyCKQ1pSO
         aHpMj1Iakf1DHgJ4mC7KPPwdA2u4NtFC6ZmDRiwiqyDiapvXQQbGJn4AmcjnW8D6fJXB
         DcowC8jw9MyGaPJaYgmmglcMHKK+bwCNTYaiMJrhhBTfJ54uu7NEB5f486ViVwlVfXET
         qvIU7iJyvVFBfZxVwMMUAsMusccxwglaZFDrVaUZEkND6QAWO992I50t0xtacgha+QN9
         MH+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=i5A0RDxK;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707642703; x=1708247503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qBWeTzL0WViFEq+WY/T7tp9Sr5ZJJ3KbnQ9bkUYlmBA=;
        b=irD/ZsqbCac4pEYx0TDZGX1U7QG7qvRc3I87CTZI5ZjcAOcPerkdN7zmXV8D/QodEO
         koXco7lB4Nrs/GkHAw4lQUyzJsjn/j6GZmArwMx0xTm3t25paUqXphd0NTVfAxzPaMik
         BcG1oiuLmxDCNEQBofPyrS446uRqS88jcawonnOkrvMR+GNy9DbeGAqgLXHADPvNt8xf
         WFW16sGSJ1IK32g0F4jXztFhLbCZkcBFOzH/omX6F/yzWjQhPiNftPeOJizr2ww3aXTO
         1cVW4cecR0wa8wsvxa/crmFd0nSVgmh0uI4eYGhTymoIycD8mL+bokBr5DH0bXwSEJuR
         E2KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707642703; x=1708247503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qBWeTzL0WViFEq+WY/T7tp9Sr5ZJJ3KbnQ9bkUYlmBA=;
        b=Xi3XRVqXVt5PAx1AnZhNgaY4FyswbLleEX/sJGT98+gaoCc3uQYzHKM68JubV64xTG
         Qe/gVZX0O1qm6o0sU/1tFZPyOSXll8mRFGPNHYONucppIrvKeeqfyxmGNCkRBwAFSn51
         klm/Z46BKGVIe3yUnkojNBdqV0l+KS5AlXpMuh4P5qZ6W/YHMRJvvY/MY0kr4PABpxwh
         5nThCvGMraOoM9OWAJSrL6yselBuUp/cK1OVOtDx08oQx3os52uEaEzrEXt/UhWFNixF
         0MySYZmSaCW8BdpGztzQpwZGfMFiUIULZ5S0j2QUPeB5M1rL8FfiiGtMLW0tbmDeM80I
         hQsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxSrtrkzjzn3pd0m/kvSQjS5HvJ9dajj+yq6oB7xMC2VwiO3rKl
	E29pfOce6+Kdq4JZBO9EHkh8Kc8bQhQ8SSURfkvEutkF23arMNDl
X-Google-Smtp-Source: AGHT+IHz9iw3ufcJjxXgBbXDfza/PMTkl2K8KBNHK6Vl2KBSOOoV5CDOPxYAbASevH62NU7D5d/Xgg==
X-Received: by 2002:a2e:a7c2:0:b0:2cd:5cfd:b13 with SMTP id x2-20020a2ea7c2000000b002cd5cfd0b13mr3461488ljp.17.1707642702116;
        Sun, 11 Feb 2024 01:11:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c2:b0:2d0:e2b8:4baf with SMTP id
 2-20020a05651c00c200b002d0e2b84bafls654031ljr.0.-pod-prod-08-eu; Sun, 11 Feb
 2024 01:11:40 -0800 (PST)
X-Received: by 2002:a2e:a78f:0:b0:2d0:cbeb:69c8 with SMTP id c15-20020a2ea78f000000b002d0cbeb69c8mr3447776ljf.22.1707642699941;
        Sun, 11 Feb 2024 01:11:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707642699; cv=none;
        d=google.com; s=arc-20160816;
        b=WikZfLKVz/1U5G01wBhSN32CFr5EmEEw+5o9blSnW0jQbjC1tNY6DC/5TgLDQNCMQs
         D60xxv9QO0bHvIoGEgVCdoc9L681ym0qTujpEL1aUa1jvnGethZuszNLSYeREXTSWtMB
         slqw0iWXuohZ4cnvRTQ7CNoWyIGdWFyjIDMfBxKvgBxUfJajo3Jx/aRCSZcyqYOtFRAk
         7KBH6u9cHy7DacdJDcjmGGZgpCuLFxuJKKEj2jnVOYqOooGdxTxI4GpsSdwfdbUhgB5N
         SAOs7S6yn8UPRiQm1ExjCvFSnL97cAK9B3AR0o+09I8r78IkN3qS7i+1s82kX2A0TfV+
         kJbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/1DqfwJGtWRTGRQ6Tc6wLUorqclXo0wzjN29vIwyios=;
        fh=IyCkpCHIxVUeCMw3vPBuyrAGODJCHPYc4ZTKer3k7Hg=;
        b=wZBbRlM/E5rUC0Vs7a/Q5QXNvzBJKb8G9kEAugbHBav3LjXry5Noz0da7Wnee/xPSt
         EE+hMqJqogKgtBjOR4AS7lFQ1LZQPVnocpZ7TtCy9Fn8gY2LeVdYpnH1kpi71cORHWrd
         e/VU/9LlMCw188jjI9GUjgK9hHQZiRxgGkXn4FKZoM2F4L/EkAxX30DS4yxd/SufGPa5
         TN5pAZ8uoVNd7t7FJDAARATHdoE4hpFoCsDHDMUqW8meb6fngwC8BjeWyc6QXnd1hAYD
         IW6ds6y9s61dZrS82W+9HUc/r6kk4l0hCFhMBJhb5tzSiDw13P9UXnkl1aW0yqbcOtm8
         tMLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=i5A0RDxK;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=1; AJvYcCUVC4wMVngMsYunzfbRakDVe+sayrJ6Y2GKMaBUYo2UUlVeJ3TRPkY5A8zcy/CnObB1IbIwfDKymyOu6l/zAbijSZa07mYPrSl5Qg==
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [129.187.255.137])
        by gmr-mx.google.com with ESMTPS id s22-20020a2e81d6000000b002d0ae4c4aaesi360320ljg.3.2024.02.11.01.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 11 Feb 2024 01:11:39 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) client-ip=129.187.255.137;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4TXhff50PfzyVC;
	Sun, 11 Feb 2024 10:11:38 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs51.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.879
X-Spam-Level: 
X-Spam-Status: No, score=-2.879 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001, LRZ_MSGID_LONG_50=0.001,
	LRZ_MSGID_NO_FQDN=0.001, LRZ_NO_UA_HEADER=0.001, LRZ_SUBJ_FW_RE=0.001,
	LRZ_URL_HTTP_SINGLE=0.001, LRZ_URL_PLAIN_SINGLE=0.001,
	LRZ_URL_SINGLE_UTF8=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout1.mail.lrz.de ([127.0.0.1])
	by lxmhs51.srv.lrz.de (lxmhs51.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id RO5beP05XWcW; Sun, 11 Feb 2024 10:11:38 +0100 (CET)
Received: from pine.fritz.box (unknown [IPv6:2001:a61:25e5:2101:6db9:145:ae0a:2a16])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4TXhfd1X3yzyS3;
	Sun, 11 Feb 2024 10:11:37 +0100 (CET)
Date: Sun, 11 Feb 2024 10:11:33 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: elver@google.com, akpm@linux-foundation.org, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Subject: Re: [PATCH] kasan: add atomic tests
Message-ID: <pqfokz55m6izzahl5jtbbhundrsjmbeaf3kmspo2q2oqv2hpcl@wdsabytutjv2>
References: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
 <20240202113259.3045705-1-paul.heidekrueger@tum.de>
 <CA+fCnZdDxot_wms3XmZonBCo7=qkCSj72inhSX+zHNF9gkMv2A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdDxot_wms3XmZonBCo7=qkCSj72inhSX+zHNF9gkMv2A@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=i5A0RDxK;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

On 05.02.2024 22:00, Andrey Konovalov wrote:
> On Fri, Feb 2, 2024 at 12:33=E2=80=AFPM Paul Heidekr=C3=BCger
> <paul.heidekrueger@tum.de> wrote:
> >
> > Test that KASan can detect some unsafe atomic accesses.
> >
> > As discussed in the linked thread below, these tests attempt to cover
> > the most common uses of atomics and, therefore, aren't exhaustive.
> >
> > CC: Marco Elver <elver@google.com>
> > CC: Andrey Konovalov <andreyknvl@gmail.com>
> > Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekru=
eger@tum.de/T/#u
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> > Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> > ---
> > Changes PATCH RFC v2 -> PATCH v1:
> > * Remove casts to void*
> > * Remove i_safe variable
> > * Add atomic_long_* test cases
> > * Carry over comment from kasan_bitops_tags()
> >
> > Changes PATCH RFC v1 -> PATCH RFC v2:
> > * Adjust size of allocations to make kasan_atomics() work with all KASa=
n modes
> > * Remove comments and move tests closer to the bitops tests
> > * For functions taking two addresses as an input, test each address in =
a separate function call.
> > * Rename variables for clarity
> > * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_s=
tore_release()
> >
> >  mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 79 insertions(+)
> >
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > index 8281eb42464b..4ef2280c322c 100644
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test=
)
> >         kfree(bits);
> >  }
> >
> > +static void kasan_atomics_helper(struct kunit *test, void *unsafe, voi=
d *safe)
> > +{
> > +       int *i_unsafe =3D (int *)unsafe;
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, =
42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, =
42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42)=
);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe=
));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe=
));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 4=
2));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, s=
afe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, uns=
afe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsa=
fe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe))=
;
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe))=
;
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsa=
fe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21=
, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe))=
;
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(u=
nsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(u=
nsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsaf=
e));
> > +}
> > +
> > +static void kasan_atomics(struct kunit *test)
> > +{
> > +       void *a1, *a2;
> > +
> > +       /*
> > +        * Just as with kasan_bitops_tags(), we allocate 48 bytes of me=
mory such
> > +        * that the following 16 bytes will make up the redzone.
> > +        */
> > +       a1 =3D kzalloc(48, GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> > +       a2 =3D kzalloc(sizeof(int), GFP_KERNEL);
>=20
> I think this should be sizeof(atomic_long_t) or sizeof(long),
> otherwise a2 will not work as the safe argument for
> atomic_long_try_cmpxchg on 64-bit architectures.

Ah, good catch!

> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> > +
> > +       /* Use atomics to access the redzone. */
> > +       kasan_atomics_helper(test, a1 + 48, a2);
> > +
> > +       kfree(a1);
> > +       kfree(a2);
> > +}
> > +
> >  static void kmalloc_double_kzfree(struct kunit *test)
> >  {
> >         char *ptr;
> > @@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
> >         KUNIT_CASE(kasan_strings),
> >         KUNIT_CASE(kasan_bitops_generic),
> >         KUNIT_CASE(kasan_bitops_tags),
> > +       KUNIT_CASE(kasan_atomics),
> >         KUNIT_CASE(kmalloc_double_kzfree),
> >         KUNIT_CASE(rcu_uaf),
> >         KUNIT_CASE(workqueue_uaf),
> > --
> > 2.40.1
> >

I'll be sending a v2 patch right away.

Thank you Marco, Mark, and Andrey!

Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/pqfokz55m6izzahl5jtbbhundrsjmbeaf3kmspo2q2oqv2hpcl%40wdsabytutjv2=
.
