Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBX7QUPCAMGQEXTKXUPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id DDD93B1516A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 18:35:44 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32b7d83142dsf22054321fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 09:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753806944; cv=pass;
        d=google.com; s=arc-20240605;
        b=bPMX/fqKnP+7mpfnsmwK5kphx+FUT9880PY8035WweiD+j4a070aeA4AZz8VFRC3VY
         NlmD3LooCmq5GUPXn7Wq5qJFMahOuyTdg3THxUUVRik3BFUEPaPM1Br03TeBTIdbBF6o
         HTdjZek4G+EfvyHXawzUKj5P6HPTE8FLygCiOp8i6d0zTw1psM7rF9EUZWEfaPYVrB2N
         AizKqg4r2eECqBfA0+L3l/3HmQURVBaf5Zu5oVkXNB0aHd5WXANlNOyObLHxQeRNV4/J
         PplHE5olxZbHLnJ3XP8myCHY0UF2eFwVg1ZXEpTKviL/kIE0bRB8ILIhrCNnNP8+DpzG
         9sfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8PMqLjGoBSVPujDxmekuCSwb+BbZHQNNEB7uVY3LY8c=;
        fh=GFMJJIq+4eH/9V8fbYqfavR2pR/WqBHsoI/Y2CgR0B0=;
        b=CcY1MFrez0L3TCfhwB5nBhNVz+tIu0+81PNHCBrd8+ItqZlnpRs2IjVrK4LTaJ4aNf
         ca3lFY+tuq19Jlm66iyj+Z9uB1nFUi/ljNFjm7ayW2eSHhCl5sYMsMF4uDFTJzourS4A
         8g/YYlWDsVyZYSZRBdvH7IKO1xS4nW6ubJDuRGstr2FhMVRZ5aoRjgY1OeNKUI+lkrp4
         ZYUT7R8ngzf6FuPmUU0H3FhCj+HtWBTTFdpIiTG8L0j4wD+flOvHx2ByquF0ZII9L+Uf
         zdfCJUBfUalDxD6KB7XzFNLLUbhQCUS5Af41q8E2B2jB8GUC91vpf22UQ64YxHZRwIpD
         F7dA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uc8urYIY;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753806944; x=1754411744; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8PMqLjGoBSVPujDxmekuCSwb+BbZHQNNEB7uVY3LY8c=;
        b=Q2292qA/DwHGdcu2HejE3wOkWSVDU51/y+f0TwX9O9AIUHpGi/aZa5zkrYV+jWhewY
         Kv2G6dRT1Bb8UZ5/LIcTgqxsd8jtcO86UTR+S0Or1VYEBGYwfmsS/k7LRRk9HQQxYQyI
         SMFbrJ+BtsL0AWpHzhAz9s0pItrEBHDJ8FNS5d1GuZpCJdqGSSCqUPq+/W3HUARIT33o
         NXKiVY44eYiaQ4veLjO+I68q5W7AHJlGODKCkC4WDz8Cqe7/Opr3Dfx9Xi/8uNSBlY3z
         6pVdEB/ObiPj+r72nZPsQvlzFl4xfRH9QaJuevO2jW3E/7dOqq29QlvRsVz10t+LZ8un
         4UDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753806944; x=1754411744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8PMqLjGoBSVPujDxmekuCSwb+BbZHQNNEB7uVY3LY8c=;
        b=ACarAxxN0uGBQjzPf9ZdxB6wrGNIP3NUYei3ujGHWLNiW/XIf5OfC7/EmQ4U6vLxIj
         V5lwJ4lw3m2Ast2O82bI8YLHYyevlKVsZF4ompB6p7+FEE62KcDgU4pYLkpoZzz8S52d
         NMg4RAgEH0seyMM43/2raMOYWKZxhdfZUuRpxCdQVCs5B03wW+c4BlMdpguYWjbB9w7/
         ZBdT65agO6lIbX9pI585gD6TvoY5Exo7cyWaFhhvYkDD2YD1ZVk0bfJpMAjFYGdbDws3
         QYeaq4lciCpi+EKW4yXnbDtWORcF+xF7DaQRKVBWX1R46LuPiuEz66OWFnjs7/DlnTCE
         MhaQ==
X-Forwarded-Encrypted: i=2; AJvYcCUXXzftcvUN5lAAWs05DwndL3gqFX0SduZ4TjBP4e5mFxodvZuzE/i7KkKGUHfhM7vv81Nj+A==@lfdr.de
X-Gm-Message-State: AOJu0Yz1KPSYesN3dM+/IckjRLX8p3IBS+ghEJl1o/1Sbuov2ToQAh8q
	yx7ilsygp6MwsftvbxP9NUfaEkQieXDUYmkzT6XjPmE3vWBdq7teN8/p
X-Google-Smtp-Source: AGHT+IGdOjn/e9mEg4QcqeVkWzRvae1WVS3CMsT4kxfwIu44t1FLejDr79m9ejuDf1P/smX5krQFyg==
X-Received: by 2002:a05:651c:4192:b0:32b:7356:94cb with SMTP id 38308e7fff4ca-33224b9051emr168521fa.19.1753806943721;
        Tue, 29 Jul 2025 09:35:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdOrI92CDJL0xdBq7+10q2iT5ckirk70hOqWwXkrrDEig==
Received: by 2002:a05:651c:400b:b0:32f:4573:b6ba with SMTP id
 38308e7fff4ca-331dd856b95ls4395801fa.0.-pod-prod-09-eu; Tue, 29 Jul 2025
 09:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXBycx1KF6WxFUGV6XA99xJHSEP34FNiOhgvSXrTE4NGTI8DXfziONvS7O0BJ6eGi0fEOZzXeB3Oc=@googlegroups.com
X-Received: by 2002:a05:651c:409b:b0:32a:8bf4:3a54 with SMTP id 38308e7fff4ca-33224a54be6mr154441fa.2.1753806940738;
        Tue, 29 Jul 2025 09:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753806940; cv=none;
        d=google.com; s=arc-20240605;
        b=C84HvQAPRVdwnvShs6/rb7O0yHLbzcV12UmIqY788Oun2qrC4R7SSrgdwMzU5pyYj1
         wSnf/n+XhLQcu/3eXKgVGQJYWNj/YD1V8VVkI/GCeSVyUAumVkwMT2qTQG30zyqFDkOJ
         Vae9+zksVJnaJR+Ml9KCFNFM/XqBg8NeIsv0GanOqNqKdF7jN8Bu9p5d6e0jqzjzihvF
         PWdAsN4/0ucKSiTznfr+V4u4Y4AaGSEc1yLWSeQK/LFTRAO9lUxdGKk2iumaiINQQH+A
         y4ufMQEU957NpMlZIrpYWoH7r2N7onaWHXGjjw+iJO/wlqxotrvuelK8G/L7vIg4Pyh6
         NB6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lv40Dlr5B9TIJUCPEQGZxzFejkaL+qCdmU+tMwtTk64=;
        fh=1etAc/nSqglySBGMbtx8om8sis8GiTONdKeJMrR4c+Y=;
        b=cn8GfjDPtoH86BR8fFlDNw/rAj0FF/1yvZ7w4MzcTbxMUeSKmvlJWtwDy8DK69WZmj
         OTVXuR90MIHR656WpDxmJMOxsBTW/L7t3zkmvJAtZJyVM8JCDWMy4qi3E0yt8ZOIdj+e
         hnEjKvx1P7+hA5iwk9QjJ724PYBdehhq/mcPDeN0AmK57QwmcJHyXvbFUEENEgnYKC2e
         SKG9MGglV9q1YH+Uw1jy1b3F28IA6FJ0iD8IPy4IbQRI2KucLvkvNwqBrM9+6qYL5Pbs
         jamUa3GBifQo1GYVeLmtZ/Q4Dz+99hAQtnu5zqTvOpgag1VVfAIoA/Fkuo70fNrp1MgT
         xO3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uc8urYIY;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f420f872si2270601fa.6.2025.07.29.09.35.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 09:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-5f438523d6fso12697a12.1
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 09:35:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVUrxMERCLtrRIBGX4PWZBF0AqUAUKuSbFyHedvlLt+9HMtSVOeq7FuqnRoHQpc4fg9YwtpE1GMKNA=@googlegroups.com
X-Gm-Gg: ASbGncsVxVI2BLzJqqbrtQ/aEwpXfuiZtZ0gTuCKELMAYRaiYgl0wgDnRBVnqKfhenM
	H7itFUPmv69Y4NkqYAZm9uePwCrebNBGaHoWmMJHWXuBtaKTbFofBoqKuOE6zJ8vxnU6zzwBgdS
	jU6nD2NkN6pcAxxg5SNWOOdRDMPInGAcy5KJZftZj0TiP+dnqyyX0muEwEqG/HLu/zSGLpwweRz
	uItUmdvZ3S5wvobpCNdJ8nC8kq8a3SrMHT69woFJAvLFQ==
X-Received: by 2002:a50:8a97:0:b0:612:ce4f:3c5 with SMTP id
 4fb4d7f45d1cf-6156680c26cmr111335a12.0.1753806939698; Tue, 29 Jul 2025
 09:35:39 -0700 (PDT)
MIME-Version: 1.0
References: <20250728-kasan-tsbrcu-noquarantine-test-v1-1-fa24d9ab7f41@google.com>
 <6aeb9c5d-7c3f-4c0c-989f-df309267ffbe@suse.cz>
In-Reply-To: <6aeb9c5d-7c3f-4c0c-989f-df309267ffbe@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 18:35:03 +0200
X-Gm-Features: Ac12FXw25dvpS-KcFMgDsvvBnkOQEQZAMrlZ9kHerHD3IUA1WAAg7ptbMtRjVbY
Message-ID: <CAG48ez2O4OvhKjdy=Y6fzuK0Qf79JQXCXV=uQV2ED08fS1RNpA@mail.gmail.com>
Subject: Re: [PATCH] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine skipping
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uc8urYIY;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Jul 29, 2025 at 6:14=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> On 7/28/25 17:25, Jann Horn wrote:
> > Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU s=
labs
> > if CONFIG_SLUB_RCU_DEBUG is off.
> >
> > Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> > Feel free to either take this as a separate commit or squash it into th=
e
> > preceding "[PATCH] kasan: skip quarantine if object is still accessible
> > under RCU".
> >
> > I tested this by running KASAN kunit tests for x86-64 with KASAN
> > and tracing manually enabled; there are two failing tests but those
> > seem unrelated (kasan_memchr is unexpectedly not detecting some
> > accesses, and kasan_strings is also failing).
> > ---
> >  mm/kasan/kasan_test_c.c | 36 ++++++++++++++++++++++++++++++++++++
> >  1 file changed, 36 insertions(+)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index 5f922dd38ffa..15d3d82041bf 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -1073,6 +1073,41 @@ static void kmem_cache_rcu_uaf(struct kunit *tes=
t)
> >       kmem_cache_destroy(cache);
> >  }
> >
> > +/*
> > + * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
> > + * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
> > + */
> > +static void kmem_cache_rcu_reuse(struct kunit *test)
> > +{
> > +     char *p, *p2;
> > +     struct kmem_cache *cache;
> > +
> > +     KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_SLUB_RCU_DEBUG);
> > +
> > +     cache =3D kmem_cache_create("test_cache", 16, 0, SLAB_TYPESAFE_BY=
_RCU,
> > +                               NULL);
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
>
> Hmm is there anything inherent in kunit that keeps the test pinned to the
> same cpu? Otherwise I think you'll need here
>
> migrate_disable();

Oops, right, good point.

> > +     p =3D kmem_cache_alloc(cache, GFP_KERNEL);
> > +     if (!p) {
> > +             kunit_err(test, "Allocation failed: %s\n", __func__);
> > +             kmem_cache_destroy(cache);
> > +             return;
> > +     }
> > +
> > +     kmem_cache_free(cache, p);
> > +     p2 =3D kmem_cache_alloc(cache, GFP_KERNEL);
>
> and here (or later)
>
> migrate_enable();
>
> > +     if (!p2) {
> > +             kunit_err(test, "Allocation failed: %s\n", __func__);
> > +             kmem_cache_destroy(cache);
> > +             return;
> > +     }
> > +     KUNIT_ASSERT_PTR_EQ(test, p, p2);
>
> Otherwise the cpu slab caching of SLUB and a migration could mean this wo=
n't
> hold as you'll get object from another slab.

Yeah...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez2O4OvhKjdy%3DY6fzuK0Qf79JQXCXV%3DuQV2ED08fS1RNpA%40mail.gmail.com.
