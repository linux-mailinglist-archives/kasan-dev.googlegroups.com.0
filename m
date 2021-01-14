Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMOIQGAAMGQEYSGMQXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EEDC2F64A8
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 16:33:07 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id q140sf9006204iod.5
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 07:33:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610638386; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vf8Bqf4cMN79NMgZRGN8yML10vTZQ3KMN5WRMZniVGXq/h16ZUJl8vwSDVG6xQIzKN
         0TvrBBoZQTe6sHeIZu9MXsV+EVSWuwx3dseQ9ap4i5kLnaT6eHUtKCWsRymw4zzO9ZBx
         hHNOp5Qe+H0Shqk81/JcPt2KFGFUGtGahzcDQGx2DePDHO8a9yXolfaAJHkgMd6kCccU
         w5uRacbyNNFN8nNtSqHBxkRAHiJ7scDNfFMQCrMuWeLL8dVEjKlkYHyf2DvLnP3P2gJu
         KRchLlIuCxThdJ4xGZVOokTVoNNPxYnkWF3IkU0kD4jiXG5/ZqsGM+Wvwk6pJPdURAN+
         pkAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=okcoqqucPXlYbdriAffN2YcmdDFA8y9DkecOYpPNSA4=;
        b=s4Y6o1hAwjyeGmCODT0VbMlN+PmfLyVPBmJsIsDLRXG5Z7KQscPFhk4qdDTlsAbc6M
         vy9uqKZvCl7qZYvbV2eIylifUS8cnmDeo7WvKP8YA56vOrwM1xkzt8SV0/rEr6LMgvi2
         hLcAj8YjcFSPkASOYRn+KHkXyIcCDJLEzyr/OPIdUhZS8Q6dFpnWSKDYvLwHNYcksdSE
         oYS95cc/lKmZdnkQMJScqVuBK71WtIa+RpoG9X964g1jzMrymTTRBBmEUXUOf6ObvGrE
         hJQd7dj7mxL53e5lOqM/c48INaToP1DdmVHE8wx35bZOLM1MvQkJUwA5vzf+S5Yultkj
         sS3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eBy7cKZ3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=okcoqqucPXlYbdriAffN2YcmdDFA8y9DkecOYpPNSA4=;
        b=oAhSyCryT2k3eoKlEq1YxZM7eE8RI7jO+fG5pR1FG8fB2ZjgMcu1gFkfEbx0tAB47P
         0iBKj4JI2GGj2yF4Vv1SfuiE4+MK7eQDU92Nzj/8FxTLt/xRL7eAZetYzsqwbAijsv28
         mxkmzDgeusfKd5UmHTUmyELYKhcIBRGEIK1KSFXjaby06MBhWJsvyGf+jqtIaNKiI41h
         CAEnSm/O1NhkuUwUOZcT3fgFuwBc//8pYkKwdMd6oer3KrHGA4TMZZev/L384mDAJH7x
         PKRUliLo9TFeCGr+aeh7eSr4hJ8eLVIdmK1Dy5aEiqkzIpFaL2Tp8Fw67dASp24XUE4B
         3rsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=okcoqqucPXlYbdriAffN2YcmdDFA8y9DkecOYpPNSA4=;
        b=eWEdu6wj2RdP6PoTsfhSMMYj6wGT1hvh12ReW8R19e1QhchjVWT7ew+0Df03Yxkgc0
         ldn9sIUydeeZ7fe7ZZgZ6PKFp7XbdZz7cTeSZcrkJcc+lufXZjM0KXuVdIFmKhm695+4
         MWj+4d9qzNfI9ozYxCwWBSFrC4Fii1JWTYsRLNI4y3UShXNK20OMKU/Hyco+ON1mhYFJ
         nDeU6IvS1UJsIQX0pf+2VANLnlTck3DozNgF6i0V6SECEdoBnvJKNCIesp7zgOSlJp3q
         DE37umpE4dJu8rZppKQOf9fGd1bN8510g0sP3c2x1diIDmJ7CkSp1TbOd5XP6/kTrwcj
         1U9w==
X-Gm-Message-State: AOAM532XBnjDqBS8q6YJ+cQRO3latW4fQHxjhZKHUdnpODyBfwAC7lIW
	PlTuw8c8mscaMrLJckxWaL8=
X-Google-Smtp-Source: ABdhPJwv66r6e5BC22Rurg27aBZjOiBzhvrE8cTkU6IzHRTLuW7PaHHpK8Wkbw87mkhtkDhULSJuJg==
X-Received: by 2002:a05:6638:2192:: with SMTP id s18mr1442974jaj.18.1610638386015;
        Thu, 14 Jan 2021 07:33:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:991a:: with SMTP id p26ls344205ili.7.gmail; Thu, 14 Jan
 2021 07:33:05 -0800 (PST)
X-Received: by 2002:a05:6e02:1447:: with SMTP id p7mr7211915ilo.93.1610638385658;
        Thu, 14 Jan 2021 07:33:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610638385; cv=none;
        d=google.com; s=arc-20160816;
        b=GncBaIU9Erk0YbDinu0F9rAcj6RuA4z/uuV0BctXCkdJCDz/MVB46NanBkbBUGXwWs
         1Opwgh2ILAUlc0MvSY5PRWk332M/Ua6TBweFWzlY6BmCwRBi9wGOExSIV0OJc100YD6N
         wY03BwSsm8CY8ITcbs6PuR6OkodkCRaWOYtuK9WPw8bzAf1MFzOm9Bg14p8y52vMhiya
         qiIgWiI+4jEMCH2PqzVi8WjWhbDv7Joth04oKfVY+X40AFSAkhx0tX7SfPpxuR1LJTD2
         lylu/PWZAp7pcaTodHfDJO2ZgLgx08/HmfdwUMwQ6dYmIyJ6xs9CMnumf0riGN0EEcn2
         1s+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rZ/Nqkyz1NzBbC9d12mdlvYcjVEDi+jgRuueCoXzbVA=;
        b=EHypOyKd8QMcIHek0OzaCVxOm7oF8xeEwTObopQJHl/u1NNXNHNWpoCdEdZ/+9XKo6
         hJ2+vcLzczkUzMi1C0jFxZHBwIZ4nUY2LwZirTPP8qPIrdfxMMWU+tsyytcqu/dTQ0kP
         2gVsGfjYvdJmMn88ResnBu9nPom9hhXxYyQY19qwLG9IRl+3zTWx6U1Fyrw747rHozIL
         13gQhUUV+bvbNylUufbz+pEvFGfyJndxnZaoSOEnrpI3ocaTRdu04wNkgaxRbCvBymrg
         FrBAVPGaPaeU4zLCTqmg2zfIb3CqBZGTY8q4enjCi5oZ/brYjle2GS+wYpxSKxfmunOi
         ER5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eBy7cKZ3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id t69si670679ill.3.2021.01.14.07.33.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 07:33:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id ce17so1109802pjb.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 07:33:05 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr5447639pjb.166.1610638384902;
 Thu, 14 Jan 2021 07:33:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <0e994d67a05cbf23b3c6186a862b5d22cad2ca7b.1610554432.git.andreyknvl@google.com>
 <CANpmjNN5t0-dEHJUqKbT8eRQcj2epdiR5xbUkp=JR-Ka7jLM4A@mail.gmail.com>
In-Reply-To: <CANpmjNN5t0-dEHJUqKbT8eRQcj2epdiR5xbUkp=JR-Ka7jLM4A@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jan 2021 16:32:53 +0100
Message-ID: <CAAeHK+zATEUJX+hm0m=jX9Z61CFRoMN3hmHuk8AL1dFy3W9KAg@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] kasan: add a test for kmem_cache_alloc/free_bulk
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eBy7cKZ3;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Jan 13, 2021 at 5:38 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 13 Jan 2021 at 17:22, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Add a test for kmem_cache_alloc/free_bulk to make sure there are now
> > false-positives when these functions are used.
>
> s/now/no/ (but by itself doesn't necessarily demand a v3)
>
> > Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  lib/test_kasan.c | 39 ++++++++++++++++++++++++++++++++++-----
> >  1 file changed, 34 insertions(+), 5 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 5e3d054e5b8c..d9f9a93922d5 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -479,10 +479,11 @@ static void kmem_cache_oob(struct kunit *test)
> >  {
> >         char *p;
> >         size_t size = 200;
> > -       struct kmem_cache *cache = kmem_cache_create("test_cache",
> > -                                               size, 0,
> > -                                               0, NULL);
> > +       struct kmem_cache *cache;
> > +
> > +       cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> > +
> >         p = kmem_cache_alloc(cache, GFP_KERNEL);
> >         if (!p) {
> >                 kunit_err(test, "Allocation failed: %s\n", __func__);
> > @@ -491,11 +492,12 @@ static void kmem_cache_oob(struct kunit *test)
> >         }
> >
> >         KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
> > +
> >         kmem_cache_free(cache, p);
> >         kmem_cache_destroy(cache);
> >  }
> >
> > -static void memcg_accounted_kmem_cache(struct kunit *test)
> > +static void kmem_cache_accounted(struct kunit *test)
> >  {
> >         int i;
> >         char *p;
> > @@ -522,6 +524,32 @@ static void memcg_accounted_kmem_cache(struct kunit *test)
> >         kmem_cache_destroy(cache);
> >  }
> >
> > +static void kmem_cache_bulk(struct kunit *test)
> > +{
> > +       struct kmem_cache *cache;
> > +       size_t size = 200;
> > +       size_t p_size = 10;
>
> s/p_size/ARRAY_SIZE(p)/
> ?
>
> > +       char *p[10];
> > +       bool ret;
> > +       int i;
> > +
> > +       cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> > +
> > +       ret = kmem_cache_alloc_bulk(cache, GFP_KERNEL, p_size, (void **)&p);
> > +       if (!ret) {
> > +               kunit_err(test, "Allocation failed: %s\n", __func__);
> > +               kmem_cache_destroy(cache);
> > +               return;
> > +       }
> > +
> > +       for (i = 0; i < p_size; i++)
> > +               p[i][0] = p[i][size - 1] = 42;
> > +
> > +       kmem_cache_free_bulk(cache, p_size, (void **)&p);
> > +       kmem_cache_destroy(cache);
> > +}
> > +
> >  static char global_array[10];
> >
> >  static void kasan_global_oob(struct kunit *test)
> > @@ -961,7 +989,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
> >         KUNIT_CASE(kfree_via_page),
> >         KUNIT_CASE(kfree_via_phys),
> >         KUNIT_CASE(kmem_cache_oob),
> > -       KUNIT_CASE(memcg_accounted_kmem_cache),
> > +       KUNIT_CASE(kmem_cache_accounted),
> > +       KUNIT_CASE(kmem_cache_bulk),
> >         KUNIT_CASE(kasan_global_oob),
> >         KUNIT_CASE(kasan_stack_oob),
> >         KUNIT_CASE(kasan_alloca_oob_left),
> > --
> > 2.30.0.284.gd98b1dd5eaa7-goog
> >

Will fix all in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzATEUJX%2Bhm0m%3DjX9Z61CFRoMN3hmHuk8AL1dFy3W9KAg%40mail.gmail.com.
