Return-Path: <kasan-dev+bncBDHK3V5WYIERBDULTKIAMGQEA3CGS6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A06C4B2964
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 16:49:35 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 125-20020a1c0283000000b0037bf720e6a8sf3719943wmc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 07:49:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644594575; cv=pass;
        d=google.com; s=arc-20160816;
        b=gqqq5dnu8RPvoio/bK9ChpLONSxXMKOtaTfCJn+7UuqMZ4ihQet/S+IoFRWkla8Dqg
         97AO7XKkieSQZDpAyrMeah4Ewfgu5HmUhuTcxJvf+o2WTHf+A0t/AevBJ3hJQ+orhCgB
         Q5VLh26cDE+NOV/xJb5sbOTb1jsiVsv0CK6CaApMvOqz47SzwFVOzzMJ/XPquVV7wRpg
         eCyCsHdQtBC86QgJ6Azm2J7B10pmRtxZU1rVFAh/5fotSnc+/+w4/NauzqsmAf42Tbmj
         llHMhR4nV3tjnmv1qujJO/CMNc6NyUqgdZTNwFNdLINmw2NLDo9VMlVJI7q5vZmX0rTE
         ugeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=XUJH+CHobdIVK0cyu4Jv7vtJnm2Mfycy1az7EQgGwMU=;
        b=Gn0bdmOEBIbCxJvgetcmebPX4icfHOFo9rinQTdIdZ6C0z3D49sozwJ6tbfAjKt8MI
         W1rw9hLmAgGnUv9Y8M0JtB3A7UJnvBCiA89WdAdrIVNqZLGTK5psAqPiStcayso0Nz1Q
         7mN65KCu+QsaDUgffyPfTQKvrCdSijO09d4ZMJBC1D2i3HGSquVtcIcjxlEeU83UHbeh
         EfincAwkzwXDJhdtrzKio4D/eBPyElzWPw6i8STuQWGlSycZiMSyLxx1/I37402EMQza
         bWSzqGEQln51QMUQbClITUAmFrz7Ta09mnHo8rThrnSFYfX3ISpL8WCBOScr39b87Z76
         9Drw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FP56XRMN;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XUJH+CHobdIVK0cyu4Jv7vtJnm2Mfycy1az7EQgGwMU=;
        b=lu0TZiYZJ6GekT38ZFWkoa3k63R/b7aNdnLdG5iQ8F0O1y2rAf1kMclWd/iu2JIm2I
         bdBdju0eyVDx7eIccjvaYAsLSjGq7RRRcCA+1WtzJDoj8vRcuLC+gD0NrSS7ATh+lefn
         w9bxVZJgzHa0PJzs2BjAclIFouhgRMCTRhoo6Mf77ZlT77MG0EBe1onMSnYyepUnJ3Kh
         XGL4Az8aacryapX/M2iD97eJQI/GrdVNb6LHgXf057iYqmX40mwbLcol6Am4DiYsrpg7
         tmDrusU62Vb6XAKiCz2v2oYJ9vY4LI2vf5sJ4gga6p9AH6C1i7V1AdnnZcFDcbAN9rQZ
         9Byw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XUJH+CHobdIVK0cyu4Jv7vtJnm2Mfycy1az7EQgGwMU=;
        b=PPBMqqhGPOrSV+1rIwT4eXDmU+Ts1xqO6t/ZioF8omQ/E/B0oen0rNIwQJuaTf25UP
         FHnIKBdiVL6Sz/KHxJ9/qKq29loBf/HrWa9yBsCxqxRSKXc2QhpbKayCukMKmqJ4GjOn
         7Tyi9jYxzlLk7a1gRKKe9RL5GTmgPvOtCDmfR+Rqu+U6AaATiP4OHUfOJ6kzbeCHcwvA
         sXauVSDtgU9DM1mGSz6bca2mPsp5fS6F7dHrVvfvyDwvUQemgEkqgs1YFyicu+dzpuRD
         gcHKslkwzW7cyjglSEtXWVuk0hqlXMBfljLJEt5weEPD6E90v/VkrIhMNOXLPW8lffcu
         d6OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LErWGOiBbbLewnzPPzBxvp5urZ0ylROud9e6zyLH5Zv2ztuSR
	CaTHvfXFfD+J9pz5/L+PP9U=
X-Google-Smtp-Source: ABdhPJxI7sRRRsuBKARYImxCO16EhCxyPFWFEO6yAQbAuzJ3MzgDLgRlxwv6jhWmJQY5vL0v3tg0qA==
X-Received: by 2002:a05:6000:15cc:: with SMTP id y12mr1882172wry.131.1644594574772;
        Fri, 11 Feb 2022 07:49:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a3d0:: with SMTP id m16ls75761wrb.3.gmail; Fri, 11 Feb
 2022 07:49:33 -0800 (PST)
X-Received: by 2002:a5d:61cc:: with SMTP id q12mr1792612wrv.497.1644594573877;
        Fri, 11 Feb 2022 07:49:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644594573; cv=none;
        d=google.com; s=arc-20160816;
        b=OaFDfhp0H2mLrIqrNUBDxlmmVjvVR4ytKP704bZDVlt4vN0CMgyo8suRQJF6g+X478
         X50V/H9ay55ASpazk0JrS3vUcw3KJwwOG9Bv2hDleZcTtzd5wUrUGkx2DK/odYa/RRdU
         bo2MKi2U7vfwItMMZYECjABMjoAhfD22+jnhVrmLfw4hP/0flQzn2Fq2eN2rNL7t/xMY
         qwAcSxTtTvuHoZQAAQjv9GpPjZ4O8WgHGnArVKVqAVIvdMwEb7No+SK8tr66MQ6jvF6m
         x0RQXSKiw1wDBp8ZQDTcsucm5T+5dufutJ4Ifao2+Vmv3NHSMtS68vtWWBUa7vhiTdQO
         PZ7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jOGYj+Ddot3c2dYIVm3IUDs6tgN4/isqSj2clhmBLQM=;
        b=g6m5ZzXJnnuv/vO0Rl7Gi01CLDsFfAcNy28CuueLOZAHuI7TrIM/wRIhig4uop9NnU
         FpTxwKIlBQHriczl+cIMf3E0ggnwbH+R626/HJyxr4eOMCjSa868afDgTruhszPOAlbn
         eS9OtDYyGENkpuqveCaOBEKvKHERbuIw4LJtDWqXhDX2sS9+yrJEEimd+6/2IkhmriAD
         s+zZicUYDqFWTMnut8lQDSFM+0shsgr4+dY+tnPZT5gU+qEPsqh+5ToclP88TCLnQ0G7
         tY5exoSDwZYQA1TWorGSvfJAMSmgu+Jc9SMae+DtbOLLmAqP65ulhfCMaTUO6UWtIT7P
         9jNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FP56XRMN;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id o19si437408wme.1.2022.02.11.07.49.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 07:49:33 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id d10so23765164eje.10
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 07:49:33 -0800 (PST)
X-Received: by 2002:a17:907:3da1:: with SMTP id he33mr1862967ejc.603.1644594573568;
        Fri, 11 Feb 2022 07:49:33 -0800 (PST)
Received: from mail-ed1-f45.google.com (mail-ed1-f45.google.com. [209.85.208.45])
        by smtp.gmail.com with ESMTPSA id jz17sm8057193ejb.195.2022.02.11.07.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 07:49:32 -0800 (PST)
Received: by mail-ed1-f45.google.com with SMTP id co28so17176826edb.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 07:49:32 -0800 (PST)
X-Received: by 2002:aa7:d84e:: with SMTP id f14mr2555166eds.46.1644594572132;
 Fri, 11 Feb 2022 07:49:32 -0800 (PST)
MIME-Version: 1.0
References: <20220211094133.265066-1-ribalda@chromium.org> <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna>
In-Reply-To: <YgY1lzA20zyFcVi3@lahna>
From: Ricardo Ribalda <ribalda@chromium.org>
Date: Fri, 11 Feb 2022 16:49:21 +0100
X-Gmail-Original-Message-ID: <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
Message-ID: <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
To: Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=FP56XRMN;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Hi Mika

On Fri, 11 Feb 2022 at 11:08, Mika Westerberg
<mika.westerberg@linux.intel.com> wrote:
>
> Hi,
>
> On Fri, Feb 11, 2022 at 10:41:30AM +0100, Ricardo Ribalda wrote:
> > Replace the NULL checks with the more specific and idiomatic NULL macros.
> >
> > Acked-by: Daniel Latypov <dlatypov@google.com>
> > Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> > ---
>
> ...
>
> > @@ -2496,50 +2496,50 @@ static void tb_test_property_parse(struct kunit *test)
> >       struct tb_property *p;
> >
> >       dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
> > -     KUNIT_ASSERT_TRUE(test, dir != NULL);
> > +     KUNIT_ASSERT_NOT_NULL(test, dir);
> >
> >       p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
> > -     KUNIT_ASSERT_TRUE(test, !p);
> > +     KUNIT_ASSERT_NOT_NULL(test, p);
>
> This should be KUNIT_ASSERT_NULL(test, p) as we specifically want to
> check that the property does not exist (!p is same as p == NULL).
>
> >       p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_TEXT);
> > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > +     KUNIT_ASSERT_NOT_NULL(test, p);
> >       KUNIT_EXPECT_STREQ(test, p->value.text, "Apple Inc.");
> >
> >       p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_VALUE);
> > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > +     KUNIT_ASSERT_NOT_NULL(test, p);
> >       KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa27);
> >
> >       p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_TEXT);
> > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > +     KUNIT_ASSERT_NOT_NULL(test, p);
> >       KUNIT_EXPECT_STREQ(test, p->value.text, "Macintosh");
> >
> >       p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
> > -     KUNIT_ASSERT_TRUE(test, p != NULL);
> > +     KUNIT_ASSERT_NOT_NULL(test, p);
> >       KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa);
> >
> >       p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
> > -     KUNIT_ASSERT_TRUE(test, !p);
> > +     KUNIT_ASSERT_NOT_NULL(test, p);
>
> Ditto here.
>
> With those fixed (please also run the tests if possible to see that they
> still pass) you can add,
>

Thanks!

To test it I had enabled:
PCI, USB4 and USB4_KUNIT_TEST

and then run it with

./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64

Unfortunately, kunit was not able to run the tests

This hack did the trick:


 int tb_test_init(void)
 {
-       return __kunit_test_suites_init(tb_test_suites);
+       //return __kunit_test_suites_init(tb_test_suites);
+       return 0;
 }

 void tb_test_exit(void)
 {
-       return __kunit_test_suites_exit(tb_test_suites);
+       //return __kunit_test_suites_exit(tb_test_suites);
 }
+
+kunit_test_suites(&tb_test_suite);

I looked into why we do this and I found:

thunderbolt: Allow KUnit tests to be built also when CONFIG_USB4=m


I am a bit confused. The patch talks about build coverage, but even
with that patch reverted if
USB4_KUNIT_TEST=m
then test.c is built.

Shouldn't we simply revert that patch?

Thanks!

> Acked-by: Mika Westerberg <mika.westerberg@linux.intel.com>
>
> Thanks!



-- 
Ricardo Ribalda

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiDSCs3%2B637REhtGjKy%2BMSnUm-Mh-k1S7Lk9UKqC8JY-k%3DzTw%40mail.gmail.com.
