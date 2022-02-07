Return-Path: <kasan-dev+bncBDHK3V5WYIERBLEDQ2IAMGQE2QH2KVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D4724ACA76
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:31:40 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id y10-20020adfc7ca000000b001e30ed3a496sf1674482wrg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:31:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265900; cv=pass;
        d=google.com; s=arc-20160816;
        b=BU1sy/Qusi8IRdmdr97bcsXe8hghyk/Feu4LxgiuROzWziHEknj5nl6nZEmbzH0Rm6
         /Qa9Jn3eIun21gZ7+uF+EiEVPOngHzFvFI41T642rtqmW4Xu0XVLHjXf15Kd3qY/yArM
         3bPTKNX0WCOIBrIb3DDPWB1p9ym7wOYXx2TDmMW3UKmgJmIDTw7mgu9Za8prico3L+TR
         29pZ+CX8CWyF1qKmX0KRdoBI+hThSGpFmF4COcRIICBa4kHyh3iR0+EfFIYJPWjWCQPx
         NKu/+lxa+5sc2EBvqxwgbLmU2NxbO1ohzp8Dnt//456YdpzIHxvfqHBJzi2R7wO56lpI
         gKvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4WHjld8ZEDzzDkmWz9Y7G8E32Ay36QdGKY3aPgRP9hY=;
        b=NO+UlSzAXsKsCS3nR8chxm3v2pvBdGN7G98+HvIl4WTMrKVKgb8bnuEDBz8EV3Fw8t
         27DK2ezTguTS2gzkQ9J0WHNhW9jZFFy4Bqz6rsxcWNAVcDtKlZPuIbIYzJnwMV/CaEMM
         7wYxOdGlj8EFAb/WKze9sKNKcOcO7WGFhFSL8LxikMvafhHfYX7IkMcjPkNt3mfMUNzr
         p7iTkd4BDck7o9FmOY7Nh7P4LS4zRm/PDNUSgYsuhypD76Hei+GEoyBtVxbnaWdXkUB2
         dJayJ7kKgYJLBzJ5mpGyymeV/R+IV1OK2AhCN7ZQERADikk/r1OzQ8lZ8+EGfFOq0Yro
         48Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JahJ6uLW;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4WHjld8ZEDzzDkmWz9Y7G8E32Ay36QdGKY3aPgRP9hY=;
        b=jEY6MeLxgILC6OIWMKuuqGH9zdhFlxz6smFZJQJPhvOUOOt/6odllWkxARsf1SCd/1
         CypkPvqPgIVM77l0o7NfqbZ/Ta242SiCnGHZNocz+7jtNSz+1dAffI8X9FCypdUHQvTe
         LPsa7rjDpfaN2rgEMmueD60bcch6K5LTJV10zMJBEEDc4TFlTukL59tKMKs58H98RT8R
         yIFfHPUpe+72LdRuNn95/OHcOaWvNw2UZ8OPOdWtnbeNJWg2ZKJ27fXN9RpjxXM+B2Uv
         8Vx8XH9tUxoPeWKY/0yjcCEWEf5cr5YKLgQAX2pZjk1SzQttuuU+ZHtGYFwLTmDLlTS3
         c0+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4WHjld8ZEDzzDkmWz9Y7G8E32Ay36QdGKY3aPgRP9hY=;
        b=XIg8p6vKKaxqkdWtp9KT7+l1IxhqtKIud8ymLrb82+heNPH1TUNhZWu5xHoS7QCGHF
         slI5Pz7s0OnRVeKH4IoVEcUO22TJiyCPz1JK0kGZUhyEx9LWbVuX6roU5H568U+cVnC+
         hQl84AJNJJId4VWjhiaBvPPqmCHPLJ3hEGQkKq0MXtO0EoLSnvaSi9XvVDpeeantx6i6
         dOguYtNWcty/0TzZGL+6dNYZDwOB6C15vycUl+13TiEZ7VIvMxosLSUZhy8233C6qOIC
         a0TvHA+Q4l6968+XvZ1hF8jRqtOVLTfFk9QDQr2w2Q27t78bebCm83llLGh0URUFO/Vn
         hCHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JaAUTg0BahE9DR3+xJcTj2OopQ6P9JgBpFuQqUcc4tUrC49jT
	1cle6tgM4QtArXwBn+Pb0jI=
X-Google-Smtp-Source: ABdhPJzt3qr8f9vVsd7IkBTBTp6b4SxHTxmCEOS0t5oaZumEkfWLYBGNV++KymUwMs+xrvzaFPu0ag==
X-Received: by 2002:a7b:c954:: with SMTP id i20mr493109wml.83.1644265900210;
        Mon, 07 Feb 2022 12:31:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a2de:: with SMTP id t30ls244053wra.1.gmail; Mon, 07 Feb
 2022 12:31:39 -0800 (PST)
X-Received: by 2002:adf:dd8e:: with SMTP id x14mr874804wrl.576.1644265899337;
        Mon, 07 Feb 2022 12:31:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265899; cv=none;
        d=google.com; s=arc-20160816;
        b=CDT9sdAw0kGZLngwUMreTUZc1shr6Yhl3v5dGDnmlgUtcgAV6lif6BOtJkaiszgdXY
         fdVTqFgoYg87ZsuvuxMK5zDaH/7nbuZz/woVNqyP7XIWL/1MKpeBrk5VyGBbfpAZS3Jc
         ZGMlD9DUXsUBCu9QhrEmQDXKa3h6OZoXxERl3QFDmQFovqrcHSVyTkC+YOiObRu4wBg4
         cOyEyRfhCg23AU6gDzDs49nVeozgUUtOo3M9BBGyy/hJ9OJYS3GV7RxETxKAnAa9/CS8
         Evmhhtq/I9wGDuuNO71Ig+0sV2/GaqrSLv7Zp9jExSIDRH4FpeMxUjCI2gZIy+EeskKY
         tQSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GD9WbSwS36ZJGxaF9Sl8pq7QQD63VifIib0L26eGX/g=;
        b=UbiuX79RWvZMcf0UoJRUUw+rCqXnOd35r0S5GC3SoTmTuS+u2VP2c1raEG3d/yHRI9
         J781MyNgtjqyYZky3kKNWpDUuCak2wfH5a1sac6Rdp8LnjbgxYxf/vBoQdl6OL72Us2r
         x1HxbjkAV1erd32esRd1KJSlYn4cTVcq4nfwgzv4kfs4eWBd87j5DrjMs93OqVbUyySo
         2Zlc992aGMaJEC3CeYq+mvT8WDHs+v9YmaGa4RQQQYQQMyKwIyS10xNoq+P2JR65MaB2
         bgtWLq/9YkWVL2sBSKV6sjf7Y/4xoq6FuK+vY446a+J2S3fWNzotxvhhYafRym0GS65W
         ir+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JahJ6uLW;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id l16si335300wrz.7.2022.02.07.12.31.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:31:39 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id y3so24803700ejf.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:31:39 -0800 (PST)
X-Received: by 2002:a17:907:6d29:: with SMTP id sa41mr1101181ejc.272.1644265898934;
        Mon, 07 Feb 2022 12:31:38 -0800 (PST)
Received: from mail-ed1-f44.google.com (mail-ed1-f44.google.com. [209.85.208.44])
        by smtp.gmail.com with ESMTPSA id z6sm4027932ejd.35.2022.02.07.12.31.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:31:38 -0800 (PST)
Received: by mail-ed1-f44.google.com with SMTP id b13so32710486edn.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:31:38 -0800 (PST)
X-Received: by 2002:a05:6402:510b:: with SMTP id m11mr1237037edd.290.1644265897849;
 Mon, 07 Feb 2022 12:31:37 -0800 (PST)
MIME-Version: 1.0
References: <20220207183308.1829495-1-ribalda@chromium.org>
 <CAGS_qxoTLwvVjDGbfeOjMrGvh7sck7TDmiVeDXS2S5oyDWiKzA@mail.gmail.com> <CAGS_qxrkswforSv4XKGChwOZ0MbTGzCqYKsZq=0Sx6ThMOrheQ@mail.gmail.com>
In-Reply-To: <CAGS_qxrkswforSv4XKGChwOZ0MbTGzCqYKsZq=0Sx6ThMOrheQ@mail.gmail.com>
From: Ricardo Ribalda <ribalda@chromium.org>
Date: Mon, 7 Feb 2022 21:31:26 +0100
X-Gmail-Original-Message-ID: <CANiDSCvJ0AnHwqZ66caT9xUidTFp1Akck_UkpQxwojQRpSLMyA@mail.gmail.com>
Message-ID: <CANiDSCvJ0AnHwqZ66caT9xUidTFp1Akck_UkpQxwojQRpSLMyA@mail.gmail.com>
Subject: Re: [PATCH 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Daniel Latypov <dlatypov@google.com>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JahJ6uLW;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::630
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

Hi Daniek

On Mon, 7 Feb 2022 at 21:29, Daniel Latypov <dlatypov@google.com> wrote:
>
> On Mon, Feb 7, 2022 at 11:09 AM Daniel Latypov <dlatypov@google.com> wrote:
> >
> > On Mon, Feb 7, 2022 at 10:33 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
> > >
> > > Today, when we want to check if a pointer is NULL and not ERR we have
> > > two options:
> > >
> > > EXPECT_TRUE(test, ptr == NULL);
> > >
> > > or
> > >
> > > EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);
> > >
> > > Create a new set of macros that take care of NULL checks.
> >
> > I think we've usually had people do
> >   KUNIT_EXPECT_FALSE(test, nullptr);
> >
> > I'm not personally against having an explicit NULL check, however.
> >
> > But if we want to continue with this, we'll want to rebase on top of
> > https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/?h=kunit
> > since a lot of this code has been deleted or refactored.
> > E.g. see https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/tree/include/kunit/test.h?h=kunit
>
> I forgot to mention, it'd also be a good idea to update the new
> example test case:
> https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/tree/lib/kunit/kunit-example-test.c?h=kunit#n76

Already in v2

Thanks for your flash review :)

>
> e.g. just adding
>   KUNIT_EXPECT_NULL(test, NULL);
> with the rest of the pointer assertions



-- 
Ricardo Ribalda

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiDSCvJ0AnHwqZ66caT9xUidTFp1Akck_UkpQxwojQRpSLMyA%40mail.gmail.com.
