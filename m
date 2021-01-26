Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPNX6AAMGQE5AG7GHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B084303B01
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 12:02:42 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 5sf7385919oth.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 03:02:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611658961; cv=pass;
        d=google.com; s=arc-20160816;
        b=L/mTSSQJOAec0Xh0S/eUgJlvophu7VwuZHRwjqtntllo6ZnJGprTJDO+b78GY+as29
         /PivAJQrt4C4Uw86gX5DAhm52uQkpnCrh5eszi1/Rg3PqyNU+0pHHhk4sJHl3i8h+yMv
         P3KN7yaPe41flDVPP570nUMT/8eHSPY0yV+7fXa4WAWja6jvLoWTzPeiuiQx1VCo48Ho
         CsFqVfXrKI37zwS2NNXj9fMI6rU5VBkVe9J8qZqI30SNkeQ7WX8mXEfkHCjs5ey8h5mx
         6fn+z4/CPvlNSLf8hqv3zNc1s7axzWi3clgPiwJJaymYoULV6C6601ng59U6mZTok5mJ
         vLaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=owhrQYcWfFf3zADnIDXS3aJOhtV6nIISan8HHW6qcMk=;
        b=aX1a0YjNzAx0qJFa5msEPTVYR2azi7a3swLVB8jZWi40UR1/3zjAfPbKIUgmbC4EYf
         bEa7EXCneSTlt+X62S9C82Dxg6ojCuoZEo6QjRU6zJeQGSozsn35N5vqhKwdtXOg6wS/
         DcFfw2Z8IzPhrdHVKLsLSa04MYldu4SMdtn2PPlHakVqsa9sNCbWTh1lEIMDt1X7dqqm
         vd9/5UYiqPPQ4xACK15+xDXD/dwhyrq8sX7hqNHCpamARqQRawDLDFzN7fkpXiTJ8Y9D
         1NXScDjGd9afTzyrpCUTMU1I4trH8tmjtMiZyTzvuAaqC1oL5M9zcxb5xGMnjBVdDh1C
         fLLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JaUENZjP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=owhrQYcWfFf3zADnIDXS3aJOhtV6nIISan8HHW6qcMk=;
        b=l1Zn119cBExvkvo2Irh5TPuT+bfwqvPOqKxLnvrZ3+lFbNfrjm/Bd9YlMK7kS2UGsg
         IX2LJbwWFRcFUlEKYVPiiaGPQub6o9l2jA2Qlc9eBaG/vcpcoSXdvahpvVTg1cZcB4pY
         lPUuymk2xB5Bb8G+4HT6vZ2FMhqGTDHYG0uaxA0SDCSIN5IQ+6guuSdM9yyj+gjbOJdU
         8s/ghNe3xDTIwOzbBOmvwfuj56QHbL01beAAzcwdJkXsRi7lt9NjKfyZu1IprVW/4wr6
         tyZdkZa41yfJpMQMZT3Ia6b+oEo09gXmCp3bwsKhfheCZVf/K3CHkGdubGy3hB2mcPlN
         1puQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=owhrQYcWfFf3zADnIDXS3aJOhtV6nIISan8HHW6qcMk=;
        b=AylKLbevCnbJVRaBfVrfaOHTmJJrIU2bE/M5nU1clKeDM7KN2GwqPn96Zfn20NycYj
         O0w5etC/aUKGIKRDAYWi+2STdBmjGwC3qly4+w014ahFALCaC7tXyXc2pd6bWaNMgKs/
         pJDY17opySDuj/zxRrScueIvkB0XEreJ/AIsqqglA1f/A+Bw2SXCg0/vu2mBOd9PDmKs
         VMGxH81vi3ZBKmzzbT+V3VN38djHN7AwrFZaDfh973vZwc/YaaDgLvdNN+fwdknpotIk
         AhcDMvtkkLxtaJREwebsi1zKFtOHb+ftMbBBJgU02IZzZqTbYmbWx7oacAfcsMFfYEzf
         ByaQ==
X-Gm-Message-State: AOAM533VSDQos+MqD1A/M7GlW0Y15Do+If4ZOdkzd8LxPCAwM1UrJKfz
	FbafqnVgSYu8O3IicDi3Q9Q=
X-Google-Smtp-Source: ABdhPJwWPrJZ0IhO1OVRixPpOsnP3MDgVJdRhDahbx5zfIGPCzwarPElEVDfGKeyAbB0uJj1ljkw6A==
X-Received: by 2002:aca:6708:: with SMTP id z8mr2919640oix.55.1611658961255;
        Tue, 26 Jan 2021 03:02:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:923:: with SMTP id v35ls3397469ott.0.gmail; Tue, 26
 Jan 2021 03:02:40 -0800 (PST)
X-Received: by 2002:a9d:19c8:: with SMTP id k66mr3645798otk.89.1611658960585;
        Tue, 26 Jan 2021 03:02:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611658960; cv=none;
        d=google.com; s=arc-20160816;
        b=LVvEagvRHZvqVKonpF6rhq0jhEqO5kAgqp4io4KZXmzcBAmJgAlQ29H3IDqmE8ZMyV
         8UN8CfxkV2Ou+Z0Q9kv1XKGgYuLEhIF1yCcR2cw94DyQAezqQYPf3/WzmEdsj7lRm5WP
         l3OY1DRPQmtU6s7+FObVW0XEm15b6NIr8yXlgMcXMKLz61x+tpi0tYwla9NLjzO22Q6j
         hsZl8zXqC9q9+cn941//lQSpxu0ADwx9XO1wA9HSokGDTZ0kZygaCx20Z0kTKk9dATjs
         NN5PcsQ0EEHTAUYWErbq/YHt0xwpQgI0XRwll+GREFvIORK3EwJhaMZRC8nlD76QH+WL
         fohw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WnWYR4SKas2U9WPFSvBQnaZKF78/yaoxJlUG6e0GR8I=;
        b=mDgElZLpZP60GFRcu0Ds0Yfw6bzmxi/zDS5p5XsWviMt9lpZ81Qj/Pftp0PqxQFGv6
         DkhiX6bl/0dnt/Aw/JlBIf3XbsTleYZrehn4/UVEeqMfB7EXZLHUYK5sxTUqmtTAe7V9
         HjSLfHTyRpegweJN1CTuSKwj0svPZcWYoDGht7oEgV7JYRoHeDkoDNyN6ifIMKUa8Ux8
         hPu27CY0mvxGt0ycDbR07OkmYkWnuM3Cy6zCEN8hrX6dunKVlFLKRIyZECsJtumvqrQs
         10zZNlT8itsKUyLhwZMkOlnYI+wn533iHPX7ypoPDHG86bfTz6y/zvZQrVc9g0MHbIU0
         trQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JaUENZjP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id j1si306744oob.0.2021.01.26.03.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Jan 2021 03:02:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id h192so18107153oib.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Jan 2021 03:02:40 -0800 (PST)
X-Received: by 2002:aca:c085:: with SMTP id q127mr2922730oif.70.1611658960220;
 Tue, 26 Jan 2021 03:02:40 -0800 (PST)
MIME-Version: 1.0
References: <20210113160557.1801480-1-elver@google.com> <CABVgOSnHh8-s+AYifkDjCDKCkkFcm=WiGSuuf2JFiMvjAU1Kew@mail.gmail.com>
In-Reply-To: <CABVgOSnHh8-s+AYifkDjCDKCkkFcm=WiGSuuf2JFiMvjAU1Kew@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Jan 2021 12:02:28 +0100
Message-ID: <CANpmjNPeKY7HZe0+zYx6BQ+oJ97Hq5j2V9QcHS_gjOJTtr8ENw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcsan: Make test follow KUnit style recommendations
To: David Gow <davidgow@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JaUENZjP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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

On Tue, 26 Jan 2021 at 05:35, David Gow <davidgow@google.com> wrote:
>
> On Thu, Jan 14, 2021 at 12:06 AM Marco Elver <elver@google.com> wrote:
> >
> > Per recently added KUnit style recommendations at
> > Documentation/dev-tools/kunit/style.rst, make the following changes to
> > the KCSAN test:
> >
> >         1. Rename 'kcsan-test.c' to 'kcsan_test.c'.
> >
> >         2. Rename suite name 'kcsan-test' to 'kcsan'.
> >
> >         3. Rename CONFIG_KCSAN_TEST to CONFIG_KCSAN_KUNIT_TEST and
> >            default to KUNIT_ALL_TESTS.
> >
> > Cc: David Gow <davidgow@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Thanks very much -- it's great to see the naming guidelines starting
> to be picked up. I also tested the KUNIT_ALL_TESTS config option w/
> KCSAN enabled, and it worked a treat.
>
> My only note is that we've had some problems[1] with mm-related
> changes which rename files getting corrupted at some point before
> reaching Linus, so it's probably worth keeping a close eye on this
> change to make sure nothing goes wrong.

KCSAN changes go through Paul's -rcu tree, and once there's a stable
commit (latest when it reaches -tip) I would expect Git won't mess
things up.

> Reviewed-by: David Gow <davidgow@google.com>

Thanks for taking a look!

-- Marco

> -- David
>
> [1]: https://www.spinics.net/lists/linux-mm/msg239149.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPeKY7HZe0%2BzYx6BQ%2BoJ97Hq5j2V9QcHS_gjOJTtr8ENw%40mail.gmail.com.
