Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZVCST6QKGQEGEEHWWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A498D2A9208
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 10:03:35 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id s201sf685702pfs.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 01:03:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604653414; cv=pass;
        d=google.com; s=arc-20160816;
        b=adseB9DzM58lnAOmgzKydg7EJAF0c7UG1FxfZAxXiqIOHpeWPi0NFYRoKibJ16KVQU
         0fl9SuquWWNg5KFgPpkbAUhuDtNzbYLV+zW6Qo5LwKup8ea72j/e67ac0giCz0WNr1x5
         CqNGr6WFmi86DNLi6G4SXphD18ZSdA8lCfb+SOQ6LXVQUBciU+wLOFXc3ACQmSJBRziY
         9K75XxQvoOTpTZyLPYaWn6GFWkWrEJScQKZO5l4slp8bq6xYMS1AWqpBn3QhjS2waWy0
         z1YMsn8JIPV39Zolo3HebtcIi+AGJ9i3C10I9kmrkFMFtwAFodRu2tuNuvafcv8yHSNY
         GZ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=R8L/NxNoc07J+jojdfGcIVasvTWDFZdDK2EFkJN07/Y=;
        b=Um2jm2+JrXe8P/6016igDyIRTgfWxymfNRqN+dweyC4wn0X76gngYh+48NzcJBpjKa
         FJpRp0gzwByiUXj7QYqf0+9zEqde6VcQVNkDMcxsidbKyt7HfGsyhIsFf8mmjbyWFllm
         mLvAMqs3JixxeFD54tmWuXvg61/QVgrvwpQbV2VAFKx1HrugXgvKbL0IlgrL2mDsFtx6
         xoLzMzxIDPGCLJepbTXSyHQFr0oE0QdNtWllLCmcfYTBqopWbo6C2f0tGwIdwpJmFW0g
         TyDIG4c3D+RtDebZPO3NYIEcJMWoCwNcNL+rh42V8QawK5OIQZ/LWGlm0kX6ec4JDFTs
         FNoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dllwsNe+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R8L/NxNoc07J+jojdfGcIVasvTWDFZdDK2EFkJN07/Y=;
        b=rGufdrC+rvcFqm/SCtzStuWKQcnVlQpbjEWYrIkxXpp/+iRvIN6xNUwAKuQlEIOL4H
         Pv6m1F4hOGw0TFPiJEk79WimO0Hmytuu+UNzb21IF+QU1NupiH9mtHLbsLHEPoylUz+h
         +VfFrK4i2NGsjKk333emKfoGi/Bl7Wpy7rsgPN8I0n9bJoGAnvvc++uigDlVWQAHAFfh
         OaQ6bivEjeKfXETWgXeZbJtaEFv9MslsIDPdObGJPcJ2eaunOa7NwDYJQndJbNF+CTf3
         QeKRANe1H5Y1zVseDAPn4CONc0S8OzSWZnckG7k4VO5SK+ocdvM8YaKF56EgSSmf17YQ
         rcsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R8L/NxNoc07J+jojdfGcIVasvTWDFZdDK2EFkJN07/Y=;
        b=s8yjUMbZnSxu3m7qoGgIPUzolqjl7ZDgCgHqczHx5JGYQOnHmbypfpj3PHAntKu2z2
         BkYi9c13/OW7RONgpHcRZoL5UvPr4PjVwKvvGafP6FwJgwbaO/STvMZNa3m7D3vbYmtK
         y7hUigLHyOwjr+2/0mb84z+fa1rgR681WAyCgP6RIqt5B/7XKFfuLUavX+5Nx4Z7vSks
         h/hvOZCk20WwAXKrTw+c1BatHcsve9FX2tsbShVFvcDAymdompJcVD9TAVjp5Mh3G5V5
         gyua5UquozA5FoWgZgEshkgGv0UbODLpoUx4OU4OXczHh1zuTRC+Gisgd1sz+mUFwRR2
         tZ4w==
X-Gm-Message-State: AOAM531s5G5p9gA95ruj68T8SvtDjV2cJxWRpSxB1aUiNgORMFcfHsFt
	t+DLJ8e25IZDFe7ZL4xY8hE=
X-Google-Smtp-Source: ABdhPJyHFZMpzoOcpOlEyiF9EOslqZJqhY4JfUgFsV0AVTmGH8i113TWpt49QUXzS68OHVq3I2IT1g==
X-Received: by 2002:a17:90a:ee8b:: with SMTP id i11mr1484264pjz.118.1604653414429;
        Fri, 06 Nov 2020 01:03:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls478418pjx.2.canary-gmail;
 Fri, 06 Nov 2020 01:03:33 -0800 (PST)
X-Received: by 2002:a17:90a:5310:: with SMTP id x16mr1409967pjh.62.1604653413769;
        Fri, 06 Nov 2020 01:03:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604653413; cv=none;
        d=google.com; s=arc-20160816;
        b=Qp61vNRrP27IFP289Zv+oPa9ns0ZNpbn0iWEEQQuDxt/Kk4tCelFLsu26bYTIWgXru
         jDy+Dcu6eerHwS2XkbkAXRbnIR9kJYELE4lKvn+xnqFBPMX1k7v0tYp/vklIdXnqRoLV
         3Vk0Hyb0YfkwnqzjUgY8dr1ErqsZF1Rx/aqeO6wj4AS0Q/x89ch+VZjiZCns7UYl7SwT
         aABwK7uTueS3xyPKmILgsJoXVH5cIQSNdMN7EPnz/oPq6J9B/b4ly110DJ8f4qzXT6My
         AdqiXPKU9tAUDumYCIiBim0UwycMWMbQzSXdAbExxBXbmbV5XyG2pU9hGC9cOxAttrdQ
         LlUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AXXvxPLeZ0ZgicbNMUP+ayy35qo6/4lRgD84ddHygf8=;
        b=pYhspIw8YqnGbRTcx5kK3GOBb9jS+gbXQFLWcLjA9wK1uEUHohjL7eoZ8LhZAs/xJ3
         lVYIIjjMhoIB2SOc1h7Y73ALDs6w//IzMhZlwd2u/D4xc3A3D+jCZ7rhHLG3xAodyiTm
         F86+avtb9lA6rWkylZ464JpsRkAGoBR1SjkswGfL3SxriR94uijSrkiKckNCDIJpqSby
         +BdhfwnNwTwVB6x/URI3wrEEcr7HIbyBnZ3OckF6Ca0B+Niyknnam2uqdpsDfBjsr+Gu
         ci1nq2AJf8TLG0Lt/2maMljC692IO7gRu/ND2Jwp8/rn5fD2h+V1hO90jFQ6tuFoyFMV
         shXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dllwsNe+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id ne10si73963pjb.0.2020.11.06.01.03.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 01:03:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id 32so637876otm.3
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 01:03:33 -0800 (PST)
X-Received: by 2002:a9d:65d5:: with SMTP id z21mr446676oth.251.1604653412954;
 Fri, 06 Nov 2020 01:03:32 -0800 (PST)
MIME-Version: 1.0
References: <20201105220302.GA15733@paulmck-ThinkPad-P72> <20201105220324.15808-3-paulmck@kernel.org>
 <20201106012335.GA3025@boqun-archlinux>
In-Reply-To: <20201106012335.GA3025@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Nov 2020 10:03:21 +0100
Message-ID: <CANpmjNNj1cc2LUrLdbYy1QkVv80HUPztPXmLfscYB=pU_nffaA@mail.gmail.com>
Subject: Re: [PATCH kcsan 3/3] kcsan: Fix encoding masks and regain address bit
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com, 
	Ingo Molnar <mingo@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dllwsNe+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Fri, 6 Nov 2020 at 02:23, Boqun Feng <boqun.feng@gmail.com> wrote:
> Hi Marco,
>
> On Thu, Nov 05, 2020 at 02:03:24PM -0800, paulmck@kernel.org wrote:
> > From: Marco Elver <elver@google.com>
> >
> > The watchpoint encoding masks for size and address were off-by-one bit
> > each, with the size mask using 1 unnecessary bit and the address mask
> > missing 1 bit. However, due to the way the size is shifted into the
> > encoded watchpoint, we were effectively wasting and never using the
> > extra bit.
> >
> > For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
> > bit, 14 bits for the size bits, and then 49 bits left for the address.
> > Prior to this fix we would end up with this usage:
> >
> >       [ write<1> | size<14> | wasted<1> | address<48> ]
> >
> > Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
> > size and address respectively. The added static_assert()s verify that
> > the masks are as expected. With the fixed version, we get the expected
> > usage:
> >
> >       [ write<1> | size<14> |             address<49> ]
> >
> > Functionally no change is expected, since that extra address bit is
> > insignificant for enabled architectures.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > ---
> >  kernel/kcsan/encoding.h | 14 ++++++--------
> >  1 file changed, 6 insertions(+), 8 deletions(-)
> >
> > diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> > index 4f73db6..b50bda9 100644
> > --- a/kernel/kcsan/encoding.h
> > +++ b/kernel/kcsan/encoding.h
> > @@ -37,14 +37,12 @@
> >   */
> >  #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> >
> > -/*
> > - * Masks to set/retrieve the encoded data.
> > - */
> > -#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
> > -#define WATCHPOINT_SIZE_MASK                                                   \
> > -     GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
> > -#define WATCHPOINT_ADDR_MASK                                                   \
> > -     GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
> > +/* Bitmasks for the encoded watchpoint access information. */
> > +#define WATCHPOINT_WRITE_MASK        BIT(BITS_PER_LONG-1)
> > +#define WATCHPOINT_SIZE_MASK GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> > +#define WATCHPOINT_ADDR_MASK GENMASK(BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS, 0)
> > +static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
>
> Nit:
>
> Since you use the static_assert(), why not define WATCHPOINT_ADDR_MASK
> as:
>
> #define WATCHPOINT_ADDR_MASK (BIT(WATCHPOINT_SIZE_BITS) - 1)

This is incorrect, as the static_assert()s would have indicated. It
should probably be (BIT(WATCHPOINT_ADDR_BITS) - 1)?

As an aside, I explicitly did *not* want to use additional arithmetic
to generate the masks but purely rely on BIT(), and GENMASK(), as it
would be inconsistent otherwise. The static_assert()s then sanity
check everything without BIT+GENMASK (because I've grown slightly
paranoid about off-by-1s here). So I'd rather not start bikeshedding
about which way around things should go.

In general, GENMASK() is safer, because subtracting 1 to get the mask
doesn't always work, specifically e.g. (BIT(BITS_PER_LONG) - 1) does
not work.

> Besides, WATCHPOINT_SIZE_MASK can also be defined as:

No, sorry it cannot.

> #define WATCHPOINT_SIZE_MASK GENMASK(BITS_PER_LONG - 2, WATCHPOINT_SIZE_BITS)

   GENMASK(BITS_PER_LONG - 2, WATCHPOINT_SIZE_BITS)

is not equivalent to the current

  GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)

Did you mean GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)? I can
send a v2 for this one.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNj1cc2LUrLdbYy1QkVv80HUPztPXmLfscYB%3DpU_nffaA%40mail.gmail.com.
