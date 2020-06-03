Return-Path: <kasan-dev+bncBDRZHGH43YJRB3G4333AKGQEQXZM4II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 996091ED1AB
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 16:06:36 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id p136sf817079lfa.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 07:06:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591193196; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHbVfXmAqy26wwEFfvM1UiiJSJ5+ERR+2n6DnE3opdFBpSWQzRZY3QUJ5IovHBu+VU
         QYaz73ofRyacIXGAC4y5lv1af0VY1p5mXSpOoR72dYiW6+C4GKs0iTzS5Mdrl889QWN8
         BWQ8P88LpCkJoOaTJPrBJxHgXqslJIgiZJ/d5oPY0r5tPYrDpWvRQlEcsAhbY3dNVM74
         Dv9VZZUKiXL/oSfqH7HsDDPWIGhLd/BAJf3LUvDDpmmtSZTBExMNQT9yw5RsN9X54h2C
         KjTn4D9EWu9e+8kET2GRPRiustpBclf2n65FckNkPo9n4j0IyMmiIwplYswlk5Ea24Xt
         50KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+gBp1GThYTI8Ev6iUC1x/fPcZxUVyWLjRzz2F+6vaJY=;
        b=iV62I2OiRR4yxFViUrWO0ocF3lhdjnxfaxzddLLp5K5d7PmkpuZdZnpFZEry45SSp7
         XVGhAxx6mg5pft1BXfTOcCo1tjMy7EgDOYsFjKiijqaCQf3Jnksxd8O+O7aFmAcKnvad
         ExY2gIIWuEA+vOjBEPkQ0YRRPsze1akoBAUSsSubqyM3oe2EV21/Ry61W35st+shSzGM
         6Ys/PVY4SqnUVma0PxeZJrecVizFzgYGaorkoNg60oHOHd9XJ34Y8p3oLEtf3/PbyjJH
         pDx1jXTwAnoLYvQkHqIn6PNXfwNFamJeQRJ/5RBcckPLLRCaiR5ICLAf+2TPOEDM8YwP
         v5vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="rajZp/2F";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+gBp1GThYTI8Ev6iUC1x/fPcZxUVyWLjRzz2F+6vaJY=;
        b=BmKu/nQwhHpTsIYyzYdpuYCIkA95RnR/TMaQQgSRgNb+qNhSyQiIoHLXVLMQa/+r5O
         qP8V+NhG+FRN7DRGOr7p8qk5O80MyKoHKBx5AReSgqTfusBdkgGy0YwXZzAJ8wAh51qb
         rzZo+txU6nr9/o8HDb/HWEiU+OFPYWJxEVzNX8FXVJ63IzDw0frvyYLf0ucA2rEY9VFh
         VjT5xynFYe1/TonD5DtKq/UujRw5VcQ3etI+RfxcZd8WqcyfO6cIqQpqCoKq0bVLF5pf
         NVu2DSpNY23fmJkXHikUppOuGK7pu85KBIDgqKBr2s8EjkEpCK4828pxxpcd75sTjguN
         BoCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+gBp1GThYTI8Ev6iUC1x/fPcZxUVyWLjRzz2F+6vaJY=;
        b=AGkSCdokPH9+vHAKvDOlGmTU1VrSAjPuyQbwHmx7uo8M1JUg+qwDEUbaq3M1xIgf/D
         DhlXUKStNTtcXAHkguBtgKrtc8QBxZjNEikHaSKtAZlBUgvowEaJP8EScevcU0+yF9Zn
         7BiKhwlCPFwZ3wgg3T+hzHqb5IMnoJf5Lu28xGOuKl7PK9eUiZ5y+61s6X9avS9CIGc2
         WqJvWpoPwnrPbUdQEs1cqJJQKHW5IIh6mzfyFm+gPNlu1czfWFTVXoZwrTXwiaLOwxMr
         Ho95v7a5YswEF0XuE/1aQi452mDHPpovwT+4HiawFNpbpF0WSYkFSsEuGXQkAtacPv5I
         7lGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+gBp1GThYTI8Ev6iUC1x/fPcZxUVyWLjRzz2F+6vaJY=;
        b=CV580+03LbM1BHEriTqMOtPH7XQCCAbbwUHt8Cp4o+4i8uPNexnGR/8C4mohkoOB+i
         2nMTKo0tNdBC+aY+btNfQGs9aTFfUEH4AbmhFhyiPZj++YY8m7BOSiZRLBRvYg+kzcqL
         CVCBeolK2ISzmCUtI1SCorEewtQkSIRNndC0WwoF9fBIzE2V6PwGy0EmGZ4GFh4iEovz
         9aAfllhoowdi9u9K3IucaABmOzNCkK0tIwdOmAzMuvtTUsJnnRtV2U9XB4BCApDZn1ZT
         kS+AEZ7gxU2LM6y9U9GHXfFD/Y+DZsLr3HEEfDDIQn3BhKUBOrlQakA9yEfPM0g0ZKM6
         ldCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CQ+665LfEvOf/6yth2KdiaG3BYThmUZt1sLixf6ePtWpiP0f+
	2ro+zusFYB4KoRLejknGV/g=
X-Google-Smtp-Source: ABdhPJyox+NNIHGY9zRppPjBe8HEnM+SbUemEo7/bKa8bn1w3O4LAPFzsAz7zwNx3Wjidlpg9iEUqg==
X-Received: by 2002:a05:6512:533:: with SMTP id o19mr2531458lfc.6.1591193196110;
        Wed, 03 Jun 2020 07:06:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:43bb:: with SMTP id t27ls717285lfl.3.gmail; Wed, 03 Jun
 2020 07:06:35 -0700 (PDT)
X-Received: by 2002:ac2:4a75:: with SMTP id q21mr2542252lfp.190.1591193195288;
        Wed, 03 Jun 2020 07:06:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591193195; cv=none;
        d=google.com; s=arc-20160816;
        b=nhnnuy3wqwmbuJFgItx+rLXWavM0xSp7N/zE56u3oA2BJ2oWR/mH/ddXJC8DBhRlPw
         uK6WmCqAw9e4kkGx6HVAJgBkcxsISYG/aH/qV0GJF+wcjvcm87fUdWRfhb1fOds10v26
         zackme5jrxam1bw4v2qHvwLz5scIk3nrhNBleTML5J9qJTymRPrSwamwduvLqLh1A5bK
         Yr+8cn6yT1r3fsxZgODQb8u9+knk5MJ5dpmP4t/aUsCK4Qdka92oClro5jd4Jg41jutu
         XXn3MPJJRUEhI46vtfu0QfYAWNaKkSWYB23B9JcX+J6UJIy3gF81cF03JJkDLVqtI2Ed
         5jRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qCMwwfFVZYEgkxVHE4dr/ePj/4wKMJeH+gSl8PNTdQ8=;
        b=C6wX8++Byyks46cwqFS6x/dgYcnt556tLvoF23X3vj7t8XZuZhwgM2ef4nWAstK3ct
         sEEJ0Q8SlGyjqhjZPQs2V1ToDZFXdYH6HS8LY0rd/fW3TVSsOOb4q0MNxPLRkAm8diST
         du9pzd9xIHogyLpYWhqN0QSzzsL40ovimKVszc+TLLxzXdNmyzeTnwpqobvJ23AeTDEo
         vPu0i6v+Zai9gq1iwBqoaxlSJPEMGGAqeSoyexv3q7PmOXY/u+a/aV7lPhPWco7mx6Pi
         DXbfJK5OO/xShDEDhHx2UCaE9yE5XZ5H3dD+rDrDcrLc2n9xuNObKfx+NFdbsP9dgGo+
         F4pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="rajZp/2F";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id o10si124336ljp.3.2020.06.03.07.06.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 07:06:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id o9so2889236ljj.6;
        Wed, 03 Jun 2020 07:06:35 -0700 (PDT)
X-Received: by 2002:a05:651c:11c7:: with SMTP id z7mr2275345ljo.29.1591193195076;
 Wed, 03 Jun 2020 07:06:35 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <20200602184409.22142-2-elver@google.com>
 <CAKwvOdkXVcZa5UwnoZqX7_FytabYn2ZRi=zQy_DyzduVmyQNMA@mail.gmail.com>
In-Reply-To: <CAKwvOdkXVcZa5UwnoZqX7_FytabYn2ZRi=zQy_DyzduVmyQNMA@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 3 Jun 2020 16:06:23 +0200
Message-ID: <CANiq72=iNHeLc3aqt0NrykucHsTPwmBfnsyaay3VYnEhV9T5ag@mail.gmail.com>
Subject: Re: [PATCH -tip 2/2] compiler_types.h: Add __no_sanitize_{address,undefined}
 to noinstr
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="rajZp/2F";       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 2, 2020 at 8:49 PM Nick Desaulniers <ndesaulniers@google.com> wrote:
>
> Currently most of our compiler attribute detection is done in
> include/linux/compiler_attributes.h; I think this should be handled
> there. +Miguel Ojeda

Thanks a lot for the CC Nick! Marco is right, since this attribute is
different per-compiler, we don't want them in `compiler_attributes.h`
(for the moment -- we'll see if they end up with the same
syntax/behavior in the future).

Acked-by:  Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72%3DiNHeLc3aqt0NrykucHsTPwmBfnsyaay3VYnEhV9T5ag%40mail.gmail.com.
