Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44QTX3QKGQE7TX5QYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E89E31F9452
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 12:07:47 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id b67sf4021673vkh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 03:07:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592215667; cv=pass;
        d=google.com; s=arc-20160816;
        b=bu/un85dWsbvHl6Dqjv7Jd7Cgn5VnME6avkjNMqVoDnLoklMlFr3+QJdw3BkEAV7Dg
         IRVMaQLGV5/xu5PTGezwj1gbAu3mw4nqQg6wkl6G9PR+QhGJhozpQdo6C6ZReM8kaYaj
         G7RTDsnqUa+CBQP2OW5EKDMr0FjcVA/6/OcXK9ZUl1t+uqEsSlrv0ipgur+gHbAhEqgo
         CE3WCNFTS6eZ9stv429oiIlX9CjT697f5THlhoMrQ/0u1/FoCwbin5ACsaSBOwHw/KXy
         WxK8Y3p2WfYiohUhg2Vq96UHIBsQseZhYbky8cZm+WQUGIVTouIdOo0URHd8Opipv325
         BkCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6nSQNnH/86j2MQan6bS8qA2hXoKznRo42IyFlQppHU4=;
        b=iXg26Mk0KdUiNk/JczFREghE9AAcIAIWXl8J1aIUvrQXjKRox8xCn9GfrHtPxNhinx
         MKfXUU9Rxz2VJtK2ttcHHUHqY9XBwRSq4+/r9BuqMzVjJabIVketMEsegVwHV2BLWoUl
         P9PmXJIXyeFICNX319kIiq11zp0p1x0Eh8YeVywzG+CJSDZtGBuvuQlGN5BFlv8yExlm
         ixUVheoMHFnZ00eyYVUdNMjyriTRO2R3IZhmnYDvWKUuGu3s5UV9wUlJSO6830tV7Gmr
         7u/3so04VKq9bw+HFkoVG00Pr5UzhAwMa71SUHjke/PfjzQHA1dSiMuIKtb29YwWvLLC
         l7Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q+B+8+34;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6nSQNnH/86j2MQan6bS8qA2hXoKznRo42IyFlQppHU4=;
        b=mpqd8COYDdCrtJ8wamICpJQvbB4t1gDEYKTqfH+ReHjihnB4+jjDDHwPxmwVfOq66d
         Za8TP/ns1BIJSEoBAnn8M+DaSyn0jw6EZvrfQN/l7IZNs0ez4P1/FqIywpl8/dTbtQqg
         npVc3ADBJ/RO98EWuEfSeH9uo4SlsbLG3EczXt3VCrRwn8wy8lz+siELVEmqvPfwQJ8r
         UjSL6wQf9Zb6JUSMJnSII4J0GFgVKvFdDnPoEC6mEYfq3YMqROhfvRfekN2pZ4lEAXhx
         S61pua55IvE13pC9yeuzCGXQZtKI1XroxPBgmt3UIhwciQ/kPP1V4BmxkV3XEJtn0JEi
         Ss1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6nSQNnH/86j2MQan6bS8qA2hXoKznRo42IyFlQppHU4=;
        b=fHFZcqLYY41niFf/uOY0wgdw41zdEi13G1ghb5FqNKrkEw9b876tEKu3S4TEGhM7pn
         gmSPIx8zsZnbo0g5deD02ijxPrSzWewVoFXJTlKV99eG58kYgv1k6iX9jpvwHnM1v56n
         tdaHpRgABwQ862xAi0DV8BOhpEFUW8CAoVlcN4XqG0BGvrRNiIhyYObw0pe90O/kSW4X
         9tz0Hyz5iaR3OMtJFY6Vqr73TLvs5HSAhbufPhbToEe47LAebSXtNBM36GYuLGkrR+r4
         xy08HdI+G2k4Q+qKze+OfIRiVUZDxMBBBA6DP4GXS5irF6aQEQCOXUTIYeBvk73mA8QF
         gdJQ==
X-Gm-Message-State: AOAM531zAdxCjtkYEnrDh1XZ/1KhqHC/1pjszSEvKApHJ2uOTCLJw+Tq
	HEsqpj1EocYXvmXJO3ZnaTA=
X-Google-Smtp-Source: ABdhPJyfCfBVV3+EiNsgoMchbHdersD4aKGV4BCClNmuYqIjwL5MX/AiOIpW1vcObaI0XCYSsLf1ew==
X-Received: by 2002:a67:db90:: with SMTP id f16mr17729021vsk.132.1592215667058;
        Mon, 15 Jun 2020 03:07:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3e05:: with SMTP id o5ls909305uai.8.gmail; Mon, 15 Jun
 2020 03:07:46 -0700 (PDT)
X-Received: by 2002:ab0:648e:: with SMTP id p14mr19044385uam.14.1592215666713;
        Mon, 15 Jun 2020 03:07:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592215666; cv=none;
        d=google.com; s=arc-20160816;
        b=nntdONhSnQTFtfyHwgNxoRHukg237gJt1p11R3c7loD4la3sHEASby/iDmAwRhPrgx
         HTNHs08aZ3b7oQH3Hba/UoRBPDVK1e1FsmrwGfYBhKUoU4sBQIRA1k/AvUyMfeCxr4On
         AIZQhz56ADUet5hTof4/wzwjc/DDHFHKp69fk6H0ffEjL0GnXr9+1+IOpK+qA6bY8ktm
         asL50Fa4mMxefuSwsQtW76N6NvQDdkq/uBd52wrOe1EjPI14MdMyHuDRWPUrNsPtobln
         /sLyA9ly2TpQ/qqEZsYIEuA41DjI3TFvVgTOBLBlMARAQmlcEtjAG5b/giy2fOdAT8cF
         AvxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s4asCK8iE1tsgTlzvkWs2MDPLf8Kbt2TTtKtjoZO77s=;
        b=K8Lr+mYu5taMBA6/PUjNFaO1hcqEB3GSrPBkyFqp9qVk+VU0dCRuWwfj2sDLE1y/PU
         1JpOSYe9YAf6bXhxt5+u16aHSJDjY3QK8Lg9izFxSG9qRqK/nGhBa6Ht4Xuv5jJ9hUU1
         Rb9YDZcJkVg+IYPO7K/xYY9uNxHsn3BvCto0YLm4uU10nJDt/lBFwizVGJ4fIuQAGk95
         zSHUIMYgY7EXZyYuOJWd7zoLEexgxuCgbM8Bxs33d6c1xZA5Gv0TyJca1EkH10coMv6f
         pG2qd+YB4aWWqAkw0DBB3XY8ObgeTCybETDPqeOuuPGPpLOlBEhzWhrV3Lq0U6M3FxhO
         RQDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q+B+8+34;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id e10si717032vkp.4.2020.06.15.03.07.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 03:07:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id g7so12640384oti.13
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 03:07:46 -0700 (PDT)
X-Received: by 2002:a9d:58c9:: with SMTP id s9mr22086900oth.233.1592215665986;
 Mon, 15 Jun 2020 03:07:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200604102241.466509982@infradead.org> <CANpmjNPEXdGV-ZRYrVieJJsA01QATH+1vUixirocwKGDMsuEWQ@mail.gmail.com>
In-Reply-To: <CANpmjNPEXdGV-ZRYrVieJJsA01QATH+1vUixirocwKGDMsuEWQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Jun 2020 12:07:34 +0200
Message-ID: <CANpmjNP2ayM6Oehw08yFM4+5xTjXWcCT7P3u7FL=cCMxFJNkXw@mail.gmail.com>
Subject: Re: [PATCH 0/8] x86/entry: KCSAN/KASAN/UBSAN vs noinstr
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Q+B+8+34;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Thu, 4 Jun 2020 at 13:01, Marco Elver <elver@google.com> wrote:
>
> On Thu, 4 Jun 2020 at 12:25, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > Hai,
> >
> > Here's the remaining few patches to make KCSAN/KASAN and UBSAN work with noinstr.
>
> Thanks for assembling the series!
>
> For where it's missing (1,2,3 and last one):
>
> Acked-by: Marco Elver <elver@google.com>

Where was this series supposed to go? I can't find it on any tree yet.

How urgent is this? Boot-test seems fine without this, but likely
doesn't hit the corner cases. Syzbot will likely find them, and if we
noticeably end up breaking various sanitizers without this, I'd
consider this urgent.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP2ayM6Oehw08yFM4%2B5xTjXWcCT7P3u7FL%3DcCMxFJNkXw%40mail.gmail.com.
