Return-Path: <kasan-dev+bncBDK3TPOVRULBBKGOUXZQKGQE3LBDKGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F9471824EB
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 23:33:12 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id p21sf3010815edr.22
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 15:33:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583965992; cv=pass;
        d=google.com; s=arc-20160816;
        b=J3CzZ5fsfbbDMZkMKfDN/o2/EeM9HulpmKYcqLbPNQcZUtWEp9BKEMWlVD3Cf5FhG+
         BFkpnTUj1MagC0gqJrFQczeyYIKdPTiNmV7bFnLHmGlKMyoK1KTnLvuSIJj66jDu95vg
         QEDjjT2UwSDB5+owovOa3I8OQef+/ByaZ+iRvtUPiUoyJT2JP+29mULTCo2dQMtDvdxb
         AM0bA/ZXTW5X66MuKvestVYLXMy7MY16SnDWw43eGs/htcjpjNDNnhXKtzn/UmuIkbJR
         jp36PrIQGSlsBhCgY4T/HHuz8b++bo45w/SiRjZCdVYjJSbk775iPW0qN6OaZE2iYvpD
         bjvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KVsDgNcOB3cf2GC/fG6ZzRqQyc4jYjcdraWi4W3KulE=;
        b=kYjuhTa0w4sbbj/IVYGF9ULvQQBmQIjsCbeJqzwTbk6O664uDOdw8moykIXg2J9QA+
         7Xh2j0T+PWKgPYtPSvSHOGCo1KY02eBe6Pub1qLH74qbf8N/K0RWdKqOg/fhw5wmE4Ei
         v3gl/Po61pkVsLOHqGWavgyvIQkMCQo1Nf+RqPi22EXPRaAzARAH3rzz7/T1BMEks2hm
         /Ld9CHkEE4kUoGkTOxjIPOlKxeU/oKoCfnXN4pUfyOe+QzrhBcNLQay4SwThZ6s6QDCo
         e+GmNT0mb8GnE4uQCDeTh4TJ8We0lziO5pI8gX61gl7wbicxg06qOBhs5m2NGHgUtunf
         +2fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gM/y9MfW";
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KVsDgNcOB3cf2GC/fG6ZzRqQyc4jYjcdraWi4W3KulE=;
        b=U1DUozGYddv7GzAd7oaHS4CMm3Vn2v6yBKiiuCUsGheVK30FbHMlR0p5VcyK+jSaGq
         RYBM+d8+AM/Udqnhochlzo7rxuLxF/ACjiU0zM/7klU7fMrFSc9tq97Pim8HBDEXvUcw
         7WJSXb4DxtrDfemLW27JK0KvFBEHgwidI6jgTFinT19zAGQP8ZvfzsGtdw8iWPSo8Lv7
         CyypMgeGw7IWTcjkEqXjkysM6F6fqAheXS86xSsKKu11ACEHzD+XQqepp4KhMPfGoP/X
         H3+deunycbltv/0dOb7c55Y6EVqSZTQ7g+G20jUt3d5GPCAY6mzy95Yuk3sZu7s/PMiQ
         u4VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KVsDgNcOB3cf2GC/fG6ZzRqQyc4jYjcdraWi4W3KulE=;
        b=nQjUUyCihi9xgN36Ra/xd8iAKMCbDZGyhFlRsszbE3U0zru8EKQ2kmRJSJc8FkahUt
         wlLfQecFFjtVOHo81KHoEj7MgR+lUffLud424HSsPk/kwSMbyergVq96vvgwQBxaHEyx
         fTY0S4ox0M+ICnagATw/pqE+FU5xtIAujXAZzxH60iF+pXVujEcTBSTd05zKZkJx8H90
         WoN2Fi2qIcw0FqSDnn5T2P9FpavdX8ewHWHaF+boGWF0EgSg2jp9BX8hZvBaRHexrgo5
         Z8b+kc00odCK5oh8BjFJOpkoOnXGn3RsdYT2vLK2L8bQMZZ4CNiWDhrriuOUmL3TuwZn
         lcAw==
X-Gm-Message-State: ANhLgQ1JX48IH0rBLg20g8Pnh6IGkeQEqE5OxhgEUOm8Dcu06hoRPnTU
	toremL6hnSt4+K3n2ASKfko=
X-Google-Smtp-Source: ADFU+vuilVniDBnpR3j7SZQBP8rbt0eBbHaxbubo54p4RfGDS/3dRqqgRtgExQJmyMDCQzD65yS8Ng==
X-Received: by 2002:a17:906:82d5:: with SMTP id a21mr4157866ejy.119.1583965992322;
        Wed, 11 Mar 2020 15:33:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4d7:: with SMTP id t23ls2368914edr.9.gmail; Wed, 11 Mar
 2020 15:33:11 -0700 (PDT)
X-Received: by 2002:aa7:d9d2:: with SMTP id v18mr5006622eds.327.1583965991676;
        Wed, 11 Mar 2020 15:33:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583965991; cv=none;
        d=google.com; s=arc-20160816;
        b=AuB4PkVZrG5zMXi236vOiEN7FdXteN3GADyDhgA5syxK+NgyvbZxk9nQGR+35xvXuG
         1VYgfiRhAoqHNZM8EECaELPon9TyUSBlGpN4yLwjTJ7qDUXIyXM6Q94FU5hC17bT1e0I
         BcWBYwM1ZHgNyyW6Elp0b4CwciF2owNXCh6nU+yvm7zi8tuAFyh69VTDYjB4qH6Obpuo
         AHdpiLy4EHhaECnB76QHCLkc+iA+BBq3+fCMR5XpVujhVLrhvsPzlSMtm1/xVRE13J3r
         btWcSdPdRMm9OtsuBTehFjlBXJPjbr6IT5sEEIr3/9Y+nfFgYGRYFhRy4uqPzvCX4/fY
         H+Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P3G5G1ycGcqjr+5+9XmfiHnkfrEJ8jgyfY9rjLHkFkw=;
        b=vo7O9Jmrfsgk2nuJ5d9muIgBO0RsMzg0g7q8MHdWKgFUfgcDbMof/xL3kBiyf4BPZg
         iJvI0RZ8SXqhkK58LOeOC6A7KFfUlu+z1RkRYGCkg5TE3qK2jWQwb3u8Py/DiTmHdY7V
         uRTUD3YTkahLLxnsARUQeuZe9Z+7Fad8cyUjzUlj0plLkU11q9nepbbiwod4HAwaj6wO
         0QoUjT465iYD1dc3AxAAOCAn3S0ZKufLM0XJAc7wuyGNEhb3e0B9ZgXFxT5xBiAnekEN
         k1v3kWCfIcXKdZNQYjYbeogTEKVesxhUhoQwctCnU416pU1zbH2GTBq7A5BhnjiM+Xdv
         FzRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gM/y9MfW";
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id cw13si195404edb.2.2020.03.11.15.33.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Mar 2020 15:33:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id 25so3963096wmk.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Mar 2020 15:33:11 -0700 (PDT)
X-Received: by 2002:a1c:8103:: with SMTP id c3mr837777wmd.166.1583965991033;
 Wed, 11 Mar 2020 15:33:11 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com> <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
In-Reply-To: <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Mar 2020 15:32:59 -0700
Message-ID: <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="gM/y9MfW";       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Wed, Mar 11, 2020 at 3:32 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> Hi,
>
> > Hi all, I just want to bump this so we can get all the comments while
> > this is still fresh in everyone's minds. I would love if some UML
> > maintainers could give their thoughts!
>
> I'm not the maintainer,
That's okay! I appreciate that you took the time to look at it.

> and I don't know where Richard is, but I just
> tried with the test_kasan.ko module, and that seems to work. Did you
> test that too? I was surprised to see this because you said you didn't
> test modules, but surely this would've been the easiest way?
>
I had not tested with test_kasan.ko. I have been using KUnit to test
KASAN from the beginning so to be completely honest, I hadn't even
learned how to run modules until today.

> Anyway, as expected, stack (and of course alloca) OOB access is not
> detected right now, but otherwise it seems great.
>
Great! Thanks for putting time into this.

> Here's the log:
> https://p.sipsolutions.net/ca9b4157776110fe.txt
>
> I'll repost my module init thing as a proper patch then, I guess.
>
That would be really helpful, thank you!

>
> I do see issues with modules though, e.g.
> https://p.sipsolutions.net/1a2df5f65d885937.txt
>
> where we seem to get some real confusion when lockdep is storing the
> stack trace??
>
> And https://p.sipsolutions.net/9a97e8f68d8d24b7.txt, where something
> convinces ASAN that an address is a user address (it might even be
> right?) and it disallows kernel access to it?
>
>
I'll need some time to investigate these all myself. Having just
gotten my first module to run about an hour ago, any more information
about how you got these errors would be helpful so I can try to
reproduce them on my own.

> Also, do you have any intention to work on the stack later? For me,
> enabling that doesn't even report any issues, it just hangs at 'boot'.
>
I was originally planning on it, but it's not a high priority for me
or my team at this time.

> johannes
>

-- 
Best,
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw%3DxWEwSwA%40mail.gmail.com.
