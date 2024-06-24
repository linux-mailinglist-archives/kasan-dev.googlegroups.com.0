Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFPE4SZQMGQEBX4KLOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D584F914533
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 10:45:10 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-375c390cedesf56412555ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 01:45:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719218709; cv=pass;
        d=google.com; s=arc-20160816;
        b=I0rI33hGPQXdc38xE5VhSgS758eQhu6GC1sXSsgddNwIoUSmggqsKLD20undRPchsY
         LfUezdBxP3n/xk/1S9KQxHrReIDnYpMUJtVBPOguxzuqjLc0oVc3crri5EKNUZ5JxPb0
         fvpfSeisrlCYu0XAc7XK4qpMVdQch7cNJKN0uYvcvHpZFVzGd6N0PrTYqiJNV6uh0Kr3
         O7yZQZJl8T99pYFa1W9RK0qNxcRTtjkryv5zIdWm+sARIcefMYAqlInYUw/poJAc9h+O
         zuYg9tcdecwVnusaGzFvENZ7zfg023Pnn2USu8XVfQz/kcU7fIoJB4vxy+A9ez6l7lUM
         12Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zo0+FSK7xakJHa9Ut98rmSNkOFpR5JXf4DSwGqwbBR4=;
        fh=7Kl+z1nnIo61hzr1mP5VUxxgMxX8RdWwgaUzfGfXEgg=;
        b=FLGIh+73R/Qb5sDxXSZ4gV0U5BR43c6loSR6XRBWWz65EgVtDz8LAXbqREq35JuYKV
         0XBfYGWdUEQ8YeY1idkNFOz+tDdxUMYmQ5mpyfiWB6fdjDDbQm+In5Um2HXZUPMBUp5o
         +jA5lHNGqId31qBQURfQMyhIuQzhm4lferS9sqJoWApiGluS4VlqAe9IV2augJEPgBL1
         /fv6PjwPu1EG4z+wGZFZ4HpZkGhdyRp3deWpl06kkNKD7+sQTFja2y+b73X0RJiftYSG
         MmrfM4QlMebVjbeQt+5kYgkCgHGL29l9cJFTlgh1yZh7Y7kYrUyTCiwdRCzXXMkGHBaB
         Akeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XiZanzsu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719218709; x=1719823509; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zo0+FSK7xakJHa9Ut98rmSNkOFpR5JXf4DSwGqwbBR4=;
        b=mzZueCyPl7jqvXpkVXDtVDtPAw3J4HNO9PFd6mpMpQlRPQJwWQEY8FYNqfVkphvtIP
         vm/AssyfLo5ZuP/3sJv9q3U8iipwsOyg48saXo0bZweVPJ7cyLQNqeLIXxlznTVCU6Nn
         YN9Ymlplpib0hdTNoUgAZKOp/mXfqXm/sqQBK4/ahmM3INzoTaYHq/FcNsGMzaDoLUtG
         PM02hpxc6Y/guXvxFGL4RqTazL8+pm8IBxdPWFY1QA25UR024uf+AMNZNCfMoWlfGH8J
         szCAVFXnU9y5GKYEURE8yn/1JTFiKa9vSbkqrJG5VQQBM/ofRU+yxBHFh/exWVNw6ocm
         /0Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719218709; x=1719823509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zo0+FSK7xakJHa9Ut98rmSNkOFpR5JXf4DSwGqwbBR4=;
        b=FzzdfxB4elLv+vaQsjwSPpn5ldtVCK1rvB4llztLBcDIZ5qMSNh3tR95EWY3hNTxiO
         q9ztaq47WV3IUyWhfa7Djlh8g9SkkNZqskCiA8EZdEERzNtwgO6ObqfrK8N8OzDhmJRv
         jJrra83zk45Wq6TrNoVh71XYVjG63361qD0w5+cUgu0ON6SMYo3CHSoETQqO6TqNjSCW
         /1hba/oWwihcjAI/lJcunjtOdsl0C8nEW3XxLBYnrYhB0sAIx+Tog/JnJ2NMis3O20aC
         Fxi3U6ObKaUgw2jOzw5pNPAhc2p7mDS1Bm8c5GWYUz4NEycsNWIg/r+oxDDTH5aaWFV6
         LAwg==
X-Forwarded-Encrypted: i=2; AJvYcCXW3sDyoRP2c9PjGua7EY0xMBJ8+73QowHxqTTE+zx5ZzuikJfAJSBvexPEueFHh/l0EwopQGwIxizy9vLBTV3+GSvV093smg==
X-Gm-Message-State: AOJu0Yzw42y9zoyba0/fqE/UZkZ4xw+vdY4qfEcG3leiW0BW1ecb52ck
	SPlBr0XWTEbme3jOeYwdw/Wh/rM5jxlT+8zfG8PYsiNh+ADXxQYR
X-Google-Smtp-Source: AGHT+IFrADHA/tx3TCnV4NCH9vitm4xn/ahiJWRHivPoZi09BtdgbK4TNr4mv9MRBLX4FPLvfgIvKw==
X-Received: by 2002:a05:6e02:170c:b0:375:a3a9:db41 with SMTP id e9e14a558f8ab-3763f5da011mr52189545ab.15.1719218709180;
        Mon, 24 Jun 2024 01:45:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1feb:b0:375:af6a:e6ec with SMTP id
 e9e14a558f8ab-3762693b4f5ls29385385ab.0.-pod-prod-05-us; Mon, 24 Jun 2024
 01:45:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJ74D0nifyK3Ow8PyaTWtoHYvdOw6l8ZvRW6J+SYo8scdYeYV8p0Dn6shEOwZL7goh7LXxvLMgrVsSBwQnTJWoZQhWnMp4LZqS6Q==
X-Received: by 2002:a05:6e02:1c4a:b0:375:ac51:9c6c with SMTP id e9e14a558f8ab-3763f5ddf0dmr44554545ab.19.1719218708297;
        Mon, 24 Jun 2024 01:45:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719218708; cv=none;
        d=google.com; s=arc-20160816;
        b=L70YfAC/TSuKb7WijEWbeCGjC+aYukCISL/LZbzjB3Ohz5PZsTiMZ9YglYSjOCgRiz
         Q7odkefCg/9njuiM1fGv0TwI3z2RB4/RX1EgIzAieezDC9YrR3x5AbbAV1qURsD1OTgs
         3AR36VK267C0PhOkDZt8vMX9QLX44SL9OxihAZpHL5jD5drRwGhpwmQ22jmW4uNcvasb
         0GYNjOZ36gEfvoMnY7XH67cnF0mGD0nEKAVt9YccYTOL/bXUTL6ai7TJIqZpmPeZnBhp
         4fwqWbH7uZB6ygDj05T/fEZUHHtyGJ8rcPsxTSFMNZxKK3hyNFzPD9arWVS7O4LK/0Gk
         rMoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qIXxm2YFEoM3D/TQ6OYSQnHC85tugn6XrgaeNPvetWA=;
        fh=jvQP2rBTXgYQxOo179MwUlI8UrrzFGHu8Nmqpj/O5cs=;
        b=QbAUbBOHaNdOhngPQIlQkbVD7oOXSteSlj+0V7+Ql7i5MnA5oZPMGWN2PB8VJomrIJ
         B6XlYjBBYE9nk5rMj9RJg/Fpo1cWUK49DpGHpSmRDv5j9zSt2xbawMgEeFUpXbFEZlV+
         ytvr+h1dGGJNDlHPwzBoJ3dOKxdb3Hk2J9iBwQ9mgWxMkR2xCQtYrxZ2AK/E+z7+S7U4
         fKiBAud/yfLGVV2tN4Ggp4T8Q9ArAB0sTrwPasgXJhv3nvX27ChyR65Num3D5H0Jg7iB
         fQtreIPJMCRDNHj7823Q6fLyz6srXipzyk0F6AEkpz6uurATxyH5M1AO+A9i/bjeTWr1
         UUZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XiZanzsu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x935.google.com (mail-ua1-x935.google.com. [2607:f8b0:4864:20::935])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3762f303139si2702705ab.1.2024.06.24.01.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jun 2024 01:45:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) client-ip=2607:f8b0:4864:20::935;
Received: by mail-ua1-x935.google.com with SMTP id a1e0cc1a2514c-80f59ebd021so943782241.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2024 01:45:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtA9crNUQyJZeHzHYtr5cVI+eRdPsxYsQDBlRdampib0qGLdH7divKbJtT3sDCxG3n2ivEhBYPz8Ri5U3/lGY7B2Z6rWyJqCQFCw==
X-Received: by 2002:a05:6102:32c2:b0:48f:435c:40df with SMTP id
 ada2fe7eead31-48f52a89afdmr4359823137.19.1719218707485; Mon, 24 Jun 2024
 01:45:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240623220606.134718-2-thorsten.blum@toblux.com>
 <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com> <A820FF35-B5A3-410A-BAF3-0446938CD951@toblux.com>
In-Reply-To: <A820FF35-B5A3-410A-BAF3-0446938CD951@toblux.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jun 2024 10:44:29 +0200
Message-ID: <CANpmjNO+1evgD=Ty8YXT6_ac33vJKE=UaOE8ADzd57_YoZ83ag@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Use min() to fix Coccinelle warning
To: Thorsten Blum <thorsten.blum@toblux.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XiZanzsu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as
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

On Mon, 24 Jun 2024 at 10:00, Thorsten Blum <thorsten.blum@toblux.com> wrote:
>
> On 24. Jun 2024, at 00:02, Marco Elver <elver@google.com> wrote:
> > On Mon, 24 Jun 2024 at 00:08, Thorsten Blum <thorsten.blum@toblux.com> wrote:
> >>
> >> Fixes the following Coccinelle/coccicheck warning reported by
> >> minmax.cocci:
> >>
> >>        WARNING opportunity for min()
> >>
> >> Use size_t instead of int for the result of min().
> >>
> >> Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > Thanks for polishing (but see below). Please compile-test with
> > CONFIG_KCSAN=y if you haven't.
>
> Yes, I compile-tested it with CONFIG_KCSAN=y, but forgot to mention it.
>
> > While we're here polishing things this could be:
> >
> > const size_t read_len = min(count, sizeof(kbuf) - 1);
> >
> > ( +const, remove redundant () )
>
> Should I submit a v2 or are you adding this already?

Sending a v2 is cleaner, and also Cc Paul E. McKenney
<paulmck@kernel.org>, because the KCSAN patches go through the -rcu
kernel tree.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%2B1evgD%3DTy8YXT6_ac33vJKE%3DUaOE8ADzd57_YoZ83ag%40mail.gmail.com.
