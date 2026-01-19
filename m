Return-Path: <kasan-dev+bncBCT4XGV33UIBBUH6WXFQMGQE2ZTI6XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A500D39BAA
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:48:19 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2a13cd9a784sf28917635ad.2
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 16:48:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768783697; cv=pass;
        d=google.com; s=arc-20240605;
        b=SEo2H7ZdOMH3VFhPyw+NGnwsNSqHFKAl7N6cb71hY9r1Jg1V3iRhWuY+XPoWayTozx
         TmUjcnxvcM9FHy412nJPHFRpky5l9rLZUqDD+5rM0JbKklrW3D4m7TfJqa9ZGL5LTZ5U
         oZGI9sZjGxCNjNy6GlSqGMi348QgaUlXL0rKLoqH1uFipAILtKuqpg4rcfGrDmbNK0We
         m0eQoTVyfDJ/xGCUJtUMPLoMvBS5f5t0G0lFDgBorfjXEYkOd39przgu8Uj3H3OEI9KP
         lSeKd/gyj65RXyG1tCbrSEQubl+LreKLy5AoBoY9J1wj/uDJgqeR7qOYm9Osg9gIzcVC
         ToDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=sQ5IBHi2pbaQt36vHiY8NY+nsRJi72z6Riu7z7j6t+0=;
        fh=nuQ/xmF7T6V3QtYzJdM0+t0HTUUkMAGDS+Gpo8+S5vs=;
        b=CaM6yHW+gDfVlFPTGThEZqzS5eY04Vt40Zifei+59yiYh3vEu+ieobIx5GpEIcAaBe
         WZSLRts/vt1N8cWuiNY6QIATGwzHdatVKFQvl/SxR6P29zh22+AKZcB/DPbV95X38XAc
         OJBkC915kGkWwSu5WrrpQ2gJcrDBVpzu7Nz0awAT8Uo1Xc8H1eOboQo0gwyqiAKu+YLD
         /3D7DcN2uCgqqE5q8syVEBXRe5ZE1US8iPMPI8BOfiQGcAUZGrXpairU72Yk9yBJoJvF
         jB1f+sI05jrXj/Grq5bWbDq38V5vAtG9KV8765KKTWCDJL3QsIWCzToEnMFeHerz68DF
         sMkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=izuf+vwR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768783697; x=1769388497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sQ5IBHi2pbaQt36vHiY8NY+nsRJi72z6Riu7z7j6t+0=;
        b=FEw17ZOaDD5pKCBZOavVnpT9TBTOOEgZ5631vL/lzPOE784f6CM/xy63WldEMUmaSI
         K8eRJ5td2rveS7mdfSvEGvor7XAhfiK/Qq9U0cbU0ZFU7cRUcAKtrc4dMo7N+1SHlarK
         GZEFdVGfGtAqaCKQIryapnuI+UOms0WCi43YQEchsZCYI2O/IKX6+JGUocVH4b+ZrIey
         4KfWlk0gHfRzCE71UMWXCQ9ibPj2JAtxlNeqdC4hhWfD/3shXQQ1ij/JNiyAjpa1VW9P
         gE4jO5xrp0GfgPPgDPWitxAxEMaJ73h7poGN+PSyj+2C6bZO5ZzfhRlVtJARmR7spxgy
         U8rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768783697; x=1769388497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sQ5IBHi2pbaQt36vHiY8NY+nsRJi72z6Riu7z7j6t+0=;
        b=NaXdkztW4U49Z20yodRdyNiJ7CtYV5jk3c6zuXsgZ13ecLsif379t9kMtIb+iQRG23
         LUr6XG2rSCj5ouxxQE8ItxhLaUxtI0ZPCzdDgbsrTubVur3od3szJvMgscFNZIipdGfy
         umP6PrUOrEkBZ/0QRiqGx6VkE84JPdaGQ9QjsDu2x/AhCr8FPZrNu19eMFeuiWhR/McB
         4g+IL7HiGnAF+c8rMOYzHVn9t2MJ0NoBtTi5FDvrKzgFfuKDUwoS6T0ob7hnbx7leqIT
         p5BZfNxYAcLLdXAyq4n9mFpdTLOeoIPgpPrMHUJOhSEJgWw/83R0KwFooJadcoYzQOYG
         1zww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiy2PIlMBWmnqnvJgvW78+tkkI8wK/8kc01tVf4BkyVMpW1P6dkTziak5RGi/QSHQ7St39CQ==@lfdr.de
X-Gm-Message-State: AOJu0YyeLroE6H2Cnk5GS0OmsXguB8NkSBI9OlgLTkRT/UXHZrb5XnO5
	t+Nnu0Oegep2HrutY7oU3dp9tFVQsLLfhVCwzes235nK91DfcwgHvaUU
X-Received: by 2002:a17:902:ce83:b0:2a2:d2e8:9f2d with SMTP id d9443c01a7336-2a71893cef6mr86748855ad.48.1768783696929;
        Sun, 18 Jan 2026 16:48:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E/+2HCetyHEuhRtJpsghl4zu2cw8GgNzpMAYmuMS1TqA=="
Received: by 2002:a17:902:fa8d:b0:29d:dea7:87cb with SMTP id
 d9443c01a7336-2a70333ee61ls26091545ad.2.-pod-prod-04-us; Sun, 18 Jan 2026
 16:48:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvz3D0jfG18Lpvh1abWVCYFGIGcyQFcsF7u1wsFla1ZfX2OjMTnNDqpja9Eyjvuc1yWHCInjGoQQs=@googlegroups.com
X-Received: by 2002:a17:902:e952:b0:2a0:c1f5:c695 with SMTP id d9443c01a7336-2a71888976cmr94378925ad.16.1768783695478;
        Sun, 18 Jan 2026 16:48:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768783695; cv=none;
        d=google.com; s=arc-20240605;
        b=fW/LAUg5dGWffa4CumV+RYDamrXtpWzFoS3YqejxTAQuOFwniQn7IcMvOzgLJ8OXZS
         Wr5T+vTOua6vyFFdEJkXfXHY2Llvn03noBXWIRogq76/iwvzOgfW9Leyf6/edvQ9B4t2
         K7t0YIeo/glkk8K+NyQouodG0r8IX2jrSGoOSMyCx2rkRNazs1g6NflF6/8+4ahTX1MZ
         y/qUxI6R2GmE3Q1V0kHI8ImRiAJ7+J+y5yXkTPaTpK5MHu2DV4CdWY+StsiAcQgJmeZS
         ChyoQIY0W4GjcWj0NTSNrnsNc/7eDzPQacNEb0/N+PI6r6UJZTRr2Wx5URQpTYd2YgOT
         Mwng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/sM5woLBxXaGwAa8CcGy0J5c58+qDh+8shI/JCC5Mgs=;
        fh=lP03iCP/YMZk3JeJGh8FL9mMxAwFx71uU6tJhhkqk/E=;
        b=MBQFbxAIszQcM+MC0wVMVz2mgGKmbfwU6Tj7vXojB2y2ldWimQ6f4JTQh6kLhn+XGu
         5cTVKKbe7nfNB6NXo02Iy5NmgV1rOgBJz8ekInwyYR5lf2cqdBkHoTASpbEKGjZLjHbt
         dxYc6t+sue4/+e24RKl8YwjqBm12wANCb0bnJqRYmVH9OiU1dmjSzh24FQzYSJMZT070
         9mkOB5G7GYCZN1KH9GzuWvhOrDWkQasPzhLlPog1yVhHJzw/XPIpzaFsVB1iik2bQnnZ
         aSeIF5drwDu36w9AcDgZRL8nTZ6DXQekaqDojxd2Hd1kUUZgQ2oP5LWSXRfpMfaJYvqM
         Cj+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=izuf+vwR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a71939d387si2579715ad.7.2026.01.18.16.48.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Jan 2026 16:48:15 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 0DF0160010;
	Mon, 19 Jan 2026 00:48:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 58127C116D0;
	Mon, 19 Jan 2026 00:48:13 +0000 (UTC)
Date: Sun, 18 Jan 2026 16:48:12 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Maciej =?UTF-8?B?xbtlbmN6?=
 =?UTF-8?B?eWtvd3NraQ==?= <maze@google.com>, Maciej Wieczor-Retman
 <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 joonki.min@samsung-slsi.corp-partner.google.com, stable@vger.kernel.org
Subject: Re: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
Message-Id: <20260118164812.411f8f4f76e3a8aeec5d4704@linux-foundation.org>
In-Reply-To: <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
	<20260113191516.31015-1-ryabinin.a.a@gmail.com>
	<CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
	<10812bb1-58c3-45c9-bae4-428ce2d8effd@gmail.com>
	<CA+fCnZeDaNG+hXq1kP2uEX1V4ZY=PNg_M8Ljfwoi9i+4qGSm6A@mail.gmail.com>
	<CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=izuf+vwR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 17 Jan 2026 18:08:36 +0100 Andrey Konovalov <andreyknvl@gmail.com> =
wrote:

> On Sat, Jan 17, 2026 at 2:16=E2=80=AFAM Andrey Konovalov <andreyknvl@gmai=
l.com> wrote:
> >
> > On Fri, Jan 16, 2026 at 2:26=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@g=
mail.com> wrote:
> > >
> > > So something like bellow I guess.
> >
> > Yeah, looks good.
> >
> > > I think this would actually have the opposite effect and make the cod=
e harder to follow.
> > > Introducing an extra wrapper adds another layer of indirection and mo=
re boilerplate, which
> > > makes the control flow less obvious and the code harder to navigate a=
nd grep.
> > >
> > > And what's the benefit here? I don't clearly see it.
> >
> > One functional benefit is when HW_TAGS mode enabled in .config but
> > disabled via command-line, we avoid a function call into KASAN
> > runtime.
>=20
> Ah, and I just realized than kasan_vrealloc should go into common.c -
> we also need it for HW_TAGS.

I think I'll send this cc:stable bugfix upstream as-is.

Can people please add these nice-to-have code-motion cleanup items to
their todo lists, to be attended to in the usual fashion?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260118164812.411f8f4f76e3a8aeec5d4704%40linux-foundation.org.
