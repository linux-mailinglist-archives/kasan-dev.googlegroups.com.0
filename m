Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMHN5KXQMGQEMUY3JFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AD8A880F65
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 11:13:06 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-29c718b7ff5sf6145190a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 03:13:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710929584; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ob94tAFIHDUP7DcdW58xmKoKEvamBZyWqvGOb1tTXixFR7QdI26UEaazIk0COBW5y4
         CEZhPnxP87fr4OD3Mb25LWGEyYAXb7yJwzgZ9Rq84s5ARlqb3qzYnasy/KwToVVYlrjG
         d4bww7q47mTLPFE7gpoXci4FG6a15d2wpYNNxwXZr9LOyDzoq35yjbzL/UapZDcBT8/X
         twK7juBSFPEx0U8M5s7vKR0gGnISWFpP9yHffs8j1cxOdkkgIFhtR4Z/Bs1N+Tf7fi0e
         hc2vijZH/055qipGP5iUVkQSC/q6U6UmcCdEQZUVv4EtRUC4OeUwujUCnXk0WrYwjRDg
         HCLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kupXLOPKdInB+kh1OfPngejTqKZMhRjqLhSQKlOuvdA=;
        fh=WB5WswjoqyCjhV6LnuClqYqmlg408C6oRUnKS2VGPVU=;
        b=cCKZa4AsOMnSUirsbxGX8ri6PHdX8wuPFiMXrBDmCPwRgbwb6OQFdbeT5f/P2s+UJz
         VeUd4dQJYVSEazYdSI8qWG0APYd/ZkNZuNaX/ITprFLb3Qw10uW9eecZ2882yMhO+oXA
         Wz/ySIJ1y9QM0JM6gF5wH+4cEJNOqrtIOxKwh33tqn4279kND5FnHwlb6hUuU6pVKhio
         Kh5YcEliimg9IwuwYf8mWv/KrdvysVZpvEx4bXKGlMdgCX5ooeb1txthv9DKWGleaJXx
         UNlABWE3/4MvEq9Rmhsp9hHn1TuhVESxHm5taFJaopprlcyAydlT0/xC6Smcgq+eZnt/
         02Jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X15+c0y1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710929584; x=1711534384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kupXLOPKdInB+kh1OfPngejTqKZMhRjqLhSQKlOuvdA=;
        b=OrB3KtMWpZIXBMlc6AGppjSNGubarMiPcu5eH/1gy5FyvfPzvDENBExAMmWMYw9YTX
         uSx+jlSbOb90kozYaF3bmil2WKtvT33wfFBFXrakvNZvwLj96YlqMJNOZLdfv3RUdSH4
         Y68nOt5Rt7uCVUwVeFUhKzGcfyF7Rg6J8DNBNlnlwDXejZ9+JwP/NfsYpGvQcTm0x5+2
         lbtRSEdvxsF1IwByVTSM7dQBPBqvmFww8Al1FP52BsPNoyqLZwczuaEuYuoVeajCY6c1
         l46wxIsAU0qC7qNlk8PJufqpFIt9XjYlT50Zu5nfm1ik6smNlOy+8iKgCde7D4NtcK8K
         SRzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710929584; x=1711534384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kupXLOPKdInB+kh1OfPngejTqKZMhRjqLhSQKlOuvdA=;
        b=G+okLC0/7TWo5iIvFUe4cgaPj1fZCKZAN/7Uej27NmHeSKRuO2kZvSRSlWdUl3vWHR
         9vm9iMOZdx/BM0ymsBIi/zmxwtslT+9DMzrqyUyYcX1+srVmAnxZK73+oMAbO6MIUo7h
         XKsQXBGUoL5KrTJ8Lfkyv0lta340V4Qpy8UuXvkwSjFUNYbXIOjF98lwDCKjUORxY7R2
         h/svnc3wmiiCwOXQ1Yn1z8vVk1FjaifWsYyzW2aWIpOSmhm5Cisc3RtE/35I7MRi7Spy
         H3Vs3awrw/+AtLQN5sQK8UfHPocDaT948QSm4EsXdHGD0ZqcJ9njwOsHs6U4UvZWldaI
         2hpg==
X-Forwarded-Encrypted: i=2; AJvYcCVc9k4FVlruDtkakuYi+scinJ/PpKjUfMuMqeCEHl8J6bvMN/9nuT7wqQULcSS4XuU+Et+GrUZHaIsBwlt/kjovlOAQpouWVA==
X-Gm-Message-State: AOJu0YwyNzyW1fSjMsR8u20wKBhMyiycNeYWYG3ULSAJ9v7ExkvQCStX
	i98AbI/LHmKlPRFXERHUYeQEH+a5f76NCfGWyMM1S5qQtsLwlenD
X-Google-Smtp-Source: AGHT+IFFbLg0tbyITF8oFZtSvIJoLzH9vmOKigCXZBrDFGiJo8J+lSfE5/YZvvUam8kXr0SF+VRonw==
X-Received: by 2002:a17:90b:84:b0:29c:7646:113 with SMTP id bb4-20020a17090b008400b0029c76460113mr4577434pjb.22.1710929584526;
        Wed, 20 Mar 2024 03:13:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fb96:b0:29b:e0ee:9070 with SMTP id
 cp22-20020a17090afb9600b0029be0ee9070ls667912pjb.1.-pod-prod-08-us; Wed, 20
 Mar 2024 03:13:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXkixr++4IC5nXY/dCCqC6it5Kv3/6+qjz7J41OpG4xzSC7/+OlOaAp6VblHxf/g/l2BKjNbhbiHQcm/lfnxYvTUk0ck4JWAroC1A==
X-Received: by 2002:a17:902:cf06:b0:1e0:2977:9dfc with SMTP id i6-20020a170902cf0600b001e029779dfcmr6574564plg.55.1710929583352;
        Wed, 20 Mar 2024 03:13:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710929583; cv=none;
        d=google.com; s=arc-20160816;
        b=o+aH+foGvKDc+ua6K3FiHRoGTykBjUkeH5fQdcXlH++kcn9pnz8z+nHdkKdjbjEW/d
         Nhdcipuk9iYRTjOUT+wiXEHOWunMnwK5jrsBKlsBE1Gm2vi8Nn1dDKbp3eIxCXIJH0Cp
         bL5y1pzEjXPhnNRrZ/zykfITfMEVAWPUuQvVvB6/8yJS9UFcCQuDLjK7YLJKx8zll02Z
         SA6p+Q3EILR+cvR7n/YrPDNY0T9asxIU+mDDCGCgLhjBbPVL0eEFxsfUGaX6ycvegrgN
         32zYm5x0MfE691DWUhJlOgYzNZ2ezITluOqHAPamsRzspgwABv8/GYqeXk/yj7v+KWU6
         9RZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tTp075kwbc6LfAaXvHEolsZ8AZN/qxf8o0cgwtL8pnM=;
        fh=3jpBYOgdRKTc9YfEzcOgdJEgTTUlxB3AQxUxXTvRZMI=;
        b=SGfUi1OrGLNd19U4Swue948lHD7E5QnH+fZdZhOyS7rhfzxW0PFoRFF6Vw1Rl00nSg
         w/YgpSMCbC2PcHNEPJLMeLeoQQ5CZ7Kzpv4kHBWj8zPxZj/PsHRKcS8EumNccCn5SEeT
         hGV6VwUDrcHgVOxcPVjzJn+9tmgeGojHLJRA9JPbKuAii3A79Xzgb5gyizgZJqL1cvuW
         MpdaBBYGEbk5Parhi6cMjGTOA8BAkHdk6D5DlBG4tcvBigXNaXPlb4jdgE1dzddSTz7k
         BWK7DP5hheR7LnAL+ljC/5E5NoJp0PDvxlkLVOAoV0Pu45UgvY04rMMJ7NNl/vcEsEHS
         DJ3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X15+c0y1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id mn3-20020a1709030a4300b001e03dfdb508si263046plb.0.2024.03.20.03.13.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 03:13:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-690d054fff2so40920006d6.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 03:13:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXDk67sO0n682BYwdK8B2PJ0bhnuupBl3ke+5Y22oJBaoUG+T3/dKIO4D7bcHdf1vDXibRL+epkGMOL5QERDe4Zi7Rf2Txem5eXg==
X-Received: by 2002:a0c:f38e:0:b0:691:3ccd:62cc with SMTP id
 i14-20020a0cf38e000000b006913ccd62ccmr5727614qvk.6.1710929582254; Wed, 20 Mar
 2024 03:13:02 -0700 (PDT)
MIME-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com> <20240319163656.2100766-3-glider@google.com>
 <CAHk-=wiUf3Eqqz3PttTCBLyDKqwW2sdpeqjL+PuKtip15vDauA@mail.gmail.com>
In-Reply-To: <CAHk-=wiUf3Eqqz3PttTCBLyDKqwW2sdpeqjL+PuKtip15vDauA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Mar 2024 11:12:23 +0100
Message-ID: <CAG_fn=WRz22XEV_Em+M2FJsNjuBr3mZFT7aA5G8YdT4OTf1p1g@mail.gmail.com>
Subject: Re: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=X15+c0y1;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Mar 19, 2024 at 6:58=E2=80=AFPM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Tue, 19 Mar 2024 at 09:37, Alexander Potapenko <glider@google.com> wro=
te:
> >
> >         if (copy_mc_fragile_enabled) {
> >                 __uaccess_begin();
> > +               instrument_copy_to_user(dst, src, len);
> >                 ret =3D copy_mc_fragile((__force void *)dst, src, len);
> >                 __uaccess_end();
>
> I'd actually prefer that instrument_copy_to_user() to be *outside* the
> __uaccess_begin.

Good point, this is doable.

>
> In fact, I'm a bit surprised that objtool didn't complain about it in tha=
t form.

This is because a bunch of KMSAN functions is ignored by objtool:
https://elixir.bootlin.com/linux/latest/source/tools/objtool/check.c#L1200

> __uaccess_begin() causes the CPU to accept kernel accesses to user
> mode, and I don't think instrument_copy_to_user() has any business
> actually touching user mode memory.

Ack.

> In fact it might be better to rename the function and change the prototyp=
e to
>
>    instrument_src(src, len);
>
> because you really can't sanely instrument the destination of a user
> copy, but "instrument_src()" might be useful in other situations than
> just user copies.

Right now at least for KMSAN it is important to distinguish between a
usercopy and e.g. a URB submission: both are checked using the same
function, but depending on what is happening the report title is
different.

The destination parameter is also used by KMSAN to print fancier error repo=
rts.
For an infoleak we show the target userspace address together with
other information, e.g.:

  BUG: KMSAN: kernel-infoleak in instrument_copy_to_user
include/linux/instrumented.h:114 [inline]
  ...
  Bytes 34-35 of 36 are uninitialized
  Memory access of size 36 starts at ffff8881152e5680
  Data copied to user address 00007ffc9a4a12a0

It comes in handy when debugging reproducers locally.

Future debugging tools may also need more insight into the semantics
of the instrumented accesses.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWRz22XEV_Em%2BM2FJsNjuBr3mZFT7aA5G8YdT4OTf1p1g%40mail.gm=
ail.com.
