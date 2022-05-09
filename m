Return-Path: <kasan-dev+bncBDW2JDUY5AORBLHQ4SJQMGQET4BJI5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7919C520194
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 17:50:05 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id u18-20020a5d8712000000b0064c7a7c497asf10204169iom.18
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 08:50:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652111404; cv=pass;
        d=google.com; s=arc-20160816;
        b=IXpPQP538rM8G1atC2TARgk7YtvZL97UwUKYGaqLtNFEy1vrB4Tmh8X6BVZH2i6hRS
         eqnKvYSvabLlnf+MwZYym37kLmhL+l5mTg6nFi+TmpQEF3NVIjcUyxhHlty3voFdfekW
         Uo5n6oFaqHw2CZpA7IH7fkw3QATwBgffG1OvcihEzN3ywCRGsO9yJMukFtL6nuKU2p3/
         iUllAp8fdRtfvRn9aLqcEnn5C6Hp4a9Ypjr2z5ZOR4GCX+IvnXBX3Jcty4kQkrhw5ByT
         kZur2X89nPjG6lZ7o+w3KOkpz/ONCHC0j+XGQnwIj/QlTKGvtrLuyAjE74CtZ8Y7Cu1W
         T6qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=r8HOP2tUgBHfw5HQEfRHxmHYzitB/37ZAmyep/y+P80=;
        b=BnY+pzTk0NPGGEdC/XKlsxuxOhqOPNaZoWBQkDBnMjPXsU2AG8eL3l3VV7Q9wqie2w
         ZO3zzkSLOuhRknsCx5Ke0E/5UhbXLvLg+FNEYqzH2YgkgYmsGqjVgGuu7NcsJFMxaua4
         y3wMR3DakQkIdWNgZZ2q4xx5XoiiQ5kJca77FBedkZguaLBXYIYgOPUZ3yRqawf7pf6M
         X8V88ZRp0+Zn8CLUPHGuGJxHpjgv3ieZ9NNVh78IUE+jmDA1q6Hp06YkEx7Gb44N1Eh/
         vE+DOzBwGPGTUtxNgZnTaV4omoBlmw8EgNm3rPzo2QYhEC9xR3THALgzSkhzgrpAiNUC
         WD/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GNqB9+dO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r8HOP2tUgBHfw5HQEfRHxmHYzitB/37ZAmyep/y+P80=;
        b=RTS7WXjhulpJ82UiJi59FEb7Ecs6mp2YKLmh/QSw/7WeCpgJSI/mPVdbyL38Ftcbav
         sMWxm5748fh1tMJQRpmvQ4+ExX6RSJfQAk9k/05srIxlDEUgvQ7bRVbBYmOQXD2m1GFJ
         s8dYdihKr6EUuyvi1q2aFn9vqw8EeUR84tJ4TJBPeUjQdgqEYcO4RwTsjNq/xCN7YkEP
         hethBMGC6Y9DhVtDshnME6eZXy6abyS3rA4yHmVSxzcssyhnoBJtDnn81XqOqO2nBVWo
         UStKoSJ622sUBiLCe9qKtSgTFWyNKYK/LYyv8RBz1EdFtd3TkW7GDo3hmmxTFTP4YhBE
         aXOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r8HOP2tUgBHfw5HQEfRHxmHYzitB/37ZAmyep/y+P80=;
        b=DZtsTGKTMcaqAxgtjaFLmCpUd4//de6ZgOdIScU2HP5jJnvllDj5tgrZI1r+mB7YBD
         bFpzoyBH5XCUYC5b41zaIKprT0vEF18mH9imVXPIivGgZsUKO5QHBS7dzJirT6wm6Y7d
         8WdTdIjeePg65zV5rgPRcw/1ro/wMynh8gpKnTHK7UeId5SYOX1nJAwtsH8kW+vSm+mI
         V4RCmGJMxuXjOk3yxukHlH4b44RC9ALdMjVFKwMODGPKtEmm6Nu7mJQMQhPaefsaFeQN
         cSySg526K9NKhb1uce4/OguJlHuEbsUfwMavfKHE/32UebtqyQNbQUC0xAkfabyz1lcx
         moNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r8HOP2tUgBHfw5HQEfRHxmHYzitB/37ZAmyep/y+P80=;
        b=i4/tid95/VcQP7ZA+5SG/bacRct28KQmonx2qb8NEnmbnR+YqmTM9bDTib8F1nd+kk
         lS5BCng4BICv34kaKXJyk6rlwhyaVtOPybDHTfcoaz7+Q6y23Q/dzDKjSPENIdHtfmMB
         iDX+B9e1UxlWEu/YLmyDFEuKxjWxeWLHz8Gf+7CXSDEaMO3q1VBrwfxgF9FmXimvu9ua
         SG0IweTOM78fpxFIoZ1piZUGkjocVzspUkFD57fyrO3yB6/d3IGdR5OtzQrGQIWeX6yh
         ptyAPs5hxGQ92dENb16IkDJAmQAnrtVPwznLPG/KWAA5I6p55GEOj5Cbb4JucapR8Zzs
         0KPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531k7lxxwInhsPRfAZ6Cik8oOmp6hSayl6dnJFfpZYDPFzGkw9aX
	80WWiKpzTFJRLyzfHQT/3ZY=
X-Google-Smtp-Source: ABdhPJwieTce5kWA0R+ttTkN4HEtXqVRR2L37JJhE7NyUUvIbPdJF1DVtTCI+nEtDGoLZU3/FP/Ypw==
X-Received: by 2002:a05:6638:270b:b0:32b:d0c5:9c79 with SMTP id m11-20020a056638270b00b0032bd0c59c79mr6606203jav.297.1652111404251;
        Mon, 09 May 2022 08:50:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:bc07:0:b0:649:dcac:247f with SMTP id m7-20020a6bbc07000000b00649dcac247fls1608370iof.9.gmail;
 Mon, 09 May 2022 08:50:03 -0700 (PDT)
X-Received: by 2002:a6b:fb05:0:b0:657:655e:a287 with SMTP id h5-20020a6bfb05000000b00657655ea287mr7094860iog.211.1652111403905;
        Mon, 09 May 2022 08:50:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652111403; cv=none;
        d=google.com; s=arc-20160816;
        b=mGLLSDIQ/G7nmYqGNj9xuDjOVDOeXmdAwcg6z5Xzi5b5tzQuw2wZn2pqrrpj6qfO6B
         3JZ7r6BjcaZqZCKcWsauB2ioOYS31FxwowIyJs1QD4uvt6galyT6m5Z1ypHXhMhYfGj4
         xEZc+YU6GIL26GrFafgr5ynVfYIhaBKpCAcTzY3MF47QkyDRBOgerUZiS8q8eOCfmnqu
         Re3Lj1RUWtAFca8mf6R/dFzmuMppE1AUtQKjIAR/0OTUQcx0bHjjZRVacARnwZHVMlh7
         CTu8uqVD/vzDhmqsbsWQPGxrQ5t8m/F072Z7rlHLmdVWTWWwRSv3xrICGYXGPV9ye6U1
         Eg6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OGkep1cFKgrJ0+QYCkcQH8E9lVqym+xbFUqlGchTBdA=;
        b=xexgFRb9hu3lH5SdU4W1T1FkQUMOpmYiC1zT8Toe59AsczHmcz7kc2WLkNzC0fYYNb
         a0gzctAR52EFKTSLIXVRcJv8Wep4/3ySuqaqSZL1lUlj/YYm+vaI5gX8lASszafMZAYP
         aeVRgOUcuRPvpZOdx57dO3tdtSABP2STyY7wBawTf2AC3zr6JPjTGCh3eSs2UawwXuRs
         yfUf2g3M4XoYhJkBLjmDUukv0+LT0jf0zeiWNVCwO/Zd3hlYNawRlTcEzowLxsp+U0jK
         pkm1Qf9wWi07OrAQdp/2HwIEl+PlE70yknVa6xbGUHoqPi5VKvCdtwe+o2v3Qd7Vtx9h
         coHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GNqB9+dO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id r15-20020a056e0219cf00b002cc062dcde7si1082974ill.0.2022.05.09.08.50.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 May 2022 08:50:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id i20so15798545ion.0
        for <kasan-dev@googlegroups.com>; Mon, 09 May 2022 08:50:03 -0700 (PDT)
X-Received: by 2002:a05:6638:30e:b0:32a:f864:e4d4 with SMTP id
 w14-20020a056638030e00b0032af864e4d4mr7221878jap.218.1652111403703; Mon, 09
 May 2022 08:50:03 -0700 (PDT)
MIME-Version: 1.0
References: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
 <CAG_fn=XFOA-qsvPwjwJ0iZH1Wy54aS7QtD4ETVdp9L-yvOkiWg@mail.gmail.com>
In-Reply-To: <CAG_fn=XFOA-qsvPwjwJ0iZH1Wy54aS7QtD4ETVdp9L-yvOkiWg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 May 2022 17:49:53 +0200
Message-ID: <CA+fCnZfkKwYRTn+oK71c89jJG9CKAUqrURxq=g6z7EJXrr_Pzw@mail.gmail.com>
Subject: Re: [PATCH 1/3] kasan: clean up comments in internal kasan.h
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GNqB9+dO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Apr 28, 2022 at 6:42 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Thu, Apr 28, 2022 at 6:21 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Clean up comments in mm/kasan/kasan.h: clarify, unify styles, fix
> > punctuation, etc.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> >
> > +/* alloca redzone size. Compiler's ABI, do not change. */
> s/Compiler's/Compiler ?
>
> >  #define KASAN_ALLOCA_REDZONE_SIZE      32
> >
> > -/*
> > - * Stack frame marker (compiler ABI).
> > - */
> > +/* Stack frame marker. Compiler's ABI, do not change. */
> Ditto
>
> >
> > -/* The layout of struct dictated by compiler */
> > +/* Do not change the struct layout: compiler's ABI. */
> Ditto
>
> > -/* The layout of struct dictated by compiler */
> > +/* Do not change the struct layout: compiler's ABI. */
> Ditto
>
> > -       unsigned long has_dynamic_init; /* This needed for C++ */
> > +       unsigned long has_dynamic_init; /* This needed for C++. */
> "is needed"?
>
>
> > -        * is accepted since SLAB redzones aren't enabled in production builds.
> > +        * is accepted since slab redzones aren't enabled in production builds.
> s/accepted/acceptable ?

Will fix all in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfkKwYRTn%2BoK71c89jJG9CKAUqrURxq%3Dg6z7EJXrr_Pzw%40mail.gmail.com.
