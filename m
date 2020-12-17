Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXP75X7AKGQEPFNLMPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 02A9F2DD4AB
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 16:57:19 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id f15sf14197931oig.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 07:57:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608220637; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTu4sLvkipn+wuAkFA6nZ+z/ArsZFewE+eB7pFj7NwWlUo6CJSbiR+WpXY7fk1doQg
         bjrJtT9Lv7vnRao88k0Kk3I9EYN94WPaVr7s91tDT+UBvIf6P4Wk3CCUUruHKByirhuC
         QfTcb0hPPlKifuVSBf+IUUK77c3m49wXsNeLInw5rh3Exjd4s6gkAnzE9iDYsDuL070v
         VRzFpXt1N/HeRirWaxyNo+6vB0xPuN+yg8WzH2FuaQj0Q7XHfj/t92SJIB+FzbWBxh/Q
         fTKSB6FVTv5fmq7zk1zOrhAXNvxwb40qPi5LX/zEL+PIKSgbwTfoJ0JAsf1H7ymZfz1Z
         n0qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZNLb5M3EMfBLRriwS1eVFslVw7jas6/v0QvzGKbKLW0=;
        b=rHB4t9qoTpXijbRURHmNPssnQsyYeeR5h2ucHuFQ8TmKxJ7QurhcFKd4Ic0pe2G0bi
         r59kh6SA7QjIRbeowuj/4qOAZwSf0QK0c6ymmI1uNYzr9lqyPOuBaQdQTrnPywMFLzpm
         kZDePBcIonm4W7DW7KLRDUI/DU5jN14CdgdyFplDNAuDF5PtifHo+ROjNv8A5W01nPzE
         fdvsS21nUVf25Knle+Bo9Z93lj89CvHDTm/N1nA9IDxsQhfpTOQpvFlIguJZDvt+D1I9
         qDUaXb8xM33FsxYIHpB0Tb8yxhr6nWbQD7+za6g1K8mr6Y5tUgz7077Vfac0gxxvjK11
         5qCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WAINATTe;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZNLb5M3EMfBLRriwS1eVFslVw7jas6/v0QvzGKbKLW0=;
        b=IrZgtpLWEJvGcLbq9Olavmo0tDW3jwyb7H9ypxiyX3WEqcnvYw+WKlwUP0X3xkSEZ2
         EyXc7F8u5hz8dhxBjHcEqK8wCusW0v9nbD7WlZK5CdAXpfLgiVlvgPsrnZ+8Rt1daBig
         VZ1b+Mv+LzVfWR+LwhroQhmUPeylvFLgPkAOdS72M80zNKM7sUZXqiOsrPK9MoNwnygW
         K8nHf/edCyPsdu1nYBjKFitObLsg+VSSwQ27p+od5Ewl0fzD2PQuhb9T4EC+U6+ADJns
         HUM7/nR/ZU36YHyKhIqgzBa9D27aruPMM4JAapcQbCzldmwzzbSPYGSUqfUKIEZfzSNn
         XMPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZNLb5M3EMfBLRriwS1eVFslVw7jas6/v0QvzGKbKLW0=;
        b=hYIgNeaopwq/t/emE6XEERJtE6FeWNQxGabANDC0VQTJAfPDSE48BRmDcCZUKBOpdE
         0WhC//MB8uKDbXf8kD5p34gIxGkziAES1gI4TaBr4uSerJoagAyEndQjHxzf+pRg1N4D
         ojOaBjKyAwItClBNYMBE8eaXQdpny5uPKc/Zs/sV62s3GqROYOEGHQI+C5dyUW/5Etiu
         JL3qmC/AoFGqBKZEu6vwgWlO4VTsI2sCE1SUOT8VS1sGZ1lnlf7SlC42hnclSUZbBiyF
         sp89dkf9WIlPiqaSWGEdWIOrb7q58hR7HU9Ng4ZfbbgvDJoQnojUTQvrGa6uV+FZJbqO
         ydMQ==
X-Gm-Message-State: AOAM533BcNR8N1zlEYFkHZ5HKuQkEYmAOWqW97ofcK3JKdXexNHJ7kzX
	FRzqqQiJ1wvM2w6By6XpiAM=
X-Google-Smtp-Source: ABdhPJwQJ0t37O0Nvs0veSTD1VIrczXV611+42wpQ2X5P5iOEIjbUIo1KkUHvtdYkj94/QPd4EI2Og==
X-Received: by 2002:a05:6820:503:: with SMTP id m3mr13953329ooj.83.1608220637863;
        Thu, 17 Dec 2020 07:57:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c413:: with SMTP id u19ls6935219oif.11.gmail; Thu, 17
 Dec 2020 07:57:17 -0800 (PST)
X-Received: by 2002:aca:b108:: with SMTP id a8mr5319145oif.108.1608220637584;
        Thu, 17 Dec 2020 07:57:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608220637; cv=none;
        d=google.com; s=arc-20160816;
        b=up3AlvKN2qjDe/rQUGFf0El+cg+W6hWGJay9p3mzbfOVl+srzh6WTXHMh0Qh1/kcl+
         2iMS2S6CrXRSWlvGraoeR2jC2roF7Ly3D5nR5zX1CwZb8hzCaAS4jfyUXnVmJqM5aEtv
         4kQfLosPjYzA/LQ4linPIV8U21uhrfAKfDMdyDrhVMOPY6qucH1vH8AMwRg2MBcR2GqB
         cnqGMISbzUPcdQlFWRFvcUZuhm0nBLUgKCOpXos4PTR82cX3TeRcWqroK/K0VVT7A8cj
         kOVvPkSDfuFhBBYU476gmFy+rSRgZ+JIpCm7P6G/tWZmONXshMrGe9G2/2RZAFuVVuNY
         hiVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T7Af0WGDzuMPlnkW0mmNLYKjVtF8jTxv62OsHLUaGj4=;
        b=ARtUbeve9AKPVXCNuF6EzZj2In535rh+pnePZO1NriI+kVOGwE11B2lJfdQ8EgQaEM
         wZD3KW4j8DxYfp+bXVzd6YQQ1OftFgucJheQV6KwDayEzFA+zopVSEcPKtU7ud+1STCo
         NX+9ru1Xvx4G0gIStVlTm6cI6ndzd3b/G0c0pvD/wn5qS6tFeWT1fZ4YDEhTtns434/y
         zelHKp2hY6vDKkXjw1qZY5PCvCNYgeDe9fRSfZi2DASkwimFK2Xpr5/Ld46Wl7tdy1dM
         gUHSAHmAq7XBBn3dPO95uNmFldVg8xoJUGX8R1JYAxCJzHlaesjHANktOUZIKtmFo9hN
         cVzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WAINATTe;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id w26si361175oih.1.2020.12.17.07.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Dec 2020 07:57:17 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 4so13481661qvh.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Dec 2020 07:57:17 -0800 (PST)
X-Received: by 2002:a0c:e90a:: with SMTP id a10mr41908062qvo.38.1608220636994;
 Thu, 17 Dec 2020 07:57:16 -0800 (PST)
MIME-Version: 1.0
References: <X9lHQExmHGvETxY4@elver.google.com> <CANpmjNO5ykmE5kWJ0x08-dTDOLe+Wu=2yQ0OmfdQEbQfHByeWg@mail.gmail.com>
In-Reply-To: <CANpmjNO5ykmE5kWJ0x08-dTDOLe+Wu=2yQ0OmfdQEbQfHByeWg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Dec 2020 16:57:05 +0100
Message-ID: <CAG_fn=WY9qkUAg+5CjQKYGHMEqxUxsGaYSYcGgb=uumiO-BnTw@mail.gmail.com>
Subject: Re: [PATCH] kfence: fix typo in test
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kbuild-all@lists.01.org, 
	Linux Memory Management List <linux-mm@kvack.org>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	kernel test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WAINATTe;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
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

On Wed, Dec 16, 2020 at 12:44 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, 16 Dec 2020 at 00:31, Marco Elver <elver@google.com> wrote:
> > Fix a typo/accidental copy-paste that resulted in the obviously
> > incorrect 'GFP_KERNEL * 2' expression.
> >
> > Reported-by: kernel test robot <lkp@intel.com>
> > Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> > ---
> >  mm/kfence/kfence_test.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> > index 1433a35a1644..f57c61c833e6 100644
> > --- a/mm/kfence/kfence_test.c
> > +++ b/mm/kfence/kfence_test.c
> > @@ -665,7 +665,7 @@ static void test_krealloc(struct kunit *test)
> >         for (; i < size * 3; i++) /* Fill to extra bytes. */
> >                 buf[i] =3D i + 1;
> >
> > -       buf =3D krealloc(buf, size * 2, GFP_KERNEL * 2); /* Shrink. */
> > +       buf =3D krealloc(buf, size * 2, GFP_KERNEL); /* Shrink. */
> >         KUNIT_EXPECT_GE(test, ksize(buf), size * 2);
> >         for (i =3D 0; i < size * 2; i++)
> >                 KUNIT_EXPECT_EQ(test, buf[i], (char)(i + 1));
> > --
> > 2.29.2.684.gfbc64c5ab5-goog
> >
>
> This patch could, if appropriate, be squashed into "kfence: add test suit=
e".
>
> Thanks,
> -- Marco



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWY9qkUAg%2B5CjQKYGHMEqxUxsGaYSYcGgb%3DuumiO-BnTw%40mail.=
gmail.com.
