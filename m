Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCVHZWVAMGQED4U42BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 051B87EAE88
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:01:32 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-778a32da939sf535884785a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 03:01:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699959690; cv=pass;
        d=google.com; s=arc-20160816;
        b=jg7D29h1yNT4hK2NFP/v9UYseo8wZcpuD9E9MZ19mvWJqDLcUfO9SQGGiKpvUlf9oh
         GxItoLZWM6ilaRN6SFDOZqnb6dNK5q5OAEsQlgL1Er6puBW+P1Uk6mDpos0rXQtzdEzP
         xREEPgwmvJCs9qA8InlvezuB8SvHZjZ2HQUp3bEUsoyQUUN/PSfLyySI1IKjhvsVZnLO
         ohZHaXsDbvS4rMvrWQ9EtAmzaovPyKymP5+VCwL87q88ogQZAyqEuirIxYxLQM/Z8GHx
         MOojb+2A8aKxKgIPD1b7MjIWJhF2HQaIYYbrRvvUEGMdp5A6GXqg/AcJCNu8Hq0D700d
         onVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ju9OhX5+hld2aa3vsH4RJQBECcrlNyLoW8qNjcM5y3g=;
        fh=DRkrkGmUOIuN9QSo/IJMlqRSusiJdYfQOPoOnGqxitw=;
        b=J9m0NOG3bf+8qymc8HKeLR5UGTanpcD2WY6DdFKJ6deF/6qdxKJRmwbG1LK+Vx4D0E
         2dMSaNz0qiZxxIABW8U3+9qlWoWFDzcCndv6rzz70va7Nm35UM3baCI1f+PMfFsIR6YO
         IxXZPXyKWMWrz+PolLojMfKrG4wshdqlBum7sSlv9temqXErFDLnr/wN55DXmr6gBSCr
         puBuCpHIyBnMNvSW9r8XXTyTAmXhL74SmkevOzlYrIxD8KRptElfwepimiFP3+PPSAJb
         AYPC2jrnC95tlHRej0DMm8Orxipc1NLs4rB6JsVS5Gq0m5+3XviBO6iYeoDtf0reW1hx
         +9cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y0e1k6oW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699959690; x=1700564490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ju9OhX5+hld2aa3vsH4RJQBECcrlNyLoW8qNjcM5y3g=;
        b=Gs4jG+P4X5q6yJPuvyN9Jf2F8iF3wp3Bg7HBGVlBqocuZwVYrmrsgM4AEJnv04aGVs
         debCa87uSd3gBj262jfL0hrTwJL52EG/cXmEk/UyhndjkD3xK+bCYYy18zmMwZR0AbR0
         RonYu/kC9TNdp0YA7L8r+GxrdOqU6iA25pxnpRPu1dXiUbny+zOh10u0tSkI4D/P67M5
         VnDmcfjFBGa+LPQBmjG0DOBkAmKCZ94ylgbwBJEjeAnw0yuiGRgbu51OCS2RZfkkWP0C
         q4QR9qmGuS+IYO9LqhArggYatC+R/9AHkXEyrSpze/ob9j+CHy22yc1eIY0q3qWgrExd
         TrGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699959690; x=1700564490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ju9OhX5+hld2aa3vsH4RJQBECcrlNyLoW8qNjcM5y3g=;
        b=Pa3jHppYStPovkV9LqaadxjBdn5Kw2DqW+H3t9cv/MsVzkjbPzTyLEHu+tPBYBgJSv
         v4qkAI9b9UezAXsFG3nqClCYYQp/Ty/TtZqBxHnbKpqa2TgXG0IUsPyAdPnh51dmEqs4
         sZBRi258mP3bM0eGK/z3dWLgjmWL4xAxCsibl1NgeM6wHL7Iv/3vfEYYtE8jqMgDCcRP
         WAB4+sXjvOA5QCHjya+VouS0x5pw3sDCbQcx/b5heiR6VS4/RhHkTNzkiGthYYDyoVxb
         RfGvu6gKYBiHHvJfQe6aE2n5Dqk8COoXvagYDUS1drh6wOURrMxKS/InMhineG+mhhWH
         PnFg==
X-Gm-Message-State: AOJu0Yy+DTkw+osWqM8QkykcF4sUuoawaoNIDJyHdCzJTAgbbc6qwfsu
	hCsD7ZoTA8zFuu6SCQHWXuE=
X-Google-Smtp-Source: AGHT+IH/7BSTUnbXSEbFLPYtBS0bMkarWAuXEHjeI+Pku+OdjFkJA7LSZRw6JcH+mOvyvntBLxQ4Qg==
X-Received: by 2002:ad4:530e:0:b0:66f:f810:9e2b with SMTP id y14-20020ad4530e000000b0066ff8109e2bmr1704922qvr.52.1699959690609;
        Tue, 14 Nov 2023 03:01:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ee21:0:b0:646:f0a7:568f with SMTP id l1-20020a0cee21000000b00646f0a7568fls746262qvs.1.-pod-prod-08-us;
 Tue, 14 Nov 2023 03:01:29 -0800 (PST)
X-Received: by 2002:a0c:e94d:0:b0:672:1d32:9d37 with SMTP id n13-20020a0ce94d000000b006721d329d37mr2009225qvo.26.1699959689477;
        Tue, 14 Nov 2023 03:01:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699959689; cv=none;
        d=google.com; s=arc-20160816;
        b=kyiAYS1UtY4neR31wPgRqc9m1WGvQig89HRnFqQju+g0SGXJfLR0tk+CAdgstDK/LD
         ZG1hxbbBR2uYx3u9kvVO87NZNOCQvCUYjKOjzxksNMF87T0r/X0vIuO4HEYzpeOCbItz
         NFMpLHij1fWKKh72y+nrB4t0i8d1rBkAjYBlvNVN9pDm+oMxmslODhSolugb1N+ALtbS
         ZA0sfTDXjep7GihPYPBvRj94t8+58fRHt4yqj8bLwfnpZIAFewncfT7DbigHC1fmGotx
         oFVnQqrMAMNlSeP2funB9Gc9sRO8CEPf0En5IRVPRC59wCEiFPP8vKBZrb2jWmPpo7FB
         kFNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xWHrJu1S5UhWNIqA9ni22z01xZVMyORc9pLCUHXauxA=;
        fh=DRkrkGmUOIuN9QSo/IJMlqRSusiJdYfQOPoOnGqxitw=;
        b=Ty6ZbMn/I1f3Th/OAwOgRsHPtchNs2YTXubERLI1TssIAR2+KDA4JJDW26C0dpKm+Y
         lQXmaVZC8a0dfqrAAQFe98mU7G3eFRGTpwMY1yJtLfL54BuAGQ9amStwkUq+EJt0G7F5
         0ozG+CyIf7FokavciQpxDja57LdjpQWZfx+L4iOQBqGhPPcOlkKOpFJ/Pzrn9w4S0yYq
         wPE/XqX0VXIeUV1BNHaCew55TDHIqCuyEV+5Xue4c1jCaD/Z8KHZk+BU66gu2SP9n6eG
         nKcsssKdW11qR0nEdaFQCVRWx4SZZSQtTMQOtFqYWt8vS5WSTUOPyrmPnoT7TCXrVBbF
         SyUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y0e1k6oW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id s17-20020ad45251000000b0065b087b16ffsi576054qvq.6.2023.11.14.03.01.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Nov 2023 03:01:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id ada2fe7eead31-45dae475aedso2146738137.2
        for <kasan-dev@googlegroups.com>; Tue, 14 Nov 2023 03:01:29 -0800 (PST)
X-Received: by 2002:a67:c283:0:b0:458:6173:8d4 with SMTP id
 k3-20020a67c283000000b00458617308d4mr4973730vsj.20.1699959688830; Tue, 14 Nov
 2023 03:01:28 -0800 (PST)
MIME-Version: 1.0
References: <20231109155101.186028-1-paul.heidekrueger@tum.de> <CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
In-Reply-To: <CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Nov 2023 12:00:49 +0100
Message-ID: <CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: default to inline instrumentation
To: Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Y0e1k6oW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as
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

On Thu, 9 Nov 2023 at 22:08, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Thu, Nov 9, 2023 at 4:51=E2=80=AFPM Paul Heidekr=C3=BCger
> <paul.heidekrueger@tum.de> wrote:
> >
> > KASan inline instrumentation can yield up to a 2x performance gain at
> > the cost of a larger binary.
> >
> > Make inline instrumentation the default, as suggested in the bug report
> > below.
> >
> > When an architecture does not support inline instrumentation, it should
> > set ARCH_DISABLE_KASAN_INLINE, as done by PowerPC, for instance.
> >
> > CC: Dmitry Vyukov <dvyukov@google.com>
> > Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D203495
> > Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> > ---
> >  lib/Kconfig.kasan | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index fdca89c05745..935eda08b1e1 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -134,7 +134,7 @@ endchoice
> >  choice
> >         prompt "Instrumentation type"
> >         depends on KASAN_GENERIC || KASAN_SW_TAGS
> > -       default KASAN_OUTLINE
> > +       default KASAN_INLINE if !ARCH_DISABLE_KASAN_INLINE
> >
> >  config KASAN_OUTLINE
> >         bool "Outline instrumentation"
> > --
> > 2.40.1
> >
>
> Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Thank you for taking care of this!

Reviewed-by: Marco Elver <elver@google.com>

+Cc Andrew (get_maintainers.pl doesn't add Andrew automatically for
KASAN sources in lib/)

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ%40mail.gmail.=
com.
