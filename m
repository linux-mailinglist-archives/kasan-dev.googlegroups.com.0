Return-Path: <kasan-dev+bncBDW2JDUY5AORBFEV53DQMGQECZFVJ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A9DB0C06AAC
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 16:17:59 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-47105bfcf15sf13540085e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 07:17:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761315477; cv=pass;
        d=google.com; s=arc-20240605;
        b=byWIiTw5jzwVuj4DQIErPjvWynQxrUgNLdwJwB8cz2apTKhEHOqydzTD0VYYtmcFKo
         eJmQuCPA10E3iFQQK2KSZV0EzLXuJvIQIFgHGc8LmcbEqpxEZuZbvaGqztWqKwm/fI/4
         11bX0SWoZZVSxbH3aReYm29C/xG+6CkEvgrYSAF+FItXZrjw85MSVOEmr8iki596KvpH
         RBt3jBhXRc/RZJPa6Zq7huhbo64HsyF6pAQXOS57szftBd7NBvzXK8fWe7VNOx0Y4Bvy
         kccjKOdorxg7UM0HfNaNV5OHcB0rRk6XtIhybQ9qnyO5UMLe9Ihg+v0uSfNMNt5B6loF
         9L+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7Xhw7Zw6qkM8VaajUKmtFOCD/gOiawuq7w+f/IxWk+c=;
        fh=LAUXbQp603GoIPFqthQLSPbsouZBvKmKatcSPtt/bqk=;
        b=WO53j76fYtGAmyhf0C845KZmpPoHhShQChFKiGe22Qx2vsxXc2LY8N2lMTpwbEjaen
         FfQRqpznFx0TRKcDZrpkHa1RLDRy7jEOP67jTsMn9k0L6iYrnzL4M8mGbPbl8Nu4b9NB
         yImAR1pfD9USt3HDoSFU1n7ayTmjbWw1R12IlntRjHq/Xjuv3NZhDwXiH74WJGMi2xa/
         lwelqmJ7K3KvZzIX4/TGej21bwZKdg0xFAfN+DYEZr+Mz1YNIkcu0TT4FGkRvYLvVgsc
         v8k4wiQVPA94oHwd6/NsshaSgGpbptniTY4CCBzfaQ9DjycIGBWHPR/LRvN3ctwQqz9N
         miTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=k4WO6oDi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761315477; x=1761920277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7Xhw7Zw6qkM8VaajUKmtFOCD/gOiawuq7w+f/IxWk+c=;
        b=STeGfoSphAjf5drrNTQ1zndcMCUcXpYa9ekbqQZXCLdMV/HSbVy7C3eMxBjfQF8Rtn
         AtXLFz5iyy659FOI7L3TFKjjWcyz+McoTGSAtquGNFuKzaIkxs2uhC/L+eB2oFOUvJpF
         /hZP7aoXJL0Abp39GyFraNZ7IaI57xuF3nHCPhGFo76aUDiWMn5W9Tec8ryEEFS1vmPN
         8Yf2wF3r/DMFiX08cZSfbfPpagN+Fq5/wjnMA20GIrTRj/pulnApZBvF7pbQmSI7UBBt
         u+CIvhejaTdLtmpkQU7GN3n+kOaqbrJ/VJ1DWRhSVSV5H4HDDGjrvWX6wuB041+iiAz0
         42wA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761315477; x=1761920277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7Xhw7Zw6qkM8VaajUKmtFOCD/gOiawuq7w+f/IxWk+c=;
        b=Am5gxJCnSWAParongOMdAe9p5vb4agzz+j/QB4CuHIbwRLAj0XuEqHI0dV4scXFxoh
         OKTjb/12TWSXkt4MX2Usq7/XQxXMogHt9BMWaf4XAvKaAkopwKxJUDHW3kmBzv8GPbQf
         ULtiyCFCMCExt56iQyLDCm7eT1bAajjOitNDDSMT8nbabB+kZ9/r5OD+OyWOhYEsJo3W
         pVMgD6cModu9v7NjcNlVHcEWJmeijPgyfp1hIYguDqygheFi3jRj9mPyA63F/rhF1W7m
         5udMCdPsp368fjcv+W5/7ljxT7mHJkDGeSsFZ4zrZh2yqeK+AiJ7mfa2MiVDaLpYatvo
         s0HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761315477; x=1761920277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7Xhw7Zw6qkM8VaajUKmtFOCD/gOiawuq7w+f/IxWk+c=;
        b=NxO9yqbcV+/cOQqzbXrSvGjvEQm77lN40a0PeUVedQ0xpc3+wuC5CXk7Eq0g+dG/C5
         c5m1sJC4kFEYtQeF8SWK9kajdcgzc4sTanw47y12jxOIemyoCbqhqb8bEMOb5lhRRI3e
         gPX4HR7ndNC0t0xSZ8WOaj2haVF02SV7YTr5RIYTLzETKUbq4rclykbQ7DoPzJ3NBFEG
         PM+iHhl/ktQw7rlxsLRT94oY+pO/w+SHSVsF4XXlkX/GOTkyUxDmFYUhUzgACgZ/e7e1
         GMY6t48FCdS9s69BsgYKfXOR4vBbmjNQm0jj7+dwA3xgMEV6Fqpz/SOzymNmLPr7MLsT
         258g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVa8A1K3z2Dw8C71SvIuoMU1TjDyZ1/Sm1Uxbb1Dc5zapM4wZjjNiODEz+uC0hu01dsE4f3eA==@lfdr.de
X-Gm-Message-State: AOJu0YwBvWtzJAAGywi8+FgyeXkFR89HDLioZdWYToncxsPZfxKUjSls
	Lvuc0csvDVrd/IT7rp7OTMe77kbUksjtMWPnbbk/3gWNkvPURFUIge8E
X-Google-Smtp-Source: AGHT+IHhJVkygTdjuAAhFnw3gJvoU3BVuoQ2SPpyxKZjRUsuNC1Ur86uZOr1iv6gsDseAVNls0gDxg==
X-Received: by 2002:a05:600c:34d0:b0:471:1717:409 with SMTP id 5b1f17b1804b1-471179071b4mr189304495e9.23.1761315476673;
        Fri, 24 Oct 2025 07:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6ctam9SHuG6gVTtCTp5DO9w6rx4HcMDnTFX8wKhfN4oA=="
Received: by 2002:a05:600c:6d46:b0:471:e4b:ff10 with SMTP id
 5b1f17b1804b1-475caa8f9e0ls10164165e9.2.-pod-prod-06-eu; Fri, 24 Oct 2025
 07:17:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWiz3UeJdjub+E7Rq4ou2fAuRZwAulxaG9wNpElsBseTXZdknVyOw/NxEG2/bZvFhjdjuavGHWtiOM=@googlegroups.com
X-Received: by 2002:a05:600c:1d9b:b0:46f:b32e:528f with SMTP id 5b1f17b1804b1-4711787639amr207048715e9.5.1761315473882;
        Fri, 24 Oct 2025 07:17:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761315473; cv=none;
        d=google.com; s=arc-20240605;
        b=S880Fnc1CKnEYRO68QAAzE/gD8kektkSvsaStHKUVvIShZSvKDy/fXSa9wyRm0KN71
         YLyjtXlpTNioDVGfblNanxVUkRHiHzmQQE/ojxK9ehR3616fywLiGb68ojOp6Fg6sykp
         5wSXAgPWn4cuuYiRRTq6Mge8oGbKeHd/Vff8bq3BLPMyfOy8L/rp9voM1PQDjpt0Jgfq
         qiKMI7EhQlu3ldaHSWoDwMpBqKnzyRHu19ZU1y3dRl32pX1iRdmhlXbg1O6KM8ArytYJ
         46mboi4P8fCu3PhFE4lEF+bbjkQPivQC+MgQKUZagrGz1w8b9VWlHHwHLE74gCKNMCb8
         IFxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SNTn99TnA1JaXfaY3Rpqv497vvNlynqkAU5Ssl8CUuk=;
        fh=l0bKO7Mb+P8c6oMBwrPYBK7O6v+XH086v3ELfu0T6tE=;
        b=SMWKZ1AB4dF4CgsAKvzf9yjqyBnVG4Uwv79HK5o09jczRdvYLisQ8XaTtaF1vS5uF7
         gdSqqQKdZFjhkyHtxq6lbdJI+7lt6gZSIoe3i67VDhUO3zVy5H9rlXOKzlyVesbYFPxb
         HCP2Sj7rEJr45dSez/JTGLoGheZnCc2DpNxt3vOYkR0drZZoKr1ePtdCyDW5JuPrIpum
         xQ3vADp3LxJY6c1z6daCWtL+/rEOJJYwRihaQemGI7sxPLraBBV1VrA5eEDacCmVvc9x
         SdEwgrtRfUKUiJt4DNDdIuQWk8eI/QA7bCIS4VRQfskZxAMG3hARNUTLBYeYZC0Ij5yt
         +QbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=k4WO6oDi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-475d91c9466si98075e9.0.2025.10.24.07.17.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Oct 2025 07:17:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-47109187c32so10703575e9.2
        for <kasan-dev@googlegroups.com>; Fri, 24 Oct 2025 07:17:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGhIC2M3y7NlMCuzuItoXiRXlNaAhLQSNfqkoRAyvBvnB5HgqhHmBeoUeLiixGAHQBamuoLKxYPyw=@googlegroups.com
X-Gm-Gg: ASbGncviOAhRE2v/e9NepyCebXDkfGmcw9+5lDLeuhTYqf2SDeYuHVF146DWzHllHxP
	L/Eqvv2FqcqG7P+WsFsSFb92iA6xguOmQIKv1g3NGBmT8dM5mC0vePqldR50s/GkLgl0XRe+xZ1
	lfXjJraIvQHGHm+/16B+WuHoQl7PDUl7g24JDbnW6s16qadBrf2Y0r6CKIyMKWJgtBkI7St+PlI
	LmvQufB9/+AP1HY0/uK/fjhNV/JY0rOW3Dq/D+UShH9j56Ije7fsSPwFzuteg7jOZoMSev50WVa
	3z1C7xcKgkTJMg5EhdMTQXVxEPenbypjfs+intOU
X-Received: by 2002:a05:600c:34d5:b0:46f:b42e:e394 with SMTP id
 5b1f17b1804b1-4711793473fmr217356125e9.41.1761315473041; Fri, 24 Oct 2025
 07:17:53 -0700 (PDT)
MIME-Version: 1.0
References: <20251023131600.1103431-1-harry.yoo@oracle.com>
 <aPrLF0OUK651M4dk@hyeyoo> <CA+fCnZezoWn40BaS3cgmCeLwjT+5AndzcQLc=wH3BjMCu6_YCw@mail.gmail.com>
 <aPs6Na_GUhRzPW7v@hyeyoo>
In-Reply-To: <aPs6Na_GUhRzPW7v@hyeyoo>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 24 Oct 2025 16:17:41 +0200
X-Gm-Features: AWmQ_bka8VrwR-Z0b8RrCs_zbS1hTWfVkUFTv-W6umfuWyIbEP-ZV0vS8gZH8jE
Message-ID: <CA+fCnZeMwOE1EwuP-3Xrs2e0qp_A5eo2aiXB_q243GiLFZV-=Q@mail.gmail.com>
Subject: Re: [PATCH] mm/slab: ensure all metadata in slab object are word-aligned
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>, 
	Alexander Potapenko <glider@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Feng Tang <feng.79.tang@gmail.com>, 
	Christoph Lameter <cl@gentwo.org>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=k4WO6oDi;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Oct 24, 2025 at 10:35=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> w=
rote:
>
> > An alternative to unpoisoning or disabling KASAN could be to add
> > helper functions annotated with __no_sanitize_address that do the
> > required accesses. And make them inlined when KASAN is disabled to
> > avoid the performance hit.
>
> This sounds reasonable, let me try this instead of unpoisoning
> metadata. Thanks.

But note that you still need kasan_reset_tag() for HW_TAGS KASAN: this
mode is not based on compiler instrumentation and thus
__no_sanitize_address has no effect on it.

(There's been some discussion on making __no_sanitize_address work for
HW_TAGS: https://bugzilla.kernel.org/show_bug.cgi?id=3D212513#c2, but
this was never attempted.)

> > On a side note, you might also need to check whether SW_TAGS KASAN and
> > KMSAN would be unhappy with your changes:
> >
> > - When we do kasan_disable_current() or metadata_access_enable(), we
> > also do kasan_reset_tag();
> > - In metadata_access_enable(), we disable KMSAN as well.
>
> Thanks for pointing this out!
>
> Just to clarify, by calling kasan_reset_tag() we clear tag from the addre=
ss
> so that SW or HW tag based KASAN won't report access violation? (because
> there is no valid tag in the address?)

Yeah, kind of: kasan_reset_tag() sets the pointer tag (the top byte)
to 0xFF. With SW_TAGS KASAN, the compiler knows not to embed validity
checks for accesses through pointers with 0xFF in the top byte. With
HW_TAGS KASAN, the CPU is instructed to behave the same.

(This is slightly different than kasan_disable_current(): with
kasan_reset_tag(), validity checks do not happen at all. With
kasan_disable_current(), the checks happen but the bug reports are
ignored.)

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeMwOE1EwuP-3Xrs2e0qp_A5eo2aiXB_q243GiLFZV-%3DQ%40mail.gmail.com.
