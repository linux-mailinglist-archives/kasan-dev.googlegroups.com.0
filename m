Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBQ6DX7BQMGQEBS6FM2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B5062B007A5
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 17:52:37 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-32b78b5a8fcsf7149081fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 08:52:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752162757; cv=pass;
        d=google.com; s=arc-20240605;
        b=G+u9wg5ecD+9EOKzBaIEqUJzEPnmkpUsd4cpXkeowTiTJOiADPzYRJ6Glex3GlXx2R
         LvsVKizd8PBATBNe1VVU5vbln227gPtgmvR/f/2fZ0fksypdK5oeSzet/yV1MIlUgakd
         cKJBwAUr3b35sGWHX3D1e9RgOo3E7jrgCairoV5bl6BOd2SEjs0ebh6jgdgxaCzUuf9k
         W42BUm6g+ZBys1km0z8xbb59MFnE/Jd+imeE1tp6UHIQdSU4ddccwWPREORhR4Ms55/T
         wla6UWU0kUOAHPO6sFWYlhD/jiVgcsZVURIqYuxzufYGcmlsQetWIpKC9jjihVgVae3Z
         cVqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=M/gSjbb/26JQMYwPg89DbFZOhFyQhHw+A2N5+t0t/84=;
        fh=YtBl19jTjd79O5ULxeFQC4KWU0kmMSfrpT0PlSmDxjU=;
        b=kGqJKZKr0+EVRy3UaAkXK7bQC8Ub0E5XhPv2XjEkx6786TEnp7rotHq5bvApFQboM5
         kdqfauVt1uD2A/WXqHLvG5BLcPZ55dg1SYf2dDqAFSPKdSU3AlWJLe+A4SnPTAKEYV5o
         UfEKijHu00kdHQR1E4wPO7fl8b2xEn7zsu1OI1iSdT/3GFLT8AyI9HGAw/e3V83mfskh
         LgZGUTQ4gbRRCj1zv/ckoM1UBLEkhktR8b9LuKsliSd14Jr+0bOpzOQKT80ymTduR934
         NO8ydOhMSnHQsdF67Kzqx51DsYVB5cXAKNYr/1Nl1PZua33KflqX3zAR+KJf6U530/4p
         h9Ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=IrfeoosP;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752162757; x=1752767557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M/gSjbb/26JQMYwPg89DbFZOhFyQhHw+A2N5+t0t/84=;
        b=lTa7il3Gvy6MQ5aT7uqSR0T2DTfRzmpTToVUbjnxcBXD/cvF2g8PvgbJTjYjJWAHHD
         KjpM2RCdGl2dqEZcxO+09bqiCo8Pzls2y/e+PUKa0xH0DeoLXzRUt/wsBj/v8xObUn3P
         /M0TO+MaBCZsYALMvOe3D8bq21rnDBjFS8EqJfK7F68M4gs/NI++pxky+lzvnPnee40c
         m9fiJsbLEEReAAALXulzQfXvbCPWBpKGcxMx5TGP9x+CoNMgYVHzIhVu40zYgQrL+314
         zIeparufWz23ATKUMXJnSVbtnXSX+sXjO7uzhPyj00Sy8iCM8d7qA7eujQZ+6I7B95St
         UrjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752162757; x=1752767557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M/gSjbb/26JQMYwPg89DbFZOhFyQhHw+A2N5+t0t/84=;
        b=ZLpNvhHNJ7Y9iZ+nU1JJmw2EjL3xxNSJqxbdkTmR8eu2Qo8JmnBIu93OpP3w7k06TS
         nn2I4kwFGvrzxImVkO6DRA2B9SgISvxq0ItDeiZQ3qr5yRCMaOk0+btqKpKKOaWd9/LI
         lZM4arnKC8jhaCdL6PVKqjlL4wJPaFnr8bvTmLh1cDvpqVCBp/ytZeG/ht6tTlkiDzm3
         ed81QIrx2zQ7RvITdixR0cFlO43L0aaa+dXJQq6G4fp+SdMATXaxH3gkpEPYR2UBYgtO
         wsXFR25oVdn43fCW1Tjs3uPMCAk0p771BgLs8W9pUly/U9CO8p+GkKVJwk9323tpxTvS
         wd/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNt8/DUtoSyqaICGEv01aMyamkl3V4ENa59aeTbnwijFDQ+kUYKoftppJ1uAEE9uOY5+Vv1Q==@lfdr.de
X-Gm-Message-State: AOJu0YxxjrOD1BWwjcpYCuCcPtfArdD2PlhQl+WNQFG+S4VhLIWF8uMX
	Rj4FVro6xZ/6PKMyu5IBs/w9Cb206NckhMTqEzfrHw5gtzIX6pUNsWMJ
X-Google-Smtp-Source: AGHT+IGWm1nvZyrDiW3pMzKX5wsoMk66XC8R3+m+gXlsIktnlVT2oi3VZ88FVA/6y3ppy23WNFzz1g==
X-Received: by 2002:a05:651c:32c:b0:32a:778d:be86 with SMTP id 38308e7fff4ca-32fb2ebc1f7mr7568951fa.31.1752162756486;
        Thu, 10 Jul 2025 08:52:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuqxN+8GPovDplwcccyLg0audlGLcDJlYeVwyJdXMOUQ==
Received: by 2002:a2e:b90a:0:b0:32a:70e1:1d4e with SMTP id 38308e7fff4ca-32f5006024els4021161fa.2.-pod-prod-08-eu;
 Thu, 10 Jul 2025 08:52:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUL7R6iOXIZ/t0S9srgjKNBF6hEFHQb3RL6PalJAQxWmSFnS4UGi5/GmpkWf5oB5UGOG5WA2wRCNkI=@googlegroups.com
X-Received: by 2002:a2e:a984:0:b0:32b:7ddd:278b with SMTP id 38308e7fff4ca-3304d90b275mr7409321fa.40.1752162752398;
        Thu, 10 Jul 2025 08:52:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752162752; cv=none;
        d=google.com; s=arc-20240605;
        b=fX1LfLKcPSBcv7JBp7N5Zn9VzgacCVarUxNt1yzZ05qNreN9wCvOdy/j7pJuoHxGgX
         Q8KOuPfQDpQyK5LbHwRGN+ZNZbg6h0WQ+bz0nL2PEollUNZV4FIhQr0NnxiQnP73C9sV
         uh8/RgEaTZ6XllJpj+ImWiefpNNfV5VMEmDitAPjAzKrNRk7zraqGiN3ZlHmZknYFxY0
         gvbPkpAt6nHtFwMx1Lm/qfoRxUOZ9JKQpFJYhO50ZPgPz0PurW/OKFyTjWlPZ7nVn+uQ
         RSKCeZFUpyx4QjOthgfqKDr2M82Um5w6sFKIDjgCuCk9I45AttSdkcTQUBjDkqjpoEPv
         yLQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DCLKwFa0neCTBla2iQUvszaIW/YcUeww7BNmMA0A/10=;
        fh=W2bBF6uI4pfCtebrsSoRYT9KKNxs0N9wQfKXg3BNGUc=;
        b=EWUNzpSCpCAPjQPxrCFavvIBzldP0wgfzEfrwC2LIFc9/Yl9DdMFKqdYtQNpsFwgIu
         MIuIofryRngj8Cptsm6NYTEDdbfstDIy/MGxZzEKzwFIH5PI/p3AEHZCVogjmjQJiClO
         0iE+yFgRYSdhRuXefych8Y6Q8TeQRQ09bJaOR+tkX2B67u08MNu0ZtVNQFZz0scUiHCH
         4orVP3StYR3EmTvZ/8grvxPtNvrNXAsPWhxRjSafL4e2aGdGoIDITAbZBfDQYggSRgiX
         AeVa8bqRj6wK44op3HDRtTZETqq8FJFkiKfXxVBXZzb+liTxliRO9+MCg2AKHfPXVaWV
         RKCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=IrfeoosP;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa29f22e5si490691fa.3.2025.07.10.08.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 08:52:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id a640c23a62f3a-ae3cd8fdd77so229729166b.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 08:52:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWW/disQdYz6oSbeCovM5w2+6fFMk5XzWwkWgGm9rKpExPmtLYwsvkxyK+xhT6B+O5B6mJ+Al4lzcI=@googlegroups.com
X-Gm-Gg: ASbGncuwgAJJ6t4Ren6foX2YFXKHpcD+C0bCSGSqEtmFaK4nbCconOy2mRZvrssE9Xo
	4cwCSATwLs2ijq/JZ2Fsq/gPLfHgkLiNPjJ7DbT+SkfR7jfZxDBmF07wrrJBcfvWuHQUl8d1Hzf
	Q2YnLGQo4N9p02YO4wv2dQ45vIDlXMwZL8H4x9LxWbqkaI9R361fd9u9oXg2MrK3t4ad6Y9zeur
	EGfJSMvyx3nltixJz45GQyaGPWOsOxzBK0c6KV/OF0hMdu38RRwlRlUi6bR0UkZAlvGOxKpkcfa
	KiUut64f7oWw+j9hXiY/uYPxODPJLevOB6U2f4BLaNE8f2/FAb8tcy59bGRFml21fR4psuX6xUh
	r3lhyVPVa8UvuphA4aZoFt2yFflfXaiYerQRh
X-Received: by 2002:a17:907:60d1:b0:ae1:f1e0:8730 with SMTP id a640c23a62f3a-ae6e70ef2ecmr391355466b.57.1752162751550;
        Thu, 10 Jul 2025 08:52:31 -0700 (PDT)
Received: from mail-ed1-f41.google.com (mail-ed1-f41.google.com. [209.85.208.41])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae6e7e949f2sm154006366b.34.2025.07.10.08.52.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 08:52:31 -0700 (PDT)
Received: by mail-ed1-f41.google.com with SMTP id 4fb4d7f45d1cf-60700a745e5so2180044a12.3
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 08:52:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV/gF6NN33Znw3hfiwCzSYqV+WtLDZ6I65eQpWksx7C/pS1fXC+ooQ06/CVCf/cCpkVtqf69JW+2Ik=@googlegroups.com
X-Received: by 2002:a50:9e0a:0:b0:605:878:3553 with SMTP id
 4fb4d7f45d1cf-611c8507641mr2264146a12.16.1752162750681; Thu, 10 Jul 2025
 08:52:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751823326.git.alx@kernel.org> <cover.1752113247.git.alx@kernel.org>
 <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
In-Reply-To: <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 10 Jul 2025 08:52:13 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
X-Gm-Features: Ac12FXyZN9kxQm0HXniuJ3TdAUc1hQKzCbrnbibn7oPEnjnUTOgpa2jjfvxQ0Ho
Message-ID: <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
Subject: Re: [RFC v4 6/7] sprintf: Add [V]SPRINTF_END()
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=IrfeoosP;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Wed, 9 Jul 2025 at 19:49, Alejandro Colomar <alx@kernel.org> wrote:
>
> +#define SPRINTF_END(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
> +#define VSPRINTF_END(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)

So I like vsprintf_end() more as a name ("like more" not being "I love
it", but at least it makes me think it's a bit more self-explanatory).

But I don't love screaming macros. They historically scream because
they are unsafe, but they shouldn't be unsafe in the first place.

And I don't think those [V]SPRINTF_END() and ENDOF() macros are unsafe
- they use our ARRAY_SIZE() macro which does not evaluate the
argument, only the type, and is safe to use.

So honestly, this interface looks easy to use, but the screaming must stop.

And none of this has *anything* to do with "end" in this form anyway.

IOW, why isn't this just

  #define sprintf_array(a,...) snprintf(a, ARRAY_SIZE(a), __VA_ARGS__)

which is simpler and more direct, doesn't use the "end" version that
is pointless (it's _literally_ about the size of the array, so
'snprintf' is the right thing to use), doesn't scream, and has a
rather self-explanatory name.

Naming matters.

                Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiYistgF%2BBBeHY_Q58-7-MZLHsvtKybrwtiF97w%2BaU-UQ%40mail.gmail.com.
