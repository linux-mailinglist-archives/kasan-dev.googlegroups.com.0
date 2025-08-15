Return-Path: <kasan-dev+bncBDHIHTVCYMHBBA677TCAMGQEWSKC6VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id ACE1CB2803C
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 15:00:53 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-55cee7a6320sf310578e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 06:00:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755262853; cv=pass;
        d=google.com; s=arc-20240605;
        b=j+gF8hkW7P0Hq/jSpVjFymSzqkqmrxJoaX8x0ahj5HRwXji/2HVjICN+1yXHus5Rc0
         uv21TzS9S1uIrEK87w/LzCU4qTB2lXtTW3mfUpZb4QhWXL2h2+JqNsw0qwRMlJtx8fgS
         ESV7vfOaMwSKPWu/jHAMf8TRVv343q32rO7qU/kaMvd+3MmsPYamCOfBkF5rvqy80eBf
         BNxpSYo+UbKNNOYZD+mt6TYBe0C1ab6QshZRBgGIaXL4m7/iCXfo+1RpoByOI+vm1AuP
         4tL19To4yIO8WdBRren7NeO9vzo04f9RAhooqvY1ummriGW+D9kEVLxAvKC7zNRXQhQj
         J5mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4/2f5+ihXRSDx4uaGovAPg0DgLG8p8JRkKP1M23Qqw4=;
        fh=9xvq+erj9rO572m9e5J5j86+zMUapxQW5k9RGC4cJWU=;
        b=VoBpUqEeoqopu2zgg/4eeudaaSYhMK+Snvg12UXviaeaOXNXtt0WolxCVZMRGvCUqo
         aHcpMi61HMvHdn6qusLSjh0oGc4Dqw45lJF7LH8KcfTw/87jRjTIeXM6bR30YsGNaJXa
         yxrWaCf8RgbUVlK7HsSreK5cueljnFtuUqVtMY/naPrG3dIqyO/aZ14dwu8fTa2djJEs
         Iwchl7wybm57DpOI1XsW/SsW6sPIIfLF6qGSODdfz722LGbjbTdD2Ou/Oww0STVMB3og
         Hpd1CcNW5sqfi3LdjdXVtux804p4dhvU4B2mo6EhEUefMaMys0Y6Yb9gbZF0pKTFJRbU
         nplg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b=N63z9Epf;
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755262853; x=1755867653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4/2f5+ihXRSDx4uaGovAPg0DgLG8p8JRkKP1M23Qqw4=;
        b=Lo9epVzjP4qFNBe01LnRzXOvRTOrPEsGpPEx66i/fccHGMue/LUnN4HDjPrYfK5V35
         DHaTG4PhwZ57T3JLjl98ZOUwEUKOEn7YEuG6OCGBHpI5NPdrnOrGAu7Xu1AVIje3r7Ye
         cr+Yd9iUudoBoGhaAWHQyWDcSwgvlBll6roA+bLYm0j5HEcp/HPeYjRPNaUHDoluma05
         aqzbiLzlgkCk3w+vKPO1X5dWDWMp5T85Hw5ZgoC7ht1aPIxmFX2DjlaIRflrGtJvzaRP
         ofxKypEZk9lzlX3XrAl74Vj5sGiq+a0z5QbMSGJOjjSVteLl2STj/2tuxk6725UX5L5F
         UamQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755262853; x=1755867653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4/2f5+ihXRSDx4uaGovAPg0DgLG8p8JRkKP1M23Qqw4=;
        b=dSNGTEXA4c9jYkyNWmP/tKNlByX9UjKhbGxJ60P6Wufn+YPhtI5SO8yimJtqDlN0Di
         rRGm/860g5jlmVNGebiR1lGixmFK1PfgRBDTVcBVknty9YbtccRP/aV+ydIp/gUJnaql
         NxbmwBjkzLyuZjnrzUPDcMZ3ew/dhMe8wh49U4RRLT9DA55aWD+qPamPhjuNx0SvlJ82
         ASx/oyyf29h7mY8lVIxLgL+d1xkqrjn9lseMVc87W3CjyFV+e7QDZc+BBpv/TYNxvP3J
         maD5DBP5Ut+MbydYAflceFl1RSg3aPELMfXPn/0lqv8GXJc8EspnsgDOlRDDhUOmknhz
         n9OA==
X-Forwarded-Encrypted: i=2; AJvYcCUZB334z+oSbT39OKfDrfytAczffblRJnmkItwvjSTKP9XSjsalWu/HYzIeKxwXIZTD7xfOkg==@lfdr.de
X-Gm-Message-State: AOJu0YxB7jngAKYoyakWU5ThfFnm/HeLLb66o9EqnOKap/xMG0IRnWPN
	DFwBV5aTcwDrB50qy8bIhDyFifFqA0V+g8JK3VXhumypdH2nSYHMjOfG
X-Google-Smtp-Source: AGHT+IFZfWGDVMLQQlDmtOpgs3u54xo7/l9Gx4hGG3xOdTX/lAia+f11u3PmxxRQoHIrnaLzL56k9g==
X-Received: by 2002:a05:6512:4016:b0:55b:910e:dc10 with SMTP id 2adb3069b0e04-55ceeb19b15mr574723e87.36.1755262852472;
        Fri, 15 Aug 2025 06:00:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfa5DK59/X+CHuWAqfja793M54UZYC51kmrtoe0f7G10w==
Received: by 2002:ac2:4646:0:b0:553:67a9:4aa1 with SMTP id 2adb3069b0e04-55ce4b25e22ls601939e87.1.-pod-prod-09-eu;
 Fri, 15 Aug 2025 06:00:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWA4oah59adpalBm2wElvl/96Qq0+TdGboJaWFtqLAnhC2RiM6lVpn3KRfsk6TjgP/Ti8ZSBAoC5tk=@googlegroups.com
X-Received: by 2002:a05:6512:b98:b0:55b:5b33:bc09 with SMTP id 2adb3069b0e04-55ceeb199a3mr599675e87.28.1755262849485;
        Fri, 15 Aug 2025 06:00:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755262849; cv=none;
        d=google.com; s=arc-20240605;
        b=d+GGY/Z5zqrGkSyp+9OkQFSwywBRjS7QSD3c2sUDfof8dV1bv46Wyp/MNqdZ7IRSg5
         +Y2LQ9FPdgX23fHKgP9TjolBz4GHl/9JBzbQuVS84FYTDCT3mX2JffEbqQ4OwHFrFJ6c
         SK9ujWMwJPbc6C5ZnJY3WColhUrKyVWHRKcwhwXFaWoObqNn04ehXlxrSBPi2CMlcLYc
         1KENeZZhP+Ao/lAt2lBYBqH4GoJsoGy7t4cHsE5vj612OYLtHOMTpEiAcaFUgYuhOmGm
         +ZmrlHlEJCj0gUp0xSjdUfQGX4eXG8ztfyakLJD3m+csHYCbJ3KOSWpvWsi9IT3R2kGi
         8ysQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=M5aKJ6EuhxrNInhVNv1lAb8m/GnY8B+pF9rLGMgta08=;
        fh=xS/LgawY0qwKMWIUdMG/vN+XRTsQ2ZYkOuJtlcL5Rp4=;
        b=baEGX4zJI8ywpM7Wn9Edg5CvK6uW3bP1W+MZtCnTN3R38EEpMN8BsiRc0NvYRSrEYa
         +uw4+0qPZ+bVmxZwcz0FWkZwUSscPrrQy9E0QmpxFN4vuZWahJ4Nk9khwbGs278kNree
         AvDfFcxybv8aVhbLNRGVy25D/r59QjTvh1GGukXIXs23n9vxDSifurYLld5Q7gfHcXr0
         MRGXGiFHiM1MrNr/Cj0rsZ8sybTILX7BulGpo6W+0w4p4NhoiRo6TR/pfVfNXVY9D+Pk
         jgEuU1QFD559HAInfHS8qxCZtMy17311urHn1HoxWq0GCXCZVGgy2fFUIs7nxKHt6tgO
         6Ztg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b=N63z9Epf;
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55cef3bb57fsi28149e87.7.2025.08.15.06.00.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 06:00:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-55ce52ab898so2264328e87.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 06:00:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5ZShypIC3xtZddpno9BSqtfPnsM8GtLHbHt2mWSqi408/AWJ/7SSNT4WicThY8zgMTQV3v+yMJ8w=@googlegroups.com
X-Gm-Gg: ASbGnctJGKnCQd6K/Rly9cwzvL/s97wbwxP8KgtCScv/oBsfMp35HU9OUmUvKuWO+HU
	Me0OttsovFKmjDbiOOY8LkviVPhMSOxXXjTFovZ3aPtYn1KA18nhJjwp8ToCjxfCXzvhpvjlR+Y
	yOtj5KM0EGHvmyKakGnREtx9BGf+2lsfwlDsOu1BRFW9Gl7Lebd1G7Pi6kL1400tyKRYD/IbGEh
	z3stoINEYuaFflLP/7y0LZPjg==
X-Received: by 2002:a05:6512:3c81:b0:55b:8e2e:8cc9 with SMTP id
 2adb3069b0e04-55ceeb2d2c4mr585014e87.33.1755262848871; Fri, 15 Aug 2025
 06:00:48 -0700 (PDT)
MIME-Version: 1.0
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
 <20250813133812.926145-7-ethan.w.s.graham@gmail.com> <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
 <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com> <20250815011744.GB1302@sol>
In-Reply-To: <20250815011744.GB1302@sol>
From: "'Ignat Korchagin' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Aug 2025 14:00:37 +0100
X-Gm-Features: Ac12FXxJSZN0OfDcjS8s6OFmiOlXF2SG0blAOcgASCk44-lWBGEmHN2xDuaUJKY
Message-ID: <CALrw=nHcpDNwOV6ROGsXq8TtaPNGC4kGf_5YDTfVs2U1+wjRhg@mail.gmail.com>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Eric Biggers <ebiggers@kernel.org>
Cc: Marco Elver <elver@google.com>, Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	glider@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ignat@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google09082023 header.b=N63z9Epf;
       spf=pass (google.com: domain of ignat@cloudflare.com designates
 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Ignat Korchagin <ignat@cloudflare.com>
Reply-To: Ignat Korchagin <ignat@cloudflare.com>
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

On Fri, Aug 15, 2025 at 2:18=E2=80=AFAM Eric Biggers <ebiggers@kernel.org> =
wrote:
>
> On Thu, Aug 14, 2025 at 04:28:13PM +0100, Ignat Korchagin wrote:
> > Not sure if it has been mentioned elsewhere, but one thing I already
> > don't like about it is that these definitions "pollute" the actual
> > source files. Might not be such a big deal here, but kernel source
> > files for core subsystems tend to become quite large and complex
> > already, so not a great idea to make them even larger and harder to
> > follow with fuzz definitions.
> >
> > As far as I'm aware, for the same reason KUnit [1] is not that popular
> > (or at least less popular than other approaches, like selftests [2]).
> > Is it possible to make it that these definitions live in separate
> > files or even closer to selftests?
>
> That's not the impression I get.  KUnit suites are normally defined in
> separate files, and KUnit seems to be increasing in popularity.

Great! Either I was wrong from the start or it changed and I haven't
looked there recently.

> KFuzzTest can use separate files too, it looks like?
>
> Would it make any sense for fuzz tests to be a special type of KUnit
> test, instead of a separate framework?

I think so, if possible. There is always some hurdles adopting new
framework, but if it would be a new feature of an existing one (either
KUnit or selftests - whatever fits better semantically), the existing
users of that framework are more likely to pick it up.

> - Eric

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALrw%3DnHcpDNwOV6ROGsXq8TtaPNGC4kGf_5YDTfVs2U1%2BwjRhg%40mail.gmail.com.
