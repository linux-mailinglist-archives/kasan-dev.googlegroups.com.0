Return-Path: <kasan-dev+bncBDIPVEX3QUMRBO5GX64AMGQESN5IKNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 950849A0D4A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 16:52:45 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-7ea750b5e87sf2529711a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 07:52:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729090364; cv=pass;
        d=google.com; s=arc-20240605;
        b=bbOPeiZ02ZljOjVEhezD8ugBfBKrnX33hfNouW7/6glWGSJYknCJa8JGdmS5utmlPm
         IKfu0c7kYBFDPlOYCr5kkFAQ6fmghy0cELBY/irYJw47ju15GIGu6jmPZw0wBzOw4mYS
         d2iWem9vy700wTlbzlwuuTYd526bwlRxO1y5MsqBmbiQ3Q4O2gfnSNlWgBvm9lb2uRXB
         TCGRXoZxjn6pHXpcZaYQVRpy9Tk3G8699FIUl6HN1UcpKBn2T8UJx7oZMIBMGP+5WW+c
         cSU/EzrUshHF7Tg7xoaaF485o/dBuoNSInCrhX9JsJWiWLF0opqHB5pE2ygGI6vQTqSM
         Lj0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-filter:sender:dkim-signature;
        bh=BD5jGmyKoQrMVPrYOGujBN6c2Osa1VaLHRGBESvJ84I=;
        fh=xuToJbNaj9TgD3hsT4KJQGfGBB9P2pFvXIUiwhKZfOk=;
        b=DWD5sjhN+VgQffnoNGHteZh3blX1reT3SGHDfYMb/XbPy3vqSRyy98uq4MEnDF//Aw
         IZXD0onbV6ap2jz8jCl8GuCkdhpp9pOIfn/S3rRVwErOzA2j29a7Kzhqscy6WQ2IV+5H
         WNEU5174zJf/AUD/QH3VXvihNOE+MQoikCyO4Nd+xnahuFIacCAomu9tFrTI8o+I4B5i
         pXEk1JaYl1EwaqzjyAr30EUkaHJT3hj1m5GZNb4LNe9Wh1q32ckno2nKcnw+wZiP5dYO
         Wdv9LrnCxzVrvlbWbsg+FepJ/Ad5aoUrsjVu5LTDB2V9tRqELSpdh5aPndGoZldkpjzK
         v4EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=sG7AtR3h;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729090364; x=1729695164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BD5jGmyKoQrMVPrYOGujBN6c2Osa1VaLHRGBESvJ84I=;
        b=CQObpVsyqtZEwGBbpl//kNTxHUZLlXQaKgyWzySruS0zuZLrVtMfzPRC7bkgjwP6w6
         wG/fqZzwpihOdqEBxBozPXprP3A9qyzazm58lwEW1EdTxlGzwLa9Mr5WO9Hu+m0RoZLi
         BlqKHbDBUHVsMO+BuWZNd3Yp/oD2Wb0lrFiA7mkbp8lauQ5ernv1vKQ4NS0dEzOC0jVW
         txl5qrhwi3n9vH1RwFclJA+N22SLgf9cqZbw4a3Q4uG+CyDInqhKLIpaSvN7qEeK5oOz
         zM4kehYXyyrKWd3MEP15eibCPwbHb1ZMaglQ7BmDUqVXctYJ3z3L4FZI9CQZ9W9NoI68
         +KYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729090364; x=1729695164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BD5jGmyKoQrMVPrYOGujBN6c2Osa1VaLHRGBESvJ84I=;
        b=Yhq5/mVRF6m3QWGpeFcY7vy1Og6VkCEXvc6og9fs0neq6eIlyXq60LiG4iii5LTTFo
         uMWNPNTISWvU8HvR3i9/2MlN4lchzGPLJQ9v+9vf6UsB02+ShJJ4qmzabAb8PWjxoqGf
         6ImVdfw+vYKYM7KaXbCISPcNJ66wPU3VcVXXhrndjfPbKaC9F+QNxN7gyJ4EeYfl1RV3
         OO8l1lUDuEU0uKfQzi7/AiJTzzElZtQZv3ir7ZJY0ehFhDdzA493i7H5FqZyrWJekg8A
         gbsmtw/UQSS2Rgbr9wk2sMQeIsLW3k8bqmOoORdMa9tuYFNi68PzpECefTZFcVJzWatk
         TlLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZfzlDPNsDo+VrtBQJYfgufucutj/jlVucVKQ1K6+djao+1q2et/E4Jbrz8oYyuJDel7EU4w==@lfdr.de
X-Gm-Message-State: AOJu0Yzg0NZQlbUBjMEoM5ZstHrALoWkXu61zJzWzNq1dCLe+NSLG3T0
	+w1mWwObus/0eEN4CxnWUXpgmETEhyf6nlOPMwvEmBGSLacvTRaI
X-Google-Smtp-Source: AGHT+IHPS0MOuWPtCyUYBfI+LeLwUkL1fR/2VL+HZI/1mXefSNNfODNS/1HExQvDhtdxldc/bAirng==
X-Received: by 2002:a05:6a21:39a:b0:1c4:a1f4:3490 with SMTP id adf61e73a8af0-1d8c9699b9emr21833353637.39.1729090364081;
        Wed, 16 Oct 2024 07:52:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d13:b0:71e:5a75:ea2e with SMTP id
 d2e1a72fcca58-71e5a75ecf1ls3436626b3a.2.-pod-prod-04-us; Wed, 16 Oct 2024
 07:52:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmPXGkjlmdPAAzOqVJwdkk0DVYbL6mUhNsFmyU2jQvVNHVbnWGgkeH7MlGH4j8SERHypW0TQTXvcY=@googlegroups.com
X-Received: by 2002:a05:6a21:4610:b0:1d8:abf3:58d3 with SMTP id adf61e73a8af0-1d8c96c4b17mr17704861637.50.1729090362897;
        Wed, 16 Oct 2024 07:52:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729090362; cv=none;
        d=google.com; s=arc-20240605;
        b=AyPcrRK327j/FfeC2MtzdyUsZQib8SLJPZS/bKKtDBAb7q1MbgNr2LzTchVcUV+Xuy
         J8ljnSW88OHsHj4t1bMHCqukMHvc8+PDb/VUN7X/HREioDomsCFq0Bn+TcgAy5UWdUpG
         qEP78T4YP9pEwC6YQNP/8d2YiRehAcBxdUxeZt1BI1A/q1t8u10xR4FewAr4IPX7r5YE
         UQtGSvvY3uI9P0X9TeI/4cm9E1V5Lm1og6Bd8HyKkmb8/tRj5rfK16XwsruOLsvVyWoK
         lH+v9eVvwPXTByoRHsylqv7nJ846SNiAsLkWMMb9pDxyL/Lz6rdaGeOFIrnWtsg4rodm
         BsEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=hrEbj5bpeB01P7bbH3mV9rjR6Y1usox02y6Xk6iwfRA=;
        fh=Bhz5TtLECF0XuqZyxNbyBgsyQ+rTiIv1HZckIFDZ1Tc=;
        b=H0r/YrQzBL9kQdDYqTtpg7ByX1mln5UxuE42xncONcUZJAPOZ7080ol32kYXZFWhPc
         QVq9UIV66imIbNW0CmJ4pa0mrt5ue9aq01zfdOlpT/tcM6R6/0tIHryfnfnM0yUyCeXW
         UW1UaM8+E/qFmJRuZ1hePWeMrBEhAihcIjxm9BUqwwzoy1y2mQ8gM29uLsCUGxyVOBk3
         LYMVr3R5DH2e/12+scqZIzXZguwZwdqX7fD6eCXZ/E5LjQoiiB4NEC8UqXBcYgGKYlAo
         0UlJervnio0k0etoxSSJG9oQVsnGIglnoqUSm8rVrSeHbgLTTQS8iAFBW+eqSUecDG43
         DZwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=sG7AtR3h;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
Received: from ms.lwn.net (ms.lwn.net. [45.79.88.28])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71e7749a6b2si197765b3a.2.2024.10.16.07.52.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 07:52:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) client-ip=45.79.88.28;
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net 1443342C28
Received: from localhost (unknown [IPv6:2601:280:5e00:625::1fe])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id 1443342C28;
	Wed, 16 Oct 2024 14:52:42 +0000 (UTC)
From: Jonathan Corbet <corbet@lwn.net>
To: Dan Carpenter <dan.carpenter@linaro.org>, Marco Elver <elver@google.com>
Cc: Dongliang Mu <mudongliangabcd@gmail.com>, Haoyang Liu
 <tttturtleruss@hust.edu.cn>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] docs/dev-tools: fix a typo
In-Reply-To: <c19c79ea-a535-48da-8f13-ae0ff135bbbe@stanley.mountain>
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
 <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
 <CANpmjNOg=+Y-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ@mail.gmail.com>
 <c19c79ea-a535-48da-8f13-ae0ff135bbbe@stanley.mountain>
Date: Wed, 16 Oct 2024 08:52:41 -0600
Message-ID: <87msj45ccm.fsf@trenco.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=sG7AtR3h;       spf=pass
 (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted
 sender) smtp.mailfrom=corbet@lwn.net;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=lwn.net
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

Dan Carpenter <dan.carpenter@linaro.org> writes:

> On Tue, Oct 15, 2024 at 04:32:27PM +0200, 'Marco Elver' via HUST OS Kerne=
l Contribution wrote:
>> On Tue, 15 Oct 2024 at 16:11, Dongliang Mu <mudongliangabcd@gmail.com> w=
rote:
>> >
>> > On Tue, Oct 15, 2024 at 10:09=E2=80=AFPM Haoyang Liu <tttturtleruss@hu=
st.edu.cn> wrote:
>> > >
>> > > fix a typo in dev-tools/kmsan.rst
>> > >
>> > > Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
>> > > ---
>> > >  Documentation/dev-tools/kmsan.rst | 2 +-
>> > >  1 file changed, 1 insertion(+), 1 deletion(-)
>> > >
>> > > diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-t=
ools/kmsan.rst
>> > > index 6a48d96c5c85..0dc668b183f6 100644
>> > > --- a/Documentation/dev-tools/kmsan.rst
>> > > +++ b/Documentation/dev-tools/kmsan.rst
>> > > @@ -133,7 +133,7 @@ KMSAN shadow memory
>> > >  -------------------
>> > >
>> > >  KMSAN associates a metadata byte (also called shadow byte) with eve=
ry byte of
>> > > -kernel memory. A bit in the shadow byte is set iff the correspondin=
g bit of the
>> > > +kernel memory. A bit in the shadow byte is set if the corresponding=
 bit of the
>> >
>> > This is not a typo. iff is if and only if
>>=20
>> +1
>>=20
>> https://en.wikipedia.org/wiki/If_and_only_if
>>=20
>
> Does "iff" really add anything over regular "if"?  I would have thought t=
he
> "only if" could be assumed in this case.  Or if it's really necessary the=
n we
> could spell it out.

Somebody "fixing" occurrences of "iff" are a regular occurrence; it's an
attractive nuisance for non-native speakers.  For that reason alone, I'm
coming to the conclusion that we should just spell it out when that is
the intended meaning.

jon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87msj45ccm.fsf%40trenco.lwn.net.
