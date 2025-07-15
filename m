Return-Path: <kasan-dev+bncBCJYX6FNZ4PBBI7I27BQMGQEEY4Z6JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F335B051A9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 08:24:37 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3a523ce0bb2sf2494448f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 23:24:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752560677; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qk4aoO6r2G0AxRpTlXLyuvrVdTBjo9Eq9lg98tkqGXc7aAhxtByL+/dmDc1aZ0et3T
         VPSJa0/3HcAfkGXWINk8sBv3AqkfOGn1Fiib4FxDOH4a1myLniZXqO/y7LrYHSaURrYG
         oo5kcSVN1CSE7+skVhZwnwDA7+eyiw3hw1jlSnrcPigh/jc/86Nz9ZwPKJoNFmvw8bQR
         EytR0V4RIXgPaEQIXdFmNp8AwbEIyGRPydzTrzB6sOaKTLPQPTHuER8BIFyJ7JJWUV0O
         gKugh3XK6kZmpu3InMfl/bl2n5D/5gohv2wlw7PIOHa2Zjsl/36+EcN6RDPXhckpjZnI
         eDmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature:dkim-signature;
        bh=4+x3ouCNZoaMaEevP2qU57yCLV5ZNDUkQy1ut/ekHYE=;
        fh=pmo6P9vpYNqFG21PoxBGZ/xna7D7pLotSauKZ+vFgkc=;
        b=TRWdrSLi6nbKrd1QHPahxxYmQo7BNckz0anhXiMIkQpRQOqIrb5BwetEqdvCfCFId9
         pQN34z5xIyAh0P7HGjWB/HWuruAUxHAg9HqIGlqXLFJqVR2rxo76CR9Jzrb2xn7yOPJv
         DvHrvPmkQVpN6qsp3Zi24rymxKwqeRsoYSTKM3aWDAI2+s6BzRkMPl/VrVlRPsJj9LKG
         6CgtHKgxSzIpUJ32di5aSN5xM3X3T4PtGqnfAnDBbDkaCFVLFdj8uhV1LUgX0YXSevNv
         djC/D6UAfjemLjla+e9Y/wHSOBb/wFBzJpv3pP1gLTnYtPvqdQ/C7JgtwaQ7V5x1UGjl
         +uLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OQMQL8c3;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752560677; x=1753165477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4+x3ouCNZoaMaEevP2qU57yCLV5ZNDUkQy1ut/ekHYE=;
        b=V/uRgBKUdzpU9ZN0SepkrgR8MJ6vCIJhjXKqK4/URzOe8ymraagRblY26C6jT6iV4c
         azf0IpiapNXdqxJn7mo4+7abUY7vKJl0S3yvfsOiVlXrIaCik6a+wN5ho5h6lT3qMe1y
         Dbcsu2x0e2uHIFHcKb51a5FIT8GbQqZ43YQlySjqWM8unVJH+5wJPIZDoqHBmY31Bxxf
         twiNBcdt4PzBChvvPau3tERafgnlBGiSbonhDxaDcbMH5c92qedPQsYPw4SWcJL5k0vE
         RNh94RlNPrmycWjeP23NlbdiYRo4QSHHmHuQUE6IoseWSCU+IJc7FZkchYcPf27iVA+a
         3tKQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752560677; x=1753165477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4+x3ouCNZoaMaEevP2qU57yCLV5ZNDUkQy1ut/ekHYE=;
        b=KfBa2V3P9/PhwAVUzAXQ8zKR/uty7/oMECzG8MrwBpSwM+vuH4r0CidedEzau+XViU
         tKfGOmH51nTvV8BfZZDaSqhuMS1r9e6jirNin6eJUAeBmxJFswczlCFE98Hxblwj68nw
         5IUyiNa7mzYMsxh7vER2kNQ1SIxQllHSAdtUgAgX/EP7ZAQs5fMwnUasuVeCI8Y426TM
         xLMWRaZBoEkMki+IDYNenFlx1ordlUYnk+uP0MbRITzq8vuwcDudnIUODXdxphuF9/+R
         Dn+0133vb8P+/IusXbwoK05KvzhpA7Kd08CmX3slac5j1FbfUhCj3UnzIjH0LMD06imO
         vuWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752560677; x=1753165477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4+x3ouCNZoaMaEevP2qU57yCLV5ZNDUkQy1ut/ekHYE=;
        b=nkXOJOPodIA63WmlaieMzPMNOYB1ujh1Z7o6OEtF5S7ce9yFrZrcBhDTGBwPLb/anZ
         hYpRg5POHpLUbG7X1i6wQoolhMU9yewNOX5Zp2FZq2Cly5lQnO9VVXalMFiXTpqUxbAA
         +T8+AS6uGxi405/tnUBq3+BMKjo54jkVY7d7sIm3JilRjKE3KNfw3Mbppu5LpJyTkAzk
         W0qTnGZqE+VX7YHb1h9cdpEgl5k2v4DwtLyClNgtZa+yY+jWtGSR1rjsF25CElU4POKQ
         l4FcQgIGPmhWc8n4NJQqgOAXnjqHYsoNWHtHDUnREri+majXAfXxQcOlp/L4uItL3gHb
         8mEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVErLBQsAqwzFjUD5Hp1UpnOeB13LhleCc+hd2x2IZRTZxNpsW6gFSF1Is9G6/L/oT9q07gg==@lfdr.de
X-Gm-Message-State: AOJu0YwGcQ3BgVGXgJfgHBJa44yg4wMkQ7P5NPmOxdvsbB5KMt7xr83m
	kLAGy9yZz4clzYqAFAwV9meSrsVUyIZzeE2KepicTYZGi/WjVoPHXfU6
X-Google-Smtp-Source: AGHT+IHZQy4YCtMdqZ9WDRHXSje9lMVW7ye5IGFRPwlTYq3HyFYPIBK+Jnkt56uJSpZGL3zcEwANkQ==
X-Received: by 2002:a5d:5f55:0:b0:3a9:dc5:df15 with SMTP id ffacd0b85a97d-3b5f2dc1ee2mr12053268f8f.13.1752560676432;
        Mon, 14 Jul 2025 23:24:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfiZ6qbTWCTPIm8dgH0QL8Z62Zd6BOyzEjn4nJ0oyA3Wg==
Received: by 2002:a05:600c:2d8a:b0:456:133f:8c4a with SMTP id
 5b1f17b1804b1-456133f8d29ls7223875e9.0.-pod-prod-07-eu; Mon, 14 Jul 2025
 23:24:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUb66dspd6VgYffrAmsOd/h6NhT1ZGQBOUmGFXcn/p32j7BwT8oMRIHfGfbOeQwsOxFYDIyH9bjs28=@googlegroups.com
X-Received: by 2002:a05:600c:620f:b0:456:2771:e654 with SMTP id 5b1f17b1804b1-4562771e755mr11463515e9.24.1752560673580;
        Mon, 14 Jul 2025 23:24:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752560673; cv=none;
        d=google.com; s=arc-20240605;
        b=C3EKJSR3QX/gxUlTVtgD+cekz9wERWnHgo+baQxDWVsClyOhWALgp6TW7nkpEM7N1T
         RE6ObYeP93AjFyrvKmmfJEqR4/5HrlPWxxegAY6zpsfZeXM7eD2mlqApRq8P5RCuJhag
         67bSc1najkBzRBhhl8ysbBFZlpOR96TiCsTNC4nadL7XWbA8aclvs+fOVTSgfA8S05Ol
         hLQaXKC1Hp/EmvfgokEJqspuceikTRvZqhPHDzMJVYF/VA+YRfsy9eTvbdjlCMs73oAK
         4Yd7rlqzjOup9KFC7fzZXwa7SpNNQfxWpbcoGwvSPk0iMXeeL68J1C5A9g8k0nUHb+Pm
         Rddg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=w4VYgGFTZ0oWXLLm71NTBXounZsQLYQkCK9H7WBrTiw=;
        fh=Cu0ws+aj2anV4DVKul82UXj5sNARNktaX7SXW+SnQCw=;
        b=dSuKqeV+Rd4jj7XBD6qhHAxMuEkT/p1jNsS08pswBjnAecdKhgUav/0RE2CzmRxXHp
         R5BMV5yN4VYXQvYPSWrWaO28FMMFGqf6MQY/FuuicgWSkQE+FfAYamR451yfHCjywyZl
         SkF0bEtIO2fooP5bBXrFOUXg4EI5l4ddlFD55TPgFk2e9uZCFBfZ+zn362cMlEgpKakw
         bm4JrtcqHTos8/aBPpx9j3AkMzTtMXiL84XmZMfCvFyx0tTApbRO+rtpBBlnofEr78qT
         iWhUeNetw7b7yz+qjikQr46Ub5fYgs8QGjII1nSFKTX1UlB3p6+ZwuPLGNSRvurY7pLF
         uqyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OQMQL8c3;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45627898572si300475e9.1.2025.07.14.23.24.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jul 2025 23:24:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-455e6fb8057so37465285e9.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Jul 2025 23:24:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVfgkTAkJnq6gmQDDD1YzjxpMLruWMF1KXRNnQQkbQYhviiEAqSL/Mc9/Ud9QkBm+DC0L0BAtlM8SU=@googlegroups.com
X-Gm-Gg: ASbGncv5uUQ/jX1HZ48ZkP7ogqgAQ6Mjl9e9dOasLkBTCI74gbzakU218kAgevgeSyZ
	aT/NW8TswbGzAtO6Itatmy6jJau6I49QoXmFAr1ObW5xWFJaDIzC+9399o8u86L3BWyDfM9IibV
	GIlRqSv0sMJKJJU8IWeUE/9ggQedk5wXVpGJ6hPzHnyMLG2nHEVlRh5kwbCkHVZAStZHuxmV+1g
	ZKFkOWLrGdyerydCz5rcz8OJvJDJXdtl4mZ3vr3INYXa7VxJlJ2v3gKI56/Z1OKhuKMhox67RYI
	Exf9VxQwjP8C9ByDly5KpN7Rr4hEf77RIkZiM/BGX8aHBWcI0OrYLcUeb4CoJjeNJGYqO3yHPzq
	FLAsSHWdoNFS0T2+NkCmCs3kDZt8UBcxE4lOi8tfuV9LxHmbqTjoN5dfJJwGWVcGUAVKMqr6qQL
	0WsUKLxx7FMOSfwvqSWMFOEiTkJ7hXmN3shLikPpwosjVBk6npQ1Kit8W30bcCFPX+pI6Jq/tQY
	SGYodc34XluPxYJkKyi2ALI7uYgUIo=
X-Received: by 2002:a05:600c:8b34:b0:456:f1e:205c with SMTP id 5b1f17b1804b1-4560f1e27femr88140865e9.4.1752560672656;
        Mon, 14 Jul 2025 23:24:32 -0700 (PDT)
Received: from 2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at (2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at. [2a02:8388:e6bb:e300:2ae5:f1e1:5796:cbba])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-455f8fc5a01sm105198855e9.32.2025.07.14.23.24.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jul 2025 23:24:32 -0700 (PDT)
Message-ID: <d43ebab47ee70cd11bddf78c424ec341b4c797cf.camel@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
From: Martin Uecker <ma.uecker@gmail.com>
To: Kees Cook <kees@kernel.org>, Linus Torvalds
 <torvalds@linux-foundation.org>
Cc: David Laight <david.laight.linux@gmail.com>, Alejandro Colomar
 <alx@kernel.org>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
 Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow
 <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,  Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov
 <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
 <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, Andrew
 Clayton <andrew@digital-domain.net>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>, Michal Hocko <mhocko@suse.com>, Al Viro
 <viro@zeniv.linux.org.uk>,  Sam James <sam@gentoo.org>, Andrew Pinski
 <pinskia@gmail.com>
Date: Tue, 15 Jul 2025 08:24:29 +0200
In-Reply-To: <202507142211.F1E0730A@keescook>
References: <cover.1751823326.git.alx@kernel.org>
	 <cover.1752182685.git.alx@kernel.org>
	 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
	 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
	 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
	 <20250711184541.68d770b9@pumpkin>
	 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
	 <202507142211.F1E0730A@keescook>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.46.4-2
MIME-Version: 1.0
X-Original-Sender: ma.uecker@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OQMQL8c3;       spf=pass
 (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;       dmarc=pass
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

Am Montag, dem 14.07.2025 um 22:19 -0700 schrieb Kees Cook:
> On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
> >         struct seq_buf s;
> >         seq_buf_init(&s, buf, szie);
>=20
> And because some folks didn't like this "declaration that requires a
> function call", we even added:
>=20
> 	DECLARE_SEQ_BUF(s, 32);
>=20
> to do it in 1 line. :P
>=20
> I would love to see more string handling replaced with seq_buf.

Why not have?

struct seq_buf s =3D SEQ_BUF(32);


So the kernel has safe abstractions, there are just not used enough.

Do you also have a string view abstraction?  I found this really
useful as basic building block for safe string handling, and
equally important to a string builder type such as seq_buf.

The string builder is for safely construcing new strings, the
string view is for safely accessing parts of existing strings.


Also what I found really convenient and useful in this context
was to have an accessor macro that expose the=C2=A0 buffer as a=C2=A0
regular array cast to the correct size:

 *( (char(*)[(x)->N]) (x)->data )

(put into statement expressions to avoid double evaluation)

instead of simply returning a char*


You can then access the array directly with [] which then can be
bounds checked with UBsan, one can measure its length with sizeof,
and=C2=A0one can also let it decay and get a char* to pass it to legacy
code (and to some degree this can be protected by BDOS).


Martin



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
43ebab47ee70cd11bddf78c424ec341b4c797cf.camel%40gmail.com.
