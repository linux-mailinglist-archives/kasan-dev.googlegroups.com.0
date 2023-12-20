Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZMUROWAMGQE42BPQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 29AD1819DA1
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 12:05:11 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4259021e5a8sf288481cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 03:05:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703070310; cv=pass;
        d=google.com; s=arc-20160816;
        b=g815Cy7/mA/5KckuV13EemBEKijJqbY8+nXnfAv5SdFPWEX9S1IcPw7mcjOJVJ+kcq
         LaSg7axIfmJOtjSxlPMMKicKS1HKACZuY87IVXOZiHbY7XQfuI1udC8R22UJBtCGUyYZ
         M+5haEb2S1wgRWveHoSlRQfJyGowmQCkCvFl/hXn2nPfwPXFTdaJRu0oPvsa0yqTCQZr
         /ELyk6+rnF25Fi1obiLv+sD2QgcW5cRkJd28TAJIDC3xOnEgwN88qvk2xcsUSX7dFs30
         nvx/T/O9GyQdK1Jzih5yXv2kxkwDAPGVDJwx6GgVHP7PK8OFcsxaj6XOUTDvB3I/KwMQ
         eIVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q2+BR3iD8nUvjS0j8PGM9wUPnn7DS617xZtSADiGP0Q=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=YuY/F5Gw3UO/Ix2T0WTVnJAMru42tCaGYbMFhRp6GcWOSq8naKRU40Yj/Z1ZlzOIsv
         LDrOEPg238N76KbyLLGAmVdZB9T1js4cu5evdDxeZEiWP3z45dNuyCvaBFxDi1IecH7V
         tm0e07VNUVoDbHoyTiDKE5wdBoi+V3wUMdh0qQQklr6/naXLQE7do76uGylb2o4JFfBa
         9BgPEvnSimd3y4sVZKN0SJsRB770iCrNagt0Kuqmbcto+Zkp8whRW7U3cs/0Y69/51NW
         /rrBDz6Zs1xVw0BaO+JQyRkxrEToTmbxpqGgWVzhZezFtFDdwIyEoDGL66xzaZ53Rsue
         sfFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JjoGC49+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703070310; x=1703675110; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q2+BR3iD8nUvjS0j8PGM9wUPnn7DS617xZtSADiGP0Q=;
        b=q/0lPND9M6uWW1ErMqPgN6ac10r0rgOyUZAH0FKqTOa/BDXsCmIWArlTI1fjwR/+mR
         HxH0OHmzrG+XPMWb3b1nYEozKEdl7bY7hUYmrkk2F9MBRdlwTZH0aPPYn88QNYY776GD
         uyi6b+/gMHTQg+bC2MvNEySiNkf/UvZCZbuM4No5AU2emUwJoeMSzkx3Nk8Eu/DQYOiS
         qZxIF7iqLX0pkAqs9zg65gg3M/ZH7Hhl58IrPwLh9OqPkLkz2b/DmJt4xL6+5sXi1WqA
         aHXtc+jXxJMm/r7lHJeD3euu2KAaFfp/TudPNylX9geAU/65p8nkTbrGzkYVnpMZ50rx
         Q/+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703070310; x=1703675110;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=q2+BR3iD8nUvjS0j8PGM9wUPnn7DS617xZtSADiGP0Q=;
        b=X9P4OJtN9GK59KmTMSzkArsnz9hSCAXez/GnJHg+O0oKoB/SY34OeQ95Ms/d02dJ9N
         sRjHd80H8wJlpPaWgq7C8FCi+TrAbXfP2PsHgsgT+NW7mXn+KzaASKqBgmphCsa/8wGp
         1c5eJzrsDBnvnS+Z0KRn58KR/vGPogUqTA6AjSF4sQWb1WV6uYU63uyW12SF3QaJnHYM
         GQpCHraqinHPw+NjIYnRioc0T1QkDvqVDnTEsa07CAEmKlYUKMmR462oCj1/csWm43b3
         /eGZszX67+6FLYt1qdybtyJIGLQLqsWix80EIWVJBXvB7RnOUP/0/UQHcepwnWuxFBaG
         7JGQ==
X-Gm-Message-State: AOJu0YwsY3UMqBWGb9PlCVumrlK1a1aEuRO7+ReM2XEmJL1ebzAnK2Ob
	QkMp6R/SwCUrrRmls8eJYR8=
X-Google-Smtp-Source: AGHT+IHlODGh689KluzqKOSgVIiQGRpzMl3rbpTIKC4HYD+AthWJO+nK+ceUb3rd4LTT1f0DY4vDbQ==
X-Received: by 2002:a05:622a:110f:b0:423:e912:54bc with SMTP id e15-20020a05622a110f00b00423e91254bcmr219200qty.19.1703070309729;
        Wed, 20 Dec 2023 03:05:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:162b:b0:58f:7a18:580 with SMTP id
 bb43-20020a056820162b00b0058f7a180580ls413588oob.0.-pod-prod-07-us; Wed, 20
 Dec 2023 03:05:09 -0800 (PST)
X-Received: by 2002:a05:6830:1e4a:b0:6d8:74e2:a3e2 with SMTP id e10-20020a0568301e4a00b006d874e2a3e2mr18168240otj.62.1703070309067;
        Wed, 20 Dec 2023 03:05:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703070309; cv=none;
        d=google.com; s=arc-20160816;
        b=WX3sBG4a16wCB0bpqKhNP9GNVldO1S9LAjBBOcpRafASR5D8WQQWknfEBOMnpL6TEN
         5ikBFTY4TyZOlwHwT3GUbf8ORkhse1EXzYa0J4Qy+SixwVO2I2u8DBW9YnDNbMLM6SfR
         Zwf0W4iW4ZCL+e0dgsDS3X09OnuOBl0mWIB5mp/vI8JuKYXPDtm+xWmCwlLEHrsONgJ8
         q2izEp5mUW0vGK3RMDLrlDkJGlryvEGM0GqI9P+Pkdf/iGoUY3qWWnr4js1f68moG6HP
         CZ+ETYTyJ8jFag4S52UgVD+lV9+Jq2dsVgxgQO+p7Xwc6IotzPXvGaqsJJfCRjIbzxaQ
         yNJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aRuOb3thPKxS5ftTwWuPZVBwpG9dfs4GXpoJ1hD7vC0=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=rjJaThgqfycmCKqeJk0HmansjdKOH1npslj9foqAqG6/WgoexZ/L9ObD7EZT4Iznng
         oLOrGBT0m4XQh4rhenqConmJmbKtcsxUW8UCOb9SjiDE5fWXkcqnI61HFU7jj93WX6qn
         bM7oY/YARdY+J2UYK2yD4HBLXdxwSoqXBWQlScpa872rdCIReAAD1wZ+YPwfnCbh+n1v
         PM1F8VFcpXpJehbF1zRZT4bBVtmrsGlOnOdpylS+ZezdrQGsV2xZ2WH7UI/3zlfRq0Sf
         Izd3qYcfKb76s4gxGwt05V4oUVRA4GIVB4HtvV56VxYZDNAn/jnt76Pc3msSzNZnadaN
         Y4Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JjoGC49+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id t20-20020a05683014d400b006dba2385915si208304otq.4.2023.12.20.03.05.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Dec 2023 03:05:09 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-781001f5e96so123893685a.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Dec 2023 03:05:09 -0800 (PST)
X-Received: by 2002:ad4:5dca:0:b0:67f:143d:b8ca with SMTP id
 m10-20020ad45dca000000b0067f143db8camr12635720qvh.44.1703070308403; Wed, 20
 Dec 2023 03:05:08 -0800 (PST)
MIME-Version: 1.0
References: <20231213233605.661251-1-iii@linux.ibm.com> <20231213233605.661251-25-iii@linux.ibm.com>
In-Reply-To: <20231213233605.661251-25-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Dec 2023 12:04:28 +0100
Message-ID: <CAG_fn=X_MejbvJRG7qYih+qrL6D0hrJW7czfAJbOdY5ES4JyiA@mail.gmail.com>
Subject: Re: [PATCH v3 24/34] s390/cpumf: Unpoison STCCTM output buffer
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JjoGC49+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
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

On Thu, Dec 14, 2023 at 12:37=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
> understand that it fills multiple doublewords pointed to by dest, not
> just one. This results in false positives.
>
> Unpoison the whole dest manually with kmsan_unpoison_memory().
>
> Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX_MejbvJRG7qYih%2BqrL6D0hrJW7czfAJbOdY5ES4JyiA%40mail.gm=
ail.com.
