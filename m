Return-Path: <kasan-dev+bncBDRZHGH43YJRB25R6O2QMGQEE3HMRDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 53F99951FA5
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:18:54 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ef23b417bcsf597781fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:18:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723652333; cv=pass;
        d=google.com; s=arc-20160816;
        b=t/zFkQTRdMba1tvPpTFKsvuFZq23hURn6GCrBpoATQ/n1quckRjQT+6BVjipX/axSk
         /ZsejAfBXiRv4uXz3txpfJA4ZLRNne7/5zmZRkTWszX0TCBKlnmYiOFfHPnq8vGq5n+V
         EoPKo+QOH0vtHJ1LGFFs/7ZV6BRFIDxEVpfPHRYDzVThXxBnJLJK1JXOt5qgbWtQIqUV
         FN8OhMAG5AcBFGACp/5uDBdc2fW0vOZA/dI3tYUuA5zJ895N9Tf7UDoRbKMqMFpD7BhK
         hH0xBNZrGPQ9hrunFAmRYllW+xVRWxDhGypqh6C4GFWxsgNYHTLHMRP5Anu2hhNXULQG
         1+tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OplNz+sPQwhWKYzxJWN2hfcm7+dCTpECNbNUTWvn/jg=;
        fh=OQiUcz7NU/R0aXETsTu3B8Sx6ZocvIoyLOCkv7WvmQY=;
        b=jmop0pM19ni7TQrgO8IHUkx9AYDF0VCrSc8DhBBCaQBZgAaAJ9ML3HrKGC6pQ5b5y9
         F1zMyEFgtoDFcS8UN56GzPngqAJK3AxqucaSJ+N7CP4y9M1RzMFBL3kPDzirKIeJEJJc
         R+BMHuh+ZwOkEh6DBx/nsy0DbYsgqVQsJ0JrttU/NPSPohaxUuMg4JpwNLAi0VDkY0LK
         a8HQapt1Q+sj/C4Vqr5tTYyVYgWd0IScpmkApY/3J5iLA/UJB0n5XaJRpB608oh1qRpe
         Fg4AqXc+mmWBX+44Rve1VD8WzbKjyxFQ5T/ykuREx9DpLWXB7oiNvHhnC9u4D8t3HnJJ
         bSPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="if2M4Z/j";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723652333; x=1724257133; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OplNz+sPQwhWKYzxJWN2hfcm7+dCTpECNbNUTWvn/jg=;
        b=DnnwnQoNxzVIR5992qg2MetRzlWa5J/yy2AwkO9yDAWmSZKH+jBFAODcgAa+W2kqir
         bxUF8TIYv1FHtv/Dpk8hl6AB6C8qcGf1bB+ew0hP+2hfB47Geq2a7SoWZydqcAehHQgU
         9FH0gKFu3kKpRhQVBGv6xUAGbSdP9Tdd14wlg+s6CI2ztjnTz0tKuo/r1ezGWJxJioCj
         +3YwlsBmhVUHNaE6gOOfM9W1PVRoorxJix2hvN6CijxmixlDAcADmK69yoItFXwM1Xgb
         t4Y3byEbY9fcFpsiMFPtSLn6K7M5mpSNPqktJvAY/0Ga9oZBKZe9uqBN4t/EZitGQWYI
         Fd2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723652333; x=1724257133; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OplNz+sPQwhWKYzxJWN2hfcm7+dCTpECNbNUTWvn/jg=;
        b=VrkUPIaZDCDWQogH/ZtqNfInEbvLSMSKyJi2Jd//HbZknDppRUITmndTU9IDHYSIfA
         iL6oJ2/Jzzdkv4owGHBjqhkU+kWLZFr1FLJRZBrm/HpnBsRHh1XR6QRgcZVZTIFGYwYy
         buLiNf06dS3oKatvEiDNqIb6tWybjpIBZ/RLPELHrEtx0HA8DMCcx9FS5m7gU7IPie/7
         R9UzUT9NLesWiFnSmnM9z6RgNA8jYovgod6t9gVi7WpaPnxyAhP7aUjDPyyW23USsf19
         yOkMN8Z71JR5iptnvbw8/ie3ec6OXDHgK2wyjJm1dNLelZDQnw0ibkAJgwoNKae7Q6bV
         Zl+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723652333; x=1724257133;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OplNz+sPQwhWKYzxJWN2hfcm7+dCTpECNbNUTWvn/jg=;
        b=k4LoRvvCO4GhwwQRbKBiR69j8m61IUvZVNl6wpHhjjOP1RT73rQ0tXXn1YnzmMr4bZ
         dXFeeEvnio5T3pynYE5B//iU9AwyqwKgp0P7kgk2Y9DMDK9YsfElcP/LNjMVDeyMLPWg
         hE5gB/Awudgxw9ju3E5QTerU0qSogrc/PcoE+TiIxMi5gmYEWABD2UkvZdUX3EhoU+8A
         2+O7W62mVnfFiJ4y87b6XtxJaoohKmDCltsxnEqsWNDtsrv7CZgOvH4s6lxS4J8YXM7y
         f4lxbCx8ExACM74932UneBNKfoyB5jLMsUJIIwNX92UcaHIJX13R2KsH7UlXkPRxEET9
         RBdw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfucKNEuXAPTFJLuvJLrJeGK+6OfopipHNeEe2UBfXh5WY3mNlQOriZgSdNdmghonjA8zAibUMluhwW3zkfftsz5YO9dtg4Q==
X-Gm-Message-State: AOJu0Yzfx0NYpPV63bixj+Q+GMDj1/yo6coNb9lYuHh+2kQETx2PY/ya
	UTwa7UbQX1ArDpsWqT0dbDB2e3SndocswAV67TmOwioHvHfvUOx1
X-Google-Smtp-Source: AGHT+IGJlPTbT24sqQl2bdEx90+q+ckK9mz+IH1gMJSLDUoTVsC9miTYEYK/FRdJ6qIfNp88L+7oiQ==
X-Received: by 2002:a05:651c:19ac:b0:2ef:1db2:c02a with SMTP id 38308e7fff4ca-2f3aa1a5766mr24273831fa.6.1723652332036;
        Wed, 14 Aug 2024 09:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b15:b0:426:6c3e:18f9 with SMTP id
 5b1f17b1804b1-429e23e66efls118355e9.2.-pod-prod-01-eu; Wed, 14 Aug 2024
 09:18:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWk5OjVNv1+L0ZO3fCg4c/+1GGHCpQnhdN4tAPr+OFnpKnVErMOa7iuXzZ9a3Sn6/YBji5kkp7BBL1KLdht5UOItY77QqP5NKiJ5g==
X-Received: by 2002:a5d:5e12:0:b0:371:7e1b:871b with SMTP id ffacd0b85a97d-3717e1b8743mr790806f8f.29.1723652329704;
        Wed, 14 Aug 2024 09:18:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723652329; cv=none;
        d=google.com; s=arc-20160816;
        b=gkjy7NBfkvZOtABrSbHHtrNjpJfkP2ffEH6iW3s0dwvoxNsSoiJQzlzaRiPPf9Kb1G
         8hN2F3ojS9TR3MT1IQ36q4W6vXnA7qX2eiN3t+iOK8ChqauQ1GYdrZ5QHW85Bq0pcDCB
         F9PaU2knUUpXNARpT9giXJoNQ1Lw5PwLptHWx6xdHvnOqI4Mxk16lyp9Pnb/gdPWUbx6
         +BkSd72WDwtiiq95n3awGzYL0hgW8hjNQyGDnctWHpUXmQj8jfu9p0P/uGfiD/7J2qBK
         IB4zFEF0DTLsxcFkEAMARcQEO6mwVT+17ksOfMpGvC+LjrkpTCdxT1i344KMqNllUui4
         DSwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PB5dkBysx9T6fJTBpImmumJYpuaHzNjh7FBAg1c/aXU=;
        fh=rfZi8eVKshw+fzGnyuV1yuAS4+8NzdHbb6xSKkAtZA8=;
        b=Z0NhfE4BWA0tH8Bnu4U0FrJhMwyFV0IT/Fm/8tPhkNW80kvd7EX5edbYjwBbYXhgSl
         Ew8/oh4SsWz+bGjzz1jsRSBhAqxwvKrgr1tpGvO5DSgdbfY9zxTOvLjfrFvJyDtE2nTa
         RL1VuQGVoJwxll8QD0EnJVGduyu3ttHhxsH33jatAcV3sfnzh5KPUg0nEvzYDGfMXqUY
         Sh09XZ7zlTsqs57fbDEqXLkTuG7WOO4TpiDmuMxaSSUmkfJSuZrkMNtvSTQbX56cx/zh
         QUQ3D7D4+ac8AfGQD8CUPHMVVOTNwDBHaNP5POl4MazIw1gpnC0FRdLQXrBD4BAKf5Rr
         kuOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="if2M4Z/j";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36e4bbb15e6si170905f8f.2.2024.08.14.09.18.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:18:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-2f1798eaee6so853441fa.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:18:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVYYPr2N/jP6cveQZYqc9SokLu4+VvgKpxGQntUl8r1mCMJU8+Dd48olyG0nfcKYVOLdvhgITYWUejxj48BkES+CXb5tLqlEFyrtg==
X-Received: by 2002:a2e:743:0:b0:2ef:1b64:5319 with SMTP id
 38308e7fff4ca-2f3aa1bcbf6mr19089351fa.11.1723652328498; Wed, 14 Aug 2024
 09:18:48 -0700 (PDT)
MIME-Version: 1.0
References: <20240814161052.10374-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240814161052.10374-1-andrey.konovalov@linux.dev>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 14 Aug 2024 18:18:33 +0200
Message-ID: <CANiq72mAce+-NCgBTE8FsaKC=87x+tGJ6xWU=BTiOLPGYObOFw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: simplify and clarify Makefile
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Matthew Maurer <mmaurer@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="if2M4Z/j";       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
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

On Wed, Aug 14, 2024 at 6:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> When KASAN support was being added to the Linux kernel, GCC did not yet
> support all of the KASAN-related compiler options. Thus, the KASAN
> Makefile had to probe the compiler for supported options.
>
> Nowadays, the Linux kernel GCC version requirement is 5.1+, and thus we
> don't need the probing of the -fasan-shadow-offset parameter: it exists i=
n
> all 5.1+ GCCs.
>
> Simplify the KASAN Makefile to drop CFLAGS_KASAN_MINIMAL.
>
> Also add a few more comments and unify the indentation.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Looks good to me! (I didn't actually test it, though!)

Reviewed-by: Miguel Ojeda <ojeda@kernel.org>

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72mAce%2B-NCgBTE8FsaKC%3D87x%2BtGJ6xWU%3DBTiOLPGYObOFw%40mai=
l.gmail.com.
