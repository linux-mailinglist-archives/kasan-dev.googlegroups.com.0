Return-Path: <kasan-dev+bncBDRZHGH43YJRBJ466O2QMGQEDNWNTQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C8D10951EB5
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 17:37:12 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-39b3cd1813asf81971135ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 08:37:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723649831; cv=pass;
        d=google.com; s=arc-20160816;
        b=yb1yYIMVWtvf5c3eE3xVlYDUkebyB1aVEe7AF4vjwhCcVk6cKlbaJsweJtuU2EPHMQ
         eS2VumsJXqgcLkfUicFZm6InHLWrcTGpu60iGBbLMMvS/BID7EQOKCdD8RnNxa7P9sH9
         S3KHW0C83m7SwsPdO8ylgkyw7Mxew7Ul065PDXbPHpwFLgDSJZlv980aG4SpztPznh4t
         ofgnqnQz3hFx0C+w5fVd4IY3cql8CY7pb/v1J7gagj6SNyq7aiLSPhB9zms3ZIAO2NTT
         Yj3IvJtVZkm2xL0dQztLwddBoKPjUYMl4Dz76F/7vooR8qzy/vnC2UsJfSZSWd1Yy5Kv
         udLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ETl61XRqcxbFUs6HXcLSl9GtmoGRF1dLCTpU+KQ8JNg=;
        fh=JG1daxxG8QbbMG/jN/eWwQfWtMHO4PcKjMa6rm/6PNo=;
        b=WPY/fERzYpGRoqTe+B3m0i0HA702njePqKnY8ln5hGV2Rm7MhI31/3deqyGw1u9u+Q
         bijY7hy7dx2H3+GI+ggnF1cavUiY/RxD16NkOQOgw4GqDdpmdeTxq41QzfrFYLsquSL6
         Q4Q2Ejppy7NKlcEvIN5+IuvPaH5N2Hk1zDLyUAQ1rsT1s1xmvebSHOMO1tbCZunp9Fn1
         cij7vu3tcFHKqZ4LsdSyb2fVa3TuAFQHxXoIY+lITziZSplDdoVvlQfXzQN6+G3wLSAU
         D1jHpO/HNbnKGWVtJeP2gAXi6s7HlQR+t8Uqo+CzACSPc4D4WbVFj0wppfONpmzBUFrH
         VaPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FjDnvGvK;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723649831; x=1724254631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ETl61XRqcxbFUs6HXcLSl9GtmoGRF1dLCTpU+KQ8JNg=;
        b=PAyVS88Yy9Wde8RNob+jhuCI8/qF2mT024xrbdT3o9gETeZqe9882nSCugNzhYc6YX
         EhaZgvm+cCigiIVv7kr835FrEPVpoGcfsbn/xETRIJ3ZhI5ETSPqRJPoA1IpscMz8+8X
         wDvOIb+mxmthqFW2jvY4qH5tFDIb0vU8L8WRwhg4Y0JoWb47UVQPoiAzp3U22OG9LTAY
         4ftZrZofOAQPuUkqipKaQHP6oav4M7vP9btunR+A57DYMP1ngK8UMBhquwyihXrKWsgP
         1r92Wh1qKGf4K7Tlysb+99JIv7++2FcehoXJ8KFXqIqaZmLyPCLXKxGjc2ezQayvNBhz
         cFJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723649831; x=1724254631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ETl61XRqcxbFUs6HXcLSl9GtmoGRF1dLCTpU+KQ8JNg=;
        b=A8pSgPFV1jlEPbVfevhNZprvAj6C8Mf1oMm98qgnjbc695dxEV8CoYntvHem2aTbGp
         C20oJIXh5IQcjZUAmlCPpXmdUpE/iFT5KiAZVdrsR9JTXN+KlQ4hBqSG3Q/HIUDyHDB4
         qoNS1NuoRkNUCbHU5A8f1LO3+UEBQUTrQnXtJ07mu/Xm4RC7TJBO/c9KfiGUEhr9TNOQ
         dQer768rTA1uUw4uiTZ0lU0POEd0LSc3ObJclWqfWBfnBfPud1pRR4c75LCH18ElMTQ7
         gHdIJihvNa/vF+hi3XuH5eFVKoQMmvtJLDehuNczg/zUPEEGcOHlqSaZZSxJ0Q4bc/MG
         m7FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723649831; x=1724254631;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ETl61XRqcxbFUs6HXcLSl9GtmoGRF1dLCTpU+KQ8JNg=;
        b=Jgnsn4fwHBKLW5AWU4nmlgOCNgnCq/fzFTYuQZy3ZD63WomB83mniY0q5uZi8It1qO
         yk5UX52fNUhbc0+aONKMIy17nvEwipQU0FNm+fdMnds5k3z85ja4qZJjI2ugLxo2gbp0
         MnswibRSLhmH6OzW4zrCBgECWSjV2a+2aZPIdb05sUHWKNhbcOdIpfVC3fSpEedZMKmW
         7GtVaRJNlYfTO0sF+RAkvPUtbxr6KGM5fVsRSdBS/50SkgvueVeXXpaGa4PW6UrhTHit
         5PokT+/i2e3M6K6M4MVC7Ju8hvmYuAyvIqaSH6eq8aZOWngFEqiRcjBA2Aow8jPAZ2wO
         Chuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyAyWCH9JztEqOGmXg4DHRlyRZICoiMsZFyhi6bGSccGhsK7v8gLDNHuwB/Q9x68Gg4yzCSxvNq1YvgYGE/3pVuZVllnyqvw==
X-Gm-Message-State: AOJu0YwZdddjqPI7cK0cp9z3txLT3+nXRKfjLt8saOZ79kqB7JxTWNuI
	PjM5OVHZCcKmDtotf3S3LoPr3BOnBA8oWTcJw5Del13Okn54ZXxz
X-Google-Smtp-Source: AGHT+IF/39z5hdCecblcz3dsUp0qWPf0lOfFVSW+RgSFLuprfye5WotEWSe2F8jSiVib9gOg2j6/6A==
X-Received: by 2002:a92:190a:0:b0:39d:1694:d261 with SMTP id e9e14a558f8ab-39d1694d430mr17706995ab.12.1723649831225;
        Wed, 14 Aug 2024 08:37:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:218b:b0:39b:19a3:19f7 with SMTP id
 e9e14a558f8ab-39d1bbeb64bls355435ab.0.-pod-prod-05-us; Wed, 14 Aug 2024
 08:37:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAxHbvndYXoSjSO48htPz7/pP1vmFeLXMohtoIJii3QBqdxKxLAJeqCS7cEaE0ACBCjdyiAuaMoQeFK5OQuZXMM4R1aDpeBEav6g==
X-Received: by 2002:a92:c24f:0:b0:376:40b7:b6f3 with SMTP id e9e14a558f8ab-39d1244126amr35852415ab.2.1723649830135;
        Wed, 14 Aug 2024 08:37:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723649830; cv=none;
        d=google.com; s=arc-20160816;
        b=OMJ/P0HyFWejcljRVha8fX9huN6c3f5dwT9xIDcYPZJVDobzuTs154YqdUEbcltG/O
         P9KQGIGQvQB7D0e8xmBg0aDWIgPhY7DVozTovtPQLA2LwNvVK4qKqpUqSHP1PBvNue5x
         YqOA7reMyingV6YHsHeC7O5ZGOkuj0kcvGZqM14x+7S6QcSwl+yfgq+1fuLNooztdDMc
         SpL2d8wJgnBSyqv3X7xIKxhCMGcWeqqcrm8OUng9UV7DrP23LiCz9vmPt7X1bDAsa+e4
         mE9q4jhlmicSwCAM/eskyb5umaRSEzbMagUhKaEodHf1GDL9DsjqD+bCqHjW6LpFZksd
         4ztQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cqf02PglwzMnUewsw7C/MM2gxFs0r5loGQKEe2O/En8=;
        fh=8wraeBRqnsMnRmxNgWvpq1O06psc/6PGgMlOQYHt6dI=;
        b=VehAVDeGUA+FE4FkvSXFl7jlqjU/xbZd2WJn57pqOwktyifnnTE7ut8XC499pssvQQ
         uWJ6nGj9xUgP6LpVVodjuZOTNluwuQdtylsHkyy+JeqokN9Y7OxHfoyX6cPuEnc7w5Rm
         mNLtqyDV3LqZKfGz2KVGA9ujeLwCRx5uV2Ch5D+bTEEfvGbm4x1qlIo4cxu1mh05vi7z
         YnT2Q8kEKgZ/mp4SjsI5RdROB6X5YIO7OnADfhO58odiE4manNvcd/4ZBg1uKo04JXya
         Qj1KSPHXvX0ouZSHTbrfrtEmQV3v298zkUdaAmToqZNl+z1cBwkVUS98QvynzOogkGFF
         q+Wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FjDnvGvK;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-39c30a9b0b0si3391115ab.2.2024.08.14.08.37.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 08:37:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-7a103ac7be3so30347a12.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 08:37:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUcURJtYSnutTIzcAZ5ShRpfavqJBHt9pIAFTQgfX1BNVE7ucXJMqo8WgW0KMyDCw+AOtS2P5oR7AWAYCGZBXnXat/Zwgfq4jFPA==
X-Received: by 2002:a17:90a:ba8f:b0:2cf:fcce:5a0d with SMTP id
 98e67ed59e1d1-2d3aab87063mr3577203a91.35.1723649829061; Wed, 14 Aug 2024
 08:37:09 -0700 (PDT)
MIME-Version: 1.0
References: <20240813224027.84503-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240813224027.84503-1-andrey.konovalov@linux.dev>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 14 Aug 2024 17:36:56 +0200
Message-ID: <CANiq72mCscukQTu7tnK0kXHg05AiMtB8sHRDTvgjWgcMySbhvQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: simplify and clarify Makefile
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Matthew Maurer <mmaurer@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Miguel Ojeda <ojeda@kernel.org>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FjDnvGvK;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Wed, Aug 14, 2024 at 12:40=E2=80=AFAM <andrey.konovalov@linux.dev> wrote=
:
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

It is easier to read now, and indeed GCC 5.1+ and LLVM 13+ both
support the flags, so `CFLAGS_KASAN_SHADOW` can't be empty.

> +# First, enable -fsanitize=3Dkernel-address together with providing the =
shadow
> +# mapping offset, as for GCC, -fasan-shadow-offset fails without -fsanit=
ize
> +# (GCC accepts the shadow mapping offset via -fasan-shadow-offset instea=
d of
> +# a normal --param). Instead of ifdef-checking the compiler, rely on cc-=
option.

I guess "a normal --param" means here that it is the usual way to
tweak the rest of the KASAN parameters, right?

> +# Now, add other parameters enabled in a similar way with GCC and Clang.

I think the "with" sounds strange, but I am not a native speaker.
Perhaps "in a similar way with" -> "similarly in both"?

Thanks!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72mCscukQTu7tnK0kXHg05AiMtB8sHRDTvgjWgcMySbhvQ%40mail.gmail.=
com.
