Return-Path: <kasan-dev+bncBDW2JDUY5AORBHVO6O2QMGQEIRLPCFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 808D0951F86
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:11:12 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5c9ae552155sf46979eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651871; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXntpwZxfakJlrQA4b+LBlHdDScgN4lWsg9ReRUPsZ1bORUIVLvgFeVzn1LJ98GSzI
         XLJ91O0rQo3049peT3CwvMiRSb5f4v5KVNrx82TWJIWXpB4Krw5YaHU25RyGqEQib71F
         XAX/3nlQVEDC6iT0QmR9o5Vgql5e1cNnDsENfOmglewh5bSNjU+iU3mvpqesP3cLZO80
         sLv9gGNm45plkc6pW3KP9d2BJ+o9uW+lrU8fHnK+tjK2Jv+1KVGE61tfQlT/1QwOz5kT
         Q+LIP+I5ueeB3V8e7zdKftmgPhKFUVIS52RoJz4OsSHug2XePVXM9x3S94WGDESAJjzz
         ZAig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MT1b5imPrhL3JY9p4KFSeU2RxPMmzxXaWf6XrBAs240=;
        fh=4a/EGaNNolN+NbAETZuqfXRV2eacMC8bUJ0Aiy0bgQY=;
        b=lRpAmdfcLxNIu7YnBH5JWEs0XXQwrELUNkrHtInSGD1oelXjJpEUmMtTQ9disMXZp7
         hn61N9UWDczZnpk3cDFaGLP8wtyPx8TlOxdDZBI7nJ1tFZ3hyPkEiswi3HLvnLk0kH6G
         wmfQfrTNAG/bHcS/JfjAwmmLkoQN5FNNx3Cd0fuMnRWchVmC4hRfso0+Ilnr6uMVBP2W
         6sPsAzsdmtXFJkbvvQsguULEtXYX0qKtInqmAiHQCv8dzULl+cNpRNNOuTblBEjKvGuD
         wkmYFmn4oF14kYRyEWNBDoAn59RNpS2PE4n4Cv8Ue7iRmJhS6V5lwlpJds6goCDXWYkT
         xt1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lvnapNww;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651871; x=1724256671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MT1b5imPrhL3JY9p4KFSeU2RxPMmzxXaWf6XrBAs240=;
        b=dE490nI/Nxo6hYiU8lf9k90tiwKAbWdZSqOD0gpSADkMCBUHBjxznFTcw++l8VtDOr
         RfUOZvLRvn5QmddT310nHgBZfxZQbG+rD6S7VfEK0H+gAdXJZo1YZu34iZn3gin/potB
         4nFubG5VqmCwygSXzRaLFBTP/ogbgwl8/qdyWDzEFf2sWOa9On0aNZxJ5vCD2O1TlMqJ
         Y8ewIKbJ28z8ZiZ18jeegaQ7Tz8ZWOuEauJnWxhma1qbwKfIBP3J35UqZo9Uwj787iUh
         c9aVHDW8jIdrKU+btHBVy2RuAc7eHhfJg5LnnT9offCJK0FQQ6IrnpnIIZCiZfkVqc3d
         9vlQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723651871; x=1724256671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MT1b5imPrhL3JY9p4KFSeU2RxPMmzxXaWf6XrBAs240=;
        b=deVaMonfgtsqjt7ij8AaBRgvTw1nlOqlk01dx+FkX/dgNVvaH/Db3aHEcxgYZb4WOl
         pCIZKBhDFIwRQfvFsTnnaysvfj9J5e98mxOs/h8+E9qFPuSwu6cZ6GqKLig/0WRPxZ5c
         XytuSj51gxFagwGhCtJpgRD2l9C2ZRbNCt21bZtgJMAOxf1bbkgrkGhQF9BEgIx4Hk+S
         sjM3whyZb8+lHK63wt0jErqiRX4GQ8VB9tppvNTjgxH7BmB5EG0ZW7bZCswqWiEn1OPV
         ARuJPB+WLP2DNbq5RpLY7v79802NFjv5yKikSvXAwAwV+1GZZHdfOZ8RCY/L6oZOU34I
         oslA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651871; x=1724256671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MT1b5imPrhL3JY9p4KFSeU2RxPMmzxXaWf6XrBAs240=;
        b=vXBRhpanvkG5eUiPXOGkBon1q9Y6sbf4ROeyYwEUUbdtn6uLDOust3VmX5JkpDgwx8
         CaVJKC05QmsBF5EmWSa+OU2FX0Bb4KoaeirYldEQ6tZEQKUfYQek6LY/Dp8S6s/3e3D8
         aDFtJiFLg2NoPiIfPMjjay3L8p3gN0eRplWlC++FVCPT5EdsE02vLX2e07i4JySda24k
         Tc7rjqvMe0SzUW4lrKR8TmmjpYRGnkCgP4Kxpl4KPLr2nMkNhfm/NPLcWbL8u2WhRnH4
         FsoK0/bP3ZjCj2oMtc1BkzmNIN7vCqBoDpPQaQCrngnsitWV6/jYkfStwSTCQVOzkcQO
         eTkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxMAqHKlNbdM0d1sW3MjnNQUZ7mKyqKVpMC62aF7CB4EA2cFOs7l9Pg+Xm93ETr1KjdOdUXICIrvNUz7eqeyM15ToliH4YtQ==
X-Gm-Message-State: AOJu0YxqKIm77jQfp8f/GqaHilUGUPU39y3hMQS4VPAzg3d8TpzXidkL
	/vjqM4m7QnKOqCnkzLMjDhvrJrqjUqgcv9QIuZrW31mJe/M57AXE
X-Google-Smtp-Source: AGHT+IFv74OMxSiB6ZfmFJ/uU9QvK/l3blh8pdyYkpY0Z5x9gf+D15UMuC+FGdhGtLOQqkEMbZbaaQ==
X-Received: by 2002:a05:6820:2205:b0:5c6:61fc:2f42 with SMTP id 006d021491bc7-5da7c6d2850mr4042965eaf.5.1723651870787;
        Wed, 14 Aug 2024 09:11:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4846:0:b0:5d5:d928:5774 with SMTP id 006d021491bc7-5da888242cbls118013eaf.0.-pod-prod-07-us;
 Wed, 14 Aug 2024 09:11:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+zJ4LGc+XFbLjjIC5PHOhCK3yuUusK9OqinbxST8Z3hgPMwDawPCHSoHNgEHToRMUHwVC9gfYNna9D1GKms2H1AjBppQj1nbI6w==
X-Received: by 2002:a05:6830:6e82:b0:703:5ccb:85f3 with SMTP id 46e09a7af769-70c9d9fe63dmr5103576a34.22.1723651870030;
        Wed, 14 Aug 2024 09:11:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651870; cv=none;
        d=google.com; s=arc-20160816;
        b=H9VWotwe2CH80Rx+FfN6c82lVvdf2jC5HfAC/E5UXlmqF2tRAlMk00ganEu8t7K61k
         Yylwk7g6yHlrTSA/7UxTcCw2WzmCMuP018LgJJBSbe3ZTRjHWUSiYjOZKgbMtopsG1a9
         s6kZJvL+iIuT3PQAEuLnqk7BTeb4I5XieIe+xNjROgxA4MO8/KHrVySdud2Q3v2bbFUm
         E0VXP0GMzcMjDjFc1A+al/V2/RnEXJL2I+I2kYDWCPsosqwucuxhfUeHuHWwBx67mRxK
         0LiYj+UT8ORn+iXxnLW8kQtPFSWNSjQcYzl9+9LAdTMeiKJQhN0Us+6yEaA3xVz3UwGx
         bR2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YojC52uHbpPliLtyLOZFETHeNy9jnfDl4e/WZwHCFg8=;
        fh=YyKYgO/Z6zAIAEcB8ZxrCvGU6z8ErkNvDkdF2kaF3/I=;
        b=uZPHXNKo2hWITeFaBsK4y5ZPvheJOhZoW+49RODL93wPVXmcyYksdtkXj+Qbb2LyIh
         gri2TpYeZ0EhliiFUjkQ+jFQwLoNFaZ3intWDsf8l9LC00+CkRlDJekhFllW7S9GEMty
         fmC779eyb5hbZoeu0SRvEtOuzaoUtIyGNp+dGg3RWeyXzbcP2xDcSV4xAmLTyteoqT6t
         I97O2DZilBgJw1dFlhB7I+nA3apiuJNUY62kRdovgZIXVyJDyZvtxLLU0R5aF+pi7fXH
         qfw5r4ND0Vx46iiOj7iXLKRFpYXJTQzWKwP1o2RDXqPtUQFr2y81j4S/IrQRrn1nivOJ
         YHCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lvnapNww;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bf5f98234esi760576d6.5.2024.08.14.09.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:11:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id 46e09a7af769-7093abb12edso4917582a34.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:11:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWnYOvJcFQcCKtbnsvkqCvV4MGSLH8ZTlL5CKBR+45MNE0xd+A32UL3rbNBdNVgdCOm7zmaw/ve17GDQ/dEBlIZUi//AMkDHLed4g==
X-Received: by 2002:a05:6358:7244:b0:1a4:ea23:b5f3 with SMTP id
 e5c5f4694b2df-1b1aa9aacd8mr407202755d.0.1723651869531; Wed, 14 Aug 2024
 09:11:09 -0700 (PDT)
MIME-Version: 1.0
References: <20240813224027.84503-1-andrey.konovalov@linux.dev> <CANiq72mCscukQTu7tnK0kXHg05AiMtB8sHRDTvgjWgcMySbhvQ@mail.gmail.com>
In-Reply-To: <CANiq72mCscukQTu7tnK0kXHg05AiMtB8sHRDTvgjWgcMySbhvQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 18:10:57 +0200
Message-ID: <CA+fCnZeD4CJheGP6D+x5dzUc4ABRZz1Db0h7hNVmwH3gUC2zyg@mail.gmail.com>
Subject: Re: [PATCH] kasan: simplify and clarify Makefile
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Matthew Maurer <mmaurer@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Miguel Ojeda <ojeda@kernel.org>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lvnapNww;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::336
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

On Wed, Aug 14, 2024 at 5:37=E2=80=AFPM Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> On Wed, Aug 14, 2024 at 12:40=E2=80=AFAM <andrey.konovalov@linux.dev> wro=
te:
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> It is easier to read now, and indeed GCC 5.1+ and LLVM 13+ both
> support the flags, so `CFLAGS_KASAN_SHADOW` can't be empty.
>
> > +# First, enable -fsanitize=3Dkernel-address together with providing th=
e shadow
> > +# mapping offset, as for GCC, -fasan-shadow-offset fails without -fsan=
itize
> > +# (GCC accepts the shadow mapping offset via -fasan-shadow-offset inst=
ead of
> > +# a normal --param). Instead of ifdef-checking the compiler, rely on c=
c-option.
>
> I guess "a normal --param" means here that it is the usual way to
> tweak the rest of the KASAN parameters, right?

Yes, clarified in v2.

> > +# Now, add other parameters enabled in a similar way with GCC and Clan=
g.
>
> I think the "with" sounds strange, but I am not a native speaker.
> Perhaps "in a similar way with" -> "similarly in both"?

Sure, done in v2.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeD4CJheGP6D%2Bx5dzUc4ABRZz1Db0h7hNVmwH3gUC2zyg%40mail.gm=
ail.com.
