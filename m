Return-Path: <kasan-dev+bncBDW2JDUY5AORBQVJWGZQMGQEXVB5R6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B70F908D79
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 16:33:44 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-35f18355552sf1119910f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 07:33:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718375620; cv=pass;
        d=google.com; s=arc-20160816;
        b=LaIu3qMrcBQAwtRD/X4ioBw4EZEBqcGxcBxW9jsBnW3cWVssxa5XcBk3CfANtiuQvT
         93Oi9rIafPYqWRDd3naw37lqnNtrXDhvQqOnFC7hqm0byQKTZHizhprTqZIHzJ4OXFqD
         zG2mSALRzYILlSsdtiTli+4lu4eyMDkbwt5xtkpGhZy5E3ht8vD5NFgbbxxmRJ7SCsLt
         X/1yC6TqNe5+0N+IvxzwHqvmwqbkYOi3A7/xd8BppfPl1E+LsHS1Yra/d4mbcSlA077l
         ZZ9lEQVNiSn9Afg4xJLslTF6f3D5KlF5+lKoa0BFR0IDhDp1dS1uLJq/AB9TeBKV0oTj
         PcIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WhDG3olrZ3kR6CGrqpBN7y6Ic9+nu3W3SDY1QaBP8aE=;
        fh=zETzlxOFefqRW0EvP31F+ES4IG/M3howexuQ3F2iG4U=;
        b=H35L7BnU/QxSpbj0fJc2AraIOPhnSNTxjCvB7N+BSqQt/F2wq5exi3h9GjP3KSoI1d
         f/9gvKsNR06pe4TDnDU/83vQE6NEjYVjHKzjgrKanahbK/A+o9J/uNDRHUJD+i2Z2IWF
         4DdctKBnZ6LEWB6pRLzMH/XYLqZ6v1ECIsi6Tm6kzjYdocZHTmnexYKVuF250Kun3Drp
         xv0CtpbvVdeAwR12f8qLDGRAa3BqcrbOQp6jRR7gTkUZ5pY3hWLfMn7nPuW7GCBGAclB
         U/26Ia1N2j2Obs4sQES57zFzGbboTh0ywkRHCNwOCWz60V2QLXsaJt2R6i0BcnzEqaar
         ySgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lMCweJ1m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718375620; x=1718980420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WhDG3olrZ3kR6CGrqpBN7y6Ic9+nu3W3SDY1QaBP8aE=;
        b=uuJQroLznAcJn/yQE4ausCbdZ++H5UK13UHlaRQZF/bAx/aO2cgwc/opsx95uS1irB
         LHo7i/waySRJJIKo9Xb+VsH5RKF9nQPttKBmU6WsbT+QFT37JUpVWQ0EomCuQXKQJNfo
         MtQ1AlqY9ExBKfYArh7i2nNO/ukGO+LDkh9SfBnCAI3rFOmeyigCnwNSoIUtcxkIPQdT
         KJCAZ6Ld9DFSIGGNzXuKZEZmClLu/+04ULfv/nGyvb9wu2FK+Jy7xYWe7UrsndnTmq9i
         RNQlCuPl3LaP7VceqABL4Zzc2HcGAW+ke2Uy0JrWbJPZaMVL3XaGQG/DH82a04orl8pc
         9NZg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718375620; x=1718980420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WhDG3olrZ3kR6CGrqpBN7y6Ic9+nu3W3SDY1QaBP8aE=;
        b=G0qeSIIFcaf57qgudeW9rFRGy7y6U7bWNIMwdg3NxFy9uGP201KFURPQApHiaIkd0R
         C325rpddIZfYBtAEzJI06CPBgInPKd+7xR/rRwTz19rf2EPG9PWwk5K+bHb4lITI7IWk
         SxmVX2keQ5jx3Ljovv9VxoiEiN2qssp0eWVCTrBEn7uRAWDwKxrkyfYybGTkhDDV5TdV
         PkKwk8isKnRsZ/FYJrTShq0GxG5uEk+8wN4GKxWeKRoXcu3aGj+z+z+iHC2WlR7GfYPt
         +K4Q4D9ei6gkHau70clNo8uDCuMNvFW4gAmPcUQ7LWmc14dgaVyfeSty9nUbPU7XJU/1
         nsEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718375620; x=1718980420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WhDG3olrZ3kR6CGrqpBN7y6Ic9+nu3W3SDY1QaBP8aE=;
        b=ZmwqGkF5g7JVJk3W0+o7KcLihWwKuwz/G10etrlaCevIAWCgYbCehIBCalbFNIX4L5
         FYRu1qC20wa5u1eucwfYiqj/y8YjOWRmIxaI3M0tWe9zrEI6bz3A1Hjdn1P5q3Zcpklr
         MPQhOAymdC0d8HixXJrdFWVWEjCRLSOrX8ASNis+0bkxOaWj4r33gZs9eTBgMRDBzScj
         mS8FtxC4cmvWicM8K2qfmtzwOVWKz3mu4fq0ENBeoD5ZbmnKO+PLDPvhjscKzEQMcXW4
         JVtJdoSrWIZ7vTZBwIpfPFP5cbzgK4BWbsfBd6m1zNXc3bFR0/Niuc5MC/RZW4Ue2EmF
         xNbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVF5ZNCeTD6Mb9pCJCmGa43lGtsEsjxpN9TImx9AaHbw8Gohoe02gZYrfi2UTq8xdcU+SGOue2jOu4ElCliytlZ5IiOoq9nWA==
X-Gm-Message-State: AOJu0YwMsiOD9lHn4Vyslaigp9qM09f9KDq/158Z4qWT4JxftxNa+9un
	YKO+W77Dx0DsIY6w1mnKn8MMQmjALH/0QYLJ+kTtFXhVpN8DJYBL
X-Google-Smtp-Source: AGHT+IHoYRltq3TPT/NgKT/bJL7hz3Zb3ezI00BUSUOfySgBbtq93d9pNgOeGCFYsGHPWV5Kmahtqw==
X-Received: by 2002:a5d:6da6:0:b0:360:83cd:ea2d with SMTP id ffacd0b85a97d-36083cded29mr1908326f8f.24.1718375618857;
        Fri, 14 Jun 2024 07:33:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4344:0:b0:35f:2b21:ddb5 with SMTP id ffacd0b85a97d-360718db9fels768895f8f.0.-pod-prod-03-eu;
 Fri, 14 Jun 2024 07:33:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjSAfYkkoMlRTDdI9f5hrDXivCLgJZu20rnYRrhoy+1uVePwZap32qEpaBPBavRmpkSY9sDjJDcN3xDQ6tTjBqo3QxvinIjj/BSg==
X-Received: by 2002:a5d:64c1:0:b0:360:8589:33f9 with SMTP id ffacd0b85a97d-36085893450mr1683479f8f.2.1718375617011;
        Fri, 14 Jun 2024 07:33:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718375616; cv=none;
        d=google.com; s=arc-20160816;
        b=fOTV4CH4psFJVDbSRJnVguF9zL8rcEpBH0qadjpvthPxwg1Bu86iPeB8Wmqptj8yrB
         E3Z+urt+plu5SPaCrfvZ6CyYKtd7DK0HH2TWq8aogJBjl0n9i9dJXVUgsU0ZuJwJYCU+
         Z9GIPBQAqTu3AbjWlas3uHSl8kR55uky/cKlPA8r+ywAKCbwdhsMzC3qmpo534wobQI2
         idhlqkUY917irzUIPFQ6/5pRzr62Io9IeJ3ckabVJY/jBqAMR3mMBFt4TK/4fepStZth
         c2rw43g8yr7g1uZTSJFXYEZ9kInAwSq61LtaDgjoZ4jdEeZOmGPzdjYovxmEf5foj92u
         0xJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B+tN6RHfXKiHus8eyH21GesugJVvgcyhoJB9y21e43Y=;
        fh=6R9hUrjUt1SN/DXamPdU48vtpwAL4Ex6jTZA6B5YQ1c=;
        b=w2uI6ZRSxXMmmx4cZZFS/dWFpamh3EFIQHmHkJ2AgM8bQlqrf1b/Pb+yg9h8jB6k3X
         bhG13945dO2Yl91hf8EYddPx/PCP7dxyAqZzhIt5IqoXDEaLtU5a+iELdBu3pRGFjyEN
         afLWUIcZM1xa2VaLfcrXFxcnZvIb1RZ+2oNse9KmLH2z3lo+o9cFgOpsp+byxEAyePjB
         Kq/n12WHU4EMcTzHWiNWfJ79JtCbMpm/z/TAFr0lQqfmsRnBu9ttEBrn5VJxmBdeq6Zo
         kwYSDiw6bjb5AJ0DLY9SUPKv32qsHHKFz4IZP+cH6oE7IieijU7tj4Mag+js4gbcczFj
         BN4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lMCweJ1m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-360750ee5d2si83428f8f.4.2024.06.14.07.33.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jun 2024 07:33:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-35f1c209842so1749851f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Jun 2024 07:33:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX45LhBwXMv0dGZx8ObUsz4ApXwivteaWmb2/uwmtNzbqGTaOvP1DPJoPafSssImPm7QeMK5e6g7CY37LtR9DqN5Yku61QNnz7Ycw==
X-Received: by 2002:a5d:43c2:0:b0:35f:444:8711 with SMTP id
 ffacd0b85a97d-3607a75eac1mr2347244f8f.42.1718375616322; Fri, 14 Jun 2024
 07:33:36 -0700 (PDT)
MIME-Version: 1.0
References: <20240614141640.59324-1-andrey.konovalov@linux.dev> <CANpmjNO0T-sooJYs2ZCAzFUs6NVkV7iacY=hzB0JtGAyKhEmzw@mail.gmail.com>
In-Reply-To: <CANpmjNO0T-sooJYs2ZCAzFUs6NVkV7iacY=hzB0JtGAyKhEmzw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 14 Jun 2024 16:33:25 +0200
Message-ID: <CA+fCnZfRtGNYw953NMm9s3JTsv6gNQJSbREcnbcUe6Zsgeh_6Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix bad call to unpoison_slab_object
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Brad Spengler <spender@grsecurity.net>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lMCweJ1m;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Jun 14, 2024 at 4:29=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Fri, 14 Jun 2024 at 16:16, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > Commit 29d7355a9d05 ("kasan: save alloc stack traces for mempool") mess=
ed
> > up one of the calls to unpoison_slab_object: the last two arguments are
> > supposed to be GFP flags and whether to init the object memory.
> >
> > Fix the call.
> >
> > Without this fix, unpoison_slab_object provides the object's size as
> > GFP flags to unpoison_slab_object, which can cause LOCKDEP reports
> > (and probably other issues).
> >
> > Fixes: 29d7355a9d05 ("kasan: save alloc stack traces for mempool")
> > Reported-by: Brad Spengler <spender@grsecurity.net>
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Oof.
>
> Acked-by: Marco Elver <elver@google.com>
>
> mm needs explicit Cc: stable, right? If so, we better add Cc: stable as w=
ell.

Makes sense, sent v2 with CC stable and a commit message fix.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfRtGNYw953NMm9s3JTsv6gNQJSbREcnbcUe6Zsgeh_6Q%40mail.gmai=
l.com.
