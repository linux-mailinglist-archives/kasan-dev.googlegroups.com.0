Return-Path: <kasan-dev+bncBD63B2HX4EPBBQHNYT7AKGQEEW5QJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id F172A2D4C1C
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 21:42:41 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id z4sf1862283pgr.22
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 12:42:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607546560; cv=pass;
        d=google.com; s=arc-20160816;
        b=WUG7RnqVUJ6fmWCJF5nemXHTA2enD0bSDGRFPF2Qk8bDLAXhXkH+t0V+tZzVAK++wO
         vYwrmn6XXwiAjaTt//wJOTCqPaoM+3BExa+p1G+LUBI/iIEU1gAqjO0KFDwJrnfLlR6t
         iYC64wcvKTtOl5GifZH8g6vDJXNQ72hVhl27WRIoRJB1L0xFDGCpcFFVAccJCDIPr2fq
         P1UQAlCpJ5F0D9fEaEHVC+5EcjG9RYwxOhfHAfF0p5I7Zfl5klE0NdRDlKzMpsh8G0X/
         XgZqzvgVPmvomVGGhtCsbAy1waeJsJ3nMjKklsF4HUdV0H3QSFCAmnWEFnfj6y3EYrRF
         yLbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=lri1lsdEfhuK9re8HRBNoJHB9FNvYycMZHyypxjLz6E=;
        b=j+/yTN99bNqOIgVhEn1dsqnBKut4pRiCdoV3We4BlshMsId+0pz2hPoR70BSGnKv9K
         zTJ+Jyrao9i+oT/HTeVveGCA+w1AUr/FoRfN4U/bCkmdZ1yoHyZk0eI+FQ+1Eut3Sh61
         ef2LAIgoGCfQmCeki1887m7PH1rI+D1fjSsBqMpIsW7Ggi5Rb1WSCkgN0c+gTYwE972X
         W4krMRdlWFjnPzKhta45vEVyqt9adLuKyD/OPwlELjj9rvOHopQ0L8rmf4r8gVp+i6+3
         sGIX+vN01qxbLeI81HDGBOoCdMT5sNxd59s0GhQs4tMuqR7Fb/grIq4WQ0cvoPNqA4gt
         kbkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=KBZI6xtP;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lri1lsdEfhuK9re8HRBNoJHB9FNvYycMZHyypxjLz6E=;
        b=iHx+j3wYZJ3Kv4LbsN6uri2yOJyfBmdjlzIGaJnVjvMoMkjiBmJg3Ap+g6nYL+jaZD
         KVWPDhmuZnjF4cQ6yln9yxj4KxDDUpjm+0csj5iTshJtKRmoGeJVeHO2pz72FtTPG2sX
         yRPW8JT6uCg7dApQ7rYYMl8NiCeEeJobHPHdDW5MmqaVc4I2spRExH2PBt6soNGfro1z
         XWnf2itRMUOfzdMh5GiKuom43VId3GmrY9p/nZ6FpV9MO+AxhViDhdtQmaKHG0sbg+DC
         IV2aVw861DYqjSDG2c0Mcc7CFoOinqyrGVD7dWH1kyMxD+J1oNm37YQB+iMcxpTC+UEt
         Nd2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lri1lsdEfhuK9re8HRBNoJHB9FNvYycMZHyypxjLz6E=;
        b=dfafW+i00z6Ouu2UYh6MDLL583dWnbRZJNt9PnFsW3Tml5cYa7rX9xraVPNU74H3Te
         BN/8gMMkwNPZSdpv3PJUVPc9n+XHEVrWHelQeezMOINK0IuYhMewmDPN9LGK4Bew98Ew
         bCkuBgYTeFU7jJ2SRv6C9eAI0nmPrSdxCI5MdUy+b/k4GpDyVi7SDdMDI6QxvRHWwx5p
         OCaPKCajuyWq2mR3BMMzU2ORX3OyP0wH2Dn89yxIVLQgQgAbaTM/i8cdtRwgWuCgn4ES
         4qmNtstIun5SybwNca0OV1D6sn91IgZroKvBK3ZATrVSYpZMRe8tEvYx6zg4ZomM4JYG
         u5Ig==
X-Gm-Message-State: AOAM530aRnpL0lQtxoWHcGY9VJfBLIf/JvxlIcTWJqEMOPme3z0Aal+u
	qPRgSJr8bHkKFlkG+BdYwcA=
X-Google-Smtp-Source: ABdhPJz9n1enS39x/y7ezj4w6SuKy4jF5aG2+7dgndKSbhuj6u2KvJ1qkTtAcuiqRanjKc2zzK5wjA==
X-Received: by 2002:a17:902:8b8c:b029:d8:de6f:ed35 with SMTP id ay12-20020a1709028b8cb02900d8de6fed35mr3584108plb.36.1607546560764;
        Wed, 09 Dec 2020 12:42:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc47:: with SMTP id t7ls1435152pjv.2.gmail; Wed, 09
 Dec 2020 12:42:40 -0800 (PST)
X-Received: by 2002:a17:902:9690:b029:d9:c94a:339 with SMTP id n16-20020a1709029690b02900d9c94a0339mr3669516plp.27.1607546560217;
        Wed, 09 Dec 2020 12:42:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607546560; cv=none;
        d=google.com; s=arc-20160816;
        b=g6zyp2Wz7WFC5o4ZEL2LKGZ5kRfD3bOnq6fZiWJLjwptdlnSEgYsBvSyftxA0bLrcv
         PQ5dAWhcJ48LYnJFo4ruURLBPOPBSboFtAXZfvVlHMg4x6p5muBww+pe74pJYU5YVA2y
         LqRzR0S3LzFJ0QeFGJ2oh7ePD2sD7ZY+ZsBKhuMFRDUmRYAn8a7+W0gbKQl7T2OliosN
         rx0WfdN0cqad1dnRybdlPTN7hDxcplIR7QP5YyX40iHdubs8JXNGbUo3UGAJFHaY5Jid
         gJsfIgK1AYj3QrTP0OrZQFF8LeXO2EVzjc+h8btSZUuSKMcf3uVbRTsW7/R/aci+N4J9
         rgFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=S+ZkYYBViMMpajd0wpOQiRkZQXnA9nIEudbBG/1qCWY=;
        b=OlUaZCX8TSEKp0cxGv3wQPPy2h0SKfSW/E9tKBmp63YQwaLj4mvmTQZbZEOXN96O0W
         8MuWKpWLDlesbRL11ezFWthjOJZR7GR8L4UzBLAE/eIjkApKe9FRx2FRPaj+jPvjekJ8
         qdHS6t6CW+Q3h3OJB7Yta/JWMp5VC7x3od/eO2nKWjRMNCULo9Qdev+qWXhvnSkQad2I
         kiOe0WSBUrQOruf6q/6Er8+hg6Iot4oNW5Pl32df/a0S9AF9C5YoYNtf2SBCtx0jXMX7
         ZbQBa5fyGABw2BL/lF5q8QOBz7FbGDssKxtJqIG3RpF0qcepfonh5DgKC5wc3LGVroTr
         HpzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=KBZI6xtP;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id k14si223062plk.3.2020.12.09.12.42.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 12:42:40 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id w4so1989683pgg.13
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 12:42:40 -0800 (PST)
X-Received: by 2002:a63:5748:: with SMTP id h8mr3507091pgm.24.1607546559946;
        Wed, 09 Dec 2020 12:42:39 -0800 (PST)
Received: from cork (dyndsl-091-248-061-095.ewe-ip-backbone.de. [91.248.61.95])
        by smtp.gmail.com with ESMTPSA id d4sm2951952pjz.28.2020.12.09.12.42.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Dec 2020 12:42:37 -0800 (PST)
Date: Wed, 9 Dec 2020 12:42:33 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201209204233.GD2526461@cork>
References: <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
 <20201209201038.GC2526461@cork>
 <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=KBZI6xtP;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Wed, Dec 09, 2020 at 09:30:54PM +0100, Marco Elver wrote:
>=20
> It still doesn't change the fact we probably couldn't get a dynamic
> branch past reviewers. ;-)

Is that true?  For the CONFIG_KFENCE=3Dn case, there would be no
performance change.

Anyway, since you have to deal with them, I should let you make those
decisions as well.  I can disagree in the privacy of my local patch. :)

J=C3=B6rn

--
Why do we need to pay scientists when we make the best shoes in the world?
-- Silvio Berlusconi

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201209204233.GD2526461%40cork.
