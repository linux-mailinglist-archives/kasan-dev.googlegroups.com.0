Return-Path: <kasan-dev+bncBDW2JDUY5AORBOOM3CTQMGQEKHZ43EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id F396C791D62
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:47:22 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-64f5aeb8388sf17258856d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:47:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853242; cv=pass;
        d=google.com; s=arc-20160816;
        b=09JRHd4+WhSB2sdJFZrq6vhbdbvp2crn6IrqnavbSL6gQ5iV2RMFrQ75tuUUJl+LSj
         /iPwe5DxZqVT0hPXS/cmGeCVIa81cJxNT9+MGZRz3yqe+tiNf+3KdfPhkOpY+lLzHAuT
         avVurEpDx3NCm+VSvi5f7Fcupzo3Ous193ynVgQWKqrlyAUV+dqnflAD3eEOm65XYw6A
         p8ZVbxUo1aHONQbbbmgOv7w9GfO+SjdeQWO8l8B8KCyt1jntg9ROJkve9VukYfy4DnBz
         9JkxhW72E2lu9Soc46pcw8OCxKWKeXhSM1QsAZiM+TRoV315qLS3ladByVL1d+CMOF7N
         dmrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=1IBOfunXxpGb+yJWxkpRMVv3Qwe/nOiisN3wEGaCozI=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=NyVk7vD6qr48uDXAh8ZER0AuMj3oIdDhAFrbFMw0+USY+Ykka8CnCTs1oymhaLamBT
         lWGf7lVX1ITZYLAcIQL2vaESTXhcmMkXscRvdKqGS119zqtahAQ9VoioWAsCj+CGUOJf
         DsYhLORWBVpNTLHDa1UHxGC/CzVX/MV0EEeQkjomsYYoGK7qqtTGCBUDmsAzq7volUh+
         KLRze5Y/SWefJ9PMrPyg4Es/z5YmSqSvn6s0bWg5c2n0arc2w/wdIOiBkiQsaeRw+Xvi
         XOyLwPKQcu7vBkf2BXIjM/LwcIbozJOGaV+7PI++40rQ/Gg8UQ/GswN7Y98f0OXI5GPI
         n4gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=WEuc7Ue4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853242; x=1694458042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1IBOfunXxpGb+yJWxkpRMVv3Qwe/nOiisN3wEGaCozI=;
        b=tA2OtIb+6yX6FvixT9lhuyLoYMRLMEqIml8zjiRuNVcQYTiG3uh+HjY5Ksax9Ba5DJ
         0pKVk/giHoXY9jICgYZBWSHZTdcPwcA+nZn63/Z6Bb6Vott3xJL08fJTJL3GH+tkQRTd
         oMup5bug+N+tpvldONjVsT98iFEwjcaHSjO2m/f+Mze1jdtae3mwtkvsBGknUGkL9j1Q
         6ZwfBWdPN0s2EUWUMIp4MAjOG25hf/tNmVnPbMNqun16SHqu87/ocjFCotc7w0+P2wzq
         UF2PewsAyVRcF066dOCCvzz9hL1Tx1xLVDDQbN9TMjXwxqf096WLpGKad+FNgJVyi4Cj
         oNvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853242; x=1694458042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1IBOfunXxpGb+yJWxkpRMVv3Qwe/nOiisN3wEGaCozI=;
        b=C/sFvLAt0G1bINFdz/yOR0Iyr428818sGNr7Cj+wjY3ACFASk9/+RlOX4nrBP5vA6K
         KaWvx+fpjGAHHvrA88jjgUQv/sgPvZiq1/BMc3ZRmlO/5qZn2Q5B92sdI3SCyd6Qbm1p
         O19oURekfKvzxe3hE58xgqDN0ij8zFPUbOhAGnT1ywFC8MtgcKkL7LzmM2/F7q5TjE0U
         28nCgPQYTLrAL2SFW65sWa4beg88KkkG7fXx1Pz7i57nTp58yj73LTFl6hkqSo6/GzzV
         ZqsFX+TD6SbRRqGZBKK/EgBiZzmHZ6dmCuTsvnKB7PghlKA5yMUaAAGOase/sCEcSPvu
         lnIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853242; x=1694458042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1IBOfunXxpGb+yJWxkpRMVv3Qwe/nOiisN3wEGaCozI=;
        b=mB8wIQkG3GrIqMNnqVctfszw/sUeByfEDUINN/C5ZN1SPLTdhuRhM05GWQiV+zzUt1
         iW8EECp4Pv6oRD3slUbC0faIjVtX/Dx7InS8atdsSBZXKydpD/pax0wyybjk7p1KQ897
         uqHrkotJM6tALMy/ILZT5b7utUezwvEDiuokkwtWe7wbkfzNIwJLDhw0mYSg23y8a4KD
         qqCIojwX9fxCvl4Cx0QyjgYp4AOyoe/uz09XoigHJJAuuuPmuMeFLsGZSMEWsnuWFK7q
         NYsVNYNZy6kv6clsWBxfA++3msfltXQg6Iw6EVS7bo3jqh4lV46IKQuV4r+ZsGwjDSXy
         X4sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy46bwXxjs/F5loZbj8OLVtpKbOUKk6eqvWUAN7Mxb/0O1Qmwl1
	TAI0+1bYffAcciaLND3nLWo=
X-Google-Smtp-Source: AGHT+IFnOxaDCRPLPFu+9Kf6jW/u7aNAB6TZBDp59fBxLgf303zBlEH0pz14Qizl6ILCucvxwGBP5A==
X-Received: by 2002:a0c:da8d:0:b0:64f:4253:f3ea with SMTP id z13-20020a0cda8d000000b0064f4253f3eamr11780684qvj.55.1693853241887;
        Mon, 04 Sep 2023 11:47:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e2c9:0:b0:647:1993:92c1 with SMTP id t9-20020a0ce2c9000000b00647199392c1ls4011990qvl.1.-pod-prod-01-us;
 Mon, 04 Sep 2023 11:47:21 -0700 (PDT)
X-Received: by 2002:a05:6102:3bd1:b0:44d:4aa1:9d3f with SMTP id a17-20020a0561023bd100b0044d4aa19d3fmr8828445vsv.4.1693853241179;
        Mon, 04 Sep 2023 11:47:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853241; cv=none;
        d=google.com; s=arc-20160816;
        b=QrzJufta3Aa/c//dx125IEgLYqG++6sfCduxiqLp1HyDEd2rj+cw2ghY1Plwm5Jfgi
         v01W2qdyv2pFrQZx3iqewndzmCDf7lBWRajmuOVLAlMz86Y7xAjq1AGsiQViQWGI+IFL
         36899J8RNSg2EuPnMlIHAxabiwUwlq7RyCwm67unaHFwvcKcbssx3BrRga0FUPsr14bO
         ClEORf6iysc/GaML+w8h1G1s423lD0KdcLgYA1FWA6whnoL6itiTcW7gRzwlhthGSOZY
         3XqCkus3yIzmLhkjgb4MSg1xcFPSkZZovUmpxDGg+zR8Dr2o1H1ck9WSU+QZtgY/8BF3
         ZS7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3eom3OuBdDLG8xLYbovI7UUXs/0ndjlGbg2m40m7XFI=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=GB7UoRvJyBbnv1HqCu0h5wNNmuGAyaAf9OazJ0OiYmWAe/WkgqyiyIuUedAup1XVcZ
         Q7gn7KbkdMDHguE1Xvp+sjYzCRj3HF02ccV2H8w9+GYUFg9hQyc6n0bl3vnKN+Ik2S6V
         ekrIQWrHxQZlS5ppsawMc4OIEnDaYLi5/xFYYzRU3SWYSDxC6u1mXbT2Ii+JK8T5PiDC
         SE2DyPvggfDFLq4+iKR2yafMpU2iYQaETdyo7aCeczQkFaC9xtEFL3lyUxQJQlvADEta
         uPGnOp2/DMEKh7ZEl5ptCPnV7wZF5nVo+dvHU2PAT7X4SujVcnWWWswiE2aJs9zsdcvT
         7H0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=WEuc7Ue4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id l22-20020ab03d96000000b007a5003d1b38si1488864uac.1.2023.09.04.11.47.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:47:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-26d5970cd28so918562a91.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:47:21 -0700 (PDT)
X-Received: by 2002:a17:90a:53a6:b0:269:621e:a673 with SMTP id
 y35-20020a17090a53a600b00269621ea673mr7908690pjh.1.1693853240128; Mon, 04 Sep
 2023 11:47:20 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <99cd7ac4a312e86c768b933332364272b9e3fb40.1693328501.git.andreyknvl@google.com>
 <ZO8Jwy5SAgkrQ5Qz@elver.google.com>
In-Reply-To: <ZO8Jwy5SAgkrQ5Qz@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:47:09 +0200
Message-ID: <CA+fCnZcwftJtROmUzhvqczxHvCxTEUmhoONPXPzX23OWMNm_Kg@mail.gmail.com>
Subject: Re: [PATCH 14/15] stackdepot: allow users to evict stack traces
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=WEuc7Ue4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1031
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

On Wed, Aug 30, 2023 at 11:20=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> > +/**
> > + * stack_depot_evict - Drop a reference to a stack trace from stack de=
pot
> > + *
> > + * @handle:  Stack depot handle returned from stack_depot_save()
> > + *
> > + * The stack trace gets fully removed from stack depot once all refere=
nces
>
> "gets fully removed" -> "is evicted" ?
>
> > + * to it has been dropped (once the number of stack_depot_evict calls =
matches
>
> "has been" -> "have been"

Will fix both in v2. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcwftJtROmUzhvqczxHvCxTEUmhoONPXPzX23OWMNm_Kg%40mail.gmai=
l.com.
