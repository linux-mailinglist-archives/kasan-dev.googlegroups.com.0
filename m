Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLHYXOTQMGQE2AIKSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49A6478D3E7
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 10:22:05 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-63d1695e445sf66327966d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 01:22:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693383724; cv=pass;
        d=google.com; s=arc-20160816;
        b=MW9gPShXrquAE2EmXR4Vq5ZaTiaF9sO3FgWLzCEB62tPFQBiYl2ZMutvkVZba4RDiQ
         HtgDpaT7vsYvNHAoysbkWF6xSrFdL626kbi5i/gxDzm/x8g7otiHqYPpWNCa1vXqfQu1
         nI9FyEA9I4uD2AcckeFKdJP6ZXv1U7N1CZakhq/VDPK6V0+0tK+jSyEVlzAowpdFGf8X
         wODKIeInkWt/je7fZrywqo4YBEOCGZTYuwy+VoRnXIK312lqYjapltGMKDRWPcImi1bL
         Mp9SLsIQVZ3XK4CEPLRhz+TT3ls+mOLTK+xB3Y094vRqFmHjXNfxzhfXcY1i3UfKa6Aa
         KPDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hEaJPAt27NV80N5gHZXE/xZg7Q0nxDzn4P6gdAxK8Mw=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=Z14yoV5M8kElYRKP56FMLFDhi8yJmnkcLuzkxCGepMeSRBphnjGuMGYdTBnhNph5Rd
         pRZLlNH79B3/9v2oMNIPElNHWiGjIZ9IygSoHM6TNMbNhew7G6bRVSA8MNwZ0ckRkA/u
         ZARwL/1pdRdVpUfZNkfE/QXkVNjEr/cp7pdAcmP6y8Hv/mFVCJSTtISuNK+VydQE7e3i
         3QvhyDfc7Nfez3JMvZqPCXfFXe7kTSuggAb2/+OwwUjkoGmdzidIC19IC6SL593Br+Wo
         YAGpT9EVU69iPuNsGPOkYtRxeLdQZyOhnWleiJEUqJQsVFYBrXJIwSNiwiWG02WBl1Ss
         Kdqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=KbQmUSgH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693383724; x=1693988524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hEaJPAt27NV80N5gHZXE/xZg7Q0nxDzn4P6gdAxK8Mw=;
        b=MuOA/vIrtog/zWLTmkDyl9r0L6DkHe13+sqLl5WdbxPCM5SWiyHobAvzEI39GH9IA1
         Jozaf/NFMAw9sZYjMtdshS5Rnc7S8spbb5ph/bLfD/xicLGcRdav24XwRLihFgzm8bN4
         1BEULPwDqpo6125g1Ib1rAjg18EiDkE4epCY7crDdY7VBeBKTHp9WEqakxTTFfs3fEtG
         hmXz5YHKoJzsZpwgl7ZH6l7TaKzhB1Kj4I4kaA7dIVYY6hJsZ19A64rDf45OfDM5/Ana
         hMty9csXLuHIpTZ5V/1nZe7pjqe7JnzxfcVWVUH2OaoK6fPPXUXQa9YMgrqeDene7mdU
         KMqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693383724; x=1693988524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hEaJPAt27NV80N5gHZXE/xZg7Q0nxDzn4P6gdAxK8Mw=;
        b=FfNfZoyRzozICTxQSlMec7hpFv4MX4bXAf221d3Rq+UthdSDDz47dnivvGd0Am0YfE
         NNy9cEzixTEmZBvwc2yPP8gy2rurXVA/+UU/0m103P9WJzRJHzSbWMwhD5h7mQpnnG53
         yEFxa/bJ2Q55xUaUokOvtRrTFi2FPDsQvO4ksfuyPfLvYvlnbR4+zjNT4SBqv6upczu2
         FMf9TybVBEutra4UjebsAhVJCwQQ47cGxbn7+tH/AijB7Pb0eGJDqzJCOlw65RpWqcgH
         BLDf4vUyPdCAgVOYH/BbDqacBLf1JfScDowHfuDT8Nps3HGAt6CnVoS59g1/xZ0jxVe/
         VvmA==
X-Gm-Message-State: AOJu0Yw5Lrsejw0XcK3oRGho7e8Ci7vfM8Ib/YzovamnnjVtf0nht5PK
	7R1iTQDq12hl1Sc2BGdwppQ=
X-Google-Smtp-Source: AGHT+IEfMvikTi2Xlnot9+Xb1WXNaIF3+51f+pZQV6uebpsH9CncIwaAIswPuuKaICplwFwXxPvZmQ==
X-Received: by 2002:a0c:b406:0:b0:647:16e7:c5c8 with SMTP id u6-20020a0cb406000000b0064716e7c5c8mr1300477qve.11.1693383724156;
        Wed, 30 Aug 2023 01:22:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e0cd:0:b0:649:bc7:cfe4 with SMTP id x13-20020a0ce0cd000000b006490bc7cfe4ls1566115qvk.0.-pod-prod-04-us;
 Wed, 30 Aug 2023 01:22:03 -0700 (PDT)
X-Received: by 2002:a1f:d985:0:b0:48c:f9e9:51a8 with SMTP id q127-20020a1fd985000000b0048cf9e951a8mr1543465vkg.9.1693383723062;
        Wed, 30 Aug 2023 01:22:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693383723; cv=none;
        d=google.com; s=arc-20160816;
        b=W7awxEabmjjym3+pULc7NEx2W9LHMYEblzJ0stV2qc6zoO951oBBIUmK6QiS+1s9Sr
         0r4GMPD96Ihb7VohEc7QI+RN63P2sZ3xluznDJyntwTBtVXUjhlXN2ZYEeC60jwcA7MK
         mOBHjAAIRknN54N0NFCu3QDgDQRoCGt3G4W041HR0twy6bj5+tRG0w0I44U8b51xP3tF
         ZfkJnAIm1gHGoR7cvpLUTEEfh2BiCB1yZWQOAIuJSc+LjNOL592zlr8rNMurQWJ5m7Ng
         Yc1sz1Q6Ayf585tMAFSUoIntoVAES0p0W1dTC9XIjvoAFaEtFpLK71RR5N+9Ajd2fwYA
         +trQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G5yOmmGKLBMpPD+EhNoomatQprH2d72p73RqEVWw00Q=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=i2Ut02Gpsi3/z/PRgAcbeuXPDWujhogRnI+b4bCigXQkANhIIs0HE15Sfe22wrytcM
         2R++XhIAaIKbF4kqw50l7zva8PQGEOuXbQnE6jHrmqjhPbLKcid+7rgqROUGoQpsovA7
         P5QMn+9/mMZ5Cpfn/dascCDJ6WeZTSZuIwZzkrZo23vzfXwfz/cMZPOD7YVzmG/0ByfW
         zJmklwuk7OMHTNDWEl3Ca+rMbwBlN/mvDRgu+p6u5nLTGVxSCxz/EnfzM+RzFlr8fU5v
         uKGg4EXeaPOZo1RdFHCxH7ZrlZblGDi9BAFet+4f7n1mkgX00GwoH+ji2/GF5XdGgEzn
         k+YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=KbQmUSgH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id q195-20020a1ff2cc000000b0048d29aa0861si1687822vkh.1.2023.08.30.01.22.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 01:22:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id ca18e2360f4ac-792979d4cb5so126846439f.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 01:22:03 -0700 (PDT)
X-Received: by 2002:a6b:7901:0:b0:783:3899:e1d0 with SMTP id
 i1-20020a6b7901000000b007833899e1d0mr1456114iop.6.1693383722341; Wed, 30 Aug
 2023 01:22:02 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <89c2f64120a7dd6b2255a9a281603359a50cf6f7.1693328501.git.andreyknvl@google.com>
In-Reply-To: <89c2f64120a7dd6b2255a9a281603359a50cf6f7.1693328501.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Aug 2023 10:21:25 +0200
Message-ID: <CAG_fn=WsYH8iwHCGsoBRL9BRM-uzKJ3+RDgrB5DEGVJKLPagVw@mail.gmail.com>
Subject: Re: [PATCH 05/15] stackdepot: use fixed-sized slots for stack records
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=KbQmUSgH;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2e as
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

On Tue, Aug 29, 2023 at 7:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Instead of storing stack records in stack depot pools one right after
> another, use 32-frame-sized slots.

I am slightly concerned about the KMSAN use case here, which defines
KMSAN_STACK_DEPTH to 64.
I don't have a comprehensive stack depth breakdown, but a quick poking
around syzkaller.appspot.com shows several cases where the stacks are
actually longer than 32 frames.
Can you add a config parameter for the stack depth instead of
mandating 32 frames everywhere?

As a side note, kmsan_internal_chain_origin()
(https://elixir.bootlin.com/linux/latest/source/mm/kmsan/core.c#L214)
creates small 3-frame records in the stack depot to link two stacks
together, which will add unnecessary stackdepot pressure.
But this can be fixed by storing both the new stack trace and the link
to the old stack trace in the same record.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWsYH8iwHCGsoBRL9BRM-uzKJ3%2BRDgrB5DEGVJKLPagVw%40mail.gm=
ail.com.
