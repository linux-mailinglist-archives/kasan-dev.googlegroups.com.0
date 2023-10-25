Return-Path: <kasan-dev+bncBDW2JDUY5AORBGOW4WUQMGQEGDNL65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C81C17D7430
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 21:23:07 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-6b74afe92dbsf62921b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 12:23:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698261786; cv=pass;
        d=google.com; s=arc-20160816;
        b=MsIBsFhgwb2MDbpnNyaECwV3L9pfKf/Du+B7QGohGkYFVKrXIR1gJ2ip6QqtjpIyhx
         mjjnP26CgphzmXSqGZ8oWjIapmEcMq6nm+A5Tqm9Bl1zs/MDSXVeM+/io7GTA+wosi9o
         YbGUsC1ghxbX1NIxKyeXxEd/6icr0JZvADYlRF4DHYgXlT5T9cSI398uzfUkOUo1amvX
         52syOVTaMcXlMG5UgSrr+Tdbpl541PfbFZR7KB9crpIkFVFXhOHcP58T/YHemLxlB6bx
         Va8tlhXcSdRJ1h/F4JezQvnr38KadnJKBeCiZFQo44wiIdvNVpxOd3hYbm91EcFyzv6M
         Frow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=5N3rJZNMW0sbIBGnidtd2R7AeJl/8WiL478jqxj7oxU=;
        fh=bXbkd7/+5kCLj5YiCl0KGrLGKDjHOrZ79PVvPym773w=;
        b=k2xAv7yn6nPNIGfX7eKpvmCiOodoqFT0GVSyypNiDbYf61U2jgb8wjWwa2XLsEAJhb
         JcOUPdp8GSji52kEw8hSJHHCd9QQF7lpvnxpFfsycOJbJ1AC75fEzX1kkqXmYbpnmBae
         xH6uhM/+O1rp+952jIOXOmTNaNZh0SIqq3GNk/80TRczBDWdtu8JHIgSypHlO/jLjdaK
         5M0NgSHIMftQ0sdF/Tlm6Lt5bsmouOxPzF7DVumQezsB4HhmxUdkdhcAuGksI//Gdw94
         mmJozBFwn6FpIyadVWKslyfa6sJkEVG9b4HWG+TjUCFymzzqwUU0abkZQb3pjYPq7es9
         Wdfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NM7B1MTe;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698261786; x=1698866586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5N3rJZNMW0sbIBGnidtd2R7AeJl/8WiL478jqxj7oxU=;
        b=xgNOIJptOdeviLBn1bi5ASaSbh6CzaIVXnUZZ5lzIx60O++lIGMcTT7ETAhmRQ34Xk
         05mHcqDqtDzdepQpD0GpXoSNLhpWJeJQvgVUZqEPIp8QX9nqludxTc3SUBvP8Q8/hX+E
         Uvvo1o3fL6DsDZfQJSPd3QP5XKY6ppwJhpyVvDBCQ3Wt0X2ctpNpuvVA4ZvlUTOSv0pw
         NlU0IGRp8VV/GONoKQO+FAz/Y053WMPWicKVhk7oIJ+mnZnVeXgZfxDYgJtOJ1oRxlI2
         fpSG1BLc5cc82BbDugDd6lblWcK/QMk0FNGOZNvXdlKScUxN7qbvx8CWHMrBasswbhQ8
         wdCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698261786; x=1698866586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5N3rJZNMW0sbIBGnidtd2R7AeJl/8WiL478jqxj7oxU=;
        b=dyMbMo0e92bkBlZN0rYhJYLKvpOL8jc2dxtytIWqPfX5N4wFtRnnFx80g3AnwAOaU+
         IQEAknppRgu8ATZAPjaRX+FREW+HKeBksG30NEmbf7WreaFI6CVezBWJYLrv1/AuYbXO
         8uIgRxZtaCCWano1wnQPrhBIkGFtKCOjmn8G1Yv7zJ7/7JvkxS0zeiOCMANHkAvz3yBr
         2+7GEBVsUHstI4J597F0sEpJenbtLESPgX1weyPbxLsAwGd3cJ8gqStgiM4cIBIXq0WC
         f8etILswCfqy4r9Ekeu63bb8OFMPM4B30nZh2N9MSQqK8vmq6e1MRMXE3AOxiVt0RfLo
         6IBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698261786; x=1698866586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5N3rJZNMW0sbIBGnidtd2R7AeJl/8WiL478jqxj7oxU=;
        b=Eu4y+Qiyc6vk6KjH/R1pAzIbyORAmQUQlKMvjByfzD6sEtHdUCzstHTk9OfxuscHfI
         FKN3FlvlkQSVCifwv/gWw5iIQP7LZPr0zkN2Y9O83nslEfY2IKp0I1s4IF2r1xQpBHr4
         IM4GHNgxt86Urp5HUj12qk2ZLHIS339bW4ayzF0RK99nPlfCnfCTLMn0eyvygHbs3w4s
         B830fzFa0dWGDpyqPiZ1fMSPWltsClJiQFettIucZnCn9feWULdws6UKskWtqVAPaGO+
         iYsuQU1Bc7Dn0C7Adrb8LJ+F9LVgXMVng/quYRyaa4avsKn3SMcnK4h0L8OWLDBcjiKi
         7EnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy6Pl5TfpUt+VOmsm8Vj4bRmI4SyekG+IHbmedhinszOpL8EPQb
	LkMAy1lVBEcRcrb4FzDkIRooXg==
X-Google-Smtp-Source: AGHT+IGsZ1q+upi9Y/e/0grEdHUrg8cO3ESliCJnM79XkXDUK3eQQALaNEi0sLup4+qIRMd2qFrxqQ==
X-Received: by 2002:a05:6a00:2295:b0:6bd:66ce:21d4 with SMTP id f21-20020a056a00229500b006bd66ce21d4mr15555430pfe.23.1698261785962;
        Wed, 25 Oct 2023 12:23:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d8b:b0:690:d40b:b5d9 with SMTP id
 z11-20020a056a001d8b00b00690d40bb5d9ls3121761pfw.2.-pod-prod-09-us; Wed, 25
 Oct 2023 12:23:05 -0700 (PDT)
X-Received: by 2002:a05:6a20:6a1f:b0:17c:c278:bcb8 with SMTP id p31-20020a056a206a1f00b0017cc278bcb8mr6938134pzk.39.1698261784839;
        Wed, 25 Oct 2023 12:23:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698261784; cv=none;
        d=google.com; s=arc-20160816;
        b=xlJT1H9p+Zd8/eVPtEM6LSi/HkjaeOomK6VT9R8B6o4MZScweuppVxD3KDdYMSQPeE
         /QyKVaaZXrrFY5ilXsnGbHJ8kKcJXYyMoDG9LYyEkcG+tl3roAMX5U2AlIPfAIU2jIpf
         eHRMiMQDNBEQnVEOsnAPctfIJUkUv5ij0JFt+AJ0AbcPS9MhCh24tthCB1O0xUE5piMw
         hgmBRHPBKG38NKgba6c77yiUzvZPdqYKCy89MUc5gmZTClC6wtRBDhbqnwJXhDcKwuSf
         Tw+l7l5tutHj89Gh7SQ3dBMwku4RHnqp9n6PvkP4EQyTH/yljzgF0yo362GlQV0bOoOO
         HgPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m31BwFRcj7ARX8+GTG5pwS7sZOyZiRPn3jP/pVTMYz0=;
        fh=bXbkd7/+5kCLj5YiCl0KGrLGKDjHOrZ79PVvPym773w=;
        b=g362BTUTYVk4u+sw3py5vBoLZWIHoDxEWZtM2PYiWfe5hwdEXOlkjVuZxuAxtU/rKI
         88ed+CCpClweEgNul7tRwL7jS2l/TveWxgZl6oL88eBqgtpGHPw9oNFLLfgtI3FQtIEb
         FRfeDEOWLaknmO1cVYMnWF2/52v6x7X+l0q9KLXSayA+R9xZYiinn32nMq8EuyGEG7TO
         Ecdy4svspkhTKud4tLb0J/ckt+BgnvgsgrYDWSZlBiKRN7vuIeHB0TnaQrdTW4XcelO5
         XY4/G2NbLwmsX2uPQq8hCWwb3sjL1tu8qpwv0r9P5VKhEami5B02luyAqcxCO3pVdZws
         WsGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NM7B1MTe;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id t1-20020a63dd01000000b00573f7777b2esi1068407pgg.2.2023.10.25.12.23.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Oct 2023 12:23:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-27d329a704bso54037a91.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Oct 2023 12:23:04 -0700 (PDT)
X-Received: by 2002:a17:90b:1b49:b0:27d:4513:9c99 with SMTP id
 nv9-20020a17090b1b4900b0027d45139c99mr14243752pjb.17.1698261784445; Wed, 25
 Oct 2023 12:23:04 -0700 (PDT)
MIME-Version: 1.0
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 25 Oct 2023 21:22:53 +0200
Message-ID: <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN report
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-kernel-mentees@lists.linuxfoundation.org" <linux-kernel-mentees@lists.linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NM7B1MTe;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a
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

On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@outlook.=
com> wrote:
>
> The idea came from the bug I was fixing recently,
> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
>
> This bug is caused by subtle race condition, where the data structure
> is freed early on another CPU, resulting in use-after-free.
>
> Like this bug, some of the use-after-free bugs are caused by race
> condition, but it is not easy to quickly conclude that the cause of the
> use-after-free is race condition if only looking at the stack trace.
>
> I did not think this use-after-free was caused by race condition at the
> beginning, it took me some time to read the source code carefully and
> think about it to determine that it was caused by race condition.
>
> By adding timestamps for Allocation, Free, and Error to the KASAN
> report, it will be much easier to determine if use-after-free is
> caused by race condition.

An alternative would be to add the CPU number to the alloc/free stack
traces. Something like:

Allocated by task 42 on CPU 2:
(stack trace)

The bad access stack trace already prints the CPU number.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfn0RnnhifNxctrUaLEptE%3Dz9L%3De3BY_8tRH2UXZWAO6Q%40mail.=
gmail.com.
