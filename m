Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHN7V6SQMGQEE4NDP7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DDA8D74D3A5
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 12:38:22 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-345765b5b71sf31390575ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 03:38:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688985501; cv=pass;
        d=google.com; s=arc-20160816;
        b=cyhdIPIfq/wa5Z1qiKSv7q0PtCJ5SdT2PpND8UMmWIiip1I4jdOeKQQxRy9zIl9GYf
         V9CrrY/1B6n4kE3uUr1TxRv4Ry/dTgFO2YeV5oBdC85W8b+ryBLof/4Xjp3etTE1FzDy
         8qhd9e+w5MIU/7MTyWL0ZRLZA25nYrFG2uCyDDwJztny5GHWcPAJ2RFSyRj52BaXE9+L
         H9jatyolr83kW3MRRHKX27t4iEWGGeuyDEYDhud4Rd1AOr1WZNI3Za+7mEwyxU8Iarrv
         roLcwBCjTAs7xwFi3LXKTuYXLwMrD1QKE9UiFByZQDvXnxda7yKvokzOwUL0Cs+Y3P7L
         r1SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r7+RWWIwnQU5TR75GKEvQrzlADnc03Rkp6EfJFwwG5w=;
        fh=I3l6q8BZSEVVxw0ZZxCYQ0USDIQ5E58I2gGuaSqKBkM=;
        b=RkQG0WmdYG9dxW+pSX21j9bdx0e/LaRcRDYPIX/AW37ZQGu7g2r/F1iNkS6NypHUL/
         Z8p7JxT7nEyxrwM6gflWxjNqNI0QyvI2LmFxRamNjK/dHdP+J5+mZyl+fYPir7NQ7RS2
         yLhePYurb/9C7NjEjUfoDlMWQwYxtO2GXnLs11o9FYroEbBlGfOfW5tlWbJKda4aqYH5
         QzrvdcNucSm6oeS+SExx3NWt0zlyZkhjNrvOtEHsy/BmAsk7HEgqo1Jr0ysn52Y7wRx8
         9XJH4nzkfzbyIPG0lTIt4v8E+SKKX7kXX2h2br3cYFMl2pyQiaZEmEkfBQMk6HxkLCM2
         Z9iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZfeBuOSd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688985501; x=1691577501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r7+RWWIwnQU5TR75GKEvQrzlADnc03Rkp6EfJFwwG5w=;
        b=HglktAHkhA8awqKkIuOld0BvLjNCpA3gMBW+VQzZvzqmohpeVEv8QytEB9MoNQa0Zc
         wdeM7tzNfdOWQY0vh8OAQAoMYrGEM+RXLkBlHYd+FUDRKW0foMt+1Q8xHbU+/tFZfszj
         uXgRkDlIh/kvKVJDWhq/kqYNQj42ZXkiONUdA0SXEKI0vmMrK8kEvIyfIlrMlF+M5nrF
         QSML74HKIq4IL9Upv8Vh2sRaeFCAybQujmKlf37t8LkKuv4Z6Ab4M7xjhjliMzBh0Yxx
         yBVLquNSuA8VqmoIS3A16I875N/tCN18pz+blJctEccz2nzk/RL/5BTHr7oVzz9od1XP
         1p3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688985501; x=1691577501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=r7+RWWIwnQU5TR75GKEvQrzlADnc03Rkp6EfJFwwG5w=;
        b=bqcq5mUIPJjcihz7ZRzDIQPQ/nJVXPsav9uym7zafD8fm7hiqqPYwIL+rfpW/ufddp
         PydgKBjlW1bMiEmM6QzCoI0G391CC2LxJKvmrFxgRF2vgWgfvHAwOJSo8PM/6WMa6Hay
         wAtdj2ZgUgl6S9PB/z+u60kKo8tKsDg9ID4uiQpfU9hQ30gkjpDWl2/BvluDjBvg714D
         hF8xoWcUjKlcKj/HfRqWE0ywFh2ApNtrkXqi2KM+qf46F7gA3cB8n0URaPCXhkaJ3xz/
         t8mtdyVtma2zllwYSU6uZy58CJdQcuaEHHxRw0NnVf8i4dUeP/Hc1lL9FOlgA5oT13pW
         b4lw==
X-Gm-Message-State: ABy/qLaksIMMtmEjQsUCIBlVb+HHpWdQ/iDOreI2kHUwdw1wtPEZ2VhG
	JYEPhTFRlvJ943jHFAKrUKQ=
X-Google-Smtp-Source: APBJJlFU8YboHWJIZUNPbbZgAFErijB2u+GWHlNeXLgyMVVQiVgJGPfHN83iymXLn1xgb0JZFlwNCw==
X-Received: by 2002:a92:d4d1:0:b0:346:4c75:a8b5 with SMTP id o17-20020a92d4d1000000b003464c75a8b5mr7361215ilm.15.1688985501332;
        Mon, 10 Jul 2023 03:38:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d07:b0:342:1e3b:783b with SMTP id
 i7-20020a056e021d0700b003421e3b783bls374324ila.1.-pod-prod-08-us; Mon, 10 Jul
 2023 03:38:20 -0700 (PDT)
X-Received: by 2002:a92:cec9:0:b0:340:aac2:6908 with SMTP id z9-20020a92cec9000000b00340aac26908mr10909105ilq.2.1688985500785;
        Mon, 10 Jul 2023 03:38:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688985500; cv=none;
        d=google.com; s=arc-20160816;
        b=ZVUQqzW/N/nmFfAeqcWWRAtxZ1V4j0jDeuVUkpC/BD80FdIKUvnjzStb5HCWgPR3P4
         5GFXqIbUTO4n24sodpkXF5k403byN8s90gska0GN/qEWRzTS/WgWplIFIwsr8W2DZIkJ
         fOFDLvCHdLjj5YeMqhIuoa6IkS24ySaGuQgBuy6hUExMmXvBq/BHaBPwhijHWee3LRMH
         17L0KUUupGZVtX6hgNNxebqgtscsdJ7VfSNMmAlXP9tyYyjNJFUYkK+G4H0U9Kky4xk0
         BMIGfJZMQPcyLTwOkq3A0B0a0+/2Uz3MPNWr+cqxec7aVsaNc7UeFoGS20Ybnw1f+sqG
         hpEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hvz04yJSt5agLndtywybtJHsB7jWS+1+gKVSsWWw8q8=;
        fh=I8TlVEBf2o11jnannDJ3ln3x0DL8glxwIDqILfWRWdA=;
        b=Zz9j7hNPQVSLnzl2FtsywkRndGql21aOPjy5SJYhQSlQHdqG/o4DvKhbrp4Y4Cknse
         lZt6To5HD2TPCSDpARD0Vng9nJ8ILSWlVXmracJf5UCy32twRJufTeQvSTp1zfEqTwvj
         Ut4Tnzdd5jZPpVs052WS6cpPXoBbFZ3mVZnMH4JUg7I3ntaP7pMktYg8hS26GFA4MkpH
         rGpqB30CcfCIMJGFSW/BELER9ETO6HWGBE0QxNAfI+G8YhI2OviKENUmlkWNrasV4MAT
         ICRYd7wZtC3Aogn89OFq/i0V1aYQ2gu8jUA1EReLt9Q6JBsDol11m1AkUKdZhE29GvCL
         f81A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZfeBuOSd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id j27-20020a056e02219b00b0034201149242si585380ila.4.2023.07.10.03.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jul 2023 03:38:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-785ccf19489so215001839f.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Jul 2023 03:38:20 -0700 (PDT)
X-Received: by 2002:a5d:9448:0:b0:783:65ba:8614 with SMTP id
 x8-20020a5d9448000000b0078365ba8614mr11099647ior.10.1688985500443; Mon, 10
 Jul 2023 03:38:20 -0700 (PDT)
MIME-Version: 1.0
References: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Jul 2023 12:37:44 +0200
Message-ID: <CAG_fn=XH8s8JbMKjsyyw_FZhLuoBqAwWU_+hCGyAXwe3wTBCWQ@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: allocate kfence_metadata at runtime
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	muchun.song@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ZfeBuOSd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as
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

On Mon, Jul 10, 2023 at 5:27=E2=80=AFAM 'Peng Zhang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> kfence_metadata is currently a static array. For the purpose of
> allocating scalable __kfence_pool, we first change it to runtime
> allocation of metadata. Since the size of an object of kfence_metadata
> is 1160 bytes, we can save at least 72 pages (with default 256 objects)
> without enabling kfence.
>
> Below is the numbers obtained in qemu (with default 256 objects).
> before: Memory: 8134692K/8388080K available (3668K bss)
> after: Memory: 8136740K/8388080K available (1620K bss)
> More than expected, it saves 2MB memory.

Do you have an understanding of where these 2MB come from?
According to your calculations (which seem valid) the gain should be
290K, so either 2MB is irrelevant to your change (then these numbers
should be omitted), or there's some hidden cost that we do not know
about.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXH8s8JbMKjsyyw_FZhLuoBqAwWU_%2BhCGyAXwe3wTBCWQ%40mail.gm=
ail.com.
