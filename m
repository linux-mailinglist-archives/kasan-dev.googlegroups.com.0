Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBW67R7ZAKGQED6HD3ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A69C15A92F
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 13:30:20 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id i67sf1462021ilf.5
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 04:30:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581510619; cv=pass;
        d=google.com; s=arc-20160816;
        b=aKDQITGig7kuhBdYdMk6DGhGJ5wsurLI5Dj1iR+7fWy1v78RwId1MijGSWW/Md8Fo2
         bR0HQyhkQQyzXndJz40V60vFPWu9BPfI1JDeufPjlBDJ1QR1abouFfe8Y8VvaBKhRQ02
         PZA2nriJHD7BN+O9SBnlA9hF3zHPJRb36F96SCFVOmpCBDMmq/mL0pe1epc9OJ3vJdjf
         D1xSwc3xVMIdOHt9VO+d+lU0NndSe30Dd+dpw1rLJVB/xhBJTg36+0vNy4cHeWskd8/w
         GvDnEIF7KZN4pn4y/TQAunQ+madQl2ja0kqhtm8PKIwOM+RzHiWUHkkRDYdenK10uBTw
         poXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=VHw+A81EMstYVQXW+Lo6lzPhJwwNElSMNt5Mqkws8Xs=;
        b=FfXb06534VJvklirI7fz4JbHLHHimW1pbT0IRmmjQiHmYydu5pvRF+WvtE3vfie0NP
         dTFxpE6rqrvafCdOBhDhHYrKved0Gh1MB7WZhc92+raCEtyoLEUr7g/YfCB9svTxKEgU
         U/XwvRln4MBlpmV6OaTqYwOyF8pQGEODeb0n21u0u/5dkjljN2Uj1Qk79qdCOww7hu12
         yWuDk8ebbpx25Y0HbCLeqtBS91wZECOMUQa+2SCI73bRhnSsNpo0jdZvQEyNRxzpjyof
         q0nj6q7PnekdNOPQHqmZDY8dWrZJAvrKjNwZPBPbbEX3OTOEr0t6RC2eCn1QbDBGAy2N
         GuAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=JsRbV06q;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VHw+A81EMstYVQXW+Lo6lzPhJwwNElSMNt5Mqkws8Xs=;
        b=WE34gxc38KYJZiufwO7bp+Q5geChNINN+rlqwAnGF5sraWdMqYmAjf2kcT4aoW/61B
         8IcIvoGo3Q9/5B8mg5aVIrGpyvQ1DH4I9xj672+JO//JCHDCVSod1OSH29fdRTui9Vn5
         cXZZsr11XqVLSt3Zcx3HuXuFNTG3bAxN9zGkYS5PnZaIR0lq+qlwdBYK+HtdEFbvSJ7W
         umMJpafWGrl2dhBb19JstPb8J1KCIDkX8cv9OcbZ8dyrJZjZ0/rzSaHh5a2/Jr4fW933
         LtdzIl66MivCh7aIXFZB67GrmdueVnE6DRqmIrbak7/Ji2MWjAuiVU2QBw7kLQTNYvmC
         DkNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VHw+A81EMstYVQXW+Lo6lzPhJwwNElSMNt5Mqkws8Xs=;
        b=Ran5HqOlge51s+UQQoHtJBb32Sf9sEbqpHb4zyTuO1yi83FXm79T1AC8PRD0K1kXgZ
         GEgX2m3FJzejdzBwBuSymDmfbbdC6IG/KIm7i6za4iF8HvvDYOxVc4JdkMKCdFHOU20k
         HKq5otWFuVQeMSCSSEFslC0WpPmEf0d3cDIHoVKfqDzflArcMakr03oiooCBcKuohCDT
         ruRrRHCWlG5AH5NtBKhEGQRMMSYimGlgl917myd4E5q6v1nS4wx7YIjBdfLLBA+smv7y
         GMZZjjEulk46qW+1/37jqYo81l6pdcPPuJgb0UPSC3kCYRkoEsKnmdpuqmN34e9hWqj1
         EmWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXpPhcxDt7vdQgO407GCGpbdlml4YgT19rnAfi7bLGFVvQrTsXs
	ZZccahJs4WpXlQxxl2Do2Vk=
X-Google-Smtp-Source: APXvYqzj17gv0MoaA4SBP92vmtwIvru18BPSQVxBHe0tfFdrMVFdVwsupFcc0YQ5jAZV0bad4YeWiQ==
X-Received: by 2002:a92:d610:: with SMTP id w16mr10556149ilm.283.1581510619180;
        Wed, 12 Feb 2020 04:30:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5d90:: with SMTP id e16ls3619290ilg.4.gmail; Wed, 12 Feb
 2020 04:30:18 -0800 (PST)
X-Received: by 2002:a92:50a:: with SMTP id q10mr11393417ile.294.1581510618766;
        Wed, 12 Feb 2020 04:30:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581510618; cv=none;
        d=google.com; s=arc-20160816;
        b=n0CWvdcQznZzL7W17Xs72BIiDnQD3r/Na7HvKmh5eudhXWalyVCSaB8wYV8Dgts/hS
         lFO/umn66ivX9ruvREMvc7MeTp2fP/L7+6NJ5oO0/iSZgXj/37MAPSl5mMlJn7wZHORy
         yi9VqMMK2cz9i+Hi2OqcAYwETZzMu2HC1o3h4h4b+RTQfu9QUjd1HO/VmmRCPKN7LL84
         28s68iOBEAgpLddSwFsurKJ+1j4MEi8LmXpfNATXVMsDc/7Jl2l5Pb/9rH/Slc26APIy
         PcSE8junmTSqWHJpNeJHhtWgAsWEI5cszGtvVqM0oUmP92N9L7tO/gJgYveUfe0wl1cx
         /xVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=2YAAi82KRVa7ktUoT85C9ZCSdgpeOgvdOFNrlRCdrz8=;
        b=fJUBEoH6Wo65Ar30sg6CcclF9uVCCz2Idk1AKTVxVVmWWGD/jLL+GzyEFCwIrSYnyj
         L6CDR0jlqK1eXtwZIBqZzrg4IJjTNLptOi8mRRSyRLV8J3WTd496XhRavxlRLZn/pTaL
         CmVgEGgjsooVh1wu9M/DTvaG8m7kQ+HmlFUAxeT0kz70+R9v9KZaVj5F8dw7X/0d7mLq
         pb0VuNOg2vXOBZPmU99l3jYFsyeMiQyfYDO1ZO8zbOz6rWPwHcMcbHGvpDhwwFfgnXD4
         B3OUaZlnk7XgoxibJMOW1pqd/AIAZfL1OZ2CVthrolptPAaob7VOO5GJRCoK172wtNpR
         MA4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=JsRbV06q;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id k9si21538ili.4.2020.02.12.04.30.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 04:30:18 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id c20so1857652qkm.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 04:30:18 -0800 (PST)
X-Received: by 2002:a05:620a:122a:: with SMTP id v10mr6440245qkj.79.1581510617666;
        Wed, 12 Feb 2020 04:30:17 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 65sm41786qtf.95.2020.02.12.04.30.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 04:30:17 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
Date: Wed, 12 Feb 2020 07:30:16 -0500
Message-Id: <ED2B665D-CF42-45BD-B476-523E3549F127@lca.pw>
References: <CANpmjNOWzWB2GgJiZx7c96qoy-e+BDFUx9zYr+1hZS1SUS7LBQ@mail.gmail.com>
Cc: John Hubbard <jhubbard@nvidia.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>
In-Reply-To: <CANpmjNOWzWB2GgJiZx7c96qoy-e+BDFUx9zYr+1hZS1SUS7LBQ@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=JsRbV06q;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Feb 12, 2020, at 5:57 AM, Marco Elver <elver@google.com> wrote:
>=20
> KCSAN is currently in -rcu (kcsan branch has the latest version),
> -tip, and -next.

It would like be nice to at least have this patchset can be applied against=
 the linux-next, so I can try it a spin.

Maybe a better question to Paul if he could push all the latest kcsan code =
base to linux-next soon since we are now past the merging window. I also no=
ticed some data races in rcu but only found out some of them had already be=
en fixed in rcu tree but not in linux-next.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ED2B665D-CF42-45BD-B476-523E3549F127%40lca.pw.
