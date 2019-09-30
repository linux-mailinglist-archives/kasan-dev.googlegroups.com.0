Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBANJZLWAKGQEKBZZOLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 86B6AC2B16
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 01:49:22 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id y16sf12067601ybs.11
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 16:49:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569887361; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGEtgTgsFIl5R5JobTdUcL3SAijaKgCzqITScdrOy2jmf8f7aNMbEjteVPp0LPN/qz
         Wp5vj6B9ajay2qFIWF99Qle/iv7iwiEn5wewiWXnBQAKKW5Feu0yfQJXxHrVtPa5JV1g
         XUqO+6kkoXwSmclkQ+3Mp69wT/pfQg/Wa019FxPvTd0UKnsP4H2n7X1dUTPCM+6922wR
         cNs4Y+2HqOHlyjDRMnpZIFZqw/GIs17J03iuG3wnOl+weuPCmJ8wVp6F99w4OU5pzDYW
         bec7mSmH363MZ7gwNj36JTHVJgyqjWOB1qLGkPvOAHVleSA6gnZNCSsjl8DH7c12PC3Y
         XxVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=LcdxY79PZUOd7i6EAATUvQybFkVL2ZGo2t5Mp+hySuM=;
        b=JREtPa8ZU84ND2ypSW5SQN7W41mi2trEfRVLZrFGuzInH49PiCKHMhr/nWzknrBsGX
         e99ychavn6xx38HqJgb3UmKi+m5I/b0g1YvtVXIZ0qY4CZ6QSj4edFwQegCCa74sUAz+
         pjuwp27z44SXnsbwAXWZqxk52mVrfiaGECIcFEtsqHXG3gS7eeQiHL37WzEq6QEGIzee
         nI8DowBXFAJ+DzE/C1ZjtcKY5P9zqLrzgL1vZsgoPaQqMDWW41nYXkziLGYfRThnKPiv
         mFWy0JbCS3tYt62+gJMFjBJIijs5rjiUUoMWcd2F7itS+YHmOtgT2kFhHIQzPAXLtAUK
         vAGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rQYI2urg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LcdxY79PZUOd7i6EAATUvQybFkVL2ZGo2t5Mp+hySuM=;
        b=NKYuafwlxZtb2JUWEIJWuZF6MI0Cre55azyAj9dDiKoLC5AHuEZzn8vOVHz1jMRUAL
         Xyif55o/J44MScjLoVz12+E9t8sHEkiiI4aP733HnIfBZ5VstoKlD94vgIIhkVLYxN0l
         wmE/IAyjrcOdN6nq7ZpPmwx1WDmrb1inQ8QVkmCLF2jvTL4AjtjaCyD3bN33nqZCDZps
         +Wla+LE0oxO/lzQYMJjr2lgZ3l+pIlPi9BGP8mtHo7qKhklDZPalUyuHTvhI2QG2pDFX
         qtkp8PYN5iqet9lJ+/w9whkJx3O5prcu4VIEreClcbMiXbPhxN0kJ10C/u0OaU9OszWs
         D7dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LcdxY79PZUOd7i6EAATUvQybFkVL2ZGo2t5Mp+hySuM=;
        b=PNlSMO6mo/d0MtOMNDG6MTleiebGrpwqqz6KILOpRUoZ3miuIBfx5N6uC3W59jyydj
         vZcOSTCtXFr2w7FIxH1qDanOFDiCu8UkMyOqfcAslv3MdANTwOsvXvWz/cv7+gQgNhi1
         itTLBcqinUe97m+jk0W46ZGM/e8ulhJ+FLbPzpenI1xdTAkC+FMCHbLkdmZ10H8BNANV
         Z8+CAk0yTcxtb4RHbC8lCvkTsw++FY/bqaUkip44Vdw+vrdHuZ6MWXKr7GBHv7taoACn
         KP/722d4xKRYXNEwDNeJWtoqszMkxiiyZODIuBSF3s0eMG33ONcv8vbOkQir9Nbt3q1z
         wjcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9jdS6HYRDYnsAp2cxDRzfTttNjfb+uXB6uMLrizlFWfWlEuAb
	5/ccNabDYQX2TVS6RO7IA5Q=
X-Google-Smtp-Source: APXvYqzRe+qwRJ/xUbsR6N5OgPKm0M4nBscwkiFQ53+O/n4uuByJZAdPWYFwKvHpbdhki6xjoWbrbg==
X-Received: by 2002:a25:b6c7:: with SMTP id f7mr15596986ybm.357.1569887361414;
        Mon, 30 Sep 2019 16:49:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:e81:: with SMTP id 123ls2042178ywo.15.gmail; Mon, 30 Sep
 2019 16:49:21 -0700 (PDT)
X-Received: by 2002:a81:fd5:: with SMTP id 204mr15609192ywp.396.1569887361102;
        Mon, 30 Sep 2019 16:49:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569887361; cv=none;
        d=google.com; s=arc-20160816;
        b=iNpOCFyg2MmPXB8LoxZuu1J0RAIupuS5redeUzV1JFb9cw50yZrcT4hUJxJTJZBTfG
         t3uVPvnTFTz9Lw9KKaJNft9pZVSIE+YCrdusRfEtIBJAQQUmBaDuIaGwOdETj510S6bb
         e314ihH24Ze+Azm9rb8Spu+kG0MjYQZJxCTbeB1GauGfBvKtMCZjfKV8gu3TyylQdV7W
         spm42ndFcJWKz7pFvKvciti8cM+tf9Ttc7EwiKBzUc2xbYuo0HOB/ue0KfveAA8mxPI7
         l3PI1pA6y+HpVQwEBFL9Is0kwC/+CL9ey1TxqhkeXD6ATbA8bY8YgPu7HLGiasQWTxJk
         bjxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=FCAEYzwQHp/oK53c+OOeDcXUXegqNanjk+gs1PbOM0c=;
        b=KyHK8omNlwD+ONd1gUDnsqhN6yCd0UFEayzhNX/M5NPFMZ+G4aQqNYsy9HlURx8/bF
         aN32nVDhoTLeyc9X7xq8qwJjOdN+dyhcvvvPi4UXdGUWnpjg+liQ9LkLJdG+1sPrff3L
         wpNsRo/eqO+NP7n0PiuqfQFhNcGxV3xrdku6A4gU987YzENZkBfNATd6SslhfkgwOTyk
         9FwI/aKmerBu1S+QeeA2myYy4PvOvn+kM5q3ZwUDUwZ7HXxdfITYiekGy9I1oeawI2kh
         8d3gGtp2ZPiVPQQOXPnJ/nUEK3JtkeF64nLI2KuUy12OAwyQ4jlk8zDF1/tHYZaCK3+0
         jL9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rQYI2urg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id n9si657149ybm.2.2019.09.30.16.49.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 16:49:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id n1so19317895qtp.8
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 16:49:21 -0700 (PDT)
X-Received: by 2002:ac8:74c4:: with SMTP id j4mr12159055qtr.360.1569887360676;
        Mon, 30 Sep 2019 16:49:20 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id j17sm10884571qta.0.2019.09.30.16.49.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 16:49:19 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from debug_pagealloc
Date: Mon, 30 Sep 2019 19:49:18 -0400
Message-Id: <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
In-Reply-To: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
To: Vlastimil Babka <vbabka@suse.cz>
X-Mailer: iPhone Mail (17A844)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=rQYI2urg;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
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



> On Sep 30, 2019, at 5:43 PM, Vlastimil Babka <vbabka@suse.cz> wrote:
>=20
> Well, my use case is shipping production kernels with CONFIG_PAGE_OWNER
> and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot-time
> enable only for troubleshooting a crash or memory leak, without a need
> to install a debug kernel. Things like static keys and page_ext
> allocations makes this possible without CPU and memory overhead when not
> boot-time enabled. I don't know too much about KASAN internals, but I
> assume it's not possible to use it that way on production kernels yet?

In that case, why can=E2=80=99t users just simply enable page_owner=3Don an=
d debug_pagealloc=3Don for troubleshooting? The later makes the kernel slow=
er, but I am not sure if it is worth optimization by adding a new parameter=
. There have already been quite a few MM-related kernel parameters that cou=
ld tidy up a bit in the future.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/731C4866-DF28-4C96-8EEE-5F22359501FE%40lca.pw.
