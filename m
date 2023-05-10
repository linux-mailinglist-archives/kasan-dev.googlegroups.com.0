Return-Path: <kasan-dev+bncBDA65OGK5ABRBUPC56RAMGQEFO4G6XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FE776FE488
	for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 21:32:35 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-52c219bf675sf4105050a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 12:32:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683747153; cv=pass;
        d=google.com; s=arc-20160816;
        b=iELzs0Hbipoxo5gz4KlHjvmLpxfuewgfkIIQU9JC+hA16rPbgjvga0UC+mSrc9pZ09
         6H84Adc+70QhE0Fke7tIbSNl6UW5IQuiYDPrRvBGBCP+B9CQvXUJwozmLSR1cCoWjsN9
         MXi5KtU/SCAeNboNsCFR28fQA0DuhPNFlxPYbwcOwp1qwL5JYpFHsKf0frbHmvoqJmHn
         Mbim+P2kAO4UZxsGO+vIs5KrI7qtrHa/HdppkMOF+DlUBgWE5Cii5clFMksB8C5ePB94
         lD5gc/KuVy2RSQ116+jknRwNbxVL3QMD7YRB6sZu0ztQ0a2BGBr2MJ6DTzqtjqYjz8k+
         Y+sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WU3fxMZ2tIHigEO6lA5GA/mukHVeJK8Mr9kzxeIPGyo=;
        b=p/gsNt9xOVeiraKtW6THMtsTA8Sw/HkkuGLEfEj17c9GX4Dra3XWpssjdanIh1jdA6
         gydgjuGHnV3O+KRpYd9m+5sGzLpOyCXb8zYnFLXstcyNBlxjNEtj9d2TAvl/X5xip4tc
         mkdOhmhzASTGHsDIcuPxzP0RacKbjm1ecMEl1OR+OGijUkMy6XS5KzRLAX1fXzSgwPzF
         96XEKt4BYFvimcmailVUcnkF07N3PFizBmKLsDz06O1PSEYIpeofS5ztEzzZ+UQpAoer
         NOwv31ml+A33KJ+O6ZRkAz1uamGq6ny1A2pn38yX42y0wpdoKqM/Eh/BTNH2kMlwgZ1O
         e7VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=EeA4kqbs;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683747153; x=1686339153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WU3fxMZ2tIHigEO6lA5GA/mukHVeJK8Mr9kzxeIPGyo=;
        b=FSAFbeL2rd/97kZzdPxlM9Fm4gXMH62h2Vk2sb4tLEelvYkJTb1IsQaD49mcsCel3a
         N7Zy1UAwj/hPzXv3YvnXQsEdw3AD+SF27M64Gai7yXNlz10tZsV3rjs/VrnpXA3ryHNS
         nLRcbvD4+rEky9M5uzbkjcLsDIxlWWw7PlyIjh+JugEo5iB6+Roc87LCwT+9tPkYU89s
         2H3tyg/A03xKlMykHUJDXfefw21KplGswpB/N5COw2Bnqq1W8eD5s6oOrodqR7cO4Dpt
         Ofxbf2VaW7VUKStZvHvJAegyn7HpbbDbDj5mKEewcSiIxnLVbw6iNpwnOhJBrpoF0XQq
         DQuQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683747153; x=1686339153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WU3fxMZ2tIHigEO6lA5GA/mukHVeJK8Mr9kzxeIPGyo=;
        b=ikj7jepldfxz+hlryTKepgSGCQJgdRCSmpMDp0Z4T+kAZq1o4e6ul3kW+4n6yDCNBG
         /TBV4wwyU3xa60K1xneMm+PUl2gdleNYxMF3Yy6k+5ppOQs7Exargg1smbyL5t+y0feu
         gGUrtA6J1Rb3Ct5Bq1UAPPwxunrTQJtwlZNihYFA78EymXb9f7ulasVL64hSVTb6oqIM
         SpZXPVIt2Xh/9AEvc1egznxF7fuDrKEt6o3XkYUV02LenYYGNVw+TgxHdzqeF+0NE/JQ
         rU0HbKgbr9pOeG1XbVT9GDlrlulLdtRLMcgeE7ux9eUbYQW48PN8nw9BVVELzg6cHsqw
         Vs8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683747153; x=1686339153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WU3fxMZ2tIHigEO6lA5GA/mukHVeJK8Mr9kzxeIPGyo=;
        b=fnjuAyYHJE+++fXn9ITfUPdyRq3j5X+zSVUdArFsYJ5v3OwjHalB4UcC4RMz5D3QMd
         D0zD139Mzo7vwm34VwnS6nh8ftO7/pNsQNPxpB9uny0eZdNJqe3q75XuL2jk2HVkDaa+
         IgS4UmEVbVQi/ctQ3DAwlSws7sv+8y+66wXZNtNHOFdLWgJNHOM1yuU/Z2Y9RcIdicSD
         uzH/kmyCE3j/rYtVy1QjwSgcgzqVCoMWeYFdW9NkvoUH3vQ+RrnP+AgjIDY4diWvczbr
         oCpqCbEl/z/E3q96AtAEPPHHK9jG7AYrvKME/AdQvT++rnV8MVftXBJb0rAvVz+NVTQe
         7WCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzYDrntQSXEnS3LsZ05dZ+RBRfcikV7ka9Ji1inB/tPVZaxfB4o
	5W0+lU0Q+ZPKJWlaXb/13VE=
X-Google-Smtp-Source: ACHHUZ4sL1+xraLJgzq+3kUPBl0Eyh753+qcbdFEgyY2tAgqjHfFN0Vue+yx5djAvXSivL5lUeAF4g==
X-Received: by 2002:a63:2e85:0:b0:520:b677:c64f with SMTP id bv127-20020a632e85000000b00520b677c64fmr5228497pgb.10.1683747153334;
        Wed, 10 May 2023 12:32:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:786:b0:1ac:40f7:8b66 with SMTP id
 kn6-20020a170903078600b001ac40f78b66ls8149208plb.4.-pod-prod-gmail; Wed, 10
 May 2023 12:32:32 -0700 (PDT)
X-Received: by 2002:a05:6a20:7fa3:b0:ef:f558:b76 with SMTP id d35-20020a056a207fa300b000eff5580b76mr23041940pzj.5.1683747152349;
        Wed, 10 May 2023 12:32:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683747152; cv=none;
        d=google.com; s=arc-20160816;
        b=rkNuLxmEsEBq2avIeLmDAd0SSvuDd62CqmJSRL59d986liOWQ4Bj9JZelMO/6qmI/G
         bpsa6KzafU7NhlZ5AFDjL4WdmvIHCCn2fqyAvhXwNfcvErydViqNwh1ldRehuh29KTzP
         pOQeiPrKwGRB5Xfc4OWd0WLMyyB3yVoStih0tc83FbwSZ7/nW/IYEDPZoOdxB9iX8soN
         9XGYnvgKJCWoIwTJIILUdEWuIgtlS4kAMURCZ67SkK6POSe1OS9ZPU3Z0CEpeZnzEWwS
         bFUPigE2McwULQXaKqybZRDMiMHJ+ijXYWGw5r4SiM7mVSCcmf+PWF20NqBRrQFMadWK
         W9YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ijF4JgZZ8UFh46m5QLshrYR4lf9mtf0Ki3Uhm/eh+mU=;
        b=DfRJD2N208S0gmmWS3bn6E/kSD2x8Wl/MDavER3jjQ6ENJEY3TU+NADS0/+DzFf4AU
         BRToB3b8rUwa2y2T5hQCveY3fe90BnxUlIr9lu9sfNrq3Y/pJcogPRjuaFvFBXewyQxk
         51AqFeV0Ic2T7/V3F4t75WND5Zkg3eC5RiV9ur/of0jqRSAnpOaC9R6aJLWZo/7y9Qnq
         A6CY62puWKZHt5KteRYiQb0kJh9RxGANWXUQujeXrbpwe/LC52UewHXDMlQQgudoQsoD
         cumigAvSETPkUfGkN0ctp7s4BsSezoQuR3okrZvy18DzopVJurJ+gVoCxyPBnl+Np5u+
         K71Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=EeA4kqbs;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id u18-20020a056a00099200b0063b655bf130si389644pfg.6.2023.05.10.12.32.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 May 2023 12:32:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-52cb78647ecso4236146a12.1
        for <kasan-dev@googlegroups.com>; Wed, 10 May 2023 12:32:32 -0700 (PDT)
X-Received: by 2002:a17:90a:a60d:b0:24e:2021:b410 with SMTP id
 c13-20020a17090aa60d00b0024e2021b410mr18111638pjq.14.1683747151922; Wed, 10
 May 2023 12:32:31 -0700 (PDT)
MIME-Version: 1.0
References: <20230508075507.1720950-1-gongruiqi1@huawei.com> <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
In-Reply-To: <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
From: Pedro Falcato <pedro.falcato@gmail.com>
Date: Wed, 10 May 2023 20:32:20 +0100
Message-ID: <CAKbZUD1vpgke_-9sijF5rwbHZ8dfcLfyNMCRYcoa4izsKmYNKQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: "GONG, Ruiqi" <gongruiqi1@huawei.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org, 
	Alexander Lobakin <aleksander.lobakin@intel.com>, kasan-dev@googlegroups.com, 
	Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Pekka Enberg <penberg@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pedro.falcato@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=EeA4kqbs;       spf=pass
 (google.com: domain of pedro.falcato@gmail.com designates 2607:f8b0:4864:20::534
 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;       dmarc=pass
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

On Wed, May 10, 2023 at 7:44=E2=80=AFPM Hyeonggon Yoo <42.hyeyoo@gmail.com>=
 wrote:
>
> On Mon, May 8, 2023 at 12:53=E2=80=AFAM GONG, Ruiqi <gongruiqi1@huawei.co=
m> wrote:
> >
> > When exploiting memory vulnerabilities, "heap spraying" is a common
> > technique targeting those related to dynamic memory allocation (i.e. th=
e
> > "heap"), and it plays an important role in a successful exploitation.
> > Basically, it is to overwrite the memory area of vulnerable object by
> > triggering allocation in other subsystems or modules and therefore
> > getting a reference to the targeted memory location. It's usable on
> > various types of vulnerablity including use after free (UAF), heap out-
> > of-bound write and etc.
> >
> > There are (at least) two reasons why the heap can be sprayed: 1) generi=
c
> > slab caches are shared among different subsystems and modules, and
> > 2) dedicated slab caches could be merged with the generic ones.
> > Currently these two factors cannot be prevented at a low cost: the firs=
t
> > one is a widely used memory allocation mechanism, and shutting down sla=
b
> > merging completely via `slub_nomerge` would be overkill.
> >
> > To efficiently prevent heap spraying, we propose the following approach=
:
> > to create multiple copies of generic slab caches that will never be
> > merged, and random one of them will be used at allocation. The random
> > selection is based on the address of code that calls `kmalloc()`, which
> > means it is static at runtime (rather than dynamically determined at
> > each time of allocation, which could be bypassed by repeatedly spraying
> > in brute force). In this way, the vulnerable object and memory allocate=
d
> > in other subsystems and modules will (most probably) be on different
> > slab caches, which prevents the object from being sprayed.
> >
> > The overhead of performance has been tested on a 40-core x86 server by
> > comparing the results of `perf bench all` between the kernels with and
> > without this patch based on the latest linux-next kernel, which shows
> > minor difference. A subset of benchmarks are listed below:
> >
>
> Please Cc maintainers/reviewers of corresponding subsystem in MAINTAINERS=
 file.
>
> I dont think adding a hardening feature by sacrificing one digit
> percent performance
> (and additional complexity) is worth. Heap spraying can only occur
> when the kernel contains
> security vulnerabilities, and if there is no known ways of performing
> such an attack,
> then we would simply be paying a consistent cost.
>

And does the kernel not contain security vulnerabilities? :v
This feature is opt-in and locked behind a CONFIG_ and the kernel most
certainly has security vulnerabilities.

So... I don't see why adding the hardening feature would be a bad
idea, barring it being a poor hardening feature, the patch being poor
or the complexity being overwhelming.

--=20
Pedro

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKbZUD1vpgke_-9sijF5rwbHZ8dfcLfyNMCRYcoa4izsKmYNKQ%40mail.gmail.=
com.
