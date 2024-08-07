Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBE4OZ62QMGQEE45CRAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6749694B051
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 21:12:20 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-428c2fbf95esf1331735e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 12:12:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723057940; cv=pass;
        d=google.com; s=arc-20160816;
        b=tFxNRMc21lLlBDCZOg61uHvKkt8Xm6tkNPAdNdYt+iqFNlToIu7+6panU8h6NVUm82
         Rvh31xCQ4u1ymSr2iVmFx2OW0GiwzcuUReO2W6Mcj3pPggEKz505Wt4gJp8jQcYeH4jH
         ysCSwGKlFuHIrEVqPseLwuv6kwlP5jJQZzH64AyDe5RoG+vgJL9XFjuev0wtrBmohF2B
         id+0yfnYmcUah/6HO3wopEJNEBd4YmsJmMLnaIe8Emu0/qMb4eZSfTOfXELziqY+wGGa
         86zK3uZatxFEQ7NWABp++wTK960zmpzMWsKeGL3IzmJl8fdT8Pw8VV00ujAQgAktXBg2
         Uw9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H1Lw7+JojLX3+XgK7Q6zRm7vGOo7H2cRz4aUrPhVlO0=;
        fh=oMCSBhuGVaYc6HWwnJodZE3doBc1TJffIdUwTnvwWaQ=;
        b=EAAdc5Y2P6LOiXPFtqTXIUkGTXQ0/tLdaGrG2ro8myPFHua7DOmZjwYMRG45iLn0CN
         30pijMg8jn+npAtYDxy84tyCAe5CXPHWVzVP7rPavy/fl8MmDuVpga/DA7+hyJagcTuI
         qOIrxTtOKjVOsR8aJp+BfHEbjMMJfMDoihYuelImrljTDRVMMxD+/schfP20L8C1RmNj
         rxt/Iat1pDoscDb3+RVFjqx6DdAJtRaNM9cTtu7X1TZqV6IvaI7fd8+mj5NbbCJdZ945
         KqE8mttMnHb/CTZWANNK3LIMCZTlqJZlp7+1W6vx7pv/SLxC9w3TpseF+cZnXkY0g0Lg
         p7Ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PbsyaRIP;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723057940; x=1723662740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H1Lw7+JojLX3+XgK7Q6zRm7vGOo7H2cRz4aUrPhVlO0=;
        b=ZSZM/NYBzMK7r3G4hmLyXVLrMvRZmG6MaYt8NNeFKFgDqx2NoXk1SaycjkawIQhfRt
         40BMzFr3VKkVmnVyIO6/9qrnsX8tG4yul7HD5IpLzd3ryBnLqAAkhxh2evcEyl7UgohR
         Nf1syQIGHOiNUxYeyH/O+Q/2em2nyevTfH3XMGuYvIIjakusN7ieqbluhJ89uc0ZIibv
         n60qoUt/haXcBnMYaUKoyUMo/ineoY4qW4PSJDvGvSLVDwx2aH+pmrB1XVBtOH6BtJ/y
         NYKiMHBJArIShrwiyDUi2cP4xJUR+noURX9FxoujjwMWawhKpDnOOsatmOwONMZQEZW4
         Zq0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723057940; x=1723662740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=H1Lw7+JojLX3+XgK7Q6zRm7vGOo7H2cRz4aUrPhVlO0=;
        b=UA8ruEBPNjQm3fxY2oK3EfHnc9kR1UrnOCmPogVFneXwK16z41s5lQHXVB9qrL+JqC
         QIzvYo3i4uvL0fafdqhtA0f6XXgklf4GfKHVH9JDzcwtoI0hqowsR0x2E4vTlNpsnn+b
         x6R5oT3Tn8YEkFkPyyTPEuixwoZ7wbY5LUehFejhjj3xOx3UIIsndOEpEFLCFUxvxwmJ
         WxQfimiKQ+/6d/ov3T/Yh2GIT9SLbKMVvDz8JmtF3IqOMPpHUpqG7iycGLoUhL4XsGkk
         q1aEFcsg+/13AndFksEAGLEKV6+duUOJZq6G8rp8VJX6vOqgFBAbRvGjv9hyFygTs6wM
         hCWg==
X-Forwarded-Encrypted: i=2; AJvYcCXcwfcb6wh06lw5Tm7hRy3kbhGOjB8k6vLjN90Em9/AKBZJ0z5uW2kUafBJoojXHNu4DYYM3veTlJVf/Z0iUw4Iy3sLg4Mx8Q==
X-Gm-Message-State: AOJu0Yxy0ALSQWhkaOGfLEf14icoMd3cOpzqAacPjX38R96fdhU3tQsi
	CqTaoZ8iRDcz0ubYVyfRGYk1egPSSqUWlMEVGI+gNCLZAgj9P9DE
X-Google-Smtp-Source: AGHT+IFETbbgH4oxp8Ruw8j5CaC/L3fa1xc8V7ZzT+AfjcwLKmE+3hJS6VF8dVFyT64UE9Q7oxbq4g==
X-Received: by 2002:a05:600c:3ca8:b0:426:5dde:627a with SMTP id 5b1f17b1804b1-428e6b7a333mr153558105e9.23.1723057939351;
        Wed, 07 Aug 2024 12:12:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:46c5:b0:425:68a1:9da9 with SMTP id
 5b1f17b1804b1-429091a1049ls606225e9.2.-pod-prod-09-eu; Wed, 07 Aug 2024
 12:12:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNubrf1fYnxQeR5ubNhydHZYVcRo7jAbA38COaO17dSxbT7duaiB9wLPIhNAZrlc+Ksh/Cl3r1tPjZ+gLtRnUHbwIPQjoYx8xGYA==
X-Received: by 2002:a05:600c:4452:b0:426:602d:a246 with SMTP id 5b1f17b1804b1-428e6b91a2bmr163162835e9.32.1723057937310;
        Wed, 07 Aug 2024 12:12:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723057937; cv=none;
        d=google.com; s=arc-20160816;
        b=0euoNTKzfndKXp2U98XK/nOpcvVJ0OPFho1ZBEE+2iabqUwuJ2BYqNd8EQ7WYIvYuP
         Vtnzd4AG4E4GU5pBbkUQY57uUXulEu8/a55XrR38PS5VOTzeYEb5CEbnBspSH8pYiu//
         TIYrf/WulfjgUuJb/prmZmD3H3J2LOpDLNj/lWeS2uhnMIdF+R8R3UQjZ0Nqli7/5D9I
         RV0TTblMW/5kGgpY4+sG4wsI1M7S4I+d61ipLURxONeKd+tbUsHfYspZmb6ZcEVIct7l
         X0vAR856kF+M37nt9BWhs2J2KFCX7zkKkWhDwYVJ/e77chnsefa4JqZo5opzFmVZqB6/
         mBnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2X2h9LiJJRq0WAJU7n+3LeTpaoc6WL6ZoTN7c5aELvE=;
        fh=zqcT6RkcDtWPZgN8Vl/IBj3J3L/UdU5ICfbXGy8Tl6M=;
        b=DrrYTzH2PSD3+5JZ56XOTg/9UWeqapsCk93LlCshzUDHOG6RNMkTjfNzoIb9Yd3V3K
         1Jx8b4HKGJGJCmhFitJRzgBrgkRB0bc0AqqlEz/h2vFnqy3qbw6zULDQDAoarhU+1Uja
         y5+o44vn1t/pO5ktv7EJrEpSAV+KKvd+gBjINVHWsy+F7e0xwNQsNBRo1SXNYlq+Nz8S
         SINpFc3ZERlw2zpsQ2ZPYoGD9HF/Yp6m85hOx5JB4uabtpK8Xj/h0AgAVk2As/DMRW/T
         xEmtdTFh78knTOUJmeipjCKChipCvKzJ8gY25PREjAB3O6d10RqVYbS5zK1PIFK0xvSJ
         y48A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PbsyaRIP;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429057ea2f7si1072295e9.1.2024.08.07.12.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 12:12:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so86a12.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 12:12:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX3ycSKktUdaOtkk6Z9iENhc0jr5ZxsNYjRB7XlAdec3HYj0ItzLC2cdcAPLkM+Ce/YPD8yBHfBHAWUElApaVCNb3Y6e0XpFrzVzw==
X-Received: by 2002:a05:6402:2791:b0:5b8:ccae:a8b8 with SMTP id
 4fb4d7f45d1cf-5bbb002ac3dmr19257a12.3.1723057935560; Wed, 07 Aug 2024
 12:12:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz> <20240807-b4-slab-kfree_rcu-destroy-v2-1-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-1-ea79102f428c@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 21:11:39 +0200
Message-ID: <CAG48ez1zR6+FxGFTT5=AmzLkwVSWfBDXsSOPs3pWW96ncZz+bg@mail.gmail.com>
Subject: Re: [PATCH v2 1/7] mm, slab: dissolve shutdown_cache() into its caller
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PbsyaRIP;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Aug 7, 2024 at 12:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> There's only one caller of shutdown_cache() so move the code into it.
> Preparatory patch for further changes, no functional change.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Jann Horn <jannh@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1zR6%2BFxGFTT5%3DAmzLkwVSWfBDXsSOPs3pWW96ncZz%2Bbg%40mail.=
gmail.com.
