Return-Path: <kasan-dev+bncBCT4XGV33UIBBJXC5OUQMGQESCZJGKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EC0677D8C12
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 01:07:19 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-581fb70456csf1951202eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 16:07:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698361638; cv=pass;
        d=google.com; s=arc-20160816;
        b=XJV3SyZ8PiUYlGBeYwc3aqxTDWsJ0Sz7th4H2JwhHq5WiLRu8llKnpKoOfQj/qvQNO
         ykzT2+tBOOm0pF9tdD9MhzoMdimhRHr7J/6fnll+meg2p5zSIEHvqcthEJhl3Lgg7sGW
         WAl4Ht6o5xHXfKPJejjW9hNBKEdGalFfaUzq7n4k4/4pQpdsZNJAoWfKvhL+RsLUieyd
         SYxy7Esi51nh8bbWd57+te6VbkaeJcfhSRSP0bFjbHo47FeIJ802Y+kawav5SIGLSvwB
         B4L3qrnDf6k0SY+A+nYJ8CBdU0C5jy+SBnNlvUuTiZTtu7dDykjUXjpqA8zmX6C/0JWH
         lyIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=b6EZSJITA41CjT77VtowO2q1I7uiuIPaQG90zZM4ia0=;
        fh=cOQ/RXj7dNMPedby0PCUImeXNcaWu0+RPL0nONsmarU=;
        b=r/TmaLjSAZXkIbDFSnAO2R45FQObmJIReZsYrkZV6wHZspllYGirpyzWlJe4aGnVVP
         tynmNebXe/J5Fd9PFU8SrjYr0cCRC3ml3bK2umfMguqkY2+d+YeA1lAi4tPpQbgM5ldy
         xJk2WCxDCAEaL5RHfoBIaSmocq9LVOvDQySBzq7xyAb4il9+ivjcR8Ypxg0GK6+Trzjg
         8i0krVdt2nc/EJfIZ8u874rOc0mYUHbTmY0oHNGfGuiqn0VDciMF7npOr6Rg+IgjuA3n
         8FRj7458k3KlRDn700JI0ZDl42GbSpoVJAlALvXn/pGbhU0DWzuBl15pf9BUtG6f0iCu
         OwHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2n+WbG31;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698361638; x=1698966438; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b6EZSJITA41CjT77VtowO2q1I7uiuIPaQG90zZM4ia0=;
        b=JMHxaRlUyeBaZL8aeb33Kn/3VcRQuH4FqoSZwznquR9rgrt5umgJ1wLsREuELg+Ct2
         mvZ/q7cWCravLVD2EXw5q5QO5iA54O3qgFO01r5F7gxODSHgWkesoZgS5cA3YtfM2lRB
         arZ1jyjkOh5aKfqXhx6LXYP1DU7SVZAh/TO8K2pnl4sKJyuGFEoGY+1J8z2HxL1JiGbE
         3r747UjkJ7sWxst9XHPZFR2lz0ul/SzTTuRuvPnXMe8NJQOmc1VaW782s2odacOE6TLf
         oWDVVYwAHZL+gvOOpck5evzWXAuvCXS7XXWr+EYipfUH7IipAeWziDZMi9xN9ts1SW9j
         Ux0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698361638; x=1698966438;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b6EZSJITA41CjT77VtowO2q1I7uiuIPaQG90zZM4ia0=;
        b=qHZpynEnXqCR3c1n2abgnb6lxqb1SQ5HCC52HDIX1sYVBH4PhvNj5kWag9cVVtklkl
         ODIKJ2TlGgMxg8f9mDBh4KXplR77jHihsdh/sVPa9DsCbaRx+eJsOTUoBJnP67AmY2HV
         HnTUKJVFxi1eE9lCV5N3yKqma1Amd4Q6W9+TyAAwhB1yPtRwHwl5FAI3j2KRsyNB0sQM
         MR7Ib1V92HYFAX5/i2PksGIpWt41siEInjja2OE4ic+wbl8H72Ou6yNy+4jtVhmAP/TC
         LRwMI5ezfIr9/XRjeOgYKtMK8S/bEn3Me3BMB3/1+98UN7rBVFnIipzoQVJOVVvCnTt+
         rSbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx+Gu2xNGpthUL/PbRGngvZ/oPjkIcCImqb1xaTg8E5ImPBbfkr
	udebjMddoTLageePx+He9y8=
X-Google-Smtp-Source: AGHT+IEyCFUbtr0JYz3eg79XIRwKeMtZidYFkujogZChN6b7MPefDamsOIdNF1EKpgigQzwpuFchkQ==
X-Received: by 2002:a05:6358:78a:b0:168:fdab:44e8 with SMTP id n10-20020a056358078a00b00168fdab44e8mr1287805rwj.23.1698361638414;
        Thu, 26 Oct 2023 16:07:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fdc8:0:b0:656:3716:f1e6 with SMTP id g8-20020a0cfdc8000000b006563716f1e6ls503886qvs.0.-pod-prod-06-us;
 Thu, 26 Oct 2023 16:07:17 -0700 (PDT)
X-Received: by 2002:a05:6102:2003:b0:45a:b096:ec7d with SMTP id p3-20020a056102200300b0045ab096ec7dmr1253477vsr.26.1698361637514;
        Thu, 26 Oct 2023 16:07:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698361637; cv=none;
        d=google.com; s=arc-20160816;
        b=ZEU3DKTZbQfp9tin1mC726kAaP+ckgOeGMoj9ONvdKYvXAQOds4HgDUIL56IHVKOb2
         3BUequg2l2xGi7o0D9lit3dpC/7GcGB09eE2D8vkPIF3UVNI3wwCAYbzxpVM6bT/VqQ2
         zZ3SGvGjix6JdhIHQ7BwYanIzqX6cBNV8wmPx3ChbZ+P7ZswZq1EyigXLtmnUPmZdqQK
         5c7VGDnaHu5+fBz82gKlJPHaVAzKc6WhsAUzn6+SXP3Nm4s3tdPYSmoB4YBFigNqPtOG
         eZmC5SJ4ysBX2sHMFlw3R441CESUZnKDWTTB14PcwNq5Hfpol5HWtqyVJ0xqSraalx0V
         0VXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=iK4DkcO0WnV8Osd00AIsJ69gmRt1I4KgYpwc14bJ2+s=;
        fh=cOQ/RXj7dNMPedby0PCUImeXNcaWu0+RPL0nONsmarU=;
        b=Gavc3oJQkrNpia+VAaml4XqcMqDAAoVnNYjP/qC8SceyiMkh07ZI6V/uUlzO/RxNH0
         jZOPy7/jaYBGf3Y6vvlLQpmPXkQ5/PwZiLRHZGHv7Niakqx6pzqNVCLLWTDfnr6G3Cfj
         fcjJ/leII1ozQAvnFcb8w/k8BF2t44ySzMW6dNORk/waPmXKt1bXhMwtbS5y0g+6NRK1
         1dBHkbOlcBtU1kP3Avz6Pkdg4wyLSLCax3GvNXs2BTEXaPvb9so0Ess8/FCXK5HBujhh
         fi+U3uzutOoeQZKd6qcZpw8OXQXpOh5GCLd7Z1+m0f3vg3XaTgZxXOQEBkYKjIseP4yh
         dZ+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2n+WbG31;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c34-20020a0561023ca200b00450f3f7cd09si98045vsv.0.2023.10.26.16.07.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Oct 2023 16:07:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E9F6D62377;
	Thu, 26 Oct 2023 23:07:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4299FC433C8;
	Thu, 26 Oct 2023 23:07:16 +0000 (UTC)
Date: Thu, 26 Oct 2023 16:07:15 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, Oscar
 Salvador <osalvador@suse.de>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH] fix for
 "lib/stackdepot: allow users to evict stack traces"
Message-Id: <20231026160715.ea74f79dea9960b8ff46d077@linux-foundation.org>
In-Reply-To: <20231026223340.333159-1-andrey.konovalov@linux.dev>
References: <20231026223340.333159-1-andrey.konovalov@linux.dev>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=2n+WbG31;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 27 Oct 2023 00:33:40 +0200 andrey.konovalov@linux.dev wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Commit "lib/stackdepot: allow users to evict stack traces" adds another
> user for depot_fetch_stack, which holds a write lock. Thus, we need to
> update the lockdep annotation.
> 

We're at -rc7, which is rather late to be merging material such as this
patchset.  Please resend it all after -rc1 and include this fixup,
thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231026160715.ea74f79dea9960b8ff46d077%40linux-foundation.org.
