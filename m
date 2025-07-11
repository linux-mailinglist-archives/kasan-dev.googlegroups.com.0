Return-Path: <kasan-dev+bncBCS5D2F7IUIITSWFYMDBUBETMY3TO@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AEBCB02484
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 21:24:59 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-558fb43d03dsf2054153e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 12:24:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752261898; cv=pass;
        d=google.com; s=arc-20240605;
        b=Np1am3RhvLbR9QiWiNCjs5bxLLig3w+bFbxdAcjpvnb7VINad1NfYe9T3gQHyVxjAd
         Fg6agrXAzuW96MVT1/zHWGxgm8TYu2FSPG9x+03msD1oeXTGEau+TGOT8mlHf2f4QC2a
         X5S/GhSgh3npOv8omH1fAuEiVd9tU4DaMwdnQL4UFaZ4bLCd0HuqH58XPNN80eZU14OD
         zer7dzNTlHV9IsO7uAI6wIx99C1QrmhUss6kIljKK+MMvJSEL9gUcTItKDOKdsAe8MiI
         vZxxAV7RuZUlicF+sJ2L/VQ6JakXv9tPCW0JuEMZE4Pb+a3wQJEUvPCybk3I76fR+gcm
         FOEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dwhwk5q6iBt7zH5sNIJ0vy3h+0bgZ37s1rTTK03p6uU=;
        fh=NxwhP4roItkdT/8bL3TuP1cjvL7jWiCao1+QCBYThZU=;
        b=HcH8kKoDOmfVm1u669ymIDPG3Fnrk91Nr/axbVewGwwYFhO9Yf7Qp42v6Dpx0r4vc2
         RtQ5bYHFERBw/b0SOjpS8q/+uW4FuarqSHv0+e+C8GpVw8JqRPiiv4Y23baR+tO4Bxm7
         1CsnMORRjpnmXLBNFZVEhB3iu1B1VZpxhWGE53hC4Oltu/1rKq480DjqTkj0fuSUu65M
         OukWjebkeyM1WfSppqf/2J0z5vUgolbGdsl9f0BNiIi1AtSLS7FEiQzLWYotP3Dez8XC
         YCZyspE857qBpcMPG2wnb/zev7ySvDJWIdeZuis3onE+eKqzq3D2/pI60hOG7g6O2v77
         svyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QXOczNP4;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752261898; x=1752866698; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dwhwk5q6iBt7zH5sNIJ0vy3h+0bgZ37s1rTTK03p6uU=;
        b=B4z4BuVM9uUWPt+oq9S02ze2wwjSa1rqGFs91dRQqw088pBCEH+r/HrVjyMZSI8E/K
         IEtoTqMvtHoqNqlMRaPew0ytmavXdeHbRu52llFbEgQvhVJyQby22M55oYPpQwPNcjzr
         aa/sGC8Vb0mmwLZSv24efSiymeWy52ZE5qNlmpq1grPn7BhB4/NMLuNDZRxpUVBIyGXO
         8N6Xgoh+DaSg/w//r83X3/cqa7SDuVsp4TnTRiDaK/gYoLXZw+leN6AwrfkpPjz0p7aN
         jw6lQPQ7c0CESTHIRjMHVAbyrqPEZwvQQq2F9EjOPf4hwkYMshSFm51KY1K964sW0Cve
         716w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752261898; x=1752866698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dwhwk5q6iBt7zH5sNIJ0vy3h+0bgZ37s1rTTK03p6uU=;
        b=B4mOVi1EY/yAhMV/NZBTXBF9mtCWdSMrDR1ylJR2s8GDxQHW5PP+GVF2UTODnTJJzO
         1TysxmRZ9jFLjppUClycXaYMOHwal5NUUQGTttwTGTnu6j6brOReOyrg/UV4mcWW6pd9
         Iuim33MKqbo92ZZjolLo2OHRZsy+3FpZ14L7P44Z2Xen4Ix5mdvqOrdJYei4Ibr6Tf0V
         TpB1ID2/xQz+KvzIJ+PXmrZLNy1ay63tZGKYMoDQO9dWenB0NC0b7mvpGxG7NxgGWM6r
         CfeUgvhPr5oCVgDpKqTo+TubBLZts6XLghYfqf5NscjQ5aevW8HeW8JwoenBAHYLrZUx
         qIRQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsE/Hpdmu8mouN7i2hOEJax+5D1uwpqXwhpECRU8IPUbFjxmcas8uqCYpy01KEwSYG7Z0VYA==@lfdr.de
X-Gm-Message-State: AOJu0YyTUruTywzh0cJS7f8QCMinSsaA+hN/SHcxLpilY5fwWDb5MRUV
	ddoFWt6wA3Mj+1lzpmDeGmJXrZ5PyzbQg+7DFv0kRbYGSNfBUWn2fWm7
X-Google-Smtp-Source: AGHT+IFlPiTfkv5vGQmxKVPUEe0V12TurDWZjQx8wlHkD9yd4Dho006CFcnyvS9GjVfJ3//pXKQJ4Q==
X-Received: by 2002:a05:6512:31c8:b0:553:296b:a62 with SMTP id 2adb3069b0e04-55a0448b825mr1588203e87.12.1752261898239;
        Fri, 11 Jul 2025 12:24:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZetEs8hstAgR72D0sTMG1JECruzjcZPv+3X15OuXw/BRA==
Received: by 2002:a05:6512:448a:b0:550:e048:74ff with SMTP id
 2adb3069b0e04-559002c8243ls988810e87.0.-pod-prod-06-eu; Fri, 11 Jul 2025
 12:24:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU74SIleFDxlzbqVwHPyj9A8/kCqOi0pT5+zPq+uxKIYOhvVZXhsUzX/FztiJK6NV6io45Z7Kr7Ah0=@googlegroups.com
X-Received: by 2002:a05:6512:3ba0:b0:553:32f3:7ebe with SMTP id 2adb3069b0e04-55a0448b48emr1226190e87.2.1752261894875;
        Fri, 11 Jul 2025 12:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752261894; cv=none;
        d=google.com; s=arc-20240605;
        b=lxu9tzBjeaKgkjGiz6QsYLRpR2mBEaSFQs43r3Jo+Plhf9UPZuj7JEae44hd5XYpQh
         02yMhIKu/LwuM2D9UgoxOveNWsSuUbgpoQ2d+DHXY+QoibvFNc81oR6QyOgnsn+MqnT5
         Tds2vOxFQ3945lTNX/T4+bqUpplWeJMdmFLkUAuHRZfA0yzpQ3tSG/S/GENXMcVHsLIJ
         7jL9CEyw8x8+S8f7BrgGivPPbo9dNRJLcV/Mzp4Vz5BTD0L0CU0SwS6Wr5JxNqHj4e1y
         TIQE/xwo8Zo7FEZqMErBpO2j7BpYFiHpoSTs6LEImpKLgCz2wg0lh9/OGcmLq3KSvYpq
         FkKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=An5C+0gDMIwtsouH1107rmybVZLRBPlp9Sd8kmMnl+E=;
        fh=lmUz+EheswsGuWAphKtLI3zXUorwnXW/b772eVsxA9w=;
        b=SQk7MsaaqzI5DjndFlaZuY8cYFkRQPC0uCegrNWuuwVKYAp2E7QdkVSeP068gTJV94
         vCfW1Dlpb2mg5/FW2OUY4vrxOPxxXZ+fly1AwXX9OwoI+KaKP86CEMOGPIkhSnLaLWau
         NJ37x0opViQy+WJk9PkxvsfkzCSpF4HyEPd+Q2oU7/ya54KUqsflQ/HNAr/6rG55dvxW
         XKNVWNlRUJ7bPi97eavsRcmJ+E8g1n0S3b7Q/phDxWtNBxhrw1FYhBBg67gbr6zuLdNf
         N4kj7Ev9W5d5d1gNyjez/XZMQ8XS6mWVw1hrzhmZ2uAwOxrPgVz2BLyvISqIHFQi3bYz
         sq2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QXOczNP4;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org ([2001:8b0:10b:1236:d4b0:a112:9c86:6a4b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa293250csi144541fa.2.2025.07.11.12.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 12:24:54 -0700 (PDT)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236:d4b0:a112:9c86:6a4b;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uaJMW-0000000E8fs-1liL;
	Fri, 11 Jul 2025 19:24:48 +0000
Date: Fri, 11 Jul 2025 20:24:48 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: David Laight <david.laight.linux@gmail.com>,
	Martin Uecker <ma.uecker@gmail.com>,
	Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>,
	Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <aHFlAB6paP2CU9Im@casper.infradead.org>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=QXOczNP4;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org
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

On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
> That kind of "string buffer" obviously isn't useful for things like
> the printf family, but we do have others. Like "struct seq_buf", which
> already has "seq_buf_printf()" helpers.
> 
> That's the one you probably should use for most kernel "print to
> buffer", but it has very few users despite not being complicated to
> use:
> 
>         struct seq_buf s;
>         seq_buf_init(&s, buf, szie);
> 
> and you're off to the races, and can do things like
> 
>         seq_buf_printf(&s, ....);
> 
> without ever having to worry about overflows etc.

I actually wanted to go one step further with this (that's why I took
readpos out of seq_buf in d0ed46b60396).  If you look at the guts of
vsprintf.c, it'd be much improved by using seq_buf internally instead
of passing around buf and end.

Once we've done that, maybe we can strip these annoying %pXYZ out
of vsprintf.c and use seq_buf routines like it's a StringBuilder (or
whatever other language/library convention you prefer).

Anyway, I ran out of time to work on it, but I still think it's
worthwhile.  And then there'd be a lot more commonality between regular
printing and trace printing, which would be nice.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHFlAB6paP2CU9Im%40casper.infradead.org.
