Return-Path: <kasan-dev+bncBD4LX4523YGBBTFAYOBAMGQEVYQAHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4594433D7B0
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 16:35:42 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id q20sf18156806otn.12
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 08:35:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615908941; cv=pass;
        d=google.com; s=arc-20160816;
        b=pPeYTNgX71y3XIqmTQD0KZg4C+yeTVYOF1PCBrh8QJpctR3yhtNA6xn5pkvk0KMEO1
         7laZ2S30YK9qhjtPPgbkmpJJ9tjsVg3kD/cNaik/HCmQ+1fHcYDcuSeaKBRG8MoRiDTB
         qGwsUgAMI7GL3M3spudlNGhH6fD8v1lON6zYUXaqvzYPiGEYc+CVTmo2rad9Vpo1efPa
         EGwC1qPT43ypa4Y+wVzbZ7FgGGB+R10XxRH7PewjjwPNjbnc4+oOMvQsr83XTtXgWzM1
         /DSVKFDn1F+AaZdyamCuyz9cC9JdaEyjnZofRyV5mJsyn3MWgcROwTD5x/diYl0Xr9O9
         l/gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=R7P5VbLUS990hR4ie554OT1Qa9dflISkvnXtU8z26NE=;
        b=Ya43N8nCn1li+mh9rf2u7noNhmG8qIlOTp+L7HurzHQ3geeXxnbCvYAMocCJyZt2AA
         q6601CZ/ESIBbU3r04pd3hfcKQCJolpId2DPaJvvQT8UZzYV9cYyT9MVTX+TceMLjcFG
         nqUco8StHPeSBmKNPSWWL4Vb6IrmGuKjHV/PuZdQ6i40J9PljpegsaP/YMZyEHa3wNbu
         W+TW1+zaCFGFt2DV5NO2zQSYMGQH0OzRVMeIX2jTDEe7rGjglSgppy6NB5XFwjp2MtbR
         UtGQWqK7OHU5SlHDdhOFqRKU8i/sFCNHoA71SAkLA0UGOXoOSnXztsPAPs7Qx0BRe+Zu
         qEpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R7P5VbLUS990hR4ie554OT1Qa9dflISkvnXtU8z26NE=;
        b=ZIX/RptNeIIaWPLds39epIT3D3cozbj+K6Kfij+z4kvG3v2PjNAPsPTP48hONht8rY
         fGNAXse9kkLM+935YI3sZ9baelR1KNrDHEHO93i7XjkVJjsbKNHqla3308x0s915VrMq
         m/nS6QzLZQr23g7gKnPfdVuSb21Lk5l4QOJiqNkvhuzl6+CHSnrvfkMBufrxDAgdMj8v
         ljBfKVTDK+usl94u/mgKjBqEBl6jWU24JdZxzC2l0C3+H9yuyjJPnItgFnZTvf+vtD9f
         JAje/c5D5apTVpJzwdkRp40aGjXF18XOjP+YAbBRFBGA4QhiLbQ8w8/umGUMBcoNTXWe
         Pdng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R7P5VbLUS990hR4ie554OT1Qa9dflISkvnXtU8z26NE=;
        b=WreSkhaqD31Lkg3b2g7GQXvkz4ufQXIgWPm6Anm+o/0K5ST57SWkkATxprn3lR8nJL
         kGRKHhhf5cIJYnUFyFaSHIVvqPShPIjn5GDYv1wAfS7HuwQ7hbrHNCAd8TfvNwfx5tu0
         BYj5xmT4+PZ5G7mWlmW1xXjrl234y01aBZ1x/USNVf1h7y8YvkRaHoPoGra/1QfffwqV
         cyw9BVqYX7JLZaQwFacYlt5qCISXGW5XpgU/Z4tIfo4OzTjiEEPCnO0TKCgQ7eZDNzcm
         AlWyW2WFOVV9lUMy4B1P1+xeqFqXFlzOZqpl20NEYFw8j8zoXTpb8ml3dQ4WESCmVSjl
         Z4jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313TcpzRNbabIPE5dTsnD828nPOMeo7Wqoo5VS7qaGjZD+5cxGx
	/Gcw2+AtxeGiyArb7b9u9xk=
X-Google-Smtp-Source: ABdhPJzEr81/z+PUNmdgcUA5YQkyORVWWix66rePE5fbqSjRssW5o3YDAPmp43zSxzBKvHyFqjLpPg==
X-Received: by 2002:a9d:ac6:: with SMTP id 64mr4101486otq.337.1615908941116;
        Tue, 16 Mar 2021 08:35:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2244:: with SMTP id t4ls4366911otd.0.gmail; Tue, 16
 Mar 2021 08:35:40 -0700 (PDT)
X-Received: by 2002:a9d:4049:: with SMTP id o9mr4136378oti.58.1615908940467;
        Tue, 16 Mar 2021 08:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615908940; cv=none;
        d=google.com; s=arc-20160816;
        b=DJRqrachQfkfJQWmanE2sG6vsgNXEzG9829Wy8x2mfePoEysFVHlI3mlQ1wbChEqT4
         JHNgWIGBAP7RN4KMLtSSmUe2z4gPq11dco33vKXiNWh82x3cujbb/l4zmsnD/0caKQps
         cSE739J1w2DAOcVehJaMST2vrHyZBMp3SWwZELZu+iSQGBgf5llMw6bf3j5+ymFHB5rh
         McBaFRemteuKR+lvgHEJ4GUZrELAYT/W51aRFjpMBW9aG0k34hPmpqVStpJ3dovm/vd9
         B6B0fjXYFI01yaFm+iQHFd79htwGTVNiBDi2dQ72IBjW/KNENQTFG40YbaTdWzUBeDcs
         YCng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XWMS+hUyuE6L1zm6H8PyNb0x+/VRMkvk/9mPyWHrpe8=;
        b=Et6kYbzBhSmALlTYQaeamB0JXg/jLpMJebBnI/mVsTtArG4CnkFl67/n/Xx/lB1wx0
         4UkLX5s6bZeGtGI8UmljgNP5vsFuL3BG+QTehANezA/BoJFbgC0ynj3j0BuvO8iUdjZr
         wYYo+RjTabpGk/r8K7O0QJGhrEua+yNHKbEDBRKbmj0knezRRaSagYOv8Jql/bOk2Djl
         M8BUGy7pxVTB7mSkffUlLCSGiakGiBik6OidwPA5q85YAqtTme5HhqlzYDQoN5RpjyLy
         WwVdNIDz7cb59nyExey76QgcZwY93GvSn4gAn2mqa4tV2NoCxOcCgzOrJAAb2uVw79Q2
         VvUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id f2si1031015oob.2.2021.03.16.08.35.40
        for <kasan-dev@googlegroups.com>;
        Tue, 16 Mar 2021 08:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 12GFXL1m029361;
	Tue, 16 Mar 2021 10:33:21 -0500
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 12GFXL3d029359;
	Tue, 16 Mar 2021 10:33:21 -0500
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Tue, 16 Mar 2021 10:33:20 -0500
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Dmitriy Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>,
        LKML <linux-kernel@vger.kernel.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH mm] kfence: fix printk format for ptrdiff_t
Message-ID: <20210316153320.GF16691@gate.crashing.org>
References: <20210303121157.3430807-1-elver@google.com> <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com> <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Tue, Mar 16, 2021 at 09:32:32AM +0100, Christophe Leroy wrote:
> +segher

I cannot see through the wood of #defines here, sorry.

> Still a problem.
> 
> I don't understand, gcc bug ?

Rule #1: If you do not understand what is happening, it is not a
compiler bug.  I'm not saying that it isn't, just that it is much more
likely something else.

> The offending argument is 'const ptrdiff_t object_index'
> 
> We have:
> 
> arch/powerpc/include/uapi/asm/posix_types.h:typedef long	 
> __kernel_ptrdiff_t;

So this is a 64-bit build.

> include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;
> 
> And get:
> 
>   CC      mm/kfence/report.o
> In file included from ./include/linux/printk.h:7,
>                  from ./include/linux/kernel.h:16,
>                  from mm/kfence/report.c:10:
> mm/kfence/report.c: In function 'kfence_report_error':
> ./include/linux/kern_levels.h:5:18: warning: format '%td' expects argument 
> of type 'ptrdiff_t', but argument 6 has type 'long int' [-Wformat=]

This is declared as
        const ptrdiff_t object_index = meta ? meta - kfence_metadata : -1;
so maybe something with that goes wrong?  What happens if you delete the
(useless) "const" here?


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210316153320.GF16691%40gate.crashing.org.
