Return-Path: <kasan-dev+bncBCT4XGV33UIBBA4FZT7AKGQEIRI7YRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id AE2872D6F8F
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 06:24:20 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id e4sf5655687pfc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 21:24:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607664259; cv=pass;
        d=google.com; s=arc-20160816;
        b=xAh0AYB6pNMzQOvCcxX3zcfy4/WpzlcL2RgcocHUyaS9HVMGGcJOPRMs0n45aK7NHa
         EJFIoC06uXxEXZkcb81Sc8EtlaCziX84eUwrHuoh7y/cI3ahc68+lSubIwGlllo+O8Dj
         YbHQYXF6pYLrTVOP23kQee9pZcZZ8NB8s+SPBQ4wZowleI7ynJihhgOPjFEGeytjLnMG
         qZtdy7XYnWl5QxYGmeuwYa9M7Yx663R9om4JhNbBX97vBmkL3KiPAB532dnIGxphvjc1
         Lcwy/B9Dn4cc7cil87PCL4c1fezDaNjnICm6FttHWJLaMhG/B+SocJVGZW/QutrXN41F
         OCJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=gFr6hClgpmDkam9J0b2/rzmSk+0M5LA2Ba+RyZSQLp4=;
        b=TU/PnxrJUzfg0KectyYSels85rDJqnbrhl8uN1n0nR6oXeEui2BExq3h9hvL3bi5sU
         J/WCC88qVtIEmy0BSmWiMTdnMM6RXe6dCbiqpWDUH0CbPJ6Op/Nd1zjbmP9OV8fs5Oe8
         xW+gShOIJL6/mBEw0QxmeM0qZhxmBI/oLG1sfsDBabA4J1Pp/Qx4zf75Xs77EwODeFNk
         o+zImEWv8lMCHxI7/i2Gq5Uv/cJga+c07f75BwKh9sHWGsOZMJGDZmFukJq4c4zDD8yH
         czQpt0GRz3zXNFGni0jsFeFaPtn+ceOJM252qAs5Cwwq6lUvcoZSc5czFJrpFfOqhVmd
         E13A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=EvpWLkpe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gFr6hClgpmDkam9J0b2/rzmSk+0M5LA2Ba+RyZSQLp4=;
        b=Wr0Up4f7AJ0e695Cz1YQ7vbdO4A9IFscOB8DgfYPbr1zjD1Os4YSRfkrH+9Bh8IaS4
         yG94vG5ZNaUWskE7hFRSURbQQuOOf+mTIyRWbOhLiZwcCaJuDbGh7SSICgcECSF6WD5H
         pyYdkDaTgTWdbEaFSJ3Vb/7cyGG6NXvEGHM9TloY+IuoXQJWWQHtsqDZLXagGQuLhCkZ
         HhbcneTv8oDOgaYhu7MNjlFZi9mw4a3lcbTAcS6k4Hgd1imgsZvSa4UphCqwEfbEBzqQ
         ts1rMV2ly3rjiRPl0q1fzDwXeXqHaVGZNthdqSbBo4mcsj2za8ZaxAG2RqaSf0Ss4fM/
         6p4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gFr6hClgpmDkam9J0b2/rzmSk+0M5LA2Ba+RyZSQLp4=;
        b=M9GHv6iMKK7EDhW3ft8moveVMNhZ97zwR88mlck/jceUkOODTzJut1LvtK1Y5+9L7F
         I64ReXcFiXGOTmJDJEknFj0QvQtXfYnzrTXiZjf4hvI9iAeRq0ny/fflfrxuyVUvW8rB
         REP6rQX6DFEARCBOQ80zqvKbKPi/fwr+QR+FOJaYT9+17oExSe/zNVNaHwxJIqQBKvin
         R8AvBc5uegYcIl6djTmVSd74Qa09Qdghtg0XBpuj1C3Q9rhm8HVkEZ+wDhNmUjnUXRJ+
         3JVRsmLOerL9ercvwQdEq8Fsm60lKcH/sd1eEnuLnihuwsjqvXfjzvlbh0JmYfzyPc+W
         eLJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ylv4WZG/ktusxYLIXuiadVY6HVMHZXCr4fscErB1SbfGQEzuq
	QZhGlAFjGtlqTVKy1I9QHqc=
X-Google-Smtp-Source: ABdhPJzfcTqYwS1go02MXBITrjRJjn8V7GEGxftLTZBAJwsNKt216Pi9rGCGfFrleMZLn/XL87Yt+g==
X-Received: by 2002:a62:7858:0:b029:19d:c011:1cfe with SMTP id t85-20020a6278580000b029019dc0111cfemr9852922pfc.47.1607664259288;
        Thu, 10 Dec 2020 21:24:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9286:: with SMTP id j6ls2907524pfa.7.gmail; Thu, 10 Dec
 2020 21:24:18 -0800 (PST)
X-Received: by 2002:aa7:824d:0:b029:18b:ad77:1a2b with SMTP id e13-20020aa7824d0000b029018bad771a2bmr9704750pfn.25.1607664258655;
        Thu, 10 Dec 2020 21:24:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607664258; cv=none;
        d=google.com; s=arc-20160816;
        b=sL4/f0pF8ljg3QW70QP+aPzRClDj5SQ/ESRHxvGGp5picOEubGwlMbggHgnM8QrbXk
         hAM00Av8rwKLRETqCwh0NF8C7gVtJ9g/MvywsapoF3+2GW5I9vXndi9+nNDZ9cxX3d3d
         PRgop8v37vtpPiZEQWl32sA7Gl8L9aa+ILyeMwMEgfFy1JXXbSNst4EFb7zjYD34A3eO
         LH3KfKy/Md8hbyoqfY1rj/wk8zW3f//yiDB/EHMuSI/Pn6L9DJcbC14AE6OZB27Fv1CS
         CvxB+nfdlCp/7oCBurY9dIQM+Fp3KRuszo19d3JsgLsX8+rtCmYhksdOmxgIPKhJRhyQ
         /eRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:dkim-signature:date;
        bh=ABi0kX/kmnbgFkUvDsMnw//n9GSh4luJKESS9yOI5HQ=;
        b=CfKU2BOxcyVeNwrpIcTKlGfaBsgO/+XaXrSyFwTBDia8YrluBbBkTEiqE42EuRZ9tR
         d69Xsv0mQkye77zwUgAFFkA28Z9o5WiojDgmlKcYUj0oT52WuEyFfKaCF8NAsSrlam2Q
         985OoAY9DosNucKF4Aa5TbYatOlP1FaQHO+t0Bj9xrqWqbFYjcDJF+rBRGUvKisTxl3A
         OX5AscYgqUvQ7u4iJMbstDyVLAEYimXtLT82KFXOBv30/pOHZjuroND+DszZZbYS4NqG
         gCrSyoM9mHSsndV5sbX0j9u9j6eqwoHO8Y/gRbG9Ei8kVsGlw42S5WZoVgXJI5o28iFb
         qnvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=EvpWLkpe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mt17si557357pjb.0.2020.12.10.21.24.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Dec 2020 21:24:18 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Thu, 10 Dec 2020 21:24:16 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Nick Desaulniers
 <ndesaulniers@google.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev
 <kasan-dev@googlegroups.com>, Masahiro Yamada <masahiroy@kernel.org>, Joe
 Perches <joe@perches.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Richard Henderson <richard.henderson@linaro.org>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
Message-Id: <20201210212416.15d48d2a924f2e73e6bd172b@linux-foundation.org>
In-Reply-To: <CANpmjNN3akp+Npf6tqJR44kn=85WpkRh89Z4BQtBh0nGJEiGEQ@mail.gmail.com>
References: <20201201152017.3576951-1-elver@google.com>
	<CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
	<CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
	<CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com>
	<CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg@mail.gmail.com>
	<CANpmjNN3akp+Npf6tqJR44kn=85WpkRh89Z4BQtBh0nGJEiGEQ@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=EvpWLkpe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 10 Dec 2020 17:25:30 +0100 Marco Elver <elver@google.com> wrote:

> On Thu, 10 Dec 2020 at 14:29, Miguel Ojeda
> <miguel.ojeda.sandonis@gmail.com> wrote:
> > On Thu, Dec 10, 2020 at 11:35 AM Marco Elver <elver@google.com> wrote:
> > >
> > > It looks like there's no clear MAINTAINER for this. :-/
> > > It'd still be good to fix this for 5.11.
> >
> > Richard seems to be the author, not sure if he picks patches (CC'd).
> >
> > I guess Masahiro or akpm (Cc'd) would be two options; otherwise, I
> > could pick it up through compiler attributes (stretching the
> > definition...).
> 
> Thanks for the info. I did find that there's an alternative patch to
> fix _Static_assert() with genksyms that was sent 3 days after mine
> (it's simpler, but might miss cases). I've responded there (
> https://lkml.kernel.org/r/X9JI5KpWoo23wkRg@elver.google.com ).
> 
> Now we have some choice. I'd argue for this patch, because it's not
> doing preprocessor workarounds, but in the end I won't make that call.
> :-)

I have
https://lkml.kernel.org/r/20201203230955.1482058-1-arnd@kernel.org
queued for later this week.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201210212416.15d48d2a924f2e73e6bd172b%40linux-foundation.org.
