Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3NI2DXAKGQESU6BYMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 69546102904
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 17:12:30 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id 125sf13855084qkj.12
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 08:12:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574179949; cv=pass;
        d=google.com; s=arc-20160816;
        b=0pEFHGD8qxiSI1aH0TaK15G2+lGBbEuJdTZoH/9mkgPldTXB+8sDUlZoXR5OLj3SSV
         DLq+JKl/gr+2rG9UmuhdbIWaNgOLxqgM5t450UDBW0blCivJPRlLBcDPf5Lb3meuvjwJ
         Mx1kgnucafE16ur4icGYub+v9mcjrfv/YHCcO3mLIqc9XNxon0ntAUdVmCMVIlGvfBcI
         uz6b28AFLrhL92iobcGgv/zjvU3HdLYNyQtqFGAhQJNMQQlIgAGl+tdsH6lBYctyH2mY
         MRRjsZ6Y7rOy8b6H/JkKH7mngEyb5e2oT+wZLqTxTxVlKANv38Jd9qPuDUbt9yAh1RkR
         YsKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fYqLvBRMzG4LmWwBfF5KnVLhgvqK6Oa50x3zQNT00/M=;
        b=FlZ8CxHryLo8m70foCFIravJw9hCrRbGjhtZnpz7MekNDaR7qoSd1YNvSynoosZV8H
         HMTUMJNtMThYM7YhYUmqgaHqQ807rXm6T8MlAHa9wBiNrSfYhaqJDPRC8D21VV93DOTD
         2nrSVRmeCYL57IHJaIN0XJYottnLq3Z6IN7ztYhxb/qcEnuw8/Nubg541DtjWY7ueUAr
         QIXpS2JNPkGG/E1tRoiXM6Zc4dMyAYoTA1ZKIGkuPAtiS+PBaDRCBbuF2zWg9QTtZ+FM
         eCeHHdt/gj7tduPy60xS5yG5sbdoygzJjSY1v9W1v+cK3EWXoWVC+qJpaJKT0RIBbPSk
         lNLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ClXF5T0Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fYqLvBRMzG4LmWwBfF5KnVLhgvqK6Oa50x3zQNT00/M=;
        b=cHeVm1Y2rwhb4cnOxdJ0Q/sw6jErmLX3rf9X3ERtqTi8kaPlCp4sFKR9kwhOUoOBKT
         OqNnI2Slpes4JkCu/eXhNCKNqIJ6Z8XMSCS+si7lmUJrAs8aKxpDcAQtV3guSHuaSEza
         Lx9A5lECD9+Pjdhy1hGQ1EJ4iymoc2glEH4CQf3/pro14ik6SxVzLayR5NSzIEO8zKi2
         HqisTpqYdEmKCxnLVK2qHQIfqPN3fBf6UTAiswnctnMSFGUHGVNtvu8IoSP/J6Qb1AQN
         ClHP7aZ0xFkTI2vTaed0DoxganRpBaLeuJE9FU0XoEAU8goCU+s+HzdMRBGDlh3cTm7a
         3UxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fYqLvBRMzG4LmWwBfF5KnVLhgvqK6Oa50x3zQNT00/M=;
        b=ELuKVeVr0A4WTqBrztqP0UNfS6XAiZ7dIeoX9mNcMBT6dWVWSMwFILgsQyfuXRNX9w
         x+yJAg8TEfjUXqAQatq3eWVQPMkXt0b7q+sLL50mYeFu04fgmCX+m8YRyDeZhtOQxU72
         8DFAn7f2JVqoCcOmKKxz5uXqNYReYDOe2dj3ro8gWIIvIyJXFpKP3r5lta89U7QOrYsb
         om8K5lWIAvwSI8eFp6F7KQ2Ym1XiE37xnBLidC5Zqv7d6JW0qTaukyLaz2HpG9m2Mh0D
         zi4yrKt3/falcdLd3SyEBP4ZRQTAfpQbyBcSH07gQTXhA7l2n4NKDa0/DKyvJADLDafS
         zh5Q==
X-Gm-Message-State: APjAAAViEySP7gnaUZi9AUT0a522LKp0O3W5V6AUgoV3Jok4IfOkw1xU
	hQXzk5hAostBxLVd2NW+v8M=
X-Google-Smtp-Source: APXvYqz/f9eoV07gXfY0+kL3P3aqHQGx530jjzcW2880Nb4V4GV53nynB5imT14ImDnL1iCtvALWtw==
X-Received: by 2002:ac8:73d2:: with SMTP id v18mr6657249qtp.106.1574179949133;
        Tue, 19 Nov 2019 08:12:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:18c9:: with SMTP id o9ls6282057qtk.3.gmail; Tue, 19 Nov
 2019 08:12:28 -0800 (PST)
X-Received: by 2002:aed:24f2:: with SMTP id u47mr33931527qtc.70.1574179948797;
        Tue, 19 Nov 2019 08:12:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574179948; cv=none;
        d=google.com; s=arc-20160816;
        b=iImriyj6fy0Ss/jPvMD1l8rYwDMK56/xuSIleyxPC7+MVqepwas2NyPvyAYUwBNuKr
         wEabXYkKFKzhf8vT0txxISsQWdG/ADbsTUB1uIPnj8Nw6l46tEL7o8LZQDlQ3sAizMPI
         y4vEz/TIVct72efR+3w/lwcfJdGSeHWTR+vYYhFXyGWO6qfe3R7AsOGSRoemOFY7jtGE
         Kt+PPzr5DNELoTs8po+3Q33YI1iI4iUXwKyUyCiujZTjQmzhV9+evgYQiBeuxiZy7Doe
         5/+lBjXL5BSDtWf868PFiztPmsqrbneXKh/Ngq9w6Q/PmY/07Dpp92lXWia5olXEwUwG
         IScw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=93xPAx0kr8oA76/KRE4IYmxNgzvAosH5EkrlivRRC2U=;
        b=gmAhNWjR/AGL9tOn1Tm5Anrs33I1A9+1iLjbrXGArYHvOgjI8SOLB7C/7N8HEWQpBK
         ZjapqpK9czaWspgJufhIcPqVyt1bddccROm5MzHVY0dY4rMD3VsF3iWenBiSyakfxFbh
         TTV8upLCrfy8FdrCecNVi2EgA8bwrUvyY+gT4IkFb66tx+EkP14AGzdGcukUkj4IBibR
         O7zSpibdnUvpsQKtiFSP/GJD9tehRlTI2UWpLN2jAacHL2BSjSBZ3gc6P87+k8hYsyUh
         T9S7hRboJDStWSkGWTGvDcL0ZwAmtiL5a1a762u/k6qZkQYSAQe7udlBej1W7Qtd2o9p
         RAig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ClXF5T0Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id y41si1462613qtb.5.2019.11.19.08.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 08:12:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id l14so18323111oti.10
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 08:12:28 -0800 (PST)
X-Received: by 2002:a9d:69cf:: with SMTP id v15mr4108901oto.251.1574179947889;
 Tue, 19 Nov 2019 08:12:27 -0800 (PST)
MIME-Version: 1.0
References: <20191119194658.39af50d0@canb.auug.org.au> <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
In-Reply-To: <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Nov 2019 17:12:16 +0100
Message-ID: <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ClXF5T0Q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 19 Nov 2019 at 16:11, Randy Dunlap <rdunlap@infradead.org> wrote:
>
> On 11/19/19 12:46 AM, Stephen Rothwell wrote:
> > Hi all,
> >
> > Changes since 20191118:
> >
>
> on x86_64:
>
> It seems that this function can already be known by the compiler as a
> builtin:
>
> ../kernel/kcsan/core.c:619:6: warning: conflicting types for built-in fun=
ction =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch]
>  void __tsan_func_exit(void)
>       ^~~~~~~~~~~~~~~~
>
>
> $ gcc --version
> gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]

Interesting. Could you share the .config? So far I haven't been able
to reproduce.

I can get the warning if I manually add -fsanitize=3Dthread to flags for
kcsan/core.c (but normally disabled via KCSAN_SANITIZE :=3D n). If
possible could you also share the output of `make V=3D1` for
kcsan/core.c?

Thanks,
-- Marco

> --
> ~Randy
> Reported-by: Randy Dunlap <rdunlap@infradead.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMpnY54kDdGwOPOD84UDf%3DFzqtu62ifTds2vZn4t4YigQ%40mail.gmai=
l.com.
