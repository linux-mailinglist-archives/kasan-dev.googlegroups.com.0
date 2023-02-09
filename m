Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5FISSPQMGQEHXXPOMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9387A690D4C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 16:42:46 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id v24-20020a2e7a18000000b0028ea2c1017fsf591140ljc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 07:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675957366; cv=pass;
        d=google.com; s=arc-20160816;
        b=OCCZmrKknESP2P9UiZyAycp/XzJ0I2F65Ui9rJH746qtRMvMp+yFbJFvQnJAa+jnIB
         M17Du9rq59Uzd0wD7KC/OyAZalJYcKx0Fuk2kB2fGSzqFr7giAMPs4H2ILxd1/hDiTW6
         ZOpvwWQq/2pKWQE9Ho/HsJHPJmWJ7SqUTXg4FIKG85fW5dNngYo/Ju9CU6hxC24pG3Nb
         0CGzCj5bypZ3GamFxHx6Pg6Okxa1G5NiXeOGs0Lpt4nqEGqf3SNHTPTARO7Jj9nayPy7
         3GkGVi2bknlsjBKafMR3KSDrbPnyoKky6AqHwc+Wr9KA0HSwSPt0Rw5/mVsFmcLHeoPa
         yDTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DfHcXvhyjUnpGgoZsmX4f3772iz8UdHKtIkjFYfk/eQ=;
        b=zT+161Wc0mchuhhdx2g2nlReOpmy3m7fxisV4Be6bAFQMG1/0GDe/K9IUvkcR90vTj
         X3nRtHM1WF+v1Nxalehd4Uw2cjx1IBaKtVO/2sWao1sm7NHnaIO+jCq/NUvswxZLOWuY
         c+LvOMkOXEu5UIPjC0iesxFMufG1ITKIxBK6PCJad8FzZHeHY/QJxztvZ1OK9XVB3P1i
         P7a+FKdWaSYm0KMrFFQpf1I+pptkQtRfVCMwauQK7ybswgsK8Q83xSvcXtrNgS26eDCG
         39LAd+V2jgsttPFAZVTUjWoXKxWbVyXMD0jcwa7C2yTHnLImF0UpYAPXY8weEO2cmmaz
         flFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dfs88Jgs;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DfHcXvhyjUnpGgoZsmX4f3772iz8UdHKtIkjFYfk/eQ=;
        b=BX0bWUOTRz5veGq1wwmdmI0ukDUazYJouDuarL2vGo0gsxLzM4XwJUEz3kxgrKOuze
         2hhtNLoSMGdZERe/AVMM1LLcnOuXjZWM619ME1YVl9Bogn8qGsv3PJSdqCt3IKuuSCMB
         xJrvXuG+CFhl0Iwv5k4WH9G8iD06IhUExcTKEo9LFdF4VHPEY3h2n79O3VvlaEjYzmcM
         IKUWImniZpEXqJ9gSWXz0cJWqhSOEglIo+V+luLF+17RI4Axl89IkQ08C1PRkb+6n38c
         VVudUssz1pkK0rZHV7kg0o9J4wFmMi/sU8CdYw+Lbf8ofr2M/eaplMRN0+ZFdo24yYB9
         LDRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DfHcXvhyjUnpGgoZsmX4f3772iz8UdHKtIkjFYfk/eQ=;
        b=QSkwr+4efvvavr3wHj1oSHrJ+CRPSm86/+IPHinYMKxiQ7gD4XwGm63kJlwQeUv2Dg
         UVcK2DlDLC07XLtkFy/qu+R1uLucL2RfItCu/AzZntQnWJELOUK3o4DzA+Iw4wKxQzsY
         tHGEVnNWJexAJzOijkPg4VP8RTBvsBHagya/vXEmIbOfCNJcKTKhynQCenJV0Hpl8g/l
         BPJ1xxwVplqhiadIJHygAildEDTazaDSPkWyPWVUA35Fi2yzm4d94Y866oCg5cQZEO2k
         DqxQZtbcAyDaomI/T5H2+B68nQpXqxttwli7QAoms3JSQ++HG4AwHtruruJdnncjMpMh
         1KnQ==
X-Gm-Message-State: AO0yUKUbCMxV75iDbwzjsuuUI/vimE28/bt5sWllNf769N33CLVPHvtK
	hEathSNhF2LXX61Q8tyt0PU=
X-Google-Smtp-Source: AK7set+QfetRXcQ6LH/NhizJnhK3PWKi0XzNvpjW3jSTuDoX1jE3mi7i81wavy6yD9ec9Hy80nOIbg==
X-Received: by 2002:a2e:b4b8:0:b0:290:65bb:6b24 with SMTP id q24-20020a2eb4b8000000b0029065bb6b24mr1845141ljm.87.1675957364956;
        Thu, 09 Feb 2023 07:42:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e29:b0:4d1:8575:2d31 with SMTP id
 i41-20020a0565123e2900b004d185752d31ls1710689lfv.0.-pod-prod-gmail; Thu, 09
 Feb 2023 07:42:43 -0800 (PST)
X-Received: by 2002:ac2:5dd4:0:b0:4d0:8469:b196 with SMTP id x20-20020ac25dd4000000b004d08469b196mr3314775lfq.3.1675957363477;
        Thu, 09 Feb 2023 07:42:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675957363; cv=none;
        d=google.com; s=arc-20160816;
        b=cK39Sb0ITpKMGL6R+TsgzQbZMjwYjrEZNjeA6mEZdItJH46eiPhnzlEE4C7HHyYMmj
         r3OiLho49LT265ZX2FlSq7Ew3Hni2yuVr4GtAZDr1YI2BAIPSllJiIk44Sw3oWHE/GaI
         3Zo3DxQ4dmUCgPUwsW/JCT3JHnM8MonQGzQ/k9o0H/sQodAZJsiiepaxZgOaR7A4XvnU
         w4XEuMPxU+paY8q3H1wDcF5rjBZtxt6HWYDcSc24tmcVG5ylfZPRS+WNfYLhbBDNWxDp
         pnEPgsxIDuCLciADBMO8ceoig1Gv8nRZMxlYzNCSuCKGwq6F6+A6aYR0CcX0gfiLuFYm
         gYGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mzvCaAOpYzaP487+BqgN7Jr/isnyXVDVjSzZh2DR0yM=;
        b=cTnhk18s4WIJHC182Mpb7rXR3z6FzSiMGdgqf9U63iLo8wbS2H1UTsxxx0sZVL9XlB
         0rSaHbkntnCq/tFkYvzMgmFtvRmewLKhve77Ji5m6RL0X+f0hk0P2grWOyhJaX6D4oHA
         gvDjN65Vur7iH4sWqYUsxJXjJtSnm9MdTeeUYd7AFMjjsC6xjLhvACqBfNhvBNV0IzQ3
         ToUJcHQ/OnqwpPQMriMfSii8Vr8kIocUHrGwGDQ+5ygBor3VBmXUY0//PmdnVQ3/zv6U
         iojFQDr9QSALepEuhTHO2zGYE7be2WI1iGXj1Ds4CfdXju4RmdwWc7kVY4ObgFvHQ3Hv
         kbuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dfs88Jgs;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id k10-20020ac24f0a000000b004d1527c0905si97661lfr.6.2023.02.09.07.42.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 07:42:43 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id u10so1723496wmj.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 07:42:43 -0800 (PST)
X-Received: by 2002:a05:600c:29ca:b0:3dd:67c6:8c58 with SMTP id
 s10-20020a05600c29ca00b003dd67c68c58mr732120wmd.51.1675957362869; Thu, 09 Feb
 2023 07:42:42 -0800 (PST)
MIME-Version: 1.0
References: <20230208164011.2287122-1-arnd@kernel.org> <20230208164011.2287122-2-arnd@kernel.org>
 <CANpmjNNYcVJxeuJPFknf=wCaapgYSn0+as4+iseJGpeBZdi4tw@mail.gmail.com> <7a62bc92-e062-4d33-9c3f-894b49452f1c@app.fastmail.com>
In-Reply-To: <7a62bc92-e062-4d33-9c3f-894b49452f1c@app.fastmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Feb 2023 16:42:03 +0100
Message-ID: <CAG_fn=VCTvUF39ORV4FnuhzD0tgRq3mGurTQrwD-_cCwEgXazw@mail.gmail.com>
Subject: Re: [PATCH 2/4] kmsan: disable ftrace in kmsan core code
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@kernel.org>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dfs88Jgs;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::32b as
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

On Wed, Feb 8, 2023 at 8:32 PM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, Feb 8, 2023, at 18:00, Marco Elver wrote:
>
> >>  CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
> >
> > That means this CFLAGS_REMOVE.o didn't work, right? Can it be removed?
> >
>
> Ah, I missed this. Adjusted the patch and description accordingly.
>
>     Arnd

Acked-by: Alexander Potapenko <glider@google.com>

(assuming you did, b/c I couldn't find the new version)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVCTvUF39ORV4FnuhzD0tgRq3mGurTQrwD-_cCwEgXazw%40mail.gmail.com.
