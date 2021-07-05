Return-Path: <kasan-dev+bncBDW2JDUY5AORBMGXRODQMGQEW57BW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 67E033BBC1C
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:23:29 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id u2-20020a2e91c20000b029017f236536cesf5375776ljg.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:23:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625484209; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uo/IkqtR23oW0xb4n8CzpeTo1j6VbCBfyIgsYI5coo+CfJoKAXzDCBsM0T3xO1aYrI
         H22KmrpHdYHvhN1r8WHe+dBxw8c4EsNhKPUftYUFEpgpSsRACqaJsrryQ+Nv9tFk1PSf
         4nbCyAqZ2iixNu233ffI8dCnQ1+djuNOoFxfZIhjFtAsKcRjwFI7gjlzOQdcaGhsGimH
         BxQIBSN4LVAKxmXrI3+uFlvCfSDtV6BfzLOyHcgFpI65Ik9db8BWC/ZXDejhq1UDmiUo
         wq1pjpZSCROlsBDf342Zi/7P8ZOfU/5ndKSHcz2SKAj8lVClwcemFVT99qg+kUGswqTq
         pSPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tpivl8cJ960hv222/xGAddwTqxif1Vw5XLHUGKBff7c=;
        b=xnN5sHqGSFUkHGH9aROaS/WjGjZ6WYoAgKCpeB3gMV9P7vBuy00FEujfNbf780Uyi+
         YKP5/aP6VwIzDlqhs85rXdt5aHdplUzr8Yfl/P3KrwJtfNhg0z3xgnvRdjaWtfj0E6D+
         3tKGlWPP4wyn3ggKN69vGrTe8uOE3pr91lmJcCCrPGG1PCeGiQ/bn2rQTYFN8O4OGWfF
         p60aBzDDoWR2MWrMg1yqtUG8Wk4sdQE1zrCnY34t/2fVgWXyCfj6cyNlbRvQszYhIh/1
         cXRExDQmHlfGwNoGOXYGroC8o0YAtEWxDYuSWPdr/zBQZV26uZMmMD2ZHmq0zRod5t9b
         Dt6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mWQhQjCB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tpivl8cJ960hv222/xGAddwTqxif1Vw5XLHUGKBff7c=;
        b=U4ldYoIOkjJxGccl9xVJfAzPQUCtSBlckR8boCfZcWBkrZ9hKdLrZGz32M1aMTblsa
         OWgFGy7LjyQ+SVyVlHPg49UOQ6GwPbMCtKKgazpPySrLyFW/wyK9LyqrB93U4YNaXzZ0
         uQRS45zsz3bWphKeSWAL9DPFJkcYQ2G01+ExDqyTqphF86CKyrjFzFgZmmdB3xMuufXz
         v/xDiffSvPzbLlluz6nobkiqjQU1wCgy14Cg/1gVa1xF2ecbnOkahVGyu8s6lxG+HxFE
         baY8eALOhmanW1aINgOeE4HdjtghnimVuxSYDX+ZfWTfE9KubFOkQRAiIIjxWSRMRnW3
         /yIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tpivl8cJ960hv222/xGAddwTqxif1Vw5XLHUGKBff7c=;
        b=EaileuiEVZG/sWX3e3Efqnn78YnGOdGbgToHlSR+dwg1eIMIftjNE5ofz5YY9qY965
         fEH/CV2A98tFYjT3wz2lZ3aveRlrxu90ejcuqXUS8QFbPIaSGxH9g8VwczQQJzxvaEfk
         0/B6ntIKzQEqXOPaP/+0gayQXoNzletJd+/PArWnjHi0OW6Ea7urMWejf+wOKKwv05cB
         kGH3/0Vv6pqLVqaokZal5yj/+D/k7/LG/q+PD37G6/1IsNEGHD3Ekgfrtvb7W6jZLD+K
         VhzguQ9xQczHgJwp7g7vWF39AeEwms9rGfu6vYTKGsf1Vhse1g9avn5pe/K/RZTQCnbN
         8ncw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tpivl8cJ960hv222/xGAddwTqxif1Vw5XLHUGKBff7c=;
        b=tp4mZ5UZqlfiW/IdQdijvfy3yqW5y5EACw5kx33QSgDsLH4WhyhSDSNbAxl2h0FV+U
         oZ42okOAIX7iPXfvl6NUj2SihwRE1CAt+GvjX2pb77ndXyXQ+/VcuD+s4OGovSjoxHsC
         hAVzDe+sdnb8TsZWMYEqjSb3JWzS4G3F7l0p+3Se9NruQTabY4isOq6uRT9DmN2zGRGL
         B3c0gaBPOx+L/dby4ratPFagLgMO1dX9vE0LXHadiTR+1ulcdLYVagTIm5m0pcUBJaH3
         sUm2lQ7DViMmDJiG8V9pUf2weDifeE0FWFilT20vT8h8pnlNIcOxYAoRwouKU58uBE8e
         IWKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CpZy8amLEs9dh1wZesUxfek18fDqCtUdHxAeJGV0iVd9uaqy5
	0RT201B2WMJRBTlWOIPOG1o=
X-Google-Smtp-Source: ABdhPJwlHMirTOuQlSsaPsTM7z68As9/pbBPUEjp4A9eDwGWp03nzkdHpzFndiDW/yiFQT5ITCy2aw==
X-Received: by 2002:a19:410c:: with SMTP id o12mr10251427lfa.10.1625484208960;
        Mon, 05 Jul 2021 04:23:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:430b:: with SMTP id l11ls1003085lfh.1.gmail; Mon, 05 Jul
 2021 04:23:28 -0700 (PDT)
X-Received: by 2002:ac2:4107:: with SMTP id b7mr10142207lfi.609.1625484207961;
        Mon, 05 Jul 2021 04:23:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625484207; cv=none;
        d=google.com; s=arc-20160816;
        b=qHBw7gS58gFdIQM0AqHpx8eZGv8DUHsXsbOKpGPX6DQc+8OeyEhlMFj68xxovO1/VF
         aZDBv75eXv3LLQj8b8syyXCQKI0wkbi5CDsitSHz6Ipr+7g4O+PtNN1fhBpqMofjDGV9
         FBeZY2Qfjtg7I62EejkMagwyJ0V1LUGzj26mxfiPJFFhegTqz0Su2zJdgnIggA8vHS8j
         K1iTEcvf4u+p7PpCaKpOcSejdGzlrA6W4yeRgCS/efILctMTsnZT26Gb2wf41glFYYgs
         ugNElqZa/zYOGnmM3gyNP8nxB/yxiGAmhH5TO8NHkXYyvZULb+NWJ+BAK1q/Vi7LqCyC
         Fs0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mdfkoj1lAbFutKa5lBXnsN9adsQUOWmNA/ZLqwOPGpk=;
        b=x9gTseeOwb1ZkIrjQRiIr5BGuTdUxWswYkhgmdTqjCOrOfQis6ymY97mXGfJMnMXpq
         hfaytkzggpE/4IbjgW6QcFTTM1h4x+hBIqdkhx9hU+2vvrpcEwdeXsd0s0XSd4JkO1QE
         MWyRkHreAb3cyq6Is74Ebc34KkAfmDVPKXOFFuQKoMNqA0yMDYT3f3KGnjFie+NPjrLC
         YIVLsRQRtpYij3Rgk+Tb/6ObYy91Mvwq5qS+WyxpLN5iCPZbC7qaZMpT48TsoRsNDG1F
         5QIJ1bxIZhO5JdVSaIATkCweqTMa/aVPQKYXFSVPSHGDkOiZLmF4s6dLdF+PUjZzj1Z4
         ocJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mWQhQjCB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id j2si259838lfe.8.2021.07.05.04.23.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:23:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id x2so4820771edr.10
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 04:23:27 -0700 (PDT)
X-Received: by 2002:a05:6402:5c9:: with SMTP id n9mr3126699edx.30.1625484207801;
 Mon, 05 Jul 2021 04:23:27 -0700 (PDT)
MIME-Version: 1.0
References: <20210705103229.8505-1-yee.lee@mediatek.com> <20210705103229.8505-3-yee.lee@mediatek.com>
 <CA+fCnZdhrjo4RMBcj94MO7Huf_BVzaF5S_E97xS1vXGHoQdu5A@mail.gmail.com> <CANpmjNNXbszUL4M+-swi7k28h=zuY-KTfw+6W90hk2mgxr8hRQ@mail.gmail.com>
In-Reply-To: <CANpmjNNXbszUL4M+-swi7k28h=zuY-KTfw+6W90hk2mgxr8hRQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Jul 2021 13:23:17 +0200
Message-ID: <CA+fCnZfKAZuy9oyDpTgNUTcNz5gnfHpJK5WN-yBNDV5VF8cq0g@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at DEBUG
To: Marco Elver <elver@google.com>
Cc: yee.lee@mediatek.com, LKML <linux-kernel@vger.kernel.org>, 
	nicholas.tang@mediatek.com, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, 
	chinwen.chang@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=mWQhQjCB;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::531
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Jul 5, 2021 at 1:18 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 5 Jul 2021 at 13:12, Andrey Konovalov <andreyknvl@gmail.com> wrote:
> [...]
> > > +       /*
> > > +        * Explicitly initialize the memory with the precise object size to
> > > +        * avoid overwriting the SLAB redzone. This disables initialization in
> > > +        * the arch code and may thus lead to performance penalty. The penalty
> > > +        * is accepted since SLAB redzones aren't enabled in production builds.
> > > +        */
> > > +       if (__slub_debug_enabled() &&
> >
> > What happened to slub_debug_enabled_unlikely()? Was it renamed? Why? I
> > didn't receive patch #1 of v6 (nor of v5).
>
> Somebody had the same idea with the helper:
> https://lkml.kernel.org/r/YOKsC75kJfCZwySD@elver.google.com
> and Matthew didn't like the _unlikely() prefix.
>
> Which meant we should just move the existing helper introduced in the
> merge window.
>
> Patch 1/2: https://lkml.kernel.org/r/20210705103229.8505-2-yee.lee@mediatek.com

Got it. Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfKAZuy9oyDpTgNUTcNz5gnfHpJK5WN-yBNDV5VF8cq0g%40mail.gmail.com.
