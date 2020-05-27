Return-Path: <kasan-dev+bncBDEKVJM7XAHRBHN3XH3AKGQEP7JH4CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 65FF01E4255
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 14:31:25 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id f62sf1090709wme.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 05:31:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590582685; cv=pass;
        d=google.com; s=arc-20160816;
        b=O706nCbK7uOH48E2eLzVUrlMoQcJqKzRTVxnhrUk0aoqvRNdaIHum5hqncUoSblWAT
         Qu5b4GAEpN215vsvDVUfJ+yQVzCgcLkLSE/MooX5lhP0xfi7ADm//ZdtDy9xoFj0j1j8
         EQEf5+vVZWw1h3vmSkXM9kmozTCdVIWj4xXn6raouo9povUC73pW7ANEVoWsCbReQbBY
         OZ+O8KJ2hyHnkUt02dLdSmzhP86PFE/97cYg8l9pLEcX5yybrczUNYXq1XMkJF0k15Y8
         M+KHHzsBCiYibk5iuhX5SGCBAK/CNfMdRSKcQwCB6Vl9V+uP2YIndIZmVqmmUoUFt4Ll
         J+1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=wOK0HvHasvG8BvHSuzTRynb7mLVZXil/3F4j1ibYF2o=;
        b=VI2xSqHA+l6+HQbofct+nzw3d8cz6IHFoALRuqkbQ7t9PUpo3K9MPPjeWQJHn72qec
         oipc/KPFparlmcgZ1jbpH7HqGDBdf3AfDi/STgRh2LkAgqfcTBRaqiStHSdpucnz47s6
         1IDeZy+CYAVrLJ/QJ2yBLWGqY0Yjc5hnjEFQpxfIC/ZMpv4+gd/PR9xAKiZPgUhOf2CK
         Fko5bFSG/rEG8AUoCKP0SewgLxhqbZaddxMxH9UrAFZbnsMVd341P3qeNoGsQMpEvLZc
         73qBsoJuOcc+/WvavbzJb9if02pu6WJ8U1Nmi7EUDVvftyVgAqWoMNCVVmvPiBFUWjKr
         pytg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wOK0HvHasvG8BvHSuzTRynb7mLVZXil/3F4j1ibYF2o=;
        b=BT9ufLThsPOHwzmzms6QCxUr7M+vozLYJqoAMpHsaHGXKgNfhw2fpiknlEmOOCI4kD
         In1xH91hqg78B5DsqZTitKpDgGYHwHtOUcDeqaYZIkyHwW5skRREw/eB//nF83LYYLKy
         aRHFVLe8or44PESbCw4U0mse/LeGcNl4MV6FXMpxgbv1Lk61QwlbeE+kt1UPJpxH9RZX
         SJBVunJXzVk+jaJSkeO3JdJn5+NryGyroAzwj7Qz/OCiMy357E3vAnJ3WfXLPb0qcBZn
         ZXfD73+2dX6PugwhpSyY2jZLY1mKkmTUi826epKvowqQrITdgE8ZWYpEbskEVhim8mzY
         xqgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wOK0HvHasvG8BvHSuzTRynb7mLVZXil/3F4j1ibYF2o=;
        b=K3hFhlXfLa4k5lbjq2eqEkSK0n/2hXlmflqIPCnwMSgIicEs+3gOUtF+ANyoHaLhrH
         MQPOal+dwA+OjJHJgL9vEwbX2IBMh14SZkzwLyxU3XED3f9J1saLWJM6pCeAu5PJAYy4
         XMrhYm5l0qPRIuDg3tn9GcdBJzgVKHOQZyPCX+6eOJyZKilfiQYiZtWtcdWId4BPKVKi
         5IwFU1nmphMm/YNQJimfqG6RFvt01xbN1ru/sNcSLp2rcpvOI/TRB4uOd/jyq++KHQs2
         Ii52HxhSCTKFoDJN6mqKoUhcwLjSfL7/t+S0nA98HvyPQgtTVUmuhjLC3Q0gwn4DeTeM
         cyVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/tOrqgeDePEyFVvLGorBZmpzaaerC+fMR7NW5ARd8WjFEzXBW
	Dl4nWwd4F69PlZDPm5P9Eok=
X-Google-Smtp-Source: ABdhPJxQ7ctVUdlp5WTBbfSfjni1a/I9E0xMyrkn/CdCgKF4rSf7Y7f43LaP/swQu78wBD9FKkP5dA==
X-Received: by 2002:a05:600c:1084:: with SMTP id e4mr4281249wmd.144.1590582685125;
        Wed, 27 May 2020 05:31:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c770:: with SMTP id x16ls1429623wmk.3.gmail; Wed, 27 May
 2020 05:31:24 -0700 (PDT)
X-Received: by 2002:a05:600c:34e:: with SMTP id u14mr4200119wmd.16.1590582684717;
        Wed, 27 May 2020 05:31:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590582684; cv=none;
        d=google.com; s=arc-20160816;
        b=B1mPSfnno2K/IIzhfT8WebNiileNEq8papnHbeRiv5BKE9N6bfLiGmiqGB6X8XyTQK
         +UcUqJ++pQDnhfOs/A11wU6bPDUbkkVWnDJcRjs2dOrFLvAfhYpjTghq5t+wQLee5/V0
         qc4U6XYLA0loF6RmXJFiWEDzxNrkVYmhwB061otOEYiai0QaJrjdhxHkpIfsEHqGgo8D
         //TKfXqlF7czZz5BRgWpwYyFuQgHG0NGaxINJId30Y2FmN6k3A1nRL0fHAY9Nom6odhr
         YhN+qO8TpbWPAqU5ZEyWtAC91La6tB7SueSsF6yfVhs/B6K3UHiF7kWIdtiTmxBfSJPr
         58HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=69SZBtRgVv11JV9GwXkF1Esx1we43TtqIdX55EWYkVQ=;
        b=IQRxDSO95oymnIWesRliaLJovNikbJN4Lcws5Gp4USrRGXmcNilnCGib77MQhzw9r6
         +/yi0XldBXob3/NwvjQF+lbKUENRVmPukexcwaOt/md+asZ126ayIcLIrELNoL93gnXU
         qlSDUIuDQoISeypah9PIlFpxk+MRguXvYCZBhoS4GEDvlfQSt9eK1z53xy0XgCAEe2Pd
         KV+bMGxlgRYw0g3krhoOCfYKAMTE0AhEesyt32kMucUsAVNAcZAx5CV+793hRRh6XXfM
         YNIN99+0Z0CJRVN+Ff399HNVsbXvBRhCXfb0c7/yXdJLzZUDaxmvn4tXyOmMnnAfNW4c
         /Djw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.135])
        by gmr-mx.google.com with ESMTPS id f16si182931wrq.5.2020.05.27.05.31.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 May 2020 05:31:24 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.135;
Received: from mail-qk1-f169.google.com ([209.85.222.169]) by
 mrelayeu.kundenserver.de (mreue010 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1N79dk-1ix66C0joi-017SIA; Wed, 27 May 2020 14:31:24 +0200
Received: by mail-qk1-f169.google.com with SMTP id b6so24033076qkh.11;
        Wed, 27 May 2020 05:31:23 -0700 (PDT)
X-Received: by 2002:a37:434b:: with SMTP id q72mr4003383qka.352.1590582683017;
 Wed, 27 May 2020 05:31:23 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
In-Reply-To: <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 27 May 2020 14:31:06 +0200
X-Gmail-Original-Message-ID: <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
Message-ID: <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Sedat Dilek <sedat.dilek@gmail.com>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:ypXYBnlbu7+8qte2/a54rtk72Qau/UhqIXkql49qXpagugfPjeI
 1AZ/LtA0q6kqJoaPoXpLyxlha7YdRK0Cdmj31v7zdYp65hLB82aRsIIl4mlbIdWWsnqsZI+
 fxzEaF8TFe5KuOw1T5JDyTQ0xdrsHr2E6iedWwzrjYnofdKSlj0KgJdYHIggLigJFTdEZO2
 7y9W/2ui/SZ5o/HfQbkGg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:tfaf0rCARNs=:2UlRODD/XCRBbCfpl6xUCo
 eLMKAIAYgyD/4689pHlitEqqlPsC6hASiLDq4PFEk0PiKOsSMwsZV8L3y8l7J1BDcpZ7MUyMb
 kE8B5RRlZw0zmRxvOfcsSkQmDQY7MjoLKigy9P4RmApzeNdIgKpCTSxQSxEAFQ58qkzro7vIl
 TJWzxhiN9hW9LbDRA0gL1Z889MOnS2Lst+pvhakPGbNbUH8IftY8sFbkA2iOfnxQE7W04azbU
 kthut8iz6oxds3TMq+FYoBt5T4NyLQ2OtXCMk8mBzoLTOcIzSbQ8Ipxsmv7RhGfpIeQb6gIb0
 De+pAlEkvtFIhMcSVIiMS0kKXqtq67w/yuum3+pxnnmTqCbWLgvcR0TTLd+Mim3EZNreWovaL
 6pi9uIoVo8Fta8znlLB2bhqdeZTD9fseQJJO2SOP+GbNKlY4cpOKU5w0zrggkfFj8B6+Xbhh9
 3r5C/toPRYgUqt+5jSuZ6hao8jcdvBBwtd4qde+TSnS+hfmVYoxDyJVslrizhOzGT6k4xPKc+
 9/Jzg+pEeRF2wyjC2V4eyqpLxv/Phd8htAf84Gx7+EGsrmtMJSn1Gih8kXwhgGtO960iNHP69
 H/a/AgKT+5jlm49b2H2MjQbh8KvalWA9Njgjjgc3Xvp2p3e7q0OkFolYaKGirGQoXmK7S4WtL
 /0nUcQj+cCbUebo0TLUaj8+Ap2Fy6xC1EwGpTKN0nowF0R0E1x8e7H88Mae8unSOWd0n8CYIB
 Z3BycFyrj7vVJ66GBlTI3kf5FyN5gKVSBaIp0Hd0yLdv5TMZZpMTVpDzwKAjHMAJsFDIQf033
 O/FNfcaTMT9El90v9as4Du+uNiUpAzGGaRBpOaWkIdherr9WW4=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.135 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> >
> > This gives us back 80% of the performance drop on clang, and 50%
> > of the drop I saw with gcc, compared to current mainline.
> >
> > Tested-by: Arnd Bergmann <arnd@arndb.de>
> >
>
> Hi Arnd,
>
> with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?

I meant v5.7.

> I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
>
> Is there a speedup benefit also for Linux v5.7?
> Which patches do I need?

v5.7-rc is the baseline and is the fastest I currently see. On certain files,
I saw an intermittent 10x slowdown that was already fixed earlier, now
linux-next
is more like 2x slowdown for me and 1.2x with this patch on top, so we're
almost back to the speed of linux-5.7.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a04%3DmVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ%40mail.gmail.com.
