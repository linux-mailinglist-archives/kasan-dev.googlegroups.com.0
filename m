Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEEHTL3AKGQEESH76PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B77B1DCE38
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:35:14 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id c18sf2971902pls.5
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:35:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590068113; cv=pass;
        d=google.com; s=arc-20160816;
        b=LPsjaFtAygtlL15ZPDdefMOtEuFeMJH9hW6YGjtNLlrNSA7Dyb8UT8dchbP/5peq52
         uJ2hVOh0xHMJtiAU4+pIkUoY6d/PqdB43TpZv5R19hIDaxs9ws9xxIj39O12Yr3UZD4j
         aBRjvslbOkb95SW9bU5GJQAgWYFzQC5X0xK56wKb8Lo5GEuYJN9CFtB9G4jBbUVkEaWh
         V7rxR09aqPmMKFhfl6M70c2Jxc8P+/kMKV4ALKuJPdB1ynwJ50VIJznoznga6hjlirf0
         pN0faVhIXQNfaZx8UyejNL0pUQYV97QNv+dQR6cDJsRR2aSIY6mCMSrF5ikpGiFsOeIw
         lJuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sgQCKNMVDu3xwjVyP3CnBS3L3DGbRmBXanFpC/x7lug=;
        b=MI2a6H9/9aE/usYGobZ8EAT99sH0nF3IwAc03dkOoY56fpH964MYxtxQHCNdZr0qco
         JwrC44eS9Y/J125rQfUebJGFSPZXC4dJX/Oahor89YB9Hx43FNu20uSPKnaqWiuuot42
         XuF/xT/8vDp3hrX5cPtSNINBDZ/AhXmh4nNZ4ZhDqcpRDye1XssoryHnywqiWJQlqb0B
         N97LNLE7ilijLA0ErWopkC31mS2vgJJn6qQRnLig1Xspe4lt3UuenX2UCIwfrBUJtBG0
         ikCB3mtEK5p2Tv8DN5simGamgnzUziYRV3n/S1ThaaSThrLTvP5Ue82+VS3X/wxD/yK1
         gizA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lbnlAAnr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sgQCKNMVDu3xwjVyP3CnBS3L3DGbRmBXanFpC/x7lug=;
        b=GPtmmJOPogoVhaT0ducUZjCRxQygNLFRU3/FG5Gck4ZjPWf4LUvDeVhuuFkern8e76
         6304EhZJl24Mk0V/6N5i8C6fNcAMiU+jLUhX//6yP/sC9sm+oGhaf71nynyyVyIJYbXf
         ZuoETT2tMuXL5IHssp2bq5TdNW1yPGmifTYly1H4iYCi6ENKa3fMK38w13YTlxbWHXmw
         iPXB8hMdlIf+noD/39og/Su+Enhnr3MJExMrPamgyFJO3FThSQOLOnyFgIrAxTCScSM3
         Pf3kTr1LDEx5ZstNwpI6Qv8mnTu9GMX6Kyt2dbeoOszUGMFS397zbCzW8/d08DtJg9/L
         ge2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sgQCKNMVDu3xwjVyP3CnBS3L3DGbRmBXanFpC/x7lug=;
        b=DNBfNk0Pxqh4ufz03hiVQcNs3bPFlbYzAdp0R5W/1YG6g2DPm/GJvPNpMB8STcxTs+
         hiyMRuPFOfjLQmcuAUhfvxvfGWYe85Kuo9oTVo5sTU/JaHdmIdw7u9qVmQTeeDKjIl8W
         3q1aIeZ7huqv7gBb2ZYbandX+IqkG0JFEnWvaKTIJ2n0LICGfkoCs1G7rbLdd8FazKus
         jKvASee6UYRRWAtPW0LD+MDc4v9uAA/d3k9F083kr5oD70eOZk+4a+EYqNyU+pgZd5so
         FWEH74oqQ4vd00IU+uEPepNPtj7fqigZDMQ8cBhdyh1B6G0RrN2C6SlWfO2hTuTtBvLT
         tU0A==
X-Gm-Message-State: AOAM532SHMuusTy2J7ZcSlqU5p8PjXMbP1d/eNXYCBy0ryA1G2nGKFI1
	jzWklIc4rS5z7Si/J1zZMw4=
X-Google-Smtp-Source: ABdhPJzE/hYn7a36CcAX2TNdObphxgQ2dlpdiqOp+V+5jdbGVKqexxkk+7SWxRKipo/jMBKNIV/LBQ==
X-Received: by 2002:a17:90a:a608:: with SMTP id c8mr11288028pjq.90.1590068112868;
        Thu, 21 May 2020 06:35:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d713:: with SMTP id w19ls839035ply.9.gmail; Thu, 21
 May 2020 06:35:12 -0700 (PDT)
X-Received: by 2002:a17:90a:4e5:: with SMTP id g92mr11510614pjg.148.1590068112256;
        Thu, 21 May 2020 06:35:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590068112; cv=none;
        d=google.com; s=arc-20160816;
        b=v0GFzwwZLR3TqxwA0PXuRQ38bRB2HnUwZDz0O4sGCTQx98uwDBfUhNNLKUOsuPwwEu
         oKsdZxZmcwBs75T01d3u7JCBghfthCAI5gQtuZsDjnNkAoNkNfdmW2hT2AP7xr+tamj/
         DLNcFMMTtVzejAwYL8+ff4mU4cN1vn9gC+zfhGlrB8csIPJgeOg1b2+EdOjbRnuaKr1+
         UB6e4/k6yZN90QnL9oJXF143Kyubk98x5v+2OrhyFDpIxvUFxlBV08SC0G2nsUv/A07r
         7IduTCr5qo4SypiChYgdmwtyO5RtC/ACec+2fGdc5UmQVlu9MSvjPke7cq8uQQDG50Kh
         gRoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zx1Zxii7kuqEBAAZh/SfralQu7+w6Yj6Omise5zlDew=;
        b=AnVIzSJKwdSh+x5vZIPv7Qfob9uv7nyEmHgAZCq5H1XCabiV6+T8am91656/3nRfuQ
         ZYScvVLrSf7CBpJkkjgeRdVqVMbfhpqK9e7XfLJBDR+5TDCmPePm5N3fYfVStykwhGb2
         pq74RzswQsw/uCOml0G4ZoLSLRz0UbT220sY/nPy5dU6/XD8u57dF50OQFx8AyczriCo
         8Ckpa949AoL09NpHUWrMLVOsZqJV2ThwGpLzcQwRv65AB5Eon/FckcqSHVCB3i9nVVww
         NYLFS73F6PM3Eo1o6xScGGOTrKE6uCFleooRrXGxc5We7sj99q2BgfQeffTPbcKul7QP
         POzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lbnlAAnr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id a1si367305plp.2.2020.05.21.06.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 06:35:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id y85so6164835oie.11
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 06:35:12 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr6839565oih.70.1590068111768;
 Thu, 21 May 2020 06:35:11 -0700 (PDT)
MIME-Version: 1.0
References: <20200521110854.114437-1-elver@google.com> <20200521110854.114437-8-elver@google.com>
 <20200521133322.GC6608@willie-the-truck>
In-Reply-To: <20200521133322.GC6608@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 15:35:00 +0200
Message-ID: <CANpmjNNgQkw77uATD0jWezXheX0ZtKK9GcgWd_EQu1_u-m3PoA@mail.gmail.com>
Subject: Re: [PATCH -tip v2 07/11] kcsan: Update Documentation to change
 supported compilers
To: Will Deacon <will@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lbnlAAnr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Thu, 21 May 2020 at 15:33, Will Deacon <will@kernel.org> wrote:
>
> On Thu, May 21, 2020 at 01:08:50PM +0200, Marco Elver wrote:
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  Documentation/dev-tools/kcsan.rst | 9 +--------
> >  1 file changed, 1 insertion(+), 8 deletions(-)
>
> -ENOCOMMITMSG

Oops. Ok, then there will be a v3.

> Will
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521133322.GC6608%40willie-the-truck.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNgQkw77uATD0jWezXheX0ZtKK9GcgWd_EQu1_u-m3PoA%40mail.gmail.com.
