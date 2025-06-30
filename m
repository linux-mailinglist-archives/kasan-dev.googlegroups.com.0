Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBXDRDBQMGQEIV7YWVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id D48AFAED4C4
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 08:41:13 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-711136ed77fsf26221627b3.0
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Jun 2025 23:41:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751265670; cv=pass;
        d=google.com; s=arc-20240605;
        b=XU/PgJNYW2u1tE6HkUmUq9wPEJ7h1IxGaCWDGhvvtE0iARd1G9p6QsQMEFrFqLeJN8
         28BOmpwBn9hqHSLN+rjWhl9eXQGTcU1LpVwvNpvKa802NoZC/gz9YWrS1Q1YCnggH8DO
         Xr0uNtzwOkUPkqVX18vgZXhZzsCPKn0pOGx+E3GFRd+SXtmt/zYnZ3McrfddPm/LovIy
         u7dh+SNYNDryeQ4sSfBDVNqlOwic/Sft6IPB4Q7NENexbmMbqW9ejZW8Lti1mVrm2cYA
         tatvLhe0SfNDm/NywMWrduOf7P/Sb3dt52XlUxJ+P3PjHNkP95R1TTQ2ffRyxdHXLzWg
         fOvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7sHEl+I4jv1BBnRFT9uxznsYeSi4IX8a4Pe7Vr1A11Q=;
        fh=1S7ng7RO6OaWcXMgPdCed0uFBwg1TOFnR1SBxphgqmo=;
        b=UQfIfGxgQPwQrJfprEYZqz2ovzCjWIFmJ2mmeFogO5i/2OUeHNq1DdiBrFkK91pkCr
         e0yhSCIHj40npajJk2CbFtJXqQGXf8kuOKhsH+PyIRi8zngCIx8+LXzcYfwzIeAM9Fzt
         50BN8pqkbpigj3jjiq02NaCUH4Y1rsvRQZcv3mZx1Cg6+gwzpKojRmT+fkbmFDyPrJm+
         bBg9dvSxqAoFCKlb23AErsDJ9rKMReN3M6UaWdPnLzForc6b+ljcMlvz8XJCIe0+t2Em
         zpOE382+//gLfrh/tAEJfrX8f5QCWh6T/ukatUv4Wx6ntPlkRePSzcF61xzieCWEQuas
         i6Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OlaPPe7N;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751265670; x=1751870470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7sHEl+I4jv1BBnRFT9uxznsYeSi4IX8a4Pe7Vr1A11Q=;
        b=ujx/+K5EqSMDy9cTVldh4sUa+VhFPSQ6AIrB5uuBayTykw60r6W9AqOdm7/FXqY5tl
         rbt/GupUhXgqUjb40wdtcyKOWJ4r/1QqJIiGLDPZi5E39L0HspoeDM15efq9pswip8vS
         NwK7Rt6FuT1WpNtLOFBHYUwPVwDZM6TVBJ6iZbjf7rIDzkj6Ojciwui0003NH0IVDsVL
         Wjjevs8DlT6wq5D7Oep7B9uR1sAm2zCqkTL1A8u0Et2rOWXe3ryRk8ixT+Se+CkGs8lh
         UXWFJqluhrUYMAly/UrqAjNMjr4SFt1uxnqaL0p1805orztLYp4uiJKhIxB1HT3MhkJD
         ih8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751265670; x=1751870470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7sHEl+I4jv1BBnRFT9uxznsYeSi4IX8a4Pe7Vr1A11Q=;
        b=DHktdWh+mutKW8WDleoEnGqdkeTBnq3pPI2JNy53i/zrXUEEKTfXuHGcEkxTXP7M7Y
         BfSrnL3WicbGzWs1i79stxfI6/SGcHiF555NZ370GjlPBC995QmnSM+0F8AimH0aYgx6
         EUswTO+dxjj7p7FdTN+n6oj4Xo3gZ2/3cXIm0/7iE3BpdqqiYiLiSxApabrFFWQGNycL
         05XRcSvLt9RlIwy/qkh3B127RUW7c+0BAHnZwLbQder14C8Gz+A0zITB3Fu3RnBq/v64
         58/5IwbcBIRmzfsnRsTzGhiZZitRsJ8LP3/kqa/n2bVxu0SiMHi0bEnqqOakW8/DwCqO
         coQw==
X-Forwarded-Encrypted: i=2; AJvYcCX6fft61RD+GhyLao13LcKuPQ/bCHRpaQWq0J5Qq6lTyM9q1i7SbezcSMTmXmZqqMROg1PjXA==@lfdr.de
X-Gm-Message-State: AOJu0YxXPYYa5RCM0vsjgqMyE8gXY2JFw1vzS2FC26ELnN61+DoEAYBF
	IkIwFL7fb1+E7xoVgjhxPgXdKjD5cbmS2BzdbV6fgKfPxa1vCysFhbgt
X-Google-Smtp-Source: AGHT+IHjU5L4iLUmqCHDNgOEASZHUAagRgMtOzG7/LOgEMbk0ymm1aXdwSgFzCZGraLOgVNXooDlhQ==
X-Received: by 2002:a05:6902:10c6:b0:e84:3769:d7e1 with SMTP id 3f1490d57ef6-e87a7af5376mr14659598276.8.1751265670193;
        Sun, 29 Jun 2025 23:41:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdWRVc+CFjGs3ZIcpr4A5F7+KhmU7Nguvg/JWCk5IXaDA==
Received: by 2002:a25:d604:0:b0:e87:c996:a10 with SMTP id 3f1490d57ef6-e87c9960bc0ls799751276.1.-pod-prod-07-us;
 Sun, 29 Jun 2025 23:41:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5JfCeFWXej39SXwnX6/lXFZBGLXYrQyW1oWlKnvkzIaAS+OxhBdk3qu6gPPDCnJ77M+PEWS5QlxE=@googlegroups.com
X-Received: by 2002:a05:690c:1c:b0:70d:ed5d:b4b2 with SMTP id 00721157ae682-7151714e384mr197099837b3.13.1751265669059;
        Sun, 29 Jun 2025 23:41:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751265669; cv=none;
        d=google.com; s=arc-20240605;
        b=c3WGB9niPPHXBVgjR49ozGh5ePNkOHm8nee7eb3Vba/r1wsxxmSeM6HVQeoFADxAPy
         +lVqe5ESpyIw468peR2trijqja0QgHwTS/Yd/gGuhst7I/MOy9pPpL4Z8BzpftzNSDrl
         k64zzzFWP7HM6UUMpSEEulyuVnDJu12ymMpp/smy+Z6jFML3+h//0WiGBjpLLSJ70r2Q
         srbcJnSkUUSr1EdFU42blRzaEVaeMME3y17F0mbz3PL7gvTpnbP8Lh7ddqgBAj0TuDEo
         1u/fDFF5gcFsNzSpTfip5+v1GmthP1sJ8VMp4LsxZbv7G1J9zB4h1yZJHLzYrFTil81a
         mJxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KE4BFQ7g5uCPPVBD+0L/Hx9uj+DiN/T64Ob2w4MxMrM=;
        fh=IKoZ8bqWNSn+XAGYkbi/0QPg2P5VaCCbTBGPPACWgH0=;
        b=aBywKAHBEYg9LOw8fsYkgH5VBZAl0JkWT/uf9JeLZy5P1aU4T9RkWQduH+iy1EjkgK
         gwXD4A/vlzxbGhbJ2c0k7oRKWGEaJm0+5xVMyDomdqOVetrBRoN++Yl0xzSbXrqNsQlH
         vPo6m0lc5H8RgS3E4g46VMUKahhkMvkhVEDK0OjpMWoQ+B2QwppYK/QaSwXN+TGHWeCM
         8DfRjzbiGqoUEmyZUH1RKdilyyeez6IhwCUAtKxmqjX5bMaMOf+ny3r5rLNGrATLyCj6
         2F4dzARpMtwG14RGWsfhXaPL/S1qlynhsobqoEMh+Dido226nPmrt+DpMYzB/N6QrRb7
         SMow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OlaPPe7N;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71515c6993asi883857b3.3.2025.06.29.23.41.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 29 Jun 2025 23:41:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6facf4d8e9eso17691536d6.1
        for <kasan-dev@googlegroups.com>; Sun, 29 Jun 2025 23:41:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX469D0pgZRxR2NKchG23w8CtW/xpbcrRAkKBZ4RaRRNW9EbIA8otEZBfRoCK1e3UhgWOMos/DBRSk=@googlegroups.com
X-Gm-Gg: ASbGncvnUgKx1aHVCTOLZsUERyiit+RqUDYH9PI6KyhQc10SklUlh1IRydhQyuUDZsQ
	qUEAQmJ44I1akPks4JCkp5uiotGNMOfca/F8NesR7JU0Xq8k9ItiwfAMj4P+t7NR16C5tGh0Tkc
	EocuDOQP7oN/T5hBCOclRIiYM71mnIGMZ2s0x1WY4fX28ZWFXBlCwPFCbQlZt55rgYdi2XD72o2
	w==
X-Received: by 2002:a05:6214:b66:b0:701:78e:333 with SMTP id
 6a1803df08f44-701078e0339mr5796426d6.34.1751265668277; Sun, 29 Jun 2025
 23:41:08 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-3-glider@google.com>
 <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com> <CANiq72mEMS+fmR+J2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7=w@mail.gmail.com>
In-Reply-To: <CANiq72mEMS+fmR+J2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7=w@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Jun 2025 08:40:30 +0200
X-Gm-Features: Ac12FXwQ3KyU9JI18-CURSuz4kh9KR0p0Ug2G1ubWlyoHQNeoc8rvy7TtHAb5Yc
Message-ID: <CAG_fn=X9++bk+NROCGZukxrDpL0_F6sSb5oJenEzC9Kwi+zk6A@mail.gmail.com>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Miguel Ojeda <ojeda@kernel.org>, quic_jiangenj@quicinc.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OlaPPe7N;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Jun 29, 2025 at 9:25=E2=80=AFPM Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> On Fri, Jun 27, 2025 at 2:50=E2=80=AFPM Alexander Potapenko <glider@googl=
e.com> wrote:
> >
> > Random fact that I didn't know before: 1788 out of 35503 kernel .c
> > files are already formatted according to the clang-format style.
> > (I expected the number to be much lower)
>
> Nice :)
>
> > I think we can fix this by setting AllowShortFunctionsOnASingleLine:
> > Empty, SplitEmptyFunction: false in .clang-format
> >
> > Miguel, do you think this is a reasonable change?
>
> I have a few changes in the backlog for clang-format that I hope to
> get to soon -- the usual constraints are that the options are
> supported in all LLVMs we support (there are some options that I have
> to take a look into that weren't available back when we added the
> config), and to try to match the style of as much as the kernel as
> possible (i.e. since different files in the kernel do different
> things).

Okay, then for the sake of velocity I can drop this change in v3 and
get back to formatting kcov.c once your changes land.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DX9%2B%2Bbk%2BNROCGZukxrDpL0_F6sSb5oJenEzC9Kwi%2Bzk6A%40mail.gmail.c=
om.
