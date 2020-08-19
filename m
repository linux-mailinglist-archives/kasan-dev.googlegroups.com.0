Return-Path: <kasan-dev+bncBDD7DG76TIGBBMM56T4QKGQEPHW4O4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 383AA249BEB
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 13:36:19 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id y7sf15431710qvj.11
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 04:36:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597836978; cv=pass;
        d=google.com; s=arc-20160816;
        b=XdGt55feWnDmIxS32B1pFwwAhUsKAkpgyrS5oy3CPIy0kyc+NZb1WdPCs117Z4WYCs
         YXdatL7rA8cNMsuxLrqL1KQmeOjlING3Vkj0AB2ERDZvMpDbdLWIQOyOqknGClWdc+HJ
         D/atuM8v5XppMSsnLfi5y2k78DoZpc+uzhBd5rEDmODQ3SktG6Chvz2VfFjF4Cz6cLSA
         CU04Sy2u1CbAp+xiRwM0SJNjefK+s2ArIOmBLFR3+kBrMDAPPxTFIDmsC4i8FC0Kst4s
         IXyEmI6QJw8WR7Hdmwf4PPX7WMiL1F0KcBXlpzYOzpr+vsCK9N6dBG3eEavJpL45c7ZE
         f1bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=eDfs4CVPNavycF2EYtRlj3h99dt5uftcYkUzH2WsOPA=;
        b=HI/9bOvxRJcBFIQdGsHs0JHLqPt/xNlfng8BSx9Hqvbo0CqtpnwOZMhhRSWfRLGeyy
         CsparTkFBqVChmGabns7esDZlx/Kw0TjEtnbjTN+1qsEtFAWq/oK8Ik3xHYfUiZ6r6/v
         dt/IUKs/exLc3Ib1Y6unuVaEoUlSDlgf7Np2umj8n3xkGbb84qTKLKI+k+Kh41GzVNSz
         +WeEIhmykisFPKBoWNrAuB8zbOSLTezpm4E+M1oM6nMPKyVNzWpRfzLWhwDFAMVWIlPZ
         E6dI8gfaSqxycNkOKY3bwkQIEIv0Fr264rt6s22IrR0v6URJ8E9tq2WkZGTNnLT/Maz5
         gW/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NLIcYPh2;
       spf=pass (google.com: domain of yhajug0012@gmail.com designates 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=yhajug0012@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eDfs4CVPNavycF2EYtRlj3h99dt5uftcYkUzH2WsOPA=;
        b=Mic46yni/Vw3itiM5pWbmhC/sE5v+ttWx24q6NMdpJcv764mfW7OxmHiC9tckucFzO
         Q+ecwFSiacay0CU9RNwP92FZF4T9SP86cFd/s0SRR6WzuNuyeuTebNmKKAnCl/duqegd
         ortL+2AEN/x6Ds6wlAJgppMPMW3DEpdxoobTau6Z4a0VG8IdWEDIqShLv54es0v3SnUT
         7uBmzlNGRi2lplu5q3hO4UZr/2UFktqGq/QaL67AGLL96EKQCjQayCMkWdVp9D1ljspq
         R31JX/eiiICA0RegcqlaP8qicM+PAbM7FqbpnpeTahisAmai64U2jUqw8UM5XJG7xcae
         tzkg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eDfs4CVPNavycF2EYtRlj3h99dt5uftcYkUzH2WsOPA=;
        b=g59l76XimrEJKZVeNMKeGBoiI19UbQytVCjpQpfdNk/yaxcPsyifkRx1jh9G1l4OBP
         HoP6FNBZPL3kpDQD85c6w2eH+HqvObtOCaOKxkou0Jbqk2ODS2HocjWJzaV/zmFfzipg
         e2QkEVepBkb/6ZYuRFvcEvWNTDa0PzBg1xCjFtP5+JxggUreOmMfR1GM9BenBWfZeU4m
         gCz73LWrp1hhAgkEJZXEVCRhRIOVC6qGBxE0onCWLxdp1JC7Fd3QnRAIaHWgZG3APE0S
         ztCX779IYFhjUuzCfAtOhhGnh1xc2gjR8Mbvhm8N/zS+4IXdKvganZ6LqCU02Bdftrb4
         //1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eDfs4CVPNavycF2EYtRlj3h99dt5uftcYkUzH2WsOPA=;
        b=JXWY4Nba3ACRsh2GKRu95F/vTFwh4yrMY6qJVo51YNeRf4J9VWJofLiAcn1NlwIm3q
         aTrXBfSRunTHSwgIrgZiTFRaREDENy21+p8zEotB0XQqPtsli6pBCGOx15K9pDqMYIhS
         HOkiMFMVhEyEwn4T8224p1pSXVtnnkyAsCXYVXUz1xwQA59wZJYU8U7VaghNIQpBxnQa
         PHda9MeA6mvuPh0kekFZNW28Y1dEmjmv/ABfMNZI1q5ccU52tHNYDTPQVqQiU9hXcoVK
         2xWySCJ1KlQulSCiXDLtwcCZka3rMzWutv/F4+8yZGFc4oj6s8xi85B06hO2wMMtft3k
         a2Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xL89UBgTeb0SbOaeZwHQjHnPwIAWSCs4vhRl7883dnWuQYz+e
	br8hDp+Qo/7OCEfP5+RxWYc=
X-Google-Smtp-Source: ABdhPJx9Pvt7az1BEYg/5KL5hM35gtbp0PaHBW/Cy4RF9ZzdJtnTppwKrcnU1NxuJ0Em1ftkn7c0Tg==
X-Received: by 2002:a05:620a:388:: with SMTP id q8mr20391797qkm.98.1597836977852;
        Wed, 19 Aug 2020 04:36:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:13c9:: with SMTP id g9ls2139426qkl.4.gmail; Wed, 19
 Aug 2020 04:36:17 -0700 (PDT)
X-Received: by 2002:a05:620a:150f:: with SMTP id i15mr21103865qkk.152.1597836977551;
        Wed, 19 Aug 2020 04:36:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597836977; cv=none;
        d=google.com; s=arc-20160816;
        b=BplV3bAASME0a848kfHXyddyfMLtCK+/NWprV5hUIhSwvvpEDB2S5gIW5ppiHNNroa
         dRfdzf+GkcthbFLilVNnoEwa8QUdDyMk01+GUPUjrPlDwrwhSQryEVuNyAFdhkdDJFKa
         AgNzTSVE7zOvP4DNBksqSydiyApgG0vnhzzRSkvdFOyupsE+Myq0RHZBnrCdlJ5SqyWJ
         ULsxbxLPsUpTNIFMJPXSy3M2Skvfe0z3nOEWbQudvcMrXTToQwRhMIwKlbCgvyv0e7Bq
         UIz7VyJcBIppw33p5ZlXGb3a8yb7JUCDSGXm4xbzIYHksHHdrr4dEM8RJcomM77xszoM
         TAVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3H3/BwWRUxBZHEL7YRgf2daDXWMwZwyjWv7M+Z0wF5w=;
        b=0yoydgc7dIehJ8uImAx4DDarSeGtfalDNSPjSBa3F3fzxM5N3iVCyzXbeMMpI+c5FI
         8eV6k+wuGYRJPVOGW4agzURSvjautw8RGoCFJgmP5JvsCG7A2xN7YG+7s5afUxZu3TZY
         hMEYo9scvXib2SQyEewlglGLiDyuZtKZLzd+zN5ST0aGB+tsJwsMvWtTq7kdbdSfOOpD
         S2GrbfoS9Wt0uGS0nQm78+TKvwoOsK063/ncP//GEyUroYeuHsevTf1lrViv9hBpFcHS
         TABLFM08WnmAAUpFq2dzTXHwbhTggrd3D7E2svlmyQwKfzgV/WsJFRh8zjw0VvEHMjcd
         HKLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NLIcYPh2;
       spf=pass (google.com: domain of yhajug0012@gmail.com designates 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=yhajug0012@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb41.google.com (mail-yb1-xb41.google.com. [2607:f8b0:4864:20::b41])
        by gmr-mx.google.com with ESMTPS id m13si1354092qtn.0.2020.08.19.04.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Aug 2020 04:36:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of yhajug0012@gmail.com designates 2607:f8b0:4864:20::b41 as permitted sender) client-ip=2607:f8b0:4864:20::b41;
Received: by mail-yb1-xb41.google.com with SMTP id m200so13139709ybf.10
        for <kasan-dev@googlegroups.com>; Wed, 19 Aug 2020 04:36:17 -0700 (PDT)
X-Received: by 2002:a25:e712:: with SMTP id e18mr15127823ybh.395.1597836977247;
 Wed, 19 Aug 2020 04:36:17 -0700 (PDT)
MIME-Version: 1.0
References: <CAJSYYSUZFTWakvGWVuw+UYdMNs40zCSQt=mszp4H=on4YaZsnA@mail.gmail.com>
 <CACT4Y+bLNzbhkJi10v4pqffaRjTsPTwNe+RmB1cjgqSdbHbGaA@mail.gmail.com> <CANpmjNPEVm9A6+ByZmzae6i=jJOjiH+g6LCrgGdB-JEdB+8c_g@mail.gmail.com>
In-Reply-To: <CANpmjNPEVm9A6+ByZmzae6i=jJOjiH+g6LCrgGdB-JEdB+8c_g@mail.gmail.com>
From: V4bel <yhajug0012@gmail.com>
Date: Wed, 19 Aug 2020 20:36:06 +0900
Message-ID: <CAJSYYSW7WDwBzfB1iC09z4Wg7VNRmMq7XC7bXE2P+n-Z_9h9bQ@mail.gmail.com>
Subject: Re: Hi ! I have a question regarding the CONFIG_KASAN option.
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yhajug0012@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=NLIcYPh2;       spf=pass
 (google.com: domain of yhajug0012@gmail.com designates 2607:f8b0:4864:20::b41
 as permitted sender) smtp.mailfrom=yhajug0012@gmail.com;       dmarc=pass
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

It was solved by upgrading the gcc version. Thank you !

2020=EB=85=84 8=EC=9B=94 19=EC=9D=BC (=EC=88=98) =EC=98=A4=ED=9B=84 4:17, M=
arco Elver <elver@google.com>=EB=8B=98=EC=9D=B4 =EC=9E=91=EC=84=B1:
>
> On Wed, 19 Aug 2020 at 08:59, 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > On Tue, Aug 18, 2020 at 9:03 PM V4bel <yhajug0012@gmail.com> wrote:
> > >
> > > After downloading the 5.8 version of the Linux kernel source from
> > > here, I checked the .config file after doing `make defconfig` and
> > > found that there was no KASAN_CONFIG option.
> > >
> > > These were the only options associated with KASAN :
> > > ---
> > > 4524 CONFIG_HAVE_ARCH_KASAN=3Dy
> > > 4525 CONFIG_HAVE_ARCH_KASAN_VMALLOC=3Dy
> > > 4526 CONFIG_CC_HAS_KASAN_GENERIC=3Dy
> > > 4527 CONFIG_KASAN_STACK=3D1
> > > 4528 # end of Memory Debugging
> > > ---
>
> You seem to be missing CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS, which
> means your compiler is too old. Please upgrade to at least GCC 8.3 or
> later.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJSYYSW7WDwBzfB1iC09z4Wg7VNRmMq7XC7bXE2P%2Bn-Z_9h9bQ%40mail.gmai=
l.com.
