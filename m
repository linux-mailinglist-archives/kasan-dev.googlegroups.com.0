Return-Path: <kasan-dev+bncBDW2JDUY5AORB6EIXCHAMGQE3BD62GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E63A481F72
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:11:53 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id m15-20020aed27cf000000b002c3def3eefdsf18112142qtg.21
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:11:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891512; cv=pass;
        d=google.com; s=arc-20160816;
        b=R8lPqMx3TfJySEt7qLA4TQ1AdPLMFntNh+KITAWguiOi5TPXNbDcW5V0YV0Gg2Cb7r
         +/vaS9vV3lmKSfhWpy7e/clX1m4g4QE0ENIgGWtN8YbU/6KKdmh2ojbtpayb7XLtXf7k
         fW8Wa05t6uO+o2Tif6Rk43jlkTqz07TPbm5KLYvF5P47xMgVW/4G/ldsabFvyJKTID0k
         lQQUHJjbHgeKwF3RMAfoQGyka14jYsgsXM4aR7iCnnrhXNegl56U5ZFaA+ZIDqJVTpQo
         V+4kXISDi906QfnSAAqXQYK5LyoTBspPKvbjVLgsoXOtQm/lreaQR0bxK0R05W5vij5Z
         QVQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=il6gFGEf2r7g0jQkk+gRWGZNTX1oTsjny7FB78eqM4g=;
        b=LZ87Qckb/Y6oks76liALyIcHzuWfdVvCUAha2TjfG1c9bDx2cTUCdajVQTZHILsx4Y
         NhBL+w80X3lCCRpxs2Z5L7ap3MNo/NKwY6aVRh04pIF9fp2rH0JJ/IhkKPU8h7Q7juEp
         Ls34EgiffI1iQy7q1bdxCLbhQW2jrdNdt2QrtWzZvvlYKhsPqIq5qeQA1FG/Zdo80mlg
         l97FdaNTr+93U7oU+koM4fzUtBdWqt+6LfUtVW+YrfnIjMUbm6QHUPOEQQJIvW0FYkYl
         tngu/r1nfgqGSfttuUI1C3h0/EwUC30eLStFaLCP47+dYvBHwxddrCucphaicNiuDZ+r
         32kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lxXkzKjF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=il6gFGEf2r7g0jQkk+gRWGZNTX1oTsjny7FB78eqM4g=;
        b=sF6KKz91Xg48XcNTEOBQeppbft9JMpnPqBcFD75Nzzgx1AP0TcUlilYoP9Fqxzgv93
         /1SNSpSZ49/5floIBcf0sV4OsjmWiSvxEDPV36HCJlyjqgmlBT2Pbz+6judgr1PUySSz
         OyIKuyM3DX4NGdbwPHavnK7jI0Jbs9yjOa5XnmDx0rZUvOkrHqkHCVZv+e7HOisAuJMm
         jLTRPB30xbZkpHh3IthBke+2l6PF61NrmgOJMvSlcjWeJj2/41B1J9gYlsIf5tvkcKOG
         XJOpA82bCXSHGs5jQsUfgsAaqPhYeIWbAJ2Qv8d5ILBlLQK0yXhmjw/LA5CAe1Z2CLJ3
         uNlw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=il6gFGEf2r7g0jQkk+gRWGZNTX1oTsjny7FB78eqM4g=;
        b=mTwbheEuvuy5iTPWt2HPYd5XfueUILD4KRyHdal1EVfG9X6Uh3aMlyaYqpuN/HaXtd
         APT6aP7R+CEY0dEoB38kS+3ARUQDbbjpdwCi4zysjDlYLvdEKQZF6PezSHcXv4K/QwOC
         Jv3AgYLaNjC3Kd2EvPm/cOTJGEMgHJbHYvNtN0zFBft5gxoL7UfTOvyq5Kw+Mh96JT3i
         KFbRQhPHpko3QXI+ft5jhPCSkd2mv4JYlboMiWhoEpXZTKUoZia6jFDPrQoOHBDShvrq
         nnV8wTSAa8E6/dv+IOTcsMwzDyk4Z6wqY9FIw9ajlI/O97yVuCyYwPcC7liMjIfwbKTN
         xpvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=il6gFGEf2r7g0jQkk+gRWGZNTX1oTsjny7FB78eqM4g=;
        b=DaPnGe2iGGKQjg/7mDHRpM6xIM9eVXBZwJsrYzVKEfkq2xK4BLPqZPe3gu1z6ippqw
         cq9XyECzlgRHKf4q0MebzKFdf0uNjodgEzygmxw9HBMhs5NR4JPKPUUMgtHR2QLlzdRo
         NEruxj+4aieYYHze1Dv7FaT7fr6V6f0azS9ie2PQZfCDFl+i1SKKVO/hELkOEVK+Pt74
         VY5vUKWJwvydi450R5l4q75jZpeVj232pastIJ/cZKNr4C2PIctEQ79aueKnAXyjn7nR
         pkKGv3TRLEfHZgD5jW4qO8hQpBM/b7aNaiCse6yf8erlS4k658/lFVdh0rJmZWbaFFGQ
         xR/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QsSBWya48qger1RlF+1FRZfZPPG2lE73d6GScvc+r9H3canM/
	Nr66xF4kBidXAXAWajHlhUY=
X-Google-Smtp-Source: ABdhPJwWWefprV2/ikN9rnIQn08EUPYZjWwDaJr8+PvNuzPVcSq+gkP773LPBmr58s3tgyA/Q/CLzQ==
X-Received: by 2002:ac8:7dd1:: with SMTP id c17mr26915178qte.508.1640891512177;
        Thu, 30 Dec 2021 11:11:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:294b:: with SMTP id n11ls13000392qkp.3.gmail; Thu,
 30 Dec 2021 11:11:51 -0800 (PST)
X-Received: by 2002:a05:620a:4589:: with SMTP id bp9mr22135033qkb.515.1640891511766;
        Thu, 30 Dec 2021 11:11:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891511; cv=none;
        d=google.com; s=arc-20160816;
        b=wBtUqLgSnoc3Yt8aqcIAs+2bNs2rUZVvbGVn95ASf2sPicjXWaWXvY6tKYfFqv87vj
         qkZkTHbAev/JIMTStKtfSszeA6eUxbo1ch/JQekbRMTPRwaOIa6hbzSb1n7BYiM1L0fX
         o/EyRAwBatZ+ehEfaTUymowNoW9RO1G2soHls+BWhRMLwLkvQramXV5QR2vy13J1vUyf
         JFWw4J3nFAEKs4GG7o+X5lBWgcervUxjp8s8Nnn8CIS0u/Js0zaupgGWFmCdilT1F7F/
         m/8S04NC6IdK8V/eaT7vFuTpTIKCVe9jLwfeWKQElnuGcmLVPG54PzP32YHHZjzVEuiS
         OpBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tpkNpBZChdk2znmZ7eLMiI56h6rQ1/cUXgZFrI/xFps=;
        b=e9gTThQm0ZP7yQQaxEH6lIGuTS0yforThDK/kluAguACoA+dZK7ozQGoXcbYJZ/ABa
         7nUQvLB2k1F81EYLkMLR46BgjVhpmJ3LlJbOnJ5pA+pyHx9+sEtm/UDAnNXy9nRRbDyM
         G3mEGhpuNQ10/deUCCh+wVxk9W9xJPagCDGRNGivX2iiFDe3jAwcgRClYVOits0MgQrf
         CU6iNvdXN3ET+AE89gL/brTe62bOQSQxEezH/03P9xLbD6tuwK0n3ncQ573WrIAENANE
         Gz57ZPd21CX/NT2AxNA9Esjfe+ZNRaLGMmefeWgXn2D1TDMGn4fVr5DjaG6DryX4gre7
         T/ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lxXkzKjF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 22si3504642qty.4.2021.12.30.11.11.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:11:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id x15so19557491ilc.5
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:11:51 -0800 (PST)
X-Received: by 2002:a05:6e02:1bec:: with SMTP id y12mr15620663ilv.233.1640891511371;
 Thu, 30 Dec 2021 11:11:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <f7e26047d2fb7b963aebb894a23989cd830265bd.1640036051.git.andreyknvl@google.com>
 <CAG_fn=VUBm7Q74u=U29zn3Ba75PsQNsObqjcH_=14cosGU8bug@mail.gmail.com>
In-Reply-To: <CAG_fn=VUBm7Q74u=U29zn3Ba75PsQNsObqjcH_=14cosGU8bug@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:11:40 +0100
Message-ID: <CA+fCnZd-Z6ySi0dqkZjgEfD2sRDvDiHc5bgxDF=x_yB1+kOLJw@mail.gmail.com>
Subject: Re: [PATCH mm v4 35/39] kasan: add kasan.vmalloc command line flag
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=lxXkzKjF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b
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

On Tue, Dec 21, 2021 at 3:43 PM Alexander Potapenko <glider@google.com> wrote:
>
> >
> > +       switch (kasan_arg_vmalloc) {
> > +       case KASAN_ARG_VMALLOC_DEFAULT:
> > +               /* Default to enabling vmalloc tagging. */
> > +               fallthrough;
> > +       case KASAN_ARG_VMALLOC_ON:
> > +               static_branch_enable(&kasan_flag_vmalloc);
> > +               break;
> > +       case KASAN_ARG_VMALLOC_OFF:
> > +               /* Do nothing, kasan_flag_vmalloc keeps its default value. */
> > +               break;
> > +       }
>
> I think we should be setting the default when defining the static key
> (e.g. in this case it should be DEFINE_STATIC_KEY_TRUE), so that:
>  - the _DEFAULT case is always empty;
>  - the _ON case explicitly enables the static branch
>  - the _OFF case explicitly disables the branch
> This way we'll only need to change DEFINE_STATIC_KEY_TRUE to
> DEFINE_STATIC_KEY_FALSE if we want to change the default, but we don't
> have to mess up with the rest of the code.
> Right now the switch statement is confusing, because the _OFF case
> refers to some "default" value, whereas the _DEFAULT one actively
> changes the state.
>
> I see that this code is copied from kasan_flag_stacktrace
> implementation, and my comment also applies there (but I don't insist
> on fixing that one right now).

Will do in v5. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd-Z6ySi0dqkZjgEfD2sRDvDiHc5bgxDF%3Dx_yB1%2BkOLJw%40mail.gmail.com.
