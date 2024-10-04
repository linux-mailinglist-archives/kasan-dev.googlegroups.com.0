Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQX6723QMGQEW673L5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 024DF990094
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 12:11:17 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2e072f4300csf2653079a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 03:11:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728036675; cv=pass;
        d=google.com; s=arc-20240605;
        b=MYBQGUH5XzREI0b0/Pw2JXcMFxkk22vaa3cYxPNISB6f+FOr1LmjccMdMfeXPmbGWr
         mNhLI31IwdgfGBeTH1TKpbQUhLXIgmtARNowz4/NrQNqiBx2cA1CvS69UuNzVQ0xXuh6
         Ii2TzxEL3/V2fF8DiMEWbCPkT3/AQerQXkY6tpLOoBT//e+VBKGtNRhzDRQvqSeq3Ydz
         crFav1x706cMmBEEL4Pfu4RYZNh50/cYHo1QdjPX4p4b89mFcoBz6FKttkYnha/RqXSP
         r3j4KADDG9NquLtfmYbWbSyoVUrZIECorHLGQKBaEiCJiuz4/ivTIJUecE1nKCU6Vd/J
         OKeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iNYLl7moxA+uPTjwD5TWZU6bQW0nwTBjPWXeZIVqpP8=;
        fh=76XvYSHBwC4ZN58nLf6IaI9lO5DotoW0a5EAwRhhXAA=;
        b=WuDG8YW9lKZ7r+bAiDYwKq0oRAdFDt3mzxm7whEM1GTnDtb/LQK3iw6FKQBjXb94nk
         hgd40kRaQjsAskgAIqQzjf+OG2rOM6STqb2mMQnRyJie+IEe2+e+hA8OFz2552b9Qgqr
         uVxyfMAtn1PxS8ojZiO/FTT35ZiTFwoyk8r5wfhG9YV1HwwJ0dm++3zMlMSHcXTLTXx3
         wai/j2vw0XCHGL5RCkUD+lnd4TN/ichZ05sUFjNdcL2lLY/VMBbbOnW9S0QRs9M48+7a
         mBTopGzNc9QrkKL7LyajEctDk2RvgGd/ezVbXislkhraFQuOTM4UkeYlqJdDezBeEdJK
         O8mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IxJMEcQK;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728036675; x=1728641475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iNYLl7moxA+uPTjwD5TWZU6bQW0nwTBjPWXeZIVqpP8=;
        b=tKlFbWDAlhBKt2OLzyMKFHN3LuiSuhiDR4J8eNpM2bAH3Bo5ff1JON0fbqACY3bDoB
         rYGDhHi0nprrnxPj/hFesS14tQBrZkCr9GEcV5nhyrDKrcPbYnmOHSrhS+jCGBK7eqcV
         3JMb7KvA870epG85Cxaqk7uoAvXpKR1etMQuFXKl/0zVqZnSxv5eqtrl7Enyz+9+UYX7
         RS1VN7P4aCqoSP58SpXGafC7A4wXMua55wEaGY5v3+M3pE1zgDITE4WUWz3zj/zRwC8G
         Eiu1piFmu6D0xQvn4IKTCmNUqQHV4Ivx9wlE//Spx53N5Yfw4yaitYlFln2aFUw8Ya+0
         +DCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728036675; x=1728641475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iNYLl7moxA+uPTjwD5TWZU6bQW0nwTBjPWXeZIVqpP8=;
        b=tpAJZsDTrCsCF66vAwFb0yqYMwT2xjg+9EWHDSMyuwXeRvd6AH8/Tml9hY6JmzVYoA
         QIFxlya0sb0BVIBCHr2LikDEqXDPk6tgCN2flmAtL+A+bMtufpg1Ol6hsVTLzw3wFUsL
         O6FWFCkI4Lmg3VEzh0GxzAXH9Hen08DsqvUBt3PsuRoo6ttfuFBLARJgDENqnX4c0tN/
         7RIb4hScg8mjHaIZdlFkWAyaUw2xjuPOZZVDF/2MDqqGtuxZcUV2J66Trht8sFL/K4s6
         2V3AbbTPoIsSpdAYycKl0HyFadgP2q1nxsfECXPqzCYxzavXZCvcRdc3ixOUD8NlACUU
         ub0A==
X-Forwarded-Encrypted: i=2; AJvYcCWYZF1pHrFD5UoicqtJ0jw/gKf1IEZe9LFOsI/H0JkUVwD99ZrDYxVPnNtkgNAaLVB7AHy4dw==@lfdr.de
X-Gm-Message-State: AOJu0YyRYkZB0kY4DhbsO5bshAxmyoUDzQgn1MDcmZOcZh3HOplChRoE
	pePe9GiocuY0NOVeCy/pt6muCVh5SRnpsgvNWLJpdDOBdoBIuYm4
X-Google-Smtp-Source: AGHT+IEvf7OEYfFYet6nE1Y4Me40w3RAoHBfDCthPrOiOf835rSU7znD8nDpXESxP9vcN3VDivLbrw==
X-Received: by 2002:a17:90b:360f:b0:2d8:8175:38c9 with SMTP id 98e67ed59e1d1-2e1e626c076mr2714027a91.20.1728036674749;
        Fri, 04 Oct 2024 03:11:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d810:b0:2e0:7e59:ea75 with SMTP id
 98e67ed59e1d1-2e1b393bf0dls1395442a91.2.-pod-prod-03-us; Fri, 04 Oct 2024
 03:11:13 -0700 (PDT)
X-Received: by 2002:a17:90b:1741:b0:2e0:9236:5bb1 with SMTP id 98e67ed59e1d1-2e1e631e495mr2510219a91.30.1728036673460;
        Fri, 04 Oct 2024 03:11:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728036673; cv=none;
        d=google.com; s=arc-20240605;
        b=YBqt294uZ7cnYyn0132wULhQ+lFOCUKol1w/SkYkIK4xwWuZk0Yjlb1RObxRSqPPPF
         4BCcXlt7+hVi/HVRGbHxfiKTmG/AYUcRRfubfo2/Dd0nrk8sd6u4xM94Tj+R+HF7bSkj
         Csfl8nESEElczMzKIDMtMV3jA3zQtyLwnqTbXPTUpQGCnB/1cVV8bfpSe3Jqw16/QFe1
         zMALg/DLzvFQWdgJ9jjoDk/1cFTUe12fBr5ycPKhw5WIuJgU7zw4H/xCFl8dIVV/bujx
         rXsSVKPo9WbLADznL6Q9xsu65G57hsLcrM85vjpEibBWGM9lYamD3rpPUuJotRRPfAZv
         DwnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7KHHpVp6y8ZuxSeBN4nLG/jfkLEBhk/D2YxBCThCvj4=;
        fh=UAeXtNxKh0BM+AxS008YifsPDP5nTivO2JMNWVUqVnQ=;
        b=Oq7ir1v8VfuLwQlPoKtX0STmBzF7OOnczieOKVwBWJKzO5gHuBb5sCoJkcclUz0ejn
         8sRElC6GlAdluswyMdnEysOTksIQsaus/Cghz01toFYBPzyoOloO9miLVL5Dn4rX8L/1
         toNdVPn5lPxkHSMRMZd/oHGKVlfHozDMxipRxi4a1HDvcqOWa9X+lf4W42C5CFEJTxgF
         mCmN3OJupwysQ1uAZEZls8juuzqLf7bTgKJcB7CREC9ylQCBwI6rJGRIjNbEHf6JCnwR
         YepW6ANQCYmK+aNoHtuWMkGhnjvkqDuOwvdX/c9kobPi8to/4+9XqysRUUj5iuuv4xnz
         MsMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IxJMEcQK;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e1e60a9be1si164034a91.0.2024.10.04.03.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2024 03:11:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-6e2b9e945b9so14176327b3.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2024 03:11:13 -0700 (PDT)
X-Received: by 2002:a05:690c:f12:b0:6be:28ab:d874 with SMTP id
 00721157ae682-6e2c6fcb299mr20222157b3.2.1728036672406; Fri, 04 Oct 2024
 03:11:12 -0700 (PDT)
MIME-Version: 1.0
References: <b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn@googlegroups.com>
In-Reply-To: <b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn@googlegroups.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2024 12:10:31 +0200
Message-ID: <CAG_fn=UM_J6n2Rem5-kYY-Pd1FzMykVsod_heXMaw=S1o2TUSg@mail.gmail.com>
Subject: Re: booting qemu with KMSAN is stuck
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IxJMEcQK;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 3, 2024 at 8:05=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
>
> Hello,
>
> I need help with the Linux boot issue with KMSAN.
> On x86_64 I've enabled KMSAN and KMSAN_KUNIT_TEST
> to work with adding kmsan check in one of kernel function.
>
> Booting is stuck after this line:
> "ATTENTION: KMSAN is a debugging tool! Do not use it on production machin=
es!"
>
> I couldn't figure out the guidance myself browsing the internet
> or looking for the documentation:
> https://docs.kernel.org/dev-tools/kmsan.html
>
> Please suggest. Not sure if this is the right group to ask.
>
> Kernel config (linux-next, next-20241002 tag):
> https://gist.github.com/novitoll/bdad35d2d1d29d708430194930b4497b
Hm, interesting, I can't even build KMSAN with this config:

  SORTTAB vmlinux
incomplete ORC unwind tables in file: vmlinux
Failed to sort kernel tables

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUM_J6n2Rem5-kYY-Pd1FzMykVsod_heXMaw%3DS1o2TUSg%40mail.gm=
ail.com.
