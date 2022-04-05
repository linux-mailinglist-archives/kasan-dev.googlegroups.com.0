Return-Path: <kasan-dev+bncBDW2JDUY5AORBTNXWGJAMGQEPWUTWQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A6D164F3B0F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 17:10:06 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id b8-20020a92db08000000b002c9a58332cbsf8290513iln.16
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 08:10:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649171405; cv=pass;
        d=google.com; s=arc-20160816;
        b=rkyAYL1jPkF6KyAWXjzcT+ETowXqdRJTcVxBTCCUQ59ZtE6SRbbnFXysRLBfYC1qyo
         dfQ/G9r9WBIeXktseEHNWoVQegzcKDotgU3pLZvYl5Vq+aqKlLEfRSrbPHuYm8vM16CB
         BanMTSUwIsF/ajM1u/Elb12BX5TuYWnHq8bgpslPI5AWXwaXnhYSYuS2e0Gr3V5YwMgd
         7MTEVpoq7/DIm/Ei5/X1sqb4534342Z6YcsOGmmGacMABzbp6m2/9vEqbP1HLweL4kPn
         t8ajlcZqA3ciuM+HSBC+3NRFMYZgyArH2JM4Mzsy0T36nSj6aPptmbwTTilldml4n8kc
         eEcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=gCa1F4ltVSxn1qwrF74yEOVytm1WSCAfjIQJz3R3MFc=;
        b=tMLBwlGSb/vjBy9TDXzqtHK7Mk9VMudCAqFl198iLov6DTjx0Zk1aG+MucZYgY2U4W
         U8XG1ongoeDtXvWzMPlUyCyS7gpaf8BicX1aMi5JhQ3weEjDMngpl3ijy9RHoXNFYfSE
         piTH26Tqzm3lGZTNowr+q1acOW8HfW1jSETyVJq/KLUAumBv6tbMbDt90pGmwOAMnuH7
         paATXU1NyyIp5IKi13OGi1qcPcJoMa9Ts1oBEX9fHr4X2seNrr1gG5Le0GrGEn6PgdJT
         F3x2mFVCT0QVkCphGX/6wGNxjdoBK20ChtSGAv7SUXMACXbArF8G/jmtct4ebwvTpI2D
         7BwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BIrJnLaJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCa1F4ltVSxn1qwrF74yEOVytm1WSCAfjIQJz3R3MFc=;
        b=aAt40nuyFupq+Sps+VZgaaBZDHgBZopWUkoKq9HCTWSc2JfzpVL4MTvtoq/XaC1Vj9
         yEE6AR6jJvlSk1SkuyVoRMGIY8tx6YX5ZPiuMRYcFNZNjgk4+F/RIZRpaEmERZtUaUM8
         cWUAkBGovQuPVir9IDGt2fsPxid+avAEqvVR+XXEIws6Gar+PbDT1Rvl89LVw595LVLH
         9OEvoWCf3PZ764TWWWAq6p8Uu/O+SUf9vRaVGBIC/0EtcLAOE+lIDwctaputFbGYt5Qm
         R+tvn9r7qdnhWMGIktlXnaMe0e2LBfWbFDnpMZAxytuNX6ug3UeFr/lDEHj4nLJI8Zol
         X+dA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCa1F4ltVSxn1qwrF74yEOVytm1WSCAfjIQJz3R3MFc=;
        b=UEYMYC+DUhnMXNWVj0ttrHte/czg8S1h6dQALQEskuEBTN2GObH55C9hog+vgOO4xP
         LgMpYT6ml8SwAp31ydjAm6GRPjZ6Skk0C8qmREk8uAHsJdIrU3Z9iC5Put5N1k4GWAqM
         fh2I7lopLuJXChSZh+JEQ0BpImKTDEIppZBFpUBi9+2eiswW84kYrpSFAaFByE3rnocL
         MPraTKauPUI4slc2KhUIZbuGWtclpkn6PXgdQ3C2MOwnglngoA61WxNnw8KIxT+MtWPE
         n+GmlCPNEFVcyXpN6V+9Z3wDPz+KfC1lT9kaG+Xn7re/juSRIIsRpAfnEi56No/ivGaM
         jUnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCa1F4ltVSxn1qwrF74yEOVytm1WSCAfjIQJz3R3MFc=;
        b=0eladZJg7zF/+fzi0wVPTpUzdJUhY7c4ZzvDAJ7Pz1Ix37MgzN7fHopF+SWzt3mTDb
         X0cUS2Ruy4L+Ji201sb1cJc5PX2iBwOt7R93ePvP0BPZXVexj0yxm9Ek+LzqBQYxvQ9y
         8Xh2hsByK9Jik4yI//fT0EqgsuS3P3j5UZ5i2Bxka/o79Oak2ahltrM4Y24aOOTXqbT4
         hqp2WWGAF+lk9URquI/qVpv/xlNFF/m7oQ9mjDAfI6a5hJvx6AM8kxoVAEk7UG377Wiu
         grJVfsr1mbEyEz+GMqcTy69taU2x0r2Kz9Dbek6lCF1viCTDwY64uDktmyqZ++vppCT6
         9fyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rHjgE8S1wizfsoqjJ62c9eO1HTXX987MIN0xWGz5YyQnneoJU
	0dPDUyBu/YvnVdOfdc687qQ=
X-Google-Smtp-Source: ABdhPJx02FIoQv38/JheV9tD8zzQI9wK4LBNLqLkMDEDMnyDPxBMsQMnICOruPPCn1RwScgpE0BWfg==
X-Received: by 2002:a5d:9710:0:b0:648:f393:a070 with SMTP id h16-20020a5d9710000000b00648f393a070mr1917632iol.176.1649171405501;
        Tue, 05 Apr 2022 08:10:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:506:b0:2ca:3fdd:9d99 with SMTP id
 d6-20020a056e02050600b002ca3fdd9d99ls1572014ils.9.gmail; Tue, 05 Apr 2022
 08:10:05 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a6d:b0:2c9:f320:470a with SMTP id w13-20020a056e021a6d00b002c9f320470amr2117571ilv.317.1649171405144;
        Tue, 05 Apr 2022 08:10:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649171405; cv=none;
        d=google.com; s=arc-20160816;
        b=yyryV/Y5KCUDoLUrNU13lphA1YunbwDnZJpfXpd0SemUykEUhVvhdq49NINpwcEgFN
         jNGD7PH6e0Hnfo0Y95o8P3WMoTNShYA134kyBqxSJzWA+oVMI9CA6uq+w961wJR8viBf
         H4eCW6WFh4zBduF/VWTYjwvNNiuZo+xW3bllvd96WBHnti+C8tp8kavp3827SFw4oQp+
         DpS80ZaAGU8UibACx1JX2ZKvTAm55Bd2MZiWR+a5sMlmKZly/u09Ijb2uSc5Z9fnYFwo
         b8R1er6zmBwkRplP0WKDPja5SpSWpy8Z24qzNSIW6pWbtna4470iETWlvx/T/5rwDldW
         pdsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=odjTcYZDlQIoWSkHe17VwGaSSDqsAiUMG/3xJUCUusY=;
        b=r8Gnguq9E6qe2FL5KdPBqCklwbOxzjKsU3nyKayxlQWrURkf86aNEGOFNGeJScg8Vk
         GtT2qEc4Fh9BK8HKCRqUT5I+sORwUjJdIZsKRZlH3tSYJsW64MKh//iGyfCP5NdPEKgo
         QdaI8IAnfazhRWal1GyysV9+jomYWu5arwXRwOaAXPp0R+eJkiyp+ckxFOOdsjGl9eQC
         l8xxH1oSVJ2+ifa2aixfDFBX04aHgWuZ0UmECUiDrCXVFq0zSIzmOLu+7hf4shi/hhlq
         i3hE8oSvjtJaq+pKKXBNnzH3GW1yIFjWgctneQrjCuqIrVIBQy0rlWNxiTq2wiIqTlAj
         VPPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BIrJnLaJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id t8-20020a056638348800b00323b343eed6si862063jal.5.2022.04.05.08.10.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Apr 2022 08:10:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id e22so15462613ioe.11
        for <kasan-dev@googlegroups.com>; Tue, 05 Apr 2022 08:10:05 -0700 (PDT)
X-Received: by 2002:a02:c89a:0:b0:321:25b2:4b52 with SMTP id
 m26-20020a02c89a000000b0032125b24b52mr2152926jao.218.1649171404854; Tue, 05
 Apr 2022 08:10:04 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
In-Reply-To: <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 5 Apr 2022 17:09:54 +0200
Message-ID: <CA+fCnZfU+Jj3Of+d0d6b3=fJC0F+SfcUHV1p0Gs95exoNsqvmA@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=BIrJnLaJ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
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

On Thu, Mar 31, 2022 at 11:54 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> That is an impressive number. TBH, I'm shocked that this has *that* much of an
> improvement, and I suspect this means we're doing something unnecssarily
> expensive in the regular unwinder.
>
> I've given some specific comments on patches, but a a high-level, I don't want
> to add yet another unwind mechanism. For maintenance and correctness reasons,
> we've spent the last few years consolidating various unwinders, which this
> unfortunately goes against.
>
> I see that there are number of cases this unwinder will fall afoul of (e.g.
> kretprobes and ftrace graph trampolines), and making those work correctly will
> require changes elsewhere (e.g. as we rely upon a snapshot of the FP to
> disambiguate cases today).

Do I understand correctly that kretprobes and ftrace modify frames
saved on SCS? So, if either is enabled, SCS frames might contain their
addresses instead of actual PCs?

If so, this is good enough for our use case. Having kretprobes or
ftrace enabled is an unusual setting and there's no requirement to
support it.

The goal is to have stack trace collection working in most cases
during a normal usage of an Android device. Being not feature-complete
and not covering all possible peculiar cases is fine.

> I'm also very much not keen on having to stash things in the entry assembly for
> this distinct unwinder.

I'll drop these changes, I'll respond on that patch.

> Going forward, I'm also planning on making changes to the way we unwind across
> exception boundaries (e.g. to report the LR and FP), and as that depends on
> finding the pt_regs based on the FP, that's not going to work with SCS.
>
> So at a high level, I don't want to add an SCS based unwinder.
>
> However, I'm very much open to how we could improve the standard unwinder to be
> faster, which would be more generally beneficial. I can see that there are some
> things we could reasonably do with simple refactoring.

The intention of adding an SCS-based unwinder it to use in production
together with MTE-based KASAN. Thus, it needs to be as fast as
possible. I doubt even a very optimized FP-based unwinder will compare
with a simple loop over SCS frames.

It seems a pity to let the kernel maintain the current call trace via
SCS and then not to use it to collect stack traces.

Would it be acceptable if we keep the SCS unwinder code in mm/kasan
and not integrate with the common stacktrace machanisms?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfU%2BJj3Of%2Bd0d6b3%3DfJC0F%2BSfcUHV1p0Gs95exoNsqvmA%40mail.gmail.com.
