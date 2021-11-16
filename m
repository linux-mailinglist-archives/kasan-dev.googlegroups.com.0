Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAFXZ2GAMGQESATAKII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CC2D453174
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 12:52:33 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id bp17-20020a05620a459100b0045e893f2ed8sf1437234qkb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 03:52:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637063552; cv=pass;
        d=google.com; s=arc-20160816;
        b=xEFnGErbz8fmiJQy3Utg6Pc9ym1dLTAqd2xQTbtL/Gu0jTD/k9sj0LygvV6tDtf12A
         Lx+MXxYITmrYOVKYKETZBE2LMjEsqC9n0DalbKC2iWram87+phTMlZdew4BXQ1nm6jrW
         VlMc3ALIePH23o+b3hLql+/cjnWIffbRO8RMEDxPVRR1fp50DYBljS8Yv5z1F7WBC/4H
         8oQnag1tAVeARFimBE5U7qCKzefj4l4lRO69CVq6wE2kRa4IrCL7odM5G3w+1RPZkdt1
         VHHVuGIMnZSBHDMoDuw7ZKqZagDaGluQQL4nmL01weIy4AcKu0B3V/I45t2N+cFxR1B8
         +qNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ajCcZC76NGlV4FJl7s1uDRQRoqTPHcgj0tie59o7n24=;
        b=xwINzi7Xrmg/sXyFQFaiDuZxop24v69CNiECb9dewRK5yt0W3c2DLdUgVwZ+HUQ/Et
         xtI9a6NrqsPYUMdVaMe5ilO08gXKbP103pUytbQvGNaPEUpUYRRlqHJb/W5c+oXPTAog
         2LnmweuQ6Qt9PVC95mcu39Xx6duv758iIr344VL9NaMmvJIMTLitMf2u/HWCriAOqLlg
         0RDKICVR/Wpuhd3D6mRJLonYLPPmNptx6rrNqECadqKcUR6XeuXlV135IKoF2gEup7gz
         bkOWII0UGqvr+0CANLaxgWXcMGmxjfg+IhjLC6KxyU5KfdAnyKwv7MiaKdit4KjqKOMw
         VupQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RPd4Eo2J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ajCcZC76NGlV4FJl7s1uDRQRoqTPHcgj0tie59o7n24=;
        b=pAdu+VA5Q/e7CQqEtkEn2T31bM32nm9NnJM94zVck9oPpzcww9TtFfILdVmnmucNyr
         flqaj+ErG3X0hfLo+YZDe1i9aVqE1U/PQPg+cfvKAe/S31LIsXUqZXFzkyFPeaShpvdM
         jwphNHyKoS6WVlx4Cpam+l3B9PFK2YAwT3eBtNqrzhuQP0oyv0nt+lghMPVcRWR1+SpB
         m1tCmXb3isIfX+e44u5P1OQHs/CZO1ZEJLYCgaEdPpuIkOYWpNgIqEcFtjJ9hBXjlOys
         QvRYrPWUh8/2Usu/wgbDpUWl2CM+podHQp3Y/10foV8tfpil6kBdQC19tnMfp9VXpmqr
         LVaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ajCcZC76NGlV4FJl7s1uDRQRoqTPHcgj0tie59o7n24=;
        b=xKhYqLAAo7e0SA9QypUJa70NtSs3C9C6Il5JR4dJuDNW6aP+jRilCu1VeAXsR7GbcP
         f2CGqE5YbWYTKfGUHP+WVh5IYfStSBCLW8hBqglPc+WoHz5HQRouH88YhqiLvDH8LHdf
         K5hKusazmfKgon50YBbMmw9IFckIgCAQS7IRiD0vKoIHmP96EAjpthf2iAE7oC+E1QSP
         1i5uWu9h4SO9/xsq1GlsrhWXbS7zrwEo8pAMUFy00qKMKNt77s9iQI4IAsxtmGte5Zdd
         TF6R63g8G7jZ9e5HrMDG2EO9YNE3HXDA0OZlMOgQmNNHE6+LV4nhDrWuem1poSk1Pkxx
         xKfA==
X-Gm-Message-State: AOAM533scBU3lsaYClr49M5zN1LEhB4OQDDtU018GnQ4R991CqjbiMOv
	08byiUjBtdtT2LvHC30LAXw=
X-Google-Smtp-Source: ABdhPJzFxWFSweY2NGUbqz6jj4J+zeU2tD9J7sGn2AZR3KGIu2+yAZSLFSsVpSFsag0Nx1vvZeeacg==
X-Received: by 2002:ad4:446f:: with SMTP id s15mr44643129qvt.1.1637063552703;
        Tue, 16 Nov 2021 03:52:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:df83:: with SMTP id w3ls5676696qvl.7.gmail; Tue, 16 Nov
 2021 03:52:32 -0800 (PST)
X-Received: by 2002:ad4:5966:: with SMTP id eq6mr44280948qvb.14.1637063552323;
        Tue, 16 Nov 2021 03:52:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637063552; cv=none;
        d=google.com; s=arc-20160816;
        b=RKefItR8vzy35QGXrq/vOp5KEOIefC4UYtkAdFqwqwteW6cjbymrCapPIHcqJNpDLi
         qBjuMweM9kTJmyi0dSf4V8IyAYJRWx7r+EmX+L7waghHnZhVdY76oIVU4juGhok5gvh7
         y9Q9K3yiVLDus2OtXpi8rI61BUH5CkonS+46eTj/dGj5ufGtoVkBGM7n7RuFSq7U4V2E
         I88Yb+ARs8/3EcY+SwxvFi3Fv0Amuq5vXUO4V/xSkI0xWoRGogfKHvmlFMWPBLxsJ0EG
         wnFGVtpuG7RCIzD0fk0Mob70SlGC2YhISfjC8ySL85Yp7mMDQ8kjze6Y1K+tS1ZcK7Bx
         blyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tris94wWX0FSNKpU5E6UQtB9xuGoHC/J1vA+RCpF/Pw=;
        b=xuKqybL7LLTW0AeYLfhUH1bQJUkcL5U9IlzStBy1/nIMhKneBVSShc2PHUkJE00L9S
         B8K/7u+lwXOsxriBv1Kes+/0ZrDutpcJGhCRLxRYnn9wWpLktOmQDaMJHC+pEK+mg7Ej
         DK/K85Ftqk1+FmdTwey/IKydLqDELpqZv/A7W0mXefHuuIl0pOBF8DKizEeAmBYPEDp0
         134Ehl8gc4S2lNs3jUIePJ+wcucuareg1EMFCrlx1I+Du4ICAeypJ+e5afq4H2lDV6vC
         UXYUIBugEjQGFGKJESiBMNuNqQbjDDiGsqL9MGbIIdEbTO2/pMKpzqbLGA5Y6C45BIwJ
         OC+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RPd4Eo2J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id d14si772806qkn.4.2021.11.16.03.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 03:52:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id w199so8656595oiw.4
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 03:52:32 -0800 (PST)
X-Received: by 2002:a05:6808:6ce:: with SMTP id m14mr5726642oih.134.1637063551749;
 Tue, 16 Nov 2021 03:52:31 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
In-Reply-To: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Nov 2021 12:52:20 +0100
Message-ID: <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Cc: kasan-dev@googlegroups.com, Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RPd4Eo2J;       spf=pass
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

On Tue, 16 Nov 2021 at 05:54, Kaiwan N Billimoria
<kaiwan.billimoria@gmail.com> wrote:

> I'm facing some issues when testing for read/write underflow ('left OOB') defects via KASAN, and am requesting your help...
> Briefly, KASAN does not seem to catch the read/write undeflow ('left OOB') on a static global memory buffer.
> First off, is this a known limitation?

KASAN globals support used to be limited in Clang. This was fixed in
Clang 11. I'm not sure about GCC.

> More details follow, requesting your patience in reading thorugh...
>
> 1. Test Env:
> x86_64 Ubuntu 20.04 LTS guest VM
> Custom 'debug' kernel: ver 5.10.60

Which compiler versions are you using? This is probably the most
important piece to the puzzle.

[...]
> 2. I've written a module to perform simple test cases:
> https://github.com/PacktPublishing/Linux-Kernel-Debugging/tree/main/ch7/kmembugs_test
> (the book is in dev :-)...
>
> It provides an interactive way to run various memory-related (and other) test cases; pl have a look (and try!)
>
> Here's the test cases that KASAN does NOT seem to catch:
> # 4.3 and 4.4 : OOB (Out oF Bounds) access on static global memory buffer.
> I'm unsure why...
>
> Here's the relevant code for the testcase (as of now):
> https://github.com/PacktPublishing/Linux-Kernel-Debugging/blob/81a2873275bd400fd235dc51cdac352d9d5fb03a/ch7/kmembugs_test/kmembugs_test.c#L185

FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
There are a few things to not make the compiler optimize away
explicitly buggy code, so I'd also suggest you embed your test in
test_kasan and see if it changes anything (unlikely but worth a shot).

If you are using GCC, can you try again with Clang 11 or 12?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNSRVMO%2BPJWvpP%3Dw%2BV6CR51Yd-r2ku_fVEvymae0g7JaQ%40mail.gmail.com.
