Return-Path: <kasan-dev+bncBCMIZB7QWENRBPM3RDZQKGQEAEYIK4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id C261917B88D
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 09:45:50 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id z39sf907855qve.5
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 00:45:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583484349; cv=pass;
        d=google.com; s=arc-20160816;
        b=lrUCmvYz3E3FeHVwdBcaFf/x9kvLZR9DnchxZhxLwwNV93ElidWhvoGJwqVa8wP1dw
         s2i7OQuU3fCFmdSEWMtPsX+Ll9bGIYktE6HryhPPXjxgzIbZZ55A4uIu7U3C42MbNwEa
         ODE5128EwZMd9MFuVeBTEXw0Au62mY7d1Ae1KLR8CHP+naUrwgz92F1u7Kr3QvSiiUIt
         JIsddt9hpTMqFQrAl5eW1nZPAniL8Aa8F214b+h+BNPTOxb8fYWoQioMWAf4O8N6AAl7
         KYGjG0DQrJBEsSHWwf6hAdsJc/dWkpWvpo28/78IkBaR7wlrhgo2ckRUyzFqflNZbO20
         DghQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eh73UVC6/PnUd5NDNWg7MmArM58mYVWXsMG+7D/8bEA=;
        b=KO0TZeUesT18Hk1ybeYHICNAYQq3XjvKuq0mtj0E/Y2No+3F0qAk3C2EWMVBkCZrNU
         VdE4ROCDKRbEPMCdFeFdMorSQApKJ9MMJ0Nicv+ZOlHlSEGloKisL1gvfVYp/tE/3VYG
         l8+G5o/lgXzIDgtlJGSjYdSgtcFCXwcmIISeOn/wkT+84nCg4ojE1JYWK/YJ46ymwEH4
         oZqHyJAIOzTh4uqvpuAb6N4RrfwbXNVbO3JF2jhN0hprYAF1UsP5Dz7fX7LhI04NbyGU
         76+uWDVzZ8/OmYeQ10srFAeiMn9j9aKi5rrJvqXU/gamZVvlxGikr0DCVp5swtu6Wbnv
         KiOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GwDGMGYB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eh73UVC6/PnUd5NDNWg7MmArM58mYVWXsMG+7D/8bEA=;
        b=Ea7MI3umYMsDJ4uq0fCAh2kCVrgEk4FFEPxK8rKjwubA5R6/M4kSYdMcZLgTUXPTk3
         QRf24U2SVAeGXUiO9xawu2AbBL4sEPaJp5Vm3nvO0NnTLir7USy6T7ntSZ0N5vOwWrGu
         Z7Cwp3kw6i0+lQBudpWat/7N70SBBtmXnPM/8y1qTSqJ5cKx0P7/dtJym9I67u6JW3eT
         uAZpOqQu+fQ4XWUPpkXPa+FY3FIIUIuKIi33UJp524qMiaKx+0BHgzRxgjeTdhW4KBPD
         kTMtiW6OygaBvcMdZMBQvQsZQkr+4zPphCu3aQe/ayheMz4btJR8g6pZh7gNebSMgyxi
         9tDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eh73UVC6/PnUd5NDNWg7MmArM58mYVWXsMG+7D/8bEA=;
        b=Shif4mpXXMDwJSUFgdo23AaHT3EkeeCfQofcvPOxjQqNKtzxi4RibLLZDVAegWR3fP
         h6+G5ryl2L4z0HSNiTStxTyKkCTEUlQ10ntmtlUI/860QVE64fiUV6mqGULK/M5p0uYs
         DRCvQMWY57GDHf4mbroLrJcW8eWx4F2kmUE7jmRGNWhxIJ9NtqpK4DpWJjiAuwTZYf/c
         rpHVu7wWLMVDiZc+LW+mrCWddY1D2ObqCF0GcMXO0JLiCsM7T1ZJrkPE870gFvSekzgK
         gzEzOz+woY6zKcr8wOwEExFwQ2miXt6TkAeF7tMLWr7nnJp97D3ABLTc90yR3wT3y1dO
         hXwA==
X-Gm-Message-State: ANhLgQ1Ya8qejs14GiPxgHwru7vjGzfER8Bz+63ml/52mzcV/ue/y3P9
	qQ+MtpjlVcSe1MyRbK3GrPI=
X-Google-Smtp-Source: ADFU+vvihIu94kiN4xU/JMVrBCL2preKUGuvyuShwYxIp1YsrD74jLIRQEua/X0LC5FfHKzhfTtPKg==
X-Received: by 2002:a37:c47:: with SMTP id 68mr2003157qkm.144.1583484349586;
        Fri, 06 Mar 2020 00:45:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b7c4:: with SMTP id h187ls370qkf.1.gmail; Fri, 06 Mar
 2020 00:45:49 -0800 (PST)
X-Received: by 2002:a37:9104:: with SMTP id t4mr1967362qkd.449.1583484348969;
        Fri, 06 Mar 2020 00:45:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583484348; cv=none;
        d=google.com; s=arc-20160816;
        b=yrnteBq9TMwFtn/6/SKFWWsRssPMPek4vCxn/q1wSQGGj/lSWv+OkWRhrJVE6dbicA
         zVSqjxxY+cGhiBLukC3AC/XhIvFB5kXu6DqPlQWCZienaJGxb0spvph8lHaFCxwB5/kE
         BjNV76ZAMBUpvTWgudoGDeq7xyQr0rr24o0zcSO8vjsMiquOP8kSk+YTbfAIKc6+vFns
         BwlGODdlvBo5qGZoVATxBL4jorwTQZyHqMAAgob0OstiX9aF1SeRgXlmOdBdC76ENanx
         ZokIM8qQTMOdOCqxflpDWPEAi+morL6rvEkRpP/RJjZnxuglsuF6EVBJQo4g4eywROHn
         wr2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lz49A25/5vJED58rnjO87kEIxwC+5eOxeJLJ9jkNi8k=;
        b=oeWlalDVvIwNQ0XRL9VkhxaNEyYNesB7HhPnGAIMaPpLVYe4hEsraLufmshNLYd1N7
         F3AHLtcr38Fqz/XnGevpUe7HVPPfm59T+/z53lF0pBUax25pNKE+O+VSbJjuj9aU1kcN
         9PZBOgnDFD9S5QlHxpauMLsSDzhOzn2q4HjL08LbAuRFRMWLcoqlFPmD0XoacCfikgYM
         1d9pFeiSIcD5bv/XaqN89k0gGRJIqmxmoGRqFG6qZYhbLf458XKDTAkU3FTDYBtijvnD
         nsV8KQ5casjNljX0cPRxqvKNLahXuqzVncjWNeHKfps3v324Drgk3YxvZPXmgGZHAzmt
         AzwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GwDGMGYB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id i26si56533qki.1.2020.03.06.00.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 00:45:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id p3so598690qvq.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 00:45:48 -0800 (PST)
X-Received: by 2002:a0c:e982:: with SMTP id z2mr1900354qvn.22.1583484348444;
 Fri, 06 Mar 2020 00:45:48 -0800 (PST)
MIME-Version: 1.0
References: <07a7e3d0-e520-4660-887e-c7662354fadf@googlegroups.com> <CACT4Y+aanRYNL6N0M7QxftmBcLQi44MenZ+oOUap8g9AtvzZvA@mail.gmail.com>
In-Reply-To: <CACT4Y+aanRYNL6N0M7QxftmBcLQi44MenZ+oOUap8g9AtvzZvA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Mar 2020 09:45:37 +0100
Message-ID: <CACT4Y+YnNXpCCfQXr_BhwKZdEFKoS_7M1AZXaxmi59iA+VFH2A@mail.gmail.com>
Subject: Re: Kasan for user-mode linux
To: Marek Majkowski <majek04@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GwDGMGYB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f36
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Jun 3, 2019 at 3:57 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jun 3, 2019 at 3:54 PM <majek04@gmail.com> wrote:
> >
> > Hi,
> >
> > Is there KASAN for user-mode linux?
> >
> > Alternatively, is would setting CFLAGS="-fsanitize=address" make any sense?
>
> Hi Marek,
>
> KASAN is not ported to UML as far as I know. -fsanitize=address needs
> to be passed to compiler for KASAN, but that's not enough because
> there must be the runtime part too.

FTR KASAN support for UML is being added:
https://groups.google.com/forum/#!searchin/kasan-dev/uml|sort:date/kasan-dev/55i8KM62aSY/_SNEkoRfAgAJ
Marek, if you are still interested, you may give the patch a try.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYnNXpCCfQXr_BhwKZdEFKoS_7M1AZXaxmi59iA%2BVFH2A%40mail.gmail.com.
