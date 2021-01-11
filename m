Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYGO6L7QKGQEQODSCWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9587C2F1F4F
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 20:30:41 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id r20sf225160ilh.23
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 11:30:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610393440; cv=pass;
        d=google.com; s=arc-20160816;
        b=enYa1BLi5tF/t9+9Xz8ZTWzVJRnCR9cWBDREyY5AR9mlGnAun9GqDh2uV5tbp62VNq
         5p3RqMHq5WHD58BBlKv5+X/n9D75LS1Bmzk8NlRifIDP7PuxQv8N+Y4vb/GBdOS7KTDR
         TFAn38RUFsJdIK20lysx0ILBt8+qd0gVdY1WbmTCtU8lhPv4Gti7/iDKCAzmpPJPr3eW
         0b90YdTd3u/rNyWKxD/nxdE4xFnzKNOE4tx8VvILR/0BsUW/DIyvA26YIQGfqjnoKt43
         QY7+Uyx5vabvgyyl9KMbbe/eQ5L2KVX9EpwjbFTk9kR8cBuXt0lKLSRy1/uAQBWaWc+8
         VbjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oBaeFKpAskcjDAuCaUn2odrgNsCy8tsJoSywJiViRKY=;
        b=AmNkqDlb4qXIupggQ132dCmqzsCwntMylpT36LOwS2l62eYrudgfJ1SEz8mpBc+MLX
         VhuvSq7iQrpgh5RsChdMyayW8Y8XQjPI2FOSD7UB3G0EWHYnsl4LkUgWDI7WrRkfAilD
         6G1B+r+u0MTAQu5rm0bGsIW+w+g5Cw8GV90gXADlsufWkKy3v0wa9Nk+SQmUtkAA4/Xp
         NsJG1G0OIY3yNNYKp67fYRQ5fu3kW52FyFWhFnNQEOrTOkILFzRNQoIgfi1x1M0dS8kg
         dEBGpuTTcDmYRvjNKT7CU4hHtR9DvKNBWTVzpKgEI0bnUvr+1ArT5XydaIhqSCLa8i14
         EqRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ax0g20+i;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBaeFKpAskcjDAuCaUn2odrgNsCy8tsJoSywJiViRKY=;
        b=KJFvmZ0Zq1qLGIG8pzX9gfy5sDaSNqpRSHUO9Jh4J1b1nJl+hD2tPtNaqbGvX8smeN
         faYVq5qiwo1tS0XDfbdTZfeb2TiJ1MJiIEBl0VCqFmBgx9JtCSfuOVyAguUIdZMSAXWR
         y7qRjAqJQxyAphRbVkoip9hV0DAnXiClDrqFUQl9UpjYqqQ693u9GbJFd8etBRXCc1HG
         cSnMaKsdt7yuVH0ovEEbJsFZLc/EayeqdnnwTGgByAHPbJP6S2+bQFaaWf71bioX55x7
         lxwL+XEjhnh+o0wR89/PJ7Zz1cF5fEtZdQpDkmmIY+Z01FCMxA5ybLZenNEIlhDbVBqY
         EhhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBaeFKpAskcjDAuCaUn2odrgNsCy8tsJoSywJiViRKY=;
        b=eUEypts+dAQZkpJrFj3WCFiQAJCENsxuEc4AQcLIjRnWrmQ2bKw8PKtPBboZ6RAiDi
         H1I+wto1jAQ0DE0tFl/4flekHKlhGCrjZthbFgmf1OuXRzxTTjzzJ6PXAohkJER4rHwT
         VMmHqr+EQcMA3+U8ujpV29XZ/RrwTfiGn4Zs/FaEOR+P6WmQRmxjIauMiw3sG4UbXFXk
         ob7YOpFhHrFagJ0QM3EA/2X6Elm6qwPJKkod1mj417JCS0Y3JpWi/qrrkCbcRu4PK81V
         XiL+zNohDO6YEW7xohzyrwbi8IPHiuqnhQIWPBhjT79auta19ZdsH7G6IsImYpDhOAMn
         Tb1g==
X-Gm-Message-State: AOAM532f9QvptNbgttI/NlwYJdJT9PhzPdiTauRoVaSGPzcrAyPUENMa
	sAqznqusTxtobz1ctWOKg2A=
X-Google-Smtp-Source: ABdhPJyh0MwiNKtrJuG67Wv5wI90W9ZyLzoNEuZqqRNBMrgVSlnaVcPRhYMzzAs342wIdqEjNftuSg==
X-Received: by 2002:a6b:c892:: with SMTP id y140mr614539iof.137.1610393440659;
        Mon, 11 Jan 2021 11:30:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c0d:: with SMTP id l13ls231453ilh.7.gmail; Mon, 11
 Jan 2021 11:30:40 -0800 (PST)
X-Received: by 2002:a92:a1da:: with SMTP id b87mr635164ill.111.1610393440271;
        Mon, 11 Jan 2021 11:30:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610393440; cv=none;
        d=google.com; s=arc-20160816;
        b=iXaFTxktCTqPYCBVx5Kag+jPYj6D74NidAqfHfrl8eWFS3ReQF6PfeYzdYjTWJy2Jw
         HokugwMNCLLkzOOPHNkqtWeT2S67Fmy5gorgO78neXps5p6bXLqlyEfRETN6uH9a07NU
         Cmo/A7bL5NLvREcUjW1fsoOT4wjlYKwoAjp829hS4Om13Qq+dBNFMW0BlfD0dq9NmAYP
         kztciYh2xwd6zEnG5aDhGReR1CXC29ZooSJCRpimAI8rqwbN+Y6DwcJSUPAkipfV8cPz
         XjYftMfmJ57C1IwNjlez+YWUo5CFM1mnD7bt3GTeN3/gWaWPVmcHB6wFVX+/ImOQTQA4
         mHVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qo2fQAXd+OsMiLPHSUfSpNVkpbDbRR3kE8tJYakNl9E=;
        b=fRcQHd09m8wSN7E723Odm7Exk9cly09ZiOstDLBducMeMQYLI8JOw0qIcjJAXjDd+r
         6tBkXGI6amzzghA/J7TtU2HH/31EgR18EyIolxWrhEuIr+INgoXLFHoMQJ4PcXT6V2yD
         cgfkSMHctb6gn08qmjErgoC5/oN2kkPF27vqQ6y43VHxGstbqPP5Blcq9Ai7JnpkdlUZ
         HEY5Gx/Cz5UuAF+dN3TVvB6sf2O3uXjlYe8fExf5n5FbudJdB6hIb01EAq7ZTJGAPc2p
         z2+vlJzB3Ht49qWzWy0BszV9gM9m/Vo7ezo3MoWsjqdIjAugnQfypi8IdoSCDRRfXvgd
         r/9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ax0g20+i;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id y16si75767iln.0.2021.01.11.11.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 11:30:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id v19so298552pgj.12
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 11:30:40 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr927134pfh.24.1610393439604; Mon, 11 Jan
 2021 11:30:39 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
 <CAAeHK+weY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ@mail.gmail.com>
 <20210111185902.GA2112090@ubuntu-m3-large-x86> <CAAeHK+y8B9x2av0C3kj_nFEjgHmkxu1Y=5Y3U4-HzxWgTMh1uQ@mail.gmail.com>
 <20210111191154.GA2941328@ubuntu-m3-large-x86>
In-Reply-To: <20210111191154.GA2941328@ubuntu-m3-large-x86>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jan 2021 20:30:28 +0100
Message-ID: <CAAeHK+x5VaQ5U4G0pei7Bzf6CWcz+BqADj411rd9P6b=j4uNvw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: remove redundant config option
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ax0g20+i;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jan 11, 2021 at 8:11 PM Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> On Mon, Jan 11, 2021 at 08:03:29PM +0100, Andrey Konovalov wrote:
> > On Mon, Jan 11, 2021 at 7:59 PM Nathan Chancellor
> > <natechancellor@gmail.com> wrote:
> > >
> > > > > -config KASAN_STACK_ENABLE
> > > > > +config KASAN_STACK
> > > > >         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> > > >
> > > > Does this syntax mean that KASAN_STACK is only present for
> > > > CC_IS_CLANG? Or that it can only be disabled for CC_IS_CLANG?
> > >
> > > It means that the option can only be disabled for clang.
> >
> > OK, got it.
> >
> > > > Anyway, I think it's better to 1. allow to control KASAN_STACK
> > > > regardless of the compiler (as it was possible before), and 2. avoid
> > >
> > > It has never been possible to control KASAN_STACK for GCC because of the
> > > bool ... if ... syntax. This patch does not change that logic. Making it
> > > possible to control KASAN_STACK with GCC seems fine but that is going to
> > > be a new change that would probably be suited for a new patch on top of
> > > this one.
> >
> > The if syntax was never applied to KASAN_STACK, only to
> > KASAN_STACK_ENABLE, so it should have been possible (although I've
> > never specifically tried it).
>
> CONFIG_KASAN_STACK was not a user selectable symbol so it was always 1
> for GCC.

Ah, indeed.

Thanks for the clarification!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx5VaQ5U4G0pei7Bzf6CWcz%2BBqADj411rd9P6b%3Dj4uNvw%40mail.gmail.com.
