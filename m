Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNNT2CQMGQERTHWMDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CD6338C587
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 13:17:58 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id x2-20020a9d62820000b02902e4ff743c4csf12942877otk.8
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 04:17:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621595877; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OIDdLC02rzAAOSx8dowXYOcPr3ROY6hTabVUczSHb9QMqIvEpYwr5caZlxFd6D/AZ
         VyagU0LguDjo873kDFXbCoAkNt608itW58wVMQtiUhyzdljTaqU3X9lS6y45z3/NmyMK
         rXv+XuZYx9CIuhJxpdfXQQHUHIKnBqB9hB/JXC9xINUYwaPe93x0kBV1FF2nvJDsXs8Q
         dcPlAar10GZalNlIBCaoTD1klK/3RtFoUUyjCVD2n708ai9xrvYAlWNIG1pHCV0jRYY0
         /QkGF7CLryP2YB0sAY/qsjFSwVczCZ7zbwXO3Z7DbRDO1BEJbtRSW7BCbHrokAWgKLo7
         GJRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kXwZhhBmTpyyqSfz0BkEXs676pHjRmmfnWbANXa9ypk=;
        b=hegLXjbAMSd6fzqeZe+k85ANKOukM/QldBqsEgWk5ZF8h6SD7ajkJ7EXFFYUuQHhYa
         htN9Lu7TTJ0+RDWQlkl0y1KEt0Q0FpsXeBBwjS7HflwK7Hs7IPy6gouAlUP8nsZxhinz
         /Xeh2bSNaX1ib/yM2LaAolEdHjLHcJcIR2+SHWZLrQk4SJRX31R7iWFZjJ0nFV3SH+/i
         J5CmQzcq3n9PFMgsr8QjAl0AWEXWsjlIST02QoDChblXwZC/p9m84WFm1LbkkJWzG8D9
         Uru6LBSC2DxoJlighW6M+YGuTURANm4s/nPPyza5mdlgQNbzsv88wWmwCbxn6zLPIQip
         tbsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gFmVEQZv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kXwZhhBmTpyyqSfz0BkEXs676pHjRmmfnWbANXa9ypk=;
        b=G/78hFBHmbgqpDUt/VHIqtazXIBHNiJ7KnQrVuWGs8ep3A/LvYb0j8BeDGiLdlsciW
         gvTH0Pan3uBGdS2fARwxVRYmWefO+rg/Tc8LXKYvh1hnTN8PDiHdhWeDkuxQx2bdx/Ea
         N0iLFjiOSlrEJuZmb35hgaTdbwZi+3Gu7PC0bEd1FBKn8vlgGsr/Zrm9+tvm7TEpfog1
         0+iaj49IPFatzjE2KSlf9xnfn6HfHxxPS48rVqdYVPQdquOod6F9n5Cv4wxyqqbLca+l
         iwmKog8K3asiQohMm3ex6GifbcxwS/uv3KrYmdLzSLGBQEJQcrsa2a9poN+Y1uoW9Izq
         rdRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kXwZhhBmTpyyqSfz0BkEXs676pHjRmmfnWbANXa9ypk=;
        b=LfdmcwhG/VP53YbyyG76aAKJdgVRT5iEC82PGVttU4yh9/u0LvTCo+RKH94IN20XSW
         7ycCo8O0K3+Hs1ywJUFwtyVfZxeweboX1A+MdSuUyY7n9q3cABU5TXHmfTJVqNUYrT/X
         BbVZxcEPEZX2g6XCgysxQzTtG4elSZ7DBNQwSFsiud27icPd5Auqxv70Q1qFxfiwGM6Y
         hLiG1+Q1AVvU72I7yKrVk7lOl35iRCS9DLQmhI9noJAiZ9CNLQoGmxY2JmNN9xgvQPMo
         pvAXfYFLVduh4PF2Zqtony283Gw/UyW8q1+HLpwXsoP7hiCvCuVKm0jMVajX7z81O4fd
         Ce8g==
X-Gm-Message-State: AOAM531iulllGNBBawmWs3xOHPF6bxmOqumtTEdhOJo3CFzqhQgQDxe0
	3L5vCX0LdwyFXMhbj05Lrac=
X-Google-Smtp-Source: ABdhPJz5INYGg93tpWGUy9S5eOT0J2gi75jtV9DPMEcVAqYH9qfie+RBjEYghk6AwHgyRYNO6VxkwA==
X-Received: by 2002:aca:4343:: with SMTP id q64mr1768097oia.33.1621595877388;
        Fri, 21 May 2021 04:17:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:641:: with SMTP id 62ls1941308oig.0.gmail; Fri, 21 May
 2021 04:17:57 -0700 (PDT)
X-Received: by 2002:aca:c792:: with SMTP id x140mr1801985oif.88.1621595876986;
        Fri, 21 May 2021 04:17:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621595876; cv=none;
        d=google.com; s=arc-20160816;
        b=hAChcsTUyPd8zOoJ671fQEhxQWPJk5xwMbMpO7kFpN9JO7arQJFAEvpf23PJ7jrur/
         Y+Y2BvvbL3vRsaRj2bgX7OVcff9Yg430TM5vl/QAqcJ0XINwt4ao5wASTnXMqSKM3R7r
         lLDJxuLFkQqwM/93mIihabOFZvDKQjegl/fwm0WXjevslhcrIAfoZxHlcxDnkOdUUELc
         R5ZO7xISgIOBBKMGmhEH7TReQ+ZbTMpI44+BfKBlxF30Uc/IEsq9gfo8th9/avPHZ40B
         k/kBW0OEVhuBPsNmWCmVsRNBMF8/44pcqgoVGJbamUA77gjX8Lr7K+ZdmHKujqaJ4Bzx
         DrbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EcIp8WA1WHrJEqMIlaVs2ij19F6h1FeNiLm8T3GjEDY=;
        b=NWLXl5gTSme3em+yT9bjSU/F5FZNl31KhK4pno9ktSVW/JOlpm4e9b+bmjy5KnhFSQ
         PEigRmb+fprGMzadgNLTD2rXCjvFgW/hca5e+HM3fRcNgNY+BvS6pR4TKua+3Gv6FhIA
         eyl49apVkDwB9ycqRjhH2uR4zS1xSgendEEr4gox6gG4me/EFxiTv6yihl8C7s1ZHkul
         oCQUdWHN9Wb4hvmjUhdKJ1JaTKJgn9M5Fp0CdwMFS3ulUj4cFpS2JFsOKsr2+TnWYRgA
         D+wKuj0Jm701OiXyoW76wM1OCh023YENAPmHfDFV7BOzo/0dlO9ZsvNUwTh5Fjuy/h4f
         VEow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gFmVEQZv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc36.google.com (mail-oo1-xc36.google.com. [2607:f8b0:4864:20::c36])
        by gmr-mx.google.com with ESMTPS id k4si680535oot.1.2021.05.21.04.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 May 2021 04:17:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as permitted sender) client-ip=2607:f8b0:4864:20::c36;
Received: by mail-oo1-xc36.google.com with SMTP id q17-20020a4a33110000b029020ebab0e615so2568756ooq.8
        for <kasan-dev@googlegroups.com>; Fri, 21 May 2021 04:17:56 -0700 (PDT)
X-Received: by 2002:a4a:cf15:: with SMTP id l21mr6404487oos.36.1621595876593;
 Fri, 21 May 2021 04:17:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210521083209.3740269-1-elver@google.com> <20210521093715.1813-1-hdanton@sina.com>
In-Reply-To: <20210521093715.1813-1-hdanton@sina.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 May 2021 13:17:44 +0200
Message-ID: <CANpmjNMD58SJPeVnKrx1=mXoudPZFs+HoCsVujYomCtZ5K+DKQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: use TASK_IDLE when awaiting allocation
To: Hillf Danton <hdanton@sina.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mel Gorman <mgorman@suse.de>, stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gFmVEQZv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as
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

On Fri, 21 May 2021 at 11:37, Hillf Danton <hdanton@sina.com> wrote:
> On Fri, 21 May 2021 10:32:09 +0200 Marco Elver wrote:
> >Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
> >allocation counts towards load. However, for KFENCE, this does not make
> >any sense, since there is no busy work we're awaiting.
>
> Because of a blocking wq callback, kfence_timer should be queued on a
> unbound workqueue in the first place. Feel free to add a followup to
> replace system_power_efficient_wq with system_unbound_wq if it makes
> sense to you that kfence behaves as correctly as expected independent of
> CONFIG_WQ_POWER_EFFICIENT_DEFAULT given "system_power_efficient_wq is
> identical to system_wq if 'wq_power_efficient' is disabled."

Thanks for pointing it out -- I think this makes sense, let's just use
the unbound wq unconditionally. Since it's independent of this patch,
I've sent it separately:
https://lkml.kernel.org/r/20210521111630.472579-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMD58SJPeVnKrx1%3DmXoudPZFs%2BHoCsVujYomCtZ5K%2BDKQ%40mail.gmail.com.
