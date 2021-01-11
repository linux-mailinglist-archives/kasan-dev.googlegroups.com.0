Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDWC6L7QKGQELD4NJ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F46E2F1E79
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 20:03:43 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id x4sf99733vsq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 11:03:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610391822; cv=pass;
        d=google.com; s=arc-20160816;
        b=JogeVyFsKtqEWPAZcsI0w6cguZ6UTCOq2GLCdhwQzH4LhUf7ALPSy8Ai+3c33gTVDa
         X0tK9uMwZfD4jo/N9JqDdBKU/kAV3tFjHLeoXzZ8hVxTg2P7UzzZl5MqoJiJ32MeyzuE
         LE+93/omPUWficwxioy21NeOzaFcZ8TjBj8rEmqZZuC3TZk17My8ZR1NfJ5YpOpfL05d
         bEp+kYS8ctmMkS5dx/+1hbEQbDMGHIm+VXzuK5TxzwVMP7j8wgPWe/POc7Fv5hy9Lecq
         HrVTeK/ts81MZDKTLX1+XbKN0u84MUft23yUxqIZ0O1VhNWxlJOCuEHcZWcxk7yBBoGq
         yAfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nQOMmYuOqbsIR7xyfV/9qaEoLrW+aBftGez5xSE0/hc=;
        b=bVjSJPh4iRumXg8sAu2SiwOalhuJ16aSiYGDd0T76hxvGJwM2LbkDhy5sxSN5UwEqZ
         DEBBzd3yYlqO0s4hQsRBpUPrXOBi4p/lDTzn4ox4mClNIgwjwPdEe4Tn/45QA4gzLVV4
         Gj9u1S8rl3D9XEOmJXwmyzYwt80KRooy4D8cg5WxC9Ut0CR0sjMdHU+Go497hUWgp2h+
         vFtEoDjQk4DTTGiryPmpbbfRAA2lF4T2ceNs+8tFUbSstrIJA9pl2nr+0TFpQW5CbAW+
         +W5lwe8a+Si9HpSjUi0MvZeBN5rXAeU9QPpSDRz0VyiqIRjgOuY7z+1akA+aLKbf0Xth
         VLJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mQxWWfxr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nQOMmYuOqbsIR7xyfV/9qaEoLrW+aBftGez5xSE0/hc=;
        b=Bfyr8ehTT5u39mJlnZWAhaisKQM7zIpNAemTc+EPo9BMI1JYT+QKa39VJRgFMxU88t
         e6nbBQehsmDZyK3LovI9CshRT6wKZT+XCI8v6JA9bBUE6CPhrxry68+9KwsFmkAv50Mv
         wJCJiKRmsx2l0ibe4iJXHtF51aGL30ykMyca5wCYGMbua5W3DbgeYBIpohR3q2tnhz9d
         KzKKoOqpyAo/uVC97kMcb69B96pyUfbA8djh2JJQcR1oPvb8hFkLbX8zvJVB9OGJ1pa2
         5aMiBFNYbyhHv8KZNALIygO9ecjDcuC8BQZ6hXp68zTi++avtXE6k/5N+d7KDm/c/n2O
         eFrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nQOMmYuOqbsIR7xyfV/9qaEoLrW+aBftGez5xSE0/hc=;
        b=P4nEUsXfcxyx/vPx1GnRTdqTgNVBZmXMMuQDtvsnnnlDA/iBcl5lO4m6OJ8GA9mnm3
         ME5pzHcnZGETU0sT1uSdWZEWMvF/nMeUGZ5gk5X0Z+A5+WnGFDXXH3oR2unfsPg5Yuym
         5Tg112iqeBIny15+mpDYWe7GfgfXil5ZAirr06kygta8V7fAO8klNs980u2OJu+UuPOD
         BPjrZM2hNAkA/pNLiY/+9PMwbI6Ivcnn2Nl67zpYZQ4lyBijFhxrvzYO33Nw0mANqBz3
         RukHQEurzfpXiSnuqV1CGmu7JO5wBb2WYUIoSmQnPxEdKL2vRRTEVmSaanuz26/jIBUP
         NRuw==
X-Gm-Message-State: AOAM531p3i3qTJwl6uBpbqsq0SdnD71BFbIp5w1WuuyHzjqa8wSQRoXP
	jL7ya9cDvckfM1qqU5AhZ00=
X-Google-Smtp-Source: ABdhPJxi055Bv4E3/FMQX/6CVNRUEdxbFV9MyQZKz6RxwPT9ZAb4EebISswaQlsnriEZmPfh/2z1Jg==
X-Received: by 2002:a05:6102:214e:: with SMTP id h14mr899100vsg.39.1610391822368;
        Mon, 11 Jan 2021 11:03:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls117704vsm.3.gmail; Mon, 11 Jan
 2021 11:03:41 -0800 (PST)
X-Received: by 2002:a67:fc4:: with SMTP id 187mr954030vsp.55.1610391821876;
        Mon, 11 Jan 2021 11:03:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610391821; cv=none;
        d=google.com; s=arc-20160816;
        b=auw6hAVsp62iSkDWBJFnXbgtRxND2O2+4cYxSj1tzhJH8eGaXAoKi142K56GuHo1EM
         KTgzijtazehFFD1bpN1YZKbzWEqCUZg+EPH2Jf3b8JPQEudhT1H3ctUcj2KowdB2TEP/
         QnVt8IaIGCqEOPC0c78GlS5Y2W+t0bDYaNKQvMkTj3ADEPGdoJg3BeF7ClsuArkiSUNh
         ZrnbJzpL9uVhi2iru9SSC2sW2pRxlBwZec16YKdvN2BqIMIp0lnJI0mELjY1wMgxYLuK
         9YsHV/DID9fB1T7d+VYRz52dZwsjtITn+oJr2c18KnVQ8OZ/0hKhS7jrLWwayjWXeru1
         auqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0M90n7WjWo+X1yIVKHdOTyfvfwcWqL9tkBr22HLMVsY=;
        b=Yqg42KmOVv101F5BOln+DubSNfYnLb7lqS+DlKtdTqDnIYC3qdW/EcVFFaKIt91dRb
         YGZdBs4ODI+mPO3KsacKE8ij8WhviU3/YETpYyGjd7fJ0Uq9VOfM7JSYipoZRF8IIX76
         QDMgPbq6SjAVMKHmBPbm03ydtCmdKCgyDO+rXcpAjB5caIlc++lqfxuJu4NK2N9Nyb3t
         HEfRmPr7+1ufPPNfa1xt0m/SLImusg0DED31OMOxkhU1JMt26OzYqnqay2ZTTHW6wYpK
         4RlT0trKnPUs3I2Z/Sw6gmajDPss5M0W6YAVdYPv0WizyMRQw6XQeBTdUr3pb6Uon/eT
         f5gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mQxWWfxr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id q22si72721vsn.2.2021.01.11.11.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 11:03:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id m6so501171pfm.6
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 11:03:41 -0800 (PST)
X-Received: by 2002:a62:14c4:0:b029:19d:d3f5:c304 with SMTP id
 187-20020a6214c40000b029019dd3f5c304mr991822pfu.55.1610391820883; Mon, 11 Jan
 2021 11:03:40 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
 <CAAeHK+weY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ@mail.gmail.com> <20210111185902.GA2112090@ubuntu-m3-large-x86>
In-Reply-To: <20210111185902.GA2112090@ubuntu-m3-large-x86>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jan 2021 20:03:29 +0100
Message-ID: <CAAeHK+y8B9x2av0C3kj_nFEjgHmkxu1Y=5Y3U4-HzxWgTMh1uQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=mQxWWfxr;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f
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

On Mon, Jan 11, 2021 at 7:59 PM Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> > > -config KASAN_STACK_ENABLE
> > > +config KASAN_STACK
> > >         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> >
> > Does this syntax mean that KASAN_STACK is only present for
> > CC_IS_CLANG? Or that it can only be disabled for CC_IS_CLANG?
>
> It means that the option can only be disabled for clang.

OK, got it.

> > Anyway, I think it's better to 1. allow to control KASAN_STACK
> > regardless of the compiler (as it was possible before), and 2. avoid
>
> It has never been possible to control KASAN_STACK for GCC because of the
> bool ... if ... syntax. This patch does not change that logic. Making it
> possible to control KASAN_STACK with GCC seems fine but that is going to
> be a new change that would probably be suited for a new patch on top of
> this one.

The if syntax was never applied to KASAN_STACK, only to
KASAN_STACK_ENABLE, so it should have been possible (although I've
never specifically tried it).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By8B9x2av0C3kj_nFEjgHmkxu1Y%3D5Y3U4-HzxWgTMh1uQ%40mail.gmail.com.
