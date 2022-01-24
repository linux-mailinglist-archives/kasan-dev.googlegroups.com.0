Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGOSXOHQMGQESZOFEDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B54498767
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 18:59:55 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id v5-20020a17090a960500b001b4da78d668sf13984322pjo.4
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 09:59:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047193; cv=pass;
        d=google.com; s=arc-20160816;
        b=R5W1I0blOcVo7tx55fTWrqBpiTPdKukoAPulEF24n3nqQWkrAY+1VZ5gzhUyPJE25x
         t45jSNoYS8km+PFe/dY6kbIiMbgtzkJvmnDG7+xW37BdXskniUJpp/W9S2UEWURoQ7CC
         zigxsndaZKgDyaQuGKlc/ogYm7j1ikJJd17uSuQLufyu+27RrUqnSiOumQOHtISetjOl
         vLtYSCcGZ9H1YnrFZJQAanA31cY5YEn+ayfIDoEkgUJBOz2+Ih568p9nHddWBm/fWKAL
         bg6AWg3RTmHEolEhhW3IBEVHx+W65oMozxAqBhe3+PwZLvEIqpk7xMbU1DycyMuQd+ux
         2hFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uCj1bOIiqeINZviA8bEpxpac7NLtKpwh8WrgQ5Js47o=;
        b=FBxxnPb/fX7pbP/ps736rWMc/4CfVMwU3ZPVa/z0ezu2p40tA1DH84oc6uSsaykXF7
         +sFqMgrl6psRWq0UrjFbNGkoxRuztVrKHGKNcYsjYyqAWqI6GuDCVhaaQxPUYVI0FGOr
         StS0m5za039J7ikiDKGqv5C+oUTdhH0I/KFS+Kh1vM8hpufFu7OXAAUuFd1HeDJpuwIs
         y2e5zvr3WCqwqbJTDM+Q6fZ/V0OU0irkOMLs4sjdhFkUPDV9/muEEToE42rFL0azBNMM
         mHyBTY62x16GCngaeBrNKZsm03pkSgCMllDWb/8n3qoTFu/w8FP1hDc8FfaOhVmMfTOJ
         QXPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hg6bbvNJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uCj1bOIiqeINZviA8bEpxpac7NLtKpwh8WrgQ5Js47o=;
        b=gQxGYxSwpAuryqJegBas4uexfkkgyv9BgctDT0Zh0Qt0kofB7SmVUIU2ikS9o1Lwgf
         UOfxeL8x0xa+QQO+zN4moXGeb5lWJ2/OvMrDq4oYY6M02rehQkqlpZ/41vleU/Kus/PD
         2KKFdkc4cGBciRu1ih51hAyZkAcGV8B2WKShlmqxNU5i64YTdWYGtZk6WWNhWLyQriSb
         ZJqkivsFtIlm91+b1fX6XYA7c9//3gof0CkCkK64pjFuDq2jGqsYiDNzgOZrXIGYTb/r
         UWrIhlJwAJvhrT43Q3EbzBgEphXs82GLP1tn7A3xCMLyRClaDGwxG9+8Cpfv+MI1RlAQ
         xNnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uCj1bOIiqeINZviA8bEpxpac7NLtKpwh8WrgQ5Js47o=;
        b=0/9qTkMf8E5rDevf0MsrL5rAJYytY9QxE2l3MEfqP/52R+EGi/9dm1nHs3rgk661/1
         FGsApnuYbZko4S6vBy+F5SYL6FIYy/+pz6teaEBhvikWTPh9YqDJ7rAJzEtjwSLIkRZK
         TTHC0TchAb3nMuYwJP2uL5W0HjDP9icTg33c+12yTqy2XD+W5TBld1V7vg/FzJnZqI5q
         tfiz2Lv2v+2m1x0LRlT5WcGFTDrcQFgyRZ0ncGDB+Bk8ilzDEmMn9FQAF2VMKgMWWq3l
         T0ceAHfdKSVqQjcW3wgb0GFsbbTBle08oR3c1n9oAUNyKC8RbcQ17Wz79jrkIRmU/ukA
         BvWQ==
X-Gm-Message-State: AOAM530EzYfhiLddnGroUE48U2t13CDvqWFot+rXm65AGJ2yO6N+gi4T
	Zb4QZfFKP/xy/e1+XYI2DZQ=
X-Google-Smtp-Source: ABdhPJxSrT3LQvusyKS4elbAbS8IOwN/cXvXGJ9jv1YEBSsWGeKfBcMpcmjcj63CFHd5h24lI1sF+w==
X-Received: by 2002:a17:90b:1e05:: with SMTP id pg5mr3049842pjb.56.1643047193487;
        Mon, 24 Jan 2022 09:59:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1a0a:: with SMTP id g10ls1216849pfv.6.gmail; Mon,
 24 Jan 2022 09:59:52 -0800 (PST)
X-Received: by 2002:a63:7f12:: with SMTP id a18mr3705227pgd.453.1643047192789;
        Mon, 24 Jan 2022 09:59:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047192; cv=none;
        d=google.com; s=arc-20160816;
        b=G0ltoPqSmRK7n9WEPEWSCEXAWlR/AHUgjkf4DdKG7HpXagbp0ZpunwuCGhw5GW9IQa
         wWn+OiqK4ZS+TL0AG63Cz1TO7NlzteohvHKTXvQlDBv+FM4rRgz2jJtdRab/78Hu+Sjf
         rRK7xQYrWhUVDBGmXe5HfmWp2fWZGKxUY7g4Vfyh710/JZE+k4X3mWSNqgNDtaK5mIg5
         wHKDcWEOFZ25ghzdvhFwa71khf0T1dmd0LIp1xMcW/cDM7TW1d4o36U0xR/nqp/qz6Pt
         VBp42LbjWehBnqDQ78XjYsEck4VJT7oa7C3yTNAzBbO8UVZPILcy1HQ87NVx5/pyQ10C
         wytg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WDJ2atOq+odBrX85L51zk+4WIQAQxuGUPgw+QxCzzw4=;
        b=tNUBn4Bx3rXStv6Rm/FiqcjvVmJq6t4soNsUSY1LeMJXnMTs2v56mdzNU86YmbusjJ
         wJYRYsLBZK2w08GdeybzS19+scey6S2EenNOy0E459ZXPTBsh1kK6HmdoaRXhsTgE7br
         Jbi9TFi7PNpRqXxkpbBdgiTlW4zCN44XaJLzKGYWviA7E1/Z9vr5FNhocJYERx778Cyh
         dZWi5ksWwmVuDlSGuW3F1Jbggsbam70u7EDAQzyBob8gHMAtGJunoTYgr0ekgBCvCrRD
         Lj1rTATtSDVpQH9Tkdv+tMAvEm30LbFPN3k9J5v4P7OZpkNZi5AhlFYFLy5KiiugbhSp
         XZUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hg6bbvNJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id gd22si1698pjb.1.2022.01.24.09.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 09:59:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id s185so9910130oie.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 09:59:52 -0800 (PST)
X-Received: by 2002:a05:6808:a97:: with SMTP id q23mr2556523oij.4.1643047191963;
 Mon, 24 Jan 2022 09:59:51 -0800 (PST)
MIME-Version: 1.0
References: <20220124160744.1244685-1-elver@google.com> <CA+fCnZd9fhv0RShoSF5xStQZuXFC2DGv8JQpthffdm6qVA2D3w@mail.gmail.com>
In-Reply-To: <CA+fCnZd9fhv0RShoSF5xStQZuXFC2DGv8JQpthffdm6qVA2D3w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 18:59:40 +0100
Message-ID: <CANpmjNNjOG2z1m-8ViiD1+mwqqOargdDp3s268k6eeTyuKeM+Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: fix compatibility with FORTIFY_SOURCE
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Kees Cook <keescook@chromium.org>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-hardening@vger.kernel.org, 
	Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hg6bbvNJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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

On Mon, 24 Jan 2022 at 18:54, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
>  -On Mon, Jan 24, 2022 at 5:07 PM Marco Elver <elver@google.com> wrote:
> >
> > With CONFIG_FORTIFY_SOURCE enabled, string functions will also perform
> > dynamic checks using __builtin_object_size(ptr), which when failed will
> > panic the kernel.
> >
> > Because the KASAN test deliberately performs out-of-bounds operations,
> > the kernel panics with FORITY_SOURCE, for example:
>
> Nit: FORITY_SOURCE -> FORTIFY_SOURCE

How did that happen?! My hands need some better synchronization...

I'll refrain sending a v2, assuming Andrew can fix up this spelling
mistake upon applying.

[...]
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNjOG2z1m-8ViiD1%2BmwqqOargdDp3s268k6eeTyuKeM%2BQ%40mail.gmail.com.
