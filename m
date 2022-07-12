Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4OHWWLAMGQENTNBFTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE8357196C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 14:07:14 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id r13-20020a17090a454d00b001f04dfc6195sf1830346pjm.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 05:07:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657627633; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zw+Z04Bdl+CRk6JC+11JgYuOX1fN6m32Ry8ZQSO2ItRpN6gOpJhQuJdUaf9aYDbGVj
         XKkt4Gpumjh5/brtVpcqMtwdh4uo7AQfdqEEck15PwXDsOHLSs+eKIdVBAL87ZFwjXJB
         W7rQN9WdpgkF0k/homU5YWyjC6beDC3FXm1sPzUu9LeSDgeKI9qNVfFvGJYVetujKd6H
         IWgDRv15/p1wFUf6UtQB14Yi5PH+03/olykirOihpinDJozWqCqjl0sxuPmZlrw770hS
         A+N8Q0BpMuv+kJxgM5vrVszzh2Im2WxCFkB+bTd1Cp8Uyk98nlyWU1kmOpwsRJ6WBOV5
         ie5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BG9o2wLodlnCoS6JfwIo3AD5WAOJI648OKL+MZ19wFs=;
        b=TG2TYE/wZBPF5Fh89amNpl2EHlP7kz3n6M6uNZhy5i9ufZTRNsK4Wuji802W/C4VEd
         EzpeY90bZaQxaZZv937Cb9NP2FibMXGhDSNIxEK236PdMAJ9gUA8g1VWgYbbD2+ipJSR
         n1GvPmFy6SHBGegaSqnLgprqRGJxjXG4LX1NfwriLbuvNZTuw1AXr2rEvCYjqwws9laQ
         WRieRsTeWmDlodfoFq7zGF9dhI4LUaZDlDr1zyxm/AkDkxaL44jXMMbZPFRKPq1ukPh5
         K6tkJCygbL0Z5gKqHBw9LfUjNYWTDHHEA8S9wUYngCz07kZYWpHSttluJ0FKwCQ42a0f
         +jqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZDVWr+p3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BG9o2wLodlnCoS6JfwIo3AD5WAOJI648OKL+MZ19wFs=;
        b=DYnTSMCWJiM9hc6/3chSZS3Jgl5VsKdzzbCU26CXzirXncBRx22oAgevwzf5Ae73BA
         PLH0Bs5m576k85kn+PA9LJ7MyGVe3E3sDdw8kZ7ywFM0lJRpt5ZnYLgbTsmvTfX+qAZ9
         eBL+PxrANffLTPbKQFezg5oLarYRMYK1fxMITOSBM4/le1vx0ptYeXde15vUZ0/lhXU8
         SZVhGM/+RVJaIV72GK1RlrAU0ET9M6LBZWx1FePlTf5sdXdE6SrDEuTG5mWvr6cIsMla
         G5rQ1fROUNOTxk2m5apC7j2WwP5ukxPnzYkTCElZLkvj4i1x6EAPHjgjtFedeZB9yNWr
         OWCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BG9o2wLodlnCoS6JfwIo3AD5WAOJI648OKL+MZ19wFs=;
        b=VBa4jQYEmG/ETGrsp8xkrkcMKfdjJcY1ksgvPlj3IogdMPgNA/w7jsv72Lhm/Fjfbk
         qtLcosORORpRDjpBUhiufDIscNLU9pTBgUVjUn4fkaHfaDosf6LvS//UALmLX5uAKGHa
         sjWXRsy2F8ljpVU9681n3GZ0rXVsRnMP8uCb38tnjfjrMn7S0ULZYVtuOVUltl7IH6AQ
         F98ddktmzmrDiCvPcOL7zeXak8Rj6uNmYn7AtDIhLd2jgY6wLS9UM9a4k9i7YJI2QfpT
         KpstqPGRmWn29S47hhSj5zuylsDG8ZpicTFqd1pgoxjEu51Yo6Tr0bIjU7pajzt2ErMn
         AzaQ==
X-Gm-Message-State: AJIora8/Q/J2eXE1m/lmVRQ5vOqJdpDONgp6UOXZcPCdG+3nTZSefaY2
	OmvLjdMg0+/wRITXqXcUMQo=
X-Google-Smtp-Source: AGRyM1v6kNCxrLL0E0FI3Ed4WQr7CgSR++IdREMVzArDz2LsoiA+dWBgmzKy3yGUF//CVWQ9sW4awg==
X-Received: by 2002:a17:90b:388c:b0:1f0:49e:b7d8 with SMTP id mu12-20020a17090b388c00b001f0049eb7d8mr4011776pjb.9.1657627633482;
        Tue, 12 Jul 2022 05:07:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f604:b0:168:9a69:49b1 with SMTP id
 n4-20020a170902f60400b001689a6949b1ls1391009plg.6.gmail; Tue, 12 Jul 2022
 05:07:11 -0700 (PDT)
X-Received: by 2002:a17:90b:4d05:b0:1e0:b53:f4a3 with SMTP id mw5-20020a17090b4d0500b001e00b53f4a3mr4011195pjb.3.1657627631725;
        Tue, 12 Jul 2022 05:07:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657627631; cv=none;
        d=google.com; s=arc-20160816;
        b=xWjeIOXaB5mwNUMZCoUbamOQh6DbIDNpB7UiXU4Qb0BTtVbvHCocBbT88th1h2iP7y
         BrNcnwn3YosYidvAK+75Yzn9HT5fgCvJi43MUGu0T79iLeZC3QHiRqrZM4Xt4FeaLSpx
         yrYPusyCkF7QKYdnPLlZqtfR83fe/cEbc9AXOhrkMCdJJvk80yBdJk5nJPhft93lyVbO
         e9OzPspJzmm8bWdqlITrcYbRlfp3TC7HksV9AkW3h2uvDt83a+5/qgMLevIc8naELttZ
         0zqsdqZrzHF3mrAwwqChPVvmxzgcTG4xVrsXM/BRZVot7JMM7e/M/bC4aOosZpw96ozW
         GC5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NcaZoHxkoPLNKyXoHKEwHY+W+ThXitk+W0hG8LqbLf0=;
        b=fdN0AshcFCNuRj20Do9g1kM9gKiM66GQY8weQQnQsNpe9h+yNGpWgu2tkfG3B7rT7t
         lW9qAoF+2XFIrg04psMvZ0F8HwaZaINLcytUwO+ubacQsRhLpl7AIcraQSMTpBGdhDq3
         nqr9MUpWpsiI5Uvz8hfNFGbfdOrsjxXbDhJyifFxDCpta7/Vk6fKMH2GFMyQ+5cHSduX
         DZLIIFB2IlFgNViJ7Jv2RQtjtdeQ2ao3fY7y/1sItj7wc8g/GgJOToijxkKPPPwilN5V
         21nwcr4no6G9FFhzPYfYiD6t0DLuusEcunWsxoY+PPat5Yt9Ke3umXZBX6BCJTIKMpex
         307g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZDVWr+p3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id s14-20020a170902ea0e00b0016be96e07c5si264663plg.0.2022.07.12.05.07.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 05:07:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id e69so13577267ybh.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 05:07:11 -0700 (PDT)
X-Received: by 2002:a5b:10a:0:b0:66d:d8e3:9da2 with SMTP id
 10-20020a5b010a000000b0066dd8e39da2mr22329810ybx.87.1657627631236; Tue, 12
 Jul 2022 05:07:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-14-glider@google.com>
In-Reply-To: <20220701142310.2188015-14-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 14:06:35 +0200
Message-ID: <CANpmjNN1KVteEi4HPTqa_V78iQ1e2iNZ=rguLSE6aqyca7w_zA@mail.gmail.com>
Subject: Re: [PATCH v4 13/45] MAINTAINERS: add entry for KMSAN
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZDVWr+p3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Fri, 1 Jul 2022 at 16:23, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Add entry for KMSAN maintainers/reviewers.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> Link: https://linux-review.googlesource.com/id/Ic5836c2bceb6b63f71a60d3327d18af3aa3dab77
> ---
>  MAINTAINERS | 12 ++++++++++++
>  1 file changed, 12 insertions(+)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index fe5daf1415013..f56281df30284 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -11106,6 +11106,18 @@ F:     kernel/kmod.c
>  F:     lib/test_kmod.c
>  F:     tools/testing/selftests/kmod/
>
> +KMSAN
> +M:     Alexander Potapenko <glider@google.com>
> +R:     Marco Elver <elver@google.com>
> +R:     Dmitry Vyukov <dvyukov@google.com>
> +L:     kasan-dev@googlegroups.com
> +S:     Maintained
> +F:     Documentation/dev-tools/kmsan.rst
> +F:     include/linux/kmsan*.h
> +F:     lib/Kconfig.kmsan
> +F:     mm/kmsan/
> +F:     scripts/Makefile.kmsan
> +

It's missing:

  arch/*/include/asm/kmsan.h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1KVteEi4HPTqa_V78iQ1e2iNZ%3DrguLSE6aqyca7w_zA%40mail.gmail.com.
