Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4VMRSLAMGQEIGKNVTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE7C565C2E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 18:33:56 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 62-20020a9d0dc4000000b0060b1e18e8d6sf3514333ots.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 09:33:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656952435; cv=pass;
        d=google.com; s=arc-20160816;
        b=JeYlsuUq73seSnd4WIcwOK5Mu7ZBQNQ0bl2D3UKCOUSYJJsowyiLTQIbhwldc85GHW
         UlRtpjy+Xu7fbSOWg6VKAYoeCyHy2GWoGHodtZRqXjDKwEZ43e3ckiFeGpvhMtK6wjOy
         0w50Hs5qUxZDTkNU+rslA4kd5NEsg6cD2/1nJ+AHX5SJCzy9H2ojWLGV8jGy0Efvkyc7
         0mjnhw40dpmq5UZO8rWwjqf3P1bQweFaBxndxEmzxuj7TNq3yPe4SzlPSh1MaQIGwM8w
         SRH6W1rMAhmMT7/XP07WG/5pYbkIqZuXTYd8hJm85Oe9O5pVPu5SL5C7s9uIvrdRkLbg
         pIIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0/Wnjkcdf08+Cuiz7fvTdlnsG7ADpOfrTck4VPJYqkI=;
        b=QVbj6etFzzSbb1Yrxl/0Jmp8EzKyMgzQsBZUjAxew9oYB//jq7HJicWIT+bioogbQp
         sj74bbmiNAex+zCuvmHkF5RBB8NVkUhlGf6M0STZfzfzu1SsBhasERzRtcRnD/pBekJc
         /Hhp0q8w5d7Re+19GCxVtCtswL1h/Ykjp1e0cxug5CIVgKJxCMAnR+BFj1aDtQQRRQUA
         mA0sfS3/b/z+fP1Y0IrVx/HtHRJOUQ36MMuYQEQ3qB6k+iRh6wL2ZiArD1b9s0EHYxmJ
         weLQfN+N9n5N0lvuL9rQpusmabIfUGeAPau5vwpNZrqWvVpcPpSghdouMbOtmZznb+Xp
         IHfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R52eKy4x;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0/Wnjkcdf08+Cuiz7fvTdlnsG7ADpOfrTck4VPJYqkI=;
        b=YQUC6VW2fNMSQa9E8vsKLHoJG+QqjcffcRTK+Pxt6W/33fK0yIpGYtNArRYmEzQns+
         EaV54kNDc3yzOkA7Y7Jr9i3Gm1/oDCblH3Zh8K9TPlc+LpbPLKKE+1ybY+gdCgjao59i
         8fxVie8ZbhOgJdnXk85daxlvUm1kmfYrRT0aEamwmVa43j0bY4eQG2HI96DxPb4UxQag
         KyOBLenli7scdQh34wcE+u9kOTpnSeVrPBnOjHGwmRrwPg6CvouYMnDOqPsnnSPXdeuN
         4Ycbf0/zHlxxLA/etNUXBPwqyNhbid0zNrqjNeMjLupf1pjzlU9UYjjHrdzRdiFK1Dsz
         2zNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0/Wnjkcdf08+Cuiz7fvTdlnsG7ADpOfrTck4VPJYqkI=;
        b=eegzJeVgklaRYa3DdK3ZONgNeqorXmB9Nc1lPSP865f+5BbPRXEPKsNSgLyMMDEB7u
         YeZKsm/PKz7gnGB2iTfuprel+yq7LoZXjfLPdvSbizBYCV7exzg89CYOrjh4KjT7ZmVc
         3AAwA6VtL9czxaRz29L57uWsK+4tMqYUp2+epa/q+rI2nwF89CR0Db8MKAykgbpvmiEf
         KhqZwNXAw5Q6WVSuU1L5/ZBol2xzlqnZ+/uFUl3z8X69Zvoc8NPlnfW2C9q1Mue1CiwF
         SCCtWLYY1ajDTq1pwhV/SQx9Sh9s+fRY1kLGItJIn21WCcBjiMl7usIhiQ9y2jXTNDel
         yI+g==
X-Gm-Message-State: AJIora+BtcRx4g/oZ0Ykyy+0IcrRgl/bTDAz+0agisWAJL3JW7fHkoo2
	d68gAYOZ0NGpDJW3Tw5PGYE=
X-Google-Smtp-Source: AGRyM1ua+aq3rf9Zryn5hs3AB27+wLZc0HzpLRhH07WTI8cAtul5At+J3lZzxtnMBgkbiDWYfPuf4A==
X-Received: by 2002:a05:6870:2407:b0:101:13b5:9109 with SMTP id n7-20020a056870240700b0010113b59109mr18721296oap.31.1656952435047;
        Mon, 04 Jul 2022 09:33:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b9d5:0:b0:32f:1186:e961 with SMTP id j204-20020acab9d5000000b0032f1186e961ls17264224oif.11.gmail;
 Mon, 04 Jul 2022 09:33:54 -0700 (PDT)
X-Received: by 2002:a05:6808:19a0:b0:335:33ec:1f6e with SMTP id bj32-20020a05680819a000b0033533ec1f6emr17352333oib.181.1656952434703;
        Mon, 04 Jul 2022 09:33:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656952434; cv=none;
        d=google.com; s=arc-20160816;
        b=SztnNS0qxmAvOObyXyhJaDUi1abpgoLsB3L828r5bY1u2C5XRuezMN4FPMmFJ08vgA
         jcRYYDlba8OHXbxv2W/BzNo0CxjjVQnf7gIs88Wpv8fHgPlu7Qv4g1dt2ZzzbS/6gW6o
         Rz5nlGovIyYtxuwTcsHGBrASsgZikazfuyC7S51plgv19AcvJEoP2fGXmWlZ5Nsvqc4Z
         PyX+8HwYe4qlt0FAxhX1f9csQ+kVkaa4cg5BLZbC2gtpsk4+ao/6EILi+jVeC0IOSAu2
         FTFll5TRyxK2GUG/AKtQuccHWWWJzFRYKwFXuyz5U1s+aoXC3XNiuRSL5tvUN4s15xwt
         O/Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uTJEKBpneiIbXMc3b2N5EXRSBaOvIi8yNaCS7kWKrlA=;
        b=tZNHW1lHfgQkAmNiJ6yj1/I/ypsHoIF5JKdomY6252p+OB3qKFIyYi6ZYM1w6l9Gtw
         083n+c7esvgq7iELblzOS0tfZOGLLqnGKmf2cMFz/PaT3V0sdn/a4DjFU4TBc4vH+T2H
         aG182LKVSzoKBj7S/Vktxf6p0rhi9HDDr65VCiJR8BPnfMrBxwXuw0kwYgzYV3ViISvK
         30OhGLbKwYwmANAuwW5+XzAyHRSnQO9qRDt0XKBFihx7HnRPx7P26LcYuKTvetxjQNWf
         DRJz3VLaUggrBRzrEtKjge9wZG801uS0eFNscItzKOrwh55YJq3GUFDBz9S3O/ED910b
         vgrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R52eKy4x;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id j24-20020a056808057800b0032f15fa78efsi1378680oig.4.2022.07.04.09.33.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 09:33:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-31c8a1e9e33so34458807b3.5
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 09:33:54 -0700 (PDT)
X-Received: by 2002:a81:a847:0:b0:31c:7dd5:6d78 with SMTP id
 f68-20020a81a847000000b0031c7dd56d78mr15980661ywh.50.1656952434098; Mon, 04
 Jul 2022 09:33:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
 <YsLuoFtki01gbmYB@ZenIV> <CAG_fn=VTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ@mail.gmail.com>
 <YsMPRuOdXJIuEe2s@kroah.com>
In-Reply-To: <YsMPRuOdXJIuEe2s@kroah.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 18:33:18 +0200
Message-ID: <CAG_fn=VhRynRP_8dPH5gb28=LUU1O69GiX5JR24naJCLuamAEg@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=R52eKy4x;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Jul 4, 2022 at 6:03 PM Greg Kroah-Hartman
<gregkh@linuxfoundation.org> wrote:
>
> On Mon, Jul 04, 2022 at 05:49:13PM +0200, Alexander Potapenko wrote:
> > This e-mail is confidential. If you received this communication by
> > mistake, please don't forward it to anyone else, please erase all
> > copies and attachments, and please let me know that it has gone to the
> > wrong person.
>
> This is not compatible with Linux kernel development, sorry.
>
> Now deleted.

Sorry, I shouldn't have added those to public emails.
Apologies for the inconvenience.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVhRynRP_8dPH5gb28%3DLUU1O69GiX5JR24naJCLuamAEg%40mail.gm=
ail.com.
