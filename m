Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWFKUSNQMGQE44AGV7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id A4C7661F5D4
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Nov 2022 15:25:29 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id q62-20020a25d941000000b006cac1a4000csf11313070ybg.14
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Nov 2022 06:25:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667831128; cv=pass;
        d=google.com; s=arc-20160816;
        b=K5bsfEqcPQUHnHk76l/CsGkzVv+VSPnMTpGGBCYM3KOmXS/9Vqwkzn560iRmrktBdE
         d5UUUGUWU/UvqtEMsBdrpNdQW0KstSwdbc4lGQS8rWsQvD2HeDNwdrWQqw8UfSR/sLjs
         53OFPw09pPgg18Dsa1a6Xzq97Q2LvuEMwMRoSer+ROrPjqLsLtOScmLTtmwz5tusR4vq
         Js06SKP0zMuB+xjC9ikmDOY1LM2L8e7EhH/WaYnD867AwALy8++t2UmIapjQEDsZgEd+
         9X97P032fOctTL0cCjRIa9pyv8yXYkLFxI6vgnw7yBcI5ZHZ8WaIPRm6Yq0CtCFduhrI
         L3uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E1BLDCrr4WJMGK06/+qMuoVqyGcGpnYUTgA9X5Dtwys=;
        b=gPC+4nNcfPiN5A1xDKqlublbNCFWltIJazgigNv+Sz0swn4G2PpQGu0u4/qAlxfsGc
         UEvL5Qr6xy9yxMkidJQPRKS1esOMpMonrbw7AsCWADFvC1PDgY/cBlaGvYmgHsg/UPIs
         ZXyoyzowi1irkYw4Vhm6dW1266DvIeQ64eLywP8dhNwbWpcRa6tMiUJO/RYsR1K3nf/k
         Pm+o++aBWrjCkGU+moTuQmtgmPE6kjnzue6g04Boz/Wac+cZigVXWqh0/Eiqw2HXI0QJ
         EGfgCDMYeEaM9AGN0lvT40+r7X+7V8B70mLluQarz7vKEvIzVqPLnCT74NSVVOpXIFT6
         r2yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LdnEeXZk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E1BLDCrr4WJMGK06/+qMuoVqyGcGpnYUTgA9X5Dtwys=;
        b=Sb6DmN7lM6MgtMUQFwwoRXOQ3/ZjX1cO2zoT5+wWh+A9NSidJEFf3t/df4prspmWvu
         n/UTXYV0c0uRxzRu34D5iZeCqxIzNJGhwo3sW+HA5z2MbM89EQkeODdBP7bmRvFmMwrX
         7EfIHJUbwUeWYvRelKKYNla1euS0eVNQsgeix5IJXTXg5zN8FkcyYppRk8B3n0cai1uw
         vEGJiLAgfDnQQDNDzhKiSzFbbLqLSra+eRzW4Jqz7YVitvCx8oPbDZ/0KBGZ6BkPV3Gq
         1qvIy/3ST4IkwcE1EcPrni9YMuFCfi3JFaj93aCdfd7hUi88h3ld5K/vJa8bI1GSgrEQ
         4nLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E1BLDCrr4WJMGK06/+qMuoVqyGcGpnYUTgA9X5Dtwys=;
        b=SbTPqC5V6M0MnkmOcgBTZbHo+MtbTlv+sjOsRkNdhZic7+UkUW+1L2Q4mvXJcW6kgm
         XFGaLAqAK2eV+Xwj0fTUQFdYLK8Nf26QGHY4TRGwbq7RVh9GosUvRMELdNtuZM7a4HvB
         pHtfUDod0tA2SkwRyCJFzkFysOtarChYVK3k4t3g9EgIQhJD/UDvvVXjwxKxmyKsdkTp
         G1oTFKRq6xvg24bJDkyahlObQJiu9Gl3KD0II46H9HcrX0hBoj8fjCfzuy5ltQzP/QXq
         WmWKtmpZYbELvOgUbbBRN2Vz9AUc2zPkyksYVKSE98ep6xJEPHFPbMvJAj+2QHRbYV9A
         peOA==
X-Gm-Message-State: ACrzQf2ShScNx4b8wm2gom1rXnABTKXpWVHSHed7zlXt83GOopdA34+V
	NwuCeMw3jPsI8mDTTUpIItA=
X-Google-Smtp-Source: AMsMyM5oB2x5Au9M60sXsy1bmsqmP58kuz2btHjEl0WOqusmHWEmq+G1nRMxoAWMPMLPTcBjoyLGKw==
X-Received: by 2002:a25:c102:0:b0:6c4:c94:2842 with SMTP id r2-20020a25c102000000b006c40c942842mr49946270ybf.611.1667831128412;
        Mon, 07 Nov 2022 06:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cecb:0:b0:6cb:a74b:6d3a with SMTP id x194-20020a25cecb000000b006cba74b6d3als5775693ybe.0.-pod-prod-gmail;
 Mon, 07 Nov 2022 06:25:27 -0800 (PST)
X-Received: by 2002:a25:d849:0:b0:6d8:b611:364a with SMTP id p70-20020a25d849000000b006d8b611364amr1392658ybg.45.1667831127911;
        Mon, 07 Nov 2022 06:25:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667831127; cv=none;
        d=google.com; s=arc-20160816;
        b=rY5b/JI3nA3hANEdgYfimbQ8bUWrPdChsNVhqEP3sgjbFxXwcwgJB2XFwvEZ6LAReM
         0rsMbiWvLXPqgAzsA4Eo3/ZV3ztCLm4svBPgqif3WffzBSo2HiuVbaPjpCKCfQxRYzcS
         sOhp/z1x3rVwG+w4XtCIpEQPFq2OaWoEr6WBK40BiDZTrsmX+xZQoWcma7m6PxooX+Ru
         2hrMJvDnbsWhw5OE+Yw5yc/fvy7i8ds2lWuwdPBvX24XCdkT3WGg8BpmGcudIbWJUTbI
         KssebwV8/8yQet98xq5ubdDVZZ+FJ8XEM1bvfRm6QQco0sOin864VA2nvj704lmvvKDw
         LZKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oboWyf02L04GWiqbRTZkWaKzcVjcV8xl9eLiAMUj/TI=;
        b=eXblDAZzOjkDDbltY9Fa8TD7C603wr+E38jYI/JNn1FF7OcE6XTuXRzblp5V/xoGqa
         DwSH4huBzZkJZMh0y5nJyBrF1DWhKLsuyY3WtUN6V7tKAhOWulJd+rmm4KDVriWYiZuj
         PGR9BvgyQ/jWW5n1s8Yk+zUWz4i8jSmk7D4PXs7rg4G9CncVk8dAxuCFZuKAJE5nwjzY
         /WcbcXE9LGzBb3aMItjMfv3dkG5rbeIQBihW5J66UhzI5TMmOQnzo7cXTuLt++n09r5T
         G9lxVFCjIRihBM0jcGLxKoZQ8aep5JI9QNxPWsUU1qpFpHR6HC4wah1GSt7rtOP2xaKl
         xCBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LdnEeXZk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id w69-20020a0dd448000000b0036bde06a6b6si345741ywd.3.2022.11.07.06.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Nov 2022 06:25:27 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id n85so8163660yba.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Nov 2022 06:25:27 -0800 (PST)
X-Received: by 2002:a25:9b43:0:b0:6b3:9cc2:a651 with SMTP id
 u3-20020a259b43000000b006b39cc2a651mr47557091ybo.485.1667831127440; Mon, 07
 Nov 2022 06:25:27 -0800 (PST)
MIME-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com> <20220905122452.2258262-7-glider@google.com>
 <Yxa6Isgcii+EQWwX@debian.me>
In-Reply-To: <Yxa6Isgcii+EQWwX@debian.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Nov 2022 15:24:50 +0100
Message-ID: <CAG_fn=VXR0FGoJZ5BonxiFd7Wr3LX1hfF7PRRfm1=26B5v7vMA@mail.gmail.com>
Subject: Re: [PATCH v6 6/44] kmsan: add ReST documentation
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LdnEeXZk;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Sep 6, 2022 at 5:10 AM Bagas Sanjaya <bagasdotme@gmail.com> wrote:
>

Uh-oh, somehow missed this letter during the review process.

> > +  CPU: 0 PID: 6731 Comm: kunit_try_catch Tainted: G    B       E     5=
.16.0-rc3+ #104
> > +  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2=
 04/01/2014
> > +  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D
>
> Are these table markers in the code block above part of kmsan output?

Correct.

>
> > +A use of uninitialized value ``v`` is reported by KMSAN in the followi=
ng cases:
> > + - in a condition, e.g. ``if (v) { ... }``;
> > + - in an indexing or pointer dereferencing, e.g. ``array[v]`` or ``*v`=
`;
> > + - when it is copied to userspace or hardware, e.g. ``copy_to_user(...=
, &v, ...)``;
> > + - when it is passed as an argument to a function, and
> > +   ``CONFIG_KMSAN_CHECK_PARAM_RETVAL`` is enabled (see below).
>
> The sentence before the list above is rendered as definition list term
> instead, so I add the blank line separator:
>
> ---- >8 ----
>
> diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/=
kmsan.rst
> index 2a53a801198cbf..55fa82212eb255 100644
> --- a/Documentation/dev-tools/kmsan.rst
> +++ b/Documentation/dev-tools/kmsan.rst
> @@ -67,6 +67,7 @@ uninitialized in the local variable, as well as the sta=
ck where the value was
>  copied to another memory location before use.
>
>  A use of uninitialized value ``v`` is reported by KMSAN in the following=
 cases:
> +
>   - in a condition, e.g. ``if (v) { ... }``;
>   - in an indexing or pointer dereferencing, e.g. ``array[v]`` or ``*v``;
>   - when it is copied to userspace or hardware, e.g. ``copy_to_user(..., =
&v, ...)``;

Nice catch, thank you! Sent a patch to fix this.


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
kasan-dev/CAG_fn%3DVXR0FGoJZ5BonxiFd7Wr3LX1hfF7PRRfm1%3D26B5v7vMA%40mail.gm=
ail.com.
