Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUVPT2MAMGQEXXPCWCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F2815A15EE
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Aug 2022 17:40:04 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id o17-20020a056a0015d100b00536fc93b990sf4178719pfu.14
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Aug 2022 08:40:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661442002; cv=pass;
        d=google.com; s=arc-20160816;
        b=AEDPEqu6QlF15PPsHX0R8eCpLjOYeWfi0E1ueSU+v2JwoY5czNDNG78jhRracuKmI9
         IK7WytONcXfzgLW+RH6FzWdhmIqyuhU9APw7TXHpY46svaKrqi3Jsx6GCgXRaB7AZKYo
         K3Z8nU2kPqkl7PpqPpo+YoB5o2TLOfYzq9cZZuGmkNtNLsTxgulsuSPQ/2hLVMLcDbXT
         fQMHOvROka8pgEofmyitcujK1bL37sLK5DS6DkXoFH0hVcC2J5Jc+QbI7od07pZjXcDH
         2eHxpv/qbtBaGUKgehgK04XiZhAFFsJPNHDAyQzo5Ol49fI6qvhHJNnAf04UYyYJnFAq
         vZ3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZJ7GcyvDOkJy8EZPo6SiJpxu3NpdKjcjfiWDHETNrOA=;
        b=nbrM9K1cRYlu7MjiU5q0Dl+k9TqJIhWyA98+qwBz2Ib8abiubA8UbIWZqS1xx+CpDG
         GtVbmwkcWiTM3EtL8GR2qeKAkpiUWyWW/Af1z8xV4E0ftclTDbcwPXcc1myP1Nks+5JS
         tEwfGa5vH26Gdv+5aUU5UhDq/ga9UQtOgpHjuyiI/to/DWJC/ZKurgz+Qq6ar8BKs6W3
         KIDBTWIj7HnAR9YYRFGfPKsmqk47YyoyCk8RkYJ4Yq4KDJ7PK7Xv+XpnlVqlF02G2kB9
         49c2MwtV2V2780f6/38n1/i77VvgwzhMaVPlPE3WuSEJJODXwT4OlY/WpGJyT6gxQqLQ
         DdmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F6xZURA7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=ZJ7GcyvDOkJy8EZPo6SiJpxu3NpdKjcjfiWDHETNrOA=;
        b=GZFcAr1tm5vdDLOzkWmFNZ4zjaEcZt+y6ml+XgCB6RcJsbn3iPA6vE4wtVLCR9ynt0
         VkaRGdUhvC5LQbo7U5/llg4+M4wjFJTLBzgQcRpri6utWGqwSt53kX81dai3GRXztnAu
         zPsnFOBcdLSs0yza8lu1LIM1/PHU0spw6PAmRxfEvxD79kBN4AlnvMzAKN6e8TpHqMhH
         EE/sv1RLt40gb+73QkNrjqA4LPsA/y/AigP2HY/YQ0QgS7Ts/iTRcLd3AYMRqTtEQ/m9
         mE4x51Q3fz05YSi/Xy4Url2OEgDsMs5GMROFkcWdmCSe+5YhNf9B4CqwRZJS7zo53ETu
         5CZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=ZJ7GcyvDOkJy8EZPo6SiJpxu3NpdKjcjfiWDHETNrOA=;
        b=nlSo95fDd8yxplmvH3ecpRoE0xkiss5Fk4lMkcwBPNo5UhSQ9SxgmPBYmPui4mTMcS
         s2QnU2qXnJijuHNXXIMHOFAxtnjd2KyQ5JchkaRjA3ZbWci0sc+XS3wnOTd5ECLN2VtF
         SXDsU5oRIXmXiSfVSYs+p7WyC8aVSo6bWG15mOYgdPY9hHYHcDyEC0A+qUGRFgDvJJsb
         P9vDKbil/L5nw2l9LEQ3yn2CkoHXGf7ZkGAOFsQiqnJFInVeeGW18YyzNfcKmt1Lx6fc
         yF30jwlauoCmUxSsMzaGr66HYfs7qZEugYJJAnN0MvzSCfuhVu9FncnoWlSQmMVXUsYB
         QmAw==
X-Gm-Message-State: ACgBeo0+fAi3erbYOkxpWhMozsWSl7oKsbVmb/VuYRYX2O02qfknXIdQ
	YcZ5sfXMYcN/sW6SRL5GD28=
X-Google-Smtp-Source: AA6agR4oNq0CoNT6L/hhi7cuPibJu6CGRi0okd/qTEZInUPKPEpKuQDQwTHN+1SfQq0aUGjjVgOgQw==
X-Received: by 2002:a17:902:ef4f:b0:173:353:3f6c with SMTP id e15-20020a170902ef4f00b0017303533f6cmr4452599plx.6.1661442002227;
        Thu, 25 Aug 2022 08:40:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d08:b0:1f5:35a6:600a with SMTP id
 t8-20020a17090a0d0800b001f535a6600als3406767pja.3.-pod-canary-gmail; Thu, 25
 Aug 2022 08:40:01 -0700 (PDT)
X-Received: by 2002:a17:903:152:b0:172:dd30:652d with SMTP id r18-20020a170903015200b00172dd30652dmr4396619plc.0.1661442001487;
        Thu, 25 Aug 2022 08:40:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661442001; cv=none;
        d=google.com; s=arc-20160816;
        b=hD78UgFf2T58daN0wYds9hmV3WAcnnrsqfwmyL4ddYF60o61Sfe+FVEYhx+/dYKT5E
         hsrC0QMH7/pxRv0UpxQjoxOVSaLEbCsIqmELCQQPcrEMr71DWxBi2ONbV1Dmbg7VRHnv
         1K6jUfF2MZNbux1ycKKMQ/ZgnDMuW+kzTYLYxeIx8ANiFC9EL8ny478Zq9vJ3UU1IEgl
         v3OvZSzGdHvcY+8Id3nujn099TFSk1E1H1M5w0nyf4vcmTaBfNssA1AbQ032RQpmizPf
         Q0vfZ52g6y8rk7pQuIl/XUM1OcaY+wW1uI4cOEejDH1voyGN3dwRyHQAV2qVIT3eehO7
         EXcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fEQ1d/PiEHzLrmSBXGQT2W8YpNnPcaA3hRqhgrIy1b8=;
        b=CHkNcML8W9bPL1SrW4dfPyj0cadRGTybvBkUxKxNNaYPUenbYo3jxOLOpj/K/5ne5L
         4H20LbGoLly+lqPPyOaYZ35i07Cx4P0uN/UFDG4zwiGes6k8GcvMrWxZpZXYC4DiaJxu
         AJ0vVIP2ilQsGcDpSOmizZuhA3Mh1Rab+qaRX66KlFIGwKhK8a36bUUvf/kwrJuZ+pyB
         fZY/gpLl3khUXdSlnBkWVH4Q05g/pF26hz31O1BUFtVPxEhaIRWoLfbRgY1xQ6vM9Cbh
         DEoQ00bf5Ey4f4SSy3ckSBBRW94K7tb2/AczNxwZKDRH2un2WICwPDAz5bbIyDUsskAD
         2INQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F6xZURA7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id mw17-20020a17090b4d1100b001f50c1f8943si205383pjb.2.2022.08.25.08.40.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Aug 2022 08:40:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-33db4e5ab43so69750337b3.4
        for <kasan-dev@googlegroups.com>; Thu, 25 Aug 2022 08:40:01 -0700 (PDT)
X-Received: by 2002:a25:bc3:0:b0:673:bc78:c095 with SMTP id
 186-20020a250bc3000000b00673bc78c095mr3870021ybl.376.1661442001024; Thu, 25
 Aug 2022 08:40:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-45-glider@google.com>
 <YsNIjwTw41y0Ij0n@casper.infradead.org>
In-Reply-To: <YsNIjwTw41y0Ij0n@casper.infradead.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Aug 2022 17:39:24 +0200
Message-ID: <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com>
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
To: Matthew Wilcox <willy@infradead.org>, Segher Boessenkool <segher@kernel.crashing.org>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F6xZURA7;       spf=pass
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

On Mon, Jul 4, 2022 at 10:07 PM Matthew Wilcox <willy@infradead.org> wrote:
>
> On Fri, Jul 01, 2022 at 04:23:09PM +0200, Alexander Potapenko wrote:
> > Functions implementing the a_ops->write_end() interface accept the
> > `void *fsdata` parameter that is supposed to be initialized by the
> > corresponding a_ops->write_begin() (which accepts `void **fsdata`).
> >
> > However not all a_ops->write_begin() implementations initialize `fsdata`
> > unconditionally, so it may get passed uninitialized to a_ops->write_end(),
> > resulting in undefined behavior.
>
> ... wait, passing an uninitialised variable to a function *which doesn't
> actually use it* is now UB?  What genius came up with that rule?  What
> purpose does it serve?
>

Hi Matthew,

There is a discussion at [1], with Segher pointing out a reason for
this rule [2] and Linus requesting that we should be warning about the
cases where uninitialized variables are passed by value.

Right now there are only a handful cases in the kernel where such
passing is performed (we just need one more patch in addition to this
one for KMSAN to boot cleanly). So we are in a good position to start
enforcing this rule, unless there's a reason not to.

I am not sure standard compliance alone is a convincing argument, but
from KMSAN standpoint, performing parameter check at callsites
noticeably eases handling of values passed between instrumented and
non-instrumented code. This lets us avoid some low-level hacks around
instrumentation_begin()/instrumentation_end() (some context available
at [4]).

Let me know what you think,
Alex

[1] - https://lore.kernel.org/lkml/CAFKCwrjBjHMquj-adTf0_1QLYq3Et=gJ0rq6HS-qrAEmVA7Ujw@mail.gmail.com/T/
[2] - https://lore.kernel.org/lkml/20220615164655.GC25951@gate.crashing.org/
[3] - https://lore.kernel.org/lkml/CAHk-=whjz3wO8zD+itoerphWem+JZz4uS3myf6u1Wd6epGRgmQ@mail.gmail.com/
[4] https://lore.kernel.org/lkml/20220426164315.625149-29-glider@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W%3Dttq6KA%40mail.gmail.com.
