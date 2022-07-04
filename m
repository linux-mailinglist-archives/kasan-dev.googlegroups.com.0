Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBSU6RSLAMGQEGU7Y6XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C8D21565A94
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 18:03:23 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id f34-20020a9d03a5000000b0060c46a7869asf3491561otf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 09:03:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656950602; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eb5KnT+E/rONt7oD4r+lG8v9VaQIlIwzDfHHwnZI1KD2XQU8zJ9oGIZpJvgNJwkR5h
         o7lVKugiw9NwwtKcIHUMtPL7DUQ8DM0TxoVpXtwScIj/c7YEpcJPrSq/fOBMrk49PrSf
         ItullH19QpQgfGWS9IvARQTcW0h+jS2blYJtpDeRMPgP+5o6ABeYGOXcxHJEtYwjLvnq
         VA/43UU7CQbrUUWM2O6UFQeXZM1hrzhKPwIGXiWrT/hyMfBvuKmb8yrnSF6Xzij4ziTy
         Kl883KskeVisgXD+v02IgdczFDEXGBHRq5kuo9Ci81Gx4Oirhx1Kofjl/gLdDdnz7omn
         WPiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=M4TsitZASSNZdmm+jcjALffsJMzYVUDnTwt0kwQPH0A=;
        b=yWAKB00YzjITocLpEm2XeN1DNenKufsS0CBgN7mukRBACmhS51k/i9jB0vncGiA9Sy
         52B4+e9e0dT2JCkOx40T89MWrpWtwVj4uhjfo09wLwtS84dZmk+rnXMoP4xw0B2+b+mT
         vhNwCGtXThM1IIl38/68eDkybCfHMxAKqZ9tGxYb40xT+xVL+p29ffhZGaKKW6iaQyFF
         LjzN9ss3Wqm3pF3H2zg5N9LoLSGnMjEp45zN5R6WpTwclwer4hVcDBdEQRbFBdB6bCzv
         pCAj4gfXass3NPLS+NsqQ6K+CgYwc6wfwm0ddO9OQHP5OljfTsfMbkGSYSUzOSGif59f
         FuYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Ql0IkogV;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M4TsitZASSNZdmm+jcjALffsJMzYVUDnTwt0kwQPH0A=;
        b=GVBClDmHwz8EjP1oPCa2gPTBDEANUEVCun29yMeZo4WMICJlPUjngKskpoex9tVBIP
         cWLW60We9uxUYkGeEOY2Wtm7vooqOXoQTnNnQe3zC55wHiQ39n/yocnS50P07ogeEYTQ
         dnIQJTDfgJs7J3X4552TnAOMmYlrIizNGwB+GxsrfcIC9KuEtfx2KcSeNpb3lbhu//bf
         m19JiX2Z6QssB2Dpy3vr2JEvzdiIbMOOqmy86RPAt9KqzOa6YRrBCOOLFU2GF5Qo+D+i
         W9CXNrZJd9ik76QCnwnVq8Gh8Wd+LBRUwKiIbRbDK8+6REGfXZgehjQAnU2nodiqR2Ye
         +eGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M4TsitZASSNZdmm+jcjALffsJMzYVUDnTwt0kwQPH0A=;
        b=h0DjNxmVH5NWYj6hulwqmYQqdT5qft5I071cgBz/l444ZQp/ahDBe2QZzHp0Hgd/ga
         /wsbuNUZxyzlJkkJKxGi929FBp2zPubFL2dU0IYlfxnD4KDMAjEumCofb1fGUnbq2LLa
         6SOOPBTsI59IEiVeJuueFwk4JWtkxF9YjMHVgy1lqc04qbmAX001s2llaqNRUB1mb1g6
         mLj+79EETn59cpsMCFxmbcecpoP22Y3QQz3AaJK71eOcYn8TP/M41PDXrrXHhmRRhPbE
         SabSXCFaUs7varPFYAohS4k/JGLuqbhR2b30GiI7x/dZoG2jyZsWQ24D7+kMbTQy+eqz
         bsIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+onwQIe6kHoVCIht3qPUvND/48Gg/07eI7fM53/ySBPVgfmIwM
	g8sojE6UiL9qU2Uj6PDEHi8=
X-Google-Smtp-Source: AGRyM1uneVdsRCTQ8sDF4C7RQbjS9CNBm9xzjAwOVVo/rxp4LClmLbKYbvuuIk/zxCbeRaBd7WSDhg==
X-Received: by 2002:a05:6830:25c2:b0:618:980c:776c with SMTP id d2-20020a05683025c200b00618980c776cmr10880782otu.270.1656950602607;
        Mon, 04 Jul 2022 09:03:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7384:b0:101:fb02:8b87 with SMTP id
 z4-20020a056870738400b00101fb028b87ls14310962oam.1.gmail; Mon, 04 Jul 2022
 09:03:22 -0700 (PDT)
X-Received: by 2002:a05:6870:14c1:b0:e6:5ba1:6194 with SMTP id l1-20020a05687014c100b000e65ba16194mr18344400oab.242.1656950602295;
        Mon, 04 Jul 2022 09:03:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656950602; cv=none;
        d=google.com; s=arc-20160816;
        b=U1CRorWWG67yjc3o/rQv/O41d3JTj0P7B8vnvjZu3DOn0ibtmlA4k5vMU047+fqWy1
         8/XUPpIMFXVAPhq5lqb0cwe0NQSNNmpqn6/y2hNuQ9ZRzuRYNoi/hdHxolvTwU37L2ZR
         bqaMyXhOp5nh+aBMW/AJl6bEcernb3gSTlhTLHU5DycDDTDDOjCdBevyb0N0zMAp5aUe
         KLMLu4Z1TVB5R8yh9KqZDWjBDsa5AssiOISDmwSkqEAeI/62YYFTHgvNV+s5Jshr/cNi
         0wu77iWJaPeYdQkEbSMgW5K9SSJeyne7K32bwJTydJdMplU0l7yJxfPUSTsFIcW7TPYG
         C8/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u9+2+BgYdXevELITx1OrbF7fQTuDUnsXo9A1UgIbV9E=;
        b=DpW715yc0O7sSegLKkc3owx37o2FTT9d3919kX/MVrWC/IE29LNRsywsbeRXhoyowO
         FRVVuVKFzsUuCVL9Ct1fo+TLT+IA1yN0pi2YA3UFenvLVCY3pveyFbnUvLvGGIjwSXKK
         jjX+KeVgGBbJwpEbS+cdmPTKheDeqIYRhRyU+Ot9rBUIG/TKSM6Q/6nHTUOuptFXRZVS
         +6JKDr7t41xzD062tklc94yNMI7MoCPAYvM+mfy1WubWkKbmdUY2tbaIKGBvx4VaKd9d
         QAWU8cVAGPhX2BbGkqqtCDH1vmiMTsDcHCl997kxl11EgZBhUA3LjDaH+jKi1ioswTS+
         dkpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Ql0IkogV;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g21-20020a4ad855000000b00425a5147e74si900710oov.1.2022.07.04.09.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 04 Jul 2022 09:03:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DE30660F87;
	Mon,  4 Jul 2022 16:03:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B603DC3411E;
	Mon,  4 Jul 2022 16:03:20 +0000 (UTC)
Date: Mon, 4 Jul 2022 18:03:18 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Al Viro <viro@zeniv.linux.org.uk>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Segher Boessenkool <segher@kernel.crashing.org>,
	Vitaly Buka <vitalybuka@google.com>,
	linux-toolchains <linux-toolchains@vger.kernel.org>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to
 step_into()
Message-ID: <YsMPRuOdXJIuEe2s@kroah.com>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
 <YsLuoFtki01gbmYB@ZenIV>
 <CAG_fn=VTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=VTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=Ql0IkogV;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Mon, Jul 04, 2022 at 05:49:13PM +0200, Alexander Potapenko wrote:
> This e-mail is confidential. If you received this communication by
> mistake, please don't forward it to anyone else, please erase all
> copies and attachments, and please let me know that it has gone to the
> wrong person.

This is not compatible with Linux kernel development, sorry.

Now deleted.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsMPRuOdXJIuEe2s%40kroah.com.
