Return-Path: <kasan-dev+bncBC42V7FQ3YARB5M3RWLAMGQEXCOI24Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f62.google.com (mail-ed1-f62.google.com [209.85.208.62])
	by mail.lfdr.de (Postfix) with ESMTPS id E8C85565E77
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 22:30:45 +0200 (CEST)
Received: by mail-ed1-f62.google.com with SMTP id w22-20020a05640234d600b00435ba41dbaasf7802799edc.12
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 13:30:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656966645; cv=pass;
        d=google.com; s=arc-20160816;
        b=ISyZmLE1V5NFSilXz/yoaYMJSmCsTZu2ezeMu76lD8uEZibI/QctxC/JwTKLNl2mdO
         N1gIWugLxHhuIpyKQpiHrRlR5ZOmTAq0kpe9yLPZEpVT4qmOZEK7qcEnJvYRZBXNGht7
         QWjDywFCy51ZJeKvTxVpMs7Mpah9NMCspzaL/Xim/TVZA+2UAJS5aM/luRvncvTs57bR
         YNsiBurs3abjd4YLnPxoA919xL2Y0sNq+yTqvwPlqk1cO4wdhF/QBCjSyUICb0AXxFQE
         wyNzIJvz0bICVJExY1OI/vjEir1vQ15wRmnfLcJf25BzvZW7PZHmubQF8G5OC02CG93f
         xbQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=Fb4nwmp3iPadYDLv17ynn7isn7BLpYlK+GhZoFnqQ5A=;
        b=0Pcj9h/LuJguMUh7fyr7cv0yitofts4k4WCsZ+z2xWfFErbH15KSzA2UDvFuKNyiAE
         +9VM84AStGnRT4S9b1ofDQFXkpKCX+64rpObPnIls7NjGrXi/r03RSanR29py8B5r50b
         oTtScXrW2wgJFRsFea9k+GxGM4g6IoqqFapLi4YK+gz2w9dxGLV/DNC040IdsBZ3nooz
         itl/Ug7BAuVLACQaPOTdBpo1BdB/NOtGLjCfkwDxkAr+u+iJ+Gmu0Q3EKtxrw3nnUBvp
         ZQFlDJ73cWKnDSihBvZH6E9OYw3w4VOXJN1hBmRtEzKq1kAvvizudjLz3lUPMaRXRW2r
         Xxsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="ne0Uf/6y";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fb4nwmp3iPadYDLv17ynn7isn7BLpYlK+GhZoFnqQ5A=;
        b=BS8Ac6SaHhTIL3rmn4TUA85ETnH9d6nYeLeopMvoacpHCgAKWbvpiOoMFmTcTYVnp5
         1sBej4kF8cFy99kg/zWDFBPxChcSTOWJ4D0yza8Dy33E+SV+OftDz35zl6pBzbvQmn9p
         NSZEG6JdvYVoGHw3OYGq6gKMG3SjZ3S38YrOPJivHF2RBVmcZbDdF59r+Xt5Fbkqa6T/
         qsqj8dzVekT1dj/RkZY6eZbMUzjUkVqRQ+449/flc/zLGek2X8Ys+henmbP1vOdT37sc
         wNdlbMdvsKRFKZne3xZRpYQn8n5vSzxfG1UCn/nSf4hjS7Puyt6NQdLFptsr8U3x5NV5
         d+Gg==
X-Gm-Message-State: AJIora+Q+SVvqx5PO0vsNpRxm+ysuJmvFzYtbYf9zjyTRKRH7nHHdm3M
	5PwM998NVJ3Hoa9IGFRiw5Q=
X-Google-Smtp-Source: AGRyM1sYKwsXt4oiCIwPZ8Zh1T+i20S6Ugak0bxNJPqRQw73QM2ie6/YAApFMMDkm3gZNYTlJD3Efw==
X-Received: by 2002:a17:906:d7:b0:718:df95:985 with SMTP id 23-20020a17090600d700b00718df950985mr30418022eji.582.1656966645401;
        Mon, 04 Jul 2022 13:30:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cf:b0:435:9b77:f6e3 with SMTP id
 h15-20020a05640250cf00b004359b77f6e3ls2272167edb.0.gmail; Mon, 04 Jul 2022
 13:30:44 -0700 (PDT)
X-Received: by 2002:a05:6402:2497:b0:437:a341:9286 with SMTP id q23-20020a056402249700b00437a3419286mr41021842eda.156.1656966644088;
        Mon, 04 Jul 2022 13:30:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656966644; cv=none;
        d=google.com; s=arc-20160816;
        b=p/dcLYINueT7kD60HVum3lceRJrQ9bd3ZG0Cp3llfmNze+uTYxGw3ID87CrgbTW65/
         gA+qpC+9Z6I1SaLpuYo1ZdH/TINq3RKNz4yvE13H14X1Ji0ilenX54ZkMDOtiYqXAo9w
         kmGK96jRypZFKlER0fD/CpIDtb0sEG6Nn6kC3AGuXb5kq6sUlNmklE6VWp0gpegr6plc
         zk9n8f9nwIMOzDQ2E1qqVgM38ciE+aHaRyQ4aVB+Acn09+iinjCKCyHJtfP+AHZml9CM
         nUobwGdZQmckmqVzLdk05JdPlFnMCdN24aLxCxbj/T0MK2ImGa30weozkimWB1/g8alh
         n/OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0ahdG6vwtrla/GfArjvdjqG8Ieo6jXxVEyUk4N9P1DU=;
        b=urpKWmLwQdMenWrZRlS1phP5z9vfsII76S4/GPOVCFelGRgQAZR6FIxvOE1t8MgTtM
         5LXF21Xmd7/fa2d32wLUCNxjbgd5wggDN/mHxW4X8Lw5Sy+CJENHb9gP8HpuoKhgc7aF
         oPHqYr+gCwLYrbLho87gMwMQ1xHYb71nEy5w+06HUFHuBOtQ2iD7NUxnJlNrLtYS/GtG
         SklBG5cFnLZnnuAnffoSCUZ8keXLOkzUAnk9arh4ftbkCqGd6Fvk96vDR/MWQKq3hesR
         8tc8esgeyN/7AhJYKMig/o2Pxnj8lSnDEqEsnDEQ0zEAq4JEA2rWSB5MtMc+h+z2lwlF
         wmig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b="ne0Uf/6y";
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si1133112eda.2.2022.07.04.13.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 13:30:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8Sho-0088HH-1A;
	Mon, 04 Jul 2022 20:30:04 +0000
Date: Mon, 4 Jul 2022 21:30:03 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Matthew Wilcox <willy@infradead.org>
Cc: Alexander Potapenko <glider@google.com>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
Message-ID: <YsNNy9o0+6Uyb9G4@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-45-glider@google.com>
 <YsNIjwTw41y0Ij0n@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YsNIjwTw41y0Ij0n@casper.infradead.org>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b="ne0Uf/6y";
       spf=pass (google.com: best guess record for domain of
 viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted
 sender) smtp.mailfrom=viro@ftp.linux.org.uk;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zeniv.linux.org.uk
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

On Mon, Jul 04, 2022 at 09:07:43PM +0100, Matthew Wilcox wrote:
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

"The value we are passing might be utter bollocks, but that way it's
obfuscated enough to confuse anyone, compiler included".

Defensive progamming, don'cha know?

I would suggest a different way to obfuscate it, though - pass const void **
and leave it for the callee to decide whether they want to dereferences it.
It is still 100% dependent upon the ->write_end() being correctly matched
with ->write_begin(), with zero assistance from the compiler, but it does
look, er, safer.  Or something.

	Of course, a clean way to handle that would be to have
->write_begin() return a partial application of foo_write_end to
whatever it wants for fsdata, to be evaluated where we would currently
call ->write_end().  _That_ could be usefully typechecked, but... we
don't have usable partial application.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsNNy9o0%2B6Uyb9G4%40ZenIV.
