Return-Path: <kasan-dev+bncBC42V7FQ3YARB3NLRWLAMGQEG6S3Q3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f56.google.com (mail-wm1-f56.google.com [209.85.128.56])
	by mail.lfdr.de (Postfix) with ESMTPS id B79D0565EB8
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 23:04:45 +0200 (CEST)
Received: by mail-wm1-f56.google.com with SMTP id v184-20020a1cacc1000000b0039c7efa3e95sf4516367wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 14:04:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656968685; cv=pass;
        d=google.com; s=arc-20160816;
        b=VU1oOIr43mwxWAT/LEp4pNZK1XW19AwnfHJJgTe33Amz5BTyfNqWew69EMQ3SmfBVy
         8AkF+Mp1HrbnHwIutSOCNg3TyBHOkmILyfcP5zlWigOrmtjGC+Zl2ZKnkKWADmAqB+7S
         cHPJyDzmqsAWZ5dzS7DzXX6itlmhBMfwu9Wt1GGCVTVjWrsPClEHuYwEtMcx2c91lae0
         ikrHdjLj81f5s0si0uyXjZJi4qj6yvwRQlWZEj6kQzbuSuzQpoNlcv7iziIL6eqJE29a
         1tm4YKoHeAGFJ3WvmEDR2YZWFYaci4M4qaCkxoxqxM6MnfN5sGy5m7LwV2qCmjQahor3
         5tYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=tfB5REgLHs/KKrBvNkAaOQPmIyXmzMrj2PUyBtzfZ7g=;
        b=Xz4XT+lpRJSj8U4eV7/GJelqsWKPyW6WBUPh8sfFv2c1fPvyCc74XO5si4kB103cbj
         WHQH95eUkeOLDTEtO7Q4T0k6OiFF+Q6lbs7uxQMoVFfe1+83//ei2WHg6skeKFL8/YTz
         n+7E/14rEIdHi653VDzQwhJBnON5hOE6zwih9yoiV/6UI5vvwLmPgq1j2qdkQDiYBw/p
         rqz7z8UuLhKoBhmC+JPY630agu5g4YCZApp7utlTdHsbtxaqLDRDf95oxNf9SCYe5dwv
         ox8leFmeP3eDwgE9q4520p4dFI8zrYBcKIxmXbn15voMx7U2+vLgyqap0VxGklJFMiKA
         syMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=AQZXT4X2;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tfB5REgLHs/KKrBvNkAaOQPmIyXmzMrj2PUyBtzfZ7g=;
        b=oC8vfbI4Q4Mc02jNU5xKdTXvNCDoCA5VJGhd6R/IvvHgVF4kDIW0h81jXus36MvAJl
         HL0mwwDzKCeUugnfITHoUNpB6vd5Io2MnNPrVszcKZ0k2+MOyxtyQ/wx6fZJmp7j9FUF
         AMEspnFttVG1WIdDUY17GjVJQz3sdl8h4QZrC15OHZVCnZc5RoKiT9DkZeosKVW+FQzn
         u2yNwQjbCrfKFMmZMyCu/3Ac0KQBMJK27Q/myFqdga22AUlWx7GVXbaGvi/nD33PQFu7
         1XLAlO8ijsrCMaSXrdAqIXjNNMGuxKYcNi4uTBXSUVZOfWwh3o//WTs+9WpHkZkz10Yi
         46mg==
X-Gm-Message-State: AJIora8Apn2H6vPks03nim6BteYMt9x1c6HEmiuRe9ncXiHCAVdknUIB
	mLMVp4cTCqgHF9EVf8ZhUmo=
X-Google-Smtp-Source: AGRyM1tWu7yitRSq3xIb7q9uW+inPbOsauhMGwFehldgLQ3VH5ZVSZ95pU+AbT1+IBUj6mZl1NFLWQ==
X-Received: by 2002:a5d:6da3:0:b0:21b:aaf5:b814 with SMTP id u3-20020a5d6da3000000b0021baaf5b814mr28346640wrs.140.1656968685343;
        Mon, 04 Jul 2022 14:04:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls24093418wri.1.gmail; Mon, 04 Jul 2022
 14:04:44 -0700 (PDT)
X-Received: by 2002:a05:6000:1882:b0:21d:1c8d:958f with SMTP id a2-20020a056000188200b0021d1c8d958fmr29474943wri.297.1656968684168;
        Mon, 04 Jul 2022 14:04:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656968684; cv=none;
        d=google.com; s=arc-20160816;
        b=HO7grDajOEPnBF/AowijYJSCvY2ttRKKtxD9lgIElLHNcEDuR6T3U8fkYdUu4sb9v1
         OyBoCUq6AOpHAGakgU39w7/oyvy2ce2RCBaI6DKHHbzbGx1YRPuiNv6kvOxRobdt7dWE
         DKrqj8iSW6ZIR8NiRTHy7OkOBdumJNJOCGhqMvhyux9DrwoqQs5TyogF6TCeZOyD8A+O
         suYAe8gvMqvUKeDxlhq1TbSUFHh8tR0+Cb8ZiZkzYsVXzNXnvxiTtam550UlB01g8VXm
         z1Qn8JboeCtqKdJS+fMqya+LNmtarGbykQS0dfUHGYikdkTWVOeJjwjov2cKgyqPws69
         3hCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=T4NEq+eMSGAkYEOA0B+r4pdVqAgo1X2D4OJSO7fEkNY=;
        b=fiYUegY7c1Ni+AMLit+F4+ulZTGW8KL0gW/LyWgdcVen0/i4cppGmTXa7FGDt74Ekq
         C8VaOa8eXi5Bb0bafPGOL0ph+xHt182mVtwScptDqNj9KUGhLfjebnfIjLlW0741DXld
         hXMkVkSsUscEeuLqDGaJPXhMbPBm0zARu664nIjHcf7LDHGuEQS7mbPouiIzCknZkx/X
         4vZC0O1fDGpRI35RjRbnJR/FJgRXNt6Zp5+yK22QBaX6yuCie026Nj2fXWrkXm3QZpQk
         9+rND/KGm5XNrX6iLq+uBX8z8l1RrLHxW8eTUiKzIyvBdTpvC63qxMnrEP6TZRZ3c9d1
         Acsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=AQZXT4X2;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id d15-20020a5d644f000000b0021d6f7a83cbsi24851wrw.6.2022.07.04.14.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 14:04:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8TEm-0088kl-TL;
	Mon, 04 Jul 2022 21:04:09 +0000
Date: Mon, 4 Jul 2022 22:04:08 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Linus Torvalds <torvalds@linux-foundation.org>
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
Message-ID: <YsNVyLxrNRFpufn8@ZenIV>
References: <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV>
 <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV>
 <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
 <YsNRsgOl04r/RCNe@ZenIV>
 <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=AQZXT4X2;
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

On Mon, Jul 04, 2022 at 01:51:16PM -0700, Linus Torvalds wrote:
> On Mon, Jul 4, 2022 at 1:46 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
> >
> > Why is that a problem?  It could have been moved to another parent,
> > but so it could after we'd crossed to the mounted and we wouldn't have
> > noticed (or cared).
> 
> Yeah, see my other email.
> 
> I agree that it might be a "we don't actually care" situation, where
> all we care about that the name was valid at one point (when we picked
> up that sequence point). So maybe we don't care about closing it.
> 
> But even if so, I think it might warrant a comment, because I still
> feel like we're basically "throwing away" our previous sequence point
> information without ever checking it.
> 
> Maybe all we ever care about is basically "this sequence point
> protects the dentry inode pointer for the next lookup", and when it
> comes to mount points that ends up being immaterial.

	There is a problem, actually, but it's in a different place...
OK, let me try to write something resembling a formal proof and see
what falls out.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsNVyLxrNRFpufn8%40ZenIV.
