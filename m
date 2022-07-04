Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBYNFRWLAMGQEVJ3HJTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CF8D565EA7
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 22:51:47 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id p2-20020a05651212c200b004814102d512sf3332601lfg.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 13:51:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656967906; cv=pass;
        d=google.com; s=arc-20160816;
        b=AtnkfYbCLJSIisP+OOQOQgxWZaxJDcrW0CtfYjKOrzdYpvan4yWM7PCo5fsK90LTW+
         9AXQAt3vv+t10cLE3Iuhq49QRh3ONZZVBNJpjQ6JgWIChnOQQ9B1eJDxeJXaN3wddSIV
         2HVY9fFnONkiIA7F8Shr8SEnkJATjT6xYlycmC3mlMkaB/bV4Lv4ndLsSUsHahks0tg3
         uYFG5wKLXi1r0fBEdLCEKvoetPJKoPNf9rQpla2H+84agmrUeUTwDvcaeU8TlOd+Mcky
         24GeONk5K3/Crlg90CA87pKbFw8QxuTuqkx1Myl4YEAIvm0AvOPbk0g0a+P7ystdlzKx
         v/6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=FYLsmMnOKUDsIUaaHI6/W7AXAhV1YPnOFm/2GfJCQ0s=;
        b=uwAdTBzEGlgJEfOo1lw/72ve8BHkLfCh9OL9BoI+XTYVzC3Om1/MRPvQIsKoJi26Vj
         EXpwwNsoFcXmup62ZiAWk4H9B9UG8yIT/o4L+9frf+5KdAsCzCoqDagFoYgtI838yrlR
         BJo98i/YxCfbzAn4Y1Jy6Bo5Alm2VdLL6uGpLXbI6f4Xh7PpsbMDxpCYbMlxna4V2Wqn
         m9t8VzZRZcvRM6rkf8D5Qcqvc7xb1CNlPOiS+mOjfDe03qqrRh+VuUlPUmYmTPIz9+cJ
         YGL0FTOY4BX/9C7mItjhflTpwYo56W4t2vsD5hRj7e6SaWUm8hl4wpQry66lLSahUn3Z
         YAoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=WC8Na+ue;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FYLsmMnOKUDsIUaaHI6/W7AXAhV1YPnOFm/2GfJCQ0s=;
        b=tJbHQFk4glp96RWvEEIy6e2m+AXmRcbmiXA+5J/nPhVX1O6bYfd5iM7EH+xEWyCy0f
         HdpXbK9BFsYKlYyTrfJs/yy5RYg8PcPF8+2CEmsRLWuRo9OWucNM0lFakZ8qZiUh1oDG
         gkPAET5z2CYMqE7mzRcqxSYp4wlAle5WzfiUqcNQ+2QcLG/MaKo78yxp4P6ffFvCGVoy
         7vpcDyLlsgJ1Q8IhgdaLLNdUjN/USqUZbyxmymS5hHAhSuy6pruVU/apGtIDH2fCnQoY
         qzkDm8aSZHO+NU88wRd9rIUFHHp1gZ5dMgQrU1a6hVIdbzw2ovZaq5z5gAQNFDel2lMb
         7L/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FYLsmMnOKUDsIUaaHI6/W7AXAhV1YPnOFm/2GfJCQ0s=;
        b=OCta2OoDPdPj1IJEhtZ3N4POCOEhaXKRqSL9ctVejWVwPtdK1gDiUpm4wMxJvhB2w2
         fIwGAd7sGCZuJ7bgwzfuhPKQdl4xanlw4nh8JbeAq5ptBSOr+Bc0R7DXPdHHyuVrTML9
         YEUdzEF2tOLjsotDmWqWG4hAeEhd4YGZMPv2sspZEJL2D6QmUZf0FdPCEttn+wCH1gZh
         nOUpsiaYB4ufB3jEgQP88XZBg//q0ijEgPx8zBb/oGZiA2U/rMlW5ZjDCFMVb+j1Kf9p
         hHAWkXAEIHPme/z1Z5QPnM81IRSlaED0PYUd/4c4iHjvgKL0q6Nkks5ErkLEsL0A7Y9k
         RLBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8PjbL3o/rz6nZW0kYyCQZc9s56ThABaf7tMY1sXGg0LJOPgfUL
	yIaGlhQZZbT6durhGnEt2jA=
X-Google-Smtp-Source: AGRyM1vNXnQtLRpytakMlaJ9UL+1pSADCT60oDBV2nj3im4zoF76hv1m5nOJI5hh4nQU3gwo+Ac3tQ==
X-Received: by 2002:a05:6512:3c81:b0:47f:ad61:7edc with SMTP id h1-20020a0565123c8100b0047fad617edcmr20463005lfv.133.1656967905552;
        Mon, 04 Jul 2022 13:51:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls71484lfv.3.gmail; Mon, 04 Jul 2022
 13:51:44 -0700 (PDT)
X-Received: by 2002:ac2:558e:0:b0:47f:777c:a5ed with SMTP id v14-20020ac2558e000000b0047f777ca5edmr20882467lfg.190.1656967904335;
        Mon, 04 Jul 2022 13:51:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656967904; cv=none;
        d=google.com; s=arc-20160816;
        b=deIBz/wpUIvLqvjWa9uVz6qtKo1gibTPvY5RKJLqDk0lqTl56VU4njbN6Y9FFjUwwD
         VHRxbdBSIYkfjfIHZ0sioS0xHSJHTTjP7Kmmi4DeL6OcyojW8P3AAgFsiBMTUjuYDj1d
         LgLVpoQZXwpqU4i8MykZQa2EXZZFa1VRLOyjWnZEmRpNC0KAomNTHhe4qfUL57KuEisu
         AphH3UL4h77+/RgjFobyiE8k6CU6YxlCaXk3ddOkkcgcPq1Pz33PNwx5sibfgAOqUxUo
         0fKsjfNZj+TpEHlLH8llX/6uk2MlBcHcfC6Kayulb6eg+w/CHtSzKuXsLwmDkdF3oFOX
         4h8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D+7oxHi4Udb60oAybVQkpA6ge9KpdkDRHq2SyT5frGM=;
        b=ilOiurUqXsZ1eiSjyh2iML6gR1oLJmjHv+4e7nYkcJy1V1EsyFePsGS5w7PQrTaAHA
         /OeSU4+qj77GrAmDMuAA4PNEzvQmZIfmZ9yOG5s3igSvkOk9uvAVBCLBK/BnGvnRDfsb
         FueDUmgvScCgTZjBLXvVJqUO/tI1QkqccXcCwKa/B7yfDL2BWd2Cc0w+2qt/lpC1I/hM
         vL95cBLJSWJYwuO0k64bKTqTOAB0IrkFO27OjOozxXWiDgT34u0tXLwPiISF7pM5UvYu
         88bl2OJRC0wQBCwB6cbvsNpq5uo/3JkuWRjoX+EEepYujZ4LHua9xafZM5f1LMxrzsch
         YkdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=WC8Na+ue;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id bp20-20020a056512159400b0047f8c989147si1237110lfb.3.2022.07.04.13.51.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 13:51:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id lw20so18466923ejb.4
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 13:51:44 -0700 (PDT)
X-Received: by 2002:a17:906:d54f:b0:726:2c7c:c0f9 with SMTP id cr15-20020a170906d54f00b007262c7cc0f9mr30630716ejc.441.1656967903827;
        Mon, 04 Jul 2022 13:51:43 -0700 (PDT)
Received: from mail-wm1-f46.google.com (mail-wm1-f46.google.com. [209.85.128.46])
        by smtp.gmail.com with ESMTPSA id t25-20020a056402241900b0043589eba83bsm11186516eda.58.2022.07.04.13.51.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 13:51:43 -0700 (PDT)
Received: by mail-wm1-f46.google.com with SMTP id l68so5976588wml.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 13:51:43 -0700 (PDT)
X-Received: by 2002:a05:600c:354e:b0:3a1:9ddf:468d with SMTP id
 i14-20020a05600c354e00b003a19ddf468dmr9623331wmq.145.1656967892746; Mon, 04
 Jul 2022 13:51:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV> <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV> <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
 <YsNRsgOl04r/RCNe@ZenIV>
In-Reply-To: <YsNRsgOl04r/RCNe@ZenIV>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 4 Jul 2022 13:51:16 -0700
X-Gmail-Original-Message-ID: <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
Message-ID: <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Al Viro <viro@zeniv.linux.org.uk>
Cc: Alexander Potapenko <glider@google.com>, Alexei Starovoitov <ast@kernel.org>, 
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
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=WC8Na+ue;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Mon, Jul 4, 2022 at 1:46 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> Why is that a problem?  It could have been moved to another parent,
> but so it could after we'd crossed to the mounted and we wouldn't have
> noticed (or cared).

Yeah, see my other email.

I agree that it might be a "we don't actually care" situation, where
all we care about that the name was valid at one point (when we picked
up that sequence point). So maybe we don't care about closing it.

But even if so, I think it might warrant a comment, because I still
feel like we're basically "throwing away" our previous sequence point
information without ever checking it.

Maybe all we ever care about is basically "this sequence point
protects the dentry inode pointer for the next lookup", and when it
comes to mount points that ends up being immaterial.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwih_JHVPvp1qyW4KNK0ctTc6e%2BbDj4wdTgNkyND6tuFoQ%40mail.gmail.com.
