Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB3FGRWLAMGQE7IDXSMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A4C3565EAD
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 22:54:05 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id be13-20020a05651c170d00b0025a917675dcsf2965896ljb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 13:54:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656968044; cv=pass;
        d=google.com; s=arc-20160816;
        b=Er4lJFwEHdVUzEtX0B2BqPZcFj8ETOPo2IFLfu0vaKAKz/sL9jnI7GwUrmToWnKygH
         09vNAK7AyTsnNCS/rAPknx/StO2fz/437yS9TGz9OXWYL5jMZeFQFk0KZuit0AM28roH
         fbGKn+GBMSSj8VaqldxCUH1L30/3oT6txJR1JoyZNSqiwDyY562NK/46pbN4/m0FIrls
         yRjmsNx0FLLDtw/q8XPzFpfXhcQNiF8fJ7TY1h7pLtxBGCoBgwEkRjmljSlF1iGYKvhx
         kCov5oDVcyNsGY6Xr6xV1aCiri8uFP16o8CfEJ6o3uYRaFqbyKSSDkMvoUbHdhy3wvP8
         iRRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=wZQNfMBJgty5HEeN8K4Oh1+ejhoBH6amqz2do29FL3o=;
        b=t7GhRTDMbdVjhSofN4xrrYBbeySJJcwGqmsgIUSmITcbx2RcAStmD/N8mJSxucCOC/
         mG/ouk/PDfGZd+qDTuP6RIxabWFJXAafMlxafPD2dKOB4cy0O1Uo3F/N98jfw/WpSHIK
         ZxGBtoiJS6JKeIUbndEOnKMZRX5l5m3Z5LwkcYo0Z9lGAnvdsLxWuQhpNMY3o3AtcvBs
         NAOMewCXToDjZvvHXahYE7klN8YW+3C6uLZLsmR43SgZ802gm65vCVFZbM/MeKE66LPU
         H5QX3YSS2USNFOJ5HFmeQZYi/B4rgeJt/TmprUqmKTjdLZ2wEIw5fLC9btnNN8VLV6O2
         s6ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=W2hmMHZI;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wZQNfMBJgty5HEeN8K4Oh1+ejhoBH6amqz2do29FL3o=;
        b=gz6ES2rA3b37i1ZCdtR4alRdNNDlLObzfVKkgF2Ll0t/+NG99DuaxYhqFzrh1isIZ+
         MHHh9c9+echmLv+PMNc7MYP2a4Bq1MIF2ZxCQDt5coon/cgsxwsOmp4BEHazicnIt5XU
         OD1wQfqD4r2dHBzLnf1Am7PA3/brtpRT9NrUxILcbqeidIqdj8ANDI/xPoa33X9XJUgv
         7PPzKuOCLvCBmkUtPhPtQ4tcW2i4Ld0TEKPK2uDzqJqsZhd+Re9hk0Z/Az2z99ss81Wi
         B8Wa2PIj/i9lnN0foWvJ+aj1UfzK89IetjqrzBP0TJivWAUkc1AjOsIRaPC8+gjajGgm
         7nyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wZQNfMBJgty5HEeN8K4Oh1+ejhoBH6amqz2do29FL3o=;
        b=F4ry2RPIe80hTP4JpUwbCAUyOAgulAKjt6gRCL8mK3UiEsOIjkdRsBXo4a431hwNZB
         EgihxqEyEBKc6Pw9fvAC3ftwV7livKXEkhODWg7FvHJj0oz/t/dSBIEPgPUmUAmRbz5x
         9ZobDqJOIYodZwydK749Cf3OTlNYde1u3944KsDPsyLKVRKN4Ii8TXBsiFZF/ZvE7qqn
         kKcoz2R/K/995s+0CuMDze+FU9k3K1BPnKQAy+j+JCfygacJtZR7L+i1r4YSMhIbLDsG
         pOaiz6ac1yZi+J34JYIs2P/NzmuyuFBFKLFIiGjBq7wfasKiBKQEUbYvTp7wFu2cVMDy
         hMKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora83a9QgUCbXm9enkWeqReHh9oYu7HNRVb/Qe+ShG0+sUySSroWw
	xow58kBeK9mNr0g3h/SoXfI=
X-Google-Smtp-Source: AGRyM1uRin0kSLTF+VTC+EX26BgnDcMKtxvkKzEZ4Lu8KK8gAzy64CU0JKxwFqVKuNRrcSUg3oGgBg==
X-Received: by 2002:a05:6512:3b06:b0:481:507e:e3a0 with SMTP id f6-20020a0565123b0600b00481507ee3a0mr17370692lfv.616.1656968044651;
        Mon, 04 Jul 2022 13:54:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:238e:b0:481:2fa:2826 with SMTP id
 c14-20020a056512238e00b0048102fa2826ls73646lfv.0.gmail; Mon, 04 Jul 2022
 13:54:03 -0700 (PDT)
X-Received: by 2002:a05:6512:b88:b0:482:c49c:34ce with SMTP id b8-20020a0565120b8800b00482c49c34cemr1929625lfv.394.1656968043271;
        Mon, 04 Jul 2022 13:54:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656968043; cv=none;
        d=google.com; s=arc-20160816;
        b=v+bElvxbfOf9susFM8CGqF9mfCBNVHzTJU/gOZMBP55/fxpufblCN+qn2B9vRSVn6N
         rPPNtKNM3jeK9gIb6bbrNdP+jPQQAVJu4rVUp+ADbmfhLujqtpABKrjB7SeNJP964cw8
         sUzIX2BW3CZksWCVObyO0J2lHA0B73t2a/pzm+kPZKPLG3ji0D1x7FthiO00ula6jVro
         v24hypxC2GNWSGotPFPDWdgFd5fAjteB4og0z1EM0iKt7mm6+HxAjKwXrR3AU4ImEHMW
         81eGe+ixbvlpUMw5VhbgLujPgJl/XMM/SDxUi2CPEmwhM3gTraLQYlIp4ZDQsCFP4Zdp
         F6EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/yAZeAbMlA0MlzGxn2hN3/XK5qxO5T7qF19l5UEr4Zc=;
        b=hVk7mkvb0M/o7OwsaHTnb8DfYNFWHZgK2+Bv22LV2wXDw6zPijPwPpNb0aFFKP9auB
         doc0eQysF9Gih3RAd2AAsI9VDXxIgN81A98HJqaDRo8KD8tSzvmRGeh+OnhukYn7jzUr
         oZWdgfEbQYmzXb/kzul38PjXbY78QXIY2Lv2s+G3vKvri8wiH9eSxre+9BCbb5P6GxTv
         35GY781PXAMcosUz9ulFtWPi+coWhVq2hzLPA4+Sw3VgUNChTq23BV8GQZRdtymKwEcJ
         9SmIiHN3EVWYAOKWXGh87ObkL5A8D7D1HI+V4frUxyE2uU7G00jMm+h5mbh6Buf5N1Zq
         srcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=W2hmMHZI;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id g14-20020a0565123b8e00b004810be25317si1031439lfv.4.2022.07.04.13.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 13:54:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id ay16so18459985ejb.6
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 13:54:03 -0700 (PDT)
X-Received: by 2002:a17:906:b795:b0:722:e662:cffe with SMTP id dt21-20020a170906b79500b00722e662cffemr30884019ejb.121.1656968042727;
        Mon, 04 Jul 2022 13:54:02 -0700 (PDT)
Received: from mail-ed1-f48.google.com (mail-ed1-f48.google.com. [209.85.208.48])
        by smtp.gmail.com with ESMTPSA id ia10-20020a170907a06a00b0070b7875aa6asm14554992ejc.166.2022.07.04.13.54.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 13:54:02 -0700 (PDT)
Received: by mail-ed1-f48.google.com with SMTP id r18so12956414edb.9
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 13:54:02 -0700 (PDT)
X-Received: by 2002:a5d:59a5:0:b0:21d:205b:3c5b with SMTP id
 p5-20020a5d59a5000000b0021d205b3c5bmr28828449wrr.97.1656967686356; Mon, 04
 Jul 2022 13:48:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV> <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV> <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
In-Reply-To: <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 4 Jul 2022 13:47:50 -0700
X-Gmail-Original-Message-ID: <CAHk-=whQ2ijKVv8eV_P3c3cNaH8B4iKU0=GgwObzsJQM6cYtDg@mail.gmail.com>
Message-ID: <CAHk-=whQ2ijKVv8eV_P3c3cNaH8B4iKU0=GgwObzsJQM6cYtDg@mail.gmail.com>
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
 header.i=@linux-foundation.org header.s=google header.b=W2hmMHZI;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Mon, Jul 4, 2022 at 1:24 PM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> The mount point check should go around the "check dentry mount point",
> but it's a separate issue from the whole "we are now jumping to a
> different dentry, we should check that the previous dentry hasn't
> changed".

Maybe it doesn't really matter, because we never actually end up
dereferencing the previous dentry (exactly since we're following the
mount point on it).

It feels like the sequence point checks are basically tied to the
"we're looking at the inode that the dentry pointed to", and because
the mount-point traversal doesn't need to look at the inode, the
sequence point check also isn't done.

But it feels wrong to traverse a dentry under RCU - even if we don't
then look at the inode itself - without having verified that the
dentry is still valid.

Yes, the d_seq lock protects against the inode going away (aka
"unlink()") and that cannot happen when it's a mount-point.

But it _also_ ends up changing for __d_move() when the name of the
dentry changes.

And I think that name change is relevant even to "look up a mount
point", exactly because we used that name to look up the dentry in the
first place, so if the name is changing, we shouldn't traverse that
mount point.

But I may have just confused myself terminally here.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhQ2ijKVv8eV_P3c3cNaH8B4iKU0%3DGgwObzsJQM6cYtDg%40mail.gmail.com.
