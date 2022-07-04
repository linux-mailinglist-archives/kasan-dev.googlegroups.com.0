Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBVOMRSLAMGQEBDTDM2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 147B3565D28
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 19:41:42 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id h125-20020a1c2183000000b003a03a8475c6sf4344474wmh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 10:41:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656956501; cv=pass;
        d=google.com; s=arc-20160816;
        b=U3PRMRfdsttnWC90jpjtLhMbSJMbRLVV//Zd1tQO5VBR2JT6EwsRyzJlpGP7WCHYh8
         I22NgfhKNjhOn+l+2beSsaLOFiV2KpjTyH5WBdCi/fFF3XmSLfA2wqybYssnmAwQM/+x
         by6M+VbyQImyhmzmaevHA7LLaKtkTzY7Fm1bmDLPkgJIW9UqiAXDkEsRL5QDXZQyjISp
         fxFCUD1ULuexRO7V8EmuIJepaThYw8gZNRy+4wnFO2/bOL8D0k5hyf5eOSJlyjs85LJE
         WWFqkvLDHTtJyEZddAHGleUXtUqbQbAxnCyk2v3FNbmXEXANv9O9mHsb02YzIkcE5Pys
         Z5Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+9vOmc2U4/w+Z6nObpNl+G2t0KuXWQ5A1TmDlZ+VPQU=;
        b=pUPKVv7YxU8RYZR4bMqhKI1MaJ1zTu42Xz0hj7Tfi78k6QEU2evm8ZXS9ND6SJdqlz
         UrO/+SgIaU5ZJXajO04PF0xRYr7Wj+PhEcbcSjqGNruXwfl5pDpuLNDMk0yRRaewOORH
         BaS/+cMSfoweQZWl1ScXuQy6TbSV8nooviOgwXMkV974I6euM1ati+kOsSdRK/WGBv1r
         giCG5lZuQMykaOYQhpHvBjVs7tnKTqkEN6sK6U64NY4S6qSwlhJFMUEYmbdJc6c8fsZr
         pCoUbXxFmD15FA2tQ9yjaxCn9w4otkeKcmWYbEWbtXEtDPBxo+7zY5xAXKc4OZkJOvgr
         5gpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=fwlp1Hgl;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+9vOmc2U4/w+Z6nObpNl+G2t0KuXWQ5A1TmDlZ+VPQU=;
        b=RjdADDokuHPtJ3tkBc62Pkka6LGqK92SUBCnkT4bk/jGsn0oyQJZMjy3mhl9prwI9J
         DNi0EePRPbBsR84upmikH4WpVB09vb8+56Kng8niQhNQHiks85oaaptZrV5jq2BT6JRQ
         lgqmiEPXHL2zQMVhMxle64i7Nq4J0/NgBe4g7dTKJcWoqqX30GeWrwhAjZ6qXeJie2eq
         UkMrn3RNwK68+tHdeU8IWdrOSWTJe4HXlao6KWd/uHLBKsjcCtepyV9WLhUQLPIgweHM
         4W4mSEJV+51yt6ZH9MOMdtJH2peo+FS5EzWcTif3hRrAF+mXVk4IldaFHGYOl/S8dpon
         PR6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+9vOmc2U4/w+Z6nObpNl+G2t0KuXWQ5A1TmDlZ+VPQU=;
        b=AMJ/LtXdsU3mNSRrxbEd/muZrz6Xv/hs5IqAf9WxViDiwt/fj78iS0N3tIWZ9df7zg
         jOLV6hyw8B1/R0B+RY16w4VShJWhAGJMD9KB0hIsI5ci845nSZGgyh6UEHbpzOcuQrlR
         OJEf9XUaLm/WCkkZnN+Q2ydsPaHQNaHedd59OQaTDIgvICCik+FonpYY/69WTQVkntXe
         O5/I5JYHNcQcWPySPB6lSHJWThUS4tx/Evzy+/CAJFiMAT11zztzrw5WmeIZtMW7CDIy
         fIxWyJolnZ5VMewIpaankf7twMMjxYO8gyfgOo3zMnMjg5FVQrpRxvjDviwwwNJrjdO3
         dm6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+decSK1dSPvu4G7vLFpBGMY0z/z9WTg4LliE3eKGzepElH15Tu
	b13ncAECtDj8FIDfPfh8pj4=
X-Google-Smtp-Source: AGRyM1uYNMestWHYSuorATjonKFBD13wnbyy3k/DLNUz2+5kmzG04XhMRL+/nu1AWMcdyvJ+ROHFSA==
X-Received: by 2002:a05:600c:4f03:b0:3a0:55a2:bb4 with SMTP id l3-20020a05600c4f0300b003a055a20bb4mr32037741wmq.181.1656956501568;
        Mon, 04 Jul 2022 10:41:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da7:b0:3a0:3b20:d119 with SMTP id
 p39-20020a05600c1da700b003a03b20d119ls7515743wms.1.canary-gmail; Mon, 04 Jul
 2022 10:41:40 -0700 (PDT)
X-Received: by 2002:a05:600c:a42:b0:39c:9086:8a34 with SMTP id c2-20020a05600c0a4200b0039c90868a34mr34401312wmq.169.1656956500377;
        Mon, 04 Jul 2022 10:41:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656956500; cv=none;
        d=google.com; s=arc-20160816;
        b=FE63vEPnv9DEcMtAqiCgd44WjaEXj5ub59VQRdA2mK/eXmiZADZRF4Oic4pOfu1x5y
         ikB8CSg+2/Ay3TiiLdoV5+qelM4/H9gYtIYjdpIKjtxS9C3lNX8pO1Dx49J6ujcyeHch
         SAaMdZ+qca+DUfR0H0h4GRr9loyXjYphbdvlIjURXcfBIGTCsYj1IpK8BqTElcwZCi2g
         GgXwO6OyR5dr0HfzJXuKYbXtSAOaUbYgHB4iScrcjaWQgK5D36Yk/JAgPzR1Aas95exO
         zSaw2olTXjgoKMbf3H3NnakbiFKLm/pY4AGlpB3CTiKsa496nbVE5wQIl8kYfJwc1qMm
         BA1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YJyesbik3li+nd7lTgRBI8S9OD6JxlDs1GIHpVzW1PQ=;
        b=n7YQ5mVBXyffJ8g/mgNDWN97+QP5mIUJMQR7pN/Di5eKWIFBkkvDR3/xXSslVIfVbn
         lxC4D2RcLymbo4IuDCMJoaULIcy8naRq/F4pYBvBA5DKtu3H1DnbLM0Ax7N32Zs5nAzw
         6GvOSIvgF0fGzHoD847CPM3CBkvJieM37DbMXZBbNBm4/zP3rfyBJN7L3GSzgzwJbbti
         SLEM+saaVr9BRklrqLHH9lWhCWYqzR+7gIfWBe+oHrA0IDy15iuR6Z4druRxKV3nlRKe
         PFqTtkeJvTvOQPdwufrvrF9XA/+ii/GnN+5Tqgaoyg9TbsMdnEafoy3EzDhn9S1HpY0T
         5ILQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=fwlp1Hgl;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id az15-20020a05600c600f00b0039c903985c6si523132wmb.2.2022.07.04.10.41.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 10:41:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id c12so2076310lff.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 10:41:40 -0700 (PDT)
X-Received: by 2002:a05:6512:3d11:b0:47f:8fe3:8e98 with SMTP id d17-20020a0565123d1100b0047f8fe38e98mr19120359lfv.53.1656956499595;
        Mon, 04 Jul 2022 10:41:39 -0700 (PDT)
Received: from mail-lj1-f177.google.com (mail-lj1-f177.google.com. [209.85.208.177])
        by smtp.gmail.com with ESMTPSA id q10-20020a056512210a00b0047da5e98e66sm5239195lfr.1.2022.07.04.10.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 10:41:39 -0700 (PDT)
Received: by mail-lj1-f177.google.com with SMTP id v9so11819244ljk.10
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 10:41:39 -0700 (PDT)
X-Received: by 2002:a05:6000:1251:b0:21a:efae:6cbe with SMTP id
 j17-20020a056000125100b0021aefae6cbemr27345923wrx.281.1656956181432; Mon, 04
 Jul 2022 10:36:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com> <YsJWCREA5xMfmmqx@ZenIV>
In-Reply-To: <YsJWCREA5xMfmmqx@ZenIV>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 4 Jul 2022 10:36:05 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
Message-ID: <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
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
 header.i=@linux-foundation.org header.s=google header.b=fwlp1Hgl;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Sun, Jul 3, 2022 at 7:53 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> FWIW, trying to write a coherent documentation had its usual effect...
> The thing is, we don't really need to fetch the inode that early.

Hmm. I like the patch, but as I was reading through it, I had a question...

In particular, I'd like it even more if each step when the sequence
number is updated also had a comment about what then protects the
previous sequence number up to and over that new sequence point.

For example, in __follow_mount_rcu(), when we jump to a new mount
point, and that sequence has

                *seqp = read_seqcount_begin(&dentry->d_seq);

to reset the sequence number to the new path we jumped into.

But I don't actually see what checks the previous sequence number in
that path. We just reset it to the new one.

In contrast, in lookup_fast(), we get the new sequence number from
__d_lookup_rcu(), and then after getting the new one and before
"instantiating" it, we will revalidate the parent sequence number.

So lookup_fast() has that "chain of sequence numbers".

For __follow_mount_rcu it looks like validating the previous sequence
number is left to the caller, which then does try_to_unlazy_next().

So when reading this code, my reaction was that it really would have
been much nicer to have that kind of clear "handoff" of one sequence
number domain to the next that lookup_fast() has.

IOW, I think it would be lovely to clarify the sequence number handoff.

I only quickly scanned your second patch for this, it does seem to at
least collect it all into try_to_unlazy_next().

So maybe you already looked at exactly this, but it would be good to
be quite explicit about the sequence number logic because it's "a bit
opaque" to say the least.

                   Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A%40mail.gmail.com.
