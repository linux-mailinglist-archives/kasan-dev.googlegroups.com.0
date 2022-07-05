Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBF4BR2LAMGQEJLGVBGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C62F1565FFD
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 02:06:48 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id w23-20020a2e9bd7000000b0025bd31b7fe7sf3118955ljj.16
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 17:06:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656979608; cv=pass;
        d=google.com; s=arc-20160816;
        b=imKi0fUTu77ZzNykqE5OoPAHz5CVWbQ51lIcs7JeJqIa+EMcRcPFpP48NMjYO4LfeA
         B/OIcrqrPYYoNfPZtLHhJP19MSu2MbDj55r7OKDUhFLeiTZBQXeYjTXnn3q82mzXszk0
         BVYcyKzEISJ/ovTzhtQdsHmFhnHAZg1zFjcgBf/IngrHFjxsSul9qZG3y1piNN/yBXQ4
         jcv9Ax+41Ib6bHIWkFolBMuqeECBs9IdreLM/fC2jXU851eaXzbfwK/z1FzhMaTIOR/2
         7Jo3FU3QUqy0Cr9K0eoI/IoxMRhSF4xExrmLErQowAToG6Fv2ZVAGXPTjAsY+3sW3ghX
         yZSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ZHmD5ZxsA5vwQor7ti7HmfOmqnjpNgZ2OFFfhP+PaSY=;
        b=lmqJC0PH2WxaenNgrVCPFUquXyvYJHgn4M3fw8AcEdCPD8OXeqAOaUxskv0kQ/QkFJ
         sdeoRa3/OkWPs1kEKC/PNZ5zUXEdi36k2MPLIMnSlViiVt7oO8UHMlThb8Q0EY6qkWhs
         OWaPr/g5Gwg7DJcnTEh7lppSpUS7J5zeLSXC2waCmCVqEJVlKCK6BjzLboo/Snag5h/L
         zvglvMOhNx6vtEopQwVIWnXJ5pNMsxr1sDsRuQ9UatI5onuRYe8WLkg4QmIMFjeC8fIi
         lqg/Ifv1pQvARSlbA+D+6cjVdJ+vsfPg/8KrBRPwJpzaVhzRQEfgXvpehbH91TjWzadj
         gYDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=DIX8InJ6;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZHmD5ZxsA5vwQor7ti7HmfOmqnjpNgZ2OFFfhP+PaSY=;
        b=m+DdOkSA8NCY7YPTh43DnDT76vTyJPQc1sSRH7aB86lHtPGFwieqHbAnE9bPy8cb4Y
         pbBrfq555aepNsSdje2RCAemszKWyC++cKFDgf7a7E/aH47SPhvCVOUfhz3oz9NW1ULJ
         1NPfnyIyf24+4kqWYnRJyJ3wKQbjKmEygFAQr+nCiEmnWPENOfRNNuTKzTZke89w/pDx
         InijVS2L13VpaOzRL3GdDNZOunMChoAteNC9cjzqcA0R2h2PfiaDvldkNkabSvjNE/vF
         vQrL9OsREahLtm9G73lQ8qABJdKgKuOr5BVpHxXZiXF30EaCx4EVg43Jy78R+2R+FpXn
         bcjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZHmD5ZxsA5vwQor7ti7HmfOmqnjpNgZ2OFFfhP+PaSY=;
        b=hK+BSnLWkmyhdTO7iBYBQ+6hXGJ8bS7NKsx5AxUk7bguGy9qeJNnMrgLabC2vi2av9
         3kQmf4qXmDhoj/HA8U8HsfqUcurVlzqMyTBawMnkoLb+vqXz2sMyblGdbJCXnAR0UD7x
         huVoy8Bn9ECMxAY9ivFwc749+4lBALfqHybeVXxriutJw2FsWV6p/b32DchVtPU0mE8n
         APFPv/twU4I/VzimuCx0RJR0CXCnpe9KknXrvcs3j3hFsk17S1CAFoLVd03H1XRweHe2
         GJnuWTIfW8NqDDjBMWnGyikCTU4H2waZPYB+pO+1tEGm6zZd9zvvPJAG6+nnmvdXvKjy
         rXEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/8KpJllRs/YkpuLQuDfUNLSOAB/T88N8XHqDfRxNRjdRejSwvr
	actUcI85coq7YLrSCaUL1Qo=
X-Google-Smtp-Source: AGRyM1thQa2XBoUqXfi6X7H3+m8sRZJSAvme5W9HQ5OepA3FJXH/8IniOXHCwJbC9Ma5h3RfjCMLjA==
X-Received: by 2002:ac2:5594:0:b0:47f:8ea8:5798 with SMTP id v20-20020ac25594000000b0047f8ea85798mr22089657lfg.614.1656979608057;
        Mon, 04 Jul 2022 17:06:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls240321lfv.3.gmail; Mon, 04 Jul 2022
 17:06:46 -0700 (PDT)
X-Received: by 2002:a05:6512:39ce:b0:481:31e4:1e06 with SMTP id k14-20020a05651239ce00b0048131e41e06mr20818864lfu.376.1656979606752;
        Mon, 04 Jul 2022 17:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656979606; cv=none;
        d=google.com; s=arc-20160816;
        b=mQv2vvCOZo4KM2em8e76JyLrSg0XZunwNO5TRgJ5usME8hXBg6hus4pAJGyFM/FEO3
         rMcP5SGuaDFfkCVY+5XHvFxM6h9jBO9eN83cw6FRiydTgxnUf2kCY3ZV+hSgzFQPYPCi
         aMHELvH3f/WT55nVRCA5gjJQ3UE2dVGCdmB4ewEF4HdnFC0nIfnXMgd9VHlyL3CLrZeL
         77I5x6G0sNMtqnkwIG8sSl6CYLRzckY2F5ztgiUApi6Xle9OnU++tVucd3fOAkwT1/EO
         kGBfTB6sxu2cMhpZLclefgn5rwSCC3BwAAfjg9zaJiEF1Ey5m+lDCBV/qvgZDphO2Cug
         MLdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qmr+F6QyjrWZ2ZNhmVLeAUEKN7hzojbkjvHu88aEdVo=;
        b=sGS4+1G7ikYSl7/JCh+OvD60BWQeEyUqZzderT69Ow5gnSopcBUux9jwKH2Nb11T6b
         hkVpJz/fmU+dSwhoikuj631dwR4sCGPYTBmCiM9E4irdRsettQaAQbKSgs3CYfX6Ze+r
         9yiJA/ipr4WXtKlS1ZrKDZ7bh6d+U/rbAiirTQbVUaL2FMmIAW/iK95t3azJtRTlkPRA
         qkKoqArQRcuMwOsJE0yZtsopIKy6x8LVg6at5PhuL6SjJixcMhDhyZAGUy1Ef8JexJPK
         U+DadIOGAImaQPHXP7Pl460aE3P0igxfskjez5IND/ZTGp6YM+nscDDFTdhQoXRki5JO
         5OYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=DIX8InJ6;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id u17-20020a197911000000b0047fae47ce32si1234644lfc.9.2022.07.04.17.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 17:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id a11so12622748ljb.5
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 17:06:46 -0700 (PDT)
X-Received: by 2002:a2e:b0cd:0:b0:25a:a2eb:e5d0 with SMTP id g13-20020a2eb0cd000000b0025aa2ebe5d0mr18708178ljl.164.1656979606269;
        Mon, 04 Jul 2022 17:06:46 -0700 (PDT)
Received: from mail-lf1-f51.google.com (mail-lf1-f51.google.com. [209.85.167.51])
        by smtp.gmail.com with ESMTPSA id x2-20020a19f602000000b004834770e37csm122442lfe.73.2022.07.04.17.06.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 17:06:45 -0700 (PDT)
Received: by mail-lf1-f51.google.com with SMTP id z13so17872987lfj.13
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 17:06:44 -0700 (PDT)
X-Received: by 2002:a5d:64e7:0:b0:21b:ad72:5401 with SMTP id
 g7-20020a5d64e7000000b0021bad725401mr27990729wri.442.1656979593298; Mon, 04
 Jul 2022 17:06:33 -0700 (PDT)
MIME-Version: 1.0
References: <YsJWCREA5xMfmmqx@ZenIV> <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV> <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV> <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
 <YsNRsgOl04r/RCNe@ZenIV> <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
 <YsNVyLxrNRFpufn8@ZenIV> <YsN0GURKuaAqXB/e@ZenIV> <YsN1kfBsfMdH+eiU@ZenIV>
In-Reply-To: <YsN1kfBsfMdH+eiU@ZenIV>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 4 Jul 2022 17:06:17 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjmD7BgykuZYDOH-fmvfE3VMXm3qSoRjGShjKKdiiPDtA@mail.gmail.com>
Message-ID: <CAHk-=wjmD7BgykuZYDOH-fmvfE3VMXm3qSoRjGShjKKdiiPDtA@mail.gmail.com>
Subject: Re: [PATCH 1/7] __follow_mount_rcu(): verify that mount_lock remains unchanged
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
 header.i=@linux-foundation.org header.s=google header.b=DIX8InJ6;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Mon, Jul 4, 2022 at 4:19 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> -       unsigned        seq, m_seq, r_seq;
> +       unsigned        seq, next_seq, m_seq, r_seq;

So the main thing I react to here is how "next_seq" is in the "struct
nameidata", but then it always goes together with a "struct dentry"
that you end up having to pass separately (and that is *not* in that
"struct nameidata").

Now, saving the associated dentry (as "next_dentry") in the nd would
solve that, but ends up benign ugly since everything then wants to
look at the dentry anyway, so while it would solve the inconsistency,
it would be ugly.

I wonder if the solution might not be to create a new structure like

        struct rcu_dentry {
                struct dentry *dentry;
                unsigned seq;
        };

and in fact then we could make __d_lookup_rcu() return one of these
things (we already rely on that "returning a two-word structure is
efficient" elsewhere).

That would then make that "this dentry goes with this sequence number"
be a very clear thing, and I actually thjink that it would make
__d_lookup_rcu() have a cleaner calling convention too, ie we'd go
from

        dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);

rto

       dseq = __d_lookup_rcu(parent, &nd->last);

and it would even improve code generation because it now returns the
dentry and the sequence number in registers, instead of returning one
in a register and one in memory.

I did *not* look at how it would change some of the other places, but
I do like the notion of "keep the dentry and the sequence number that
goes with it together".

That "keep dentry as a local, keep the sequence number that goes with
it as a field in the 'nd'" really does seem an odd thing. So I'm
throwing the above out as a "maybe we could do this instead..".

Not a huge deal. That oddity or not, I think the patch series is an improvement.

I do have a minor gripe with this too:

> +       nd->seq = nd->next_seq = 0;

I'm not convinced "0" is a good value.

It's not supposed to match anything, but it *could* match a valid
sequence number. Wouldn't it be better to pick something that is
explicitly invalid and has the low bit set (ie 1 or -1).

We don't seem to have a SEQ_INVAL or anything like that, but it does
seem that if the intent is to make it clear it's not a real sequence
number any more at that point, then 0 isn't great.

But again, this is more of a stylistic detail thing than a real complaint.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjmD7BgykuZYDOH-fmvfE3VMXm3qSoRjGShjKKdiiPDtA%40mail.gmail.com.
