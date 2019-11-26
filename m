Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGNB6TXAKGQESCF5ONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D295109D36
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 12:46:35 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id x22sf10586944pgh.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 03:46:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574768793; cv=pass;
        d=google.com; s=arc-20160816;
        b=kG63V/Y+IksVnbsqxQTMqk/lNddJWSGHz8w0cLfyruyUniVZK9jjcCQxgs6QUjLxpR
         3Rsv1gvdiOKaX+X8yq+so6M+zcRSi5YfO/Ids5p/NrA/v+T/2roHvtJka81YeRrulegI
         7DbPwuQVcjjMtiWZSeMlj2HWRZxuo41REPQTSLXNrIDV6fsw0mUCMcG90kX/pMCuhQsI
         /8uXLg8iWb3IsCuWkNLBhGfjOfyID0NxZrzs1rtNUKNaSd84BlHQXjDbMACGosmb8GCW
         UbD0FG/S3ER+GV0KeYmGoQtCU+OTxwd5ITyxyvkSb0X/1FKiuOoHm9yuCKQXe95zYIJa
         5sPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1sMj8CKaNG6pywfhHon0J9e49p0tgQyAtDs5n8Y80gg=;
        b=jI4Nc4Xld4pf+OOUw30YhuaUdCdHrSrQNkVE/hSIqjBp86iq+Hpnet0uMAiyaZoMn3
         S00we3bcL87Fb25bPHH6SVQzbaio5fGB0mhWmE6vx9CnpO2E/031GZ542Pg9hk2NlGgO
         eo11vd4kLPMtAv6KUsv9HHPKhrm7NlKgfCRLoN+cfLb9iYVW19auyhqLWKphIJ8POo7u
         4oediadWrhVEF60Zvdt3j6v6aT5hyXnBDzouz9JnX48wcLVKzN8LSdDc1871p38WQKa6
         ICgSM4EXmM7XeDCSjq6xBEZOeGWoc9bfznJCZ9R6GNMT0JF5Z3QGDQKojcdWWFNCrVCP
         G2kQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c5Pahk6W;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1sMj8CKaNG6pywfhHon0J9e49p0tgQyAtDs5n8Y80gg=;
        b=eHapPPtqIco2vwNmU9cdyBusKkBxHNZGvYb+qYmKOnXKSvDeMXiwQpTh6WAk/AZH31
         UJnTNEA5uPI249LGoVy9W572XTUQhfPY3dSLbcR9y+ELVKUmuvJ9wdnA2ZHqqoAArBnQ
         UfKYRX1TzyWQNSpsbDgzjl+rS9APItsnSuXwrdd09W3YWd4GHjon/vMQe+jYUBxFymN9
         r/Syislc3ZNKhr2O5wYTBMA2Brl+a3zQ70fxATLpust6JCiYi7t7mWO9Z8s8bPZlnGdZ
         fM3RymhpSM5tKaa3n98tIterb+1T5R3d/qVBx6tjkYoCFF/ubCAO6qf1QDtKGc2K4KVF
         TsGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1sMj8CKaNG6pywfhHon0J9e49p0tgQyAtDs5n8Y80gg=;
        b=Z4J4vzwWWFQktfeix2wL1xziAQQkPbJ7MPrhGJHmcFYVrfyJoa0S9hmula992kmOVi
         u4SWEwtpil3XVdOyqv3u2yFf5/C8VP2mYch0eZLb0bM2NglTmW+56of2SeiXP0oFmy7Y
         8Wf4l63/Y6TrQZvSe5bT8cfBOUTxMR/IBraytk0VfPrmjwstsVF95CS8iDudI/oSxmU4
         3s4TT5VrvrJK9AKdHzApvSU8REqbNuuQz9cOoa+gvwRPae0vlnyvZQsjDjNLN+NceOSZ
         Ypr9PVzz0XWsW8tWM+rOYtdXL/BFTvJed4CrKz4wJOgGUO8YA2Qyll7EIx2LgD2Yv3Im
         PaFQ==
X-Gm-Message-State: APjAAAXIBfExfzLepe4JvQbD0oB/PCfPrvsoK1dHDTB2qWJGn+lDdmt7
	0bp9KaXTxWnlOIj7q9NlqmA=
X-Google-Smtp-Source: APXvYqwBUb4yJyyhZwgj+HqRTNODSZeZzWjzhd5y0OyjOFEHjkwCcLi8E9vxBi6U3UAt/evjadKrcg==
X-Received: by 2002:a62:e105:: with SMTP id q5mr41178440pfh.105.1574768793446;
        Tue, 26 Nov 2019 03:46:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2ec5:: with SMTP id u188ls4966776pfu.0.gmail; Tue, 26
 Nov 2019 03:46:32 -0800 (PST)
X-Received: by 2002:a62:1b4a:: with SMTP id b71mr40906029pfb.167.1574768792933;
        Tue, 26 Nov 2019 03:46:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574768792; cv=none;
        d=google.com; s=arc-20160816;
        b=twfEVBAzMiMh9T29QWRbpZbHDOWn/hJg+RoQcI53XFxlu2QbgBcP4w6D4fY+lz2IeT
         4qcBXKmGh2FFdYpsqQhn3dbnxNcr7AfWYm5ZhWbOWKVjjDa7Ka2ON+f1M1KUYwnFEqnu
         c83GGtPC51oMMFpY6t1wt4BW7uRSLY0KDKaJR93vrZDFY2u1HXuQZqyS2syrCSNcNe8W
         HXYKC71le9bpPwrqVqmVjNhWcyqdPH2JB88yerd4hMiq9WXIISQVZXVzDkMBlvyJu5xa
         SKecSTJo05GjYe2pswu1nrU4FSViBqvjI9KUv07Fcsn3epBeG2sIlRenH1trBqtPmiz1
         VJlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tjdzshLYgCCgwbhmOuSJ84yu2IodR1Sq0mvSDQia2nY=;
        b=MzYHRQRmhFszwV1dRHVbwn7AWYh95b5EzNpE0RZOFpIFi5TGzPtp/1GmyAn03ork67
         ZSzm2pIpiJCIuJl8F3ab6baVE7DtSYT6iX8bxAqF3BMz9ZsW3Uv1rEkLAz+EjIqTY58N
         kZO7OIMiD89q0nObQy+qXMZcmlRYF+wD0VIS4/KqwLHLtFQrGMNoRat6l8LiZaujNWmX
         pnf7IO78dcRDiUGCQRwaPOa/7RuQe0TQidj4nIDA2UDN7zhLr5jA9kF4LBMids5qANn4
         WWsrb45fbqNALrrwLFOD7Orv0MxFQl98kOb18kvQG3NsSTC7Gv0UrFDa4vgrk+V3TMjJ
         0Nyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c5Pahk6W;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id h18si75411pju.1.2019.11.26.03.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 03:46:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id n23so15568068otr.13
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 03:46:32 -0800 (PST)
X-Received: by 2002:a05:6830:2308:: with SMTP id u8mr23115197ote.2.1574768791781;
 Tue, 26 Nov 2019 03:46:31 -0800 (PST)
MIME-Version: 1.0
References: <20191122154221.247680-1-elver@google.com> <20191125173756.GF32635@lakrids.cambridge.arm.com>
 <CANpmjNMLEYdW0kaLAiO9fQN1uC7bW6K08zZRG=GG7vq4fBn+WA@mail.gmail.com> <20191125183936.GG32635@lakrids.cambridge.arm.com>
In-Reply-To: <20191125183936.GG32635@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Nov 2019 12:46:19 +0100
Message-ID: <CANpmjNM5tgiyFOt4jW97Dg1ot1LmJC1rcrQX+Q74B28c=t7Kzw@mail.gmail.com>
Subject: Re: [PATCH 1/2] asm-generic/atomic: Prefer __always_inline for wrappers
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c5Pahk6W;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 25 Nov 2019 at 19:39, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Mon, Nov 25, 2019 at 07:22:33PM +0100, Marco Elver wrote:
> > On Mon, 25 Nov 2019 at 18:38, Mark Rutland <mark.rutland@arm.com> wrote:
> > >
> > > On Fri, Nov 22, 2019 at 04:42:20PM +0100, Marco Elver wrote:
> > > > Prefer __always_inline for atomic wrappers. When building for size
> > > > (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> > > > inline even relatively small static inline functions that are assumed to
> > > > be inlinable such as atomic ops. This can cause problems, for example in
> > > > UACCESS regions.
> > >
> > > From looking at the link below, the problem is tat objtool isn't happy
> > > about non-whiteliested calls within UACCESS regions.
> > >
> > > Is that a problem here? are the kasan/kcsan calls whitelisted?
> >
> > We whitelisted all the relevant functions.
> >
> > The problem it that small static inline functions private to the
> > compilation unit do not get inlined when CC_OPTIMIZE_FOR_SIZE=y (they
> > do get inlined when CC_OPTIMIZE_FOR_PERFORMANCE=y).
> >
> > For the runtime this is easy to fix, by just making these small
> > functions __always_inline (also avoiding these function call overheads
> > in the runtime when CC_OPTIMIZE_FOR_SIZE).
> >
> > I stumbled upon the issue for the atomic ops, because the runtime uses
> > atomic_long_try_cmpxchg outside a user_access_save() region (and it
> > should not be moved inside). Essentially I fixed up the runtime, but
> > then objtool still complained about the access to
> > atomic64_try_cmpxchg. Hence this patch.
> >
> > I believe it is the right thing to do, because the final inlining
> > decision should *not* be made by wrappers. I would think this patch is
> > the right thing to do irrespective of KCSAN or not.
>
> Given the wrappers are trivial, and for !KASAN && !KCSAN, this would
> make them equivalent to the things they wrap, that sounds fine to me.
>
> > > > By using __always_inline, we let the real implementation and not the
> > > > wrapper determine the final inlining preference.
> > >
> > > That sounds reasonable to me, assuming that doesn't end up significantly
> > > bloating the kernel text. What impact does this have on code size?
> >
> > It actually seems to make it smaller.
> >
> > x86 tinyconfig:
> > - vmlinux baseline: 1316204
> > - vmlinux with patches: 1315988 (-216 bytes)
>
> Great! Fancy putting that in the commit message?

Done.

> > > > This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
> > > > in the KCSAN runtime:
> > > > http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> > > >
> > > > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > >  include/asm-generic/atomic-instrumented.h | 334 +++++++++++-----------
> > > >  include/asm-generic/atomic-long.h         | 330 ++++++++++-----------
> > > >  scripts/atomic/gen-atomic-instrumented.sh |   6 +-
> > > >  scripts/atomic/gen-atomic-long.sh         |   2 +-
> > > >  4 files changed, 336 insertions(+), 336 deletions(-)
> > >
> > > Do we need to do similar for gen-atomic-fallback.sh and the fallbacks
> > > defined in scripts/atomic/fallbacks/ ?
> >
> > I think they should be, but I think that's debatable. Some of them do
> > a little more than just wrap things. If we want to make this
> > __always_inline, I would do it in a separate patch independent from
> > this series to not stall the fixes here.
>
> I would expect that they would suffer the same problem if used in a
> UACCESS region, so if that's what we're trying to fix here, I think that
> we need to do likewise there.
>
> The majority are trivial wrappers (shuffling arguments or adding trivial
> barriers), so those seem fine. The rest call things that we're inlining
> here.
>
> Would you be able to give that a go?

Done in v2.

> > > > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > > > index 8b8b2a6f8d68..68532d4f36ca 100755
> > > > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > > > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > > > @@ -84,7 +84,7 @@ gen_proto_order_variant()
> > > >       [ ! -z "${guard}" ] && printf "#if ${guard}\n"
> > > >
> > > >  cat <<EOF
> > > > -static inline ${ret}
> > > > +static __always_inline ${ret}
> > >
> > > We should add an include of <linux/compiler.h> to the preamble if we're
> > > explicitly using __always_inline.
> >
> > Will add in v2.
> >
> > > > diff --git a/scripts/atomic/gen-atomic-long.sh b/scripts/atomic/gen-atomic-long.sh
> > > > index c240a7231b2e..4036d2dd22e9 100755
> > > > --- a/scripts/atomic/gen-atomic-long.sh
> > > > +++ b/scripts/atomic/gen-atomic-long.sh
> > > > @@ -46,7 +46,7 @@ gen_proto_order_variant()
> > > >       local retstmt="$(gen_ret_stmt "${meta}")"
> > > >
> > > >  cat <<EOF
> > > > -static inline ${ret}
> > > > +static __always_inline ${ret}
> > >
> > > Likewise here
> >
> > Will add in v2.
>
> Great; thanks!

Sent v2: http://lkml.kernel.org/r/20191126114121.85552-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM5tgiyFOt4jW97Dg1ot1LmJC1rcrQX%2BQ74B28c%3Dt7Kzw%40mail.gmail.com.
