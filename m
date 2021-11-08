Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJFNUSGAMGQEXCS4ENY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AE85447F75
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Nov 2021 13:23:01 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id g25-20020a25b119000000b005c5e52a0574sf1133598ybj.5
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Nov 2021 04:23:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636374180; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z8LO2frkfrjGyWfNvifDAVMsHIaXZ8uTQnCz6n5UVzK40vj5Y0Fkf0NFGHVEnvXsQG
         yQ2r3p1qJ7l+Y2RRUq6Pb4XGBV9ckCq3vgzIfbmQkPBhMjqPWKGQI/Cp/EQtRnb8RSIV
         RvSABj+sZFognkpKn7pVqrN22LO1hy98HBotGIyvaroJ5reMGUH5GTyCAUaJgiMRo0ny
         CdmH/TCyp9JZMAmakIamHzmVRq6bKmMjby+9VX0jUk1feqyXKLdEC9OXbP7k4iK5CKO0
         Gp3ZGpeG+9SlY3EmgMx+Ev3YtXPWVCzU2Cj2hJofXg+Z1J9s/9tRdnxnUjDGjIm/o+0F
         PeNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aYlpHWFlDtVwgA+IqYb675OaH1c7MzKz+lNz5ot5WtA=;
        b=NFMy4kID9RDX3ZWg3RugJ0UctUlB3R6jjN84guasvdp3GcJnKRP8Qv3+JLGohUrlEZ
         M66Iy2twMQ1vQTrw5HJ5EtCM9IawniFLXun2LeRSDpjb1HJ455d++rkF9Hka1HFZFmot
         3vJBxEbZf3Nmu5JeOcTqSQGS4QnJrRZLm6qUZ2rdwPCxY+KsyZi8SE6x7VvTmNZ7/OGV
         lmYZj0vEtFtE96HReCPQNiNWbwbktCInzaxjZkiTkc2twWZQCTUeqUCHx+Zv4u6ijtZV
         j+2/yow4dZVbJ6tu4FvjHRGoaxQwYCrx6uj0k1l5O7RUdWRxkMIiN90L+FbVeuqk/1z3
         zHCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TMWKPx9M;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aYlpHWFlDtVwgA+IqYb675OaH1c7MzKz+lNz5ot5WtA=;
        b=opWJwG4Dk2Ng9p7f1tonuoe8QUKN3MogpXFUZFZCIWUkMRRm2zvmfQEtcW3jg30DI4
         Gbsf2jxTvDQEEDlKb2wglYPL2UXY8K+XKByDcmdNR1CYXuB/eAdKqrlYWw5OvfBkd6aK
         pWdqF1yvijul5gIQnsWDgouQgr2jwP6sXI4V31n8bIwSxgZdPcLDNuvMt8BClq4G00fH
         RgzR3ydWjYjSrgQc8EU+g4X5EnhA+HNq7/+iBYDjjqjpsDbezCt4G7U89SF5VXhps5o4
         SK917tZGzoE2QLiKtVNCtu+ZcN457ZlZpdzoXaqKwf3hFEkHg7BN9yW33oB900Vt3m7e
         3iEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aYlpHWFlDtVwgA+IqYb675OaH1c7MzKz+lNz5ot5WtA=;
        b=0BkHdtF9klbaTN9EunmaBZ0N0Fio5pBHrjKqh4oFY5IxGLPlEeMGcgIDKPrhHDP7hH
         k5bdXvbMjBATAJ63HWoLgjtvMN42cULc3X9/vKSnHHK5P7h5RQqZPxEyHBBm6uhSkCEH
         1f/gHXXR5jGfXXjkopxB4EMWHHajbGO1z1BHq9zarK4ofsiMibNfk9BZw7KxTdrFAKxk
         tMvwihJ6vWp8L0peQ2rAvshhjpM6NV6GfDmAxW+VOX3KLKC5mQeCMnIhAuJ2sDlghWfU
         kR1LZwDSNRnRcp64YhNVuBntNkKG2sPM31kIh/CCDX56x1zqA4fX4OzKrDk/PfjI+N9q
         uolQ==
X-Gm-Message-State: AOAM532WyMQh2dVkftlNGNqHTTCfPBokDSwqrNDXVvgvnJuEYerAhijh
	oO9EWhJeyBTc8WYoyxQtxck=
X-Google-Smtp-Source: ABdhPJwkZJKDA/x6awqeifHS3tz/h8XzcCIcyDaBWuLlYBoUGKY/2O96Fi63doEZug2r/RwHglBHZw==
X-Received: by 2002:a25:238a:: with SMTP id j132mr74770942ybj.530.1636374180442;
        Mon, 08 Nov 2021 04:23:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bb8f:: with SMTP id y15ls348655ybg.1.gmail; Mon, 08 Nov
 2021 04:22:59 -0800 (PST)
X-Received: by 2002:a25:db0f:: with SMTP id g15mr76975322ybf.414.1636374179923;
        Mon, 08 Nov 2021 04:22:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636374179; cv=none;
        d=google.com; s=arc-20160816;
        b=AU8RzVzuOb9oYK68XhfRBHrpfb/dRoP6b4OFRNidVyflpVzvFssh6nUTscjC3m15mg
         xEQ0PSVwjTmBJOAi52SDUNKDAA6RiOyyzYjYhIQ1QMCTmRSxSSCvlYUSpOpjogNOhL6P
         sUCc9u2a8I0n0TXIxIRMawHDkvTDAFRerJNKkhyM12qNOUaM29XQU+kty0ZpmrrJbStW
         PC4RSV80arpkwZEfnV/LeVbLH2KYN7vdQw3Bimow8voDwWe96PsAkzxwN8uEYyaAkgeU
         ikimWhDZBet6VI9seOvQqMQVEhPqjBfXkX9MdGVkPy1ciVha4fEWo7DRzxxdY42/rB+3
         UzEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oWxAh99exjntWaHx951+lk35+JEy7HDXRjBJyaOouWU=;
        b=Ltng/4Rk3Xx6qnxWtORaZVf42QchLeXcQA48I7ioEmWCCrXLjmRiu+EniwohJQDN1D
         9VCJHNBXN1HLWcCqa/ucW/QCSrZasWJE0O2mwt9zcuJ2tEygFHwgr4kCOUiNN+VP+seV
         kFzFOJjjrNGP7StCJ0Ihxtt5Y01QdjVDep00vQUNFF69RVl4/O0xYuMr5QvjxUeoJGyy
         37DIXsMQhXp/hdEmX0HaPCz3biqd7tpxcBoEunLgVXVpWp7WqXGAvF0TlHfkoTrYNvoY
         cZ6WcHmuVI5xP2Yf85zTA0yyumvIpENQjXAGfnUaVGgo6m3NKS7CQH7xWO3rW8C/a6pv
         YrXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TMWKPx9M;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id k1si1884433ybp.1.2021.11.08.04.22.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Nov 2021 04:22:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id h12-20020a056830034c00b0055c8458126fso6247577ote.0
        for <kasan-dev@googlegroups.com>; Mon, 08 Nov 2021 04:22:59 -0800 (PST)
X-Received: by 2002:a9d:2ac2:: with SMTP id e60mr60084401otb.92.1636374179281;
 Mon, 08 Nov 2021 04:22:59 -0800 (PST)
MIME-Version: 1.0
References: <20211101103158.3725704-1-jun.miao@windriver.com>
 <96f9d669-b9da-f387-199e-e6bf36081fbd@windriver.com> <CA+KHdyU98uHkf1VKbvFs0wcXz7SaizENRXn4BEpKJhe+KmXZuw@mail.gmail.com>
 <baa768a3-aacf-ba3a-8d20-0abc78eca2f7@windriver.com> <CA+KHdyUEtBQjh61Xx+4a-AS0+z18CW1W5GzaRVsihuy=PUpUxA@mail.gmail.com>
 <20211103181315.GT880162@paulmck-ThinkPad-P17-Gen-1> <20211103212117.GA631708@paulmck-ThinkPad-P17-Gen-1>
 <309b8284-1c31-7cc4-eb40-ba6d8d136c09@windriver.com> <20211104012843.GD641268@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+bih9gX2+XvRh3q7XYe8rbgCDF5=5eMV8cxBimvPLQtug@mail.gmail.com>
In-Reply-To: <CACT4Y+bih9gX2+XvRh3q7XYe8rbgCDF5=5eMV8cxBimvPLQtug@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Nov 2021 13:22:47 +0100
Message-ID: <CANpmjNOHvG-9tWK-1Kk4o+L=XXd09xBac_KpCr9PR5us2m-vTA@mail.gmail.com>
Subject: Re: [PATCH] rcu: avoid alloc_pages() when recording stack
To: Dmitry Vyukov <dvyukov@google.com>
Cc: paulmck@kernel.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Jun Miao <jun.miao@windriver.com>, Uladzislau Rezki <urezki@gmail.com>, 
	Josh Triplett <josh@joshtriplett.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, qiang.zhang1211@gmail.com, 
	RCU <rcu@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, miaojun0823@163.com, 
	ryabinin.a.a@gmail.com, Alexander Potapenko <glider@google.com>, jianwei.hu@windriver.com, 
	melver@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TMWKPx9M;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Mon, 8 Nov 2021 at 12:42, 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
[...]
> > > > > > Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> > > > > I have queued it for review and testing, thank you both!  I do ha=
ve
> > > > > some remaining concerns about this code being starved for memory.=
  I am
> > > > > wondering if the code needs to check the interrupt state.  And pe=
rhaps
> > > > > also whether locks are held.  I of course will refrain from sendi=
ng
> > > > > this to mainline until these concerns are resolved.
> > > > >
> > > > > Marco, Dmitry, thoughts?

It's a general limitation of kasan_record_aux_stack_noalloc(), and if
stackdepot's pool is exhausted, we just don't record the stacktrace.
But given we just can't allocate any memory at all, I think it's the
best we can do.

However, given there are enough normal (with allocation allowed) uses
of stackdepot with KASAN enabled, the chances of stackdepot having
exhausted its pool when calling this are small. The condition when
recording the stack with the _noalloc() variant would fail is:
stackdepot runs out of space AND the same stack trace has not been
recorded before. And the only time we'd notice this is if we actually
hit a kernel bug that KASAN wants to report. The aggregate probability
of all this happening is very very low.

The original series has some more explanation:
https://lkml.kernel.org/r/20210913112609.2651084-1-elver@google.com

> > > > Well, the compiler does have an opinion:
> > > >
> > > > kernel/rcu/tree.c: In function =E2=80=98__call_rcu=E2=80=99:
> > > > kernel/rcu/tree.c:3029:2: error: implicit declaration of function =
=E2=80=98kasan_record_aux_stack_noalloc=E2=80=99; did you mean =E2=80=98kas=
an_record_aux_stack=E2=80=99? [-Werror=3Dimplicit-function-declaration]
> > > >   3029 |  kasan_record_aux_stack_noalloc(head);
> > > >        |  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >        |  kasan_record_aux_stack
> > > >
> > > > I get the same message after merging in current mainline.
> > > >
> > > > I have therefore dropped this patch for the time being.
> > > >
> > > >                                                          Thanx, Pau=
l
> > > Hi Paul E,
> > > The kasan_record_aux_stack_noalloc() is just introduce to linux-next =
now,
> > > and marking "Notice: this object is not reachable from any branch." i=
n
> > > commit.
> > > https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/c=
ommit/include/linux/kasan.h?h=3Dnext-20211029&id=3D2f64acf6b653d01fbdc92a69=
3f12bbf71a205926

"Notice: this object is not reachable from any branch." because it
kept changing the hash since it's in the -mm tree.

> > That would explain it!  Feel free to resend once the functionality is
> > more generally available.
>
> +kasan-dev@googlegroups.com mailing list
>
> I found the full commit with kasan_record_aux_stack_noalloc() implementat=
ion:
> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commi=
t/?h=3Dnext-20211029&id=3D2f64acf6b653d01fbdc92a693f12bbf71a205926
>
> but it calls kasan_save_stack() with second bool argument, and
> kasan_save_stack() accepts only 1 argument:
> https://elixir.bootlin.com/linux/latest/source/mm/kasan/common.c#L33
> so I am lost and can't comment on any of the Paul's questions re
> interrupts/spinlocks.

None of the kasan_record_aux_stack_noalloc() code and its dependencies
were in mainline yet. I think it landed a few days ago, but too late
for the patches here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOHvG-9tWK-1Kk4o%2BL%3DXXd09xBac_KpCr9PR5us2m-vTA%40mail.gm=
ail.com.
