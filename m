Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBHEOZ62QMGQESS2EW6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE6194B054
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 21:12:29 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-5ba4f359c7csf132a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 12:12:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723057949; cv=pass;
        d=google.com; s=arc-20240605;
        b=QHjSjxT9wOXcFGKDDb42/6GdTNgu1M7Mt7FMo6cGIR1pJkA9UWBFozQdxM9wFVmHbj
         jt64RWe5pwWg+w23AaXF4brcTU/nh0O+khmfnkAaq8Jp5k8jCSU/FY9VrwwO92UnQVM0
         pEX9Tu3l7v/CPWkeOdCRnuKp7BGxzkFtcVasOQZFc/On/R2EWV0KEbMsaCo8a3OPXS+U
         a39IH0qWr48NIfMRevHO8cnMDlxoXe+l/pwnScK0512tpz4x3PloRHlSIUXARv8+ThHg
         W+kbEbrUMECN+R1tozf5xcwIxda8UCWRl7INmz8dTzkezSiLAqgnhC3XDXd9uMK5gASs
         //AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jhLjiTXCIrxKHqgi6smVhdtEj+Ybk4XbW7WT+5HtVVg=;
        fh=nzPxstP6mpBD45lZwfzn7xUmva6XWYkyCmevNbLrYog=;
        b=ijAYA4F4WlSYZtYSeRih7xExT89OOFPv5i1euBUblBLFXbtreLDDnVOnC/y07y8iHX
         36zvanDyesvr8v5aAgtT6i9zvmmy+6G3unNNKcqX44DcITP4Ip776o4T5sVVPprxCQVl
         Yp00XILHO+3paKJYzTrtiRF5MOJcO5Tu3RO7ru6fanpIBECl7l4+8Gr1SeNxND0Xc5X8
         WoWiSKZXlTAFKtFGoyKOv3q0sP+qgSm3xloNj0v2XMCfGsiPSn3tDXOSHVcTNcNqhJTe
         DXgvr7uJlHTtoFq0I5I2fPvcQyhdDuWCNZlBrC9PUjxkYrPsTpXcSC4XenZ6AOIEq60M
         1+5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MH2ORfPH;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723057949; x=1723662749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jhLjiTXCIrxKHqgi6smVhdtEj+Ybk4XbW7WT+5HtVVg=;
        b=FJntpq/dtij67dXP+qzvl3uhgwX6I2mIlNU2LfmKtcRQ2Vraw8jHnyrNzQ+13HdW7+
         JSTFkwahmQ1DAhsrKJRX/rc3MpbBtlWi6PCYd3m2YFq+LCsfGPo3BjHq5JKFeDdJV7Lr
         3zTX3nGnEq8vdUeMs+5j6ph9KSFK5YYz+cXf6STpjAaii/l9S8GaT9vCNygPCb9NUYa2
         WG18UVgd969C5Xem2m8BmmirvpG5eFGYfsqowSRea1KoTdGN51MAJ2LMnd9h5hJ2h++5
         kDYBXt6M39NUv1af+MaPfh8e6nlTpvxEcNvKDR3kOpD+tYV9yFMjb/wxSPxuJlIiLii2
         RRBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723057949; x=1723662749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jhLjiTXCIrxKHqgi6smVhdtEj+Ybk4XbW7WT+5HtVVg=;
        b=nJe4fdrKv5uhgLA5QbLXLArXQ3rYZQhBqrVPL+1DEhf9dmb8dQ/W3m/quHnEVRAO5k
         xHwK2B3cDQ4Xtx7pxqVJIhsWlwTxSggMIRkQkeP9z8bg0cYWxTQh4VmxVhGHApQI1FxC
         UTxN81qJWesAWbYcOycDSfk1SUr3Wk7PtjCDkki5KJ0CU3HwQP5QP6M/k97KJg+zSQq+
         4t2pqeaMG2SqPsXbizNqdG/Gx6wdi/QejcbmptF/XUyUaITGZi1GUx0PiQ/ZeJU3JlOj
         2KYQ53Dajj1uvrRgueNBMvJHePZ3TXQCAZr1LWBAtFAiUl6jGiekitItRjCD2EF5z7sk
         HYWw==
X-Forwarded-Encrypted: i=2; AJvYcCVMEye+o3Mt+YVDnSbYetKhrcIkmXYgs85g6MGKQhC12SFtX95fOJ3j45MVF2jVlgRaoDxTNhf7Y3ZXYRdHu9rPcVY/hSEqwQ==
X-Gm-Message-State: AOJu0YzqTC15Q96AvKjQZmXk556Nn5NwN9+K37TWlpnKVhNdYboZigaB
	dyUedIufcxJsGruipiCdAoXNk7kABZpjnEQg9UTl/4FdOcz/ebps
X-Google-Smtp-Source: AGHT+IEcaxz9mAIr6eKJ3VPXKkVZpGGKpH7OgLXH2mx/sCV54gBqlEcrJlS2tlJPyNhCl8Ca40ffvw==
X-Received: by 2002:a05:6402:27c7:b0:5a0:d4ce:59a6 with SMTP id 4fb4d7f45d1cf-5bbaff307d6mr42166a12.2.1723057948850;
        Wed, 07 Aug 2024 12:12:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c6:b0:595:7fb0:945a with SMTP id
 4fb4d7f45d1cf-5bbaf049413ls87758a12.1.-pod-prod-02-eu; Wed, 07 Aug 2024
 12:12:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+2B2oCn0kYw/ixwZ8RIrOfQCxnHVMqvLoZJ8QUSOgCZnIu68gKuwR/c8DJ2xvE4iY3NFgSZ2QCUb2ii1DFOhSX1iNJOXGaSL1/w==
X-Received: by 2002:a05:6402:7d2:b0:5a3:3553:9aaf with SMTP id 4fb4d7f45d1cf-5b7f350204dmr12232773a12.2.1723057946919;
        Wed, 07 Aug 2024 12:12:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723057946; cv=none;
        d=google.com; s=arc-20160816;
        b=YY2/O6nRQpj2dYz2MG1zTKaHVm20ZBy4PgucO3K/KwASh1zp1y/AKC5G66YMyh9cj8
         f1i94zt/dScMhfn3Ney1U1nvcU/EOmNZ0/OjTrGLBUZEve+arTvL4yPP8OUVnZZ3SJsI
         9+qg6TvhYfYKF2kCNRLotTr+HurQzE8gbfjVgYYT6EN0psLVAQuk7AvpUa2G1BIwOB5L
         WN2ZxZLUieFdaluGpIXp10vNuYX2o344qQVddMdezLpLJ4mZ5vWCb2L5eC4QpcDqhzfh
         R66b77QRtwHWuA791AQ1qpM2R/2xVIGwWVtUMv8Gwugj+4IjXTNzz/GW/9xxTBP0q66U
         kNgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1WLs4U4pJAgrGVVsxUErTGOk4QX7JD1FuPYUe1vFarI=;
        fh=8gRC+GfwTeI1+dc0EnIISZRJ5RpxTHpvQn5TBVbEFm0=;
        b=FzEMnlp+Jwvl5qsRBYrAmcltQCgkl4m9N6Wxe9WowYaw1batq4AV1hHoiTNWa1JGhY
         rNIqnFvTMTBbnWNGxq6nsL7aaoGrWqreNUUmhFVm1Qu9a5D4tMHwNwgY1aMxmtoOXasH
         /wRU2fEUU6HvkZhWW/FXx9pG3PFvKSiIgpmO3CRyHiviHr43nAAavJsqSh8I5nssHrCr
         83iQbNgHi0pahAHN1qMq2XkivvZ+/gbW9ISUxvQHuOdvRkDgp4sQl5PMl3Z9wjwu33BX
         sMkQJFYQwZWJaG0PgD7351Z+Ooc+UXIHE5Z+JxpIlrYX6xnu8Nq3TE2zCSRGK6zUjO4b
         mk8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MH2ORfPH;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5b83972193dsi281186a12.1.2024.08.07.12.12.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 12:12:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso4023a12.0
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 12:12:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVqPraxbA8PV12C319WlHtLR/5rlQAVGf9Ra0Mpz9eyr9SpKhFVg9MV97f1U0VBxMoqTGWeYV9RP/x63qXeZ24tuR91He/Ckvw+rQ==
X-Received: by 2002:a05:6402:40d2:b0:57d:436b:68d6 with SMTP id
 4fb4d7f45d1cf-5bbb004ab49mr17751a12.7.1723057945956; Wed, 07 Aug 2024
 12:12:25 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz> <20240807-b4-slab-kfree_rcu-destroy-v2-3-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-3-ea79102f428c@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 21:11:50 +0200
Message-ID: <CAG48ez0j7qx3mCtQwq-KfkG+nj_k7w9mmwL=FDx_sMSVphhncg@mail.gmail.com>
Subject: Re: [PATCH v2 3/7] mm, slab: move kfence_shutdown_cache() outside slab_mutex
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MH2ORfPH;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Aug 7, 2024 at 12:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> kfence_shutdown_cache() is called under slab_mutex when the cache is
> destroyed synchronously, and outside slab_mutex during the delayed
> destruction of SLAB_TYPESAFE_BY_RCU caches.
>
> It seems it should always be safe to call it outside of slab_mutex so we
> can just move the call to kmem_cache_release(), which is called outside.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Jann Horn <jannh@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0j7qx3mCtQwq-KfkG%2Bnj_k7w9mmwL%3DFDx_sMSVphhncg%40mail.gm=
ail.com.
