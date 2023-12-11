Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7VX3OVQMGQEANYBKSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id CA34980C544
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 10:53:04 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-6d0908565f8sf880919b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 01:53:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702288383; cv=pass;
        d=google.com; s=arc-20160816;
        b=bojZ8CT0u2lSto9VTYifmjy6hONlfOMQaTEul3RN1B4f3pQygQf12b2LnCGh3MrnJP
         bE9qLjSgBUVhX6NzSVDE2COyq8aV9eJ3S6qJ9vUg2yUrq1WzfvbkkUC2XJVbwaaFBl92
         b2fnTuyTfkWrLRbSD7uF2lKnwYX1BXwqz+4BJFPj0+GzsYyiEgc2AlgxySaKyWXRLq/H
         dnjiCnOAr7uDmG7Am2Z7kDZQ7oLaJlB30LxA25tSa77YDz/8nngf2hKR1CrN+VF+zeg9
         lpeHz/XKWbvJUBoLz9wQ0P3uWDxgdUfQFaDWoNJyodFzeJ2hDQuvNVLgDZBBVtTeBBzO
         Nfmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fANLcLsz9S7fXglzl9dTGTMiKtFtGlbSjN7iJJL8Tfc=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=iwfTcAC032fUsc87J1xus+bgoK62ikxCs8IKOOc23zJHDChw7ZVsoBH055r3rTwvUD
         /mf6zy+EBFDnGA1C3kHeTpHcsiREWbJT6G1vBBo5vhESklh5kSFmNfk+YPpyBe1ahKHb
         8Kqjz+HxML+gv8Pqx64BJz16E83ZQ7F0a9UJmmACPu1n1sFVErcWpt/6RnY/ul7CF60T
         zDhWy7mec5iGkt+/5H/AOA0CeG8wl8TyShUaxO4xI7ENUWniIAcsp5ND9C4rRuEPJHoc
         mTNpNEYxAi3grcSnLDACPLHnpk2iQszc1ChWqNZ4LphUAF9UDKy1d4z6LJOQpZUN4CAg
         E0HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SSfRZPxJ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702288383; x=1702893183; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fANLcLsz9S7fXglzl9dTGTMiKtFtGlbSjN7iJJL8Tfc=;
        b=hI/KKqnPIn77Ake69apz+9zjK3P55G4n2eWlx/2TD+EGzhHf0CRrrBKkb1RD5WOZgn
         MNzGx81m10CZ96clrBf52DNSRdjBMY7asIzjc3Ruanar5sCuD3c2rcmmsPDmbwDA+xfd
         iC3EZF+iItnuJABRVs3OT4wO+5mueR3KoJD+UFYlzQhmvONn58QQkgdOQ97Z+XyJLTho
         d4bXpemwGVcDi+4po47fufOSKNOCCYn0l74WUeOZGILF92WiP2M+jdA9dTd9TjSbmhap
         tgsvdt1+B1pChdjdOTkYf5bnriArVp0RNweNub2TTf126eYvNSz7yh4E3ZwIi6KMXmut
         2fdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702288383; x=1702893183;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fANLcLsz9S7fXglzl9dTGTMiKtFtGlbSjN7iJJL8Tfc=;
        b=ECvPOxcDpDQT9xNrTVI9pGBcRaeV5HufUgM9/+WKtEymGEcq9SXcjVPQC+7hmF28wC
         JlAQkjhoGm5fKrYUipisnzA1m37Pe4/03J7TmTdjZ8kVSMVIHvbWgsAp/9iWph5umHx6
         2sGizbZRCLJAs4/u5Wv7CZKhwJCUtJIwYW2wtQKDzEWuxyLURS7GnZuHeS29zr0t4+dW
         9/uHXEq+FlbwD7hM8oX1iicvam51CJxw/yAHYLiDAszQHuMtnC2hcLXKGDPd1PtlpvD7
         Dd5N+GYI+/AdU75FMPa0/CAblUO04TxDX92F9SLbKzsLGCgoqMhYbAEPSsXRe4cbsZfA
         6dDQ==
X-Gm-Message-State: AOJu0YxVgAPBpI1/CMw9kO2CbRwVcco874UW0aLVBWWPa/kPIiUaaELa
	46r4FJKkY+Hia4Yob6m9mJE=
X-Google-Smtp-Source: AGHT+IFuMD3GZe2PQ7Cy5dPpN+ymOFaX8uwjJzn7RT/PFsdtSg4ph3R90kVgHKksWXHENt/qkF5fUg==
X-Received: by 2002:a05:6a20:7486:b0:190:d60b:e27d with SMTP id p6-20020a056a20748600b00190d60be27dmr3015878pzd.90.1702288382769;
        Mon, 11 Dec 2023 01:53:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f0c2:b0:286:4c11:14bb with SMTP id
 fa2-20020a17090af0c200b002864c1114bbls1004072pjb.2.-pod-prod-03-us; Mon, 11
 Dec 2023 01:53:02 -0800 (PST)
X-Received: by 2002:a17:90b:11c8:b0:286:6cc0:cabb with SMTP id gv8-20020a17090b11c800b002866cc0cabbmr3104029pjb.50.1702288381779;
        Mon, 11 Dec 2023 01:53:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702288381; cv=none;
        d=google.com; s=arc-20160816;
        b=VimcW9bZcrtBG/d7dNglvjJfdsTz5fDzElrychqa4iTJCs+w9SLtbT4egW4DTJQPmY
         9qHpjYtz+cacTXZQyT0OQs7EB/NTpCD77uaA+qDJ3cLYVhnIaK7cRW6jZKRzGP7mklEz
         a8l+UI8rj+M15nGiPxcTvN2R2sOA8lOVqjIpsSJ+8Ikx4a535r8s8TPyfa7UaJHNNxho
         /L5ja8+UJaTry0cyPZsMK+3aNpNBbxWFJ0sP2BjDQuKtEWEjA2G87kUoH5ZfxabgHldG
         mx9cf0rTD/ePwF2NoY6SQ5NLQ6FS3WG6obyL0emGYke1bV7dOyGs6WYBHHim5ThkIVTZ
         AW4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RkurISIjMkn+2I3PnXKwVyMchslMNcfqaTJxR0Aia2Q=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=bTITu378wjNqoknzgD5tVPH2KPizGPZB2RcC2HZMjOZ7ibvUD2f3mMnIEQeK0c6VSl
         y17Imhn0NiFhWnfBGGNPvN6obVIAcudMTSomq5EYNQrWDIw+pAqpGC634pcNJglLRlst
         sHJij7Un+k4bgzn1uJHbnUKdMtOLc7Jj9wA7g2Ym6rX0RAlyBU9gOfjt9/AzZ5th8ovT
         ikNtwrus5V+x5c3d9XEAhsOIzn1Z5Pxn/pjS3CKDiVT7kKTU2ym/d6QEXNTrDc2ARCgh
         XVq0YaVgjtf8hqrc9h7KPfoD3HvdpAjP8cNTRsUctqVGnvkKnKM3QYOgBq3uNjq6y+eB
         WAqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SSfRZPxJ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id x8-20020a17090a9dc800b00285b65a9b31si555121pjv.0.2023.12.11.01.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 01:53:01 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id 5614622812f47-3b9db318839so3067240b6e.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 01:53:01 -0800 (PST)
X-Received: by 2002:a05:6870:418c:b0:1fa:406c:219 with SMTP id
 y12-20020a056870418c00b001fa406c0219mr4019357oac.28.1702288380928; Mon, 11
 Dec 2023 01:53:00 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-6-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-6-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 10:52:20 +0100
Message-ID: <CAG_fn=UZs3-J-ay9yOovUZZr60vbQz+HC0-peRxuKPvq6N5Gwg@mail.gmail.com>
Subject: Re: [PATCH v2 05/33] kmsan: Fix is_bad_asm_addr() on arches with
 overlapping address spaces
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SSfRZPxJ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::231 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Comparing pointers with TASK_SIZE does not make sense when kernel and
> userspace overlap. Skip the comparison when this is the case.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUZs3-J-ay9yOovUZZr60vbQz%2BHC0-peRxuKPvq6N5Gwg%40mail.gm=
ail.com.
