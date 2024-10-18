Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSHBZC4AMGQEVH6LLJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 994C59A3A96
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 11:56:26 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-71e5a7bd897sf2335041b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 02:56:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729245385; cv=pass;
        d=google.com; s=arc-20240605;
        b=kk19vsDYe7M/7+LPKjLg7n08F6oXFlJv0QVEs1d7EHH3wNCAFfz33HQys0x7Wjne1s
         2Ho7bAmxI4E40PGce5IBvxYkNy3fZnoI/gjbrPWLl12bL8yu/JjQSOUNJV8y//+QYNP4
         l3DiSAuJFNfcmLGOHmD11S64jcUJ62XRZ1gOGQtTRIE9rqIdP8AXZAiC/h9+05f6oCZ/
         P92bzkUVaQuYvLju6Ec4P/2TNjqjqB0XcF5fzAyRMEinwlnERyFa/uVgGvjUdip6TKqM
         xWli2nKKeYgdVnzCMV+q3D07TA9bi5S8n0pv3HQ15/SmjMBzWT78ahf7rdxPI0gicyWI
         hBiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3GQcBOHWma1c521Z5AfN6q3Lcae6ezM/XtB7PlgTxgI=;
        fh=ATMIWB8qpIWcO5zM2beUIWHkMlvOuArtBC+U1D8G0pk=;
        b=WHc5hsdRxInlczNGZE4AiSiBrtfL7VnC5QAqlOoSziQPD6Nkms6R3BpkxkNFMpcseb
         umJR0UQE2uG7Ftx8cr95jhEklwMC7P5NnnrohX78I0RtMlkisXRL9Wra1K3uv1Loj1Ax
         C5F0PpwRrOp6QMffA9kH02J4dvL51vobmS6fSzKMgwZvJ1HSC0ERKt07BgpHYirigyQ5
         3fwxQvAn94Q+OJL3tZ8D63zCrbtveZ3OcjrsfLaAoRQsrDZBj7SS7uFcdN87A9PHjTfU
         rA2k43Xn4yCTY6EffERriBHKZscs10oVYqY28MX/HmPZ0WoZkh5RKgjKZs0jJgNRy9Kt
         A3+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kbtkVeBU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729245385; x=1729850185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3GQcBOHWma1c521Z5AfN6q3Lcae6ezM/XtB7PlgTxgI=;
        b=vDBiCA2wtWqk/22m3MpitDImoFk1sZMQtAHDza4h0sO0f2MCRctUarMHy28MwcVF7B
         PfdaGcq+aRU77iq8GN96vME3LBcPg2oEPsICBd9TXUoT7jSe6NXMsbClek2s8jeZGW+n
         jNBc9hrcvuUp8UFU6KCTEscjNazmdbVxaWapgPtcY6JGoCnv+7Z/jfCqZzyB9kpISjX1
         LnwEQbA1XoyfpNlSmGPTvEk+OdR+1LiyPyR8OFBAtOiVgEcJS2R7B8tE27qhQWSu7CXF
         KdoDZyFtTtyAoE2kKw17CThBJqiZBo9AoPqSnlegEU5jjS9jyi6f5J23b98wW5sDt0cq
         927A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729245385; x=1729850185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3GQcBOHWma1c521Z5AfN6q3Lcae6ezM/XtB7PlgTxgI=;
        b=nZti8kEJr5zapCDyvzyMxFnDPeKtBXegc7DwoAwVaMlpiyBpVLjrlTN0uzsTvn641a
         hpQeQwDIZnX6mv/+XmxeCfx9jJDLcVMopIFszazXQDKe8R9iMTGiiZqGbtMbezOQoLZZ
         SabIDDN+5pJgbNrlHAvULJgHJZe2KbSzVJ2ia2xvP1GjPhoqHSogI9yqI71dfd5Xt9hk
         go1R0rbMG4gKoYcsumfVM46wSISQw59ovvNmOdXUMouritu7hwpQL0bVK2jY6OigsC6I
         OEMwDxdsfvqz11FrvAj4XgIMgueV7OO3/XAQ+GvlofwHG2EnwxX3vBvNuGXeEHMgh6ZA
         4+9w==
X-Forwarded-Encrypted: i=2; AJvYcCUGdh3qRDvfmNsOmHhlIoYRHTt8MJ51rjx8e9u1RhGEwpiadg7zjv97j9D6a1MEC8k5yoUvmQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy6rhVyvhrlb1YsS9UokohKxyPsu+dzjAMB7Hb8Nt6PNFYSMtQs
	XJQWPO2O5YtF0OigtPKtXG0PcVQcJL9wILRHOhaxh5dMaB2Zx4+2
X-Google-Smtp-Source: AGHT+IEmT2Yv2AjzM2w2Q9SK7WgPKg+4X/Cfxp2YDiMwXtS4+ECZnKjeZCFzn3kulScjleDL/PLJtQ==
X-Received: by 2002:a05:6a20:ac43:b0:1d9:1334:27ca with SMTP id adf61e73a8af0-1d92c50862dmr2467468637.22.1729245385059;
        Fri, 18 Oct 2024 02:56:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:de8b:b0:2e2:a2ab:516c with SMTP id
 98e67ed59e1d1-2e3dc1827f1ls1203179a91.1.-pod-prod-02-us; Fri, 18 Oct 2024
 02:56:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj3GzkTlNXpDtDOxUzxZJk2dYzlKTIsv1mYZx++xcgVDknT4xaaoAJ8NJGJ8R0tIK/DV9uUyjtoHM=@googlegroups.com
X-Received: by 2002:a05:6a00:1ad2:b0:71e:693c:107c with SMTP id d2e1a72fcca58-71ea31ae9a9mr2382726b3a.11.1729245383645;
        Fri, 18 Oct 2024 02:56:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729245383; cv=none;
        d=google.com; s=arc-20240605;
        b=cBDarzJ+p17jVRMmdcuxiQrE+J6TBt+0ITszKXipEFcn6eVY3wPm6D8O//C/cE39ie
         cCY1qioX1qXhH8SZ+iaOkUH1NRS024IvVseesGq2379fTG54o/TAbnlBOKVglSQWc4WM
         pfxPhCnrwOXSCYjQ0X8sYNsvP0gvsNiUiZd0Y47A2yPgRTdgjC4uHXsk0A8v76WQxOM0
         qfKTtXsSDQHMe6hulUAxpg9SjQXvaANNV+KTAqhCrJ0Hmmch409s3430M3MS4AdXSK0p
         ag11n3CwR1Wr5dSaIPL2yHkDBjcRuNCnsfFEzLqUJ1vDNn9Qusyd3MB3bhrtzu2G1eaX
         qBrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4hQeIDWuF+CNLT10ixei+G2LZf/sS6xqu32asalRwsQ=;
        fh=yLtCAegEgtcwq9Ry6jwcVMUnPQNEoevrKpkUZzaILw4=;
        b=ARFyijN0LAvzby6uPP7+dxv277ipafwLKrOupGPc5p4mrbWKBaNApOK8qeTjHVvL0K
         5w04uihKdJ/N8yfXglKnDzbdmiqE8RF1T1eVVDKwsojLOhUe1eDMJsgcIYr6oUaYfBj0
         8Lrjun7nHduE1nqH5gn3+gFVnrTJwb7hnbtEt6NUQYO7avTbInrS87KVzf0uCB0V9hVG
         jqqS0L4Lc8vwNrYbvdFCf/TDfiOPFHg8Gk+UXqtR5pda3wA+1MT+3hk20L8+lcfXwXv8
         llFxTXcCQyWnYW+ynsU/3IvlgScjtDwdwEDMk/FrMZosuOtNgcpIeY7G4d2+pWdQlDsb
         Vq9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kbtkVeBU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71ea337a509si55772b3a.1.2024.10.18.02.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 02:56:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-6e390d9ad1dso20305427b3.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 02:56:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQvhBoujcuJeo7zbBB1QraE4gx3EUf5xL3QzivABo1x9r/FScMRCpTkrGib/TB8/4dVto5PRhj2po=@googlegroups.com
X-Received: by 2002:a05:690c:18:b0:6e0:447:f257 with SMTP id
 00721157ae682-6e5bf9e837dmr16944557b3.22.1729245382584; Fri, 18 Oct 2024
 02:56:22 -0700 (PDT)
MIME-Version: 1.0
References: <CAOuPNLgOtRUUokXX=FvOJmfuNzkiVPaP78xHs5uC5PfaRd_1Ew@mail.gmail.com>
In-Reply-To: <CAOuPNLgOtRUUokXX=FvOJmfuNzkiVPaP78xHs5uC5PfaRd_1Ew@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 11:55:43 +0200
Message-ID: <CAG_fn=WZPeHjTn4Fw9S6-R9RnBBBUVrLwGkd3_8UV3GYCDnvfg@mail.gmail.com>
Subject: Re: checkpatch issue: stuck on file mm/kmsan/kmsan_test.c
To: Pintu Agarwal <pintu.ping@gmail.com>, apw@canonical.com, Joe Perches <joe@perches.com>
Cc: elver@google.com, dvyukov@google.com, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Shuah Khan <skhan@linuxfoundation.org>, Dwaipayan Ray <dwaipayanray1@gmail.com>, 
	lukas.bulwahn@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kbtkVeBU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 14, 2024 at 8:30=E2=80=AFPM Pintu Agarwal <pintu.ping@gmail.com=
> wrote:
>
> Hi,
>
> This is to report that when I run checkpatch on a file
> mm/kmsan/kmsan_test.c the checkpatch gets stuck and never returns.
> I am using the latest linux-next repo.
>
> linux-next$ ./scripts/checkpatch.pl -f mm/kmsan/kmsan_test.c
> [stuck]

Hi Pintu,

> Not sure if it is the issue with the file or the script.
> If there is any issue with the file, please let me know I will try to fix=
 it.

This is an issue in checkpatch that came up previously:
https://lore.kernel.org/lkml/3e32e97858d5bf9d88cc03136d7abc7af2dd7f30.camel=
@perches.com/T/
Andy, Joe, any chance Joe's patch can be landed to fix this?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWZPeHjTn4Fw9S6-R9RnBBBUVrLwGkd3_8UV3GYCDnvfg%40mail.gmai=
l.com.
