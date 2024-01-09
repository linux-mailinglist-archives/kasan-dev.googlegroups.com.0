Return-Path: <kasan-dev+bncBDW2JDUY5AORBQX26KWAMGQEBKL5I5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32465827D56
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 04:28:05 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2cd03f1b24bsf21328721fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jan 2024 19:28:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704770884; cv=pass;
        d=google.com; s=arc-20160816;
        b=E0P8OKyKsstEg8WkrGRDg0+8LX0VCtHezhXrI0Z5IvrThVy/1Nvgmspf6vO3vp0MDW
         MKSfkp6kT2fxZxAm3XSpS/PjBOCvKCrTBU22EW6gucM4aB12k84KI1Rx2++TEN8NOvyw
         QX20QYu1gTcwgPiJ7V/aUBnJcTrTa9FR9ZcPLqqFNy44/JObEyuNyCcrtz+Swj6PseRC
         4rkhDf8RAwoO2JoBhr70w7ireXbP9/7k9g6pK/haqnqS0/jT2q0Oqb79Lc8XsbIwc2uS
         nvkslovaNmqfznbGy2mdpP3rYqsqXTabhLAS3e81+ChIJs3VeeCosPfqHI0j0cAnaeRw
         MW/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pzEW4sSMUsIadMJ8hveoaEKOWZ621QGAJ59orRroA7I=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=FTc+L2N1MTvthlaH61DYOBc1t0SsFV5KIlBtl1XVoo9l+LDgUWWL/u8dbob2oRCpon
         u9CE7hAmyuw2kbPUcxoVRH/H7zL/1wKGHlCJ5A6k+EsXL+Q/C1qB752l3hwlQJ+Y92TI
         nAEpz/vnaXfMx0zl4ygHxT8/ctSvi7dwyE/z2u+rgytym412zhAXr1Utdz2mUcYpC8WE
         RBSkUwvYpDjw20Mitwvbb+HxpGLm/3BwVlP3tae69tZYHCoFZwzwJxcEZt8/mS6hRaUp
         KQAJcoZlRIzDSiAoiws6jC9TwXbn1XuIr6FNcmdrvomc0z6O2yeeyZwRf0E+2hBn8rr/
         e9zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mw29KSHg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704770884; x=1705375684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pzEW4sSMUsIadMJ8hveoaEKOWZ621QGAJ59orRroA7I=;
        b=DliKgXLjPW6zlL+Lgkd9JPGi+x7N3ZCU8VY8Kn0qTlqvnTcVkOpOboDx97DZVedarM
         p4rizc0Fs5rUeHopVj9AhxFmVlhUanWPpiyTzN/HF+yUxAq/lR141vhsWg7ARqFv1ZGg
         AJlyZbrO/YzPiNjxlndiiH9W+MTWItS2efjQWlVLy9ZH8YIbEty7hm4yIiE40Fhq+yWV
         M9ffM423Dlx0q6tGq0KxTwlihHDE6y9ui6kpw4rs6ojSLSdxx1VczFyJj1Z66JASxupy
         2mnjmPoDNjAoeVvx179yBnENqT53biHZ/Xq0ted19NoNruYOq7nXsPgeLlOI7wKzar4U
         zpig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1704770884; x=1705375684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pzEW4sSMUsIadMJ8hveoaEKOWZ621QGAJ59orRroA7I=;
        b=ls1UapaFpUYBJk4xFHsubD7tpRGJDi3Mz3aASRJ+G3tNKeIp4lsf2l7zG8bVRpeAwg
         lebjYlrHA5eGM8Yl6uUgb3TCrbWbdWmMC9K8RqN1QV34HKvPfeTDE3Br2xdVLGco77oZ
         v2k/sHWi3Qxk8dE6eaEV9KKZgj8enbEh67Q9bRAFDQ+Zauxvao/VbWgYw3rHjjO3lI6v
         74Qr/0CvVjvmlyZnaiY/8GqghC2p+p1Z1UealQGv6aAOFZwZY7RzQ+j+5C1Oyaqa+BdG
         YQkRYadFUOFlRr8g6UaDB/mTRZP0/a66bKSRAH9M31JCOwExgwLZme5aTMrWWMvtFVmn
         Jntw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704770884; x=1705375684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pzEW4sSMUsIadMJ8hveoaEKOWZ621QGAJ59orRroA7I=;
        b=coGaSxdXpl79+L/je25dv36VVgL6APN1uGPE+4Z8hFTDVSArCWWwG0ejFfrw8OCegR
         dSFTx2udrMfZo9y2YAXuyFlIA2ZDDLthsXLyOqIRlzMRf7cZbpRkd0eNqQSAOtAAOd8Y
         Grbp21jmdhYAW0zIBUkYfCjEBfEmAitpmxWJmt1WcoynH/A019ofDG/YXCVgMzUzLsg0
         TN/NcaNto6KTWgI0BNlw3l9YwK5NrjbGY6sDuleln5sA7Om5D35bmXpMkjLv9Cbap+NC
         ghhAE1K+wSTjGmfM5LqXUsvQWYVcNq9/pzy+z+9SW13T7BOcDpARj4lerGouTejnJisB
         MZgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz7kAWqZnjUtkBQykn2UYsGHh1jtPQ7k7UBBofVvD2wVm7AI4jI
	VUPTZWl37sU6pDnlW6Je1eo=
X-Google-Smtp-Source: AGHT+IHYtKMOBYX3WV/3t4VlB/ECpiDPnl0l8TbHTRdXfAV99HhBHC1/qsPW2AFjNNeCJLTjg7jY4Q==
X-Received: by 2002:a2e:8348:0:b0:2cc:e51c:4d11 with SMTP id l8-20020a2e8348000000b002cce51c4d11mr2221372ljh.30.1704770883230;
        Mon, 08 Jan 2024 19:28:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a11:b0:2cc:f3c5:647f with SMTP id
 by17-20020a05651c1a1100b002ccf3c5647fls583879ljb.1.-pod-prod-09-eu; Mon, 08
 Jan 2024 19:28:01 -0800 (PST)
X-Received: by 2002:a2e:8091:0:b0:2cc:f6b9:3bde with SMTP id i17-20020a2e8091000000b002ccf6b93bdemr2193575ljg.74.1704770880883;
        Mon, 08 Jan 2024 19:28:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704770880; cv=none;
        d=google.com; s=arc-20160816;
        b=AmclTEmTol/pJczi8VrZ4zysXltGs0uzFm7qqhPZqIrXHg5C9YtgMUMQ7l7XLMTWHP
         lKjO3foAxM5vIQVs5Y8KviWO22UuD0EZULV7IA9sYnLUEQAaTkXuzs1vdrX9JosH9YUr
         mLCJ8Y3bZh3/2JXZ7h7e7kljvNnJ/YUffqHdSp/wuY09xmLCFj2lwbdQD2SA75afjCpl
         a8jbBN0AU1iCGZk7KoNPyH35VzOiE7EKOh+sJiaHpDoKlFBxb5ZKwG2QcsTjDaXkvftZ
         KIqTltF3hEsZYoYOoIOdiqV6AgdgM2TsaeE9SD3bGfBCshXxAS9s2QeKEAEvSmPbGi2C
         2t3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G5FTBQx6CxuffH+TulsrcO2jk2wY7catmAEyarNb8Sk=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=O7VHGSnc/SNV7qiuK5psfQcb3c6FvGB+avgVLJ5ZsA+yOXn0PaoEpxRJsLg3ZlKzfA
         3FcQ7jF37XDXbEqHIX3KAjYF6/SnJUIhm4stzswC8Xss7RIPApSmGIWsnrznvEiK1Ad6
         8C4BK27rZxOw2PLHXM7qCSYGMdC68ZVprLvsnlBI7cCUC1dW0MSbZTXzyJFJ1Hmy/9cL
         +TZgszYrYURkZEHGqiKsTTpkgOYprBgGOzAQITss8E8sJWMMNPh2ZosVzma/KnHbq5fI
         U+QQEVy/is5FcDPGMEUq/XuZYvw4VZqpISb809bH34I+C3JvSSftVXxiY9Y3pCXtJFi2
         3CLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mw29KSHg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id m1-20020a2e9101000000b002ccdcc1fd1csi33002ljg.6.2024.01.08.19.28.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Jan 2024 19:28:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-40d8902da73so23521795e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Jan 2024 19:28:00 -0800 (PST)
X-Received: by 2002:a5d:5406:0:b0:336:5b14:525f with SMTP id
 g6-20020a5d5406000000b003365b14525fmr215214wrv.132.1704770880022; Mon, 08 Jan
 2024 19:28:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
 <ZO8IMysDIT7XnN9Z@elver.google.com> <CA+fCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA@mail.gmail.com>
 <CANpmjNNtT1WUpJu_n5x_tA2sL4+utP0a6oGUzqrU5JuEu3mowg@mail.gmail.com>
 <CA+fCnZdAUo1CKDK4kiUyR+Fxc_F++CFezanPDVujx3u7fBmw=A@mail.gmail.com> <CANpmjNNfyKV0Ky=GRiw9_6va3nJMtYejWZJL0tn5cjwXTY8e1Q@mail.gmail.com>
In-Reply-To: <CANpmjNNfyKV0Ky=GRiw9_6va3nJMtYejWZJL0tn5cjwXTY8e1Q@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 9 Jan 2024 04:27:48 +0100
Message-ID: <CA+fCnZdjF=8bchUs1RNA2e+8HSZTkOw6Tkz0Ye6Znh=zdf8yrA@mail.gmail.com>
Subject: Re: [PATCH 11/15] stackdepot: use read/write lock
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Mw29KSHg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jan 2, 2024 at 1:59=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> > I started looking into using percpu-rwsem, but it appears that it
> > doesn't have the irqsave/irqrestore API flavor. I suspect that it
> > shouldn't be hard to add it, but I'd rather not pursue this as a part
> > of this series.
> >
> > So I still propose to keep the rwlock for now, and switch to
> > percpu-rwsem later together with the other perf changes.
>
> I may have gotten lost in the post-vacation email avalanche and missed
> it: did you already send the percpu-rwsem optimization? I am a little
> worried about the contention the plain rwlock introduces on big
> machines.

I didn't get to working on that part unfortunately :(

I filed https://bugzilla.kernel.org/show_bug.cgi?id=3D218312 for this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdjF%3D8bchUs1RNA2e%2B8HSZTkOw6Tkz0Ye6Znh%3Dzdf8yrA%40mai=
l.gmail.com.
