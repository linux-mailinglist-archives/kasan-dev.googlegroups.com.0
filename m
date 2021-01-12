Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6NN677QKGQEHX7LZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D2DB02F3691
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 18:06:02 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id 68sf1753080pfx.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:06:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610471161; cv=pass;
        d=google.com; s=arc-20160816;
        b=iAYqayBC/+joYOSxAHZxXYzYaNr455vahyW+5+tu2FNwfctUi5njCwDzxmFMvrApRs
         pCpl3xUAfn5R5QL+mpFCmWSK7tBuRs2qzSAO9szyu4YL2OBYbOZnLY+pQ1JoszuC2Py1
         RjxBjmCEVdmGcpeDa2Y/NEKxGK8pL6B1TtA0PydsDrhnoctyWAyIuG//sfGRq48ig5rH
         xemDwNRqTTIgz+/AmphFqduPEA1NRqPsawSi+JJCvIrveJeRgxggMt1rcTMP7ys9EFpB
         N5gfYtXNYibbGK9zexDeDS3U6+37pIqM87lh75/0uhAfADEUsbhD+8zsPIFvsZ4vk9nh
         0sCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J7ULmGG8iK9R9769eIV3UyDhmESeAzdwbDFAuUUm7Sg=;
        b=RlrfBARq7U/jcTzsdg9KHG5Bb5Fzo9UGGShdERH7QIEVvKLibSNxyCDDZgG0PIi8t1
         sewXTICvCEefwO2jzlGsxJw15XQajnuNflTtjf7qH6XGXWpG/WLNLIUfCPQY4u1MTYNs
         FTkaEYmLUKohiZbOJ4jpf3ogrH7DKi69Dran+7nNtLkO8VhkylZfSiz2HyiP+xCkKsOQ
         MhOOwlgEo330P2yhbSl7UcHekoirCHzcNQhGtnwCmDAifbOfEjEKT062lsy1Iu96hgwY
         vWN9o9t2SeekPVxn/Q4gLIy4cFVttLqZypIc4gAnNO7/J7J7QW1O3lj3Q8hViSATSB7q
         UPZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kqpelUn3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=J7ULmGG8iK9R9769eIV3UyDhmESeAzdwbDFAuUUm7Sg=;
        b=TM0fAYZ/bDDskDfgQT+nBUfOAAisEua7Wn7pRo2dH4RQgKycDHn68efgqI1Padr7ke
         Gnr9jRGTX5jvwQFGT+JMGN3ozjdFVXXpiu9Tx8TIiuUdUbnHqqz8E7Gosa7Tzi/Rtxzl
         ImqzPHbPaVvjlRiu0JCNzK7TbGc0bYNvOtku7TKaYFSlxTGc7SPlK0opRWxhn0ff8DLb
         S0bT8ZerYKsbZOS29dnCKwWh2sJpsN6gSBmmKZqiInXfk5ufTRm+4d6bHnGxDSLx4taO
         +tPjN/7ot/T8uAu4qghaY5J2OpMplx1n+Ywhley6NknHWEYSsKYZ58smoM6NvV5mv3SF
         cuLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J7ULmGG8iK9R9769eIV3UyDhmESeAzdwbDFAuUUm7Sg=;
        b=H1JuVV1xAR0OMXiz/n0aaSjgNh6t/Yi3ccjGNeB/SsD+3Pb6MT7uTi88ZwYWR5QxNx
         uGJZk/OsAIAKks6Duh1d0ASFpR1J7CrJe40bIywWqdqTz9OJU/0+/W8Bn92sMj41hFzT
         4MJQYhOmexzGuJgdTUnT06Z8/Fq4zruavUJButdhj4GAwTJ5Q6OvH626vhYl4TNPQrNI
         boetQ1fkgiJ8kLWbfM6CuDrRwd46JuP8yHKHawY3yark71ZJOjMzTcs71Gxby7mV31gB
         QFnW5AL20mMFoP1zqgYu9FETCY5asCKuvGSyIgnqkKx35Y7EIWL30ZpvKFRCHWUDS0Be
         hZ4w==
X-Gm-Message-State: AOAM530q4fAGGRfYoujgZ10zhrYnmZw/z93uX785iH5E42ixU+yxN3Pq
	3gC+yA7h7UaW7DMdfw2llIo=
X-Google-Smtp-Source: ABdhPJz7nfddzXxMdS0vUBl27sONHsEGGnjuFlbLgdbTz6gcZUZa8rLja4xH8YXkAGTiPxd16ZHFVA==
X-Received: by 2002:a63:d246:: with SMTP id t6mr657pgi.283.1610471161532;
        Tue, 12 Jan 2021 09:06:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a416:: with SMTP id p22ls1816155plq.3.gmail; Tue, 12
 Jan 2021 09:06:01 -0800 (PST)
X-Received: by 2002:a17:90a:1c09:: with SMTP id s9mr26427pjs.83.1610471160868;
        Tue, 12 Jan 2021 09:06:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610471160; cv=none;
        d=google.com; s=arc-20160816;
        b=DzTSUGOhDOGEk8ieoIT288QM+SmV/xMQnS89f76Oz1JiXGoiwpNw2fujhOJtXYi5iD
         hYBsA4Z4NRKumgDZcSioM4k5pO083koRgOQbXhBSk9Xs44vnpWeXZ4js8AOIf3bVkYDz
         KGaF5w29c5MydjG+edXYtHKrUDLpBFNSXma95ARGOzAnXJYDFvhA3ajkfULQF0m0m6c6
         Ax4/KpTHGnOQI/vJuIk9hSvZDpeUCkT+OPtsY1Gj+GVeT92zaI+a16n62nRAJu6LqfHh
         TlxtyYe5UKujNrfIwC1LMaVXsVIdFKjeZulxXad0p+Tv0yKz2OW/lpra+uuWVLdKtIZL
         pikg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cW/mhnZc2jnbLJEi99RzYHxXLtfnaEgmdGMdhytYu8I=;
        b=VAerpX4LD9GChu0SMMugNgL0t5L4p50806E9xZG1Nise5D1/uNoDZDV7kPgt9iB/yZ
         ytAKnxH7UzSpB/9lUAV6rOuBVHG472EJUrArqofwbZNz12TbtFd026pnQ2gkU4/ekPHb
         E0oApD5OXKPXplLAHEjlEk9GRv8Fk7eBdEsvzyDeGfikSD8Jih9rSmsyfNerSVvB8gRi
         gF+KDan66kjKpwcq+Ou8PoYR7tvB+d2wR/XWxrNY7D9xcY2kcknqq+hiv9sNmr8QSjXs
         EaFMvIetAF4AscsBGCMfvnChcv8WwTprxuPc/Rl3PN0iAH8EidsvMJM5VlUzJcjx+/9C
         uqqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kqpelUn3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id kr15si282986pjb.2.2021.01.12.09.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 09:06:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id v19so1811859pgj.12
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 09:06:00 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr30528pgk.440.1610471160357;
 Tue, 12 Jan 2021 09:06:00 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QUZzBtGAk7Tghf+ZXxnnjPuSvHLHTs3imM5N9ZmVFSC7g@mail.gmail.com>
In-Reply-To: <CAD-N9QUZzBtGAk7Tghf+ZXxnnjPuSvHLHTs3imM5N9ZmVFSC7g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 18:05:49 +0100
Message-ID: <CAAeHK+z03_kxkzj=sckT87PdrtjcZAYszq62=bUD=FwZTjjSag@mail.gmail.com>
Subject: Re: When KASAN reports GPF, when KASAN reports NULL pointer dereference?
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kqpelUn3;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 12, 2021 at 10:30 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangab=
cd@gmail.com> wrote:
>
> Hi all,
>
> from my basic understanding, KASAN can catch invalid memory access,
> such as NULL pointer dereference. However, recently I encountered one
> case - BUG: unable to handle kernel NULL pointer dereference in
> x25_connect(https://syzkaller.appspot.com/bug?id=3De4a61ec2a7dc1ec6161714=
2a0f7a7d0427f8c442),
> the kernel reports "BUG: unable to handle kernel NULL pointer
> dereference" with KASAN enabled. I don't understand why this occurs.

Hi,

If the memory access is not instrumented - like in this case where the
access is done from inline assembly - KASAN won't detect a
null-ptr-deref.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2Bz03_kxkzj%3DsckT87PdrtjcZAYszq62%3DbUD%3DFwZTjjSag%40mai=
l.gmail.com.
