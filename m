Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEIXWYQMGQEAWHDXZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 02A138B51C5
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 08:54:19 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1e8d6480f77sf44313645ad.3
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Apr 2024 23:54:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714373657; cv=pass;
        d=google.com; s=arc-20160816;
        b=W141SYk7gpwWaTV1uvEKAJXlLQxfS/DhrDQJGy5WofmBdMFeslIpbTGwPMOnYbsIQz
         rnNLhXB1kds6WnKJ5gybvqXwTMqdYNiGYlXewozlWsjkuoS2jsKXvAybeZKVYWOy2HNJ
         zpC8v9eCnvA8CLGqueL9DRpwH8ZkLAR20/9A1/8e2EshlmRGhu8F8P8D+7lME5ksfGi4
         VTAFvi/wo12kubmVZzAy0YeRbTWrJPbi0MOYxhPqcPISgGohUZFWvAqp6hOnyhAkKtCW
         5zLzw7SvaBDsLiw51afeVSYHbQTfJlIDswHC9Cl8Y+iXK3cpyymkaazSbnMkKTpYhK0v
         rOLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=toTC15X7xkDcFKSlFVpsp9CJKjyHwNSsH7Jdd0BOKt0=;
        fh=fR77a97C1yl80aaZq/VJ24TGpgOn2EXlNgf64WBG7LA=;
        b=Xtu9c4Bc0WRN7ACvHtb+cOH035ID+WXXxZkDf78bVKi6an8UymPfqNrV5AYy/v9ZgM
         hwW68QiSiSd6/XjuewfWhXg/knKKwLywOo/E7Ig7SEarXG8vXu3kmYagpsUBKj2Q4Wl/
         zFLZXpiEVKkegpKl25F7Ulb+Pzfj6vJdeWWsVS7dfqcq3L1ixLR4CwS6dfAQnuvD9zqX
         Vsh34N3HCWx7tlou+s4kHebItLuZb9iDQQcAL9SHDUSzTeQihj5YEkBVqDxAIsYL8dOu
         Kf/k61X1ayq8DumqRG3ACAKrc812GZ7fCa3PWQUt78p5fhmRfuKNM+OjZuoYBj+kaQLz
         Lk4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vTLP/VSQ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714373657; x=1714978457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=toTC15X7xkDcFKSlFVpsp9CJKjyHwNSsH7Jdd0BOKt0=;
        b=RL1mBa8spcBks6vuVAKPplRjnL6n8hifjbl8+9kKLQGCUL9M278J7yKs4s7l82TZRd
         Waz+6C2m5YUgS9RpRWw3hSgXAO9+yMv0+Lr8Byqi81CvjfusHNiU/5BzYYUtyhbTL3Eq
         a3dacrBVAPhXSdvoJqEN4Nog4hM9a//eUqo7L5RKzKcqyykFjH9+2NyYN7U9rDwymCm8
         Dy6OH+jpPJsW33Xk2VHmZZmBSJYsNQX2bWVFRbI43WN7y/q0HcG3U1ozqIakxmkpG/AU
         kKTNIvs/h/wJktCOMBrFshgnDeq84WH77l/aDnRu4t6ThRjNzTStSZDsV8WKaR78gZXo
         6X+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714373657; x=1714978457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=toTC15X7xkDcFKSlFVpsp9CJKjyHwNSsH7Jdd0BOKt0=;
        b=uRYlJQkNrDVmXpH58VIpsKts6+EPg8WU7n26iSiJCiRxDtD9u0Jf31oJ7XHhfTocts
         REJVnqopnJOVMu5xzRTJb3YCTk48pnTI8GgM3Q+BgiWOXSR9UaIdjOkkess0oPrrmfAf
         xIw62zvvjJ4zubSYtwm2k00E5LD7SW9y8bTEztqij7lw5SNO1iQsuAUPbuJJg0K3SjCb
         pfoewdna7G0wupUlo62ryduzr4jJH7JJYmEyE5mjkGJq+7lrROSSKnpXZAaFBAfKMAzp
         WmM9hJ8qHryYXQlwR14V+uJ+7GrtcpmUc+mzTguQKfS+soxvL539irwebFD6HZ0hC3yL
         QUKA==
X-Forwarded-Encrypted: i=2; AJvYcCXpcj+3LvnD8hQ0oi1vw/zWGtHEglXYCop3zDp3DmBzRVSvlh+t/GilSVrudsQ7wUo97d7wuh9f9OBlhgajMyEFOejCeiGatQ==
X-Gm-Message-State: AOJu0YxRMVm1MtTOQQ5GdMwLB93ZIZzgzuTt3WlfycjCbUVXHOa7+VgK
	bQ9RkraPXO94tVxt2kxLxQ5GTN52p3mmTvFJd3uSrwBDAC9q+9Ws
X-Google-Smtp-Source: AGHT+IG5BGQjbRLBD1X9KNv9v/R0KY0kuUbLpkIPikl3m1vVHO0Ev2P72dweN6md9hlkyhuG0c15Zg==
X-Received: by 2002:a17:902:7802:b0:1eb:7dc:709a with SMTP id p2-20020a170902780200b001eb07dc709amr9331966pll.40.1714373657116;
        Sun, 28 Apr 2024 23:54:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32c9:b0:1eb:5f5f:1e7a with SMTP id
 d9443c01a7336-1eb5f5f21c1ls9978885ad.2.-pod-prod-03-us; Sun, 28 Apr 2024
 23:54:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWwdPnnDoMFGfErJ+EHAnFuo7+wkrLW0MzHAWKGx1OnXsZfNwEtCpRuBbDG3BgHKZUt/STwAaLZxe8cFHExr+JMmaFOBN9q0+U9g==
X-Received: by 2002:a05:6a20:3d95:b0:1aa:340e:237e with SMTP id s21-20020a056a203d9500b001aa340e237emr11812832pzi.59.1714373655729;
        Sun, 28 Apr 2024 23:54:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714373655; cv=none;
        d=google.com; s=arc-20160816;
        b=w+MIyQD/PktbcIrvnKM+F7pX4Q2TGTfIdmT+Pl+Im4sD1d7U0hmlmAMq9KPklR9DLR
         vG0r6iClkLOEOQo97IO1s1IoM9vb/G+wBhhydo7/kBlHAnIwIjWiIdaNM6YkQD2Oxq0P
         NPVBwwXzp/W5xOQa3uy02yEkmXuXhArDyA9X3zYrgZQzYf5ZS45tQDOZhLEVd5OncL76
         qerN/KAM2EXpl7lmMG1Nmzb7ItZ9fvkDBEey/IrQkExRDQYkNVKaebf0b7v31UDQhzz5
         Gnqc5gSlnRaVwNGJv+cGFMHckL/6dHFaF47Ibpwo0rxKfUAHFXAGxh0t6vr5/re6Lf+G
         P7WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rCVP1TbqI5DFaYlbbppm8OrGSIFR+5y7OXC5pe0YXUg=;
        fh=Q3mtzkSeXXSJvIuusdpRBUjFrTf9PkRPy/icerN6lwk=;
        b=gRgiOG4qUQycwocaOFv70rGAMawBUN7TXug3tOIqhD+bxhb4WcEVO5tWAEaOGLVCWb
         MuwErEBu4QSlHyOLw6+XtR67pZzKVN0MSN4YeT5ll+0ZBOYsnAqWjc8XZk8t+q1Wiwpm
         cYoWfolF7Spngk7rFhrMmK9d5jUGRRTCi7Y22KyfthLENlNHlwirlHMBywIYJgLa9BHO
         Fsu7XgWTx7aFby4iHQIchk2yJwRSL6QR+gY+lfFPuF1VtocToInIKW9iKQoXcqYX9467
         01awjbfqOaSlhnTZ0Oe9MZAJaEGrKWeeB93o6m8cFfHzY3nUJ07nuBARJ7Hp4ofqmEAc
         pRAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vTLP/VSQ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x936.google.com (mail-ua1-x936.google.com. [2607:f8b0:4864:20::936])
        by gmr-mx.google.com with ESMTPS id dn14-20020a056a00498e00b006f3ee965d72si233507pfb.4.2024.04.28.23.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 28 Apr 2024 23:54:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) client-ip=2607:f8b0:4864:20::936;
Received: by mail-ua1-x936.google.com with SMTP id a1e0cc1a2514c-7efa7296beeso1123947241.3
        for <kasan-dev@googlegroups.com>; Sun, 28 Apr 2024 23:54:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXl11xKuMBFnSdFRmhi5oJCXG6bRMXQtmcAXdFO1O2QirUU1BWb6mr1LG67OQaS6QEpmcsREBZOcNhVAGoiAzmCXm0Ngn2hagLhRg==
X-Received: by 2002:a05:6122:916:b0:4da:aa48:dab4 with SMTP id
 j22-20020a056122091600b004daaa48dab4mr8771333vka.4.1714373654581; Sun, 28 Apr
 2024 23:54:14 -0700 (PDT)
MIME-Version: 1.0
References: <e1fe6a44-3021-62ad-690a-69146e39e1ac@I-love.SAKURA.ne.jp>
 <20230424004431.GG3390869@ZenIV> <8e21256a-736e-4c2d-1ff4-723775bcac46@I-love.SAKURA.ne.jp>
 <2fca7932-5030-32c3-dd61-48dd78e58e11@I-love.SAKURA.ne.jp>
 <20230425160344.GS3390869@ZenIV> <1b405689-ea0a-6696-6709-d372ce72d68c@I-love.SAKURA.ne.jp>
 <5cebade5-0aa9-506c-c817-7bcf098eba89@I-love.SAKURA.ne.jp>
 <c95c62ba-4f47-b499-623b-05627a81c601@I-love.SAKURA.ne.jp>
 <2023053005-alongside-unvisited-d9af@gregkh> <8edbd558-a05f-c775-4d0c-09367e688682@I-love.SAKURA.ne.jp>
 <2023053048-saved-undated-9adf@gregkh> <18a58415-4aa9-4cba-97d2-b70384407313@I-love.SAKURA.ne.jp>
 <CAHk-=wgSOa_g+bxjNi+HQpC=6sHK2yKeoW-xOhb0-FVGMTDWjg@mail.gmail.com>
 <a3be44f9-64eb-42e8-bf01-8610548a68a7@I-love.SAKURA.ne.jp>
 <CAHk-=wj6HmDetTDhNNUNcAXZzmCv==oHk22_kVW4znfO-HuMnA@mail.gmail.com> <314a8e87-8348-4f40-9260-085695ac2dcc@I-love.SAKURA.ne.jp>
In-Reply-To: <314a8e87-8348-4f40-9260-085695ac2dcc@I-love.SAKURA.ne.jp>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Apr 2024 08:53:36 +0200
Message-ID: <CANpmjNMx0eiNUY7C6t_Aay=QMUT6743axZB3wn06jL6Q_JTXOA@mail.gmail.com>
Subject: Re: [PATCH v3] tty: tty_io: remove hung_up_tty_fops
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="vTLP/VSQ";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as
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

Thanks for the ping, I haven't seen it. I will respond to the below
thread separately. But before I do, just I get it right:

There is a real data race where one thread updates a function pointer
and the other reads it. After a function pointer has become non-NULL,
it will never be NULL again, but will only ever be updated to point to
some other function.

The assumption is that both read and write (even though they are plain
accesses) behave atomically, i.e. no load or store tearing or some
other way the compiler miscompiles this. The safety of this idiom in
this case really depends on how much we trust our compilers. Nothing
new here,

Correct?

On Mon, 29 Apr 2024 at 02:19, Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2024/04/29 3:50, Linus Torvalds wrote:
> > On Sun, 28 Apr 2024 at 03:20, Tetsuo Handa
> > <penguin-kernel@i-love.sakura.ne.jp> wrote:
> >>
> >>
> >> If we keep the current model, WRITE_ONCE() is not sufficient.
> >>
> >> My understanding is that KCSAN's report like
> >
> > I find it obnoxious that these are NOT REAL PROBLEMS.
> >
> > It's KCSAN that is broken and doesn't allow us to just tell it to
> > sanely ignore things.
> >
> > I don't want to add stupid and pointless annotations for a broken tooling.
> >
> > Can you instead just ask the KCSAN people to have some mode where we
> > can annotate a pointer as a "use one or the other", and just shut that
> > thing up that way?
> >
> > Because no, we're not adding some idiotic "f_op()" wrapper just to
> > shut KCSAN up about a non-issue.
> >
> >                      Linus
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMx0eiNUY7C6t_Aay%3DQMUT6743axZB3wn06jL6Q_JTXOA%40mail.gmail.com.
