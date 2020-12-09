Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYUKYX7AKGQEGITIQBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EC7F2D4D0D
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 22:45:08 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id w135sf1965872pff.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 13:45:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607550307; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqGH3/7+/5RPC32q+q9sR0aHxxl659aDeOjBDWY8itOJ04qJzs4HAMZJ6VK6y46GwV
         82bC5aVuTJ/FkmoQDsyWCu/yc2dG2RmRykdkvA8nHSrjAteVtd+kXMUg+sg0R9FWLqMK
         JHU7SQBUL5tCViKocEpZEoGEaWjQxo3iyWS7I81iTyupcP8m86unIxoiBvvvmRp+dJU/
         adxa0p7HeFA3ZggRWvbXpWq9BtJ0+fK65jHq+47pijgTLMNbUSAXSuC77Tb4iGVvfA8K
         xhGN6j3wQakp2fQM0g5L8uXiMszPdHUeGaQF0wjubysIlF1ZbbtHjRdty20asyhLiJXm
         np7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1R6IxiyN6ZTBBAWyiY8wuyfXOt7D5yTDiWEQU3KbKrI=;
        b=gAAOCLBvwJ/zhDiB++zFRVB3bkBscW/gYlLEDfDDOCOoYnb8ITmzV8OkL2/28VmeS6
         yxjAbvrKmDReJCGLg3eadMhQkgkrmqQaTOcc6x9Jgx+zl/BzBBwkmTqsP0738OPdWgR9
         XJWMy3GrHT5qTyOtngKiUiLJGUmdcfp+Z5OKwKJ1H8TiYzSK4sO/MlzG/Qu0OkgSJ2r6
         YxyZnU3QB0b8qqNft86PJLHNRkBQMhqtmfB9ENv+QqqOuPklJjYkvab30Z217Izh18n7
         LLi9wnKYF6ZbzvUlaqJJ2vc7aSZtOG8Nw6bz6cnxn5f/tXAwclKYvG1TDs939LtD5PRX
         IPrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H3IzZY9S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1R6IxiyN6ZTBBAWyiY8wuyfXOt7D5yTDiWEQU3KbKrI=;
        b=c9xYd1ojNn9j8a/cXmRPgFvPe64MbWkp0wT0wMMvbtelDvSGKLww0piyefb8nvynmk
         60xUulOP8MXrZ8tBBiPig0CV8Uyemkkop9SOua1f4Wn+RdbJ7vf4bDOg8BhhxaWvroOi
         Ahc3VL46fzpdac//tYoqMqpSXTWC/SBGC6xpEH7Kro9twtdDkwnc86uBWYL6+NczKN4R
         X66nI1MLynZMZj3VF6r5//uKMSnmiAHq4yYcRpPeCavt0bpy/Cg/pD1brY+N2c8Z7kRT
         j0cmCNfOPMi1OONDzGXn83EKdV6j8AYEir0VnSF5+EpIfjZJ4dt+OEMgZK2Mf6anokOF
         WCDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1R6IxiyN6ZTBBAWyiY8wuyfXOt7D5yTDiWEQU3KbKrI=;
        b=Pzyt4zTZMDQd7ADwfSfomCujYdW76sXAivf3c785Qf3HnSCV1jPVBrJLJLMRqds/cx
         +8NqKHJmWZ+KibmeqRhjB6nKdxCx9QUXwLPNW7XmFb2dZm0opdIkDchLOqSDsvkzr4v5
         YAugPmvVVB7laJcMi0N+3LOWYpCbYuO7qVuV2dZLqMQYy8Xo1HWSa4CWfNW+sWXDTDsX
         G2PwiLyEDjgz5CBcN9petQQHfnVqWo/YycxfHa9zYQ67jqHbr5KrUVmUZ17uplyYGmFM
         u7+2DNm4FNtmj9yQoBosPavSZ7jGRIKNNeWnsXy9kP5k5EYrL9FZyQhZjHWPMz8pCt5i
         P67g==
X-Gm-Message-State: AOAM532U5mDj8BPc08stWIOKdcIuoLlnLS+gimDtTteCekA5BUOkh70t
	4SnJT9V0WIZKZ3WVKCz+qlQ=
X-Google-Smtp-Source: ABdhPJz/g5pSUID5qmTyjuAT/2l0tSxoVioqSVqoyRYxkKrPDS+iczpSj5IdDMKpuFwzhfmpOM88nQ==
X-Received: by 2002:a17:90b:697:: with SMTP id m23mr3994495pjz.35.1607550306934;
        Wed, 09 Dec 2020 13:45:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5612:: with SMTP id k18ls1173016pgb.7.gmail; Wed, 09 Dec
 2020 13:45:06 -0800 (PST)
X-Received: by 2002:a05:6a00:7cc:b029:19e:30b0:6eae with SMTP id n12-20020a056a0007ccb029019e30b06eaemr4075869pfu.5.1607550306326;
        Wed, 09 Dec 2020 13:45:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607550306; cv=none;
        d=google.com; s=arc-20160816;
        b=b0yzlSPkYeRm+ig1dzLK0birpmpFMBTzikVN+WG3jHWU2MmIkRBsEclR2cgZnWCNRO
         BNMJXXxy0aO2Mc1KGukrSwFrnjxKBFf+mQtZklE9b9+wD1nCKhoij4f4qxjdan8Yp0Nq
         l/WiyDoyfsfv8TEWwmpOBN/PDPrC3FLMBG6biQ2GFbBBOo4nOGXji1qmGS/LHlAduJio
         5CCxA3DerzWb3QAqND0hf4tcVk981IY2rCo8HrxvsYNJfMscRlXtcHDY0GDG3zWZQfAE
         rnzF1s0B9i8J78e2yeimK8jVZqetNcDf/leW4+crTnQqNuqR2Q+gfwlT09Kupf+/kg1r
         WpaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VTZ9zzWo5Itj99pZH9XB9OWs7C8A2BkhFDuwiDt+HkI=;
        b=DgbpvJ0PZIPe1Uun1ld/jxtf9LokxLFRMYnKEYeGb7duLrXZ4MVzMaTtlVnH3k92TI
         OLOMN+tEVfxFg4U5kYLDgBOZweXp7pEVMPT7uLPGz9s8La1dROMY7ckoUpcun5W5vG1n
         0Wx91X+uUvDdSZRaUdtYmOVbUUHJZzyjpz7cjH8JjPaVO/LligzkSuMUrdbL6sqyMYLi
         DhUYzUspJjUQ78+bS8CXcLhS9lumb5r718CG9YqYHZOeyCoOh7QrYHmHVJsENMekxQ13
         yLoluxcGV69omNIJeLOQfWYd0Dn2DQWFYtO+2bsrocMNDIRG9d7DNErh0MeFvKNGD/pY
         jkAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H3IzZY9S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id v8si286122pgj.1.2020.12.09.13.45.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 13:45:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id x16so3393802oic.3
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 13:45:06 -0800 (PST)
X-Received: by 2002:aca:3192:: with SMTP id x140mr3336219oix.172.1607550305727;
 Wed, 09 Dec 2020 13:45:05 -0800 (PST)
MIME-Version: 1.0
References: <20201014134905.GG3567119@cork> <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork> <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork> <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork> <X83nnTV62M/ZXFDR@elver.google.com>
 <20201209201038.GC2526461@cork> <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
 <20201209204233.GD2526461@cork>
In-Reply-To: <20201209204233.GD2526461@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 22:44:53 +0100
Message-ID: <CANpmjNMXOYkG25Gt6n54Ov+pxVjGMXRUWAMkDD4JWtLCNq4jPA@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H3IzZY9S;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Wed, 9 Dec 2020 at 21:42, J=C3=B6rn Engel <joern@purestorage.com> wrote:
> On Wed, Dec 09, 2020 at 09:30:54PM +0100, Marco Elver wrote:
> >
> > It still doesn't change the fact we probably couldn't get a dynamic
> > branch past reviewers. ;-)
>
> Is that true?  For the CONFIG_KFENCE=3Dn case, there would be no
> performance change.

I was curious, here's what I get -- sysbench I/O 60sec, 5 samples
each, reboots between runs, VM with 8 vCPUs, but using 500ms sample
interval which is closer to what we want to actually use.

Static branch samples: [7272.36, 7634.77, 7380.72, 7743.89, 7480.7] #
Requests/sec
Mean: 7502
Std. dev%: 2.26%

Dynamic branch samples: [7354.06, 7225.33, 7154.76, 7535.82, 7275.94]
# Requests/sec
Mean: 7309
Std. dev%: 1.78%

=3D=3D> Static branch version is 2.64% faster (possible significant effect
given std. dev).

Of course, that says nothing about the real workload, and if you're
wanting to reduce the sample rate, at which point things will start
looking different again.

> Anyway, since you have to deal with them, I should let you make those
> decisions as well.  I can disagree in the privacy of my local patch. :)

Indeed, but we've also learned that the static branch certainly isn't
one-size-fits-all. And that's absolutely fair. :-)

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMXOYkG25Gt6n54Ov%2BpxVjGMXRUWAMkDD4JWtLCNq4jPA%40mail.gmai=
l.com.
