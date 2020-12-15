Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMOC4T7AKGQEBDSSUCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F6B52DB55D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 21:48:51 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id gj22sf258743pjb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 12:48:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608065330; cv=pass;
        d=google.com; s=arc-20160816;
        b=C5CiHz9RB//+8gjORjCFmzilPqHxVeehzymWBq1jsK7UyV4UhRsrpkRJVk/7cgoexf
         RDhHiYD13UGQnKNaf8cOkfZEcRyC/GIz7xaKMMcb2iQ0fCzC7jN11pISXcIPm+/geeLO
         a3O7F+UWw1CaW+RheT1Z+2UxUR6fvQctulhOIUfRna2GYz0STiEceWriFLHre9w2ME4S
         N22xg/t7l5+8d8KyGf7XAvPRJPLpTlYSMdlZOLvt7+ARl8ou2EITFI0F/GhK/wXS4F8E
         WWEQ6bgf9Xp55VbUcpo7ZhfNHdsBtR7ehZBrqi1qn5fqQ5M9HvzCkbVVnNA9s+f88XIB
         t3Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ehv9+VX3kwJJLWPKOqYMnEp6F84DRBLOjiuEUXboYzM=;
        b=ggPO47wjbUFWL+YnNubaNFLjsnHboLLEcM47PJtWI1NQCOX6iDNl6Jva8Gtg/LSlGC
         vjzzwe+e0mlv8iGZfXl/tVST1QDw1W6boctvOQAugqt3JU3YVXhgC+EI3xAQAHukjAcz
         CA8I49stc8dkSPexxMgMRJBVJOdkKs70s+seAcHuHjDMz/EKtNbcEX+wudBB+AxKOrGH
         CCtdugSP9wJxA6ydYnCT5rjE1HmKsea60LO7tI8BA1gwiRfPxE2OYIjllNRiIxIBlbP1
         kto+tGe7QaR0J79pTjMrDtkiAPDTF8Xh3cMdkf3WdLYvIGq0/avrwseGN0hadBkBpBZZ
         s8Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=frNUd1VF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ehv9+VX3kwJJLWPKOqYMnEp6F84DRBLOjiuEUXboYzM=;
        b=MlRAVFE7pkTMuKJdEilweUs5ciYMabizcoLq5X6dzv6kln6Uf0hL8NyiTdAMoxwjkS
         UQB9EZjLg7fq7Xzm71BOLuGJbQNE3w73DoOrDbCkh9j00ZMXmDwNB/hzhkYKU1QUk/xg
         Ws6gvrPaW1a0b0E4g1a5fxxN9/djPj9Lz/kouZcUVABnvIfhjl5rJVz6ElIUpYWjqpwx
         f9XKuvbDKaMalS69dOq9ZHxvOQuJCqF2c30SrZAdJHFLd41dSfj1GantdTwvgtfUuPRq
         jUm6UOzyMxWj4fT292WTazTnXKzBR2XSGfmXKQr2u9xHxLQGo6Ieqiw1jE4s+YDeXR7L
         3MHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ehv9+VX3kwJJLWPKOqYMnEp6F84DRBLOjiuEUXboYzM=;
        b=kBAkmSI7azItDmjm4X9pl/cSG9f0dzEnNxTPn5o20gvQfgVK7ABV1V1MMixb9lY2q/
         CF0yk+A8zOPULhOFSTLg5ALGbtvivN+capYaEE+MuSGx1bA46/HyfO/f/Q9QPiJip14j
         XlqPzbSYveEqymHZiF2qApGKhzt22Y2DilPSfa0tpkYggMrpjQd7dFBgoylMJuL3wSAZ
         wqmIgPBTF55xqk0Pv7/3h4pt2rLcjlyrGI2jTq22Nz+M0CzP1TS0QEg2NFojDK/0jgBr
         Fq9XQ2CacikaRobyEvE8YnW3UnEyRmL+uqivtRgRLdMFMp7gZwiu5tnzXAW/dwtRUDrH
         3Xkw==
X-Gm-Message-State: AOAM530q2EwRJDgFajjC0SVN1UiSwuIpNXIg2p/hwImm920y4P2JgNgm
	KAwykg75rdIKjfA5TzZJANo=
X-Google-Smtp-Source: ABdhPJyEYOPG+kWn1onNuueM115qRHgvsdGBj58xeMFr7hhmIl6EseyDpWUTEPpVoQwMUq9YHiMDmQ==
X-Received: by 2002:a17:90b:4b06:: with SMTP id lx6mr576930pjb.224.1608065330033;
        Tue, 15 Dec 2020 12:48:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc47:: with SMTP id t7ls80722pjv.2.gmail; Tue, 15
 Dec 2020 12:48:49 -0800 (PST)
X-Received: by 2002:a17:90a:8d84:: with SMTP id d4mr597792pjo.56.1608065329234;
        Tue, 15 Dec 2020 12:48:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608065329; cv=none;
        d=google.com; s=arc-20160816;
        b=Fx1HQwtu3nCgYuvYfiIZdmhCrudqjpbeqQKZvi8FssHXzPdpg+QK6bfjYE+e7na+dk
         hlxPF9lJQ9+h5qbiUPidQWYUXw61jkfVjkb33eA/KmJui7Y7LquL9dz5/UusHjdcJT2g
         gYoZPTO5v2ULKhmf1Pnu+JWLcCRj83nsxlznn3NRNmBy4pbMkm3euUaJYwrGQaU5FbeC
         IsgYhm9aSuqZE7cvgBAEcTG4j6kuxkbz+b+5LZxsSaSbqRujkk0rl+b3qV9eDriOxycH
         NyFUspE1jIbbOaLUnip7APJY6vyEjt86eB7AzWRLvCDn+IUc8Toh+x1Tb4vHDZvik17f
         wMJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wLuchAKizQyMjLfVFEcxdz9NR2mD4uG9BjTzNSH6HeE=;
        b=qeNFuQaTgKA2dvZoIh+CDzsu92o4/iiDr4fdFJxer/aaW64T7TkmSmP6KX4lBPNLnY
         yReS1kkciHBuZjn7aCwZzqyTqu8BHeuJlZ6Kwv7PrjodmkT4I3XM67hvA4cnjuQ9NCpq
         VevioLvUd5XM9kl56CT33CaBDb+HrKp3wpp+ZCs2zcf2kTuKXVXRMqp+gDxeEpelaTCK
         cOMiL+/l0A3QKZiqrkAE6YJ2NmwMP3cN9QNzulAcYLvPUL8wWDF/dRii30YfOANlKBsu
         gZV44muFb4RjrsDv8zLaTwjKmulAwtfWoqZ7D7OjA/eCJ3ZOJWr7IkZwb0TIM/4iqcqt
         OB3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=frNUd1VF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id y68si1627155pfy.0.2020.12.15.12.48.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 12:48:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id f132so24856038oib.12
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 12:48:49 -0800 (PST)
X-Received: by 2002:aca:3192:: with SMTP id x140mr455280oix.172.1608065328457;
 Tue, 15 Dec 2020 12:48:48 -0800 (PST)
MIME-Version: 1.0
References: <20201215151401.GA3865940@cork> <20201215161749.GC3865940@cork>
 <X9kAeqWoWIVuVKLq@elver.google.com> <20201215200217.GE3865940@cork>
In-Reply-To: <20201215200217.GE3865940@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Dec 2020 21:48:36 +0100
Message-ID: <CANpmjNM29k68CZXnS4mfzsdW3YJf5FdXBA3mZtuLcSQA7+EfTA@mail.gmail.com>
Subject: Re: stack_trace_save skip
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=frNUd1VF;       spf=pass
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

On Tue, 15 Dec 2020 at 21:02, J=C3=B6rn Engel <joern@purestorage.com> wrote=
:
>
> On Tue, Dec 15, 2020 at 07:29:14PM +0100, Marco Elver wrote:
> >
> > I'll send the below patch with the round of KFENCE patches for 5.12.
> > Not sure why we didn't have this earlier, but I guess we were busy just
> > trying to get the basic feature polished and these details go missing.
> > :-)
>
> Nice!
>
> Then let me see how far I can push my luck.  For an unrelated debug tool
> I've decided to finally sit down and write a stack dumper for userspace.
> But before I start, maybe you have already created something like that
> and I can save the effort.

For ASan etc. LLVM's compiler-rt has its own stack unwinders so that won't =
help.

Perhaps libunwind is the right balance?
For C++ maybe https://github.com/abseil/abseil-cpp/blob/master/absl/debuggi=
ng/symbolize.h
could be useful?

-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM29k68CZXnS4mfzsdW3YJf5FdXBA3mZtuLcSQA7%2BEfTA%40mail.gmai=
l.com.
