Return-Path: <kasan-dev+bncBCMIZB7QWENRBKP5S6YQMGQE4X4IJ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A768AC401
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 08:07:39 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d855c0362bsf32427041fa.3
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Apr 2024 23:07:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713766058; cv=pass;
        d=google.com; s=arc-20160816;
        b=znkn8itRmREZo70YKcIW7xuOExwiNkrcOLTcxn1g+nrNGHCYnHYn1IHsz8aJHOEYVo
         Jky8WQq/+a1i051cBdDmA0BReKhNmxKBY+NLVPaitQqpHQu3MSol7oVeo/cB7FQmTLux
         XS5EKl0LyNGGy00fS0nDjW51jVKRkm0NJzliWR4jj2d7rcncQqrSsFqSMAOu38LJ0UX2
         ijEudVsZBw+QzEQgCq6Zk3zkeyACjo7ylRyriFCK9zn7RsoYAeoo2uTZYaGXXtcStet8
         e7BNVahV22qb2PYg1GdMOCVzAj4uFpTcKkvNSzvt39c5bI+L16gV34vGXpGGyOF7F4pT
         yOEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=m+TBdgZTLTOa31q46jFIm3tMBGeNU5f9vtkSo2jJtTQ=;
        fh=8ciL2ba0fZ8gPihkYjaotNe1DEKav+PRo5ryLEL3RoM=;
        b=IaSGMGH9yBPOauhng75EyINehHidpjaThSceiGGL1P4kmt49mU8vu8t7IqLhkxTsHl
         C/qufPq3ZKbYF2YjlNgerajG2jbQ3+eFqhZF17NwYFqO/f/tvSgIMIQKmzRsZ8dE5liF
         WL4QSMF9W0huXniI1wAZ2uzz6BczN7DZ50TJqElNWpBUXDbsih2C4pG/rektFKwyg9CG
         gTzNQdrpx0tciOiSk61HCfan2Iuxc6Y4r21N1n+Tl1NDWLlhH/Fl49G9j8yrWJAqFefZ
         Mcr8ET5yeTI1odUBpfn47LaLirUEYcU8bnKGj0DMn0UFp3xcGkMV0UfwfdZ4cw7AXYPj
         ghhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tEvTZgxA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713766058; x=1714370858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m+TBdgZTLTOa31q46jFIm3tMBGeNU5f9vtkSo2jJtTQ=;
        b=ChhtjILu3W18nVGsTeYEaNBJEZqvfoPwjjOzLyIGOgIIZf4Y1C1+kUE0DlNC4gGr60
         4lF/ZlGvjEfEd6/twdwjNrwAkrf6H6Htje2l569sALxW/jMFtbsKeGML+N3M9eLb6vdZ
         ea8Zv5lvv57yGYSu28Ry+vRFJhjznDfxTlpz8kNFf2OIktwmRA6+h7kg/DdkndldJum+
         HNY1BEWmSutQx+U1AjbQSSvTm5bPKdbp4Ar7jYrP5bNSqkJSLwJwXpNBF1hwVJHOsl0b
         ZZwMb/vmmQIVKyz5lc0tCEvQoMoIsq54CeOMNMolDKXSIWWoBVJw2LTHAwErBkunoYYR
         VSFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713766058; x=1714370858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m+TBdgZTLTOa31q46jFIm3tMBGeNU5f9vtkSo2jJtTQ=;
        b=nqe2blWcWgXS5N/Kg5n92NQ1BdYl7vO8RB8CA1sh8sIwCGQs4P/IdaTIu1BP4pO9nq
         5iY/wPu34IydWk6+yaeILRrAab9L1iVfuwPZaKed2fj0MqrMst5e1J5tRl62Qa6K5guw
         2Ew7JJ7aWcGHpk3Sh7h7DQnuUBkSdPW/wfl/DP4wnlBX/n0xp3cPCged2h786ieY3KXs
         FME6SkyH3QUfIlG8BLdCcV4MzY+21VFOF1P/QoR1+FjpWmWa03aFIG0dd5vywIxmoHnc
         qRRiYbKClbfgmuR2IjmjlOq+qH+0kM11McGPvizo06Nh3poAp3ZKJ0wm6it58tbsDSX4
         +Log==
X-Forwarded-Encrypted: i=2; AJvYcCXYWc3St/UjuyKrxJWXc0k9oFHoOi46cv+I5Ga+yjSK8V7USiqawTNRXvWZGek1B4Gmwq2aCndZmGD06Hw80oCsy7dDXMwCqg==
X-Gm-Message-State: AOJu0Yw5r+U3uQT0shjnReQWjZS0Dpt/qgbcC0fgtgd958WCo4EuRcxq
	HLSkCWw3hSkijaaI2lxiFilGADBbeEQjB1TY1ogfYWfojLBO/p4S
X-Google-Smtp-Source: AGHT+IGwYKpodx2Nk9W+cAFNd1s83S8bGmBT0PDiryJwIKZ0m37wL4owadygAHvY8NjI4RJWhR0Pew==
X-Received: by 2002:a2e:b3c9:0:b0:2d8:4637:4062 with SMTP id j9-20020a2eb3c9000000b002d846374062mr5884478lje.28.1713766057948;
        Sun, 21 Apr 2024 23:07:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b13:b0:418:f5e7:b642 with SMTP id
 5b1f17b1804b1-418fec2b90els15705215e9.0.-pod-prod-04-eu; Sun, 21 Apr 2024
 23:07:36 -0700 (PDT)
X-Received: by 2002:a5d:67ce:0:b0:343:ba6c:16e9 with SMTP id n14-20020a5d67ce000000b00343ba6c16e9mr5651463wrw.9.1713766056158;
        Sun, 21 Apr 2024 23:07:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713766056; cv=none;
        d=google.com; s=arc-20160816;
        b=bOpBYHDdHbgqMxopsiJNfeKnRobxz+tkY02s7PjCwekhDrqPzzGAW0SzftZcJhWQNK
         BZF9+9RuJXjoZe6QgPCF9U6qR4y+Zl/dUbDXg0gjmXD8ZEaszNComvhjMGO7o9rtwGkk
         ByQjYfYLzFUYX0hFvgUtB4tFHhJvOuitOqYip+gG2+AuB0RIydIklBpnBvAmL4GUBu53
         9UJB9MktyOKpLhS/0AOrCs3B3PBBgvIxcYghuOgItKm+d5/hro/fJSZRVSnSmTmOlScW
         7Og5VvUjApJMURo6vKGIadO1UWwZdnh4hEJ/StGyYcudGTpt54Q6Xxt74GwR/I7pZNyS
         ChGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pGSzCKv+4ecZJeN3OmWLsZ/ca4kRN45aIfuAzwO1g1c=;
        fh=5R0VdaN9D8Jivgoa6eNHW/VR4w17Yza8kJX2LNiR0Ig=;
        b=a/UFX610ewzU1SyI6xhNAT4eW9SGMn6Xl259lspkALXcuSEvQTSyqk4FD+FLDPBCI7
         2gAgx7vK1+tBzaJ2A93nKbb6w+UHA8S5HlVrhfNs+aViw5Cv8RLba0emEJBEIGKY+5bx
         iaNQwlecTN/hbr7HumlDFrlxVoNRfQeVHc3+ZiO8luXkVqlZF63t4zRu0TpZrawez16L
         pGHhrsBBi0hJNVXwvzsR8EYvL4af7Zx6GfNJqOH1B79Vao7y5QLxNw79i55mu7eGb1We
         LZV09ZokScNWG5qSlGdhiHqi7RvOxdWDEmKE21ngYdsRqopMF0Wm7iLGP3rCjKew9m6e
         X1yQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tEvTZgxA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id ee15-20020a056000210f00b00341c9bc6836si164838wrb.3.2024.04.21.23.07.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Apr 2024 23:07:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-51a1ff50480so4391e87.1
        for <kasan-dev@googlegroups.com>; Sun, 21 Apr 2024 23:07:36 -0700 (PDT)
X-Received: by 2002:ac2:4e8d:0:b0:51b:50ed:d56c with SMTP id
 o13-20020ac24e8d000000b0051b50edd56cmr26234lfr.1.1713766055113; Sun, 21 Apr
 2024 23:07:35 -0700 (PDT)
MIME-Version: 1.0
References: <202404191335.AA77AF68@keescook>
In-Reply-To: <202404191335.AA77AF68@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Apr 2024 08:06:00 +0200
Message-ID: <CACT4Y+Z2T+A2xwZ=MOVnoUewAxnTcQ3B4AcCKpsUyp2TFSX8Ng@mail.gmail.com>
Subject: Re: Weird crashes in kernel UBSAN handlers under Clang on i386
To: Kees Cook <keescook@chromium.org>
Cc: kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tEvTZgxA;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 19 Apr 2024 at 22:38, Kees Cook <keescook@chromium.org> wrote:
>
> Hi,
>
> I've found that Clang building i386 kernels seems to corrupt the handler
> data pointer. I'm not sure what's going on, as I'd expect syzbot to have
> seen this too (but I can't find any cases of it). I've documented in
> here:
>
> https://github.com/KSPP/linux/issues/350
>
> It seems to be present since at least Clang 17. Has anyone seen anything
> like this before?

Hi Kees,

We don't have any i386 instances on syzbot. We have an instance for
arm32, which still has some value for the world. Does anybody still
use i386 for anything real?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ2T%2BA2xwZ%3DMOVnoUewAxnTcQ3B4AcCKpsUyp2TFSX8Ng%40mail.gmail.com.
