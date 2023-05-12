Return-Path: <kasan-dev+bncBCYPXT7N6MFRBC6X7GRAMGQENOI6CGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D021700D27
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 18:38:36 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id a1e0cc1a2514c-780d1c6574csf37118332241.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 09:38:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683909515; cv=pass;
        d=google.com; s=arc-20160816;
        b=PNuQxEE6ScbWk8JRb2wtXucK36XCiMUw62MyBLLF/c+onZX9+86NLEu1mgdqPNKZV5
         XBa/qAfNDaAkmENXdniz6sdj9020oAmbKiRGp9m2lHLTLI883cW71ZJjZN+foqlUfcwJ
         tdoz7/fifaJsJc+YZBcbnocNFxOfVBVI4VSs9uNL38s6ES1dKsi+t+LOcXR5NCJiRfyP
         HHzL4+G9J/+CT0ZXdsNH2bPjIueHn92Pm4I4OdK0OoWBCKTwjXIjsTJtosIH0gFEZ4lU
         raNrwpIZifLtDxN809uIQmN9Fj00zF4B1Cx3V4I7gVGWicA9kOcLWqIqiED/X2oV9W20
         JwYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0lqzuwKyZkybammiPS2i5q4U6YLhdLt38f6fjHoBMOU=;
        b=gnf7YGX1l7eJyxh5+qXRt1+AvwD7u7HlL4kNQvBABP2SBfLFZgeBCjj115uld2gjmQ
         OsxASiASwVGU5COLt0Yo7eDpOShknmw1JQDZpDDW2joj4QNVm/892nBO3dksy6aQYmqG
         blSMgeMhU6BRVI6egK3adAah5trkBAHpxw1hYrCC3jCQD7MbW1vxRTlibKHBImhE6wxR
         qJz9qLgimUow3yhR1YR4a34bb+zUgVU0Ee6E569z1R+XyUl+R9cKgoLQRlBqRkf4P5IS
         TM9JiRPI5q6RhM3MV72X/L9RCZKLyAjPBDJV+6IoltzAsRtgnNbEiOT/RZVbq4mRRRHN
         Cxzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=rtNlldms;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683909515; x=1686501515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0lqzuwKyZkybammiPS2i5q4U6YLhdLt38f6fjHoBMOU=;
        b=gzr6VnivshlUn8HzgCYzkTkKwEe7/vLrQaoUFVZw2b4QP13Fl5zTUl7SFFOifj9R/9
         SIyiRsjwyIcFQCTdNGrz5iGYVVPmG3RO6X4/kcdhXzqgYRWVNXTgoRKF+azO1jjiYxKQ
         nrMqYKUZZ+IzQGQgA1okOLQU93kUrmZ9WtM5HvVWHijU+5R2cekim7kDz7FYCju8P2mq
         G+3+cxzkBK+lL1Cu551LGJi7xJ8QvSYI0V4k/KRUv/Z6hTm6Ohm9fhehkJcbXNW+NsnB
         asc5CAEHsOEcHpQvaT7Y4mVOqzffSrG/ipSNCN+/Ul9LNU2vJy+nLGxXIRID+eG/Vzcy
         c25g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683909515; x=1686501515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0lqzuwKyZkybammiPS2i5q4U6YLhdLt38f6fjHoBMOU=;
        b=ALYe5O7OzeZDL1dic+NLyXHs+rnZYsK4RV8q+6/JE+ZIykSE4FSHQXbeO36h8cN8jC
         L7dr4To64znMqilMmbdcSlyvPDipFhF3BCdywEHoQZeZp1YhB5m+mUurSNwMWWscVnnU
         jDppZki7Q8VhNkcfDwzU3P9V+Iu2g5MD8LnINlcKe5EA8B6Km4EzIn7g3Sv0JSpd2PaP
         yNEM4A2DBptDkOckFuVSPchEhZn/CbvZA1k/FCt6GbAacWXFgJvBZJzS6VSgCDBeTB1T
         gTjgNPJdrj2f4HUAUmc73Lq1Rroe1LoXs0+P9/EqJs1DdPUtU5aaXWRhhmZLwdhP8NFi
         0K9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683909515; x=1686501515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0lqzuwKyZkybammiPS2i5q4U6YLhdLt38f6fjHoBMOU=;
        b=D/0uB6mqpVqn4NWLF7URWn81g+fGX/BtAetx2NSszaljpnf+OcdDvvWeyNqY+kyNbj
         gQSaS5B5v4DTRoNv7h51lNKwCZZWa+11EhCHclpzFtdbpM9bjPgokShZjv8YK0wl0cww
         +Efo/DfdQJHlPkHmOZ9uJR6CTKtCQY/RREluzfmfMePARUDnqx5b46RZRrICp+44Rz2G
         8vi9uTZtL0B+vPp5dx4G6eErG4SzVkOhTIpcsGck0V0TrWdyfufUcrJ8wmzMhBiVUHkf
         2ZrSE9hy3TDE0Tbxc/6hgA/8QqQ58zZjRwydfEEjGsfsOM6EbsjvpBigIZx5H7F3o+oX
         jU2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDysmTYOBJqsGQQjDCtAB4iK04MmYVF5kHwP2z5zYsJEzWo1eLpv
	iQOKvZihEWksc4NjdgSh17c=
X-Google-Smtp-Source: ACHHUZ59V73BrObICEh7B238jLA5FXltBCeSUROv8RdueBt7XJFJRFj6imfH4CeB5c78KXswr3yy3g==
X-Received: by 2002:ab0:5605:0:b0:73f:f15b:d9e3 with SMTP id y5-20020ab05605000000b0073ff15bd9e3mr14599103uaa.0.1683909515173;
        Fri, 12 May 2023 09:38:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:e11:b0:430:362:2d2b with SMTP id
 o17-20020a0561020e1100b0043003622d2bls10026372vst.6.-pod-prod-gmail; Fri, 12
 May 2023 09:38:34 -0700 (PDT)
X-Received: by 2002:a05:6102:e0f:b0:42c:66ea:7ea4 with SMTP id o15-20020a0561020e0f00b0042c66ea7ea4mr10231688vst.15.1683909514484;
        Fri, 12 May 2023 09:38:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683909514; cv=none;
        d=google.com; s=arc-20160816;
        b=bQCpui6iZh4mEw3X4F3jikvqYc6Y1DQDH/U3M04bHwqLl6G3dMf12IvP+iDEG2kjH1
         mIxPhgUTOz1nUV6bG6xdhLuXBgBzSOgemxDlI8KoVrSG3lfNBKcjKCb0aSXQnC4348Et
         vtBFtMpmFwlRx7kcPA9G1SkyOGCoaxQRsGP6HPdL0UcY2EW4JzvLxqSNYfao5lPXikW7
         QhLdUKo6FxYYDUpebgJo7QCwMJKxe6pwQoiTg2FPrmI4kErp85qjPIrsMpQhCSfWUDGT
         AoJB++7XcNt0Pn41t2IYeE8TIYW0Maw4LeHeRM5UP4c4niqOjuVMVe9wFRAsDJj6hxYm
         q58w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DI3VClWXDuKTFGWdg3vQHVn8mYYEQYaV3Uoj0tZUhr8=;
        b=RvxaEmNBzTh/XDf1qvqyLjXpZUjf9pfSvRcOVckTrXdKKonM6sM3zGFlzFlQs0Pe6w
         wHCYxq14gfKLMTbiNBMF9qZCjmWxlSsvgRg6OPVsBOaWrpLhENdkGtcngKZlDFUcN34L
         72mHxadLVzN61COPUaTivVnCvvGQQZqv6QnFBAtiLbOhdEoZpFNtz+Se3BSk3D3i5B0S
         TxhZpzxvLiuukyIG70qBOBlCbEAg8tSlrS7ZdhGknobkSiHkiAo5/N4UwGrPHkSo8fvF
         pAUKSNethXbuvBJOHBxrCxazfJT6KNWhhBBXa+CcBXkqiuCo8MKFM9KRCOKcFyqwXoIV
         sGzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=rtNlldms;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id a33-20020ab03ca1000000b007836a48d143si449268uax.1.2023.05.12.09.38.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 09:38:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-64ab2a37812so6107685b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 09:38:34 -0700 (PDT)
X-Received: by 2002:a17:90a:9f87:b0:24e:201e:dcbd with SMTP id
 o7-20020a17090a9f8700b0024e201edcbdmr30692013pjp.21.1683909513955; Fri, 12
 May 2023 09:38:33 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1683892665.git.christophe.leroy@csgroup.eu> <a6834980e58c5e2cdf25b3db061f34975de46437.1683892665.git.christophe.leroy@csgroup.eu>
In-Reply-To: <a6834980e58c5e2cdf25b3db061f34975de46437.1683892665.git.christophe.leroy@csgroup.eu>
From: Max Filippov <jcmvbkbc@gmail.com>
Date: Fri, 12 May 2023 09:38:21 -0700
Message-ID: <CAMo8BfLYp6yKC6o8Z8qSYQq3BhBmHfQ32F_ShsgqRbfVepkv1g@mail.gmail.com>
Subject: Re: [PATCH 3/3] xtensa: Remove 64 bits atomic builtins stubs
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Nicholas Piggin <npiggin@gmail.com>, Chris Zankel <chris@zankel.net>, linux-kernel@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	Rohan McLure <rmclure@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=rtNlldms;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;       dmarc=pass
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

On Fri, May 12, 2023 at 8:31=E2=80=AFAM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> The stubs were provided by commit 725aea873261 ("xtensa: enable KCSAN")
> to make linker happy allthought they are not meant to be used at all.
>
> KCSAN core has been fixed to not require them anymore on
> 32 bits architectures.
>
> Then they can be removed.
>
> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> ---
>  arch/xtensa/lib/Makefile      |  2 --
>  arch/xtensa/lib/kcsan-stubs.c | 54 -----------------------------------
>  2 files changed, 56 deletions(-)
>  delete mode 100644 arch/xtensa/lib/kcsan-stubs.c

Acked-by: Max Filippov <jcmvbkbc@gmail.com>

--=20
Thanks.
-- Max

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMo8BfLYp6yKC6o8Z8qSYQq3BhBmHfQ32F_ShsgqRbfVepkv1g%40mail.gmail.=
com.
