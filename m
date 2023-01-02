Return-Path: <kasan-dev+bncBCYPXT7N6MFRBRMZZSOQMGQEYQJQVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 28B6665B566
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Jan 2023 17:56:39 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id b14-20020a170903228e00b00192a8ae9df5sf6538738plh.7
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Jan 2023 08:56:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672678597; cv=pass;
        d=google.com; s=arc-20160816;
        b=gy16hDnsoGW5TeivPIlEVTiNgTeXqpmNjGZJCTHSZ516yNntkyChTb/atSqwn/7TxL
         XVmCq6IViCmuHuefBo2SWLkx7ncNIy90pLSK13ikLPDFMRxM4ZoHGUvjf5HS7VnMLmM0
         SRgsK+Cc2/WHMY/J1oENtlwnePt0C/sxiKhRyY2LsiDl8gHqs7d0/oDhBjRTIXM70P7M
         49M0pTOXLP5wTwJs8/brU7+PmI3rFsRQwlMzfCie/6qUvFdBKbJYb42zKwXRVR+7WEfn
         EZf2ynBHhEHAyeXTH6VzXqhsfPwjDpRO8jLDAQ0HAktxyxaJ5eQynbNpa2SOg+T+KcLp
         Zjhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=icsYsw1B8SrTgILYdYE6jiZSZQd/5ntuVV3nIoFR86Q=;
        b=glgImw66zEsS7feTm/FuVs9sx/jKfl/CXOlhED8NNmWTt9Wf3B+MM2ReD53jhXH5he
         UC0yA/7luQaAl19gA3b+vD4J7fFyrp1VXLgdOQfI6CkeKNzHwqa+MH+c4gR8NR4TRwPo
         nSEFfx5BhwGRQIoSrvj0vfrN+wVLxNcB7mPekZfwIX6JqgpsLJc5lrI2dZD9WZxy4Cp4
         BDr7UCsXSV0tB3S6tkibCJkj9PScdmtawwCiaDqkQ7MGpyNpAtX9FdESpEABys9v7wgA
         euBw5FuZDMsuLsCTtL569wxikv7kH7n0P5CBxhtv4Qu4o84wV8cMKBmTkSXVksquUvjC
         bKDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qR9odOqK;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=icsYsw1B8SrTgILYdYE6jiZSZQd/5ntuVV3nIoFR86Q=;
        b=sDX3QO0t5B7m9xjvk1tpamnzLqtN6yHdzsDMTENgVQyutM3oMkBg7qy4Q/7+bjcXmF
         gqhWJzn1VkmF69QbQLh4WgW4a4D5N3KlDeIm+58Wa/fdptoTsYmZ/7UIs0sHoCrZEIM/
         t8ijSISAbpqUd6vWfdGribd13EFrGFsn4ZhQK7pSVCALN3GwmTvl/TYetG6I39EvVY93
         MK7Nx1NtX17PyIMPBXWbc2vn+K1zerxXomCzg2sYbhmYtJwc9Zt2pNu7TtKjxWrP5G42
         5LCjVubEQ+m21azcBWuzqeTt/aNTNxWqZmT6qRLS29S7/YyTPJKzSFYH4GEqyLcv5TGk
         8/vA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=icsYsw1B8SrTgILYdYE6jiZSZQd/5ntuVV3nIoFR86Q=;
        b=FtuCLaaXT7O3FSmNI8vsvYtn40tNQE64nrlCPuiN67Y0ABZETzHnZncU0S/vyUDAPp
         UEZhwpCKxKajbPqBVBj/z0pZNdfwME2fgNDIttR7thnM0Cjxkr3BidEVpIFw2H+IDMvG
         oBfmstqeCU9aDmU0WI/QF2TqV4V6n6hk3vc2nyhirHsEKmuGrkWMoPeei5k5Bi0M1x+4
         P6TycYsySy7Q525yeYuuAXWHFrkeawnAnEkmMUhf9b7HGpLGARMhn5CeFy/cJgwEfJs1
         /ubDRixerD5FI2Jhj+l1RuLeNaXI2bsrCFRONb93GekvZiOVFRnIVLuYEWNKxZkVz1jS
         iuXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=icsYsw1B8SrTgILYdYE6jiZSZQd/5ntuVV3nIoFR86Q=;
        b=A3e3OdQJ+s4vKbp5NnWpOLiSq8TCXIf8P+GlbTw8JsrQxv2gmg6jWuuhVGwSBN3+Gr
         wPuik9YR6AOsLK09VPKpgTxnkbPzgLT2MixtZUETW2dUiW/lTRkfh8/r2iE37ke68d7s
         MhrSeya5nbYpuGbCyxVoz9QR3tHlFSZdxOQfY/iawfaDyqxI3Uy+qsBQohXnRx7Bg5GK
         F3jxqJWoGgEWXqmrZXboYfJ0htGlIDgzcxBXoEiTHNL0DjC6cgD8PMWyMHF3AoWPFN3b
         f8deMg3mzoeXaoRcIiWGDXgmC7vcFZAmF/6BzV0GwSHv2dx6ORodDsCvOqmkisNp6as9
         U9Rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqOGT4yszEf5xzzoHqcfjKfgtC8WkczZssB5NaoGQadygeb5Avl
	p7kKGKTzNrUune/nnnChvNE=
X-Google-Smtp-Source: AMrXdXsk4tPr7PEAlwJzIfcJJp7bviLEF6nAdGHp2MWPZtlkNF7F1HVjC8zu0RO8UNNAffVzg2HKJQ==
X-Received: by 2002:a17:90b:264e:b0:225:c362:738b with SMTP id pa14-20020a17090b264e00b00225c362738bmr2970873pjb.237.1672678597269;
        Mon, 02 Jan 2023 08:56:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e0d4:b0:178:5938:29de with SMTP id
 e20-20020a170902e0d400b00178593829dels29435163pla.2.-pod-prod-gmail; Mon, 02
 Jan 2023 08:56:36 -0800 (PST)
X-Received: by 2002:a17:90b:2412:b0:212:de1a:3559 with SMTP id nr18-20020a17090b241200b00212de1a3559mr50349541pjb.8.1672678596556;
        Mon, 02 Jan 2023 08:56:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672678596; cv=none;
        d=google.com; s=arc-20160816;
        b=vA0QGcMBD8MIySkO0YGx/IFfp+uTPc2gMo0s57ESm9aGVeKZ9LWHz9cNT0WVJFpn8c
         TTiXIZDQVhjhlOV9MWnkh1qHX0VvbN3t+Tu7dsa4ag/yx2iIrzqUDBhaJX1tKHhWu8+t
         RRov7ImF2GMkd7NB90C4dXqTDhxgCMcQe+9Fu+qUWcadqqseJq3jF7NSRf1mp4rNiG76
         haQ2NSPIKgtTOyTB4Aa4uZmofordJTx72DFWxH6tTYPoprclawMmfi+aFxAVnuE2YsAs
         wcVZ4mNZr4yQ7cEujako6HF+yxvih554r+TRgofNRzlNUd2jzeSI5qOV0UrLUA0KjYu+
         fbEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wKUflxNaDzEkyY/mzA+LlW6n4mjVpXQBQ+O9ORYw2l8=;
        b=ZnhWSBNflym+1WrEEfNFQnAvEkK5k3dKVx/AWhIA0a3/pdRELRc0deY4+QZwxNdIua
         xKX92E1DbULUZU8ko+1QN/ARMLcbBJkkdjfKTbZyw+9ydLR0oZ9uUz3c+gAOkNQIIPb1
         Ln1g7cftGBjGWHOMDLStCtugSg1Sv/yPt/3ggKWityB8rnIejuDLeo22YMHvLHWVtsRt
         vilVKfp6P3Cbi2vPLmSfJFsU6cIYKmR4SVUKPvd2WjeE3E2VKqXIqZnYlTIp4KcSIb6s
         BJhbJIgXTrLTzzN00wfyhPKLHdLTFbPvCYdhdA2CziMlHexnlfNt2xNr9QgSTWL0BMyZ
         vkjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qR9odOqK;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id x2-20020a17090a9dc200b00225a3067b07si1828008pjv.2.2023.01.02.08.56.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Jan 2023 08:56:36 -0800 (PST)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id 83so29848893yba.11
        for <kasan-dev@googlegroups.com>; Mon, 02 Jan 2023 08:56:36 -0800 (PST)
X-Received: by 2002:a25:4c81:0:b0:6f9:ece2:7b87 with SMTP id
 z123-20020a254c81000000b006f9ece27b87mr4712634yba.485.1672678595897; Mon, 02
 Jan 2023 08:56:35 -0800 (PST)
MIME-Version: 1.0
References: <20221231004514.317809-1-jcmvbkbc@gmail.com> <CANpmjNNPTT+K3CRZN+RnUbHwmtUUzqb0ZDP=M6e8PHP0=qp=Ag@mail.gmail.com>
In-Reply-To: <CANpmjNNPTT+K3CRZN+RnUbHwmtUUzqb0ZDP=M6e8PHP0=qp=Ag@mail.gmail.com>
From: Max Filippov <jcmvbkbc@gmail.com>
Date: Mon, 2 Jan 2023 08:56:24 -0800
Message-ID: <CAMo8BfJRb3aqkd6sdeT5DsDQAgZP4BBHCQgToCfN+Fxj6s-NuA@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: test: don't put the expect array on the stack
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-xtensa@linux-xtensa.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qR9odOqK;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::b30
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

On Sun, Jan 1, 2023 at 11:00 PM Marco Elver <elver@google.com> wrote:
>
> On Sat, 31 Dec 2022 at 01:45, Max Filippov <jcmvbkbc@gmail.com> wrote:
> >
> > Size of the 'expect' array in the __report_matches is 1536 bytes, which
> > is exactly the default frame size warning limit of the xtensa
> > architecture.
> > As a result allmodconfig xtensa kernel builds with the gcc that does not
> > support the compiler plugins (which otherwise would push the said
> > warning limit to 2K) fail with the following message:
> >
> >   kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
> >     is larger than 1536 bytes
> >
> > Fix it by dynamically alocating the 'expect' array.
> >
> > Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
> Tested-by: Marco Elver <elver@google.com>
>
> Can you take this through the xtensa tree?

Sure. Thanks for your review and testing.

-- Max

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMo8BfJRb3aqkd6sdeT5DsDQAgZP4BBHCQgToCfN%2BFxj6s-NuA%40mail.gmail.com.
