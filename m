Return-Path: <kasan-dev+bncBC6LHPWNU4DBBM5R4OMAMGQE2PXILYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 584855B0BB9
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:45:25 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id q5-20020a056214194500b004a03466c568sf7782596qvk.19
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572724; cv=pass;
        d=google.com; s=arc-20160816;
        b=UzD6TJO7JCId7MA2M9sQpBwEUKKVaQ4RinhhBWg7kxOoP4dfeGOJzf7XBQOvMGdjWz
         le13OF6kiMESJj/+CP3Iqc0WCbqqW0iQrJcHtJEUTridwE6gEeyJGVbcY1Xde8vYuD7N
         kAlvuWKZ0WUZN117CCemk9ydemlW7Tk2lWCkniR91MAG31aAibW53K/ZvG269rki0A2J
         F8ZtxorxJsAwLvemCd7f/FtWMii2MrDGnaaQxR31alO78HWqsq86ZjmLsXWbwfPYZoPS
         MOPkhhY8iYQeOdzppBqYoRK5ZV5Ksc005J28TCgu66Li9+2+jb9isIqFSq57JhCzZMC+
         VkKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=rdQavjeT+BQG7JLaUzkaoisPmq66hq9wemGH1sUJ/qw=;
        b=P/n6Tm5jRJa27uChGKxAwxwNVdC9j1dqC1UTxtXDDiLybcxzo56VW/romBezdJxBCP
         VsaODRHr1eJcrUFdlKh4Y2GjDe7w1vZlXVAtFYogmOqMhHAHirpAF/DWf+afsTCKbhPe
         py88cBjV+RGczIrH6bHuvMgKlsgjXG+k65Bl0Uwdkz7M7wcM5jp79hOd2B+F4ZWqC7ok
         /uab2D+KPjwtYEO4SsgjK3qmy8/V7eis1jzf0F2S791DHijwH592QEpixTT0JwYTce1V
         xsqlYLBw7lYBEjnzS8FmasBrwaRCRXKgOSy4ok5YOu2zzH+Dvq9xEVbfNF3CYoTIEoZv
         DlyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iRBDHJm0;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date;
        bh=rdQavjeT+BQG7JLaUzkaoisPmq66hq9wemGH1sUJ/qw=;
        b=ehWcwetZkMUJ170jCBHzgJWyoBFEAqWAiGj9ny2nQfwnYqAUBNjwZkXh4h6Ojz9ich
         AFogC+Pe2NwWNfLJ3kErxkZgI3rqdi7OHaBLntd/JFb30Yyq12NM2DscIXnf1CoI0y4a
         G0T7o6xBlVtwmB6jiTuDRvzGPesT0Lc43Sh0LceQcKrXuu6DEoURz/bYSzhqttVTsePy
         DaeeuKxRVgQuh3VQ0gYKVxBuSga8zzTkxy5NQAqIY2LJQToyc681QgzEakuYURkML5n6
         V/aUx6D+CKiF44dmGFONqfEjiWWgLuFHJ+Y5cPs83TjMhBkdca7w+GCkdRQ6opSFMwGc
         QEjQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date;
        bh=rdQavjeT+BQG7JLaUzkaoisPmq66hq9wemGH1sUJ/qw=;
        b=LVD/Uu0WE+LmE4VJlaVtbOyHjfqE65BFH74n67T/V3qcaV/sQL1AmnOTn4iRvp1b2Q
         x0fAM4SSuUDX+tcxIXofcRQK5+JWy0RjlkmXThyVEOZiQExnpldS1cNt0hbLtDVI01co
         k3FD1SAi6zSC0Ntm5D+0uLo7G9KR6xucwFK30uyIFEFb67zWoZoYQ88owijTbT8nhuVz
         I0Fjol4cdzcURE7Bi3gTj19j+SmCFRcg+z8o5Eq9dGl8wqkdgRWqmceVNGZnOHhu/gLq
         TlzKyKVo/mhPKH91Pt4+usryhLBGX83H6eaQf9eIURGzkxf3DxEe8ApGYrPSI94cktfM
         jV1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=rdQavjeT+BQG7JLaUzkaoisPmq66hq9wemGH1sUJ/qw=;
        b=GAWlz7DW01RGi5xVPwTGKGlaFHrrMhEX4TECZtr3vv2qOGBkBT70T4dFFZpo2PlunE
         Q2WeYUab1JPfPhuC9Vu6mZkhTTZ3fUu4j6I6RYFQrT3Nps6gx/HyUfee9H8iGV02g66K
         v0glGftZsURxJJ6D4UeF1qNhrusHx5kHd0AFOohLvhiHxFvRfU/2YRCoHjBc4ximjMhW
         L2K5Tb6+7wPvKNEaDIajHZWUIAUUQ9vmOESGjFo3zA3grIvFQgco+P9GpISxrBKPEWT4
         8iKaSxSfeubmn7yoMr8pcr8lXhz3VPoH8b2ordv/pefo3Fu+Y0Vuxl5p1FygFKqkCNke
         yffw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Okcn9UYIpSzhxUJUGdCtzBTELVyJZWILhi+EQ/ZVrFUUMCL/2
	yKnOtdPF3x2VxcBVTCKbdCY=
X-Google-Smtp-Source: AA6agR5fMf/lJ3rAh4xQhod3vJ91cZ5ghYsqwlyYY2JGSqe/NG02OHvWyTJlU86RBVvkQBhmsGMLwg==
X-Received: by 2002:a05:622a:50c:b0:344:8b06:4e92 with SMTP id l12-20020a05622a050c00b003448b064e92mr4299150qtx.569.1662572724101;
        Wed, 07 Sep 2022 10:45:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:96:0:b0:342:f1c7:49fa with SMTP id c22-20020ac80096000000b00342f1c749fals12600097qtg.6.-pod-prod-gmail;
 Wed, 07 Sep 2022 10:45:23 -0700 (PDT)
X-Received: by 2002:a05:622a:4c7:b0:344:a02a:8ef with SMTP id q7-20020a05622a04c700b00344a02a08efmr4411678qtx.118.1662572723598;
        Wed, 07 Sep 2022 10:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572723; cv=none;
        d=google.com; s=arc-20160816;
        b=ojaOtRxoWna4Cm/LDEr4+u1y+Fh7kK2VAmAsjrhrVIZUv/qu9tZfrjl/bwiTwFISc9
         26coiDf1l4n/cTQ+4mpEuZR42hwwa1lnIqz9RsP4BAAnTE4UcH6Vg27V18nIKyUDtOW/
         O6lCshojpFHgn0VVeLxd/HIweFv0zs1b6J0ElofqG7o4TraEi66p0PS6fcV8SAVvJVGv
         hf4XJcFCcUYPAO4YLPxbyzgN9u90nEn0sqw3iOg9/QvAwA/mHjjvTzw7a24Xpl2GkE4z
         UhpRU3eCEdPsu0rOZs+QVTNtTq6igZQsZBksqHOOPOtsrCBE5+xSnehcaVnPujySOnFc
         V2Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=5TF/7Ge8AarupLQS/YY50TBrTd0spxW1v76SnBwcGAo=;
        b=xDpWLLwYR3tRT1I+Y8HaeywKABh62S6ESsKy+XelAa91gCZtSLAYpoMkvmHRsoMVsR
         pNoaNrmuJyWpQ2y9lm1VPLFhH7EQ8+NQFC8A9fdlIyuzN9Qs2y/8a2J+V/ccXSrTu91s
         Rl8id84gNBy5l8cDD3+jogAwD0XLQT90VvH/8pif28Rr+i8nu2RfyBsM9gDEzZAbu3qG
         RWSWhNF6tNlCazIqlxSd9tY5ALVfVb+ypIu/8eX4hAcOQDRiXotlTdE0Wq9ASnNNdBtk
         pNk7uZZGkK/Y/4kn50TxEj9OdCVYIB1dOHBo1+jC+BKjrxF9nPvd4VlEr7tiYObCFgJO
         x8lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iRBDHJm0;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id gd9-20020a05622a5c0900b00344e41c5e4bsi1003005qtb.5.2022.09.07.10.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id l5so11022004qtv.4
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:45:23 -0700 (PDT)
X-Received: by 2002:ac8:594a:0:b0:344:9e0e:cdc1 with SMTP id 10-20020ac8594a000000b003449e0ecdc1mr4411158qtz.144.1662572723386;
        Wed, 07 Sep 2022 10:45:23 -0700 (PDT)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id 73-20020a370b4c000000b006bb619a6a85sm14075841qkl.48.2022.09.07.10.45.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 10:45:22 -0700 (PDT)
Received: from compute2.internal (compute2.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 8DFC427C0054;
	Wed,  7 Sep 2022 13:45:22 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute2.internal (MEProxy); Wed, 07 Sep 2022 13:45:22 -0400
X-ME-Sender: <xms:stgYY3n5uO-BxZxO3jSOmW-0Y2vweT5QpkbrdOGD2oOSfVq64VGHzg>
    <xme:stgYY60KZ3OYLIWrKVCN5bs8-FFyetB_0AlC6KUYSE7m0Ek9akck5daFwcKAWiqxX
    6K5kzLoBiyGTPm5Wg>
X-ME-Received: <xmr:stgYY9pRU4vSM2YTk7D_eux6SftdT8vSQSl-sLf3Tg1BQmlMWhH7RaPYjsY>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvfedrfedttddguddujecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpeffhffvvefukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhq
    uhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrf
    grthhtvghrnhephedugfduffffteeutddvheeuveelvdfhleelieevtdeguefhgeeuveei
    udffiedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomh
    epsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedt
    ieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfh
    higihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:stgYY_kh3_N3Ad4NorsIKLTFeyQ4AteU7NOQ67MLPByzOQn49LHM4w>
    <xmx:stgYY13xVsoeBq_vu0DXKErcV5IKpht9NgV8MW11F9Y0d5nbi6Dxqw>
    <xmx:stgYY-vugOztKNY58mmD98DcRmfgM_PaTk4cNgWnQKuVfTIt7jAXqw>
    <xmx:stgYY_yy1Is6mgViGl2LK297ISntb9MZKXlHhhfa1R2GyGDkW2aPSA>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 7 Sep 2022 13:45:21 -0400 (EDT)
Date: Wed, 7 Sep 2022 10:44:03 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev
Subject: Re: [PATCH 2/2] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
Message-ID: <YxjYY6SJhp1PtZos@boqun-archlinux>
References: <20220907173903.2268161-1-elver@google.com>
 <20220907173903.2268161-2-elver@google.com>
 <YxjXwBXpejAP6zoy@boqun-archlinux>
 <CANpmjNN2cch+HDVUYLD27sF9E39RaFrCf++KN=ZZ7j0DH8VaDw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN2cch+HDVUYLD27sF9E39RaFrCf++KN=ZZ7j0DH8VaDw@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=iRBDHJm0;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82c
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Wed, Sep 07, 2022 at 07:43:32PM +0200, Marco Elver wrote:
> On Wed, 7 Sept 2022 at 19:42, Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > On Wed, Sep 07, 2022 at 07:39:03PM +0200, Marco Elver wrote:
> > > Adds KCSAN's volatile barrier instrumentation to objtool's uaccess
> >
> > Confused. Are things like "__tsan_volatile_read4" considered as
> > "barrier" for KCSAN?
> 
> No, it's what's emitted for READ_ONCE() and WRITE_ONCE().
> 

Thanks for clarification, then I guess better to remove the word
"barrier" in the commit log?

Regards,
Boqun

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxjYY6SJhp1PtZos%40boqun-archlinux.
