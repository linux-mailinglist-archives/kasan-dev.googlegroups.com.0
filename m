Return-Path: <kasan-dev+bncBAABBWXQYKSQMGQE6ZQ74YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C3F0752F8F
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 04:52:12 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-34630d33c79sf541565ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 19:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689303131; cv=pass;
        d=google.com; s=arc-20160816;
        b=djPtzcAB4IIjn7usnwspc2esSHvQNTzHD1lZ2nRHNgf1SdGr2bqdVQN1fLkq3/XGw1
         SMElbfjbwo81rZW273k3sC0dWxEZwTWP0r14ndjSNnRU/mQdbXiDb79tM9D7lF6sRgyK
         D12JgjJA5v0K2pJfMRH5yadMknOQ2CvQXCGumPS7GyG/i4XHZbi0lvEZvSlFHPbQuk0q
         e/vJarQZkkcVSwBHTj+3aiR9Uqub2wy3BLTp4rE07D4C0ywccQ4ZxsIw0xwNalTYo/an
         crznPCzAe2zXeykKl5bcUwIvZs5jHimChHcMv8DCpomWNKlDQHf7sTbzEqUa3nhSpcJc
         Ed/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=FtBuTO0RqksU1+UNzSVlDO96D4bXkKHN3x07n6gycVk=;
        fh=OjuHNQhFfQtzKPU9mzbP8HXMaJaNhoJjI4DeCQtBIuY=;
        b=l4PSa/a3MmPIE1uQMHhd8a89WCowQdhzw/2P7bedb8hL76ywy9jg0nmaHK7Q7ZXy1E
         f6e6ZLKY54yfUlSszFnzmxr5gx7gbtM23OLHNMAVuWW++h1QgPJSiGxJwwb93MIzYGBK
         rjcWD6if+ZbPwz1Bho3m/H4lyBT3CAfFOjRjfjrroqfYkEFrGs9BTiE5+Fihd50eyMwh
         4gHq6LTi/0dQrOx9bMT9JmWQ7dh06poHkql4H11gOA99IzKzEkEVZ3c/J4BcdVEPdt2G
         l8CdRxG/DXCtDyImUz90Zj7rrHQU2e5DZlMOkrihnP+Cu9WTbtx6KIvFxuT3+gwWOSGl
         WVYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HLRP6iBt;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689303131; x=1691895131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FtBuTO0RqksU1+UNzSVlDO96D4bXkKHN3x07n6gycVk=;
        b=LTJtdWoh+epnZEuoDd93etrRsjwrFk5sRzC5OARyfIhysJeDCV8PrLPgzawOfGxC94
         zDDKRRJ0BvcdfbOO+iTn7WHG2MDpuapz9ky5YudqHgvP/G8Fky1YgR8EYdj452Cc+WAR
         LioqdUo1SHhnyRq2tkBNdx0fvCdCpsfsE6x+pok10B3NgwBQ4u3aGQLe1hT+fafObwpY
         nKK6XyIv2/W8It2ulVBUw9WqP/7wafimaF1lNomxsWrk3m8668b632k3zKKAfi1w7/fA
         7TU1q+cxuBtXnDL/uqu8nzZYMiTLCq+FRdcXjF1jttzdkoH1y6q5cSXMepkBLoYI5jMm
         cdDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689303131; x=1691895131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FtBuTO0RqksU1+UNzSVlDO96D4bXkKHN3x07n6gycVk=;
        b=WdhFuQI8r1dabFy5k4MQP9Il5IM5Rdscrkg0vP9bHQ+7uepCeDgpWcb+uV5tNi2NhQ
         aPQfeBcOEwqACp1VHf2eK9MC/9u0Y4SVMEW1FIC4lH79d1I016SU8JrdtTekLrOxy7OJ
         cQbEaa8SoFCrIC8T9dj/JGET13F1lnuGR8eXdgJDF7w1PP2i25daslRrD2R/QJdRavTC
         GdfP1i9KZ+ixu4tw64MTb/5dNKxP8Lu00NS0qkrzyKel5sMzUw0nPmGiYEJPoZZFBLtO
         wxf+Lc7NOqsralKyVMdw820UVbjlkqlfJsz3To8LDLDRVP6tbV/Q3VKU7hRPAUqp0Urw
         tpkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYZoqNewxxhg8E6FP+AKX8riMhdJx/EEHJTQWnKrOT4q2s9hCzI
	crQ+NwJ8FSkjVId0ScLAvYo=
X-Google-Smtp-Source: APBJJlHZSFmfBOVdY7y6MJMZHwB1yGwsu+YVJQDor//UgQrmZUfHYENgWEX26xF3mFlHWQNbE2retw==
X-Received: by 2002:a92:c545:0:b0:348:48c3:27e with SMTP id a5-20020a92c545000000b0034848c3027emr74464ilj.2.1689303130833;
        Thu, 13 Jul 2023 19:52:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d07:b0:342:1e3b:783b with SMTP id
 i7-20020a056e021d0700b003421e3b783bls750503ila.1.-pod-prod-08-us; Thu, 13 Jul
 2023 19:52:10 -0700 (PDT)
X-Received: by 2002:a6b:da17:0:b0:783:5e20:768d with SMTP id x23-20020a6bda17000000b007835e20768dmr3705738iob.18.1689303130298;
        Thu, 13 Jul 2023 19:52:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689303130; cv=none;
        d=google.com; s=arc-20160816;
        b=fOmRo2yq+4deSjbmOepTYvT+cZ0n0mK2iaX/m81T0i1kPEk3zdp4m7uGh4BfQ2sMYY
         heP51hjM+RbGHjb+zxeuvz3bx3AZqGtNJ9IohFTY6S5OUdyLlLAWNmagMZyP1e1TBJ9M
         ZTvLJ005IbTouYQVj9w7Kl1Ve4DxjgcP7R8DQOPwhCfhQxklA+1U88qKQVbYoAWiwdCQ
         jcRrrQiPA6Sb5VXugjTk1kM6xxehXHVaEOTHiSOeyQh3EUTBXMQaSAqihxfxj0AwIWjM
         EV/1MfPWmelTzC/SvWenCxVHQZiB82wiPCWZ3tDlEHYDHM7R1FdmNt3EadRkuDCezUWF
         eaPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mpD1AKmF4xzmLvg+uOq6sPq080cy1bNjZJTqROi/dyA=;
        fh=OjuHNQhFfQtzKPU9mzbP8HXMaJaNhoJjI4DeCQtBIuY=;
        b=c+whorKfl1/rYGy28WPndHos66B7dq0FrdTwEYHVTlIyp8Ami5qok2Fdz6S8jDgvf0
         iMA3NH9Nip+wIA7fsAvZKdeytZWTi17NL4Xtop2xHfBYjMl1TtMzaYhnHjFFxOHI4Nvu
         ySAKaDEaSfsjGFLGRnZZiAO6qurPtIrnPMX0ILwI1sMC7QDCGlKXmyrYNJQTyxdI9x2w
         6ZQtii3PHk5l6YbgRXwjFp5IL602qZNp35eVDw+hs7LIVH18yIG2/yAAo+/NZI8eqFaA
         xl/Kb1gck2ZhTjOSuCe6iBXQH3W1Cb7xgMot76r9GN0IjpbYXGs/Ai8gP6/qKcjPwufh
         ZM/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HLRP6iBt;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id t71-20020a02544a000000b004290a6a5a08si759686jaa.1.2023.07.13.19.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Jul 2023 19:52:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DBCEF61BD1
	for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 02:52:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4A180C433C8
	for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 02:52:09 +0000 (UTC)
Received: by mail-ed1-f53.google.com with SMTP id 4fb4d7f45d1cf-51e99584a82so1748416a12.1
        for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 19:52:09 -0700 (PDT)
X-Received: by 2002:aa7:c60d:0:b0:51d:9195:400f with SMTP id
 h13-20020aa7c60d000000b0051d9195400fmr3345345edq.17.1689303127563; Thu, 13
 Jul 2023 19:52:07 -0700 (PDT)
MIME-Version: 1.0
References: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
In-Reply-To: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 14 Jul 2023 10:51:56 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7oegnkmDOUoUbf99jkqPFBxcDBxr5L_qefv1sQERE0vQ@mail.gmail.com>
Message-ID: <CAAhV-H7oegnkmDOUoUbf99jkqPFBxcDBxr5L_qefv1sQERE0vQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/2] LoongArch: Allow building with kcov coverage
To: Feiyang Chen <chenfeiyang@loongson.cn>
Cc: dvyukov@google.com, andreyknvl@gmail.com, corbet@lwn.net, 
	loongarch@lists.linux.dev, kasan-dev@googlegroups.com, 
	loongson-kernel@lists.loongnix.cn, chris.chenfeiyang@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HLRP6iBt;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Queued for loongarch-next, thanks.


Huacai

On Tue, Jul 11, 2023 at 3:11=E2=80=AFPM Feiyang Chen <chenfeiyang@loongson.=
cn> wrote:
>
> Provide kaslr_offset() and allow building with kcov.
>
> Feiyang Chen (2):
>   LoongArch: Provide kaslr_offset() to get kernel offset
>   LoongArch: Allow building with kcov coverage
>
>  Documentation/features/debug/kcov/arch-support.txt | 2 +-
>  arch/loongarch/Kconfig                             | 2 ++
>  arch/loongarch/include/asm/setup.h                 | 6 ++++++
>  arch/loongarch/vdso/Makefile                       | 2 ++
>  4 files changed, 11 insertions(+), 1 deletion(-)
>
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7oegnkmDOUoUbf99jkqPFBxcDBxr5L_qefv1sQERE0vQ%40mail.gmail.=
com.
