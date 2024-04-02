Return-Path: <kasan-dev+bncBDE6RCFOWIARBXWBV6YAMGQEP762B7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B858C895087
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Apr 2024 12:41:35 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3699565f54fsf25649615ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Apr 2024 03:41:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712054494; cv=pass;
        d=google.com; s=arc-20160816;
        b=PUjL9b9ucRkXC0ioP41gl+amVvppXs1gOOFqp4qITyeD3SN+x/U/2cGR7fQBZXYSBU
         VBTgU4hjQ6n+NbUYDQkvjbGut3I/TiQUEgvI7xjHKpAMbckmL7Np6m1Nuw4NP4YY8iau
         1QWN69DEwTP2J51XPnzHPbeS8y3WzNRCmj6i+8xA1foazf0ONa4b9rGBAy0X/Cj2BW7q
         AGgT0oLmLGSmsxek3eTYqlj70atCRtqQnzYopjPeSDLiRFs2BMvgWwQH69tcbuhxi5LX
         5qLGip2bRbqKo9nAOzzdioXSa8k/0eqfbhYbA26MEhOdXSuvTgrx2ebph6VHDGuGNdvR
         wWvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=LqDZG/MPtrhBTfsjVFkGMhUdr3ymDB8nARGfVBU2JX8=;
        fh=sZWa6yqUTzPkpa/yT2DZga3FVwaPdFMPnQ4OiXP+/3c=;
        b=RFt/lniRQTQjoN0b1pShWQU1/+OxtEfFPPm521g3RTH4IYUCt+6FnB8G1efp1GSneV
         PRPVfqKRQzhVXoiKpScIbQ9GTLr7XsrkCVKtf395AEMK3dS03OiCAV4aXhaE6whlGD9a
         OxB+4rWHYUTDp6jTJJaRT45s7wGPrewH50X0xYjiKMKoE8H7XV+S8o3RJKiF0n+hbC4N
         3sM8TXGiqWBm7pkRJj6J0XDGPBEyXg1t/ippv7sQ0GTj++qo1q2Z3EweZr0paMJzpYng
         l10J+MZtaQh7y7n/ISfGRISezsr3r6Ofch+pgHuyPh5yua7ye4QI7Idgl5z9yazfWo2D
         uIPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=vEqCOZNN;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712054494; x=1712659294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LqDZG/MPtrhBTfsjVFkGMhUdr3ymDB8nARGfVBU2JX8=;
        b=Lz6ZyG+kKeFMMdrb6yZYGtNGN9rE5/FxZ4aCfGnsv36dcZPsGmCcdNUdU+iwTyv0+3
         IuNhwP4BzdxG8GA9XouQl0scqOd8BsB3+iIbYgdacG6xV4J7qhPjUmnxlbLPsoMiMvgk
         RhR/I5NTSyEgXmftshqTP45UNdFZRfVyK22y62QmRMzHWS7UHoM2KwQsTfYscwc7vOij
         vepiWRnWy/e2eyLwdAqFlYBHnHQHvYw6iTlN0ITCmkE9S6irnnVGz/MwB7imPFym5KgR
         scI0PYDu4XMrw/6+IyY/5MzkiIorN6MAx7LL7wKaAAsjxNHUhhcPP/vDNtGE+d/IZm65
         dEZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712054494; x=1712659294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LqDZG/MPtrhBTfsjVFkGMhUdr3ymDB8nARGfVBU2JX8=;
        b=G7xJZA0D4+KBsjLG0h+EOQCd/RaFSwi1cvY/7LaWPwQqfGO7lHkODNiUSKvj+gngbC
         Xm6cK12yEUPnxolKigf7Ri8eoLHq3d4NgNC4Uyj/dqBAbRVl/gCOzG+iyx+5nfFIKtle
         yhL2n8u6oMH+xAVZUb1ka4HyVmgGKKW49PzkSwjUlvfBKcqZSakrD3pL/1MtAgfxfQJU
         RXcC4NyqmqZFqYGo2+6kRXxXGSPXRFe4BVJC3+V0APAdaV3898ZixkEymqcMKlGnQ6nE
         1CnXQ2mn61ZUl7cFuZDQSKCLSvLRN1sBrzG7pMB4NqgEKCCytdUP5MHQNbomOfAKeppi
         7qRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVRWhJDFkdvF06LVAzOWCYjNPWcIZ+/XdduYUXTzQjhM9f9Tk2FRDY0HtIJ71X4HAwVu4mKUyL9d18ce+jFqN3gDLVZBc8cPQ==
X-Gm-Message-State: AOJu0YzGVqwk5U0Od/geLZ2bMB6QWLG81zUoAjRvJuZ3+2HxgrzHHdB/
	4cPHAaurfw3pZaLjyY4hjn1ob2q9MIYIrPz5Treuo0567Vck87EB
X-Google-Smtp-Source: AGHT+IEILOo14tPkkgs6sNXMg8wqG6V6bKNcBiQEjEwnn2LR5n5eCui+sbQQzeNnzI2cDGrhVqsiOw==
X-Received: by 2002:a05:6e02:1fc3:b0:368:4def:9d57 with SMTP id dj3-20020a056e021fc300b003684def9d57mr13883984ilb.30.1712054494316;
        Tue, 02 Apr 2024 03:41:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13a1:b0:368:8295:6251 with SMTP id
 h1-20020a056e0213a100b0036882956251ls135966ilo.0.-pod-prod-04-us; Tue, 02 Apr
 2024 03:41:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUW5p7Tz9JiWcINp40x8HFzqt3SUGOay23CaFkYp0EQCJrZrcb7hHzwvv6RFRObvqjy2HmlP2QKvUHL3IVeyG1dWq14NzNegBI96A==
X-Received: by 2002:a05:6e02:1c0a:b0:368:7e16:d32c with SMTP id l10-20020a056e021c0a00b003687e16d32cmr15471855ilh.29.1712054491807;
        Tue, 02 Apr 2024 03:41:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712054491; cv=none;
        d=google.com; s=arc-20160816;
        b=DOpni1Stj8UDbrbr4Nhi/fSjx1RA+vnupi1uC6BpN7+leQoH5hhcjUglC/6Yehovqw
         j7vw9+dLJDNo8qzdZJDBbHOSFtM8lECKu01WGg+K/2QEFEe+T4pDfXxdzuTclwbrvoK/
         Tffi6DLZ8y5mDein1NPDDDyC0wsbS+a9ZuD1ZNNiYwZ+zo2v+xZ28sZt/8aY6T1HZH9b
         s1W0F3Vr4ehIuxpg5vMVqfZLqco/O2NPLLJ2z/p7hgq77RxC3LJwzjJnk4IHK2F53s40
         9kZrO61POo7Rt6rXadUD9WAptKoSo6J+1HK/sfeY/GlmidYp/W0vXWyRnpvj62Il0kn5
         p0JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ApXaBVn2XS6OYYCjGNp8YjyB5+PeDb/eSjzi35GKmCY=;
        fh=SBDCInSq8AQkl7vWwvAr98ayr8B/i++7P5FI/6wFpEU=;
        b=L0nmpv2f0IFfTmCubQXv9HIkk3q9FPz4o0YXShjFOOBAROoDmQGzeA9tFT8HAb7uoY
         JTn+PzE7npqAtLBgVFMhTtQKqbRYsUk8D24vQarI0EnTtwe+Nqu5DaB3N5r7Z1rDZuHk
         7vcpFJXwQ6n6tiOnJ5vmyNIT5lklBhsVdxae2BB5N/Dq9XS1yHo0I66w3XWBuCxtxus9
         5qFwJdCIzsCOxlpv8kzMUSu4LLYWgay4hXv/auZRpUxwgiR4SX3o6DwQBrPlW+oyUW+M
         sEavUgSBduO1FM83TUzagkAHogkbZcssNqS2RKrrI26mrTJ08PszN/BAAGckoDv0Wif0
         07OQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=vEqCOZNN;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id t36-20020a634624000000b005dc13d8277dsi948017pga.2.2024.04.02.03.41.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Apr 2024 03:41:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-dcc71031680so4537550276.2
        for <kasan-dev@googlegroups.com>; Tue, 02 Apr 2024 03:41:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyXgdJ6VN8tnh+EtS6Obh0HMqWSHLNPSDykXZd1cqUv9MOjdAl7MfkgO8IqZzuUu8bIuQBZCBiDDUblaTgveYqdutN8zkjGOk/fQ==
X-Received: by 2002:a25:16c4:0:b0:dcd:4d96:741f with SMTP id
 187-20020a2516c4000000b00dcd4d96741fmr10305474ybw.10.1712054491019; Tue, 02
 Apr 2024 03:41:31 -0700 (PDT)
MIME-Version: 1.0
References: <20231222022741.8223-1-boy.wu@mediatek.com> <6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel@mediatek.com>
 <Zghbkx67hKErqui2@shell.armlinux.org.uk>
In-Reply-To: <Zghbkx67hKErqui2@shell.armlinux.org.uk>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 2 Apr 2024 12:41:20 +0200
Message-ID: <CACRpkdaNtXDYOMbRbbsXb+frYa18+ErVWP966LFGt-GCXbL9iQ@mail.gmail.com>
Subject: Re: [PATCH] arm: kasan: clear stale stack poison
To: "Russell King (Oracle)" <linux@armlinux.org.uk>
Cc: =?UTF-8?B?Qm95IFd1ICjlkLPli4Poqrwp?= <Boy.Wu@mediatek.com>, 
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"angelogioacchino.delregno@collabora.com" <angelogioacchino.delregno@collabora.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=vEqCOZNN;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Sat, Mar 30, 2024 at 7:36=E2=80=AFPM Russell King (Oracle)
<linux@armlinux.org.uk> wrote:

> On Fri, Mar 29, 2024 at 03:17:39AM +0000, Boy Wu (=E5=90=B3=E5=8B=83=E8=
=AA=BC) wrote:
> > Hi Russell:
> >
> > Kingly ping
>
> I'm afraid I know nowt about KASAN. It was added to ARM32 by others.
> I've no idea whether this is correct or not. Can we get someone who
> knows KASAN to review this?

I rewrote the patches from Andrey, Abbot and Ard into the current form
and I tend to keep an eye on it, I can add a MAINTAINERS
entry for arch/arm/mm/kasan_init.c pointing to me and Andrey
so we (hopefully) get CC:ed on these patches. get_maintainer.pl
won't help in cases like this patch though :/

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkdaNtXDYOMbRbbsXb%2BfrYa18%2BErVWP966LFGt-GCXbL9iQ%40mail.gm=
ail.com.
