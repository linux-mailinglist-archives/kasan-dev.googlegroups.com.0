Return-Path: <kasan-dev+bncBC447XVYUEMRBUUXWGDAMGQEHIXIUVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 18ADA3AC508
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 09:31:31 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id w186-20020a1cdfc30000b02901ced88b501dsf2943144wmg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 00:31:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624001490; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVs7uugebeHq04YoFTlU0lXF3DRtr1vUyB21VFO6UvXFfZZi5CCNNrbJ9UzE6P+oO+
         w7iO3ELcKF2ZNQbdfSGTORVKaI8R/RozG75IBPxndtdWaScHGMiOPs1oJUnUqljVIKuv
         K/XQx7ZPD+dTxmOZK5piNugWnesnXmaEYx3ROJJOV84uL7PslMGFkvJNSmTHpvTW2zKi
         fXpUQ0OyZNCGmcnTkKuFYAkWY5UzK9J6k0CKBqhjoXmdS5wgFqPGeoG9SZdIKjzBGG3V
         C0KI/Vw7h5J8bwKHs3IU7CGLSJakrb/rHr3FNP2p296iD5EedxcH6laUgZPYMLv1l+Ro
         E+BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=1v3MpQXkUs8b+bjoNGg3hABBYhkQJPcXEiJ+7AQ//Pc=;
        b=WRizMdwH6vxjYt7Kans9ZGy4x5/w/8qunsbIwqzm49HBakHFrvTDHjM24Zwx8S83VQ
         3mUHT0LDDuhtXwTQ/3vbJ5MbM5+Rm7fEKTTmxr5zu+7npWa8sm2D0J65GFjU/qYSoDwA
         4c6hX/awTKcBzf5K2Pup3Xs0p8nykaI5tm+v3/p2H6exCZmigJuKWn7jHb+GmY+2dFqp
         2OJvhbroAB07vxwDEIUGPkBnRjiezvfc8Fv6/yejqBo84t8pkzV/vdSrGzyI1lhGSrl9
         hGViH3N5zyM8gX6BtZxYrJC2XJhHmlxKhmUQoeYj3/5XMhlTAG88IOzSmf1QyPVLeyQq
         Ouww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1v3MpQXkUs8b+bjoNGg3hABBYhkQJPcXEiJ+7AQ//Pc=;
        b=NOcxrBUgbYsassG7w6qg5EOtI4v05b633qOnVznQuirD3cO7b6EQBbavEKeyB3hQCz
         6i5TM81/XRkc+A19AmJp8YnM0J+FXy4gJ+Jhtkx5AZzOcE5RZRXUBv4CJNIYs+Z7zzs2
         wEoqo25FXGuPzL7+ChCfK4QtkclCpyhZmmDsJ3C9LbNxj1+/EuVz6Pt9IRVeWNxVcJvq
         QOCDdhB+swqlMAQ6nS6BYWecS/Pl8e8H20JH1bTBz+BI4kluf59O1EOqci5Ogz6xbs6A
         kl1H+CbKxDTM/0JsIwpbrNNp9kav8tLjJsjP9Zpf5e9oD6mPMCg3+nTUc2jyyyKAUVzV
         KgSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1v3MpQXkUs8b+bjoNGg3hABBYhkQJPcXEiJ+7AQ//Pc=;
        b=o4LKxmcWf3R3h3GhoKCyzunbVKi1qr0hSB+z/OGSNuXtYYb/e2K6iHSrkEpLggqJ+0
         4tcrD1RJIzklnLyirhKgy82hi+4EFxLo43b/UYser1qr4Sp/NrohGTgBxyfTctiLVVXp
         utlJXVcuss8Q1YASxaUDZBudW4fwXsh6vYrmh86Bjp2WgztMoyLzpLHnp5S1RF0FCgE3
         lp+BI7CvxH/IZCplNQ6fP9NaoSJJD3bsLXpF9eaJRzkT0hvtmzaSyKUh0DWJS3e/csSa
         kJYhDRvtZy1oNSFXaa5klEjtuTrCKkooGnfhFPIsO33uHnzqusQXYcRgGmNWUi1/T0mI
         x/vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GifPFMnL3+fROeHSyGzmdDPhJErsp7PW//+4GEzZ/bihN4Hbd
	LQLxGKGMHwx8Y96ql6gEv4M=
X-Google-Smtp-Source: ABdhPJy+ZYG56FhtYB3GFyV75k6bFxbn7kdcugvB5lCoSBC5yK7eqbrVZhwLCDZF+T0kTCvP+JmjMg==
X-Received: by 2002:a7b:c394:: with SMTP id s20mr10129218wmj.24.1624001490864;
        Fri, 18 Jun 2021 00:31:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d0e:: with SMTP id l14ls3987241wms.1.canary-gmail;
 Fri, 18 Jun 2021 00:31:30 -0700 (PDT)
X-Received: by 2002:a7b:c006:: with SMTP id c6mr9735025wmb.11.1624001490036;
        Fri, 18 Jun 2021 00:31:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624001490; cv=none;
        d=google.com; s=arc-20160816;
        b=cck5G1Mr0zkmmiRTronJqQRetdlWpDQn/JhvM2YMeZAecFNUjSi1Iv42JMGwKOHOoH
         vVHJjndIyg4cfa8cmVwIwcgy0PFVHzCOHxoIb95QW/lKlaVzmeCgw96spybUgqHl+nhm
         k+xAkQ8vmCZ4xC390DQq1Tfuen+zIi6vkJFkUBUP7XROl3JVbUGjWZ+C/tYtfDZEbKNy
         IM8vmkLI7kHKw0YI48DXWRTmkguHfq37VQ3LjSdsDUWruh/BTrPgUnX1Hg1ha55TqMqM
         1nMxPWiZJNV0MFRR3/SD8kCenGR1/ltQWNTkt0yAfE5hfjUEZei8WyeNPpqHhyGdPyk8
         DLVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=7Cvhw9eFqKZfVZk7WBURr6cmjiLbKeJqpRoXZRuJW/k=;
        b=oMSw/XriVt8mh9FCIzE8H9MOJ8M4QnUCoL+LrmBDo2CpT4OvC5uG0bTrGVKMmwh9Qz
         pS430gwfdeZTLNQm98xEljjBRWXqgAi4OjnVHbz+teJuQ50z3X2FpumLEcUkgHZSfRQ4
         Ri0xo94TiNXUHLp3sEmBBoPRInT67mc1C6kgq/rD8WILFREheKg9ckx9GdXBdSPdbcO9
         vxLjPFXLIK537vGIzQRiDZvz8TpbLJ+Da2kFYzjYAVZpng/FZnhRfRWoDRstRkJDwOAV
         wM74YYmYiNfanPhLQn5wqdQdhDrxT8T6m6JzsyBAd74lbELitXP5D1YV5pkdLFmRwol8
         oaYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay6-d.mail.gandi.net (relay6-d.mail.gandi.net. [217.70.183.198])
        by gmr-mx.google.com with ESMTPS id v4si424050wrg.2.2021.06.18.00.31.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 18 Jun 2021 00:31:30 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.198;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay6-d.mail.gandi.net (Postfix) with ESMTPSA id 50B66C0012;
	Fri, 18 Jun 2021 07:31:29 +0000 (UTC)
Subject: Re: BPF calls to modules?
From: Alex Ghiti <alex@ghiti.fr>
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Cc: Jisheng Zhang <jszhang@kernel.org>
References: <54bac02c-8c87-a194-c2bc-fdd9bb0959b7@ghiti.fr>
Message-ID: <ddcc4893-6152-9ecc-99ef-891bbce78aec@ghiti.fr>
Date: Fri, 18 Jun 2021 09:31:28 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <54bac02c-8c87-a194-c2bc-fdd9bb0959b7@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.198 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Sorry, I was thinking about a KASAN issue and sent this message to the=20
wrong mailing-list...

I send this message to the BPF mailing list, sorry again.

Alex

Le 18/06/2021 =C3=A0 09:27, Alex Ghiti a =C3=A9crit=C2=A0:
> Hi guys,
>=20
> First, pardon my ignorance regarding BPF, the following might be silly.
>=20
> We were wondering here=20
> https://patchwork.kernel.org/project/linux-riscv/patch/20210615004928.2d2=
7d2ac@xhacker/=20
> if BPF programs that now have the capability to call kernel functions=20
> (https://lwn.net/Articles/856005/) can also call modules function or=20
> vice-versa?
>=20
> The underlying important fact is that in riscv, we are limited to 2GB=20
> offset to call functions and that restricts where we can place modules=20
> and BPF regions wrt kernel (see Documentation/riscv/vm-layout.rst for=20
> the current possibly wrong layout).
>=20
> So should we make sure that modules and BPF lie in the same 2GB region?
>=20
> Thanks,
>=20
> Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ddcc4893-6152-9ecc-99ef-891bbce78aec%40ghiti.fr.
