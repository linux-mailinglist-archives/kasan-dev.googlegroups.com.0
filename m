Return-Path: <kasan-dev+bncBC447XVYUEMRBCHU4OAAMGQE56XLW6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 049A830B857
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 08:06:49 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id n25sf9531597ejd.5
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 23:06:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612249608; cv=pass;
        d=google.com; s=arc-20160816;
        b=quiMrHBCZC8XKXA8MslfNVY4nsmBwDpTwjS5W9b+3fAznw+LHlR+IrMdbaSsKIejm4
         UgSvnLEWgNO9npJ+ca2JT3U0kgYf2tLxsOuabC1wzFxHxgbVxv5ezsAbKrdaNLlwOXBh
         RXJy6TWlQgKCR8Ng3JkTCvR41fBrX4cRtLpiAj0uU5G9AzANfiodWcFL/bgFs3l7zqif
         7RwAKxfVB01OjJriTXga1P+E/cVQsHwzWCqOBOZogQyb+3Caa0IfvwePfBGRbQDwzeAf
         5FL6kpQGDVX0CSFqSqtCPrL0TCa8ab3E+aVUjnJxTk8OPgBAB9RLamfkUL346I3k+Zoz
         lB7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=wgsGgYMW0rFsLl3WuERhAE+bprwUlHM/tV1YOYtLu5g=;
        b=dKj0yAwyldg/qy4/HHKWpOiEmwGY8uCPS4InbQ+sTErfR/CY8KbpXiEHvstTQHzSfx
         biBxp/iiO9je8XS8M6z9TTse6HUIucrFlkLZQsXn6RKPz4xEY79j24RbMwCGdwPTk9Az
         7cIVR/BiaobiJWNqjntepGrAy3NkNcNAbgqbJ8/VpzCk+TkS29GzkXQi6T2iVSzJ0qah
         H+sWzt2kmuFjGFYmGtn5W8Bykap2HTikrwWL+49GDZsemtPFAbgjeGa4CnUC3g5QFjAJ
         6Tb1KaKU7Duxsez7TAq0GKLA5QvMR0B8pWBCebzPr3AvlrsP4qSfQFxub1VKoLewT4Qh
         tfHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wgsGgYMW0rFsLl3WuERhAE+bprwUlHM/tV1YOYtLu5g=;
        b=dzOmjrf55+vUrybp6LhMmRDBwH0HMjLy1nJVrl0QnC1MBEu4LkADPAQ5Th3F3LLeCx
         nre0oxR85f7P5/qXZlOkZ+RrTCeynTn2mE/ZDnKNFLvnUmH+TEGm1dTbG/wJCbI4Suxp
         Da5XWt9J8NxVPcxyYUG0Rv+TdJzS5g1Y5Ropqlim9WsAO+x7WE4R2KGunTvuszGXFB4X
         UU9/iHOTP+IVPYtosjUa2DDPuRZhH0oIxdOq56bv8ubeaCEcArjD75DWXq6w4Cl++sKf
         IR0YWzcUnJMcojhWSW0qRzkcPdzYYjZq4pt3y1dz5SxgoL9dfELzVAkmVA2991E54faU
         Tg5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wgsGgYMW0rFsLl3WuERhAE+bprwUlHM/tV1YOYtLu5g=;
        b=FjJpJLfCkO7Nanc/d+MZflq3jaC0J3tQUpe/bPqUZzrk3fQa0W+NrnccuOo7cNj54C
         +kosmrNtKIx4YhbGM9OD1XHhqVHA7n6vs64OsC8DUb1Mt3Nb2C/TIgmojjp5imkNfMv3
         4xOH0IIx0uChd50bwc5fYw4OaXqka4YAa7iKs66SxW0CcPbKzrlz+faE1NSYdbWpSE8K
         V8xM++Yn1BBFP1ct2ZOkFn2zTmrtny/1BCNeVCqnfNyvsUs9CtPvk2kBJsksx4aWuN0l
         kds95HjangDmOg0zBaTospVEBDG74sogeC902ZEYl3yQOdIuIT6QtAsbrOUDiG8hPTus
         0pWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kYnJeG+DnsaFq+whViUkV/f5DTBjyheeDytYdDfRcWkN/yesm
	QGGJVHjOytnhP+epbO9QHj0=
X-Google-Smtp-Source: ABdhPJxNeUSU+2xlbMvJEbmL+sXGdLh/2ryXIaqy+ppGrU0crJ0HUL0K6dutGG4vzVarQ5EHayXe+Q==
X-Received: by 2002:a17:906:f0d0:: with SMTP id dk16mr5750798ejb.533.1612249608804;
        Mon, 01 Feb 2021 23:06:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:e8e:: with SMTP id ho14ls596078ejc.3.gmail; Mon, 01
 Feb 2021 23:06:48 -0800 (PST)
X-Received: by 2002:a17:906:1d0f:: with SMTP id n15mr20252439ejh.26.1612249607960;
        Mon, 01 Feb 2021 23:06:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612249607; cv=none;
        d=google.com; s=arc-20160816;
        b=aoSQ4VIEP700xFsMLl4KgCE1sL77BvkLSD0KDJGjH/l/bxMZZUKAWPTy5rxlFTGuXp
         +BRYLvhEI/nNdIiTJmwnfNGRIlkhNu6x0Ig9JFV5P8N0Aewu9z0CaWZi2KCcxTk05sLJ
         mkVHGsxdxgvCy++ME47mgVqomXcBAASPnRfiVDMALX4b7PR4nCWD35zuM6FnOp9rNnfF
         7cJ1qGIQUzeW/SPdX7n+1KPkgDUNxvHFiogRfH8OumEcjoi683oK6C4Ozoic9vYcQfXx
         HVBMQEpiF5NtdOElMVU/qMb3AWx2gOeq2nstOdP4BYik4ZxYUBw0Iw7SPICatsWMjMUP
         ExDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=TTylvedrxZz0fYRFe3cvucZLUep1O7J4SLvFlFI1C8U=;
        b=HPbt/EArD51QSFNjSuKQ9fH0sk/j1s0j0ybx+WeSn63zIGwPGuWvhtkhBEJfSqXeSd
         /QuT9ZykKEfWisr8Y8LG14s+AbERLL5LBF1bbSE1QRFhxG5oa8y5k3tqBzZ1BstDCdum
         9plT6ySSjkji2nDmYRec4wO5XFd/fhNw/iIdCbQPhNK+b7/FVLgWCB5uV+INQL9rbfQ2
         bS17J7MnKhWjFu2h5K9hLDTACXRrwbkeGXHw7MfVGMZPpDZmnfY8ODqRrCA4KRaQPQRe
         6HCHfgM/12B3uxluBsKKhe9pYUVXTgTUgsdlD2qP+OpZMkEBLhPK4cfkWatRoq6K6OqM
         5J4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [217.70.183.195])
        by gmr-mx.google.com with ESMTPS id dm8si820412edb.5.2021.02.01.23.06.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 01 Feb 2021 23:06:47 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.195;
X-Originating-IP: 82.65.183.113
Received: from [172.16.5.113] (82-65-183-113.subs.proxad.net [82.65.183.113])
	(Authenticated sender: alex@ghiti.fr)
	by relay3-d.mail.gandi.net (Postfix) with ESMTPSA id 773666000A;
	Tue,  2 Feb 2021 07:06:44 +0000 (UTC)
Subject: Re: [PATCH] riscv: kasan: remove unneeded semicolon
To: Yang Li <yang.lee@linux.alibaba.com>, aryabinin@virtuozzo.com
Cc: aou@eecs.berkeley.edu, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, palmer@dabbelt.com, paul.walmsley@sifive.com,
 glider@google.com, linux-riscv@lists.infradead.org, dvyukov@google.com
References: <1612245119-116845-1-git-send-email-yang.lee@linux.alibaba.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <4b3294d7-ff30-8f02-81ff-d2d73a79e465@ghiti.fr>
Date: Tue, 2 Feb 2021 02:06:44 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <1612245119-116845-1-git-send-email-yang.lee@linux.alibaba.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.195 is neither permitted nor denied by best guess
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

Hi Yang,

Le 2/2/21 =C3=A0 12:51 AM, Yang Li a =C3=A9crit=C2=A0:
> Eliminate the following coccicheck warning:
> ./arch/riscv/mm/kasan_init.c:103:2-3: Unneeded semicolon
>=20
> Reported-by: Abaci Robot <abaci@linux.alibaba.com>
> Signed-off-by: Yang Li <yang.lee@linux.alibaba.com>
> ---
>   arch/riscv/mm/kasan_init.c | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
>=20
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index a8a2ffd..fac437a 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -100,7 +100,7 @@ void __init kasan_init(void)
>   			break;
>  =20
>   		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
> -	};
> +	}
>  =20
>   	for (i =3D 0; i < PTRS_PER_PTE; i++)
>   		set_pte(&kasan_early_shadow_pte[i],
>=20

Reviewed-by: Alexandre Ghiti <alex@ghiti.fr>

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4b3294d7-ff30-8f02-81ff-d2d73a79e465%40ghiti.fr.
