Return-Path: <kasan-dev+bncBC447XVYUEMRBOGGZGAQMGQEOUCMADQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id BF6DE320A9D
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 14:42:16 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id y18sf4189367wma.8
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 05:42:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613914936; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ow6+D1Bs8CbU8lvhzaQbieqIAkGJ/0N3WOP6qZfAkzFUHvu6XHp+f3fTGEgLRkz7IE
         B6mFBUeMfG/OSH6DOmkBuSrmwRR6nOszZuVg6LoQFoWSpE9AE4nXN/0L68vDNYzQtXeB
         ri4W+NsFqM8gk2q6ZTfSrZx8AySazj8bQcifLW8AMjIOFG8PZQ5j/WUl/JmTI6WZEMdg
         GokerFwfqrh+gHN7reM0F6WBpYplJunVfBTEacjSsJjNLAKHy9jrQn7NCo+eqZIO1GmF
         z5lOGmljGvkr79SLsqADBLDmBmZ90+bqL3i0Lxp4GzLcqiXdl7OKhBopgNf+p4boUdMY
         c9FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=VmGTLv6lyfSVEZpcdAmHY48qc4KchRsSX80eT7Lhris=;
        b=Ksh3+MN48BG47TeWOJnjJKm3nJ932pzedsbhAs4ab3WdLJ3jL8vf9xoXGDsceftWWX
         vCzErAFwrHv8jy4aXacgWyIecPgJmqqTxB6DzkOmzUO04QXB4nHc1pWosKNA92scIC1p
         1yG0MVQEjs2KgggfAcbOdjSltvOxsTW3IKabHQMFy85MqEFpjIkCR3HX6ISMyyhX0eFo
         zpF6ByMSiXY+xQLRlu3T5TrBDzs50YEe3AUGOul8yLZ00I5ioIIJ/DqJjPtcl3wDNPV+
         4g71sW3bcNm81gv/7/eNAQO9/0LPa/Fee9+UxRAaD8hkNi4699fzfvqGlwHGTBUJllqZ
         9R4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VmGTLv6lyfSVEZpcdAmHY48qc4KchRsSX80eT7Lhris=;
        b=ljJqDUenELbPfqwREzMrdj8liaa8ZKFfPf+6rQ802TMe3tUQelupVlblnda/5u7Xu7
         Oyk9vIxzAede3Zf6jyfoEdtgG1Y4azlbXorVuCWBbg94TuXwvYUwxC+IYZdV+SkO6gvx
         s+OiuF5WK+CRpPYjXy1KSORUwWMq6/7Nbso91khZ6KW0LNkv+4XRyO6qPCCHxcXd9uXK
         dZCmUqxhpHMkCxnXe4PoYYsAqmyy42rwMr1zOZnTYtcQsMDHU2rvZN6lemfn4SYgrlfa
         BjbZd3cwSwIsk5hsZC5c+fI19U1BdznfniEdlUOXp1D0elDw5zb744/dHxpDa9C+eXdK
         0IHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VmGTLv6lyfSVEZpcdAmHY48qc4KchRsSX80eT7Lhris=;
        b=N5u+w0IL4GdBrqa+LO6G5zwaV0lkAYPi7uwJEz5kMB3p9TjuELtri8gGsar6/90+/d
         0us5TD5t1NWRMemk0p5alDoykHHGhAe/m5/bHaARt6ShN2Jjrg8fHnKJwcKZWaTKh87J
         nse08x1p01KrIX6csWz90VqeuI907mrelGC6PMl1ema9H5DaXmLHBwYFNEFdZe7eczVN
         FxqjhTSzbXI6vcH72pUkUiqzIM199GR52SVc70dhKSM9M9DBj73/9b6LZt4ld8mSwzHK
         FeZdhxHFyUMcCNFw/n4bcHywsc+Sj8bMeui0By7kVBdNXq7VsTxj3TGiQKmxc/qq1Wxx
         J1YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OylmCsQys8iQzj8fM+9KxI0u/rVkjlwSSagZUNeT8oDobNxN+
	uT17QApqZQctl9NrPtA7k50=
X-Google-Smtp-Source: ABdhPJx0+d5hkZ67/t8mbEcbKoCaWuOswN358r40ymOH6M23yaTKPaucHaVVv+0DnVAYhXFcOibDTw==
X-Received: by 2002:adf:d239:: with SMTP id k25mr18213669wrh.308.1613914936525;
        Sun, 21 Feb 2021 05:42:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5592:: with SMTP id i18ls316239wrv.2.gmail; Sun, 21 Feb
 2021 05:42:15 -0800 (PST)
X-Received: by 2002:adf:fac7:: with SMTP id a7mr16957381wrs.206.1613914935747;
        Sun, 21 Feb 2021 05:42:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613914935; cv=none;
        d=google.com; s=arc-20160816;
        b=HedcUov4DPsQCufnno8iJ9Uav0AG/0Q4GydPnEAV9R/9tN9Td82yaNoGsOg0KAhroV
         FKteJdrbrSjiNV6sNmorvl53Nh4hJ87eGY+Gxg0tTtXeb6uykG/uAQLTU4NCsAEPrSVF
         Ngnewt6nKHpKY7Ulv0eTUzTbk9t9kNa97GU6NsXGVNlxQSfdBhSgdDaGbSrw4aT2MhX+
         LWzFEsziAoR4qecDjbFFFA4omuQow72ETj2HOMq/kL/tS7p5O2b6LJ5ApfQ+aUoPXme6
         If1zur7fP13sIgICQYoDUaiVGbpdgejB8OyB2kpYuRJbCVD8GIyihbsbKJJHuLncjK5y
         16WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:cc:references:to:subject;
        bh=wHo3dRGvfPGQLsBYBRTH9MD3www1VUH0lsxxxS5CAXA=;
        b=fgY+f4KhDuk8QCc8rwuQ761R0s3rT1C9Y7BvUBKmB68/QC+pwXaNxOXV4vEyd02Qci
         rqOdWplflUT+hmUwj/SnPG70+TqkUq+hE0ynUOUf9W5lRpJgeloQGMDwS5JO9knI7zpO
         sFuWzOTWV5W2naSgmJqeEBoV8GEfnNTD+WLsWd1UaT5FEMhY+dpiU8lstoCyyWzvrQTQ
         SLmKYEw44koKvUOVH2gDF6yu5gFGgXIBqorWzxQkHpn5o63cTXrKbZbNBK1EJ/F8xUxC
         LkpANMguF1mSMj6H5eny4cvA88b7WAxNGInhIb6nOFf6fzYFk0Z3W3eXHeSAxMeZoLjz
         n5Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id v6si557243wri.3.2021.02.21.05.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 21 Feb 2021 05:42:15 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id C7EE1100002;
	Sun, 21 Feb 2021 13:42:09 +0000 (UTC)
Subject: Re: [PATCH 0/4] Kasan improvements and fixes
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org
References: <20210208193017.30904-1-alex@ghiti.fr>
Cc: linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <24d45989-4f4e-281c-3f58-d492f0b582e9@ghiti.fr>
Date: Sun, 21 Feb 2021 08:42:08 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <20210208193017.30904-1-alex@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
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

Hi,

Le 2/8/21 =C3=A0 2:30 PM, Alexandre Ghiti a =C3=A9crit=C2=A0:
> This small series contains some improvements for the riscv KASAN code:
>=20
> - it brings a better readability of the code (patch 1/2)
> - it fixes oversight regarding page table population which I uncovered
>    while working on my sv48 patchset (patch 3)
> - it helps to have better performance by using hugepages when possible
>    (patch 4)
>=20
> Alexandre Ghiti (4):
>    riscv: Improve kasan definitions
>    riscv: Use KASAN_SHADOW_INIT define for kasan memory initialization
>    riscv: Improve kasan population function
>    riscv: Improve kasan population by using hugepages when possible
>=20
>   arch/riscv/include/asm/kasan.h |  22 +++++-
>   arch/riscv/mm/kasan_init.c     | 119 ++++++++++++++++++++++++---------
>   2 files changed, 108 insertions(+), 33 deletions(-)
>=20

I'm cc-ing linux-arch and linux-mm to get more chance to have reviewers=20
on this series.

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/24d45989-4f4e-281c-3f58-d492f0b582e9%40ghiti.fr.
