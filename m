Return-Path: <kasan-dev+bncBDLKPY4HVQKBBXWQ23CAMGQEGRX22DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9988EB1E36A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 09:33:52 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55b91d6fecbsf959650e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 00:33:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754638432; cv=pass;
        d=google.com; s=arc-20240605;
        b=FpI1qemXqS5qHUCErvCUxsaPkaau9xiVukuonHZq3soroVO6QDFgzz/WfNRj035dHA
         sdl3JOB0XlavPJ39Me1FH+QQ9j4rKpg0hT41gQ3QzWu6/I5ucR2L3VvyiDZl/XVNRABN
         Oz+JcLbMXmk6MA3qr9RkRSUkOxlXLFdOO3P4+c6VR8CxdwmYBZ9wgbItUvY6kzeV114v
         hO7UsZ5majuHm5sg921btSoClmoU5wYxJ5LLEIy1EzHsWP8/sWQhvbU453yiI+ATPdHF
         4G0mlJrK9CWoYMYqXrKjzXZ6hxsBe5UiinWB2v2QB0Ga4H0xnIDxe5ejDkjNU1eKX1CA
         GyuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=TLW39YPCtgryowDhoOIyaoA96rWeQ1E3rGXKkSnfMp8=;
        fh=s3sGK3ZZlshHq4ZZfT7WDrTySnq85FRsRRSmvMQ80x0=;
        b=APoV21h+K0H4n5uTxyGwKhN5e0HvKqFVsUrAGGdXBkeL9qNqzo5KXsUjy049bT5zwH
         wjwfclYPNr2IRTxuZZFvyyJsT0xK7JTcK9HOEU/vlPq8yk8q31/MRUJnuwzvZILYWrS4
         OH2np4J48jXTfYCPj2XZXeoxMZeSxbhNKdpO6wRMx8JDrC4VO3OYEAy6/b1jveRVACEn
         FtYNqwAeXDq019VIRUgG1NVAJfxn2s6eipeWTJ19vuvWlOyLp1Lvxjl9bD2JORVt4iNG
         WSDay7XmH1V4Tzv0puT4vC+lma2V41uWb3NJn+t1rRmFtnFuRMq/Vgxo5b+Vrpfg2EMA
         1DBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754638432; x=1755243232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TLW39YPCtgryowDhoOIyaoA96rWeQ1E3rGXKkSnfMp8=;
        b=BbW2KpGehLwzjZwDnZTafq4U9f9gYuGqhQQH/JRMT2FY7zkGWUjQLIq978jFjKKV+N
         oPwP3dgGK7s241vSA9IS8//4iWj5T2TSsSBWODziNmRtY9bfUWhKmXP2RV2m8WHkKuRv
         xiMKsBWK6r/3mh6HZC7ByVbhge4Uid7KV5Q1JfVgedtuQOe9GHX0hVZbAyuAdrEDGV0l
         hJce+WF9/+qo8LEBM3R62IQ8hiuUrFNfTD8sWMVF4/NT8LtHpLe03HcP+94igY1do3Me
         3Sa1RJHwM8PBVJbpa+ZZYIBC58LJ5qte+HD269G8XZ6ZS2EPAaaI9d8broxozK8Df48c
         swDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754638432; x=1755243232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TLW39YPCtgryowDhoOIyaoA96rWeQ1E3rGXKkSnfMp8=;
        b=hnEKa+L2qfw7vIWOBT1U79VOrQJuJONnDTX+QgXc5UiS6wXZFvMzEkRKQyf9G8JGEW
         o6WJOTTYfvptBFyjh1HNu8LusWgJnL9IaYc0i+fAjKFBzNZUy/dq6N5Hrb81EhhVCALP
         xTWV26JN6kdO/4zPljKUh7iqq86RmUBLww5bq6DplH3REhVXBxD+9vjveSZRd4l9NLkq
         FYSSM3zHzboup+Cr11PogRtx7/03c4c0uR/e17D7GAp1d4QEOkBMeDud07hnyc+9aJG7
         glNnNiAk9H/QizvecmQGiAPb+fgac9MmAUjudGeFpC7MlIY+JabwQnJMIbQDZCo2T8tj
         BqHg==
X-Forwarded-Encrypted: i=2; AJvYcCWZLNO1kKQf7J0QOhjAtNmk0DjcOP0hMg7GmTi1RLoaxA9LEiC61l7dQIJiK0dKO6CADi7gLw==@lfdr.de
X-Gm-Message-State: AOJu0YwLd2l3VEk65qvNK0Mpowl1LGmBfWYqRQc0BPb6b5/Q12Qao2NH
	pLQvJMwR1T0CDpZ2umLG3BPkcjv8Ym68cSOtpBMyKQNdKyxwa6n4ITtC
X-Google-Smtp-Source: AGHT+IFcZBbvLOgQQMKfGet5ueM3xsarH/teBj3CqyggcPHg93Q0rDERUilUX8AJRJB+9q0qhCSBPA==
X-Received: by 2002:a05:6512:3d86:b0:553:3422:c39d with SMTP id 2adb3069b0e04-55cc01349e2mr528016e87.37.1754638431276;
        Fri, 08 Aug 2025 00:33:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfVnNAYFZAD9AKD9eoyQcaAv4GoQz3Gy4aqwTaszeHCwA==
Received: by 2002:a05:6512:6406:b0:55b:74e3:1cd3 with SMTP id
 2adb3069b0e04-55cb5fbeab0ls615056e87.0.-pod-prod-07-eu; Fri, 08 Aug 2025
 00:33:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQb8JgAliHJ9FCrUa/E/SKroMi8wwx5ry/tKnm15SokaQnBo/uFDPoV2h76KRmJ+kmxgMidZ8M9c0=@googlegroups.com
X-Received: by 2002:a05:6512:220b:b0:553:2ef3:f731 with SMTP id 2adb3069b0e04-55cc012bca7mr428042e87.29.1754638428395;
        Fri, 08 Aug 2025 00:33:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754638428; cv=none;
        d=google.com; s=arc-20240605;
        b=kuMWhp1VwTbyQh+A9eqGccJKy4BD0qrhgvJrJ+HqbZSih6md438zHJcv7gCGdrG0Wy
         NHDldJDbLDAxU1uzGRELSfBu0UGBMhfbPx2CbWDLw9BhVE6+jpNNh357/2a4QET0Za6O
         LpiXMJS9W6wu8bQa67g1uRiDrF6zY0LQfKv52L3YzC4Brr/207VMDlh+1PD2lMr3O+kt
         C3PZBh0IxwEyKMCPPYLfmzXZcl8GCSNW1TTcWPyDuUDCS16sNcL5fIafTi8ZJ+/HDO1w
         QR+qsrRmwwsLGI2ytxPwBxskva3IH2410xlFL2QSnF85eHPtzTjVrI5Dxi2gFPDLsIzj
         xzDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=MYY170L5/j8gQmCV0i0KP9yMXLZ9vOW8yjQXrZqWtaY=;
        fh=DkJkO0OvdwwhqNlqvuor+nsn8PcgEicU5yv/ktwlxXQ=;
        b=MnrXnrJnt2sejxW3pcNO5LQw3m4tX/lblhAcLukE0AcuOebRqf86mCyG2kWpetbC+t
         5XzYleVnIbjzH5gIP7WFEvRMVpdZsqd5Z7ZUzFEqIcf5U2Qdl7mkKMUK9mfglhuZ2ljQ
         1Szw/Exh+FbYFXcM6hESlLEM7m5qkEbMdv4M4LyVkbX/2aOJ6jeSZaGJWV4eVX6tMkaq
         /tQ7QSsLsPwaPxkZwKNlnVe1/mwfim3l/8YdqkFjJaoiS1gAYlTRrOiLM197vG6qVF2q
         2tFV5Y3P879NnQPUP246wPROuM+Et+4V1BCr7qX3GwYrjLaowMjRlQGvH2OLYISVN5Qw
         CuWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b9f778a88si352864e87.1.2025.08.08.00.33.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 00:33:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4bywkg3Mhqz9sS7;
	Fri,  8 Aug 2025 09:33:47 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 6-UTSoBBRo41; Fri,  8 Aug 2025 09:33:47 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4bywkg2Vk1z9sRy;
	Fri,  8 Aug 2025 09:33:47 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3F40D8B770;
	Fri,  8 Aug 2025 09:33:47 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id UAt1KEdP_5VW; Fri,  8 Aug 2025 09:33:47 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1F8218B763;
	Fri,  8 Aug 2025 09:33:46 +0200 (CEST)
Message-ID: <59ce87be-0a0a-4f6b-b439-bc7a4a037fc2@csgroup.eu>
Date: Fri, 8 Aug 2025 09:33:45 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com
Cc: bhe@redhat.com, hca@linux.ibm.com, andreyknvl@gmail.com,
 akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn,
 davidgow@google.co, glider@google.com, dvyukov@google.com, alex@ghiti.fr,
 agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250807194012.631367-1-snovitoll@gmail.com>
 <20250807194012.631367-2-snovitoll@gmail.com>
 <22872a3f-85dc-4740-b605-ba80b5a3b1bc@csgroup.eu>
 <CACzwLxiVURgamkv2ws5sK9BQVMz7VPSWGy_aQb+MT8jtv03d3Q@mail.gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <CACzwLxiVURgamkv2ws5sK9BQVMz7VPSWGy_aQb+MT8jtv03d3Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 08/08/2025 =C3=A0 09:26, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> On Fri, Aug 8, 2025 at 10:03=E2=80=AFAM Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
>>> index 9083bfdb773..a12cc072ab1 100644
>>> --- a/arch/um/Kconfig
>>> +++ b/arch/um/Kconfig
>>> @@ -5,6 +5,7 @@ menu "UML-specific options"
>>>    config UML
>>>        bool
>>>        default y
>>> +     select ARCH_DEFER_KASAN if STATIC_LINK
>>
>> No need to also verify KASAN here like powerpc and loongarch ?
>=20
> Sorry, I didn't quite understand the question.
> I've verified powerpc with KASAN enabled which selects KASAN_OUTLINE,
> as far as I remember, and GENERIC mode.

The question is whether:

	select ARCH_DEFER_KASAN if STATIC_LINK

is enough ? Shouldn't it be:

	select ARCH_DEFER_KASAN if KASAN && STATIC_LINK

Like for powerpc and loongarch ?


>=20
> I haven't tested LoongArch booting via QEMU, only tested compilation.
> I guess, I need to test the boot, will try to learn how to do it for
> qemu-system-loongarch64. Would be helpful LoongArch devs in CC can
> assist as well.
>=20
> STATIC_LINK is defined for UML only.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
9ce87be-0a0a-4f6b-b439-bc7a4a037fc2%40csgroup.eu.
