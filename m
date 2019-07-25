Return-Path: <kasan-dev+bncBD42DY67RYARBZ4L47UQKGQEFLLNSQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C56D75224
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 17:08:25 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id w6sf38614849ybo.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 08:08:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564067304; cv=pass;
        d=google.com; s=arc-20160816;
        b=JJ4hQzG7aex3ARp1nTqkJDswd86gaU4RqpnK3VErZiNVNhwVqOaL2JDbe3s4MlMiJg
         LuzYIUlUbMA6cR05Q8sPhqOPzgGCGcK+T+W6HNCs8k9LnpMgPT3c9kU8L3m/9WkDihVQ
         7STRvUdDHjtxbWbLar6GjDFLD7IGeTQ3cNWU4S4w6dc4FXqz/e4prOh8Kz01wGryZWx/
         l3NL2ZSJ8I8abZLKFc4/A6uiz0Wr6lPZJL3tNNjkDvL/4pTJUMnr8gySLXRhA/gA9OW1
         bPXURiXMpABjyy3LI5zxJ8ALYjV6iwfdgsGzasvis3Pt5wPL+3ihyIyMvcQIC8/5JnAx
         qsKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=uUvBaHrL5zKIbkorkOcd2O8a0cSh6eV05xeM//VSiWo=;
        b=z9vjIqWAXbkcItKrwWT61VajVAQdRRhxwd5TJvfEyvroYJp9a/yWFgchVjLXEWaPER
         /H9uQOT85VxIqrmEu4ZBPUStCy835Uc3pGjeaFIbdDeu/BmzWlDCBYjW+JHJWFXV86s7
         ouSkQE2U//3z6QlKgIuZ7X06sqoFeT7ftUsxN836p3zS8CZYOK7+0A0EVciaVbod4KBH
         kGkcQ20BvatC+kpWSwelQyxp98jRIF3QpjKXU+LGAymZiu7f/EX+2iQEJ/Xf8fc6W3W7
         HBs0hbXTkuULXJtzePyyMC5djgy+F14VoZu0JfN4xY+vngW2m0bj0mtXoKykULspsI5D
         5CQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=qRC1ruUX;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uUvBaHrL5zKIbkorkOcd2O8a0cSh6eV05xeM//VSiWo=;
        b=nAtlM1XDQRgw8jGWg/NI4vITNW0xhHB6VPjwKFQeqCTxhjrv+0nj3NFg+dWu+KC2Qi
         8Kf9hYanyATr1dUO9NZ0yXJh03TyiE2ZEnwvSjAx6arDfuszkoOZ355qNJtD4RdQi62/
         FjaEtO9nYPwsqRuakT+znt05KbhvY/+/6eYDqoXgANE9bqOcAgDsEhLiYoGVXWI2JtgP
         c9oeoCjzGyRoYTjsQVNQvoHLzk0H/ErbDnrMHnzwzLH+mwWithc2ePQVhZ5jGh6MTacM
         uPFaYbpFDNpJtXQNG2Am+vi/7tTkhcuJdXwMPhsd2A5jEGYrgVhxDZ/6RYUODdiUawIb
         88uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uUvBaHrL5zKIbkorkOcd2O8a0cSh6eV05xeM//VSiWo=;
        b=VrGsgSPi4K0WV+ho5SjrEiL5pTjDyDv7mpRaxujiis+A8TkD0gGlZlytlsrydqQTLb
         NWpM9oXCpEu9J8EMUwX3HKfCtC3PxQLBP7aydB1Y3xpRlprr1gxhvNZXCTCLptrJJAwK
         cdgxktmBaomhp9kit2RtLASW/ZKJgmB2rz2T0+Vq46M2wNcVf8svQ21OYV5L0J5pJlQr
         vJYj7+sAT9Ul/g4zhZO+Ukv+6DQ9Gk8RjDr9E0XRSVrhazAOk+/xo6n0Tf8ns8dbG7T1
         zABjXDLvIbPWHARVSaz0kjtzCm+a7XkBJsoj56iAH/jLW/fPNpdLlUUB6IV9X6iu15+o
         8syA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVvcg6xBvUgVjaPQwslndIKTI0k4cTxzH3WudWqBhCw2H7g6Wd4
	ltF/hGWnl/0gqKauoLHaRYA=
X-Google-Smtp-Source: APXvYqxe73Jj+lt8u4PLB4JhO5WwO2BHiJuD4xZqoNiN4DTjOy/IXcKosXMmAKaKORWjaBhtXQOxjw==
X-Received: by 2002:a25:1283:: with SMTP id 125mr55899436ybs.55.1564067303878;
        Thu, 25 Jul 2019 08:08:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:23c9:: with SMTP id j192ls5794579ybj.6.gmail; Thu, 25
 Jul 2019 08:08:23 -0700 (PDT)
X-Received: by 2002:a25:86cf:: with SMTP id y15mr54486238ybm.15.1564067303576;
        Thu, 25 Jul 2019 08:08:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564067303; cv=none;
        d=google.com; s=arc-20160816;
        b=PosBZhBXIa2BIGr8d84mDxxlIZkLINsZDeDRRumn9YyyEF8kPhUauk1hnh4EcyjDmH
         WdX1HGBP1beNfvmOGbcM5kc3Y/6W+4ugmisRQZOUj+BYK8ydKh0wlTi9VM7jJx3fyssq
         Ylm6qPp6z4b5LrXSCmMvJhvidNcR11Te9ZS8c/pZSviV+GK3vzQTe0A5f8G7VCUxsPw7
         T6WBLZLChunGZHg1dYgmsotBFSzGHcvtBue6QxsQ7bJUmYIjeDGjDBG0OO6oD05QAKOH
         SwKyCm7i406RITO1B38rggLDu6qF0yvsIHUoygboeHKcXGKGEt/ztsfqJZLjk8gIK4ch
         tYdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=83mWQew2TppWX0X+agKs+C2fhodByufyMhvIxXXCS2s=;
        b=xG+sVw+EFs8QSompjWdAAYZdwK230qv7aH3LPJjw/re/qfFIvFJkk6jFDesBhs/5xL
         GSYMWwVN/WFKhZFyRJm673bD0lCVhhrh1p3B6vXT6ESu3m/MCpMxNh/S0J3letMmmaw/
         gn4yhyWI+/g7VSQMVO8zagIiMMpFA3J8JOjoD8kbO6k+8C8c/RJA7aQtpF7bHvIj8A5B
         dh1NvG5mFbXcY0hihpy2s45tqmcz1e8GW3fgPo0g40tQH6df57n3W5wtUhIxmeoAXB2B
         +/MgcnktuxJmu6GyIz9rc4lcrQROCg+dCE47RpyYQqn+RbtgWd4s92rchd7ViuusAtjq
         sJVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=qRC1ruUX;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id r1si2880339ywg.4.2019.07.25.08.08.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 08:08:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id b13so22912968pfo.1
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 08:08:23 -0700 (PDT)
X-Received: by 2002:a63:6c7:: with SMTP id 190mr85625071pgg.7.1564067302595;
        Thu, 25 Jul 2019 08:08:22 -0700 (PDT)
Received: from ?IPv6:2601:646:c200:1ef2:2d12:dd93:21e:b639? ([2601:646:c200:1ef2:2d12:dd93:21e:b639])
        by smtp.gmail.com with ESMTPSA id v138sm57834072pfc.15.2019.07.25.08.08.20
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 08:08:20 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH 3/3] x86/kasan: support KASAN_VMALLOC
From: Andy Lutomirski <luto@amacapital.net>
X-Mailer: iPhone Mail (16F203)
In-Reply-To: <CACT4Y+aOvGqJEE5Mzqxusd2+hyX1OUEAFjJTvVED6ujgsASYrQ@mail.gmail.com>
Date: Thu, 25 Jul 2019 08:08:19 -0700
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux-MM <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Content-Transfer-Encoding: quoted-printable
Message-Id: <D7AC2D28-596F-4B9E-B4AD-B03D8485E9F1@amacapital.net>
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-4-dja@axtens.net> <CACT4Y+aOvGqJEE5Mzqxusd2+hyX1OUEAFjJTvVED6ujgsASYrQ@mail.gmail.com>
To: Dmitry Vyukov <dvyukov@google.com>
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=qRC1ruUX;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=luto@amacapital.net
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



> On Jul 25, 2019, at 12:49 AM, Dmitry Vyukov <dvyukov@google.com> wrote:
>=20
>> On Thu, Jul 25, 2019 at 7:55 AM Daniel Axtens <dja@axtens.net> wrote:
>>=20
>> In the case where KASAN directly allocates memory to back vmalloc
>> space, don't map the early shadow page over it.
>>=20
>> Not mapping the early shadow page over the whole shadow space means
>> that there are some pgds that are not populated on boot. Allow the
>> vmalloc fault handler to also fault in vmalloc shadow as needed.
>>=20
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
>=20
> Would it make things simpler if we pre-populate the top level page
> tables for the whole vmalloc region? That would be
> (16<<40)/4096/512/512*8 =3D 131072 bytes?
> The check in vmalloc_fault in not really a big burden, so I am not
> sure. Just brining as an option.

I prefer pre-populating them. In particular, I have already spent far too m=
uch time debugging the awful explosions when the stack doesn=E2=80=99t have=
 KASAN backing, and the vmap stack code is very careful to pre-populate the=
 stack pgds =E2=80=94 vmalloc_fault fundamentally can=E2=80=99t recover whe=
n the stack itself isn=E2=80=99t mapped.

So the vmalloc_fault code, if it stays, needs some careful analysis to make=
 sure it will actually survive all the various context switch cases.  Or yo=
u can pre-populate it.

>=20
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>=20
>> ---
>> arch/x86/Kconfig            |  1 +
>> arch/x86/mm/fault.c         | 13 +++++++++++++
>> arch/x86/mm/kasan_init_64.c | 10 ++++++++++
>> 3 files changed, 24 insertions(+)
>>=20
>> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
>> index 222855cc0158..40562cc3771f 100644
>> --- a/arch/x86/Kconfig
>> +++ b/arch/x86/Kconfig
>> @@ -134,6 +134,7 @@ config X86
>>        select HAVE_ARCH_JUMP_LABEL
>>        select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>        select HAVE_ARCH_KASAN                  if X86_64
>> +       select HAVE_ARCH_KASAN_VMALLOC          if X86_64
>>        select HAVE_ARCH_KGDB
>>        select HAVE_ARCH_MMAP_RND_BITS          if MMU
>>        select HAVE_ARCH_MMAP_RND_COMPAT_BITS   if MMU && COMPAT
>> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
>> index 6c46095cd0d9..d722230121c3 100644
>> --- a/arch/x86/mm/fault.c
>> +++ b/arch/x86/mm/fault.c
>> @@ -340,8 +340,21 @@ static noinline int vmalloc_fault(unsigned long add=
ress)
>>        pte_t *pte;
>>=20
>>        /* Make sure we are in vmalloc area: */
>> +#ifndef CONFIG_KASAN_VMALLOC
>>        if (!(address >=3D VMALLOC_START && address < VMALLOC_END))
>>                return -1;
>> +#else
>> +       /*
>> +        * Some of the shadow mapping for the vmalloc area lives outside=
 the
>> +        * pgds populated by kasan init. They are created dynamically an=
d so
>> +        * we may need to fault them in.
>> +        *
>> +        * You can observe this with test_vmalloc's align_shift_alloc_te=
st
>> +        */
>> +       if (!((address >=3D VMALLOC_START && address < VMALLOC_END) ||
>> +             (address >=3D KASAN_SHADOW_START && address < KASAN_SHADOW=
_END)))
>> +               return -1;
>> +#endif
>>=20
>>        /*
>>         * Copy kernel mappings over when needed. This can also
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index 296da58f3013..e2fe1c1b805c 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -352,9 +352,19 @@ void __init kasan_init(void)
>>        shadow_cpu_entry_end =3D (void *)round_up(
>>                        (unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
>>=20
>> +       /*
>> +        * If we're in full vmalloc mode, don't back vmalloc space with =
early
>> +        * shadow pages.
>> +        */
>> +#ifdef CONFIG_KASAN_VMALLOC
>> +       kasan_populate_early_shadow(
>> +               kasan_mem_to_shadow((void *)VMALLOC_END+1),
>> +               shadow_cpu_entry_begin);
>> +#else
>>        kasan_populate_early_shadow(
>>                kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
>>                shadow_cpu_entry_begin);
>> +#endif
>>=20
>>        kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
>>                              (unsigned long)shadow_cpu_entry_end, 0);
>> --
>> 2.20.1
>>=20
>> --
>> You received this message because you are subscribed to the Google Group=
s "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send a=
n email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msg=
id/kasan-dev/20190725055503.19507-4-dja%40axtens.net.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/D7AC2D28-596F-4B9E-B4AD-B03D8485E9F1%40amacapital.net.
