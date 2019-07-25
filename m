Return-Path: <kasan-dev+bncBDQ27FVWWUFRBP4247UQKGQEAXT3DKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 259BC752F6
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 17:39:45 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id d9sf42577388qko.8
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 08:39:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564069184; cv=pass;
        d=google.com; s=arc-20160816;
        b=aZGZUbyXhv2dGE8AzBMhZluoavIpriqKEzapKmxXy9wLtZ/SePl/ZdJwq1ekqwCq4E
         9KFkQ0BBGd4H9vlK862QZ0zJLpC6AZgRHDAxoUb7VTQYrbJYIlufbwXmKzt7iw3grDQK
         XyKlkmWHUrwjRZl7AXMe+mF41fsMEX7nuANC7fq/hLHQ3xu8t1Ms5UQMUlFZMrpxqqRz
         69w/aKZcKlVtsgo7bjpgdFHtj/IgsMJeXUc4u6gybHToyZ6LZz0nBrLtm3QZ3ZsFiP7b
         GR0T8W6klabXUjfjy/5QqED+KaFU43heurKO2WLRZGtZTTGPN3kFBkNywRHrZPnxCmtp
         IZkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=8KP7N02lNNwTSBsHY79f5xEtrUBIYyVxwmiDRhKkyx8=;
        b=ECk+FdJLuVqgVqAxE2ZwYMqgawoRalzHOvV5eluRByI5JWxup0oQJHF9hoAohkmXd8
         UUr07OZw7VpzkCe1rmE1LwSj/nuziA/lPcZG3A0ESg7ASjBsb4hvJtlJPDYQRxHsrrTG
         rPK+LjuIjFlLpiqPMVwMYmHo9yFjQ3zI//NI2zM+LsLpeIWSV6Y0qn6rlI9+dr0c8/Pt
         ZLQYZgRBJrWNVEx5JwfMMlohFanUtU1kqKw74IScU5OBIIo0mZsp8iVTpxoAVFZ03NHr
         8Ccecluo+L0cav2VFrnJqp3j8kiNrsUHO4t+4VGX3leScsvU3/Xx7uw5UH0uen3c+m2p
         SM+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XJhOr3aG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8KP7N02lNNwTSBsHY79f5xEtrUBIYyVxwmiDRhKkyx8=;
        b=dn0IVyrE5xIX4CNtZmyJTHO36rA4revZ/eK7upf8WdoBIgBNhExAiaRse5wZhsM/oG
         GlppXB+eheKURaccD+EuY9FtPqcXSipUQ6H1rvDd8q4VfzcwT4MPvmN56WIqxjO4D4vI
         S/TUiT/9a0gt9RVwOceTK2L0+Nai6zPSSnhVLDlMa8IVscgrQjw2y8KOlNstowIBmCzv
         4PY5YW7+HbyuuFc08X2ZU2tRwmXT1Z0GuJ4KdxlHQ6DIVx8LT0+apIOU4DVbRiH7ifft
         GlvZyskjU400G+/08so5AcgoKhvlQBlBPq/HVFRMG4hMvQt52Rru2+b74XK9tDwcRBXq
         eTMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8KP7N02lNNwTSBsHY79f5xEtrUBIYyVxwmiDRhKkyx8=;
        b=daKfuhABvo6hxLwzBaLBqRd4XH+uwRV1nsgZ6ghHP4gwnmVyvhW2hOFjr5OZuDD9gF
         GO7YyC522kdbVLxQwpGpF6UvvHGBoVlmyoI2IRUizKCNTtxVFO154ZXjHdYwNvzZQReq
         nRSfCH/MfyBpZ5b0PhkvH7oApi0pvT+g4Lm/G56HiS/NQG1UXdzf7HUJiq35UVqbevFA
         B/e3oo00gGsWdlWauO0V6kxTBn3y7x/5O2oUJYAOWIm0vAhNdnlOGopZjOVeEBaEaKMg
         3GONCZHpQWT9STykjzc6yGhHvLG8+QIXTaTTRN02kvUz2e1OHFbb5wtwQnj2iy9QpFo1
         IfOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVYeH0fKm0auLrOrhcHvJICVsE3AywDnNGpJ39cKaI5KaJTqFmw
	NafIjX6SUlNJHr/kJqRgamg=
X-Google-Smtp-Source: APXvYqwn502iXGjKfSZS79G/FRh9XG+/xv9wHyv99ps0hijWTfpW4avLphfvVWxA+DQFj0LIuwzr3w==
X-Received: by 2002:aed:2667:: with SMTP id z94mr63974025qtc.2.1564069184004;
        Thu, 25 Jul 2019 08:39:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:540b:: with SMTP id f11ls8106709qvt.0.gmail; Thu, 25 Jul
 2019 08:39:43 -0700 (PDT)
X-Received: by 2002:a05:6214:1c3:: with SMTP id c3mr57357048qvt.144.1564069183692;
        Thu, 25 Jul 2019 08:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564069183; cv=none;
        d=google.com; s=arc-20160816;
        b=m3HumB0s25hDuo8sgQ+HBlHRGl/k3Y3bHPAjjn5rZT1SPCbDLjXNhncJ1kr8E26Ass
         J06ATOurzlknWk8H8wiKEDlUXTgXosi1IHyPvigQlUy3w//VlXlyY/OmqNpyI0Bd/qbQ
         Aps21pyL/QWl6HgCvxGPpoEsZtYh5rjXB+/ErCf0C+SluLIKrj30SVxV93RaVuHfS2cy
         2+vIK17gSubwfkK/cDjLYsq9vw9XyOFsWFYUGwMJDBE91svfqqw+fVf/cTVPtkH3Ea0M
         /oADqpspxS1LY/MVhGxKc4HmFwoI/G18O4k1xLE1WIfT91fFA+Hg1SjmIFuaC9GzlXBD
         p4Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=C1z55Z2C5T/VVbilD04bgcsRmc4fMIXBlsOukeF2YXM=;
        b=Fhs6VQGw2yet8tJhJ0RxHd7QFezAnboRiZuSye4PAEHtkvhKY5GJUXex6H/hamJHnY
         tyha4MSpZ8UjbqT+FnYlfmA/WJIGOZ6geHqlRSgiFTJSeyEpnjyNpttTxcpPktb/QZva
         HbWFDlrlXKBDgsKm650Hx/Tvt6su1IRzmUitm/RF8JeOI1jijlOrI1ryjpiQdPHoKoD5
         GuEvZEZ8YI8fm1SzwGVw699Fjw02CCYh21QKgb3CX8jBgzF1MPgcnxsFWZNzOhBEt1+c
         eVvORtX6R5QHvfZwLJXJEQrUGPGC1AjArPPH+tpeWgJE16bkZyMqYG2BbT4E5WJN8NsC
         bjKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XJhOr3aG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id l17si2237434qkg.0.2019.07.25.08.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 08:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id m30so22965694pff.8
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 08:39:43 -0700 (PDT)
X-Received: by 2002:aa7:93bb:: with SMTP id x27mr17847025pff.10.1564069182790;
        Thu, 25 Jul 2019 08:39:42 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id o11sm83158287pfh.114.2019.07.25.08.39.40
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Thu, 25 Jul 2019 08:39:42 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andy Lutomirski <luto@amacapital.net>, Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Subject: Re: [PATCH 3/3] x86/kasan: support KASAN_VMALLOC
In-Reply-To: <D7AC2D28-596F-4B9E-B4AD-B03D8485E9F1@amacapital.net>
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-4-dja@axtens.net> <CACT4Y+aOvGqJEE5Mzqxusd2+hyX1OUEAFjJTvVED6ujgsASYrQ@mail.gmail.com> <D7AC2D28-596F-4B9E-B4AD-B03D8485E9F1@amacapital.net>
Date: Fri, 26 Jul 2019 01:39:36 +1000
Message-ID: <87lfwmgm2v.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XJhOr3aG;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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


>> Would it make things simpler if we pre-populate the top level page
>> tables for the whole vmalloc region? That would be
>> (16<<40)/4096/512/512*8 =3D 131072 bytes?
>> The check in vmalloc_fault in not really a big burden, so I am not
>> sure. Just brining as an option.
>
> I prefer pre-populating them. In particular, I have already spent far too=
 much time debugging the awful explosions when the stack doesn=E2=80=99t ha=
ve KASAN backing, and the vmap stack code is very careful to pre-populate t=
he stack pgds =E2=80=94 vmalloc_fault fundamentally can=E2=80=99t recover w=
hen the stack itself isn=E2=80=99t mapped.
>
> So the vmalloc_fault code, if it stays, needs some careful analysis to ma=
ke sure it will actually survive all the various context switch cases.  Or =
you can pre-populate it.
>

No worries - I'll have another crack at prepopulating them for v2.=20

I tried prepopulating them at first, but because I'm really a powerpc
developer rather than an x86 developer (and because I find mm code
confusing at the best of times) I didn't have a lot of luck. I think on
reflection I stuffed up the pgd/p4d stuff and I think I know how to fix
it. So I'll give it another go and ask for help here if I get stuck :)

Regards,
Daniel


>>=20
>> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>>=20
>>> ---
>>> arch/x86/Kconfig            |  1 +
>>> arch/x86/mm/fault.c         | 13 +++++++++++++
>>> arch/x86/mm/kasan_init_64.c | 10 ++++++++++
>>> 3 files changed, 24 insertions(+)
>>>=20
>>> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
>>> index 222855cc0158..40562cc3771f 100644
>>> --- a/arch/x86/Kconfig
>>> +++ b/arch/x86/Kconfig
>>> @@ -134,6 +134,7 @@ config X86
>>>        select HAVE_ARCH_JUMP_LABEL
>>>        select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>>        select HAVE_ARCH_KASAN                  if X86_64
>>> +       select HAVE_ARCH_KASAN_VMALLOC          if X86_64
>>>        select HAVE_ARCH_KGDB
>>>        select HAVE_ARCH_MMAP_RND_BITS          if MMU
>>>        select HAVE_ARCH_MMAP_RND_COMPAT_BITS   if MMU && COMPAT
>>> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
>>> index 6c46095cd0d9..d722230121c3 100644
>>> --- a/arch/x86/mm/fault.c
>>> +++ b/arch/x86/mm/fault.c
>>> @@ -340,8 +340,21 @@ static noinline int vmalloc_fault(unsigned long ad=
dress)
>>>        pte_t *pte;
>>>=20
>>>        /* Make sure we are in vmalloc area: */
>>> +#ifndef CONFIG_KASAN_VMALLOC
>>>        if (!(address >=3D VMALLOC_START && address < VMALLOC_END))
>>>                return -1;
>>> +#else
>>> +       /*
>>> +        * Some of the shadow mapping for the vmalloc area lives outsid=
e the
>>> +        * pgds populated by kasan init. They are created dynamically a=
nd so
>>> +        * we may need to fault them in.
>>> +        *
>>> +        * You can observe this with test_vmalloc's align_shift_alloc_t=
est
>>> +        */
>>> +       if (!((address >=3D VMALLOC_START && address < VMALLOC_END) ||
>>> +             (address >=3D KASAN_SHADOW_START && address < KASAN_SHADO=
W_END)))
>>> +               return -1;
>>> +#endif
>>>=20
>>>        /*
>>>         * Copy kernel mappings over when needed. This can also
>>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>>> index 296da58f3013..e2fe1c1b805c 100644
>>> --- a/arch/x86/mm/kasan_init_64.c
>>> +++ b/arch/x86/mm/kasan_init_64.c
>>> @@ -352,9 +352,19 @@ void __init kasan_init(void)
>>>        shadow_cpu_entry_end =3D (void *)round_up(
>>>                        (unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
>>>=20
>>> +       /*
>>> +        * If we're in full vmalloc mode, don't back vmalloc space with=
 early
>>> +        * shadow pages.
>>> +        */
>>> +#ifdef CONFIG_KASAN_VMALLOC
>>> +       kasan_populate_early_shadow(
>>> +               kasan_mem_to_shadow((void *)VMALLOC_END+1),
>>> +               shadow_cpu_entry_begin);
>>> +#else
>>>        kasan_populate_early_shadow(
>>>                kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
>>>                shadow_cpu_entry_begin);
>>> +#endif
>>>=20
>>>        kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
>>>                              (unsigned long)shadow_cpu_entry_end, 0);
>>> --
>>> 2.20.1
>>>=20
>>> --
>>> You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
>>> To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
>>> To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/20190725055503.19507-4-dja%40axtens.net.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87lfwmgm2v.fsf%40dja-thinkpad.axtens.net.
