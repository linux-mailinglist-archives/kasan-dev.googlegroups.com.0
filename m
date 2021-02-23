Return-Path: <kasan-dev+bncBC447XVYUEMRBJNL2KAQMGQEHAQ2Y7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 765A632257C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:41:57 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id v130sf730044wma.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 21:41:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614058917; cv=pass;
        d=google.com; s=arc-20160816;
        b=FYrN9KunTFxsSkKZQkbkqzTyKBsz2VziEfkhbET2gsBexghuAuXFAitWdXgGZWViUD
         Mhqf7WN3pktkueluscizHHiN5BXPSkP9yFm2pJM0c+QwT/nKlxUJsaLa0bSEycfoaFED
         if9zaiOts6arLSapOUKGVEg/whhtm+oDh7ywkDW3MDrPoanQPUMbopK91SI6wmN8EIbN
         LH7tsZBr6ihmIaqlvB6Ezn6pF1EI7UmRwbCRRN7tT++XuUohnA1mIFTuR+JBGJN+Dl/b
         pDzSHx++d1h71tqC6rgVj31QyKSwBFDRgVS6yZbR3rnwURVD7WeMU2wf0ZUmbNxBpAL/
         TpCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=uFP5gKJ56DfQVZPriHvkCJ/TbdqV5TwwAj9OM9gtHBk=;
        b=G7T3dgPKOLWN1/kyOf6iwIYMMtqCa8W/Mze+1WOfADL72tlUEtQe4VtQaSN+X3nh6W
         q9UDLcIelJ4XrgfMiyuYYt0EPf1e8nkLZLyAW1ZPsbbJPW6wJ6/7fb4TgEpLm+2wB29B
         Ms9AWllXuUdIhw82nFoRu1uadX45Z1163ib+JBKwoJhJB26GxPGRi83dzdrArXgYa9yc
         6ZEwkB3GIasOLclCKj29AtGn5NFCOox6brJVoio5yYc3H3Faa8zp5Ehwwf+mkCJq0olq
         8E/HgcuISWpv0pZLOIF6jwlKUnF9mI+Z9ejoyDna8EqvMsQdpN18rJRASOBmpL5+MD95
         Fu/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uFP5gKJ56DfQVZPriHvkCJ/TbdqV5TwwAj9OM9gtHBk=;
        b=a4nu4QFeXw1uNPrt0SJpLHi5nBtjYTIkYMBsiduT9eUMyWpPU3gAUR9SSqmZpFTViT
         pBe7zji+YugP1TnhnOtMdB74XEWJNVFeCZwDAgrxtyqxfBlVYs2+LAq3IzCFTfN9VhCl
         F9jhNqq9cK1zLNhEo8GGSt53H3RzOYtaOAEd9qcjBy4Hb/JmfqWb4JA561no8bfVE7oN
         hi94Og7trdv229csWlv5poXRpRxsGBTzbJN4GCZLYaVGa4hKkqDcUXqSLlNBq5MFpgq6
         sbg11TH4Yh5b7lxAwRPb8dxhwRYzk/PdeCNfQ3t2Lan/S/TxuolGz9avgX2zxUJyaSsg
         bCNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uFP5gKJ56DfQVZPriHvkCJ/TbdqV5TwwAj9OM9gtHBk=;
        b=Y/WlG/ccxD1GVfCNjjX+3oZEn1DqtZuOGYYJ8oVsPJP+sDzfrti9xwa6xYYExHyu8C
         b44EjpDj0s1xjGhWFfpTdTSmddu3ZADdPaIK0aMa+knPaIAUwDTgOybd1qsLOiLArk7F
         bNgDYoN+PL2WKM7QlwrKuttBBR7v9wY5dGqowmvTVuPJCozQsDLToJIAtAzuJ7OlgkSw
         ULGRusJPwKZRNFDlQIORi0Rem8oHGesTJ6NJLitboYPxd7t0m0ZVZSTx0zeORnSoua8G
         nlvaxqX5cI40/cIbHIFOMOn5ATaPutCMXhgudRtFHnzERibhQPmSf42Qp9/RSOQRI2el
         7asQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rp7ZXr1DywMyJ97l/D4LbtrgoxgrbNvI44rLYngqhdMFHbDDC
	LCDDvL5s+N4wmg8xnNfgnhg=
X-Google-Smtp-Source: ABdhPJz1pPNHcZLgX1qdIxF8glaUnKVllU/bFQ8wqlny4lUS601ekKMZ4lyjvEP5y3QPmxYMtZ04Fw==
X-Received: by 2002:a05:600c:4f07:: with SMTP id l7mr17137222wmq.141.1614058917259;
        Mon, 22 Feb 2021 21:41:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls627879wmi.0.gmail; Mon, 22 Feb
 2021 21:41:56 -0800 (PST)
X-Received: by 2002:a7b:cb05:: with SMTP id u5mr19939985wmj.46.1614058916552;
        Mon, 22 Feb 2021 21:41:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614058916; cv=none;
        d=google.com; s=arc-20160816;
        b=cW7Iyvgii5lYI56mjmIcPU9VAV+yXW1Yj/R8EQJ8G2gPlpiLNh/rYQNozGTCJo4EVY
         lgvipp0/yXr60Q+HGJLsPlVDzOZ6X0QhlqwgOs49UqbVQiwplLy0CTOpjyDmrZ3o1Idv
         SDJe6b2SOPqjwtF2KCPWWtkEFKkLgVw4afMHO3nHRQiAqZgcogWTwIXzJPVfgRK6vOoY
         bf+oGgGutKIiDpl/Hd0OTRf4HhMFyQAQ3QHFHP4IFB7vyR+4xmCZ5tQr7QRNTNU69rYu
         3FcP0UU+jpFE1O+KHBXXr4laxrDIFrT/fiV7tL9r2hLxc3bRgFm5qr6xjVWrxoFr2twI
         60og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ImLZQIcWQieEHMY3TxwO0m9XRaXWF4TITl7z1/Z3xv4=;
        b=NXN2Rr/K0d0bNZxYLrXE3BqjsAVmmVqqdRApjHVUwLdcPxCRADZjth5DBMLLt7BSuc
         TK/I6dEPJxOvZbUU7dR7LoKo+gpXcHry/iQrsMo+bSfxkSR2Btok2CKRZL13xu8gf8o7
         yd06JLCU4Z54iebWLtJ47qKFdqCmyGQlXskcHUttlBn3tSdEtKcfw3hpMEyh+NVN6VcU
         RYDa0CCE7cLD2FywdY1oJO1dkLSvgSFKKlQS5QZSi6J/RGKE3P9yJqnKpvawr1sXaqU9
         y3te1rFYFA9DTxtIKUepV4I1zoal0Cnfy0v6p7ghf6LEkfdv2pHiHm2fOIJAyu2fCK5n
         NzEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay10.mail.gandi.net (relay10.mail.gandi.net. [217.70.178.230])
        by gmr-mx.google.com with ESMTPS id t25si63070wmj.0.2021.02.22.21.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 22 Feb 2021 21:41:56 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.230;
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay10.mail.gandi.net (Postfix) with ESMTPSA id CBC6E240003;
	Tue, 23 Feb 2021 05:41:52 +0000 (UTC)
Subject: Re: [PATCH] riscv: Pass virtual addresses to kasan_mem_to_shadow
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: aou@eecs.berkeley.edu, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, glider@google.com, rppt@kernel.org,
 Paul Walmsley <paul.walmsley@sifive.com>, aryabinin@virtuozzo.com,
 akpm@linux-foundation.org, linux-riscv@lists.infradead.org,
 dvyukov@google.com
References: <mhng-ed9c69f4-96ab-417c-90da-4c03a48d1268@palmerdabbelt-glaptop>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <ed70634f-f578-d1d5-7543-915477466d6f@ghiti.fr>
Date: Tue, 23 Feb 2021 00:41:52 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <mhng-ed9c69f4-96ab-417c-90da-4c03a48d1268@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.230 is neither permitted nor denied by best guess
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

Hi Palmer,

Le 2/22/21 =C3=A0 9:58 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Mon, 22 Feb 2021 00:07:34 PST (-0800), alex@ghiti.fr wrote:
>> kasan_mem_to_shadow translates virtual addresses to kasan shadow
>> addresses whereas for_each_mem_range returns physical addresses: it is
>> then required to use __va on those addresses before passing them to
>> kasan_mem_to_shadow.
>>
>> Fixes: b10d6bca8720 ("arch, drivers: replace for_each_membock() with=20
>> for_each_mem_range()")
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>> ---
>> =C2=A0arch/riscv/mm/kasan_init.c | 4 ++--
>> =C2=A01 file changed, 2 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> index 4b9149f963d3..6d3b88f2c566 100644
>> --- a/arch/riscv/mm/kasan_init.c
>> +++ b/arch/riscv/mm/kasan_init.c
>> @@ -148,8 +148,8 @@ void __init kasan_init(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 (void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start, &_end) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void *)_sta=
rt;
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *end =3D (void *)_end;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void *)__va=
(_start);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *end =3D (void *)__va(_=
end);
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D end)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 break;
>=20
> Thanks, but unless I'm missing something this is already in Linus' tree a=
s
> c25a053e1577 ("riscv: Fix KASAN memory mapping.").

You're right, I missed this one: but for some reasons, this patch does=20
not appear in for-next.

Thanks,

Alex

>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ed70634f-f578-d1d5-7543-915477466d6f%40ghiti.fr.
