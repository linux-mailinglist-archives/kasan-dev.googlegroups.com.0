Return-Path: <kasan-dev+bncBC447XVYUEMRBPGW4WBQMGQE3M3MENY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AD648361E31
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 12:47:24 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id m16-20020a0560000250b02900ffde35c102sf4270896wrz.20
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 03:47:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618570044; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUPx7oebnFCTF/Z54NUuB0pL8dByAg3E4AYJ5iwz8QNOtGEBH6lZvPtpc3yFWAuxDy
         CeF3uHOD6JMZatYt/XyeErNvGqT7pM5VhD9SAO11cI1H2tckTgh0u0GLOOjX/c+oL1AH
         ERORCY1SmeEOaOjd9egSM1YPOfQCpljDHSZjolQ0898uY8yQ9DdpXwTOxttib6tOBBbu
         /B99+a80Do8Vplq6z9YpUcz50ynPV/JliS2jsSAEVi1cadVrp/MuXMzHsz7mThB+wygv
         D+9ysZ78Advjk8ARwR/HWlh0/JNv/ojvU/xWgnKWsQ06EkSV+RxHNApqYJcsYr01XFG+
         Ktlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=YWHCD2lBebNid0jQDtczQOi+IUv9gmVVxlYIXJhZJio=;
        b=gR51IGTYIKya2wZc0enbLFqLbZeIuLbSVnLFRZcxTZeZB0HnmYBJJdc/5NKKXR8kAc
         ZliZY5fPP1IQOXO3CVe6lNhq2KiXFR4tD8BIWN/QbwZgICsXuJsDQ1VtwI/BILBrbAR8
         1bUz9tf+xjQ8WZYHkkxVoX46VDrLEHBpb/4SPlUsdU49YUU5JbHNNk2sIpsVnbZqxt/T
         G7lCkoPWkLFah1pHW7mR9kU0ZLea7YpNKE2bsFF8K4QPlPwVH+D2BVyYGdzrSMoNYXYs
         oC9Z7zwKqPP0CsOm44YrTdz0K8wHpqkNOput/Hax7pw77NW3nIYwNR5pgJO0rZLcoOhq
         KGWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.194 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YWHCD2lBebNid0jQDtczQOi+IUv9gmVVxlYIXJhZJio=;
        b=KhYkLNhrK/G1DvJCdF8r3ulx7PPPuXR8ATzFQiKGdoYyIi7puH561Ji6LT3DIvrcBy
         1lTr/9z3RMNG1mde0FVD3bqExeCuTPKaiwA4JkpeCT2nX0+Q7hDxJtGDf9JlRTrNVHOr
         IVSV6MSiNLe8IAoJcxXFk9RjvjhHoXhwD7JTTJcS9j1Fb35M6ZutFchCYnJv/HV+oqc7
         RWPhQs52MLSZEdXseOlXRWkISsfGRdr49ks8DNy5bfCkvssG5I3YF5yA07qrYaamvWH5
         xSaavA2BjiH0casWG3x7f6UAztnE+Z09VEv/VYxQXlkbwxAJZR4vh8gpzmwVfVYWT7fO
         S2gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YWHCD2lBebNid0jQDtczQOi+IUv9gmVVxlYIXJhZJio=;
        b=R+dKyzGmi9EYNwmtQg0eiITuUzvhsnLsCd1tDq3r0KBeN2pzoTgUggc6eWJQseX8FS
         kNY6Ij4zADCkmXWkQoSCfqz7faUwEwQzKy6dvjd7/Sl34NW35IAk92dBq0VS1sUXjzaB
         FIoTjomcAu9WfSCqVPQyaNC9ieWwbry0USiUobPcVKx4wT/gKjYPDCQkIDPX9LHlPlpF
         szRmt1T66otCM8VAcvp05pErRxs1vN1QHJvGZsOdhGiFbflb+peqhFPSu0TTuCUogZc+
         cSe3obyBSnGbofqyjl6CQdcQf44fjm58/t0nSumGA/flvJ2hndjsFkgRc75EQHAzZmh/
         shIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EoNHUieHR5Ftf9ZSmLerFfaghxiM5wxnAEJrlxzQvXZoHewEL
	kapfgtBi6wCJKMPecxv3c6w=
X-Google-Smtp-Source: ABdhPJys22muzSDTDm1ZteyvxokLVmR027E8zSwEmTcOchPkxCdLBAKUjts5c/xbxzbX8/7FjVwuMg==
X-Received: by 2002:a5d:4488:: with SMTP id j8mr6523695wrq.83.1618570044479;
        Fri, 16 Apr 2021 03:47:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fb47:: with SMTP id c7ls173031wrs.0.gmail; Fri, 16 Apr
 2021 03:47:23 -0700 (PDT)
X-Received: by 2002:a5d:55cf:: with SMTP id i15mr8102491wrw.289.1618570043681;
        Fri, 16 Apr 2021 03:47:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618570043; cv=none;
        d=google.com; s=arc-20160816;
        b=YoRK21sUP8Zw1tBiDu4xkyL+sDbAtTvHTcKG2KBzlNaSYmgJkJ/AbI5pHigmGpRyNA
         bXSEGICUUKJusu3YnebU0bBQ6Erz/O8CQzqUm2nOiQ3F3DQZ3IF1mZ1k4CpiiTgBhEKS
         fs7b9Gjt69JU8n5ZmT76rN0SwEDF2JUjm7Of6MfA/xLy4mz8JlNy4Dq4M4RX6Nh2c2sX
         MnhPVin6h3KfldSfA0lUtLARBBpTpiVCuLeF8bj4LfcRP7gxSFSBBSYvWJv/XyA6tf2U
         mWnyKaHbXe4G85CoK46VpMieVVlwka6ZqV0r5Nz7poGahqnyo4sxbUQho+9NyLJI3Kit
         orwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Nb4eAVWb/jm8f0DTNdfSUaAZRgWKjTREkrcPE0XfuQs=;
        b=CvT+iAZ7ieace1XinAnJ2A/ekfXRJh5ziIr8gDCvICARjUCfD+EzO/BwHOFg4XBI4l
         GhfKF7s8EyJ8puwY6g1hxVnQLrX5++DDJmXWjv8oYZCjG8bHIPK4KQfDSdcQ7RUDc8OC
         b6E3jYUZ4CGSsnVa9WtnoUYs91nsGhYT6hdGb8VVOCIhjzGj5Xvc0ssbLEpd011FfaYN
         tfXeatNITL3HUde61ru1r32p9pBgQYZ644NlrWO0I7JX+TK9SWsDbNSlcCtAvDiwDbOM
         Asz2PX15ZH1Sh6xe1slCjNokb1Yx3BkYeD9+mM8dEy+3mN0k4ykhycgXpM0lbEm0eDeo
         +psA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.194 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay2-d.mail.gandi.net (relay2-d.mail.gandi.net. [217.70.183.194])
        by gmr-mx.google.com with ESMTPS id k6si265605wrm.2.2021.04.16.03.47.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 16 Apr 2021 03:47:23 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.194 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.194;
X-Originating-IP: 81.185.167.252
Received: from [192.168.43.237] (252.167.185.81.rev.sfr.net [81.185.167.252])
	(Authenticated sender: alex@ghiti.fr)
	by relay2-d.mail.gandi.net (Postfix) with ESMTPSA id 62B3840011;
	Fri, 16 Apr 2021 10:47:18 +0000 (UTC)
Subject: Re: [PATCH] riscv: Protect kernel linear mapping only if
 CONFIG_STRICT_KERNEL_RWX is set
To: Anup Patel <anup@brainfault.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 Albert Ou <aou@eecs.berkeley.edu>, Arnd Bergmann <arnd@arndb.de>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-doc@vger.kernel.org, linux-riscv <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com, linux-arch <linux-arch@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>
References: <20210415110426.2238-1-alex@ghiti.fr>
 <CAAhSdy2pD2q99-g3QSSHbpqw1ZD402fStFmbKNFzht2m=MS8mQ@mail.gmail.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <f659c498-a273-f249-a81b-cab1ed1ba2bb@ghiti.fr>
Date: Fri, 16 Apr 2021 06:47:19 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <CAAhSdy2pD2q99-g3QSSHbpqw1ZD402fStFmbKNFzht2m=MS8mQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.194 is neither permitted nor denied by best guess
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

Hi Anup,

Le 4/16/21 =C3=A0 6:41 AM, Anup Patel a =C3=A9crit=C2=A0:
> On Thu, Apr 15, 2021 at 4:34 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>
>> If CONFIG_STRICT_KERNEL_RWX is not set, we cannot set different permissi=
ons
>> to the kernel data and text sections, so make sure it is defined before
>> trying to protect the kernel linear mapping.
>>
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>=20
> Maybe you should add "Fixes:" tag in commit tag ?

Yes you're right I should have done that. Maybe Palmer will squash it as=20
it just entered for-next?

>=20
> Otherwise it looks good.
>=20
> Reviewed-by: Anup Patel <anup@brainfault.org>

Thank you!

Alex

>=20
> Regards,
> Anup
>=20
>> ---
>>   arch/riscv/kernel/setup.c | 8 ++++----
>>   1 file changed, 4 insertions(+), 4 deletions(-)
>>
>> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
>> index 626003bb5fca..ab394d173cd4 100644
>> --- a/arch/riscv/kernel/setup.c
>> +++ b/arch/riscv/kernel/setup.c
>> @@ -264,12 +264,12 @@ void __init setup_arch(char **cmdline_p)
>>
>>          sbi_init();
>>
>> -       if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
>> +       if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX)) {
>>                  protect_kernel_text_data();
>> -
>> -#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
>> -       protect_kernel_linear_mapping_text_rodata();
>> +#ifdef CONFIG_64BIT
>> +               protect_kernel_linear_mapping_text_rodata();
>>   #endif
>> +       }
>>
>>   #ifdef CONFIG_SWIOTLB
>>          swiotlb_init(1);
>> --
>> 2.20.1
>>
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f659c498-a273-f249-a81b-cab1ed1ba2bb%40ghiti.fr.
