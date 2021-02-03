Return-Path: <kasan-dev+bncBDLKPY4HVQKBBT5V5KAAMGQEWXD4WGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 1641830DA0A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:45:04 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id p16sf14190190wrx.10
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:45:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612356303; cv=pass;
        d=google.com; s=arc-20160816;
        b=fs5HUKqsmCvcoM0Jgd9qaRQ+Sw6PKaQX93WKpKAH61JiIdnzdrn6lJJExCRtUCQzA1
         gIOrVC2dDwWePO/RHFvziYUdzsAry93DZTxz7Updt559Zwq7I3RRFLq/MfF/TycoqBAi
         xhBNP+PJ4LToRjJ5RN9eK+NVYkJr/SD01o0Q1NP2QZJri6t9ss3rMaHYCaDqPOKNS8Nt
         JygiTJTzNni52Z3/EMA3dxv2Bu++b9Vw5yqq12qLA9wwonfx0GwA90njPDrHrIrS8gEz
         ra9Woo1cUHbhVkn422/QOwjeGEo83uTSxeya2NUHEGRnsY/MTtlN93hEoxdBZO3NVK6a
         ddnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=i1/FLn82PV7oy5tDypZ/FK29G+lvML4V1J4tNz/b6pk=;
        b=yZIKs4duMA4dxRbSs98k30TR7yTJ/kf5LGUSJwBT4+L+xa6ra8ydC0UYz8svDKaVa5
         1LhyC/rtKjLd0IYmZwTl6CIpXJlVrhh+0Vl9VIVM2p8LTWqUniEG/93M86VmCCqXghVw
         2YK/E1hYCUK0DrlABA4Bmaj0l2wpFInjQU/uUUJlzBMmMeVWUWkBeXdAakoIQ3/2wjXk
         0iA2r2VibAh/IH587aajGonntBzGkDROD3xdrx0ShrFFsxrVuAoQW2GDSlivZZc/lYhE
         Es9SUdJuSEownlYdAOALYPKoohTwDfjcyCjfMnKAg6Spz/g8RAh/tRFpLrpq4KguzVoe
         cL3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i1/FLn82PV7oy5tDypZ/FK29G+lvML4V1J4tNz/b6pk=;
        b=GNgb55+brMKzUT5YC21yis0eITuTr/MZpVQMJIO6weH7bMul1K1TDUvVRween2gft+
         Xqtas1B5fkRSJ7M2LFduOprgFIAv/COKRFAJI3jinqdY287r5aNZD3u3zIbzJYPWAR9v
         vojMgcjSYYbcEvPrHMYSbynJ7Ik1oHIKjnybIhDnHQ1MHRcyfBniDxvaRq2Zp42b2XZx
         ZsYsVUXIaStkI3K3fNMaOVzA/QPnRBlYS7As7Umun4zH1LFUUlSqCVXMsRm8STlhiUI2
         I4iQTcP6EQ3lvV6Z5KzgHF7DVj5olDalqlfDhy8idBvhXEvgsDVlp/sh/edux/Ru7DbL
         w1Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i1/FLn82PV7oy5tDypZ/FK29G+lvML4V1J4tNz/b6pk=;
        b=QgB8FRc1SxZNEvfOmjOoIZluHcx2T1dqXUOdeSCZa8nX9o86aCTdiE6C5IWgLZCa6z
         /kNRdC7M8DPbUfzBe+VZo0W7Igkb6UkkjD70LEZ1umfW8H9W4kOo7rFo0mGwRWYpG2mx
         GADviFMKCnUqxD2xCwUCCFq862C4fNi8dqGemYU37lORIOCUJ7+SOqZV1GF0oyoskyjQ
         TzkiTKk0SUxDCLVhuNhPh9xqtJqfBQTV8t74B5mrGcTzii+EoqVdAOiZ1N3I1PhAsFKF
         nTXx0C5+MAsKi23PufX9U1b4AcMQ3dqJV893ur2lq+XWljkEFkT7hI2srtUbouKY1tmY
         QTZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dYkLVfV034PxxVvj3MLy31aSeKKCdQp3r7Ub5qpgq+cqY2tzp
	uiqasLjq4iOckLRXh/Ti/Yk=
X-Google-Smtp-Source: ABdhPJxjgImD7zh6Ue2Tos9N9QpUU/EGdKXkN0htrVW/eQ/el+qk3ntVst6Jfu5GF+VFIUknsTraFg==
X-Received: by 2002:adf:eacc:: with SMTP id o12mr3307056wrn.202.1612356303845;
        Wed, 03 Feb 2021 04:45:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2ecd:: with SMTP id u196ls983205wmu.1.gmail; Wed, 03 Feb
 2021 04:45:03 -0800 (PST)
X-Received: by 2002:a7b:c77a:: with SMTP id x26mr2687465wmk.143.1612356302974;
        Wed, 03 Feb 2021 04:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612356302; cv=none;
        d=google.com; s=arc-20160816;
        b=sy6NHTHqK/FmJTgXmnuX0AtYwvTUh2SbitdQ//3Ui2czWZ0F3hWha255olZv0Ci3oG
         Wqzyec3Z3pw3UxZ642kVutFnTOZ+q9+z1ipTi3Z1H+BYi3Z8nmoo8S9BBn0S0djLbEKa
         GUD8bW2YdMXYNXCR4MVHZ7Jc7ZME+kjyTXxQWByMy87wP9Xz2zXATonKDc2Tp2QOzLrw
         sqU9F8WpnHrIG7Ssi8z5ouR7bvMvny73Sk8JVbNYacmLATJJ7eQtngdLcMsI4KJm6ZWo
         kKSvjO1i2x/JjDZl+jpGvGVdvoy5kMKO1jnF9DOFh7JAipK1/sgmsQ7+MdC+3jd4Swhk
         iFMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=Jxg7ncPfrs04PL85aYY0F6I/0yuluQmy6FQkkct5zEc=;
        b=XST2AF8Az0FmJXe0Gw9g5gzOMuo25Egre4pFBl0Tz6+GvijiNBJH8tx9UdxbBbjM/j
         vRYmlR4mAo/dJwkTXPm0vnGYS9Jq+OHScr9nO4WJIuTPA5+fCxyLH8hpNXhtp9X8f6u7
         ZqYqVfALkXO7lFtkt8pnG9zrwa0mCJaFBHBMMevDEgt4gH6JUacyLm6tPubssu1pnD6C
         xCvWwnYafqHeJEpT4ISQyI3NNa+GoyKwrjgTm0iZR0/4a6o9YLFBC7rx8xtMXAkdmgSf
         vUfARtoqWmXwHxmafGX/VQPsPvmF5ge9FaeThFVe/VkJ3wPP+aHvMf8Jna9UlRONSBxw
         m1OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z206si96770wmc.0.2021.02.03.04.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DW1bx1lvkz9txxD;
	Wed,  3 Feb 2021 13:45:01 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id HjMAXj_hX0ua; Wed,  3 Feb 2021 13:45:01 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DW1bx0MsNz9txxB;
	Wed,  3 Feb 2021 13:45:01 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6C76B8B7E6;
	Wed,  3 Feb 2021 13:45:02 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id NgsdGv0kVo9P; Wed,  3 Feb 2021 13:45:02 +0100 (CET)
Received: from [172.25.230.103] (po15451.idsi0.si.c-s.fr [172.25.230.103])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3E2FC8B7E5;
	Wed,  3 Feb 2021 13:45:02 +0100 (CET)
Subject: Re: [PATCH v10 6/6] powerpc: Book3S 64-bit outline-only KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20210203115946.663273-1-dja@axtens.net>
 <20210203115946.663273-7-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <4b790789-052f-76de-a289-726517026efd@csgroup.eu>
Date: Wed, 3 Feb 2021 13:45:00 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <20210203115946.663273-7-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 03/02/2021 =C3=A0 12:59, Daniel Axtens a =C3=A9crit=C2=A0:
> Implement a limited form of KASAN for Book3S 64-bit machines running unde=
r
> the Radix MMU, supporting only outline mode.
>=20

> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index a66f435dabbf..9a6fd603f0e7 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2157,8 +2157,8 @@ void show_stack(struct task_struct *tsk, unsigned l=
ong *stack,
>   			break;
>  =20
>   		stack =3D (unsigned long *) sp;
> -		newsp =3D stack[0];
> -		ip =3D stack[STACK_FRAME_LR_SAVE];
> +		newsp =3D READ_ONCE_NOCHECK(stack[0]);
> +		ip =3D READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);
>   		if (!firstframe || ip !=3D lr) {
>   			printk("%s["REG"] ["REG"] %pS",
>   				loglvl, sp, ip, (void *)ip);
> @@ -2176,17 +2176,19 @@ void show_stack(struct task_struct *tsk, unsigned=
 long *stack,
>   		 * See if this is an exception frame.
>   		 * We look for the "regshere" marker in the current frame.
>   		 */
> -		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
> -		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
> +		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE) &&
> +		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) =3D=3D
> +		     STACK_FRAME_REGS_MARKER)) {
>   			struct pt_regs *regs =3D (struct pt_regs *)
>   				(sp + STACK_FRAME_OVERHEAD);
>  =20
> -			lr =3D regs->link;
> +			lr =3D READ_ONCE_NOCHECK(regs->link);
>   			printk("%s--- interrupt: %lx at %pS\n",
> -			       loglvl, regs->trap, (void *)regs->nip);
> +			       loglvl, READ_ONCE_NOCHECK(regs->trap),
> +			       (void *)READ_ONCE_NOCHECK(regs->nip));
>   			__show_regs(regs);
>   			printk("%s--- interrupt: %lx\n",
> -			       loglvl, regs->trap);
> +			       loglvl, READ_ONCE_NOCHECK(regs->trap));
>  =20
>   			firstframe =3D 1;
>   		}


The above changes look like a bug fix not directly related to KASAN. Should=
 be split out in another=20
patch I think.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4b790789-052f-76de-a289-726517026efd%40csgroup.eu.
