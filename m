Return-Path: <kasan-dev+bncBDLKPY4HVQKBBSOA26CQMGQEQWP6O6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 79F25396DE1
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 09:22:50 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 133-20020a19058b0000b02902a413577afbsf4714973lff.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 00:22:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622532170; cv=pass;
        d=google.com; s=arc-20160816;
        b=HA65sUNTpwyP00WzxLTDDVDzYXOxVi6C901Af7Verq7l1vxxaLFXoN0FNB5hsaEr2b
         6IEhqnph2CbRhq7FuuvHDAKpFOyLx/AYMqq4Q9UkSrb4OydrpGgrI5ac1gn7WD92MJ3s
         5Jt/UK33mRAcIaeXf01HR8IJ2504YCKeYjztFNDFWE0UMaNwBFO2cVCp3GiDnM3LIllV
         WCeB969m5ohavIE7HXRfL/TAz4TcWM5tmdEYybUtaeZMdYyV40WB0M2Tb8JQMtxSU+6P
         U2oLe59G7y1Hk6V+yeI6lQZg1H3KYhO3GOPW4YIQTUJSce773m0/iSOqFrFtf/7M5Fm4
         wTAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=0RK/vsFdmxRyj7haAmRp5Bg8RhYriSQERkX02/qnCic=;
        b=My0Dity5VkHRjsB0w/npQu8QhphHbpky0tTgK8t/XNHIpVsIuZJ5QfB/0d3LWopVS3
         Afm11WfRULYkKASlsfm/mRscSr4cU7AD+rW2WAjMlXL2VsXI8SKPH+GJQmrV08nCBejK
         /Bw/vwUUjLQ3j3d6B4nRLnAjF5S0FcuokR6pKpgZMIdKh2sVMoDTxVFKfC4Ge3YrcKpL
         jM7Vbpk0rby8EvFAm4sSL/nujeauNGOCbwweaInqoPMdPrPtSzEyy2wGC7x8kg/od2kL
         pFe5aKlx2hWk1kA+iJiVocAeAciX7K0veDHPDwuocFuQwA0iRNiCpS8IFXPjIBBmeUb/
         IL/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0RK/vsFdmxRyj7haAmRp5Bg8RhYriSQERkX02/qnCic=;
        b=VRpyCpB5RYcU2Z4RRoL80Ul98D/uOAkO18fn0kGlCq5zCRKQHaySSkz6eCtL+KZd4V
         y1LXVvMnd7hRNV6kq6aD2juSLckos43KvHutgjwuyGq+6jbnpe90wjIh7dnkz2EpsMUd
         bM+lg10rZvofU/dP9vEHY/6k/Cy5z6Vc83XLn/uLN2sxjhSEJjZN8/EXmvNOWbDeyY4l
         8mH3ZKzjFL5nVXuJ0rHWfAkzTSCglQP55CNtkAJmPFR2DAQNlSxg3ZhfM+OdEyilDWHI
         aGnfOKeAk5v9erdrEoSzhoG3o1IH1MG+Z+mpq0hdNI0fXeoInytMNJ4i1GlXvT7OAzm5
         6/Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0RK/vsFdmxRyj7haAmRp5Bg8RhYriSQERkX02/qnCic=;
        b=PH/jmEy9BpwAqXUcvP8QKp1Rs+OU1+Ac9OW2YTnl+apjJ2pO/LEUlz0AtljIAO7RsH
         aZfI+9yd9SQfmX9R2bR5mnvu05sOEGgjY6K7Oj+nkT2MqRsaBVPCwN4Eqwlty+e3BEB2
         8LCRMyo/lh4sHHVoALvPJKDcupR+12WgPa9B7Ei4lJRijh5k4/3XbiOEj7ZuZclHhSFp
         /VJ/x3iRf7T3Cj+g9+UibEgjQSUTwTLFHSu5g4t1rsF5wVIKKSEosjYr6k0YATguzgnj
         xFENdUBznnDn7bLRLtYUF2D8tAKCxERmELM7tpsqCJ+L+aUoSJd3phqKoDajYKxqdM8I
         oSAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OsjlUHO35VmsADYsGf/ftBuKuiuqEGWCz05z4jsXrzEHfQ47K
	V+z0+UsZa4xklm/1BUXkLgs=
X-Google-Smtp-Source: ABdhPJzEvpFFqChibJTulDBj+zgfaaWoJ3Zs/lHUMCqhF6l5S89uVafVt0vrY8mMwuyV7TKK4uqS1g==
X-Received: by 2002:a2e:9787:: with SMTP id y7mr19833983lji.65.1622532169849;
        Tue, 01 Jun 2021 00:22:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7008:: with SMTP id l8ls2981925ljc.4.gmail; Tue, 01 Jun
 2021 00:22:48 -0700 (PDT)
X-Received: by 2002:a2e:7018:: with SMTP id l24mr1008833ljc.12.1622532168622;
        Tue, 01 Jun 2021 00:22:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622532168; cv=none;
        d=google.com; s=arc-20160816;
        b=ann0e48LKsx2D5TbWrvpgbmYPU7wakZFy1q88SnPCWA9g6OeAUkg4WiLjxvg8Mmc+y
         EuMRZkR1XQkTa/Bu0I7IFCRcAuwudcxGCZeavcvxnr/KwLwOkNJvevUoSXYCkk3kimis
         T5TDZspI58MvDMUmFPO5CDB5PnsGxMAyp2wvM2ps712qwSEYgxOEe6sl2qgYpEZ0+Znb
         xseSBes+l0IkXhsZgpb2HRl1I2ESOVsCHWd8f2TxUsAceaGYU8WJmXk04JZIkinKQoYP
         kIAM68WRXMe5vOBVTwhrMOy6E88rsAJr1DWs2YmZ6FCqyyjtyDVo8PQ9JP1ZdLJ0LLyG
         BQBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=YGj3Ll2rv2K/rsDhsr9+gd8dOE6Jf41/4LgsXTpU6wc=;
        b=NYs72FCm01vfBq75GqWG7sTw28Uq8hql2Xlduv47lzaRcOE3Ua9AGZllH3g5z10KEp
         xLvTQNKus2QC3y8en0s1hXi0yAEReNWT9LE1jhCvgeitvHJ6L1ESJk6LQ2nraTmwINkR
         Ai47E5FxAp/Ni0MTi3rlsc7H4kE53QafZX9Z1R51TQNLYna+bhRoUHwVnRDVMG75rSSe
         zHMSenvg7QBEEmc4oDw/BTFPASM7kdjZusd4Bhsh+43FpSqWMn4D72qyXSFhrRGox20f
         4Ho0QcphUxlzwajwXbKRdj5W7KJGcHa72zDuW/GU679emy450siEY19gWKrI0/bKnYpi
         jkhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id o13si584868ljp.0.2021.06.01.00.22.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Jun 2021 00:22:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4FvNsg5K2JzBDlZ;
	Tue,  1 Jun 2021 09:22:47 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id KCSf2hoQB7ao; Tue,  1 Jun 2021 09:22:47 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4FvNsg4QcCzBDlT;
	Tue,  1 Jun 2021 09:22:47 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 82DAF8B765;
	Tue,  1 Jun 2021 09:22:47 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id oR-q5SgmhKex; Tue,  1 Jun 2021 09:22:47 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 34D5D8B7AE;
	Tue,  1 Jun 2021 09:22:47 +0200 (CEST)
Subject: Re: [PATCH] powerpc: make show_stack's stack walking KASAN-safe
To: Daniel Axtens <dja@axtens.net>, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com
References: <20210528074806.1311297-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <19442f8a-43b2-b51d-b1ad-3d27bb5fac49@csgroup.eu>
Date: Tue, 1 Jun 2021 09:22:46 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.2
MIME-Version: 1.0
In-Reply-To: <20210528074806.1311297-1-dja@axtens.net>
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



Le 28/05/2021 =C3=A0 09:48, Daniel Axtens a =C3=A9crit=C2=A0:
> Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
> generic code, arm64, s390 and x86 all do this for similar sorts of
> reasons: when unwinding a stack, we might touch memory that KASAN has
> marked as being out-of-bounds. In ppc64 KASAN development, I hit this
> sometimes when checking for an exception frame - because we're checking
> an arbitrary offset into the stack frame.
>=20
> See commit 20955746320e ("s390/kasan: avoid false positives during stack
> unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
> frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
> Prevent KASAN false positive warnings") and commit 6e22c8366416
> ("tracing, kasan: Silence Kasan warning in check_stack of stack_tracer").
>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   arch/powerpc/kernel/process.c | 16 +++++++++-------
>   1 file changed, 9 insertions(+), 7 deletions(-)
>=20
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index 89e34aa273e2..430cf06f9406 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2151,8 +2151,8 @@ void show_stack(struct task_struct *tsk, unsigned l=
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
> @@ -2170,17 +2170,19 @@ void show_stack(struct task_struct *tsk, unsigned=
 long *stack,
>   		 * See if this is an exception frame.
>   		 * We look for the "regshere" marker in the current frame.
>   		 */
> -		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS)
> -		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
> +		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS) &&
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

Actually you read regs->trap twice now. Can you use a local var and really =
read it only once ?

>  =20
>   			firstframe =3D 1;
>   		}
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/19442f8a-43b2-b51d-b1ad-3d27bb5fac49%40csgroup.eu.
