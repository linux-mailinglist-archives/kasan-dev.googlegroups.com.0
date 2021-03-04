Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZWTQOBAMGQEJVFCNLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B57E232D4EB
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:08:38 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id g6sf9923775lfu.13
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:08:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614866918; cv=pass;
        d=google.com; s=arc-20160816;
        b=tk2LBAwBjuJ1L3QaV9/KqY1YqUhfC6abh521YvH8jAJv4Os8tkQjHwFY+G+j7999I0
         VtQAruNEPNuxCooIUwLRX48IfZTpccial3T5qcd1g3Gt3oeGJcXaYR7SrwMKKQ/YENz/
         VQJd1JbL/IwwDFjC2unZWQb4Mq7Q5Af757SFo3U98JQreNU1+dbkE4iAbgFD7Hrs2Ro+
         EX+fCglV+Gfb2/tQunmevQfyFYyU4/OeFduiIMrQug1/bkVaag/Kn/Vb5x/STx0AVciH
         PHz9aRm9WJ6xdCE5Uh1M0PRQqqAtXVdJBlRrK4QHBm+LbJ/VvLmjG2VfsceogRgAgf+f
         W9Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=ybrYgbUtqfTERGPsCAi0dBbLF2F0DoZDDko59Wfk5xg=;
        b=YVsFPz3vrdvw/NU6LEUQKFfhCTiSja9xCezyXBewgNjXzVgeAJ9kDr77mP99EqmeRo
         kqw4fBT62hARMAkTN/NTijl6tN0NQc6BjT36bF4s7Lg01NIp9+c8iwrkE1tSaM6XedjD
         4YKuAQdShpKY4ZcCRapX1LQBkwCIyQ4OUVoNr/D3KeW5Onn1sabiaHC635gz4u9mhmio
         OOJNa9DFm2tHjaD8ObmWzjbEPMOBSHi0WybGFv1PFKAZXkugx1ZnJCzEYtpIeB2Ofgso
         TZhdpApNsfg4pTvkNmBW0yC4o4ou/3OFC7MlmTKNzqYLoPg26J8k0WEVCssHRps1CqE/
         ZrQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ybrYgbUtqfTERGPsCAi0dBbLF2F0DoZDDko59Wfk5xg=;
        b=jPq5Pdw9MObPHYCHjAkMbBstCtmL06l2T/As3SBugokWd1GrpFSuBW9hTif9Emjbgc
         cT6FFjU2qZc9PjM4rkvb3wvDhaogJA+gB8MBoUIYB18kG/euc9aTSLxR1yUkP9mcq40Y
         IjohHqKVPawnRpQDbFEK/O123j84Hc0Jw/yadQ365FgWsa/hBpabSyGymuZBPg77xPDa
         o1FiEfo74Lbq2hcgb+m2MzEeD3vMutc4PvR+tvQKU4UfRTMAccyQtZnJ/XHbRAt+mKK2
         w3DmNDrCmzcwdKgkAp9bZWtr+QWWZGkYVDYxI328ayf2Hcj6Xeur1CwaD65NTZwcmSn6
         UIjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ybrYgbUtqfTERGPsCAi0dBbLF2F0DoZDDko59Wfk5xg=;
        b=E8KH4beOYThc+z5XeiQwKoHY0Xm227dxPpjZkMt4ZXzYQ1RVnORIUCd41bYYPkM+qX
         pTm0o+suYGwpcuS4QN+iWHup6nczKmUIM2MMFbC6lSfNH4e5l+ZiPUvdNaY/dxpefi26
         EantixqDWfdwt8ValA7t7eoXBvZn+rcdmrhwSXc/Zl4z9S49UaMzaYum0+J8UTZgqRPE
         Xkjq7kRN/MwI6tnNtoXLup+TF9sV9xYvbgCNIDRvc6j2fhZ3lUei33stVS4qNvjE7Ens
         fwex71GsomDikZSwpWuV5buRLhiA1pbIqQYyzCSxNYCq/sUd+0CS7lREugvTjZO0Ao5x
         N1uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JRPQyB930S4MdnnhfscSj1xO6zuqshkdmJWzdA+VtH2r+sGmV
	+iX2G9xPBRxcisAPQGLcVug=
X-Google-Smtp-Source: ABdhPJzspr2jg+k61xeZJnGSbNJ7/iMmmWg5ED375mAs28t4Ktl53u58Y0dhj02MygGyssTS2cLoKQ==
X-Received: by 2002:a2e:8118:: with SMTP id d24mr1677605ljg.133.1614866918266;
        Thu, 04 Mar 2021 06:08:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b603:: with SMTP id r3ls1209258ljn.5.gmail; Thu, 04 Mar
 2021 06:08:37 -0800 (PST)
X-Received: by 2002:a2e:9c10:: with SMTP id s16mr2268699lji.457.1614866917169;
        Thu, 04 Mar 2021 06:08:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614866917; cv=none;
        d=google.com; s=arc-20160816;
        b=RiOfihu6yjVLu2QtPJ6LT+kxKqCjjRSkZzSzOLHeoEs4+PyuWVd5/wnsf2YHCajaBa
         2PHz6RwlZxY1FcHAcnlBi6ZDSas0poxZdFTEM87m06fGysrmGCEGtdbQWcbK+cM7IDFX
         VJoJMaTAFyOapD3vNtKsyr8yyMU0CdKXyTAxNSqHRN7QTU/FiuUyz/uHqIbAyab3ZqHR
         0FE3jy+ZEj6NHwsXwDK4dS/qidkJ14aPtzjMEax55DY+KY0nkDeF4A9LT0pX1M1KhDQM
         C7T9yAOdAsYe99FjSJWtekrrlVL3Bd3nLPsLjZ2KdUUBoVKUOuGjC2Bp4nKFJqTlyvD7
         CIGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7w+55pfTVH4wQxX+7+fGj9XRpIuXYUnYYSmvDDuR078=;
        b=lAHpNq86WCZGr5Ur1VF4zc3Y5Tn0iEJEm3WKrp2r9N3AVpow45BNFmqJuB2H8ddcLT
         enLsMgMFDjjbovInpBv/xq6rMpMKQpmy86f+gATRFLpjYxGs6360i+qyNbhJADN4TnyP
         hHGMypQRVM3MFUv27y9H4R3SBtwoVf8XdX5oZB58+PD3NvH78elQxbTUpO1dTcw9aTRd
         bb7xEqFo01wjqicnTZw17hJri286keNSfl8A+5/y0Zc7oTQl5T388ZcrXUFXG6pblrfY
         dYuoJ+ajWcJ3TxdR7PkBLN7Q4VCaALfT1Ml/ck0hYjE6g2G/vW3Zzr9ow/+FU29nMTi7
         yZ/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z2si1048693ljm.0.2021.03.04.06.08.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:08:36 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Drt4x6GPgz9v4Tn;
	Thu,  4 Mar 2021 15:08:33 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id dT301ejb3PY6; Thu,  4 Mar 2021 15:08:33 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Drt4x59X3z9v4Tl;
	Thu,  4 Mar 2021 15:08:33 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B7EE28B80A;
	Thu,  4 Mar 2021 15:08:35 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id LRqkBOW4SWOI; Thu,  4 Mar 2021 15:08:35 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0DB758B812;
	Thu,  4 Mar 2021 15:08:35 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
References: <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
 <YEDXJ5JNkgvDFehc@elver.google.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <4b46ecc9-ae47-eee1-843e-e0638a356b51@csgroup.eu>
Date: Thu, 4 Mar 2021 15:08:31 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <YEDXJ5JNkgvDFehc@elver.google.com>
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



Le 04/03/2021 =C3=A0 13:48, Marco Elver a =C3=A9crit=C2=A0:
>  From d118080eb9552073f5dcf1f86198f3d86d5ea850 Mon Sep 17 00:00:00 2001
> From: Marco Elver <elver@google.com>
> Date: Thu, 4 Mar 2021 13:15:51 +0100
> Subject: [PATCH] kfence: fix reports if constant function prefixes exist
>=20
> Some architectures prefix all functions with a constant string ('.' on
> ppc64). Add ARCH_FUNC_PREFIX, which may optionally be defined in
> <asm/kfence.h>, so that get_stack_skipnr() can work properly.


It works, thanks.

>=20
> Link: https://lkml.kernel.org/r/f036c53d-7e81-763c-47f4-6024c6c5f058@csgr=
oup.eu
> Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Marco Elver <elver@google.com>

Tested-by: Christophe Leroy <christophe.leroy@csgroup.eu>

> ---
>   mm/kfence/report.c | 18 ++++++++++++------
>   1 file changed, 12 insertions(+), 6 deletions(-)
>=20
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 519f037720f5..e3f71451ad9e 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -20,6 +20,11 @@
>  =20
>   #include "kfence.h"
>  =20
> +/* May be overridden by <asm/kfence.h>. */
> +#ifndef ARCH_FUNC_PREFIX
> +#define ARCH_FUNC_PREFIX ""
> +#endif
> +
>   extern bool no_hash_pointers;
>  =20
>   /* Helper function to either print to a seq_file or to console. */
> @@ -67,8 +72,9 @@ static int get_stack_skipnr(const unsigned long stack_e=
ntries[], int num_entries
>   	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
>   		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[=
skipnr]);
>  =20
> -		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_")=
 ||
> -		    !strncmp(buf, "__slab_free", len)) {
> +		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfence_") ||
> +		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kfence_") ||
> +		    !strncmp(buf, ARCH_FUNC_PREFIX "__slab_free", len)) {
>   			/*
>   			 * In case of tail calls from any of the below
>   			 * to any of the above.
> @@ -77,10 +83,10 @@ static int get_stack_skipnr(const unsigned long stack=
_entries[], int num_entries
>   		}
>  =20
>   		/* Also the *_bulk() variants by only checking prefixes. */
> -		if (str_has_prefix(buf, "kfree") ||
> -		    str_has_prefix(buf, "kmem_cache_free") ||
> -		    str_has_prefix(buf, "__kmalloc") ||
> -		    str_has_prefix(buf, "kmem_cache_alloc"))
> +		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
> +		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
> +		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
> +		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
>   			goto found;
>   	}
>   	if (fallback < num_entries)
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4b46ecc9-ae47-eee1-843e-e0638a356b51%40csgroup.eu.
