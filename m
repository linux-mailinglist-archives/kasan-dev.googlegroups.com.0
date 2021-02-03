Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQVZ5KAAMGQEGKY4YXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 1457B30DA3A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:53:25 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id j17sf10171531oig.7
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:53:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612356804; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rx7fi8aGeHeDudqZ116gh0RAwf9U/vwuITEKjnsR+/5VLFMgkGc8qDW1k89TMjgsBY
         um3UaMe34rwC74/UnygeAKVY4lDwcgQ+3diy4THLqBlnSShy8hCgMyK1NGlsYMCTu5WE
         bB+2z+P9BhNTIZc19cg543vZEkDKYjb0OBfKa0BqKKGlzqLO4wnzcQpRB5P2eKi0p6aU
         S50xGfgzXFlKxvxG3RV2Mz2ZsDmTkb8YR9BZY0WKFqHYL8OvsswT3MzT7/mNRrmH7TYE
         03m1VCR5NZjuwZRtqpcLNReEimscOBiTG4IMYECrMANg1A9UpItsOyWpRgnN0d+hlzNP
         chzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:to:from
         :sender:dkim-signature;
        bh=G2cXA2h5K8+RJtAlWUqFAzVDjVIEnpHCM2+Xkv+fE08=;
        b=DLtjQ5t3FcdcuUKgOgHf4H/b8eD+ndB03jnpgj3QeLvASOKVJGhTqFylJb6E8uGbnN
         nB3Mk+OtN/Uj93O+pRW8FCPY0TaArk7m1gUe4s4S8fAdG3KCAcCSnGjY8OC2dl5P3tGW
         I4rFMvbqWuFdKp5fux7cll1o4uw9w0kbVZx7wAIyOqTJRPhMlR6lJHvUbY252BOabDm9
         XgDSB5CP4KFqbh9liqwG1zvITrOtdlxzEDxuze5Qb8oqd/rOqLMs+q15IjfRsID5aqyG
         WzSoNRreIaj052A9eYB0bM04YVcLIkPfs2lvROpQ2YGi6Gx2N/UVRfzWqOpl09tTOv1o
         ZLZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=b6TzmQGy;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G2cXA2h5K8+RJtAlWUqFAzVDjVIEnpHCM2+Xkv+fE08=;
        b=NLSlSsEkSs9sD+4ILMLO5PDS3v8pH/jXWU7BwM95HgidHVqDC34ScD/mK1X3CFZII0
         uQ/6KqZSo2nV3jGQQdh5+GmxdxmpEjVU25PjtRGju8xljIAb65+Kh7b7CRxFsWZSpLkd
         4mY1nCYK7RUKZj5oHIQCpJ1n3IHKXS5mcT++ayH3EAzguCwxRiQZOn01fWx2B+gZ+EwK
         0JIa0+0N4wVs+SdXusgxA4adSR1/u13aUEHs6tLc774zvmmtp5p/GaLlyLMSPJy1YNr5
         w3AlBxOObicyLNxsCe2ggHF7JpwpxIMBzOoYfjHBAetYPVXcCP5KkJ08id5xOcdqaF/K
         qT/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=G2cXA2h5K8+RJtAlWUqFAzVDjVIEnpHCM2+Xkv+fE08=;
        b=dr8DisEt0s/f8INslZRKkVS4sy7aA45TjXgVGuLPoVWT9pBEyh6iBt9dH+cViWYtdo
         UOE+6IwRAzIvAuEjQ3KiK5GNI59lM1898hmktrD6nudnOJ7j5qCzdDYusV7sJSPq1j92
         x5UL1rbmroIqTXQ/WgVjkFzUaAo/kMx9/kFYF2iuStmx57NKu1oYcC2oD9fteNaT/mxz
         Fq22iYnYom0FnOSDwOzZVS6lIzTksHKnHwjU5jY4gsffoYMqJlmauCsDnj3ChwriIY5N
         TG1SVNKY4RL+rnIE3HMIxdr99P7WjfL96eTJZutnsvi5VUsmyNt7IY/f0UpfZCPE1VZg
         VGog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OMDZ2ncmLGDDF9Q/U89/cIyDpYNX26EjCloEOTJPnQiSAKWnU
	MgSly0s9uFj8DfMJlBTz7SQ=
X-Google-Smtp-Source: ABdhPJzKCNgNdlUpuZX5unzKsApkQsl/ZC1SEqhCSk6sookqB46bkB6qzCZkfVpyVAD0xkT3eaAqCg==
X-Received: by 2002:a9d:68d8:: with SMTP id i24mr1949241oto.14.1612356802590;
        Wed, 03 Feb 2021 04:53:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5786:: with SMTP id l128ls490617oib.1.gmail; Wed, 03 Feb
 2021 04:53:22 -0800 (PST)
X-Received: by 2002:aca:d6c4:: with SMTP id n187mr1938649oig.28.1612356802068;
        Wed, 03 Feb 2021 04:53:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612356802; cv=none;
        d=google.com; s=arc-20160816;
        b=zVhCe1DhDNd5BbIDBuayQxbVsBgI9J4rfU5ubdJCxxQ66dSnM/u5yNjnCco8mfk6WX
         /ZzxymUan/CXxD4E0YD149qoFw32qYxBPznl5TUWKhR23kPeJ1G7oAK4V8zxOWGbf0o1
         +DJv2DHrYNAVsCSgSIG/3jfqGL+QQ6OdzfAcFz9Rfa9khcesPQ4oJm730/Ap+AjLOvZn
         DEajEeyoMYdmO+1qslQOJAuxU10WikvlgXtSvEvPjl8T13FcqAUqfk61O2MuyvlprGTG
         nUjfc/AQNU/3CqLp2TuNqTHWApPEWK7VAEHfD90cNE2JTLPqi7ix9tGAnRaCO2jdaJhu
         9G5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:to:from:dkim-signature;
        bh=LOtl+4N3n7HC1FTJVHyIZDNqxeDX06oURAfIAKcKhm0=;
        b=xYmjryVaVCtWyDzLKPzFhSbV79bhEcm3LU23wEHr0Wym0qrjv/8rso+ApBp+z6DBxm
         QulV4/d081OX9qpTsIgbiJ2IamTYOgEjA/yP45YNkd+nF0MVmkYrGTO3NCuIqHGlBjCJ
         2D9RHDGLxDJ4hoAY5trtMDVC7sFUFQZc7BLIAUh8Vikxp1rg1q9CjLHY2BO+rrNn2Se9
         i1MgEmSxKqdoq8YTzh5ZPJKnEt67TEILcuU0Kma40I1JTxf+uirPB+3zKIdDfz9g1cKz
         UrSFq+vMjXynnujYP/Clc4Gw/w80JCTvNJc7qZjB2JSt0RIpsNUofiRo1I7vQTvxPAcy
         VuOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=b6TzmQGy;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id e184si160559oif.0.2021.02.03.04.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:53:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id o16so17334368pgg.5
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 04:53:21 -0800 (PST)
X-Received: by 2002:a63:ff4f:: with SMTP id s15mr3522513pgk.62.1612356801346;
        Wed, 03 Feb 2021 04:53:21 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id 9sm2288251pfy.110.2021.02.03.04.53.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 04:53:20 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v10 6/6] powerpc: Book3S 64-bit outline-only KASAN support
In-Reply-To: <4b790789-052f-76de-a289-726517026efd@csgroup.eu>
References: <20210203115946.663273-1-dja@axtens.net> <20210203115946.663273-7-dja@axtens.net> <4b790789-052f-76de-a289-726517026efd@csgroup.eu>
Date: Wed, 03 Feb 2021 23:53:17 +1100
Message-ID: <875z39wbwi.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=b6TzmQGy;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::532 as
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:

> Le 03/02/2021 =C3=A0 12:59, Daniel Axtens a =C3=A9crit=C2=A0:
>> Implement a limited form of KASAN for Book3S 64-bit machines running und=
er
>> the Radix MMU, supporting only outline mode.
>>=20
>
>> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process=
.c
>> index a66f435dabbf..9a6fd603f0e7 100644
>> --- a/arch/powerpc/kernel/process.c
>> +++ b/arch/powerpc/kernel/process.c
>> @@ -2157,8 +2157,8 @@ void show_stack(struct task_struct *tsk, unsigned =
long *stack,
>>   			break;
>>  =20
>>   		stack =3D (unsigned long *) sp;
>> -		newsp =3D stack[0];
>> -		ip =3D stack[STACK_FRAME_LR_SAVE];
>> +		newsp =3D READ_ONCE_NOCHECK(stack[0]);
>> +		ip =3D READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);
>>   		if (!firstframe || ip !=3D lr) {
>>   			printk("%s["REG"] ["REG"] %pS",
>>   				loglvl, sp, ip, (void *)ip);
>> @@ -2176,17 +2176,19 @@ void show_stack(struct task_struct *tsk, unsigne=
d long *stack,
>>   		 * See if this is an exception frame.
>>   		 * We look for the "regshere" marker in the current frame.
>>   		 */
>> -		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
>> -		    && stack[STACK_FRAME_MARKER] =3D=3D STACK_FRAME_REGS_MARKER) {
>> +		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE) &&
>> +		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) =3D=3D
>> +		     STACK_FRAME_REGS_MARKER)) {
>>   			struct pt_regs *regs =3D (struct pt_regs *)
>>   				(sp + STACK_FRAME_OVERHEAD);
>>  =20
>> -			lr =3D regs->link;
>> +			lr =3D READ_ONCE_NOCHECK(regs->link);
>>   			printk("%s--- interrupt: %lx at %pS\n",
>> -			       loglvl, regs->trap, (void *)regs->nip);
>> +			       loglvl, READ_ONCE_NOCHECK(regs->trap),
>> +			       (void *)READ_ONCE_NOCHECK(regs->nip));
>>   			__show_regs(regs);
>>   			printk("%s--- interrupt: %lx\n",
>> -			       loglvl, regs->trap);
>> +			       loglvl, READ_ONCE_NOCHECK(regs->trap));
>>  =20
>>   			firstframe =3D 1;
>>   		}
>
>
> The above changes look like a bug fix not directly related to KASAN. Shou=
ld be split out in another=20
> patch I think.

That code corresponds to the following part of the patch description:

| - Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
|   generic code, arm64, s390 and x86 all do this for similar sorts of
|   reasons: when unwinding a stack, we might touch memory that KASAN has
|   marked as being out-of-bounds. In our case we often get this when
|   checking for an exception frame because we're checking an arbitrary
|   offset into the stack frame.
|
|   See commit 20955746320e ("s390/kasan: avoid false positives during stac=
k
|   unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
|   frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
|   Prevent KASAN false positive warnings") and commit 6e22c8366416
|   ("tracing, kasan: Silence Kasan warning in check_stack of stack_tracer"=
)

include/linux/compiler.h describes it as follows:

/*
 * Use READ_ONCE_NOCHECK() instead of READ_ONCE() if you need
 * to hide memory access from KASAN.
 */

So I think it is sufficently connected with KASAN to be in this patch.

Kind regards,
Daniel

>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/875z39wbwi.fsf%40dja-thinkpad.axtens.net.
