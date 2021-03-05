Return-Path: <kasan-dev+bncBDLKPY4HVQKBB2OUQ6BAMGQET5NSJPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id CD02232E38F
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 09:23:05 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id j15sf503151lfe.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 00:23:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614932585; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rwj9Oh8/S/5cQGMZ5TYeJb5pKolUiV9K1Mcw15qArQTeNGu+9rOT5LyfeycqUqSW1i
         DIwEvyAY1alYnRPZyCgJGT0UzB1lZS/Pzpx/8ziSwJlFxxyG+CJKJp01oAFXxxGJkpI7
         7f4YiYeFDvg6KvXYKuVxiD0S0LknzpBOlKta9ul6YZSY66HSD2Q5zP6Jl0mM7WP0b1ch
         DNhgqygzJMgJ+N4q1ulgykuor4AVZq8e1fQc4wQF+4wZXWDbdw+pgLSzATpfkCrC9mBz
         3zGr/kV78pYg/dJ5hNmxVzXXO+J2dlSqIRbZ6Jsaoc0n7WZv03T1s82HV4L7H7BxHhJq
         ibog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=fc5Pq/WsNZt2KSdO1yl/9ab+UJPcZSSO9nvVzzGOUmo=;
        b=EaDgrg67wGHa8ffgbPijzNkhFOxONBXXsRQkzi5WrZmjBzosdz0eKjYsL4o2wCaxZz
         rgi1wwlhtrMbIKg1P/fvweXuR+vXPkt9/nILDeHY9kaP1ilMiivd1+MhsHiAcSkXIRx2
         yikxoBXubn/Cj1OhAyGSAgfMZm+WcfISjnG5tEPpeETIaaKMVKEQwncMTHvAjGkx59m5
         sXmwTGizGHYJoWj30hwWV873Ddfx/0VUahQrXnp9dvqxizXGSGtNZVrhM8rjkFt3X/5d
         6iLVkLsimhrAW4eUzt+EZGHtVdfMyC/V53Bzav3kC9CnfeWXCzY/Y1hJLr+KRd9z7HUn
         qmZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fc5Pq/WsNZt2KSdO1yl/9ab+UJPcZSSO9nvVzzGOUmo=;
        b=WZAGRHrMuTKs1JReQE/7ia7u55QZZjUY2C9hovma6jVbAri7a7lgdq9THxjEyse+wl
         ZsfQloz+jKrGrjuQDjeFgQV/RqeOIw5Vn4c0cIzcuV2qL5pB6n6o8s9UZuCkdt/e+T7Z
         WWUp4ysKa0yRXMDmajU5i4dD3nLVlnn2CxPkICpZxsyTgkLSmFLLedZBRaj4Ek386RCe
         aIFbTcDrfODNQABJWqPtbTuOfpF/euGw5tvzfcY6/AuHycCGIfDGsW372VZYarWwK1JS
         fiAQJYPqKiqsGmAiuMxvLtOj9qxque4UFmDfiNoPnuYVszwRaiAGgSts/7+saR0628ma
         NHOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fc5Pq/WsNZt2KSdO1yl/9ab+UJPcZSSO9nvVzzGOUmo=;
        b=tclqYv/egwcoUKDzjn8ulQKhbSjH8uKfgFls2zbG9Q5GMNQjxv0gvxez6Fxfu5ixsV
         unLxzbYfnA8gQu0An+lRTQ780RmXfWpR1SaRao4zxV1Klzy5REm/n80PPd8cttH+HqCL
         Nmb2qdE3UhdWWsm2nfRztzqx67HIQdzYCynsSUcbBEykjLykhT1jZI2jnKdK/T0SX7TA
         IrJE0n4ovNeLg8TVTVgm7ptxff0W1aO782dYcJrEglcKpRKRHAqG3mI64LpOgQDZOMUc
         3ASV11qdfpIAUHOkZ1WUcRbVxzfydsh2EbacB94A8pPjbyVk5zcoPYoU4b61wphRjURq
         I7dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NxhLQk3jJJWMHP+dUbisshS+93XyzPXWT8e4N22G4jED4uQds
	4Ox9OuAt4IN0ODoDt+wyXyQ=
X-Google-Smtp-Source: ABdhPJwNKwj7G1mwcpjnqTGGJ6zT28VLV91CvrCxifmCJPHvwcgFOepFZv5nDPvj5lhiSIxx5r1FUA==
X-Received: by 2002:a2e:1649:: with SMTP id 9mr4737297ljw.74.1614932585393;
        Fri, 05 Mar 2021 00:23:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls3134304lff.1.gmail; Fri, 05
 Mar 2021 00:23:04 -0800 (PST)
X-Received: by 2002:a19:5f4d:: with SMTP id a13mr4893650lfj.174.1614932584356;
        Fri, 05 Mar 2021 00:23:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614932584; cv=none;
        d=google.com; s=arc-20160816;
        b=FnoKnCi/Tn1OLQgorncYxKLuv91qyRFYBvzTfBgdC0u5n3b6sQ0ApqiYwdIvhhaT+o
         /othARaY6NSk9vXYbUz5H5wnRhWPPtrjefUQHBiwoVvdKXjKXtI1k03cAi1dVX8Da2LV
         io7NwaqKMv9MeRw4K064EHHe13ELPnT9Qgem/deon17sRBmCNwkjF7edUJh2kkjQRDwa
         RxzF+n2YPMkex/HhxME/+9zV8Qe65kezmk7FjqJOWDq4GQX27OSdc4wQuBCBucvefsBd
         TrnGQqVZgR4rSLj+WQpF7Bev9bRhbTUX9HjRgPLt2F3aMmuUZVJ7m8aLCc4/YXH7NxYZ
         5Oyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=jGN5myyGuCkN/1Y/lQ63m8wV+6R58xBLyj3xgppqyH4=;
        b=LW7AfY8AOUh8LrNgWojEsTRiS8GICDoXe5ao1/mp9YNWU8+e89sh5s6XaZvbp5QOmi
         7OBU9Nrw6MsfdpqBW0t3+G3+vT7GT9nhHbwMqcWxu9aWP0C4WKiz3/F5PJIO60OyulTo
         Lxtk1jplFDWDiGYlrJ6yeei4LFq8Uhkt6CO15YTY43wiO+OMD7sdn+9282yhIHWvHSdl
         3MmU8G0MQBlRNl0gPQdhJeJ8flXwIR8+gCnp2LPNiJ0spjDCnnXKq3VLO9b5WZ/UOlo/
         C/KJTfR9YTSFaMaraGOuyI0xbLR30CWFrZWt2le54IYdW8vKVSNDyVRBsswxOpT0SSOA
         QUEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id k21si70399lji.3.2021.03.05.00.23.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Mar 2021 00:23:04 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DsLMp3HQjz9twsB;
	Fri,  5 Mar 2021 09:23:02 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id kZwaV1QlYV6g; Fri,  5 Mar 2021 09:23:02 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DsLMp21cgz9tws9;
	Fri,  5 Mar 2021 09:23:02 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 499B18B78B;
	Fri,  5 Mar 2021 09:23:03 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 0Bg31oR211ZU; Fri,  5 Mar 2021 09:23:03 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 8075A8B791;
	Fri,  5 Mar 2021 09:23:02 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Marco Elver <elver@google.com>, Michael Ellerman <mpe@ellerman.id.au>
Cc: Alexander Potapenko <glider@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Dmitry Vyukov <dvyukov@google.com>,
 LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
 <YEDXJ5JNkgvDFehc@elver.google.com> <874khqry78.fsf@mpe.ellerman.id.au>
 <YEHiq1ALdPn2crvP@elver.google.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <f6e47f4f-6953-6584-f023-8b9c22d6974e@csgroup.eu>
Date: Fri, 5 Mar 2021 09:23:00 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <YEHiq1ALdPn2crvP@elver.google.com>
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



Le 05/03/2021 =C3=A0 08:50, Marco Elver a =C3=A9crit=C2=A0:
> On Fri, Mar 05, 2021 at 04:01PM +1100, Michael Ellerman wrote:
>> Marco Elver <elver@google.com> writes:
>>> On Thu, Mar 04, 2021 at 12:48PM +0100, Christophe Leroy wrote:
>>>> Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit=C2=A0:
>>>>> On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
>>>>> <christophe.leroy@csgroup.eu> wrote:
>>>>>> Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
>>>>>>>
>>>>>>> Somewhat tangentially, I also note that e.g. show_regs(regs) (which
>>>>>>> was printed along the KFENCE report above) didn't include the top
>>>>>>> frame in the "Call Trace", so this assumption is definitely not
>>>>>>> isolated to KFENCE.
>>>>>>>
>>>>>>
>>>>>> Now, I have tested PPC64 (with the patch I sent yesterday to modify =
save_stack_trace_regs()
>>>>>> applied), and I get many failures. Any idea ?
>>>>>>
>>>>>> [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
>>>>>> [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_=
free+0x2e4/0x530
>>>>>> [   17.654379][   T58]
>>>>>> [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence=
-#77):
>>>>>> [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
>>>>>> [   17.655775][   T58]  .__slab_free+0x320/0x5a0
>>>>>> [   17.656039][   T58]  .test_double_free+0xe0/0x198
>>>>>> [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
>>>>>> [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x5=
0
>>>>>> [   17.657161][   T58]  .kthread+0x18c/0x1a0
>>>>>> [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
>>>>>> [   17.659869][   T58]
>>> [...]
>>>>>
>>>>> Looks like something is prepending '.' to function names. We expect
>>>>> the function name to appear as-is, e.g. "kfence_guarded_free",
>>>>> "test_double_free", etc.
>>>>>
>>>>> Is there something special on ppc64, where the '.' is some convention=
?
>>>>>
>>>>
>>>> I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf=
64abi.html#FUNC-DES
>>>>
>>>> Also see commit https://github.com/linuxppc/linux/commit/02424d896
>>>
>>> Thanks -- could you try the below patch? You'll need to define
>>> ARCH_FUNC_PREFIX accordingly.
>>>
>>> We think, since there are only very few architectures that add a prefix=
,
>>> requiring <asm/kfence.h> to define something like ARCH_FUNC_PREFIX is
>>> the simplest option. Let me know if this works for you.
>>>
>>> There an alternative option, which is to dynamically figure out the
>>> prefix, but if this simpler option is fine with you, we'd prefer it.
>>
>> We have rediscovered this problem in basically every tracing / debugging
>> feature added in the last 20 years :)
>>
>> I think the simplest solution is the one tools/perf/util/symbol.c uses,
>> which is to just skip a leading '.'.
>>
>> Does that work?
>>
>> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
>> index ab83d5a59bb1..67b49dc54b38 100644
>> --- a/mm/kfence/report.c
>> +++ b/mm/kfence/report.c
>> @@ -67,6 +67,9 @@ static int get_stack_skipnr(const unsigned long stack_=
entries[], int num_entries
>>   	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
>>   		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries=
[skipnr]);
>>  =20
>> +		if (buf[0] =3D=3D '.')
>> +			buf++;
>> +
>=20
> Unfortunately this does not work, since buf is an array. We'd need an
> offset, and it should be determined outside the loop. I had a solution
> like this, but it turned out quite complex (see below). And since most
> architectures do not require this, decided that the safest option is to
> use the macro approach with ARCH_FUNC_PREFIX, for which Christophe
> already prepared a patch and tested:
> https://lore.kernel.org/linux-mm/20210304144000.1148590-1-elver@google.co=
m/
> https://lkml.kernel.org/r/afaec81a551ef15345cb7d7563b3fac3d7041c3a.161486=
8445.git.christophe.leroy@csgroup.eu
>=20
> Since KFENCE requires <asm/kfence.h> anyway, we'd prefer this approach
> (vs.  dynamically detecting).
>=20
> Thanks,
> -- Marco
>=20

What about

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 519f037720f5..5e196625fb34 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -43,7 +43,7 @@ static void seq_con_printf(struct seq_file *seq, const ch=
ar *fmt, ...)
  static int get_stack_skipnr(const unsigned long stack_entries[], int num_=
entries,
  			    const enum kfence_error_type *type)
  {
-	char buf[64];
+	char _buf[64];
  	int skipnr, fallback =3D 0;

  	if (type) {
@@ -65,7 +65,11 @@ static int get_stack_skipnr(const unsigned long stack_en=
tries[], int num_entries
  	}

  	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
-		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[ski=
pnr]);
+		char *buf =3D _buf;
+		int len =3D scnprintf(_buf, sizeof(_buf), "%ps", (void *)stack_entries[s=
kipnr]);
+
+		if (_buf[0] =3D=3D '.')
+			buf++, len--;

  		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") =
||
  		    !strncmp(buf, "__slab_free", len)) {
---

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f6e47f4f-6953-6584-f023-8b9c22d6974e%40csgroup.eu.
