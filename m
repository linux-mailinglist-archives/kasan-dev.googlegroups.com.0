Return-Path: <kasan-dev+bncBDLKPY4HVQKBBKMSQOBAMGQEX7ORCII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D80032D1F9
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 12:48:58 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id n17sf2441327wmi.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 03:48:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614858538; cv=pass;
        d=google.com; s=arc-20160816;
        b=DuVIDzShoxczorRultYQUwtcsXmFFCCvt4/jTlSvi17gP3hYriIUnh26Wft4h3gSri
         97NDDa5kjkgmCgQLYd/0bpEfGE3C1iHsgTOvjYg5Cj2UfnauPwUscSCYOyAPaWfEDgr9
         qcKyt9uf+sstzIDTBzDDgDK0/laAL1AT3TifJtcdtBav6AO9FLY8NmrwL4sqpHYyyn9O
         NITqC3Kc2VaYtYqFMq/ulsDbXEO3MHROxHrDw6W1+KxeX4AnFjzjPGnz5Begwr6jTwTq
         PXSVEseu33bGkvTBW+IcbBrUHPVZICN2p4WSHZEwobLsp0e+nL5FNeoDP/aLgmA5vx3/
         ruCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=RWSSXWOx2aOlBp/zeGr0ZfOUpPoEcr5Hm5ioi5G5GHM=;
        b=kgJLmmqb9GgFfHPb1hmHuv8adGZTzAzKMPv3LpWB6JMdzK3bvr/s8Fp3NgOTJ02HZS
         rMCRK+5LsS11s90QWjRJftYZMctyKdc5rPT4PdQCM8ph+BpKuahtFLmVwvIMVeXf7IXn
         +LG4nmR74ckN/+j6Zn7VU8wg4s1UwvMkW206Wz4NMIuCm3npgrfuSs8iMEfMiee95WgF
         md9/JsgrBcs5TYi0EUt4o/hOKyBzJrlrbTDHB+1U3Xu35zL03r0G8NZgyKnWPAWaUB4y
         I1qn+OkQb8+cUV2LJyGTui1OgfnVPdCNQudcmjjgvL2P1gF/hpfoKv+bEBLsJmvtB/Kk
         1JOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RWSSXWOx2aOlBp/zeGr0ZfOUpPoEcr5Hm5ioi5G5GHM=;
        b=fVpeVY4NFogD4qJkfdvHv5lMp599Q+L3jHemfaC0tjiyFKUvkrgNyLMg/Rt6GnvDf0
         rS3CY8hzZYnjuilODnNBqZq3mbU+/x3vaP3QapC2Kv+aOO4hg+f7hZu+vQyaLhcjlLyA
         lV5MnS9MiPxFujKyWLR7SeuWDU0yoYVxdwd6ozz2XUn6troMrjVQ6XjTwlEvsbrOOdT1
         zcs/cT4Jd9P1SnznPr0DjBYRfwoXF2sIFFOVFXahyxrEIHS7Mvupsekyf+t8zZipGRD1
         IdZUxHjhaAJwN3/Oi/vmGdUUWCtSwsRzxS5WQYUVlksXY1DVrcDoLDimBs45y6ZrDI5l
         mpkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RWSSXWOx2aOlBp/zeGr0ZfOUpPoEcr5Hm5ioi5G5GHM=;
        b=KtOd+C4BtwTxwldEM7GTObdlac0xYnWAe7ih9bVr6D39F76dpM0RgYAdzlp6CVg6bb
         znhcTXUNkUCX00QowXZBVUe3vJ/YYc3AJNsI5wMDFQYqytyCe6g8ZGT7krklOor30nDT
         ToecuIWJayuj26/0OW3InFSGgXKj9N4lEq6Wv7gN7DNvFdY5W+G0Q972gq+TGuHAoLFm
         PmytyMClXafUDRNtHU4icm6OWj7ov0oGcCp3xoZMGnxqyqaMLyfYayF3qatTQtQaVKCm
         sbQ1fGVk/bEuCX9ta2od0mxeINdo3qFntidGHT6znC5XipW3lDzHmEztHhEot42MAmh4
         lP3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qqVV9y/dHIUC9IunwnuDF0Z/laUzHjAdUWuG+8ftWOpXQhWI1
	f6GqVxypuV4nqtzy3OnsNDM=
X-Google-Smtp-Source: ABdhPJz0Ogk8Zj4H1j/qJD0ZOpAdrL3vJk5KtpZMoGnIXUEG8FeGai4kTw4eD3sjQR1X7EI8Ywa1+w==
X-Received: by 2002:adf:e74a:: with SMTP id c10mr3708272wrn.409.1614858538078;
        Thu, 04 Mar 2021 03:48:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1981:: with SMTP id 123ls2689943wmz.3.gmail; Thu, 04 Mar
 2021 03:48:57 -0800 (PST)
X-Received: by 2002:a1c:e4d4:: with SMTP id b203mr3395802wmh.105.1614858537295;
        Thu, 04 Mar 2021 03:48:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614858537; cv=none;
        d=google.com; s=arc-20160816;
        b=VcuID1CxWj3n0fVwCj4vEdrNQVe9uBDdzuxyyzIqDJuW3+BdUBxa5agMw0Vv1WhFcV
         ymROtxczmTgYyo8rSMgUfd/RQL6KGoLGYxaophT0HudRbRTlC4o7rSRDgE7Ng4KqlGSz
         KOre3xX6AqHvu5TNozdh3/atS7AoIUQuQPlgzrv/IW3fmygjd/Gm3B+Vdqkfwtx+XPGp
         spE+My5//aec1meHdGDlV0IA02HGj6wFx27aNsDUtD3Ts+NKg7CkxB1ogzNmcSIb9dCC
         jvQuSmfnFXjghALmFYQbYgk3H2go+fgf2dVSYuTmHmJQCsefWRNA8BECJcbqPkkLYYwp
         Z9GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=VEsGbcp7NJOM6owMdUzrSzC8MzhRaXkplHYLocJwJxs=;
        b=TXcJBTaICkLDTr0Kz8KBdMporgDg/+RBz4pYw/vZURUE4pWibX530wfmLpUl3aXTN9
         MLw57U408c/FlSeLBzGqtYJ0nerpAj+YQErIqcvHHgN/jsQAxFPFoqRGVwN9sR+MTIgW
         m7ZdxL+Yk67Zi7c3+Eyxhkiha3HV/6g2EVJ22j5Vj7X0TXiZEvs/9FBKshHkC5LIfJPS
         iVmmffd7x7orplw80Um2AALHFDE4MMOp8uJ1ebBJVC1Vd7lbNminPDOeG4GmoQjXQGc/
         uRfO67iPRXQknhbJOEmn0pRn77yqAbCKqH1QQnRuX4doOKBhAD/D7vUW+NdPx6r9Vp+I
         Vw8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i22si558827wml.2.2021.03.04.03.48.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 03:48:57 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Drpzp3xTYz9v1sK;
	Thu,  4 Mar 2021 12:48:54 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id h-mitI98mN7r; Thu,  4 Mar 2021 12:48:54 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Drpzp2DxPz9v1sG;
	Thu,  4 Mar 2021 12:48:54 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 2270C8B7FF;
	Thu,  4 Mar 2021 12:48:56 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id VRrx4alowTpf; Thu,  4 Mar 2021 12:48:56 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 665B48B773;
	Thu,  4 Mar 2021 12:48:55 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
 <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
Date: Thu, 4 Mar 2021 12:48:56 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
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



Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit=C2=A0:
> On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>> Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
>>>
>>> Somewhat tangentially, I also note that e.g. show_regs(regs) (which
>>> was printed along the KFENCE report above) didn't include the top
>>> frame in the "Call Trace", so this assumption is definitely not
>>> isolated to KFENCE.
>>>
>>
>> Now, I have tested PPC64 (with the patch I sent yesterday to modify save=
_stack_trace_regs()
>> applied), and I get many failures. Any idea ?
>>
>> [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_free=
+0x2e4/0x530
>> [   17.654379][   T58]
>> [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence-#77=
):
>> [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
>> [   17.655775][   T58]  .__slab_free+0x320/0x5a0
>> [   17.656039][   T58]  .test_double_free+0xe0/0x198
>> [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
>> [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
>> [   17.657161][   T58]  .kthread+0x18c/0x1a0
>> [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
>> [   17.659869][   T58]
>> [   17.663954][   T58] kfence-#77 [0xc00000003c9c0000-0xc00000003c9c001f=
, size=3D32, cache=3Dkmalloc-32]
>> allocated by task 58:
>> [   17.666113][   T58]  .__kfence_alloc+0x1bc/0x510
>> [   17.667069][   T58]  .__kmalloc+0x280/0x4f0
>> [   17.667452][   T58]  .test_alloc+0x19c/0x430
>> [   17.667732][   T58]  .test_double_free+0x88/0x198
>> [   17.667971][   T58]  .kunit_try_run_case+0x80/0x110
>> [   17.668283][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
>> [   17.668553][   T58]  .kthread+0x18c/0x1a0
>> [   17.669315][   T58]  .ret_from_kernel_thread+0x58/0x70
>> [   17.669711][   T58]
>> [   17.669711][   T58] freed by task 58:
>> [   17.670116][   T58]  .kfence_guarded_free+0x3d0/0x530
>> [   17.670421][   T58]  .__slab_free+0x320/0x5a0
>> [   17.670603][   T58]  .test_double_free+0xb4/0x198
>> [   17.670827][   T58]  .kunit_try_run_case+0x80/0x110
>> [   17.671073][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
>> [   17.671410][   T58]  .kthread+0x18c/0x1a0
>> [   17.671618][   T58]  .ret_from_kernel_thread+0x58/0x70
>> [   17.671972][   T58]
>> [   17.672638][   T58] CPU: 0 PID: 58 Comm: kunit_try_catch Tainted: G  =
  B
>> 5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
>> [   17.673768][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [   17.677031][   T58]     # test_double_free: EXPECTATION FAILED at mm/=
kfence/kfence_test.c:380
>> [   17.677031][   T58]     Expected report_matches(&expect) to be true, =
but is false
>> [   17.684397][    T1]     not ok 7 - test_double_free
>> [   17.686463][   T59]     # test_double_free-memcache: setup_test_cache=
: size=3D32, ctor=3D0x0
>> [   17.688403][   T59]     # test_double_free-memcache: test_alloc: size=
=3D32, gfp=3Dcc0, policy=3Dany,
>> cache=3D1
>=20
> Looks like something is prepending '.' to function names. We expect
> the function name to appear as-is, e.g. "kfence_guarded_free",
> "test_double_free", etc.
>=20
> Is there something special on ppc64, where the '.' is some convention?
>=20

I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi=
.html#FUNC-DES

Also see commit https://github.com/linuxppc/linux/commit/02424d896

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7270e1cc-bb6b-99ee-0043-08a027b8d83a%40csgroup.eu.
