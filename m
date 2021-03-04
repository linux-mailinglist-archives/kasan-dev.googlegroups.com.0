Return-Path: <kasan-dev+bncBDLKPY4HVQKBBTMXQOBAMGQEMTVNWMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FC5C32D221
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 13:00:14 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id f3sf7453195wrt.14
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 04:00:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614859214; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJXRzTIKAvCdajxQ7cj3N2iK2HvPdZhVm+OGGXc6AQV5YkdT9d5HdmJIXGLHr/nplz
         Litkf1ByCrDb/mmCvy/FK+1hOb6Q4Y0Mr3q7AKHiL2n7M5IVP6CIUuFgW7fTH3o3Ytka
         oeADDVEbYrMnGr6aC4PIZ8JPQQ9R6PXYxvogYMf80C9DcgZ0JgFA0CAtvToWQBglKFFx
         hxHrWpf7pi7iSxrTCmSD4bfkltq1k7H0eg81+hR8tLIFgyaZMNxktw80qCA8bEkiZ8rw
         jYlGPYhBlkiRlffGuk2aeMmQgdGlfm0EMTxNv6zbqejGi0e6nerJk1B7dQra79QB5JVG
         66Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=peTQte6jgahwjItOaagHov/Inu8gbJ6u6wX9ThLeeRk=;
        b=k3hX6gwSbiTc3P8WvfOQ7QFKNCw4FOf14/pzyWLFqlDSL3zue7uWi9n2RFebZedHw/
         BKUvLJv1mPa2rnSkF5TIMhOTNKFxPW96zImE1gGTOT9L5Kyrr1olghL3/FlrycSu7FSz
         6joR6qIb1/ZXIbotVWNi3voLvRMIHjuLA6BJatB3iMyNJtlNuWtZK5LoFWS+quGFBhnS
         yY3LPxunI5YCQKpiwm4HGc9zEWT8DBvjnAwBXaafcUQss2csF5XX4BWvF4irRgETJGAR
         H6bBAMM0gM73CnyA801hZUVUStZWJFJLD4lyJxhpUDjeogzWTLz8QdWSBLIVLECO/Z7o
         FEkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=peTQte6jgahwjItOaagHov/Inu8gbJ6u6wX9ThLeeRk=;
        b=ifQxlCMMs8/6r5KbpgV+tXf0KRtvedH7+XFPCEXtIZX48gT/MDe85Z3Cguw0orOMMo
         1I6+K6BfNg03R87r1wkIle792qVXZ4m2Nn7yQksAFvPIKqJvyU7ept4oG9RPExGLFMbm
         GB4dJDLwwUFRvmTN8xrLy1TgyXiz65bk0yJ4//RtzJUFa76ao5kOnD/jRbZST+aHGe29
         6dRy4pzpB3VLSOjq22VgBPgdxe0UpLkna573SkLT0h8WvBGPZodDaYeb8mPMiINH/e7W
         b8rjMji981jP3sOYDIPbqsJvd1hTdttCdy1mENx95KDzF3BWzuDvJrV+9pfRiXvFqnwK
         RPFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=peTQte6jgahwjItOaagHov/Inu8gbJ6u6wX9ThLeeRk=;
        b=k63U5PXouioU+UmdR0cjxehjxa5cZsuyM0goKctCXelwzXyv/soAxww9YP6OGYpcBu
         +Kn3OxUPf9FPkST7TYBciveTaEnF4Txhmqc+9AkTn1++AVyXNA/IDJFHFnEjdyhUag5g
         RU8kmZJ8iDjyOoJD7mPflPKjQKyXoF3yt8R0pF2KPGFiFOTmEjgAE2/pdjyVjePUJFAh
         ejes3EZ9ccrZHgbUVIFjoTfQNTKXtUYBTbzpeA+IESWX3gg4N9Q0iVzILPWtuCO1+dLh
         apihSqpWpHJLj1zLoQe0f3d/RBJmakOeqjNJwk/DtXzlwmsa7F60zr8yubCUthP8T1hu
         TvFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qa3sVbpkYM12aS4oNj20+2IBN7pfj0Igdch88m0XEAWuPRF+n
	LzcfcUydm41jS84ta5x/QIg=
X-Google-Smtp-Source: ABdhPJzjry0+J9dLWbigjPvzRDOGM5uXwyn57GMLi7QxyK7p7Tpa9w0jG3QbiAaAcQroeQOzmLIfUA==
X-Received: by 2002:a7b:c750:: with SMTP id w16mr3646215wmk.184.1614859213976;
        Thu, 04 Mar 2021 04:00:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4ecf:: with SMTP id s15ls3103737wrv.1.gmail; Thu, 04 Mar
 2021 04:00:13 -0800 (PST)
X-Received: by 2002:adf:df10:: with SMTP id y16mr3660679wrl.372.1614859213159;
        Thu, 04 Mar 2021 04:00:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614859213; cv=none;
        d=google.com; s=arc-20160816;
        b=JojskxYQJs83yJMzSE+HB8RV3xEgQ1C6skVEcu2DKLgM65TSgTdjDEB8Auv5svfM5I
         OykNV8T/KDCbc0FFYPWvN8LD68lWD/eSfuPkBAKN//cY/R11H4pMuwRCRTvNpTbQcfXT
         NcwSreGxI6RcZJJ2g400vgYNKLUM3PThNWquKkHBUS9ntRVN/GyxviQMyj1Ak+lNmYed
         hgHcfF7FUhe2Zd3ezCS7Hf9kFt3S2Nl9pvXSp+VagvzB3cbuQeldlQqlbd+E8SJOHgUb
         xOA1ZUo1tHEepBukgODr0zBGYSBhkZFAcuycbzqmEcVwjoTE+NVzlGblelyylqAJv2mm
         id6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=8c6ImtNcDQdeuTDhXsft/HEXDIn9L6WiedEhOvf6jcY=;
        b=faZglkiBPEVb+mkZbUVJ7vEo7iBvvQ9pGB1p18HBAYCHxTnRL73WHAXPPv9IZCIOPv
         Num3az9gGCuDEX80rPWE0CbubUpYzyEm4iO4/F7+aNCposhm24OVluMQhfph7pW5eV33
         0g8lwvIpdBP9feE+bSXkiYBMItDVhFFLXCEVTmQUUcpyaST4dT64UQw5fSSPQUlCd4i0
         rVMVhckFDLZJnMypFdvhECgI6l9cPbuIJKcQoz0559K3HrskObbbIFDFgcQAzfFuTrWs
         chtE5SVotpHu/As423it4JwCMG4kqTpNy2ynJ74Iv3vWqkeG4tY9Q6TpdqshW00HfcOG
         E8cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y12si746560wrs.0.2021.03.04.04.00.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 04:00:13 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DrqDp6YzNz9txSQ;
	Thu,  4 Mar 2021 13:00:10 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id ul2e4nFalk73; Thu,  4 Mar 2021 13:00:10 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DrqDp5jDSz9txSN;
	Thu,  4 Mar 2021 13:00:10 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 7298D8B773;
	Thu,  4 Mar 2021 13:00:12 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 3Rhw-N1jCZuV; Thu,  4 Mar 2021 13:00:12 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BFDDC8B7FF;
	Thu,  4 Mar 2021 13:00:11 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
From: Christophe Leroy <christophe.leroy@csgroup.eu>
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
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
Message-ID: <72e31c34-e947-1084-2bd2-f5b80786f827@csgroup.eu>
Date: Thu, 4 Mar 2021 13:00:12 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
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



Le 04/03/2021 =C3=A0 12:48, Christophe Leroy a =C3=A9crit=C2=A0:
>=20
>=20
> Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit=C2=A0:
>> On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
>> <christophe.leroy@csgroup.eu> wrote:
>>> Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
>>>>
>>>> Somewhat tangentially, I also note that e.g. show_regs(regs) (which
>>>> was printed along the KFENCE report above) didn't include the top
>>>> frame in the "Call Trace", so this assumption is definitely not
>>>> isolated to KFENCE.
>>>>
>>>
>>> Now, I have tested PPC64 (with the patch I sent yesterday to modify sav=
e_stack_trace_regs()
>>> applied), and I get many failures. Any idea ?
>>>
>>> [=C2=A0=C2=A0 17.653751][=C2=A0=C2=A0 T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>>> [=C2=A0=C2=A0 17.654379][=C2=A0=C2=A0 T58] BUG: KFENCE: invalid free in=
 .kfence_guarded_free+0x2e4/0x530
>>> [=C2=A0=C2=A0 17.654379][=C2=A0=C2=A0 T58]
>>> [=C2=A0=C2=A0 17.654831][=C2=A0=C2=A0 T58] Invalid free of 0xc00000003c=
9c0000 (in kfence-#77):
>>> [=C2=A0=C2=A0 17.655358][=C2=A0=C2=A0 T58]=C2=A0 .kfence_guarded_free+0=
x2e4/0x530
>>> [=C2=A0=C2=A0 17.655775][=C2=A0=C2=A0 T58]=C2=A0 .__slab_free+0x320/0x5=
a0
>>> [=C2=A0=C2=A0 17.656039][=C2=A0=C2=A0 T58]=C2=A0 .test_double_free+0xe0=
/0x198
>>> [=C2=A0=C2=A0 17.656308][=C2=A0=C2=A0 T58]=C2=A0 .kunit_try_run_case+0x=
80/0x110
>>> [=C2=A0=C2=A0 17.656523][=C2=A0=C2=A0 T58]=C2=A0 .kunit_generic_run_thr=
eadfn_adapter+0x38/0x50
>>> [=C2=A0=C2=A0 17.657161][=C2=A0=C2=A0 T58]=C2=A0 .kthread+0x18c/0x1a0
>>> [=C2=A0=C2=A0 17.659148][=C2=A0=C2=A0 T58]=C2=A0 .ret_from_kernel_threa=
d+0x58/0x70
>>> [=C2=A0=C2=A0 17.659869][=C2=A0=C2=A0 T58]
>>> [=C2=A0=C2=A0 17.663954][=C2=A0=C2=A0 T58] kfence-#77 [0xc00000003c9c00=
00-0xc00000003c9c001f, size=3D32, cache=3Dkmalloc-32]
>>> allocated by task 58:
>>> [=C2=A0=C2=A0 17.666113][=C2=A0=C2=A0 T58]=C2=A0 .__kfence_alloc+0x1bc/=
0x510
>>> [=C2=A0=C2=A0 17.667069][=C2=A0=C2=A0 T58]=C2=A0 .__kmalloc+0x280/0x4f0
>>> [=C2=A0=C2=A0 17.667452][=C2=A0=C2=A0 T58]=C2=A0 .test_alloc+0x19c/0x43=
0
>>> [=C2=A0=C2=A0 17.667732][=C2=A0=C2=A0 T58]=C2=A0 .test_double_free+0x88=
/0x198
>>> [=C2=A0=C2=A0 17.667971][=C2=A0=C2=A0 T58]=C2=A0 .kunit_try_run_case+0x=
80/0x110
>>> [=C2=A0=C2=A0 17.668283][=C2=A0=C2=A0 T58]=C2=A0 .kunit_generic_run_thr=
eadfn_adapter+0x38/0x50
>>> [=C2=A0=C2=A0 17.668553][=C2=A0=C2=A0 T58]=C2=A0 .kthread+0x18c/0x1a0
>>> [=C2=A0=C2=A0 17.669315][=C2=A0=C2=A0 T58]=C2=A0 .ret_from_kernel_threa=
d+0x58/0x70
>>> [=C2=A0=C2=A0 17.669711][=C2=A0=C2=A0 T58]
>>> [=C2=A0=C2=A0 17.669711][=C2=A0=C2=A0 T58] freed by task 58:
>>> [=C2=A0=C2=A0 17.670116][=C2=A0=C2=A0 T58]=C2=A0 .kfence_guarded_free+0=
x3d0/0x530
>>> [=C2=A0=C2=A0 17.670421][=C2=A0=C2=A0 T58]=C2=A0 .__slab_free+0x320/0x5=
a0
>>> [=C2=A0=C2=A0 17.670603][=C2=A0=C2=A0 T58]=C2=A0 .test_double_free+0xb4=
/0x198
>>> [=C2=A0=C2=A0 17.670827][=C2=A0=C2=A0 T58]=C2=A0 .kunit_try_run_case+0x=
80/0x110
>>> [=C2=A0=C2=A0 17.671073][=C2=A0=C2=A0 T58]=C2=A0 .kunit_generic_run_thr=
eadfn_adapter+0x38/0x50
>>> [=C2=A0=C2=A0 17.671410][=C2=A0=C2=A0 T58]=C2=A0 .kthread+0x18c/0x1a0
>>> [=C2=A0=C2=A0 17.671618][=C2=A0=C2=A0 T58]=C2=A0 .ret_from_kernel_threa=
d+0x58/0x70
>>> [=C2=A0=C2=A0 17.671972][=C2=A0=C2=A0 T58]
>>> [=C2=A0=C2=A0 17.672638][=C2=A0=C2=A0 T58] CPU: 0 PID: 58 Comm: kunit_t=
ry_catch Tainted: G=C2=A0=C2=A0=C2=A0 B
>>> 5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
>>> [=C2=A0=C2=A0 17.673768][=C2=A0=C2=A0 T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>>> [=C2=A0=C2=A0 17.677031][=C2=A0=C2=A0 T58]=C2=A0=C2=A0=C2=A0=C2=A0 # te=
st_double_free: EXPECTATION FAILED at mm/kfence/kfence_test.c:380
>>> [=C2=A0=C2=A0 17.677031][=C2=A0=C2=A0 T58]=C2=A0=C2=A0=C2=A0=C2=A0 Expe=
cted report_matches(&expect) to be true, but is false
>>> [=C2=A0=C2=A0 17.684397][=C2=A0=C2=A0=C2=A0 T1]=C2=A0=C2=A0=C2=A0=C2=A0=
 not ok 7 - test_double_free
>>> [=C2=A0=C2=A0 17.686463][=C2=A0=C2=A0 T59]=C2=A0=C2=A0=C2=A0=C2=A0 # te=
st_double_free-memcache: setup_test_cache: size=3D32, ctor=3D0x0
>>> [=C2=A0=C2=A0 17.688403][=C2=A0=C2=A0 T59]=C2=A0=C2=A0=C2=A0=C2=A0 # te=
st_double_free-memcache: test_alloc: size=3D32, gfp=3Dcc0, policy=3Dany,
>>> cache=3D1
>>
>> Looks like something is prepending '.' to function names. We expect
>> the function name to appear as-is, e.g. "kfence_guarded_free",
>> "test_double_free", etc.
>>
>> Is there something special on ppc64, where the '.' is some convention?
>>
>=20
> I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64a=
bi.html#FUNC-DES
>=20
> Also see commit https://github.com/linuxppc/linux/commit/02424d896
>=20

But I'm wondering, if the dot is the problem, how so is the following one o=
k ?

[   79.574457][   T75]     # test_krealloc: test_alloc: size=3D32, gfp=3Dcc=
0, policy=3Dany, cache=3D0
[   79.682728][   T75] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   79.684017][   T75] BUG: KFENCE: use-after-free read in .test_krealloc+0=
x4fc/0x5b8
[   79.684017][   T75]
[   79.684955][   T75] Use-after-free read at 0xc00000003d060000 (in kfence=
-#130):
[   79.687581][   T75]  .test_krealloc+0x4fc/0x5b8
[   79.688216][   T75]  .test_krealloc+0x4e4/0x5b8
[   79.688824][   T75]  .kunit_try_run_case+0x80/0x110
[   79.689737][   T75]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   79.690335][   T75]  .kthread+0x18c/0x1a0
[   79.691092][   T75]  .ret_from_kernel_thread+0x58/0x70
[   79.692081][   T75]
[   79.692671][   T75] kfence-#130 [0xc00000003d060000-0xc00000003d06001f, =
size=3D32,=20
cache=3Dkmalloc-32] allocated by task 75:
[   79.700977][   T75]  .__kfence_alloc+0x1bc/0x510
[   79.701812][   T75]  .__kmalloc+0x280/0x4f0
[   79.702695][   T75]  .test_alloc+0x19c/0x430
[   79.703051][   T75]  .test_krealloc+0xa8/0x5b8
[   79.703276][   T75]  .kunit_try_run_case+0x80/0x110
[   79.703693][   T75]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   79.704223][   T75]  .kthread+0x18c/0x1a0
[   79.704586][   T75]  .ret_from_kernel_thread+0x58/0x70
[   79.704968][   T75]
[   79.704968][   T75] freed by task 75:
[   79.705756][   T75]  .kfence_guarded_free+0x3d0/0x530
[   79.706754][   T75]  .__slab_free+0x320/0x5a0
[   79.708575][   T75]  .krealloc+0xe8/0x180
[   79.708970][   T75]  .test_krealloc+0x1c8/0x5b8
[   79.709606][   T75]  .kunit_try_run_case+0x80/0x110
[   79.710204][   T75]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   79.710639][   T75]  .kthread+0x18c/0x1a0
[   79.710996][   T75]  .ret_from_kernel_thread+0x58/0x70
[   79.711349][   T75]
[   79.717435][   T75] CPU: 0 PID: 75 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   79.718124][   T75] NIP:  c000000000468a40 LR: c000000000468a28 CTR: 000=
0000000000000
[   79.727741][   T75] REGS: c000000007dd3830 TRAP: 0300   Tainted: G    B=
=20
(5.12.0-rc1-01540-g0783285cc1b8-dirty)
[   79.733377][   T75] MSR:  8000000002009032 <SF,VEC,EE,ME,IR,DR,RI>  CR: =
28000440  XER: 00000000
[   79.738770][   T75] CFAR: c000000000888c7c DAR: c00000003d060000 DSISR: =
40000000 IRQMASK: 0
[   79.738770][   T75] GPR00: c000000000468a28 c000000007dd3ad0 c000000001e=
aad00 c0000000073c3988
[   79.738770][   T75] GPR04: c000000007dd3b60 0000000000000001 00000000000=
00000 c00000003d060000
[   79.738770][   T75] GPR08: 00000000000002c8 0000000000000001 c0000000011=
bb410 c00000003fe903d8
[   79.738770][   T75] GPR12: 0000000028000440 c0000000020f0000 c0000000001=
a6460 c00000000724bb80
[   79.738770][   T75] GPR16: 0000000000000000 c00000000731749f c0000000011=
bb278 c00000000731749f
[   79.738770][   T75] GPR20: 00000001000002c1 0000000000000000 c0000000011=
bb278 c0000000011bb3b8
[   79.738770][   T75] GPR24: c0000000073174a0 c0000000011aa7b8 c000000001e=
35328 c00000000208ad00
[   79.738770][   T75] GPR28: 0000000000000000 c0000000011bb0b8 c0000000073=
c3988 c000000007dd3ad0
[   79.751744][   T75] NIP [c000000000468a40] .test_krealloc+0x4fc/0x5b8
[   79.752243][   T75] LR [c000000000468a28] .test_krealloc+0x4e4/0x5b8
[   79.752699][   T75] Call Trace:
[   79.753027][   T75] [c000000007dd3ad0] [c000000000468a28] .test_krealloc=
+0x4e4/0x5b8 (unreliable)
[   79.753878][   T75] [c000000007dd3c40] [c0000000008886d0] .kunit_try_run=
_case+0x80/0x110
[   79.754641][   T75] [c000000007dd3cd0] [c00000000088a808]=20
.kunit_generic_run_threadfn_adapter+0x38/0x50
[   79.755494][   T75] [c000000007dd3d50] [c0000000001a65ec] .kthread+0x18c=
/0x1a0
[   79.757254][   T75] [c000000007dd3e10] [c00000000000dd68] .ret_from_kern=
el_thread+0x58/0x70
[   79.775521][   T75] Instruction dump:
[   79.776890][   T75] 68a50001 9b9f00c8 fbdf0090 fbbf00a0 fb5f00b8 484201c=
d 60000000 e8ff0080
[   79.783146][   T75] 3d42ff31 390002c8 394a0710 39200001 <88e70000> 38a00=
000 fb9f00a8 e8fbe80e
[   79.787563][   T75] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   79.804667][    T1]     ok 24 - test_krealloc

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/72e31c34-e947-1084-2bd2-f5b80786f827%40csgroup.eu.
