Return-Path: <kasan-dev+bncBAABBZMAR26AMGQEIX4DR6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B0BAA0A7C7
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Jan 2025 09:42:16 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2ee6dccd3c9sf5727191a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Jan 2025 00:42:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736671334; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jw/WfvRGWOFExrWMNpFVwpwonyjnapnUE2ZjY/AxZzVlEsFc74lkychaIfF9qM7uSD
         7vtSpTB0/OGni3jU5yZcIg6SEoGixwZgan5kZU9NNEmyowEzlR2IVXuUt7KJFTNbe4YN
         BuuRTrMr6AI6aPZtrXK1OFKte1Jul1TERFVjSMskVKmfUEVT3bDmJfCG9+WC5JPofqKJ
         YqNMuqPo/lXbVuWuy0B+1BLsupHwOM4rRiqkP1z14EiVEBHtXird9wOxqtGLEZ10n3gz
         t+v0jpCgsa7sAAvT8RM2EtnsCM5i28H1ZA8NmFTbku0RyqX51EOcIFhiR5PW4QlFlb6T
         SydQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:dkim-signature;
        bh=k+ZzNZcN8hEG5452Js1pJuY11qHxfIIGza0hhIopq7s=;
        fh=q4IOZs3h31GRmpYvhGTPdqDAZJB6Pwb5S73zSC6dtW8=;
        b=EhQnUco07BTsp6J0NaFWbJthXGaUNL3qHcPccIc9yiwvCEIHgleJcUVy/qkJaVAulg
         yZ+SD0G8a2vsgTEJbABa5+lIuDkDC6Wk0D08hOdOWWXmLWVCIdYZ2qYY25SqFzyYS96W
         3iB0aH8WnVlKBa7rBuX+rQMLO+ZmVkQ0m5P6UBUCzGFLpgHWOAPdt3kVQ35vozSKAd+6
         qLVb1htNXm76ld1m+iUhZtoH6fwkH8ynknPjU5FslzISjFhDExQpQUaXqFCqhkd/ZCed
         dGIfWzkARvxQStQK+UmbHpE92URQt0eVoyO1FZ04/HrY1+dzb+v846uheboJ9EdLntEQ
         qf4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=h7F5RhYu;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 54.206.16.166 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736671334; x=1737276134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id:to
         :references:message-id:content-transfer-encoding:cc:date:in-reply-to
         :from:subject:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k+ZzNZcN8hEG5452Js1pJuY11qHxfIIGza0hhIopq7s=;
        b=M+D10jC7kqFcRj7Mk8HtKeZhPs2mQXcxfbnpPirdxO/qCjy/0rnKfy6Ap4P+N686BT
         0NbAmw3IKQPHf8nGDprkxJFoE9+B5G+6Rsd8lsHeKkxfe0p8zL+b7cQxWFFKVcUY3GdH
         dJNNN0C9N/r1MTtci8IuFR7g2dZK94E67Rp4bXUIBlUMJi/ISWuiiyVGSW61TuQ785m6
         h8sLTbtEnL40Ki3Obic9CO+ln3vzNdzGfLObn7KfLvqF1tLOe2pCa9jVKABpF92m38lW
         oaAGFMBOmiiTFk4BNoyZpEmUgCJxtTHMwfm/8LXJXtawPg0Gkoc2Lg1i1KyNPNZQl44X
         2g1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736671334; x=1737276134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id:to
         :references:message-id:content-transfer-encoding:cc:date:in-reply-to
         :from:subject:mime-version:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k+ZzNZcN8hEG5452Js1pJuY11qHxfIIGza0hhIopq7s=;
        b=Az5vuWccAIkiter0vN6fcW+Erzeb3kfzCTrpP5ExC/ZEtQeOy1YNxId9z7aiaaPiw0
         ZBGuzch/R2MJWGApRdDmN/ikOBe1Kke1dU9TdMuMeZZIOypk4sLLt7GoZmMPlvjGfQHy
         9i23z2QMz9wuZn+SOW/L7WlN4bCOA+Xjr1OGXeh3m07oOYWOXITNxFyD79bpKsmDFJGe
         9EUicKLJAvHRqTn1eGVs9Km2P8lhtcOEOLiDOHdGM4EhNeUpwGjZdshgpM9GH6BhAWIJ
         sFS/+4LSthtbtAORU7QYpSpdaUmafkYoe/2ryeDfBnd2qx0Rayu3zqCxw9Sx3v5sOcmr
         Nbbg==
X-Forwarded-Encrypted: i=2; AJvYcCVZ+2rHU3z3ROWWu2WylcscwSzrSvMHxPkgUdmep2pr70cRmaP6CLxfsSWCg0fPOVnUCSYybg==@lfdr.de
X-Gm-Message-State: AOJu0YwKp/4ZzCYyS42YQJo7VkBJPGppr3EKlhGkHWx9Wr2buPIo2suQ
	ARZRHQrJB2p0wQEcuCF7qULij3+9pxW6+aRujQolnW3RQYOWCtUO
X-Google-Smtp-Source: AGHT+IHoR6FARq5Jc19092LkM7BoJxrK3lwA7RY0FmgSDrNNMpAXBi2ilrHjPmwDwpEZesq9KySfkg==
X-Received: by 2002:a17:90b:2d43:b0:2ee:9d36:6821 with SMTP id 98e67ed59e1d1-2f5490bd0d6mr23410794a91.27.1736671334015;
        Sun, 12 Jan 2025 00:42:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d650:b0:2ee:3c7f:184d with SMTP id
 98e67ed59e1d1-2f553f1aed8ls2882551a91.2.-pod-prod-02-us; Sun, 12 Jan 2025
 00:42:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXv60AIN4dRchI5F9cckB6SxLYlQ003DTSndtOhL9VQxHiXY7u82RpIobObeDA/SRiqz3MJy7JJc2I=@googlegroups.com
X-Received: by 2002:a17:90b:4d0c:b0:2ee:8619:210b with SMTP id 98e67ed59e1d1-2f5490bd21dmr24353817a91.29.1736671332798;
        Sun, 12 Jan 2025 00:42:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736671332; cv=none;
        d=google.com; s=arc-20240605;
        b=XsjnI9W0LuFTv0pjOTFMGJatMIvaUDGhJPyIGEJw8eAU9kHuaj1dOgnT4WwtdCE4rB
         tHPM7SR7Uc7dOivtvFl3fDWlMfLlj/HSgnfaTauvcBtZoKHGrs/jm4dkn7VNPAx8/1Uk
         Tac0LNdDunJwFEKvRm7W/ncjACQQoYmi88KCzg+wjfeOQB3MhjIXTK78+7UN1PU/SV/1
         wAuv7ewvTV/OuzN1TRtAg0QYyV5vdqEd6OXE2wTJ+lRfC0oHImZJbHvNM0FusIRtu3ea
         ZkJuBAtzWBq37dychlTmcA0WLVP9X7Php6lu6Tn4nM6/Enub+/9R9q8rYNsI52GL4TSD
         L0AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:to:references:message-id:content-transfer-encoding:cc
         :date:in-reply-to:from:subject:mime-version:dkim-signature;
        bh=oNEKYTDX/hCIqBqr9q6Hr89yNR10OK7/PjayG1YOTKw=;
        fh=DiJ1eAvENomTvgicBYn02Qp+6ET7zh+82IGb9bY0qPM=;
        b=QoNojtFY9hJGY0j96CgwnyoA5tUGc5YndUvNk+cT/wFxvVzDyNvdZ4BaiC/KB6mlIK
         PTH4vWF0lIbyirDAnM2qyP5/cBmxglStZE/9qWwBw2o6DvlVvambx3dC9vPOKWuPEtlD
         74f0LSR+V5QFh8Yicxzo+zIAp6w4yCRpWbDNaJHKK7SzcJ9qyZs59ULM1QQEWie/PjLN
         cA91GYyIwEjsWE/+Nsp6RU+ec1skkt9/CSEcezn6X8uMIAcHv56PwqwlVYW/xWWaCnNh
         Z6c9quxP2VznftvoDkPTphXRUk1nqtehnTpBz/QPLFMlMg2TMet0SFUyR+THglyq4zTX
         p6cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=h7F5RhYu;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 54.206.16.166 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
Received: from smtpbgau1.qq.com (smtpbgau1.qq.com. [54.206.16.166])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f53ef0ac8csi466027a91.1.2025.01.12.00.42.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 12 Jan 2025 00:42:12 -0800 (PST)
Received-SPF: pass (google.com: domain of huk23@m.fudan.edu.cn designates 54.206.16.166 as permitted sender) client-ip=54.206.16.166;
X-QQ-mid: bizesmtpip4t1736671294txcooaf
X-QQ-Originating-IP: pHwoD4Hz423uK357Oxc0AzVqkbvgk3IISwNTdVAHrXc=
Received: from smtpclient.apple ( [localhost])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Sun, 12 Jan 2025 16:41:32 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 0
X-BIZMAIL-ID: 7406929187187062416
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3818.100.11.1.3\))
Subject: Re: Bug: Potential KCOV Race Condition in __sanitizer_cov_trace_pc
 Leading to Crash at kcov.c:217
From: "'Kun Hu' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CACT4Y+aXtpXOzesh=+52Vt4+hufixQ8HrHMJXAQ8MFeRR5D_Sg@mail.gmail.com>
Date: Sun, 12 Jan 2025 16:40:08 +0800
Cc: andreyknvl@gmail.com,
 akpm@linux-foundation.org,
 elver@google.com,
 arnd@arndb.de,
 nogikh@google.com,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 "jjtan24@m.fudan.edu.cn" <jjtan24@m.fudan.edu.cn>,
 vgupta@synopsys.com,
 Eugeniy.Paltsev@synopsys.com
Content-Transfer-Encoding: quoted-printable
Message-Id: <5C10A890-F1C0-453D-98A2-0FF06D6D3628@m.fudan.edu.cn>
References: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
 <CACT4Y+YkkgBM=VcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w@mail.gmail.com>
 <FB52FB66-5210-4FA5-BF1B-415234AA62EB@m.fudan.edu.cn>
 <CACT4Y+aXtpXOzesh=+52Vt4+hufixQ8HrHMJXAQ8MFeRR5D_Sg@mail.gmail.com>
To: Dmitry Vyukov <dvyukov@google.com>
X-Mailer: Apple Mail (2.3818.100.11.1.3)
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtpip:m.fudan.edu.cn:qybglogicsvrgz:qybglogicsvrgz8a-1
X-QQ-XMAILINFO: OBUGnm9pFasA45rhy3i5tr+emy17PhFy8eJbeBXOpJB3YruvhFvwByQ7
	NY9OiSjnHPAXsvgy1MfCumRMPyIZNb45MvtlFAaKZ3+I4vXA5slEwJk4PvfsHu2eQs5tFca
	AZgupQoK6AScZvP6F/Ga4IFCHlKkZuyRy5IxzWo2R6Yw9tibGlgmMvFB9Iuiw0cdqzWMJ6g
	o6bQI2o21TxIt2WkZ3p7CZbYoyQfr7OHBpVvbuogqgHccShh0vj8xpvfUG0czvNLZxzanuA
	MKiL4QAyJKHMal1V0Ke6CMoBNtGsH22hVWQmEY8YQJD1MUiZxZdq6sz/3tALSth0oLgAgg6
	UsARy3uby8APhxT0Wpc2xG9VFzUt7qs2ky62gEmL+ADOKmdeW1wcmVY0fwlsOBRExcYchzf
	fJiq8nwjyg7qLZ0LHuOywS41tEsBcj6xjqbkUnuXnKeCjX8DBd9AwnWmJw0EwTRCZyxomel
	lprdDtQZ7eiG5+eVTZkzWj+hOazra6ku6hLmBpCVZ6estlj9+INGtO+LM8hChw1RRTIiqU1
	Ji68IHEH5n3BV/YZ4XevqrPr4aWOcAW5a+0wCY4jhwRpMHN1Ss6QZHXmPserzm7uLMnQbbK
	EF0ydvQUkZoxTpQ6g7lWM6DIwcFSK5rFcNjiwbHbu45yn4Jtkd+C81PZbGhGo2uGp6WvXC7
	wYBrYCfezOTleRXzEVgCSR6/5znj15TJFfKQ8200aTxy8fVm6bHGrvmHqjyD9XuGueaOzO+
	g+ZFgrOdFhQ2QB4QSimwa3KgGvudzuhgozeFOPfEqjYwiRsq1SAbFcsX98rPgaM0BEj0XHW
	k8k/RGEmPt+qErwl+psTL+tP/fwLLlDJDqSzmbI1i7Dm9YPz+GsFa/F+SNHnKZI1EFeV+rx
	/rQbBLXoT3hIh2M4BWmVHIRJ7qCZlJC+9Xw/Qt8iWsSFQgCO5k2IjlHVAUT3P52UjjWjio0
	qT7tWs5l/LiYN/20jesi7cRDFj5VKqg/jPGcd+IvgJv2nfSmII31b/oXO
X-QQ-XMRINFO: Mp0Kj//9VHAxr69bL5MkOOs=
X-QQ-RECHKSPAM: 0
X-Original-Sender: huk23@m.fudan.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=h7F5RhYu;       spf=pass
 (google.com: domain of huk23@m.fudan.edu.cn designates 54.206.16.166 as
 permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
X-Original-From: Kun Hu <huk23@m.fudan.edu.cn>
Reply-To: Kun Hu <huk23@m.fudan.edu.cn>
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



> 2025=E5=B9=B41=E6=9C=8810=E6=97=A5 20:13=EF=BC=8CDmitry Vyukov <dvyukov@g=
oogle.com> =E5=86=99=E9=81=93=EF=BC=9A
>=20
> On Fri, 10 Jan 2025 at 09:14, Kun Hu <huk23@m.fudan.edu.cn> wrote:
>>>> HEAD commit: dbfac60febfa806abb2d384cb6441e77335d2799
>>>> git tree: upstream
>>>> Console output: https://drive.google.com/file/d/1rmVTkBzuTt0xMUS-KPzm9=
OafMLZVOAHU/view?usp=3Dsharing
>>>> Kernel config: https://drive.google.com/file/d/1m1mk_YusR-tyusNHFuRbzd=
j8KUzhkeHC/view?usp=3Dsharing
>>>> C reproducer: /
>>>> Syzlang reproducer: /
>>>>=20
>>>> The crash in __sanitizer_cov_trace_pc at kernel/kcov.c:217 seems to be=
 related to the handling of KCOV instrumentation when running in a preempti=
on or IRQ-sensitive context. Specifically, the code might allow potential r=
ecursive invocations of __sanitizer_cov_trace_pc during early interrupt han=
dling, which could lead to data races or inconsistent updates to the covera=
ge area (kcov_area). It remains unclear whether this is a KCOV-specific iss=
ue or a rare edge case exposed by fuzzing.
>>>=20
>>> Hi Kun,
>>>=20
>>> How have you inferred this from the kernel oops?
>>> I only see a stall that may have just happened to be caught inside of
>>> __sanitizer_cov_trace_pc function since it's executed often in an
>>> instrumented kernel.
>>>=20
>>> Note: on syzbot we don't report stalls on instances that have
>>> perf_event_open enabled, since perf have known bugs that lead to stall
>>> all over the kernel.
>>=20
>> Hi Dmitry,
>>=20
>> Please allow me to ask for your advice:
>>=20
>> We get the new c and syzlang reproducer  for multiple rounds of reproduc=
ing. Indeed, the location of this issue has varied (BUG: soft lockup in tmi=
gr_handle_remote in ./kernel/time/timer_migration.c). The crash log, along =
with the C and Syzlang reproducer are provided below:
>>=20
>> Crash log: https://drive.google.com/file/d/16YDP6bU3Ga8OI1l7hsNFG4Edvjxu=
Bz8d/view?usp=3Dsharing
>> C reproducer: https://drive.google.com/file/d/1BHDc6XdXsat07yb94h6VWJ-jI=
IKhwPfn/view?usp=3Dsharing
>> Syzlang reproducer: https://drive.google.com/file/d/1qo1qfr0KNbyIK909ddA=
o6uzKnrDPdGyV/view?usp=3Dsharing
>>=20
>> Should I report the issue to the maintainer responsible for =E2=80=9Ctim=
er_migration.c=E2=80=9D?
>=20
> If it shows stalls in 2 locations, I assume it can show stalls all
> over the kernel.
>=20
> The only thing the reproducer is doing is perf_event_open, so I would
> assume the issue is related to perf.

Thanks to Dmitry,

Hi perf maintainers,

We reproduced the issue for multiple rounds.=20

Does the frequent occurrence of perf_callchain_kernel in the call chain ind=
icate a possible problem with the call chain logging or processing logic fo=
r performance events?

We lack the relevant technical background, could you help us to check the c=
ause of the issue?

=E2=80=94=E2=80=94=E2=80=94=E2=80=94
Thanks,
Kun Hu.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
C10A890-F1C0-453D-98A2-0FF06D6D3628%40m.fudan.edu.cn.
