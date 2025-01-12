Return-Path: <kasan-dev+bncBAABBCX6RW6AMGQEJBPNKEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 521F3A0A7C0
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Jan 2025 09:36:28 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-845dee0425csf261944639f.0
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Jan 2025 00:36:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736670986; cv=pass;
        d=google.com; s=arc-20240605;
        b=aIX5uD8s4ri3CwW3Wo/WYZOEmoKA2zfKsQD01t5AQgTHNhEHXA1n1/Tod8db3qpKjT
         Xf9BheUiFTiZpVuJF9KHxzs//HWpkgItsoggS4qffcsBHHs8AdySHXjiGu1u7/2D7ZKi
         6sOWmfdQYXjrnikPy0r3aHQohM2OyAwOvlrKN8Bpoi2NTEopA8D7zEiIUNihx4VwIxio
         HwFqIpsXOnsnugBflHVj5FjAAea7eADyFE4bGKXLkglU3O0KBJ5/OPQlRGUcHYoBBf0c
         HH34vvqNck3quBDX9yV2q8V2/rhLyXQO6gU+YgYkQheDetPhEZXp6usjse2dmCA67BdP
         w0ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:references:to
         :cc:in-reply-to:date:subject:mime-version:message-id:from
         :dkim-signature;
        bh=o4I4V/OMiXB43haeBDeJba990bxy6X7FzmHv1otWVDE=;
        fh=YdqSFQChETsn3TvaJvQeAa2qaE1I2hBQiJkK2SFMMc4=;
        b=g2fHplbI7PumzsU7ngCpZSAnIkfh1tKSkmKFrn0PHqcfurfDqwt2pKt56DvxyTk6WG
         A29jfJ+2rW1lK/q5w6YQrgUlX3FFIgCRjPbRkQvXJOc7jsl4m011voeHvBXu4SPwRd4I
         bPsHZXEz2IXHa3Aibo6EsCRUlEzaHBqKJSlWzIO0qfhsidaYAirTxjY7uNBB5X28131+
         hu5X2/yK/zLTqwnMxv2TF6kCRgMYVXFnjukBGZqaekOnBluRiGwUbKN76lfDjgt4JYL5
         5lNirOOIIv2SlrJsdfGV13yFETkTnr0q+i9Rf+HZVD5/i7PNeTx75s1Zgw5TQOfaCnAu
         jBhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=I7evU3aC;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 54.254.200.92 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736670986; x=1737275786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :references:to:cc:in-reply-to:date:subject:mime-version:message-id
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=o4I4V/OMiXB43haeBDeJba990bxy6X7FzmHv1otWVDE=;
        b=u3cSaHDsWz25cD39CnseRkra/CWkFxdJlmxXEfx7wu3NBmcNDDOGUDIxQvxzI34BSM
         HhMkP0OU66/UXrjo+DDZ07ywi5JOIVrcwEK/lAgqSo7N/p5SbeBh7GfZ4gHLs73Cdqwl
         ANP3XUiztlRdJvWz2EArNVi33qFBrk4CyAgTysOmdAv8GMvBodiZ3s1bK6EvOm/Lx7jB
         YfzIdb37+X+OoDO+U2UuvQiQ40PJ+CUQoMy1XuRrhAcO3lbYNlcJK3YY8PMCNNF0VPNl
         /ZjIP/WOVgWr07sGwzQ8ULH+CxTHTWqxp+bIK4svu9Z9fzsVXd5cM3Adg8vrfLpvuJ8M
         eMXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736670986; x=1737275786;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :references:to:cc:in-reply-to:date:subject:mime-version:message-id
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o4I4V/OMiXB43haeBDeJba990bxy6X7FzmHv1otWVDE=;
        b=swzkUxQL7ubGKtObGNjBHj/D2IEoU2WC5CrRasTzJjt8atql/8/v7TC8C9GQV9DSl5
         eEXoBnHebHLOBAwdpRR1cNakgSL0ITzNwhqq0o1BHqxtHz4CQ7NyZzaPjLapdNwHwuRR
         9XOYCRYff86sl5/fFPzHJuyk5Xzt/GRzTDOlFughB0WaWJxxyFEB6kcdre/qyen77nm+
         UcNlRs1ds4BJwVpKhJV4VWXHwDS+QZ44lQ3UhpcF3WI3rT2lkRcjk/D9ayYTUeReomxd
         Otvu4dvH2I0JMy2sc56SRGdMnMQbhkW8s5mCAOq5M1aUjDho60tJuBN4suJZ581qxsx3
         3jSA==
X-Forwarded-Encrypted: i=2; AJvYcCU+u/Fmv1Lr1FFz7Far03OaWL44/ZLezwFN7rcr0KC4hZDgADmiVkLr+IpWmmINqDevVnWJsQ==@lfdr.de
X-Gm-Message-State: AOJu0YyBRpzy/OhZ4tX03uab348zAflY2uaFJaE0aF5v3bfIK7P/8wBN
	iW9d06Os4DyTHoaj7zWBjkKF26Gx0rZK/jzTyWCp4ZUOoI/jjTSy
X-Google-Smtp-Source: AGHT+IH7cD+rKGWlz5HJyLKCnDdKh0cTsJgAN+C/6BNJUrlBukV5Z0qU4sUCox0dPb7giHc4Y/8hhg==
X-Received: by 2002:a05:6e02:1d0a:b0:3a7:a553:72f with SMTP id e9e14a558f8ab-3ce3aa5b1ddmr130242615ab.18.1736670986584;
        Sun, 12 Jan 2025 00:36:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dd90:0:b0:3a9:d878:72dd with SMTP id e9e14a558f8ab-3ce475ce0d1ls16839225ab.1.-pod-prod-07-us;
 Sun, 12 Jan 2025 00:36:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVMCNP21FMuyiQdWnaiWifEZeLMBWFWyBePXd5LgWJRQEmw7O4ikXfZfNH20ytz5g4XHwQEmHWtpF4=@googlegroups.com
X-Received: by 2002:a05:6602:418c:b0:832:480d:6fe1 with SMTP id ca18e2360f4ac-84cdfde0d5fmr1461449139f.0.1736670985809;
        Sun, 12 Jan 2025 00:36:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736670985; cv=none;
        d=google.com; s=arc-20240605;
        b=g6d8guhU+kovFV5rlKpepCgUOiRabzqQuMsLvNx5dWoYvGhkqEYOsr+YEQaRmpVXK1
         qBaSGgMcpRE8+ssHm8lR+4dXvtqKiHniHSjI0rFE8yu4Cn0hTqvkt4X8W9QIebTG64WP
         85feoW2sGPlpDOU3/d41Ugo7lh0vp6/iLfzIiEggoTFmBFJBZqZWsRAA32/hhgGb5LsW
         wc/NjcWMyXr8mRXv34oBvoOQw5Bf16wqqPm/lsZdcTadI86C9SYcbgu5OVHjYDfxoZ96
         SODwjTnX9VZYxP1cCuD/k5MGulmGtwFNDhmVPBy9j2gHS0H+yhjFiqexkEnyqOb5aAde
         5BEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:references:to:cc:in-reply-to:date:subject:mime-version
         :message-id:from:dkim-signature;
        bh=Ih5wbyRiSasBTJi2L8jSkU9wOACTPs2eYnIbIguAI6M=;
        fh=8Md1Ewk1L34Jwg7N7JatoT5kkhxRJ5idPyhtpCdyY3k=;
        b=aw9OswqBm9EdEi5XfgS9JEtsrALnDaV5FWGq3QCAKLTn3y4l13y9RCKYGBoOb41OF8
         d5TC98hm8H2iIi9ujZLbIKMx4jqpubrwxHGLYxeLAzXIAAu+hA1IvPNEaXMDlMulysla
         sGz+2+krhFndLZxZeyG8sB4tn0uw1OZF/ghFaGoYy8TM0scw/h+4LF3GwQG7H1ay1vU7
         GCriS4chFFvW7yxY87pXIJh/KPwEZBsZ/1J9e4doehkdoQnj8FcswKXk5VA86PU1cnNT
         SRgXz+/Dtud/sIpFwbG77bw/cVAZltR5/c+NMhw75DsUEdWlKiior5YDF7+2Y4QfrhPT
         Z1Vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=I7evU3aC;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 54.254.200.92 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
Received: from smtpbgsg1.qq.com (smtpbgsg1.qq.com. [54.254.200.92])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-84d3c8297f1si29352839f.0.2025.01.12.00.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 12 Jan 2025 00:36:24 -0800 (PST)
Received-SPF: pass (google.com: domain of huk23@m.fudan.edu.cn designates 54.254.200.92 as permitted sender) client-ip=54.254.200.92;
X-QQ-mid: bizesmtpip3t1736670943t38mbss
X-QQ-Originating-IP: P5iizlItWzNqKvM5t8FF5JLsrkcwdbz4RMzR4+OdqgY=
Received: from smtpclient.apple ( [localhost])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Sun, 12 Jan 2025 16:35:41 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 0
X-BIZMAIL-ID: 5278771888799376029
From: "'Kun Hu' via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <4CB5EE98-DA69-4598-B08F-C9F432C68707@m.fudan.edu.cn>
Content-Type: multipart/alternative;
	boundary="Apple-Mail=_15931BE7-DA7E-4563-B05A-40487D552431"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3818.100.11.1.3\))
Subject: Re: Bug: Potential KCOV Race Condition in __sanitizer_cov_trace_pc
 Leading to Crash at kcov.c:217
Date: Sun, 12 Jan 2025 16:35:31 +0800
In-Reply-To: <CACT4Y+aXtpXOzesh=+52Vt4+hufixQ8HrHMJXAQ8MFeRR5D_Sg@mail.gmail.com>
Cc: andreyknvl@gmail.com,
 akpm@linux-foundation.org,
 elver@google.com,
 arnd@arndb.de,
 nogikh@google.com,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 "jjtan24@m.fudan.edu.cn" <jjtan24@m.fudan.edu.cn>,
 Dmitry Vyukov <dvyukov@google.com>
To: vgupta@synopsys.com,
 Eugeniy.Paltsev@synopsys.com
References: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
 <CACT4Y+YkkgBM=VcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w@mail.gmail.com>
 <FB52FB66-5210-4FA5-BF1B-415234AA62EB@m.fudan.edu.cn>
 <CACT4Y+aXtpXOzesh=+52Vt4+hufixQ8HrHMJXAQ8MFeRR5D_Sg@mail.gmail.com>
X-Mailer: Apple Mail (2.3818.100.11.1.3)
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtpip:m.fudan.edu.cn:qybglogicsvrgz:qybglogicsvrgz8a-1
X-QQ-XMAILINFO: MvyKdZyVtFx3qXyd20Y2vs8IpVU6zQhc1b46UJpZcCl+Cx3Bmd4czzvz
	yYrmABGfanXPF/UlUGndP7a7s1HZZ6kL41tZyvm/6WW8DLd1eBBlV8AozithV6LGVjWI6XU
	d+72kOVBx2wOjM2ElPPy6/VKnwNRAuv83zsVYotigGnqOyBjiVsRQMRwuy/fPHmdCQT0Rtt
	xKm43G5pADxX7T69J9fOtH0YT1P5ZuuhZQCpGc3YyVfGxoNKUqXMfvCHf0K+t0GctpRgaEx
	FaFpz18xi5z6cmAON0K8bLAG2yJg3oDYY20U5Osi9U0B4bKIV3vwQHLz8rAobDvBLPnkMM+
	6fDRCGHQXAI/GJRAS+awCHoLuQ+vlwawHmbsR8OvMDG3qPf5pT4PpzDBvHzowodVe9W7+Mj
	SiGq999/YXHRfrc4n20OyuQxH9iRofFULSkrls51ijRsq69JkbWJVr78mxOsLRjZ0pdLZYd
	sJcDFyvqDBQSvVPmiP/pkMdJbdJ5wly8zGVTCQvHXK4wGpdYPmYFUKriQgRGxDdEKvwmEEW
	O2VJ5K/qCrVeOAhEAdHe6WRpoIIjWGbW4GnSJoja14/59M4rflcESmaXoPgzD44MQnotVdl
	kfdv3RxNLQqk045YEPlkTqKELBbK+1y47tXIA0Se1ccZnjtBfI7az5yZDU59StCKgcnNpEm
	s0mI+e2asH2AbkLovXcrp7H+p9clILZKhTEaHP/QXpMisRdgG8MVypcQAhrhivYo8F4pTc8
	YI8j1YFVwFQOv/4fMhPQPmPuHQ24TRaYi1ntoFy0tnafnHu13zJi+Upx+kQDxW3dDLQHFa4
	xo71QYu28Q4zO5ZmFTyh1UQ3S6HNTZSrrZmhoS6Y2NMraCgMdHZ6SnhHsBCK/8EGLmKumnh
	TMBugutiS8Dlg6eX5Y9keg6mfu2HBUNNZRCvEIqr3aFnuBe8O4CXVqFFiDSbBwYvrUQGvbw
	TWUdeN6QiHAuVSDau2ix5FYl6pp0J/qv4WbegBTVYhy9zeIbI4EaLu7reJeqk2Fdg6rR6db
	VEoB8WdL76+mBhXAbE3G68O/2ZLr6PM5YVrjUd+xoLIgV+0x2UW+EqJ81K7XQxSGk2bBe2d
	aE0wNx11428WyGobTznuYy1c+deqMH2nA==
X-QQ-XMRINFO: NS+P29fieYNw95Bth2bWPxk=
X-QQ-RECHKSPAM: 0
X-Original-Sender: huk23@m.fudan.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=I7evU3aC;       spf=pass
 (google.com: domain of huk23@m.fudan.edu.cn designates 54.254.200.92 as
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


--Apple-Mail=_15931BE7-DA7E-4563-B05A-40487D552431
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"



> 2025=E5=B9=B41=E6=9C=8810=E6=97=A5 20:13=EF=BC=8CDmitry Vyukov <dvyukov@g=
oogle.com> =E5=86=99=E9=81=93=EF=BC=9A
>=20
> On Fri, 10 Jan 2025 at 09:14, Kun Hu <huk23@m.fudan.edu.cn <mailto:huk23@=
m.fudan.edu.cn>> wrote:
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
CB5EE98-DA69-4598-B08F-C9F432C68707%40m.fudan.edu.cn.

--Apple-Mail=_15931BE7-DA7E-4563-B05A-40487D552431
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="UTF-8"

<html><head><meta http-equiv=3D"content-type" content=3D"text/html; charset=
=3Dutf-8"></head><body style=3D"overflow-wrap: break-word; -webkit-nbsp-mod=
e: space; line-break: after-white-space;"><br id=3D"lineBreakAtBeginningOfM=
essage"><div><br><blockquote type=3D"cite"><div>2025=E5=B9=B41=E6=9C=8810=
=E6=97=A5 20:13=EF=BC=8CDmitry Vyukov &lt;dvyukov@google.com&gt; =E5=86=99=
=E9=81=93=EF=BC=9A</div><br class=3D"Apple-interchange-newline"><div><meta =
charset=3D"UTF-8"><span style=3D"caret-color: rgb(0, 0, 0); font-family: He=
lvetica; font-size: 12px; font-style: normal; font-variant-caps: normal; fo=
nt-weight: 400; letter-spacing: normal; text-align: start; text-indent: 0px=
; text-transform: none; white-space: normal; word-spacing: 0px; -webkit-tex=
t-stroke-width: 0px; text-decoration: none; float: none; display: inline !i=
mportant;">On Fri, 10 Jan 2025 at 09:14, Kun Hu &lt;</span><a href=3D"mailt=
o:huk23@m.fudan.edu.cn" style=3D"font-family: Helvetica; font-size: 12px; f=
ont-style: normal; font-variant-caps: normal; font-weight: 400; letter-spac=
ing: normal; orphans: auto; text-align: start; text-indent: 0px; text-trans=
form: none; white-space: normal; widows: auto; word-spacing: 0px; -webkit-t=
ext-stroke-width: 0px;">huk23@m.fudan.edu.cn</a><span style=3D"caret-color:=
 rgb(0, 0, 0); font-family: Helvetica; font-size: 12px; font-style: normal;=
 font-variant-caps: normal; font-weight: 400; letter-spacing: normal; text-=
align: start; text-indent: 0px; text-transform: none; white-space: normal; =
word-spacing: 0px; -webkit-text-stroke-width: 0px; text-decoration: none; f=
loat: none; display: inline !important;">&gt; wrote:</span><br style=3D"car=
et-color: rgb(0, 0, 0); font-family: Helvetica; font-size: 12px; font-style=
: normal; font-variant-caps: normal; font-weight: 400; letter-spacing: norm=
al; text-align: start; text-indent: 0px; text-transform: none; white-space:=
 normal; word-spacing: 0px; -webkit-text-stroke-width: 0px; text-decoration=
: none;"><blockquote type=3D"cite" style=3D"font-family: Helvetica; font-si=
ze: 12px; font-style: normal; font-variant-caps: normal; font-weight: 400; =
letter-spacing: normal; orphans: auto; text-align: start; text-indent: 0px;=
 text-transform: none; white-space: normal; widows: auto; word-spacing: 0px=
; -webkit-text-stroke-width: 0px; text-decoration: none;"><blockquote type=
=3D"cite"><blockquote type=3D"cite">HEAD commit: dbfac60febfa806abb2d384cb6=
441e77335d2799<br>git tree: upstream<br>Console output: https://drive.googl=
e.com/file/d/1rmVTkBzuTt0xMUS-KPzm9OafMLZVOAHU/view?usp=3Dsharing<br>Kernel=
 config: https://drive.google.com/file/d/1m1mk_YusR-tyusNHFuRbzdj8KUzhkeHC/=
view?usp=3Dsharing<br>C reproducer: /<br>Syzlang reproducer: /<br><br>The c=
rash in __sanitizer_cov_trace_pc at kernel/kcov.c:217 seems to be related t=
o the handling of KCOV instrumentation when running in a preemption or IRQ-=
sensitive context. Specifically, the code might allow potential recursive i=
nvocations of __sanitizer_cov_trace_pc during early interrupt handling, whi=
ch could lead to data races or inconsistent updates to the coverage area (k=
cov_area). It remains unclear whether this is a KCOV-specific issue or a ra=
re edge case exposed by fuzzing.<br></blockquote><br>Hi Kun,<br><br>How hav=
e you inferred this from the kernel oops?<br>I only see a stall that may ha=
ve just happened to be caught inside of<br>__sanitizer_cov_trace_pc functio=
n since it's executed often in an<br>instrumented kernel.<br><br>Note: on s=
yzbot we don't report stalls on instances that have<br>perf_event_open enab=
led, since perf have known bugs that lead to stall<br>all over the kernel.<=
br></blockquote><br>Hi Dmitry,<br><br>Please allow me to ask for your advic=
e:<br><br>We get the new c and syzlang reproducer &nbsp;for multiple rounds=
 of reproducing. Indeed, the location of this issue has varied (BUG: soft l=
ockup in tmigr_handle_remote in ./kernel/time/timer_migration.c). The crash=
 log, along with the C and Syzlang reproducer are provided below:<br><br>Cr=
ash log: https://drive.google.com/file/d/16YDP6bU3Ga8OI1l7hsNFG4EdvjxuBz8d/=
view?usp=3Dsharing<br>C reproducer: https://drive.google.com/file/d/1BHDc6X=
dXsat07yb94h6VWJ-jIIKhwPfn/view?usp=3Dsharing<br>Syzlang reproducer: https:=
//drive.google.com/file/d/1qo1qfr0KNbyIK909ddAo6uzKnrDPdGyV/view?usp=3Dshar=
ing<br><br>Should I report the issue to the maintainer responsible for =E2=
=80=9Ctimer_migration.c=E2=80=9D?<br></blockquote><br style=3D"caret-color:=
 rgb(0, 0, 0); font-family: Helvetica; font-size: 12px; font-style: normal;=
 font-variant-caps: normal; font-weight: 400; letter-spacing: normal; text-=
align: start; text-indent: 0px; text-transform: none; white-space: normal; =
word-spacing: 0px; -webkit-text-stroke-width: 0px; text-decoration: none;">=
<span style=3D"caret-color: rgb(0, 0, 0); font-family: Helvetica; font-size=
: 12px; font-style: normal; font-variant-caps: normal; font-weight: 400; le=
tter-spacing: normal; text-align: start; text-indent: 0px; text-transform: =
none; white-space: normal; word-spacing: 0px; -webkit-text-stroke-width: 0p=
x; text-decoration: none; float: none; display: inline !important;">If it s=
hows stalls in 2 locations, I assume it can show stalls all</span><br style=
=3D"caret-color: rgb(0, 0, 0); font-family: Helvetica; font-size: 12px; fon=
t-style: normal; font-variant-caps: normal; font-weight: 400; letter-spacin=
g: normal; text-align: start; text-indent: 0px; text-transform: none; white=
-space: normal; word-spacing: 0px; -webkit-text-stroke-width: 0px; text-dec=
oration: none;"><span style=3D"caret-color: rgb(0, 0, 0); font-family: Helv=
etica; font-size: 12px; font-style: normal; font-variant-caps: normal; font=
-weight: 400; letter-spacing: normal; text-align: start; text-indent: 0px; =
text-transform: none; white-space: normal; word-spacing: 0px; -webkit-text-=
stroke-width: 0px; text-decoration: none; float: none; display: inline !imp=
ortant;">over the kernel.</span><br style=3D"caret-color: rgb(0, 0, 0); fon=
t-family: Helvetica; font-size: 12px; font-style: normal; font-variant-caps=
: normal; font-weight: 400; letter-spacing: normal; text-align: start; text=
-indent: 0px; text-transform: none; white-space: normal; word-spacing: 0px;=
 -webkit-text-stroke-width: 0px; text-decoration: none;"><br style=3D"caret=
-color: rgb(0, 0, 0); font-family: Helvetica; font-size: 12px; font-style: =
normal; font-variant-caps: normal; font-weight: 400; letter-spacing: normal=
; text-align: start; text-indent: 0px; text-transform: none; white-space: n=
ormal; word-spacing: 0px; -webkit-text-stroke-width: 0px; text-decoration: =
none;"><span style=3D"caret-color: rgb(0, 0, 0); font-family: Helvetica; fo=
nt-size: 12px; font-style: normal; font-variant-caps: normal; font-weight: =
400; letter-spacing: normal; text-align: start; text-indent: 0px; text-tran=
sform: none; white-space: normal; word-spacing: 0px; -webkit-text-stroke-wi=
dth: 0px; text-decoration: none; float: none; display: inline !important;">=
The only thing the reproducer is doing is perf_event_open, so I would</span=
><br style=3D"caret-color: rgb(0, 0, 0); font-family: Helvetica; font-size:=
 12px; font-style: normal; font-variant-caps: normal; font-weight: 400; let=
ter-spacing: normal; text-align: start; text-indent: 0px; text-transform: n=
one; white-space: normal; word-spacing: 0px; -webkit-text-stroke-width: 0px=
; text-decoration: none;"><span style=3D"caret-color: rgb(0, 0, 0); font-fa=
mily: Helvetica; font-size: 12px; font-style: normal; font-variant-caps: no=
rmal; font-weight: 400; letter-spacing: normal; text-align: start; text-ind=
ent: 0px; text-transform: none; white-space: normal; word-spacing: 0px; -we=
bkit-text-stroke-width: 0px; text-decoration: none; float: none; display: i=
nline !important;">assume the issue is related to perf.</span></div></block=
quote><br></div><div>Thanks to Dmitry,</div><div><br></div><div>Hi perf mai=
ntainers,</div><div><br></div><div>We reproduced the issue for multiple rou=
nds.&nbsp;</div><div><br></div><div>Does the frequent occurrence of perf_ca=
llchain_kernel in the call chain indicate a possible problem with the call =
chain logging or processing logic for performance events?</div><div><br></d=
iv><div>We lack the relevant technical background, could you help us to che=
ck the cause of the issue?</div><div><br></div><div>=E2=80=94=E2=80=94=E2=
=80=94=E2=80=94</div><div>Thanks,</div><div>Kun Hu.</div><br></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/4CB5EE98-DA69-4598-B08F-C9F432C68707%40m.fudan.edu.cn?utm_medium=
=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/4=
CB5EE98-DA69-4598-B08F-C9F432C68707%40m.fudan.edu.cn</a>.<br />

--Apple-Mail=_15931BE7-DA7E-4563-B05A-40487D552431--
