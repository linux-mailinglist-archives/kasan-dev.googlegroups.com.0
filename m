Return-Path: <kasan-dev+bncBAABB5NNQO6AMGQENPBVFBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id ADF69A0899E
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 09:14:47 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-21661949f23sf54485085ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 00:14:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736496886; cv=pass;
        d=google.com; s=arc-20240605;
        b=OCBN319gMZNnH+njnD1g84Fmjks7Bfvh3zRq02PrR/mWW46ePnB7wTt4RjuSsBMuRN
         4xLj8Lo+sImhcZdc8xdLseSXAn10KxOJ6RINok0pJr6rF2al7hfxw/RQtoYfeip7WUmA
         pwMfu714zBhZ1HRXuWgmrBr8uG4bfstaXD7CFs9xqMG/sAAxLQb9GyDZ/6P1euyR/OUL
         s1Y1kQLM8KelzfhEZI7aM2JFamwJyqabH8IEogof8bjOkNPh7kp4GFoPIzpt0PQAGaof
         o4+MJitELsc1qF346Oomf+uCD8O5B040TRA0To9YlctUIlI5QCwnWXftPzU7rtoVfsl2
         enjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:dkim-signature;
        bh=vLilbNbgtSe+S7WY8CNtWj++b2N1XHV2km3bBLaobGQ=;
        fh=EF0kFFrmeXKoIuKiwOuhGsCKXSzfYcfIu/BMMSH7Csw=;
        b=BcBIH3q2/mkIsgBCcLq8iVM51+8kJGM2vXZdlIUVjer8j5GyoeXr1BrhXiNYr7WoSC
         Fri3xuT8cpK+iBrxnIr5DyA+AXDJWKBjve9yBTo611jiFPOKk2ntLnysft3e4k8mWRey
         q6Qa7+yD+KqFaCNwQP9Ugnsa13BtYDK5aqAUW6lcZ0Vl9Er0Y7xEMPSpkQXKQN2OElhc
         48Ju0ZSF2T/HltEINkxgXo/YPtS5P+3shdbzrBfQ3DqSGTWJPnFr+MbsJ7EYiMJNbynJ
         69GrDA4GdvDTYnB7CJLWGPm/fQTzkz2UFGxs619rL/qyC/uTsJcxLyjuBWCLG9etKrZ1
         isPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=ZzQ6vyNn;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 18.169.211.239 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736496886; x=1737101686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id:to
         :references:message-id:content-transfer-encoding:cc:date:in-reply-to
         :from:subject:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vLilbNbgtSe+S7WY8CNtWj++b2N1XHV2km3bBLaobGQ=;
        b=rAwzJ9nH1eg1Ye98YukR6CYT1jENBpredeQ2aOfeUGUfQCEJbu7GAaVv66fYaUhGf3
         P+bSiC1ydfxL+N+BP1+BTpShqqJd6/hrtH9IFbtvc0HlI3kmihZWKpXW6axq2wqAwPMx
         bKJ1tSlFCKj/gDollUymXzlM7R7JZWyTkW7qyOowiXYLZk459D/4yYZ4HoC8aWZJwSfw
         yhrk6rQCN0q8+Uyskn84wYXMmIN+s4xKQre1lNnCIOEa15kk/9sEi/JkkLw72foglNKP
         FLF7ojPlUUFaTAd1BF/B7mS680BziKC7A9rsiU62gd/D1zJMyR8ePdhh7L4MuLj2s7MK
         +Hjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736496886; x=1737101686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id:to
         :references:message-id:content-transfer-encoding:cc:date:in-reply-to
         :from:subject:mime-version:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vLilbNbgtSe+S7WY8CNtWj++b2N1XHV2km3bBLaobGQ=;
        b=Z4v/CmaDHd1EzryhbJIxupuQPG1r5S08KCtlKn6snf+ucPGA6j0vkZLRonjC+8g78I
         bKN2X01s4ckzb+vGAt+zODH8eUOl9sqgYuDvmWBwzZ1UQN5KVrmyvxyB2k+2Y8REH/MG
         3dlYmT7hOZiPAj1HrUO6y/0pyJfmkL7KoQhWO/NklH8nKoX7yaiQB3o9SMMx6LZ3JsCI
         k7h7s1kwBpgzsazGEJV3be2cGBhsGu9RQyogKURE5iimHOjq2hJn1k3osKl7QAn3nCaX
         EoxemNRbRPD8hnH4Vq5U/CU45IxtClfMI+7ua7h/tBitI56dAAwiQ3OXw4ghn5vw1eku
         fusw==
X-Forwarded-Encrypted: i=2; AJvYcCXDZjMNbCjE+6GRCZJ0yerhgk6osyDLNZ6PjyV2mhcX6tPx5lW2q+ShnVFCs1Le+NgzDFbCkA==@lfdr.de
X-Gm-Message-State: AOJu0YxvgIjcwi5JJrFzl3AIY61bzRS6t5EI80mcxKNc39u2yqAm94cW
	OQBlsZPHWDYT08t3aJzPqSEQQJtkaU7ab60pV9cIdk/jO96mxM8y
X-Google-Smtp-Source: AGHT+IHIL6xXCCKUaMNy2v4rApWYuzEVWIlnYVQ5Hp/qEtZQMRs8j0MMnw8Q1gsleKwxRA+HvERPCQ==
X-Received: by 2002:a17:902:c406:b0:216:7ee9:21ff with SMTP id d9443c01a7336-21a83fdf307mr152746175ad.49.1736496885586;
        Fri, 10 Jan 2025 00:14:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f103:b0:216:3440:3d18 with SMTP id
 d9443c01a7336-21a8d342ec1ls14125655ad.2.-pod-prod-03-us; Fri, 10 Jan 2025
 00:14:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVU/vAKu0tqb36FzQiG9BXOBx9XTH1+7Ph+kwMw2w4WbsfjRoDyHUbDzce15HO29ewI3E8G1Sk0oJg=@googlegroups.com
X-Received: by 2002:a17:903:1106:b0:216:361a:783d with SMTP id d9443c01a7336-21a83f6609emr165622115ad.28.1736496884514;
        Fri, 10 Jan 2025 00:14:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736496884; cv=none;
        d=google.com; s=arc-20240605;
        b=j5kp6B4h0fUf71gdOzrQXvRcwITybhrOOQboTx9fL3yS2Q9PkokFKYJZ31zjNKgKp0
         sHQtdFf2KAO+mZ05rLc4Enht7tyxCmSFcy6g2PhslCyxAs7+aXUV9dD6L+J9fPskhqiU
         1FKhSIg0PsfwFsj2F9ce5KjzsJQMo1ORMbKY623OURlzHuf0jtDze4oAQiLrDmynbTrw
         ne20zO3wXIWN4UXlHEpE+mMybeQg38JY3wStYj3MykXs8ilGwTDeALz4NZjCr1/GvL3u
         Zy5eYvLkoyIYZRMehAfThYK/uUu6J3v64SSDPP5l4bDuWU20ols7bjrKnX9N3DEj9gvJ
         IdnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:to:references:message-id:content-transfer-encoding:cc
         :date:in-reply-to:from:subject:mime-version:dkim-signature;
        bh=4do73kgMoO4zP61zvJEgervWr6gXj86RlQAnZwcEy2M=;
        fh=dZ/m1aXlzG3wq+QVDcn5syGAAAmnruHhUC+Etu8Izhk=;
        b=loAcUXoiCKYtoK0W1qEsUn8uF1ZFl9vtowgU+o2XSZMTcx3BjlA7RoyulTo9ly7cJE
         aGl2pEm+OvoFoq/wnG3vTGGXvV3HSYuFaMqklnI4L7kvpgdSva6/mAqw0bjdgakHi6Lq
         1GnuOON8oaBdfPEWfFkMeWzUfxUHzOaVkWxiX3ETRHA+lXk6p0GvzPuK5Tc8I37tdqlv
         WmmcRMQbIANghhNgPZKAZ1oYniWoGxlMRmO7iA9AfIyKc4pye2Ne5bPic/d07b/aS73k
         5IhvsS8h/m0ndB4z63DrycJYsrJIW/IKyApnChOGzT2rtK5GF0G5OAAH4ZalVcGwTsSO
         Kabw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=ZzQ6vyNn;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 18.169.211.239 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
Received: from smtpbg151.qq.com (smtpbg151.qq.com. [18.169.211.239])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21a917751f3si1097685ad.6.2025.01.10.00.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jan 2025 00:14:44 -0800 (PST)
Received-SPF: pass (google.com: domain of huk23@m.fudan.edu.cn designates 18.169.211.239 as permitted sender) client-ip=18.169.211.239;
X-QQ-mid: bizesmtpip3t1736496847tdpfqvg
X-QQ-Originating-IP: jwvGRi3dXAmfmz9kyIWX6mu0JVudaellsfms0+oEFkI=
Received: from smtpclient.apple ( [localhost])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Fri, 10 Jan 2025 16:14:05 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 0
X-BIZMAIL-ID: 8268675839993049304
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3818.100.11.1.3\))
Subject: Re: Bug: Potential KCOV Race Condition in __sanitizer_cov_trace_pc
 Leading to Crash at kcov.c:217
From: "'Kun Hu' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CACT4Y+YkkgBM=VcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w@mail.gmail.com>
Date: Fri, 10 Jan 2025 16:13:55 +0800
Cc: andreyknvl@gmail.com,
 akpm@linux-foundation.org,
 elver@google.com,
 arnd@arndb.de,
 nogikh@google.com,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 "jjtan24@m.fudan.edu.cn" <jjtan24@m.fudan.edu.cn>
Content-Transfer-Encoding: quoted-printable
Message-Id: <FB52FB66-5210-4FA5-BF1B-415234AA62EB@m.fudan.edu.cn>
References: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
 <CACT4Y+YkkgBM=VcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w@mail.gmail.com>
To: Dmitry Vyukov <dvyukov@google.com>
X-Mailer: Apple Mail (2.3818.100.11.1.3)
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtpip:m.fudan.edu.cn:qybglogicsvrgz:qybglogicsvrgz8a-1
X-QQ-XMAILINFO: OHTF91J1Rz8hrbDTPXb35Jg1CIYT8lCX81R4Ubw33nwCZtoYKfQzlyQy
	z1w4DArjDzIhE9ATxhqTfVbyG4rUewc5shV1MvB5c1yZrx8p+jSr8P8JkTbhrC5veFGX4I5
	l+QyxBmZm5lY68J5j1YUHBzc6bGQ2V3IwF8e0VG8orxFadVwo/hWjyFst5bDZeFlmhqQea2
	1t8KjEubN1KRhEohoz1eUzIFL6FtfAvmbTtFMCLHX9ZREuoQ7r4I9ktcku2Xoh/sDJhQ8iW
	gY38jdksGL4mB/lirHUqlaSlyMxFoC/od4NvDYaxRH5dIwFy0b3cu45F1trjREvGf5oAtbQ
	GiGNl1W5t5DEp/mds9+sIuyMR0SOktv8KeudhHvTTn1jofAP3JkHpGlChd9oD8D3xI8P+qE
	g5dzNQpJr7ZzyS5QUbUcBKpG1AiLVry7RrzG64WYGRo0HRmpVH8OYcoElcYUQUkle0QVWfg
	oMjJBMUgLjhPiCVMH8UsoWe5FN/UhICzz+t8FCInUa5egLu3rYjytjsw7sq0RMUzxsmqEAf
	IHEHzwQ3RPwtz4fra1n+9LHsUwIMwoCLCrwDDCdSfNYEbbDQ3AoWvMoAhYkdPwNNlJz1xQa
	qu15gjZpQG8AlcDxVYkctbh43MwpZpFlHibtJ5toIouVnbr53SGpPCLEbtLn7QLRcXPK39T
	r3pImu0OI8yWwLRyi2GepmLAHF8ZBhSuTKQMpbS3nOTW4w/2GHp4SyprnsevkIp5BjxE+CN
	DJ6tTwp+9xFGCV3GyZPxTErqUNLpK4D5wbTnKvaanaYjRIQoq+H7dXbozR8N/KYuGbzuMKR
	xZzFXDTyC+bq4CCO2uodh0OX0ws79BpWMLO0gEdti51HZQLWMQtaZfRnfE2LPit3fHEf719
	w4FP+9zFvUP0lJ5DKOVzbnUpmBnTtR7UmacbfhyoIJlUpK8NFC1Li0s5OfoQrVpxmon+j4g
	yDbZJSUBkRyS8KvWdtOTmyFXI
X-QQ-XMRINFO: NS+P29fieYNw95Bth2bWPxk=
X-QQ-RECHKSPAM: 0
X-Original-Sender: huk23@m.fudan.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=ZzQ6vyNn;       spf=pass
 (google.com: domain of huk23@m.fudan.edu.cn designates 18.169.211.239 as
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


>>=20
>> HEAD commit: dbfac60febfa806abb2d384cb6441e77335d2799
>> git tree: upstream
>> Console output: https://drive.google.com/file/d/1rmVTkBzuTt0xMUS-KPzm9Oa=
fMLZVOAHU/view?usp=3Dsharing
>> Kernel config: https://drive.google.com/file/d/1m1mk_YusR-tyusNHFuRbzdj8=
KUzhkeHC/view?usp=3Dsharing
>> C reproducer: /
>> Syzlang reproducer: /
>>=20
>> The crash in __sanitizer_cov_trace_pc at kernel/kcov.c:217 seems to be r=
elated to the handling of KCOV instrumentation when running in a preemption=
 or IRQ-sensitive context. Specifically, the code might allow potential rec=
ursive invocations of __sanitizer_cov_trace_pc during early interrupt handl=
ing, which could lead to data races or inconsistent updates to the coverage=
 area (kcov_area). It remains unclear whether this is a KCOV-specific issue=
 or a rare edge case exposed by fuzzing.
>=20
> Hi Kun,
>=20
> How have you inferred this from the kernel oops?
> I only see a stall that may have just happened to be caught inside of
> __sanitizer_cov_trace_pc function since it's executed often in an
> instrumented kernel.
>=20
> Note: on syzbot we don't report stalls on instances that have
> perf_event_open enabled, since perf have known bugs that lead to stall
> all over the kernel.

Hi Dmitry,

Please allow me to ask for your advice:

We get the new c and syzlang reproducer  for multiple rounds of reproducing=
. Indeed, the location of this issue has varied (BUG: soft lockup in tmigr_=
handle_remote in ./kernel/time/timer_migration.c). The crash log, along wit=
h the C and Syzlang reproducer are provided below:

Crash log: https://drive.google.com/file/d/16YDP6bU3Ga8OI1l7hsNFG4EdvjxuBz8=
d/view?usp=3Dsharing
C reproducer: https://drive.google.com/file/d/1BHDc6XdXsat07yb94h6VWJ-jIIKh=
wPfn/view?usp=3Dsharing
Syzlang reproducer: https://drive.google.com/file/d/1qo1qfr0KNbyIK909ddAo6u=
zKnrDPdGyV/view?usp=3Dsharing

Should I report the issue to the maintainer responsible for =E2=80=9Ctimer_=
migration.c=E2=80=9D?

Thanks,
Kun Hu

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/F=
B52FB66-5210-4FA5-BF1B-415234AA62EB%40m.fudan.edu.cn.
