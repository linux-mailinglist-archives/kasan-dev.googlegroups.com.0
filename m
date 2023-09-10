Return-Path: <kasan-dev+bncBC7M5BFO7YCRBZHF66TQMGQE5JCGTBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id A9538799F04
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 18:46:30 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-26f49ad3b86sf4574321a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 09:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694364389; cv=pass;
        d=google.com; s=arc-20160816;
        b=yEFECVf2PTcJy9zJDR92xo8XIfm+1E/KNdyX52uuN3q9EzI0F5pqONYcohRBIb0fnI
         UdFRrZRu40OFRkB63PjPCITdt8ZcYHi4zMD7agSLr2Ztk1jbegsZ7qVjfrsISGnryKdg
         IwYmP0HgSUQKVP2ZQ5HWEVA66+OXqXsOdFPtqfjThNJAf803ozmEA8bQgrlAIT+RBjlu
         E4P923LCwaRWpRB3i7kSI1x6sNnZSOXVwxtwZ+0s7P5CS+SMTGI0Nnma6fJ+NszzH/5s
         hm2dVeLSILSM4+H77XZ/rMRgX6zMprB9VVbJN/m5jIKT5BxU7ngFcew3XNh2Y03lGSHv
         Uwvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=xJZfDr61Z4YsX9dqqr0mCPJpWUyHBcQ15GLgp7RBbDk=;
        fh=eYG+YXAxYhkQ9ZQImXJ+v8jHTytD/xSOca7sp/tDKBs=;
        b=iNdR59GIOISt1ckssOtGxGkzJJUuGozKZEJ86U9IBpXp6DCa/p27CqhEgX7z3yVY++
         ZLgD0cvIG706rN/tOwCOIFkPC4fng7ytcrgzL8cSi3bkIJCHDJb5fyeSgMwEtI0UrHGt
         jg46WsnsIvSBOkZ76jwpD6ZkARbTd5bLDXXCA4frugCPNdkNxZvDF+vQSC/HnbwaAKMR
         B0iOWZ+ZFA+v59UUCxOBDFRgp+V+LeWwO10qNaNrbfaz0sHz1GXwjxr8DDpKzw+c4k41
         43di/gnXCPlq5MoAfjxIu51/4+GMnRVNkq6HqZto5t+g0bSU73jFgC12plTg7ijgLuVY
         PvzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=q1M9NaeB;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694364389; x=1694969189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xJZfDr61Z4YsX9dqqr0mCPJpWUyHBcQ15GLgp7RBbDk=;
        b=BcHEVBJtRjsFZpCBauNhicInvwv57UFLOi5uggF8YGst7+GejCkaTixsncno++gOeV
         B0dxiL1i6AKV72NEMOlRJf0pZEeZE0Uz/MfbSXsA8BKp7y+mdwhUbf8uKXnXCPvPcyxj
         plj3CRuEF4bh0Enf0aJMjS/TyUTeLnFVy1esJG5B7LNGTlIe4y37jCleC9a9qIS7mua0
         5h4FmuDY4zOGedQdzkraU3v39piA/OOnGKHCtGkl0+Qmdm/zJYCEL6FuBFhTPG7hjnTw
         moJddmTziADOSY7mbb9biRrZC3UkiQZYembijTagVQPuIoJZ5/j6j1o81tP4ycOCxoey
         6wSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694364389; x=1694969189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xJZfDr61Z4YsX9dqqr0mCPJpWUyHBcQ15GLgp7RBbDk=;
        b=ZUAavfn71hVS4Yo2nvLz99Eb1mOMiNxZ+0it58mQRdY7ruSbzRwHVxGIACmNgimRHD
         41tTNrNI1yIGXcNm2V0SiTYmVPSrppxWMhZSfsh2ZdVm/xtSXxxzhKYdYD7jWcy/J+s0
         8aJCHwyKuCkta+C3MdNvg1uElXzLYJFYA/z077IzGq9sC5R9AMVAce+2GNLswgZ9S+0l
         I6wBV5dwKDzVfCB0tXKeVxDjksV1aA0yX/F77cga1zC2rVschELTd2oS3tS24ea+es7d
         UeIhk1UOq/o8HTaLMMpeEpgM5JY4PG9GuCzbOtD0OumUYrGHJJXeb9FW/nyTjCX/sdLq
         XnAQ==
X-Gm-Message-State: AOJu0YzjcCTx4ksZZfQvDTuGmtbpAiDX971SLGNhng3v4S0wBCn6oJTN
	JWm6vhw0YsazT7Z3QA2VAvE=
X-Google-Smtp-Source: AGHT+IFXFnAFbqvYOYzY+BamolNEzolhhZlUuqvh1YXx489zRkYNNCLaKJsbKpVolW2vtb8aiOB3RQ==
X-Received: by 2002:a17:90a:e144:b0:274:1bb1:415a with SMTP id ez4-20020a17090ae14400b002741bb1415amr68222pjb.41.1694364388706;
        Sun, 10 Sep 2023 09:46:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1912:b0:262:e296:d183 with SMTP id
 mp18-20020a17090b191200b00262e296d183ls1824020pjb.1.-pod-prod-09-us; Sun, 10
 Sep 2023 09:46:27 -0700 (PDT)
X-Received: by 2002:a05:6a20:428b:b0:14d:7511:1c1 with SMTP id o11-20020a056a20428b00b0014d751101c1mr7451653pzj.49.1694364387514;
        Sun, 10 Sep 2023 09:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694364387; cv=none;
        d=google.com; s=arc-20160816;
        b=C8XV7lYn7Kry9b2RKL1mW2UfFCDw+TLqPWuTRUPAvnnC24CTM6xn9uO4Lmg6YdxswB
         Lej1w+Q9PyoHNUbFv5QG2ucAbwouILo0CKombPcqLwVKbO47L58ma6tM5X0KCXtSWOE3
         PLxXsW/YNvyC1Oi4lFRc8kMKUoYFtsa2pwaZgo5J8iS8RIiPTYGrozE4Rx/I5aunqt8U
         0RardiH5sQkUHVl2Ubw7J5OH7pwB6RVpd6fQauBfRYRqW+nvFs0dkIM1vIDbDstYlEv6
         hIXG7un8HKkFiHFMle5vogRHx/6HOPZxjOFBUi6898+dfZU/JYnHn2SGp5cKBTHff+qm
         K5Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=61vUwUdH6cPiu3s3z2+GRh4ZeJftNEs+VBuIsIetADI=;
        fh=eYG+YXAxYhkQ9ZQImXJ+v8jHTytD/xSOca7sp/tDKBs=;
        b=NpAE6XgnntPmT8MtxCfJgVzlpgcN7GJJG69fHkoVCvYnZY7FB6vo/e/ccnf1eGzeZE
         ENHo2taumXgat83IMVux4yYYpF1iZeOx09K6l8SfC7uIO6MLBLfy314o/5s1FrppRhUk
         l8GEq3/juQSzldNmxjLGK6C8wpT4zoXqLIuHg+2Kr209ne0sYFHWhg0PEZFDRN3oK1HL
         oj7OAWDERqp2Ofv1jhauN0keNyD/X7xtK8mWmB2vPBFKGIqfljjIfZKqV+zSKtL3hvJO
         Q5KdnCwTO9wgv2fx1D6X/+L6QieCnw46BlGXubI2a5NFYcm9fshYm4mIxrf4Us0ihOoM
         xrng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=q1M9NaeB;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id y13-20020a170902b48d00b001b8a5937569si514505plr.8.2023.09.10.09.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Sep 2023 09:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id ca18e2360f4ac-7928ba24936so141857339f.0
        for <kasan-dev@googlegroups.com>; Sun, 10 Sep 2023 09:46:27 -0700 (PDT)
X-Received: by 2002:a6b:5915:0:b0:795:16b8:85fc with SMTP id n21-20020a6b5915000000b0079516b885fcmr9051442iob.0.1694364386703;
        Sun, 10 Sep 2023 09:46:26 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:329c:23ff:fee3:9d7c? ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id g2-20020a5ec742000000b0078337cd3b3csm1729489iop.54.2023.09.10.09.46.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Sep 2023 09:46:25 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <2520edfc-32a3-a838-ef80-337f20cd7d9c@roeck-us.net>
Date: Sun, 10 Sep 2023 09:46:23 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.0
Subject: Re: [PATCH 2/2] LoongArch: Allow building with kcov coverage
To: Xi Ruoyao <xry111@xry111.site>, Feiyang Chen <chenfeiyang@loongson.cn>
Cc: chenhuacai@kernel.org, dvyukov@google.com, andreyknvl@gmail.com,
 loongarch@lists.linux.dev, kasan-dev@googlegroups.com,
 chris.chenfeiyang@gmail.com, loongson-kernel@lists.loongnix.cn
References: <cover.1688369658.git.chenfeiyang@loongson.cn>
 <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
 <66522279-c933-4952-9a5a-64301074a74a@roeck-us.net>
 <ed3d5214b0a84486080993b56c0de45accfe4fce.camel@xry111.site>
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
In-Reply-To: <ed3d5214b0a84486080993b56c0de45accfe4fce.camel@xry111.site>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=q1M9NaeB;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::d31 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On 9/10/23 09:07, Xi Ruoyao wrote:
> On Sun, 2023-09-10 at 08:51 -0700, Guenter Roeck wrote:
>> Hi,
>>
>> On Tue, Jul 04, 2023 at 08:53:32PM +0800, Feiyang Chen wrote:
>>> Add ARCH_HAS_KCOV to the LoongArch Kconfig. Also disable
>>> instrumentation of vdso.
>>>
>>> Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
>>
>> When trying to build loongarch:allmodconfig, this patch results in
>>
>> Error log:
>> In file included from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-lin=
ux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/options.h=
:8,
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongar=
ch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/t=
m.h:46,
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongar=
ch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/b=
ackend.h:28,
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongar=
ch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/g=
cc-plugin.h:30,
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 from scripts/gcc-plugins/gcc-common.h:7,
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 from scripts/gcc-plugins/latent_entropy_plugin.=
c:78:
>> /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/=
loongarch64-linux-gnu/12.2.0/plugin/include/config/loongarch/loongarch-opts=
.h:31:10: fatal error: loongarch-def.h: No such file or directory
>>  =C2=A0=C2=A0 31 | #include "loongarch-def.h"
>=20
>> for me. I tried with gcc 12.2 / binutils 2.39 and gcc 13.1 / binutils 2.=
40.
>=20
>> Reverting the patch or explicitly disabling CONFIG_GCC_PLUGINS fixes
>> the problem.
>>
>> What compiler / binutils version combination is needed for this to work,
>> or, alternatively, how would I have to configure the compiler ?
>=20
> Hi Guenter,
>=20
> This is a GCC bug.  It's fixed in GCC trunk and the fix has been
> backported to 12/13 release branches, so GCC 14.1, 13.3, and 12.4 will
> contain the fix.
>=20
> The fix is available at https://gcc.gnu.org/r14-3331, you can apply the
> patch building the compiler.
>=20
> Sorry for the inconvenience.
>=20

Thanks for the information. I'll add a note to my builders and just disable
gcc plugins for now until the new compiler versions are available.

Guenter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2520edfc-32a3-a838-ef80-337f20cd7d9c%40roeck-us.net.
