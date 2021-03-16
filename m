Return-Path: <kasan-dev+bncBDLKPY4HVQKBBJ62YGBAMGQE7A7M7WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D72533CFE7
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 09:32:40 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id h30sf16355709wrh.10
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 01:32:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615883560; cv=pass;
        d=google.com; s=arc-20160816;
        b=hwFCX5n29ABb/yAgRC4QdQbO0r+0jWrGDSXiQvaStj5k9mnm4cDTadTDkpRCes4c6G
         Tx0g7yL8fGEY75qoC+DQKAqc8vW1EghIEiz+j7dy7J6bR/A8TZ81z7PXcOoAXCMKnZnr
         DT9ycL4hUSYKdqfsjlzl25YQ5nnYFPsyuoy8YcExKLvG1OpR8OW5njirWRBRWBRQ5wik
         q4cpe7yp8KfUQZyfEfvY2yi6qw8f9k8JVm/ZovfHMPHZERuD6rvBUsxq8DPd5fNmnc9k
         I2pwEldfDiJNrtBtAwEt13DFhXGbAzygx3ig5Km4Xi+fykyJClIrx0uCdkBPrP18C/RA
         jBMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=4U7BxUlzEyNGAnVynxycWkHlsoB3KpqMVQyczTFU3J4=;
        b=n4h1TisxmW971T7dfcWst27GbZDtTsQjiMSOwVSRKaPeexTo0SMXstSWvWacrUa02V
         ZyzUI2jUFnCAHy4GMLZTpTp5aJr1bKUwtXLxkg6OyTSx/SIiYA4GSkz98AR2hhxCAQE7
         +PQd+uJMc6bemabhmdaLmdjOxK2/N0Wxjx4zBcyqKOclnLQWAqK1Z7UtMuJhS5zI18H/
         oXpnOFr4FS8eJpXbbgbLG9LxXgAPvg0+twxWSL9JA2qYWuNCQr5bL2b7XVpSrdaCnHPi
         WU33MaN7osZRRvoTSqL6vJpKNNCDuiW+7OCMjTL0Lqr+8IEoKEK16vjdVl8iPj840dg4
         lHGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4U7BxUlzEyNGAnVynxycWkHlsoB3KpqMVQyczTFU3J4=;
        b=r6oS2wr24JHbn7UXo8Aj0Q85uNXhqAMxdP49GY7Ys+0um7mCxRYKYo02ji+k9P+tNU
         KDGQMIGXmPcNDUMZTlu0T6vjxReRfDw8ON2TqMkVr2tCRoTZv3w0kkqxiL9mMXJ+Ouuj
         IFQ6afaG+0BFQPMlrWbZCbfkY24had09oIo03szTlrwLxsGsQ7cBPakjtTqTLTxE271p
         X5Bi1dIjCxk9a2gEN9/374+3V1aQHeg0j50O1qqNXv/3KCZXuq6ymRm1DvX0+v2WoxZq
         fVGiFFofgVVhziS2VcU0j4/VrnSLTSkkQHddvtHr9b6pLCPmIuz6uUjvDgFwgD0W0+Xq
         Aj3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4U7BxUlzEyNGAnVynxycWkHlsoB3KpqMVQyczTFU3J4=;
        b=keM6Wi3BlxZU7gxUAhGt2La5odnwxM7p4vdzZ6POVz7OxoKYO8QjjXIKeY2rudoNpw
         +IiLBtnViFaVEfWeO2jhyp0XZ8N0jiYLFEiya4TSsN68UvyDtL4hP89ZS1OZIKq4l6FC
         ekw8OxvNfPol8jrDJwSVpMcVwBiLy7JOBVsDhfctO5qVSYpdwX+O46MqCC0D6m/lbX8Z
         bMfNG5J21coRkqGcM1gmZMefaeFJDBRfEOrqiL8QmD96H1avELNZpjso6Vk+r/qcJs1b
         984frubJvShTIiIxNZYzAPf8Hojq9eCiovvmiVwoM9XUB4FfF4dDduc/cqUa4czENcN9
         2C7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530R239rWrRFp2yU7VYqYsT+6mjQPBo0P00d6xqc/txubCeh84kL
	oxll1ZTTbOg8yNHCMbfFLzg=
X-Google-Smtp-Source: ABdhPJyLqiND0SYMIvbyhx9jw2l1TqyG1gXWrd6PUoHFMa52nbtSy9mKf9Iq7YQhcweNxQACrHtjXQ==
X-Received: by 2002:adf:db4c:: with SMTP id f12mr3550754wrj.93.1615883559888;
        Tue, 16 Mar 2021 01:32:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1546:: with SMTP id f6ls1452271wmg.3.canary-gmail;
 Tue, 16 Mar 2021 01:32:39 -0700 (PDT)
X-Received: by 2002:a1c:7fc9:: with SMTP id a192mr3420226wmd.15.1615883559076;
        Tue, 16 Mar 2021 01:32:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615883559; cv=none;
        d=google.com; s=arc-20160816;
        b=rR7yNP43BgD/ht6WGlAVU1mv4VrtT7O83NfQ+rIe3hn9sicV5qrJqpMGAhou6hHB0q
         9dtX0FwNeEIHzkjHyd7PKlv9mhy85ablT6+T33FWheMSsqKm34kJFFyZuHULI7VtcZ7T
         jz7jLHA0R78JKzE5NVWkBFNFxb0pPjHYixP93fQkBfRq8qgGZqXcz/nIBE+/fA9CYSl1
         3/nXZ0JQ7KbwCX5UiLtD0NsDR7Z/jx1CSCR8Vq/qwKbpSWrHIpY2MUsIeVumUw7a7SYZ
         bZ3x2/qC3xXB/UIOleF2KJn+aYW2lZ9DZx4TSmfxiTymlsZcUZlXwpouh94EW54STA0c
         9ZgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=dakvnM85NLOgwPHhk/GAs2gr3/rtNx7+zqP36xIqwGw=;
        b=UOTxinESAtybr0Xwtrc9fQAzF2sHUxkue1UzCK7ELneAnifDC8yVfVuudJOAz9Owl5
         9+pZTAdsPy176YRuGM0rKeUAqJQrC4vRwFtaEMWKFWYERiDhb6t9tGMmycJX8Pg6XCZM
         0BNO5qDOKAcAhdr9RCIDfpQ6jQ6evqyY+1pTPRYfGx1iuAcS/C4kVx0QrAeNnoDFbbx2
         ZB2MnMvVZcOKbF6Q2syzjmKRq1JHtsu/DQmzs+UkRQ6089Jz3qXRyEriPNNsjGkJ4RRO
         tGRpTTe0L1Blwh8IhLyVny5s3Nkei2cdKDK6UglEDf/D5gPZZs/06u6eOrPm7+02E1ZK
         3uJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id b6si953759wmc.2.2021.03.16.01.32.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 01:32:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F063n3w10z9v02D;
	Tue, 16 Mar 2021 09:32:37 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id l5wHRkQBPkSS; Tue, 16 Mar 2021 09:32:37 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F063n0rlPz9v02C;
	Tue, 16 Mar 2021 09:32:37 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E4E128B789;
	Tue, 16 Mar 2021 09:32:37 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id jhvqrq-uzdBC; Tue, 16 Mar 2021 09:32:37 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3ADBD8B782;
	Tue, 16 Mar 2021 09:32:37 +0100 (CET)
Subject: Re: [PATCH mm] kfence: fix printk format for ptrdiff_t
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Segher Boessenkool <segher@kernel.crashing.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Dmitriy Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@google.com>, Jann Horn <jannh@google.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20210303121157.3430807-1-elver@google.com>
 <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu>
Date: Tue, 16 Mar 2021 09:32:32 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.0
MIME-Version: 1.0
In-Reply-To: <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com>
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

+segher

Le 03/03/2021 =C3=A0 13:27, Alexander Potapenko a =C3=A9crit=C2=A0:
> On Wed, Mar 3, 2021 at 1:12 PM Marco Elver <elver@google.com> wrote:
>>
>> Use %td for ptrdiff_t.
>>
>> Link: https://lkml.kernel.org/r/3abbe4c9-16ad-c168-a90f-087978ccd8f7@csg=
roup.eu
>> Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
>> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>=20

Still a problem.

I don't understand, gcc bug ?

The offending argument is 'const ptrdiff_t object_index'

We have:

arch/powerpc/include/uapi/asm/posix_types.h:typedef long		__kernel_ptrdiff_=
t;
include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;

And get:

   CC      mm/kfence/report.o
In file included from ./include/linux/printk.h:7,
                  from ./include/linux/kernel.h:16,
                  from mm/kfence/report.c:10:
mm/kfence/report.c: In function 'kfence_report_error':
./include/linux/kern_levels.h:5:18: warning: format '%td' expects argument =
of type 'ptrdiff_t', but=20
argument 6 has type 'long int' [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SOH'
    11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
       |                  ^~~~~~~~
./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
   343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
       |         ^~~~~~~~
mm/kfence/report.c:213:3: note: in expansion of macro 'pr_err'
   213 |   pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%td):\n",
       |   ^~~~~~
./include/linux/kern_levels.h:5:18: warning: format '%td' expects argument =
of type 'ptrdiff_t', but=20
argument 4 has type 'long int' [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SOH'
    11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
       |                  ^~~~~~~~
./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
   343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
       |         ^~~~~~~~
mm/kfence/report.c:222:3: note: in expansion of macro 'pr_err'
   222 |   pr_err("Use-after-free %s at 0x%p (in kfence-#%td):\n",
       |   ^~~~~~
./include/linux/kern_levels.h:5:18: warning: format '%td' expects argument =
of type 'ptrdiff_t', but=20
argument 2 has type 'long int' [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:24:19: note: in expansion of macro 'KERN_SOH'
    24 | #define KERN_CONT KERN_SOH "c"
       |                   ^~~~~~~~
./include/linux/printk.h:385:9: note: in expansion of macro 'KERN_CONT'
   385 |  printk(KERN_CONT fmt, ##__VA_ARGS__)
       |         ^~~~~~~~~
mm/kfence/report.c:229:3: note: in expansion of macro 'pr_cont'
   229 |   pr_cont(" (in kfence-#%td):\n", object_index);
       |   ^~~~~~~
./include/linux/kern_levels.h:5:18: warning: format '%td' expects argument =
of type 'ptrdiff_t', but=20
argument 3 has type 'long int' [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SOH'
    11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
       |                  ^~~~~~~~
./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
   343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
       |         ^~~~~~~~
mm/kfence/report.c:239:3: note: in expansion of macro 'pr_err'
   239 |   pr_err("Invalid free of 0x%p (in kfence-#%td):\n", (void *)addre=
ss,
       |   ^~~~~~


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c1fea2e6-4acf-1fff-07ff-1b430169f22f%40csgroup.eu.
