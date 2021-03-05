Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZFDQ6BAMGQEUIIC75A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A2D932E259
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 07:38:29 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id a9sf381992lfb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 22:38:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614926309; cv=pass;
        d=google.com; s=arc-20160816;
        b=l/wbjoiZlA1Gahl3ECRH2rrvSns3OPJ+MpEyDsbsdOBIICHZDw5phMebpLDGISM+gj
         wJYVLRo2yAehIfMaY/55Edpj2oPV5MPHs9t8ysykAAGeyspl8mLJ8KWq3Hz+p3Ve/t1s
         nKqXv8gYG0spb7124niuLD+/ndD6CWrkCE3OtAgBi2OGjssEmT9/pfPP3SCamZ/oJgp4
         YGLK5mtf5Xv4F+kn+RQyHHW8tkyHzPNMYBWdWthcVCAA7eXykfayqtzSkdWqY2ak7l6s
         Bve7a7P6Afm+F3wjf/Jjj58r9H5Cf/n/zv8frhptp5ujZlAnJq8GKxbqd+u8RgRsbrR2
         R5Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=TEZQ0I7Ueb1wM9JG5ZeeZrTV6ChcEdr0kwh8X0aiKro=;
        b=uloPWpA1IJ8H8B5xwGKsBpq7ekFZUMMXs77tvL0OzmJYG5RdXZo9kOm/nhoMvAg96C
         jD45VlWBmFufU06oKWCesVTknHf+YoM+pqU1wKO5x4/rrKm4CjwWRObdUkCeuSyW58k6
         E56lxtgiJKwWP6c882z6y40b4M2ScWMGJlNEV68vyYHsEYRUeqF1jy3RBkrclfTlfbcP
         jg+PGnRY99pTsISP/UfeGi2U3FkbrmKOAUXqOCO8pvUifyvD+HQeBmXybMWIPH/BwF1x
         rRk8Iafw0ky0nt4MKPOU7BpPFAJoOpESkwnXc1jZGKrl1IK3zmHkvxbFhajbY6ISGZym
         bkBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TEZQ0I7Ueb1wM9JG5ZeeZrTV6ChcEdr0kwh8X0aiKro=;
        b=T042lmxTWvdKEtq26OuTlwcl/uJiq7nB53cLSjjDFDPGpiTN2lFmAyGA+W2BZ43x3o
         36BkUKefQK0zBYPL5yyHHnz8Rt2fIn/kNFM0bTLJT09kWrM0/zGnLke20O6/5tT+HvaL
         vQYnTGEbnhn+b3fdqZqdtosc3Fi2A8uAeFXXu3EN+SQObxQ+5J+1ECJWnsEFaTd/FU8H
         MaiCab03wPH1FW7LILK1nAqQfULkobVK+vANTzRIdJKOq29fCvlgfMMd+s31AVZoPDns
         YEl3mZ70GFZ+SXnS0C0qJU9p32c/N0uSXPhKP5HANYx0noMZki5cLXDeREPlApX+su0D
         9KDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TEZQ0I7Ueb1wM9JG5ZeeZrTV6ChcEdr0kwh8X0aiKro=;
        b=WL2/HiBmCJUN/t2+O5gcafnx3kK4mKpXy4/WCKSXMytsDlC81Z/jeaZIxg0jXEwtFx
         u286d2Jv1anCHSz5itXVdgpE/KeRT2Jt7WOUsxl4ZrX2dAFTK/2/AdyKXF/Mu/j68IqZ
         HjPAJHzFIBJ234z0t0OK1bLvcs4T/p0IGrFnKYXvAaKWPSoAOocj2/RjSfYKXgYhgPbJ
         Mj0sRMaBc7X80Y73AuEBjpniGkACnh5WKM4m90Y1xt34QGIo4quKlUUOsI8hTnTcvgfC
         O68iyag0jkDowkBK9yNrmkJa/IHLnDgTi9IAuPammgILdAZGKb9w1ZiLZaa5pdkpE7wd
         TXwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531fDvYxCUafsZpRkJZqaWd3JqIoiN4lkeANRYcvFu1DgU9EyWq3
	pM55/YUme37IaoBbDQByR8w=
X-Google-Smtp-Source: ABdhPJwlGgdagXEgZL5+YompjBGO4G5407CCF1iPneOXxNaQCFH0sVM6mzjvLbECZDlHODKM/CPTRg==
X-Received: by 2002:a19:7402:: with SMTP id v2mr4489836lfe.58.1614926309022;
        Thu, 04 Mar 2021 22:38:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211f:: with SMTP id a31ls1620383ljq.3.gmail; Thu,
 04 Mar 2021 22:38:28 -0800 (PST)
X-Received: by 2002:a2e:a177:: with SMTP id u23mr4257790ljl.286.1614926308038;
        Thu, 04 Mar 2021 22:38:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614926308; cv=none;
        d=google.com; s=arc-20160816;
        b=yLvobVaIDDZfX/ELYYtjyJHS9VaLoz7BlW5h5xLZUTUX8eF2Uencgu3bas/cw20OgV
         IE/1BzSDd9d1EwKubRVd4+pXFr4MdV0ipIJRhGyIjJ3YWee3+paB0elvB38gsUlq4m1q
         estmdDIkVn1Dd0y2738hg2WJHZyeRW/CWKIOLde/Yf9zie10KrvWEWdTiMQLjNntHsR6
         9i/0BkwIuoljBYWZqNwuwc76mePhRF37cOk1sxcS9NDqT9A7rstW1gwqu/pFcjGdit1W
         XCafJEjT8MLGRNS6pRe6mzVU0sETnWluUQB4jAQlTLNSwggR8xZQCBiFFRjPiM/Ze+5M
         f+VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=QIfd0rlA3nQoIC1cOAkJcelkPK3nJfejXaOA4Bu2iDA=;
        b=OiKNedt7Z8FSdXZ/T++yyH9RvNdme1iVXPaaUR0iOs+52uQ0z3INS0RC36RilG6bIl
         4/PIo5pnZ10DmhN5+tNrfkFVqWbV7Xmutwlcf06HlmmsDpsLkU0TFP+g1xJi19Xo7NFP
         PeZzCaKh7giJNYzjuUJ0Rl4m3A7v6532Ga6JznB9YckUlxqGWzp9zkrd81T8fVQtQXZ5
         J0y8XixC/TrsnzH28VesY1xYIssTVUOARYjFFWC9bjgHNG08FuX5uyOd+brNImAvfgrZ
         8ZMZ7NEwvDeASpTKCBVE+PFwGG95vfVmZkaPDKORT+BUXCUbZtDaLPUFSgznnaQtxzcF
         FNQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id b27si47843ljf.6.2021.03.04.22.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 22:38:27 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DsJ361tD8z9v0yd;
	Fri,  5 Mar 2021 07:38:26 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id IJ5de3KGMh2A; Fri,  5 Mar 2021 07:38:26 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DsJ360HPSz9v0yc;
	Fri,  5 Mar 2021 07:38:26 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EA39B8B78D;
	Fri,  5 Mar 2021 07:38:26 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id LcyMHL2QgMzb; Fri,  5 Mar 2021 07:38:26 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3D2998B78B;
	Fri,  5 Mar 2021 07:38:26 +0100 (CET)
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Segher Boessenkool <segher@kernel.crashing.org>,
 Nick Desaulniers <ndesaulniers@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Mark Brown <broonie@kernel.org>, Paul Mackerras <paulus@samba.org>,
 linux-toolchains@vger.kernel.org, Will Deacon <will@kernel.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local>
 <YEEYDSJeLPvqRAHZ@elver.google.com>
 <CAKwvOd=wBArMwvtDC8zV-QjQa5UuwWoxksQ8j+hUCZzbEAn+Fw@mail.gmail.com>
 <20210304192447.GT29191@gate.crashing.org>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <ed3c08d2-04ba-217e-9924-28cab7750234@csgroup.eu>
Date: Fri, 5 Mar 2021 07:38:25 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <20210304192447.GT29191@gate.crashing.org>
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



Le 04/03/2021 =C3=A0 20:24, Segher Boessenkool a =C3=A9crit=C2=A0:
> On Thu, Mar 04, 2021 at 09:54:44AM -0800, Nick Desaulniers wrote:
>> On Thu, Mar 4, 2021 at 9:42 AM Marco Elver <elver@google.com> wrote:
>> include/linux/compiler.h:246:
>> prevent_tail_call_optimization
>>
>> commit a9a3ed1eff36 ("x86: Fix early boot crash on gcc-10, third try")

https://github.com/linuxppc/linux/commit/a9a3ed1eff36

>=20
> That is much heavier than needed (an mb()).  You can just put an empty
> inline asm after a call before a return, and that call cannot be
> optimised to a sibling call: (the end of a function is an implicit
> return:)
>=20
> Instead of:
>=20
> void g(void);
> void f(int x)
> 	if (x)
> 		g();
> }
>=20
> Do:
>=20
> void g(void);
> void f(int x)
> 	if (x)
> 		g();
> 	asm("");
> }
>=20
> This costs no extra instructions, and certainly not something as heavy
> as an mb()!  It works without the "if" as well, of course, but with it
> it is a more interesting example of a tail call.

In the commit mentionned at the top, it is said:

The next attempt to prevent compilers from tail-call optimizing
the last function call cpu_startup_entry(), ... , was to add an empty asm("=
").

This current solution was short and sweet, and reportedly, is supported
by both compilers but we didn't get very far this time: future (LTO?)
optimization passes could potentially eliminate this, which leads us
to the third attempt: having an actual memory barrier there which the
compiler cannot ignore or move around etc.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ed3c08d2-04ba-217e-9924-28cab7750234%40csgroup.eu.
