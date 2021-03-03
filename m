Return-Path: <kasan-dev+bncBD6MT7EH5AARBDOS7WAQMGQEV4WTHPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 58AC832B6D2
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:46:38 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id o8sf8930891ljp.15
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:46:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614768398; cv=pass;
        d=google.com; s=arc-20160816;
        b=RDwURLcpDfU+8lZUs5wGHs2u3MXfSKkWq/D+vzoP8lnl5i40Lcd6fDePPa315DIU3w
         NLOBoPw/XfsVp4QUU0RA0DN7N/7lVT76D2y8q1zTR0KUx+pfuRsAUK5FLSoghAUX9gEM
         8SSmkgOJYtVRVUGxWHw8V8AQP2/O1WGiGmWx0VG/WwQKvHfIld6XKgqnBir2gWb7JEqK
         gZuEP9jY+f2F4V0I0PeiLnAwhcwOJLo+4ntPDqTcmo1q6yLsrHc+D5uFRppwq2NUQGbw
         mQYr6IaSbnT1QnkY6j7eR5bzucxewN+rMHfCTqwSS+CeJf17UWZm/2591KhfN0EMDkSU
         ZdWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:sender:dkim-signature;
        bh=GPvYmklejp98dRPorkbjJLfWj5EzSyfAnhglRsfMFK0=;
        b=yZwHHQwqy7MQrluoHWuHMRuiwtcMgtxbN3/t9Fl1xTC7hkeTm2aulXD2VBD7ohdmwx
         Rk7KHufRhgLYtQKgVUwfAiShxZ6uvahj7/4d1OS/24QLn0vI4VKkVuHp46X/rwFQPagl
         CtavCGp+S1zfqRuoDH2toNeUNKZr/kQm+RThhszSNT2JrWFycjqp1Z1RZLsE48FN0VFP
         VlK74sjcSFiUanaNpL0E89sSFX00ivyIuMs3SvgkQpIGA5aSs763k0ROK3JFoBT++3rV
         b4rd91W9dLY5sCSePptPc/Dd8d1HJ1our6W0P0JmmkS+tWZVO9jmmLX8q9qa8sLUEDkr
         oCFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GPvYmklejp98dRPorkbjJLfWj5EzSyfAnhglRsfMFK0=;
        b=J+W3NO7PXnsCDt3RQRQlAGwZfO7jeEUOlrxsME/hG7J4VBPns/L6w3MjudomYR4NJO
         lev/4aOjX+EBNlxKXICLQp1s4kEKIctPLkeSmB/Z7up2V1K0pC76JfES/DvLdBRxpNCE
         WSFkEB9/Zj2ZAbKqSGp57bf9pmwWB1XddsrvAfirlRWqbr7eOLXB0ZQP/kFtNVb+HRy9
         SrVPDChh15bmsej9RedqxMemrLrcwI3vDbfdB/llzLyhcXOPKb1GcGGxrXCn3wvw7cgM
         1LBPhlY2L5bM/NjbJrZbVmTFhycHvszl0zbQPQZbzRcdNZ4kfRyqO0tthkjEx2aPlrRb
         jpoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GPvYmklejp98dRPorkbjJLfWj5EzSyfAnhglRsfMFK0=;
        b=GzpWXKWJu5w73KHqVoypSZcskMZOeHps73osIan96PNNHsu4qwCACdlIi/H+1V++1s
         40ALHIbe3WkOMeVMu1b3Gjx9pc+BMQVcwpn+BS26R4efE+51S1iufTDsKbRFUxaWTzW1
         9x86dQYf6w7jGI2Kuy1Wz09xsxVmI/3yXLUE+eWaet0jTjosyJnmVxWiLGNlA2hBXQlo
         r8k0M/ycw0BV8zXtPtSX++y8S3Asv/rR/XpFs0GL0Slo5nbZF6JjO++0at6hWFCceF/t
         +orZSs8Pg7pPYUDXh2KW3PdoVgAkiNMMBcACvLV51vNepny08nxEovd+nwO7KxdH9Z7D
         OQMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MvYw2/xpKknXQo8hXdK60HRr+rQbc41Ae6SVU3Y4jBA0UD1ul
	er9J4Tmrz/cvaVFns5Q1r54=
X-Google-Smtp-Source: ABdhPJx/BUOTanlO/tjy5/wVhxlF4B0EbVzK0tX97DrSN+hHvUKzvlTPhrivETTRti4ecNCMatKg7g==
X-Received: by 2002:a2e:974f:: with SMTP id f15mr12081522ljj.352.1614768397956;
        Wed, 03 Mar 2021 02:46:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls787646lff.1.gmail; Wed, 03
 Mar 2021 02:46:36 -0800 (PST)
X-Received: by 2002:a05:6512:b1a:: with SMTP id w26mr8754416lfu.206.1614768396926;
        Wed, 03 Mar 2021 02:46:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614768396; cv=none;
        d=google.com; s=arc-20160816;
        b=RXI+rjYuuQp7MlgVBjNjCrHDj0ukelX+1Ayhju2/4gi+CFXD47rSiP0/Svl07faMey
         caxBdrRbI0Mv0Bln37104EmwZ+rva5AuY4PmxvvJyJIQxQBlr3yEX/4C11K9Gjq3nUrA
         i1kfAbsU1ZH2Ajnct+RhptQvPEfe2tJLkUxlmWhIhle1tPoj5z9M693ghlkvqSF4Lniv
         Ac5wti9S8jsa/67bbg0NhCx+FkhIGW2eIBBAITJQ8BQDxquYVkPPPbscLIj2pOLo83qM
         7v112hhCSfRh1ZOt1+g1+cNQbghRY4I90TqphfnXBPmO5id5dTELqpi19MKceAzL6NVT
         qFwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from;
        bh=KQXvgyhSrjF3BinYyO09oyvL9i4UaN+F4g55KY1VE+g=;
        b=y46IaoxZbjQfWQKIPKwYRDK3E1k1DZEsCKPyzBQPsK8JkOINsZyf+NYHzqcdjhlUff
         98mEy62E7XtKVRHwK33t0iVVYGPs7+zJ5NZ54JxzaASmxgSmcjv1WTv5OMryME3vq/D+
         Ld1+j64xbBb+eIqIbwxFTYwKrqgaTh5uH1cxhk9hic9Zy8rTjMbWwaYThMi3OUVahbrN
         HnnlMmD+ydClhvBxYI+YLr4shFS0mk4BkNVcYEfELZSbHFm9GE+QTAk2Bd53qVeoHXjy
         GXRCFEQW9j/kHLQagmqYc5quUo1qp32KDe0FZ+fcT24qU9vjwScMelIzACDKpT6zAGhG
         D7Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.9])
        by gmr-mx.google.com with ESMTPS id a17si660250ljq.5.2021.03.03.02.46.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:46:36 -0800 (PST)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) client-ip=212.18.0.9;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4Dr9fN2CZxz1qtd7;
	Wed,  3 Mar 2021 11:46:36 +0100 (CET)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4Dr9fN1Ftmz1qwjx;
	Wed,  3 Mar 2021 11:46:36 +0100 (CET)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id SblTSEWGU7-O; Wed,  3 Mar 2021 11:46:35 +0100 (CET)
X-Auth-Info: Axyhjc4rBEzDLbMrWl1hfC1lqjWQmeVKKob8n6+6z1N27WUyAB38JWBlHrVKC9BT
Received: from igel.home (ppp-46-244-163-86.dynamic.mnet-online.de [46.244.163.86])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Wed,  3 Mar 2021 11:46:35 +0100 (CET)
Received: by igel.home (Postfix, from userid 1000)
	id 586712C36B8; Wed,  3 Mar 2021 11:46:34 +0100 (CET)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Marco Elver <elver@google.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,  LKML
 <linux-kernel@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>,
  Alexander Potapenko <glider@google.com>,  Paul Mackerras
 <paulus@samba.org>,  linuxppc-dev@lists.ozlabs.org,  Dmitry Vyukov
 <dvyukov@google.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
	<CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
	<b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
	<CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
	<f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
	<CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
	<3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu>
	<CANpmjNMKEObjf=WyfDQB5vPmR5RuyUMBJyfr6P2ykCd67wyMbA__49537.1361424745$1614767987$gmane$org@mail.gmail.com>
X-Yow: Somewhere in Tenafly, New Jersey, a chiropractor is viewing
 ``Leave it to Beaver''!
Date: Wed, 03 Mar 2021 11:46:34 +0100
In-Reply-To: <CANpmjNMKEObjf=WyfDQB5vPmR5RuyUMBJyfr6P2ykCd67wyMbA__49537.1361424745$1614767987$gmane$org@mail.gmail.com>
	(Marco Elver's message of "Wed, 3 Mar 2021 11:39:02 +0100")
Message-ID: <87pn0gy0ol.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1.91 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted
 sender) smtp.mailfrom=whitebox@nefkom.net
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

On M=C3=A4r 03 2021, Marco Elver wrote:

> On Wed, 3 Mar 2021 at 11:32, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argume=
nt of type 'signed size_t',
>> but argument 3 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>>      5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>>        |                  ^~~~~~
>> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_S=
OH'
>>     11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>>        |                  ^~~~~~~~
>> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>>    343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>>        |         ^~~~~~~~
>> mm/kfence/report.c:233:3: note: in expansion of macro 'pr_err'
>>    233 |   pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)ad=
dress,
>>        |   ^~~~~~
>>
>> Christophe
>
> No this is not expected. Is 'signed size_t' !=3D 'long int' on ppc32?

If you want to format a ptrdiff_t you should use %td.

Andreas.

--=20
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint =3D 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87pn0gy0ol.fsf%40igel.home.
