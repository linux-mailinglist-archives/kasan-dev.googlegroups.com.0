Return-Path: <kasan-dev+bncBDLKPY4HVQKBBUPFV23QMGQE6US5VCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id CC39197C3CA
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 07:12:51 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2f760cbd9desf2730171fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 22:12:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726722771; cv=pass;
        d=google.com; s=arc-20240605;
        b=QBhp2521aSb4fKhoop7+n071yTSHNglocc663pQklNdvE66g0r3Aj8gYNHSe31uVpw
         naedjQMeVeeVug58Rg1v2MM/RBcapfhWlg9Eo8WYsUF+R2fOOid1/CFmSvfbi7OZbU/8
         L7CDqGgCTgJheqj5ayT14DXOxWuCovnx9IUvpeS87/enmZih8x98B2UITQBRO2M+pgwd
         4PsPD6dFtVS0s7yz652g7Pq9XDJiWLYNaC3/JogYlmBpxiiB0VXOKM3wTpMI/FSzAHzd
         8LXnymPsUsM+MxZK3fN58xWGJkv8zYOQIVRUOYd+8tbJ5vgND+nnAxIZQXVWpJ1FwiAM
         o+dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=o2KNGY4hxuCCXBTH+GS/XB+1xQAQN2Y/DK/cgys/vas=;
        fh=TBgEJI1ZOnMDzSXfKAMCumGuxmZk9zSA2wGaNrD3Knc=;
        b=BhVa+tWQopTWMgHnCalyELmE687Ayn/j+wulu7zeuS0tZFtA5WDD3n2ZW0FWwnBlhH
         p4xNnHqJCGcrixiCmxeHzqnTAQJQtUooEUVtEC5Ix89Cu07aohxq5QqHT5qoctxM1vbQ
         lWpBG3AxJe4A3N6XDGbh4X8yR42hkjBn52JkVG/XtptMrxFUD0ih/7s9xowWVrSSzDcX
         Fz2XhOWSjYfWLL/tr01t28L2BMGrCFZMnOafzk5Cv9HaKF7BybD7OxWXru4wUMVogBUb
         B7n0qbfbHruHyMjZg6urJu0otTvb6Z76/G8BhgirVdlOczdNFg9zPPASYkjfPcIZLM7s
         PMHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726722771; x=1727327571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o2KNGY4hxuCCXBTH+GS/XB+1xQAQN2Y/DK/cgys/vas=;
        b=c+7POtGfl9lo19pA4F3UtFuGglY6QGDJQr6VIAeGOELPDdE96xH0kgoHmYDr6xXSAc
         03I3lTpDftbXpCYGt/PkpfcPL/yR/0MWo5LHva2k68tX7q0ttSOfo+0xAoWM0tzlRDwY
         DVELWpk8l6yChXvDDFeuSgI+57VjypPrAzGpNn7WpjNlTD/P65BF6nMXAAjcwHgKH/Yk
         bLvXFuvXJ4JPtJrWnWZicSQAQeGCwCZom7entxh3MgbtRtjsHihrjJnhHzajdVoM6rC5
         OFNahZinzmfUW/B1tAimoyv6kJom5PUjsz+f0YjHdW3qW8RIEtm+ttUyQzmP2SRVQ3pj
         aXdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726722771; x=1727327571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o2KNGY4hxuCCXBTH+GS/XB+1xQAQN2Y/DK/cgys/vas=;
        b=vm/d2ngBM5Cbz/ry0nvoap+8Q5bPPZ4mGmo+5TwG9EGimjzWrWdHJakjSY6uKSswL8
         1uP+imC9vbdZg2nK6MZcvoFjeXAstwoHq1H2Ra4fKZ+nmdCvZ6I5HF+85yduGe38CBv6
         RLQAXicczPj/2771LAKt8er4ovkaoTjq8Grga3vFYLBP8lphvZ0IxyNSslmjjDKeR0Hv
         cbmCWTptQ0Ti9sAkFPJMfVugvlW2jFi/bhi5q+41eK3lHqg8SryE4hOMdDR4jn2sCApM
         ksG2z8sl4KRNWYpVsR8WUy7VYViImbRE2KIZFx8Pdp4NSBmliL6vDvOtZuYEqlPjizNo
         aqYw==
X-Forwarded-Encrypted: i=2; AJvYcCXze59YIS3+mdVLaEWB+dsToahu44GcO8TiM/fesn3k0w5VcBiBw6rYyFf9Wmu9YlCHNHyChw==@lfdr.de
X-Gm-Message-State: AOJu0YyHo//JLj3d8kSFpmp0zmcs9HX+Lx5W2SxczlztMA3fFwCkq8ML
	NqqFDksa9Aryj8g7GnK19kgD6KoVg/prRrn/P3tF9P6jqvXCqz88
X-Google-Smtp-Source: AGHT+IGK08Yl1ARK1L2q5slrl9rAA2+qeKg2jv0lisr9V7iGkxsWIcmQEroGC7DWzW1f81Bz6HHIKQ==
X-Received: by 2002:a05:651c:198e:b0:2f7:583e:e967 with SMTP id 38308e7fff4ca-2f787f4505emr131395311fa.40.1726722769566;
        Wed, 18 Sep 2024 22:12:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:ec1:b0:374:c05a:403e with SMTP id
 ffacd0b85a97d-379c77a8417ls142601f8f.2.-pod-prod-08-eu; Wed, 18 Sep 2024
 22:12:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOgJwU6MvZX9FmGb/fLovx0N3NCYGI0zPN3wzYgkvNkVWEj0Ivlesi9alwIBLBbWbm6SBN/Rhsuz0=@googlegroups.com
X-Received: by 2002:a5d:5f52:0:b0:374:c949:836d with SMTP id ffacd0b85a97d-378c2d4d80fmr14964544f8f.37.1726722767505;
        Wed, 18 Sep 2024 22:12:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726722767; cv=none;
        d=google.com; s=arc-20240605;
        b=X8Nd9V9J+EBG3+2N37RElpN2OtyHXEVjHrYXzR2tR0FEQDB1dBXiSYAMoVMu9dZGCE
         IupNndRL3ASbtnnC3SnLOweXBiFkw0Z88iRzRPUCnLDhuB/MKXz6YQXGCa9jAtkGGzgF
         jfXzDyHbVuAUp+wijCdKknH9Q3sEl1Ur8Loz+jfx/mWCsnUA9fxu8WYu2JUe/n1Sndz4
         60VJxu8SzcbnhpKFSGTz3B6L/Q9LbBCug0KL68cfLPuJ/Xal7gMydkN4INM/M5gB2htE
         a5XR14OZULvU3EazDKahmXI55aPDCrYT5cbDWCC2EzipjJYwty2tHXG+qWnTpBUxxHLS
         q/pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=4zpcdFnCoTeK8iU0GeUVVMww8lNj1OYq8wkhh/Mkm4g=;
        fh=xjEXquc2EKTa/Dia+hbxeStup2lpzaszFCnP02L/7W8=;
        b=MCTVD95F04ZiQTJ57jmWxUooox1nv0GBV+k3+XpbE0EJxgA12XgbijZAnKhMWyOoQ+
         Mc/by5MWdZ6qE9tFyg0sWH1wzxRdF8Y/3XKcuXoAcSpmXDITUiQf4XYSzJdNL3Jf3lO+
         YzEWp0p6TKEldmlGcIMoad/uZQlTGA6Dv4S762u4lnraxdGDWtPHB/nqqJR0VGqRQYmM
         gTpTPLTq399Oe9hacARVYmWdbudaVbYBTLO/JGnnVk7BUgvi/Nah6cI+ZjX5MWc64nhV
         aeMIh55jM95a3lpl6HFQY8d68HToe4I6Gz5KGCaG/zsMujUg26/S8Dfxlk/15+i6Nok4
         XCwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-378e78022besi451009f8f.3.2024.09.18.22.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 22:12:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4X8Nv262lTz9tQt;
	Thu, 19 Sep 2024 07:12:46 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 4RULTJogRSBh; Thu, 19 Sep 2024 07:12:46 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4X8Nv25Brdz9tQC;
	Thu, 19 Sep 2024 07:12:46 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id A1CF48B775;
	Thu, 19 Sep 2024 07:12:46 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 9-15FAM90Jzf; Thu, 19 Sep 2024 07:12:46 +0200 (CEST)
Received: from [192.168.234.38] (unknown [192.168.234.38])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0416F8B763;
	Thu, 19 Sep 2024 07:12:45 +0200 (CEST)
Message-ID: <65664ab8-4250-47c2-be50-d56c112a17fb@csgroup.eu>
Date: Thu, 19 Sep 2024 07:12:43 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC v2 02/13] powerpc: mm: Fix kfence page fault reporting
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
 linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin
 <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
 Hari Bathini <hbathini@linux.ibm.com>,
 "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
 Donet Tom <donettom@linux.vnet.ibm.com>,
 Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
 Nirjhar Roy <nirjhar@linux.ibm.com>, LKML <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com, Disha Goel <disgoel@linux.ibm.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
 <87095ffca1e3b932c495942defc598907bf955f6.1726571179.git.ritesh.list@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <87095ffca1e3b932c495942defc598907bf955f6.1726571179.git.ritesh.list@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 19/09/2024 =C3=A0 04:56, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
> copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
> /proc/kcore can have some unmapped kfence objects which when read via
> copy_from_kernel_nofault() can cause page faults. Since *_nofault()
> functions define their own fixup table for handling fault, use that
> instead of asking kfence to handle such faults.
>=20
> Hence we search the exception tables for the nip which generated the
> fault. If there is an entry then we let the fixup table handler handle th=
e
> page fault by returning an error from within ___do_page_fault().

Searching the exception table is a heavy operation and all has been done=20
in the past to minimise the number of times it is called, see for=20
instance commit cbd7e6ca0210 ("powerpc/fault: Avoid heavy=20
search_exception_tables() verification")

Also, by trying to hide false positives you also hide real ones. For=20
instance if csum_partial_copy_generic() is using a kfence protected=20
area, it will now go undetected.

IIUC, here your problem is limited to copy_from_kernel_nofault(). You=20
should handle the root cause, not its effects. For that, you could=20
perform additional verifications in copy_from_kernel_nofault_allowed().

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/65664ab8-4250-47c2-be50-d56c112a17fb%40csgroup.eu.
