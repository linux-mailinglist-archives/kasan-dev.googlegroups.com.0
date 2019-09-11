Return-Path: <kasan-dev+bncBCXLBLOA7IGBBK6V4PVQKGQEXZDATLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 21890AFCE6
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 14:38:04 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 34sf12525733edf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 05:38:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568205483; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2h82pGQ6htwY3obMBOlLJnbPFckiuBgXUPFGSRU7OvFef8fpuPjYuXJCr013wL1Mo
         1OlVwr1W+zaYynPTO8j4pnEk3BIWiAlg8UGOEeBGu3ySJlYvgm7uc1MdODbXYgSsUHDy
         olV/TsSlPK8QD98/uLfgNqOXl8rcDAe2KPqOB9E8iwiV3TWlvAo8c5DHSoPTkp2x4pAR
         nvMk/heT3JfLRdr9Fqblav5+f70DEWZtlc3kRKnkGSev9WNOS6479GvQJlqSl1lctMhM
         OVOUJZJZsj7tVxYvCN+hLIqUB7PoRyGzKhj7ffudCrogrtK4EuZD1YuJa6Ppl7M5zlMZ
         Z3nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=uHjJGDwy0yodkVjsRBXieR9V2WXTuXWFVGvaIIbqaf0=;
        b=g8FH/37i11WKLR4MCYZGQRri6ntCc+1x1MbxnCfb0jdx3ZGFO7ULZYi0BAxKGCzU14
         3b6oisg0Zf4H6gdcMzq4idOEcondi8r1t+IFLn1cY5NedFnWLJvzEEBMCA9+gjROP9pg
         OdzDVdW25xFUtoK1e5nK/tt72jrPiJfi/lJi/ao36Sm5krarIB5vaHOehFClVTBImEMC
         mlKUleWPAsCDnJLbos+Z2G+2Wd2KWTddDTuMS2lguLDVpavcR4/bjAjtsyqZsffsBmja
         hPwryOWFfABa9OxNlPrsts2bsiwvbQQmSetT+E9WRwn9mib3W2a4kV1M9Bmi+OxtwLCZ
         ScVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=BheTapsZ;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uHjJGDwy0yodkVjsRBXieR9V2WXTuXWFVGvaIIbqaf0=;
        b=DQjtSAkvjjt2t1A8r7rdbd3DGRk3ua+CBoq4N33mZiIz4EJbGq690mJl73n/9S8K8I
         AON/CnBtGsdrl/VQBGwSNS7jNYPkKMF1z+GVsUcZSDl7Sh8HtC/PS5KQGWFBL9zPrCka
         ZTJzULrPhi/0LXxJYvacdt2ob/PQsXtfFsijPJ9PAGQXGSQtNxc06Aze71sqhNJDn1Wk
         SclzWVeqKPLvNkPDcsx/Ko/q4Fb+HxGA761H8dF89wvih4y9bwZh4KA/qfsOSWVy6wka
         rrL0/imnNS1sBMlvuQq/dwOxUw8kualF+r/tiormoGOeqHSLcoDD4zI5LovbZd9y0WPZ
         Fs2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uHjJGDwy0yodkVjsRBXieR9V2WXTuXWFVGvaIIbqaf0=;
        b=hi6hQ8disHlhl09yjwniUjQ4U3BtixtUuSJB4E7CEXgDWNveDgwN8RZUhzIekqX9Pz
         KxK+QKpcp2TnfBrUaMGTyP2bE+W8ToX3gwkXYdDm9tOVnetitLwBZetrAImkFngwz3s0
         Esv0dd0a2/2952IUB8l+jfsRUhfhuzI+oO+GCGvgI6icy8tpcPpOyNsTC7+iq2QXBRbu
         mC2vRbKKEUdMRpVKVx+a6uNRV13txBg2J5whYpkfvtQhxPsHKcHMy+l1DhSLA3NUkFFd
         73KFn3A9XOzwRJ3qxhMmwJGKhd1fK4JE2wFdBeaeBueiW4bQ1RpMbhzF+SqynFZXl3L3
         PEsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUUAP9t9GZh9S59vxyxOIzmDkf/GrD/3MiNi8Wd1emRZ8ClxNl8
	QfShLrE7Wrna58gHFY8oQx8=
X-Google-Smtp-Source: APXvYqyPWdng9X1uMFvxJB7B8fUprcw0bB1stM1AYPm56Pf3L/ar27mtejvXFap0rUPPz/qdMRr5Ug==
X-Received: by 2002:a50:f04e:: with SMTP id u14mr36252915edl.247.1568205483794;
        Wed, 11 Sep 2019 05:38:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1a24:: with SMTP id be4ls64445edb.1.gmail; Wed, 11
 Sep 2019 05:38:03 -0700 (PDT)
X-Received: by 2002:a50:d68a:: with SMTP id r10mr36495666edi.151.1568205483316;
        Wed, 11 Sep 2019 05:38:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568205483; cv=none;
        d=google.com; s=arc-20160816;
        b=OQJKg7sS8eTwGUWdHZr43ckNsgmWiSYAFisHsf+tUmno2GENljiWZQ3VsxTHK1im5I
         KKdxOJM3sqsRdzhHFZwERBYN6GyJ1a978xw54VV0KPFVWa61QC+GMyPnNUPerac4Dtkf
         N4cXAYMsd4PlXNm9IQXVo3IwSXwG4f3wuCQsrOEiLr/HN0CaEZuqrmd9CC8or7oOXej5
         XM/KJ9nlTuzy4r0APg8B+G+ctdXN8Eob41E7p89Rw8p7tZiSju3GJDk/sZZfYK91t7sm
         PtEcMZpPliIIvWgFWJXRgGp925gey0eAny4j2qF9TX59s/H+cdfwUOEWO8nWBSkPJ+ZH
         yHBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=DhX4WED4iVEDvM7Oo6DUrJ7y5zvr1cIiyY6i5byB5xc=;
        b=lEU//rd+ej69CUX9RBbddpXvT+ncv0vnkN4/MAhS01FiiC/oBXX+uT3r9p5fwv1tTS
         r3jnRhDWaF6vtHn1CqXRGBIQMFY+PIIPz8tMW+5Wo0DcrNoO7hRvqwg7Rc97RXqr6NiW
         T/GG++HBoMTuiSj0muxo5WBms4zLrWzKcEJQ9oTWPdmcjxQdSyIj9ZHFi1c1WfV+W1nq
         47u2nZDFbxhhTkKCrLZLSaJzrn+Vnvf60yhpBux3tc3RL054GjAAqxTuM/N5OBKIXfNi
         3wSy3zIa5xU9bJwwip/UkVaXiyeH3wlu91e6edaVacpMn1jq4dBHfcmXMCOW2viEp38u
         SPaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=BheTapsZ;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id f20si997329edx.1.2019.09.11.05.38.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Sep 2019 05:38:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46T1dj3qf5z9ttBh;
	Wed, 11 Sep 2019 14:38:01 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id mYSQiCEUNZcF; Wed, 11 Sep 2019 14:38:01 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46T1dj2lqhz9ttBL;
	Wed, 11 Sep 2019 14:38:01 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BB57A8B8BF;
	Wed, 11 Sep 2019 14:38:02 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id SJCnYKUN_9kO; Wed, 11 Sep 2019 14:38:02 +0200 (CEST)
Received: from [172.25.230.103] (po15451.idsi0.si.c-s.fr [172.25.230.103])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 945FD8B8A6;
	Wed, 11 Sep 2019 14:38:02 +0200 (CEST)
Subject: Re: [PATCH v7 0/5] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
 glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
 mark.rutland@arm.com, dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20190903145536.3390-1-dja@axtens.net>
 <d43cba17-ef1f-b715-e826-5325432042dd@c-s.fr>
 <87ftl39izy.fsf@dja-thinkpad.axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <f1798d6b-96c5-18a7-3787-2307d0899b59@c-s.fr>
Date: Wed, 11 Sep 2019 14:38:02 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <87ftl39izy.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=BheTapsZ;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 11/09/2019 =C3=A0 13:20, Daniel Axtens a =C3=A9crit=C2=A0:
> Hi Christophe,
>=20
>> Are any other patches required prior to this series ? I have tried to
>> apply it on later powerpc/merge branch without success:
>=20
> It applies on the latest linux-next. I didn't base it on powerpc/*
> because it's generic.
>=20

Ok, thanks.

I backported it to powerpc/merge and I'm testing it on PPC32 with=20
VMAP_STACK.

Got a few challenges but it is working now.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f1798d6b-96c5-18a7-3787-2307d0899b59%40c-s.fr.
