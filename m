Return-Path: <kasan-dev+bncBAABBLXSQO4QMGQEF27BCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 951C29B4CCB
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 16:03:12 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2889e4e9a62sf6191069fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 08:03:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730214191; cv=pass;
        d=google.com; s=arc-20240605;
        b=jXJ740vZnvlphlLMGOcnAsMb3y2vest4/NMbx1UCzz29jwuqR4I3Vnh8eCz+oG6wty
         UrFDJks2tJk0p5SrZlnFGYSGFUkmo4FNanOqQsjtrOVZwTwc9SScQLOA20h9JEz6Yaa5
         F1kyPbo810DtveOZ9f96jHLEuu0TOwnSEr9P9AuQQK1uqPeIDOJA/yfk5+yZFTs7H0D2
         V1S8FpxHhIcLZPbIYe9p+MCSozGDz1upHAT/ktQmzNLAWMZPgl4HBAOqpwdyNf3jP/tU
         Z3plk8C0ZzukD1KXRGoamMQEbldxbTLXXHFS33gMh+mMlpCRTSnra9QW3EsS/FtDzqaW
         BrKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=e4dmmORfjB8220OR9iGSAy5xnigBSeH6eDj8QDexEH4=;
        fh=beTecZqfuvCFvaYF1DszguDIOqgCfwFPmL3IdPVkLWk=;
        b=U7B33TT3Ocmxo+zPz1439RsqNmWwMpOsaA1a59C5y32PUL1VpKX3zZXAkAV/ADDgnr
         5K7E6RJ0H7dWEX+yPF0W3oGAwQqnGLqhoHYHnZrlOqDYotLQo5QN7HtM81+g+D7LYMGJ
         Xs9P380NtOZVsJoTbVoFHhqDyAJzvxZy/2GAQMp9URcICM1J1LK1r+q6ZY+RoAMAcbs6
         IKF5opu6ybWlNZxXS4Wsw3ay5IfvFYMckgGXTM3ZiNuxB6MZKgOq7oJ4Rly1Z/Qadeim
         nq3mHYiOoZsageFjrsa+9zoZ0W2VBHdsV5jc1pd7iQjijckbzlf1uPfdqCtMqzUJzsK8
         lviw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@foss.st.com header.s=selector1 header.b=hZ3d57Iq;
       spf=pass (google.com: domain of prvs=1032c950c7=clement.legoffic@foss.st.com designates 91.207.212.93 as permitted sender) smtp.mailfrom="prvs=1032c950c7=clement.legoffic@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730214191; x=1730818991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e4dmmORfjB8220OR9iGSAy5xnigBSeH6eDj8QDexEH4=;
        b=M5ZPrumw7vGHUqwLZ/bi36oY3t4//KYn/KHstNAzD619cJ6sJxwjPWXFcKvF7dyZLG
         YMbk01zW6MyMzfslCNVL8LUCzcRh0d5ftBZf6jQH6H9IPGZpSfTdTSrz+3KsyJbWrJ0Q
         btHBx1GQuo1DNTyQm+vj1mbxbA6/m9565wr4jTKeUsKqsmsTSfDYJ7++tucOjT2GtOYl
         ZUGLh3qo89WRLOIrzY55kFzGKblV9OwCoDtlJzbsu6lKYCfIouFtNeWQmEtHWC0hWFLm
         BFzUjxKDciOhW8DBMi8DQlNtmUre8y6vgkdN5Leo+QPcIi9629TuI4qv4RXzxjyPX/WV
         htog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730214191; x=1730818991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=e4dmmORfjB8220OR9iGSAy5xnigBSeH6eDj8QDexEH4=;
        b=u52Np1HMLzI38iQcDcUL0u3SLzBgUogAtQ6jKkM95Q4nHdj5D0UzY6tc8plptP1vgp
         GFw4ry1g9v1vxAOANpIkUtLu4KXZzIJ2RbDEZ4JY7CdS9qQfD311dhK6R7EeG99hOgp0
         SLRjhcJNPz7YESqifgOSZS/jyxuDmdIalrPe5zXeNOnCjZ4ODjCSZ1F0x4zVXioAJYWE
         ggzzqB0jwrnsYIIoBpY22TpKrZjngkp2HT0R82iBOTJ0wWVBbjZckiFBErO/9HB1FenQ
         HHv5OcJTEafDoHwnsTU8FtpK9DhyEdRtayBzo5lU6bfSHlCxUggF2Zd3shWkeYnuYANP
         r4sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRaHH4fXlL6DVimjLGAQWFst0i+0br1sSP/GvnrSK8OC93J53TA6UdrarbWKpX9rEk6OJNQA==@lfdr.de
X-Gm-Message-State: AOJu0YyykujckynTsqSGGL3CjiS88y/NmbrA7ou+C0VeHYyx5iJ9sV9Q
	7wd+dZOO2Dy0ZL+GtpVMwc4iZ8CTKhi0TSObWDT17dE4gZM5hRyB
X-Google-Smtp-Source: AGHT+IHFy8zy0dsKGPn2HzSYzD9vdKSqtHhY9UWW8l8rOUn0OBPl+dLnEK1KwUHpWslcMRrt7RVVpg==
X-Received: by 2002:a05:6870:55cd:b0:287:7faf:2186 with SMTP id 586e51a60fabf-29051bccc4cmr10889905fac.24.1730214190512;
        Tue, 29 Oct 2024 08:03:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4193:b0:288:39e2:5483 with SMTP id
 586e51a60fabf-28ce47b0805ls5309827fac.2.-pod-prod-02-us; Tue, 29 Oct 2024
 08:03:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUS67qxJDwcKXPFAhVg4ZaeTCas35UhFKfhf3bWrvwDxQaOVrwONhnBdesIbR6Mv8ncLWOxf8E1D90=@googlegroups.com
X-Received: by 2002:a05:6870:2113:b0:287:7bb6:3c54 with SMTP id 586e51a60fabf-29051d4304fmr10528971fac.38.1730214189582;
        Tue, 29 Oct 2024 08:03:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730214189; cv=none;
        d=google.com; s=arc-20240605;
        b=WVipJvg8IkGwV8+UE/MVk+J6x3yUXenm7wPq2dBaAtvr9yem/ZigI61b4zJnQNKNPI
         PURrKcGKb7lr7LZ9dgKCHZt3P/v6GZOpMMKaWGqM5k7Y0KTI2o0IqP2xqfqg0cODtzFZ
         KX6RcaiB8lNeJu7WKbrZDrfioUFUVtgPExos5cuJwo/j3eJQtp6XaOsJkzhF/DnPUB7k
         sTopmGSt5DATTdmTsNZS0X2zjWNCH9UHw5au1+rwZOuOwTwgDwpB6qqlnZioQKAO1YK6
         h6R/ccV8hSNpy+2NAY+SYlVZWGBq5b3tfEWMp7NA88vepbscr0soCcARTBIws8zxm/wr
         ceoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=UqeRlTfozsVN09UU+kff1ZF8lDSMEDqo8CyqaqZhk/Y=;
        fh=D6eXkIe5nmd/RISPau0pIn5rjMekmJrjLqHLTGk03Po=;
        b=LPgKj7mOOZxYd3tTJZ1j6DhrZdDDeWJyXutS5FjtzrNDOIJKFnwFUgm1iNxu+bxjEv
         cUHbPV7HdndoNwuDXW9bdWToERPoboHdc3H0yF41g3AcjlvGPFpaaxmirIhWdAW5nOgA
         bFcTvfz/e32OdE1vP1uoZrWFVSyDCIGyadAOQMPzlh8t/kJDgZHLuzorhnLhv0XPKOhM
         yI38goqVCCSFMV4cKcNoeJXHddRvxnYPkAs/Ddhk6EgPN9fh9qealJGJutjGModquSNd
         m4uHE/ymaDOiqjURau7oS5++NGa+mRwpdt81xs1fCz/BJPYGw8tU2z5HtA6PNc5IQ/Cy
         q5ZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@foss.st.com header.s=selector1 header.b=hZ3d57Iq;
       spf=pass (google.com: domain of prvs=1032c950c7=clement.legoffic@foss.st.com designates 91.207.212.93 as permitted sender) smtp.mailfrom="prvs=1032c950c7=clement.legoffic@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
Received: from mx07-00178001.pphosted.com (mx08-00178001.pphosted.com. [91.207.212.93])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-510042e4f27si403149e0c.1.2024.10.29.08.03.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Oct 2024 08:03:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=1032c950c7=clement.legoffic@foss.st.com designates 91.207.212.93 as permitted sender) client-ip=91.207.212.93;
Received: from pps.filterd (m0046660.ppops.net [127.0.0.1])
	by mx07-00178001.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 49TCVZdE022650;
	Tue, 29 Oct 2024 16:02:54 +0100
Received: from beta.dmz-ap.st.com (beta.dmz-ap.st.com [138.198.100.35])
	by mx07-00178001.pphosted.com (PPS) with ESMTPS id 42gnj4ff7u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Oct 2024 16:02:54 +0100 (CET)
Received: from euls16034.sgp.st.com (euls16034.sgp.st.com [10.75.44.20])
	by beta.dmz-ap.st.com (STMicroelectronics) with ESMTP id 7183B4002D;
	Tue, 29 Oct 2024 16:01:12 +0100 (CET)
Received: from Webmail-eu.st.com (shfdag1node2.st.com [10.75.129.70])
	by euls16034.sgp.st.com (STMicroelectronics) with ESMTP id 1A45E26702B;
	Tue, 29 Oct 2024 16:00:04 +0100 (CET)
Received: from [10.48.86.107] (10.48.86.107) by SHFDAG1NODE2.st.com
 (10.75.129.70) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.37; Tue, 29 Oct
 2024 16:00:03 +0100
Message-ID: <aeef0000-2b08-4fd5-b834-0ead5c122223@foss.st.com>
Date: Tue, 29 Oct 2024 16:00:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Linus Walleij <linus.walleij@linaro.org>
CC: Ard Biesheuvel <ardb@kernel.org>,
        Andrey Ryabinin
	<ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey
 Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev
	<kasan-dev@googlegroups.com>,
        Russell King <linux@armlinux.org.uk>, Kees Cook
	<kees@kernel.org>,
        AngeloGioacchino Del Regno
	<angelogioacchino.delregno@collabora.com>,
        Mark Brown <broonie@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
        Antonio Borneo
	<antonio.borneo@foss.st.com>,
        <linux-stm32@st-md-mailman.stormreply.com>,
        <linux-arm-kernel@lists.infradead.org>, <stable@vger.kernel.org>
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com>
 <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com>
 <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
 <f3856158-10e6-4ee8-b4d5-b7f2fe6d1097@foss.st.com>
 <CACRpkdZa5x6NvUg0kU6F0+HaFhKhVswvK2WaaCSBx3-JCVFcag@mail.gmail.com>
 <CACRpkdYtG3ObRCghte2D0UgeZxkOC6oEUg39uRs+Z0nXiPhUTA@mail.gmail.com>
Content-Language: en-US
From: Clement LE GOFFIC <clement.legoffic@foss.st.com>
In-Reply-To: <CACRpkdYtG3ObRCghte2D0UgeZxkOC6oEUg39uRs+Z0nXiPhUTA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.48.86.107]
X-ClientProxiedBy: SHFCAS1NODE1.st.com (10.75.129.72) To SHFDAG1NODE2.st.com
 (10.75.129.70)
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Original-Sender: clement.legoffic@foss.st.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@foss.st.com header.s=selector1 header.b=hZ3d57Iq;       spf=pass
 (google.com: domain of prvs=1032c950c7=clement.legoffic@foss.st.com
 designates 91.207.212.93 as permitted sender) smtp.mailfrom="prvs=1032c950c7=clement.legoffic@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
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

On 10/25/24 22:57, Linus Walleij wrote:
>> What happens if you just
>>
>> git checkout b6506981f880^
>>
>> And build and boot that? It's just running the commit right before the
>> unwinding patch.
>=20
> Another thing you can test is to disable vmap:ed stacks and see
> what happens. (General architecture-dependent options uncheck
> "Use a virtually-mapped stack".)

Hi Linus,

I have tested your patches against few kernel versions without=20
reproducing the issue.
- b6506981f880^
- v6.6.48
- v6.12-rc4
I didn't touch to CONFIG_VMAP_STACK though.

The main difference from my crash report is my test environment which=20
was a downstream one.

So it seems related to ST downstream kernel version based on a v6.6.48.
Even though the backtrace was talking about unwinding and kasan.

I will continue to investigate on my side in the next weeks but I don't=20
want to block the patch integration process if I was.

Best regards,

Cl=C3=A9ment

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
eef0000-2b08-4fd5-b834-0ead5c122223%40foss.st.com.
