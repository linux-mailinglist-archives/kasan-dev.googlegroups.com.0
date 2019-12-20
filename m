Return-Path: <kasan-dev+bncBAABBR6D6LXQKGQEZT76EXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3975D12793E
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2019 11:26:17 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id r2sf4990409pgl.4
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Dec 2019 02:26:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576837575; cv=pass;
        d=google.com; s=arc-20160816;
        b=uASlSTCFDoyDnMbvj1W9N3haFcuKDsX/9rGVEbe4Q7k8GnT2KVVjA81tYiLCaHEdAV
         q7lYtroih//KgBgscr4AHJhvQb2/zuWwG1uhyAYirk15tl8SzLm0FGcEAd+7kG1k0yVB
         RiCRGqidcD/MaYSpy39tdk6iu/VRWBd43zMaLtq1/xd0MWOhGorq52xQ1hKfqZway/xP
         t5yPwF2sv5eX/RISmkAi3RCpdTBcIBqiqBxWOoWfkjMwjP6s63TQJrDuoeLsLIs7uvUi
         3Bwpx4Hmpi2jx+/XkbDFiMk9FqIWqoMn1ZWN4oEa83B05AfL+GFTB5Ccc94ISXkSqfAS
         Nx1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:openpgp:from:references:cc:to:subject
         :ironport-sdr:sender:dkim-signature;
        bh=uGpxdOEUcCJPOJi1IZ9MPankPkEAYnPoqUj+ASYB8sI=;
        b=Kurl6XV+wmFgPZPYfNQuh20bm8caZiA0qZczM3Qtxlo+RUEORGb3E/9KfcjORWPwE5
         nxnXgYfHjK3VKntY3p8rgQkRI49DMSNKapbClaswx1jWjStMB76WH5vHhe5hCYL78hHy
         7/jHDWEVLYTSZ3mYHSWrG7Ht8VUrniN91vG2UU4YaQnyFQhErOuJHAUC4b9poWYxT4Po
         amq0nPhD+gN2cI1yT+ij/ePtTe0KxKh+b3L6oDU2wpdXMQgY0xK1/mepfOhutzXBKGWx
         7JRsRc0Qrsj7AHyyUF5DWK8z62ExEwSVmDYwTazCx1hN0I/+aUv8tqih7z2qCC+/B+SZ
         0G7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b="PzJEr/im";
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:openpgp:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uGpxdOEUcCJPOJi1IZ9MPankPkEAYnPoqUj+ASYB8sI=;
        b=ZURy9I8a6Et94W6H3N539MuBxpA9bXUzuIE8Ar9GABNmmke2U5Xbm/w1B0nObYg9wJ
         wKMAJjMF2Wy3CE0azi0WIdpIKLsvMQcQ06WrLpyJ4JWfXsZ1jVk3psOdd8cRtex5IG8P
         PTedHVcGLO1iqs3Gwdi72nRrQp/PPiodzxR74ITM7xwwFPTOoGHiwhouwBvtIzvGhVFl
         AxgaXu6DmGnobg7uie6EY1MTdm/vTZWUvqHUg1MfS1jgG5weBVu10UzRJA7HJ18EX/3W
         YVVRK2mRRfqxFdg5eOq5U+1be1f6ojb83NTFtbKOAXwyhlpE0sbnat4SV0YC5ScMQwuE
         ReEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:openpgp:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uGpxdOEUcCJPOJi1IZ9MPankPkEAYnPoqUj+ASYB8sI=;
        b=HVc0FmlM2YrKng5KWayYG6y5dgcehGcX4N373PZADw2fLytAP2DhdnwTslnz5KPvKk
         UH2DuO636Eso8Fh0m8G4BXONHyC6SJpOajmNr/ShC3uNbcq6/zNCWN9Zebpx7tTUNAX/
         xCZkwjGPN6zh4lqna5MjnraJ9ur44FDpqnnXO6pcncSL8f7S3GwRISZKK4kGbqaVhpDp
         pcFos9G+8xQytRhulRXh7e/AEHzr5BGmKsJO4QAoFOu97h3l5tpsfWVZB3q0xyR9uVoy
         StXA79+2A1XH37Do3U6ZVUMG6Q2kYGCEHF5+NlqoTRDWR5cImYHnuzDXnvswy+XCTyEA
         SqUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU68MdpoZ7kZ+vlxsRK5DUXJrNBeyqggLA2L3PO5lPnN8Sbffn2
	IrIjFr5sPbrXP82HaGsywlk=
X-Google-Smtp-Source: APXvYqw/3vz7c9ibkfqYJVOUuHRK/j6Z8k8FtajY0VOPh+Xk+gslgMkHThT6dApllqKi+3xrB6m7EQ==
X-Received: by 2002:a17:902:202:: with SMTP id 2mr13884336plc.271.1576837575544;
        Fri, 20 Dec 2019 02:26:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:668f:: with SMTP id b15ls2033297pgw.13.gmail; Fri, 20
 Dec 2019 02:26:15 -0800 (PST)
X-Received: by 2002:a63:cd16:: with SMTP id i22mr14636775pgg.239.1576837575147;
        Fri, 20 Dec 2019 02:26:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576837575; cv=none;
        d=google.com; s=arc-20160816;
        b=MwWlVowvgf13jkkS+cmxYGZ2Pi0khCj0qecATCEPUrurRmy8ezrMfqKsImCsXYeV1N
         bceNGRbn+GmRwtFu+AH3sAZHknu1iZ9/iU6CS1yE6JyqzAn6HS6OLmJdyO3P2z/FGjTR
         1RWOo/jE7xprp2TzplmKfMPzE58JjaJ9rjGAX4EzwdoucALJFPxZKiMNSu4u0N2egfk8
         hy0tjEqjIZICTHEZ4iMzyylSRWFMzm0pn4W/ofJpMnpK1Ua4TzoLAA2s1gFF7tmXnWLm
         B7no+QKqN4kgxRJLcTa1vucrSwolaT11HFaq+vHZjNozMGLnN9i+nwFQSGODXj6G7j5f
         UCPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:ironport-sdr:dkim-signature;
        bh=cDQc1J7CEMUIu3LOm9MgdFXn0UjCxBtegk4YVp3Fvs4=;
        b=IXuAEkgADrNmD/DDNYTK6ufGM1bxcwvs01fkMoYn3kci1e0jRe/VyFi6ufzy/pSuCf
         sJZ9VaumwoYhU5RFSIpF6RmLzZ+fCa3G15Aigud0HKmFhkEBXghRYkPdzi+dL6E9bsEa
         FNRejy5oy1qucyep55SB9NRg3nscHkSkIE1xtonoFtSshOaBkpkQ6PoI5GN1BEG1B3eP
         7qqNvyE1CIKYRW4FtKw9Nrzr4V0/fmJ0ik27o7APoePhqLi+4blo7hblC1gAJWjrSSwv
         iw3XViplSFiNWrfd3GLEm2DgAr4h7cJ3zX0DcSqpM1zzc9yp9S3z8GDNpfeeIkmnTgHc
         0qlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b="PzJEr/im";
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id w4si346022pjr.1.2019.12.20.02.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Dec 2019 02:26:15 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) client-ip=216.71.145.153;
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa2.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: ygeX7qekbly+WJR7PauT6acqdlT4Bu5b+Hs5JEG2Sv3tc41I6Ub6YIbPIoUiFCSgibE6+JmIeM
 XGOwP2drPRcuC1FEMjSFz4aXP8JLvYjcUmqZlyOyyXd39HAFfNojLgkDrwTJk1h3b47816//s7
 5ieOKMyZoJhi5L4vOIBONzLXj8X5OGln/+s5aMRrLZZa3mJ7728lX7v5FYqCU/JqPeN1psKELA
 1114hhXKSdqSJEO5zL5ppDiYZ7WX3EQGRWxUiBuM6A4yPGtL6wJK87yvhE3fQ9ElRn4kmnMV+r
 rs4=
X-SBRS: 2.7
X-MesageID: 9994545
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,335,1571716800"; 
   d="scan'208";a="9994545"
Subject: Re: [RFC PATCH 0/3] basic KASAN support for Xen PV domains
To: Boris Ostrovsky <BORIS.OSTROVSKY@ORACLE.COM>
CC: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Juergen Gross <jgross@suse.com>, Stefano Stabellini <sstabellini@kernel.org>,
	George Dunlap <george.dunlap@citrix.com>, Ross Lagerwall
	<ross.lagerwall@citrix.com>, "sergey.dyasli@citrix.com >> Sergey Dyasli"
	<sergey.dyasli@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
 <7301D02C-D33F-4205-BB32-C3E61015D26E@ORACLE.COM>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Openpgp: preference=signencrypt
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <4595107c-64aa-5139-c86e-f5bff5b3d87d@citrix.com>
Date: Fri, 20 Dec 2019 10:26:09 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <7301D02C-D33F-4205-BB32-C3E61015D26E@ORACLE.COM>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b="PzJEr/im";       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

On 17/12/2019 18:06, Boris Ostrovsky wrote:
>=20
>=20
>> On Dec 17, 2019, at 9:08 AM, Sergey Dyasli <sergey.dyasli@citrix.com> wr=
ote:
>>
>> This series allows to boot and run Xen PV kernels (Dom0 and DomU) with
>> CONFIG_KASAN=3Dy. It has been used internally for some time now with goo=
d
>> results for finding memory corruption issues in Dom0 kernel.
>>
>> Only Outline instrumentation is supported at the moment.
>>
>> Patch 1 is of RFC quality
>> Patches 2-3 are independent and quite self-contained.
>=20
>=20
> Don=E2=80=99t you need to initialize kasan before, for example, calling k=
asan_alloc_pages() in patch 2?

Patch 1 is enough to correctly initialise PV Kasan. But without patch 2, lo=
ts
of false positive out-of-bounds accesses are reported once a guest starts u=
sing
PV I/O devices.

--
Thanks,
Sergey

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4595107c-64aa-5139-c86e-f5bff5b3d87d%40citrix.com.
