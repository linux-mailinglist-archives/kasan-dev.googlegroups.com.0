Return-Path: <kasan-dev+bncBAABBK6I4HYAKGQECXQTDSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CC65136C41
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 12:46:52 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id s4sf723179vkk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 03:46:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578656811; cv=pass;
        d=google.com; s=arc-20160816;
        b=grKFWU5Dhn7HcO56KTl3HXSuJPK53ZpFuigw3AljHHP9SVy5ZKHTaexPzeo8pgmjYv
         6wwURI3jKZqVUpXd3LEeZ8EeR+q2pVsAHTvUu/BLsXByB2uhXE287JYdYNuenpMYeOoF
         IP5Km8QLxRXnx1+UGqXfnskjKhUw236D//RDFDPtNpLMDlCLg/E+ZGs2s7WvYDu32ilb
         p+47OswCMExjypGCf7qYRX8oyZ3JRbNmVOGw6Sm0sqS7mdpwhBFWOll4djT5xkgVpUUb
         E9S8ugGq8xN+X1Saxf1OCvBItaowW1EScbDSbct2dp1/RHdHxcxQS0OGDxsMaEy6TiDB
         S9Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:from:references:cc:to:subject:ironport-sdr
         :sender:dkim-signature;
        bh=ow6b4cfBeiYfJMPgyPPGr8i7FaJ3bS88aMy9JSU0s3I=;
        b=I4XFDgJU2AouRuXAd3+FPYopDPlwQqquHixGq7KT68Jkp588i0cz2YzWAu+Vpr4p6t
         SUcSp3Op+aIwCEEOwDkIk19o16eKMZBY5/wwdSHT+UEYtKtOza8Lr+uKqoYG7IIRBIEJ
         lGCxNPfQjyhfKZU9DI42UVOuCP1V1zeQuJS142N89/W4y4NCh0dhCjDDXN1bHhqc98Gw
         Xokn/lkiuNeaZghiOzo+X8di4L+LhvaXEGKoFgp1tGhMe9+u0sT1LfF4+jwYd/+QBLeH
         n89LF4lsk0X9xmx2kJDw9uTJI/4J9lcR5apMIbr2C1j6vHMDx2D16NQg4m5eoCYmqus0
         zrLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=B+39KPb4;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ow6b4cfBeiYfJMPgyPPGr8i7FaJ3bS88aMy9JSU0s3I=;
        b=rEYp2cHew6ohDJOKl11CuosufJXJGSaLIz9TlkmfASLW65J6uXQMhIeKBD41ptvuJX
         jDVyz2jWASdukewMOFmSTbTCxpeQ2Y4zyMxTEvy+WwwpV5yhK7pq/dom11c/SOPaJETb
         i1wjGoNiqV36PjZmyBVTzCAFv0rGMkzuAVNk+LUWEGZHOWpu6Q3HKtDB3nwUaotm1Ooc
         ci+8WKCWJsD01ba/OB+Td54fPcQ8falbSvzMje9SetI1CJagVm58j+QJYhiB0c9iWmcQ
         Hz/Vx/Qq4nesXXHmYN31hH2NENGAi6B+OID2XLYZWQvWjR8xbNZtloTQJolw5RW9QOMz
         /K7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ow6b4cfBeiYfJMPgyPPGr8i7FaJ3bS88aMy9JSU0s3I=;
        b=mPMNAN3cPpG+O8/vaRn4Ig7eX7adwq9yPAF7JZhguKSF/rTOt0wFlU7Fq4ElDZ1zUo
         VvF8Vj4JmvUqlKoWmojFPa5WR8uxHRAnyr52qFhopFnYAEPTjQPtDHaVcwvEwTxi6KdF
         sBjypWyzVNgytM3fGY4Jnu0EvHkVkaaxhVHWjgvIpubQnzj0w4rzQrvJ9kypE8Jdd2/Q
         AAQXlXcASNXRgDobIL4N3VOqwpy+XZN2eZC4bb2nWjfN/y+U0eB6RR/HLOjbKT+0rh9g
         Nfnnn9B2YyaT//ZazWQ/tLmTCorx//HaAZQvPB9J7ZSe5AV6g0GXVqVakLBVrThYeshf
         +t4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFuZiSoTDJHLGDY9tMUGcAKMFKuA8kcssiKgOKtu2TTCYhAdy/
	VCOp7OXssPWXHsNcRHU4nJU=
X-Google-Smtp-Source: APXvYqwv5SVqbfArXKJq8nK+3uIYSfTG74h76IX+Y7nzXdoEXDXr70uySQsGa9GUrb0ADUQ3tNcL3g==
X-Received: by 2002:a1f:2a95:: with SMTP id q143mr1665067vkq.2.1578656811506;
        Fri, 10 Jan 2020 03:46:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:664b:: with SMTP id b11ls296338uaq.3.gmail; Fri, 10 Jan
 2020 03:46:51 -0800 (PST)
X-Received: by 2002:ab0:2797:: with SMTP id t23mr1593496uap.84.1578656811198;
        Fri, 10 Jan 2020 03:46:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578656811; cv=none;
        d=google.com; s=arc-20160816;
        b=1EOonV9tY4FS3x/4c9btKYadh3Dh27bGa62+bQQ3e6K2A6MEt6YZLfkHq9F6T+IIlX
         2NEK0NIFSyvKoio0a3HRAS128xnbjIWunUkn+rzvYz9wMcvO67YIHTRD8i5zAEXa0Csw
         MxILZBP4GZPXhOdwH3+UQLW8TFs5QqUliIQqUvypvckmJySKSix46nfvk9UKVE+HR++6
         GflBXmFqX43//jVkL0dvsBOCSoD3izN3koOc5JI7dZteBaqKPgL8vkaPzLTXZ2Z4Cq6h
         xvKgQ9VUABm7pT6XUa4NXsemZA1dnhX4uxLN6f1qFHFrag8+AN3ACLNcyu5ENzYa77Oc
         iJmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=AvqWbnDxt2gASFgpZVTbGM5YgLVciDGpIY4x1sP+PPo=;
        b=ngXzvDM8maFhQYT6tsLr/QC8gt3CVMKCL8U1ViFCEBB5s3OM7nlb7Mbh6I0XOvxWgV
         T3bX7Faj2az+yv8EVTDQ11lzEBlJWO3CIH4eFlpHPWUY+MlMV4b2v9GK5lHrdX05tdoM
         zPdY2p3pPlttvXV0RpQNcpPyILjGS5UjD0Q8AJLtTo4oUKPh4xD2VJk2Xe/XSQLBrMsv
         A0NDXHmGNKi8Cbr9KmULZnFUAc2hq4Xy+Fj1L1LbkbILnxO9mB+XY5gUAYt2GiueXP4Q
         4j3Qg/X0kxaUVIHmrEDrUaPitZT8P3BVkEmX6kyENBtYmSnRwnyP3okSpjp7AKZSp2rK
         3DZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=B+39KPb4;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa1.hc3370-68.iphmx.com (esa1.hc3370-68.iphmx.com. [216.71.145.142])
        by gmr-mx.google.com with ESMTPS id 75si98361vkx.3.2020.01.10.03.46.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jan 2020 03:46:51 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as permitted sender) client-ip=216.71.145.142;
Received-SPF: None (esa1.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa1.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa1.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa1.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa1.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa1.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: uyM5kwOdR2boap5K896BuZM84UBNSBDkO98FNlQkAu1Pj8mEBmSHIJetocQa4TMSHZ5FlS1ZZ8
 LQ7Ezx4Cyu7dTOA9vnCIENf0//Jq9LBonK00mllB4r9zO85tePdpm8VKBNWPtqdtrz95uK2CSm
 4wNwJiYw4IV9dZU+CcLCtIYauqxKnZ2eXkLY9MyWOibSjc/+GtY9Jab+ag3z78vT2azmeSx9BQ
 LtSAC1vlJ2gPOsHdFGAd4MyoA0rR+e5lIIYaoRs30pVRHB2FiFLgC8bvfSky/1sdJYTgceZCE1
 xzI=
X-SBRS: 2.7
X-MesageID: 10896649
X-Ironport-Server: esa1.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,416,1571716800"; 
   d="scan'208";a="10896649"
Subject: Re: [PATCH v1 2/4] x86/xen: add basic KASAN support for PV kernel
To: Boris Ostrovsky <boris.ostrovsky@oracle.com>, <xen-devel@lists.xen.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Juergen Gross
	<jgross@suse.com>, Stefano Stabellini <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, "sergey.dyasli@citrix.com >>
 Sergey Dyasli" <sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-3-sergey.dyasli@citrix.com>
 <5214cb54-1719-f93b-130f-90c5da31e22a@oracle.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <76cf8b94-6f71-9f8c-0fc9-07ad4aded3be@citrix.com>
Date: Fri, 10 Jan 2020 11:46:45 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <5214cb54-1719-f93b-130f-90c5da31e22a@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=B+39KPb4;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.142 as
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

On 09/01/2020 23:27, Boris Ostrovsky wrote:
>=20
>=20
> On 1/8/20 10:20 AM, Sergey Dyasli wrote:
>> @@ -1943,6 +1973,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd=
, unsigned long max_pfn)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (i && i < pgd_index(__START_KERNEL_map=
))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 init_top_pgt[i] =
=3D ((pgd_t *)xen_start_info->pt_base)[i];
>> =C2=A0 +#ifdef CONFIG_KASAN
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Copy KASAN mappings
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * ffffec0000000000 - fffffbffffffffff (=3D44 b=
its) kasan shadow memory (16TB)
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 for (i =3D 0xec0 >> 3; i < 0xfc0 >> 3; i++)
>=20
> Are you referring here to=C2=A0 KASAN_SHADOW_START and KASAN_SHADOW_END? =
If so, can you use them instead?

Indeed, the following macros make the code neater:

#ifdef CONFIG_KASAN
	/* Copy KASAN mappings */
	for (i =3D pgd_index(KASAN_SHADOW_START);
	     i < pgd_index(KASAN_SHADOW_END);
	     i++)
		init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
#endif /* ifdef CONFIG_KASAN */

--
Thanks,
Sergey

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/76cf8b94-6f71-9f8c-0fc9-07ad4aded3be%40citrix.com.
