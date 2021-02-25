Return-Path: <kasan-dev+bncBDE5LFWXQAIRB2GG36AQMGQEK2VVMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 13B6F3254BC
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 18:50:33 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id a12sf4945881ioe.5
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:50:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614275432; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pd3RXutoq6bA1KbYt+H36VhXN5BiqzOTtgAkc47zZ1tf5EhyO2L8yHei0cfhROQVbt
         vPMGTu14p80z4DWTYKZxaxgDr+VgbOORTwRNDgirzPcPDssMe2GZYS/g5ayTjwXstFT4
         pbNxZiKeJ8oI8M/mStzoQdYM3vtgP70dcl4ll/uf0wz/tlPn8WmUAEgco9g036aaROk+
         /oU4CBv+EVKsgeubW4McVfC31VfrKi+Fur4dmq40afDiVLsWEv2shbPNCTAi3C1lq4QC
         4K0LopzRanNxC+w8jSUpFrbGHoOQ5cO/OyizpZdnIl7N/54HFgwK/RuHJ9b08Wa/kpsW
         cDDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KzGH6brZ/1GYiIIVbNerfctxjt0MA3+9VY+desjc+/g=;
        b=khP077+wV78EwFLcRlfwdSM7AOFDvoqipDZpWyiTQbg9+6FsU7BDXouEJ9UurogV6R
         G2A93norTHe6kb+ApbYVrvW81pnrYXallAMKcgIOjiHBKGuzVfRBwB9UP1oHfHcyDSmL
         EzvWCki8Wg22iCXLOMLJ6QkgSM0a8nrbf38VHqTpAjGBVME5RO5oJoP3LrTf5Xe92yP2
         F9y3RCZ6VprfVwTuquilfPR0/i8BUaHFl8XA28K4HQFkI2U5SNBdcJWlehRrU0Vu9QDL
         yGsF2eJrwQhU4/ysVMtGqNCwqy1BsHa/P4kXQQFDjNdLLBPBvCChj0cUaXgOHnXzN+cm
         EW3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jLpmAJ+H;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KzGH6brZ/1GYiIIVbNerfctxjt0MA3+9VY+desjc+/g=;
        b=QupQ1l2qCSqBf2fiZLYndqMNUD1LsvozCyPI6QGFDZBZi4bi2rGRutRnDv4hcncRl3
         CAGlc0hLyIPPfBXFko+Ir3uSh/wb8TY6E2V41zxkuB7r78rLvkh19mh6UHchE/0OAKdz
         YiXimtyvX0PqdTXd0z57MdpStIA7HzmjvvBpyQBXYJhOCtOMqDHnl/U/a7hIICXc9gCT
         hgUjRFfnT/k2kkdY+9eSePs/lDHPgBP66LdmVuVFzViwgTpTT+oiUxNWlBfrL1dTjG/s
         h+0pX7ttnNNoBBqZ0IZgieXKXooV2KfpZaJOPm9QZ+Q1V28s/7WFrq8qBlbWrRlvN+p/
         FhUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KzGH6brZ/1GYiIIVbNerfctxjt0MA3+9VY+desjc+/g=;
        b=O1o68cF9U/uY3+WCUagSbxINYmSQKFLQKpLNqMDQnRidmT+sLZdkxrkPS4hyzw7fay
         77lKUtydqr3HrG0CNL/ENM5Nsju1xo9vThSmBegE+Mz6tjZwfDYKC9yObZUrgB5DG2/7
         GyHNOKING90sZwXRDJ0PMPKosZ7R+HkwXrVMh1YXmvrxtqp3dRXPPgnS9n3n2totKS6C
         ehLjjrLb7lIK4YdrB4DZcDOzqVVljVcBDVRewE80WtXiSaM0aPBxz8D5/hxA6Srdh6DM
         BZKkMkJqhTVhVeGU2jfxfMN2jbjV21O8tMA6WGovmO81Rk1vXhzGf5E0SiGiA8XaBP2b
         bcIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533I2F05wtzT/sbJZte4l52g1mG6+J528OzfJnBYQQcmuSuiTm7O
	+TOD2rkZ5d4T1FPyFIAQlo8=
X-Google-Smtp-Source: ABdhPJzNWSe528yfcpxlAkcEOxMJH8qv4uk4cDhhADruJKvCo2wEjsZpUL1LkRNonIjPPu0VycV6Kw==
X-Received: by 2002:a05:6638:1607:: with SMTP id x7mr4340068jas.63.1614275432046;
        Thu, 25 Feb 2021 09:50:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:9146:: with SMTP id b6ls924916jag.10.gmail; Thu, 25 Feb
 2021 09:50:31 -0800 (PST)
X-Received: by 2002:a02:cb45:: with SMTP id k5mr2496388jap.107.1614275431690;
        Thu, 25 Feb 2021 09:50:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614275431; cv=none;
        d=google.com; s=arc-20160816;
        b=Xaz1w/a8fqkdhPOHS+zqpvbhmaEpIKkhB/RaKeNSsT0eVBoO+worY1FT+sIZW8XOGz
         jSwPgKF+JaLejmUoXr1zs2yn0rdlY8Ba3hcH6h4KzZYsShsALEfZFuvHADycg4RK2RmW
         1II1eJRYtuc6M4agEZ0yLYzfWYZMT8zdDvfUPbOsbJBkzxSMapoRCP/5SUaXIgNenwYm
         yocjPsIM/8StqDGyQx4/I+0Z+lA674KZf/623oCW+1yjp6jlhmKbeM3Q/iiVXEXdi9si
         zY2qCFDv/azc1iwMbxJ8VAD+W7/zgFyYlqG6a4TuNq+BNwcqdo63llq8Qf4P38His0w0
         QB8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Dj0Pa8aF0tC5Uv5BuKgWwY3C1VrzZLxPJIwF5G/jwvk=;
        b=fl3nMBwaqWSEZ6ANMEcHyieua2iGJfQP9O8BjELEBm6gd5xYSGOz1uDKLLrxsPQcCe
         TdJYZ4cVImIG+NNiKm/1UzJ6Ah3tw4TtP23rYt60nFB4oCNmqo6x6lstdYUMvyTIQlYm
         Lc1vnN1cUmPz/lVPp60jeSrt0Q0dTJjkc7vLQ/4aWUgAVIRYtzztox3xsu4EGOt1MSVy
         W0APlr5XFfeLjmCSpZ+4MvjzcarOMocDD2PaY0zQqiOZygEyxxzH5g+hy2yFdr98ukX+
         pTSAOAAMh5QpRp4CCXfkZSc66s7uG76chxs0zD/8XE+rnpIGF05bZFK1hrnAOJ57hWkg
         jCtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jLpmAJ+H;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id g4si555375iow.1.2021.02.25.09.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 09:50:31 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11PHYDt1066795;
	Thu, 25 Feb 2021 12:50:16 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xe106cj5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 12:50:16 -0500
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11PHa19U072619;
	Thu, 25 Feb 2021 12:50:16 -0500
Received: from ppma01fra.de.ibm.com (46.49.7a9f.ip4.static.sl-reverse.com [159.122.73.70])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xe106ch5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 12:50:15 -0500
Received: from pps.filterd (ppma01fra.de.ibm.com [127.0.0.1])
	by ppma01fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11PHi6BY012014;
	Thu, 25 Feb 2021 17:50:13 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma01fra.de.ibm.com with ESMTP id 36tt28aekq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 17:50:13 +0000
Received: from d06av21.portsmouth.uk.ibm.com (d06av21.portsmouth.uk.ibm.com [9.149.105.232])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11PHoAmD36765968
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 17:50:10 GMT
Received: from d06av21.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D28985205A;
	Thu, 25 Feb 2021 17:50:09 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av21.portsmouth.uk.ibm.com (Postfix) with ESMTPS id E438852078;
	Thu, 25 Feb 2021 17:50:06 +0000 (GMT)
Date: Thu, 25 Feb 2021 19:50:04 +0200
From: Mike Rapoport <rppt@linux.ibm.com>
To: George Kennedy <george.kennedy@oracle.com>
Cc: David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Konrad Rzeszutek Wilk <konrad@darnok.org>,
        Will Deacon <will.deacon@arm.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Christoph Hellwig <hch@infradead.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        LKML <linux-kernel@vger.kernel.org>,
        Dhaval Giani <dhaval.giani@oracle.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <20210225175004.GG1854360@linux.ibm.com>
References: <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <dcf821e8-768f-1992-e275-2f1ade405025@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <dcf821e8-768f-1992-e275-2f1ade405025@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-25_10:2021-02-24,2021-02-25 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 mlxscore=0 impostorscore=0 malwarescore=0 priorityscore=1501
 suspectscore=0 adultscore=0 bulkscore=0 mlxlogscore=999 phishscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102250133
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jLpmAJ+H;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Feb 25, 2021 at 11:31:04AM -0500, George Kennedy wrote:
>=20
>=20
> On 2/25/2021 11:07 AM, Mike Rapoport wrote:
> > On Thu, Feb 25, 2021 at 10:22:44AM -0500, George Kennedy wrote:
> > > > > > > On 2/24/2021 5:37 AM, Mike Rapoport wrote:
> > > Applied just your latest patch, but same failure.
> > >=20
> > > I thought there was an earlier comment (which I can't find now) that =
stated
> > > that memblock_reserve() wouldn't reserve the page, which is what's ne=
eded
> > > here.
> > Actually, I think that memblock_reserve() should be just fine, but it s=
eems
> > I'm missing something in address calculation each time.
> >=20
> > What would happen if you stuck
> >=20
> > 	memblock_reserve(0xbe453000, PAGE_SIZE);
> >=20
> > say, at the beginning of find_ibft_region()?
>=20
> Added debug to your patch and this is all that shows up. Looks like the
> patch is in the wrong place as acpi_tb_parse_root_table() is only called =
for
> the RSDP address.

Right, but I think it parses table description of the other tables and
populates local tables with them.
I think the problem is with how I compare the signatures, please see below

> [=C2=A0=C2=A0=C2=A0 0.064317] ACPI: Early table checksum verification dis=
abled
> [=C2=A0=C2=A0=C2=A0 0.065437] XXX acpi_tb_parse_root_table: rsdp_address=
=3Dbfbfa014
> [=C2=A0=C2=A0=C2=A0 0.066612] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 B=
OCHS )
> [=C2=A0=C2=A0=C2=A0 0.067759] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 B=
OCHS BXPCFACP
> 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.069470] ACPI: FACP 0x00000000BFBF5000 000074 (v01 B=
OCHS BXPCFACP
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.071183] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 B=
OCHS BXPCDSDT
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.072876] ACPI: FACS 0x00000000BFBFD000 000040
> [=C2=A0=C2=A0=C2=A0 0.073806] ACPI: APIC 0x00000000BFBF4000 000090 (v01 B=
OCHS BXPCAPIC
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.075501] ACPI: HPET 0x00000000BFBF3000 000038 (v01 B=
OCHS BXPCHPET
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.077194] ACPI: BGRT 0x00000000BE49B000 000038 (v01 I=
NTEL EDK2=C2=A0=C2=A0=C2=A0=C2=A0
> 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.078880] ACPI: iBFT 0x00000000BE453000 000800 (v01 B=
OCHS BXPCFACP
> 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
> [=C2=A0=C2=A0=C2=A0 0.080588] ACPI: Local APIC address 0xfee00000
>=20
> diff --git a/drivers/acpi/acpica/tbutils.c b/drivers/acpi/acpica/tbutils.=
c
> index dfe1ac3..603b3a8 100644
> --- a/drivers/acpi/acpica/tbutils.c
> +++ b/drivers/acpi/acpica/tbutils.c
> @@ -7,6 +7,8 @@
> =C2=A0 *
> *************************************************************************=
****/
>=20
> +#include <linux/memblock.h>
> +
> =C2=A0#include <acpi/acpi.h>
> =C2=A0#include "accommon.h"
> =C2=A0#include "actables.h"
> @@ -232,6 +234,8 @@ struct acpi_table_header *acpi_tb_copy_dsdt(u32
> table_index)
> =C2=A0=C2=A0=C2=A0=C2=A0 acpi_status status;
> =C2=A0=C2=A0=C2=A0=C2=A0 u32 table_index;
>=20
> +printk(KERN_ERR "XXX acpi_tb_parse_root_table: rsdp_address=3D%llx\n",
> rsdp_address);
> +
> =C2=A0=C2=A0=C2=A0=C2=A0 ACPI_FUNCTION_TRACE(tb_parse_root_table);
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 /* Map the entire RSDP and extract the address o=
f the RSDT or XSDT */
> @@ -339,6 +343,22 @@ struct acpi_table_header *acpi_tb_copy_dsdt(u32
> table_index)
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 acpi_tb_pa=
rse_fadt();
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
>=20
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (ACPI_SUCCESS(status) &&
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ACPI_COMPARE_NA=
MESEG(&acpi_gbl_root_table_list.
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 =C2=A0tables[table_index].signature,
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 =C2=A0ACPI_SIG_IBFT)) {

We have:

include/acpi/actbl1.h:#define ACPI_SIG_IBFT           "IBFT"    /* iSCSI Bo=
ot Firmware Table */

and the BIOS uses "iBFT", so we need to loop over possible signature
variants like iscsi_ibft_find does.

Do you mind replacing ACPI_SIG_IBFT with "iBFT" and try again?

> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct acpi_tab=
le_header *ibft;
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct acpi_tab=
le_desc *desc;
> +
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 desc =3D &acpi_=
gbl_root_table_list.tables[table_index];
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 status =3D acpi=
_tb_get_table(desc, &ibft);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (ACPI_SUCCES=
S(status)) {
> +printk(KERN_ERR "XXX acpi_tb_parse_root_table(calling memblock_reserve()=
):
> addres=3D%llx, ibft->length=3D%x\n", address, ibft->length);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 memblock_reserve(address, ibft->length);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 acpi_tb_put_table(desc);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
> +
> =C2=A0next_table:
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 table_entry +=3D table_entry_=
size;
>=20
>=20
> > > [=C2=A0=C2=A0 30.308229] iBFT detected..
> > > [=C2=A0=C2=A0 30.308796]
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > [=C2=A0=C2=A0 30.308890] BUG: KASAN: use-after-free in ibft_init+0x13=
4/0xc33
> > > [=C2=A0=C2=A0 30.308890] Read of size 4 at addr ffff8880be453004 by t=
ask swapper/0/1
> > > [=C2=A0=C2=A0 30.308890]
> > > [=C2=A0=C2=A0 30.308890] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.=
11.0-f9593a0 #12
> > > [=C2=A0=C2=A0 30.308890] Hardware name: QEMU Standard PC (i440FX + PI=
IX, 1996), BIOS
> > > 0.0.0 02/06/2015
> > > [=C2=A0=C2=A0 30.308890] Call Trace:
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 dump_stack+0xdb/0x120
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 print_address_description.constprop.7+=
0x41/0x60
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 kasan_report.cold.10+0x78/0xd1
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 __asan_report_load_n_noabort+0xf/0x20
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ibft_init+0x134/0xc33
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 do_one_initcall+0xc4/0x3e0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? perf_trace_initcall_level+0x3e0/0x3e=
0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? unpoison_range+0x14/0x40
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? ____kasan_kmalloc.constprop.5+0x8f/0=
xc0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? kernel_init_freeable+0x420/0x652
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? __kasan_kmalloc+0x9/0x10
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init_freeable+0x596/0x652
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? console_on_rootfs+0x7d/0x7d
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init+0x16/0x1d0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ret_from_fork+0x22/0x30
> > > [=C2=A0=C2=A0 30.308890]
> > > [=C2=A0=C2=A0 30.308890] The buggy address belongs to the page:
> > > [=C2=A0=C2=A0 30.308890] page:0000000001b7b17c refcount:0 mapcount:0
> > > mapping:0000000000000000 index:0x1 pfn:0xbe453
> > > [=C2=A0=C2=A0 30.308890] flags: 0xfffffc0000000()
> > > [=C2=A0=C2=A0 30.308890] raw: 000fffffc0000000 ffffea0002ef9788 ffffe=
a0002f91488
> > > 0000000000000000
> > > [=C2=A0=C2=A0 30.308890] raw: 0000000000000001 0000000000000000 00000=
000ffffffff
> > > 0000000000000000
> > > [=C2=A0=C2=A0 30.308890] page dumped because: kasan: bad access detec=
ted
> > > [=C2=A0=C2=A0 30.308890] page_owner tracks the page as freed
> > > [=C2=A0=C2=A0 30.308890] page last allocated via order 0, migratetype=
 Movable,
> > > gfp_mask 0x100dca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO), pid 204, ts 28121=
288605
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 prep_new_page+0xfb/0x140
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 get_page_from_freelist+0x3503/0x5730
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 alloc_pages_vma+0xe2/0x560
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 __handle_mm_fault+0x930/0x26c0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 handle_mm_fault+0x1f9/0x810
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 do_user_addr_fault+0x6f7/0xca0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 exc_page_fault+0xaf/0x1a0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 asm_exc_page_fault+0x1e/0x30
> > > [=C2=A0=C2=A0 30.308890] page last free stack trace:
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 free_pcp_prepare+0x122/0x290
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 free_unref_page_list+0xe6/0x490
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 release_pages+0x2ed/0x1270
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 free_pages_and_swap_cache+0x245/0x2e0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_flush_mmu+0x11e/0x680
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_finish_mmu+0xa6/0x3e0
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 exit_mmap+0x2b3/0x540
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 mmput+0x11d/0x450
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 do_exit+0xaa6/0x2d40
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 do_group_exit+0x128/0x340
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 __x64_sys_exit_group+0x43/0x50
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 do_syscall_64+0x37/0x50
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0x=
a9
> > > [=C2=A0=C2=A0 30.308890]
> > > [=C2=A0=C2=A0 30.308890] Memory state around the buggy address:
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f00: ff ff ff ff ff ff ff=
 ff ff ff ff ff ff ff
> > > ff ff
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f80: ff ff ff ff ff ff ff=
 ff ff ff ff ff ff ff
> > > ff ff
> > > [=C2=A0=C2=A0 30.308890] >ffff8880be453000: ff ff ff ff ff ff ff ff f=
f ff ff ff ff ff
> > > ff ff
> > > [=C2=A0=C2=A0 30.308890]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453080: ff ff ff ff ff ff ff=
 ff ff ff ff ff ff ff
> > > ff ff
> > > [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453100: ff ff ff ff ff ff ff=
 ff ff ff ff ff ff ff
> > > ff ff
> > > [=C2=A0=C2=A0 30.308890]
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >=20
> > > George
> > >=20
>=20

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210225175004.GG1854360%40linux.ibm.com.
