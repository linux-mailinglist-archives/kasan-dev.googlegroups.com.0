Return-Path: <kasan-dev+bncBDE5LFWXQAIRBOFY56AQMGQESIM72EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7817A3273BE
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Feb 2021 19:08:57 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id m3sf11565793ioy.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Feb 2021 10:08:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614535736; cv=pass;
        d=google.com; s=arc-20160816;
        b=M5CxUuStnVzllGfTkwb/XYmN13sevrPOZtUkMfwILsHdwgZVG88wCDrXHGs0crbbs4
         u8LHxcP+5scOozhPKGzPeCnAeuT0VpbLI6lq1tZO8ng0INqclcQIozAgoUEIrpswfZIE
         9C/P4s8nfFvoC/QyR1NLOrdkPUQCBknEA+wpbK2OXnxN6UDQV6WAB0hdX3C6pnMjlaAK
         HmC03Z8p/oZ8VWxt58NIWb/sOPeSBKQCmo2nT8zhWafjV57paqZAi3Sn7mUkoAAK4n2L
         KPGV8+FIRvrh4Jnox6AITQsGRSdzm7fBTj+9yuS7HA4UjRxG2QzkzX4nx/o2rVYCCUiU
         kIbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Hq6b5r4NzoNOQY5rFAAnaTNWBPaZAi2YcG5X9ZUeTE4=;
        b=WzG5+eqjhSMWNx0bymLn0QGwzD70X5V3Yn6kay+ruzlILw5pbygKlSiAHbbAUVgQUR
         RZJGSlNXKN8JuwN1KFrpGsqSpKB8xU3SxWxQgbrk6s/h/lc2S5vV5jT4IIuxDADSII+J
         1JkHvRTqDTx7XVWXrD9PWOGQgtd9lEFgoWdUoPip5QhyKpDFGRv3M8JxL6gxwxZpqAsQ
         XbXBRw+dpW7WQTocuDUbqdI1n29+lX/tTEBRS6sv290D2AP4EoLcNwecivwFeoV9ulwo
         UkoYq4t1nBSHvq9sFXTQygfOsel2RgNTYSURqnKMwUyoCVFZctl4A7Cn12Y2pTp5L1He
         T84A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YE21XdX4;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hq6b5r4NzoNOQY5rFAAnaTNWBPaZAi2YcG5X9ZUeTE4=;
        b=FLzxpwNnAmHMiS8W5jx3x1rpArZCqsMHJL3Bk3WMDQTtRyaiEA2sgF2Izpj1flcanv
         idKHiubJVw3L+KShXwUsFhOvP3roxmCZLiX6wBJB+iBOFUR6zOke9ZfvsEW1ZVawA5Wa
         qOKZKxFHbTMkcvmpk1M6EoVCIRXhqqazMwQyLLS/CnXO4gNmmVkNFzeUqaPsS0wnRjTh
         DFUx+6i0Ny4GaX5BxAgBSOHRLQASqzxesA4rLie5VB0TcxCt9WBCC63ooQLbXBoHzzcM
         5B2NTLDVpuW4PcxK6Uaeb7k53zevkKoe8OLNN0tbMYPPXw2NkfOipBMgCB2+OgzhyeSl
         4cZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hq6b5r4NzoNOQY5rFAAnaTNWBPaZAi2YcG5X9ZUeTE4=;
        b=A/ZLl+VVjIzwEBDATcMBMBymihh2G8ualP0JlE4Xzu4cihiSzBOlTkc8oyujKsB4fZ
         9O0pOPyTr6ShkxUAhDaRBSbWU2l7nCwsU1evj2NxzWUVgmSnHqNKly2mf895+S3nHBAP
         qXS/j4KpQvCQzklwQcOe5YSki0+bL2Jw+BErs4S4VKv/gK7ieuECankiAsRtgJpfahhN
         MkFkAAhyWeV+WiZdO4veDME9+wj8VgcFWEYGgHIckuZgSYfYBogFhx9bydw65dRiwqCt
         TYITD+XrznKQu/s4RcGB4wExOWYounXeHuXYZ6UOSd4hqXY0R0ISoQ+eZc6oHk4omdda
         403A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311rVxuXeCESbSGOtadmKSsHfwM7MXn1VN1zvE270sHNZnUL4b+
	7erM4jTxkn5VLVLAEHLk0Ww=
X-Google-Smtp-Source: ABdhPJzYGIm34buHmYN4nSYyH+Wqgh28EPMxQHhfatFeL6SPSnwTMJ8Q7fnqNEmpVIZ5+YABjb3hAw==
X-Received: by 2002:a92:290e:: with SMTP id l14mr10232683ilg.36.1614535736247;
        Sun, 28 Feb 2021 10:08:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9691:: with SMTP id m17ls2414077ion.2.gmail; Sun, 28 Feb
 2021 10:08:55 -0800 (PST)
X-Received: by 2002:a6b:5809:: with SMTP id m9mr10336235iob.3.1614535735855;
        Sun, 28 Feb 2021 10:08:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614535735; cv=none;
        d=google.com; s=arc-20160816;
        b=aCGk6rg6lQdx4HjS5FQ1ktsRzge9Hm3zlOjwnfQXo93grgS7Nt1e+8l1QE7p6cA6Hh
         5w8e+/MHcgDR5TxfA5YUs3Fa5RTkaFJDm4trChM+tx0w0zKNk0y6S+pLDHxp5JuDspTa
         pcif4mNQWzE8w59+7WZQFwuHOz1WB2O939kfjUACb4FrX5XN9L17p9kStgsaD8ZYz/fi
         LDhnu0ihM3e0awaCIyEU46qbu9JNNKyKHPUl+3+kvGaGehaNmV5P1A35GyHArth3Hcvq
         HpZgOT4Z/8GpliTjLY2DF8XVgay4AxjIcmAZKY4GSQWSdMqMEu3XYUt+GkV0jPxUDSgl
         BcPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=4bb935c/UZyEQhCai159ASVF1c2deNbr/2p5TWhmbJc=;
        b=OJ9PMgNby57CBWQV8FJv67ESYx/tPx7WYCtKX3Xe4ybdrCT6R34OVqiQ/3peSX4BwL
         dSBAV+0ruE1XMfdLziT6lH+CkVL6ec1Lco835HylGcIXucmR6DZE2cMep5XQlR5ECXJh
         7ogsGS/yfDInXJel0aduWO70q5tldXn+jy5nFDJ7gpjqH8HqVXE619itkHFkqBlNt96W
         F4ZKYOTUXFZc5GxzpQLSE+dpOdK5Rg/TkRhH4IIgR/ibrVSVj2nqM124+vVFbTKU+Yg1
         E9KuDV0DfR0HUItL3bpOuy7jntClcW8gBThS5A4fI/b42TvXU03F/y4JTmVZd9PgY5fZ
         5/Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YE21XdX4;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id g10si1156854ioo.0.2021.02.28.10.08.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 28 Feb 2021 10:08:55 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11SI4TRM141005;
	Sun, 28 Feb 2021 13:08:41 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 370410w9v2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Sun, 28 Feb 2021 13:08:41 -0500
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11SI4iI1141354;
	Sun, 28 Feb 2021 13:08:40 -0500
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 370410w9u7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Sun, 28 Feb 2021 13:08:40 -0500
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11SI2b3G020519;
	Sun, 28 Feb 2021 18:08:38 GMT
Received: from b06cxnps3074.portsmouth.uk.ibm.com (d06relay09.portsmouth.uk.ibm.com [9.149.109.194])
	by ppma03ams.nl.ibm.com with ESMTP id 36ydq893ed-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Sun, 28 Feb 2021 18:08:37 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps3074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11SI8Zsh31588766
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 28 Feb 2021 18:08:35 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C302BAE045;
	Sun, 28 Feb 2021 18:08:35 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7A0D7AE051;
	Sun, 28 Feb 2021 18:08:33 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.18.192])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Sun, 28 Feb 2021 18:08:33 +0000 (GMT)
Date: Sun, 28 Feb 2021 20:08:31 +0200
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
Message-ID: <YDvcH7IY8hV4u2Zh@linux.ibm.com>
References: <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
 <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
 <20210226111730.GL1854360@linux.ibm.com>
 <e9e2f1a3-80f2-1b3e-6ffd-8004fe41c485@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <e9e2f1a3-80f2-1b3e-6ffd-8004fe41c485@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-28_07:2021-02-26,2021-02-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 phishscore=0
 adultscore=0 priorityscore=1501 spamscore=0 impostorscore=0 mlxscore=0
 malwarescore=0 mlxlogscore=999 suspectscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102280156
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YE21XdX4;       spf=pass (google.com:
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

On Fri, Feb 26, 2021 at 11:16:06AM -0500, George Kennedy wrote:
> On 2/26/2021 6:17 AM, Mike Rapoport wrote:
> > Hi George,
> >=20
> > On Thu, Feb 25, 2021 at 08:19:18PM -0500, George Kennedy wrote:
> > >=20
> > > Not sure if it's the right thing to do, but added
> > > "acpi_tb_find_table_address()" to return the physical address of a ta=
ble to
> > > use with memblock_reserve().
> > >=20
> > > virt_to_phys(table) does not seem to return the physical address for =
the
> > > iBFT table (it would be nice if struct acpi_table_header also had a
> > > "address" element for the physical address of the table).
> >
> > virt_to_phys() does not work that early because then it is mapped with
> > early_memremap()  which uses different virtual to physical scheme.
> >=20
> > I'd say that acpi_tb_find_table_address() makes sense if we'd like to
> > reserve ACPI tables outside of drivers/acpi.
> >=20
> > But probably we should simply reserve all the tables during
> > acpi_table_init() so that any table that firmware put in the normal mem=
ory
> > will be surely reserved.
> > > Ran 10 successful boots with the above without failure.
> > That's good news indeed :)
>=20
> Wondering if we could do something like this instead (trying to keep chan=
ges
> minimal). Just do the memblock_reserve() for all the standard tables.

I think something like this should work, but I'm not an ACPI expert to say
if this the best way to reserve the tables.
=20
> diff --git a/drivers/acpi/acpica/tbinstal.c b/drivers/acpi/acpica/tbinsta=
l.c
> index 0bb15ad..830f82c 100644
> --- a/drivers/acpi/acpica/tbinstal.c
> +++ b/drivers/acpi/acpica/tbinstal.c
> @@ -7,6 +7,7 @@
> =C2=A0 *
> *************************************************************************=
****/
>=20
> +#include <linux/memblock.h>
> =C2=A0#include <acpi/acpi.h>
> =C2=A0#include "accommon.h"
> =C2=A0#include "actables.h"
> @@ -14,6 +15,23 @@
> =C2=A0#define _COMPONENT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 ACPI_TABLES
> =C2=A0ACPI_MODULE_NAME("tbinstal")
>=20
> +void
> +acpi_tb_reserve_standard_table(acpi_physical_address address,
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 st=
ruct acpi_table_header *header)
> +{
> +=C2=A0=C2=A0=C2=A0 struct acpi_table_header local_header;
> +
> +=C2=A0=C2=A0=C2=A0 if ((ACPI_COMPARE_NAMESEG(header->signature, ACPI_SIG=
_FACS)) ||
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 (ACPI_VALIDATE_RSDP_SIG(header->si=
gnature))) {
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
> +=C2=A0=C2=A0=C2=A0 }
> +=C2=A0=C2=A0=C2=A0 /* Standard ACPI table with full common header */
> +
> +=C2=A0=C2=A0=C2=A0 memcpy(&local_header, header, sizeof(struct acpi_tabl=
e_header));
> +
> +=C2=A0=C2=A0=C2=A0 memblock_reserve(address, PAGE_ALIGN(local_header.len=
gth));
> +}
> +
> =C2=A0/******************************************************************=
*************
> =C2=A0 *
> =C2=A0 * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_install_table_with_override
> @@ -58,6 +76,9 @@
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->flags,
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->pointer);
>=20
> +=C2=A0=C2=A0=C2=A0 acpi_tb_reserve_standard_table(new_table_desc->addres=
s,
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0 new_table_desc->pointer);
> +
> =C2=A0=C2=A0=C2=A0=C2=A0 acpi_tb_print_table_header(new_table_desc->addre=
ss,
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);
>=20
> There should be no harm in doing the memblock_reserve() for all the stand=
ard
> tables, right?

It should be ok to memblock_reserve() all the tables very early as long as
we don't run out of static entries in memblock.reserved.

We just need to make sure the tables are reserved before memblock
allocations are possible, so we'd still need to move acpi_table_init() in
x86::setup_arch() before e820__memblock_setup().
Not sure how early ACPI is initialized on arm64.
=20
> Ran 10 boots with the above without failure.
>=20
> George

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YDvcH7IY8hV4u2Zh%40linux.ibm.com.
