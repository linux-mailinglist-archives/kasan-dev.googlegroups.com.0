Return-Path: <kasan-dev+bncBDE5LFWXQAIRBE4Y7CAQMGQETNWVOGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 722E5329896
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 10:57:40 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e16sf14144981ile.19
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 01:57:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614679059; cv=pass;
        d=google.com; s=arc-20160816;
        b=IumH4gd2ZJXmwG5C6cZ68Mq5jo3/Vv6pZca3rGRCNzxZg/jgBhIsMwZ7wK2J9DG9Sd
         YS2r3FHkbw1+efNuNFdbp4/QWtaAk2T3QntllqFcqX2yN74phfAw+buPK2sxUhRotwdW
         e4V4lrYWlhtiWTSpOa0NyQqth3cjaWEo5qVIDVhxWFMbdmvuoizvBZws8NgKVUmY9OdG
         DXT0niC3GLuRVlgqHO5mqI/q3reX8G2K397MQ2yzZ5qwe/u2rRxTuypHN0aGiVfFdNnK
         6j8k0r7elWsN5OF/kpDMEHm4BpZOdEgDMAt1ky4AIuvzNmd2GypjLxk0Mgg9U9hpffPB
         oP7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=AI4W9YK+Lbd1Ndrca+JMoFONi5uH5YyQeDVB9QIwUUg=;
        b=m46XuZPFOxnb5xX58dUTmmODVXx5PjhmvdJEVnNN9qjrHSDvt/pRtZ2IqaBnW1fMcu
         VbvzLWkL9GQ4yvjDT/yEPXks0pVDJoAQBfkFWksgEcKrDMWPGIzQ3N4ZCxb3Y2gnwd5A
         GPEwdPr+5RdUKYxAcKwdMdJRvTq3d/RnVmq1+ruBTwKUu57VlqSevtO9ikevo5nZOzxs
         MhD3d4Opo3roMGVeumpnenh2PCgFCH6M9ZOFtWrBva7DXiff9CzjpiB+sLzzaw3b7UW2
         9gQzwp4S7FXYsmeZAb6nlCGtiXkj5n6w3r/qzvG4H+GdHtILmWQVxoBI8X6A4a4X5Xm/
         ouNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Jn5lxbK+;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AI4W9YK+Lbd1Ndrca+JMoFONi5uH5YyQeDVB9QIwUUg=;
        b=JKSQWqIf2CptSdbGzjm1K635CSvIp6jd0zF4OK7JCFT8+37BBffhOu4MUdEB2jFT3X
         MIackOk5LkmMQhZfzR9ilgQnuVmGqua+GR+vGq5fRXF2pvP3I0trWEb79/IeVDxMqrK1
         wyJTIfeu+RDViSckUKQ5HOho/2bQnn99lI5blvvIZeq0FxpYNtWBUP/T00Gmg+w1Tl6t
         yC2kXH0h909wozkKnKLZS5WBzNHP3eKhnOR8bhIaYpwntHseF4b3ZsPxzvrrWC4xWGM0
         jyimO/A89dGY3YQDOdt08JetzZXhWpRtbbvv3YImdNRrRmaH7LOFWyM00lUV0ylhgT28
         DLng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AI4W9YK+Lbd1Ndrca+JMoFONi5uH5YyQeDVB9QIwUUg=;
        b=fBGkoCusDlacor2ASyxcKbaYTeATqYOeumbprJZDGwbA5NNuOnVdKuywklaNrGlXPv
         OMe5bLdNzBsChFH/SlAvme+/J6kiEchSNUlFmzAmi6Zhts8hsb2gIGrReot8o5d/Jk2W
         j0N1KpXvK5fksArtZToH4N/lmNrLLmyZtrlz/zYyV+74L6o8sNiza3kz8wftVDgJB3QE
         0OZCZpJzfB3+LazrjfrxcHTojLTMaiHeD/a9LetW0SxaFdgglfqyQ8FGwuzzZGqez7mP
         MGNw7DS0oALa3t6VajeJbpp65Gaz8TC/p3QKGatmTixcKk3rfMdr5UrPlQJyU4dhWcpu
         jOzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HhiHsfMwjMesyhcri/Ft6Yt2BHeLmT2FMa4bEpxYVCigpu7dy
	LC5KzWbiw8vqIVjKOPlf4y8=
X-Google-Smtp-Source: ABdhPJwnxkV0roef3JmdpWxuLzi0uNlcnsr4u7Sy2Rc5S4gNzsgdwTTDj7E56GrUbY5vIZIE0BBlZA==
X-Received: by 2002:a05:6638:614:: with SMTP id g20mr14129442jar.85.1614679059137;
        Tue, 02 Mar 2021 01:57:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3606:: with SMTP id d6ls4717326ila.3.gmail; Tue, 02 Mar
 2021 01:57:38 -0800 (PST)
X-Received: by 2002:a92:1e12:: with SMTP id e18mr17021781ile.270.1614679058791;
        Tue, 02 Mar 2021 01:57:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614679058; cv=none;
        d=google.com; s=arc-20160816;
        b=auDtjz9QJVnU9qIXHX9IHth7c3tFs+GTI0vZ8I3txH504Fk/Dz0nLR5zhnJFA/BFAr
         Yh6VYhI56I/LcyPHi4TVHJViMiLfSicgN2yUEEeM6oPDC+1NGIimy9uhtzhOW56UAr6O
         d9ksJ0FJ1BmnLW6Vywzv8IPCMaAyk9I6jf84S8Ca6IDgMCPqtcvqeD13KOcjk4hgGXYf
         TtZsnYyj4zzzZtDoQpvj4s7SxWelar0Y5PqSVJ2fE5xzXylucU2dJDYVysic/0Kuxfay
         kjpnM7zdzWAs4nXSwe7oGfneZg1FuNcBWu04ut6Yv2XeM70yUoEEjf4+oLNqN+ZZlwPV
         /LUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yKyKNplrnfGIMREBrT/v98LCI1geLYbB+er4Q6fkd9Q=;
        b=GIDHxhKi3JGPeueiYNSLa9E36jpd/v/Sfccxf5U3lSjRhy58PZfiG6kGienqs8I3ve
         2e6jUig2MsHOJiqn2zSp6xywCRQ94yaky1ULaF23Lm6uv701WRra66Wc7Ob9mw/R5FLx
         qOmpimecbcm68GBPHPHDdj4Ffjs2bL3uEzo4ncBU1N6PUcpDEdU20HgzbszPt/sTcCdn
         SofQLSW6SooJjfQqJKEfDOTC0I8BVpmqpz1vWb/MiUlH3lXYy5fbZyLpHc2saWZB7LZD
         sHCS/UQpzcXYQRYWyxSa7ilnE5e8FNdt5GuZ/4akKNWIuGNgOxPkWbtGtfjqOTzUfpsC
         nU4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Jn5lxbK+;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id c2si968973ilj.4.2021.03.02.01.57.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Mar 2021 01:57:38 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098417.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 1229aYR1184438;
	Tue, 2 Mar 2021 04:57:18 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 371gvtn1hy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Mar 2021 04:57:18 -0500
Received: from m0098417.ppops.net (m0098417.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 1229aqv3185978;
	Tue, 2 Mar 2021 04:57:17 -0500
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0a-001b2d01.pphosted.com with ESMTP id 371gvtn1gq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Mar 2021 04:57:17 -0500
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 1229vECn024285;
	Tue, 2 Mar 2021 09:57:15 GMT
Received: from b06cxnps4075.portsmouth.uk.ibm.com (d06relay12.portsmouth.uk.ibm.com [9.149.109.197])
	by ppma04ams.nl.ibm.com with ESMTP id 3712fmgpx4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Mar 2021 09:57:15 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps4075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 1229vDsg54526246
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Mar 2021 09:57:13 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3E643AE053;
	Tue,  2 Mar 2021 09:57:13 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 88387AE04D;
	Tue,  2 Mar 2021 09:57:10 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.23.212])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Mar 2021 09:57:10 +0000 (GMT)
Date: Tue, 2 Mar 2021 11:57:08 +0200
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
        Dhaval Giani <dhaval.giani@oracle.com>, robert.moore@intel.com,
        erik.kaneda@intel.com, rafael.j.wysocki@intel.com, lenb@kernel.org,
        linux-acpi@vger.kernel.org
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <YD4L9DCpsFWhjSlJ@linux.ibm.com>
References: <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
 <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
 <20210226111730.GL1854360@linux.ibm.com>
 <e9e2f1a3-80f2-1b3e-6ffd-8004fe41c485@oracle.com>
 <YDvcH7IY8hV4u2Zh@linux.ibm.com>
 <083c2bfd-12dd-f3c3-5004-fb1e3fb6493c@oracle.com>
 <a8864397-83e8-61f7-4b9a-33716eca6cf8@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a8864397-83e8-61f7-4b9a-33716eca6cf8@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-03-02_03:2021-03-01,2021-03-02 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0
 priorityscore=1501 clxscore=1011 lowpriorityscore=0 impostorscore=0
 bulkscore=0 mlxscore=0 suspectscore=0 mlxlogscore=999 spamscore=0
 phishscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2009150000 definitions=main-2103020078
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Jn5lxbK+;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender)
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

Hi George,

On Mon, Mar 01, 2021 at 08:20:45PM -0500, George Kennedy wrote:
> > > > >=20
> > > > There should be no harm in doing the memblock_reserve() for all
> > > > the standard
> > > > tables, right?
> > > It should be ok to memblock_reserve() all the tables very early as
> > > long as
> > > we don't run out of static entries in memblock.reserved.
> > >=20
> > > We just need to make sure the tables are reserved before memblock
> > > allocations are possible, so we'd still need to move
> > > acpi_table_init() in
> > > x86::setup_arch() before e820__memblock_setup().
> > > Not sure how early ACPI is initialized on arm64.
> >=20
> > Thanks Mike. Will try to move the memblock_reserves() before
> > e820__memblock_setup().
>=20
> Hi Mike,
>=20
> Moved acpi_table_init() in x86::setup_arch() before e820__memblock_setup(=
)
> as you suggested.
>=20
> Ran 10 boots with the following without error.

I'd suggest to send it as a formal patch to see what x86 and ACPI folks
have to say about this.
=20
> diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> index 740f3bdb..3b1dd24 100644
> --- a/arch/x86/kernel/setup.c
> +++ b/arch/x86/kernel/setup.c
> @@ -1047,6 +1047,7 @@ void __init setup_arch(char **cmdline_p)
> =C2=A0=C2=A0=C2=A0=C2=A0 cleanup_highmap();
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 memblock_set_current_limit(ISA_END_ADDRESS);
> +=C2=A0=C2=A0=C2=A0 acpi_boot_table_init();
> =C2=A0=C2=A0=C2=A0=C2=A0 e820__memblock_setup();
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 /*
> @@ -1140,8 +1141,6 @@ void __init setup_arch(char **cmdline_p)
> =C2=A0=C2=A0=C2=A0=C2=A0 /*
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0* Parse the ACPI tables for possible boot-=
time SMP configuration.
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0*/
> -=C2=A0=C2=A0=C2=A0 acpi_boot_table_init();
> -
> =C2=A0=C2=A0=C2=A0=C2=A0 early_acpi_boot_init();
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 initmem_init();
> diff --git a/drivers/acpi/acpica/tbinstal.c b/drivers/acpi/acpica/tbinsta=
l.c
> index 0bb15ad..7830109 100644
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
> @@ -16,6 +17,33 @@
>=20
> =C2=A0/******************************************************************=
*************
> =C2=A0 *
> + * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_reserve_standard_table
> + *
> + * PARAMETERS:=C2=A0 address=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 - Table physical address
> + *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 header=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 - Table header
> + *
> + * RETURN:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 None
> + *
> + * DESCRIPTION: To avoid an acpi table page from being "stolen" by the
> buddy
> + *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 allocator run memblock_reserve() on all the standard acpi
> tables.
> + *
> + ***********************************************************************=
*******/
> +void
> +acpi_tb_reserve_standard_table(acpi_physical_address address,
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 st=
ruct acpi_table_header *header)
> +{
> +=C2=A0=C2=A0=C2=A0 if ((ACPI_COMPARE_NAMESEG(header->signature, ACPI_SIG=
_FACS)) ||
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 (ACPI_VALIDATE_RSDP_SIG(header->si=
gnature)))
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
> +

Why these should be excluded?

> +=C2=A0=C2=A0=C2=A0 if (header->length > PAGE_SIZE) /* same check as in a=
cpi_map() */
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;

I don't think this is required, I believe acpi_map() has this check because
kmap() cannot handle multiple pages.

> +
> +=C2=A0=C2=A0=C2=A0 memblock_reserve(address, PAGE_ALIGN(header->length))=
;
> +}
> +
> +/***********************************************************************=
********
> + *
> =C2=A0 * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_install_table_with_override
> =C2=A0 *
> =C2=A0 * PARAMETERS:=C2=A0 new_table_desc=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 - New table descriptor to install
> @@ -58,6 +86,9 @@
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
kasan-dev/YD4L9DCpsFWhjSlJ%40linux.ibm.com.
