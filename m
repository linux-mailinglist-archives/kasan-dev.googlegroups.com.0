Return-Path: <kasan-dev+bncBDE5LFWXQAIRBC5U2OAQMGQEOALNAEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 27E0D3228E6
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 11:33:49 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id o8sf9817361pls.7
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 02:33:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614076428; cv=pass;
        d=google.com; s=arc-20160816;
        b=X1upORyY2ySOTHEu5Vf1lTUuZKT6aHPBi66e3ptlE3sQuLAfi4Nv+li/wF/+/DOPaA
         6VS/3owd2fzzGkUGZvFjv9gqByLKAHHK4OuzyYFFd30diMbwEkNHRuPZk6+sLKab9noA
         90XZYZyC6UKSjZ6fKoOFoZuGD6NTuwRlY4UjHdUnqPpmwYW8VDvGF8XG2Y9M4QY1abhV
         oGWVabt3xuMpdGaaQFkvt00pUu6HVtd36fX39GBFO+mM5IZI2F3NynL6XLD9gL+pWWKc
         41+KNIY64ghu1qV7Fw9w5yu9JrlA/9g2ZN906zVnxZIDbqOIU/197/oD3KU+75IZtAQo
         VNjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UgR0cg2HM0awUjGl9vXuXqHAt5bwR/24A6/J/uSu8Sw=;
        b=rRHYzoYBxBDS1xDdjvOobjcPijGA81Osp/MoMJ/jIiaakx5pw5Zq0rzXoq/h8lxCHU
         BD2zxZZuk1wdJiunkVbZ+D89mFjRDdPIZIIOefBqabxi00emZTtwUZN75YR0tMdlS80/
         FWkAVox749oZNelAOWQZYVWpTTXNEBIg9WVMjekv1dScwM1soWrNRFAL/416iRbGRkMw
         dS4sc7BkaN3lwQclTApAFPntnIRXlHjVJknyAdTrWQyte2+nxlFTP26kQYQwzay9WIiU
         N3sw1Ovaqgp9ekgWoPyWVomFDHoOB7HuCXUoHCVDV1owXSqF1ByERsitmDSe5yRMR4St
         kMAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Lc491rjl;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgR0cg2HM0awUjGl9vXuXqHAt5bwR/24A6/J/uSu8Sw=;
        b=n9Yet2RLv6dfIIxwm4x2htIPZ7lA1YBZe0Zqzdgtb1qmVr4zhAKCmCh2h3arccbEKo
         jBLf1j9rAkpnUeineSPomu1EbmSB5GHqD/QmEJCMBWKVnToxUIp/4iny6T3/qNMpa+d7
         0sBTF7yj+HP4poO0JD+q7ErCANGUiaLRwgdUQblkf4WVTaXQZ8fmJT/cVRMU6fYDYxV4
         Ah8KWD6kvEiEL7TQqkGizuN9ukGHBlk5uZ9WvtZN3qCJN9jq22h98K0tvG51rlQkW9pK
         wLinAvPXoRVdt6E2HTyqPc9xW222RZFcQ36Fj2ynKQc49lSrl3E1JLHWLNjcXT4sZ6up
         aEdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgR0cg2HM0awUjGl9vXuXqHAt5bwR/24A6/J/uSu8Sw=;
        b=FYBKNoIyKYSyJS/H3VQaD1PLXFzyQ8LhlNN/T4x6iB9y59jKhnZeEf8CYAi/j0lqzd
         +K/rs4DNePaZiea8MCzqUhC72jBL3FuI8BLlV7FTIcRBPsxhb/mpc8UsQtyPhNzzmiZi
         aeVsTOW6fipOt2Gpw9RNKj2ZR3CuPrSixp4uiBek5y/3595CqEMfn066uhGlueRH5nPk
         qz3EgXv/E9aRIEOswQuhcCAXQQnKm02NcYs36hgoobruKtxeWSQuvUyAgehQPoGE+SiC
         0qBrZ5nj8MZBs8Frwk7xcl+Q6w+GoO25oGjRWJVFHn+cTelzsmXQvjmc6q8CwaCNwXQ+
         7Tzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530c52UmFcr2USMVNvhl2UZqrkUMzToncIvDZZXNvkCk1iQvapx7
	X08t6kykTbzkUT6Z+UNp5gk=
X-Google-Smtp-Source: ABdhPJypENcDRtP9mlyRMPIs/6W/4XdKn9Zd+J8UtSVwXKbMBLp6cv+Wfxgk0owOSYcxN86mHlOX9Q==
X-Received: by 2002:a17:902:be06:b029:e3:7031:bef with SMTP id r6-20020a170902be06b02900e370310befmr26246099pls.19.1614076427888;
        Tue, 23 Feb 2021 02:33:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8a52:: with SMTP id n18ls1731999pfa.9.gmail; Tue, 23 Feb
 2021 02:33:47 -0800 (PST)
X-Received: by 2002:a63:4084:: with SMTP id n126mr23565545pga.80.1614076427226;
        Tue, 23 Feb 2021 02:33:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614076427; cv=none;
        d=google.com; s=arc-20160816;
        b=x4Sv+YFDVKDdAb2DCEfUWg6iELIJe0qeEZ88K8QSy/ZgH2fbwiG1GbQjCzD1B35rTA
         mMJBsu2s/w9pgXhjCVY01vQ/g9vwT7MEHDS6eSEl7P4B5NvXMnUGvrggS36YlCOWWho8
         TxpvXVT4Fnae3rnFPeN808e8ftM4smcH/PznaXIglwgG1LQqZnNHBYg5gPYIirL6/99I
         y1dvDMurbKFSDDHzCAzFQXuqeWDmUsXb7N20c2KXyqR4NKiIYJPgrmDFRRHmr5gHPwcu
         9UJt+7JA/6smGag1UtyJkiP0bD5YfN3K6W0xThlxofmclYwK9PR5ohmFuoKY4IdBrDvb
         NUqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=O4eU9dLNgm0ga1w/UcGK2aRgCdfR9UK3xwlc97+j95Q=;
        b=c/2mDRUvKxyh8rBBB04o9TG3fBPy2vkuFyodJGC0QVxZl2iuaz4YSx3cKn2uieTT62
         jAb853TlNgeAAGNushJtU+Dko5a0rUxeTBeXQvj2QCeDNetv0oJDX4j88FeY94NrdaAl
         bV5f8/40S3v+M/z4XkhVkg4zXC5i7MsFeVaEo+hRjNzb7STtdVVGxBMY2ZCCJu376EcK
         MDw3FVTfsX88FIfz1OqKnPGAg75l025ejXGyMg/6VpoynLzHw5GQuZG9DqJC5R1hRXkT
         FZFJZpRDSE4MKwOQ0/SMwtoKxxeItMIxo2TbF8lFoOVndBB8beGWBBEkHs55Y/HddPQ3
         4rWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Lc491rjl;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id n9si123845pjp.2.2021.02.23.02.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 02:33:47 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098410.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11NA4mkm021603;
	Tue, 23 Feb 2021 05:33:32 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkg2uxu0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 05:33:32 -0500
Received: from m0098410.ppops.net (m0098410.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11NA4lmC021561;
	Tue, 23 Feb 2021 05:33:31 -0500
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkg2uxt0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 05:33:31 -0500
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11NASo0e018736;
	Tue, 23 Feb 2021 10:33:28 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma03ams.nl.ibm.com with ESMTP id 36tt282ge0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 10:33:28 +0000
Received: from d06av23.portsmouth.uk.ibm.com (d06av23.portsmouth.uk.ibm.com [9.149.105.59])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11NAXDkb34931070
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 10:33:13 GMT
Received: from d06av23.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 419C3A4053;
	Tue, 23 Feb 2021 10:33:26 +0000 (GMT)
Received: from d06av23.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id ED331A4051;
	Tue, 23 Feb 2021 10:33:23 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av23.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 23 Feb 2021 10:33:23 +0000 (GMT)
Date: Tue, 23 Feb 2021 12:33:21 +0200
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
Message-ID: <20210223103321.GD1741768@linux.ibm.com>
References: <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
 <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-23_05:2021-02-22,2021-02-23 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 adultscore=0 priorityscore=1501 malwarescore=0
 mlxlogscore=999 mlxscore=0 impostorscore=0 bulkscore=0 spamscore=0
 phishscore=0 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2009150000 definitions=main-2102230084
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Lc491rjl;       spf=pass (google.com:
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

(re-added CC)

On Mon, Feb 22, 2021 at 08:24:59PM -0500, George Kennedy wrote:
>=20
> On 2/22/2021 4:55 PM, Mike Rapoport wrote:
> > On Mon, Feb 22, 2021 at 01:42:56PM -0500, George Kennedy wrote:
> > > On 2/22/2021 11:13 AM, David Hildenbrand wrote:
> > > > On 22.02.21 16:13, George Kennedy wrote:
> > > >=20
> > > > The PFN 0xbe453 looks a little strange, though. Do we expect ACPI t=
ables
> > > > close to 3 GiB ? No idea. Could it be that you are trying to map a =
wrong
> > > > table? Just a guess.
> > > >=20
> > > > > What would be=C2=A0 the correct way to reserve the page so that t=
he above
> > > > > would not be hit?
> > > > I would have assumed that if this is a binary blob, that someone (w=
hich
> > > > I think would be acpi code) reserved via memblock_reserve() early d=
uring
> > > > boot.
> > > >=20
> > > > E.g., see drivers/acpi/tables.c:acpi_table_upgrade()->memblock_rese=
rve().
> > > acpi_table_upgrade() gets called, but bails out before memblock_reser=
ve() is
> > > called. Thus, it appears no pages are getting reserved.
> > acpi_table_upgrade() does not actually reserve memory but rather open
> > codes memblock allocation with memblock_find_in_range() +
> > memblock_reserve(), so it does not seem related anyway.
> >=20
> > Do you have by chance a full boot log handy?
>=20
> Hello Mike,
>=20
> Are you after the console output? See attached.
>=20
> It includes my patch to set PG_Reserved along with the dump_page() debug
> that David asked for - see: "page:"

So, iBFT is indeed at pfn 0xbe453:

[    0.077698] ACPI: iBFT 0x00000000BE453000 000800 (v01 BOCHS  BXPCFACP 00=
000000      00000000)
=20
and it's in E820_TYPE_RAM region rather than in ACPI data:

[    0.000000] BIOS-e820: [mem 0x0000000000810000-0x00000000008fffff] ACPI =
NVS
[    0.000000] BIOS-e820: [mem 0x0000000000900000-0x00000000be49afff] usabl=
e
[    0.000000] BIOS-e820: [mem 0x00000000be49b000-0x00000000be49bfff] ACPI =
data

I could not find anywhere in x86 setup or in ACPI tables parsing the code
that reserves this memory or any other ACPI data for that matter. It could
be that I've missed some copying of the data to statically allocated
initial_tables, but AFAICS any ACPI data that was not marked as such in
e820 tables by BIOS resides in memory that is considered as free.

Can you please check if this hack (entirely untested) changes anything:

diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boot.c
index 7bdc0239a943..c118dd54a747 100644
--- a/arch/x86/kernel/acpi/boot.c
+++ b/arch/x86/kernel/acpi/boot.c
@@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
 	if (acpi_disabled)
 		return;
=20
+#if 0
 	/*
 	 * Initialize the ACPI boot-time table parser.
 	 */
@@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
 		disable_acpi();
 		return;
 	}
+#endif
=20
 	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);
=20
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index d883176ef2ce..c8a07a7b9577 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1032,6 +1032,14 @@ void __init setup_arch(char **cmdline_p)
 	 */
 	find_smp_config();
=20
+	/*
+	 * Initialize the ACPI boot-time table parser.
+	 */
+	if (acpi_table_init()) {
+		disable_acpi();
+		return;
+	}
+
 	reserve_ibft_region();
=20
 	early_alloc_pgt_buf();
diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscsi_ib=
ft_find.c
index 64bb94523281..2e5e04090fe2 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -80,6 +80,21 @@ static int __init find_ibft_in_mem(void)
 done:
 	return len;
 }
+
+static void __init acpi_find_ibft_region(void)
+{
+	int i;
+	struct acpi_table_header *table =3D NULL;
+
+	if (acpi_disabled)
+		return;
+
+	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
+		acpi_get_table(ibft_signs[i].sign, 0, &table);
+		ibft_addr =3D (struct acpi_table_ibft *)table;
+	}
+}
+
 /*
  * Routine used to find the iSCSI Boot Format Table. The logical
  * kernel address is set in the ibft_addr global variable.
@@ -93,6 +108,8 @@ unsigned long __init find_ibft_region(unsigned long *siz=
ep)
=20
 	if (!efi_enabled(EFI_BOOT))
 		find_ibft_in_mem();
+	else
+		acpi_find_ibft_region();
=20
 	if (ibft_addr) {
 		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);

> Thank you,
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
kasan-dev/20210223103321.GD1741768%40linux.ibm.com.
