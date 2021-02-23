Return-Path: <kasan-dev+bncBDE5LFWXQAIRBSWH2SAQMGQEJWYHOTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EA1C322DE5
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 16:48:27 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id n68sf11120918qke.10
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 07:48:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614095306; cv=pass;
        d=google.com; s=arc-20160816;
        b=jD2KHuxZGzleEeoesXC0aWNonyViw3IWHZRBMr56zKVMuGiulahWVqnEz6SBJjwtnV
         42bzNcAzXLtjMBE8yv74IR29BnVK/vM5W2cFQrM+MqHri3FXx7c4GwSgTa6hD19W5+lz
         nIZYlxR663GHsyXLIolslgZIEARuZGdQh1SXPg54+2XmDukKQKkbjyEvrnDP2bE0ZPuF
         Ma/5feqef/HsAsMaK8HgLBWlmgF0FeqyoR2164Q3Sa0TBboAdtxUpwWQ6zDEME4Trzo1
         N7THV3bdXes0Ekjv49lsLYwg8jcqHLbPkjMv/LxCIgrEQP04tHUOxmHd7FA79h/cgrvh
         kEFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Nbj/ZltQR2HsI3pXMZkr1lDElCEWqA1m7rJLQFeWlEw=;
        b=wHFtp1dXIMI7PgH1oSSR/wGzddDIFVt8eCBI2DAPjLcSaGQsGyg24h7jg1bKLVYedn
         Y44yYfmWwT/e+aR75EOsn3KYrTzroNDOyLqJAu8PEClf6j/+tBAxj7X2Uym2bX8e8NrW
         36i4lTF7mjGzlDwOiQ3L+8ywa9XffWPviu2Og4g3Ym7ENE+Z2mXLj+K5B2MgwEr9dKAj
         FzXJPPrrzTF3j1T0JypRN3sC1NZBKQ1bzA+oxmcAVd20Ti/9MFmBwmG0vnBbAiKb8Nlc
         kFntToVZMtFtYG2M8+9aSziQFpmht7mq80ETAowjU02NyCyxTFkglO98iYYqk/gYxfyM
         6CwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gVd6dsjS;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nbj/ZltQR2HsI3pXMZkr1lDElCEWqA1m7rJLQFeWlEw=;
        b=Xt7oW4yzAt6uA4gL2TDIjV1IQ9NZym7cbInDkc0lpduwdLIo0tY13WtAZmjJWGHTW4
         jdAkfbeqEQ4oWW4hLZlZ1bMRSci79+Ac/PjpDW9QcNLtPQYUDF8TjLiEYoUmGn/ZcNjZ
         2q7dtpTnNPvXyNiFsT78nm/LIst2o3TUnbxur7E00GDiUPc4fM9jEV9S/TYQh43I3sRN
         jsRggk/5kKCj89UT73lEs3rcpSCcgoET6F3vVtXrUj+Mnb1+WpQzKPo+62q9JOcaWHl5
         iUlEvykO84KmphqP/1nJ+VhLm0iBwGY1vSZ+zXE1UV6EtUSiIvuic1CHIoGUcTQp2VCW
         dpRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nbj/ZltQR2HsI3pXMZkr1lDElCEWqA1m7rJLQFeWlEw=;
        b=ZkQa0NYdtkDRL2vKIzKrMGqfR/F3a+zRaKl8ObKsYp9e8pY6/HSUFLmpBnGIo2q1wS
         lCnmrTN55JW6pSFEk2R565n9CofOmp+w555kEuid62SMABXIdCZYDbMfOp7LvJwSMdoB
         ABbDD3HlObUgXjpJjwEJFanbhLjmg/rludhJGKCOVxxjCkFzhOgZerGFyIGSBkN58M8w
         ewAmX4Yje2y98R/FSUid82UR4KiisERbXHX0w6ZIOb7cE2i8cc2qoDz8KNVkkhNorQ5K
         yCIT8RVB98UNVFJPvkVrSn7mkA9rSr1b+sQ0IRa0jS3Mleh6OdqbfqWC+7d6tSLIr9/3
         DXRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329XwJ86QLLFvdPimEjJ5i7nTMCcm5/nWt1OsY7Y/PFCK2osRdd
	UzyrNGT301YBiKy+Or1V5Uc=
X-Google-Smtp-Source: ABdhPJxJvu6dcNLXG5jPhUjkQb4KCNOdVByaPtIU1lQSnTm//KcOforqVQ2pvmqMWbB5Mc65Vl8itw==
X-Received: by 2002:ac8:7186:: with SMTP id w6mr6039910qto.255.1614095306125;
        Tue, 23 Feb 2021 07:48:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1674:: with SMTP id d20ls10532118qko.0.gmail; Tue,
 23 Feb 2021 07:48:25 -0800 (PST)
X-Received: by 2002:a05:620a:2149:: with SMTP id m9mr26998881qkm.218.1614095305682;
        Tue, 23 Feb 2021 07:48:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614095305; cv=none;
        d=google.com; s=arc-20160816;
        b=n+Tcr6uMErvwxNHPqCKAKNUFXGojYfpp0DDLyvfCWdruD/w53uJDZ7d6j93N72b2u9
         0LFOuL6VOTd1ygVj2DwyABfsfKaGoXn7/Qr6xDGtvgSVrGeVe5fQn+kc8IipvCAXPC9j
         /StH797wzL9apjzY5AcfX/tz5VndSTUSXx6L8t0jOP5Rs75qisblwQzNUdoLDcSKwGxo
         KUh3indWrTewSjKG5yR5fe7IgzeY+ltTgr+UgsNT3d4XAgqz36OgSYzKp7QUFZvCpK9i
         1G7yTK1j729CPjUmBu0GLUuIxcfhTNBfG22aoPDLXbM5gz+mT59szLiJlTJ220WpW8D0
         TX1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Ak0FuL6cI8F0mJstd0CancH+iLPnxA3Bs8nwiMOi/W8=;
        b=NMlL2BrMIm8WqfA06xRh2pGRGyspRVPWH+ncWQN+Vgp5U632adxRMNRwtx1a9qQRih
         JcFIdo2SHU0cVb5inZLHRQ/FfyUY538kNVf2PA/yjvyMm9omou5OYO3cns15GPxP9hfC
         N9SB/hZixxTsb080IaMmOpv45oC0TyxHH29EW8b+nje5a9Y1VYuWgeJ5MDCiY3HGzOsT
         LH+9KuJ5x7njQNbM9iaGfIV8nFeLiAOIm+UJbwbR59SS5gdCHnjGPfYtRvhx5A3czx/W
         q4YSwOjraeTlr7Aui+Nk0GH/+Blj8Mo+ijFWbmB02VbecqINGwY7iRSnwgXhvM430ufZ
         7ciw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gVd6dsjS;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id w30si489929qkw.4.2021.02.23.07.48.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 07:48:25 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11NFYKn2068294;
	Tue, 23 Feb 2021 10:48:09 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkfudctf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 10:48:08 -0500
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11NFbBSc085265;
	Tue, 23 Feb 2021 10:48:08 -0500
Received: from ppma06fra.de.ibm.com (48.49.7a9f.ip4.static.sl-reverse.com [159.122.73.72])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkfudcrm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 10:48:08 -0500
Received: from pps.filterd (ppma06fra.de.ibm.com [127.0.0.1])
	by ppma06fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11NFhUPm028665;
	Tue, 23 Feb 2021 15:48:05 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma06fra.de.ibm.com with ESMTP id 36tsph9ep4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 15:48:05 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11NFlolU26345776
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 15:47:50 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 01B75AE059;
	Tue, 23 Feb 2021 15:48:03 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C0698AE045;
	Tue, 23 Feb 2021 15:48:00 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 23 Feb 2021 15:48:00 +0000 (GMT)
Date: Tue, 23 Feb 2021 17:47:58 +0200
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
Message-ID: <20210223154758.GF1741768@linux.ibm.com>
References: <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
 <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-23_08:2021-02-23,2021-02-23 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 mlxlogscore=999
 phishscore=0 spamscore=0 impostorscore=0 malwarescore=0 bulkscore=0
 adultscore=0 suspectscore=0 priorityscore=1501 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230131
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=gVd6dsjS;       spf=pass (google.com:
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

Hi George,

On Tue, Feb 23, 2021 at 09:35:32AM -0500, George Kennedy wrote:
>=20
> On 2/23/2021 5:33 AM, Mike Rapoport wrote:
> > (re-added CC)
> >=20
> > On Mon, Feb 22, 2021 at 08:24:59PM -0500, George Kennedy wrote:
> > > On 2/22/2021 4:55 PM, Mike Rapoport wrote:
> > > > On Mon, Feb 22, 2021 at 01:42:56PM -0500, George Kennedy wrote:
> > > > > On 2/22/2021 11:13 AM, David Hildenbrand wrote:
> > > > > > On 22.02.21 16:13, George Kennedy wrote:
> > > > > >=20
> > > > > > The PFN 0xbe453 looks a little strange, though. Do we expect AC=
PI tables
> > > > > > close to 3 GiB ? No idea. Could it be that you are trying to ma=
p a wrong
> > > > > > table? Just a guess.
> > > > > >=20
> > > > > > > What would be=C2=A0 the correct way to reserve the page so th=
at the above
> > > > > > > would not be hit?
> > > > > > I would have assumed that if this is a binary blob, that someon=
e (which
> > > > > > I think would be acpi code) reserved via memblock_reserve() ear=
ly during
> > > > > > boot.
> > > > > >=20
> > > > > > E.g., see drivers/acpi/tables.c:acpi_table_upgrade()->memblock_=
reserve().
> > > > > acpi_table_upgrade() gets called, but bails out before memblock_r=
eserve() is
> > > > > called. Thus, it appears no pages are getting reserved.
> > > > acpi_table_upgrade() does not actually reserve memory but rather op=
en
> > > > codes memblock allocation with memblock_find_in_range() +
> > > > memblock_reserve(), so it does not seem related anyway.
> > > >=20
> > > > Do you have by chance a full boot log handy?
> > > Hello Mike,
> > >=20
> > > Are you after the console output? See attached.
> > >=20
> > > It includes my patch to set PG_Reserved along with the dump_page() de=
bug
> > > that David asked for - see: "page:"
> > So, iBFT is indeed at pfn 0xbe453:
> >=20
> > [    0.077698] ACPI: iBFT 0x00000000BE453000 000800 (v01 BOCHS  BXPCFAC=
P 00000000      00000000)
> > and it's in E820_TYPE_RAM region rather than in ACPI data:
> >=20
> > [    0.000000] BIOS-e820: [mem 0x0000000000810000-0x00000000008fffff] A=
CPI NVS
> > [    0.000000] BIOS-e820: [mem 0x0000000000900000-0x00000000be49afff] u=
sable
> > [    0.000000] BIOS-e820: [mem 0x00000000be49b000-0x00000000be49bfff] A=
CPI data
> >=20
> > I could not find anywhere in x86 setup or in ACPI tables parsing the co=
de
> > that reserves this memory or any other ACPI data for that matter. It co=
uld
> > be that I've missed some copying of the data to statically allocated
> > initial_tables, but AFAICS any ACPI data that was not marked as such in
> > e820 tables by BIOS resides in memory that is considered as free.
> >=20
>=20
> Close...
>=20
> Applied the patch, see "[=C2=A0=C2=A0 30.136157] iBFT detected.", but now=
 hit the
> following (missing iounmap()? see full console output attached):
>=20
> diff --git a/drivers/firmware/iscsi_ibft_find.c
> b/drivers/firmware/iscsi_ibft_find.c
> index 64bb945..2e5e040 100644
> --- a/drivers/firmware/iscsi_ibft_find.c
> +++ b/drivers/firmware/iscsi_ibft_find.c
> @@ -80,6 +80,21 @@ static int __init find_ibft_in_mem(void)
> =C2=A0done:
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return len;
> =C2=A0}
> +
> +static void __init acpi_find_ibft_region(void)
> +{
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int i;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_header *table =3D=
 NULL;
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return;
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRAY_SIZE(ibft_s=
igns) && !ibft_addr; i++) {
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 acpi_get_table(ibft_signs[i].sign, 0, &table);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 ibft_addr =3D (struct acpi_table_ibft *)table;

Can you try adding=20

	acpi_put_table(table);

here?

> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
> +}
> +

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210223154758.GF1741768%40linux.ibm.com.
