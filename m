Return-Path: <kasan-dev+bncBDE5LFWXQAIRBBWL3WAQMGQE7LM3FNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C333324C40
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:53:27 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id v19sf3021689qtw.19
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 00:53:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614243206; cv=pass;
        d=google.com; s=arc-20160816;
        b=iL3Nzrvb9TFtfbxoeROVpq9kYHn4+lF+VpZp1kczGlZ8sduBdpv7j5CUSAsAFWxVmm
         TofPVVgeXU09y5ti9+8kCfKdI3fCsPQVqByChEGFEL9QS71z+Dzh01YUeSn78k+fzSAP
         k/JtZbD+4LJThPQFyV437ILkyu/E84dT/uuExPMT8ElPFzMgugJBhRjOEn/7roOgL4rf
         8CmQxigj6345W2WhLa6NSwJDOUl7WLXm37G2hDanv294nZsep/v79wgY8SMzzxQRkYXX
         i3rm+AWzhNX5W+0ZKwLveU0EWQ/0XJgAUxwP35l3FXsG2T01tODemEEr68wk8LhJDBvM
         HpKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=y1WB02lFDGkk0jALGbPewVi/BcZY3w0wZerBciys/y4=;
        b=DdMU7l6IuiyQCZgwZ3dEpwBMG4XpEhXD9z1GUxBEpXdlSm5DLAYqsQKfDDQ+CdzfEn
         IgK/IxikmXYIacWqoInn9/mPomTdkrDtPBbuIa0Dr1o+RBLCgXIGfScW2wdSdvF183Lm
         QiVmDPB59fP7CIH6heqLET0b/LDWkbb8s+xW5fpkWqmfXxoN2PsVl8DBDWA4SDScuQGo
         DeOCAq6BKGvmBbDFejQU2riIm49AR8L6XadFQu+WUuOjS6snNGKrAY49Jw+dQ43/kXRE
         l3Ju74uyrNnz7snowvgwXdmlzOZgMm4uRRd+DFEVG8iUAh1Ghz18BLa8rWfS1+DDWWeQ
         QXnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=j2PrgI5x;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y1WB02lFDGkk0jALGbPewVi/BcZY3w0wZerBciys/y4=;
        b=Z+Gxk/3yougOT1xzhC/x7MoyG79qz+BSJSXgv3y2CMTLDJkEyg5mw65qv4h5HR4rjF
         tYLD9OT4k/D3USmmpbYh9lLR/fFML1kn62TkRBlTRR/H6abf2nXplxfaF6PMLte4yjJf
         jKTVOmxp30OgQJUg/TeiIj9lBMjPECjBmxxJpr9/FkcGUpLMw6WaHrJLeb/KWon7lna8
         K1GuXf6X9OLRNW+nfriBRRlqtjy/XhCl6BrHsoQFVOxwI+pAy2zfXJ+xERAsca0Z2/MB
         qfVawaIGm34tnT+akWBu//Qc+LQ5A+0EDdQT4yE43FVkfEoxRSJE95fPYWcZ2fKq1pLb
         +1fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y1WB02lFDGkk0jALGbPewVi/BcZY3w0wZerBciys/y4=;
        b=rzcAd/2OdSXZTi37oiPS/VdaLBCbkBcQ7qC1tXfumCHIR5mZRjssXEJjL1034PUNzp
         ytF8l4NHwFxGzeEmXZ1YMgeK6jKM5SY/43PzniOJ5p6KkLZez0OydlJ8zxmDKcbYjRZM
         +UWWX6euWORTu3OyB7TcEAv/hs6YoULMgURrqBkJt2zrZ1+4FOitAE8qQBMPXg9zYXU9
         Z5ff7XAo/wgqjcVVa23B7lz9Xfhplufd5v49Z8IWiHj0LhosXAg52wtxAGwJ2VjMCj1o
         VL+I6gFiyDpDVyJJVZzpXG6dGWfWxBl3tgUWKcnTXB/maQpm05wCli6bu5bRGBUZWbxe
         /MXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305jL0sVHVAlMyzW82gJwue23mtyTWpFdFFfrwQfTSkMSUKRhZx
	6Gl6YpQAu+WJ45DXMZB+G9k=
X-Google-Smtp-Source: ABdhPJwYXeuW6gsg5xOyCRHAJxMdaV6LUgV53IgBJjy/xBa2hXg8qh37+h4PLAgKTj2j3bMlY9bidA==
X-Received: by 2002:ac8:7209:: with SMTP id a9mr1412272qtp.349.1614243206507;
        Thu, 25 Feb 2021 00:53:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2583:: with SMTP id fq3ls1323751qvb.2.gmail; Thu,
 25 Feb 2021 00:53:26 -0800 (PST)
X-Received: by 2002:ad4:53ac:: with SMTP id j12mr1715550qvv.3.1614243206085;
        Thu, 25 Feb 2021 00:53:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614243206; cv=none;
        d=google.com; s=arc-20160816;
        b=Rm3E7/NPNjbffBkyqY4BwMnOmwQP3gJGUUds6ZPAGYBKQMa0PcQ8kDQXoeqp6zZhg2
         h58UbmuPdKgEfCRy3zeuuyhcrnecbZomf6Q9C+7t6sAZSmFnEQbIWzTqS9cGoyFZcIg9
         KSvuM34LurNy0eTXsKAK8IylR6U9+t9YZq/6b1XhmF8SKF6s6d4KsLiDNR+DcZjWvzAZ
         7STOoXJVZ0/pTCKQUOFgOxe3bUKY45k2LRX9/yn9+fDms/I9pavTkmazKioRkOVAYHkz
         OM7sbH6xM2pyCrwtAQ6cGy8XtE00X7MLF+VONUMNMEdj0IdiO39Skx9TDz4lX4T/uuu4
         YoYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=h+Bg1KAb2M3NX3MNkh6cvynOcax+Mj6ebzjJBOaspRU=;
        b=xLH3Ak9XpimH5JSJda4A96b6NBAOKlZvFPj2OPUDbpSqaRR90rEob4iJwn6ogcK7Gs
         qor4tD96wE0S0XspS/yQAI0GSvighUili+MhTNoTrrig5dIqmQWlc3r8D1nlZjhbZnTz
         xW6uA6G97TmLfjn7KMA9hlv9T4aDbNaLUI+TpjeO8SLwbB6D+4LapugL//Vb/yP8RZ/G
         g440/x5HGqpoxVjHBJmnaD7TZ/hJrZahg6C2twUM4jgbPRMFpduP4nE3o6NiTWFWfBh9
         WaM//zjGVw0IiPYnf0IoIzwVKzf+nAEnZI5EX+qEXmJZTl4USwwwalw5SU50Nd+Bziuf
         bDBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=j2PrgI5x;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u5si238380qtb.5.2021.02.25.00.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 00:53:26 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11P8XKh7013629;
	Thu, 25 Feb 2021 03:53:11 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36x0qrkupd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 03:53:10 -0500
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11P8rAmb089588;
	Thu, 25 Feb 2021 03:53:10 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36x0qrkunc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 03:53:10 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11P8mveG018466;
	Thu, 25 Feb 2021 08:53:07 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma06ams.nl.ibm.com with ESMTP id 36tsph49cp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 08:53:07 +0000
Received: from d06av25.portsmouth.uk.ibm.com (d06av25.portsmouth.uk.ibm.com [9.149.105.61])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11P8qqHB36569356
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 08:52:52 GMT
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5529F11C058;
	Thu, 25 Feb 2021 08:53:05 +0000 (GMT)
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 987D311C054;
	Thu, 25 Feb 2021 08:53:02 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av25.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 25 Feb 2021 08:53:02 +0000 (GMT)
Date: Thu, 25 Feb 2021 10:53:00 +0200
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
Message-ID: <20210225085300.GB1854360@linux.ibm.com>
References: <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
 <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-25_04:2021-02-24,2021-02-25 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 impostorscore=0
 malwarescore=0 priorityscore=1501 spamscore=0 clxscore=1015 phishscore=0
 suspectscore=0 mlxlogscore=999 lowpriorityscore=0 adultscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102250071
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=j2PrgI5x;       spf=pass (google.com:
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

> On 2/24/2021 5:37 AM, Mike Rapoport wrote:
> > On Tue, Feb 23, 2021 at 04:46:28PM -0500, George Kennedy wrote:
> > > Mike,
> > >=20
> > > Still no luck.
> > >=20
> > > [=C2=A0=C2=A0 30.193723] iscsi: registered transport (iser)
> > > [=C2=A0=C2=A0 30.195970] iBFT detected.
> > > [=C2=A0=C2=A0 30.196571] BUG: unable to handle page fault for address=
: ffffffffff240004
> > Hmm, we cannot set ibft_addr to early pointer to the ACPI table.
> > Let's try something more disruptive and move the reservation back to
> > iscsi_ibft_find.c.
> >=20
> > diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boot.c
> > index 7bdc0239a943..c118dd54a747 100644
> > --- a/arch/x86/kernel/acpi/boot.c
> > +++ b/arch/x86/kernel/acpi/boot.c
> > @@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
> >   	if (acpi_disabled)
> >   		return;
> > +#if 0
> >   	/*
> >   	 * Initialize the ACPI boot-time table parser.
> >   	 */
> > @@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
> >   		disable_acpi();
> >   		return;
> >   	}
> > +#endif
> >   	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);
> > diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> > index d883176ef2ce..c615ce96c9a2 100644
> > --- a/arch/x86/kernel/setup.c
> > +++ b/arch/x86/kernel/setup.c
> > @@ -570,16 +570,6 @@ void __init reserve_standard_io_resources(void)
> >   }
> > -static __init void reserve_ibft_region(void)
> > -{
> > -	unsigned long addr, size =3D 0;
> > -
> > -	addr =3D find_ibft_region(&size);
> > -
> > -	if (size)
> > -		memblock_reserve(addr, size);
> > -}
> > -
> >   static bool __init snb_gfx_workaround_needed(void)
> >   {
> >   #ifdef CONFIG_PCI
> > @@ -1032,6 +1022,12 @@ void __init setup_arch(char **cmdline_p)
> >   	 */
> >   	find_smp_config();
> > +	/*
> > +	 * Initialize the ACPI boot-time table parser.
> > +	 */
> > +	if (acpi_table_init())
> > +		disable_acpi();
> > +
> >   	reserve_ibft_region();
> >   	early_alloc_pgt_buf();
> > diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscs=
i_ibft_find.c
> > index 64bb94523281..01be513843d6 100644
> > --- a/drivers/firmware/iscsi_ibft_find.c
> > +++ b/drivers/firmware/iscsi_ibft_find.c
> > @@ -47,7 +47,25 @@ static const struct {
> >   #define VGA_MEM 0xA0000 /* VGA buffer */
> >   #define VGA_SIZE 0x20000 /* 128kB */
> > -static int __init find_ibft_in_mem(void)
> > +static void __init *acpi_find_ibft_region(void)
> > +{
> > +	int i;
> > +	struct acpi_table_header *table =3D NULL;
> > +	acpi_status status;
> > +
> > +	if (acpi_disabled)
> > +		return NULL;
> > +
> > +	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> > +		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
> > +		if (ACPI_SUCCESS(status))
> > +			return table;
> > +	}
> > +
> > +	return NULL;
> > +}
> > +
> > +static void __init *find_ibft_in_mem(void)
> >   {
> >   	unsigned long pos;
> >   	unsigned int len =3D 0;
> > @@ -70,35 +88,44 @@ static int __init find_ibft_in_mem(void)
> >   				/* if the length of the table extends past 1M,
> >   				 * the table cannot be valid. */
> >   				if (pos + len <=3D (IBFT_END-1)) {
> > -					ibft_addr =3D (struct acpi_table_ibft *)virt;
> >   					pr_info("iBFT found at 0x%lx.\n", pos);
> > -					goto done;
> > +					return virt;
> >   				}
> >   			}
> >   		}
> >   	}
> > -done:
> > -	return len;
> > +
> > +	return NULL;
> >   }
> > +
> > +static void __init *find_ibft(void)
> > +{
> > +	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> > +	 * only use ACPI for this */
> > +	if (!efi_enabled(EFI_BOOT))
> > +		return find_ibft_in_mem();
> > +	else
> > +		return acpi_find_ibft_region();
> > +}
> > +
> >   /*
> >    * Routine used to find the iSCSI Boot Format Table. The logical
> >    * kernel address is set in the ibft_addr global variable.
> >    */
> > -unsigned long __init find_ibft_region(unsigned long *sizep)
> > +void __init reserve_ibft_region(void)
> >   {
> > -	ibft_addr =3D NULL;
> > +	struct acpi_table_ibft *table;
> > +	unsigned long size;
> > -	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> > -	 * only use ACPI for this */
> > +	table =3D find_ibft();
> > +	if (!table)
> > +		return;
> > -	if (!efi_enabled(EFI_BOOT))
> > -		find_ibft_in_mem();
> > -
> > -	if (ibft_addr) {
> > -		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> > -		return (u64)virt_to_phys(ibft_addr);
> > -	}
> > +	size =3D PAGE_ALIGN(table->header.length);
> > +	memblock_reserve(virt_to_phys(table), size);
> > -	*sizep =3D 0;
> > -	return 0;
> > +	if (efi_enabled(EFI_BOOT))
> > +		acpi_put_table(&table->header);
> > +	else
> > +		ibft_addr =3D table;
> >   }
> > diff --git a/include/linux/iscsi_ibft.h b/include/linux/iscsi_ibft.h
> > index b7b45ca82bea..da813c891990 100644
> > --- a/include/linux/iscsi_ibft.h
> > +++ b/include/linux/iscsi_ibft.h
> > @@ -26,13 +26,9 @@ extern struct acpi_table_ibft *ibft_addr;
> >    * mapped address is set in the ibft_addr variable.
> >    */
> >   #ifdef CONFIG_ISCSI_IBFT_FIND
> > -unsigned long find_ibft_region(unsigned long *sizep);
> > +void reserve_ibft_region(void);
> >   #else
> > -static inline unsigned long find_ibft_region(unsigned long *sizep)
> > -{
> > -	*sizep =3D 0;
> > -	return 0;
> > -}
> > +static inline void reserve_ibft_region(void) {}
> >   #endif
> >   #endif /* ISCSI_IBFT_H */
>=20
> Still no luck Mike,
>=20
> We're back to the original problem where the only thing that worked was t=
o
> run "SetPageReserved(page)" before calling "kmap(page)". The page is bein=
g
> "freed" before ibft_init() is called as a result of the recent buddy page
> freeing changes.

I keep missing some little details each time :(
Ok, let's try from the different angle.

diff --git a/drivers/acpi/acpica/tbutils.c b/drivers/acpi/acpica/tbutils.c
index 4b9b329a5a92..ec43e1447336 100644
--- a/drivers/acpi/acpica/tbutils.c
+++ b/drivers/acpi/acpica/tbutils.c
@@ -7,6 +7,8 @@
  *
  *************************************************************************=
****/
=20
+#include <linux/memblock.h>
+
 #include <acpi/acpi.h>
 #include "accommon.h"
 #include "actables.h"
@@ -339,6 +341,21 @@ acpi_tb_parse_root_table(acpi_physical_address rsdp_ad=
dress)
 			acpi_tb_parse_fadt();
 		}
=20
+		if (ACPI_SUCCESS(status) &&
+		    ACPI_COMPARE_NAMESEG(&acpi_gbl_root_table_list.
+					 tables[table_index].signature,
+					 ACPI_SIG_IBFT)) {
+			struct acpi_table_header *ibft;
+			struct acpi_table_desc *desc;
+
+			desc =3D &acpi_gbl_root_table_list.tables[table_index];
+			status =3D acpi_tb_get_table(desc, &ibft);
+			if (ACPI_SUCCESS(status)) {
+				memblock_reserve(address, ibft->length);
+				acpi_tb_put_table(desc);
+			}
+		}
+
 next_table:
=20
 		table_entry +=3D table_entry_size;
=20


--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210225085300.GB1854360%40linux.ibm.com.
