Return-Path: <kasan-dev+bncBDE5LFWXQAIRBXHV32AQMGQEEATGGMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 58BB93251CA
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 15:57:33 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id k1sf4194735qtp.12
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 06:57:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614265052; cv=pass;
        d=google.com; s=arc-20160816;
        b=UB8xDOn7+WmACGqPOAPIBx3oRJsXA/wwcPmz6lJFFFeF5lFu3+wyIgu+WF9zhEKgPf
         fvVOELsfpVUnRj8PMEbtuyAMgijG6MBlixmHTu1fwX8olNHAy3E0NWl12m5ernjkrl03
         t/B5c0AWffbxtiyOYjoQ51LznVxg5EXwo7Zyuisf2k3W2/iZJB6F/pK2s4+QGQtMBtBw
         kzGFc8cQiLeVhSZtGS+oq3F2/ixHq4uFE38SZgPf6Y5tv3MxjQLyV24JlUNrtO4wX22e
         jjHIb4Np17b/wlL6597S+AO5ZqwfLMk7e0bNMwrVsr97u0NLbj13jewJ3VL+9EvjVYyt
         qkQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RZ6RRDrHcwq8aXpV+boj0pRMDJ7JVVHd3NeGyXbCu7U=;
        b=Z+PAClCw5XnKB7IUb/1sqMctyzNEBpw8eYsyCm1FPp+Q/fH/JKaDreJHUpoZ/kwpfY
         jSOWnA8NhXjHotbCrqWQlVe79iWHi4xQgSHAvvTuY8uZMEVobXc3RtAOraeoQ2CMgeXd
         H9Uv/aqPGf/UQGScT4o/qZxDKKOLM3k6GFbMYMA58pyZRb6XcAO2oh3YnJtr6o8Yfr2e
         LifEXN7BFj1H+M13ze5cvC9NvP39Tm9cjuhkB7KB/iIJhjSEv8gGBult1iQUTv7x85dv
         Gttg3v8MAGdqLiyAE6qQeaFpXYlRAod12kB5Z4hdxXaA+GkhLm9u1hNELkNpa3wKw+Yt
         wvTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kPXWWFBO;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZ6RRDrHcwq8aXpV+boj0pRMDJ7JVVHd3NeGyXbCu7U=;
        b=lFxgVyRlSUFc3IyY7meVs8fsYfK1CjpKH0uu4OWDOvKY9OYknfEc7/7jZtPDfGo0Br
         p90cGl99VR432xW0SAREpay4JNw3Xg+ZKsgY4Pd2wNXeeMu3oEDn8N37q9JdYYPdeqSt
         SjgbU1mcRRVFI6nLsUWW1VoFyFPc+saiFmVqqDQGbeXeG+n/5+1FFaXsWS7U8Z068w52
         jrOwXOXmKz08hSUIA56wNkBsPpOcWCS5Cxv9ylQXJ1Bw2zLWXbM/iRUhQbv6CzzlKd2w
         jhMvBlp3NCJKYgNMsc7UV4dxrxYCug5ZzpBKaDztqV3ix4a6NudHYX12KzeL62/U3rqo
         3EuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZ6RRDrHcwq8aXpV+boj0pRMDJ7JVVHd3NeGyXbCu7U=;
        b=nTcnot1Ljl39BG6q5aAUaof1Id/JY0WiFPXOBEFI4gQXxwQD+oXPE+wBQMOOAcqO3o
         WcBmDbsg6r3M7bFwmo8KRv2AF/Op2ggAHrpsUQ/S+9ZHG8FNOiB7B055DYxLdKYIrSeR
         wUjk3enbwxpfJapmDMsaZOKu5YzGod5p50PWl4XYpKn/V9W8JZiW3/xdslyYtz2NOfxj
         rGIukXqs7UA5o55f0IOjGJvY7J84alD78xcw7bZ+0FhScItogPbRsdzaJWFXUSfv3UCB
         4+Ty5VbkIPYnS9SAhOmAr5We1hdanGUP9MdbEqCjwDfUohWdj7mCodMpbl42Dv+uON5w
         jifA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nyvSksmfnE1SAhLtMwepXZhwODaOBgIpkMakr1fnxsdS07wP8
	sQyOyvXocd57Mzk/XoGEQ/M=
X-Google-Smtp-Source: ABdhPJwtA+gmg4UNLTV0s+riWNNb246ZPGAyZqUSrPrG1A0t0ZL0FmF1Hd3Im+qQEVu1S/NyrBi4Ow==
X-Received: by 2002:a37:aec5:: with SMTP id x188mr2974145qke.144.1614265052095;
        Thu, 25 Feb 2021 06:57:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:991:: with SMTP id x17ls3144962qkx.2.gmail; Thu, 25
 Feb 2021 06:57:31 -0800 (PST)
X-Received: by 2002:a37:a8cd:: with SMTP id r196mr2875763qke.451.1614265051651;
        Thu, 25 Feb 2021 06:57:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614265051; cv=none;
        d=google.com; s=arc-20160816;
        b=YrJpjIaar/0TOUMlsvHKwBBrMGjTnwa4LybfPrB0nOVTB3RHGv4fCcv71FAu4hTI5o
         FqbKdscoSYHp5DhS7FbupgpUYbyD2+j6HPNScLSU/2a3aYrsPvmoigchelWGPHZhEFUI
         Gii+7RsXmvd1zB8GMGGVCiNTM6bBrVBMBjtsTKxSqdPlNBWzFcZBeRXS9PsdpeMLFseA
         bMj2zraS46UCSR55BJj4h+aGNcukb/Bd79c3wuNHBNysqfNWt0GqPVKyJrv9lANBLfkx
         ZME6stzA0D4vIBL4kR+5fFGbYXc8u8HqAG+IuestZrC+kN25P2lMhIptvZo8FTVoA4RE
         PEOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=mMaj3P4SrpEf4+/aFD9uJ8yy0sa8Fh7SEIG9gR0/fc4=;
        b=rXJcVLxwV5WCDgYc4OoA73MT4xqW4mDEX8NHDYdAAkb5sy9dufHRCXncH27ItLj57R
         9g83iIH6vNQHsaQgUYkbIDN55opHcN7ZbgSa7PJ/Je29U9Bb4OulUZ7UUcst3gTBuLad
         6lqk2wUYnaGLySHN6t7erHWAVsQyRCYZMNHmC7el017MyYA/XXESnSCK8kf/vT2FbAhQ
         btcpHha0xvpy1e23WpPx5l6983+BGfJDv/vq1ZTWpUXSm/S3XVJzzdGLI4ZSXvUmNGsV
         bJydyMlTStZIlXDZzu+EK+Z6rxXEWQKK2vXOz51MFiIuhTSWuOU9/bZgzaEZTXyyJaW/
         y48w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kPXWWFBO;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d12si238433qkn.0.2021.02.25.06.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 06:57:31 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11PElcBD053797;
	Thu, 25 Feb 2021 09:57:11 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xdpws3gg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 09:57:11 -0500
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11PEmLqW059649;
	Thu, 25 Feb 2021 09:57:10 -0500
Received: from ppma02fra.de.ibm.com (47.49.7a9f.ip4.static.sl-reverse.com [159.122.73.71])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xdpws3fa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 09:57:10 -0500
Received: from pps.filterd (ppma02fra.de.ibm.com [127.0.0.1])
	by ppma02fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11PEqPQp012125;
	Thu, 25 Feb 2021 14:57:07 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma02fra.de.ibm.com with ESMTP id 36tt28actd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 14:57:07 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11PEv5BL43319776
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 14:57:05 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 74F36AE053;
	Thu, 25 Feb 2021 14:57:05 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1D106AE04D;
	Thu, 25 Feb 2021 14:57:03 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 25 Feb 2021 14:57:02 +0000 (GMT)
Date: Thu, 25 Feb 2021 16:57:00 +0200
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
Message-ID: <20210225145700.GC1854360@linux.ibm.com>
References: <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
 <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-25_09:2021-02-24,2021-02-25 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999
 suspectscore=0 malwarescore=0 impostorscore=0 bulkscore=0 adultscore=0
 priorityscore=1501 mlxscore=0 clxscore=1015 phishscore=0 spamscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102250118
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kPXWWFBO;       spf=pass (google.com:
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

On Thu, Feb 25, 2021 at 07:38:19AM -0500, George Kennedy wrote:
> On 2/25/2021 3:53 AM, Mike Rapoport wrote:
> > Hi George,
> >=20
> > > On 2/24/2021 5:37 AM, Mike Rapoport wrote:
> > > > On Tue, Feb 23, 2021 at 04:46:28PM -0500, George Kennedy wrote:
> > > > > Mike,
> > > > >=20
> > > > > Still no luck.
> > > > >=20
> > > > > [=C2=A0=C2=A0 30.193723] iscsi: registered transport (iser)
> > > > > [=C2=A0=C2=A0 30.195970] iBFT detected.
> > > > > [=C2=A0=C2=A0 30.196571] BUG: unable to handle page fault for add=
ress: ffffffffff240004
> > > > Hmm, we cannot set ibft_addr to early pointer to the ACPI table.
> > > > Let's try something more disruptive and move the reservation back t=
o
> > > > iscsi_ibft_find.c.
> > > >=20
> > > > diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boo=
t.c
> > > > index 7bdc0239a943..c118dd54a747 100644
> > > > --- a/arch/x86/kernel/acpi/boot.c
> > > > +++ b/arch/x86/kernel/acpi/boot.c
> > > > @@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
> > > >    	if (acpi_disabled)
> > > >    		return;
> > > > +#if 0
> > > >    	/*
> > > >    	 * Initialize the ACPI boot-time table parser.
> > > >    	 */
> > > > @@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
> > > >    		disable_acpi();
> > > >    		return;
> > > >    	}
> > > > +#endif
> > > >    	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);
> > > > diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> > > > index d883176ef2ce..c615ce96c9a2 100644
> > > > --- a/arch/x86/kernel/setup.c
> > > > +++ b/arch/x86/kernel/setup.c
> > > > @@ -570,16 +570,6 @@ void __init reserve_standard_io_resources(void=
)
> > > >    }
> > > > -static __init void reserve_ibft_region(void)
> > > > -{
> > > > -	unsigned long addr, size =3D 0;
> > > > -
> > > > -	addr =3D find_ibft_region(&size);
> > > > -
> > > > -	if (size)
> > > > -		memblock_reserve(addr, size);
> > > > -}
> > > > -
> > > >    static bool __init snb_gfx_workaround_needed(void)
> > > >    {
> > > >    #ifdef CONFIG_PCI
> > > > @@ -1032,6 +1022,12 @@ void __init setup_arch(char **cmdline_p)
> > > >    	 */
> > > >    	find_smp_config();
> > > > +	/*
> > > > +	 * Initialize the ACPI boot-time table parser.
> > > > +	 */
> > > > +	if (acpi_table_init())
> > > > +		disable_acpi();
> > > > +
> > > >    	reserve_ibft_region();
> > > >    	early_alloc_pgt_buf();
> > > > diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/=
iscsi_ibft_find.c
> > > > index 64bb94523281..01be513843d6 100644
> > > > --- a/drivers/firmware/iscsi_ibft_find.c
> > > > +++ b/drivers/firmware/iscsi_ibft_find.c
> > > > @@ -47,7 +47,25 @@ static const struct {
> > > >    #define VGA_MEM 0xA0000 /* VGA buffer */
> > > >    #define VGA_SIZE 0x20000 /* 128kB */
> > > > -static int __init find_ibft_in_mem(void)
> > > > +static void __init *acpi_find_ibft_region(void)
> > > > +{
> > > > +	int i;
> > > > +	struct acpi_table_header *table =3D NULL;
> > > > +	acpi_status status;
> > > > +
> > > > +	if (acpi_disabled)
> > > > +		return NULL;
> > > > +
> > > > +	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> > > > +		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
> > > > +		if (ACPI_SUCCESS(status))
> > > > +			return table;
> > > > +	}
> > > > +
> > > > +	return NULL;
> > > > +}
> > > > +
> > > > +static void __init *find_ibft_in_mem(void)
> > > >    {
> > > >    	unsigned long pos;
> > > >    	unsigned int len =3D 0;
> > > > @@ -70,35 +88,44 @@ static int __init find_ibft_in_mem(void)
> > > >    				/* if the length of the table extends past 1M,
> > > >    				 * the table cannot be valid. */
> > > >    				if (pos + len <=3D (IBFT_END-1)) {
> > > > -					ibft_addr =3D (struct acpi_table_ibft *)virt;
> > > >    					pr_info("iBFT found at 0x%lx.\n", pos);
> > > > -					goto done;
> > > > +					return virt;
> > > >    				}
> > > >    			}
> > > >    		}
> > > >    	}
> > > > -done:
> > > > -	return len;
> > > > +
> > > > +	return NULL;
> > > >    }
> > > > +
> > > > +static void __init *find_ibft(void)
> > > > +{
> > > > +	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> > > > +	 * only use ACPI for this */
> > > > +	if (!efi_enabled(EFI_BOOT))
> > > > +		return find_ibft_in_mem();
> > > > +	else
> > > > +		return acpi_find_ibft_region();
> > > > +}
> > > > +
> > > >    /*
> > > >     * Routine used to find the iSCSI Boot Format Table. The logical
> > > >     * kernel address is set in the ibft_addr global variable.
> > > >     */
> > > > -unsigned long __init find_ibft_region(unsigned long *sizep)
> > > > +void __init reserve_ibft_region(void)
> > > >    {
> > > > -	ibft_addr =3D NULL;
> > > > +	struct acpi_table_ibft *table;
> > > > +	unsigned long size;
> > > > -	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> > > > -	 * only use ACPI for this */
> > > > +	table =3D find_ibft();
> > > > +	if (!table)
> > > > +		return;
> > > > -	if (!efi_enabled(EFI_BOOT))
> > > > -		find_ibft_in_mem();
> > > > -
> > > > -	if (ibft_addr) {
> > > > -		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> > > > -		return (u64)virt_to_phys(ibft_addr);
> > > > -	}
> > > > +	size =3D PAGE_ALIGN(table->header.length);
> > > > +	memblock_reserve(virt_to_phys(table), size);
> > > > -	*sizep =3D 0;
> > > > -	return 0;
> > > > +	if (efi_enabled(EFI_BOOT))
> > > > +		acpi_put_table(&table->header);
> > > > +	else
> > > > +		ibft_addr =3D table;
> > > >    }
> > > > diff --git a/include/linux/iscsi_ibft.h b/include/linux/iscsi_ibft.=
h
> > > > index b7b45ca82bea..da813c891990 100644
> > > > --- a/include/linux/iscsi_ibft.h
> > > > +++ b/include/linux/iscsi_ibft.h
> > > > @@ -26,13 +26,9 @@ extern struct acpi_table_ibft *ibft_addr;
> > > >     * mapped address is set in the ibft_addr variable.
> > > >     */
> > > >    #ifdef CONFIG_ISCSI_IBFT_FIND
> > > > -unsigned long find_ibft_region(unsigned long *sizep);
> > > > +void reserve_ibft_region(void);
> > > >    #else
> > > > -static inline unsigned long find_ibft_region(unsigned long *sizep)
> > > > -{
> > > > -	*sizep =3D 0;
> > > > -	return 0;
> > > > -}
> > > > +static inline void reserve_ibft_region(void) {}
> > > >    #endif
> > > >    #endif /* ISCSI_IBFT_H */
> > > Still no luck Mike,
> > >=20
> > > We're back to the original problem where the only thing that worked w=
as to
> > > run "SetPageReserved(page)" before calling "kmap(page)". The page is =
being
> > > "freed" before ibft_init() is called as a result of the recent buddy =
page
> > > freeing changes.
> > I keep missing some little details each time :(
> No worries. Thanks for all your help. Does this patch go on top of your
> previous patch or is it standalone?

This is standalone.
=20
> George
> > Ok, let's try from the different angle.
> >=20
> > diff --git a/drivers/acpi/acpica/tbutils.c b/drivers/acpi/acpica/tbutil=
s.c
> > index 4b9b329a5a92..ec43e1447336 100644
> > --- a/drivers/acpi/acpica/tbutils.c
> > +++ b/drivers/acpi/acpica/tbutils.c
> > @@ -7,6 +7,8 @@
> >    *
> >    ********************************************************************=
*********/
> > +#include <linux/memblock.h>
> > +
> >   #include <acpi/acpi.h>
> >   #include "accommon.h"
> >   #include "actables.h"
> > @@ -339,6 +341,21 @@ acpi_tb_parse_root_table(acpi_physical_address rsd=
p_address)
> >   			acpi_tb_parse_fadt();
> >   		}
> > +		if (ACPI_SUCCESS(status) &&
> > +		    ACPI_COMPARE_NAMESEG(&acpi_gbl_root_table_list.
> > +					 tables[table_index].signature,
> > +					 ACPI_SIG_IBFT)) {
> > +			struct acpi_table_header *ibft;
> > +			struct acpi_table_desc *desc;
> > +
> > +			desc =3D &acpi_gbl_root_table_list.tables[table_index];
> > +			status =3D acpi_tb_get_table(desc, &ibft);
> > +			if (ACPI_SUCCESS(status)) {
> > +				memblock_reserve(address, ibft->length);
> > +				acpi_tb_put_table(desc);
> > +			}
> > +		}
> > +
> >   next_table:
> >   		table_entry +=3D table_entry_size;
> >=20
> >=20
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
kasan-dev/20210225145700.GC1854360%40linux.ibm.com.
