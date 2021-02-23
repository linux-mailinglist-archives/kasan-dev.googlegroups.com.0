Return-Path: <kasan-dev+bncBDE5LFWXQAIRBLHJ2WAQMGQEHLAPAMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 48D5C32334D
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 22:33:33 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id u6sf7979274uaq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 13:33:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614116012; cv=pass;
        d=google.com; s=arc-20160816;
        b=aNVqQtHehesOxJsSqM5maEx0nAR0EEiqm5UXIi8cof2VI04AiStKhmUGbc5ejLGdmM
         YWXdFU4HyAT36FBHbeFVr65QQH8w+KRzJBZiiYEmaYrG1238FkCZV2OJd2ep/sq4MnBT
         /eqNRGMrrr+VBTEatRWhxrG7zB3VE1C3ipUWz5E/i86e27+zCsMeeWn9z2fSNFhZ4zQL
         SFz3svOP4nDb7FKJjTyCZig5uehsBrpMHb6onr5Ef4QcA6niS1/G3vTTicDNFq2LOlEk
         qkv3LDPsWI8nyRsZJ0+2AWGzh1tyBlenZGNlCfhvITtlu/fLOaooaVXpf0CJnZ7jJcHb
         n4ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=m/OHNmdXjQcRH5PZS+vBQfAk/v7tvw1PjEsKVwjdXd0=;
        b=b6wIykymIttftZ9E+J/hvaIRy1fEGj+gAM7UBWu3tIoLejsG/sdSoud6Ruc0goFIx9
         RGFcrRCi40S0v0bw/Of2gY63VPFqhpHypeeIoj7aZ6ldluLd23Sx5GhJknG0C9bNM8qD
         2OEVDi2JPdaYWB97HNoqUr1/ldW/0O7EciDBCY/BQxZ7zBVJp3WLBoqIqwCPEYlNGOzn
         Su90IIGM1Wabgi/8NtbqPcaxDMOjvrSF4EsN/GOBurqApAUMSVjA9exuUFD/vfHwOvDk
         VUQOoW/NCVdm1Y292Qy7ya3oyMTp4Ft+xorrds5tUvsk37clDNfbqvdw0nQ94KExTPv1
         jpaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ZqU9E81U;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m/OHNmdXjQcRH5PZS+vBQfAk/v7tvw1PjEsKVwjdXd0=;
        b=oRaMBXsuos50N5+Jk5NzswFViwdyeSlpiy3tmsQo4Hjy1OR1PQL+EfVN8YAR8vLZfP
         Y5Dipif0K6ZOtyD2ZFB4VPQGmh0w5bCjeZe6sO+p2UsHkwW312IkCQfOREIYfLStLzU5
         ILjef9rvWsyP2Y4jd7koSkRYEGnJamNKNFnJRtPdEtSZx5EcE9L0v4AX5MitqCxuZAM8
         eJN708O9PLTz/mRplObn7aV7d0FATbjyi8R4jbTXlgBbo6WPuRyTumWXc2jlhEt2mVpB
         6gl602ba+cppHoT98W6pH1UiCGtawMAvcXDlVem9jRbzX7qqf2WOGPTkQXw5vXROkhdP
         JlxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m/OHNmdXjQcRH5PZS+vBQfAk/v7tvw1PjEsKVwjdXd0=;
        b=crdUZi5aKKs7Jmb1LfGWV4XPNRMeX2u5cEIm8uiqdUQ2YglpJqSaaj7udX0BPaiqnS
         DIcv4/Sb9kU9uSEvKfEptVMmhpVnfvX5cSw19gwEy0Qcp3zJLwFp71o4499vSS8l18eP
         8H+OLbNxokio3HkR4PUWcy8WiYSyVuw7o4q9RckjowRJBfGEQWsLfHYKH8AaZ8Q1DwRM
         6GVJpdrVxrelWoSa0Zlu8d1M6ZUS7UZe8QHG80Bd25SYxQ1EyUn2SI+qKvBAA8AkeQjG
         r7x+1IKmk/Geu+WEgQbEGAh5H9E6Iwslo35lqYTKh4f3JZ7Dxf8AUN5qWE13HsRAkeuN
         kF6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jej0AUZKt0t57xs7XujUQvOp684DRak79BOo/J9cHKWSgH4K0
	81sO/8gcntJfCNsTW2p4SDE=
X-Google-Smtp-Source: ABdhPJzGdI0crN5QtvyYE9lv1IsV4ctaZVKcutkoBa3iNPyK8EXx5bdkdG7Ju7fvWoPoM04XuttEnQ==
X-Received: by 2002:a67:eeca:: with SMTP id o10mr16648003vsp.30.1614116012336;
        Tue, 23 Feb 2021 13:33:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5e9d:: with SMTP id y29ls1688993uag.9.gmail; Tue, 23 Feb
 2021 13:33:31 -0800 (PST)
X-Received: by 2002:ab0:5e9f:: with SMTP id y31mr18210894uag.119.1614116011795;
        Tue, 23 Feb 2021 13:33:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614116011; cv=none;
        d=google.com; s=arc-20160816;
        b=gIXtSTk4bOng/Yj/UXAy75lOzIOM7guZowq/doq0SAX9qaDrCtp0L+wYWofwu6JHno
         aCamMnu0GO0fHuQOr9syaU7z9OrK0dNTpI0LLOmjv+f1Kf9Cv41r32kOTdnLfsmHNow5
         cqZ+jv5yv3lVhmNJdGxXGx4Kk0SFy/zuOPXmeD32G4eb93FBC2fSryBNAwydAee6VeUr
         MjSNkw6Hm5u9kEd4wStMmuP8Pm7UwgUo4AauCBKkIExW55P8WwgPXo99FJDsEqF1Afcl
         PxQWSLoE38peXlqaG1vP48dXrblclsG7ujGtP+NnJkQqY++5vSViPtUsBmSMQYb5ayfw
         A3/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=g5+5H7lYHfmYYrC/nKWeewchJ8EAOeOow/Zy0rM5V4Y=;
        b=ZXzEj3XqKH2/+MUIDG0YM7qL/U1V9SiEOZgyWk0qE37trDR66z1UfthaX4R7BM0EkI
         1+NoYoaaKN+UdF+hNSpAWuKfBKlal/F0vF6SgcJ7es/6h1M9mRMBLNltUYDa9xaiACrE
         zY7TO9se9UBOies5a7Po7cWcm3oaAfBiZAAv75RAsJxE1/PwCwDKowFspSFfzY2cKAMo
         frv0ToiJu2fgCa6rI1kWEKWrHmfkiPvFZ0LT0Z7/A9SlWBZPOZp78BNcLsdk/M83ZbLf
         z64a6smcO9FJZMsOrY8hbZxfBwBa3NsF4a5pPpcf4JkiZFeyw0SBktHmDCbuqnhcZZgh
         Pjkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ZqU9E81U;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id l11si1208582vkr.5.2021.02.23.13.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 13:33:31 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11NLX8wv102294;
	Tue, 23 Feb 2021 16:33:15 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkf8y2fv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 16:33:15 -0500
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11NLXDQ2102798;
	Tue, 23 Feb 2021 16:33:13 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkf8y26j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 16:33:13 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11NLSUfS008614;
	Tue, 23 Feb 2021 21:32:44 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma06ams.nl.ibm.com with ESMTP id 36tsph2ynk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 21:32:44 +0000
Received: from d06av24.portsmouth.uk.ibm.com (d06av24.portsmouth.uk.ibm.com [9.149.105.60])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11NLWgKH50856352
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 21:32:42 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3B94D42042;
	Tue, 23 Feb 2021 21:32:42 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E36274203F;
	Tue, 23 Feb 2021 21:32:39 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 23 Feb 2021 21:32:39 +0000 (GMT)
Date: Tue, 23 Feb 2021 23:32:37 +0200
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
Message-ID: <20210223213237.GI1741768@linux.ibm.com>
References: <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
 <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
 <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-23_08:2021-02-23,2021-02-23 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 malwarescore=0
 phishscore=0 adultscore=0 mlxscore=0 priorityscore=1501 clxscore=1015
 spamscore=0 lowpriorityscore=0 suspectscore=0 mlxlogscore=999
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230181
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ZqU9E81U;       spf=pass (google.com:
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

On Tue, Feb 23, 2021 at 04:16:44PM -0500, George Kennedy wrote:
>=20
>=20
> On 2/23/2021 3:09 PM, Mike Rapoport wrote:
> > On Tue, Feb 23, 2021 at 01:05:05PM -0500, George Kennedy wrote:
> > > On 2/23/2021 10:47 AM, Mike Rapoport wrote:
> > >=20
> > > It now crashes here:
> > >=20
> > > [=C2=A0=C2=A0=C2=A0 0.051019] ACPI: Early table checksum verification=
 disabled
> > > [=C2=A0=C2=A0=C2=A0 0.056721] ACPI: RSDP 0x00000000BFBFA014 000024 (v=
02 BOCHS )
> > > [=C2=A0=C2=A0=C2=A0 0.057874] ACPI: XSDT 0x00000000BFBF90E8 00004C (v=
01 BOCHS BXPCFACP
> > > 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> > > [=C2=A0=C2=A0=C2=A0 0.059590] ACPI: FACP 0x00000000BFBF5000 000074 (v=
01 BOCHS BXPCFACP
> > > 00000001 BXPC 00000001)
> > > [=C2=A0=C2=A0=C2=A0 0.061306] ACPI: DSDT 0x00000000BFBF6000 00238D (v=
01 BOCHS BXPCDSDT
> > > 00000001 BXPC 00000001)
> > > [=C2=A0=C2=A0=C2=A0 0.063006] ACPI: FACS 0x00000000BFBFD000 000040
> > > [=C2=A0=C2=A0=C2=A0 0.063938] ACPI: APIC 0x00000000BFBF4000 000090 (v=
01 BOCHS BXPCAPIC
> > > 00000001 BXPC 00000001)
> > > [=C2=A0=C2=A0=C2=A0 0.065638] ACPI: HPET 0x00000000BFBF3000 000038 (v=
01 BOCHS BXPCHPET
> > > 00000001 BXPC 00000001)
> > > [=C2=A0=C2=A0=C2=A0 0.067335] ACPI: BGRT 0x00000000BE49B000 000038 (v=
01 INTEL EDK2
> > > 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> > > [=C2=A0=C2=A0=C2=A0 0.069030] ACPI: iBFT 0x00000000BE453000 000800 (v=
01 BOCHS BXPCFACP
> > > 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
> > > [=C2=A0=C2=A0=C2=A0 0.070734] XXX acpi_find_ibft_region:
> > > [=C2=A0=C2=A0=C2=A0 0.071468] XXX iBFT, status=3D0
> > > [=C2=A0=C2=A0=C2=A0 0.072073] XXX about to call acpi_put_table()...
> > > ibft_addr=3Dffffffffff240000
> > > [=C2=A0=C2=A0=C2=A0 0.073449] XXX acpi_find_ibft_region(EXIT):
> > > PANIC: early exception 0x0e IP 10:ffffffff9259f439 error 0 cr2
> > > 0xffffffffff240004
> > Right, I've missed the dereference of the ibft_addr after
> > acpi_find_ibft_region().
> >=20
> > With this change to iscsi_ibft_find.c instead of the previous one it sh=
ould
> > be better:
> >=20
> > diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscs=
i_ibft_find.c
> > index 64bb94523281..1be7481d5c69 100644
> > --- a/drivers/firmware/iscsi_ibft_find.c
> > +++ b/drivers/firmware/iscsi_ibft_find.c
> > @@ -80,6 +80,27 @@ static int __init find_ibft_in_mem(void)
> >   done:
> >   	return len;
> >   }
> > +
> > +static void __init acpi_find_ibft_region(unsigned long *sizep)
> > +{
> > +	int i;
> > +	struct acpi_table_header *table =3D NULL;
> > +	acpi_status status;
> > +
> > +	if (acpi_disabled)
> > +		return;
> > +
> > +	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> > +		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
> > +		if (ACPI_SUCCESS(status)) {
> > +			ibft_addr =3D (struct acpi_table_ibft *)table;
> > +			*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> > +			acpi_put_table(table);
> > +			break;
> > +		}
> > +	}
> > +}
> > +
> >   /*
> >    * Routine used to find the iSCSI Boot Format Table. The logical
> >    * kernel address is set in the ibft_addr global variable.
> > @@ -91,14 +112,16 @@ unsigned long __init find_ibft_region(unsigned lon=
g *sizep)
> >   	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> >   	 * only use ACPI for this */
> > -	if (!efi_enabled(EFI_BOOT))
> > +	if (!efi_enabled(EFI_BOOT)) {
> >   		find_ibft_in_mem();
> > -
> > -	if (ibft_addr) {
> >   		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> > -		return (u64)virt_to_phys(ibft_addr);
> > +	} else {
> > +		acpi_find_ibft_region(sizep);
> >   	}
> > +	if (ibft_addr)
> > +		return (u64)virt_to_phys(ibft_addr);
> > +
> >   	*sizep =3D 0;
> >   	return 0;
> >   }
> Mike,
>=20
> No luck. Back to the original KASAN ibft_init crash.
>=20
> I ran with only the above patch from you. Was that what you wanted? Your
> previous patch had a section defined out by #if 0. Was that supposed to b=
e
> in there as well?

Sorry, I wasn't clear, but I meant to use the first patch and only replace
changes to iscsi_ibft_find.c with the new patch.=20

Here's the full patch to be sure we're on the same page:

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
index 64bb94523281..1be7481d5c69 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -80,6 +80,27 @@ static int __init find_ibft_in_mem(void)
 done:
 	return len;
 }
+
+static void __init acpi_find_ibft_region(unsigned long *sizep)
+{
+	int i;
+	struct acpi_table_header *table =3D NULL;
+	acpi_status status;
+
+	if (acpi_disabled)
+		return;
+
+	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
+		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
+		if (ACPI_SUCCESS(status)) {
+			ibft_addr =3D (struct acpi_table_ibft *)table;
+			*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
+			acpi_put_table(table);
+			break;
+		}
+	}
+}
+
 /*
  * Routine used to find the iSCSI Boot Format Table. The logical
  * kernel address is set in the ibft_addr global variable.
@@ -91,14 +112,16 @@ unsigned long __init find_ibft_region(unsigned long *s=
izep)
 	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
 	 * only use ACPI for this */
=20
-	if (!efi_enabled(EFI_BOOT))
+	if (!efi_enabled(EFI_BOOT)) {
 		find_ibft_in_mem();
-
-	if (ibft_addr) {
 		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
-		return (u64)virt_to_phys(ibft_addr);
+	} else {
+		acpi_find_ibft_region(sizep);
 	}
=20
+	if (ibft_addr)
+		return (u64)virt_to_phys(ibft_addr);
+
 	*sizep =3D 0;
 	return 0;
 }
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
kasan-dev/20210223213237.GI1741768%40linux.ibm.com.
