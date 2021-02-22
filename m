Return-Path: <kasan-dev+bncBDE5LFWXQAIRBUOQ2CAQMGQEQ3UIKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 792633221D9
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 22:55:30 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id y15sf8798563pgk.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 13:55:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614030929; cv=pass;
        d=google.com; s=arc-20160816;
        b=BOLEk+qiE5P+DhpsVPiX0IHzVgm8v1XeFyKLgKxLAyHZDlcK9KHVluOdND8lqHspu+
         poLghIZh6FdocReJ+uB6W0SWR0uVdcBKLM32foLzwSkEa0cDvtOSKm8Apo7LVSsDbUmV
         n10rcIg98Az+elHZ392soIR/FR7kSCrDwbd4bKLqKCiqoKbqu92GLnLXQrdyAJsRBUIe
         4aPGRaZdPGM0SWg9lBjOFetnzgXy+hduUtf06i8PLlwbQNhb1TPGSI0Mtm0m2038IT/Z
         VpDSJF+41isDZBPIecKyRKKrIWotCfscGm9YagrgulqcLPBjHQzdwAZKnYpHxeYt0HiO
         BjFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=tmjuZrjRpRAmgF5Y6vFNvAvbuAIkrmlihjCxdS5Rm8Q=;
        b=sY3TsBNDe/alQKw1ESxRyWUn0bKpEL34DA2l4+4/tvTgJ3NCYphya6g/Iopr4YpMcA
         c1tNvfxtAfDrkHC0xV305eCNOFBpi5hLhVZBLBMLHGgJj3OTp+3rrKL+RBHdFp/Ch81J
         fGns2vciWFgCHDp6eOqyGEPQf2XZhXQRDIsSP0XBoaV4K+H9ZJidSL8Tmw8BOWEiuh9G
         xRCplf1b5hy4unM6xJ2WjjlUrQacTePiHuce1lk4qFm5ettMj8Bs0oXBgCWj8pNCJ5m5
         Nb/uFpK7p5qbMa5S1Rab9jd3OAuF/em6E9/6NJE2XSM/K9qb3rFiE2pk80pMWa96H0HW
         b2AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TTGdvXlp;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tmjuZrjRpRAmgF5Y6vFNvAvbuAIkrmlihjCxdS5Rm8Q=;
        b=Fg8aS0iA4Riyzjnwa3to55bAdtOxNp4FZOdsnOhF3wRX0qsQssXZMcEBY8KxEYXWrX
         DPdIXd4veO8R9ZCrgAwVL0qj0sRSqB6oT9wIHOmelMDY+1s+VRrsp53cI3s/TpLRNpKy
         uIw5eKqSCoUwKwc9pHbgs5SUyawEJUREvcnXuG2ofQSqvEq3UWJq0/dAI5A4gvsfKLrn
         kS0iiksjDGkBJZcLxjepfhg7K5i9y5563f7a++gS/c077liG2hXjLPdIipOuZqCChrOr
         2YXx+IjQv6VZH/T3FIYSmv2l34b89d5ZhJFznNulEEAaEK8ZV/3hY1/U9vx0v4cUdxAo
         dX6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tmjuZrjRpRAmgF5Y6vFNvAvbuAIkrmlihjCxdS5Rm8Q=;
        b=Xx2wnv1DJwyKa4pEJAuule/VCOVHDOgc7J2l8bZS2/juOZot1VdHZmb1dGPjDIClLZ
         3LkHZUXAGouTVMRIUlhgyguBYT5Hs+XBhXbhqZuTWDdsDEAFHrBYm4mOEJegtUreFuu4
         7FLNg8s0mOozHMKY7m010JgeF5pkZLJbS6A61pTzWV7pikh8FJl4RvEtmdPMO5hgf/lt
         HTWY+DxgYPt+hoqd/gLJNMQMJznRHiCCBCP1KbLofcjt4U5cx1mA0RHmDcEhfF2bRf3T
         ub+3mPkCKS9GhiKlu4iQAzIWyVNgis3ueQ7pAhx96pYPewZAyUpCAsK+CI4kk6JyrNQX
         +2Cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CwSyQZt0BJyQUs8fNw9s7KWy+qhTdPQWUMEkw1OVm+CPrOT0V
	LIRpQa8OX2ybJFmimcirjdQ=
X-Google-Smtp-Source: ABdhPJzScFB8A/L4YTLZzX2YOCJFWYZTOZFnqbjICO9vs+T1Gj4HczGHb1EZE/Nb2vbYKL3RSVE9Qg==
X-Received: by 2002:a63:4a1a:: with SMTP id x26mr22191808pga.260.1614030929224;
        Mon, 22 Feb 2021 13:55:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ec53:: with SMTP id r19ls1368594pgj.1.gmail; Mon, 22 Feb
 2021 13:55:28 -0800 (PST)
X-Received: by 2002:a63:5745:: with SMTP id h5mr21489128pgm.354.1614030928611;
        Mon, 22 Feb 2021 13:55:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614030928; cv=none;
        d=google.com; s=arc-20160816;
        b=UFIr+6rucUxI8cIa8D+IqbyT2vVdGYdAx4TRRmziKJAQBsr43MmF+QoDpnlqjWPBnz
         jYYPj3dC+15HqozKYLPiDWUos8etUzbMFrNL0c/1F2V59AaGmreFDC6sAPp5ZxSPXqkK
         Q3FBqY39QChiZ73iELwwsmfvELjTQQYhvuwIu95np405roIGh8eN9GUjGwZq+LE76y90
         bNRsxeQAtAoH4ddQ1TJAguw4Wc+i74H+BxagSyriWVT4auBb7WoTx4LX30Gdb/MyDyrF
         NBknIuGVQ6o04RL9Ynd1ow1xRyVygrDkbZcPgVRMhRAfZ0PROnwfxmWnpUOaT4ANhRDs
         BEsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=R4rIU2G5kKIHfDd+43BWvqmZDKp/IJsUHSHYByhbHpg=;
        b=xE+i3sAr+qlfr0jbqWj3YAN/lR8M+mYgFySNeCqhUn/QXeHZr6x/WiA8/8eGX0WTq4
         AW5EzbuxZrV5Hi/WXy2jQw8GdaPN11KUfao/ir9qetYU+VX6eetR+FKNvuub9jU6r/fU
         us21BDfy5KyJljUqlb0I11QaSossx7mEhwQdpr9CwbiB5tvlF32W1KSpD7jlFelVZtPC
         2Ud9H4taQBjE0OTj7hS3iHfINsLaBMV7RQ2Ujbom3WxaheqjIcBe8b5ss+oMO943qE0O
         xKXpCqBH62OCOLW9HiHnmTWQoqY3U2p8XqAAjHPaCbBnCAi1a/Cw4iVczcprNRDQQtEg
         l/2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TTGdvXlp;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d6si937034plo.3.2021.02.22.13.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 13:55:28 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098409.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11MLXqIa132709;
	Mon, 22 Feb 2021 16:55:13 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkfs31pf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 22 Feb 2021 16:55:13 -0500
Received: from m0098409.ppops.net (m0098409.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11MLYruF142830;
	Mon, 22 Feb 2021 16:55:12 -0500
Received: from ppma03fra.de.ibm.com (6b.4a.5195.ip4.static.sl-reverse.com [149.81.74.107])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vkfs31n9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 22 Feb 2021 16:55:11 -0500
Received: from pps.filterd (ppma03fra.de.ibm.com [127.0.0.1])
	by ppma03fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11MLt9Mk031004;
	Mon, 22 Feb 2021 21:55:09 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma03fra.de.ibm.com with ESMTP id 36tt28s27c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 22 Feb 2021 21:55:09 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11MLt7tQ45941092
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 22 Feb 2021 21:55:07 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 29A824C04E;
	Mon, 22 Feb 2021 21:55:07 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E4A5A4C044;
	Mon, 22 Feb 2021 21:55:04 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Mon, 22 Feb 2021 21:55:04 +0000 (GMT)
Date: Mon, 22 Feb 2021 23:55:02 +0200
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
Message-ID: <20210222215502.GB1741768@linux.ibm.com>
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-22_07:2021-02-22,2021-02-22 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 mlxlogscore=999 priorityscore=1501 impostorscore=0 lowpriorityscore=0
 phishscore=0 bulkscore=0 spamscore=0 adultscore=0 malwarescore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102220187
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=TTGdvXlp;       spf=pass (google.com:
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

On Mon, Feb 22, 2021 at 01:42:56PM -0500, George Kennedy wrote:
>=20
> On 2/22/2021 11:13 AM, David Hildenbrand wrote:
> > On 22.02.21 16:13, George Kennedy wrote:
> > >=20
> > > On 2/22/2021 4:52 AM, David Hildenbrand wrote:
> > > >=20
> > > > Let me look into the code ... I have little experience with ACPI
> > > > details, so bear with me.
> > > >=20
> > > > I assume that acpi_map()/acpi_unmap() map some firmware blob that i=
s
> > > > provided via firmware/bios/... to us.
> > > >=20
> > > > should_use_kmap() tells us whether
> > > > a) we have a "struct page" and should kmap() that one
> > > > b) we don't have a "struct page" and should ioremap.
> > > >=20
> > > > As it is a blob, the firmware should always reserve that memory reg=
ion
> > > > via memblock (e.g., memblock_reserve()), such that we either
> > > > 1) don't create a memmap ("struct page") at all (-> case b) )
> > > > 2) if we have to create e memmap, we mark the page PG_reserved and
> > > > =C2=A0=C2=A0=C2=A0 *never* expose it to the buddy (-> case a) )
> > > >=20
> > > >=20
> > > > Are you telling me that in this case we might have a memmap for the=
 HW
> > > > blob that is *not* PG_reserved? In that case it most probably got
> > > > exposed to the buddy where it can happily get allocated/freed.
> > > >=20
> > > > The latent BUG would be that that blob gets exposed to the system l=
ike
> > > > ordinary RAM, and not reserved via memblock early during boot.
> > > > Assuming that blob has a low physical address, with my patch it wil=
l
> > > > get allocated/used a lot earlier - which would mean we trigger this
> > > > latent BUG now more easily.
> > > >=20
> > > > There have been similar latent BUGs on ARM boards that my patch
> > > > discovered where special RAM regions did not get marked as reserved
> > > > via the device tree properly.
> > > >=20
> > > > Now, this is just a wild guess :) Can you dump the page when mappin=
g
> > > > (before PageReserved()) and when unmapping, to see what the state o=
f
> > > > that memmap is?
> > >=20
> > > Thank you David for the explanation and your help on this,
> > >=20
> > > dump_page() before PageReserved and before kmap() in the above patch:
> > >=20
> > > [=C2=A0=C2=A0=C2=A0 1.116480] ACPI: Core revision 20201113
> > > [=C2=A0=C2=A0=C2=A0 1.117628] XXX acpi_map: about to call kmap()...
> > > [=C2=A0=C2=A0=C2=A0 1.118561] page:ffffea0002f914c0 refcount:0 mapcou=
nt:0
> > > mapping:0000000000000000 index:0x0 pfn:0xbe453
> > > [=C2=A0=C2=A0=C2=A0 1.120381] flags: 0xfffffc0000000()
> > > [=C2=A0=C2=A0=C2=A0 1.121116] raw: 000fffffc0000000 ffffea0002f914c8 =
ffffea0002f914c8
> > > 0000000000000000
> > > [=C2=A0=C2=A0=C2=A0 1.122638] raw: 0000000000000000 0000000000000000 =
00000000ffffffff
> > > 0000000000000000
> > > [=C2=A0=C2=A0=C2=A0 1.124146] page dumped because: acpi_map pre SetPa=
geReserved
> > >=20
> > > I also added dump_page() before unmapping, but it is not hit. The
> > > following for the same pfn now shows up I believe as a result of sett=
ing
> > > PageReserved:
> > >=20
> > > [=C2=A0=C2=A0 28.098208] BUG:Bad page state in process mo dprobe pfn:=
be453
> > > [=C2=A0=C2=A0 28.098394] page:ffffea0002f914c0 refcount:0 mapcount:0
> > > mapping:0000000000000000 index:0x1 pfn:0xbe453
> > > [=C2=A0=C2=A0 28.098394] flags: 0xfffffc0001000(reserved)
> > > [=C2=A0=C2=A0 28.098394] raw: 000fffffc0001000 dead000000000100 dead0=
00000000122
> > > 0000000000000000
> > > [=C2=A0=C2=A0 28.098394] raw: 0000000000000001 0000000000000000 00000=
000ffffffff
> > > 0000000000000000
> > > [=C2=A0=C2=A0 28.098394] page dumped because: PAGE_FLAGS_CHECK_AT_PRE=
P flag(s) set
> > > [=C2=A0=C2=A0 28.098394] page_owner info is not present (never set?)
> > > [=C2=A0=C2=A0 28.098394] Modules linked in:
> > > [=C2=A0=C2=A0 28.098394] CPU: 2 PID: 204 Comm: modprobe Not tainted
> > > 5.11.0-3dbd5e3 #66
> > > [=C2=A0=C2=A0 28.098394] Hardware name: QEMU Standard PC (i440FX + PI=
IX, 1996),
> > > BIOS 0.0.0 02/06/2015
> > > [=C2=A0=C2=A0 28.098394] Call Trace:
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 dump_stack+0xdb/0x120
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 bad_page.cold.108+0xc6/0xcb
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 check_new_page_bad+0x47/0xa0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 get_page_from_freelist+0x30cd/0x5730
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __isolate_free_page+0x4f0/0x4f0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? init_object+0x7e/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __alloc_pages_slowpath.constprop.103=
+0x2110/0x2110
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 alloc_pages_vma+0xe2/0x560
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 do_fault+0x194/0x12c0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 __handle_mm_fault+0x1650/0x26c0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? copy_page_range+0x1350/0x1350
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 handle_mm_fault+0x1f9/0x810
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 do_user_addr_fault+0x6f7/0xca0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 exc_page_fault+0xaf/0x1a0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 asm_exc_page_fault+0x1e/0x30
> > > [=C2=A0=C2=A0 28.098394] RIP: 0010:__clear_user+0x30/0x60
> >=20
> > I think the PAGE_FLAGS_CHECK_AT_PREP check in this instance means that
> > someone is trying to allocate that page with the PG_reserved bit set.
> > This means that the page actually was exposed to the buddy.
> >=20
> > However, when you SetPageReserved(), I don't think that PG_buddy is set
> > and the refcount is 0. That could indicate that the page is on the budd=
y
> > PCP list. Could be that it is getting reused a couple of times.
> >=20
> > The PFN 0xbe453 looks a little strange, though. Do we expect ACPI table=
s
> > close to 3 GiB ? No idea. Could it be that you are trying to map a wron=
g
> > table? Just a guess.
> >=20
> > >=20
> > > What would be=C2=A0 the correct way to reserve the page so that the a=
bove
> > > would not be hit?
> >=20
> > I would have assumed that if this is a binary blob, that someone (which
> > I think would be acpi code) reserved via memblock_reserve() early durin=
g
> > boot.
> >=20
> > E.g., see drivers/acpi/tables.c:acpi_table_upgrade()->memblock_reserve(=
).
>=20
> acpi_table_upgrade() gets called, but bails out before memblock_reserve()=
 is
> called. Thus, it appears no pages are getting reserved.

acpi_table_upgrade() does not actually reserve memory but rather open
codes memblock allocation with memblock_find_in_range() +
memblock_reserve(), so it does not seem related anyway.

Do you have by chance a full boot log handy?=20
=20
> =C2=A0=C2=A0=C2=A0 503 void __init acpi_table_upgrade(void)
> =C2=A0=C2=A0=C2=A0 504 {

...

> =C2=A0=C2=A0=C2=A0 568=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if=
 (table_nr =3D=3D 0)
> =C2=A0=C2=A0=C2=A0 569=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return; =C2=A0=C2=A0=C2=A0 =
=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=
 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 <-- bails
> out here
> "drivers/acpi/tables.c"
>=20
> George
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
kasan-dev/20210222215502.GB1741768%40linux.ibm.com.
