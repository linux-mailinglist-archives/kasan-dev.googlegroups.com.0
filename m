Return-Path: <kasan-dev+bncBDE5LFWXQAIRB6GC36AQMGQEDTEYB4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 036C53254A3
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 18:42:18 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id jx12sf1916101pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:42:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614274936; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0bTVNWe4+76Fm+slZLim2aLIhffIwCNj9Nqf2zXeJF0wllXhLIYX0YHO0fKsjJ/E5
         EqYUye/EK5RXfyrbVLYLTGJkDilHChkhfkwZfL1oXQzSnOwbXmOD1HILAG1mXpZMBGSy
         I7YJPeZVJfg5AMglDc9IzEj9UTvGYtWYRnz22aUXh82uPvX7cgvIrUKMbJyLHbZEfO2t
         YiQr8sXk5OL2UMj3J/YVlcCb+rapvbiMWvn0hl44CsgeikkEHiiFCRkA7q5xMnOYO4AJ
         SZsRMqlfazorOUUfOs1iIGT9wGFQmAdZtt6BvzWiialB1QQYJd3zHsILZcm2aR7GKmhs
         A9kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=9LNxzCj7IIrNAi19CCpnWBzUMdN5RCK/FHE1TM1X+LE=;
        b=xDFLNSo82FdlKdo8iWW7Xef49JScMeJSvVNGRyqF0LO2peU9LSRnFQm8dmDRw+pLLg
         yi8Ygr8Ygp+gjNMdjGf0Fc0Luz/eENV0t0RHx0exWVYeXW5dn8PfRdzKCvLQBltQRwu1
         hXAcTrJGTD/iOaRJZNfo5eePaYsJ63ESL6MxGyr2Ql5/kZ7HmbVb4r64Hnce1EB96DMH
         aWACxD2ZRL05yuSWS0sTuUDBWzIxuOwedhho7rTHZikAQMBrpxWONMIr44tsxRiM9EhX
         PoDqnbUWxhNBG8CsVLoN8Bu3+E53ZRoaVYwa7gngvu2a1WA+xbx8w0l023f/4x6Tkkkg
         A4xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=irXn9tef;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9LNxzCj7IIrNAi19CCpnWBzUMdN5RCK/FHE1TM1X+LE=;
        b=eIiLhflUY7WgOKF1JpY5Pe4LiiILbugFvjt4dsfI15H7dcUfXyU1bvwu9M1JC/Lzpj
         OuPTw+hHRvvd2R4oKsbRTCJE/TIydkwwuDmpBpOR/27EoZoax2d+fXBcrvyiTWGH2sH9
         /jv0jfNyqR9M+3SN4Nzue2DD58PbdYsYw9tqlL8gTWl723vNos3P5KNJ8xgH+u3TSK3p
         rEwVGTR8Mqe6ZTfAv3e4a5lkgzc/2cl8nnnZxzJSeL2Nc7Jaws1KpkhEgiWfSeyD1Zyd
         rm7T74+zFHVuXawSUKx5Baic40y6T01TioSysK2peUVialZABx0P+rIicf6ifOA3xK0Z
         kfvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9LNxzCj7IIrNAi19CCpnWBzUMdN5RCK/FHE1TM1X+LE=;
        b=CQj9ODVUEa7/HgDdGdsNB6BLgLEPliHo3GDqOrhebE6j9TQ8PQIFCq6sjdHXj7+Vbw
         ZlWyhrjG++RJGIQtlC/h64qFnxfD47WmpGfzQdJSmSH++HPemlFM4CW/Bminfsd5lnQT
         +Nyyqsp7PIDV3kSxf8BODWc9P0HzSaIBtd5gKGkGEFMO56ROF86cY19X/wD+gg42GPfq
         y/Ryg69/UcMSr5abKH2NszTSdt5In2bgLP36WI3pwfzSPsACBzG7MbyLzuDSqKZovLr3
         6WxTbTiEwAj04I0c7KosB3LWmXZJpp6YH6mAvrupFBBE5xftfoF6UKFjrXkfHzVyc+4G
         UsGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310nTJNGQBUy8V71ux8+mHhgJoYTpmku3ifc7h9+O5ZGE61j9c6
	2ThUrX8op5fHPgcdN6QNxf0=
X-Google-Smtp-Source: ABdhPJxN396RjoiNp8BPS6cdQpSYNHsm0TQ323NVDiGCSwFxG4UXeP2bnD5eN23tdtJRKi+HFG745A==
X-Received: by 2002:a17:90a:72c4:: with SMTP id l4mr4480438pjk.52.1614274936575;
        Thu, 25 Feb 2021 09:42:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba17:: with SMTP id s23ls3839286pjr.3.canary-gmail;
 Thu, 25 Feb 2021 09:42:16 -0800 (PST)
X-Received: by 2002:a17:90b:696:: with SMTP id m22mr4325341pjz.67.1614274935925;
        Thu, 25 Feb 2021 09:42:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614274935; cv=none;
        d=google.com; s=arc-20160816;
        b=mgGxKdOc5+NJLdM1UzaFIO2b26oZWY+foKOgTDMP/K9/FXI02rMqvnR1jEPKSH74SN
         Vs5Z8EjAsKoLjTrlZTiIjOgh3I5wYbyzT1Uki7dXJNreYnTQ2U7iGAIutDHzTWh+iyHc
         H4jjgg8El2oEOmKo/FeYrpz47DmVVXzkwBOWj+Im2+YihhI9NG7kA90jKHPdi+DQPegC
         adoMSE7TBq4ETAH1OjGoKlRGG7K4lNYuW35Kv8S300ODNSM5iT0nnRDgw34853nyEdCD
         cDQxD++Zn3FZb+cCOfMvBhnz6Jsu8uZr3arJ9Da27WMUKpW7qTtkyTQeglsKp9Qm6WnB
         vp9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/nWMJgwtZ7Cm8sF4GEYJiUOZKiRImRLfYOx8gpJxRys=;
        b=S1n/rVS+12dHctwYuU2j/tC+wpdXeO0Jw8WetGPtzeR9x1jxgHOaHY48A/B5n9Hdng
         /MmTll7S7Lsu0GNNAvoFAd3cHDAH+oNl11ipXp3OFvyWCFJMwD/nHY3IY+KFCCAHsnsY
         3SRKWn+BV3ewCOJ+Hh0hIUYRxlOK2EkJgKg3AnfRMA973/qEWjtGM0GaUMuro0EI3YDV
         yfHXhFSFDm9J8IyIAqO04Nz9zyKjgmzp+5HDrJFI9AlQy7EdQhB+K2tdv+njtm3A28BP
         sm5yT9yQXUDzUYu+74PKTuixbI36V1ET5eJ7lL3fklVtYdwFDG/aRi8uvCQr5cV8JNcN
         qO6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=irXn9tef;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id n2si383799pjp.2.2021.02.25.09.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 09:42:15 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098410.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11PHWmPL004083;
	Thu, 25 Feb 2021 12:42:00 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xfcxadey-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 12:42:00 -0500
Received: from m0098410.ppops.net (m0098410.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11PHfx3A039690;
	Thu, 25 Feb 2021 12:41:59 -0500
Received: from ppma01fra.de.ibm.com (46.49.7a9f.ip4.static.sl-reverse.com [159.122.73.70])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xfcxade2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 12:41:59 -0500
Received: from pps.filterd (ppma01fra.de.ibm.com [127.0.0.1])
	by ppma01fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11PHbiII007103;
	Thu, 25 Feb 2021 17:41:57 GMT
Received: from b06cxnps3074.portsmouth.uk.ibm.com (d06relay09.portsmouth.uk.ibm.com [9.149.109.194])
	by ppma01fra.de.ibm.com with ESMTP id 36tt28aehq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 17:41:57 +0000
Received: from d06av23.portsmouth.uk.ibm.com (d06av23.portsmouth.uk.ibm.com [9.149.105.59])
	by b06cxnps3074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11PHfsg026280326
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 17:41:54 GMT
Received: from d06av23.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CAB1CA4040;
	Thu, 25 Feb 2021 17:41:54 +0000 (GMT)
Received: from d06av23.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6E755A4057;
	Thu, 25 Feb 2021 17:41:52 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av23.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 25 Feb 2021 17:41:52 +0000 (GMT)
Date: Thu, 25 Feb 2021 19:41:50 +0200
From: Mike Rapoport <rppt@linux.ibm.com>
To: David Hildenbrand <david@redhat.com>
Cc: George Kennedy <george.kennedy@oracle.com>,
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
Message-ID: <20210225174150.GF1854360@linux.ibm.com>
References: <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <dcf821e8-768f-1992-e275-2f1ade405025@oracle.com>
 <24e43280-1442-3c4e-aa57-ac84b987aa58@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <24e43280-1442-3c4e-aa57-ac84b987aa58@redhat.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-25_10:2021-02-24,2021-02-25 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 phishscore=0
 mlxscore=0 spamscore=0 priorityscore=1501 impostorscore=0 clxscore=1015
 malwarescore=0 adultscore=0 mlxlogscore=999 lowpriorityscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102250133
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=irXn9tef;       spf=pass (google.com:
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

On Thu, Feb 25, 2021 at 06:23:24PM +0100, David Hildenbrand wrote:
> On 25.02.21 17:31, George Kennedy wrote:
> > : rsdp_address=3Dbfbfa014
> > [=C2=A0=C2=A0=C2=A0 0.066612] ACPI: RSDP 0x00000000BFBFA014 000024 (v02=
 BOCHS )
> > [=C2=A0=C2=A0=C2=A0 0.067759] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01=
 BOCHS BXPCFACP
> > 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> > [=C2=A0=C2=A0=C2=A0 0.069470] ACPI: FACP 0x00000000BFBF5000 000074 (v01=
 BOCHS BXPCFACP
> > 00000001 BXPC 00000001)
> > [=C2=A0=C2=A0=C2=A0 0.071183] ACPI: DSDT 0x00000000BFBF6000 00238D (v01=
 BOCHS BXPCDSDT
> > 00000001 BXPC 00000001)
> > [=C2=A0=C2=A0=C2=A0 0.072876] ACPI: FACS 0x00000000BFBFD000 000040
> > [=C2=A0=C2=A0=C2=A0 0.073806] ACPI: APIC 0x00000000BFBF4000 000090 (v01=
 BOCHS BXPCAPIC
> > 00000001 BXPC 00000001)
> > [=C2=A0=C2=A0=C2=A0 0.075501] ACPI: HPET 0x00000000BFBF3000 000038 (v01=
 BOCHS BXPCHPET
> > 00000001 BXPC 00000001)
> > [=C2=A0=C2=A0=C2=A0 0.077194] ACPI: BGRT 0x00000000BE49B000 000038 (v01=
 INTEL EDK2
> > 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> > [=C2=A0=C2=A0=C2=A0 0.078880] ACPI: iBFT 0x00000000BE453000 000800 (v01=
 BOCHS BXPCFACP
> > 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
>=20
>=20
> Can you explore the relevant area using the page-flags tools (located in
> Linux src code located in tools/vm/page-flags.c)
>=20
>=20
> ./page-types -L -r -a 0xbe490,0xbe4a0

These are not iBFT and they are "ACPI data", so we should have them as
PG_Reserved set at init_unavailable_mem().


[    0.000000] BIOS-e820: [mem 0x0000000000808000-0x000000000080ffff] usabl=
e
[    0.000000] BIOS-e820: [mem 0x0000000000810000-0x00000000008fffff] ACPI =
NVS
[    0.000000] BIOS-e820: [mem 0x0000000000900000-0x00000000be49afff] usabl=
e

                               ^ iBFT@0xbe453 lives here ^=20

And it should be a normal page, as it's in "usable" memory and nothing
reserves it at boot, so no reason it won't be freed to buddy.

If iBFT was in the low memory (<1M) it would have been reserved by
reserve_ibft_region(), but with ACPI any block not marked by BIOS as "ACPI
something" is treated like a normal memory and there is nothing that
reserves it.

So we do need to memblock_reserve() iBFT region, but I still couldn't find
the right place to properly get its address without duplicating ACPI tables
parsing :(

[    0.000000] BIOS-e820: [mem 0x00000000be49b000-0x00000000be49bfff] ACPI =
data




--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210225174150.GF1854360%40linux.ibm.com.
