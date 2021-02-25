Return-Path: <kasan-dev+bncBDE5LFWXQAIRBREW36AQMGQEAIPTSAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C8140325313
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 17:07:33 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id a6sf3715807plm.17
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 08:07:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614269252; cv=pass;
        d=google.com; s=arc-20160816;
        b=r7QKDZZmEa3uF+RYkgYP1FmMk7p/UB5KfT7aLVyQdropHmR9R9RlBVm2M5OH4hMTkj
         EeRDm8/dHmyBJcCzxB4pJoKWiX6+d9TDDRi6+inTQkNYv+5iBvLQseI6UWkkaUUwc9i7
         t4P2/wKe3LDWqdjh7WvHef+8NK9IJoGknVAfAU7ibW9vEs23f+D85ezn3jfOhusETv4K
         1KyNW2abIHFSQqO5XTcZqF7o2yE4fBs1BsQJaGZ3WnYuxRdBkpIIALvWfpui2BbMA4ka
         /jOZSEH8bRyo0fU8M/GWwdvMJMbwDOoN66bNGKgti/9TyrqEPL9y/4ncRThO+2rwqsqD
         uCgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UcJLQ5u2kSN/RchAS6mLoZIWC7DLx5NQLPDlP4Fhmew=;
        b=wBuCpP1F+E6RCVisTozyf9HOcKdmZiVOwp58BShPl5XH9LSqMgkTjx8vLtkdZ9XTaH
         UcHRHlimbZj47luuABW9GJWkPCXuJBf3JUtfI2SVwhzPPeBjs6JmPg+2O4L0VuXf2qu5
         WhXuDMqZx4KL8kFDrfjglwUJ2bvl+Bj1T/mrbrb7SDzia6JhXHjjjIP0qkTx3z/uV60S
         9rWo7Do26NC8QmqhODpuaAfWe/nXnF+ceNwbEkkUP4IHZDW+rmaT4WYY6UqVZ4EJhXps
         ntfTz6/NB8UNRHTjNu74fZqPtQ+deh1WaGhXLqLakYMoY84lAQuXx4pnsG7GEQPlmxZt
         gW3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=huhV46PA;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UcJLQ5u2kSN/RchAS6mLoZIWC7DLx5NQLPDlP4Fhmew=;
        b=lBjdY68Oj5lZXNDJE8LNMrDV/koGvfsPimlO4EK09BgrVe0qTLxHn7f5QZpHc39nnq
         rp5TaJphMaaFEpj9dmP8eXqt0zb9bmEoAj1uVsK3hM28XRCKTLp3r6FcBXjFf/5bfhNb
         M0MV3quqMy7SN0zxw+WE0VvOO6LnXTL6q9d3I1t3Nam4ybhX4sFd8KygY8dKnbw1Bnjt
         3fIGflPSVWqb04jjvSfHzYOmEXP0J5CGMybkDUB12aNXYONTTm2GCHfLhrnPWbC1TnsL
         dfdVzhKhBBYIet0lYmdHDY8PwkabT0MJ9DSt4DkyhO7EN7Jfclno9bZEmOkYYlw4nHrY
         nXxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UcJLQ5u2kSN/RchAS6mLoZIWC7DLx5NQLPDlP4Fhmew=;
        b=tbkck92E0X64ulCQ5wY3hmgAWeKrJY/8P2RV3ghvok6dVvaxU5mIny+CtdGBIqk6uj
         5gmU85PR1wqzgbQ10DxsnD2XHObifSOQjFPRxrL/OrAlzQgdxbtmBOxzANo7XIoo+/Ey
         9cEuAzuHlDri6swZN6WK3XAgZ7xgAhhvCje39UklSDZLF/cnq2+iJ6Kqmfj5uob8OjPx
         WYlf97e3QPgwaZuNVqI4qYYO1EnemF73mcip1wgLrtdGa0jb/FeyyVCPOf3+iAFzWKlG
         JutzmQTJx8UKqcRlYk0VcGxwj6M1qAd5dLta7WuA2uMqvaI04X4jSb/8OnvX9X6CifH3
         G9Mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530us82AiTrtuMuoXQD8T9ts3vvYN3mehR4rRV2E5q1aBwsR7o2W
	3vKkbRjckw5NTKmGxw4/IkE=
X-Google-Smtp-Source: ABdhPJzszBDH+r6+6UyJKefaGboNs/gUIFyPaOpVYkZOCSwLyVWDVEXICaKtNrPjO2ymbF6n3Z++zA==
X-Received: by 2002:a65:62c7:: with SMTP id m7mr3599493pgv.50.1614269252349;
        Thu, 25 Feb 2021 08:07:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:88b:: with SMTP id v11ls3722719pjc.1.canary-gmail;
 Thu, 25 Feb 2021 08:07:31 -0800 (PST)
X-Received: by 2002:a17:90a:3804:: with SMTP id w4mr4037120pjb.189.1614269251713;
        Thu, 25 Feb 2021 08:07:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614269251; cv=none;
        d=google.com; s=arc-20160816;
        b=G67mkQWBOuGP/NlKI0ThoDK2A1VgDerftqGYs5sTs9QFEIdozwtL6Q78VsHMy+8Jpi
         hPB761itK3vZ4wKPBFyLz8hTJuw5Su3O5OHOlBVUYmY7Pr32+TW6kIcPzzS2Lz69FvXU
         DrRYYtNXTDvFYbuliWre0i8J5Pq/hdBavK84wcRwFucybNCZRwn1jA/B8Wja8aXvekoX
         hCbsLDtUU1GnKSSRFi22jdYSha0PABE3on+StLyjLl0lS420lg/oHz18BfEkRKSJa1Ao
         44+R6zvmjRXDCWaO06ayMoHxn0RG1j7vgRUDJwU+cQuJ3yCrZgrqP4yb8USmDH3VDHeb
         DUuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Yq/02UZSE8vCULHuZGHZmGpjiIByKs4OEh4fjJendZI=;
        b=vu7nNfOpFl3em/d+c3ANk2F7dhH/K/Eebujnq/bGVlEuQ4B/1LRqmrR5qSLgvMeQKo
         JzOzVVBrll+F1mVZXhgIPNCJsVww61USovP5wwuPypEfB0GwmuNywOMV/mwTM7niAC5M
         vnOkDkQQOkqIC9vV5eyDQKsO57OXyx/yqIiJYdGzJ8b5MRyMA4ktvrhI2agxBgXaJIt5
         yonbUrLJI752vGj3laMdxmZrUaHXu2SdnYUvmVQCPkE+/wGtWnWAoVOp1KaFS8X0F2jd
         W/pe93Y0F52JKqCTpTqrQiEiPEYtF9sbnvUui2tjO/cWeu3r4Fiimg3htkvTTrP4aicN
         NmPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=huhV46PA;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id z13si583950pju.1.2021.02.25.08.07.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 08:07:31 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098419.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11PG2VXp145227;
	Thu, 25 Feb 2021 11:07:17 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 36xeec1tws-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 11:07:16 -0500
Received: from m0098419.ppops.net (m0098419.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11PG2fTw146394;
	Thu, 25 Feb 2021 11:07:15 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0b-001b2d01.pphosted.com with ESMTP id 36xeec1tvr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 11:07:15 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11PG2GG1008731;
	Thu, 25 Feb 2021 16:07:13 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma06ams.nl.ibm.com with ESMTP id 36tsph4khq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 25 Feb 2021 16:07:13 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11PG7Bp949545482
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 16:07:11 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3EA77AE053;
	Thu, 25 Feb 2021 16:07:11 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DB5C1AE057;
	Thu, 25 Feb 2021 16:07:08 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 25 Feb 2021 16:07:08 +0000 (GMT)
Date: Thu, 25 Feb 2021 18:07:06 +0200
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
Message-ID: <20210225160706.GD1854360@linux.ibm.com>
References: <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-25_09:2021-02-24,2021-02-25 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 priorityscore=1501 phishscore=0 clxscore=1015 spamscore=0 mlxlogscore=999
 suspectscore=0 bulkscore=0 adultscore=0 malwarescore=0 mlxscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102250127
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=huhV46PA;       spf=pass (google.com:
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

On Thu, Feb 25, 2021 at 10:22:44AM -0500, George Kennedy wrote:
>=20
> > > > > On 2/24/2021 5:37 AM, Mike Rapoport wrote:
>
> Applied just your latest patch, but same failure.
>=20
> I thought there was an earlier comment (which I can't find now) that stat=
ed
> that memblock_reserve() wouldn't reserve the page, which is what's needed
> here.

Actually, I think that memblock_reserve() should be just fine, but it seems
I'm missing something in address calculation each time.

What would happen if you stuck

	memblock_reserve(0xbe453000, PAGE_SIZE);

say, at the beginning of find_ibft_region()?
=20
> [=C2=A0=C2=A0 30.308229] iBFT detected..
> [=C2=A0=C2=A0 30.308796]
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [=C2=A0=C2=A0 30.308890] BUG: KASAN: use-after-free in ibft_init+0x134/0x=
c33
> [=C2=A0=C2=A0 30.308890] Read of size 4 at addr ffff8880be453004 by task =
swapper/0/1
> [=C2=A0=C2=A0 30.308890]
> [=C2=A0=C2=A0 30.308890] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.11.0=
-f9593a0 #12
> [=C2=A0=C2=A0 30.308890] Hardware name: QEMU Standard PC (i440FX + PIIX, =
1996), BIOS
> 0.0.0 02/06/2015
> [=C2=A0=C2=A0 30.308890] Call Trace:
> [=C2=A0=C2=A0 30.308890]=C2=A0 dump_stack+0xdb/0x120
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> [=C2=A0=C2=A0 30.308890]=C2=A0 print_address_description.constprop.7+0x41=
/0x60
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> [=C2=A0=C2=A0 30.308890]=C2=A0 kasan_report.cold.10+0x78/0xd1
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
> [=C2=A0=C2=A0 30.308890]=C2=A0 __asan_report_load_n_noabort+0xf/0x20
> [=C2=A0=C2=A0 30.308890]=C2=A0 ibft_init+0x134/0xc33
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
> [=C2=A0=C2=A0 30.308890]=C2=A0 do_one_initcall+0xc4/0x3e0
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? perf_trace_initcall_level+0x3e0/0x3e0
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? unpoison_range+0x14/0x40
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ____kasan_kmalloc.constprop.5+0x8f/0xc0
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? kernel_init_freeable+0x420/0x652
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __kasan_kmalloc+0x9/0x10
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init_freeable+0x596/0x652
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? console_on_rootfs+0x7d/0x7d
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
> [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init+0x16/0x1d0
> [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
> [=C2=A0=C2=A0 30.308890]=C2=A0 ret_from_fork+0x22/0x30
> [=C2=A0=C2=A0 30.308890]
> [=C2=A0=C2=A0 30.308890] The buggy address belongs to the page:
> [=C2=A0=C2=A0 30.308890] page:0000000001b7b17c refcount:0 mapcount:0
> mapping:0000000000000000 index:0x1 pfn:0xbe453
> [=C2=A0=C2=A0 30.308890] flags: 0xfffffc0000000()
> [=C2=A0=C2=A0 30.308890] raw: 000fffffc0000000 ffffea0002ef9788 ffffea000=
2f91488
> 0000000000000000
> [=C2=A0=C2=A0 30.308890] raw: 0000000000000001 0000000000000000 00000000f=
fffffff
> 0000000000000000
> [=C2=A0=C2=A0 30.308890] page dumped because: kasan: bad access detected
> [=C2=A0=C2=A0 30.308890] page_owner tracks the page as freed
> [=C2=A0=C2=A0 30.308890] page last allocated via order 0, migratetype Mov=
able,
> gfp_mask 0x100dca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO), pid 204, ts 281212886=
05
> [=C2=A0=C2=A0 30.308890]=C2=A0 prep_new_page+0xfb/0x140
> [=C2=A0=C2=A0 30.308890]=C2=A0 get_page_from_freelist+0x3503/0x5730
> [=C2=A0=C2=A0 30.308890]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
> [=C2=A0=C2=A0 30.308890]=C2=A0 alloc_pages_vma+0xe2/0x560
> [=C2=A0=C2=A0 30.308890]=C2=A0 __handle_mm_fault+0x930/0x26c0
> [=C2=A0=C2=A0 30.308890]=C2=A0 handle_mm_fault+0x1f9/0x810
> [=C2=A0=C2=A0 30.308890]=C2=A0 do_user_addr_fault+0x6f7/0xca0
> [=C2=A0=C2=A0 30.308890]=C2=A0 exc_page_fault+0xaf/0x1a0
> [=C2=A0=C2=A0 30.308890]=C2=A0 asm_exc_page_fault+0x1e/0x30
> [=C2=A0=C2=A0 30.308890] page last free stack trace:
> [=C2=A0=C2=A0 30.308890]=C2=A0 free_pcp_prepare+0x122/0x290
> [=C2=A0=C2=A0 30.308890]=C2=A0 free_unref_page_list+0xe6/0x490
> [=C2=A0=C2=A0 30.308890]=C2=A0 release_pages+0x2ed/0x1270
> [=C2=A0=C2=A0 30.308890]=C2=A0 free_pages_and_swap_cache+0x245/0x2e0
> [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_flush_mmu+0x11e/0x680
> [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_finish_mmu+0xa6/0x3e0
> [=C2=A0=C2=A0 30.308890]=C2=A0 exit_mmap+0x2b3/0x540
> [=C2=A0=C2=A0 30.308890]=C2=A0 mmput+0x11d/0x450
> [=C2=A0=C2=A0 30.308890]=C2=A0 do_exit+0xaa6/0x2d40
> [=C2=A0=C2=A0 30.308890]=C2=A0 do_group_exit+0x128/0x340
> [=C2=A0=C2=A0 30.308890]=C2=A0 __x64_sys_exit_group+0x43/0x50
> [=C2=A0=C2=A0 30.308890]=C2=A0 do_syscall_64+0x37/0x50
> [=C2=A0=C2=A0 30.308890]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9
> [=C2=A0=C2=A0 30.308890]
> [=C2=A0=C2=A0 30.308890] Memory state around the buggy address:
> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f00: ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
> ff ff
> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f80: ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
> ff ff
> [=C2=A0=C2=A0 30.308890] >ffff8880be453000: ff ff ff ff ff ff ff ff ff ff=
 ff ff ff ff
> ff ff
> [=C2=A0=C2=A0 30.308890]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453080: ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
> ff ff
> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453100: ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
> ff ff
> [=C2=A0=C2=A0 30.308890]
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
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
kasan-dev/20210225160706.GD1854360%40linux.ibm.com.
