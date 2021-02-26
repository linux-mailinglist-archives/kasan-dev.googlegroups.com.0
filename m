Return-Path: <kasan-dev+bncBDE5LFWXQAIRBZVR4OAQMGQE63VX4UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A5993261DF
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 12:17:59 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id o20sf5919495pgu.16
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 03:17:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614338278; cv=pass;
        d=google.com; s=arc-20160816;
        b=GbLWpE3u+I+u9BS6+w7AXmvm/0fMEMOASP3foNbD6AMj4VliTxO4A1uaLFOd7xV+Rf
         9cT/gmsnSGXNz+JtokEGD/8NkCZAAM8HkMxywGX84SAUZ/hWSfMM3L0/illsmSNpdSFo
         1SXIs529m8XvhHQKIaRpk5s04qtXladqOoMsojYE7MWaFoPkmImyFJIcDPn2nu636hcv
         XnWpvENcODN0cegZGcEHMHBU4ZnC+MD4ILgj+onTP2ATV5oWkSft2wLWNQUjY82QFc8/
         bztWQMfd+U92wdR9XRy7Xw96fgC+ewovF/t+ZPQlSiUPVv+DW4lLgwEr3a6mhgLZSw1m
         8hDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=33ptlY/bVXm/uiCsgrhP/rmxwAAq0jTASipRQEMtCcE=;
        b=bO+wxLG5MmKk9Nm3FIxJGmfsgNOke55rldodoFgDOOx8yFeQXe6r5I4tVBo8Ra+v8h
         D/8fii+axL82XCK7Vr/tXuRkIs2Lk/7+X5L6s4ED5ayk/3t8qQFRny1C5UWk5ARn0mSM
         xz2I4DSCjYGTfv7MACxxUqRr2FfKdtCfhcQtVKnnXIpyygO+sI52tj3tkAycOzw1H4Mq
         AeTQkLjE+e0IH1oA/+oJs9SCJuu9mOWZgDJnrjB67cLsOAcNQgs2D49EqxyQbLsy5Evr
         GJj6D+5pEa9a3yZIdM3qPZpxVD9eYsSVv/KvtjxK5jlMzxarBvmCjbSeCR0ewPvKRMKH
         2S9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EbjwnvBb;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=33ptlY/bVXm/uiCsgrhP/rmxwAAq0jTASipRQEMtCcE=;
        b=p7fQHVLJPsu/abO2JlaV0w696sZ9OLAKeni1kgicaD+uhF/oPQ3/2iJ0j8QWj7/ChE
         XRNB1mjN6Y6z0ZRGjRuu0Gvd1NvLPXC9OWDsTJ7rrbLIDX8qw6N1w+ZfDMgDdjWkp/Ai
         ZF4SQnh7JVg4XwFpJSPsNruSkYawwAfZkpzFleqk+KMvc0lWNY/QNp11dO6XLaiRObNq
         r6biK1AwhpLrdZFokQe3pf5b1t/IfH1cNmyCex05wmuUUjf3z3vRLBGZ4CLoJFhcVFiT
         wHCfQDU0GIXEvJHO/yb/efJWCf7XZTDkubxb4mQ9i82wh3ZRtXSdGUY3V6MhSCJeeLc6
         LPbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=33ptlY/bVXm/uiCsgrhP/rmxwAAq0jTASipRQEMtCcE=;
        b=ZpZROehTDxkLgUwb0y3OoEB2pf+c+7KHtYWfYEgNzCnJmr0/eNNpljGdaZNtSv5XdH
         fNLeX5IL5J2JRtrX9bsRo5EQqaDjAlM3Se6/99OZfXAFMcs0WaOG3Ng5RnG2jf0gZ/Ib
         53Lwt1Vk4Rd0SXy9gheg+QSIEp3cXLG2ZZ+MZA1AD3/yWM5e8IyQ5+fl9xMvoKZplw9h
         A7YdQR/zO9d4zihlOn29hddfWOXumsgz7oq8AAYiN+csNcvyBNBm7BwnCZQCa649nP8t
         QhD9HvB8kxT+M3EiFW24ql3Xceqj5ONmtQaL4BIBz9rIG4PeUizvJfqzhqkxuvGfQHIU
         JoVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532da5k7c+iEKRWNHMwdUisp+5LL13/Efj5qAt93so3EfaOYa+IF
	V3uRaujoEBdF3sd6chJ8jcA=
X-Google-Smtp-Source: ABdhPJyPSTi8zsBNs67/VcpDsFiBXp/njnJ5VsWTrfa74tm3Xr254b3LtSJLF2hsnIv/gpxngYFtbQ==
X-Received: by 2002:a62:2f83:0:b029:1ec:48b2:73da with SMTP id v125-20020a622f830000b02901ec48b273damr2735497pfv.1.1614338278234;
        Fri, 26 Feb 2021 03:17:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:842:: with SMTP id q2ls3879182pfk.0.gmail; Fri, 26
 Feb 2021 03:17:57 -0800 (PST)
X-Received: by 2002:a62:2b0d:0:b029:1ed:55cc:25d9 with SMTP id r13-20020a622b0d0000b02901ed55cc25d9mr2773557pfr.54.1614338277716;
        Fri, 26 Feb 2021 03:17:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614338277; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+2Q/AFEh++2b4rorjaydvKRxZfzn2YCVd/gFu6vL6Z0g3kz4uaCgR9ByHhXKDXO3E
         I02Wxkmde517KW8cBdwLOR6FiNby3qqGYTiNg/G8rzRXbV9cOqKkGBGVADzJFF6CvCGo
         UCiZDNc0Ym/YQyPUHiaZGBtIHil71QFU0XOBgej0dA9PuZHjG3kOx3/RDqZn7NXDFX6N
         rcU3ZFGLUhFzo1AShgnuE4GUQJ07t/g9sx/v7JBZx8uHI8dCDDa2IbGNWmhaRgDjMEeJ
         /84uUZU8UMdDB15GMdLXqrgTIAYJ4CnejTODhGdQbmPeqihOKmWfsPEURd3fLnmupjLW
         BQ/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yhvr1Xkbh7XOwtOWAyA3QzMCb183Bb/rbHDxBvE6E48=;
        b=kZSbfhHMFZhxecRHpjK8e07zfzmUkFqVZs/+OBVtgSKnMDFzWUclLrh12tq4yzF0xf
         fJiNDnI1FZ0in8CIsfb0BdNM5snq4UJF2NNfSfsxbkNgLHT6cP1/CoQTfH9lqgAFESb4
         tDK8bStmeqYoW7qaMRMgdsRvYWl+3edxgGDnGN0/F2p/fAkKWzI6U/I6etx2MGVY7JAa
         1Yz/t5/Vc/R18U21g95s65dueegBLjfi5xVsM7a2zco6ozst2jw3AWsi0qjsSkNe8OkM
         z+1ffwnRfFOGw6OWosh4NVtz6nLa0arDEYHbh3uCKxEtHsZn5aTdgQExL1VnXda38twn
         NJag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EbjwnvBb;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id n10si479102pgq.2.2021.02.26.03.17.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Feb 2021 03:17:57 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11QB3jwR080096;
	Fri, 26 Feb 2021 06:17:39 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xphuq02m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 26 Feb 2021 06:17:39 -0500
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11QB41fZ082178;
	Fri, 26 Feb 2021 06:17:39 -0500
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36xphuq01k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 26 Feb 2021 06:17:39 -0500
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11QBGZHP032136;
	Fri, 26 Feb 2021 11:17:36 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma04ams.nl.ibm.com with ESMTP id 36tt28d7bu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 26 Feb 2021 11:17:36 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11QBHYHX35913984
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 26 Feb 2021 11:17:34 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 547BFAE04D;
	Fri, 26 Feb 2021 11:17:34 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 26B05AE056;
	Fri, 26 Feb 2021 11:17:32 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Fri, 26 Feb 2021 11:17:32 +0000 (GMT)
Date: Fri, 26 Feb 2021 13:17:30 +0200
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
Message-ID: <20210226111730.GL1854360@linux.ibm.com>
References: <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
 <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-26_02:2021-02-24,2021-02-26 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxlogscore=999
 malwarescore=0 suspectscore=0 priorityscore=1501 phishscore=0 spamscore=0
 bulkscore=0 mlxscore=0 impostorscore=0 clxscore=1015 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102260085
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EbjwnvBb;       spf=pass (google.com:
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

On Thu, Feb 25, 2021 at 08:19:18PM -0500, George Kennedy wrote:
>=20
> Mike,
>=20
> To get rid of the 0x00000000BE453000 hardcoding, I added the following pa=
tch
> to your above patch to get the iBFT table "address" to use with
> memblock_reserve():
>=20
> diff --git a/drivers/acpi/acpica/tbfind.c b/drivers/acpi/acpica/tbfind.c
> index 56d81e4..4bc7bf3 100644
> --- a/drivers/acpi/acpica/tbfind.c
> +++ b/drivers/acpi/acpica/tbfind.c
> @@ -120,3 +120,34 @@
> =C2=A0=C2=A0=C2=A0=C2=A0 (void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
> =C2=A0=C2=A0=C2=A0=C2=A0 return_ACPI_STATUS(status);
> =C2=A0}
> +
> +acpi_physical_address
> +acpi_tb_find_table_address(char *signature)
> +{
> +=C2=A0=C2=A0=C2=A0 acpi_physical_address address =3D 0;
> +=C2=A0=C2=A0=C2=A0 struct acpi_table_desc *table_desc;
> +=C2=A0=C2=A0=C2=A0 int i;
> +
> +=C2=A0=C2=A0=C2=A0 ACPI_FUNCTION_TRACE(tb_find_table_address);
> +
> +printk(KERN_ERR "XXX acpi_tb_find_table_address: signature=3D%s\n",
> signature);
> +
> +=C2=A0=C2=A0=C2=A0 (void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
> +=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < acpi_gbl_root_table_list.current_ta=
ble_count; ++i) {
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (memcmp(&(acpi_gbl_root_table_l=
ist.tables[i].signature),
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 si=
gnature, ACPI_NAMESEG_SIZE)) {
> +
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 /* Not the requ=
ested table */
> +
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 continue;
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
> +
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 /* Table with matching signature h=
as been found */
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 table_desc =3D &acpi_gbl_root_tabl=
e_list.tables[i];
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 address =3D table_desc->address;
> +=C2=A0=C2=A0=C2=A0 }
> +
> +=C2=A0=C2=A0=C2=A0 (void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
> +printk(KERN_ERR "XXX acpi_tb_find_table_address(EXIT): address=3D%llx\n"=
,
> address);
> +=C2=A0=C2=A0=C2=A0 return address;
> +}
> diff --git a/drivers/firmware/iscsi_ibft_find.c
> b/drivers/firmware/iscsi_ibft_find.c
> index 95fc1a6..0de70b4 100644
> --- a/drivers/firmware/iscsi_ibft_find.c
> +++ b/drivers/firmware/iscsi_ibft_find.c
> @@ -28,6 +28,8 @@
>=20
> =C2=A0#include <asm/mmzone.h>
>=20
> +extern acpi_physical_address acpi_tb_find_table_address(char *signature)=
;
> +
> =C2=A0/*
> =C2=A0 * Physical location of iSCSI Boot Format Table.
> =C2=A0 */
> @@ -116,24 +118,32 @@ void __init reserve_ibft_region(void)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_ibft *table;
> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long size;
> +=C2=A0=C2=A0=C2=A0 acpi_physical_address address;
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 table =3D find_ibft();
> =C2=A0=C2=A0=C2=A0=C2=A0 if (!table)
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0 size =3D PAGE_ALIGN(table->header.length);
> +=C2=A0=C2=A0=C2=A0 address =3D acpi_tb_find_table_address(table->header.=
signature);
> =C2=A0#if 0
> =C2=A0printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,
> virt_to_phys(table)=3D%llx, size=3D%lx\n",
> =C2=A0=C2=A0=C2=A0=C2=A0 (u64)table, virt_to_phys(table), size);
> =C2=A0=C2=A0=C2=A0=C2=A0 memblock_reserve(virt_to_phys(table), size);
> =C2=A0#else
> -printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx, 0x00000000BE4530=
00,
> size=3D%lx\n",
> -=C2=A0=C2=A0=C2=A0 (u64)table, size);
> -=C2=A0=C2=A0=C2=A0 memblock_reserve(0x00000000BE453000, size);
> +printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx, address=3D%llx,
> size=3D%lx\n",
> +=C2=A0=C2=A0=C2=A0 (u64)table, address, size);
> +=C2=A0=C2=A0=C2=A0 if (address)
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 memblock_reserve(address, size);
> +=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 printk(KERN_ERR "%s: Can't find ta=
ble address\n", __func__);
> =C2=A0#endif
>=20
> -=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT))
> +=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT)) {
> +printk(KERN_ERR "XXX reserve_ibft_region: calling acpi_put_table(%llx)\n=
",
> (u64)&table->header);
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 acpi_put_table(&table->header=
);
> -=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0 } else {
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D table;
> +printk(KERN_ERR "XXX reserve_ibft_region: ibft_addr=3D%llx\n",
> (u64)ibft_addr);
> +=C2=A0=C2=A0=C2=A0 }
> =C2=A0}
>=20
> Debug from the above:
> [=C2=A0=C2=A0=C2=A0 0.050646] ACPI: Early table checksum verification dis=
abled
> [=C2=A0=C2=A0=C2=A0 0.051778] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 B=
OCHS )
> [=C2=A0=C2=A0=C2=A0 0.052922] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 B=
OCHS BXPCFACP
> 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.054623] ACPI: FACP 0x00000000BFBF5000 000074 (v01 B=
OCHS BXPCFACP
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.056326] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 B=
OCHS BXPCDSDT
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.058016] ACPI: FACS 0x00000000BFBFD000 000040
> [=C2=A0=C2=A0=C2=A0 0.058940] ACPI: APIC 0x00000000BFBF4000 000090 (v01 B=
OCHS BXPCAPIC
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.060627] ACPI: HPET 0x00000000BFBF3000 000038 (v01 B=
OCHS BXPCHPET
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.062304] ACPI: BGRT 0x00000000BE49B000 000038 (v01 I=
NTEL EDK2=C2=A0=C2=A0=C2=A0=C2=A0
> 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.063987] ACPI: iBFT 0x00000000BE453000 000800 (v01 B=
OCHS BXPCFACP
> 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
> [=C2=A0=C2=A0=C2=A0 0.065683] XXX acpi_tb_find_table_address: signature=
=3DiBFT
> [=C2=A0=C2=A0=C2=A0 0.066754] XXX acpi_tb_find_table_address(EXIT): addre=
ss=3Dbe453000
> [=C2=A0=C2=A0=C2=A0 0.067959] XXX reserve_ibft_region: table=3Dffffffffff=
240000,
> address=3Dbe453000, size=3D1000
> [=C2=A0=C2=A0=C2=A0 0.069534] XXX reserve_ibft_region: calling
> acpi_put_table(ffffffffff240000)
>=20
> Not sure if it's the right thing to do, but added
> "acpi_tb_find_table_address()" to return the physical address of a table =
to
> use with memblock_reserve().
>=20
> virt_to_phys(table) does not seem to return the physical address for the
> iBFT table (it would be nice if struct acpi_table_header also had a
> "address" element for the physical address of the table).

virt_to_phys() does not work that early because then it is mapped with
early_memremap()  which uses different virtual to physical scheme.

I'd say that acpi_tb_find_table_address() makes sense if we'd like to
reserve ACPI tables outside of drivers/acpi.=20

But probably we should simply reserve all the tables during
acpi_table_init() so that any table that firmware put in the normal memory
will be surely reserved.
=20
> Ran 10 successful boots with the above without failure.

That's good news indeed :)

> George
> >=20
> >=20

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210226111730.GL1854360%40linux.ibm.com.
