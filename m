Return-Path: <kasan-dev+bncBCVZXJXP4MDBBSUE6W5QMGQEFSTWZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8417FA0439D
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2025 16:03:43 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2efc3292021sf36127071a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2025 07:03:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736262219; cv=pass;
        d=google.com; s=arc-20240605;
        b=AEwEoj8TASsXY9EI9bVsox5MAapI/iacjotCS03g1R+xKCgzcdCk/WGbT6GN0WooCH
         MgW2jB9+as1dBRS2IxIoB6c5PrArbDe8NnfXtOgetXYTOOKtT4EX8tSsq6M1BVdEISD1
         LViYEDNYrRRX6cPRiJj0x9puCawlgfvjf+6JYphxswsGhZ5ZJZRU7hgAucrt+7bjsnu5
         hCZKfBKqfdA4rzYWuFyid+ReAFLFkrUx9UbC70eLKmEvDbwYze3/ig3ITRwz8jzJHMr6
         3Gp17ghYnwphMpBWo7Ka9hJfl2klfWgrLtpVSFceznzEE7usZSWQ4VLS9aBHb3yB4auL
         jong==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6iA/eJ2Z1bXUwN1n/XAkUWrPKOOCF7+18eRxIP2jXvg=;
        fh=L/GVURxZL/yq5TaeAw93k48SBrqXhhy5EN5wlDF90FA=;
        b=UKSxhPtv04+NY9fJVRiBNOHaUOGqLNjc+FAOr2CEmMVCpX/YGUOsDCnHjk7P4BHay3
         6PuIm/pxPqeV5+KtCbuzPsRGo4APCjsKCotOXEZVuK/FPPc2+87mTi3WD+uCYn22dPRB
         +zwxGDvEV+t1Q9QL2NDVeIP+Qzj6rj69zLg/cquOEdiRpnXbEtnU6nmbIgw7p72WTljc
         p/9H9iH3K6qVGajnMQxIDJdvMlhWa/RBe1QHqjamtM4X6Rlu0xIpnCO1PsZV3aLXVit+
         vbVjH5tTtub4GrjDexGNe8nKWWNr0An2zMDklNMnpiTDzc9TwxBF+vZWsRsZz8XNeanh
         i41g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rdj4BTKq;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736262219; x=1736867019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6iA/eJ2Z1bXUwN1n/XAkUWrPKOOCF7+18eRxIP2jXvg=;
        b=UFWJ7T3S+U2JtkxpsEUtL+5401LCYd8AHUmdUI612LBnoNm5nA/GhTYCf3i7V60+S5
         K+dPESMib1nMB7X37AVCSfYdfs14yPv9E8FeRexMnIkW2d495fyIe2747X9qCbWBdd7T
         a6oKmGJ12Hhs1DHpHPNgdisFRf3cZ8c7hmtPgvRgh5d5GAP4Ju5ahhYeIyb+TGlJgDE/
         GCAaU/YQdCcjghUOBX5qHdeBOL4w5fYlc4O/1wTsw9o2IwtY9llTI9WXNqWLHL/xQBfB
         OUUsBXAqCuoWK56Lv8csWblPzqyPzrn5SP5tuQPGrwPHxV31a+8BuPCkpGPQ6800D6SF
         7AaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736262219; x=1736867019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6iA/eJ2Z1bXUwN1n/XAkUWrPKOOCF7+18eRxIP2jXvg=;
        b=akK8QYPpmm1Hpduw41nCyCAdV8YnDJEJoEEcjZKVBOHBkWtjV8eZtx0Zib2Tu1NdNr
         yHh2GvhYhAikrC8sTiNtMZ1/1ffoCh5Rbjk7aiAV1xEnW4sPlZNJBGYPNbq3A8Vrquaj
         SwJ5Dpd9w3cKGvTX41NCGfGR4C9qyMKNw16GBmdMliaJkVBHVJ9UnYXSX8YDdJiKLs8y
         o2zlXW0n3U3Pl2IWS+oPiNLnMWI+Pg0foLw6ODQFSTUw177EKqDKZoCmM2IsldsVE7J4
         vwa1s9uzutbm7oQLrqCDCscn4AnwxgLjJdY+hVuXm2V9ctw/eEJOSE6w13x0snnzcm60
         5IpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWaUvHaWGjh2efnvml9e1R2/2ZZTnljDNU9A7LUiPm6dJnm8rdsRFLK14YkVpVyK+W9Metl9Q==@lfdr.de
X-Gm-Message-State: AOJu0YyrhLMoYxGmwFA+uMd5Vfd5DU6kh+OscEvBfYA/wvEz9cFYLAyv
	gUm6Ih5++qqGTbOGYMvBjwDfujfmHjCtUw1PLw/h0l5s+4qWosyW
X-Google-Smtp-Source: AGHT+IH1/663mdnxKq6tbFvRSxvJad/DfX29Gitk2btKZrmRpfHHVP6wz0Sg8GOs8sDxz3H0XayiPQ==
X-Received: by 2002:a05:6a21:1517:b0:1e1:adb9:d1a6 with SMTP id adf61e73a8af0-1e5e08439e8mr98780150637.41.1736262219042;
        Tue, 07 Jan 2025 07:03:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1484:b0:725:efed:3617 with SMTP id
 d2e1a72fcca58-72aa9928adels499249b3a.1.-pod-prod-06-us; Tue, 07 Jan 2025
 07:03:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVByrAE7vJa5eaMXE6ruR2RDGo8lLLXrPtXdNK4t6Ze252Gqn0kQhE2BXDJETACWwEhcyHBlJaHu3Y=@googlegroups.com
X-Received: by 2002:a05:6a21:680b:b0:1e1:ae9a:6311 with SMTP id adf61e73a8af0-1e5e0458dcamr89571193637.4.1736262217543;
        Tue, 07 Jan 2025 07:03:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736262217; cv=none;
        d=google.com; s=arc-20240605;
        b=dGKnoKl1ldRYQofXggJ32YrNJGcuhveUXYGb2jBCb8xem6WHGNzegwMQFRpMGUbGgg
         9FE7G6rFAiTzBp07iJQNGbGs5ZCUVPzHBYgTAMl2TXezANQn8uql7/c76COIdFjbv8Yk
         viVYw3lAKljEA/4VOsa2krZZ/1vFjNfudmfdjAdYqDF1at4VjLH0P5JV9m+jBrmvsGS+
         KWcP3lMyAFsIEkN8OXHjN4ErHE7qUIJO/8EWuhkCBHcXCNgzAqSupf2lcMLucERDAWSK
         Vf7uFB4Lk/5wF+RuqZLgUASQbK7uOE6BLbX8sciNPndvMwiycqtxGVuPAxyW91I54TWU
         4EfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nGMTr1inoVWG3ARe8QoGoEOSwdCntuqZy8bhdK6O/ME=;
        fh=uukfGpnDvHRyawIUeNSA6EIDv8EVP+Ar6G93rohwKRw=;
        b=deHfjl3su2wbmMdBKER94Q5M2yn9Jv0H16IVUex0hTW/e6/eSJDlrLHX7MRzsF6Eqs
         oQagV7mdqLR1C8WPrE130C8EUG3fPqwL6vDVv/rR4qG3fW+EmcBs3OzYRGLFTrDU33nN
         kBAMxxHD1goCjQJ9jeRLofRTuG8VBRVctCmPQqK0f8vUb9Ghu8D1Ao1aSEt/D1YJ7Hol
         p2qY6WCsKtYB8cPCcLKeVrq1SafxBlSecMhkFs9N6MvNbmT9xFXB4vQWMDbNzKQuxG+6
         P+O4bgc934pPnt0aiAcEh4erY2Xl8GtEDpsFYxgqsZnDNQ5jiqLOe09OoAHZhxwx9Ge+
         UnhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rdj4BTKq;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-89e5eea8d1asi1085691a12.0.2025.01.07.07.03.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 Jan 2025 07:03:37 -0800 (PST)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 507CSCqI009587;
	Tue, 7 Jan 2025 15:02:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 440s0abfbu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 07 Jan 2025 15:02:55 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 507EivrM024320;
	Tue, 7 Jan 2025 15:02:55 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 440s0abfbp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 07 Jan 2025 15:02:55 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 507E2w4n027938;
	Tue, 7 Jan 2025 15:02:54 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 43yhhk2t7y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 07 Jan 2025 15:02:54 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 507F2nAY55837076
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 7 Jan 2025 15:02:50 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C602420043;
	Tue,  7 Jan 2025 15:02:49 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 683182004D;
	Tue,  7 Jan 2025 15:02:48 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  7 Jan 2025 15:02:48 +0000 (GMT)
Date: Tue, 7 Jan 2025 16:02:47 +0100
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Guo Weikang <guoweikang.kernel@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
        Christoph Lameter <cl@linux.com>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Sam Creasey <sammy@sammy.net>, Huacai Chen <chenhuacai@kernel.org>,
        Will Deacon <will@kernel.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Oreoluwa Babatunde <quic_obabatun@quicinc.com>,
        rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>,
        Hanjun Guo <guohanjun@huawei.com>,
        Easwar Hariharan <eahariha@linux.microsoft.com>,
        Johannes Berg <johannes.berg@intel.com>,
        Ingo Molnar <mingo@kernel.org>, Dave Hansen <dave.hansen@intel.com>,
        Christian Brauner <brauner@kernel.org>, KP Singh <kpsingh@kernel.org>,
        Richard Henderson <richard.henderson@linaro.org>,
        Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>,
        WANG Xuerui <kernel@xen0n.name>, Michael Ellerman <mpe@ellerman.id.au>,
        Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>,
        Stafford Horne <shorne@gmail.com>, Helge Deller <deller@gmx.de>,
        Nicholas Piggin <npiggin@gmail.com>,
        Christophe Leroy <christophe.leroy@csgroup.eu>,
        Naveen N Rao <naveen@kernel.org>,
        Madhavan Srinivasan <maddy@linux.ibm.com>,
        Geoff Levand <geoff@infradead.org>,
        Paul Walmsley <paul.walmsley@sifive.com>,
        Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        Yoshinori Sato <ysato@users.sourceforge.jp>,
        Rich Felker <dalias@libc.org>,
        John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
        Andreas Larsson <andreas@gaisler.com>,
        Richard Weinberger <richard@nod.at>,
        Anton Ivanov <anton.ivanov@cambridgegreys.com>,
        Johannes Berg <johannes@sipsolutions.net>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
        linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-arm-kernel@lists.infradead.org, loongarch@lists.linux.dev,
        linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
        linux-openrisc@vger.kernel.org, linux-parisc@vger.kernel.org,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
        linux-um@lists.infradead.org, linux-acpi@vger.kernel.org,
        xen-devel@lists.xenproject.org, linux-omap@vger.kernel.org,
        linux-clk@vger.kernel.org, devicetree@vger.kernel.org,
        linux-mm@kvack.org, linux-pm@vger.kernel.org,
        Xi Ruoyao <xry111@xry111.site>
Subject: Re: [PATCH v7] mm/memblock: Add memblock_alloc_or_panic interface
Message-ID: <Z31CF9f//ZD+VH59@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20241222111537.2720303-1-guoweikang.kernel@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241222111537.2720303-1-guoweikang.kernel@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: dCCQ1zYhGRi9msJXR2I1JBmo9iJqcs5M
X-Proofpoint-ORIG-GUID: ti6I84LhDp7SvrcEw02BBExl0BdjrhaR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1051,Hydra:6.0.680,FMLib:17.12.62.30
 definitions=2024-10-15_01,2024-10-11_01,2024-09-30_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1011
 phishscore=0 mlxlogscore=999 lowpriorityscore=0 impostorscore=0
 malwarescore=0 mlxscore=0 adultscore=0 bulkscore=0 suspectscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501070122
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rdj4BTKq;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Sun, Dec 22, 2024 at 07:15:37PM +0800, Guo Weikang wrote:

Hi Guo,

> Before SLUB initialization, various subsystems used memblock_alloc to
> allocate memory. In most cases, when memory allocation fails, an immediate
> panic is required. To simplify this behavior and reduce repetitive checks,
> introduce `memblock_alloc_or_panic`. This function ensures that memory
> allocation failures result in a panic automatically, improving code
> readability and consistency across subsystems that require this behavior.

I believe, you also want to make similar function against memblock_alloc_low().

Please, find s390 comments below.

...

> diff --git a/arch/s390/kernel/numa.c b/arch/s390/kernel/numa.c
> index ddc1448ea2e1..a33e20f73330 100644
> --- a/arch/s390/kernel/numa.c
> +++ b/arch/s390/kernel/numa.c
> @@ -22,10 +22,7 @@ void __init numa_setup(void)
>  	node_set(0, node_possible_map);
>  	node_set_online(0);
>  	for (nid = 0; nid < MAX_NUMNODES; nid++) {
> -		NODE_DATA(nid) = memblock_alloc(sizeof(pg_data_t), 8);
> -		if (!NODE_DATA(nid))
> -			panic("%s: Failed to allocate %zu bytes align=0x%x\n",
> -			      __func__, sizeof(pg_data_t), 8);
> +		NODE_DATA(nid) = memblock_alloc_or_panic(sizeof(pg_data_t), 8);
>  	}

Please, also remove the cycle body brackets.

>  	NODE_DATA(0)->node_spanned_pages = memblock_end_of_DRAM() >> PAGE_SHIFT;
>  	NODE_DATA(0)->node_id = 0;
> diff --git a/arch/s390/kernel/setup.c b/arch/s390/kernel/setup.c
> index 0ce550faf073..1298f0860733 100644
> --- a/arch/s390/kernel/setup.c
> +++ b/arch/s390/kernel/setup.c
> @@ -376,11 +376,7 @@ static unsigned long __init stack_alloc_early(void)
>  {
>  	unsigned long stack;
>  
> -	stack = (unsigned long)memblock_alloc(THREAD_SIZE, THREAD_SIZE);
> -	if (!stack) {
> -		panic("%s: Failed to allocate %lu bytes align=0x%lx\n",
> -		      __func__, THREAD_SIZE, THREAD_SIZE);
> -	}
> +	stack = (unsigned long)memblock_alloc_or_panic(THREAD_SIZE, THREAD_SIZE);
>  	return stack;
>  }
>  
> @@ -504,10 +500,7 @@ static void __init setup_resources(void)
>  	bss_resource.end = __pa_symbol(__bss_stop) - 1;
>  
>  	for_each_mem_range(i, &start, &end) {
> -		res = memblock_alloc(sizeof(*res), 8);
> -		if (!res)
> -			panic("%s: Failed to allocate %zu bytes align=0x%x\n",
> -			      __func__, sizeof(*res), 8);
> +		res = memblock_alloc_or_panic(sizeof(*res), 8);
>  		res->flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;
>  
>  		res->name = "System RAM";
> @@ -526,10 +519,7 @@ static void __init setup_resources(void)
>  			    std_res->start > res->end)
>  				continue;
>  			if (std_res->end > res->end) {
> -				sub_res = memblock_alloc(sizeof(*sub_res), 8);
> -				if (!sub_res)
> -					panic("%s: Failed to allocate %zu bytes align=0x%x\n",
> -					      __func__, sizeof(*sub_res), 8);
> +				sub_res = memblock_alloc_or_panic(sizeof(*sub_res), 8);
>  				*sub_res = *std_res;
>  				sub_res->end = res->end;
>  				std_res->start = res->end + 1;
> @@ -816,9 +806,7 @@ static void __init setup_randomness(void)
>  {
>  	struct sysinfo_3_2_2 *vmms;
>  
> -	vmms = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> -	if (!vmms)
> -		panic("Failed to allocate memory for sysinfo structure\n");
> +	vmms = memblock_alloc_or_panic(PAGE_SIZE, PAGE_SIZE);
>  	if (stsi(vmms, 3, 2, 2) == 0 && vmms->count)
>  		add_device_randomness(&vmms->vm, sizeof(vmms->vm[0]) * vmms->count);
>  	memblock_free(vmms, PAGE_SIZE);
> diff --git a/arch/s390/kernel/smp.c b/arch/s390/kernel/smp.c
> index 822d8e6f8717..d77aaefb59bd 100644
> --- a/arch/s390/kernel/smp.c
> +++ b/arch/s390/kernel/smp.c
> @@ -611,9 +611,9 @@ void __init smp_save_dump_ipl_cpu(void)
>  	if (!dump_available())
>  		return;
>  	sa = save_area_alloc(true);
> -	regs = memblock_alloc(512, 8);
> -	if (!sa || !regs)
> +	if (!sa)
>  		panic("could not allocate memory for boot CPU save area\n");

Please, replace memblock_alloc() with memblock_alloc_or_panic() in
save_area_alloc() and remove the error handling here and also in
smp_save_dump_secondary_cpus().

> +	regs = memblock_alloc_or_panic(512, 8);
>  	copy_oldmem_kernel(regs, __LC_FPREGS_SAVE_AREA, 512);
>  	save_area_add_regs(sa, regs);
>  	memblock_free(regs, 512);
> @@ -792,10 +792,7 @@ void __init smp_detect_cpus(void)
>  	u16 address;
>  
>  	/* Get CPU information */
> -	info = memblock_alloc(sizeof(*info), 8);
> -	if (!info)
> -		panic("%s: Failed to allocate %zu bytes align=0x%x\n",
> -		      __func__, sizeof(*info), 8);
> +	info = memblock_alloc_or_panic(sizeof(*info), 8);
>  	smp_get_core_info(info, 1);
>  	/* Find boot CPU type */
>  	if (sclp.has_core_type) {
> diff --git a/arch/s390/kernel/topology.c b/arch/s390/kernel/topology.c
> index 0fd56a1cadbd..cf5ee6032c0b 100644
> --- a/arch/s390/kernel/topology.c
> +++ b/arch/s390/kernel/topology.c
> @@ -548,10 +548,7 @@ static void __init alloc_masks(struct sysinfo_15_1_x *info,
>  		nr_masks *= info->mag[TOPOLOGY_NR_MAG - offset - 1 - i];
>  	nr_masks = max(nr_masks, 1);
>  	for (i = 0; i < nr_masks; i++) {
> -		mask->next = memblock_alloc(sizeof(*mask->next), 8);
> -		if (!mask->next)
> -			panic("%s: Failed to allocate %zu bytes align=0x%x\n",
> -			      __func__, sizeof(*mask->next), 8);
> +		mask->next = memblock_alloc_or_panic(sizeof(*mask->next), 8);
>  		mask = mask->next;
>  	}
>  }
> @@ -569,10 +566,7 @@ void __init topology_init_early(void)
>  	}
>  	if (!MACHINE_HAS_TOPOLOGY)
>  		goto out;
> -	tl_info = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> -	if (!tl_info)
> -		panic("%s: Failed to allocate %lu bytes align=0x%lx\n",
> -		      __func__, PAGE_SIZE, PAGE_SIZE);
> +	tl_info = memblock_alloc_or_panic(PAGE_SIZE, PAGE_SIZE);
>  	info = tl_info;
>  	store_topology(info);
>  	pr_info("The CPU configuration topology of the machine is: %d %d %d %d %d %d / %d\n",

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z31CF9f//ZD%2BVH59%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
