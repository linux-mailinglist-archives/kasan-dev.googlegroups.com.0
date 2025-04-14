Return-Path: <kasan-dev+bncBCVZXJXP4MDBBFNS6S7QMGQEIWA7THQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id D7137A88455
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 16:17:59 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-22406ee0243sf33012655ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 07:17:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744640278; cv=pass;
        d=google.com; s=arc-20240605;
        b=gRGjTHE7WsFfVdthrC0J0sBtlp/iM4F0Kn9SQecHumdfEu3aO5pHC1/Wj8z8b/umwf
         ZiYz5dT9XosMy/9LaycpK3IP8cM+7zRTvfkJCmuZEOIekhRqMTjWrD6mJoDUSltba9hk
         yzXeHCnPmWIcu0WQCmkMhg5tktYuszeUzGfRThJ+8qXWlZ34yDWUlp1amXxao4UoElvB
         8SZpLAxalpIhZ8HnqFgyGkCbCLuSWFOZgyapPfb2zMwZmS0M3Vstfdmjz1oIyq51jOCC
         gLdzkbms1I0C21RGFNMle7VP/laDid/ofWs0gpzFz27nyuZUtEFmCPJHYk761SOwwMZG
         wDDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xQprt2y1+pQWpL6hMWEhJTBEpVKzlq8OTZlPk9XCL7U=;
        fh=6I6Y/iVpzT9S7i/DULYF3rfRomtY2fo3MEKO4qgRSo0=;
        b=Cvk+JWpn8xaOwlvvvG4baYTvI1/GsLqn3KZHSELvaI3uQqTDvDE+IHinYMFW62IUtI
         Dnan+M9lVjyv5FbvqrFu8hDWbNVroEYtu8WYAUE58xIzKRnWCu2joQHtKYW1RYecygCr
         +I5p3PRhU8LBJ32fxktQcvM7J/JbsCAap/Cujm17L4NpnX0g/DnrSrPdxnlS/kegoXlu
         OcwXF5I8trbzbdC1cot+P8mBkV7uJuzZRC/h7I7yRI61KN6Rd5ZNOZztR8tW35sFfOxJ
         9RKcD+JmqKPzS5RLfkgVN2iiyH/XnirLw48fuMCU057//dDNXaOqMkSOTrGkZDIz2Mvu
         krTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ah561Kin;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744640278; x=1745245078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xQprt2y1+pQWpL6hMWEhJTBEpVKzlq8OTZlPk9XCL7U=;
        b=BZOxEI2rc6EPudvNpmhA1cA11fR/VVBdb0qym1AMOCQaOyORj3SSmAbru1lE5gRCOe
         Rj5JK5zWdqhUHM89/d7PafGT+VCDOOlgRmYPcJeb03wQQKkyXtMGcT+0Jy+8pTy2wrOK
         VajaDrzueK/dbw/NT8s9FVQNDVfF9H3pGrn4GEmMLANVlfOtjq+jk/MmwZh5eljWLEMZ
         vI9tRSN1lZ6iGcZz94xmW0MlAocr1/GH23HYZkYsPhyAA07R9dR5LbsTT/UoLmo5a0OA
         He8PMBq9YpT+mQB1h7YPN5xgLdzj22hN7OD3FJkaUqWQhBLD7Ly1lPD7aZQflJDTAT3V
         CV+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744640278; x=1745245078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xQprt2y1+pQWpL6hMWEhJTBEpVKzlq8OTZlPk9XCL7U=;
        b=BCh0diFhYj07/KZSHP26sbhhpzS+caXOYBxeDH7ZuYBTY40fEGoT++PgrL2BnZfoVu
         HKIkE3W5NmOgVN0ufCM8KD+uSVLB0w/aluhLa3y8ODgUH+a/93qVRvsXofuGdTeSm9ot
         pIJ57KU97UiIlLulu3lzxrnvqfKmbkjgEvZYbplUugco10G/LDc4QGdGc09ZlmlFdbvp
         u7+Zak4hpI84EN4noxV9vzbJEpFxRx6YFA0t+W627/j6HUA0vgcTNTluu01K1d9gfXwl
         j4V/hA/o31jKHc+ACvhTkfLCv3zLKYWBM02IOpHPnuZdPRPuiUFY0Vyyc+WnJOxOttCG
         yi6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjkpELK0ZF0dXkees9x8+PNDKivPtWgdwFDRK0kYyfmMT73iEd6m8xIyDSlWCGGqS3sw0lIw==@lfdr.de
X-Gm-Message-State: AOJu0Yx0UF1MZOO6o82PP0IGMyMJR2lhPcpiUivLh3FUSujiLR+OqK9/
	RMQS0a2BLRG8CAlvIPsA1xQoMbAyS65XANO9NyAgVra7iIZWI1Bf
X-Google-Smtp-Source: AGHT+IEB3Eyht4Lxq4FdEuTbOHhAfd7aIrh5tS0dB13bR5c+W5oTwkfg7oeRRKLuZ9vkD8wTKdSbmg==
X-Received: by 2002:a17:902:f54f:b0:21f:61a9:be7d with SMTP id d9443c01a7336-22bea4fddfamr140841665ad.49.1744640277694;
        Mon, 14 Apr 2025 07:17:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ443HTyYEdsK/qqYNdJnE57HLSKyWvQY9ih20yJ5o/LQ==
Received: by 2002:a17:90a:cf95:b0:2e1:1d4a:962a with SMTP id
 98e67ed59e1d1-306ec114551ls2042539a91.1.-pod-prod-04-us; Mon, 14 Apr 2025
 07:17:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXL0b3Tzf8wmuXMsSBVw7zhuK7FeEl/ykuNzFADgjnPoA+BTXo68XXg+NrGpA8EOAgCe6ZvdSN6f7o=@googlegroups.com
X-Received: by 2002:a17:90b:2742:b0:308:1ee5:4247 with SMTP id 98e67ed59e1d1-308237c114amr15893861a91.32.1744640275630;
        Mon, 14 Apr 2025 07:17:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744640275; cv=none;
        d=google.com; s=arc-20240605;
        b=l0kE9YnwmJpUaxsv5OtN8BdiBt1imhsd1LFeVD0danRrVoZJmED6fh68juvdaBCgWt
         D6+Py/NZnnX/8qaDEwIpg033PAUZgod0nDA1lS25rcMONg4pJaT7sLUzNdP3CG9dNvjg
         0Z286KhYQ+BmAZ6gpgkTtziLhRlxWyUeB2rkhB32DJFxPD4Ro5hHEN2xMYb7yfrTqrm+
         0jCmCHgERw8xhAU+E1y9SweVYO/6FKZLUGkEewL3LoathhJBSGOdWAZpd8Dswmc6Pmn1
         Qmgnid+8nFWapSGRpJIEmQ22DxAYgMWwPCPLve1yh+EgL618e+eqByNTCuunGCg08reL
         BZxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=J1d9DTJcE/z+4d1uC+sEutnQDyUt9v5FZ9je4Eup1Ko=;
        fh=k7ZYnR6kzy6Q/UpH6eAB60S6YCOdOnTfXOTZM3ObKks=;
        b=XUdQbDhFrUEQsrbpdSolfOrtV3rO44OGIc2UBM2qV2gWS+fyfo09bhIkMevstCDJmG
         Shfr8yXpb7EBxn+3LkhyA8NNB5ktleVl1HjZznrg1/4hmg62nRNCD6yb1XuMGc1uBHzi
         qvPjOuH9Jml89oyFYKKjncNW3iB4hXsambM0idJKxbQlCN1QaYekFTIWnPZ8CVcjOrca
         KtnM1PmEEeUVhhWeJoznSx2T/Y6yhewwEqxFEryXIetJh+QDmC5rVSnYvvqrgQbTOoVl
         5JNbEn7ErwllgCp9XUcIIS1QHLw3yOsUGS+t/DldEtGs50Ad3XQkepwN3zGVY9jvUheJ
         VY/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ah561Kin;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-306dd568075si496270a91.1.2025.04.14.07.17.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Apr 2025 07:17:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53EAKA71029133;
	Mon, 14 Apr 2025 14:17:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 460nc4bs6s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Apr 2025 14:17:54 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 53EEDPx6027591;
	Mon, 14 Apr 2025 14:17:53 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 460nc4bs6k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Apr 2025 14:17:53 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 53ECwxMl017183;
	Mon, 14 Apr 2025 14:17:52 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46040kpeha-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Apr 2025 14:17:52 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 53EEHorV51577248
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 14 Apr 2025 14:17:50 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2CE2320043;
	Mon, 14 Apr 2025 14:17:50 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2BFC320040;
	Mon, 14 Apr 2025 14:17:49 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.13.82])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 14 Apr 2025 14:17:49 +0000 (GMT)
Date: Mon, 14 Apr 2025 16:17:47 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Nicholas Piggin <npiggin@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Hugh Dickins <hughd@google.com>, Guenter Roeck <linux@roeck-us.net>,
        Juergen Gross <jgross@suse.com>, Jeremy Fitzhardinge <jeremy@goop.org>,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
        xen-devel@lists.xenproject.org, linuxppc-dev@lists.ozlabs.org,
        linux-s390@vger.kernel.org
Subject: Re: [PATCH v1 2/4] mm: Cleanup apply_to_pte_range() routine
Message-ID: <Z/0ZC7HcSmoOEglw@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <93102722541b1daf541fce9fb316a1a2614d8c86.1744037648.git.agordeev@linux.ibm.com>
 <D93LW58FLXOS.2U8X0CO2H9H5S@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <D93LW58FLXOS.2U8X0CO2H9H5S@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: u44-EjcfNgIEy_4sPtFf7SZelDSyFVJd
X-Proofpoint-ORIG-GUID: DiJ-rrsNSTwxXUpWJqT680rFpek1uPzj
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-14_04,2025-04-10_01,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 bulkscore=0
 priorityscore=1501 mlxscore=0 spamscore=0 adultscore=0 mlxlogscore=844
 phishscore=0 clxscore=1015 lowpriorityscore=0 suspectscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504140102
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ah561Kin;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
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

On Fri, Apr 11, 2025 at 04:46:58PM +1000, Nicholas Piggin wrote:
> On Tue Apr 8, 2025 at 1:11 AM AEST, Alexander Gordeev wrote:
> > Reverse 'create' vs 'mm == &init_mm' conditions and move
> > page table mask modification out of the atomic context.
> >
> > Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> > ---
> >  mm/memory.c | 28 +++++++++++++++++-----------
> >  1 file changed, 17 insertions(+), 11 deletions(-)
> >
> > diff --git a/mm/memory.c b/mm/memory.c
> > index 2d8c265fc7d6..f0201c8ec1ce 100644
> > --- a/mm/memory.c
> > +++ b/mm/memory.c
> > @@ -2915,24 +2915,28 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
> >  				     pte_fn_t fn, void *data, bool create,
> >  				     pgtbl_mod_mask *mask)
> >  {
> > +	int err = create ? -ENOMEM : -EINVAL;
> 
> Could you make this a new variable instead of reusing
> existing err? 'const int pte_err' or something?

Will do, when/if repost.

...

> > @@ -2944,12 +2948,14 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
> >  			}
> >  		} while (addr += PAGE_SIZE, addr != end);
> >  	}
> > -	*mask |= PGTBL_PTE_MODIFIED;
> >  
> >  	arch_leave_lazy_mmu_mode();
> >  
> >  	if (mm != &init_mm)
> >  		pte_unmap_unlock(mapped_pte, ptl);
> > +
> > +	*mask |= PGTBL_PTE_MODIFIED;
> 
> This is done just because we might as well? Less work in critical
> section?

Yes.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z/0ZC7HcSmoOEglw%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
