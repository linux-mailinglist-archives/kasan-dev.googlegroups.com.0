Return-Path: <kasan-dev+bncBDE5LFWXQAIRB6FSWOFAMGQEI2YBSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id F03E4416619
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 21:46:01 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id j16-20020ab02510000000b002ba380b6ef5sf2689846uan.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:46:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632426361; cv=pass;
        d=google.com; s=arc-20160816;
        b=sKFHl9FnasxwA8HO7N9c3TTbRXY9QmLwApv7D05ESETgk1ou6yejGKc2YIrKyEWpCb
         32eZD90YHk4RbE4okys7QUfPEQ8PJhYPu5fUxgCtUvO56+ieNtv6LGbqQP2juQmj56SO
         m116I0jWgEr3n140N7vzwSGrrx8qRhj8rjVnrj9g81mxVpins02RT43BvJyPHvaJk2BG
         09kMbMWcNGsYcVjROPpr0bKExPQeBeqJSXZiJRnCadVz+wlnRbA9fAY44j2lcfs1jE3y
         Lz1h99oglhhJ/VfKsu72r/nxZnntkV1CxxwbpXyPcXInRWwn4mCOo1svm7CRf1tVkFD9
         cmgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0Vw6pr08CV4FCZ05EUucKgcwqeKTJGQoYKETA2WALJU=;
        b=xNuPc+cBijr9Rlgb0RwKQDklfca/k5ywgVmVi6AFxLvWYD0Qii9tYxPaPI8wsXD4Ff
         uxCpkjhtun6C8h7EpFsYtmw4yOVFmgeoBFQit7MZjwZDAjqNVBRbxS448TZPr8FMfbvm
         erLEJ48NiPDL5JDsBmJ7Nc1NBCh9P9Kfin88Ux4apmh2SwBu7GzEBLIvd4g0osZNLxsH
         IpgKeWe3lDZ72GDFTXftu+XKhNnEFiuJTl7LiJE3U2vYODIUESVOtdiuhz/CyGPC+wdR
         JKuRayuRgpqyewvP8m+DSrUKNSG++gnRSlItTjEKVp0WsOY4g77A3ASZsWOKxENze5c2
         q5Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=o2g9xUdg;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0Vw6pr08CV4FCZ05EUucKgcwqeKTJGQoYKETA2WALJU=;
        b=h1H1Pvu8ZSrUDtty8s3c2e4SFK8+ce4MY8OjFvY2CjJ+zuYS5mtnNYXfGyc38s+99N
         15so+eyiIn+7lfU4Y9I4zLH/ZvkMzn4m2g69iUNDH2TUV8FNibx8NbiHt0fdij6tsGGj
         jH69x+dFiVJAjUlJjh3gF3kC0gjmQUAUoawZEbkJX9ACXSjEVATznSeNOxxF5i1MK2TY
         oX8RoVaoR1i34DcHOmvMIX29c3GzAKWTg6YupJBeM7XK6KBU//3os8iwTdooS8scWWnU
         /EcGIbO4POa7zcXhc6mMeK+Ixp7QhlawePKXIOXfQvdKQy44UpRdwh57oJGT3NpLAITZ
         LnDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0Vw6pr08CV4FCZ05EUucKgcwqeKTJGQoYKETA2WALJU=;
        b=Q6KvT8P6koA0+j9ByzpcmpE+2r43I2GxZZoPBlC3L9eBYAOeqkdYpllSj9L9X4KxRW
         /anEktqxByfjkyduVis7op3zBiOnYvpEE/OH18Xmqe88KuKeoz/rdyeC9xweXwisSOlQ
         aa60hSdzHhNPHsXuTM2Ojtmu6LdNynDQsQHqiROXwnvwnVsHpUlVu8ruTjY1cgtRUFzV
         RJkAAylmyg1dk1nHxpA/t0Iut+L1riZ+z4O3plpsRIjoyQP91cXlb82irQX61lpaED0a
         k4x7ikm6CPIAYNdueSZtpTlxdu4JTul1zIKRCjjcfhz5woCy1s/1TD1AIwG7T4P1rSEZ
         YkBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gAhBtj3YTJY5EG3j3WboYMffLKomhVXf3bmvOZRLePe9qVGyv
	opsvGxRb+E58F6+J1nuECm0=
X-Google-Smtp-Source: ABdhPJxhcj9Y9QTXm+eoGbAUjKXHwiToco3+uso3PlOenJIDl2mwVuNN13+Aeav/n0JCCjP+HY22wA==
X-Received: by 2002:a1f:ee0b:: with SMTP id m11mr5379218vkh.19.1632426360847;
        Thu, 23 Sep 2021 12:46:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3768:: with SMTP id o8ls945159uat.8.gmail; Thu, 23 Sep
 2021 12:46:00 -0700 (PDT)
X-Received: by 2002:ab0:5596:: with SMTP id v22mr427524uaa.99.1632426360369;
        Thu, 23 Sep 2021 12:46:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632426360; cv=none;
        d=google.com; s=arc-20160816;
        b=XCT+HMxfOhVb19nzYn5m3BZ440KOMKGwbvkoBFjFFXf64ZK4Jr5BDIfx7FAv5hPcaT
         OENrzTb5y8AkQ1KPEMOVkMT161aPkJcMrw/Nk7dOnFjO0vJvEPNv+q5WJsv+HZA3XbaU
         /NRstwY1dzmSIg4xpnDlhouX05uwVFiigp8EaMEP4VwyuXUiWGVtCkbCYagg6WBEfrU3
         3MoqtPYoKMW/2yQIxPFmsjPe8P3RMUfCnqC0zZHIgZrbjEt9UBy/0lxS2kQ3ZwwUnHoR
         rcdOAz63/hEGkheP1F/CfqHcNEgBOKex9UVhzbbnwlitcoyScjucaQ24DlxoPuAx58ms
         u/ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OlfxwL5SxCQJGsEygNnP+Bd9S5CycoibyIwI1T9qbFQ=;
        b=v7Q+4d6rqOtxmXW+DyG64eVyT+AYFih5qnMxBxMwNVPqMGNsaWKRUhUO5zEifDSqTj
         BjZjvPpHsqrctrExU2xcQ/kTuMbxQ1ElUVOI05J5LJAoONZBrd9ikHfIR6u6WW3CxHIi
         tqWK+jkB4BHczDVg9GYb67DmNr0doRDqEP3UfrAzvGGh3Oe1ZQgDSG4uFAuPpG/XjvKg
         9/UoQbRklBIsiWRkyJ09b3pRvtwE4HkTiL51rNvkkXltkoxXqi5yJCUMfMg/JScjeYua
         yzlV7ar3pTSnkoHaZa1hqiQIqCe7sfFc8VFfCZStEAbDHE8eqV51Rq8s0g7v+U9HLDd4
         QUmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=o2g9xUdg;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id a18si106155vsi.1.2021.09.23.12.46.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 12:46:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 18NJW36f031236;
	Thu, 23 Sep 2021 15:45:59 -0400
Received: from ppma03fra.de.ibm.com (6b.4a.5195.ip4.static.sl-reverse.com [149.81.74.107])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3b8wkuupat-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 23 Sep 2021 15:45:58 -0400
Received: from pps.filterd (ppma03fra.de.ibm.com [127.0.0.1])
	by ppma03fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 18NJRuDe003688;
	Thu, 23 Sep 2021 19:45:56 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma03fra.de.ibm.com with ESMTP id 3b7q6kd587-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 23 Sep 2021 19:45:56 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 18NJjrxv44106172
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 23 Sep 2021 19:45:53 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A19734C04A;
	Thu, 23 Sep 2021 19:45:53 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 903DC4C05A;
	Thu, 23 Sep 2021 19:45:51 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.159.121])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 23 Sep 2021 19:45:51 +0000 (GMT)
Date: Thu, 23 Sep 2021 22:45:49 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Mike Rapoport <rppt@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        devicetree <devicetree@vger.kernel.org>,
        iommu <iommu@lists.linux-foundation.org>,
        kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>,
        alpha <linux-alpha@vger.kernel.org>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        linux-efi <linux-efi@vger.kernel.org>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        "open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
        Linux-MM <linux-mm@kvack.org>,
        linux-riscv <linux-riscv@lists.infradead.org>,
        linux-s390 <linux-s390@vger.kernel.org>,
        Linux-sh list <linux-sh@vger.kernel.org>,
        "open list:SYNOPSYS ARC ARCHITECTURE" <linux-snps-arc@lists.infradead.org>,
        linux-um <linux-um@lists.infradead.org>, linux-usb@vger.kernel.org,
        linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
        linux-sparc <sparclinux@vger.kernel.org>,
        xen-devel@lists.xenproject.org
Subject: Re: [PATCH 0/3] memblock: cleanup memblock_free interface
Message-ID: <YUzZberbgZE+7HEo@linux.ibm.com>
References: <20210923074335.12583-1-rppt@kernel.org>
 <CAHk-=wiJB8H5pZz-AKaSJ7ViRtdxQGJT7eOByp8DJx2OwZSYwA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wiJB8H5pZz-AKaSJ7ViRtdxQGJT7eOByp8DJx2OwZSYwA@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: NmcKtlYbna1qS7iyZ4wr-YnA7UP6mwwQ
X-Proofpoint-ORIG-GUID: NmcKtlYbna1qS7iyZ4wr-YnA7UP6mwwQ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.182.1,Aquarius:18.0.790,Hydra:6.0.391,FMLib:17.0.607.475
 definitions=2021-09-23_06,2021-09-23_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 lowpriorityscore=0 mlxscore=0 malwarescore=0 spamscore=0
 priorityscore=1501 bulkscore=0 clxscore=1015 suspectscore=0
 mlxlogscore=691 adultscore=0 phishscore=0 classifier=spam adjust=0
 reason=mlx scancount=1 engine=8.12.0-2109200000
 definitions=main-2109230115
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=o2g9xUdg;       spf=pass (google.com:
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

Hi Linus,

On Thu, Sep 23, 2021 at 09:01:46AM -0700, Linus Torvalds wrote:
> On Thu, Sep 23, 2021 at 12:43 AM Mike Rapoport <rppt@kernel.org> wrote:
> >
> You need to be a LOT more careful.
> 
> From a trivial check - exactly because I looked at doing it with a
> script, and decided it's not so easy - I found cases like this:
> 
> -               memblock_free(__pa(paca_ptrs) + new_ptrs_size,
> +               memblock_free(paca_ptrs + new_ptrs_size,
> 
> which is COMPLETELY wrong.

I did use a coccinelle script that's slightly more robust that a sed you've
sent, but then I did a manual review, hence the two small patches with
fixes. Indeed I missed this one, so to be on the safe side I'll rename only
the obvious cases where coccinelle can be used reliably and leave all the
rest as it's now. If somebody cares enough they can update it later.
 
> And no, making the scripting just replace '__pa(x)' with '(void *)(x)'

These were actually manual and they are required for variables that
used as virtual addresses but have unsigned long type, like e.g.
initrd_start. So it's either __pa(x) or (void *).

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUzZberbgZE%2B7HEo%40linux.ibm.com.
