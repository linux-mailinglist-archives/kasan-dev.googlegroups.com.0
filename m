Return-Path: <kasan-dev+bncBAABBJFA5X3QKGQEIHW4DTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id A475620F77A
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 16:45:57 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id w23sf7144306pjy.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 07:45:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593528356; cv=pass;
        d=google.com; s=arc-20160816;
        b=LV8yM7omRFWqqfWxIoNYMBKZ+m7++KBNesKZuEy856HFHM6fts+JlW+BKs4o/mwafa
         w8vCBU6h3Mso3l1Vygvt8qaZKG5u8bN2WHRwKSGssOvedUkgIBuHQJs9LA8LIqeQUeBH
         DW/3pM1JZRRsFGVP9DnP+8G56rmPGQuzI7PpxnnwxoiEXT8iinhjZrcpmw8dVQYHgP9v
         UEonpba6ItuXq4IavCtIunX9wENd2KKdC63FYQX+OmU8q+mzbH2Bx5ZROVqflsjBKKu2
         c/IxkOI+pFos18WWDG5SPeKk8LqyhnAaID317xAQKuBrbQVoERcHrGUd7d6RxLxtgReP
         5IPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MEIyPnnXCEwrQBYPir+8N6AYc5tE37Yjt0LjQZxw4AY=;
        b=ZZDxUezfipbnmpRd+E/MQAl0xNDJ4SLZsRCqFXbS1NaPjPHmeD3fRZ6FauwhcV8NbS
         1rwdRI7T2pR+yCz9r9xOSs1+hmuBhrn8LbGa43ThBQ8lC01yunzwgyWJ4S33yjVegoyN
         v3egCwDzcBNpqGc3rslAqNDz7qSLyQljjT0xwiw2xqNw5k8D2bfghCcFurE7v1f87BKt
         joVGtIDdD/71UBdwTVqsP2vpgCiJmklegB0VMnQD8CUyVX6cDAaoMzm6JgNyXc/RmqQP
         ls8A8/Rja5x5xyVYEeeOYalDxlaiiWIo5P6kFZ8Gfpsx1S88kk3giIrOV2E9F88efqXE
         d5tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MEIyPnnXCEwrQBYPir+8N6AYc5tE37Yjt0LjQZxw4AY=;
        b=Znr1UxVMsBCzVHPkDNqMmbGxzbGaTdAZ/pFblQ5YoGJdGXcPKjDKJjvy7eK28C5Amx
         oP7ApIlvbDMV1RqHt+waBOaJJ8tVaGgbVxpriok/jNC/n+0LUNZck1fKGqiLl96mFnqt
         ijolUV4R+0IQk6EdJk/AG8LjgFxD7Qh8PX7/bTcbzC59qJNLIvHKgW4vzwIsp9ncbEPf
         xqJ8IeZT6SFDt4HvpsZpGN5JQ97IY0xId4I5HZv3PdGJ+3X+JgdfghnGGS2xB4C6IgV9
         ok+nVX809H0nPMCAGyYlnlrh529EsVzQHROt/36EPM8i04nZsR5ZxjdO6my8wVIFhFbY
         HwXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MEIyPnnXCEwrQBYPir+8N6AYc5tE37Yjt0LjQZxw4AY=;
        b=d2eXK0/2rG7CGsfaforYFkJr+icMcz3QELNrnbivEHHCPBYHU+FV3dB+5fTwrFvCiG
         9jnwSfD5tJ58UnkOPE1gcId+nHsdwMZM84C4UkC2ZFLiv9TNGF/5e6O0Hls8d0zcIcUG
         e/SLPveBmusor/9ds9gtMv6VLV8aV2V2YTzsxkrq2l3VSaYLmwNfwfTUaCdbY4dXDd1E
         Jp3T8arVrXA0eyKy2SdlulhTRX2i3s7nbqvUuZJhhHZdrUZVUtiraBJ1ci6pNKC4AKK6
         x27g0K/KKD1zMu/hU7R6UPksy2QCC3cQe4wDd5S2pUaUH67O8KHHY1okNFNF1SzctUbt
         Smbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uYdgsvllvb390u59ApcpTScYi1GcyaU5TXNtPHbVwy9exxTNc
	WNF7YglSOTEkwh6Nk1Skn2E=
X-Google-Smtp-Source: ABdhPJy3zuL3So2XcU8uwsLYa4v4ibOVtmkB13kCh6ZCU0B1qLl5/74iYmbu/7VrwRAR775+VGeOXg==
X-Received: by 2002:a17:90a:fe10:: with SMTP id ck16mr23727447pjb.147.1593528356281;
        Tue, 30 Jun 2020 07:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:718c:: with SMTP id i12ls1388097pjk.1.canary-gmail;
 Tue, 30 Jun 2020 07:45:56 -0700 (PDT)
X-Received: by 2002:a17:902:8694:: with SMTP id g20mr18162675plo.332.1593528355963;
        Tue, 30 Jun 2020 07:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593528355; cv=none;
        d=google.com; s=arc-20160816;
        b=NH+P3bu5tG+ge1o7SZcGhlSP+Co5BNMNG6hEgYTLvovmEHgcwdYsn9qsFuaKnH6J19
         xCgDwC7+LmuyN74uT23PKOnhrIZJ70RVGDymJg0oF67TILhethR/bivuCmMLmmDmVtOl
         l+stveMg2Mdop1wPmqD99/VLGtzp10PEV4Y6DfN4zF716uBnQ55Wz9hngZklJWb7kox8
         Dkn3gdgsF5S7/tDJYLz3tExa+R2/bLrR8DiCrS9pL3CVNdPFDFfnwbTQWysUAMWZMWzs
         MB0FBwBxa37WPz9Vg7aB4lvOVXVqcc+GSNg+X9p0QrkMSznwuHkooCWtOU6of8pZbCxZ
         PDYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=oQ30wHYDk3I+0gjyGKhu0vCTArobW5cTclMO+7MbTpI=;
        b=oXTM+07NKzwjvH/uWFXu4ZbbL8bdoakP+mRnkuOM+Cx5wnZss/idyJy4APWYMeRv6T
         NmvLVeNZ4xmZETVR+dWHOjbBenC1xUIdz8SRUfDuvBCT7Ms7qVscKJtXlbPHiDrmF+Gk
         QvFyXUtvHh73wtM3oKJ7C8BnctV5EhjHLtPp+Qh5OIaoO3DZxk4VC4kOaGysvtwQ2eWN
         RWbIozzVLIQeWT4LEr98BKIgOlZHzPCpXvsFWmc8m9NR/8xuCMAl8QLzaeeErt261ENv
         Papo8f39w7EzkLSwThCVZtSkXBiqNKXc2qYLTRTPD9t4TWTD/hL5Nas+EPxFOPvr4xfo
         vUFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id b8si203441pju.2.2020.06.30.07.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jun 2020 07:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0187473.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 05UEXCca075212;
	Tue, 30 Jun 2020 10:45:49 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 31x1rvv7av-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jun 2020 10:45:47 -0400
Received: from m0187473.ppops.net (m0187473.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 05UEXRL3076948;
	Tue, 30 Jun 2020 10:45:45 -0400
Received: from ppma05fra.de.ibm.com (6c.4a.5195.ip4.static.sl-reverse.com [149.81.74.108])
	by mx0a-001b2d01.pphosted.com with ESMTP id 31x1rvv748-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jun 2020 10:45:45 -0400
Received: from pps.filterd (ppma05fra.de.ibm.com [127.0.0.1])
	by ppma05fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 05UEU11p022017;
	Tue, 30 Jun 2020 14:45:30 GMT
Received: from b06cxnps3074.portsmouth.uk.ibm.com (d06relay09.portsmouth.uk.ibm.com [9.149.109.194])
	by ppma05fra.de.ibm.com with ESMTP id 31wwr89rve-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jun 2020 14:45:30 +0000
Received: from d06av24.portsmouth.uk.ibm.com (mk.ibm.com [9.149.105.60])
	by b06cxnps3074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 05UEjSA01114434
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 30 Jun 2020 14:45:28 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6006F42059;
	Tue, 30 Jun 2020 14:45:27 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 429B34203F;
	Tue, 30 Jun 2020 14:45:26 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.148.202.137])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 30 Jun 2020 14:45:26 +0000 (GMT)
Date: Tue, 30 Jun 2020 17:45:24 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>,
        Abbott Liu <liuwenliang@huawei.com>,
        Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 4/5 v10] ARM: Initialize the mapping of KASan shadow
 memory
Message-ID: <20200630144524.GB2500444@linux.ibm.com>
References: <20200615090247.5218-1-linus.walleij@linaro.org>
 <20200615090247.5218-5-linus.walleij@linaro.org>
 <20200615143316.GA28849@linux.ibm.com>
 <CACRpkdZvQgPXBsdUO1JwBW0gE-Jhse0s8U0-Y5BGCcxkq_Ue2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdZvQgPXBsdUO1JwBW0gE-Jhse0s8U0-Y5BGCcxkq_Ue2g@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.235,18.0.687
 definitions=2020-06-30_06:2020-06-30,2020-06-30 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 cotscore=-2147483648 lowpriorityscore=0 phishscore=0 spamscore=0
 bulkscore=0 adultscore=0 mlxlogscore=999 suspectscore=1 clxscore=1015
 malwarescore=0 mlxscore=0 impostorscore=0 classifier=spam adjust=0
 reason=mlx scancount=1 engine=8.12.0-2004280000
 definitions=main-2006300106
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE
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

On Tue, Jun 30, 2020 at 03:22:19PM +0200, Linus Walleij wrote:
> Hi Mike!
> 
> First a BIG THANKS for your help! With the aid of your review comments
> and the further comments from Russell I have really progressed with this
> patch set the last few days.
> 
> On Mon, Jun 15, 2020 at 4:33 PM Mike Rapoport <rppt@linux.ibm.com> wrote:
> 
> > > -#define pud_populate(mm,pmd,pte)     BUG()
> > > -
> > > +#ifndef CONFIG_KASAN
> > > +#define pud_populate(mm, pmd, pte)   BUG()
> > > +#else
> > > +#define pud_populate(mm, pmd, pte)   do { } while (0)
> >
> > Hmm, is this really necessary? Regardless of CONFIG_KASAN pud_populate()
> > should never be called for non-LPAE case...
> 
> It is necessary because the generic KASan code in
> mm/kasan/init.c unconditionally calls pud_populate() and act as
> if pud's always exist and need to be populated.
> 
> Possibly this means that pud_populate() should just be turned
> into do { } while (0) as well (like other functions called unconditionally
> from the VMM) but I'll leave this in for now.

Yes, making pud_populate() a NOP will match the "generic" implementation
in asm-generic/pgtable-nopmd.h. 

If this patchset will get to v12, maybe it would be worth doing that  :)

> >         cpu_switch_mm(tmp_pgd_table, &init_mm);
> >
> > And, why do we need a context switch here at all?
> 
> This is really just a way of reusing that function call to replace
> the master page table pointer TTBR0 (Translation Table Base Register)
> while setting up the shadow memory.

Right, but is this really necessary to create the shadow page table?

If I remember correctly, the mm parameter is anyway not used by ARM page
table manpulators and pgd_offset_k() can be replaced by
pgd_offset_pgd(tmp_pgd_table, ...).

> Yours,
> Linus Walleij

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200630144524.GB2500444%40linux.ibm.com.
