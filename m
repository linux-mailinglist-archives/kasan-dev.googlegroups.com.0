Return-Path: <kasan-dev+bncBDE5LFWXQAIRB65MST6QKGQEYJWT52I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A8392A9279
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 10:25:16 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id f9sf289577qkg.13
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 01:25:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604654715; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9ytoOC1XOl27BgLBpE4aQOz3z+OJrp5C6hQ6uSWlULb6hUt1UTFiB3GkyMZaPCypQ
         9e18WzgS0K7/Iux/gqWJS1W9P07bpd+bgoBFBJ5m78WaOVWIJzZwIuiNkdImsbUUpzxn
         ZaHiNQj1B/ZXi8o8Y8T71tgwBo0BYmTqtWc5/kjKNgdF0CCgtMiH7/A65pAdRuABw3fF
         AiEX7NPyiDMG+dydl9sozpj2EUZoqWjfl//pW7EmpvbtBK4m/j1RYT7gXly07EP+Iu3P
         r7Ile/t5Nf4HMseT4j+8BD6u8EmcWcwoYKDZ2UKsfmKqSUFi36PeQxsvDQUeBH5Uzl0u
         74+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Hca9ozmYwn7+1oCPbRY9twfaUCG5Rbw7QAyKVdSgteQ=;
        b=vMt0wfG3QGi6yCCCB1wQ/4fbsJVlqjYYDP/G5ANIvJWqgdY53xDLR+aAJS2H3749RQ
         mKuf4PrrpgkUkdBiCNJ27yD0S7uuimoDsgNmccBr4tjhno9gJZS5JrMgQ8RB4St2oeA7
         WE6fogrnl8IlfPVosRj8vOgfH5U6Bw1RPJN4kbLDv8kedE+Bo3taWDcXRPxesTaOtot4
         S5ZRIMO6hEGyaTLgzwWNZB8DYV7rW7NdwR9cWExQT29gMnchcvs/nW0FYuSpGKUDH87v
         pgx18tcylk0bczUY/xW5PkOfJJtKfca36ydLjyz3w5QkyUrxA2PGjrR4F80GvfJtD9qJ
         yvNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="ktNx/CDj";
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hca9ozmYwn7+1oCPbRY9twfaUCG5Rbw7QAyKVdSgteQ=;
        b=IdRD7vR+dZ5ix4vCEiTQQODyI2sDbD7+p7aTCvlQkl/oVIVqDBskeldx/kBytJYgoK
         HrpRS0JCaXT+HtS+qsMB0yXnBa9lxhVOGpyuNtDTpmt/vCBcJezx2U9h4/Vt7WZtrtyW
         +fHAeI3YV1EuACvoo8katY7xDZooDHm2xVWpTKHCOO0Xw1j6PNEKnRa9W1bTlvgxMLe6
         U7MDNFMbmOsNCu/IspOwzEmSfdm3yRW6RlTJLj445VFV/WzJJupsFSLgYGwK67m+BWc3
         6QL3EFzj4b2bhAc6GfW+hGkBFZqHYbOINpHTlzI4LHIuicxn+msb1/9uqHSMG+u/3Ws0
         bw2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Hca9ozmYwn7+1oCPbRY9twfaUCG5Rbw7QAyKVdSgteQ=;
        b=izxIZ+veOjWXog8W4eRrAC7z8lIfUhgAO4woACCVi+/a/pIum8M1oRoFH80TvoFXrK
         szlZoukvGBh7/unij4lu9t/EXRK6Jxw1peWvzKVaf/pGboXPzwmutq6gziB6eCfnWpKj
         k8H+FRoIhYuMQGJvEoG61UkI18j3i+6g5E/SKsC2UjXx6ye854bnGb2FZ8ButSa7Lf/u
         TqhRDNFggtvBmRSER73HYTfbEX7uH9rlyzH09M0lvGDYw2Ok56aorQDzV3EtCQ9xjR8A
         b4SqFLMs9VnOhZpdSEImmYzvq6jHyiyhmYReTRg/QSaegQ7Quj7AP+QBjGREziKVElMs
         u4zA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VamOeU9RLCrx/g2VtcY9355r8RMPOWxIvaG08QKCSYFAR7UEv
	7PMhCrEv3RhUURnQ1acWSmM=
X-Google-Smtp-Source: ABdhPJykIcsF7vBBu6J5QKSuE7twn06P3TaYZx6Jq9kw07gJdJIMN/vbz3DxiYtahYrRe8ZGakYNMw==
X-Received: by 2002:ae9:dc06:: with SMTP id q6mr655264qkf.310.1604654715199;
        Fri, 06 Nov 2020 01:25:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2726:: with SMTP id n35ls305903qtd.3.gmail; Fri, 06 Nov
 2020 01:25:14 -0800 (PST)
X-Received: by 2002:ac8:3797:: with SMTP id d23mr634988qtc.205.1604654714755;
        Fri, 06 Nov 2020 01:25:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604654714; cv=none;
        d=google.com; s=arc-20160816;
        b=xXh+0THg2vX4f45ifd8HBd72xVWu9OtkiJhpObK8lnnUT/0YDWNH7/ahuf/teg9aJy
         PuIR/8CX1QLVCgCaCdUIRFvUp8ylpLaxaS2jVW+AuetR+siNr6scKPuMbfGJ5WXBpPpl
         +2sdAPHTuTdrQ5umg4HJYfSBSABQ0y934pKaD/QRU0paE4+7SKeE8oQ/ldYPPShJ2W+W
         JOJ4jfcEtEvqCm//OiAXOLErQ7MJopfP5EEWYybm+TsFZ4wDPWZdk1RzaB+4jMPU+fF+
         10fMF/MeW3W0TQmq8m1zpdOYXaIeyWtat+VLnc+F5QF/iFguYKTzWfvGdek0TQF0uBKO
         qnJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=whxGTLidgt4WCSNFPfbVNsLDhpMuDlzniATFjm780nU=;
        b=inSgoAGt/L1AyNEtySEZ/7V1h04DlptjdMXDTgMC1ei8FrR6ujscHT5sgcIznrFxWi
         D9uw2lJucoqRhGIV7Rv+R0pk8tWKQHoq4U0nLYHF7yRLy+t2Kq3uchgv2MH6h8ABp1E+
         bQ98iwG73P7hpLirgnKgSevlcZMA/T5rgypQTRoyQJyjPKW6KJg3mgF79+cJVR6WA22V
         utv8sjnp5MLX0oyCWxc2Wtz9yDFjbYvoKXjqm91vCLG3Xmc4T7OtFEvKX7Jh4ajwDYz5
         zjLgtH9k+poCKwvyoYLHcl+TJacGSxOtDxWqMnKU9Umc801NZ5L9mxRTFTbG5dhUR4aZ
         pewg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="ktNx/CDj";
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id t14si34801qtq.5.2020.11.06.01.25.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 01:25:14 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098410.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 0A693lYn144185;
	Fri, 6 Nov 2020 04:25:11 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34mhxk9ywp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 06 Nov 2020 04:25:10 -0500
Received: from m0098410.ppops.net (m0098410.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 0A69FrhU043716;
	Fri, 6 Nov 2020 04:25:10 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34mhxk9yw1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 06 Nov 2020 04:25:10 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 0A69E48l003402;
	Fri, 6 Nov 2020 09:25:08 GMT
Received: from b06cxnps4075.portsmouth.uk.ibm.com (d06relay12.portsmouth.uk.ibm.com [9.149.109.197])
	by ppma06ams.nl.ibm.com with ESMTP id 34h0fcxbcg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 06 Nov 2020 09:25:08 +0000
Received: from d06av21.portsmouth.uk.ibm.com (d06av21.portsmouth.uk.ibm.com [9.149.105.232])
	by b06cxnps4075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 0A69P56265798542
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 6 Nov 2020 09:25:06 GMT
Received: from d06av21.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CF2625204F;
	Fri,  6 Nov 2020 09:25:05 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.7.6])
	by d06av21.portsmouth.uk.ibm.com (Postfix) with ESMTPS id B29065204E;
	Fri,  6 Nov 2020 09:25:04 +0000 (GMT)
Date: Fri, 6 Nov 2020 11:25:02 +0200
From: Mike Rapoport <rppt@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
        linux-arm-kernel@lists.infradead.org, Arnd Bergmann <arnd@arndb.de>,
        Ard Biesheuvel <ardb@kernel.org>, kernel test robot <lkp@intel.com>
Subject: Re: [PATCH] mm: kasan: Index page hierarchy as an array
Message-ID: <20201106092502.GE301789@linux.ibm.com>
References: <20201106085157.11211-1-linus.walleij@linaro.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201106085157.11211-1-linus.walleij@linaro.org>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.312,18.0.737
 definitions=2020-11-06_03:2020-11-05,2020-11-06 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0
 lowpriorityscore=0 malwarescore=0 priorityscore=1501 mlxlogscore=999
 clxscore=1011 adultscore=0 impostorscore=0 bulkscore=0 spamscore=0
 mlxscore=0 suspectscore=5 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2011060066
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="ktNx/CDj";       spf=pass
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

On Fri, Nov 06, 2020 at 09:51:57AM +0100, Linus Walleij wrote:
> When freeing page directories, KASan was consistently
> indexing through the page hierarchy like this:
> 
>   static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d) {
>     pud_t *pud;
>     int i;
> 
>     for (i = 0; i < PTRS_PER_PUD; i++) {
>       pud = pud_start + i;
>       if (!pud_none(*pud))
>         if (!pud_none(pud_start[i]))
>           return;
>     }
>   }
> 
> That is: implicitly add i sizeof(put_t) idices to
> the variable pud.
> 
> On ARM32 arch/arm/include/asm/pgtable-2level.h has folded
> the PMDs into the PUDs and thus has this definition of
> pud_none():
> 
>   #define pud_none(pud)           (0)
> 
> This will make the above construction emit this harmless
> build warning on ARM32:
> 
>   mm/kasan/init.c: In function 'kasan_free_pud':
>   >> mm/kasan/init.c:318:9: warning: variable 'pud' set but not used [-Wunused-but-set-variable]
>      318 |  pud_t *pud;
>          |         ^~~
> 
> Using an explicit array removes this problem and also makes
> the build warning go away. Arguably the code also gets
> easier to read.
> 
> So I fixed all the kasan_free_p??() to use explicit
> array inidices instead.
> 
> Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
> Reported-by: kernel test robot <lkp@intel.com>
> Suggested-by: Ard Biesheuvel <ardb@kernel.org>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>

Acked-by: Mike Rapoport <rppt@linux.ibm.com>

> ---
>  mm/kasan/init.c | 16 ++++------------
>  1 file changed, 4 insertions(+), 12 deletions(-)
> 
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index fe6be0be1f76..3c74c30996ef 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -285,12 +285,10 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  
>  static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>  {
> -	pte_t *pte;
>  	int i;
>  
>  	for (i = 0; i < PTRS_PER_PTE; i++) {
> -		pte = pte_start + i;
> -		if (!pte_none(*pte))
> +		if (!pte_none(pte_start[i]))
>  			return;
>  	}
>  
> @@ -300,12 +298,10 @@ static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>  
>  static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
>  {
> -	pmd_t *pmd;
>  	int i;
>  
>  	for (i = 0; i < PTRS_PER_PMD; i++) {
> -		pmd = pmd_start + i;
> -		if (!pmd_none(*pmd))
> +		if (!pmd_none(pmd_start[i]))
>  			return;
>  	}
>  
> @@ -315,12 +311,10 @@ static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
>  
>  static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
>  {
> -	pud_t *pud;
>  	int i;
>  
>  	for (i = 0; i < PTRS_PER_PUD; i++) {
> -		pud = pud_start + i;
> -		if (!pud_none(*pud))
> +		if (!pud_none(pud_start[i]))
>  			return;
>  	}
>  
> @@ -330,12 +324,10 @@ static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
>  
>  static void kasan_free_p4d(p4d_t *p4d_start, pgd_t *pgd)
>  {
> -	p4d_t *p4d;
>  	int i;
>  
>  	for (i = 0; i < PTRS_PER_P4D; i++) {
> -		p4d = p4d_start + i;
> -		if (!p4d_none(*p4d))
> +		if (!p4d_none(p4d_start[i]))
>  			return;
>  	}
>  
> -- 
> 2.26.2
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106092502.GE301789%40linux.ibm.com.
