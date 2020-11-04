Return-Path: <kasan-dev+bncBAABBYP4RP6QKGQE6GTH37A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE1402A6DB8
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:17:54 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id bc2sf13650749plb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:17:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604517473; cv=pass;
        d=google.com; s=arc-20160816;
        b=gFtZ1+wmZH2MRq6QhtVOm+Wnl/O1Pg1CNWRVMnb2S7juHm5nXIwp/NirUdMH66tMLu
         6BIp1i9WRuA8mX4qU/3RWAuwoWYUOo9eAF7/IF9r+gNX9LA4gyVLe3bC8OYpLERSYLaU
         vaNVlZDu2ZbcxWopBCo6P10gU6f3aMTf28EFMQdFrahrnzH9YzgEyGfgkHH0dN1v2rxg
         FhiQPCm4Hc2ye+poOXHtz8kebF98I10sX9f42UACOMW8m9IjhNEV8Oi+8WEjZwNuZz4G
         lP3WG1Gr+JNmKFOPUo0qwdPa9wIhGckZp+fnsW62L6z5kpctmn9DoDbreQoIP7XTOatl
         Vrlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7qQPjJ7yMWiw8sNEjSbX5iLAtnlGyZm9EUm5cCCSjJo=;
        b=xufRdVAO5iPLzyDb0e7BUVV0aIFTyo+DgMfwc7iPli+BAUfXChBn6+D3jWgmOOsO0z
         DKAGi0ntGzCHVHblPGZbUNblO9fvXHpxCQ2Ao6Mp0ikdC++XMeUfgFGFhm15bp3b9CdB
         QD+62BzDTMXvP+OZHYLyKJ4cT0/NMNgAeE6AOhXTJ0F8FGtb3WkJirjQM2eflPpT5FgG
         ChL2BCwyOlDQ/tWA/PlxDR0Ro32NvFz/pdkzAdHO38HzstcmpVXDSOYffm/RqiSLWKlI
         Cvw67bUVDFYYXrVRfYMYTgmpIyIWsiVXX8p7BflUY50wJmEO/tAth9MD166atJIEeid8
         VoAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ovWSDkZj;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7qQPjJ7yMWiw8sNEjSbX5iLAtnlGyZm9EUm5cCCSjJo=;
        b=mCr8hwa7IeU163yBfuzabuWHvBXvuCaiEJWKV+fGQXJAHo8qvd28gJ+VWGPm1a+cn5
         aX7BDJw5XazV3KA7lOCPxu9pa9oSUsviuhXDuuTGOedWzPAaN6J1feyiJwRoKgjXw/U6
         4lE3CH0IcwBO3V6k/ZXATPx0Tf08rLgcLwBzvjOOilP3Jv8dOlG5isiqdnGUKjjTCWXU
         E0diVkmlE7oglFXYpCz64YAoifvHif2SexBRnOedTWxEZbyVpMChvx6WzaGfGRUsR9Ox
         QIY9FDpJIoVA7gLxLEZuvNRWZd09meCaWa2eZQpzvser0nCA6+Ii/0qYYKJ+CnY621MV
         2Sxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7qQPjJ7yMWiw8sNEjSbX5iLAtnlGyZm9EUm5cCCSjJo=;
        b=O9dcDcW41YOcNMZG5zckyDzjKsbUh6MzzoSQzZimvgKyGxLT+k8O0bhoeXYyIe0Vga
         LzqkWPQfv1Cup0XbpAwmMHqF0SVsuGDfnO28ZfSDPM2lGh9WNANp1F8JSaHd6jgONNWM
         3VXWyw+3Cj6S5iQ4q5tENGB40d7LIgpYjFh9jJGO0KtEe5p/tc2bQbO5CZJQC6872uOn
         Mzr1n2MKStD1bqlWoNeeRovILwkPrNUYHjt8V0BxJjBFE/I9KTxOhiZpok+uTUisb0XP
         XfDf+ATZ65IRQ3KbSfEDYjhDIlxKMuyCN6ZnJfpQrgo98Ed0yyrb0JFNMtpSTUZjPGW/
         cu1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532N9efA+voa3agQQKkyemlJIUECnSYXSVN3RIl90emYqF0MU5UA
	So08hGei5K6wkzzWZ3PPnAE=
X-Google-Smtp-Source: ABdhPJwhdvISe5RCKsgd39+hDz/czFPwoLwb0OXtNBSWGoB2zu8JmCQtXQmEgEJC8aeXbIRLalNpxA==
X-Received: by 2002:a63:984:: with SMTP id 126mr22768841pgj.231.1604517473322;
        Wed, 04 Nov 2020 11:17:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:da56:: with SMTP id l22ls1277048pgj.9.gmail; Wed, 04 Nov
 2020 11:17:52 -0800 (PST)
X-Received: by 2002:aa7:8545:0:b029:163:c9a5:97d with SMTP id y5-20020aa785450000b0290163c9a5097dmr31549097pfn.38.1604517472826;
        Wed, 04 Nov 2020 11:17:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604517472; cv=none;
        d=google.com; s=arc-20160816;
        b=zVRoHpzD8mOeEV77xv2yTAVeScI8vkHSwXHfsmCHmU3mCKDR4WaSNC/X4QybdNMqs3
         OPW77xRQttMuO8YW9WJD9scbrgTbVYEwMzzF1iiuJcAkt5mHd/UHeZ1gPVnxMn2cEo7n
         zxq/1aiYzOM2iDOFlZGMNpoioDEj5cDMG5Q56DJclQUbx6gxwrVVqUClyF7NIJ82afJl
         wBWZeTBzXo9GFsF3xJzyrzqvpxaeIlVhSgYXoOBfVx0hwj0wLWdsR4Lxgl78psrGYo1V
         76BQrZW03G4zV5Jo5ftrGM1mSV134MOkSQAqGiWHs/UfXJyT91kQKajnnwdpKdrNrphI
         Zw1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fdOGxWPYu/5JHKOXeU4bs0lQc/pjEQxcAHUKgqGUprs=;
        b=nsDeiClFWDPR27L+MHQc5DB1KbAuZn7UyedgFeEU+8fxdCzmzKPE7l7jcJ5o7hPbGw
         nLlhV8zUuyBNkmVJ+jDhBhiCY99ru86KRHVCcaTeVbVJ2wLam7veefGRRzf0Wgx/77OZ
         8n+XVipoRem4yz7GAO/BFi2GdAf/mCzy+kGp4iND/xc+dbLnji6Eqo+gocBL6uwODlb3
         YyTVc/4mnF9q2z4N2xGWb8/ZsuS1YvNwsXUQiwe0M1zKGKJojHuFLerQlearoWTLq4Hl
         FjSRjdEbm1jRlZpsFIYRAjVb+iq7lDlWRhZHlecNWpjFkz46q3hHVvXMN2OXHy5TGF9O
         NQHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ovWSDkZj;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d2si250148pfr.4.2020.11.04.11.17.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:17:52 -0800 (PST)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0127361.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J2RRX006370;
	Wed, 4 Nov 2020 14:17:49 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34m1v40u82-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:17:49 -0500
Received: from m0127361.ppops.net (m0127361.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 0A4J2Z84006711;
	Wed, 4 Nov 2020 14:17:41 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34m1v40u75-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:17:40 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J7Jgb021441;
	Wed, 4 Nov 2020 19:17:38 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma06ams.nl.ibm.com with ESMTP id 34h0fcvn7s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 19:17:38 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 0A4JHaoC3539506
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 4 Nov 2020 19:17:36 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 24EAE4C040;
	Wed,  4 Nov 2020 19:17:36 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F10C64C044;
	Wed,  4 Nov 2020 19:17:34 +0000 (GMT)
Received: from localhost (unknown [9.145.163.252])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Wed,  4 Nov 2020 19:17:34 +0000 (GMT)
Date: Wed, 4 Nov 2020 20:17:33 +0100
From: Vasily Gorbik <gor@linux.ibm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will.deacon@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
        Elena Petrova <lenaptr@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 34/41] kasan, x86, s390: update undef CONFIG_KASAN
Message-ID: <your-ad-here.call-01604517453-ext-4014@work.hours>
References: <cover.1604333009.git.andreyknvl@google.com>
 <bd64e051e8e36ac25751debc071887af3d7f663f.1604333009.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bd64e051e8e36ac25751debc071887af3d7f663f.1604333009.git.andreyknvl@google.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.312,18.0.737
 definitions=2020-11-04_12:2020-11-04,2020-11-04 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=1 adultscore=0
 mlxlogscore=999 clxscore=1015 phishscore=0 spamscore=0 priorityscore=1501
 mlxscore=0 malwarescore=0 impostorscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2011040135
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ovWSDkZj;       spf=pass (google.com:
 domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=gor@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Nov 02, 2020 at 05:04:14PM +0100, Andrey Konovalov wrote:
> With the intoduction of hardware tag-based KASAN some kernel checks of
> this kind:
> 
>   ifdef CONFIG_KASAN
> 
> will be updated to:
> 
>   if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> 
> x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
> that isn't linked with KASAN runtime and shouldn't have any KASAN
> annotations.
> 
> Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
> ---
>  arch/s390/boot/string.c         | 1 +
>  arch/x86/boot/compressed/misc.h | 1 +
>  2 files changed, 2 insertions(+)
> 
> diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
> index b11e8108773a..faccb33b462c 100644
> --- a/arch/s390/boot/string.c
> +++ b/arch/s390/boot/string.c
> @@ -3,6 +3,7 @@
>  #include <linux/kernel.h>
>  #include <linux/errno.h>
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>  #include "../lib/string.c"

for s390 part
Acked-by: Vasily Gorbik <gor@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01604517453-ext-4014%40work.hours.
