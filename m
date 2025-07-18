Return-Path: <kasan-dev+bncBCVZXJXP4MDBBQEA5HBQMGQEPABTO5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1B6EB0A44A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 14:38:26 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b38d8ee46a5sf1976187a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 05:38:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752842305; cv=pass;
        d=google.com; s=arc-20240605;
        b=hPPdK92s3n8bHMa9mOHX8Hgo2KGeGuU9qvEBw70mhSLWdOL3UU8G9FC6R0VEAJLNJH
         Ni4D/F64IMtW8jB+GR7aI8bIUzbFuTUAayr/N93m8VXpr6vDi5n9UFk6oFW0ZzEEeBQL
         w6ZXXUjvoyW1SLjX/XlJkDRKzm5ChGm77JwKrcQt1hqleykiNIoSSYpOGzR8WVXlNkid
         t6RXS6+XTfql7ePoZKXlqpu5MXea/GffIFTy6EId5X0NFHQPJQ8vMa0ZNArCKHIcxk6d
         yhCg2ujykfLFeb9pUnsvWSDhCxwLIijOIQXvPqDpaUF191xWbz7yI+rrLWLniYkuF4o+
         wsFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OCd1TsTx+M10z6qtChWGkTeAB3O7DapAo2h51tNuvGk=;
        fh=KdA2QisTplC9VTxayQ4wTJr/hdCAA8Tvxt9+9vL9QfI=;
        b=HalurlgvNoiOUyWnyazmIf1wwIk/9bJtJMw/B/a4elivoTJ2MlV3gX+SjCIHNSL2wH
         oKC+nEYQ31KnT0xwT2LnTUEGLIQQqBCepc8iA/HnWDEfM9Ex1wezQ5dfNK0Zye2A3ii0
         w6F4E+2dOqZLFsSDH6XeW0QF3+zDoezCKDVR5jFdePdBlwKmJwc1C04aqoD24RKI0eMq
         Q0NuJvzLVpqhi4s2tyGnG0OuLeRS908lWCo40aqYairSkhCRZKYHFeaML/NDqaMMAOOF
         AGG6kvvI/5s2erVkOCiJsOVWRoekZ5+ID2cqUWe4qOQCEKVyGjDNQkPd9YlFtRnPf3MK
         CotQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=URKeXKJu;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752842305; x=1753447105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OCd1TsTx+M10z6qtChWGkTeAB3O7DapAo2h51tNuvGk=;
        b=F1mGLA2mAiiVMjrS1+4rWq4yiVIyBD5OJznNESWSCNRGH5wkvR6+QGWJRpFa+617Vu
         9Q83alagNNpuXqibU8dKuvdrMGVGGSlBLzj2PSMc+4g+yOZYA8XpndOhu9ADqxgeRRCT
         iv47k7/cLcU14MEZSccMQ+cxxKc1UAy1WwsULONwYLb3g35HKAgd3yCOZoNydj75vZNM
         q4LBNKSLkzbbE0/5w9I5g7qfcbW1htMqGOibsctZXFOoCOVSesVfHWdkalCA9nSUwWPz
         romYHoPHfK4aYUxYF4AS5xxYRO/ITgnxS67+RLWJUj8LnpZSA0je1GbnfAiRjz839OzC
         LzPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752842305; x=1753447105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OCd1TsTx+M10z6qtChWGkTeAB3O7DapAo2h51tNuvGk=;
        b=JCq+BDqPA0sfSE59ARwfMP7BbksWHMFG6ivsoosWUaZ0kSeONq2NrFYZ17oIO2Au9M
         b5k1S3Kj5udr8wHvYnXnnBSp1blO40pDSiohLL98rsn6yXanfwo1VYDWPCBp456uyFao
         +Akev56rAS/IDTDzwz/NF74i9pFL5OorYWGbuZVYDMYAuRPf4B4dq+bX2PxMBuHo1uwc
         naphECHV2VVouHAf++fYsd1HgNMoo2bQJinlodZkvl8ylSFpN+FnkzCmYN5wvY432Vez
         y4rS7gQtkjr5v6Ms1vwM0LQOJj3TeIWxl0f9Kj75HkY78CeQWrOl6znNotIZNku2eCKg
         1bmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRbTz27Qy9lfpabndi4fzOj1d+kZGXYACpS901JKYJqFHzvLy47i7x7ysF2nwq/Jaaoqx4hw==@lfdr.de
X-Gm-Message-State: AOJu0Yz9AZ29bE6hgwFDWNE2xP/V1LBKilmLd73LrooLYyrbJJR61idC
	4M2oXgZSHcMHhz6NVGPgECXCkuBkkyD5qb3UaTt1eph9FY30F3XwwNBY
X-Google-Smtp-Source: AGHT+IFGTdx9j3Vu1dfhbkSzuTWGkdd8ouVzzhSuoInP5G/VYM/VSblEFclbX1DkNJzwpcWnZoay/A==
X-Received: by 2002:a05:6a21:998b:b0:238:351a:f960 with SMTP id adf61e73a8af0-2390c84dd57mr11890067637.23.1752842304751;
        Fri, 18 Jul 2025 05:38:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeZcz/gzWZXlkYSHciu/o9cj1IPqojCWlYQjmhb9KWl3A==
Received: by 2002:a05:6a00:301f:b0:756:a488:4d6a with SMTP id
 d2e1a72fcca58-75914683cccls613803b3a.2.-pod-prod-00-us-canary; Fri, 18 Jul
 2025 05:38:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqjsaHhrEDh2c6UnGAEe/B+5GzD2vX78OIXgnpKpiU6mUZfhHhyk/MaLdCi/00HWmEWElWT3sLPaU=@googlegroups.com
X-Received: by 2002:a05:6a21:b97:b0:235:7452:5867 with SMTP id adf61e73a8af0-2390c80c2a2mr10969193637.20.1752842302979;
        Fri, 18 Jul 2025 05:38:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752842302; cv=none;
        d=google.com; s=arc-20240605;
        b=hUqjNF4CS9tIFfwYTjwYLkhouhL2W0j883QYbZFueQNRwFfTBVCqRpJkfeDawPCR7l
         91NMrRXRhi+mEqePKTa5w5DZQ6ZrxiYNAj5od9L47i79m11fxFRzJCOsnVrvMZiuhmGr
         LWdPoJVZ/xFAWwVitddr0E8lPTX4r4AsqIh9t1w3PvVzayMdgTW+qt6gg0SRnaTW7RBw
         L6Y3gK9NSKUwCWhQw/cxxJwKdzhu3vyEhwMcdhuBHYg2DtFJoTgUh6OoEa4PpeNh5e3Y
         Q9mHkC1xcCON+g9jTbNkqG0ZOnVwzXgtUUYpn5TEzenisKXHM+ieE+/LM+l5MQ4btAOd
         gEpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AJ7Yc9S8ybUjsYZ6mEaq1yLAIUmrbNSGYdtADWMsG68=;
        fh=guuIat1T0YbT7cNxCBN4i+yC/+npJB0DEKEXacYUZeQ=;
        b=d656c+7zkFTRyitU0Q900HE8jJ0kwCmq2Y0ib7qFbGXRnXBZT6Rz3Ja/wCx8VZnFgM
         Nr9YkykEkn+Z6NPvdu6giaaYcLvFxwQ7bGkKtXKLd6y1jTOfNBU1LMlx77+zFB99N+NB
         TAolOQ6FhZUX/7uhG8b7CwB8DrJ2XDTYlVwUJ+RbmGEmJ7WfO6OuPiGZQZ6CqTNU/pa8
         Lr2i06H95M706AJ4i/XKQaXLURG1luXjQrDYBKIriLCa7MLB+t+RHVQFT+Mub4J5iBkh
         9n+8aEfg05xoUOHBXm3YbQfw4JEqcWcI3Rx/WoXzGTbvvBC6qoFghuIUuayO0WUsFAEZ
         1DVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=URKeXKJu;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b3f2ff1be5csi83836a12.3.2025.07.18.05.38.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Jul 2025 05:38:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 56I8Vqmq024126;
	Fri, 18 Jul 2025 12:38:19 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47y07txh9t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 18 Jul 2025 12:38:18 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 56ICcIx9012599;
	Fri, 18 Jul 2025 12:38:18 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47y07txh9p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 18 Jul 2025 12:38:18 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 56I9BoEl025987;
	Fri, 18 Jul 2025 12:38:17 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 47v31q18vh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 18 Jul 2025 12:38:16 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 56ICcEjA53543262
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 18 Jul 2025 12:38:15 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E2E4A2004B;
	Fri, 18 Jul 2025 12:38:14 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B69C620043;
	Fri, 18 Jul 2025 12:38:13 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.87.132.117])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 18 Jul 2025 12:38:13 +0000 (GMT)
Date: Fri, 18 Jul 2025 14:38:12 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
        akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com,
        dvyukov@google.com, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-mm@kvack.org
Subject: Re: [PATCH v3 10/12] kasan/s390: call kasan_init_generic in
 kasan_init
Message-ID: <8412bf39-8235-4abb-ae35-db6029a605b3-agordeev@linux.ibm.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-11-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250717142732.292822-11-snovitoll@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: mdxNuC1xCFhuxtIpSH9TZqP6KhLLlotA
X-Proofpoint-GUID: vIORyTF4ypaBonjC46BtYf4jbJ2mxKDQ
X-Authority-Analysis: v=2.4 cv=d/v1yQjE c=1 sm=1 tr=0 ts=687a403b cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=kj9zAlcOel0A:10 a=Wb1JkmetP80A:10 a=VwQbUJbxAAAA:8 a=pGLkceISAAAA:8 a=VnNF1IyMAAAA:8 a=cM5Q7b1H7_XZ2lFhe3QA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNzE4MDA5NSBTYWx0ZWRfXwYseivfKqS1x J8WeqMyeE4+9+fwXyYNzZbOhx8wQEU+BxVKA5pL924Piu0WwYnZ0ds8Gg6cLrfaUCEmqngt+K2h v0iQpTIsCHidE0ZLR0UHnsBWuH3UYoIGkKH5HBy3pVo4QZasuFlmAgru0z1FY/j8NsXwfkpXZxf
 P46pOLu6NzYfd/QSa1kpO8S7p+tsd29lPZD2iYUmkG34IGk5n0wysprtNon/KZ0ojmcC9eLbIuy IJZ06FnAowNYqChDKS5euUgyI5PN9bMJlP6hA85NQeYAk9U5yWGraX/LIaWr6M8JtPEGSrTaRm/ 97uHxnx4L8KCPt+hyzHTf8w8bwvZvsP8xkv54H22+2e+so4ZRLAKAvDB9IiTB51ufI4/jZQUx39
 cC7c3CC6MUmnD00YlyhwGtbDdUSPCITIRC25vIbBO7x884VH8097j8NcoFOgTL8icQ3rTJvo
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-07-18_02,2025-07-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=984
 suspectscore=0 spamscore=0 adultscore=0 mlxscore=0 priorityscore=1501
 lowpriorityscore=0 impostorscore=0 bulkscore=0 malwarescore=0 phishscore=0
 clxscore=1015 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2507180095
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=URKeXKJu;       spf=pass (google.com:
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

On Thu, Jul 17, 2025 at 07:27:30PM +0500, Sabyrzhan Tasbolatov wrote:
> Call kasan_init_generic() which handles Generic KASAN initialization
> and prints the banner. Since s390 doesn't select ARCH_DEFER_KASAN,
> kasan_enable() will be a no-op, and kasan_enabled() will return
> IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.
> 
> s390 sets up KASAN mappings in the decompressor and can run with KASAN
> enabled from very early, so it doesn't need runtime control.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  arch/s390/kernel/early.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
> index 54cf0923050..7ada1324f6a 100644
> --- a/arch/s390/kernel/early.c
> +++ b/arch/s390/kernel/early.c
> @@ -21,6 +21,7 @@
>  #include <linux/kernel.h>
>  #include <asm/asm-extable.h>
>  #include <linux/memblock.h>
> +#include <linux/kasan.h>
>  #include <asm/access-regs.h>
>  #include <asm/asm-offsets.h>
>  #include <asm/machine.h>
> @@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
>  {
>  #ifdef CONFIG_KASAN
>  	init_task.kasan_depth = 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>  #endif
>  }

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8412bf39-8235-4abb-ae35-db6029a605b3-agordeev%40linux.ibm.com.
