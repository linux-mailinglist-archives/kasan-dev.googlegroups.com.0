Return-Path: <kasan-dev+bncBCYL7PHBVABBBEOR2CWAMGQETR4ZK4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 58990821E81
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:15:31 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dbdb14f811csf11052130276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:15:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704208530; cv=pass;
        d=google.com; s=arc-20160816;
        b=KEFxActr+/yO+2WK/J0isUdhTWzb0eJm3z2E78wbHj4hHDU++53Sth8r5wyAQo2zab
         BlxJcaN5/cOeuTx7wd5AWP9HDYgAe/wY3mdjc3Rvsfbveat2rBU6pYDnf7H36v5+MFp/
         6WGmlFDyk0UalolWd0nqsjtUp3gR8wZd0qICBfeTNTY0vJOH2F891E6Y04VSznslTI18
         osVvXg0YffFxaY7idBKuv1y1EWCkxAhacF+4DIZ5WY2ehFsCVr5HvbfpqVJYjvf3mHhb
         //+2yU8W9o+KWTOnN9Gif6sID5nT0ExM32gHBXk1nVEVdvVnXywzsd368/ThuxqTfh3x
         aWUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pi009uZeHDNkDXPibkI43i5tzCIy7Z5K5YwuJ02xpIo=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=y5QK0Z75gHwFnT95MaFg3/aBcpLz22GdORd8jZx7rBwJNiclrk+YhrRVFB09WBubPP
         JkpXRDbK7yzwWxNoC1KTknbgEKqwy7zN7jWaCfLKXQ+5gxctgMPiHI1gJoMwXaM7vbBV
         xEQQ4LDa+FWvmSk/1+13PHPhHB5Syq0H4IyDROz+fOuXUbaMLJKgZ1lxUERUXCRyociS
         f8Cr4dv+Ivs01AU0pLNwBLqW4UBQv5TnwL+Pcz5lYEMIMb+kEc0OxIRLqLWIGXDXjYq0
         85473kLH/XlZtaekWpwe/9CUK8Xg75iofWCtqnTBRK9VS0kfpc4pftx5C2Qb2GdxOQNg
         Sd3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=AZeaP+FE;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704208530; x=1704813330; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pi009uZeHDNkDXPibkI43i5tzCIy7Z5K5YwuJ02xpIo=;
        b=ZPQpSIVWU/QECFAQ0WfhBQ5Kv8M9vZV/6izhd8j1ii3C3JVAABarl9ZhtfDzU3cext
         STNxJxZDCOsPyHElr01+mLcvgH/1witc1UKAlkBnUh6eURxwUYzsZ0P5VMETyWopk23t
         XSEoUnXUMv14NPpUdbL5GxHuDTk+Y2OMteeAv2qy6ven1NN02qpfrOOxD+sHPgcU1eYF
         n9SnhLu2XBp2ASoww1divoNjCRyIxmPUK6MXwqErLW2GVE1o+qyR6FZ3buBZO59h7gQn
         qe7XB+jPbCLXdox9oyPjNTCfdUEZSfchht925R1qlojqkdx6L2/PgaRyG6HQnUV6VEWS
         bhkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704208530; x=1704813330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pi009uZeHDNkDXPibkI43i5tzCIy7Z5K5YwuJ02xpIo=;
        b=FKKbvfJPUlsRY/oDNze9ex/t+jLUgmUSKRmQRzAiofcZJnYtPBWRWGU/BgnlVnbRcB
         UJ1JZrovP6koVLSfgf95TvELf92I0tL5s3Aq6WMeAWnm3Iym4HfmboYTKhh8Zf1AJIBx
         6zp4fnjR2QG+Ueh6qnHIxlPXe07ZOBu06dJt04xznYvSsVaaHPpnpeAx81EVdWrBkpK5
         IJ12nVaIt8O8T5aEE0zk7JNPW7mcok4x5XzDmLTQk9SkbH7NPMq/vU51hznAMXAuVMBJ
         wBNqVxtrbLgDgHEXf/lXYuVM+mN+iCXO+nv+br7TgdeiSCmOa3ODC9T2E/sX27F7XBn7
         AciA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyien1RgW5f4b7qxMICz7zOii99aNscrGz2F4p5D1kEEkVzks9f
	mlL8brjsZsWz3rqB+QaJ5cw=
X-Google-Smtp-Source: AGHT+IGhaRvcsMLfJ+qWkuMVoTKBQ0hBVkuxN6HEfMrpAI3uIcAMmbgHw7+5JWh7/mvzJ2x5aPwjZw==
X-Received: by 2002:a25:86c1:0:b0:dbe:3d4b:227 with SMTP id y1-20020a2586c1000000b00dbe3d4b0227mr5109624ybm.36.1704208529936;
        Tue, 02 Jan 2024 07:15:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:38b:0:b0:dbe:30ec:9f7d with SMTP id k11-20020a5b038b000000b00dbe30ec9f7dls2295637ybp.1.-pod-prod-05-us;
 Tue, 02 Jan 2024 07:15:29 -0800 (PST)
X-Received: by 2002:a25:6802:0:b0:dbd:abc6:e649 with SMTP id d2-20020a256802000000b00dbdabc6e649mr8421398ybc.82.1704208529186;
        Tue, 02 Jan 2024 07:15:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704208529; cv=none;
        d=google.com; s=arc-20160816;
        b=fBnomuROD0pq3DCOblgcHejivLl1FdWPMkOh28cySk34Lq5O0irwwTyAo40uzmcMqj
         cbMZn6Z9cn6H/w1fJuEKHlHnX3PRl4boJo7E2Rq4N90Ses2f2rrB7URE/SCS3MVb+ffa
         sxBeN/SgzggxtHfSV/uul7SmlknnxTe2uuMymWAOUAGpRwefdKxM7zmDhH3jmN9h66aY
         Zcf+5gpM+u/blTk5sTyr2vbiVQnWeK7vKAT/kKtVcmAJzSK7U670UPDcqH+9yV3HaSRL
         Ab6M+IuzLOHKW1xfIxukPRwgtMStU0qBlS5xyua7WXgt28VKnf6BidnRHiRbFuY4GaZE
         rgQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZePuaqf95Nzl9ilTMV/3DOU+O4S5focb2gIDtdxHQS8=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=YBfDjoPjdfPGXcVVh4XrmUYK8s+/ahZrO3NSBtcZ0ohnCL5OcnlwnE5Lx6G5Gn75j+
         wrPryjXGKiP8EF52Rnu7+bpKSE/fI8AeqkQ+dq69vz511WCnp48Bp+/fcBsG5kzuR98s
         ht5edTEGIqvoLwwfd3AjRCrRqX2EgjXFRHCiuM7QMBn8WsPjHd7GHSadGK08D5+Z5i+4
         meYEvYMpppLRTzZnDxSz/+ZGhu9YzdLDQ8G+Wl2XweQYUJEmDspbMl4OE7mQHeG2iMRe
         umN5MZz8+aS+FqT1Gf/Cr65dmpqGS2jcASx4uZia7lMGfkrBOCNbcmuUqKdVrMmtaGZ1
         INHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=AZeaP+FE;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 206-20020a250bd7000000b00dbd7490d3d4si2438657ybl.0.2024.01.02.07.15.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:15:29 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402EQJKE007842;
	Tue, 2 Jan 2024 15:15:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7xb6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:15:24 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402EoHY2028745;
	Tue, 2 Jan 2024 15:15:23 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7xap-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:15:23 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402Ds10Q017834;
	Tue, 2 Jan 2024 15:15:22 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vawwynpdr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:15:21 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402FFIDY19726886
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:15:18 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AF6FC20040;
	Tue,  2 Jan 2024 15:15:18 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 578BE2004B;
	Tue,  2 Jan 2024 15:15:17 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:15:17 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:15:15 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>
Subject: Re: [PATCH v3 34/34] kmsan: Enable on s390
Message-ID: <20240102151515.6306-K-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-35-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-35-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: X2M9AhYJh0LDYXS1OWAtColsS1LRacgj
X-Proofpoint-ORIG-GUID: AlwpV_5Ls8uTkbHHOYGbse9PLYlauG5U
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 phishscore=0 lowpriorityscore=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 mlxlogscore=444 clxscore=1015 suspectscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020117
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=AZeaP+FE;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Dec 14, 2023 at 12:24:54AM +0100, Ilya Leoshkevich wrote:
> Now that everything else is in place, enable KMSAN in Kconfig.
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/Kconfig | 1 +
>  1 file changed, 1 insertion(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102151515.6306-K-hca%40linux.ibm.com.
