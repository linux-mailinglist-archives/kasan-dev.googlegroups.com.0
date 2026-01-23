Return-Path: <kasan-dev+bncBAABB5GLZTFQMGQERXXWV3A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wB+LMPYlc2nCsgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB5GLZTFQMGQERXXWV3A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:38 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 473F471DD5
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:38 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-8947c4398c4sf56821336d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154037; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qs78X60JKASO30MRSpGlVXAB2P5SLdBidGArolD4B+qYsmN2Kx3kQaQQ86EBP9G5uf
         BXzx8uuseMNTTDK3zlSmR9DffgO2YWOCC87UIw2Jp/Ca2P7cp//PncXntdkbhgvcdGhX
         r96bg4zCqlZ+XBPoaX/8rr77NzVnCT3mxZk+RfdMk9j1P+Pc3RwUFNRHK8ni/zqvCu/N
         Z7h/Hbm1ctz1mYlPawPJBxjotvp0fmti/rtef/kk660TNagoUJUiIlwFDy5sjIuUn8zj
         Dv8UkXy9owPCH+7IBxvvV79cghGcZGeNZuNRrPu1BjT6QDIUXkJX23p+Yz6SZ9G0U4rQ
         rBGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=oy7VE+1DBV8b7ABkI5jZ1ZB3HzxCIbSJHDc2PUZ5K40=;
        fh=+rjYIlHlaSaVTh/eULZNQ1iFisRpf5KUZzw2BtoeTtQ=;
        b=HeCDk5upUVsMNkWGNvezPR/VAooTx0PQjvyUSuToq2o/uuIcyqteexelFYTjXBBo0R
         TfUZVf6T4eTBe+6UpBj/2FTxpDUb5jdVsOrpJIEDido2Fr6Ela33SaeKT+9qGzKM5Kw+
         Y1bukKngZig3n1dPxdbXWwfyJz9ZA3O3rVugEnzsHMlStiJAE5OYfCXaTuCsjgLXzf+x
         eIuq3VJplqp3Y2Acg9rURLd2eVZXqe0N1cGUgzkYPnW+LOsFYG0HDbs5k0/yVomm4mRP
         5GHsF+lfdPxU2959xNRWtwCwxyQU0QaRQ2Fni8Bg2LIhNb51bjVGDm1RCa5BWO/VOs8D
         xdOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GZsYDl6c;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154037; x=1769758837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oy7VE+1DBV8b7ABkI5jZ1ZB3HzxCIbSJHDc2PUZ5K40=;
        b=QRMOjd3trjBKRjDliKJBunEA0xd9vWUXvJgAAaBlbP+u5Q8r40v3C0yI2tUnM3XtTN
         eNA73yr+5uHQy7sSKtwDPHG3QA7ovzU79YHL0kCAa553UIRyerFg1P+JeRSqPSpQlLXM
         rsr7prviW7k/CT5Rib7O0ugTZQ98tpVT2wqJtNtt/P/kFK+rue1oSK7xhgmlVZzr4ImP
         m7Yi9KGU9EdCN61CEo35pBrJ3vW2PjjTahpj1HehFWwAekzj2xsR8T4BIl09r2yXIIV+
         +GVxP3oXFrzmAPiyfFRkg+zhTvEZDeweyUoKLNe6WyRRanc+2sTT63mP7RLnz4nIDSkd
         AirQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154037; x=1769758837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oy7VE+1DBV8b7ABkI5jZ1ZB3HzxCIbSJHDc2PUZ5K40=;
        b=Wj25aK1mhJsNR5G+aVY8lkWX7WLWBIqeEzeXtXx6xZFDBZP6OFKPflka9lc5nrf4G9
         y/9WkS+AQhayKwN7T4vVOidJU5nOSvLXf7Tc907VIqYHy68kMFL7gX7GjnyFGrRqCA7E
         lRKnBbXmo/8yhORGZqnBA/mIaHnY4AL9y7qJA7WGKh2o27NZcOoEyD1EySUfxM2GTVfT
         xUQ5xsI7j/pZ7kdRB5czL5JvWIR8ZcvHX1zWmqnehkCPnaXZmeinPy/0zMLx6MRbdlz0
         /TdLv82F6MlTt4iR4QRdO3KCOFKcMpmVHuAVmPG0vtDn4uLo6IRaXC1ZlLFH7DcFTDgx
         t6LA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVV63AViTseVScmJUMjW2Kr3TYyujyEMilRuU/s7mtUZFrNBHCAxNrNL/CHmJ5tSXulPHcWPA==@lfdr.de
X-Gm-Message-State: AOJu0Yw9o9K8kB18E63u74Oq5zrKmPVhrFWVLbeoU5EAYF2JK3RGZhCv
	6KXgFRycRjQXKAt2s5qmeOcu5b2DVZSDyMI0nfGbmDKb10s2uQXFUPiG
X-Received: by 2002:a05:6214:4064:b0:894:7144:7572 with SMTP id 6a1803df08f44-89490253221mr20196916d6.64.1769154036804;
        Thu, 22 Jan 2026 23:40:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GD+N/ThcR3S6o8d/lrFvnj5dwofnQFkgqmCIalOXI+QA=="
Received: by 2002:a05:6214:c43:b0:882:63fc:f004 with SMTP id
 6a1803df08f44-8947deb64cdls35772126d6.2.-pod-prod-03-us; Thu, 22 Jan 2026
 23:40:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUN+PYCldRtjB78OWEIDY6c0RAfgzB3HyPhjZzBTkQkw5vJLKdiQyqAQmk35Is6luFvkjunkFQ0fpU=@googlegroups.com
X-Received: by 2002:a05:6102:40c8:20b0:5f5:4e4e:2cc1 with SMTP id ada2fe7eead31-5f54e4e2de1mr320914137.20.1769154036105;
        Thu, 22 Jan 2026 23:40:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154036; cv=none;
        d=google.com; s=arc-20240605;
        b=NPPqgYDthOhR1p7rMaGWu4riVm42SkVHxXIaO2W+5xfuelIFF54QjiDQxTz2BHbfUu
         /zXNieHxoeZX26R04IkMe7Tld3TwNBnEHt4zCAYiN39wWv+tINXfkvK0b3CcpN+zezAN
         VxEw7/6x94xy65SkoWk681LvepN+uDAcfM+RRhaGsU6ux3vYzqyMi/LYZaPgvgaX7Aji
         7ituiYYWdc81rJZhJ+LYRY+fEbm5KjWelPSjHzMmstZkpYioDlIfuUmYRc5LV+0cNTZu
         5qSddB+3U9p7eEYdTwkRhJ91w/F+3iELyxLd7NxG+5c/JHWNCTDi6Ml95Y2tx0ZWR2Xc
         IWJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=J/EE/DYnX6Bhj4nfQ3fbkX6rrIqmphYbY+E23N5Zjp0=;
        fh=4dZC5b+GxnxvIHnzjVMCNym7rZ5j81Xogzb8TUs6Lt0=;
        b=K87jRxK7NeDcfveEWZ/doCPeSBCRNiNFbxHDr+GbQ5RWN9V4f2l2gfHV1bLpFQUoiy
         zn+YB7Uld51h/PjuYgmq0PaX5r1g+c5KaIO5upNUJFQR9hlobY0iITeYD8Vhm6bT12gX
         PwQbyhczyakh9/XemlxVm7zjRrUNpnTLami5iZuICrwn6LPx1ZYOlJsnmuBMiAb7iFGG
         0yqqBY9qFN/hFfkO3TVojq7/dQCS9ZhRvtg2wNGYX+rST4gAebhCWn2tMQeTZZeQjEeq
         t9TPjlbi79rOHPmXR4qEPgxHj2ZAoNx0117bvtNWCcvD4AUY3vf/Ys5nIEoEvHwIlZdy
         5X3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GZsYDl6c;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5f54d5fc0ccsi60586137.4.2026.01.22.23.40.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:36 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60N0cpKK028538;
	Fri, 23 Jan 2026 07:40:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt60f274g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:25 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7YZ3O006421;
	Fri, 23 Jan 2026 07:40:24 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt60f274b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:24 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N7Txxu006424;
	Fri, 23 Jan 2026 07:40:23 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 4brqf1yg0t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:23 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7eJd843057516
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:40:19 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 45CE12004F;
	Fri, 23 Jan 2026 07:40:19 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D917A2004B;
	Fri, 23 Jan 2026 07:40:13 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:40:13 +0000 (GMT)
From: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
To: maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com,
        chleroy@kernel.org, ryabinin.a.a@gmail.com, glider@google.com,
        andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        oleg@redhat.com, kees@kernel.org, luto@amacapital.net,
        wad@chromium.org, mchauras@linux.ibm.com, thuth@redhat.com,
        ruanjinjie@huawei.com, sshegde@linux.ibm.com,
        akpm@linux-foundation.org, charlie@rivosinc.com, deller@gmx.de,
        ldv@strace.io, macro@orcam.me.uk, segher@kernel.crashing.org,
        peterz@infradead.org, bigeasy@linutronix.de, namcao@linutronix.de,
        tglx@linutronix.de, mark.barnett@arm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com
Subject: [PATCH v4 6/8] powerpc: Prepare for IRQ entry exit
Date: Fri, 23 Jan 2026 13:09:14 +0530
Message-ID: <20260123073916.956498-7-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=WMdyn3sR c=1 sm=1 tr=0 ts=697325e9 cx=c_pps
 a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=785Y-I4ahskik1WtazUA:9
X-Proofpoint-GUID: jSLJ0Tzgr6rqp0yXsErN0PGrr2jKZ3B0
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfX5EohOX9silAG
 2vfsT/NyKBXIdYRSRgQRo8Uk7yCN7dkFVlC8lyKd197OWdGlYX3Wte+z3KV/nHpNolY4w9VLUDJ
 /Q2Hp6vpiC0xVssfAzgLnuvUtFFeBWVQ98ShRN7i6A4zlhWArakW7/2/iElQ7wy2MwGq8JSxyIn
 tdNtTf+aU/35QwnRRsNjQHe0ZgIAgnV06CaglIX+NsMquoUJl0PiY51xMxrrScyJecIeJTRrqby
 KV64aZID6f1ZlDS8nPfnv0GnMsWq+QCDlADuiwOhcxodNMuHur+A81Phf7xKXRDs0HCuSOjz16e
 6riu5f+WQmitYGMWuk3wp17I02iiN65mUJe1B8/Ahmg0L3xAidu4UxwpfzJdUBUEpwdnAqDKYvX
 pUj4m8gl0vW3kkFPhfZ6qBzEGWUyaKKvMK+RjheSzR0rMuRTb9l5IAwuRBqztW0tDdgm61j9TSs
 2yzhV3G1kZmdX0crBSw==
X-Proofpoint-ORIG-GUID: VAsOwozJyxy0Nbi8NtZYWxzaxDzQFd2U
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 phishscore=0 malwarescore=0 suspectscore=0 bulkscore=0 adultscore=0
 impostorscore=0 spamscore=0 clxscore=1015 priorityscore=1501
 lowpriorityscore=0 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2601150000
 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GZsYDl6c;       spf=pass (google.com:
 domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=mkchauras@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
Content-Type: text/plain; charset="UTF-8"
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_CONTAINS_FROM(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABB5GLZTFQMGQERXXWV3A];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[31];
	TO_DN_NONE(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[mkchauras@linux.ibm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_TWELVE(0.00)[13];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-0.998];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,googlegroups.com:email,googlegroups.com:dkim,mail-qv1-xf3f.google.com:helo,mail-qv1-xf3f.google.com:rdns]
X-Rspamd-Queue-Id: 473F471DD5
X-Rspamd-Action: no action

From: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>

Move interrupt entry and exit helper routines from interrupt.h into the
PowerPC-specific entry-common.h header as a preparatory step for enabling
the generic entry/exit framework.

This consolidation places all PowerPC interrupt entry/exit handling in a
single common header, aligning with the generic entry infrastructure.
The helpers provide architecture-specific handling for interrupt and NMI
entry/exit sequences, including:

 - arch_interrupt_enter/exit_prepare()
 - arch_interrupt_async_enter/exit_prepare()
 - arch_interrupt_nmi_enter/exit_prepare()
 - Supporting helpers such as nap_adjust_return(), check_return_regs_valid(),
   debug register maintenance, and soft mask handling.

The functions are copied verbatim from interrupt.h.Subsequent patches will
integrate these routines into the generic entry/exit flow.

No functional change intended.

Signed-off-by: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>
---
 arch/powerpc/include/asm/entry-common.h | 358 ++++++++++++++++++++++++
 1 file changed, 358 insertions(+)

diff --git a/arch/powerpc/include/asm/entry-common.h b/arch/powerpc/include/asm/entry-common.h
index ff0625e04778..de5601282755 100644
--- a/arch/powerpc/include/asm/entry-common.h
+++ b/arch/powerpc/include/asm/entry-common.h
@@ -5,10 +5,75 @@
 
 #include <asm/cputime.h>
 #include <asm/interrupt.h>
+#include <asm/runlatch.h>
 #include <asm/stacktrace.h>
 #include <asm/switch_to.h>
 #include <asm/tm.h>
 
+#ifdef CONFIG_PPC_IRQ_SOFT_MASK_DEBUG
+/*
+ * WARN/BUG is handled with a program interrupt so minimise checks here to
+ * avoid recursion and maximise the chance of getting the first oops handled.
+ */
+#define INT_SOFT_MASK_BUG_ON(regs, cond)				\
+do {									\
+	if ((user_mode(regs) || (TRAP(regs) != INTERRUPT_PROGRAM)))	\
+		BUG_ON(cond);						\
+} while (0)
+#else
+#define INT_SOFT_MASK_BUG_ON(regs, cond)
+#endif
+
+#ifdef CONFIG_PPC_BOOK3S_64
+extern char __end_soft_masked[];
+bool search_kernel_soft_mask_table(unsigned long addr);
+unsigned long search_kernel_restart_table(unsigned long addr);
+
+DECLARE_STATIC_KEY_FALSE(interrupt_exit_not_reentrant);
+
+static inline bool is_implicit_soft_masked(struct pt_regs *regs)
+{
+	if (user_mode(regs))
+		return false;
+
+	if (regs->nip >= (unsigned long)__end_soft_masked)
+		return false;
+
+	return search_kernel_soft_mask_table(regs->nip);
+}
+
+static inline void srr_regs_clobbered(void)
+{
+	local_paca->srr_valid = 0;
+	local_paca->hsrr_valid = 0;
+}
+#else
+static inline unsigned long search_kernel_restart_table(unsigned long addr)
+{
+	return 0;
+}
+
+static inline bool is_implicit_soft_masked(struct pt_regs *regs)
+{
+	return false;
+}
+
+static inline void srr_regs_clobbered(void)
+{
+}
+#endif
+
+static inline void nap_adjust_return(struct pt_regs *regs)
+{
+#ifdef CONFIG_PPC_970_NAP
+	if (unlikely(test_thread_local_flags(_TLF_NAPPING))) {
+		/* Can avoid a test-and-clear because NMIs do not call this */
+		clear_thread_local_flags(_TLF_NAPPING);
+		regs_set_return_ip(regs, (unsigned long)power4_idle_nap_return);
+	}
+#endif
+}
+
 static __always_inline void booke_load_dbcr0(void)
 {
 #ifdef CONFIG_PPC_ADV_DEBUG_REGS
@@ -31,6 +96,299 @@ static __always_inline void booke_load_dbcr0(void)
 #endif
 }
 
+static inline void booke_restore_dbcr0(void)
+{
+#ifdef CONFIG_PPC_ADV_DEBUG_REGS
+	unsigned long dbcr0 = current->thread.debug.dbcr0;
+
+	if (IS_ENABLED(CONFIG_PPC32) && unlikely(dbcr0 & DBCR0_IDM)) {
+		mtspr(SPRN_DBSR, -1);
+		mtspr(SPRN_DBCR0, global_dbcr0[smp_processor_id()]);
+	}
+#endif
+}
+
+static inline void check_return_regs_valid(struct pt_regs *regs)
+{
+#ifdef CONFIG_PPC_BOOK3S_64
+	unsigned long trap, srr0, srr1;
+	static bool warned;
+	u8 *validp;
+	char *h;
+
+	if (trap_is_scv(regs))
+		return;
+
+	trap = TRAP(regs);
+	// EE in HV mode sets HSRRs like 0xea0
+	if (cpu_has_feature(CPU_FTR_HVMODE) && trap == INTERRUPT_EXTERNAL)
+		trap = 0xea0;
+
+	switch (trap) {
+	case 0x980:
+	case INTERRUPT_H_DATA_STORAGE:
+	case 0xe20:
+	case 0xe40:
+	case INTERRUPT_HMI:
+	case 0xe80:
+	case 0xea0:
+	case INTERRUPT_H_FAC_UNAVAIL:
+	case 0x1200:
+	case 0x1500:
+	case 0x1600:
+	case 0x1800:
+		validp = &local_paca->hsrr_valid;
+		if (!READ_ONCE(*validp))
+			return;
+
+		srr0 = mfspr(SPRN_HSRR0);
+		srr1 = mfspr(SPRN_HSRR1);
+		h = "H";
+
+		break;
+	default:
+		validp = &local_paca->srr_valid;
+		if (!READ_ONCE(*validp))
+			return;
+
+		srr0 = mfspr(SPRN_SRR0);
+		srr1 = mfspr(SPRN_SRR1);
+		h = "";
+		break;
+	}
+
+	if (srr0 == regs->nip && srr1 == regs->msr)
+		return;
+
+	/*
+	 * A NMI / soft-NMI interrupt may have come in after we found
+	 * srr_valid and before the SRRs are loaded. The interrupt then
+	 * comes in and clobbers SRRs and clears srr_valid. Then we load
+	 * the SRRs here and test them above and find they don't match.
+	 *
+	 * Test validity again after that, to catch such false positives.
+	 *
+	 * This test in general will have some window for false negatives
+	 * and may not catch and fix all such cases if an NMI comes in
+	 * later and clobbers SRRs without clearing srr_valid, but hopefully
+	 * such things will get caught most of the time, statistically
+	 * enough to be able to get a warning out.
+	 */
+	if (!READ_ONCE(*validp))
+		return;
+
+	if (!data_race(warned)) {
+		data_race(warned = true);
+		pr_warn("%sSRR0 was: %lx should be: %lx\n", h, srr0, regs->nip);
+		pr_warn("%sSRR1 was: %lx should be: %lx\n", h, srr1, regs->msr);
+		show_regs(regs);
+	}
+
+	WRITE_ONCE(*validp, 0); /* fixup */
+#endif
+}
+
+static inline void arch_interrupt_enter_prepare(struct pt_regs *regs)
+{
+#ifdef CONFIG_PPC64
+	irq_soft_mask_set(IRQS_ALL_DISABLED);
+
+	/*
+	 * If the interrupt was taken with HARD_DIS clear, then enable MSR[EE].
+	 * Asynchronous interrupts get here with HARD_DIS set (see below), so
+	 * this enables MSR[EE] for synchronous interrupts. IRQs remain
+	 * soft-masked. The interrupt handler may later call
+	 * interrupt_cond_local_irq_enable() to achieve a regular process
+	 * context.
+	 */
+	if (!(local_paca->irq_happened & PACA_IRQ_HARD_DIS)) {
+		INT_SOFT_MASK_BUG_ON(regs, !(regs->msr & MSR_EE));
+		__hard_irq_enable();
+	} else {
+		__hard_RI_enable();
+	}
+	/* Enable MSR[RI] early, to support kernel SLB and hash faults */
+#endif
+
+	if (!regs_irqs_disabled(regs))
+		trace_hardirqs_off();
+
+	if (user_mode(regs)) {
+		kuap_lock();
+		account_cpu_user_entry();
+		account_stolen_time();
+	} else {
+		kuap_save_and_lock(regs);
+		/*
+		 * CT_WARN_ON comes here via program_check_exception,
+		 * so avoid recursion.
+		 */
+		if (TRAP(regs) != INTERRUPT_PROGRAM)
+			CT_WARN_ON(ct_state() != CT_STATE_KERNEL &&
+				   ct_state() != CT_STATE_IDLE);
+		INT_SOFT_MASK_BUG_ON(regs, is_implicit_soft_masked(regs));
+		INT_SOFT_MASK_BUG_ON(regs, regs_irqs_disabled(regs) &&
+				     search_kernel_restart_table(regs->nip));
+	}
+	INT_SOFT_MASK_BUG_ON(regs, !regs_irqs_disabled(regs) &&
+			     !(regs->msr & MSR_EE));
+
+	booke_restore_dbcr0();
+}
+
+/*
+ * Care should be taken to note that arch_interrupt_exit_prepare and
+ * arch_interrupt_async_exit_prepare do not necessarily return immediately to
+ * regs context (e.g., if regs is usermode, we don't necessarily return to
+ * user mode). Other interrupts might be taken between here and return,
+ * context switch / preemption may occur in the exit path after this, or a
+ * signal may be delivered, etc.
+ *
+ * The real interrupt exit code is platform specific, e.g.,
+ * interrupt_exit_user_prepare / interrupt_exit_kernel_prepare for 64s.
+ *
+ * However arch_interrupt_nmi_exit_prepare does return directly to regs, because
+ * NMIs do not do "exit work" or replay soft-masked interrupts.
+ */
+static inline void arch_interrupt_exit_prepare(struct pt_regs *regs)
+{
+	if (user_mode(regs)) {
+		BUG_ON(regs_is_unrecoverable(regs));
+		BUG_ON(regs_irqs_disabled(regs));
+		/*
+		 * We don't need to restore AMR on the way back to userspace for KUAP.
+		 * AMR can only have been unlocked if we interrupted the kernel.
+		 */
+		kuap_assert_locked();
+
+		local_irq_disable();
+	}
+}
+
+static inline void arch_interrupt_async_enter_prepare(struct pt_regs *regs)
+{
+#ifdef CONFIG_PPC64
+	/* Ensure arch_interrupt_enter_prepare does not enable MSR[EE] */
+	local_paca->irq_happened |= PACA_IRQ_HARD_DIS;
+#endif
+	arch_interrupt_enter_prepare(regs);
+#ifdef CONFIG_PPC_BOOK3S_64
+	/*
+	 * RI=1 is set by arch_interrupt_enter_prepare, so this thread flags access
+	 * has to come afterward (it can cause SLB faults).
+	 */
+	if (cpu_has_feature(CPU_FTR_CTRL) &&
+	    !test_thread_local_flags(_TLF_RUNLATCH))
+		__ppc64_runlatch_on();
+#endif
+}
+
+static inline void arch_interrupt_async_exit_prepare(struct pt_regs *regs)
+{
+	/*
+	 * Adjust at exit so the main handler sees the true NIA. This must
+	 * come before irq_exit() because irq_exit can enable interrupts, and
+	 * if another interrupt is taken before nap_adjust_return has run
+	 * here, then that interrupt would return directly to idle nap return.
+	 */
+	nap_adjust_return(regs);
+
+	arch_interrupt_exit_prepare(regs);
+}
+
+struct interrupt_nmi_state {
+#ifdef CONFIG_PPC64
+	u8 irq_soft_mask;
+	u8 irq_happened;
+	u8 ftrace_enabled;
+	u64 softe;
+#endif
+};
+
+static inline bool nmi_disables_ftrace(struct pt_regs *regs)
+{
+	/* Allow DEC and PMI to be traced when they are soft-NMI */
+	if (IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
+		if (TRAP(regs) == INTERRUPT_DECREMENTER)
+			return false;
+		if (TRAP(regs) == INTERRUPT_PERFMON)
+			return false;
+	}
+	if (IS_ENABLED(CONFIG_PPC_BOOK3E_64)) {
+		if (TRAP(regs) == INTERRUPT_PERFMON)
+			return false;
+	}
+
+	return true;
+}
+
+static inline void arch_interrupt_nmi_enter_prepare(struct pt_regs *regs,
+						    struct interrupt_nmi_state *state)
+{
+#ifdef CONFIG_PPC64
+	state->irq_soft_mask = local_paca->irq_soft_mask;
+	state->irq_happened = local_paca->irq_happened;
+	state->softe = regs->softe;
+
+	/*
+	 * Set IRQS_ALL_DISABLED unconditionally so irqs_disabled() does
+	 * the right thing, and set IRQ_HARD_DIS. We do not want to reconcile
+	 * because that goes through irq tracing which we don't want in NMI.
+	 */
+	local_paca->irq_soft_mask = IRQS_ALL_DISABLED;
+	local_paca->irq_happened |= PACA_IRQ_HARD_DIS;
+
+	if (!(regs->msr & MSR_EE) || is_implicit_soft_masked(regs)) {
+		/*
+		 * Adjust regs->softe to be soft-masked if it had not been
+		 * reconcied (e.g., interrupt entry with MSR[EE]=0 but softe
+		 * not yet set disabled), or if it was in an implicit soft
+		 * masked state. This makes regs_irqs_disabled(regs)
+		 * behave as expected.
+		 */
+		regs->softe = IRQS_ALL_DISABLED;
+	}
+
+	__hard_RI_enable();
+
+	/* Don't do any per-CPU operations until interrupt state is fixed */
+
+	if (nmi_disables_ftrace(regs)) {
+		state->ftrace_enabled = this_cpu_get_ftrace_enabled();
+		this_cpu_set_ftrace_enabled(0);
+	}
+#endif
+}
+
+static inline void arch_interrupt_nmi_exit_prepare(struct pt_regs *regs,
+						   struct interrupt_nmi_state *state)
+{
+	/*
+	 * nmi does not call nap_adjust_return because nmi should not create
+	 * new work to do (must use irq_work for that).
+	 */
+
+#ifdef CONFIG_PPC64
+#ifdef CONFIG_PPC_BOOK3S
+	if (regs_irqs_disabled(regs)) {
+		unsigned long rst = search_kernel_restart_table(regs->nip);
+
+		if (rst)
+			regs_set_return_ip(regs, rst);
+	}
+#endif
+
+	if (nmi_disables_ftrace(regs))
+		this_cpu_set_ftrace_enabled(state->ftrace_enabled);
+
+	/* Check we didn't change the pending interrupt mask. */
+	WARN_ON_ONCE((state->irq_happened | PACA_IRQ_HARD_DIS) != local_paca->irq_happened);
+	regs->softe = state->softe;
+	local_paca->irq_happened = state->irq_happened;
+	local_paca->irq_soft_mask = state->irq_soft_mask;
+#endif
+}
+
 static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs)
 {
 	kuap_lock();
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-7-mkchauras%40linux.ibm.com.
