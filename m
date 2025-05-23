Return-Path: <kasan-dev+bncBCYL7PHBVABBBAUDYHAQMGQE5VSAL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B015DAC1FD0
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 11:36:04 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-742cf6f6a10sf7644274b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 02:36:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747992963; cv=pass;
        d=google.com; s=arc-20240605;
        b=izXcBCoXjXqs+ChUorfzT5p42gEBmmG42Ct6t7IFea2zEBKbJwvDlhuXlEUjMq0FTC
         yCX9rGiT2PHJ1Cr6ebIv5enjoWatzg2agOmFWqLIuNbyWg9OoffUfp2jUi2BvUR5ZT14
         HXJbjnfcqAvONXUy5G/v7Z64nrRXMsdABokL4JYmu8WtVynPSJ9sYniNU0du8cbrwzkx
         UnbcN68DSvyznRXZYp/xhlJgwh9MT8KyZorl9tJtGC1sF19RFPIwtc7MCwHIk1KVG0VJ
         IiMs7/hwi6/ptwUhPCI4uYWYF8AWfMsrZwIPjqpvmWfYNBva13TkEzHhYpcgIq4l6dPL
         mfzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rVDivsda4TJeo7TK46A+gtB3COPUjDkmDaupzSsa1gk=;
        fh=qBl1ZszozulPuD3mtxiXbpgEOFa6kJIwBVhRzGrckHo=;
        b=K9Mj+kr3LG/kRiVPm4eSa06s6hIRZwY67eHY8Vs9wqb9PtPaTqytCflo/L/G6D1OWk
         ePTRhveRu/EJj6Zn/oEBqr+NrS2U1tLe59Gc5d43BA5BBIJnUf96EEU2g7RjTr//24Xj
         7gHDAeBaHtQYQGTiA39Vgook6TbfR49+VgzBzMWciwSOPN4tpxA4FVQhFfhOHRNgb0XT
         kn+FG4oRntp9wJvUeVxk/q2QfyQwJEYp2fpnwV8QBLuImDo6oKBjuud7bBGzlMq2auAC
         Tm3L1//SFMEAsw/A5kwcUvXOI93PKeQzEDPLxp7CVooiJfp36YWtI3MBFPpEEEPwqfsD
         8Igw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=R3CkCkzB;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747992963; x=1748597763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rVDivsda4TJeo7TK46A+gtB3COPUjDkmDaupzSsa1gk=;
        b=wLvKKVMkQkDJD4ys4UKHt7hUJA+biAZk3nT7bzUn0fIlxa3FmbnBR1LcqZEuEmYjm4
         ka7pIwFXZ/RgRH3FOWwkSpN+EtsNiLmQu5IZIc1GXtTNd/+xOoQroj/aweyIBhZdTf2v
         85mDbFkSLSIU5MnKtzlhMhQtpXd6W2E7CkgIzCpPQDt84VuzQa7k+AaVdoyGVn2z0bl7
         PzxhOHnbs+mLoIavfx3fqPqaP2gXk/6VJhugK+oQ7wf7Wa77VpiQHpy98V/UVYbBuqnE
         T8nAVRGXLXcKAc0Yzoz+bRtHHw+MCKP62etZWYaGvSYWw6SYra17ky7zXSBqL8UJIU5W
         BJ+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747992963; x=1748597763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rVDivsda4TJeo7TK46A+gtB3COPUjDkmDaupzSsa1gk=;
        b=YNRbUvz/fRojHtoyneo5nc4wWX3mqVaUvUX2bj9PRnh8BocuTWe7GubkUWE24kpEVR
         h6rexdcCiCYmf0PO6G3M4qc1f/W0YHGSF6c8NCnNH00q+LUHX7+fUpWXjn2nivhQfzes
         ip9nRpbbqPH0GcEMr1rsGVrDZRMbJV5CatraMwIoWn3FrItC+1RBE/EOpYo6E/NlVPVj
         3cVvSCXoKXrNmjVFhGU/rvge9mu3gnUhXDPWyOIkhXjBiLNdgcKLkhLwVWG+ZFY6OxXT
         q7p5z4pHXh2olhsgFl2Q5fEmEUXybMxVPZ6tuRJ9/IqSxrQmP/V0rt3u/k4DPSxO9FXV
         fKZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/SBWKvEnu9sRmWhjoBxIutIfNqIl6ng7fnfsQLIHl/3kgq+2dB3al2RBKxH/ul8+meAlEHw==@lfdr.de
X-Gm-Message-State: AOJu0YwCDbN5OU9XiVJhUfdNr/CtyoRNjZNIbc2wkbfIuauh4SNee3TN
	V6RpNX/GRYKkeq0UPicB8k1t0eEO7nTW7rYzqPbhQHuaz3O7LKs/wDcU
X-Google-Smtp-Source: AGHT+IHiBpV1K/XIX8+N/qgwdCyskhG7gZpz/6ob+4iEnEIYpbsNlHkJ3WfRYk89d3Hb22p6NXqndw==
X-Received: by 2002:a05:6a00:a96:b0:740:b5f9:287b with SMTP id d2e1a72fcca58-745ed848ee4mr3186956b3a.1.1747992963030;
        Fri, 23 May 2025 02:36:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGBjocEroiuIoGzjVPgQf490TKx+ITJ3uQBjfcS1Q/AHA==
Received: by 2002:a05:6a00:2e1d:b0:742:8b2f:6e98 with SMTP id
 d2e1a72fcca58-742967d06a2ls4540062b3a.0.-pod-prod-08-us; Fri, 23 May 2025
 02:36:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYBz2h+DDgTYlxxaYR+iKreTAIWVrRKIM7AN1rslIONf5PXOSmyF+72o4ofhBiZxzjBwXbfwl8cN8=@googlegroups.com
X-Received: by 2002:a05:6a00:2392:b0:742:a82c:d832 with SMTP id d2e1a72fcca58-745ed90b653mr3818016b3a.24.1747992960215;
        Fri, 23 May 2025 02:36:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747992960; cv=none;
        d=google.com; s=arc-20240605;
        b=Ww1MBTp392yqypI52rjKlpfM3Qj+oanORA60hpnSuYEFALfAVlhuDqr114QHAouXBi
         xS1Llj5zfAiF5tATeUF5K64qNFgVDJ4nRnX7q9HIWQms0Re2kvFN+015txerskEbAKH9
         Gbgmx0/ZTtJXvj4Ft+JUlGVawKhPdG20hKSvnZwlNaVz04a9xGySH0mWGeXpqQu/iR46
         dNMBvI3noaI3m+cWUWGh/FsuvxjnIp+B/V8WxNz+CqVgzq8epFsVk2tqWqESdaI8LRTq
         40OKQtsoY6exSI8t9LZTrGR3+YnY8H+4fDagPpEIroZH64omqBCsfjVF5KXMahdWQIya
         yMDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vMybJrVOxCi72E1Pt60pMqYpdyjf6Ss0XPZB55xj29M=;
        fh=6xmIQvpBqzqoZzayDl1Prk2ZnwYDXCFlJYF9dY2LWi8=;
        b=OXGAQuUaiRZJSyCjAfVNY7h+/cPbe2l0y0C+sB0e/I4iaeglqMHZH3n/34BwpbylVN
         FzUINb49+VsqvjrXDoC9tmdde17ncW+rAzxpM/yKEv3fuHj1LK8pEHdZcsnyiHW3jfAg
         vjv1zUx9fWy2tacTS2HdR9y/rBnfP6Y7qigpfvtIOm+FhBuYOb7Zd2vC6CkIlb5saDbE
         cLM7jrLl2rwqfVXzztsYkSVfoWJDwV0nmho5vogHESqpGW4w1HD+bUOQYn87pyGjZyoL
         2qVM32Rb4t3BzVrndOKohHV/efe9LZJYXazI9Tb+viBsiWH2pOZi2CxMA4Llq+xxGdiH
         SyTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=R3CkCkzB;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-742a97ee804si294182b3a.3.2025.05.23.02.36.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 May 2025 02:36:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54MNWFqO004792;
	Fri, 23 May 2025 09:35:57 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46t14jp33r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 May 2025 09:35:57 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54N9Ub2D019284;
	Fri, 23 May 2025 09:35:56 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46t14jp33p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 May 2025 09:35:56 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54N65XYR020693;
	Fri, 23 May 2025 09:35:55 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 46rwkq5x35-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 May 2025 09:35:55 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54N9ZqFH47186204
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 May 2025 09:35:52 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0B10D2004D;
	Fri, 23 May 2025 09:35:52 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 47DD220043;
	Fri, 23 May 2025 09:35:50 +0000 (GMT)
Received: from osiris (unknown [9.111.71.83])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 23 May 2025 09:35:50 +0000 (GMT)
Date: Fri, 23 May 2025 11:35:48 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        Gerald Schaefer <gerald.schaefer@linux.ibm.com>,
        Gaosheng Cui <cuigaosheng1@huawei.com>, linux-s390@vger.kernel.org,
        "Gustavo A. R. Silva" <gustavoars@kernel.org>,
        Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Ard Biesheuvel <ardb@kernel.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Nathan Chancellor <nathan@kernel.org>,
        Nicolas Schier <nicolas.schier@linux.dev>,
        Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
        Bill Wendling <morbo@google.com>,
        Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
        x86@kernel.org, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
        linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
        linux-riscv@lists.infradead.org, linux-efi@vger.kernel.org,
        linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
        linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org,
        sparclinux@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2 07/14] s390: Handle KCOV __init vs inline mismatches
Message-ID: <20250523093548.9524A8b-hca@linux.ibm.com>
References: <20250523043251.it.550-kees@kernel.org>
 <20250523043935.2009972-7-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250523043935.2009972-7-kees@kernel.org>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: KqDaZI-N24qPBCncGoId1M5821jvyXiL
X-Authority-Analysis: v=2.4 cv=XOkwSRhE c=1 sm=1 tr=0 ts=6830417d cx=c_pps a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=i0EeH86SAAAA:8 a=ZhbCrNo_nw5myWupG0oA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTIzMDA4NCBTYWx0ZWRfX0w0P9E3aDLPl xKkdIDIhLiwjTmqVc2SrRDCWVWFZrVDCFjUtGWXwGKiqzPx3aH1H3kR3L9ztCvCTG2dYW5CKwL9 sICNUHibIsoUXe9IU/++4/n8wIvLqcN/lTpzb6AwUj21nwbHo2PrdccpN7uJ5neULr3iZ+x0IDO
 cp9vaJXECGONZX36cRDNAuI3GEBAklLQu6bmjDNQyoWpyWcL52i8nxzjSMmMG12/PXn7Ht4o/I9 rKz7HWr8sXVyui6OGhJ6oXDcKWfiiMUq3fRRvh9CBFKWIWsQnUS30/UPfY4kp/wqVcXw92l9rKW 3UN+JfNQzPqTmiL+lKipax/ZfWe+uKv2lFByzGPt8jex7JX31DFbbxTGQxDZdrqyBmdG3LASN+L
 ff1/Bps89M6t1nUW1d6VQ0r0f4R0IG0qDcI6J5H3ztJ8TgF0KLAewZp36812jwJ9B/V82K6H
X-Proofpoint-GUID: FAZQIEfWbNoED4pzflxHiaQq3RMT7Za1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-23_03,2025-05-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011 malwarescore=0
 mlxlogscore=586 bulkscore=0 mlxscore=0 lowpriorityscore=0 adultscore=0
 impostorscore=0 suspectscore=0 priorityscore=1501 spamscore=0 phishscore=0
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2505160000
 definitions=main-2505230084
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=R3CkCkzB;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
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

On Thu, May 22, 2025 at 09:39:17PM -0700, Kees Cook wrote:
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> s390 this exposed a place where the __init annotation was missing but
> ended up being "accidentally correct". Fix this cases and force a couple
> functions to be inline with __always_inline.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Heiko Carstens <hca@linux.ibm.com>
> Cc: Vasily Gorbik <gor@linux.ibm.com>
> Cc: Alexander Gordeev <agordeev@linux.ibm.com>
> Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
> Cc: Sven Schnelle <svens@linux.ibm.com>
> Cc: Gerald Schaefer <gerald.schaefer@linux.ibm.com>
> Cc: Gaosheng Cui <cuigaosheng1@huawei.com>
> Cc: <linux-s390@vger.kernel.org>
> ---
>  arch/s390/hypfs/hypfs.h      | 2 +-
>  arch/s390/hypfs/hypfs_diag.h | 2 +-
>  arch/s390/mm/init.c          | 2 +-
>  3 files changed, 3 insertions(+), 3 deletions(-)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523093548.9524A8b-hca%40linux.ibm.com.
