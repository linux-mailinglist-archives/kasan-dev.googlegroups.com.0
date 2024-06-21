Return-Path: <kasan-dev+bncBCM3H26GVIOBB4HP2SZQMGQETXJ74TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ABC7911E72
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 10:21:06 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2c6f1c0365esf1741814a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 01:21:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718958065; cv=pass;
        d=google.com; s=arc-20160816;
        b=AzLbqmNphXb/pNMoU4iVoV+jbV+84pyrXdtPR7K8dvUYrq6cTSm+fbJAQOqSMHVvUN
         X9Nq8SHmYgPjsAk7c/pyPdMau5CRTXyPvjPE2ZvoQPJCkZ5xOk2yNdIH+p186bc0doLV
         OZJuDR9nCozWDd80IAZwl0opfXsGTN+hNED4uOe5V5c/PQfU1j476ES4PBPZZS2XpniM
         CG1DvlybW/AzaiFHJn8ACYgkKt0JFh+Ynkj6sIdbm12hKSCsz4nOrpNKMDYG+RChwjKR
         iP40U/NONbQM9EnjIp/D48PHW8b+9xUZB9VxIMDNIuiDJTo0NjgmNL8x21tEIO8v7CNV
         hcXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=/rlJ/CE8YhCByax1zfTvcysNh9MY8kQ93yNtfnIjIGA=;
        fh=dJcq10sBDe5aETNhSOb2DnZWY2CjWJd3hpS588IzDuM=;
        b=ahi0F4w5U7yysz95I2Xm7zDU2XtpjubdQ6ZoIJEE7QCB//hIwqfNCIxJcQth35Tc5O
         kOttv/UpFsR1mx3uJdY9y6O5fFjxOsvvjhtNosii5/NBXLzSnFn5PclH5GXWHvChdIVS
         EadGuSFOGoetcIZvrIAUScO6gd3Qu3IPa+x5O1reskhK9May9Mhx7quXXw4VCTi6gXfU
         4HRH0+t6ITR2YAwRVqTrcndLVENoTRhEbQXQkJeZBLW/peLr1WXrI6AN6laXbYof4m/A
         W6Fg5wdeM3x0CnIf+ctB2O2iYePuB5sW/lETPzg9FfV1lKdi7LuV52mh9cukjVk1d/wH
         R9tQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WKPjtw7y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718958065; x=1719562865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/rlJ/CE8YhCByax1zfTvcysNh9MY8kQ93yNtfnIjIGA=;
        b=VUSCn7yRX+sRrAfZCszp7UjQecSHDgkLcJW0ZNS20MGhAepMdsHCWLcWYyTahk6OJI
         m788AaPh2kpjhN/GwlNzSUaoHbDCKJIsofLoVCw+yQR9Q4SbGBXJpI9zSOKQUf2KrUJK
         9RyMvRlGoKEVdSaGPfb+fjDmENs66rfoPg62OSVQhttaiTW08tJhpSuB1gL8FrLMRsaI
         WoBpkqVuXpxjnefIMU/9o+fq+hWMLSvNwDngac4dDyD91Rzs4N1dXKChJvKPYADjdxYG
         aT2i8V1IKbKpkFHTDF+O5spZSoI8gnKsUvmolq1Fpmq3E4GwpKbzffm6QiRNGxPiO8M8
         RrqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718958065; x=1719562865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/rlJ/CE8YhCByax1zfTvcysNh9MY8kQ93yNtfnIjIGA=;
        b=sG6rThkgLWj3dLqrfdWbwTLoY6u/RjPSjXJH76VDqMMweJiJLfiyJYC7+N8fF+R3b2
         O/5tt268lXM9NPrvxpMrZtxX1xN2wc9MFEQIfrHkCGhpWaL9QAP6ZXCUw39ZkT/gP5qf
         OsQDkz+6OyyfzhP8bcSyetuZmO5IU2t2poNJdSC2n8F4Gf8ozTolhjudxdW6FjlHMRwY
         yyeM01zFLo/ClRZsjwtuIAE3fb/CrsRPFQYtZxFo4Ntfl04gbWE10urdXapiFxIsxN3H
         4CrhCP1t3oDACyxfFgLqMV/c/wzShy9kA1orsqxOs90gGPd56TABCwGd/f2dpHMTaxhw
         CPow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVceb+GEvthGy625dy6RkZ2rziLEUM8KrMULmuW642ymJMYnahxEJZfliLjESIzrweNpCb0SU/DoE3twodJaQSua4BjYjcnJg==
X-Gm-Message-State: AOJu0Yx3lPwD1MpzD985F5yO+vlJwkjEx34VtHEqpIk8Zp6AcwWqeV2F
	Hcgu7s55EAY0f1Tl6CJ5K4NihHgNDvAZy5DZtlqqX4Wfzrl7cLix
X-Google-Smtp-Source: AGHT+IFPhxn9EQtG/oZ2+rJSfnRfW5Wu/nn5XDtsBdt+JAsLhOOG1EmqutI6PPCnk3fnvySopcYyKQ==
X-Received: by 2002:a17:90a:6fe3:b0:2c7:b164:3ce6 with SMTP id 98e67ed59e1d1-2c7b5cc9652mr7467724a91.28.1718958064771;
        Fri, 21 Jun 2024 01:21:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c683:b0:2c3:dc3:f285 with SMTP id
 98e67ed59e1d1-2c7dfbddfd8ls1025719a91.0.-pod-prod-01-us; Fri, 21 Jun 2024
 01:21:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0A01xwrUVAemICmYmmsMsVxbkJGifum2ryfZFYRFfYG2QjRLAxbwBa66TW+nHDEo9I3eiv9hU2+7JoOM5ElQKhG9FDEqB9BwnTQ==
X-Received: by 2002:a17:90a:fb8a:b0:2c4:ee14:94a2 with SMTP id 98e67ed59e1d1-2c7b5cc9e23mr6835051a91.27.1718958063345;
        Fri, 21 Jun 2024 01:21:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718958063; cv=none;
        d=google.com; s=arc-20160816;
        b=KtvLxF4Bgmvn4sZ/BdXOYQ6rvw0gXgkgM1F8Noi7bW7OHqnkjoTkxNI7oD4wpL8pjx
         49WRKfyw2Q44ATOADd7o+vP43JxE5ocwhTlmTT3xJkwk4o5k8yYDaCpDMXUj8O3HWdJk
         /jKIN5hC4cfF8B9YhkwNInboByPpU5rkCckIhuCfd/kdZ5dmZlaREttzhM/RzFvaRjHi
         6hFfAZDfM62pq0j5RnuXdjUrdM00dPHGVsf9qzwy5O/Yg1m8QdN+rFRNHaBYTFrFAh0x
         YbkpgzaUcRcx/f0IvruY5z6+xfWNxKm/4zni339XcM0gz9b8VZXKGFt6dQaHqTXy5NMU
         xxVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=bOMJVb7Zy5y+AcLTafdKk+2YiRA7kTcVYCv4Y9XBs08=;
        fh=Yls2NrJ0cwMKcFqrTJkhXd28GI4hX1O0l0BqpdJC6zA=;
        b=ng4G4C4VUnpXdxlMoyZ+DbS1vUyDgLRZ4sFekklZwALgJya2YXZD/OuOXuq5V2wgSM
         sZeAu/TVU6c1SFQDdBKv6gtx4g350CETyQo7QEOImyE9/Km0ZXf865cBaSuCh+1uxZRU
         oKK6Bsy3CNg4n9jeQMPOGok75IrdQo0ge1zL9gD7+/X327mgjqYEl8yL8mmyQWoehRw4
         ivcKDwsY0BtBMVrIOY4sFT0Fi5RMk1CgW99STnLGKBFJtyIbVrmvNka0kZav5JKxrRxo
         lABMnz519UkGH66SL31wZY6brOq4D42v/DQ+DzPxWC0RolRubASpcO8DZSgeyh7OktpM
         6p6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WKPjtw7y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e945195fsi167984a91.2.2024.06.21.01.21.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 01:21:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L7v5Gn010169;
	Fri, 21 Jun 2024 08:20:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw0ry0qsg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 08:20:57 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L8KvJp016031;
	Fri, 21 Jun 2024 08:20:57 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw0ry0qs9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 08:20:56 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L7GTtQ030896;
	Fri, 21 Jun 2024 08:20:55 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsswsuq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 08:20:55 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L8Kn2x55771402
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 08:20:51 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8BD2320043;
	Fri, 21 Jun 2024 08:20:49 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3FFA220040;
	Fri, 21 Jun 2024 08:20:48 +0000 (GMT)
Received: from [127.0.0.1] (unknown [9.152.108.100])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 08:20:48 +0000 (GMT)
Message-ID: <ec92cdaa57866306a6fcf52a386193bafcb2155b.camel@linux.ibm.com>
Subject: Re: [PATCH v6 32/39] s390/ptdump: Add KMSAN page markers
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko
 <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph
 Lameter <cl@linux.com>,
        David Rientjes <rientjes@google.com>,
        Heiko
 Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco
 Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka
 Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily
 Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov
 <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Fri, 21 Jun 2024 10:20:48 +0200
In-Reply-To: <20240621002616.40684-33-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
	 <20240621002616.40684-33-iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: VeEapbGV6IkSc8UA2_9IOlInc0MQ5ih1
X-Proofpoint-ORIG-GUID: r7kSYJf0oRMft-JV5P--079W7nGU4PZ_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_02,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxlogscore=999
 impostorscore=0 lowpriorityscore=0 priorityscore=1501 phishscore=0
 mlxscore=0 malwarescore=0 adultscore=0 suspectscore=0 spamscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210058
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WKPjtw7y;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Fri, 2024-06-21 at 02:25 +0200, Ilya Leoshkevich wrote:
> Add KMSAN vmalloc metadata areas to kernel_page_tables.
>=20
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
> =C2=A0arch/s390/mm/dump_pagetables.c | 30 ++++++++++++++++++++++++++++++
> =C2=A01 file changed, 30 insertions(+)
>=20
> diff --git a/arch/s390/mm/dump_pagetables.c
> b/arch/s390/mm/dump_pagetables.c
> index ffd07ed7b4af..f51e5d0862a3 100644
> --- a/arch/s390/mm/dump_pagetables.c
> +++ b/arch/s390/mm/dump_pagetables.c
> @@ -36,6 +36,16 @@ enum address_markers_idx {
> =C2=A0	VMEMMAP_END_NR,
> =C2=A0	VMALLOC_NR,
> =C2=A0	VMALLOC_END_NR,
> +#ifdef CONFIG_KMSAN
> +	KMSAN_VMALLOC_SHADOW_START_NR,
> +	KMSAN_VMALLOC_SHADOW_END_NR,
> +	KMSAN_VMALLOC_ORIGIN_START_NR,
> +	KMSAN_VMALLOC_ORIGIN_END_NR,
> +	KMSAN_MODULES_SHADOW_START_NR,
> +	KMSAN_MODULES_SHADOW_END_NR,
> +	KMSAN_MODULES_ORIGIN_START_NR,
> +	KMSAN_MODULES_ORIGIN_END_NR,
> +#endif
> =C2=A0	MODULES_NR,
> =C2=A0	MODULES_END_NR,
> =C2=A0	ABS_LOWCORE_NR,
> @@ -74,6 +84,16 @@ static struct addr_marker address_markers[] =3D {
> =C2=A0#ifdef CONFIG_KASAN
> =C2=A0	[KASAN_SHADOW_START_NR]	=3D {KASAN_SHADOW_START,
> "Kasan Shadow Start"},
> =C2=A0	[KASAN_SHADOW_END_NR]	=3D {KASAN_SHADOW_END, "Kasan Shadow
> End"},
> +#endif
> +#ifdef CONFIG_KMSAN
> +	[KMSAN_VMALLOC_SHADOW_START_NR]	=3D {0, "Kmsan vmalloc
> Shadow Start"},
> +	[KMSAN_VMALLOC_SHADOW_END_NR]	=3D {0, "Kmsan vmalloc Shadow
> End"},
> +	[KMSAN_VMALLOC_ORIGIN_START_NR]	=3D {0, "Kmsan vmalloc
> Origins Start"},
> +	[KMSAN_VMALLOC_ORIGIN_END_NR]	=3D {0, "Kmsan vmalloc Origins
> End"},
> +	[KMSAN_MODULES_SHADOW_START_NR]	=3D {0, "Kmsan Modules
> Shadow Start"},
> +	[KMSAN_MODULES_SHADOW_END_NR]	=3D {0, "Kmsan Modules Shadow
> End"},
> +	[KMSAN_MODULES_ORIGIN_START_NR]	=3D {0, "Kmsan Modules
> Origins Start"},
> +	[KMSAN_MODULES_ORIGIN_END_NR]	=3D {0, "Kmsan Modules Origins
> End"},
> =C2=A0#endif

Please disregard this patch. It's not essential for the series, and
also has a subtle bug: this block needs to be moved upwards, because
right now { -1, NULL } overlaps [MODULES_NR]. I will resend it
separately later.

> =C2=A0	{ -1, NULL }
> =C2=A0};

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ec92cdaa57866306a6fcf52a386193bafcb2155b.camel%40linux.ibm.com.
