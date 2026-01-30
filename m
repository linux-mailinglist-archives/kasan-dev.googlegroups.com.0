Return-Path: <kasan-dev+bncBAABBBXK6PFQMGQE7MQCDNY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8BhsCAn1fGlLPgIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBBXK6PFQMGQE7MQCDNY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 19:14:33 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9354CBDA21
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 19:14:32 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-6465127b47dsf3506735d50.0
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 10:14:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769796871; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dfg7eGVv33NKM9BDL957lw+z4h0yOAIaQFcqoYmgE15sW/u6UyKnKpL9cOCf93pGwY
         8FIBAFB60yvlX3/GN5VN5eptWECLeDij09Yv+GNwA1B8iCBj+SvqtzXMF0KcMfSKNlss
         jcEJEGoSuhpKDZ9lTMVNl+XzEkTlMSpK8tbfaA4A+/k1GQzNrr85by2iq4Sn2Q6QPtSu
         F3yChFS8M44TaVSIweRX8XAG/Eten1yDINSplGQQ3hd0s47IFmcNjFveHopxVux+pj9E
         TOq4pS35gWAaCWv/sxPDJo8A/qmALvz5bPU0TVD/S0bnMtUtKcuWQa4D6geLLPPQ0+sY
         4Ycw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=nKCrVuxmZGwSc/45N/eY9CnPJCD+a7jX+M9TIm0zmEQ=;
        fh=VcurUHUoe2wKAHG1JsP9CtktRlUNCHUgP0u2n7B88bQ=;
        b=IfD4pUIWouQpjUSbjQGu2j+J4ehgyyKSnEXVdFiwtMwZGsR28/B677AuwUuslc101/
         xleDi11DgZVk6MGQHjhaxmGQtlsHNNkFMCY6qhRmge6+VQlw5qb6wfwT0B7rUF/pOXp3
         s9NWtQAL2zXbXG7I9OwGcuSooYF4pjvjwAR2zITzqrvXV96YfS7XZVt+TtIEim68REK4
         kFLXqrzhCiUL/k4uLvnk4BXzS5bGuhExm1nSlD2GMb4eh+hyAGtfwHh+VOo6Hd3cOTB1
         MevRIINgi9OkoY7dpZQZSjmLERaa4ZBOK3MZk3DpTI9Nr5DZhHjuWC5vwaDsyREgE8ij
         a2Og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="opNnqx2/";
       spf=pass (google.com: domain of samir@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=samir@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769796871; x=1770401671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nKCrVuxmZGwSc/45N/eY9CnPJCD+a7jX+M9TIm0zmEQ=;
        b=vQkhsZVtVUkTMdhhHWGXjOVZO0sH5CSuqkQJJpkrS719Q/VJzMaoygoStSQpmMYch7
         s6R7QCxJPG7L3/hzIojxgdG49krtjTxLk/KzvvJ7F+czth+kvlRQYPWjZt9E9J9H/jYn
         4oQrPWwrBvdilEla4OQsGnF6LuvdNc+qWrJ3IlkQAizlZWpohhxP4pOeVYY37h+H7Z0H
         5ySkDh1aVUKtL4bV5xRG+f8llMegg72S5yWw81m/xtUy4aJvGUEjmMVEnw+X8hBAX08z
         3W1jH224YVV4k/N/zEyWuiEQKhHR2tuSrIz3aR9na4MduZLuZ2Ohj/VfGwHoC6SvbruG
         Wvcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769796871; x=1770401671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nKCrVuxmZGwSc/45N/eY9CnPJCD+a7jX+M9TIm0zmEQ=;
        b=LOQvsrbi1oqDFMmpdAhf6QWM4oCm1lKa/9kpMM0krhMmm7oaSbk/gPxJ+K+76a1A65
         IYM9Q02J/pzZM3LtgHFDF6C2UqUfa6E7LF1MeEftrybvJfC1Vqa+WL/2mx0/u9W3WElF
         NYz3yAwPMKhYA0VROQyowSUImRuyA4xKpwQVa+TZu82tzpoGvw0WPYL48tUU3jThl1IR
         HzAycvFttEmjZLoQ0AvGWyda+qDvgriRqKE0E00haMpuvMLUXQHEMOcNO9DKGXD1OPcJ
         ykYR4XrU8CvDieMxGQZikPvugch7PIZMAfKKyoG3fbswZiAxrBw+7cqi9dzTrW3EEneQ
         cJbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVV59KDNGOY87RSUD3WkoBgsG9EOR9km+AqXeTRH6+nYDxmMPDwXgzaS/dUq0uWgjbLdZ7ZgQ==@lfdr.de
X-Gm-Message-State: AOJu0YyezFPyLQ9OlFsCdFZoggM2N7f/3eBwYgVWxkLBf82U1pjdptsy
	U8xjIEJrQLW3D+YLvogYZqUx2iLiLCJ6ovRC/N7eOlvUE9nWtpLCWtoz
X-Received: by 2002:a05:690e:1402:b0:649:5926:91e1 with SMTP id 956f58d0204a3-649a8436a6dmr3111576d50.6.1769796870765;
        Fri, 30 Jan 2026 10:14:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EWd3cNtzSAvXMZsjyEVMobwIaWWYOiwSp1X1dP8llSdA=="
Received: by 2002:a53:bd84:0:b0:649:3fa4:9e9e with SMTP id 956f58d0204a3-649a023230els1376114d50.2.-pod-prod-05-us;
 Fri, 30 Jan 2026 10:14:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX4QSs7bSzM/1QzBc/l+/WDJr2FKw7u1VuD7qw46hWjkDJxsrycDsCebpNvG8BweruF9qX+bEU3N84=@googlegroups.com
X-Received: by 2002:a05:690e:168e:b0:645:591a:cb6a with SMTP id 956f58d0204a3-649a8552f2emr2929911d50.70.1769796869986;
        Fri, 30 Jan 2026 10:14:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769796869; cv=none;
        d=google.com; s=arc-20240605;
        b=d1NsPTKZbGEB1ougQSps8VKckZ9DJjpKIH+p6GK+ya5hJmuBuSeih5VpI+L/+wjRhf
         txrsrAIVUCUgUr1fhpYrfZCdAm57jSL0HW/TGJNcMnPUuuPCAumKM5pHrHtNJWupX6qI
         RDV9pMRhiTMgtm0T1+IQCT2+Oeqi3X9wm6ZYUKAshE/Avl3Lyt692/TnjeFODGuJH5nQ
         h0dZ5gwG8fIYfZk8f2Ans4zWiJiLM6UNz3N4lQPHXup0ZuIoejAUDzGL1AP3jDoyky7K
         HXuEEaV56Bx3IoifgqVau/xsay3aaazaG9+OIXyyYThW7Hz6SByJg6wf0XI3+wJN2m4y
         PbYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=w1nW3KOUvCdqwlN8NuW8QfC4bZBs8Lgb4Y/hZ2Npil0=;
        fh=ApZLEvhiwHudDKw/U9jOj85yZTs/ZjSK3tbtuWhHKrI=;
        b=ZwO4iKpoTXB3pbviiWym2XtdIAhgvKSHQ0HDM6qR/zeVV75J0e1Ci5ZIPfa7TxBR7z
         OTyVBES0/ht2rLRT3P1/3M/jzq7A86RxoTTQqZYY1aa+4yYJFr2SkW+5EGHoVy7XfEkl
         qmggRlMWCiR22aYPR+0BI+r1ukpQ1a4BpMFK2foFWCD2AOtCWFCRD2q+ojqhBJvod6ZY
         3ArSrnrXsi0ybqThf0nN7oCistbFqoTzDWgOGvbUagZDVxX1RgeFUM1ibgeYkY8VYLHH
         fPNYDjuE/Z5/Yr2yPMyLjT1EOmECr3PbFAZvnMpF6h4Zjiy4b/Lu4UZeAv+HzpTpsBrc
         8eEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="opNnqx2/";
       spf=pass (google.com: domain of samir@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=samir@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-649960e0262si318429d50.3.2026.01.30.10.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Jan 2026 10:14:29 -0800 (PST)
Received-SPF: pass (google.com: domain of samir@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60UHReo8022770;
	Fri, 30 Jan 2026 18:14:20 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bvkgn46rs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 30 Jan 2026 18:14:19 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60UIEJKv017601;
	Fri, 30 Jan 2026 18:14:19 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bvkgn46rp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 30 Jan 2026 18:14:18 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60UHmidH017966;
	Fri, 30 Jan 2026 18:14:18 GMT
Received: from smtprelay06.dal12v.mail.ibm.com ([172.16.1.8])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 4bwb4271t5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 30 Jan 2026 18:14:18 +0000
Received: from smtpav01.wdc07v.mail.ibm.com (smtpav01.wdc07v.mail.ibm.com [10.39.53.228])
	by smtprelay06.dal12v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60UIEGb131392440
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 30 Jan 2026 18:14:17 GMT
Received: from smtpav01.wdc07v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9275058063;
	Fri, 30 Jan 2026 18:14:16 +0000 (GMT)
Received: from smtpav01.wdc07v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4F61058059;
	Fri, 30 Jan 2026 18:14:04 +0000 (GMT)
Received: from [9.39.21.87] (unknown [9.39.21.87])
	by smtpav01.wdc07v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 30 Jan 2026 18:14:03 +0000 (GMT)
Message-ID: <381b6d7d-69b0-4fdc-bd42-5779e5778374@linux.ibm.com>
Date: Fri, 30 Jan 2026 23:44:01 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 0/8] Generic IRQ entry/exit support for powerpc
To: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>, maddy@linux.ibm.com,
        mpe@ellerman.id.au, npiggin@gmail.com, chleroy@kernel.org,
        ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
        dvyukov@google.com, vincenzo.frascino@arm.com, oleg@redhat.com,
        kees@kernel.org, luto@amacapital.net, wad@chromium.org,
        mchauras@linux.ibm.com, thuth@redhat.com, ruanjinjie@huawei.com,
        sshegde@linux.ibm.com, akpm@linux-foundation.org, charlie@rivosinc.com,
        deller@gmx.de, ldv@strace.io, macro@orcam.me.uk,
        segher@kernel.crashing.org, peterz@infradead.org,
        bigeasy@linutronix.de, namcao@linutronix.de, tglx@linutronix.de,
        mark.barnett@arm.com, linuxppc-dev@lists.ozlabs.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
Content-Language: en-US
From: Samir M <samir@linux.ibm.com>
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=Gr1PO01C c=1 sm=1 tr=0 ts=697cf4fb cx=c_pps
 a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17
 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=Yqzg2m6fQhnNyKgerrwA:9 a=3ZKOabzyN94A:10
 a=QEXdDO2ut3YA:10
X-Proofpoint-GUID: JGzjuNtitJMVHxJlJV3X6tzSw1CTD6F7
X-Proofpoint-ORIG-GUID: SsXK2U34AYQ4lw-l7K_LPzM9FXnK_LAP
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTMwMDE0NiBTYWx0ZWRfX1H8YSZfRyKlE
 IsgOACPSoIh12ZMHDu2CUAVnzTNvBO9qSqAbs0tGLk5KKBeaO2/wEoPzK5j2F+cVcIyYKrjqQtQ
 gAd1qPGOL/u/vduSzvbdaolKzD9kfH5UoWMKM29OpJMGNlcw/QeKlDtpniVjCWsns+xCCQjvCLS
 Q+v7w4Mw/pNRxdvRWNeiWMZoVxbhwSKjVv3nkr4cFTxaBBFn8fnHloEXwkTtHIynlVCvGnczAIR
 1aRFohRBF3gsW4Z3ZY2zVqfm/yPtBf2Q0bvDWTiu2RtrzjAmqeDWwFM3NMMAiCg/sxuNPzCfz3u
 XUqW+FkLaCvELrERht22DllDzvNSJGuzTZ7YkY/rATA8mbM5wJHNM42UqM74OqpF6QNVHS7lZT0
 p0cCphib+l5yxVZyYjoJJ4DMWZeYHGJ5rWcAX1SteDjQY3d/oYwusgi+IaaGmtUQP+8mc1KtwtD
 2Vb/oEQYoZt3Cg8mtrQ==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-30_02,2026-01-30_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 priorityscore=1501 clxscore=1011 lowpriorityscore=0 suspectscore=0
 impostorscore=0 phishscore=0 malwarescore=0 adultscore=0 spamscore=0
 bulkscore=0 classifier=typeunknown authscore=0 authtc= authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2601150000
 definitions=main-2601300146
X-Original-Sender: samir@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="opNnqx2/";       spf=pass
 (google.com: domain of samir@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=samir@linux.ibm.com;       dmarc=pass
 (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBAABBBXK6PFQMGQE7MQCDNY];
	RCPT_COUNT_TWELVE(0.00)[32];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWELVE(0.00)[13];
	FROM_NEQ_ENVFROM(0.00)[samir@linux.ibm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,mail-yx1-xb13c.google.com:helo,mail-yx1-xb13c.google.com:rdns]
X-Rspamd-Queue-Id: 9354CBDA21
X-Rspamd-Action: no action


On 23/01/26 1:09 pm, Mukesh Kumar Chaurasiya wrote:
> Adding support for the generic irq entry/exit handling for PowerPC. The
> goal is to bring PowerPC in line with other architectures that already
> use the common irq entry infrastructure, reducing duplicated code and
> making it easier to share future changes in entry/exit paths.
>
> This is slightly tested of ppc64le and ppc32.
>
> The performance benchmarks are below:
>
> perf bench syscall usec/op (-ve is improvement)
>
> | Syscall | Base        | test        | change % |
> | ------- | ----------- | ----------- | -------- |
> | basic   | 0.093543    | 0.093023    | -0.56    |
> | execve  | 446.557781  | 450.107172  | +0.79    |
> | fork    | 1142.204391 | 1156.377214 | +1.24    |
> | getpgid | 0.097666    | 0.092677    | -5.11    |
>
> perf bench syscall ops/sec (+ve is improvement)
>
> | Syscall | Base     | New      | change % |
> | ------- | -------- | -------- | -------- |
> | basic   | 10690548 | 10750140 | +0.56    |
> | execve  | 2239     | 2221     | -0.80    |
> | fork    | 875      | 864      | -1.26    |
> | getpgid | 10239026 | 10790324 | +5.38    |
>
>
> IPI latency benchmark (-ve is improvement)
>
> | Metric         | Base (ns)     | New (ns)      | % Change |
> | -------------- | ------------- | ------------- | -------- |
> | Dry run        | 583136.56     | 584136.35     | 0.17%    |
> | Self IPI       | 4167393.42    | 4149093.90    | -0.44%   |
> | Normal IPI     | 61769347.82   | 61753728.39   | -0.03%   |
> | Broadcast IPI  | 2235584825.02 | 2227521401.45 | -0.36%   |
> | Broadcast lock | 2164964433.31 | 2125658641.76 | -1.82%   |
>
>
> Thats very close to performance earlier with arch specific handling.
>
> Tests done:
>   - Build and boot on ppc64le pseries.
>   - Build and boot on ppc64le powernv8 powernv9 powernv10.
>   - Build and boot on ppc32.
>   - Performance benchmark done with perf syscall basic on pseries.
>
> Changelog:
> V3 -> V4
>   - Fixed the issue in older gcc version where linker couldn't find
>     mem functions
>   - Merged IRQ enable and syscall enable into a single patch
>   - Cleanup for unused functions done in separate patch.
>   - Some other cosmetic changes
> V3: https://lore.kernel.org/all/20251229045416.3193779-1-mkchauras@linux.=
ibm.com/
>
> V2 -> V3
>   - #ifdef CONFIG_GENERIC_IRQ_ENTRY removed from unnecessary places
>   - Some functions made __always_inline
>   - pt_regs padding changed to match 16byte interrupt stack alignment
>   - And some cosmetic changes from reviews from earlier patch
> V2: https://lore.kernel.org/all/20251214130245.43664-1-mkchauras@linux.ib=
m.com/
>
> V1 -> V2
>   - Fix an issue where context tracking was showing warnings for
>     incorrect context
> V1: https://lore.kernel.org/all/20251102115358.1744304-1-mkchauras@linux.=
ibm.com/
>
> RFC -> PATCH V1
>   - Fix for ppc32 spitting out kuap lock warnings.
>   - ppc64le powernv8 crash fix.
>   - Review comments incorporated from previous RFC.
> RFC https://lore.kernel.org/all/20250908210235.137300-2-mchauras@linux.ib=
m.com/
>
> Mukesh Kumar Chaurasiya (8):
>    powerpc: rename arch_irq_disabled_regs
>    powerpc: Prepare to build with generic entry/exit framework
>    powerpc: introduce arch_enter_from_user_mode
>    powerpc: Introduce syscall exit arch functions
>    powerpc: add exit_flags field in pt_regs
>    powerpc: Prepare for IRQ entry exit
>    powerpc: Enable GENERIC_ENTRY feature
>    powerpc: Remove unused functions
>
>   arch/powerpc/Kconfig                    |   1 +
>   arch/powerpc/include/asm/entry-common.h | 533 ++++++++++++++++++++++++
>   arch/powerpc/include/asm/hw_irq.h       |   4 +-
>   arch/powerpc/include/asm/interrupt.h    | 386 +++--------------
>   arch/powerpc/include/asm/kasan.h        |  15 +-
>   arch/powerpc/include/asm/ptrace.h       |   6 +-
>   arch/powerpc/include/asm/signal.h       |   1 -
>   arch/powerpc/include/asm/stacktrace.h   |   6 +
>   arch/powerpc/include/asm/syscall.h      |   5 +
>   arch/powerpc/include/asm/thread_info.h  |   1 +
>   arch/powerpc/include/uapi/asm/ptrace.h  |  14 +-
>   arch/powerpc/kernel/interrupt.c         | 254 ++---------
>   arch/powerpc/kernel/ptrace/ptrace.c     | 142 +------
>   arch/powerpc/kernel/signal.c            |  25 +-
>   arch/powerpc/kernel/syscall.c           | 119 +-----
>   arch/powerpc/kernel/traps.c             |   2 +-
>   arch/powerpc/kernel/watchdog.c          |   2 +-
>   arch/powerpc/perf/core-book3s.c         |   2 +-
>   18 files changed, 690 insertions(+), 828 deletions(-)
>   create mode 100644 arch/powerpc/include/asm/entry-common.h
Hi Mukesh,

I verified this patch with the following configuration and test coverage.

Test configuration:

  * Kernel version: 6.19.0-rc6
  * Number of CPUs: 80

Tests that are performed:
1. Kernel selftests
2. LTP
3. will-it-scale
4. stress-ng (IRQ and syscall focused)
5. DLPAR with SMT stress testing
6. DLPAR with CPU folding scenarios
7. ptrace, ftrace and perf related tests.
8. Build and boot.

No functional issues were observed during testing.


Performance Tests:
perf bench syscall usec/op:(+ve is regression)
syscall=C2=A0 | without_patch | with_patch |=C2=A0 %change |
--------------------------------------------------
getppid=C2=A0 |=C2=A0 =C2=A00.100=C2=A0 =C2=A0 =C2=A0 =C2=A0| =C2=A00.102=
=C2=A0 =C2=A0 |=C2=A0 +2.0 %=C2=A0 |
fork.=C2=A0 =C2=A0 |=C2=A0 =C2=A0363.281=C2=A0 =C2=A0 =C2=A0| =C2=A0369.995=
=C2=A0 |=C2=A0 +1.85%=C2=A0 |
execve.=C2=A0 |=C2=A0 =C2=A0360.610=C2=A0 =C2=A0 =C2=A0| =C2=A0360.826=C2=
=A0 |=C2=A0 +0.06%=C2=A0 |


perf bench syscall ops/sec:(-ve is regression)
syscall=C2=A0 | without_patch | with_patch=C2=A0 |=C2=A0 %change |
--------------------------------------------------
getppid=C2=A0 |=C2=A0 =C2=A010,048,674=C2=A0 | 9,851,574|=C2=A0 =C2=A0=E2=
=88=921.96% |
fork.=C2=A0 =C2=A0 |=C2=A0 =C2=A02,752=C2=A0 =C2=A0 =C2=A0 =C2=A0|=C2=A0 =
=C2=A0 2,703 =C2=A0 |=C2=A0 =C2=A0=E2=88=921.78% |
execve.=C2=A0 |=C2=A0 =C2=A02,772=C2=A0 =C2=A0 =C2=A0 =C2=A0| 2,771=C2=A0 =
=C2=A0 |=C2=A0 =C2=A0=E2=88=920.04% |


IPI latency benchmark (-ve is improvement)

| Metric =C2=A0|=C2=A0without_patch=C2=A0(ns)|=C2=A0with_patch=C2=A0(ns) | =
% Change |
| -------------- | ----------------- | --------------- | -------- |
| Dry run=C2=A0 =C2=A0 =C2=A0 =C2=A0 | 202259.20 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0| 201962.38=C2=A0 =C2=A0 =C2=A0 =C2=A0| -0.15%=C2=A0 =C2=A0|
| Self IPI=C2=A0 =C2=A0 =C2=A0 =C2=A0| 3565899.21 =C2=A0 =C2=A0 =C2=A0 | 32=
71122.04=C2=A0 =C2=A0 =C2=A0 | -8.27%=C2=A0 =C2=A0|
| Normal IPI=C2=A0 =C2=A0 =C2=A0| 47146345.28=C2=A0 =C2=A0 =C2=A0 =C2=A0| 4=
2920014.89=C2=A0 =C2=A0 =C2=A0| -8.97%=C2=A0 =C2=A0|
| Broadcast IPI=C2=A0 | 3920749623.87=C2=A0 =C2=A0 =C2=A0| 3838799420.04=C2=
=A0 =C2=A0| -2.09%=C2=A0 =C2=A0|
| Broadcast lock | 3877260906.55=C2=A0 =C2=A0 =C2=A0| 3803805814.03=C2=A0 =
=C2=A0| -1.89%=C2=A0 =C2=A0|

Please add the below tag,

Tested-by: Samir M <samir@linux.ibm.com>


Regards,
Samir.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
81b6d7d-69b0-4fdc-bd42-5779e5778374%40linux.ibm.com.
