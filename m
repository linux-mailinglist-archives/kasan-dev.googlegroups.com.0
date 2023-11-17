Return-Path: <kasan-dev+bncBAABBYVP32VAMGQEEIGGFHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F0617EF662
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Nov 2023 17:42:11 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-35ad87eecd7sf20733855ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Nov 2023 08:42:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700239330; cv=pass;
        d=google.com; s=arc-20160816;
        b=mvTkCkL2HUaBdrrk+3GNJQm8FjUNyy0uQfFA34qJJs8OkIYhNUpqt3lLRbA7kihCcY
         AoRMmCViH88qtsI25DV2mDmBoMheDfky3RVWD8TTobhNbTaq1XqZiuRkdbAM12tIHe62
         7JckTib+wlcUnXT1glSF5lcnVY9HPWHbWCaHSF62uNzsxxCG0eBnfFdZTB1xvZ/l7GQm
         fbPU4S/bYfZFDgIzHh/qFZrD10iFG7juuMq3gd1zJSZPtaDeUvhWAzA+0o/cs1IRzAWv
         t9IkMzqPlOPDLxGybxbNFMWoCK5BBH7y4LNtPlbfxP+7RtKbNmSkbPM6YQARC4s/k5tp
         SwAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xp/oNAtrxxZC+kOOxaRBQ03JQcCuo+ArGhKrfxNCAbw=;
        fh=Tn2XH5b2kYU3ab1LqFpLLGVHhVt1QB18/WdR3821wN8=;
        b=LDjun58bSrok1yi4pybvGDKCTMlUnGn6nrGVO2wBCHTrdpw4NCPqH1YVjUupI6GfW+
         aIi+dFxklCsRVBpcbORW6w5Wxcup7KnPgLWguS9qO2FPtF7hJZMxzNzqIlJ2LxDvfUAT
         Se4Ql3esK3cWzJywPMJyRRBEJCTgLEtyLh4bST/jWJb6UlZi+gDjjdNKPsQApJWoUQvB
         FAIIncqi/fXEHI9lq7FKntTDBDkNljHq01l0uvxonU7i5bakA3KPJO4pTCAVWU2mPmuS
         r7+ipJE3J56lOgty6u6GIsF79yr0YybYzT3VGojVj5hulpnUNuH0IMTcIveZbCXvuyaU
         c6Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oMXbX3n5;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700239330; x=1700844130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xp/oNAtrxxZC+kOOxaRBQ03JQcCuo+ArGhKrfxNCAbw=;
        b=VpFwYOslfQvICsX4LEedjH5rBo6MCsIa04UOfAbl6KRio+xPcWZ5guW6BaVivDCzvu
         rgk6/opOOnNPmPZXFuFlpCkF8vUOHZN3L8H9VJtGVwuH3zdMQ4O1EYe/jH9rDl0nKxtO
         Lf5zrgcBrg+DsPd0QvM0njFocIbo9stubQZcdYYGlCql33pxad6tSW4O5s/D2js5ua9Q
         qNphkCol0ns9WiFj3n8y9ATbAGVhiz0i+9MQLoxxauGeQJc+O1TLyCgniN9XKG4k22om
         cV9grITpbelsM4ZyANvPjJRRwGDaT5kMSRf1f5TODzdYrKj7KWCUwj4rV5AkYQM5KrP7
         uWpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700239330; x=1700844130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xp/oNAtrxxZC+kOOxaRBQ03JQcCuo+ArGhKrfxNCAbw=;
        b=JP7gtAvVhE/RKt2G6gETkqOQfo46a6FNBNOFRxV3iBij7aFlSd0vjUXD9uaxnvs64e
         eFPM6PixdU/xEC7jTFM/ZjbR7OmBXlXR4II/sihiG55hEBMw9YHh7YzDPdabE2j/D/Oh
         PiNeROm9kAuM8CdN06lEyRySAQsedqFhJWtRZTGMGJdZuUMoN0awslhRN1p+KyMKLIBP
         CuZFPXbHD7J9TnJjju2rgMa3FOM95JqWSca+Ogb8rxp7lheLIfCpzAx3BFe3waomCz6j
         RuyI2HHSX54ojyN2RLWfLfk9ppCH1AK59JFeGZp3HEuyH6s8rHrA92LUjhjmhN5I+Fr/
         alwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwHBA1bp6T7FIU6Q0BnlDK8hwRFyoEs/Bz//IhtkHD90A+qqV7n
	kBr8I08bjAZKjBfMn96twy0=
X-Google-Smtp-Source: AGHT+IFfTT44yKXW5pvSTwxbUK+Sd5LQGSrPWWGx00Lb3Fi6bh9MjSvBFCv//CIasM13+LVAyfdb9A==
X-Received: by 2002:a05:6e02:1c04:b0:357:f487:32b6 with SMTP id l4-20020a056e021c0400b00357f48732b6mr25638401ilh.22.1700239330188;
        Fri, 17 Nov 2023 08:42:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c04e:0:b0:359:3b32:16fc with SMTP id o14-20020a92c04e000000b003593b3216fcls954588ilf.2.-pod-prod-05-us;
 Fri, 17 Nov 2023 08:42:09 -0800 (PST)
X-Received: by 2002:a05:6602:2ac5:b0:7b0:1caf:33fc with SMTP id m5-20020a0566022ac500b007b01caf33fcmr24407473iov.14.1700239329448;
        Fri, 17 Nov 2023 08:42:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700239329; cv=none;
        d=google.com; s=arc-20160816;
        b=jXIw06d4wVH63RERJc7GKyTBz3NCR2xWQhHlwy51Y02WpfV8gnx/nLo+CwSx6vR8wG
         +9QAX4Hu/RA80CWqO2202HQYGxul3xtclu+bJpxsrUJvH8R9fMmwFAmZ7md1TW2ZGQn7
         bCv+Kh2LtFVj/oz/zL2iX+UQP3BhpqBd2/2ReAq9FDB/SOfqc1fSlXmAvWI3138v9egE
         Bn/W4aUaxIMPdyZ2uJ70H4S/geWMKTa75NVaiOL+uVXLl4RADX4Y5ZIPIvogl3GFNDsk
         wR5SrtxLjr4SmgwRAq9q4kwl3CT0rx9H7ZilGvIN3HIICOyTKtRqPVd0yBE1/CKNkdy+
         MrAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=StP4cu79FPer/ncWhUGarKu7uDEe4P30IUkZKgB8Pno=;
        fh=Tn2XH5b2kYU3ab1LqFpLLGVHhVt1QB18/WdR3821wN8=;
        b=EEP7BZzAJJMiDk+D0z2nqRuC9gjjuMQLPzOm9CJqW8t/qZHdfPmWZVBXK0RuBHv08M
         qEV5SQ2fnFuNrhpHwxdV7fBLp7577/TfuSq1iQgQntmecejXzNbFM7Yn2SkWQF7Xob4E
         nvJbkmaOXoNLcJD6r7zVgV0Y9DQeZzOj0bLQTOlrlI4gASf0WcEhve3WsvMgShhmFfA1
         kGZfSmWCZguRP+ETLFtL2mHxIipsJBHoi7H02/cLvf6hju4RHS4G+mXvsBRPWyqkdu9W
         iRx01O9eHF0ELHQDjuwIAq6IJ0cgtHSM0yrWT413up1W1k2axphgAJFE1z/qbQ2pZ18m
         +EBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oMXbX3n5;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id dk36-20020a0566384be400b004312fb02a61si195269jab.4.2023.11.17.08.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Nov 2023 08:42:09 -0800 (PST)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AHGcfOD021383;
	Fri, 17 Nov 2023 16:42:05 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uebve828t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Nov 2023 16:42:05 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AHGdXHQ023036;
	Fri, 17 Nov 2023 16:42:04 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uebve828g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Nov 2023 16:42:04 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AHG48xD009036;
	Fri, 17 Nov 2023 16:42:03 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uanem75jx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Nov 2023 16:42:03 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AHGg0dK20775522
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 17 Nov 2023 16:42:00 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 935B020043;
	Fri, 17 Nov 2023 16:42:00 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5C1C820040;
	Fri, 17 Nov 2023 16:41:58 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.53.3])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 17 Nov 2023 16:41:58 +0000 (GMT)
Date: Fri, 17 Nov 2023 17:41:56 +0100
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>,
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
Subject: Re: [PATCH 26/32] s390/mm: Define KMSAN metadata for vmalloc and
 modules
Message-ID: <ZVeX1K6jIihnXIox@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
 <20231115203401.2495875-27-iii@linux.ibm.com>
 <CAG_fn=XSKh=AmU3mEC7dNmEFk5LaLt+y+TfsVcD0Dn5NsbTBSw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XSKh=AmU3mEC7dNmEFk5LaLt+y+TfsVcD0Dn5NsbTBSw@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: uOIqbaNKTfMkkRxqsp7HM2Lax2N0tjjf
X-Proofpoint-ORIG-GUID: cilvsidISOBHr1Hvn1uIcIjCKlM8WL09
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-17_15,2023-11-17_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 spamscore=0
 clxscore=1011 lowpriorityscore=0 phishscore=0 priorityscore=1501
 mlxscore=0 impostorscore=0 mlxlogscore=633 suspectscore=0 adultscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311170124
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oMXbX3n5;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
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

On Thu, Nov 16, 2023 at 04:03:13PM +0100, Alexander Potapenko wrote:

Hi Alexander!

> >         /* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
> >         vmalloc_size = min(vmalloc_size, round_down(VMALLOC_END / 2, _REGION3_SIZE));
> > +#ifdef CONFIG_KMSAN
> > +       /* take 2/3 of vmalloc area for KMSAN shadow and origins */
> > +       vmalloc_size = round_down(vmalloc_size / 3, PAGE_SIZE);
> Is it okay that vmalloc_size is only aligned on PAGE_SIZE?
> E.g. above the alignment is _REGION3_SIZE.

Good question!

This patch does not break anything, although the _REGION3_SIZE 
alignment would be consistent here. Yet, we might rethink this
whole code piece and the next version would reflect that.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZVeX1K6jIihnXIox%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
