Return-Path: <kasan-dev+bncBAABBWEXWWXAMGQE5UYKVJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5248C855739
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 00:25:14 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7c2c96501e6sf19358339f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 15:25:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707953113; cv=pass;
        d=google.com; s=arc-20160816;
        b=H5Zue38XeCISWGHL/l9mRYo3Y1AsEHKpzRltHegqtRuLdUGGdYGlvXwHNf9ThynlCX
         tgeHUptH8aqF6fcldrLXM5Hwo5oJwUyVKkuuePZWYmNmVPt/qRf2uREdsV/8vADDrVNb
         LHK3FMe/fvuxkAWNFYXde7IA3moTPNbTx3aQcgfUA00YRV5LiIiNSsFaI5qTAuMHHDad
         +nz403lc5DBJkJUvNVd6i0h6ICjO97rSDKlGoY9RKXjYZHC3B07QtnYNwf+XakWuI12H
         egAKGDJFl21zJjUR2IQDl9840AN9PJAxlbEokeV9z2Ehi2bYpehb1WA9q89vAht8Sbtu
         dLFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:user-agent:autocrypt:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=Sv0nZuaM+ovUpGjc4zgc2wTUM1yu9b4jpR1KsuTqHTo=;
        fh=Y86pGsWTgCYXADy1qvMOK/5QgLq9ThQlKfF3J2KEnsY=;
        b=of+MtAe9K3hcJJlQ/RcyUzvW6GJV7g240tF2pJJtG6/oz6pz6QVFMcekjaALy6aa6F
         AgPPtP6HwYDoMPdPwfpqKKC+E4k4zeOGtTmXCuNOdOsi9Vc871pLic+gmkzHyQQZBxgj
         cUIctt2jBKF5qWP6CJXsCio/IlZiPPTQbcA5A1aE8sH8YWBqloS+f3nThp6CTXEojJPt
         F19AibhldslhR+4KnNVRePtMg48c0igyUlO3MYzugbyNx2oMCMN+lAfF/L5jMGXbMOKG
         IS2s8HKDc9rdNsklfJ8FCdJLGQDupsND57mkLmnvYZboz0IcgS4s1w0fmtdAiChEdk2M
         4Xcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Wkdq3tcg;
       spf=pass (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=bgray@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707953113; x=1708557913; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:user-agent
         :autocrypt:references:in-reply-to:date:cc:to:from:subject:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sv0nZuaM+ovUpGjc4zgc2wTUM1yu9b4jpR1KsuTqHTo=;
        b=UMpJzn241vwYE6lppsQtMIyu7mXBLIrhl+RLCxOT9mJSjhWqj4raReX0x74huJlwtq
         mijpVYuhUBpX76r2bdXO4Ks9fosLtX0pZ83zX6vnwYdgvVznuY1xAXIXAYYb2Ym2BsXy
         p1FrmZbeB3rwztv2F4PfcBaf6y2tw5/8LiKi4UYCtW8cqNbRcQ5rM2QaXZwkbslVzQk+
         vXWG2TO+SklkKAiq5lmftw9zlXve0pIQ8n3JCJbzio34rOMuxUkETPqp49KVStrIAzPZ
         2wKEY/B74tc78uNAjA4oQkRpV7MAGd11XPOMEX8E2s+sqWJmvepQlX19kF9fyzHJSzci
         5/bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707953113; x=1708557913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:user-agent:autocrypt:references
         :in-reply-to:date:cc:to:from:subject:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Sv0nZuaM+ovUpGjc4zgc2wTUM1yu9b4jpR1KsuTqHTo=;
        b=Vy1b/6huo0jbJ/ggJaK4bGuiS8Tyd/LozJKNGbeIATx4N0hafT3u4HKIfffRMiSSSB
         3olavMDwni8RnAZLmeCXgyJpPMlm9OljubK0hfMIy7zBqQGCFIz0ZBMGxsx/mIHYxskX
         T9K8WgiVjjVsEok1cOGfsZ9oKOCdYCteozLXaxdECGpkQDJ2y3i90wBAA2mOz27kr+8w
         LW/ubCd49SCfADXuod5y/cvHv4Fq/kHr92ckeoUrA1t/yerqAo+TWjMLFyvvDFVUe+HS
         mJB9MqgE49IkabQpqZKBqdmpkvJ8fUxR4mOMjIVsYyINJS0JBM/KqCBhMkuxOkXyDy8t
         BaCg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0gDLv/vIDEXSdWOeRdf7Lu8RUwktQRsF1zgDepNe36melHx220Jel4SoRsiLPZef4Zi5YhgYyxCwcQxTpKKKqCPvm4zR6XA==
X-Gm-Message-State: AOJu0YyS0SllB9hXvnO4LUM19a/aHS0/jr8ejZ1XOg1KTamZ2/rD6qrc
	PbAQbeKG412M4FuKz8gCvyTjZQ10gNkhrzavLcvg+0/DAdZJI6wA
X-Google-Smtp-Source: AGHT+IHfmG1Tn7aHxpGDahrSkcBvnK6UHDtHAXw89IuNO3WQXtrv6CV2hUrwbIUh/COkmzuGVb1tCA==
X-Received: by 2002:a92:d7c2:0:b0:364:91fe:d9f4 with SMTP id g2-20020a92d7c2000000b0036491fed9f4mr2450054ilq.19.1707953113060;
        Wed, 14 Feb 2024 15:25:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1aa8:b0:364:ed2b:1f69 with SMTP id
 l8-20020a056e021aa800b00364ed2b1f69ls376943ilv.0.-pod-prod-02-us; Wed, 14 Feb
 2024 15:25:12 -0800 (PST)
X-Received: by 2002:a05:6602:2558:b0:7c4:4a9c:4b54 with SMTP id cg24-20020a056602255800b007c44a9c4b54mr223103iob.16.1707953112066;
        Wed, 14 Feb 2024 15:25:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707953112; cv=none;
        d=google.com; s=arc-20160816;
        b=hECfw+RbzWvaQz/0RFQFje3k8Or1vpyb7CLlhjXbiPKf2WzBN8O/YLcAWNE5TMDOwm
         yKssTlpPkSngII/LMiBbjvp1yPUTh8G2PPCueAmytBBJroUwF6eRMvYq7qC+uEKhMQ5x
         cRKP4bBYi4tlKPnGOqdewRwgJyqYHAQxwLUDk0fLHXXs7723ysDRVwgmm9CU9702z2Lw
         6z00226YTg1FQ4Y1VJJ21qmZ4OA6zbat2DddbGxv5ZTFFs53yeOztPl/QJywfkDYEETr
         UcjQtLJDrqxqn9Y7Ez5n6h9aRshJ9QViA51/3Zs2oPmPy0Axg0pI6ILj6l3FzIV7e7OC
         e0ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:user-agent:autocrypt
         :references:in-reply-to:date:cc:to:from:subject:message-id
         :dkim-signature;
        bh=hiwpEroaJMALZiL5s/hLE8vSgGJ/Bjyy7lCDadDN3f4=;
        fh=xCvsLCpqB94SBG5uOoHb0mwgIsOjoNQfgZ/loi01GIE=;
        b=JMY4nlF+6H2UdTnQL4ov/fLscDUm/wdvlukRx1SR4OHUru8hxWb3jsrM3jqM2dWCR0
         bZglHYZIirSMPjqBg1Lg+cbhKeitn9ovPiL4D22hyo5HPvZ2UICqhrrA8v34akBwVODQ
         FnPOf6vvKKKxPBKMiPZ5z5sunVDxRD23b8ONnVYkYJna3CzsJyCB7ws9AHjJMK9r/Yap
         s7VeTOXK4Yv9lj7qIaccXz/MG4wC9Il6t00CZ73PBu73GBFmFNhn9ukxnXcU977xAZ5t
         Tje4ErktKSmWpEogHxSQ3hubug6KHzryklf6dZsmx6GIZ7BLO3JDnlmOa8zWI/g10uBT
         s8/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Wkdq3tcg;
       spf=pass (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=bgray@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y127-20020a6bc885000000b007c3efd14598si1757742iof.1.2024.02.14.15.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Feb 2024 15:25:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 41EMh5W6029840;
	Wed, 14 Feb 2024 23:25:06 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3w96j6gu3f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 14 Feb 2024 23:25:06 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 41ENP5xH014416;
	Wed, 14 Feb 2024 23:25:05 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3w96j6gu38-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 14 Feb 2024 23:25:05 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 41EKp056032553;
	Wed, 14 Feb 2024 23:25:04 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3w6kftsd4x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 14 Feb 2024 23:25:04 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 41ENP1Q22687668
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 14 Feb 2024 23:25:03 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E67DB20043;
	Wed, 14 Feb 2024 23:25:00 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 26B0520040;
	Wed, 14 Feb 2024 23:25:00 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 14 Feb 2024 23:25:00 +0000 (GMT)
Received: from [10.61.2.107] (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 27A48602C2;
	Thu, 15 Feb 2024 10:24:55 +1100 (AEDT)
Message-ID: <37d83ab1b6c60b8d2a095aeeff3fe8fe68d3e9ce.camel@linux.ibm.com>
Subject: Re: [PATCH] kasan: guard release_free_meta() shadow access with
 kasan_arch_is_ready()
From: Benjamin Gray <bgray@linux.ibm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kasan-dev@googlegroups.com, mpe@ellerman.id.au, ryabinin.a.a@gmail.com,
        glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        akpm@linux-foundation.org, linux-mm@kvack.org
Date: Thu, 15 Feb 2024 10:24:54 +1100
In-Reply-To: <CA+fCnZe2Ma6Xj5kp6NK9MekF+REbazTFwukdxkgnE9QAwyY=NA@mail.gmail.com>
References: <20240213033958.139383-1-bgray@linux.ibm.com>
	 <CA+fCnZe2Ma6Xj5kp6NK9MekF+REbazTFwukdxkgnE9QAwyY=NA@mail.gmail.com>
Autocrypt: addr=bgray@linux.ibm.com; prefer-encrypt=mutual;
 keydata=mDMEYzuwexYJKwYBBAHaRw8BAQdAsgBYEqW6nNaL7i0B3z1RqyMl8ADupDef+5Sfe+JbzeC0I0JlbmphbWluIEdyYXkgPGJncmF5QGxpbnV4LmlibS5jb20+iJMEExYKADsWIQQ9K5v9I+L06Hi4yOJ5xrdpFsvehAUCYzuwewIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRB5xrdpFsvehCiCAP4g7CDkmsakpwv9QxU2D8dophyCIS8meDOQX4/83/sjHgEA5HWbUsbRCpVmeIgu0iNwhw3cmqhkv7ZkBGe3HhHaXg65Ay4EYzuwkREIAJjQ1EDAmLbOENucLy7VUzyNNCHkBirK/+FbjwOW7VIphc8zgsbZ26ZjIu5vC1NY7U7DpOvLAfR0g4+2QeKiQ8EEcuxLhif5X+jsekq0oSTVLcyNYXArJ3mhmV7jRhz8wBueMoXY/k+P3HCVLi4vzroJzN06Hrnmeu5ELlC4MbuvGRTvW751Y/o7gTa6hyyLb2P4pQ+sj/PuIn2Ly1RJPF839HVcOOERkjZ2QZNJnXEhlpfDD7LyRsy9Xm6MxGKRE5VsfjaO+Q8B6ByhXIy5/QK41AF1uSIPBfkZ8+AsBFw8Z87VGQ61tDdzi0U77IdYr98KsgRJ30vHInfKKdSj4csBALzNKjOFmp7dS8mefp3viouy4vWPla8+XZU6ZrRNtD8hB/9FsE7KVTdIBp4xqf6oN1ieTD7PNsQsBQWdDA/rg2bP7IJQkf4Pvn0yoATOFgqhQwadkwT7fwWAfk0YPEE+DPom1V3JwNM6wPaEJeNaMjleqTfAfauLaB9Sc+zJvN5cORrEjSL/0jfJBBdjW5j5BmdUDM1mGuBNVQhGlWHc/Rf7qokMoZAfYiPi/z44rB9zvNfb8t6sVNqHbC2fKRBn/0k8cZ9+qBEIj6vbkqUuih8xNDA+TU+FxPqJxyahqFv+LL9cfZelC0v3D
	mjW5LaBPOdGiiDE1w95Ri9HRK27S2dRZpyib9L4mkfYWPAF41mTudjKmVpgtBLO//rO+zmF04OMB/4sWJhLfvhq1CXULDqw5dcuIAIYwf2ughOtyAPFK1ViDcMO5X1bVpNAFO5m4VBpZvFDQ0j0JfqfVBdL68uH05W1/8dMj76RaWj5m0rLM5slY1FQUPddSU+ic9vaZhlDepjU3ZyI8fmioofNGHaxJq6uNTytKdj87kwDV6PQ4hmuGtY56C7JCgjp053sRJ6sXqgKBWfe4ZOJH17mQm+fws93byLoZvvz4Z3im0Rb0MlFo/WirNyhu+TmTNLpnzFUZfenoKrqAkZLY8u1iCFquhgqA321P+sfYew66DtwQmaoi2GKmF89y2enXXzjLNKfLDKkuVoKxFSPeizYqrLi22R9iO8EGBYKACAWIQQ9K5v9I+L06Hi4yOJ5xrdpFsvehAUCYzuwkQIbAgCBCRB5xrdpFsvehHYgBBkRCAAdFiEESFUlaLYscsf4Dt5gaavCcpI6D/8FAmM7sJEACgkQaavCcpI6D/95UgEAqfSj0QhCrYfazQiLDKJstrz3oIKFjhB6+FYMZqt+K1MA/2ioFtHbypeeWbsqYYRhRyTjAKcvE1NZGtH/YWLgkViUidoBAN6gFX/P+VWB77/w8S/BnPmnJx45wmphlkCL8ckOyopFAQCj9eWamHCl2DSaASMSuoZed6C6Gm0OFtuZh/r8K485BQ==
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.50.3 (3.50.3-1.fc39)
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 28sis1PAt3z0spvv2_0KraAKwsIPmY3z
X-Proofpoint-GUID: QK2CRMBOfryH0TTcKE0juV2MtLDDPGy9
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-14_15,2024-02-14_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 mlxlogscore=999 impostorscore=0 mlxscore=0 phishscore=0 lowpriorityscore=0
 bulkscore=0 clxscore=1015 spamscore=0 adultscore=0 malwarescore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2402140176
X-Original-Sender: bgray@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Wkdq3tcg;       spf=pass (google.com:
 domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=bgray@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE
 dis=NONE) header.from=ibm.com
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

On Wed, 2024-02-14 at 23:18 +0100, Andrey Konovalov wrote:
> On Tue, Feb 13, 2024 at 4:40=E2=80=AFAM Benjamin Gray <bgray@linux.ibm.co=
m>
> wrote:
> >=20
> > release_free_meta() accesses the shadow directly through the path
> >=20
> > =C2=A0 kasan_slab_free
> > =C2=A0=C2=A0=C2=A0 __kasan_slab_free
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_release_object_meta
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 release_free_meta
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_mem_to_sha=
dow
> >=20
> > There are no kasan_arch_is_ready() guards here, allowing an oops
> > when
> > the shadow is not initialized. The oops can be seen on a Power8 KVM
> > guest.
> >=20
> > This patch adds the guard to release_free_meta(), as it's the first
> > level that specifically requires the shadow.
> >=20
> > It is safe to put the guard at the start of this function, before
> > the
> > stack put: only kasan_save_free_info() can initialize the saved
> > stack,
> > which itself is guarded with kasan_arch_is_ready() by its caller
> > poison_slab_object(). If the arch becomes ready before
> > release_free_meta() then we will not observe KASAN_SLAB_FREE_META
> > in the
> > object's shadow, so we will not put an uninitialized stack either.
> >=20
> > Signed-off-by: Benjamin Gray <bgray@linux.ibm.com>
> >=20
> > ---
> >=20
> > I am interested in removing the need for kasan_arch_is_ready()
> > entirely,
> > as it mostly acts like a separate check of kasan_enabled().
>=20
> Dropping kasan_arch_is_ready() calls from KASAN internals and instead
> relying on kasan_enabled() checks in include/linux/kasan.h would be
> great!
>=20
> I filed a bug about this a while ago:
> https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
>=20
> > Currently
> > both are necessary, but I think adding a kasan_enabled() guard to
> > check_region_inline() makes kasan_enabled() a superset of
> > kasan_arch_is_ready().
>=20
> Sounds good to me. I would also go through the list of other exported
> KASAN functions to check whether any of them also need a
> kasan_enabled() check. At least kasan_unpoison_task_stack() seems to
> be one of them.
>=20
> > Allowing an arch to override kasan_enabled() can then let us
> > replace it
> > with a static branch that we enable somewhere in boot (for PowerPC,
> > after we use a bunch of generic code to parse the device tree to
> > determine how we want to configure the MMU). This should generally
> > work
> > OK I think, as HW tags already does this,
>=20
> We can also add something like CONFIG_ARCH_HAS_KASAN_FLAG_ENABLE and
> only use a static branch only on those architectures where it's
> required.

That works too, PowerPC should only need a static branch when
CONFIG_KASAN is enabled.

Loongarch is also a kasan_arch_is_ready() user though, so I'm not sure
if they'd still need it for something?

>=20
> > but I did have to add another
> > patch for an uninitialised data access it introduces.
>=20
> What was this data access? Is this something we need to fix in the
> mainline?

I don't believe so (though I spent a while debugging it before I
realised I had introduced it by changing kasan_enabled() dynamically).

In kasan_cache_create() we unconditionally allocate a metadata buffer,
but the kasan_init_slab_obj() call to initialise it is guarded by
kasan_enabled(). But later parts of the code only check the presence of
the buffer before using it, so bad things happen if kasan_enabled()
later turns on (I was getting some error about invalid lock state).

I think this only applies to generic though, which currently runs with
a static kasan_enabled().

>=20
> > On the other hand, KASAN does more than shadow based sanitisation,
> > so
> > we'd be disabling that in early boot too.
>=20
> I think the things that we need to handle before KASAN is enabled is
> kasan_cache_create() and kasan_metadata_size() (if these can even
> called before KASAN is enabled). Otherwise, KASAN just collects
> metadata, which is useless without shadow memory-based reporting
> anyway.

I think they do get called, it turns out they are part of the 'bug' I
mentioned above.

>=20
> > ---
> > =C2=A0mm/kasan/generic.c | 3 +++
> > =C2=A01 file changed, 3 insertions(+)
> >=20
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index df6627f62402..032bf3e98c24 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -522,6 +522,9 @@ static void release_alloc_meta(struct
> > kasan_alloc_meta *meta)
> >=20
> > =C2=A0static void release_free_meta(const void *object, struct
> > kasan_free_meta *meta)
> > =C2=A0{
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kasan_arch_is_ready())
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return;
> > +
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Check if free meta is val=
id. */
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (*(u8 *)kasan_mem_to_shad=
ow(object) !=3D
> > KASAN_SLAB_FREE_META)
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 return;
> > --
> > 2.43.0
> >=20
>=20
> For the patch itself as a fix:
>=20
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>=20
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/37d83ab1b6c60b8d2a095aeeff3fe8fe68d3e9ce.camel%40linux.ibm.com.
