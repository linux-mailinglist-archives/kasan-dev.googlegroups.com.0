Return-Path: <kasan-dev+bncBCVZXJXP4MDBBP4KRDAQMGQEY73KWGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A403AB3A89
	for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 16:27:13 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3da779063a3sf49554495ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 07:27:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747060032; cv=pass;
        d=google.com; s=arc-20240605;
        b=jc/rVJDInPk6mCtnBZ/MjC83kYo+PGIVjFNqC0A41s6jhuO7X2pJf66igL2MSUVSAQ
         dEpNiCxwXDNuL/j9sbdkCCeaPk3jjUAYFwEp77IujR/Qe0bRG7wRQLAm+/QzR1+zAnyc
         Ub14zC8WDVyyaMWKPjVR+HKfjbfougF4WRnZ/Sz07tei0tDP21h9GKaQhRPAsZy9n+5S
         GCA/N2abZLpKSlBnYia9layPojkicBuTWI/PV3BHbEQciubJoXkfyKUZrP++QI1NO7rQ
         bl1w9elCVf7PSsNUTIU4Z5am2zoglg+uzKmEFj0dtCfAZC0tMJAZc3XZWvStfV9aTXeG
         CefA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zGAZotNwURodWTFxVOx4SKjLdyANLgLVj0TJ+Cqk9MU=;
        fh=VR7mLJdhNmhl3qDswvT2zRU0CTEC277f2mxTDU0UuJA=;
        b=VoklrvILxxhnxIzCZqpn7edWVjk50VPfbiMEVqi4viN86y6iYIKy1JrRhI+pMmkLfE
         sJ/nq280SstASjMUqMHfW8b/t60wRX6xE5znv+hr0uKd4f+CDGDgJJbx5Kp/mSbwHOWx
         bmH94dTVLSa02C8Mh8rNb/G2D4Aviq/SBY2DytCH3LDyfhY3Z4UAQ7dA+JOo8tDkODWx
         UpQbAAQIGtQfugOS/pbMDkCrLmTaOQKodB8gXv5gt/V7nmiWLPHPNkgO7Jj9ndWS01Vr
         yt86IdR0dvPMMtPKxF8aHZn29aXx5Tjg4t6cj5eHzoSIudwS9a0aqZ2DoOKmDkDPUlEM
         4w7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oT1uURl3;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747060032; x=1747664832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zGAZotNwURodWTFxVOx4SKjLdyANLgLVj0TJ+Cqk9MU=;
        b=ZPkin2baWSQHhKCAOsGrBE5yqx6cVBAqXFlQmGrBy+T+UocRg6Ys3Ld0w9mQHdISsf
         qGI67cHR1HT/VuZ1YjTqMjZVzi5BL5psVzFAylUsr9t9GgnK3FJUrM2ZK9jdpfAEKemv
         1FZWv7CHoSX7PsBJWkBAHRJuHGVGSfUq6qEJ8DVhTk+zTn+lArVW0UNRuoUf3c8NUFlC
         fTAKzVGbGnp83yxRW38Nlp0GNt29fcjGOslaaflofwzuhUfrJV4N5W3IhbAL9c2jViTn
         p6Ezb6enTlkmCb6Fxjgele8dmMRb64yn5iyWFtoNQhHyepF6bbKQtnzAdzG+FR1eEVPx
         8tJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747060032; x=1747664832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zGAZotNwURodWTFxVOx4SKjLdyANLgLVj0TJ+Cqk9MU=;
        b=fO5FyHu4N1UDFzutPwoUEZdoJmSS0IpyQRKtqU/EHbcF2P/I92fRbid0Sa+AMso5zh
         IWHpdpESwZrS5OQfFml8Nl0L2xHtwCRCKdszjOjM6qutUM+gx396XQK+4+hk10TgO6qT
         eks10/1Sw9a67QgWK5RK8tAYkP/CkqkmnzqVLIIXL6NVa0RPmvOex0okIYFFtSgfYImp
         2Kq/CMGxtKZccsMZgPBbsnBChH4ZJvmlLzVNdJPGsHq4lXSwX6896lW5njBMwHwJyAdO
         ejUIwx1NfHujwqxaxLwuneC6Mw05sYYYDuar+BHarhGpbTsTJOm46lIUdB5vuhJTorLS
         B82g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4UT2Yv/lwlHPUXmzL24sFey8Ulp8Tg7pegq5I99xxVot57bVsYhL+7ojo4mstLCpsaTbj/A==@lfdr.de
X-Gm-Message-State: AOJu0YwiAce+F0jY6RJ0wN8nw3f+OG1blstD+vCc2usi3n+gY5LYis1y
	ixjZkxYypCGZoBSl0e0nLi2yC6Fk/TLvnLwgWGQTvYGQeb2EmJJm
X-Google-Smtp-Source: AGHT+IGxp1ExgH3nfxlnFx0fnSoY62EmP5PibZa3v+ciHRC/3q0yPbvlQcfCEVP53ou5ECFpWxVGpg==
X-Received: by 2002:a05:6e02:1fc6:b0:3da:7161:23ec with SMTP id e9e14a558f8ab-3da7e1e1a63mr154737665ab.3.1747060031671;
        Mon, 12 May 2025 07:27:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHKIlaMdo0QBLIdolgKG7iALy4gcpnwCfLpNNephLhAhQ==
Received: by 2002:a92:3642:0:b0:3da:7167:d2a4 with SMTP id e9e14a558f8ab-3da78546e0bls2681005ab.1.-pod-prod-03-us;
 Mon, 12 May 2025 07:27:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMIVGcEQHaIArQg9dBH3rGoK2tFyV1oDem3K6M8NlGzsA9OScPyvx1l2PJrpnLashNWsaFifgEFPY=@googlegroups.com
X-Received: by 2002:a05:6602:15cc:b0:85b:3f8e:f186 with SMTP id ca18e2360f4ac-8676357736cmr1641813739f.6.1747060030765;
        Mon, 12 May 2025 07:27:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747060030; cv=none;
        d=google.com; s=arc-20240605;
        b=Mk3OaX4Izn03COBr/dDXgjgDQUzW/4H+A51B8euuyj/tKLI1pPnrJqi1BakAy6tScd
         aiSgsRkYjqT8s8jX9SD9EBewPbf4S5gxcyMgOcagdw7Or6qb6ePcFaSw6P0PkUNVPCvN
         FZ+mAGGIeq8piT9I1BdrcraCvisVo8SO4zH2FicSXuO6I2MZxiblK4ZSAiV2Mbw12M3F
         irJbd3v7Gzh2g4qK7ZdSILkduyi+ibEZoyLel647xaVSSsOTCujPO8LFqxGR4cL97Re3
         qmqVPXEkI4aAUoQWnK8dGiJv5P07VsEGEqpiJr7kffDNS63dT4Vx+tlEZEZWEYBDmiN4
         CuBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=H0Tkx7+SzjOipSHRz7BPdyfgQj+BfPBXjD5Rb6Pz8m0=;
        fh=JeYjkRDw/VSjlVIISM+t2OTgWgKSm5f4n50024gbhWA=;
        b=lKgYCLVsOtvm6mgnnNr8OJRxjEhcBwSJjH0wFuEdslQOk6GBoUeNcY5bNwmH5cQZXA
         QH8sRk7BKcZwsFCobjnqPDBs/YU+Jy2CbPAyJLf3tz1Lak+wYjaubGFZvQ8yTxjpDTQ+
         pNF2kYaHXGStPc3NypjOhaZIEa1XAHHEYMEYaCJIWSWPlEhTOr6/0vdiIbOquyAq6/Cj
         6kz1lRI4YE2z/rCTkMe2/nCSXrGsIBw4lCfNxqkAK9TQqWAji0Q2TA4oYhKVPAYdBxOm
         ocsLFUkt3UlKYEUxN00FdbWIq+u4beHqAXpWo7zgPotpOK1s/jq162Xhpw1fZiw9f133
         lhYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oT1uURl3;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-867635f9ec6si16299639f.1.2025.05.12.07.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 May 2025 07:27:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54CDnTtO001587;
	Mon, 12 May 2025 14:27:09 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46kj7586ts-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:27:09 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54CEKfRR009975;
	Mon, 12 May 2025 14:27:09 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46kj7586tn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:27:09 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54CCLZN2016348;
	Mon, 12 May 2025 14:27:08 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 46jh4tej1b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:27:08 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54CER6lD56558036
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 12 May 2025 14:27:06 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AC25D200BD;
	Mon, 12 May 2025 14:27:06 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 99755200BC;
	Mon, 12 May 2025 14:27:06 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 12 May 2025 14:27:06 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 535AFE0315; Mon, 12 May 2025 16:27:06 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v7 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Mon, 12 May 2025 16:27:05 +0200
Message-ID: <cover.1747059374.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEyMDE0NyBTYWx0ZWRfX4J+iA0krVspB fQXC+GPt+teDfwRbINmzxCYUQOg8HemzNXsTeqjzpOjeOYBI0CnzDijCkjgXOZXdWNhRCgRDnaC +qE1EMDLjSgRkh2PH6GM7/G6SHwdBpu7Ayg1OtUxE10edQ+JDp2UvFh0v45pDUxwMepS4IFwUBG
 uZZpDAU5FpnryRkLfg/Gu+P8WMobEifo8tJWz1nH5jTJqwhruQvOtcILjNad4G053qFfNU7uk01 lHlw7uTQp6IlWDDC6OxheOpA8lS1ssT34q07RwafLp7DxKanPq/ZtLc/hJTchc1WtX5W97W0Pri Fy+MOPMwArVWO6gKRFHx5ROhIjszTPU77LRmv/xx9d5Yfla2BiX4Qm0BosBgIEUvadFAvl5par0
 5AAzwoHXreVc2ZNMcAZ2PXsQm7fDD0+dega9J0HPPKQwuTdp1dQ34D1yNnIJtV9/OFcM7GhK
X-Authority-Analysis: v=2.4 cv=J4mq7BnS c=1 sm=1 tr=0 ts=6822053d cx=c_pps a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17 a=dt9VzEwgFbYA:10 a=gOThRBi6ftkcs8ZoH28A:9 a=zZCYzV9kfG8A:10
X-Proofpoint-ORIG-GUID: qnJ4pF3Y3jPbDL6Rvh_FxR_LAFkxUmHH
X-Proofpoint-GUID: vE3qFts5VaV5FnJpIAEOEtiXGRMzf5Ec
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-12_04,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 adultscore=0
 lowpriorityscore=0 bulkscore=0 mlxlogscore=680 priorityscore=1501
 mlxscore=0 impostorscore=0 malwarescore=0 phishscore=0 clxscore=1015
 spamscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505120147
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oT1uURl3;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

Hi All,

Chages since v6:
- do not unnecessary free pages across iterations

Chages since v5:
- full error message included into commit description

Chages since v4:
- unused pages leak is avoided

Chages since v3:
- pfn_to_virt() changed to page_to_virt() due to compile error

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 76 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 62 insertions(+), 14 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1747059374.git.agordeev%40linux.ibm.com.
