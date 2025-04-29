Return-Path: <kasan-dev+bncBCVZXJXP4MDBBD7TYPAAMGQEUISJQLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id C917DAA1142
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 18:08:49 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-30828f9af10sf9663147a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 09:08:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745942928; cv=pass;
        d=google.com; s=arc-20240605;
        b=HqTVOvY4tvthz63I7hJPLCn6bBpIFVsjuolbP9HCmzPaQp/5+XkbzlI7Zv+zrRwCuA
         vMAHF2o6UcZxfaqW522GfhGV7tb6IOvFXBVjZ0hBYkbCfnF2s0tI/y/mZcknBqtj0A2M
         +3e7J7yxWR/Zxa9tmtpQusPSVbaOlYQTYVBmo8/Gsz0yUFJ8Hx2YABXkXdBvvBAQOssG
         Jp+f3LZ3Y3b8XGsbihic85pYdk/EGjc95mjxVaEAbXVEjYu1nxRDZqdyI5SJZOpgxU+O
         rums8nOptnctdfSum8SKem75V7bTYPwkWF4e9aW/76VfYDYsNRdWirjsdARcAnla0L1D
         f+JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sYUI7dXQCoijqzDv4nCFbGQvx6xCxzSmDSBoHo1B958=;
        fh=C4VGVzhQ4MhB5h2OFZQZYthJdnSshPVXWYq5aKc5ilQ=;
        b=bJttHVX8CrRUuj919UWlA5/I7YKXq9UlwszKlfoXzIh024kSe0/5dNslyub9NcZjVx
         eJ4K/OZ8cv9er6QqCktKN+M5tg2HElU+HBCi2tJrv2x+kFQAlYB34t6WpHxWVG2kknPH
         6X5JoLESzqM4er/d+KoiJBIeO8dJBQ8gk7Qy9bTtdkC6angcMoTEpuQo8hbdaGyqIfJQ
         75BYS6rnlw6ML+omTFQJRg+6m92alg37e35dhJjfTNOMTX4ZKSSeFzO7cEZdUB4B2yDd
         WFc/2b2ot7bSZn3xU/ZTZ9JL4ybVARdZcyUwxWqLKZ0ElUsjjaPXaXQYQN6glyIy+fte
         e9xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gbNW+wZh;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745942928; x=1746547728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sYUI7dXQCoijqzDv4nCFbGQvx6xCxzSmDSBoHo1B958=;
        b=TptsViBqUB4gud9+MXMfDH8ROyrS33jTxxXFjFx+I6MZ402nk3ADIFNlq2T4b/ELF1
         jU9LFqExaAVJ6qU8aev9BH+CGGDls/XzoH4fCAmVfMivqYbf6WIJRbH9vpL0kBKAjeMe
         tHd2szGQ1p3/s/1MMwdqK2zDnCqsSjzrvZO7VR3Hugv0x0o5KUj7l9QAHkBCPobegoyH
         IZzgHF4O+xFAcjYfJ0hzGqtqdOi1QkmXhFVAstvXHSksnO6dG3iS7Tod2SxZ434IzOpc
         NeScxYIDnMBQcYnlsCe+AqyT8q/BCMCH2UCHMyn4E+6eoWtLwd+YhdEjH87R/UQFv+zj
         I0kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745942928; x=1746547728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sYUI7dXQCoijqzDv4nCFbGQvx6xCxzSmDSBoHo1B958=;
        b=VUMJdWy97tff7qsU9sEp5NCf4DRbPXOX2FGgPwWxjldUepF4ZT/+bxdEEpetr68PNC
         2KIiTLJOo0y4pCsQoTJ3X8jiDAyEAmR8Z36Xnlp0/rytuJWO0ur2q9zg6jCC5jhGCTqZ
         6Ir2nrsLMAxYugC0MyhhSlZfCQwb6Ny6PVj4vSpSrhfWV6dN6EipdyZFfza+zuIHxofh
         NjfNIFP2FwVh2Jf30Iw0+4pQcNMAtEcDB8/8AiuRtawkVSYkbj1yKPiINLKx0zn3TDYO
         ydWsN3F2yhu7xVs6XnKOzb/cGP9nlGiBo95BtK9BHc9xTsYsteRdzDqEmDVLbC/I3fST
         KaJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeb+iLATELu2Cpi+lSbXu3NFTlzxg2YrMUAJI3QDCybjCzJ/oBd+Wqwp/iMJHizSofG5zS9w==@lfdr.de
X-Gm-Message-State: AOJu0YzeDSgILWXECnGq2sO8GKfIRlxUPfn6jkqsA1dAYlF9LgVmNofN
	X/eA7fWOEiwfGWBETOtn3XHRo7maxKY8m8euDtxpHHb5bP2qw537
X-Google-Smtp-Source: AGHT+IECG25qpl/gASG2COpLCfZlTTC5ZIh1xayEVC54SsYwK7gnn3P2n6imwCS1lp7ZWfsA5QPBew==
X-Received: by 2002:a17:90b:4e87:b0:2ee:9b2c:3253 with SMTP id 98e67ed59e1d1-30a013d9433mr17070076a91.30.1745942928047;
        Tue, 29 Apr 2025 09:08:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGxePkkFcdkK/9hyuU8dylq2JmsjQK0zCuqc/kDh0JUdg==
Received: by 2002:a17:90a:de0e:b0:301:9a05:8467 with SMTP id
 98e67ed59e1d1-309ebceb7dbls2798905a91.0.-pod-prod-06-us; Tue, 29 Apr 2025
 09:08:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo/8s9+8AvM9r97+R1ARCQpftBKouD2x5elWSfS9zqQxMbYWtqXzxajBHs4xDloFjdTELMTcPCBx4=@googlegroups.com
X-Received: by 2002:a17:903:1a67:b0:220:bd61:a337 with SMTP id d9443c01a7336-22dc6a0f297mr206034955ad.23.1745942926522;
        Tue, 29 Apr 2025 09:08:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745942926; cv=none;
        d=google.com; s=arc-20240605;
        b=I2WEbXFEPZvUETnEAeNans8Vc4e5hUsOWoPhqk7QgHMSgDTKqDokrHMPRwyrFvH97K
         N8XXfNbd0L0PrYD4rFYYc7pzpADobWgMoa3sYxDJSirs3GHZytpRugcOMTqee7oE0oqr
         HIE5Am6d+Rq8cDxpP1kVeiCkbiQSqAiEuMcM/vtF45MWF/nNlL3PWH/9JmoQ6fLnDkeb
         hihEwBJMVOVSPx1CxwirAvs0Lb9TKpKFanP3dKZlTlxk6inriMBPZBaHKgNk89032uOh
         DZfjxC+vOLASiW5J83oEtv30lu6qpU0Jxy9fvtvYN37z2OEI2PhYqfEMxpesVYkSuk8n
         KimQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=vNOzSBSOSEnG/goQiLTZesHUpOBG2VowETXI+5leBH0=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=aCIAt6giisg5zgBpGH8JYacZWZnCBZiWXBx++dCTvvs22Dx+ieDkth9GF6uTJfWZCr
         HrZuMHsKM9kCD4/QB0v0H7mnvLDxLnzyD2ji1L+seCZnJRRyqcHkTZutV/eCHdvJzkHN
         Ns+dyr8dVlYE2tmnpWp0QInEsk4FnU0m7jjilVXMXmmsqbE7lpOAG6Q0VPP4GfsYVmvn
         1JJEbkDHFL7WpetojEpRdrnNyQVE8/BTI0XjQbesR+SSFNDqxmJEeMmy7hAbXUMkvn9y
         fsJSEhVygHzwMnRxVpnlnczAoTUUsNYqXIhZkmXfafzEmCrPvEBhHw9457ldg7GlwMdq
         6kbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gbNW+wZh;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22db4f12ba9si908455ad.5.2025.04.29.09.08.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Apr 2025 09:08:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53TAf99I009668;
	Tue, 29 Apr 2025 16:08:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46aw7t1hxj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Apr 2025 16:08:44 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 53TG8iis007753;
	Tue, 29 Apr 2025 16:08:44 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46aw7t1hxg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Apr 2025 16:08:44 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 53TDXUel000717;
	Tue, 29 Apr 2025 16:08:43 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 469atpc0jw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Apr 2025 16:08:43 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 53TG8f9o52625900
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 29 Apr 2025 16:08:41 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A9DBD20049;
	Tue, 29 Apr 2025 16:08:41 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 96B1220040;
	Tue, 29 Apr 2025 16:08:41 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 29 Apr 2025 16:08:41 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 4D4F5E05FF; Tue, 29 Apr 2025 18:08:41 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v3 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Tue, 29 Apr 2025 18:08:40 +0200
Message-ID: <cover.1745940843.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNDI5MDEyMCBTYWx0ZWRfX6b2AMYNSl2Qj whmcHnWA2LOtwMkhM1ZGagtfNeXgKHA3/XAeqegiBht+FHwH9U5rcd0CBy9wu/VDJ4XNgUMbXn+ fDKVBUOzUH+zbhfkybKBO0eol93PXaax7ZLZJAt14imrORL8cZtVLtQZlP4S4hn3hV/WuoMVNG3
 WWn+aJGKlnIvDuF1S01X+DeQFUh6jFA9QKRkDg7fSNrL2ZRq8H3yBSjFt47vfzMHM5nJjKo291h 4I69VCZa2kvA6qcxLa0Le/BO8HqKmhE5SCu7EEWJp/PREUuJB/raZ39oPHGH8a3PSgvGPrODOTz 86kQGvbOYiRqLxTf/lE5fQgr1DCB6XXgwExiby59qF2j48O6rfECHjs3cYD+lRGXZZZET0LTJAB
 8L4rhs3KMR7kv7Lb6REj4WHWsooNw3V++PaSNpjmcHpWDBgRYuoNF9E2eu2SwBLJHcgDa0hM
X-Proofpoint-GUID: NsphRUiY2q1Gr5aRWLKjtKe-3YuLzCiX
X-Authority-Analysis: v=2.4 cv=MJRgmNZl c=1 sm=1 tr=0 ts=6810f98c cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=XR8D0OoHHMoA:10 a=Jfx5KTgcOMEgCse_l18A:9 a=zZCYzV9kfG8A:10
X-Proofpoint-ORIG-GUID: aTUTgI_UqpX2h7jR88zO9b2BtzhZz50p
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-04-29_06,2025-04-24_02,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1011
 suspectscore=0 priorityscore=1501 phishscore=0 adultscore=0
 lowpriorityscore=0 impostorscore=0 malwarescore=0 mlxlogscore=539
 mlxscore=0 bulkscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2504290120
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=gbNW+wZh;       spf=pass (google.com:
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

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 65 +++++++++++++++++++++++++++++++++++------------
 1 file changed, 49 insertions(+), 16 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1745940843.git.agordeev%40linux.ibm.com.
