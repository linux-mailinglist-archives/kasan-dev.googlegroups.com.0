Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBJ6YRGZAMGQEGIAR63A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 59A668C479C
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:38:17 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-61e2b365c9fsf4375294a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715629096; cv=pass;
        d=google.com; s=arc-20160816;
        b=nJBBbWqiidzBtWGV9ClPdcgflvtr5igln7qX5TdNG48lOsXZd2oJkaHFsgRFn1ZJVL
         WKHe4o6UV+sNDtXRrhJhIKT8DitJmWrAaOkW7KMWOS6l6+Y/1wpdwrK8hdULZPBVX2u0
         YfFf9FohMs5MiGxoGeu1+mKoYDnH9bcq/g0Rvi7sb4WbL/JNUs+Nr84c98Pt1HJ+pfzs
         +CVX1VMKD+2k23tZVxejCv+O2CJlAlSGKZnOPaMZrXqYrBlkSBCkKq+s3gxm2D0tPXJ1
         kABHxDPwfFxFTJb0YPOawf7vrlYYz0VHfKjMKrRzUU+aOG3G9e1t/KVert0tfHe+dUgd
         fAbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=lgt/+gTWIsP40s67o8KSInblYdE4hkKWENKpFZ2mU1E=;
        fh=b+RPK2k9saC21tm8cMwBeGPs7jMbjE/G/7VjEv5gs+w=;
        b=TMM1L4XGBNi3ZJJucVK7T8sqh3Tx7tTHDhU1wpbMl56WSdjm9uE/m1T2jGYgKst0Mx
         yo8Y5P+1gB2HXmuoFTyWm0hgk7uQT4d3pl+wYSd9NytH5l3JdjL8fehwQ34K+DSOeMOu
         qWhdRMjtACE+YwWajxjsmFhRbMcZdMEzWJA18TPHYM0lGv6Tjru9Qt6QaHBLKJtXVaK0
         kUiq+SrQOkbG9nDENcIksYYeEBrRUfRHZpKZ2NmecTCXGTzhIMaZIVvWE+FlVj7smz7d
         r5hL1jmOWOLDTDoOMsAf0owIlTc4DxigJD+Xvzyp9rcuPSHqUjG/75QhWF0ipGooxG89
         yc0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=iQaHNjsf;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715629096; x=1716233896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lgt/+gTWIsP40s67o8KSInblYdE4hkKWENKpFZ2mU1E=;
        b=I/WHtQE3Z1t5XWcDa+Y3kLZVYk9o08OghD9+fGmTypd1IH2FTpnv4XqzsUCzSIzU73
         FquQ2PlnlOAxWtoAUtVJOtyVRM7Wcy5po+Tn0dRNDCQbSkHeR1ohphxtDIYhqVfnTKH7
         5B6rw+86ZrdXWo1ydB6qIdbaA6wo6xCQC7dRANgVa9Hy8/0h7pMbNi+9srpnZPIOmeF6
         S5RtB+HTaaMLd5X1OE8A7TgiNmrDhubXSQ32DS4MgeQ5dyDq1TGXTDIySqpksrPb+4/Y
         MaZ1CsPXIFtUR/VITTmW6/DkFh+ZKUBfcG6yyIIPGqJtvlZ7AlnivD+13V+SuI1NQ6me
         cF+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715629096; x=1716233896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lgt/+gTWIsP40s67o8KSInblYdE4hkKWENKpFZ2mU1E=;
        b=L8biux6dRwzn8GejUFrl+zTCbH4Yc4kVILkLdr/ih6YE408M2/lzJ+gjqnWkYyp5Yd
         84f2iMuC6U3Avv7raaPyt4/KWaE0L2Uy+2xNmhjoMnoYYWYwIYoG2SYnNFESl91ErvLs
         IbLKhhCtcCnGmZkeaMRthgmNoXr2fRLTzoXUPcq8kw/ChYvN5hZpejH+20LUgk0XLfQe
         6OPxn8XPlEGKVsfP6W4nz5k3cERWHcankTTnVOYz4HACjsAPPIkfFnCfSGVcortJKZau
         kUVv3qaiH+2Qkim/UlNaUzAvHa1kXniXoby+kpEIxyc3q78Homv71clBtzEg4IRDJVWc
         RXog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmhy+r2pkMkdogpH2o2hp261nFrhJzC93NahnpDLMw0TS9DYIFwFnc6jxhYDUfVfpbdpu3a61H8EDbswG4hWo/5XhR+DqRbw==
X-Gm-Message-State: AOJu0YxxzU9BzUiDL5fIWLWe/93qXrvQ9e1gCoe9TURqRQi29r6cBzNg
	O+RlSO+15+AsDKOqv4xRaYMSDEXRkEizm1f4/ERtfXM6r4OBbmdC
X-Google-Smtp-Source: AGHT+IH/xJCvL7wnqzqaN4cGHsLx2CjDPj0Z9TtXMf++vzD3JTeNnR/bLP3pZXllNMIOBWKUZFOOdw==
X-Received: by 2002:a17:902:7893:b0:1e2:9ddc:f72d with SMTP id d9443c01a7336-1ef43d2af36mr103084605ad.26.1715629095759;
        Mon, 13 May 2024 12:38:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22cd:b0:1e5:5569:7322 with SMTP id
 d9443c01a7336-1eefe781978ls30695985ad.1.-pod-prod-02-us; Mon, 13 May 2024
 12:38:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvRyVyGwpspoXX6V7qJrT9iOWESWPS0XUEI/ZEQfyqTQIW645pFv9DfqofGBqia8tfYiOPiN06PIeO3HFxoG/QUBxmUCf6oIkTsQ==
X-Received: by 2002:a17:90a:b289:b0:2ad:5195:1eb5 with SMTP id 98e67ed59e1d1-2b6cd0e798emr9088918a91.40.1715629094695;
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715629094; cv=none;
        d=google.com; s=arc-20160816;
        b=Zn3OH7p3O/MZjL2+jsNltv3Z/hwUg9eX9FemBxH9iA5cynXj+T57u33FipdDKSNd/h
         L+NgNQCN9zjRT8xXJxXuh5rLBI1UZtXoCt9bTEWj/IaYz7XcTtJJHnMaKqMKVLgFC5bG
         PMHLAuDchXVTtSp80P7w1rPd2LEgxRpdZI9df0Qke4OsLUIQ7u0qq7NOUaMimuZ9yD3p
         ihAF8udltfqeR7AJ7/eNUMo6R1c+exuoq5MX9QB/oBVzHbWBjnlYdYcnZOPbTsxwkoFh
         NrVhxPo831qZL0vqwtTO3yk3sy2lxsmGB9fHgxH7Oi+bQs0OmirDlOX2AlerMFxhA6CY
         gpnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=SZpIbLKZivcC1Yccbd547Zg73kvUS6pwvyQbOpZa/84=;
        fh=eDdK40krtWyjNnSFs4h2SepZVdd7qicqp3ugeX6jaYw=;
        b=fgKuLUwY4ZN7/wcDH2J6H8OYYkQeWvqoB/9gXbAHZadDaFJcXwgKyEqYFZQtw8ZfT8
         3emBzNpXpVtHHoOWJr1mcCEZ5C6jN8fyWt5Ex7RT/HrR+OoVgUO2yy2UJ0YZNgMdIqdT
         9jwFERqVrRYPmhpECHGZE7g8SgKqfJQbUW9QSWWsH9nbB2arB13h8FdQ1g6+KZEofMIQ
         f0aqMuwDAt86jKJVnltqevbOflaSThgCYFbKoyBfO66hxUUzQy2P0cpjJxDBBDToNlKk
         gX4kRKATVSUEi/ou3Iygd9P5TgtYXzjbGdQ/6oLr+zJiKKBMkaKx3Gr8qgyPLvHEQwyd
         qNnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=iQaHNjsf;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2b5e01c2c85si1038444a91.1.2024.05.13.12.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44DJ8UrW003261;
	Mon, 13 May 2024 19:38:08 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3y3j28h14y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:07 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44DJc3NM004093
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:06 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Mon, 13 May
 2024 12:38:03 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Date: Mon, 13 May 2024 12:37:41 -0700
Subject: [PATCH 4/4] mm/zsmalloc: add MODULE_DESCRIPTION()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20240513-mm-md-v1-4-8c20e7d26842@quicinc.com>
References: <20240513-mm-md-v1-0-8c20e7d26842@quicinc.com>
In-Reply-To: <20240513-mm-md-v1-0-8c20e7d26842@quicinc.com>
To: Miaohe Lin <linmiaohe@huawei.com>,
        Naoya Horiguchi
	<nao.horiguchi@gmail.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Minchan Kim <minchan@kernel.org>,
        "Sergey
 Senozhatsky" <senozhatsky@chromium.org>
CC: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, Jeff Johnson <quic_jjohnson@quicinc.com>
X-Mailer: b4 0.13.0
X-Originating-IP: [10.49.16.6]
X-ClientProxiedBy: nalasex01b.na.qualcomm.com (10.47.209.197) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: -HIQdNi-5IXsB_Rfj1gPSehmxSuJD8gX
X-Proofpoint-GUID: -HIQdNi-5IXsB_Rfj1gPSehmxSuJD8gX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.11.176.26
 definitions=2024-05-13_14,2024-05-10_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 spamscore=0
 impostorscore=0 malwarescore=0 phishscore=0 bulkscore=0 suspectscore=0
 mlxscore=0 clxscore=1015 priorityscore=1501 mlxlogscore=801
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405010000 definitions=main-2405130131
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=iQaHNjsf;       spf=pass
 (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

Fix the 'make W=1' warning:

WARNING: modpost: missing MODULE_DESCRIPTION() in mm/zsmalloc.o

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
 mm/zsmalloc.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/zsmalloc.c b/mm/zsmalloc.c
index 7d7cb3eaabe0..29b74f706509 100644
--- a/mm/zsmalloc.c
+++ b/mm/zsmalloc.c
@@ -2276,3 +2276,4 @@ module_exit(zs_exit);
 
 MODULE_LICENSE("Dual BSD/GPL");
 MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
+MODULE_DESCRIPTION("zsmalloc memory allocator");

-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240513-mm-md-v1-4-8c20e7d26842%40quicinc.com.
