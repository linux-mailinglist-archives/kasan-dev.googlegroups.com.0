Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBJ6YRGZAMGQEGIAR63A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 463E88C479B
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:38:17 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-6f449ea6804sf5473754b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715629096; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIv5+fg2K5oCykSk4+4oGRRneON6kroQN+n1ix2AHld+Xt1ZaTu5XnFGZSiasbgqYj
         FD75/0THXfzLqKSZzZbQzi8hssfx+TvFNUmYvWcyO411n5A6ubzZSWsR1UjGLSkHNxx7
         7yJHet8BenjTGkM9TPMEVIF1YIx21r+jtfV/AA/GEFrGa8QbZDoLaISq/VugDSjLCDgm
         TES/QcsWe80WDmv92LYsAqS2Ecu4HLCJ0Gg4JRM9/hX+gU/1eHWh4DZfj3/wBin6Xeen
         vApuXdJed0uSWjQp3tcLFuMv+B3DdZuJBps6K5780qYGkJ+exr59efwzdadhgioRpHiK
         yNpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=X/S8lmhsbWZaosahx5nrVfSpvoqIN9PqKKF1FiotkI4=;
        fh=7a9b9g3Jq/mYIprfmAX+JQv2J9S9BLyIK5Z5ZVM7DPk=;
        b=ED7iT1tSJjHv/Mn01GEGkMn3QeaCIqKR7uvatz0yXELTgU3PzlYpMuiUGW9fn0zim7
         7qJvjGuu83SUhuY0FHGAazitmlW/GMFKA0PvPZxweYGqqCJ64btS2Ep3XyceJv5Q3Bg0
         LxLXmfMi/P/WMmqQtvgRyoxbUAsXXnah2WpJJ7yaL91FNj+lQKbM3wW/54yU4+DoOldP
         NiTYZYQrk9grEiBqat7QrHojfzwMAu75RW9w5hn4U8k83+3PgjKQDjgbZIIuQQlk0IOo
         iFuPmiQE503M5vLex/VdHG99KAboIGRC0jeCNs4R3lfOoLeR7BX41a6t9q/7WdgaAQl6
         NZfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=eCS4H08Y;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715629096; x=1716233896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X/S8lmhsbWZaosahx5nrVfSpvoqIN9PqKKF1FiotkI4=;
        b=R6BN3jABb8OYzaPKs78F75klWY1pbDHyZzr3qXziC1zitgIMaVQt5JtZCK/O4pecnJ
         cAlZ44rMFmv97Q8BfWK1ycZvUsS3zspH3GTqzVBykN/GQ6Qz8gQZnIEa7pcTEyr8pXuv
         TKHFhLHmnwhw3sP4fGNvAHN0R7/1JiCEG+jzsfwWaLtElzRWbC+wNm7HDdae79RnY9dC
         XsqgpZ6D5CJutGPE/MtZ7pdJaDJwDSJbIC0nfmjVt5h+FZo5285tGkgglQYtD4pI5tjX
         WTMd+SHFHZQQoEtw89xrM/ZHB0dF54ANoop/VE5+YadaQiKNyHM6V4aLCNXFS6S5mwYN
         dYmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715629096; x=1716233896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X/S8lmhsbWZaosahx5nrVfSpvoqIN9PqKKF1FiotkI4=;
        b=cAjCPoPkxFZuwtd+M+w/1jmWxxoctc95rYhNs8khkAtXfToxhnAMsI9JjmurFFBrd9
         wDS9stdToXE4B0lUu9uZfBU6DAI/DfiANAIWWEVIK/Mudp3adzTWkw3ibudW/b4wak2T
         ls0YzignhbbK7qV9QFwxMnamLQd6lJJSKm35jQUZgsNpeKUyw5aPFGlM8tVeR1eSKuHh
         VW6An66Tbxe7enI4QunXuUqieVO1n9AAMel4C3yuxS4A36+43aKsCxy3dMzW6Nih2SlO
         726NFg5MFg58L0SWX8Vot0v/sc/ucHHb5mqrfZXYFNtfe1gURn3RBL4eLn0KdmfPBUug
         Qzyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWaZRV5fatfTNDAxuafk0By2igVNLq1ONXDkFth8g042scEJj7z0+FS34EpB64vT90DQ2CJS8RzqluVd/+h33O7h9tAwdVpVw==
X-Gm-Message-State: AOJu0YzHAHIxaD+R3FlVohx4TtDEx0nE72sJHRz8fewTik4yclSaPHto
	mxOf+/sy3Sz0aOxyxuU1t3VgPBsX7i2ywGcW1cX/HGPg2Para5RM
X-Google-Smtp-Source: AGHT+IG/kBFqVzo3iPbgdePJEW7zDRQcpNSRh5V9H6dd5Ptf/Kv4MH8mz+9qbZ+be05qV1gaGW46xA==
X-Received: by 2002:a05:6a00:39a0:b0:6f3:8aa5:829f with SMTP id d2e1a72fcca58-6f4e03298c9mr14081403b3a.33.1715629095854;
        Mon, 13 May 2024 12:38:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:6ca6:b0:6f4:7305:2b01 with SMTP id
 d2e1a72fcca58-6f4cb775aa3ls3908232b3a.1.-pod-prod-03-us; Mon, 13 May 2024
 12:38:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4Vltrt226jnZs0nUHYeHrZOdjTEELgVJPG8EEKkJuMuDi1T7TGzZ8p/beAVUX6Hc2XddJmolJzcRSJdOJD9jYuNW8HaYmLknixA==
X-Received: by 2002:a05:6a00:2da8:b0:6ea:b9ef:f482 with SMTP id d2e1a72fcca58-6f4e02f5f00mr14065002b3a.24.1715629094754;
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715629094; cv=none;
        d=google.com; s=arc-20160816;
        b=VBd0DFWuaNu7zhJ60qgCcy2XYyyB8y3SurcZZuLTiZGr/3bQxUnZTSP71BM31GNXX+
         JF837V9iHYn713AIdau7lsip0QdI2+LOk2EUSn+o9a9134lmFeusIyXv1b/o2HcVdbQ8
         AbpMkigSMVJDrUoZJ5C9nTn/nLsrMD2YCrhWxsTIMq5jJP1NqrcsY3DvfgFubCmvlHZg
         dqhddF7G4J6Ac+K7vAmEgeVRsjgSytnYw87UM4OYk9m1ParXjZ0YmckxVjtbkJz9qJ09
         w67rXXQtV1dcTc0g1pobGIpe4bhhOQ1KRAsBRQCPN1KpbZ6V2EfibBdBqCT7Co80N+53
         hNeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=utludO3sqtwnj1dM01Y5bTnUD7G81v38tyL2hzxTiJ8=;
        fh=eDdK40krtWyjNnSFs4h2SepZVdd7qicqp3ugeX6jaYw=;
        b=vkmssJPxa3BnwjXQCnf6l5UraEv/Iw6Rd5DMV9E1yS6mekGxlZfdp3aGLPAaN+DElA
         viRu7SdqUkYoB0NsMd2DdVyq+ag4Ig2HImy7Q17VLreIR7jOwzQvhiTLIUVwLpT/S4eB
         eGog3wN69HiB3+Oo9bmsSu8jc/AQDQhR4QPtNw89tNNjylB7yAgQVX6/o+0aZ7Wc1m0a
         odHeolnLCNMBoJtp+SPnZvSMkLdAJPFnD0HrlIZkgbFL+i/6h7/YdWqokpTeIYXpPbG2
         H6N10bQqqx5sOoO5O83LyyZNIkcAUBYfuYORivErvUMRbO+dEER7DXWVA+Svp2oG1M2i
         mjBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=eCS4H08Y;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-6f4d2a72e6dsi683708b3a.1.2024.05.13.12.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279872.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44DJ8Xqc024006;
	Mon, 13 May 2024 19:38:07 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3y2125cdm9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:07 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44DJc3NL004093
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:06 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Mon, 13 May
 2024 12:38:03 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Date: Mon, 13 May 2024 12:37:40 -0700
Subject: [PATCH 3/4] mm/kfence: add MODULE_DESCRIPTION()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20240513-mm-md-v1-3-8c20e7d26842@quicinc.com>
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
X-Proofpoint-GUID: eQDbYw0N_xlwn63HOf1HuOWH_llEaQYu
X-Proofpoint-ORIG-GUID: eQDbYw0N_xlwn63HOf1HuOWH_llEaQYu
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.11.176.26
 definitions=2024-05-13_14,2024-05-10_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 spamscore=0
 lowpriorityscore=0 mlxlogscore=877 clxscore=1015 bulkscore=0
 priorityscore=1501 impostorscore=0 phishscore=0 adultscore=0
 suspectscore=0 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405010000 definitions=main-2405130131
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=eCS4H08Y;       spf=pass
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

WARNING: modpost: missing MODULE_DESCRIPTION() in mm/kfence/kfence_test.o

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
 mm/kfence/kfence_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 95b2b84c296d..00fd17285285 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -852,3 +852,4 @@ kunit_test_suites(&kfence_test_suite);
 
 MODULE_LICENSE("GPL v2");
 MODULE_AUTHOR("Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>");
+MODULE_DESCRIPTION("kfence unit test suite");

-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240513-mm-md-v1-3-8c20e7d26842%40quicinc.com.
