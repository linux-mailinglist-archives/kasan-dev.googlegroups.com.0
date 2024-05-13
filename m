Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBJGYRGZAMGQECXVG2GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 520C48C4798
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:38:14 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-620a2321b0fsf74139447b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:38:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715629093; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cm2nvHGV+a1z051FeszNdOoWIyQ2znfI5Mz2cvQmumVD/up2R4r/A18NQLVYP+2u0P
         HNw3IMzHMr87Jq4fssBaRfzPb9vmaLaQqcRI72n3LUAYr5y4iilubHUHeCGL6/n9tnf6
         yl944fzzDK/ZJV69CaduDBoYBeBJpJ6PJFx0OKee2JHUL+L6QThLgX2RSJbEgoN+biH+
         923uR78L+nuPdmrToSFpuOnzeQbE1U0Ja93SzfGfSAzlLWy/RD0N2t7XwdUhQ9tAwArh
         Iluz2fCD/Scx3pjtGktzBBTYzleN574obrxbsDuCYdlL8X+r1bKx1w5Sf7BmJDdgKQPL
         KU1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=Ek9B9z1yvoO8KCbJmMcJrONMcbKuG1jM6vV2v+MtUtE=;
        fh=MJv+rKLBaDwTynJagCchLRBnAdvrN7kZ5EkO1uHigzo=;
        b=j6Hds2o4biC8hyJiW541MPHBlr2DE2f/N1x7jTEPa0/wD9yWbWc0EXjuxpawhQcYnh
         JxrQrBY8x5BjbpVGW+ZCQ+O3FfwloVf9cat9A0P8xX4YbGpBbc5Tb5+M5y0s3KMuG2mM
         dwT4qTsGSMyWuZ9kygWmfd3yNb4sxehAnN3jmLKaO6jtAQtiOmy+AwBGaTRsi7GTZxXE
         wlTZhBIbaPyYUN7L90qdUFrthXva/vU2veDk9Mgw5J4tvtOWV3VQIvzSW2IVVzxRKJi+
         43xFTryTrat2gHFNOOMhlZZzfQfDv4YOD18nPjBVSqYfPRJSEALkeNmdo3F7KF5hrgUr
         HGVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=kezNOi9u;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715629093; x=1716233893; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ek9B9z1yvoO8KCbJmMcJrONMcbKuG1jM6vV2v+MtUtE=;
        b=W7RoUa3kkBh3zpImOdmK5LByb4mc2klD7Ss0KKqFI8olk44dRrxBFiE+hkQmw6+Xfh
         XaMTNRSJJCMpypv7Npr7qgy8UNvJw5f3h4xkAKl2QFJai4jcIlgcc/Yi++dlbn/oDmKz
         +ySAvqY7A29ZeyJKGgn8r5DJnDK7qq46PP3MUzEio2vC1ELa7u9kxD6x1yXOO3L/wTzj
         07In/Dg9jnzTwOYCvaytf8lrxdjHUtpXXior8MewOd+LKyKyHbopXTVdgg10pFifeH2B
         qX4oBGzr2s1374ozCPxP/PpJJ48JJL7Wri/npI+juAyZfj33dWsbuyf5EnqHffS9cisf
         7yQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715629093; x=1716233893;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ek9B9z1yvoO8KCbJmMcJrONMcbKuG1jM6vV2v+MtUtE=;
        b=e2UYpgQJGKiqk9jFfOZsxpYcr4ZDnIA7tQTbhNdyIGGKKz/F1W9jSN2ej6pESvfIay
         BWirUxycL1iEb8iz2BArbPfnUltk3gybLsDqd2nOao2/ZyEJCpOEFBPLBR/mEkn/QmWy
         paqwOybD9qb8H1NyBPlgKT0Fm8Yx3YfwCjM6OddYwYDBxSI+jfmr06Du1/q2Ehk3BiSR
         pQpREQJn9vbrKlYUvLNSxMB9SV0FDj8rP0ATMMTzIgZxBYTM18NzDRSvqtnRuQ2kQTLh
         /plqHz+kM5Ba69UZk5DSieerSEMjjm4dn5tWQqL7gxIhOwr3mrPepA6Ysr/h6nt5PXmr
         UXMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2A1/W/a1Mlis4vmrwX52+lB9SlXhsS1WhuEdZQo17zKnV/97/+yi2LTmrjqwgiI6Q2F7pZ5S4kHPzVr4iTB5VUv7z8wAf8g==
X-Gm-Message-State: AOJu0YzLVdDeApHbbVh704g51F7BIfxNBD7f2Ntt6C2jDwl0LhMnACC3
	Ys9m+deI0JnFYB63Sl4sGtkv2opo4Fz8nDZi0NgzWj/iClgL4DED
X-Google-Smtp-Source: AGHT+IFMjOwTlv4DMOGvnqOlqB+O422JH7gwN3LhrkO1/dRSo0z4KXVdDzfr554Z+ct/xrqxNYVVxw==
X-Received: by 2002:a25:2d07:0:b0:dc7:4b0a:589 with SMTP id 3f1490d57ef6-dee4f4bf2d8mr10575788276.55.1715629092911;
        Mon, 13 May 2024 12:38:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a2c7:0:b0:dcb:b370:7d13 with SMTP id 3f1490d57ef6-dee5c9007bdls3899295276.2.-pod-prod-04-us;
 Mon, 13 May 2024 12:38:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCYJ2VsYt7SVWQ1aejR6dC2Q0PhEHYXZwV9nN3B9d7E5d6iT+0bMlitcr9WJVtx8L3hko7XxR5yOfkq8IyAa3RMvjxWc9I5buwPQ==
X-Received: by 2002:a81:498b:0:b0:61a:bc15:8359 with SMTP id 00721157ae682-622aff42dcfmr105497187b3.9.1715629092193;
        Mon, 13 May 2024 12:38:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715629092; cv=none;
        d=google.com; s=arc-20160816;
        b=Kud5u7JV0Aysmg8gg1q0XTBjMHTb0SB12nWNpD2pn72e44VvEKJkzSonPsgJho3+zT
         4X6IZMt2AsHrQoy/1ws6OsmBNwJkypjm3B/GHo0ZAIeQZi8NPDRtzZUa5IN++LCzFTuk
         uLhLVSXirs52wgmOzHH8NGGAEDOWtodLXT0eN9m14ow32nI4ZLP+xTL1QH9nIL5+MUkv
         Zl5+Uyr6Ddfy+ohH2gCklhy24OBNjPNOQdmv5s0YBHH9gp0kbBNyYesVn7zWFbtangK6
         yuT8H6e4HEi3xva0TmUX7MeVHCmR40AgVW27wbkgWqOI3Ch1MaaMT5Fl1EqX79GL6ACn
         a9Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=vgkF7qcOVafQ40ar+TMVWPZrx+hHUDzCAOxXY5A0EMc=;
        fh=eDdK40krtWyjNnSFs4h2SepZVdd7qicqp3ugeX6jaYw=;
        b=rTgK9iuwA3uA4mGu5eOBqNjs3QelmG7PrQY/Ug6y9Xy3yb1SvdzPhh7XnUDVXK0fOi
         yuxQr5zSotVHahZWplzRHfOVJD+J0DRhJ+08AgLyJTJxQS7D/YlG4P7EQGdc3pzHRLav
         Q3T/GfHx40RnQQoUP6u4UC48xcHEQBiPM8cG5FnQx9y1xBE7/AFBLFUUsZ+8IrPtEm9d
         L/YdIRZRyY9xQqMPXcCRlNVz3r2qpiD5GHMpIlQUeQDxCPu21ZlTmm11PIDXBJgkV1OR
         22T+R0tnUTVBZh5sy3e7GZgvKCsSt6s94jmhfprwpZpnEtzP4vm39KopD3AeaviGqZT7
         +1cQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=kezNOi9u;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6209e2464d4si8601747b3.1.2024.05.13.12.38.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 May 2024 12:38:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44DJ8WJk003283;
	Mon, 13 May 2024 19:38:07 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3y3j28h14x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:07 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44DJc3NK004093
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:05 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Mon, 13 May
 2024 12:38:02 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Date: Mon, 13 May 2024 12:37:39 -0700
Subject: [PATCH 2/4] mm/dmapool: add MODULE_DESCRIPTION()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20240513-mm-md-v1-2-8c20e7d26842@quicinc.com>
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
X-Proofpoint-ORIG-GUID: IT9Nqciwh67l9pF9BwbpT2_gGImHBq_K
X-Proofpoint-GUID: IT9Nqciwh67l9pF9BwbpT2_gGImHBq_K
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.11.176.26
 definitions=2024-05-13_14,2024-05-10_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 spamscore=0
 impostorscore=0 malwarescore=0 phishscore=0 bulkscore=0 suspectscore=0
 mlxscore=0 clxscore=1015 priorityscore=1501 mlxlogscore=872
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405010000 definitions=main-2405130131
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=kezNOi9u;       spf=pass
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

WARNING: modpost: missing MODULE_DESCRIPTION() in mm/dmapool_test.o

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
 mm/dmapool_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/dmapool_test.c b/mm/dmapool_test.c
index 370fb9e209ef..54b1fd1ccfbb 100644
--- a/mm/dmapool_test.c
+++ b/mm/dmapool_test.c
@@ -144,4 +144,5 @@ static void dmapool_exit(void)
 
 module_init(dmapool_checks);
 module_exit(dmapool_exit);
+MODULE_DESCRIPTION("dma_pool timing test");
 MODULE_LICENSE("GPL");

-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240513-mm-md-v1-2-8c20e7d26842%40quicinc.com.
