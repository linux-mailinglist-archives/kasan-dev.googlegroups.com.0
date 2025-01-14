Return-Path: <kasan-dev+bncBCLMXXWM5YBBBUPPS66AMGQE6ALIFFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C31EA10064
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:36:19 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-29fcd0ef678sf4744713fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:36:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736832978; cv=pass;
        d=google.com; s=arc-20240605;
        b=G5gKBI4fzO/Map8ArKntvv1GUlZPGAr6XseZHbUXWoLAQCCvVo+wWjlGzeVR1A57DO
         a6uHVv4ZlVNgcFNKQ1vLGXHiX8gRBqOUt+7a5ksp5qcC3YbENo1M/4yZ91hY/4R98K8X
         PtfWZYxDT+2vFsnW1V7811JHGLam+ZIerFEGsGqXMHCrD0fiyG8etuwjtB01ZhF+/6l6
         F77UIm/acBaxsAj7L2Llcf9vGAd1rO2cnRvL6cdnAf4mbluhf/wn/SKk1nFYJFO8yF7Y
         Yyqj/JImVqfusqKLOgnF3SvGGnb7v3fbEZLbK6pvRmA0aJp9Z3I8yqryMQr00SUEbHLX
         n6Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=aoYk+q1UqF1BXaNzGRLTndHYD2BVnQQ6vXfr2mK1c74=;
        fh=wET0rWFYRJE+fstQeCfXhrzLQe58WJ02t0aGKOn/iu4=;
        b=Ond9fqfOWlJ0AfeyJs5wPqN2IdfWaPWMzVmtZwrxaboNzOM8yYtMMpB+1Rj+lTSP6H
         Tj3ACc7SvtvgjoLUSGqJTXU6ED29n4Bg63zwo7SWYNccMWY4FEyzustVU5usvnvP2Sok
         3cmNvqzEpFd8AHMwtDrJmTt1tPmrkImWjaczTpLHTEdXJ6YOoOG4ZY1qV4UQYoVyFfJb
         uvGuMk/7SyvASDCeVOuSzmQC8T9kvOXW2JaCNq8UaCGsmOGtmUNlFrgy7EgJax4fvuby
         Iv+Ux2Lmo+7lAFHxw8nNQEssydO3Co0t4WS6EsE1hRwrveWBuXcElcumShkepEI8QsEw
         Q+CQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=pib3eWcG;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736832978; x=1737437778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aoYk+q1UqF1BXaNzGRLTndHYD2BVnQQ6vXfr2mK1c74=;
        b=uK8bN/sO33SWUUAZvicVAnMThiyhJ53OOOrtcPhdOMIO8md28IEjP8xkFaSpoPRrSf
         sabzkv1w9y3GFKT6iyR98IptspcGRTBbUCgL1TJ/Y3opGfVQSHeqPORJf8n9G/bu1hab
         IXm1EmqkScNaNCyNBSxsQ+pfSzAF3NLuKbxy4hRSXfw9WF6+4+vZhEUFmRGiT93oRIyM
         Qe55/Iy48JxtLXJICEMcrPEfyilPV4gpQmxP7wP0o/Op244eSZ637tuMzq4mmYZKYTUK
         trL6c01idK/YjU3hhKSRbgVsRwiTvltpWK3OshwnEjC2jisKpBZVjcEn/hzB2SGEjnnL
         +5UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736832978; x=1737437778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aoYk+q1UqF1BXaNzGRLTndHYD2BVnQQ6vXfr2mK1c74=;
        b=NhMmsyieEBUnuYUGF+8CavkTZMEqQd/QfEJPdqwL149fjqOgYsbSHvovYbQADgtN4l
         t6k2L3zIt+GLS5hcnfJMCmPaxqf4+9kfAHVDLRvuvdF3xz71L5RYpXl5PFniplUkyCPA
         PNBq70MqPeFoN1b6kOa4Cnd3gb0RKgDyAO7gvqMzSyYVURkjR91Ak1isdghXx+B4Uhd2
         CQdXidBllD8x3JQ8zXI91S5TsL/48lh5HWeKpUqhMHQ3mE7cHo+5Dl3kREqQjcrlJ17f
         eTZ3Lnzn/vw8VToZpuDMiBXeNWb3m4BozAJaCBb1mXAn/Z8JJwOzqISe2r/TT+1Pmnoc
         8hWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZWTehsuJ+cpJCJo7P74U5SYl96wbxmWobmawtFRoI7vt3n02dMbjgCCZmslYQ/CsOEpGamA==@lfdr.de
X-Gm-Message-State: AOJu0Yzr4hI/5Dr0a9hSpocyWHN2EjE+SfeEFR8ptc7f7EhAAu5VuDJV
	Q7t001TPUgldf94P/1/yXOeKq47mNuKFALer8+8anlrAwhpMIBrI
X-Google-Smtp-Source: AGHT+IGAcfptrEQu0wTdLNC4LUdlhlp3uG0nltgV1jBXpFlzvxAdFx1NObjYBCWa4Jwj4J2VtulS+A==
X-Received: by 2002:a05:6871:e086:b0:287:886:2e62 with SMTP id 586e51a60fabf-2aa06696c13mr13065511fac.12.1736832977966;
        Mon, 13 Jan 2025 21:36:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2a45:b0:29f:f56e:68fa with SMTP id
 586e51a60fabf-2aaad6df5aals2878178fac.2.-pod-prod-09-us; Mon, 13 Jan 2025
 21:36:16 -0800 (PST)
X-Received: by 2002:a05:6808:170a:b0:3eb:5e08:f806 with SMTP id 5614622812f47-3ef2ed37401mr14794215b6e.29.1736832976368;
        Mon, 13 Jan 2025 21:36:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736832976; cv=none;
        d=google.com; s=arc-20240605;
        b=kL3uIYy8fIl93glrVpNUiWHcYP79UmxjLh5O2E80WvUrXnEodFvmkHWCsVqfG3s/Q+
         Ed0mb92Gl4Hlom9rgzb5Blm9dmxVYCkZ7MvPDpOn3fYZv99r5S3/D0J/nzwZFLBlPwRG
         Gp6hGTrrVp9j34t2CNUT6AEi0dW1gpJnoh6Nx+d6EkLhRoa3spWi7RBHo4MhrMrjVksH
         /tNYp9zhd2LZEFzo98PM0xMvpAbN1ZYx95XEiL9oKG6kq54e2fIJcInSaUaUomkDHp5E
         7/90o9RKyRxHGpmIAhNO4/WJmBFzc2mM3nP1OO9pdmRCvev4FsmHzVKd3s5Gr6bNsL2C
         cQIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=sbZl6GtDotLNfy1i0ybFvuNDyQMsou97Y3PruXQtvYc=;
        fh=IrFMU56A0U8g6WEnzuhC3mVEK/1VXa8G0j09OJ6Nq3U=;
        b=dZU1qg1TeS8ah1JY75AmN1f1ajwFBPHu7v8nKxaowe7+gCUiTYasC1TA6kWRd5gAvt
         c5TmwlV6zhfFWzdkP5z+xSrTl6aXySW8pm0lPh+zB7k9aCQBf0c1bnEyRV9GQUzx7fsd
         0z5kj+frIkcx0Aj8mSJrspgR50SrRJnVqFb3a/BvfI9InCThhmDkfBncL/AVaZDNTkjY
         ug/FccXokM9VZ/kRCsBvH1yc+HWL589eFPWhhS+eN58i+6nvYVfCs7dHY5l9lDpRrGnK
         qUOkOvxg+rvMjGykLXmtBXoOGV+1CFO5CknCzOxXvuKBN0+2Np3UUQCbPDAd7+lVAZF2
         ZrMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=pib3eWcG;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f0379f4115si489222b6e.5.2025.01.13.21.36.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:36:16 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279867.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50E40k6j020873;
	Tue, 14 Jan 2025 05:36:09 GMT
Received: from nasanppmta04.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445gh60522-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:09 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA04.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5a9Sk032192
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:09 GMT
Received: from la-sh002-lnx.ap.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:36:03 -0800
From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Date: Tue, 14 Jan 2025 13:34:36 +0800
Subject: [PATCH 6/7] kcov: disable instrumentation for genalloc and bitmap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20250114-kcov-v1-6-004294b931a2@quicinc.com>
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
In-Reply-To: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Andrew Morton
	<akpm@linux-foundation.org>,
        Dennis Zhou <dennis@kernel.org>, Tejun Heo
	<tj@kernel.org>,
        Christoph Lameter <cl@linux.com>,
        Catalin Marinas
	<catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
        <workflows@vger.kernel.org>, <linux-doc@vger.kernel.org>,
        <linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
        <kernel@quicinc.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=ed25519-sha256; t=1736832942; l=875;
 i=quic_jiangenj@quicinc.com; s=20250114; h=from:subject:message-id;
 bh=EXcTVhs0X6v2Sn7y/hEncpAKcEG0rAcAKxXrOMGyy08=;
 b=DPbLlmPLNl9LVZSN1bfAVqQsyLNyv2HqNKFt/s+LvYi8cIICAf3fRzFkJUf2iumIUN1xDcknK
 z8FbRLfWBReCSA8dPFnjOChSeV9/ToF4C7tcNQG1a9YzeqfEVSpKKbd
X-Developer-Key: i=quic_jiangenj@quicinc.com; a=ed25519;
 pk=JPzmfEvx11SW1Q1qtMhFcAx46KP1Ui36jcetDgbev28=
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: CzmwwnNWwZyaCVN5LYXu9a4ccWBCgyOh
X-Proofpoint-GUID: CzmwwnNWwZyaCVN5LYXu9a4ccWBCgyOh
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 suspectscore=0 malwarescore=0 mlxlogscore=778 phishscore=0 clxscore=1015
 spamscore=0 lowpriorityscore=0 priorityscore=1501 bulkscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2411120000
 definitions=main-2501140044
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=pib3eWcG;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
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

gen_pool_alloc in kcov_map_add triggers recursive call, which trigger
BUG: TASK stack guard page was hit at ffffc9000451ff38.

Disable KCOV to avoid the recursive call.

Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
---
 lib/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/Makefile b/lib/Makefile
index a8155c972f02856fcc61ee949ddda436cfe211ff..7a110a9a4a527b881ca3a0239d0b60511cb6e38b 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -15,6 +15,8 @@ KCOV_INSTRUMENT_debugobjects.o := n
 KCOV_INSTRUMENT_dynamic_debug.o := n
 KCOV_INSTRUMENT_fault-inject.o := n
 KCOV_INSTRUMENT_find_bit.o := n
+KCOV_INSTRUMENT_genalloc.o := n
+KCOV_INSTRUMENT_bitmap.o := n
 
 # string.o implements standard library functions like memset/memcpy etc.
 # Use -ffreestanding to ensure that the compiler does not try to "optimize"

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114-kcov-v1-6-004294b931a2%40quicinc.com.
