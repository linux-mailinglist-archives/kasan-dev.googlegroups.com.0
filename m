Return-Path: <kasan-dev+bncBCLMXXWM5YBBBHH42OUAMGQEYRYEIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id D31487B116E
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Sep 2023 06:16:29 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-59f616f4660sf188151627b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Sep 2023 21:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695874588; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZWv3az4xsVl2EckFwecq83JwAbD84NmH6Xdg/+5GJNanfRPoIcf8wjoQVsUBzkCP18
         OV5DuJofHKoFa80wSOVsNBokLc0hgORkB+lNPanJEZAuslud/eAxF4TAeK108qCdbmPz
         V4hTPy0WHwESI/jG2+4us515rZzd8l6wPZS3EFToa4IrfpKb5CeqEagZbT1lRsjJkw6r
         WRHdhX7vDYz+Mjxnahh6YMZkz3/AKE5W97JUy2iaPC0lW+VVU5XDLwa3SsstrhvimVGz
         OPnM7fK0kz5dKI+3BNvnfT6XPnVlm1MvEZbKkmEymglgU+7Sr+N+l2twEPNxmYG4l8Cj
         j+iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6vh+xzK+U7nTqWnJ+ixD7ptxkFm/ecC8ToLX2+bgA2w=;
        fh=TnMi4LIElhec6nBuvjSEia4oFRusBugqdUa4W9YN3Fc=;
        b=Xu2L068To6GUD/TFGPvoA33TASD0lDWsbiXr4cuuoGUFQQXwtRPJyXws0F3CG0VTud
         SQcX5oZSZLpSMj3LEvp/yf9qCScVLOWYrUQFfrNoqrAbbW1a+DYvjJpbamoobHMbow6G
         t7/CZBYLxIsf0I8y8+w3Qt2sn1/GWV4r37NbAwi197xu7oyhOtdpN00bGzMLOM2R99zd
         H4Vkr8vZ3HfhgKyvK1aiCYerggh+FlKG5AuiyMWMHTr51O/i7MWFnnTe+2Cq8TFcbUSD
         pzD9oV6P3wlNESfeaugn4YNF9NgwaLN1XBmiO3S2gD1uxiwlS+y7EK2t7VlnToVo7Kjh
         azEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bxFSBGfX;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695874588; x=1696479388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6vh+xzK+U7nTqWnJ+ixD7ptxkFm/ecC8ToLX2+bgA2w=;
        b=SikUIdvERN3z0jWPRDLQ8sQ3kXUaeNCjgmG7GT5aX/vchcmTD81u3TGpSUy+jXqUeY
         JJhkgIopNxQRsAvvo6ct1Yee1wCFhiofPGe/DuCCrH5NoLH9f14hTafO8r79ujD9wei5
         y3Al6WZI9qR6rsQmAKIGjOzAPa3/UcmpN+avBWhM/soG/B2kCzOAL5afooKHQ5mB0imj
         VKI3awpyqxCEc36EkYRMfil0OIgNTTgPo6EhOMpanvydB3GO4qhebtfXNl907r7c0jrw
         WDGTDR9//RMUwVZpRmddd4sgv1iJQXTU15pqs7r+hbKQl1sSklOrj8bf+y5NKyA9RzZJ
         2AGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695874588; x=1696479388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6vh+xzK+U7nTqWnJ+ixD7ptxkFm/ecC8ToLX2+bgA2w=;
        b=qT6oTLlyvwUkXDrdilAjAKS4SPB6DE9+4XZg8SsqD7uxXJ58Nb5N3Qg+rwvz7aMQ93
         CjX/kjnkrmz1Ll3jGnkZfNM7B3wZUZ5PCCviQVM4ayfi3tPVN6GNWBUt/Fge4fl93FP2
         C97/c1vuSgvbxM0sPXGYhnOQDGW4vLhVCPPg6qkXBpCrDFtHjcJPOhXI5EVeUCxprwEI
         CuZ52IlyJqcB8XcRS+428dYSDz30pZM7xk27ZXWKuaRSBulpUaVs5riskhFwVXHkDmJP
         7MTWnpWCKpJWANPAbLMSv1n1I62vq8ErXDKstgHkQ94yVFf2iwiKpA+DNMVfVxsUINMc
         wUKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxgDNJdsawSiLF73LXnOrr5TN6sQz7LvHn6o/KNQ3nj7Vuyyf1v
	hPFUye4V08+bzTAlh5zDLiQ=
X-Google-Smtp-Source: AGHT+IH8wX61qCfBtnIWv+QmUFP60uHma9uu5nYgav7+n12XaOVQT8Dhs1NN8Ex5PlXXm9ENmgc6jA==
X-Received: by 2002:a25:30a:0:b0:d89:47d6:b4f9 with SMTP id 10-20020a25030a000000b00d8947d6b4f9mr96165ybd.23.1695874588245;
        Wed, 27 Sep 2023 21:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:18d4:b0:d81:43fc:d6d with SMTP id
 ck20-20020a05690218d400b00d8143fc0d6dls951847ybb.1.-pod-prod-05-us; Wed, 27
 Sep 2023 21:16:27 -0700 (PDT)
X-Received: by 2002:a25:b10:0:b0:d7a:ee98:4f8 with SMTP id 16-20020a250b10000000b00d7aee9804f8mr122489ybl.30.1695874587241;
        Wed, 27 Sep 2023 21:16:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695874587; cv=none;
        d=google.com; s=arc-20160816;
        b=F2u+d6EK6jsAGpPExMiw9xJ9MWMVwI28TloqnPGCzcom+V18OOg+AuXGHJMQjmIoRE
         6DVaTpKG/XyeiIq2gcX6JqWajBxA1d7qWLButeZgx4aciSPGqidXaZAhzklUDjLPLr8q
         MwJj4BzZ6Q6jfoWOsmylJh7Fd44jtRb6HswXRSPEF9jOg9C6pfGJNpXAarga3y5wGhao
         +OvcFxCfwBEa1okBW6ab0efSrdUJgWvoEeHdi/RWPWrJFZ53/MrGLBy6lRZobQDmV/8k
         nOh3dRDgK1vyKI+c1wV6FcrEvObHRtoIbjQMC7ixYUeSUHGzfgVclGRd1ZeZd+1GslGL
         bJGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6CCI68ah3xAwytDjix9FVL7747Qa3cO2Y4a+ve6LKqU=;
        fh=TnMi4LIElhec6nBuvjSEia4oFRusBugqdUa4W9YN3Fc=;
        b=0n4EdGEQvaTJLBSscs1PTrGrzxSpkcH5j+CXYSNij/sLHKBpzMC8pEc5uXAMVmv9d2
         CNXEMK9c0t3hcx7JGwL1pPcj9Df4U88X88Zy10AvYrKpWLa2QoWa16a9rJmbdE5QEi8Q
         LyKMcyAjrv8aQK84Kzbq2dawYw7y1rJV487iJ6DJvjZQYspr1u7hdRWRBq31Vd8/uJ2R
         pptQX6it0KLSdpxP0IyHt0Sw0rtO/icqK8eRMWbPByLtcOFz8sVt0zO3fgGU1aj6gHgU
         lYSrcwDlGFdeDMuvv0hmYA28OQfofCpwZyJthczLrwvAhids4f3rK1374hMbMBF/jVt7
         8axA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bxFSBGfX;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id p62-20020a25d841000000b00d866d666ad6si1035402ybg.0.2023.09.27.21.16.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Sep 2023 21:16:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279870.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 38S3MqXC030058;
	Thu, 28 Sep 2023 04:16:18 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3tcmqe9u1a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 28 Sep 2023 04:16:18 +0000
Received: from nalasex01c.na.qualcomm.com (nalasex01c.na.qualcomm.com [10.47.97.35])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 38S4GHo2020993
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 28 Sep 2023 04:16:17 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nalasex01c.na.qualcomm.com (10.47.97.35) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.30; Wed, 27 Sep 2023 21:16:13 -0700
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: <kasan-dev@googlegroups.com>
CC: <quic_jiangenj@quicinc.com>, <quic_likaid@quicinc.com>,
        Andrey Ryabinin
	<ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        "Andrey
 Konovalov" <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Masahiro Yamada
	<masahiroy@kernel.org>,
        Nathan Chancellor <nathan@kernel.org>,
        "Nick
 Desaulniers" <ndesaulniers@google.com>,
        Nicolas Schier <nicolas@fjasle.eu>, <linux-kernel@vger.kernel.org>,
        <linux-kbuild@vger.kernel.org>
Subject: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode
Date: Thu, 28 Sep 2023 09:45:59 +0530
Message-ID: <20230928041600.15982-1-quic_jiangenj@quicinc.com>
X-Mailer: git-send-email 2.42.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01c.na.qualcomm.com (10.47.97.35)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: GpCpWJnb2Fhr6tVP9PFPXQ5MhDfiNxpf
X-Proofpoint-GUID: GpCpWJnb2Fhr6tVP9PFPXQ5MhDfiNxpf
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.267,Aquarius:18.0.980,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-09-27_17,2023-09-27_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011 impostorscore=0
 mlxscore=0 malwarescore=0 mlxlogscore=849 spamscore=0 lowpriorityscore=0
 adultscore=0 phishscore=0 bulkscore=0 priorityscore=1501 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2309180000
 definitions=main-2309280036
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=bxFSBGfX;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
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

Fow low memory device, full enabled kasan just not work.
Set KASAN_SANITIZE to n when CONFIG_KASAN_WHITELIST_ONLY=y.
So we can enable kasan for single file or module.

Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
---
 lib/Kconfig.kasan    | 8 ++++++++
 scripts/Makefile.lib | 3 +++
 2 files changed, 11 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..1cec4e204831 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -153,6 +153,14 @@ config KASAN_INLINE
 
 endchoice
 
+config KASAN_WHITELIST_ONLY
+	bool "Whitelist only KASAN"
+	depends on KASAN && !KASAN_HW_TAGS
+	default n
+	help
+	  Say Y here to only enable KASAN for module or files which has explicitly
+	  set KASAN_SANITIZE:=y which is helpful especially for memory limited devices.
+
 config KASAN_STACK
 	bool "Stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 68d0134bdbf9..e8d608ea369c 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -158,6 +158,9 @@ endif
 #
 ifeq ($(CONFIG_KASAN),y)
 ifneq ($(CONFIG_KASAN_HW_TAGS),y)
+ifeq ($(CONFIG_KASAN_WHITELIST_ONLY),y)
+KASAN_SANITIZE ?= n
+endif
 _c_flags += $(if $(patsubst n%,, \
 		$(KASAN_SANITIZE_$(basetarget).o)$(KASAN_SANITIZE)y), \
 		$(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
-- 
2.38.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230928041600.15982-1-quic_jiangenj%40quicinc.com.
