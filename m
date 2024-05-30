Return-Path: <kasan-dev+bncBCCNRMPMZ4PRB6NL4OZAMGQEZ26PZGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EF3F8D5268
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 21:39:39 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2bddcf62cd3sf1051160a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 12:39:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717097978; cv=pass;
        d=google.com; s=arc-20160816;
        b=yiNfJIWnFzxjix+7bwQURuEqI4RSI/xynjz5IurzDjbTZZl4cBt53fUNONh9q2Icxi
         h9S5lCOuD0K04o/i/niQKylwnF5HJoLgzOkTxV7RS74lWFiM4W2v3XjXA0D0wDZGm/nW
         IwzkqVHe2yabrJSNyZRDsMRWfGGEenrnYqn9pGBgDOAtxqct0iFI0PXws322r+zLRwiF
         PqWXxjunlnAI/kO4CU2MM4RkNWiK9UWpNsy+hqDj+UQGMy5hNVMdOMnyXOv6/tAw4Xpk
         /ZSZpLhBW+FpArLo8XrVBYXL7VxU4Ho3xdB+qXf4T/nBrZ8PQ+PbkKJAO7ZoHSB/iMhD
         M/kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=LF9jphtvu112sAh6qhc8n3W+/6H7BoXP5COVBaDmxwI=;
        fh=fJUx45+rB6IV6mHFJQPk/FdkW114NSrR9jTWxik6Ymg=;
        b=Wqy7VCO7XnFghG/T2EqYyjQFEXJCfKI+I58NvskzzqXkRZ8qm+w+Dq80g3hyPeF3bz
         YJcjwNcQUbI/D4zbI1Blh9Q5Ag5LQnD2Qq6eKYDoeMK3Yn7qdCY8aCGk7IFEL/8Wzp5x
         6chsymL6IU662AN6IwXTUpc2678YhCZVyUvWQbs6LE6dPrdNseO4GUOLxzxeRNVrq4XN
         huXyPgRm0CD+oYaT+zvqQSyU3FsQvW7oE+tKQAgR+ZzuxvmFBG+Rbao0eedF5F/nSjZj
         wXoIDF98e93qO8Vo1W8kNzckYRxCZziwaFM3pJt78oEyja7Tr4iDwHo4DkNlXNx07GUC
         WOQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=kGAodZpT;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717097978; x=1717702778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LF9jphtvu112sAh6qhc8n3W+/6H7BoXP5COVBaDmxwI=;
        b=A/XI2pOFUOtVYpCjcMikXfECn280bTSg5/DAzAFNk8PoG1DGXia4VB5xT5ftbZrTqs
         FkrjVqz4nasRQexbo7FE3Zuc6vDcnSBvH2Xklau2m6KZUx9r8NedT4uDE80X8eSDZz05
         2aeA8symaL0tAyc+A9CyaDRdq7fd1UNmgnwTeyFEFxkxl2Medb/tbHStTKxCB/HQUcLA
         tnJlFp/ggbtVDUnEl0pX3YGrLshIFi6tCMyUnNMVCJeLMhaTNunYTPcA3cpkPKq9uXug
         x6ExNna9txdUWenHMgtXldAOVTcKQ8yfwQYs1gzp9U3uQzqHhao/yNP5bKadbyhxA/7U
         DWAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717097978; x=1717702778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LF9jphtvu112sAh6qhc8n3W+/6H7BoXP5COVBaDmxwI=;
        b=aiyyev2TDzIcC5AL1h8m9g+iGfx1mpWhVzvN2T0FloXS+KfQRV8HSa5KGj5BInOWVz
         olPRik4PtMlZkTzhlb8Zatcvo6mpWTsu/i9pqfzlOjvX9Z1tOBUNeYSsSlwLVo+55yn2
         kfDPQqyg+wr2JDgIH3jYYwlASxAJzxwNzmnacSXbAHb06wc3IgrkRPOcWFnwBw6oyQmp
         TxIrQ2xIOoknf5y04wHCcTqihC66SxR4Daebjdq5sdDPmaUIgnUqG5XTAY2q2axeGqxT
         N7nv0xO4bW4790DJG6aGIDwRfhGVJ3XC6kIsOJmOG9arulrwhShL5E95KxXgPyh8gmbZ
         +2fg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXaIOiREmJlfNuRjlkKhBpOetgSK+ZjMT1qH9AIf4uJmRXTRI3+UtVEOqRdZnlVwbtqbseJEeWQv8kNqOmlop2aoz0AGAegIg==
X-Gm-Message-State: AOJu0Yzw40n4IQghLDsQeayG1CTlO9azsWmE/flFW6jnUICP1QeXJTm6
	eFbs3Ychoje/8ZHFOjGJHVoaczzdJ/yYFsGFTDKIrGPBASjnULw1
X-Google-Smtp-Source: AGHT+IFemHCmxhr7ggf2d+zGemjtxe4UACdLUZCzJV3CcgUUjoNKQtIY8OCYIaPeWlEWlRgcj29Ojg==
X-Received: by 2002:a17:90b:168e:b0:2bd:d2fa:275f with SMTP id 98e67ed59e1d1-2c1abc4a25cmr2867530a91.41.1717097977534;
        Thu, 30 May 2024 12:39:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f418:b0:2c1:abd8:b7a2 with SMTP id
 98e67ed59e1d1-2c1abd8b875ls670970a91.0.-pod-prod-09-us; Thu, 30 May 2024
 12:39:36 -0700 (PDT)
X-Received: by 2002:a17:90a:2e0e:b0:2c1:a557:fee5 with SMTP id 98e67ed59e1d1-2c1abc4d29dmr2610120a91.47.1717097976276;
        Thu, 30 May 2024 12:39:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717097976; cv=none;
        d=google.com; s=arc-20160816;
        b=vcnydKY5fcM5N9AvF5F2yk2U/1nT1Z4Zkw1+2fsw0BRR2UoCUGouy4ZnAEIq6DKMO5
         5T3EruQLXP5b4vXd+geb9JkinVkI1DCIN4FoMgo8VGiJEkVp59uEbBeC5e6d6nI7vVhW
         FseuP1mdCuo1prOvzmJ/M39I6y2/WxZusqSEIaFER6VW00ICVbbkUfSBPpikKiL3r0/n
         uGQmEbswAdHmS+sxfbVpRnNzpL5I+ijcFetzRActwtsMfqKIjIepffqVTSq6HzNfHt+7
         GYTttlXkmT7pHBCraqofpNfpCztO8XJFOvFcKM9N5POMw38L62hVQDSkCFd9PvKoK020
         Cqmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=G3LhfMYXLod+WXyf4kdGO/jHODsxn9J3pVc37hfWDsY=;
        fh=AfiDK0IDo7I0oAb2V1A1CZHp1F8fmHsZn58xCyMs3oE=;
        b=0CRhhuInHgp18jfop2WhLEbU+8AguKmLqsmCCm/aUjeBSWV6uy1L+pkYVDZ5GRSh7n
         oz1YD2z2c9jq3exFCXnNs3wN54hOYWauHRp0GuIP2TBIr/L0yUey9nXn5pu92VUlo6aA
         ii4SXqr2KfKw2BTluSxUCd0aez7JLD9pQ+iSj3V7AcY4NiKXZdc1N9sfDIJOdUwVYiHS
         D4FZHduK/N2WF+a4zTe7A0hepLwI/5/WFSDgPcvrnaQShtqdh48hR2oqfzVhmN0Oa0V5
         Y+FWEgooXB7KDCFCgt+D15JcaMkr5WbMK8N5x5nDaZqW0ciFYhn8iaYFbu5vCOU3bNXF
         6wtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=kGAodZpT;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c1aaade0b9si218708a91.1.2024.05.30.12.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 May 2024 12:39:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44UGpGxU024728;
	Thu, 30 May 2024 19:39:32 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3yba0qmyvw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 30 May 2024 19:39:32 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44UJdVmU011554
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 30 May 2024 19:39:31 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Thu, 30 May
 2024 12:39:30 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Date: Thu, 30 May 2024 12:39:26 -0700
Subject: [PATCH] kcsan: test: add missing MODULE_DESCRIPTION() macro
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20240530-md-kernel-kcsan-v1-1-a6f69570fdf6@quicinc.com>
X-B4-Tracking: v=1; b=H4sIAO7VWGYC/x3MywrCQAxA0V8pWRuYPgYZf0VczCPa0DZKolIo/
 XenLs/i3g2MlMng0myg9GXjp1S0pwbyGOVByKUaOtcNzvcOl4ITqdCMU7YoGM7B5+B9W/oEtXo
 p3Xn9H6+36hSNMGmUPB6fmeWz4hLtTQr7/gMZhQwLgAAAAA==
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
        <kernel-janitors@vger.kernel.org>,
        Jeff Johnson <quic_jjohnson@quicinc.com>
X-Mailer: b4 0.13.0
X-Originating-IP: [10.49.16.6]
X-ClientProxiedBy: nalasex01a.na.qualcomm.com (10.47.209.196) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: p3zlZjerhl5YzVcwUELOeuVp3a5BI-Jf
X-Proofpoint-ORIG-GUID: p3zlZjerhl5YzVcwUELOeuVp3a5BI-Jf
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.12.28.16
 definitions=2024-05-30_13,2024-05-30_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 suspectscore=0 lowpriorityscore=0 impostorscore=0 clxscore=1015 mlxscore=0
 mlxlogscore=999 malwarescore=0 spamscore=0 adultscore=0 bulkscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2405300145
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=kGAodZpT;       spf=pass
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

Fix the warning reported by 'make C=1 W=1':
WARNING: modpost: missing MODULE_DESCRIPTION() in kernel/kcsan/kcsan_test.o

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
 kernel/kcsan/kcsan_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 0c17b4c83e1c..117d9d4d3c3b 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1620,5 +1620,6 @@ static struct kunit_suite kcsan_test_suite = {
 
 kunit_test_suites(&kcsan_test_suite);
 
+MODULE_DESCRIPTION("KCSAN test suite");
 MODULE_LICENSE("GPL v2");
 MODULE_AUTHOR("Marco Elver <elver@google.com>");

---
base-commit: 4a4be1ad3a6efea16c56615f31117590fd881358
change-id: 20240530-md-kernel-kcsan-9795c9551d3b

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240530-md-kernel-kcsan-v1-1-a6f69570fdf6%40quicinc.com.
