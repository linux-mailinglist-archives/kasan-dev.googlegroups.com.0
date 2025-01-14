Return-Path: <kasan-dev+bncBCLMXXWM5YBBBRXPS66AMGQENYWXB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 34E19A10060
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:36:07 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4679becb47esf122449311cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:36:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736832966; cv=pass;
        d=google.com; s=arc-20240605;
        b=dech0NOZekihNgTpXU+nGQ3VINE+XEu+srnjs6T+XaGPpTroMCAkr9XraYKi10lP+a
         kr9bEp9uJJpP+0mOFiChNv8GdPFHxE+WSGPJDbEr0UvdQkBfiYqkd9FPafBAgZrxPyTR
         EWSYvyquzUvDJG3qDjlUERVsWhjSZxcVcvV8btZuZ5Xi35y6wbgyp89sn27aWyAaClRD
         Ezm7afrOkPMmqIRmdRAiwMKiaHKu2efhTVF3EfUyP4pLp2FN7NgV0qP6hQkP1u9h8Nqt
         VBVg8teDJN5E6z7asNIHbAY8WvXnRyHbP8cFtV8Y6aiC7n01RKedhpyNsRJ1tkPrF47s
         PxMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=zNugLl3S2Nn02yhe9tXv+FQTMgJk9VKu+nFNtwLlR1U=;
        fh=dyxOTyiG1VpAJ9626qryQytlJ8EN2x/Aa3gu9Smj/KM=;
        b=MDHhlUUYOeDvni0kuW18BSMHtcqp+ibuumafPSFTlRHaVzb0S8H5BTsv1r4SDNZxx1
         WRYOtNg5dqz50u9ZqPm57JkIwQxGXXVqBBrpcVuLbjPww2V3zDBljwbtLsYpjuAw27a4
         +S7iKEN7xa/+HolGP3EIOOEBYVG9A27SMW/l/L4sDYmhwq3Qq6HPEwqn1NX33zL1tlqY
         mpOWPte5TSwlLTVZ3IoUOD5lpj7s6vhB6twl5MPC12QeVzj1S3/m6J8xut6mcHzEwRdP
         eYwS3lxFx5S0LvYiA5rjPrLfZwPXqYQkRNAjJWTh8UNSpyhcJUGsBn4DS2j9uZk+FtNF
         ymPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=aXbBkGUg;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736832966; x=1737437766; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zNugLl3S2Nn02yhe9tXv+FQTMgJk9VKu+nFNtwLlR1U=;
        b=TWblUQbx5HMxC44rxpOzf6weCb90Us7zxwKeOC2QKcEG7QHeBEXl03kDhcYREdiaye
         3BZd3gGY5unuYO1tddMFfzR7HpFjXGBGQXckpXzXxaWRc0B5+bQizS+wz3bjXhPgDEQZ
         Tm9T7skaJaMXee1vm2vOyphUIPL2gEbYY73RO23EgJvZH0jbjnSwEsLp5H4BhUER2uc7
         xhaYIxNwGxCkAChwWNX4FimVokhq400iq/T6aujryCKDJ5NHHL6o7M7tPpOzxyAry3SN
         eGNrFdBTqsbJak6wAos4E3G8s1XJ797W1Kv6zlCm9iBGTLxldggKf7ELnd/PwyN6bS6H
         rpLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736832966; x=1737437766;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zNugLl3S2Nn02yhe9tXv+FQTMgJk9VKu+nFNtwLlR1U=;
        b=xCWbOUgGR06noLP/Xz0A/yK+SixUoU94FLVmF0g7OCOeO1vaZQ0nL4njub9Rt/1oQi
         0MQ53ShdidK4p9OI7QxkVbi2uX7cFcWUcNmkzDbV107hD2Y0L3HUaGRO0p+EJMkcc24C
         zwGGTrEHvJhV15Ey/rLknEKJJQWuN09bkf189ijpQfBjcQYQlRkxpr/Ecr1IFCrHls7L
         H5RKDETlgSvs/kDVUTE1F+zS19QgGfeVirXjRgUNMn6UUIpnFSmmMpsqLdpZ3mdRJ+03
         8lGU4ILfGn7LvjpGorT2FZL/Bgaw1YMR+fv3KQyuAm3G34tqgx0sb9kmXb++yz3W8DZh
         WZkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBBZhpCetlxqehxoNfsHtifzlWHLQh78ONReyZ3i6QSJcEAw0lGGd/bIvk6MySyoPw3a4x0Q==@lfdr.de
X-Gm-Message-State: AOJu0YxIX0vGOmOI+DXnoCtunVdVnmMRNvW7ABdMQLDQdJNg2nYbln7v
	1wiW9iCFn+XKlarpPJYwG8DFXQjuejhKTTWg3sT69PjyWuooAX6j
X-Google-Smtp-Source: AGHT+IFN84jXxWxG2Df0oKO4uUmKA0/6FjxVMTM0HZy5FA9akaZvql3HUEOKNv6HDp9ZEmuatRSsHA==
X-Received: by 2002:a05:622a:5:b0:46c:791f:bf5e with SMTP id d75a77b69052e-46c791fc2a0mr243844151cf.42.1736832966165;
        Mon, 13 Jan 2025 21:36:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7ed0:0:b0:467:6771:ac55 with SMTP id d75a77b69052e-46c7ab80090ls3117991cf.1.-pod-prod-06-us;
 Mon, 13 Jan 2025 21:36:05 -0800 (PST)
X-Received: by 2002:a05:622a:1e85:b0:46c:728c:8862 with SMTP id d75a77b69052e-46c728c8a88mr389616561cf.31.1736832965240;
        Mon, 13 Jan 2025 21:36:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736832965; cv=none;
        d=google.com; s=arc-20240605;
        b=asCQ+YJI4zPY4DQtXf/FiN0e1+/C6sRy/r+AdbAeCn2T9HZ5Kw1HciTf6Lo3+6IHZC
         YLMPjtkQASqE3xg7FaGvba42eG6p2E22oQGf8Tp41PxKUWVWtRjrdsjU96KpwR/e83sJ
         tCZVwtvBpspa2iCbPb8m+UPwnDhW1GVvx7HRmYsmJxfnbTltYQkiVP7sJH1EYrmoIHsN
         Aq8MQxfe7H5P7kWlCM6JhPmuaaysI0VuHQ0wMW/i1frcmKYTRuT7nP6mCYkn2V4/MK5G
         TrKs1KbBuJwhOL4LSePNUog9E0vJg+jYraNml2reZJHpRaGmY8FQVm1fKa31NyGdFkS5
         B1Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=CFVY0tjOmtO4qAqPnzy1tUQpQ6ETWmPtYq/HPU3qSi0=;
        fh=IrFMU56A0U8g6WEnzuhC3mVEK/1VXa8G0j09OJ6Nq3U=;
        b=hiKIoX4KzKCgqH7oRjz4e9aYFZzMkdk1ZSkvAmnYYn8wTKQQVm38JYcTxacOeYJKny
         GmL/T44UIgBrTciQybgKqKu3o6EJhuVO87EbXi9aJb8hwsj7PtfZ94jzzxOMt5Qu0llk
         RPcmWRNDCbRR4ehSZsdou42HWrDe2AlwzXn2fkZg/stQwpC4ihUkO6kvV/YERlP39Bia
         qJuSTFvweHzZ6DAsZPOl8UvI6Ekv+7yOKPVJmc0EIisM1NZ/O0q1SnXML2N//vhu5+Kk
         gHf2s8M1HgiyPg1uXL0KpHfpuNMuOdwhnU22/kmBcFKYgyop2UIr4/TmCJhRFk2uEPmN
         //8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=aXbBkGUg;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46c8734d169si4034871cf.2.2025.01.13.21.36.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:36:05 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279870.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50E2fc3u019144;
	Tue, 14 Jan 2025 05:35:59 GMT
Received: from nasanppmta01.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445fc68apd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:35:59 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA01.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5Zwtu020376
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:35:58 GMT
Received: from la-sh002-lnx.ap.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:35:52 -0800
From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Date: Tue, 14 Jan 2025 13:34:33 +0800
Subject: [PATCH 3/7] kcov: allow using KCOV_TRACE_UNIQ_[PC|EDGE] modes
 together
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20250114-kcov-v1-3-004294b931a2@quicinc.com>
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
X-Developer-Signature: v=1; a=ed25519-sha256; t=1736832942; l=1250;
 i=quic_jiangenj@quicinc.com; s=20250114; h=from:subject:message-id;
 bh=cUrFJ9xlku6iOVJmqRm3AKSPyxlxbIELfrHlRVSE678=;
 b=PN4imkwKcD7/nAryYV3lJaq77IA4e+9rhwFDEIua2TPoylFR2tEVvYzX1A0kElet197HOJhRv
 KnL6OAxKhzVAAeMfHluhR5AD/KnczeQvktL1Pe8Wg8BhWFmOtiquMjy
X-Developer-Key: i=quic_jiangenj@quicinc.com; a=ed25519;
 pk=JPzmfEvx11SW1Q1qtMhFcAx46KP1Ui36jcetDgbev28=
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 2ybqo6M8sHxWZsrwE_g4pZ5-4RN20TNw
X-Proofpoint-GUID: 2ybqo6M8sHxWZsrwE_g4pZ5-4RN20TNw
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 lowpriorityscore=0
 bulkscore=0 mlxlogscore=891 adultscore=0 suspectscore=0 malwarescore=0
 phishscore=0 clxscore=1015 impostorscore=0 priorityscore=1501 spamscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2411120000
 definitions=main-2501140043
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=aXbBkGUg;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
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

KCOV_TRACE_UNIQ_PC and KCOV_TRACE_UNIQ_EDGE modes can be used
separately, and now they can be used together to simulate current
KCOV_TRACE_PC mode without sequence info.

Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
---
 kernel/kcov.c | 14 +++++++++-----
 1 file changed, 9 insertions(+), 5 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 5a0ead92729294d99db80bb4e0f5b04c8b025dba..c04bbec9ac3186a5145240de8ac609ad8a7ca733 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -716,6 +716,8 @@ static int kcov_close(struct inode *inode, struct file *filep)
 
 static int kcov_get_mode(unsigned long arg)
 {
+	int mode = 0;
+
 	if (arg == KCOV_TRACE_PC)
 		return KCOV_MODE_TRACE_PC;
 	else if (arg == KCOV_TRACE_CMP)
@@ -724,12 +726,14 @@ static int kcov_get_mode(unsigned long arg)
 #else
 		return -ENOTSUPP;
 #endif
-	else if (arg == KCOV_TRACE_UNIQ_PC)
-		return KCOV_MODE_TRACE_UNIQ_PC;
-	else if (arg == KCOV_TRACE_UNIQ_EDGE)
-		return KCOV_MODE_TRACE_UNIQ_EDGE;
-	else
+	if (arg & KCOV_TRACE_UNIQ_PC)
+		mode |= KCOV_MODE_TRACE_UNIQ_PC;
+	if (arg & KCOV_TRACE_UNIQ_EDGE)
+		mode |= KCOV_MODE_TRACE_UNIQ_EDGE;
+	if (!mode)
 		return -EINVAL;
+
+	return mode;
 }
 
 /*

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114-kcov-v1-3-004294b931a2%40quicinc.com.
