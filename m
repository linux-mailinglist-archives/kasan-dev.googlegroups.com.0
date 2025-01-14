Return-Path: <kasan-dev+bncBCLMXXWM5YBBBU7PS66AMGQEFWC7CXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E1BF4A10065
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:36:20 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e54cb50c3basf12920701276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:36:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736832979; cv=pass;
        d=google.com; s=arc-20240605;
        b=BbtFnnYUhw95/n7q8eZJhUFwLgWQ0VztkbblsLtifHR5ZepY0XqOyBbwAfO/1d8ED3
         FpyNyK9B0eJiuGoVSChvtHPieYwQRowW/TJhheE+MuNppFxvs6HQMQMV+Pg0PJU3am1r
         zjJI00i3C6+fMh6jcHHMMIQu0BQ+cw/s3XQu0I1hI5uAzKOYMzkqsj2dp5ASAc+J7rhQ
         3g8DIryPclgiyfLZMwhw+CcrfcVbx/3+gX8chVX7ajd6824W2MMy48iOTPwA8HgM3bmb
         izG5tvMDZpHalhNBLAr965DO7oYMV93hoKcVTVP8jkW7qWmFL39oLrw7k8weryBdY7pT
         kWyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=ULHd7kflCu/p0h6IqrFHJZpuaCb3J22QtiuGOBSVDJc=;
        fh=ujqFCZxwz7ZBXesmO2BzCbgmJCMo9fD4PGsJMljBJ9M=;
        b=GeuWoTbhRDyNN5DDB/HClZnWxJ0Q6AGoZXYiocXFMERKK/PTaDXzG1Gsy4faYzsOqo
         TbvBGJI3SU7GhrjO7pzbRVKc6/DNmHFMZxdgWfP3p19hHZlgaa9Wqy80nv1zNPlDcIYV
         dfn7LghCep68CMz0hQBeJjYv/6JI/lnNO958JifyDvYS6cpwMvrtwpoNQ8McT1qvFq2A
         +w6xM4KTSFF4pL13JdNC6n8AAjrHpMpGwGe1buPScUP0t/0LmylTUkZG6e9DrhDab3Gv
         Cn205lWZgsWcRbpy9DYzpjB5RKsOSNFy8zEn6wKaL8YzF9XfEGAsltWMzcUoh/O9swRt
         evDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=HikSzvI7;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736832979; x=1737437779; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ULHd7kflCu/p0h6IqrFHJZpuaCb3J22QtiuGOBSVDJc=;
        b=tb8YnIlQdhkLo+EgLviDe+4/BVPaREVXVBmdRkOFoSa4DkIntvxj0S4ldVPVM82WGo
         GfcuW19CfevV/5Q3eBYed8DPj6wIIyARwIzcubT6yFPEiF8ydwVfg36DtqBIHTqcRHLh
         qH0POsOi3JvrbQeAzkBzWBQq7WomuTXpvXPJPZaeY+zDydtclwd085Gs4jO+vjI3jluX
         0npSYuinLxzBpVFz+ZS0VWDspOVDI8opPcuNL9vlDPTOVnUsMdxSyyxQY3B1aeRdBTGw
         SjNX9MiqwddbeAovCwQZYITBN+jVSu0hrLZeQDaFlHaYu/f9TPdNEyUxd3QcXq3GX7Tj
         Cy8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736832979; x=1737437779;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ULHd7kflCu/p0h6IqrFHJZpuaCb3J22QtiuGOBSVDJc=;
        b=jYzOi3NK4nYSyAXy5eDHNZM9A8I4kC9lfn91SpUYkikyMP3fNTtaHkp2R0UqDw+vrQ
         iz5ufJgn02QlcnFMk8VOAkP9Nb0CcgSsfSx1BKJlMpaSOpGbvApwjoBOBE3kQv04qvsi
         TI1Frvw6SCTVDip8RnCEVtGCcDhzJvaINxQhKfyBBZOre2ojOkVT7elzrV+6BXFr9izz
         d1AM4qtBUFmANLpiaC3HQ1eVTQ5v0nr+fv3lkDMPg9dPI91gfL1Sy6qp89xt7nx9lNQQ
         fGfo5zEu+9EaKsWWpqExo6ZnRPE/KfBr8zAGweNeCz49xLoJTTAza8tR7Z6Q9lVAXdvS
         xeeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeEzbZWy3wCRyPbQf60yQe3xdtGT1H71VA/YbPiLFhI91XdgydYrEybm5Ec6gQxKfalhwnlA==@lfdr.de
X-Gm-Message-State: AOJu0Yw17SPUrGoX+WEYO0ZCiSllrfGvYk9XAniEqTzp+hqJJvEW5+ox
	U3IMv9bF43R0pUJwZmfxv1oXUZR52p2WlwxV4Wt1Tueik/EAWEQA
X-Google-Smtp-Source: AGHT+IFy91u7Tvh5VQlV8/llnp+9683VNSFWC9NB623Au6vNlCPNbYC9afD5H1l17DUcypGbSlepMw==
X-Received: by 2002:a05:6902:2e84:b0:e4e:32d6:e9f2 with SMTP id 3f1490d57ef6-e573a6ee614mr6977715276.6.1736832979678;
        Mon, 13 Jan 2025 21:36:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d816:0:b0:e57:281d:8823 with SMTP id 3f1490d57ef6-e57281d8ccels1515501276.0.-pod-prod-00-us;
 Mon, 13 Jan 2025 21:36:19 -0800 (PST)
X-Received: by 2002:a05:690c:6f06:b0:6e2:1c94:41f8 with SMTP id 00721157ae682-6f5494ea761mr147388147b3.10.1736832978923;
        Mon, 13 Jan 2025 21:36:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736832978; cv=none;
        d=google.com; s=arc-20240605;
        b=iaa/l+Y6t2MFUfZ8vC9NJbjB4VJvnMZ02wkzFXcHXTT+XldfY5qf6mQCtOu6Sg6j69
         vYabsZroB7zW98adyf7wHqCYEk+1aKlW4W1Q0vugWHxXcr6/L0STCyYlhNwShMyneilV
         Sp9zqfWfdO6Izhvqn480iHxZzNExu2bIWOcWJZRSsbrMbp3JF3sqZ+wrDSK6v6lyX7P3
         bW4M5vqMwIQaHMnbnQqec7Q0elmTOQDFMSll4pCH2d5qebFzRL6yzLpSQL1Pg4sQjgrP
         r22ls+GjvNeEbwrMMiighPkxZHo+lJbb91TE59BKe0cCbd5xoNxi2cyozGbqywR5XjEQ
         LkHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=/Ra3dSoqbIv2eF9zoZUbyQQPjXpOzfwJvCpeTMxHEKs=;
        fh=IrFMU56A0U8g6WEnzuhC3mVEK/1VXa8G0j09OJ6Nq3U=;
        b=jqNZq3Ml2QNgQ8iTbhs80kHMy0iATtVeijf9CaVHVEpxp493MIZdtmtJa6AW7zr8vB
         ELsJvmzHFgZltpdITpnIubnLkl9jt53PD5XuuEgbi1rj5Lu472vcaQ8HtoBK+O/AF+w8
         KcsWB5MtJ2ayxDIvqOLl2eu+oBrIaUCsY7anwzsMHhmH0dt8shBldVFVXo2Uf1TRrq+H
         +lrCEy9xGs2w4kbvr0EJChSrENQg101YHZ0zs1G5bbF8migNC7JeK1oPZhDi7hLEUsNY
         jmWiT6DDULbq4TlXG+HxAkUAiBwWS+5r5xUlAUDxff+YMjL73vbfGV5Jj6KNHyJJZELm
         jgow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=HikSzvI7;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f692e37d22si2798587b3.1.2025.01.13.21.36.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:36:18 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279867.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50E40bZB020725;
	Tue, 14 Jan 2025 05:36:13 GMT
Received: from nasanppmta05.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445gh60526-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:13 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA05.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5aCok016202
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:12 GMT
Received: from la-sh002-lnx.ap.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:36:06 -0800
From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Date: Tue, 14 Jan 2025 13:34:37 +0800
Subject: [PATCH 7/7] arm64: disable kcov instrument in header files
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20250114-kcov-v1-7-004294b931a2@quicinc.com>
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
X-Developer-Signature: v=1; a=ed25519-sha256; t=1736832942; l=1362;
 i=quic_jiangenj@quicinc.com; s=20250114; h=from:subject:message-id;
 bh=1kWeMy8H18bHx7q6bxqI4S7xMp8TmEXRvurq+o8jSTk=;
 b=zPdx/wsH9uf3YlAIvy013JGGUIrnRUGzN+n5UmShLK05sjrO5Bv+UKhmFiYiSigdphGdNZ4mt
 wlcCgEsIO2HASI15aSluF7QMoXny39DoX3F20cozNtGxwEHgHdqrSVX
X-Developer-Key: i=quic_jiangenj@quicinc.com; a=ed25519;
 pk=JPzmfEvx11SW1Q1qtMhFcAx46KP1Ui36jcetDgbev28=
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: SJSYjyfLnYMRCxOaFXFtA289YzGmtz-L
X-Proofpoint-GUID: SJSYjyfLnYMRCxOaFXFtA289YzGmtz-L
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 suspectscore=0 malwarescore=0 mlxlogscore=761 phishscore=0 clxscore=1015
 spamscore=0 lowpriorityscore=0 priorityscore=1501 bulkscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2411120000
 definitions=main-2501140044
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=HikSzvI7;       spf=pass
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

Disable instrument which causes recursive call to __sanitizer_cov_trace_pc

Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
---
 arch/arm64/include/asm/percpu.h  | 2 +-
 arch/arm64/include/asm/preempt.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/percpu.h b/arch/arm64/include/asm/percpu.h
index 9abcc8ef3087b7066c82db983ae2753f30607f7f..a40ff8168151bb481756d0f6cb341aa8dc52a121 100644
--- a/arch/arm64/include/asm/percpu.h
+++ b/arch/arm64/include/asm/percpu.h
@@ -29,7 +29,7 @@ static inline unsigned long __hyp_my_cpu_offset(void)
 	return read_sysreg(tpidr_el2);
 }
 
-static inline unsigned long __kern_my_cpu_offset(void)
+static __no_sanitize_coverage inline unsigned long __kern_my_cpu_offset(void)
 {
 	unsigned long off;
 
diff --git a/arch/arm64/include/asm/preempt.h b/arch/arm64/include/asm/preempt.h
index 0159b625cc7f0e7d6996b34b4de8e71b04ca32e5..a8742a57481a8bf7f1e35b9cd8b0fd9a37f0ba78 100644
--- a/arch/arm64/include/asm/preempt.h
+++ b/arch/arm64/include/asm/preempt.h
@@ -8,7 +8,7 @@
 #define PREEMPT_NEED_RESCHED	BIT(32)
 #define PREEMPT_ENABLED	(PREEMPT_NEED_RESCHED)
 
-static inline int preempt_count(void)
+static __no_sanitize_coverage inline int preempt_count(void)
 {
 	return READ_ONCE(current_thread_info()->preempt.count);
 }

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114-kcov-v1-7-004294b931a2%40quicinc.com.
