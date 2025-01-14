Return-Path: <kasan-dev+bncBCLMXXWM5YBBBSHPS66AMGQEK7HJS2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D114FA10061
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:36:09 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3ce7a0ec1easf4567765ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:36:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736832968; cv=pass;
        d=google.com; s=arc-20240605;
        b=cQ8Xsnu5xzLa+GFGCr7D9OGvaLTSBfLPRmBjqLJss1n85awxlATz48WnhIJRnE0vOq
         TWRaK+HG2neLBeqgqz0S584LaZ+Rw2hz4ButFs0fK/GCn1gTwOLnzNInmpzcrvVz3S5i
         drpM44C0jG/JtQEO8Fm5raJx9HsZwMf+CJq5aiH4+nRMlJ9YE+u/4hlkvoj605OUIFCu
         TTGdD3SF7B+V4Cke1CyZFcX+0yCmBiPt15WuyNANIukm/PKxPKK/AhAjb44VX5vNa4ca
         ftGSzTp2iQgldPLHkMjN49ssMDo8x0BerR2XhySAHpWyGXM5MgN+jB2r9YDwCPBUvmuB
         Whuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=I078gj+ySaRAbHIwXYULiuI+Qb1jJBcVvBKnh2Qh09A=;
        fh=MBifqUfpcFQ3P1OJ5G8iI/jMxHTGucfGSXxFXvQo8A8=;
        b=PyL5iukNmIzHOC6vL3kJlywnxtpncn7Svy1YVql0FdA2UaJaADFgwQSpopsjoVJdUJ
         tbvvuQokvVySBsEdTUZFFWR1PW0lug/EhxkgQExWbKUHfPGW7CpedPfM8FyHQ941rEc2
         HWvJa4DXcT+p65FwY+du3qJio36ua2G+tNiaKYv3ZNV3X/oWiXsFxrIjiaaJBBE8qyFA
         /S/FT+tz65fM0p6QnEvGmV68mOSKL+RC9b/98qokZsvf8IeWYs1zVhjusiAkZaZ1E+81
         GvUrqgCuSexit81CFTJMZd/7yd0A7tSH8jqmQZ0FHKT7IgYCCMeVhvmuClIZqRFvIMEk
         YhKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=iXWopfu7;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736832968; x=1737437768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I078gj+ySaRAbHIwXYULiuI+Qb1jJBcVvBKnh2Qh09A=;
        b=qx8LdcQrsqpjj44QlUQOr7JkMACB7bAZxP/fxpmZKtYYd4d7k2C6cTLwb+O2Q/8Rfy
         oNUAUudXgOFv2incUB/qalEmSdQm86oX5rrm/Ql4mEtUnuFey8QeJGOKZx01V8q0yX5t
         5NZ4N3msbok1ddpFpf65YXEwHeFboA3xqTh9uBr4xop9f5h4PvoRp++uSEAw6ko6cZvd
         QJYAsAZOuBqKcegpzE2SwYCgw/ttP8uyHi4TtadUovEIhfe+Xj9kkHNKf1g0snfbUG3u
         gQXOPk9786P4Xp4NbmGNTvvobH9uypTsKlrGu2twnhWUmj/eh0yUY5s8FSFJ+rF6NiLy
         Sd9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736832968; x=1737437768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I078gj+ySaRAbHIwXYULiuI+Qb1jJBcVvBKnh2Qh09A=;
        b=nngvDyiUN2r/vwc3BIF/VchxJWlGlEYXPSstQxq5AHxZAwpl3j1CPztDYpfEgwLJPx
         BX4NoNQCxA7Xio7IXh+ME/ymolN0ebwsDwcyPqJjm8VG+Rzsw54d36eiZw021fimEprV
         q5OvZssFTONQC1GnSb+a8a6Ar7rniQPY749fQzZwJl749LVS5RaCmjtJlmjtKF0CBcLd
         HpsoO6hXSURr4wyFBeaY+2vUukHLTezCSDUoPlGge/L2Cr4I70X3rqsc8voeAJ6NWXpH
         Mwg9hZE3rzpGr4Br8vGl/e0742qaSey9v6VpTLxSoxfnnv/315qxyePhp1syJ1c+tOnh
         I6tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUfkGUP5xhQ/L4qCvEKHDtWTFnriKeuwpfH3urDDB02UVlSJFu/PB5dsCuNjLmOD3NBQtIA5g==@lfdr.de
X-Gm-Message-State: AOJu0Yw7NmECzWH2/i+DuCBQaJGy50IOTAZ56gtCiGofWQfjwjs0MsYq
	DzfNrFcl96S4vPXxyKdBnyomLkXL5QM/6d3Ysy9dj8v03Q76Atyk
X-Google-Smtp-Source: AGHT+IHm53crw8Y5JFvgvUmN4P16Sps+SpezXNaMGXxhugkn0JWnl8LIGbifiQIDVfxOuTe+vxagmQ==
X-Received: by 2002:a92:c9c6:0:b0:3ce:64a4:4c44 with SMTP id e9e14a558f8ab-3ce64a44e2cmr60796095ab.1.1736832968635;
        Mon, 13 Jan 2025 21:36:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3cc8:b0:3a8:1477:b10a with SMTP id
 e9e14a558f8ab-3ce473e197bls2872035ab.0.-pod-prod-06-us; Mon, 13 Jan 2025
 21:36:08 -0800 (PST)
X-Received: by 2002:a05:6e02:1f89:b0:3a7:8cdd:c0d2 with SMTP id e9e14a558f8ab-3ce3a7a9681mr169460965ab.0.1736832967860;
        Mon, 13 Jan 2025 21:36:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736832967; cv=none;
        d=google.com; s=arc-20240605;
        b=ClAt53xz9LadqAs/+xh+CZDuJGQ9TUpeY2queXN1HLgbImqJDmKe91w5e0ZTEF3Id0
         r321M/LvcymmvBWUaLBMrO840GPuQVokduo1JPAPMVwKmy/hU6deOhMYYn9n4azf9DyF
         ZHPPPJIZoVGgMQb0rgsNjW+ffy05o91PWpZEO1XVB4b+vHlX/dlGfKKu401yu/R8jhb6
         As4fX/lfwhooBkVtbV4ewI3aeonHrznOox1nkPhGro2hM7fyaLywxU+peDJi456W0SLS
         +9BcTPGSIr28OwpY59AxYB23bxenpGWzCZD80FMOlRmv71pI591dtiZcfEJx7P07Mnmz
         v9VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=drhXWUnxNp13ZTiPp3leq5WA8tzUkJEr4CWQ0Yv1pZw=;
        fh=IrFMU56A0U8g6WEnzuhC3mVEK/1VXa8G0j09OJ6Nq3U=;
        b=Y2/jICDews82HRdL5dmwWXtYM+G0K1+N3Qj6dp07IbRxPyejPMF1AkaVwllVeEtIr5
         oq18pJN06Jh1qr2My7QwNtRGrQKzW3/B5CKPuZ2eXe/hrzJayQUjEY+3elrLHm/vKNAv
         Yc7BgQZw/uD6Ho29zAiUDb3L077U1VbqtLItvxkDDWCpGLlB7AFCiA8B9+h7tvDiKLV+
         tUOYT8FIw/TNvdRTQfwjKNL+oQ55rhq0+v76DTFoIrQL4SbQpmEOEYGfkCn0KJX5rvwa
         oBTP9OwNnqk+0m1vwL6kw93XWPxAcAEioVPF4xmKOvF5yrMJbcwHq/oR30/cgUCIs8B/
         lmeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=iXWopfu7;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ea1b5ea9f9si378935173.2.2025.01.13.21.36.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:36:07 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50DH3oqq020410;
	Tue, 14 Jan 2025 05:36:03 GMT
Received: from nasanppmta01.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 4456wa9fhh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:03 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA01.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5a28k020523
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:02 GMT
Received: from la-sh002-lnx.ap.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:35:56 -0800
From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Date: Tue, 14 Jan 2025 13:34:34 +0800
Subject: [PATCH 4/7] kcov: introduce new kcov KCOV_TRACE_UNIQ_CMP mode
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20250114-kcov-v1-4-004294b931a2@quicinc.com>
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
X-Developer-Signature: v=1; a=ed25519-sha256; t=1736832942; l=6956;
 i=quic_jiangenj@quicinc.com; s=20250114; h=from:subject:message-id;
 bh=87rus4o59M/h6mbCeTYN+uwPYg3Cu8v5VQQt/ES6TT4=;
 b=dLbyxsjISwicFnHI2UlW7HXO0FqBJGbKRAtWrXffXPrseH1onOKQ7Uil5a0dOqyIK0G9Sonh3
 Af14LF0A5HiDGL5/ZS9Y7gv/n6tgLyBJ6vxQua47w0wN4Ujd1sTIXzx
X-Developer-Key: i=quic_jiangenj@quicinc.com; a=ed25519;
 pk=JPzmfEvx11SW1Q1qtMhFcAx46KP1Ui36jcetDgbev28=
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: -qyd1GNp6Gcg_3HTW0CFg-UHDCJbFmyY
X-Proofpoint-ORIG-GUID: -qyd1GNp6Gcg_3HTW0CFg-UHDCJbFmyY
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 clxscore=1015
 suspectscore=0 adultscore=0 mlxlogscore=734 priorityscore=1501
 phishscore=0 malwarescore=0 impostorscore=0 lowpriorityscore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501140044
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=iXWopfu7;       spf=pass
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

Similar to KCOV_TRACE_CMP mode, KCOV_TRACE_UNIQ_CMP stores unique CMP data
into area.

Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
---
 include/linux/kcov.h      |   2 +
 include/uapi/linux/kcov.h |   2 +
 kernel/kcov.c             | 112 ++++++++++++++++++++++++++++++++--------------
 3 files changed, 83 insertions(+), 33 deletions(-)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 56b858205ba16c47fc72bda9938c98f034503c8c..a78d78164bf75368c71a958a5438fc3ee68c95ca 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -27,6 +27,8 @@ enum kcov_mode {
 	KCOV_MODE_TRACE_UNIQ_PC = 16,
 	/* Collecting uniq edge mode. */
 	KCOV_MODE_TRACE_UNIQ_EDGE = 32,
+	/* Collecting uniq cmp mode. */
+	KCOV_MODE_TRACE_UNIQ_CMP = 64,
 };
 
 #define KCOV_IN_CTXSW	(1 << 30)
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index 9b2019f0ab8b8cb5426d2d6b74472fa1a7293817..08abfca273c9624dc54a2c70b12a4a9302700f26 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -39,6 +39,8 @@ enum {
 	KCOV_TRACE_UNIQ_PC = 2,
 	/* Collecting uniq edge mode. */
 	KCOV_TRACE_UNIQ_EDGE = 4,
+	/* Collecting uniq CMP mode. */
+	KCOV_TRACE_UNIQ_CMP = 8,
 };
 
 /*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index c04bbec9ac3186a5145240de8ac609ad8a7ca733..af73c40114d23adedab8318e8657d24bf36ae865 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -36,6 +36,11 @@
 
 struct kcov_entry {
 	unsigned long		ent;
+#ifdef CONFIG_KCOV_ENABLE_COMPARISONS
+	unsigned long		type;
+	unsigned long		arg1;
+	unsigned long		arg2;
+#endif
 
 	struct hlist_node	node;
 };
@@ -44,7 +49,7 @@ struct kcov_entry {
 #define MIN_POOL_ALLOC_ORDER ilog2(roundup_pow_of_two(sizeof(struct kcov_entry)))
 
 /*
- * kcov hashmap to store uniq pc, prealloced mem for kcov_entry
+ * kcov hashmap to store uniq pc|edge|cmp, prealloced mem for kcov_entry
  * and area shared between kernel and userspace.
  */
 struct kcov_map {
@@ -87,7 +92,7 @@ struct kcov {
 	unsigned long		prev_pc;
 	/* Coverage buffer shared with user space. */
 	void			*area;
-	/* Coverage hashmap for unique pc. */
+	/* Coverage hashmap for unique pc|cmp. */
 	struct kcov_map		*map;
 	/* Edge hashmap for unique edge. */
 	struct kcov_map		*map_edge;
@@ -289,14 +294,23 @@ static notrace inline void kcov_map_add(struct kcov_map *map, struct kcov_entry
 	struct kcov *kcov;
 	struct kcov_entry *entry;
 	unsigned int key = hash_key(ent);
-	unsigned long pos, *area;
+	unsigned long pos, start_index, end_pos, max_pos, *area;
 
 	kcov = t->kcov;
 
-	hash_for_each_possible_rcu(map->buckets, entry, node, key) {
-		if (entry->ent == ent->ent)
-			return;
-	}
+	if ((mode == KCOV_MODE_TRACE_UNIQ_PC ||
+	     mode == KCOV_MODE_TRACE_UNIQ_EDGE))
+		hash_for_each_possible_rcu(map->buckets, entry, node, key) {
+			if (entry->ent == ent->ent)
+				return;
+		}
+	else
+		hash_for_each_possible_rcu(map->buckets, entry, node, key) {
+			if (entry->ent == ent->ent && entry->type == ent->type &&
+			    entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
+				return;
+			}
+		}
 
 	entry = (struct kcov_entry *)gen_pool_alloc(map->pool, 1 << MIN_POOL_ALLOC_ORDER);
 	if (unlikely(!entry))
@@ -306,16 +320,31 @@ static notrace inline void kcov_map_add(struct kcov_map *map, struct kcov_entry
 	memcpy(entry, ent, sizeof(*entry));
 	hash_add_rcu(map->buckets, &entry->node, key);
 
-	if (mode == KCOV_MODE_TRACE_UNIQ_PC)
+	if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_CMP)
 		area = t->kcov_area;
 	else
 		area = kcov->map_edge->area;
 
 	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_size)) {
-		WRITE_ONCE(area[0], pos);
-		barrier();
-		area[pos] = ent->ent;
+	if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_EDGE) {
+		if (likely(pos < t->kcov_size)) {
+			WRITE_ONCE(area[0], pos);
+			barrier();
+			area[pos] = ent->ent;
+		}
+	} else {
+		start_index = 1 + (pos - 1) * KCOV_WORDS_PER_CMP;
+		max_pos = t->kcov_size * sizeof(unsigned long);
+		end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
+		if (likely(end_pos <= max_pos)) {
+			/* See comment in __sanitizer_cov_trace_pc(). */
+			WRITE_ONCE(area[0], pos);
+			barrier();
+			area[start_index] = ent->type;
+			area[start_index + 1] = ent->arg1;
+			area[start_index + 2] = ent->arg2;
+			area[start_index + 3] = ent->ent;
+		}
 	}
 }
 
@@ -384,33 +413,44 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	struct task_struct *t;
 	u64 *area;
 	u64 count, start_index, end_pos, max_pos;
+	struct kcov_entry entry = {0};
+	unsigned int mode;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
+	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP | KCOV_MODE_TRACE_UNIQ_CMP, t))
 		return;
 
+	mode = t->kcov_mode;
 	ip = canonicalize_ip(ip);
 
-	/*
-	 * We write all comparison arguments and types as u64.
-	 * The buffer was allocated for t->kcov_size unsigned longs.
-	 */
-	area = (u64 *)t->kcov_area;
-	max_pos = t->kcov_size * sizeof(unsigned long);
-
-	count = READ_ONCE(area[0]);
-
-	/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
-	start_index = 1 + count * KCOV_WORDS_PER_CMP;
-	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
-	if (likely(end_pos <= max_pos)) {
-		/* See comment in __sanitizer_cov_trace_pc(). */
-		WRITE_ONCE(area[0], count + 1);
-		barrier();
-		area[start_index] = type;
-		area[start_index + 1] = arg1;
-		area[start_index + 2] = arg2;
-		area[start_index + 3] = ip;
+	if (mode == KCOV_MODE_TRACE_CMP) {
+		/*
+		 * We write all comparison arguments and types as u64.
+		 * The buffer was allocated for t->kcov_size unsigned longs.
+		 */
+		area = (u64 *)t->kcov_area;
+		max_pos = t->kcov_size * sizeof(unsigned long);
+
+		count = READ_ONCE(area[0]);
+
+		/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
+		start_index = 1 + count * KCOV_WORDS_PER_CMP;
+		end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
+		if (likely(end_pos <= max_pos)) {
+			/* See comment in __sanitizer_cov_trace_pc(). */
+			WRITE_ONCE(area[0], count + 1);
+			barrier();
+			area[start_index] = type;
+			area[start_index + 1] = arg1;
+			area[start_index + 2] = arg2;
+			area[start_index + 3] = ip;
+		}
+	} else {
+		entry.type = type;
+		entry.arg1 = arg1;
+		entry.arg2 = arg2;
+		entry.ent = ip;
+		kcov_map_add(t->kcov->map, &entry, t, KCOV_MODE_TRACE_UNIQ_CMP);
 	}
 }
 
@@ -730,6 +770,12 @@ static int kcov_get_mode(unsigned long arg)
 		mode |= KCOV_MODE_TRACE_UNIQ_PC;
 	if (arg & KCOV_TRACE_UNIQ_EDGE)
 		mode |= KCOV_MODE_TRACE_UNIQ_EDGE;
+	if (arg == KCOV_TRACE_UNIQ_CMP)
+#ifdef CONFIG_KCOV_ENABLE_COMPARISONS
+		mode = KCOV_MODE_TRACE_UNIQ_CMP;
+#else
+		return -EOPNOTSUPP;
+#endif
 	if (!mode)
 		return -EINVAL;
 

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114-kcov-v1-4-004294b931a2%40quicinc.com.
