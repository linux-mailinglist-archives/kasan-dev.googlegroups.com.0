Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBP4E5KZAMGQEEQ3W4VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 10AA68D6D71
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Jun 2024 04:06:57 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5b9b5e39e9bsf2142399eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 19:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717207615; cv=pass;
        d=google.com; s=arc-20160816;
        b=rlfVWuE7ic21qWAqvRGDPo7fHgXNS81gjio7FkOde7priTABBCncP/0g3352mlHa35
         2TNPjhFzc2JuAVLxLJ9fdo9Q6ir7eTxSVwgpz3HGWW1nclFa0YjEcifL+P+LYW6uVpAI
         SnYjs7WP/tNkgA8aD4XytL6nCa5cUCYi2L/TLJrxw4hGp/OmOFqGb/3yCtAgX/1rCsC0
         5Th8ILdLRK5cnH+36YjxswcExICYhHqO812d9IarNk5pfXPjZzk/CfxVkpBS5YNKRcli
         UA2wOfqj4IzFkF+ei93dY2H9QZZGBw7wDa5MRKD9DwVn5gmHAemt1svplQsd0DKMBywz
         ovyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=ELWh6MjVVdFN1dm0/TdTGYrGng0NckKb4rf1st0bAS8=;
        fh=jezfN/yrEpDbb27QlZyOoypqzz08mlALngEH/cTHG/s=;
        b=IJq5zG/dDQnRuWbZkNInAQku/fT0I/fj/vqji6IXiKyBF8k0ZRNX2PX73c+VezSItF
         hnnpfq0C8IvVFbOcYWKmVWkqxiR+V0B44SMa2HZcDOAIWhg9pLTNei0NYg27yH5vyIh7
         HukHJbG5wVhd9tglvr1rbfNH1YmQMoxasRGvPEhCD+kLzYnzWE6QiAc4sYnunAzQ65lv
         u17K10SKImBLyxKgX5CqldYgDTyWGurGXjzkj1qCI9X5E3kZP0z4ob6CG7CSguIlreAV
         QLOUxuLMtc2cxXbhEzm6/rav5STjtCH2nuHtXFhveT97wUb6kQP5Vf6hrjm5pucQEV+A
         jmlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="cX42ucI/";
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717207615; x=1717812415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ELWh6MjVVdFN1dm0/TdTGYrGng0NckKb4rf1st0bAS8=;
        b=Qn9VlnFn/w9qC0Kz5kKeJPsAL5D8jYz0fiv4V/I5tUK1RnJ0ImFsuvyV9XfRyFeadg
         SyfO7cY3Vx4XkO5unNFwq8lopQzMNVugXviF+tEfN51ytWAmeulX9o3zacI8PfUe/6fL
         gWfBi309NeKJXDxxg5b0k0EBwnczNsE0AoPqz6s8zEg/oFBQElw+T0aYHB/Zg6TK2qsq
         2HkQrRrrkGfzEl/P4dYkDvp9Dx8GWjLrX9K38FFH95OBf1uOFp/M2jQo7PTa22CS+EFh
         XLI3HfvLrn7m63z5/vgMlSi8hZVl+6PxUDXBMtt307Cw+MP++7xo09knwshIZe1FggKE
         K4gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717207615; x=1717812415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ELWh6MjVVdFN1dm0/TdTGYrGng0NckKb4rf1st0bAS8=;
        b=kwqf0xuDQL5WJUjoEYZKG1jjLt1xqGehnNO7SPNb40Wo95Gom21k0HcIsg9DPfgs1X
         U4rRoNjagyYywjH8U9LHWHCDDdYi3NZp4BC4xTw0TVf7FdAuy5FDq4qSzmS+lKnuEfXG
         taOU1m4a4GVLDV5TDyh19S2LBw8WPm3YYSUCT9RxX2J24QWeTI5SgHi+hwUlq6fXS6D9
         s49It+MhaOEBixwaDxSA2cley6fuhBfILTApbmRTyEOXFbqVujAqf3FNtMIYHr/i6hES
         mF37Aemb3i2JU79BpkYV+g55YpdmpTlvdTZdjjUi8FPOKr0wGLkTHKvkwdc9TbdL57ZO
         mMpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVG7kOi2ozFr1oXJsShuGBUapqd/1hkBcIgFZuc1Btn+jShaHHIyDRyg4HSOKMFJQvMM4bOJ+sxHJyYjcdYlIReoZyQdsWbQ==
X-Gm-Message-State: AOJu0YzLV8BzbPGAHFPV8KWeNvu+kAvCB81Dsjh7RX+diDYLAoexijaR
	JXRGJTNjxo4CVGRA18Ikig5ZH2QU+zMIJe1WA5zL7WOQyAB1Elh/
X-Google-Smtp-Source: AGHT+IGjzRzbV0lCKcheJ6n6M1+nmGPMGrwAVIdGoMiY7NGvmKPoeSCh1CU8IgVFnkXczD+Kj5JvnQ==
X-Received: by 2002:a4a:d88f:0:b0:5b8:80f1:934 with SMTP id 006d021491bc7-5ba05d87709mr3030475eaf.9.1717207615548;
        Fri, 31 May 2024 19:06:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:abca:0:b0:5af:c4b3:9d4f with SMTP id 006d021491bc7-5b9ea8953c2ls1311328eaf.2.-pod-prod-06-us;
 Fri, 31 May 2024 19:06:54 -0700 (PDT)
X-Received: by 2002:a05:6820:82c:b0:5b9:d2de:ade2 with SMTP id 006d021491bc7-5ba05413c79mr3912416eaf.0.1717207614598;
        Fri, 31 May 2024 19:06:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717207614; cv=none;
        d=google.com; s=arc-20160816;
        b=V27p9beo2fUjU6J6NHo1qqCxgrCMe3voC05Wf4XAVkjI9o0P8P5IwRXJngw1vCAm6P
         BYiPwHDA1nBQv8T82exernlSqoORZUk9pIRv8sZ1VIZZtHCPCmygPfAqag+s1NN1bYBX
         ODuZY8O8vWGz6P5tq+4mgV4lE8PXhtRBd7tpiKBGn5npvLSzt8IzRXJunGqq5O1y6Gh+
         8lrbGzdORNo8zngys8AIpZ/ulcSRKl1uVjc+lcBu8X5WaDg0g9rmaFguN8Z4xsTqBVBT
         xhXoGrqxHRhlukPUFozyAbqe7sAw6GpKosHh0OknjTvemrrfS70f+IGbo/0h5w0SbJ+w
         rjPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=mQNOrNlJBOfvXJ16Q5dYxv0u9N5NbtCaHvP2WMeYy0o=;
        fh=ey30KnJOMRePVcc9aBuMzenZgBuJHiWl07Tsx5jq5D8=;
        b=JQmHCInc1vCagnLVy4eyulDk7rBpvjUrwicoBbVE4+Ddh989i/+VNN3Yp08XJ1iLow
         tcMmsCG8w5kuV7EwTflpEH2w88DvIHVPY+JQkLQreMc/Nv3bKJQcad9r15j0AEADUwlD
         Q6fMQ6JUsZeDtirmOi41vkGZ20gGsns6O1WMpFzMlGBdy4aK2U5u8Kwvz1SrLHSGoRvo
         aPwkWvA27VXxSQF545asBvPtbgKo9kqNL/vYXaWK4hnm/QpnTIxRhOVDDCZ0ZJzLwZs4
         zpI1gGMrkTETpt5oVi/GsOaeOL+j6WnneuhdTtqjePNM4G5JFgLR1Ir2R7e0Pa4doWlv
         SQTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="cX42ucI/";
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5ba004b16b5si153686eaf.2.2024.05.31.19.06.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2024 19:06:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279863.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44VGeT3v022112;
	Sat, 1 Jun 2024 02:06:51 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3yfj9d97b8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Sat, 01 Jun 2024 02:06:50 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 45126nPI013007
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Sat, 1 Jun 2024 02:06:49 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Fri, 31 May
 2024 19:06:49 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Date: Fri, 31 May 2024 19:06:48 -0700
Subject: [PATCH] ubsan: add missing MODULE_DESCRIPTION() macro
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20240531-md-lib-test_ubsan-v1-1-c2a80d258842@quicinc.com>
X-B4-Tracking: v=1; b=H4sIADeCWmYC/x3M0QqDMAxA0V+RPC9QnVvHfmXISGucAe1GUkUQ/
 33dHs/DvTsYq7DBvdpBeRWTdyqoTxXEkdKLUfpiaFzTusu5xrnHSQJmtvxcglHCEMkP1xs57zy
 U7qM8yPZ/PrriQMYYlFIcf6dJ0rLhTJZZ4Ti+TyP834IAAAA=
To: Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
        "Andrey
 Konovalov" <andreyknvl@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-hardening@vger.kernel.org>,
        <linux-kernel@vger.kernel.org>, <kernel-janitors@vger.kernel.org>,
        "Jeff
 Johnson" <quic_jjohnson@quicinc.com>
X-Mailer: b4 0.13.0
X-Originating-IP: [10.49.16.6]
X-ClientProxiedBy: nalasex01c.na.qualcomm.com (10.47.97.35) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: Xj-dqjCY6hcxigd6yxhJKqMMseUSsBJa
X-Proofpoint-ORIG-GUID: Xj-dqjCY6hcxigd6yxhJKqMMseUSsBJa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.12.28.16
 definitions=2024-06-01_01,2024-05-30_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 priorityscore=1501 impostorscore=0 lowpriorityscore=0 clxscore=1011
 bulkscore=0 suspectscore=0 mlxscore=0 malwarescore=0 adultscore=0
 mlxlogscore=968 phishscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406010013
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b="cX42ucI/";       spf=pass
 (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.168.131
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

make allmodconfig && make W=1 C=1 reports:
WARNING: modpost: missing MODULE_DESCRIPTION() in lib/test_ubsan.o

Add the missing invocation of the MODULE_DESCRIPTION() macro.

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
 lib/test_ubsan.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index c288df9372ed..5d7b10e98610 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -156,4 +156,5 @@ static void __exit test_ubsan_exit(void)
 module_exit(test_ubsan_exit);
 
 MODULE_AUTHOR("Jinbum Park <jinb.park7@gmail.com>");
+MODULE_DESCRIPTION("UBSAN unit test");
 MODULE_LICENSE("GPL v2");

---
base-commit: b050496579632f86ee1ef7e7501906db579f3457
change-id: 20240531-md-lib-test_ubsan-bca7f68a0707

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240531-md-lib-test_ubsan-v1-1-c2a80d258842%40quicinc.com.
