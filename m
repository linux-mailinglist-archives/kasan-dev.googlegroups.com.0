Return-Path: <kasan-dev+bncBAABBENS5KVQMGQEBKBTWJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 588FB81272D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:35 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-58d5bb052dfsf8687371eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533394; cv=pass;
        d=google.com; s=arc-20160816;
        b=z8E5Fy4UM75KeO5LPZ1VA41tCbpI61oXtxo49emi7HrIjJJiq3Iud4STfzBjSADs11
         zaeJP89Aukewy4Fkr2IMXGObrtRy7wPNH/PemZEpwtS2M7zy2jNvAnM+Ysmttt3w7W79
         CC2Gc0LBgIANkuHU59MLIw29MLG+5aZPbSRDkFo45YZdj8yTmKF5u1VVIujo9dhUAAJ1
         uSsxNHM2XvSaNGPNGiHO8pzyisJho3MBk5U188wdPrQOAcLZvwzWQRpQ38jzEg4TzGLS
         zvxfIEENCcSkuQgoHbYR8Ki6Vge4ONDI9VR4Da5ebsdS2hSdm4Zb86klOvOEeojdRmQm
         VNKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R8ZIQfwqkoSopCkL9LF40zE/wz1NBpJRbtcrjLOacdo=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=rG1JZzy7QQJpHCOLilarqbM6EWHJEdOTFoKPFFSZg8lYzSyMIzbpYld5lBsgFzpyBh
         2vMAAl5I3MwbZZ+UxUWFsbpB7apL6Wcw5TnvXycCzVfSXIiQzhMWwO1wLWRBwem3d8t+
         kl9eJwxkKJhWkYLMOXm3bj9USskl+NOBGeAxlmpXIic3+HkTPDphTXMEPKOjSKS4nHrr
         sr17PFcxZUIkGyBYiiXfbTySl/VR84e4Bo0QmUOfsdSg55Q3C9Sh+N6Uhl83nAJIHtxW
         V2BJvkIA8AXYEWaVzU9B8Ujm47QAhlVvvGnlusVaeGuDzH+HthunCpsbVDLSuOAoVIco
         42RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kbdN2RUv;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533394; x=1703138194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R8ZIQfwqkoSopCkL9LF40zE/wz1NBpJRbtcrjLOacdo=;
        b=bszA2MimhSrdbqFzSvO0K1uNPjcm8Fe6OgF3JDRFnvwevEzA4zjux/5Ee53Z1EszV/
         1hi6pCpA4jjTD+yNccMi1GQguRrY+q1wsbOdorM2N617ScgGJBlVu2lyf9TzPM1VwbSV
         cpBlTgxFfSKF8cStfVMDi77PLs5pZtRehjPTaJ0nA2x108w3nRElKqLFeezsUsbCq0ac
         qOHFfHxw0bI5NR/Fuzo70C03kHVWwyb3FpqKIWm1RU4TEa7qcgQyGokAZ/zCXkh2ukXR
         I8AhxGnx6meR6oK76nqSYOrijCs41Kqetq8CL6gsYV54om+ECkktRrm8jPArC0mkys5U
         gYKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533394; x=1703138194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R8ZIQfwqkoSopCkL9LF40zE/wz1NBpJRbtcrjLOacdo=;
        b=w6fwtaKKcoHEEgEVedY+pp/4H42mZOATqgNGG/9DsMIqT+mekHEhGLNXl56wLOXSgR
         A4xTxoIgbwr+Uc49V5O03MBDIkynXrgWER1qV6DGvDxSKC0ZknVVYwpxqNcUe9SBt6s8
         DVhDxHB98DYxteXYwq0ZDChHc8iIp8njCaZRdEEttYMVn88lTH0VnBUlYmE+eKMYYB5k
         sV6v/v+xGllQ2W1liyXCrnP/x5GPjJFGOaY0tVCuv/0vGzh7WfHRmu3gnY/Olobsu/ko
         Pyw/3T9kOojkkfdTutCJqFyrvwFdC9pPRzFKLpgdi9aOVwKABrX87lxpSfn9sT1LoqNC
         hQNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxCJDscbRsRlucfCKK2IpnkxY+UXPeIgAAO4I2SEy1D9Xdp3Xrd
	qsYrmgCumdxFTSymeG1CBO4=
X-Google-Smtp-Source: AGHT+IHrcEHZCbipNgL4n6AK76SAvgCTvbCS5f3DeQ0JC/mPfKB4tAh9GXNX1gHF9v7vbw7oDsQn7g==
X-Received: by 2002:a4a:3517:0:b0:590:7706:55d0 with SMTP id l23-20020a4a3517000000b00590770655d0mr8647808ooa.17.1702533393868;
        Wed, 13 Dec 2023 21:56:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:221b:b0:58d:9e35:a9fe with SMTP id
 cj27-20020a056820221b00b0058d9e35a9fels1546891oob.1.-pod-prod-08-us; Wed, 13
 Dec 2023 21:56:33 -0800 (PST)
X-Received: by 2002:a9d:7690:0:b0:6d9:9f0b:ce9f with SMTP id j16-20020a9d7690000000b006d99f0bce9fmr8711846otl.43.1702533393157;
        Wed, 13 Dec 2023 21:56:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533393; cv=none;
        d=google.com; s=arc-20160816;
        b=Q5/uInqJ/2ktBt/6/3sOmXEvmWzR6As75N78X0o+SvFYwuVWFlqxbsnvfgaUA1e8JZ
         e9zgtdL9U1aC8L488zYWTeG1v2Qn1fl2pPsViZjU/mMiXtiCFwLxnhhKsBI5VOk6ZrWr
         zWN0YOY7e52k9Ki3uiZ/QYkhQNldgE/nSoPY3lpTShpYKVFlyoUUS7xWoScDYUqbW00i
         H806iwxalc3n0gszgBii/AI95pQqi6fF3DQn1H7faU6L8bjpyg0K/BqGuCaaVK50zjUV
         J0JwsIv0K4qYo+ObxAyhVkC99lTGj2L26fEZLoKEiMW3Cuuw3vQF2KGUQTJyXUnyUDa1
         3QIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Juc4Y9f1da+QG61OsnOsRxYD8gnzRS0DoClXjZT+6Ac=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=w9/Q+irGxMZLgj0Hs4/EDD7cPYksex1xKYMmIRlW0VmbN/UNevjhBhZ1HqYcD7O/MH
         gCdQcid3zzx6zvwFmbjnxdS1Qozmgl/DfUIDheMeR/QqPrTqfLei72XAYxd4x413JH0U
         xFtSu4d1IauApzuy94YW+ZK+xFRw+7y7Mk2hNBDhyG6MW0EcghWZUqBx88jYzOL5iNCU
         WxgTWNEahRQeS5qQqcXp4JYTMLBmGsZjwN0le75CRD5tkn8QpYTKhNqfvT5J1AddrejP
         9/cjvfzQkZLjIGthzLC8ylPNW+NE+iTUt6s/jgX/dWtfwCt6lm/S/si8tNMCi+8EPGJD
         jueg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kbdN2RUv;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id bq6-20020a056122230600b004abd0f58a5esi1694660vkb.2.2023.12.13.21.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:33 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5a1Q0017827;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6etp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5oqdo021978;
	Thu, 14 Dec 2023 05:56:25 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6et5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE59ikW005066;
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skp2pc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:23 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uMki23593568
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:22 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2ABCA20040;
	Thu, 14 Dec 2023 05:56:22 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A3E6A20043;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 614A160512;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 02/13] hvc: Fix use of uninitialized array in udbg_hvc_putc
Date: Thu, 14 Dec 2023 05:55:28 +0000
Message-Id: <20231214055539.9420-3-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 5s9tPtGFdVEMzglhXmmo7wVAP7ART-bK
X-Proofpoint-ORIG-GUID: Ud8w0bTXb7aQg9hzmWAmWuScZ2QEkFZK
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 clxscore=1015 malwarescore=0 bulkscore=0 mlxlogscore=858
 priorityscore=1501 suspectscore=0 phishscore=0 lowpriorityscore=0
 impostorscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kbdN2RUv;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
Content-Type: text/plain; charset="UTF-8"
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

All elements of bounce_buffer are eventually read and passed to the
hypervisor so it should probably be fully initialized.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 drivers/tty/hvc/hvc_vio.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/tty/hvc/hvc_vio.c b/drivers/tty/hvc/hvc_vio.c
index 736b230f5ec0..1e88bfcdde20 100644
--- a/drivers/tty/hvc/hvc_vio.c
+++ b/drivers/tty/hvc/hvc_vio.c
@@ -227,7 +227,7 @@ static const struct hv_ops hvterm_hvsi_ops = {
 static void udbg_hvc_putc(char c)
 {
 	int count = -1;
-	unsigned char bounce_buffer[16];
+	unsigned char bounce_buffer[16] = { 0 };
 
 	if (!hvterm_privs[0])
 		return;
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-3-nicholas%40linux.ibm.com.
