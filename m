Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBJWYRGZAMGQEEL3ZLWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A1938C479A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:38:16 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5b27ba52399sf2499963eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:38:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715629095; cv=pass;
        d=google.com; s=arc-20160816;
        b=XaLFy9tHuQtCsLm+lecU6rac5S3s7wiPkHDAqEffkLRgIYojF3FUu7kUG6v/Sw5sj7
         PZKj43DoAqZDLiHx2T/qUfwtDYUqKpNyDCEKhzH86JUZfL5ABnBiks5E5W4JtovWW8Ic
         ny59uZU3bcwFbTTn5g9ODcRau5ARoX3Gh+Q32Wcl1FtDd3KJdoFvRVUZ/mGVpQogiLiu
         CW0mz4PIPXc8xDOUnHqtj94DTMmEMp+f3hv0AnfHosKfuC/7/Hy8tLu+9eCxUdmryIYi
         A6xobCIX+ElBC8XF8BKhf1dvsY1S92KiaIRvfpB2O1qOOPCccjYQsw9Vw8mjAy938OFI
         3kTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=iKPZvx2psmWAEWV529s36U0Ja9lxqlkBrdlrLYnN1dY=;
        fh=Vtdpty/uM7rJYbLo31YCeE4lpmlnnfXzx2FayK5Hj8U=;
        b=UmmKjhz4B0nsRpTewKN//0RZrgcYNVJSzdVNN6CUg8oYN6MFTqJFjQxirA0xtz7CXG
         WfLMqp/Z0KEyhe8PrYRlGgW8XpVwzKD9P84oTb6WUEOujHk96pw8/nJQt7f8IipMkdRb
         Kbkogoe9IgYXfeIkXl2I2dLETi/zuAty9ujyDxvLfjndrbSxcQdbCoC4U2fgAWNoCP0O
         6s6oY0pC+H7wCaRTk4+9PBjyBzgglXdHs1s/kUuyAbci4zdU6Q1ydkRq/oe29TpfjSYg
         dXWrXylU18ujZ7w0Ok4c7/b9yPz7mwIuErg8djQQsL0g41TS263xSiZs9o1mRT4uxNGG
         oq6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Tn2WlWNg;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715629095; x=1716233895; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iKPZvx2psmWAEWV529s36U0Ja9lxqlkBrdlrLYnN1dY=;
        b=BPtx2eApoVbUqIrXo/x8GyBs91rVBBl4KG8qrUeXtWqGtqS07juPqjtw5+Var5hP+t
         adrS3is6ECdsPh7f/ZfGbWVKxuOMEE2GSGlbYpHYqhrSjb67JhP4mNNfQ55vT3Su3fxG
         1oOI0lqtAvWctbNEOiXZ4lLQQbhxghkK/X2g44vE9w9cYAv4OACeuH01lUFjHHU4Qf0N
         JQbEIUXEhERGZaygzGLIrClWtJX2ROMLsvc3xDKPzFSiMSiiA/S/eNAbTU3gRJ+Io467
         I21tU5HmgeU/kZ4WCd9pCsFV7lWwt6iInrmbOYjIiSmgegQoTWYidWLzfarDQn0oUKVz
         JQwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715629095; x=1716233895;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iKPZvx2psmWAEWV529s36U0Ja9lxqlkBrdlrLYnN1dY=;
        b=vn94pfvO0MdfMG25dIZBoF4vikwv5dqtnJf7MFlKOfcNnqBoJnDXnmfIFazUZaGvqG
         SYDqt6MS7aRLP6hVhY+PZEZJ7EUp8/usP4KLQpZIWUaIdzawh4eMXURDNpaeril1Gk4g
         2oAh9cZqg6SRBxPdQ7C6JqbhzIK3BhlvYwX421y8ViSIACmoF880Fw8ArvAKCMg/xWTE
         fL8F7dN7vKUl0GEW+x7IoZLEjpjeVFhF4Trch13vnUnycFZEGLqy/0/6DLBXlFoVmklH
         +EH0xEJUHmroRmXacfYXnc0PtJzQIH1aTWBbghkIV03+K50Mask3fz99hmCO9AEakAAE
         +vSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxTXSJerPNiaqqnnz2CFEcOWi8ayssyfOWCrbLqE6KJHtObipwKugJsei/mhCkZTEQzTN8QjQANIdF1AuBjyuCiYLReZsEsw==
X-Gm-Message-State: AOJu0YygnOwqMEwL9vpxzMgK1ysL+xdLwrMAt+TH63YLnETWz5AcNlCm
	2s5pCG8hWu72t0A4REan/8r8Hzn0eMDYTvlHdIImJuseZg6qJJ9Y
X-Google-Smtp-Source: AGHT+IE/uzJgVCrEorzetsDQ4PWAbCmPrzD0xf3rNJq3cVBmdoLi1IpKP6lfaCNYWIVS8d6tK8m2NA==
X-Received: by 2002:a05:6870:c155:b0:233:9ffa:dc3a with SMTP id 586e51a60fabf-241717302f0mr5315753fac.3.1715629094963;
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2214:b0:23e:6f12:5de8 with SMTP id
 586e51a60fabf-2411821a5bfls2411538fac.2.-pod-prod-00-us; Mon, 13 May 2024
 12:38:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCO0wIp6P7teGtKhkl7JfgV4vC5HVunJsp7glIeoCRxshUg6yzo9GQ8qMYW+PlYHBNbBTy5qywkKrhSicqxW+xmGK7J83UXqf7rg==
X-Received: by 2002:a05:6871:711:b0:23c:253c:283c with SMTP id 586e51a60fabf-24171e0f27amr5413363fac.20.1715629094173;
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715629094; cv=none;
        d=google.com; s=arc-20160816;
        b=YRYMPXra/RuZWjXQ9kKwzmz09pygumbuTwqOXx9anBV1CRpnj/ZvFjpL5WrDDYWDZB
         5GkzG7dQw+2qr2Equ0L2Kb+oFLinEwZFOrgq3mvv/z5eThWLhBwQLfqSYp09/2bPTJkZ
         HrUWPWu6tF5+sEyogK1Hg4p2D+rFejWjpxB44JkxkVYiFIEKg5NOLBf9yEzCEh8L479V
         6BXf3Tx4Zws5ymvkkiS8SaZd7njiojPH0MDI8itqbjYCLYDj1q+3Lv3vMb6EpZ1PfEiH
         FfIysPbSBD4QP7uMgUrrF53rOs5F3xlNxH/1kGERwOsp0mj5qg3MSoXb425QF+wBNI3x
         8+EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=M5On8UDNIfPjL9B9SOl2Byx+r6yib+177PbilkE9xME=;
        fh=eDdK40krtWyjNnSFs4h2SepZVdd7qicqp3ugeX6jaYw=;
        b=ihPzpwYQMz0W/PhlKnBPhYHHQyovMr6+HYwWeKJToKPxyVsDPGLODo20qvSQ7eBe/s
         aJTsiUSUADvYIl9rtxdhXfg4eE0FFfxIUYsuQAUPHxABQT95VugndbXHYdARVwBJoutZ
         jHjZ9LInDU2VQJX9Fj9f1NCRiDHtOuiocY/6CZ2GESM7Yx1aOI9VYkfShzpsDXodkcOs
         1uwrfrBcURK6Hl21jT8TnB230DheQTHzUaPdR6sFpUUcs7XG4HTEbjpXB52nJPXe7XJ0
         ZCPhLXsVE8FNOtvNSuQbo2HEFdkOgCbUHesqmfbXk6yZ0pbaDWLt9jv+K2VhSXmYgiAC
         0MmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Tn2WlWNg;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-241295829f1si960741fac.0.2024.05.13.12.38.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 May 2024 12:38:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279873.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44DJ8Zw0027313;
	Mon, 13 May 2024 19:38:06 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3y1y9mchuh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:06 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44DJc3NJ004093
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:03 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Mon, 13 May
 2024 12:38:02 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Date: Mon, 13 May 2024 12:37:38 -0700
Subject: [PATCH 1/4] mm/hwpoison: add MODULE_DESCRIPTION()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20240513-mm-md-v1-1-8c20e7d26842@quicinc.com>
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
X-Proofpoint-GUID: nG7lJYwglfeYIktc6RVkONFDtBx6Ma9g
X-Proofpoint-ORIG-GUID: nG7lJYwglfeYIktc6RVkONFDtBx6Ma9g
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.11.176.26
 definitions=2024-05-13_14,2024-05-10_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=912 adultscore=0
 priorityscore=1501 lowpriorityscore=0 spamscore=0 phishscore=0
 malwarescore=0 suspectscore=0 impostorscore=0 clxscore=1015 bulkscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405010000 definitions=main-2405130132
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Tn2WlWNg;       spf=pass
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
WARNING: modpost: missing MODULE_DESCRIPTION() in mm/hwpoison-inject.o

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
 mm/hwpoison-inject.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/hwpoison-inject.c b/mm/hwpoison-inject.c
index d0548e382b6b..7e45440aa19c 100644
--- a/mm/hwpoison-inject.c
+++ b/mm/hwpoison-inject.c
@@ -109,4 +109,5 @@ static int __init pfn_inject_init(void)
 
 module_init(pfn_inject_init);
 module_exit(pfn_inject_exit);
+MODULE_DESCRIPTION("HWPoison pages injector");
 MODULE_LICENSE("GPL");

-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240513-mm-md-v1-1-8c20e7d26842%40quicinc.com.
