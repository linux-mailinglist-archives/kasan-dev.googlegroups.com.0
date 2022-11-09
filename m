Return-Path: <kasan-dev+bncBDFONCOA3EERBYPEVWNQMGQEWG23MCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C4D6226DA
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 10:26:58 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id l6-20020ad44446000000b004bb60364075sf11417145qvt.13
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 01:26:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667986017; cv=pass;
        d=google.com; s=arc-20160816;
        b=daVwfN4LwCT4OIbiW+e1EOxo0u8StAxH+bVgJrIeJU5BNaTCYIJyhH8pm9L0Prx3+4
         mg8vVPfjNmZm3MJcgffS6chPRVJPJ8VcCUzW2r0qPYKKjSKfJMKm7dtn+IHywdlfrRiX
         t32IuJwhQ6ntOsy5i9RkYhAkd/WafzSIvRt5CbiYqPJYq1zdm5ODwd9SiqihFq8vf3vM
         4nR2sSTJyXHl8Xv5Rq77IADQeSeppRBwkO6CX1To2MehONI7gOjR10Xd6SEAckdhJFve
         Pb1oUe3a3JOq2VP2XvGr82NATPSCrn+YjSLAajqgz39YKAtw3yYU0ThOQeeUA2djOnvl
         hIWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=s35NZ0wBIsu3Ac2WrtbiDgJoMBAYBlyX5ynh64pjiEY=;
        b=OuGKXOR2kR+IEOYJQE5x9pU76LG2Ui3g6kZHn3iEIGCFnFPqRu0q15fuwp1rbhg6w7
         M58oY6xclRjO8At3WYAOv/tvgLKl/6DA6I8HCuTIUP5aWPOP3xSFgdjDHssqCm9BPAKL
         YjyrpTCnKQmR7e/DafUSXlQ+IqTu2Zf9fk7fRed2x9+uE5dA2f1RzvTGX24Pf8joGZh0
         Y1njdbIdGDQ8ZrXnx8labRE4IcZ5SVesme/OYbLLqPhPBkCx/ApDYTMhWZKi5ylSt2sB
         tJD2wA/DVUuflYXe27iA54tyQMkrkaYFH336eyFFSUqMd5VwfxdHOXJ/TKAIeW4CwEMr
         cLAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=fK3wkGjg;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s35NZ0wBIsu3Ac2WrtbiDgJoMBAYBlyX5ynh64pjiEY=;
        b=iiXUjKvlYutcAdtJA/Rl1PaMQaRoe7Hohq/YpU6UYavsO/wKMKDu4pb65SlzJu+VP+
         qz2nPZiWKvpJt/U54bNCQlC2MeoP9wyefU2vo0ZZ9JoVxrXb7T95btjIAoBFT91+SE5z
         qRF33PGuuJdMtBeqTwynVExrj4QT++ESGmj9xMGbCjYt0E7Kxaj9kb/w/1+gh+R3OUq5
         RiLdrfBgugO3AEBRA6vfTk535Ur9m7H61DVx0HTC/nj5zUx9I0CKrRKrtJbKRQyIijxt
         NCZsDGcbGLXP3jxYte443proHgBEtOCnkWvpSA7U0nU1SiVG3Y6BZC8AV8bg5/++5vSR
         t6tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=s35NZ0wBIsu3Ac2WrtbiDgJoMBAYBlyX5ynh64pjiEY=;
        b=g+4mvOb9lQx+iBUtR7aUGizjNvmEFPVMY/BicQgcqiAZmNC8TUphxYPldfXBGoqhUn
         tSph2il4vx9Wtd9+7iGuMSlYYWuSKo9ohLAZMAiaAXKLnIIVAUXLcy+R2nDCvZYhvSAh
         L9Z/9UZtejzB8SzsvIPyPhKUXYYcGdCGEslhgVcTA03EKWKCb285M172TKRTcje/dPtI
         lah23B3vAw13kCflAJlcNjR6Dektn05V9mwm633wkZP9XHclay6SAtXYjz7rO8fG/Dlu
         za8tLmKAijGCJkwxn74AqS0Nzm2yj4h5IjAaAiaYhycw1jSez+HNnX3E9+xMu8I2SyT1
         GUzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0xdsstozBwNUh4TLbzQpP3ypBfrvJPJTHSEGvR0dAMYR47Sqq6
	dBljy+h2FKa7i+YI8uzeGfQ=
X-Google-Smtp-Source: AMsMyM78fFxz5KCv94tZ4hY7P8mknhZF+lkvc49H7103QnmaFeRpymkXjs247Sa1kgrNCmlgRzSRJw==
X-Received: by 2002:a05:6214:f63:b0:4b8:c0bc:c43e with SMTP id iy3-20020a0562140f6300b004b8c0bcc43emr53623087qvb.119.1667986017801;
        Wed, 09 Nov 2022 01:26:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b3c4:0:b0:4b9:d85c:f017 with SMTP id b4-20020a0cb3c4000000b004b9d85cf017ls9194844qvf.11.-pod-prod-gmail;
 Wed, 09 Nov 2022 01:26:57 -0800 (PST)
X-Received: by 2002:ad4:5766:0:b0:4bb:f0a3:aec7 with SMTP id r6-20020ad45766000000b004bbf0a3aec7mr48568083qvx.86.1667986017291;
        Wed, 09 Nov 2022 01:26:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667986017; cv=none;
        d=google.com; s=arc-20160816;
        b=J0bPvTUQcePZd89b2OBYCP2VZ3PogC+bR28yXelBcMCliEW/QgyhOBnj96ZK2ozGrZ
         MPh97giIdz0KtHAy5JJtUolEPd2PQWHaINaOcmuRjvOwRBNABXwLvfukfJI8oAOKubNe
         4dTXQrnWMo5jigbvwZykuBzkaI94jGHRJAU08Jf61ng8mx0jaLexX9Lds6cVo01kp36R
         +xRo9pp7cv2/NDrEIYvh3to+y6w7VemWTFBcuVRlndzr2V8NtrN/+H2t8pFTgyyU8vNh
         iNeE26qk08Kbnw5pgIIv+e+7OzHlil0cxTg60gVLINz1wLb2sM5s0iPe9IHe/rs2/hE6
         Y8FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IGlfqAanlK48mImb41Tw+3F6UP5C64sbnIN3RocolP8=;
        b=a7s6hFKomQWMfvDwFMwuBO4qIcZhVm+fhcJx7TyVuN94hDMLt08Q55S9aTLURPW2Tb
         1yxG0UFEKuQLRcELA+RGnvxwJNAXPSiNqSytrFKLOnZMJE1Asiv4WKA+Bs8QvMvqtBfJ
         abrfZmEUDpX7fAwkJW0S6RZLYNCNKEHOmS9Dqy0F6MXROytwJtFhyzd5jqO6zxg+zNHf
         +vkX/qxh5ODMbHOPF/baidvjkNmNjwWd81RrrNh3YjlRubBebPGLEAgcEE7NXGHGWtot
         kAAdmi2iRlfvWeoGHM29Sd45Org0Mr1HzxJBYKMi/KB9GlgGYGrS3MgTSn8FYK/lHm2f
         EZoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=fK3wkGjg;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id d22-20020ac84e36000000b003a577449007si504117qtw.2.2022.11.09.01.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Nov 2022 01:26:57 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279872.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 2A981qS5005483;
	Wed, 9 Nov 2022 09:26:55 GMT
Received: from nalasppmta02.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3kr68ngh68-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 09 Nov 2022 09:26:55 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA02.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 2A99QsHa021939
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 9 Nov 2022 09:26:54 GMT
Received: from quicinc.com (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.29; Wed, 9 Nov 2022
 01:26:51 -0800
From: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko
	<glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: Peter Zijlstra <peterz@infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
        Pavankumar Kondeti
	<quic_pkondeti@quicinc.com>
Subject: [PATCH] mm/kfence: remove hung_task cruft
Date: Wed, 9 Nov 2022 14:56:46 +0530
Message-ID: <1667986006-25420-1-git-send-email-quic_pkondeti@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 64oPdNQofgGegYgIaFrSNehMaTYkmIqm
X-Proofpoint-ORIG-GUID: 64oPdNQofgGegYgIaFrSNehMaTYkmIqm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.219,Aquarius:18.0.895,Hydra:6.0.545,FMLib:17.11.122.1
 definitions=2022-11-09_03,2022-11-08_01,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 malwarescore=0 mlxlogscore=869 suspectscore=0 clxscore=1011
 priorityscore=1501 lowpriorityscore=0 spamscore=0 bulkscore=0 adultscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2210170000 definitions=main-2211090072
X-Original-Sender: quic_pkondeti@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=fK3wkGjg;       spf=pass
 (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
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

commit fdf756f71271 ("sched: Fix more TASK_state comparisons") makes
hung_task not to monitor TASK_IDLE tasks. The special handling to
workaround hung_task warnings is not required anymore.

Signed-off-by: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
---
 mm/kfence/core.c | 12 +-----------
 1 file changed, 1 insertion(+), 11 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 1417888..08f5bd6 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -26,7 +26,6 @@
 #include <linux/random.h>
 #include <linux/rcupdate.h>
 #include <linux/sched/clock.h>
-#include <linux/sched/sysctl.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -799,16 +798,7 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Enable static key, and await allocation to happen. */
 	static_branch_enable(&kfence_allocation_key);
 
-	if (sysctl_hung_task_timeout_secs) {
-		/*
-		 * During low activity with no allocations we might wait a
-		 * while; let's avoid the hung task warning.
-		 */
-		wait_event_idle_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
-					sysctl_hung_task_timeout_secs * HZ / 2);
-	} else {
-		wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
-	}
+	wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
 
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1667986006-25420-1-git-send-email-quic_pkondeti%40quicinc.com.
