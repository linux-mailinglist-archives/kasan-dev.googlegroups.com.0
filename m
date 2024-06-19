Return-Path: <kasan-dev+bncBCM3H26GVIOBBLP2ZOZQMGQEAYHEUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id E4E7890F29A
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:50 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6b062eba328sf86542026d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811949; cv=pass;
        d=google.com; s=arc-20160816;
        b=qRv+cBfQXzKcDWFqMbJsTc6gHC3LvcCCo364OuTPP0EcQnxIg9BU/BX51YoF/gxmqw
         3Gx8mRCAyQdGRa2dIqv4iE0XRQBAqzoVSBVJ+dkwtVAa5zq3G3qHcUZdmnTXkwGCjJez
         L3iTX/2ZX/dRp/BOR4WVl9HlPLkOuLaNOOS3Tsnu3RAEbSaQs4DS7um6bQyAnhOgD5eF
         OBjqsNwmxpnWrfQOG5aDetl6+urDkrBAV1iIviIXfYIM1nEFeP72s55yg3+PjFq/AJms
         mHAKWyTuS9CmJTeXE7GzPoSgHh/OKrsz5mUoLDbWCrj24pcxkwUA00KDYFxG35YdK5UF
         UY5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sSwPDoMPNRO2Jd5BJyXwe84gXvFgsPvaqoVRLzLbQcg=;
        fh=zjDiolvgNwt0jB5Emo76r+g3jhuJqGMckHscbujuBzI=;
        b=B3INftAY4HF/N6HoUaJsfxHAQHuyvqKHVHE0rKXHoe4I0nx6IPXtHKemgXVH+S20Jk
         FNI2DIN2YjpxYkuX9yBm6KqhnJgYARPfo2pwJXSACZMzs9o/hndfRLdU0MkcCPcl5U5D
         lv6Y7RIzWBxpQzkPbbUvUeO568FV7ziSGpVxsF7c/RHSNg+n17/jbODoSz+4eSkRbraL
         JP16YyXs3e60bHF1iBTKFSa2+prMRIsdL6xlYV9hIQPZogthExm92hxcw1oZG/9j7uqt
         LBnMaFzq46y2+oOS150UarjOcQ3n8lmLbVWL5DsKmuigxJw4RM0J9PT3b61nvupF2bBy
         EtAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="r/ZDXUf6";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811949; x=1719416749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sSwPDoMPNRO2Jd5BJyXwe84gXvFgsPvaqoVRLzLbQcg=;
        b=QT2uvU49QZQESjXX+9c3Ys58Kp3l+4amTuf2RxPW9LGygMFB5Zi2jHHgiOUHkn632b
         3NMgki4rISYCCrE1V56oYeJRo4C+Fy1qMCQp16hwQ3WoK01b6bb+lXoE0u1jIn2/+g5e
         1wBohQHFBuWTNv/jw0wVXwWU44cHbNj2b7rkNuAUieyvDUfALvI4rHA0LecjyVbV+lNw
         an0W8KaOAjmJb6xhR4FiMMfxSVlx2NWvbSksRvp+fzuftgueDV8XIfVx5AB9M/GzAmq/
         dhtgRkVkCSZ9a6SYvOA1LSu0TrgV0QyozbkGphYm/3HRvRT9v68yf2ioIxx5T4dLdIpB
         oZuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811949; x=1719416749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sSwPDoMPNRO2Jd5BJyXwe84gXvFgsPvaqoVRLzLbQcg=;
        b=Ojpy1HcKvKdcn5kNok3mhxtcM8WTQN8B3oZ9FiIG4ncmwyZB/DrB1eeIrWNmXhaj4s
         l3aF6nKuBZjb2HIGkPYM9CoOfJLE/cs91NwwMnBX6e1hEuT859nVaMCEhEDPy5adyVIP
         cQKWrIcZHVJpp39y+9U+UIv3hIQlBihZBxbCsMm4+c6MjsJhWdYlMEdFyoGRMvexO2QC
         xFBD4F9OFwaT8AstcN4TA9Q1k9hJFjgqr5DqKbXgSV6vyT3L+up5+HF26NMTAx96Ujd1
         7wlCd+e6haRJHpXIe6ifZFdGV0GfoHPBMU7CpBPt5KZL2y6fquTnrVehWIRLagXj2uZI
         OGXg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeNI1WS1C8Fi8tD22vltlN7Evinvza/zxsD7AkxslBqrRznhUDqvD3pTSOZJnF8oGr2eCo7bV50MdwK8N+y+fG+IvYIaeLSw==
X-Gm-Message-State: AOJu0YxG3ZrAbNxvXLGH/hCm9NfAnDIvpWVlry+r0OdMSGV3su1xc9QB
	mjY1+r+rDBW+TQh/fvMgHbForFiTcbVpA0R+BDLkOazCiQS90exu
X-Google-Smtp-Source: AGHT+IE/phZ2hN0h6PG4vR+5YhVLRa8CZilAzbuFfb9H+h5jVwmVj0K38Uv1dDyf3tj5vggPjnGxPA==
X-Received: by 2002:a0c:e34e:0:b0:6b0:762c:d045 with SMTP id 6a1803df08f44-6b501e575a6mr33140586d6.35.1718811949334;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4403:b0:6b0:88f4:b00e with SMTP id
 6a1803df08f44-6b2a34fa9b5ls87504276d6.1.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVV9wLmZt8+5uMMVpPKBAWKY9kV135hLL/PG09JD4GkXBvbDmAF/+Psax41vtmGs5t9Lu8n0hRvPovdVpvFwQbBBsN9GW1VOZ6Osw==
X-Received: by 2002:a0c:e354:0:b0:6b0:8aaa:ff2c with SMTP id 6a1803df08f44-6b50d1b0423mr8770796d6.51.1718811948627;
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811948; cv=none;
        d=google.com; s=arc-20160816;
        b=dB+79bn1T2KwOfzKdKJQV8yE/cJaT6Xinb3hO2vGa9fCQmn0FAantyYFSnYJVEa3qZ
         qLaCOXzS6WHPFUlz8Mn9noAARKZiH2WXmQmV2ZHHiTlp2tk5AgnlbcF13EHOnRN79BB9
         vYVziJD9BLlQmtNScTRZ4iYTndFsyTzsNFdWfPza/+KHjQzGBsbwpHtEslkG27cMTGo4
         uB2WyNNUHl2NU23WRtBXs2e5X90r0bdp30/hO+Z729WOUVDlmtoEdkED9QC+LSFjxp+d
         Oz4boWgXXa6CFvJ7gfh8FuiHNkS+LP8KdlI8HEQCPsjKI5f6qNRMJwoOzvLnV5CWPTtu
         h2mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ah4xfVCHNViASZu9OS8C5bCxAH6NMTO/t1qMSUm0DA8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oiQV9oljvZYGHofDzjTwD/2SMA2MvV6i9IW/SgCsA+JN2QUyJXykky5l7NUwS/Ze3P
         u7nlpKCzO+Do1oXKSFxESGcY+EZePKnsQHlY608I+00yGEClzhzeHXqbwM+D/ETSF9v+
         wYEJPOiVYisuf0JEil2pp083SiyHt3V4VClpYtOpXVhnRBelZRCsWM9HHhDAitEAAlpa
         uP0phopkYfBJzLgSq8jfD/+dil4hMEv2hps2wgr9tthqGf1vIGscKzAz78CeeMfEJKuF
         zBw4Zjc2wZMOaQnTGl5ZGZL1SvTrMUIfh1fnxXWvb9LJ3LUAMfrNIJz7M+xeGJ08m2uC
         MlAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="r/ZDXUf6";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b4dd1b4072si1693856d6.4.2024.06.19.08.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JETPqC000732;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8bt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjie4027313;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8bh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFDe1R019670;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysnp1e4w7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjbuF15663542
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:39 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 52CF620040;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0482F2006E;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:36 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH v5 10/37] kmsan: Export panic_on_kmsan
Date: Wed, 19 Jun 2024 17:43:45 +0200
Message-ID: <20240619154530.163232-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: RiUUTktqT1yLNQLtzUUbCFUd6AFkCIeA
X-Proofpoint-ORIG-GUID: 7_qealJrcwwEHN-o48FoPO7TmZIHaGqk
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 mlxscore=0 clxscore=1015
 spamscore=0 mlxlogscore=999 impostorscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="r/ZDXUf6";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
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

When building the kmsan test as a module, modpost fails with the
following error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 02736ec757f2..c79d3b0d2d0d 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_lock);
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-11-iii%40linux.ibm.com.
