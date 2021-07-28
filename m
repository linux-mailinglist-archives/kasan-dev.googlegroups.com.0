Return-Path: <kasan-dev+bncBCYL7PHBVABBBZ6TQ2EAMGQE5Q7MTYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 22B403D95C0
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 21:03:05 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id q3-20020a25bfc30000b02905592911c932sf3267242ybm.15
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 12:03:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627498984; cv=pass;
        d=google.com; s=arc-20160816;
        b=GBDslNOZbuNIGVFSOBt5ubDSdDCLvrsZCKHyMAc3G2m6MhY1yNSUQCD2/uuOOeksHR
         D3BL/YpjWP1A3U9KhclPBFRypfXrsM79eDL3AC7wtAvIvnIFAMZv/O2WBdj+mDlV6xoE
         hluqdIiYhg+35ZoFiWOvib4wY5oCgx09WuTMbbwSXBE03IqXopumKhtw/7vnBWeGUdoR
         pVopMsIHAHH/oN7831fT84zyAAOHy0LJzZ5c8b56wl7vRABPpu3DBakijfQdbZvGWGlO
         1f7YYTNxPFlyuRWTvGSwh7O+nnqSFP7lqABz2Vc/4yHh/Yr4lRO56/vnRCoG2xcWdRZS
         tKVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=atEqLTqVO4Dg4EHeDLdDLQboW/192irqVs2lpaqRwu8=;
        b=QwjdUfaMG8Xvyxv0PefGzoPmiQhRWY5Uw+6xkTBJoyl/XOKO5QEj33Q2+4aOA/DIWV
         jNorgGLEywNIMlf0E1FV0sQvJ3b2X6JCeMCE3NpkUkqmlNiu82yVj/iQQI3NdzhwnJpy
         P70mXG/uyiSZeBIkLBo6WMGaXepK+/YolGXCbVA24RCLxFTuDk4Sadg5P/1911qsOXTT
         2x+QfNxcrvF5o5qrzyZcXaKfmE2/LCXryE0ohDEeImv4nEoTJytmyulpYQyZutxBj1zx
         n+aF1NHgWPUXkbfItYLHOWKx2COGBjvgFTNv53jw47NkwbFXCjzWodN/NMVIVRRVxhZh
         MfTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="e572/hQB";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=atEqLTqVO4Dg4EHeDLdDLQboW/192irqVs2lpaqRwu8=;
        b=Az/2wJ61kMNnOv67NYEVGx+klsUr9LAreH5JU0r4eEWUtFxWXGxBEyFiGOKwFzneVN
         cTxGvedWBVUTOaVvUu1iaObxAUC+KfyXVC0sppl1RQJ0gAsW+3X36zn60pEK12Ate0Yv
         5hEi2p5wf5rtiidcb37ueGuu/qUSS1CByd53Wn1u4SQBBHLyWTaF31WqUB2SnBOCk5zt
         IlvPjiuika5oH/WLghVO4hM5wBIqRTfMuuklOZqE9xml/HKfoY+qRx0QS6aErI6/b75O
         JAApUHFzGZJ9KhVLgvGs7cJUdVElAejIo824kGbXnQYGLyIUM76qI8LGCSsigHy+Suv5
         Lt6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=atEqLTqVO4Dg4EHeDLdDLQboW/192irqVs2lpaqRwu8=;
        b=tKnkQRcubHU6ilc92AwgGAFHhz8o07BsKNXZkBZPgpUUDyRnIP4JMhQ9YB3jn0IcBk
         AoAIlQwpUA8GqOl+XKvbYDttjfHBAvE5JI4raugWmZX29WPl7NQijum0sPrDEaZ5jCa/
         /x6uLbPaP+NO2N7z6x74ZNeWsGYuiCetOdvnnanVqHX68nGm4CdoG1l76vS+6aCO8zVg
         SZJi8x3WGntTvcLMaS3ToqxOnl7BAyrJkD55TJ2DElmzns5m1TMUJSIXNhZKvN9OrlRo
         VSyrSKihGblp6aCcrI89cWcLXdY7hPmwRubEIjg6uVN0w8m2sYvWMM6lxVnPH8OuKUka
         9ylA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53131ybvBDUAtYHTzqpe6OFX4zr8vnXXSrNS9elBEgQhsTkBkchZ
	MYfk+2Ns/+ATG+ce12Ma0Ro=
X-Google-Smtp-Source: ABdhPJy1oiYpQ7fF9lrcNvgNfIJDAMP+Fjd7TdivdJzM1b0bdh5xLNGntLf1ZsC3bemdiOg6aBasqQ==
X-Received: by 2002:a25:d0d4:: with SMTP id h203mr1664374ybg.0.1627498984021;
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7bc7:: with SMTP id w190ls1883845ybc.2.gmail; Wed, 28
 Jul 2021 12:03:03 -0700 (PDT)
X-Received: by 2002:a5b:c52:: with SMTP id d18mr1692861ybr.248.1627498983526;
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627498983; cv=none;
        d=google.com; s=arc-20160816;
        b=VYBkOYMSLghU6t/k/UC4MIpagY1uRrAQZt88GpBBv2iiZvwcGK6duSrqd0Nz17Xk6e
         FA3vxO2FZZ4u4H15Jl5btucqUqeNrDrLmi0390CqPEzhk4AKUYRpUovQVrazNXwGCJ7Z
         9CwhnGKTB5vXIfNWnnvxH3wRv2ZVcz59XTOC5UMyB7ysthk4V9BRmSYYQQBXUDAtPtiu
         D04KctwKKBMiUT8zYgQmQDDsRV9QpdcBV/DstlYhZE087I6bAin+QJnVYOSLphrxWtHF
         QIQNIucPaCWUCO+Euw/tR0ZyfsaHj/fq7xGpFT6fg8CK4S7DrcDqLvqPa8bLnDFCDXbJ
         nbvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8IQoq9d9JRaCzftcndSZz9ID4zL4uP+cWMNHvn6nuv0=;
        b=swtODhpla3Ik+p5s7LH3WVs9+E45nFqxOIQKVsl1la7zPavCSqCHE5X2tGvM9pieKu
         Ww0UjRF5niUs0T1Ygp2XA616eKw5WxqTIC1MRCCBcF8ok3OpECd5JeFENghkeSP1t2v8
         YTv45AAZFJuG4pPdwAuqo1iR/It/8s1H+spMSphWviWZR6e2TDmdCrRwcEw6P0FenMx6
         Ht6rbGgtudelBADriF1SlUYoiX4kVSnKjTkz2dWfOohh5BEora5usKbjRxdvGvGmWY7z
         GSwup6BR596ELqaABskvZvNYtgqbSH/F0y8wj39+CVtxekayusteZknOIfNX9v7p4v8f
         fCXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="e572/hQB";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id q62si45655ybc.4.2021.07.28.12.03.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098394.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16SIf0EY028915;
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3bwm1gq4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from m0098394.ppops.net (m0098394.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16SIqIoi106631;
	Wed, 28 Jul 2021 15:03:01 -0400
Received: from ppma06fra.de.ibm.com (48.49.7a9f.ip4.static.sl-reverse.com [159.122.73.72])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3bwm1gp9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:01 -0400
Received: from pps.filterd (ppma06fra.de.ibm.com [127.0.0.1])
	by ppma06fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16SJ2j49014691;
	Wed, 28 Jul 2021 19:02:59 GMT
Received: from b06cxnps4076.portsmouth.uk.ibm.com (d06relay13.portsmouth.uk.ibm.com [9.149.109.198])
	by ppma06fra.de.ibm.com with ESMTP id 3a235kgtuw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 19:02:59 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps4076.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16SJ2tl230736734
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 28 Jul 2021 19:02:55 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 86E96AE04D;
	Wed, 28 Jul 2021 19:02:55 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1B0C4AE045;
	Wed, 28 Jul 2021 19:02:55 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Wed, 28 Jul 2021 19:02:55 +0000 (GMT)
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 0/4] s390: add kfence support
Date: Wed, 28 Jul 2021 21:02:50 +0200
Message-Id: <20210728190254.3921642-1-hca@linux.ibm.com>
X-Mailer: git-send-email 2.25.1
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: j97TaW2Of8FDCrA7PepNrglp6nV4Z9Jg
X-Proofpoint-ORIG-GUID: borSlyoue7H9mxxHLLVA9li_lNMCF4-y
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-28_09:2021-07-27,2021-07-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011
 lowpriorityscore=0 suspectscore=0 mlxscore=0 phishscore=0 impostorscore=0
 mlxlogscore=999 malwarescore=0 bulkscore=0 priorityscore=1501 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107280106
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="e572/hQB";       spf=pass
 (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE
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

Hello,

this patch series adds kfence support for s390, and was mainly
developed by Sven Schnelle. Given that he is currently busy I send
this out for him, since I'd like to get an ACK for the second patch,
which touches kfence common code.

This was already discussed here:
https://lore.kernel.org/lkml/CANpmjNPAS5kDsADb-DwvdFR9nRnX47-mFuEG2vmMPn5U3i3sGQ@mail.gmail.com/

With that ACK I'd like to carry the series via the s390 tree, so it
gets upstream during the next merge window. Hopefully that's ok.

Thanks,
Heiko

Heiko Carstens (1):
  s390/mm: implement set_memory_4k()

Sven Schnelle (3):
  kfence: add function to mask address bits
  s390: add support for KFENCE
  s390: add kfence region to pagetable dumper

 arch/s390/Kconfig                  |  1 +
 arch/s390/include/asm/kfence.h     | 42 ++++++++++++++++++++++++++++++
 arch/s390/include/asm/set_memory.h |  6 +++++
 arch/s390/mm/dump_pagetables.c     | 14 ++++++++++
 arch/s390/mm/fault.c               |  9 +++++--
 arch/s390/mm/init.c                |  3 ++-
 arch/s390/mm/pageattr.c            | 15 ++++++++---
 mm/kfence/kfence_test.c            | 13 ++++++++-
 8 files changed, 96 insertions(+), 7 deletions(-)
 create mode 100644 arch/s390/include/asm/kfence.h

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210728190254.3921642-1-hca%40linux.ibm.com.
