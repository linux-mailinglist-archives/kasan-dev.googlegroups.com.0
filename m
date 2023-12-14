Return-Path: <kasan-dev+bncBAABBH5U5KVQMGQEACXOXYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 87DCC812783
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 07:01:05 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-3ba2f8afd12sf610108b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 22:01:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533664; cv=pass;
        d=google.com; s=arc-20160816;
        b=qp7rL5d5rSM5csfu/8qPL0eqkJkeJT2gbgMS4OFoEejYswclzJa+WOipG9b+cGiDmk
         LjE/78pyHA3RL65KTKYbueFn1NVnpUPFHAy3xPJ29y0glvJzNEUVJ7+ZXdZ67BygLD+7
         /4vYS8J5CMa1w2VKjMK8rF0dl9P0b8nR939A51OukXINZSxKpy8p9+zuSf9qc0alNsFK
         0/2FtTKLzY6hJiyafUbNYcijTN6ZIMrvOGXykcte3DJCfXz46RBRsgeCIDqb1orr+gTi
         gjUwBsHAybjBkI2NOA4rI94IB4NwK8h4tsUX8iO8BxaSSS8nHGWmSkta+PFeMRw1Py7x
         H9KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZQcs9wiSTGkfxMTfZkJsXUqwT3pRSLckgcrFCSToHiU=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=Mxth/Chmx4PTYR+jsREh774SlQNGy7oKZdVPcYYgiyNs+Rywk9A2dRx09dTQmFHpLV
         0NXbfUZLIHqVq1CMg9OFodC2Z/E3T3c2Hu9tgyqwneO9yTKFiiuWsnUy+oMecAROHAM9
         hJld0a4ClJw5smWAbpNQCRijZstbUoOOzg5W76G0Nu0eceJgVTYK+A8F1v7SD/ov1xSQ
         /DNcrW+wshgGQnqRoiQoWn/krPj/uU2Dy0/121pXcfrgRH4Gr05q9Vv4DKkYP0R68b9L
         75l3EKWUmeMthhhWNY5qJdXUnIaKqS5WhWJ9dgnP4SqHW6U+xE6t9WLiEjpqZEnEeKwr
         uekQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=O7P4PPAw;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533664; x=1703138464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZQcs9wiSTGkfxMTfZkJsXUqwT3pRSLckgcrFCSToHiU=;
        b=S9oh8uDVl8PNP+MQxjZYfEPaDth/UomH48GoKoX6mVTLCVAMg3+nBKZL9bOqDYictc
         nP8haYyNHOigSsvz7D5iX1mE096Mt+jE/kVCyhdnRu1h3zwOXwRMxKJyrRSxagLxES1V
         odfkf5fmAsndBccIAGukKJQueIGWj9ImoXbvkUt19mZ1E8N+AC2IsegyKCxRUx9P2kDA
         gee1S5rrKGFr0ASj7HIx1Wg2yeJrZsDJbTStq0+S8UBHCHZNKPYFOnSGnisVmJmn99to
         R6DElFuZ9CoTqwhgnKis279QVNIChe6qaDWCdDHdJq8O1nXFKaAi09GraL7sTstsDcJr
         42ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533664; x=1703138464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZQcs9wiSTGkfxMTfZkJsXUqwT3pRSLckgcrFCSToHiU=;
        b=TmGiVTr+F7pC+vaH/CY4pnTqdcRHyx17Tzgp8Cb90OrThgy683Y61K5v9aCsPdH6lq
         fadAEq1IKz4JRXzHbDsGDPIbsykWEEUbomNZq4AHXMAIOwC/FAMTDOmaggnVP+ApvwcV
         e11lbrzqp2xPwJll5UE33KorjIZAfClofYO6ScF+Ucl/ykDQsvusBCAwM0OT95lSvcS2
         95d6Du+rCo+al0czcqQXz00VWtCPW74rSKzFghrY29QbBIOLhm0761pKDNOHUN8a96i9
         1owrmYNMwLNTEtsE9a+dc6HpzsQ6frnT9RhCz49qxIzXRmT//BNgT3r1YQ7C8fcug6Uf
         vR3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyl0VuRPOUG1WPPuaKQm5Ti611oIeW9fAygtheCHMlgXmc25pff
	fKOphKOZ7SBuu3xiWMjmvb8=
X-Google-Smtp-Source: AGHT+IE4QIqmR/KHBq8tcyoMbosE2FpGZzYgAl/a/NZnKhQNJqsQ/JpnzmplKZqh1r4KYfGrNKfbMQ==
X-Received: by 2002:a05:6808:2097:b0:3b9:d75e:f92f with SMTP id s23-20020a056808209700b003b9d75ef92fmr10694326oiw.7.1702533664025;
        Wed, 13 Dec 2023 22:01:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:518c:b0:67f:ab1:c86c with SMTP id
 kl12-20020a056214518c00b0067f0ab1c86cls247128qvb.2.-pod-prod-08-us; Wed, 13
 Dec 2023 22:01:03 -0800 (PST)
X-Received: by 2002:a05:6102:a4c:b0:465:fc90:2cc8 with SMTP id i12-20020a0561020a4c00b00465fc902cc8mr3565433vss.7.1702533663174;
        Wed, 13 Dec 2023 22:01:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533663; cv=none;
        d=google.com; s=arc-20160816;
        b=lldsrYU3D8WC7fTc9g9hP045aHv/Kb831s5b76eXjJbgijrodxgfUUj5yYf/inIkxn
         FgY7zeQvjESu6IoestH1E6SGNYkvztT03t+8/4VqFi73Y3kzTFbDVK3FYx1yb+E2Q/kk
         zHK0M7+JgV7JaKj6mDi2kpEP9xMAppShggifRr1YaW5eKg4P9K/7PKaljszJB55vQIBq
         +g4Oyf9IQ8X5vYkvDrZ8QOR8VxsdnPP85fsZIosPNiWiaypVzhhIZ34Qedi6OI+3JF44
         hpwBPksI22RZX6aaiDoFvDGJ2fWDzwPXYN2kIYeU383jKiuoGjlXTllXFXL6vQ2LPg78
         oONg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cHxReqqGIjRID+MyVHm8vhatwbiHa0YC0anP1AdF18E=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=UfucRy8IHS8ZvsYoSVyNoPN94+69uKbAJZpB5AFFMbYxKXpshjFAw8phSe5Dp/jRMH
         FXA01T1tFTb86Vp3h0Q1Y1kjwy6elZB1hME8fpQUTfj8Lq2aSIr/YwVwehajpzG2iJkw
         8VMDHv4eBOfWJTyI2gZrace1yv5DLr3MUFU62n+souVAlRlRfeG17AhZsBS0UKKCFeYw
         tVQ50KQDPvoPlNYr/pXKfXp4I+9ZgzqYkSIyDnq1NK8r14g8BixiTvgaqzQjnWsZ47Op
         7WhNTXY0H3nNWM4NckEJ72pDNsilcGt7IVm2YkO7ksb3lROrTVjB8BmWWi/tzHlI9z7x
         V8Pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=O7P4PPAw;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id i13-20020a0561023d0d00b004508d6fcf6csi3250442vsv.1.2023.12.13.22.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 22:01:03 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE4t7Eb006214;
	Thu, 14 Dec 2023 06:00:57 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyu3h95tt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 06:00:57 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE60toY021803;
	Thu, 14 Dec 2023 06:00:56 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyu3h95d0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 06:00:55 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE54w48004701;
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skp2pd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:23 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uM6c11534940
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:22 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2F24620040;
	Thu, 14 Dec 2023 05:56:22 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A75202004B;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 53F426047E;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 01/13] kmsan: Export kmsan_handle_dma
Date: Thu, 14 Dec 2023 05:55:27 +0000
Message-Id: <20231214055539.9420-2-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: h7MhkM45JBHxG2kSFrgHGvwhIue8lzZJ
X-Proofpoint-GUID: 2bQX-ReiYWMtgXVfFKBDU7fT8v6iA0b-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 spamscore=0
 clxscore=1015 adultscore=0 priorityscore=1501 malwarescore=0 mlxscore=0
 suspectscore=0 phishscore=0 impostorscore=0 mlxlogscore=993
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140036
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=O7P4PPAw;       spf=pass (google.com:
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

kmsan_handle_dma is required by virtio drivers. Export kmsan_handle_dma
so that the drivers can be compiled as modules.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 mm/kmsan/hooks.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 7a30274b893c..3532d9275ca5 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -358,6 +358,7 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
 		size -= to_go;
 	}
 }
+EXPORT_SYMBOL(kmsan_handle_dma);
 
 void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 			 enum dma_data_direction dir)
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-2-nicholas%40linux.ibm.com.
