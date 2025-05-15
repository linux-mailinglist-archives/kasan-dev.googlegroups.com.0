Return-Path: <kasan-dev+bncBCVZXJXP4MDBBY7SS7AQMGQEIZNGWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B82AAB895F
	for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 16:25:42 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d94fe1037csf12093645ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 07:25:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747319140; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q16y9qPxiivdlC1q1iT3WkU0VSzLjdW4bCgZ0mmmhhuuXO/0bpPd4xVJ0zmuHa7OsA
         VNb7cmaegr3Xyy8m7HVImE0SSOZcHzIT7eQ+cpK5DvqwlMCImbFaDkItzjs52MI++1Ea
         ie2wu1x3xWec2yB1Pn+EsxhZDiA0LXUXheVfjhoGmfcs1HXscCcNjgAjevxUcqfp1wi5
         0d6uRule0Z6E5xrjyv4/y3xDnS4zruQv4H6O0JYEpBSXK3blu3re+kiuG1BRf5pF3seP
         0fC4EEWOGiiGQd5KM8GGdqjRys8RaijpuvtxVtwvPRgTGd1Mm0UXFW7ICHagXPl3/lgn
         VJSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=96cJc3yxttb/TQVt7xNFZqouVg0tUNBhl/MdIgsPopw=;
        fh=p1WDidKK/hDHBSNUUjRGvtOmHaTxy+xIeJsY2WdJUn0=;
        b=eakLuvbFOsuP1MK+YfBBtLeYr57P2Fiygxgw7tU5SL0aqH6shbVY3XUVIqeJL2N+Q+
         Nri5hw4mtQzdILYOqO9c3IdCwgCpat7W3781wQLYYXEbbpN80QtTABSsFN+acFKRzdGK
         F7I1UJSuNDPui4oeejqs73IzRism4yKeYBEhPpsiRzk6/PA109w/2Tgqb5+ZLfgQQzOe
         +M3FvA47jTGr6Pa9fw09AuuTlM3p6O3mdJFu2k40HqDxYyk7u4ium4qfwLdwLjz6/Jbw
         3gK67p9hehR7U+D1aIvsNC4ZI7cdUVD8TIROvJRaworzltDiaJVfZOtyrMphHGMiIzoQ
         xqYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WmU5zAaU;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747319140; x=1747923940; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=96cJc3yxttb/TQVt7xNFZqouVg0tUNBhl/MdIgsPopw=;
        b=bZSD//nbZyS7mX9IXsDg3J+DsuFENyR936pXJu+187xraGMzPk4CVZGcLl+HXYoBVg
         SE5gtXW89CTdsecH3cRXUqWiYEwjiTUwTsUXAyKjz1CxGaLXp+g3o1uHkkjIYlCwH6BZ
         aJFnWe7v8etbrflW6IehLnk1B7K3nlyfrnEh/AYOHg7YzwEi9pb5rpaS2lDcCffRRdl/
         hH+40jOPcNvMJtbkJsR/H/pwTE5hi78wKNElwiEsqgASiFzS2O96bdPYN2S3iP3+Hd0q
         3kwkFqAQrROlhJ9sAneWRpiwSdEeSqDanu0QecS2YzuR6fayJsZFvu07ZrrUuHUGHFbs
         H6Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747319140; x=1747923940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=96cJc3yxttb/TQVt7xNFZqouVg0tUNBhl/MdIgsPopw=;
        b=hdb3UJPgZKmhlIqzeACfArXIbuKUMIYEnI4kxwMXcTf0BZ8OKS4+flj2gD9AZLyfmS
         XmB9b8XwTWeuKrM4bBjwt5uObsKaBSMM/FjPDVkY0Reu3VsRkBEJVjqpTsX1IgkTLWgf
         v1d2hvMbcDXfAX8a3vDFeDONg2/UOivxpJ3DizGzv6YQvrhfv1XYGN3QIn4hyBX8gZI0
         m4SMoWHd8VxOwZ3Xr8W+hVIVXEa+MnuGUmOiA4MZZdKQ5TvH6CyFM1D6yUPs2InV1ybq
         Zmgb9g4axyv8fjksQORkSwRb8b6P1HHqrh62g7r4fmt7t9saUS3bDPUR7PqMQROhC8Qh
         YGFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbRAmvurgZJEl9hJStWs34rQtB8sGWxCJm0IiMvr1pjk2+IAX8OEEuRKGDVK5AkMUhbUxmXw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8dhCjMLTLj7aM5Ucbqe859MEgWFOeZQNyMXqv0kQBjN9s8Se9
	NZ0voCrqJuP0CVambFhV4yXpw/i1OLl4X0BCMTYq6MgAnGSTqlsr
X-Google-Smtp-Source: AGHT+IE5SSkF/B2oaUUCFYBu2f2el0/9w68kbgn8VjUth3E0t2mbW4+9BmHPp0pC075ZM7/jK/b3CA==
X-Received: by 2002:a05:6e02:3812:b0:3d8:1a41:69a9 with SMTP id e9e14a558f8ab-3db795b5f23mr30687095ab.12.1747319140188;
        Thu, 15 May 2025 07:25:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFA32NOgPhijMMc35X7FR7Sm1AFI8S8ZPJ9b3N40T17iQ==
Received: by 2002:a05:6e02:1fc3:b0:3d5:e479:cca0 with SMTP id
 e9e14a558f8ab-3db77e60528ls8349395ab.2.-pod-prod-06-us; Thu, 15 May 2025
 07:25:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOhcuHEjLi5d3Ozd2RX5/7oNoTL25q5dlLEww2R8pGThscpxvEmSo7YmhHVTmKkIoiEqnb/lQI+QY=@googlegroups.com
X-Received: by 2002:a05:6602:379b:b0:864:a2e4:5fff with SMTP id ca18e2360f4ac-86a1a039fe2mr436229339f.4.1747319139295;
        Thu, 15 May 2025 07:25:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747319139; cv=none;
        d=google.com; s=arc-20240605;
        b=ej1bcK67nrs+xgiwvetCwBUrp1Hi2aF1QpWWeMPqogzDRZGUyMZXB091q2wlf62lBr
         BseDgjmDAEqhM21ecZjtXbZBeQpKlRDYd1Fg784kMuzBmMDNmtT+EoAdSrhXnhhebUgp
         fEMorRAQ1AZwAoZTCjWlXdxYrf5viWs563nAKmbMK1SmPvC0klH+qRf7g12ltJ4d6mh8
         we/jzHwyhjoYiY1hAb571NjTy3hVzY9XhhPRUaXcNOsQUrsKBNeiUMDA3kRzWEPhzKVF
         QPSQdILC3VB4LG6o+VCsJ4t/X6kcIkQ8J0MqQ2yPAcKmIgi5UllMgswbXpoN5TMMEX5E
         CefQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=VEW6q6K77hbBMnPiQrFGgC+mDti52fcTnsB0C6QjaAM=;
        fh=JeYjkRDw/VSjlVIISM+t2OTgWgKSm5f4n50024gbhWA=;
        b=aLghYeqVdykPFdySKgWQ2zhfW4wfJVkex5s9MNf2e/AxhaitUBWVCFmtgjkpFekjPK
         x0NtaQuGkcNUeUCsrZy3s+o7V4174WCylaznDKuHbpRxma0sHiy0PrsSsfyrdqjGs/bE
         XUgWUqkoDc7AImT3mhbffxHsO22+UlA4lY/OrgfHeUujETNnm6i+nZ3KA2xBL1ynVeAe
         gheWk084byVAjJXIqHiXUYvrHVTQFyQN42a2VD7kymHjnWFj6HL9UhaNQthNbqlJdQJJ
         4KetvLg6JDqliY92zWNqj3xczEfoE/uxvsSQ1DrV4bPzQJ+gbMj5BNUVOMk7ufjNkwRE
         Gvkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WmU5zAaU;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4fa225025ccsi590082173.5.2025.05.15.07.25.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 May 2025 07:25:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54FCg8sJ002405;
	Thu, 15 May 2025 14:25:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46n0v6mxmq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 14:25:38 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54FEPbQJ021983;
	Thu, 15 May 2025 14:25:37 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46n0v6mxme-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 14:25:37 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54FEL9Vm021574;
	Thu, 15 May 2025 14:25:37 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46mbfrtmt6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 14:25:36 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54FEPYUv54591780
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 15 May 2025 14:25:35 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2E3CB2004B;
	Thu, 15 May 2025 13:55:39 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1B6E520040;
	Thu, 15 May 2025 13:55:39 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 15 May 2025 13:55:39 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id CFB7AE0697; Thu, 15 May 2025 15:55:38 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v9 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Thu, 15 May 2025 15:55:37 +0200
Message-ID: <cover.1747316918.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=IqAecK/g c=1 sm=1 tr=0 ts=6825f962 cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=dt9VzEwgFbYA:10 a=M4n5Zv9w_bjhLjlc4U8A:9 a=zZCYzV9kfG8A:10
X-Proofpoint-ORIG-GUID: gsjWp-Ng0dC36Dn2cBR5PS3eptApZOz5
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTE1MDEzOSBTYWx0ZWRfXxmHO/rxvOS6Z 3fEjEqJhV3MG0Cl4RIn0X+tlTvzgH63kEaBU7Pf6gPK3R7u6sHrFJaENBG6tOAKgxduSdeiEMVq Mi/mFGc8J4pov1w/K5o3hWHd2YHZ4kbxtGvZLV+jK0COKPnCmK1J5oUJGiuqapxWqBy63x38TPk
 F5itjgMCxz21A0joByb3ds2Mak4sk6O8MjzIeJVqRwTKy2VfcXTgCw8OSS6Hi3/qxZarlSX7P3E wx2WamWYFoce12j03HoPx0FMPaLNKLhwWvEkllkaSI3H/Elr1A9IcQxsICkLwdBpSm6ObbAqTIh 7ftPBMdouk3FdIJAN779vddxznFJg4K7m8DlTUwaAzNKN9tMFGMTe41togkHfQ7T39WUb0GVdYF
 nRdwdoZdkpyIQ4rwX6c3jJy+Pwc2yH0nAC4oObHuF6Ecy6mxm7ow1jIEb82fy74/3wkRhW7r
X-Proofpoint-GUID: Hz4sHBe_8I6zp0zDv4Z_aaQ_3JO_OM53
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-15_06,2025-05-14_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 malwarescore=0
 adultscore=0 lowpriorityscore=0 phishscore=0 impostorscore=0
 priorityscore=1501 clxscore=1015 spamscore=0 mlxlogscore=735 bulkscore=0
 suspectscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505070000
 definitions=main-2505150139
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WmU5zAaU;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

Hi All,

I dropped Harry Yoo's Reviewed-by from this version.

Chages since v8:
- fixed page_owner=on issue preventing bulk allocations on x86 

Chages since v7:
- drop "unnecessary free pages" optimization
- fix error path page leak

Chages since v6:
- do not unnecessary free pages across iterations

Chages since v5:
- full error message included into commit description

Chages since v4:
- unused pages leak is avoided

Chages since v3:
- pfn_to_virt() changed to page_to_virt() due to compile error

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 92 +++++++++++++++++++++++++++++++++++++++--------
 1 file changed, 78 insertions(+), 14 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1747316918.git.agordeev%40linux.ibm.com.
