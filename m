Return-Path: <kasan-dev+bncBCYL7PHBVABBBBHWRKEAMGQEJJ2MWWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 130913DA65B
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 16:28:21 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id t101-20020a25aaee0000b0290578c0c455b2sf6853514ybi.13
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 07:28:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627568900; cv=pass;
        d=google.com; s=arc-20160816;
        b=kuGmwCJPitzgewXLHliFwyzbgBaEUPwAGoQLSO0CL1xIeLCiWVQ6Gr9UyChWQpGP4q
         8Nr2fQwMVL2wNN/m1biAFKxNYRQ3GQUoltfV88mLg20Is/13xRl8LpDKLsVOX7i+fYrk
         r8DbPlUTF7yTnBUzmS7G0kXUvekZVPQMQ+d+tmAFXAxKXHqq3cFxe5AgdCivH1ZQBQdb
         4RvR26ga8+RrwjXCLlyA2NqdcGvzJWxMibHCYPwlQsXC6zfqcReAs+A2m2JuJ/A3sqol
         W7GPcAhdROXWKJL50RFi9AQns/gyz7lE7ynEdTdb4uv0feM3DOXqeb6t5JM5jJP8Y+pr
         i5gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=V2Wish1dW85OIZ36ldt66jgfBbfxpf/hQrk8kYCpQY8=;
        b=Lud9eT0VvDe0L0lkau/3aLe1ICVpR5MnoCd0hWQvnlPg7qwWriD+CJ5xodJbRIySxe
         JNW6clazW0q5pxYrY3sA5u6A4tFio7SbaUl8odkC3PHO0mChgJ28OyUQ/Mnwf14QNBK+
         5YK+236z8EiNlWshfIiqQqvqWTb9z9P09xEY8thcTxnQtvCUV/mzgyzUIlr4ht3CAu7H
         7wA6MTIXxmJcJ5GoNjQMTGFcqmB30NOyOPwwWmC1aznipO3oR2qitmQ34uNyB/pl0zae
         VymKeDkQqUUA5kiKSy26VtLO1JSmbSwzw2mX9IbvTeahMwl1rZ22L8gLR/+fZXLHjxQm
         y2RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gwPosHOP;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V2Wish1dW85OIZ36ldt66jgfBbfxpf/hQrk8kYCpQY8=;
        b=eErl+dl+eUGG/Uxw7m/iY8CQj6frGN61+oL/q+FyCFmt4mkLfPkLl734L4iTAHsXJq
         CDnrgkmb3gTkK7ozBMZcCiUEsxC0M2SK5rOfz0AEooTZLkJGvEe9L41+CGCmxdhEUxFF
         Cv05Hcgs6abbMhKu1XbPbS1Fsvd4Vm9hz0ySAA/H4NdCyZ2CfPKweGPOUVstMXuoUe1I
         yIrLYQVgOti0d2vMfm99jw3FK+KR4Mlx6lbDkthznbkR+3EwY89tcHLiwShnLTkSf/By
         6P+0K9hTGy4syixmEZlSLDauZlJKHtR1dn/53h/IJFinZz3emNkLtXeoDDgZAwXd9o9k
         BFZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V2Wish1dW85OIZ36ldt66jgfBbfxpf/hQrk8kYCpQY8=;
        b=VDWK5oFHEfjURHqjhgkwJ/v4ydugb1trJ6TWsENdIDZxefkj1jtPsAaIlGA1CDrYMd
         X05YNYSSC0iVtS+AgdoQZgiW23ErE57Y7D9v0lslvN3Y2iqiEjmXkT83MF6M8Bpk0wwb
         7SyvOqhUos8XjB0HFnM/KN8zHhw5nwskAgFKECZ/IDGsX1svX6MBe2PgE/IhE+wJ3z+/
         JOBZsnilExzhE2/DOlwFSDCH/TGrfP3MTTv5HO+Sj0DpCMJ8M2fKo0lZK7ykh+D8QBw7
         +WIhfnwZx5BK97KXJ/VDu/Hb967k6sfcYuI9wH8ms8or7pX9aWkEivhmyAkK/dx8wC4Z
         NSGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IRDNwER7RnZrWrTg0WUESv3R1bUXt4uYQIMs4kfcFZ3FcPdUc
	7tMQIzdI9Qe6jBOYqUwYWps=
X-Google-Smtp-Source: ABdhPJz2mLtc0Mxz44Ir+IIKsIqeRhO+8GElCPulEwKWWE5UnSi4KcPmoQOQ0DHV6v55XOsndpvpaw==
X-Received: by 2002:a25:ca58:: with SMTP id a85mr7078079ybg.318.1627568900186;
        Thu, 29 Jul 2021 07:28:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:add4:: with SMTP id d20ls3227514ybe.5.gmail; Thu, 29 Jul
 2021 07:28:19 -0700 (PDT)
X-Received: by 2002:a05:6902:521:: with SMTP id y1mr6959803ybs.338.1627568899702;
        Thu, 29 Jul 2021 07:28:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627568899; cv=none;
        d=google.com; s=arc-20160816;
        b=JXDM9TztFPZlO6QO8dplbplziRrTaw7di1ihE302FKflVEmk2anNGFAskJhBcuin84
         oKt/188kmbax40rWaqnGR7W9KR6WgC+FWWWqBhtj94zvR3z6/j6s1zGc14L8iXZvSug6
         uWellIKrvZk787AYspiB/HBIMb2nMEB1MlWv6b1qZ/s3mnZ6gbO2O92nUk6iTUH1FhpF
         9b0j4rpREEhkw7587Fo5jJ00ekZKuY3HwStvyRZaQDmzifAXXUxM1Ptw7PPNdgmmxtY6
         B6aZsyhxFOZIBiQHyk++fp2CblEMDgdMYr8L2WjCVyJV2EmRtsRYylwWdKTblStRAJZD
         la6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=XRODP8YE+txQpLPc89b48UgaznBirPsnMkB+vT1cawU=;
        b=DNsvWHCOzshuL+Hnft1VKA9Vz1U6PxrMjEONo+prI9INK5K3dLJUmrhFFkY4JLUCDq
         dIcqBOt/y9h2W0HhGcW+9BVfAHpX4iYS+WZ6km6UQtvW0D4g99MiBtaq4iNFX+e/Qp1a
         EeECxiUN++s2iC4Ie+oVyokY8rc4e/09HyR++I9rkUH6F72bwcjC7/cFl+QOAnp6nYZ9
         76AJ1EK/raLyT7HVAMnA0QdIREO8okfTAJqNlS+IwOiAiWTyrdSf39a+OzCQTJTQV4io
         RL/HN/EdWZQRKkZU/UPc37hs8ms0+zVmAuscXSfaAOB/oeWqmn6b42QVBDSj2JfQaLbB
         zfrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gwPosHOP;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id z205si379411ybb.0.2021.07.29.07.28.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jul 2021 07:28:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0187473.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16TERnP3017894;
	Thu, 29 Jul 2021 10:28:18 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3wnehrap-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 10:28:18 -0400
Received: from m0187473.ppops.net (m0187473.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16TERoqJ017947;
	Thu, 29 Jul 2021 10:28:18 -0400
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3wnehr9c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 10:28:18 -0400
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16TEE0gj028769;
	Thu, 29 Jul 2021 14:28:15 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma03ams.nl.ibm.com with ESMTP id 3a235yhs7b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 14:28:15 +0000
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16TEPRr020906300
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jul 2021 14:25:27 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6ADD2A4070;
	Thu, 29 Jul 2021 14:28:12 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1FE28A4066;
	Thu, 29 Jul 2021 14:28:12 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Thu, 29 Jul 2021 14:28:12 +0000 (GMT)
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org
Subject: [PATCH] kcsan: use u64 instead of cycles_t
Date: Thu, 29 Jul 2021 16:28:11 +0200
Message-Id: <20210729142811.1309391-1-hca@linux.ibm.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 9Jgx2r-XZ9TgTC-47AcGHpMtFkUCF5P-
X-Proofpoint-GUID: AlFAIIaxLvX5D_dB6HE9gxXME3G4Fqba
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-29_10:2021-07-29,2021-07-29 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 spamscore=0 mlxscore=0 impostorscore=0 clxscore=1015 suspectscore=0
 lowpriorityscore=0 adultscore=0 bulkscore=0 phishscore=0 mlxlogscore=999
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107290089
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=gwPosHOP;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

cycles_t has a different type across architectures: unsigned int,
unsinged long, or unsigned long long. Depending on architecture this
will generate this warning:

kernel/kcsan/debugfs.c: In function =E2=80=98microbenchmark=E2=80=99:
./include/linux/kern_levels.h:5:25: warning: format =E2=80=98%llu=E2=80=99 =
expects argument of type =E2=80=98long long unsigned int=E2=80=99, but argu=
ment 3 has type =E2=80=98cycles_t=E2=80=99 {aka =E2=80=98long unsigned int=
=E2=80=99} [-Wformat=3D]

To avoid this simple change the type of cycle to u64 in
microbenchmark(), since u64 is of type unsigned long long for all
architectures.

Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
---
 kernel/kcsan/debugfs.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index e65de172ccf7..1d1d1b0e4248 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -64,7 +64,7 @@ static noinline void microbenchmark(unsigned long iters)
 {
 	const struct kcsan_ctx ctx_save =3D current->kcsan_ctx;
 	const bool was_enabled =3D READ_ONCE(kcsan_enabled);
-	cycles_t cycles;
+	u64 cycles;
=20
 	/* We may have been called from an atomic region; reset context. */
 	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
--=20
2.25.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210729142811.1309391-1-hca%40linux.ibm.com.
