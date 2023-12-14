Return-Path: <kasan-dev+bncBAABBEVS5KVQMGQEFO25TVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5919C81272E
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:35 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58a276efa48sf9716218eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533394; cv=pass;
        d=google.com; s=arc-20160816;
        b=d4rk/54loZ0NVCrxqVYqVzg9ECViECqqHOha60dU/e8LaLKZ/zJZJtxUnzZdmyqJXm
         EaHzsoLtuNTRhMt7cN7dI6ubsHCsXyZ7Dll25xIT5o31ziQwRv6A6gq6YmYTcBvWknGF
         3Pmf+1evpp7sn7hMn3RxhsnWGNnc5pqs/DMZMYQhyLmMgoPhP5WAlWxbiEhy2xE4seXv
         Ukd6aBRaWUapmlRAScVW3MtR+q4AsAIj+sSHyM/H7ub+Xy6XOSulc/bTq/EVX6Fnxi8x
         hkXNr3cXLkd5affz+K8eOaeOqHrBQgMmd9qTXwLVppGgXXRH7ukSQTInXUVyKdV6/UPS
         pMlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5BkBeXgcbQW/MaA8TMa5CwPW+8DUMDPcxBkX5RFPvKs=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=cM2oPX7Bxxm3ygs5C4ICAvQOAy7kBLOVlJMLzgbEKJYbxp65HvQCuno28P347XyLBV
         JUwnYiIvs1nHc0iCQFz2OPC5k/gtjjPI9Z10sipYLqSrFQ9peFETCo1P+TamJ9h2RIfH
         5vCqaXGdKyqfjcvKzIBjlVWwHxXLHaCSfbQdg0naltma/TAea+tnnnDx/cPzY9+3C5zU
         ftg484gdlDyOXPoI9W5pB+QAzlFuYFlZ8V4ybqPuO2pWvaFepxS6/9VZlOZxUUrTadag
         b560G06bAy4MczvLbTKzE9gpxG6uBcHIe+Lz8Vj9jrHwi9hAxan7fpLawLuY0qlhY5J/
         om+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qy8SrAG9;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533394; x=1703138194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5BkBeXgcbQW/MaA8TMa5CwPW+8DUMDPcxBkX5RFPvKs=;
        b=gU6QckyibRqBXauzZC6ad6Ga4FPzISqqy9tffuJQDmZu0uSs9BFXIAAkmHTWXvXY5Q
         eG41fQfVDYDfLFafW2tSqdtMpKFGP86bgQw1XNnj3F+6Dez13/I5ZCHPHvHOeub6BeRe
         /k6hQlcyQH2T90aIF88Xrrxod7MLUusEQQq0iWam8G5XzQb1IlkEnPZqCNyeeI7RClCP
         xjOZ9NhvDRPs/zzqelfbSMbugRk0jPNOJhuIiXJ5UWtHpwEPwdGVOMidBUQvbiAXrNh2
         jzNJHkf4Anczhhx7WpMyOPpDk2queb8vnvWimMCvY/eqOiGbO5Fxv/+Ah8ETtw8NKWN4
         jnow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533394; x=1703138194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5BkBeXgcbQW/MaA8TMa5CwPW+8DUMDPcxBkX5RFPvKs=;
        b=B15EgdyTMNrd80cVG0AxJpxK5CpfhV38SIHuiY0NuI75uDDmsr/FuEjbU9hTFeIWvO
         +QBLCE7ImVf6Fv2zqy9tC4BsbHthF7R5hqJ0VlauQOx+V5/heH0FauOs+NPCvBO6d7hn
         EljUSN31VxYBQ0h7JYgEoILRXjyShYma4z1nMKXZSTT8fkK4cPkm32kk2q5ndGuS9xmn
         XbhoRBfw+SxVy8gNjtGduyWpwucfpQGGwFuZk4Tp6Kgwbphfue3JMOZTDlrojG7deuYH
         SW5IyDGPfE15yqwjc7D12Q8NDRS1uATt7ADllotzeP9Kb9Ii+cIz06lgqhsXrBmqo1oT
         acpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxfwUKr7ezkziucoUHYcDg4Fm+UZ9BeMaFy70UDonUuNRz3bVdA
	ZsRqBO2SY5hTzAWdkYvA9ys=
X-Google-Smtp-Source: AGHT+IFRfuznAmz2P+6DXNRz40lGvQKXQKnk1n1k1V400BsceFQV4CvN8G/YZfmovCcGXVA4H4CLUw==
X-Received: by 2002:a05:6820:1627:b0:590:2b6d:a862 with SMTP id bb39-20020a056820162700b005902b6da862mr7322628oob.15.1702533394143;
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:602:b0:58d:c8ea:facd with SMTP id
 e2-20020a056820060200b0058dc8eafacdls3099513oow.0.-pod-prod-01-us; Wed, 13
 Dec 2023 21:56:33 -0800 (PST)
X-Received: by 2002:a05:6808:640f:b0:3b9:e4d1:9657 with SMTP id fg15-20020a056808640f00b003b9e4d19657mr9866560oib.19.1702533392866;
        Wed, 13 Dec 2023 21:56:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533392; cv=none;
        d=google.com; s=arc-20160816;
        b=KWV6fftkorbqdEX3sAeUek/qk3+5wDeBtADBpkjxpegLX+p9IA+A2q1DraS9+AMBCG
         88jo+sU4ceyz4q4vNgW/lWoUsLEMpF6d4wbP7E4vRLN+AvuuBR1prpY3tAPsJYpTm9LF
         lMGvd0qXYSwktgl+uix/S0Iwcb2ZjGLcAh3tgCpeW/3E/3s/R5MPqYg1ywuH14O4ASGW
         KG/PrNpHMFY3dJhMNECs0JTS+XcAC9j5JXV9VCLJBNPDFAZFok0wG0rTVPxiqN2BZSuW
         c56AJ8bkYn8L6I7t48MeANCvthbw6fZ8csRtX7dGVj30pFQUH2aDA2atJDDezbJ9TxbY
         nzfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iEucn8MPWHb8gdt1ku/4VB8RB4S52vsUNHa2ubv6AXM=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=L/ewJdCpQ5PZ+0MuIBi3B/jxXRmOdiD/VXR+R/ixVLpc9d1lYsQ98Hr/buYVbMHj3L
         YgPVhGY9eJfUfxk5Y6flAHShWRESJ/xc+uCgciHItiXFAQEblMo1JasqUbXHOLh2PISn
         RSzULNZZGuPdGUvZ2wS9rntflNgbnSOmpT2vUQrUbUgZB692Pn6iWVcjMmQQ2AtfJlng
         1qY6ZjAoGj7N2NfTgNn/G4zVVhf4eosTy9fdkMpOiH0p3YvvhbGAGtX94vBjgA74VzPf
         yHaqnfSd8tWMVQnUFpTxPxhPvVEaXRZI15OcAVYZVwBoKDTBUmjvD/G+uOTbU6sMJywE
         XWiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qy8SrAG9;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id gu17-20020a0568082f1100b003b9e85a78ddsi1267143oib.4.2023.12.13.21.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:32 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE506VA007793;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg3cj6q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5PCHY009786;
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg3cj67-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:24 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5sZq6008442;
	Thu, 14 Dec 2023 05:56:23 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtpnfq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:23 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uMHA22151726
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:22 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EAFB92004D;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7C7D120043;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 6ACA2600D6;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 03/13] powerpc: Disable KMSAN santitization for prom_init, vdso and purgatory
Date: Thu, 14 Dec 2023 05:55:29 +0000
Message-Id: <20231214055539.9420-4-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: tGzZF3E5YBSAEi-LT31YAzRubiKi2f0r
X-Proofpoint-GUID: BEavQEDS5PQBgWzLfLd3K1kN0uk1GSRB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 priorityscore=1501 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0
 lowpriorityscore=0 mlxscore=0 mlxlogscore=431 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=qy8SrAG9;       spf=pass (google.com:
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

Other sanitizers are disabled for these, disable KMSAN too.

prom_init.o can only reference a limited set of external symbols. KMSAN
adds additional references which are not permitted so disable
sanitization.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/kernel/Makefile      | 2 ++
 arch/powerpc/kernel/vdso/Makefile | 1 +
 arch/powerpc/purgatory/Makefile   | 1 +
 3 files changed, 4 insertions(+)

diff --git a/arch/powerpc/kernel/Makefile b/arch/powerpc/kernel/Makefile
index 2919433be355..78ea441f7e18 100644
--- a/arch/powerpc/kernel/Makefile
+++ b/arch/powerpc/kernel/Makefile
@@ -61,6 +61,8 @@ KCSAN_SANITIZE_btext.o := n
 KCSAN_SANITIZE_paca.o := n
 KCSAN_SANITIZE_setup_64.o := n
 
+KMSAN_SANITIZE_prom_init.o := n
+
 #ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
 # Remove stack protector to avoid triggering unneeded stack canary
 # checks due to randomize_kstack_offset.
diff --git a/arch/powerpc/kernel/vdso/Makefile b/arch/powerpc/kernel/vdso/Makefile
index 0c7d82c270c3..86fa6ff1ee51 100644
--- a/arch/powerpc/kernel/vdso/Makefile
+++ b/arch/powerpc/kernel/vdso/Makefile
@@ -52,6 +52,7 @@ KCOV_INSTRUMENT := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 ccflags-y := -fno-common -fno-builtin
 ldflags-y := -Wl,--hash-style=both -nostdlib -shared -z noexecstack $(CLANG_FLAGS)
diff --git a/arch/powerpc/purgatory/Makefile b/arch/powerpc/purgatory/Makefile
index 78473d69cd2b..4b267061bf84 100644
--- a/arch/powerpc/purgatory/Makefile
+++ b/arch/powerpc/purgatory/Makefile
@@ -2,6 +2,7 @@
 
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 targets += trampoline_$(BITS).o purgatory.ro
 
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-4-nicholas%40linux.ibm.com.
