Return-Path: <kasan-dev+bncBAABB3WLZTFQMGQEWFBBNEA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uDVMB/Elc2nCsgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB3WLZTFQMGQEWFBBNEA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:33 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 980A871DCD
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:32 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-29f25e494c2sf21523335ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154031; cv=pass;
        d=google.com; s=arc-20240605;
        b=NtLsNA+4VDuyV3OcOrtRFCJkYBECC7Yz2Yq6Tf1NxGr4cy2lY1e3jq1ksSsjmE2AW1
         M5gIAxMPOA0z+SrCZ7LvHkiGK8jzOrNrrrGg6iyXBphjgOb4BZn1NY8Xs9CPa8dAe2jE
         whsbGU/PzilUTyGcyHWdd2WZuncvt4Ws6BQh9eTURApcVkRUc4iHZa5NYM85XfHa+SZd
         Q1PRH76eXEHhc02OKwj221sA5D516NNUCxKdTQTm3AX8p6OQthNELGLnx80/2GzORuKM
         8oW2zGqcCEWIDEjk8r7Eno5NoqVloewLsQ1HYhZXspoQ1WcbC0MaN4UwZQDplmKnNxPX
         V7Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=VNRf1cfJcv/FSuNq360+TZf4Jjt3gFpAqpfKaGa6LYQ=;
        fh=8G8x1o1sYRPN0TIpTw9efO2e4VE3EB+7bn3PfJI0UkM=;
        b=RQGWcj6cFyayLdK6R4ovvaXZ7MiuQLjLRbDbTgwQqRZKJ4OUBEsfVmfOJ1p1vKn+al
         rlTw/JsQAhxHYQdfhZOVHBENWWem46kAd68L+Gksnm1IA41xFF3Yle0oGszAT4GJrYxP
         F4gf6H9tU84P8KTKkO0leJozWC65/Co1k7SM+/v+nYQZA+l9jzuNCRIhZjBsAHEGERVW
         jUImKVcg9vn9ujcr48jRI/H8W7YRmn4YOK5JWUvH2fRFTjRCDW1LiI01/5Vd9eNu5niv
         4BOjDhewrG2sURqorOpyo4RjMi3LwimMDRWAdiV05FRLTa3u02i/twyzl/R9f8c1rCS4
         C2eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=F3toyvyN;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154031; x=1769758831; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VNRf1cfJcv/FSuNq360+TZf4Jjt3gFpAqpfKaGa6LYQ=;
        b=BLxooCcJTG0ITo+MLqjCScBKbPU65mvzEnipvZjnk5u6HbbL/LWL3KNr0bn1ZABykh
         JdeqRI/PDwAIzzsIKY38GDH2ok2SLUWQ+gTS+YRPqytsWLo8oVkpWp1OZaya58C8qDv+
         /OCcTeG3lQfzUIYKHc3p0SNOchEwpO5Z8s9aCv3nIdag0u6JTrDqpgKe5znVktjMRY30
         DV5Z23ThrDQMyXorQnIAI0DGNceMZwKvYkV3I9FjR/pLvupcGZAdE7jXvlTSs5n514yz
         GQXIbmlRiVdTiuf4b9aLLfCOdLeWOc6LynmVRQu00LqrBK8+pgTL6vphkzPQn1P5wfe9
         BX2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154031; x=1769758831;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VNRf1cfJcv/FSuNq360+TZf4Jjt3gFpAqpfKaGa6LYQ=;
        b=EXIAN1XKJ2R4izAWOQaaxulFsQk940KbHiF5eIoKipgYULpaa40Iq4oSYKfNADWIDL
         XE6zapmjRUXNOZF3GMBvWXYd9wr/2ByxmmRI/MO+Lif57ECu/jjlMESjzZSOuwB6TrN4
         DghtoO9SFRSGCx7Jdk/6Q0NWIJlH4MLX6gkLM98RSqqNgineb+6y9EtouZmcaHY8Ncq7
         SxNezDNksLy0xIDIGsoBJ8BSZKekDxNTA1+54W/R95BaiFBCwX/CStdbiEAkiA41HO1B
         SKmAjd+oxBtgFoIjpHAea5cnXrNlblRUW+smosbcRbM+BhV2OWeXgUBYkSrSquiUyoIj
         cTtw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnn/iX246LVJgaaF5R4V0m+6WS38+om0EE77/S2QxY1nhRJie53yPriU9sdNs3T+e0K6+h9Q==@lfdr.de
X-Gm-Message-State: AOJu0YzFG73Oa74kHV7eqKr+p3XdaUQqtyhraNpd2jogvrYVqd4qe6vX
	LmleWz+PSefmyylRu0JrFCezbMqJS1cJ/sWfYDd3GIBmWFEWFBncgpRc
X-Received: by 2002:a17:902:dad0:b0:2a7:a1f3:f327 with SMTP id d9443c01a7336-2a7d2fa093emr50544895ad.20.1769154030927;
        Thu, 22 Jan 2026 23:40:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GCHVIy0kHDlmaka/kWaP5iBoN1G5Om9t372DAl7nFtkQ=="
Received: by 2002:a17:90a:c292:b0:34e:be5f:7cfe with SMTP id
 98e67ed59e1d1-352fad4f56cls1098769a91.2.-pod-prod-00-us-canary; Thu, 22 Jan
 2026 23:40:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0IZuBzXy4hlg9zKdfh4lGnwlHltZrCHcyp2CJgatbGKubOJl61o9z2dLcXJSUu3gCOfBl0f/Ljhs=@googlegroups.com
X-Received: by 2002:a05:6a20:5483:b0:378:53dc:ea9c with SMTP id adf61e73a8af0-38e6261e344mr5237315637.3.1769154029361;
        Thu, 22 Jan 2026 23:40:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154029; cv=none;
        d=google.com; s=arc-20240605;
        b=emALW+UNeri6SKLuBoLsY5Rsx/a3lwelgHaHmaHsKQl5bfV8PheYOIb7PWfZ+Orxn1
         rwFH0q0h1j5vsstn+asVf26vK68USGnf20SZd1Vkrod5tPLd/zozixFcdMLzWYrVxTTX
         AsrK2MAd/mXpIjo7zCOa7rc1Juy2uH7FQcEn7n8mgqw8l0OGG5Uk2GST4D604vnXhpAz
         f5y7+RvnE5EwjRqj2M7hnNZSX/T7SenA5xtS6rNUtD5zqFzqjoMVBvcZ2TNE8OFuGGRt
         b6UdVtffmDSmq7kLGpipIbSWv5NN4OX2bvLCs6cp/RYSox0XH/3UmJ3Zo9Pz66NJ8VWK
         FJiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=B96eqxBiTo98pHzqabXyu4MFkhh6JhjrUmi6hCNa5VE=;
        fh=4dZC5b+GxnxvIHnzjVMCNym7rZ5j81Xogzb8TUs6Lt0=;
        b=aEyPfUzwhDdkGFW8t3+3OXODTRAC1Ku+0WSsvFnw7/HhEjlZe+p/lUEhnZoC/Dj7t1
         4p2VJoys0CEcT8Nh8OTEoaShkaDP9KSrLFa8crTFDJW3iGMsM4Arllk4jz5ItRLrwk77
         godzT6vi1wyeQS/tE0AzQ/lxg429Pth6JivMkNCWnT+9vtvqhstxZHKjwbOVU12V1gsN
         Kqy8VZ+233rTE9/bWI52BnJFEdxhEl54904YDhcxl6YOsGnq/AtUalwEGIU+PpjDsn9k
         v9hsXo6KZVaGiCFF1b/PuEka50lqfIdY7TSQelroccfqSmvmmWVGhbu0mazQugaWIrmN
         n1/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=F3toyvyN;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c635a1200eesi63490a12.2.2026.01.22.23.40.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:29 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60MLCbOf006864;
	Fri, 23 Jan 2026 07:40:20 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br23senpb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:19 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7aBEf022230;
	Fri, 23 Jan 2026 07:40:19 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br23senp7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:18 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N6G4oS016668;
	Fri, 23 Jan 2026 07:40:17 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brn4yfxhm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:17 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7eDub32637298
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:40:13 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8AE252004F;
	Fri, 23 Jan 2026 07:40:13 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 269792004B;
	Fri, 23 Jan 2026 07:40:08 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:40:07 +0000 (GMT)
From: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
To: maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com,
        chleroy@kernel.org, ryabinin.a.a@gmail.com, glider@google.com,
        andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        oleg@redhat.com, kees@kernel.org, luto@amacapital.net,
        wad@chromium.org, mchauras@linux.ibm.com, thuth@redhat.com,
        ruanjinjie@huawei.com, sshegde@linux.ibm.com,
        akpm@linux-foundation.org, charlie@rivosinc.com, deller@gmx.de,
        ldv@strace.io, macro@orcam.me.uk, segher@kernel.crashing.org,
        peterz@infradead.org, bigeasy@linutronix.de, namcao@linutronix.de,
        tglx@linutronix.de, mark.barnett@arm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com
Subject: [PATCH v4 5/8] powerpc: add exit_flags field in pt_regs
Date: Fri, 23 Jan 2026 13:09:13 +0530
Message-ID: <20260123073916.956498-6-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Z0DOHKyWIf7TUDiVz_KZIDbrmZn-ldJ7
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfX63DDZlzSUdRJ
 ZfgOP4BwRqgqDJYwCOx6ozJ8J8jj+/zaqvNfZyaHvdNpTD151C+OCnJRfQpMx+lUjMIkpH+U3S2
 2Tsqqp87JCw6saL8Ea4CNra1HCg+N9bf4wJNI8mU9+QFwvBv6WyFUazX6N6egN3DKUS16iF4GL4
 Ao74DkBYgEQSGMKKDg0HJm/e0cF5z5IIO1WRHlJDSgLpKvHJeV3LbEX2kceffZailZN4cSsxe/9
 n/tX9zxdrbpqXaOd658heVGongn3lrdRW3LKiIFoL2206Lh+hx4zJDNxUio+wA7xfxfbDFNAqQr
 RONSmUNjho6CVtxw5adjHdfhHhRYp1GX2PZwMbrGn+yJk69JaWNFIUhnfl5hWDYy7U1Mg5p4Gga
 dCnELYz1YLzbafDVnNBIjHeD46j4mcWLdxwOd2UK/UdBtRrrHl2Lh5nDYQ1Geea3EY1Gk91GcqM
 yICZAeazwUuO7aYd3Ew==
X-Authority-Analysis: v=2.4 cv=J9SnLQnS c=1 sm=1 tr=0 ts=697325e3 cx=c_pps
 a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=wNVWKEKBPlwGkIktZH8A:9
X-Proofpoint-ORIG-GUID: EJsRJh1CGK2KQJfwhIF5-bniCn4dDvkX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 priorityscore=1501 impostorscore=0 adultscore=0 suspectscore=0 spamscore=0
 lowpriorityscore=0 malwarescore=0 clxscore=1011 bulkscore=0 phishscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2601150000 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=F3toyvyN;       spf=pass (google.com:
 domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=mkchauras@linux.ibm.com;       dmarc=pass (p=REJECT
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_CONTAINS_FROM(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABB3WLZTFQMGQEWFBBNEA];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[31];
	TO_DN_NONE(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[mkchauras@linux.ibm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_TWELVE(0.00)[13];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-0.998];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 980A871DCD
X-Rspamd-Action: no action

From: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>

Add a new field `exit_flags` in the pt_regs structure. This field will hold
the flags set during interrupt or syscall execution that are required during
exit to user mode.

Specifically, the `TIF_RESTOREALL` flag, stored in this field, helps the
exit routine determine if any NVGPRs were modified and need to be restored
before returning to userspace.

This addition ensures a clean and architecture-specific mechanism to track
per-syscall or per-interrupt state transitions related to register restore.

Changes:
 - Add `exit_flags` and `__pt_regs_pad` to maintain 16-byte stack alignment
 - Update asm-offsets.c and ptrace.c for offset and validation
 - Update PT_* constants in uapi header to reflect the new layout

Signed-off-by: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>
---
 arch/powerpc/include/asm/ptrace.h      |  3 +++
 arch/powerpc/include/uapi/asm/ptrace.h | 14 +++++++++-----
 arch/powerpc/kernel/ptrace/ptrace.c    |  1 +
 3 files changed, 13 insertions(+), 5 deletions(-)

diff --git a/arch/powerpc/include/asm/ptrace.h b/arch/powerpc/include/asm/ptrace.h
index 94aa1de2b06e..2e741ea57b80 100644
--- a/arch/powerpc/include/asm/ptrace.h
+++ b/arch/powerpc/include/asm/ptrace.h
@@ -53,6 +53,9 @@ struct pt_regs
 				unsigned long esr;
 			};
 			unsigned long result;
+			unsigned long exit_flags;
+			/* Maintain 16 byte interrupt stack alignment */
+			unsigned long __pt_regs_pad[3];
 		};
 	};
 #if defined(CONFIG_PPC64) || defined(CONFIG_PPC_KUAP)
diff --git a/arch/powerpc/include/uapi/asm/ptrace.h b/arch/powerpc/include/uapi/asm/ptrace.h
index 01e630149d48..a393b7f2760a 100644
--- a/arch/powerpc/include/uapi/asm/ptrace.h
+++ b/arch/powerpc/include/uapi/asm/ptrace.h
@@ -55,6 +55,8 @@ struct pt_regs
 	unsigned long dar;		/* Fault registers */
 	unsigned long dsisr;		/* on 4xx/Book-E used for ESR */
 	unsigned long result;		/* Result of a system call */
+	unsigned long exit_flags;	/* System call exit flags */
+	unsigned long __pt_regs_pad[3];	/* Maintain 16 byte interrupt stack alignment */
 };
 
 #endif /* __ASSEMBLER__ */
@@ -114,10 +116,12 @@ struct pt_regs
 #define PT_DAR	41
 #define PT_DSISR 42
 #define PT_RESULT 43
-#define PT_DSCR 44
-#define PT_REGS_COUNT 44
+#define PT_EXIT_FLAGS 44
+#define PT_PAD 47 /* 3 times */
+#define PT_DSCR 48
+#define PT_REGS_COUNT 48
 
-#define PT_FPR0	48	/* each FP reg occupies 2 slots in this space */
+#define PT_FPR0	(PT_REGS_COUNT + 4)	/* each FP reg occupies 2 slots in this space */
 
 #ifndef __powerpc64__
 
@@ -129,7 +133,7 @@ struct pt_regs
 #define PT_FPSCR (PT_FPR0 + 32)	/* each FP reg occupies 1 slot in 64-bit space */
 
 
-#define PT_VR0 82	/* each Vector reg occupies 2 slots in 64-bit */
+#define PT_VR0	(PT_FPSCR + 2)	/* <82> each Vector reg occupies 2 slots in 64-bit */
 #define PT_VSCR (PT_VR0 + 32*2 + 1)
 #define PT_VRSAVE (PT_VR0 + 33*2)
 
@@ -137,7 +141,7 @@ struct pt_regs
 /*
  * Only store first 32 VSRs here. The second 32 VSRs in VR0-31
  */
-#define PT_VSR0 150	/* each VSR reg occupies 2 slots in 64-bit */
+#define PT_VSR0	(PT_VRSAVE + 2)	/* each VSR reg occupies 2 slots in 64-bit */
 #define PT_VSR31 (PT_VSR0 + 2*31)
 #endif /* __powerpc64__ */
 
diff --git a/arch/powerpc/kernel/ptrace/ptrace.c b/arch/powerpc/kernel/ptrace/ptrace.c
index c6997df63287..2134b6d155ff 100644
--- a/arch/powerpc/kernel/ptrace/ptrace.c
+++ b/arch/powerpc/kernel/ptrace/ptrace.c
@@ -432,6 +432,7 @@ void __init pt_regs_check(void)
 	CHECK_REG(PT_DAR, dar);
 	CHECK_REG(PT_DSISR, dsisr);
 	CHECK_REG(PT_RESULT, result);
+	CHECK_REG(PT_EXIT_FLAGS, exit_flags);
 	#undef CHECK_REG
 
 	BUILD_BUG_ON(PT_REGS_COUNT != sizeof(struct user_pt_regs) / sizeof(unsigned long));
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-6-mkchauras%40linux.ibm.com.
