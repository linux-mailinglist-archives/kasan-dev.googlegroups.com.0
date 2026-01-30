Return-Path: <kasan-dev+bncBAABBXFZ6HFQMGQEPSTIPBA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CEZTMd5cfGkYMAIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBXFZ6HFQMGQEPSTIPBA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 08:25:18 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 40BA5B7E58
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 08:25:18 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-8c711251ac5sf471319085a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 23:25:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769757917; cv=pass;
        d=google.com; s=arc-20240605;
        b=fs1Kj+cHPVg5bYT3XZOWTkFgvIh7aWtNwvUSxx+8V0EV56l7OKHdAxpNVmugEVlIJW
         4TUb0LcCxBypAX3yPzr8sN9Q87DKh0BLF6qn2L/zRLMfKl5E1F6ZVMKMvHDCLOQYWKj3
         f1uDWVSckrnCPIYgJfEtS2DagQcL6M7PnVUSNva4qmKDjxCRjU9lDtWYWKI0QIRGikqT
         DQpqZIATLWGu1XL0nrsfhH/05NR95ZLFrjXhVCH1jR6PJUmCxes7rWKlTXjwm4LE0hoU
         xgVZp0lxn4k+keg9Anhgybbp2mi/sVn8CXkuIZzMU3sTHa7E7+Un6UPmUhO+chmHH1dc
         oF/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=rlt6zsjtPgWRp2DqRBuhFtmeA7alt6N3smqkm5k4jv4=;
        fh=pU7QLJLbi5mioLHLnsSJYeVfvqx4TEaiFtrVQQ9jjfs=;
        b=K9O/DPAUJV24sxYEmLtxQn6CVxKE+XfP4sSRHLoWkMl4gmFgXBKbqsmIY1yJc/0yLE
         t9iGDOqpHHoaih32tumCKbSpUSaNG4TMuXeE3BX8yMuO0kzHwcd5yuNdos3utYs8ka0Q
         XiyrdHrc/xq73u29B0e4n7FSvJ65JJPc7rU+zW5GGzia584sCBmST28Uki1bZ9Knd3wn
         BbrLjKXLBKBrFwboChh+hGBp8EzXhIriN22zvM5loFKM0Q0fhdLG+jRsiXT2vrAD1TKi
         2M6wVZGbVOpfsGQYV5tykzAKgfj+H4t3mTvrvwY20DoOvQweLRYmqABv/IOOetlrjwpr
         zmoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KrNkDNoT;
       spf=pass (google.com: domain of venkat88@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=venkat88@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769757917; x=1770362717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rlt6zsjtPgWRp2DqRBuhFtmeA7alt6N3smqkm5k4jv4=;
        b=TWE8xn0tK6+BVXEo4Pfc0kRn46ToyaXcNZ3fO4KeBQbHtfoLFQ7jXmkWYrQvdP3Gsi
         Qd5S+1GSBMBjAwKTtxnBGncaovmNyrbwGhf3VLam78zQhwzjguvU1ZFLHEi46z1UiRnl
         mRlH8XyjbgRogHnZF4PAVcCDLJqrmmdtQ/rj05jHre3sSAKPGsYOG0wTv+f3g3GIKAJJ
         BPEFSroJwF85TRYbp1eTinYAnGaxFUx1UNr7X0dQ8Ykn8iV9Vd9hDSMnqszTQi8D/W57
         bIwuFLPj2L/2qnVuQ5AE3abF+qkNQLo42Qvo1xlyYHwBdHVXN22g7/boufh1Jr3BCuuH
         U8EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769757917; x=1770362717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rlt6zsjtPgWRp2DqRBuhFtmeA7alt6N3smqkm5k4jv4=;
        b=Kp9fRTgPWOuGTx9zCQmSI+HwsKjdsUUIreVQCWbYvKgjD8wGNS4rc+HKGt0HuTMZI2
         yL4r21E9SchBfA1uMT26xWMEJ7fTQ6FbvC0i8nF1JdpM8Y9wg5Gv0aECPl74osf8fFbs
         70REmfVZAXveC9JVBRhEmoqs5r26azNtCYezl5D/UnBvBMfJ+T5Ie/OEcbn0OjnnFIhK
         8dKmzTvKNvYfM2K6+xe0FEB38/KcurOup+Q5Kjt/UWt0LLhsPLiX5UWDuNSzUa92OzUt
         wXgekUxcQPWOqIo1l4Zven8q5AkGLoQTljhhiUk+dBRtpfECvplGXASWOdB/FF9E9Tii
         u95w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlbi8YflwPxEqiEtjbj06YRJesJBpdxPyj+MrFAu6OLEr7Mt+sRcJrTrdSRoCJJlfxonY0Ow==@lfdr.de
X-Gm-Message-State: AOJu0YwesUo5OLvM83qMCdOnqbIIfPOAz3A9mwPONrPcDByVArW4mMWp
	/+Xi9F2xJt2SlwvtSdPzJfH8UNLUCbsYn1Y7UckvgAiVE4IWSNMP7Vvt
X-Received: by 2002:a05:620a:4154:b0:8b2:e1d7:ca6a with SMTP id af79cd13be357-8c9eb31574bmr280284885a.75.1769757916715;
        Thu, 29 Jan 2026 23:25:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E6U5+A7OxJUpTV22dBxOHGY7YSEItKwFfyK8i6l6dsyA=="
Received: by 2002:ad4:5c6d:0:b0:882:63fc:f004 with SMTP id 6a1803df08f44-894e0c19cebls24075426d6.2.-pod-prod-03-us;
 Thu, 29 Jan 2026 23:25:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWuDfom+Essam/WNp5I6lkZvgds7Nu4CmF1tdjXJx265i6g/Fql1nCZxsY3FQFKunobd++pRcFkSgY=@googlegroups.com
X-Received: by 2002:a05:6122:46a3:b0:559:6d45:9a1c with SMTP id 71dfb90a1353d-566a0004642mr673452e0c.3.1769757915893;
        Thu, 29 Jan 2026 23:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769757915; cv=none;
        d=google.com; s=arc-20240605;
        b=hQinSQhzX2S6EiBxC5DeyeA3+L8HWsD3mUSVuhalBLceQTdBAIAKvXIvpGcn56kWy9
         1eBviZJ5B0kZy34YX/G+irk3ky74AWscFR/dBCD6Wu395BqrPZZnMD+GXgtF1pmJZlTL
         bA9t8f+jU4KYJVJpmPeri4Cc3FHzN2ISK+/AnteovG1AjueyEf2xiU3NsL2oFFgchlE+
         HVSUUGY8YhnEMO/sXJGVkrSQfoHYIZamMI//R7UnnMPmGPQLOKyBivoxe7dM5ZCMOOMZ
         Pepz6WRKF1wmFVwvWnxbBGdC8grPOmmb4lJZ9S+7hlyg+lln+rJu7ycvuWSZBOLoMGt9
         wqHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=Vp/MVXWKLfmcf3W30OS3OMGE1YCMMoCP2G4v7UNz/A8=;
        fh=AHviIPwk6Spb40nffcgGbPHb8mnurxsGNG5mjRifMAE=;
        b=BMabySxzIciq88Zu12+EnsYOdGPVhF3sDef46GcRx9jM1n7LhbXMMHpLcMsrNuOk6f
         KlpR1t4zCsp88NcsAm+zlmS6+2JxADCTsdFfF0yBomKSxEiwVhgQZ2Epitf1iQAOkD0I
         Mq2Zw1n3gDnNHcjOARKyOU/HmXChhagN9mX0dJaWJ2xItl0WzBua7OW6pBmqhadKxgIN
         hX6eYV55/kDuSJQmpcVrtok0OzQtFWu+HlXfTgXqJ8zrQZJerzFoTh8yARmxsprcVr49
         6viViVKhwt5tn0bX+V+0YsrDQvqimAbsfRDTCnZG918/sVsGl62/WABK+DCAc3oSeeQr
         qtYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KrNkDNoT;
       spf=pass (google.com: domain of venkat88@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=venkat88@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56685ba8018si265490e0c.3.2026.01.29.23.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jan 2026 23:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of venkat88@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60U2vfVe011251;
	Fri, 30 Jan 2026 07:25:06 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bvmgg9u1a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 30 Jan 2026 07:25:05 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60U7P5fx015866;
	Fri, 30 Jan 2026 07:25:05 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bvmgg9u15-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 30 Jan 2026 07:25:05 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60U24ewf018303;
	Fri, 30 Jan 2026 07:25:03 GMT
Received: from smtprelay07.dal12v.mail.ibm.com ([172.16.1.9])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 4bwb4251x9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 30 Jan 2026 07:25:03 +0000
Received: from smtpav03.dal12v.mail.ibm.com (smtpav03.dal12v.mail.ibm.com [10.241.53.102])
	by smtprelay07.dal12v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60U7P2X831326754
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 30 Jan 2026 07:25:02 GMT
Received: from smtpav03.dal12v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7568058061;
	Fri, 30 Jan 2026 07:25:02 +0000 (GMT)
Received: from smtpav03.dal12v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2AF2958056;
	Fri, 30 Jan 2026 07:24:53 +0000 (GMT)
Received: from smtpclient.apple (unknown [9.61.240.86])
	by smtpav03.dal12v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 30 Jan 2026 07:24:52 +0000 (GMT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3864.300.41.1.7\))
Subject: Re: [PATCH v4 0/8] Generic IRQ entry/exit support for powerpc
From: Venkat <venkat88@linux.ibm.com>
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
Date: Fri, 30 Jan 2026 12:54:40 +0530
Cc: maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com,
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
Content-Transfer-Encoding: quoted-printable
Message-Id: <E4046FE5-A919-4B30-B6D8-8F968628CFE3@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
To: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
X-Mailer: Apple Mail (2.3864.300.41.1.7)
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=Z4vh3XRA c=1 sm=1 tr=0 ts=697c5cd1 cx=c_pps
 a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17
 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=PKHrbpWhOttoSJa1NdwA:9 a=QEXdDO2ut3YA:10
X-Proofpoint-GUID: MOtuIipkCsAG32U1n9mma2eNkA-XhVLe
X-Proofpoint-ORIG-GUID: 1eWwm_FmuSP_nBNnRBgIffQncjCokOBm
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTMwMDA1NSBTYWx0ZWRfX6KNP6j5jq2+v
 nANystBdQ3Fe6bnYg3ATgoo+QUV4er0iY7XpMFXF6xm5NXGu8g6n2OmS2JJ1vFdFmpVKJwPgEhV
 IJ9UGdgyz1ALoUiOn//fgKTy4a3AwPq5Qs9AA1D+tCLocmcZds6VGjlFkYKl8ivJRf4+bbEZuWi
 rqyzd+piEVUiMufOrJLG2UsPpzDfEiPFQ/R9CNiS25MimTVdXcZvI7uChznUmALsqlgo90rtMdh
 cDsCLkuk3oRTGy34U0XMcanL0XPCbqRNZh9JjCP+PGbJ+Gxtqq+SwUtcto7WhIBIORo/xeNKIy3
 x9k80cATF1slciXugXstQ4HmrCunD5pu9RznmUy8ScwmmcPfRhfJnMGngRAbmpQ5rzyE2mhz5eQ
 uW7f77p2ph2EhGB4/TwTpDUUJmhE2RWmlS9WJbYLzeYlePxq6Kq8KYMvmrkXGhvhmSHCeIJi/no
 rxB7pPwZihtWOZ0gxfA==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_03,2026-01-29_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 suspectscore=0 malwarescore=0 phishscore=0 priorityscore=1501 bulkscore=0
 adultscore=0 clxscore=1011 lowpriorityscore=0 impostorscore=0 spamscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2601150000 definitions=main-2601300055
X-Original-Sender: venkat88@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KrNkDNoT;       spf=pass (google.com:
 domain of venkat88@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=venkat88@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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
X-Spamd-Result: default: False [0.39 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MV_CASE(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBXFZ6HFQMGQEPSTIPBA];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_TWELVE(0.00)[13];
	FROM_NEQ_ENVFROM(0.00)[venkat88@linux.ibm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	RCPT_COUNT_TWELVE(0.00)[32];
	TO_DN_SOME(0.00)[]
X-Rspamd-Queue-Id: 40BA5B7E58
X-Rspamd-Action: no action



> On 23 Jan 2026, at 1:09=E2=80=AFPM, Mukesh Kumar Chaurasiya <mkchauras@li=
nux.ibm.com> wrote:
>=20
> Adding support for the generic irq entry/exit handling for PowerPC. The
> goal is to bring PowerPC in line with other architectures that already
> use the common irq entry infrastructure, reducing duplicated code and
> making it easier to share future changes in entry/exit paths.
>=20
> This is slightly tested of ppc64le and ppc32.
>=20
> The performance benchmarks are below:
>=20
> perf bench syscall usec/op (-ve is improvement)
>=20
> | Syscall | Base        | test        | change % |
> | ------- | ----------- | ----------- | -------- |
> | basic   | 0.093543    | 0.093023    | -0.56    |
> | execve  | 446.557781  | 450.107172  | +0.79    |
> | fork    | 1142.204391 | 1156.377214 | +1.24    |
> | getpgid | 0.097666    | 0.092677    | -5.11    |
>=20
> perf bench syscall ops/sec (+ve is improvement)
>=20
> | Syscall | Base     | New      | change % |
> | ------- | -------- | -------- | -------- |
> | basic   | 10690548 | 10750140 | +0.56    |
> | execve  | 2239     | 2221     | -0.80    |
> | fork    | 875      | 864      | -1.26    |
> | getpgid | 10239026 | 10790324 | +5.38    |
>=20
>=20
> IPI latency benchmark (-ve is improvement)
>=20
> | Metric         | Base (ns)     | New (ns)      | % Change |
> | -------------- | ------------- | ------------- | -------- |
> | Dry run        | 583136.56     | 584136.35     | 0.17%    |
> | Self IPI       | 4167393.42    | 4149093.90    | -0.44%   |
> | Normal IPI     | 61769347.82   | 61753728.39   | -0.03%   |
> | Broadcast IPI  | 2235584825.02 | 2227521401.45 | -0.36%   |
> | Broadcast lock | 2164964433.31 | 2125658641.76 | -1.82%   |
>=20
>=20
> Thats very close to performance earlier with arch specific handling.
>=20
> Tests done:
> - Build and boot on ppc64le pseries.
> - Build and boot on ppc64le powernv8 powernv9 powernv10.
> - Build and boot on ppc32.
> - Performance benchmark done with perf syscall basic on pseries.
>=20
> Changelog:
> V3 -> V4
> - Fixed the issue in older gcc version where linker couldn't find
>   mem functions
> - Merged IRQ enable and syscall enable into a single patch
> - Cleanup for unused functions done in separate patch.
> - Some other cosmetic changes
> V3: https://lore.kernel.org/all/20251229045416.3193779-1-mkchauras@linux.=
ibm.com/
>=20
> V2 -> V3
> - #ifdef CONFIG_GENERIC_IRQ_ENTRY removed from unnecessary places
> - Some functions made __always_inline
> - pt_regs padding changed to match 16byte interrupt stack alignment
> - And some cosmetic changes from reviews from earlier patch
> V2: https://lore.kernel.org/all/20251214130245.43664-1-mkchauras@linux.ib=
m.com/
>=20
> V1 -> V2
> - Fix an issue where context tracking was showing warnings for
>   incorrect context
> V1: https://lore.kernel.org/all/20251102115358.1744304-1-mkchauras@linux.=
ibm.com/
>=20
> RFC -> PATCH V1
> - Fix for ppc32 spitting out kuap lock warnings.
> - ppc64le powernv8 crash fix.
> - Review comments incorporated from previous RFC.
> RFC https://lore.kernel.org/all/20250908210235.137300-2-mchauras@linux.ib=
m.com/
>=20
> Mukesh Kumar Chaurasiya (8):
>  powerpc: rename arch_irq_disabled_regs
>  powerpc: Prepare to build with generic entry/exit framework
>  powerpc: introduce arch_enter_from_user_mode
>  powerpc: Introduce syscall exit arch functions
>  powerpc: add exit_flags field in pt_regs
>  powerpc: Prepare for IRQ entry exit
>  powerpc: Enable GENERIC_ENTRY feature
>  powerpc: Remove unused functions
>=20
> arch/powerpc/Kconfig                    |   1 +
> arch/powerpc/include/asm/entry-common.h | 533 ++++++++++++++++++++++++
> arch/powerpc/include/asm/hw_irq.h       |   4 +-
> arch/powerpc/include/asm/interrupt.h    | 386 +++--------------
> arch/powerpc/include/asm/kasan.h        |  15 +-
> arch/powerpc/include/asm/ptrace.h       |   6 +-
> arch/powerpc/include/asm/signal.h       |   1 -
> arch/powerpc/include/asm/stacktrace.h   |   6 +
> arch/powerpc/include/asm/syscall.h      |   5 +
> arch/powerpc/include/asm/thread_info.h  |   1 +
> arch/powerpc/include/uapi/asm/ptrace.h  |  14 +-
> arch/powerpc/kernel/interrupt.c         | 254 ++---------
> arch/powerpc/kernel/ptrace/ptrace.c     | 142 +------
> arch/powerpc/kernel/signal.c            |  25 +-
> arch/powerpc/kernel/syscall.c           | 119 +-----
> arch/powerpc/kernel/traps.c             |   2 +-
> arch/powerpc/kernel/watchdog.c          |   2 +-
> arch/powerpc/perf/core-book3s.c         |   2 +-
> 18 files changed, 690 insertions(+), 828 deletions(-)
> create mode 100644 arch/powerpc/include/asm/entry-common.h
>=20
> --=20
> 2.52.0
>=20

Tested this patch set, and it builds successfully. Also ran ltp, ptrace, ft=
race, perf related tests and no crash or warnings observed. Please add belo=
w tag.

Tested-by: Venkat Rao Bagalkote <venkat88@linux.ibm.com>

Regards,
Venkat.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/E=
4046FE5-A919-4B30-B6D8-8F968628CFE3%40linux.ibm.com.
