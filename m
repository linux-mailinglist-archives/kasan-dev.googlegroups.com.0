Return-Path: <kasan-dev+bncBAABBW6LZTFQMGQE5OFR7HI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SIR8Ed8lc2nCsgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBW6LZTFQMGQE5OFR7HI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B82171D9F
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:13 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-40422dd039dsf4611897fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154012; cv=pass;
        d=google.com; s=arc-20240605;
        b=D+WQO04YbGAK0NelxVqrXMS3ecgU7zAcwN5X9rFTO3j0bTgZTBx6XWZi1E+MZFiH9/
         fP5ihFTHMUdw9JL/X9pPt9MxntGYOb8YaF44k0ra182wzDRSjOGE6RgxRw/G2JI2AvOn
         8qBE9S1qxEzm45fPAdIUCqF3JBEvfqD5JZAm88F+LV7aWuN9Zg8zSJWvPdONyDYv24J+
         F+TokBETejYX6Qmy4YAOFg/JwKu1YVoocjOCIXfCiSA7f6LDl+pw6ifKNkee+JeUvQzV
         JwNPQXnP9UZJtmP/yrEl/sUgyhEnGrRN74GjDkPBLAx6gSuxW8mdehJQC+LXvhZ47pwT
         Tx7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:to:from
         :sender:dkim-signature;
        bh=1CkokzljBSrCXgWCu4XzrFGOlJqOQJXB+LMazbVwHUs=;
        fh=ivtzCQ5cwUIbaUkaeezHdI2r1+VEKQ5Hm44jPH73aLc=;
        b=ePFmj3jBEbx4F/EUyR9MPX+Wd8jwP8NK0yt/MSm1krp9uOnRFQMwNUAXj7/9fE74aR
         VgTGuUa2lGoNr1QHT1FNWdUJMTIQgFU3L6xTK96TKMtJ9TxVE4hHRZ/tqH8yk2R0JwkV
         DEuA9SvWCb6jxUm+Dp1R3UIV7NJAxYDf1klll5HVA0NuhMUydhkXozw3055GW94QfcKA
         PW6Xpw/u+Rs78Uea8MPleSlxIhLUobm8QO2qgDquJuOrwoy5lUwSg+O7HNVKQmU+9Mpw
         VzukqD8qDi5f50b9/eAB8fmJ9kcnF4wRhmTm/KnCMGMtqq5ys0yG3lQCTaYtnLGb8NTu
         cnRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WbAVleIh;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154012; x=1769758812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1CkokzljBSrCXgWCu4XzrFGOlJqOQJXB+LMazbVwHUs=;
        b=cSYT9n3vTZ4Rx99ungG3toXfmDcfJ4U8z82NU3jFBzIpZdVa1TMcuz/I7AewLjwlQL
         TxIoI1EnwI1wexwXvsjE0v0EQ65rpGx6LqxKzqK6O96ONLRiiqLoY92hA2qxTQm3eyHS
         V/CLS8RC2eDhVGQwqx10sVDGl7c6rysd5VBltT0TUy/MWamEGQxDISJL50yobIKIdKyv
         IWzUgbskfTj5z20qb6LFTMpeCJobktva8WbISjYcrgkUHgxt6T8pE3QdZAZhWg0j6SWA
         ABlizOXx5ZqwZ9bx22YsaYXiMZraexpIoszysU2dPk7ByGvQJaZf9QJkHzSWOsJc4j5+
         NhLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154012; x=1769758812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1CkokzljBSrCXgWCu4XzrFGOlJqOQJXB+LMazbVwHUs=;
        b=CSdSeNBwWomQ/tWkS2g4q567hhYZ8jsrZL24bD4NNOg/y6JbZXwE7JarL+T9Ug6QCd
         8KBgHNiWpm9Q81duvcInEpkgDpUH5OuxwEg6MgyT37ydji002TPMVnbUnAsbwi9p8Oii
         z0LNIp0ZcxkrczKu6SbF/8REe1RwviTLx+CuFTKiYnoToqI6hWcwqyujGFAmpZjGP0qt
         EWUSeznytH1aGzHvlsmPGSHlFzK/JRubCyiTwQ6KFZROkZRzIlgP8cmEzcTpmzbGzgTn
         7jPv+Ff/4Z9gXASmyPy3+G8xuiygfvhiCVtvXiwmzbrVYP1p5Rsiq85E7csYgjYYrzLB
         CgMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGiILS3Cp+7+fZK+WUETfNG0nUrrG/6iBwHvOHNGoMsZtL79lIuw1wfobx51ATE/hLmfGXEA==@lfdr.de
X-Gm-Message-State: AOJu0Yz6lZI7q8ZeAYJQAoeKjuIq1sNPThQNpkvBNu8yT1kGcycQrAeO
	Exotb22L1f9MD40tGdRA+mBtTdTarJqNKqFa6UCTXvfdGiuJjDH5idM/
X-Received: by 2002:a05:6871:c7:b0:3f5:b761:5234 with SMTP id 586e51a60fabf-40882f2a468mr3088161fac.28.1769154011676;
        Thu, 22 Jan 2026 23:40:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FGarbhCRKEmfbcaSbZ7jrP/TktKFeWDdxzZKB+lL81qA=="
Received: by 2002:a05:6870:8917:b0:3fa:9f2:b79b with SMTP id
 586e51a60fabf-40882083c11ls781334fac.0.-pod-prod-00-us; Thu, 22 Jan 2026
 23:40:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUOIXuSJOcUJAi2bysaNR5sIZhxIJptG1EkXM+JqsnGP9xx1XqIODtlMvXBPG/OX9Zxrjx9l36VkXI=@googlegroups.com
X-Received: by 2002:a05:6870:a24d:b0:404:1ec2:562c with SMTP id 586e51a60fabf-40882a48cdamr2934450fac.6.1769154010909;
        Thu, 22 Jan 2026 23:40:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154010; cv=none;
        d=google.com; s=arc-20240605;
        b=e9TLYP3xON5ApM8s1TBbYysl7a4cZyIKEdlm51ddaMa1+qhw7EnRe5sskiHusyynZ6
         mhoRfjvtFdCR1LKshCsylFilmeGZUpVFiMWgYRwD7ieC7pBXymeiNmNFt7lwu+jWXv9l
         I7e6zTM/d/vdMYIsnXLgX2K5xe3CfU22yXQeRpmA7w4U06wtjahlzjyejRLsifCy43pK
         JJB56b6QwKeLOXRcX7Md97X4JhweV3svhj2NE7ZKkybnzgkCl84yUgEwt9VFdA2AHsmw
         Jl1+R9BGgaNRXBLlHrAXv7SSJ7H5khvR+8gLeOMB0IXkKylIMtm2/4VnJ2n5Jomxk1R5
         NBGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=3/4eib+xpLvUzfwQLFLDzDvh/omm20aA/cPzLNpHvRY=;
        fh=4dZC5b+GxnxvIHnzjVMCNym7rZ5j81Xogzb8TUs6Lt0=;
        b=VU9dmb2kvlLkwB8PuAtdbgRj5YCUe7W1byeABEN5+ENdXn6xp/Kay4nr99IiIMKTO1
         IYQukra3oHaTXXSSOLqsXGP7UaNz6Br4dFTH4cIVQ92+zY8wKAsZw+FPtm3gwaaUbTix
         Ldexj+hgIMawfocDYS9zJPg0ucTinN+suSB23bsrChKqiHUvuS5WuhK8H5lCfLL9Rj3a
         SzCRFsWSKh5cODsrwC2MSQYsYyqaYMsR65BLZUt/BlchYe0ahG6PdQKKnR4MIL2SJmdj
         3kZCR9gl384Ta9xSLyXzyt41EdbQUEyFObqXRz2WWytzEgLPojfjclg9NyPdOOzVPUOK
         tvdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WbAVleIh;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-408afc039fasi54965fac.7.2026.01.22.23.40.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:10 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60N2HhiR021317;
	Fri, 23 Jan 2026 07:40:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt612ha38-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:01 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7e0US011041;
	Fri, 23 Jan 2026 07:40:00 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt612ha35-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:00 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N6bXj5027298;
	Fri, 23 Jan 2026 07:39:59 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brnrnfspa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:59 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7dtcj38601128
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:39:55 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9DF422004B;
	Fri, 23 Jan 2026 07:39:55 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C594320043;
	Fri, 23 Jan 2026 07:39:49 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:39:49 +0000 (GMT)
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
Subject: [PATCH v4 2/8] powerpc: Prepare to build with generic entry/exit framework
Date: Fri, 23 Jan 2026 13:09:10 +0530
Message-ID: <20260123073916.956498-3-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: QFzIB8v5osvdoZ0BbGLVSG0g9IifkH2n
X-Authority-Analysis: v=2.4 cv=LaIxKzfi c=1 sm=1 tr=0 ts=697325d1 cx=c_pps
 a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17
 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=-TJU0OSysTv48yDGXSgA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
X-Proofpoint-ORIG-GUID: uIZUXHrmeQnPdbkQ9oHd1eIwYKWxfSrG
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfXwLKASYox5Xxp
 ccGuhy2n0WNj6J8qhjlvJpsqOUcVsjlqDLzuPJLxMnBfMeWZrf0By6bnRUIHAKeYRoaAUyGR+N8
 z+/Xy8i7zKNY8f1eUHbFPmxeVabMJWQaHY/dxidcSi30ZcFux3rLrG+o6p9TbYbcdD5KT3NN/1b
 QOXD5KaG84ZuDMBDROu8MFrvI9+D0NwJ8boFYIbUeA7KkEwBEpSfynV8PAYhTOBtZVTd6bN9P27
 l1V5llOXYHzYHl/7YGNqt0MHkNbhmwnKIgoLshJM3DyrLqcamqIrAQTuBsdqq0DCnWUcLEQI5HE
 zfahrRrcJZTx58DCAmD4skBsw9bDkSB4FiDcgif9sAH6jv6c0MhDwokn6CxvzyYA3YsMkO8pqda
 ncOta2GZN3iJJeqd4T9ZWeqppkpPmuKYbuJxMTAbTVG9rwWmn78FbBGD1AGQevxGhsPRZJrm4ht
 YBMCd4MfQexvGOnnGRw==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 bulkscore=0 adultscore=0 phishscore=0 priorityscore=1501 lowpriorityscore=0
 suspectscore=0 clxscore=1015 impostorscore=0 spamscore=0 malwarescore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2601150000 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WbAVleIh;       spf=pass (google.com:
 domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=mkchauras@linux.ibm.com;       dmarc=pass (p=REJECT
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
X-Spamd-Result: default: False [0.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_CONTAINS_FROM(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBW6LZTFQMGQE5OFR7HI];
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
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,mail-oa1-x3f.google.com:helo,mail-oa1-x3f.google.com:rdns]
X-Rspamd-Queue-Id: 5B82171D9F
X-Rspamd-Action: no action

From: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>

This patch introduces preparatory changes needed to support building
PowerPC with the generic entry/exit (irqentry) framework.

The following infrastructure updates are added:
 - Add a syscall_work field to struct thread_info to hold SYSCALL_WORK_* fl=
ags.
 - Provide a stub implementation of arch_syscall_is_vdso_sigreturn(),
   returning false for now.
 - Introduce on_thread_stack() helper to detect if the current stack pointe=
r
   lies within the task=E2=80=99s kernel stack.

These additions enable later integration with the generic entry/exit
infrastructure while keeping existing PowerPC behavior unchanged.

No functional change is intended in this patch.

Signed-off-by: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>
---
 arch/powerpc/include/asm/entry-common.h | 8 ++++++++
 arch/powerpc/include/asm/stacktrace.h   | 6 ++++++
 arch/powerpc/include/asm/syscall.h      | 5 +++++
 arch/powerpc/include/asm/thread_info.h  | 1 +
 4 files changed, 20 insertions(+)
 create mode 100644 arch/powerpc/include/asm/entry-common.h

diff --git a/arch/powerpc/include/asm/entry-common.h b/arch/powerpc/include=
/asm/entry-common.h
new file mode 100644
index 000000000000..05ce0583b600
--- /dev/null
+++ b/arch/powerpc/include/asm/entry-common.h
@@ -0,0 +1,8 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _ASM_PPC_ENTRY_COMMON_H
+#define _ASM_PPC_ENTRY_COMMON_H
+
+#include <asm/stacktrace.h>
+
+#endif /* _ASM_PPC_ENTRY_COMMON_H */
diff --git a/arch/powerpc/include/asm/stacktrace.h b/arch/powerpc/include/a=
sm/stacktrace.h
index 6149b53b3bc8..987f2e996262 100644
--- a/arch/powerpc/include/asm/stacktrace.h
+++ b/arch/powerpc/include/asm/stacktrace.h
@@ -10,4 +10,10 @@
=20
 void show_user_instructions(struct pt_regs *regs);
=20
+static __always_inline bool on_thread_stack(void)
+{
+	return !(((unsigned long)(current->stack) ^ current_stack_pointer)
+			& ~(THREAD_SIZE - 1));
+}
+
 #endif /* _ASM_POWERPC_STACKTRACE_H */
diff --git a/arch/powerpc/include/asm/syscall.h b/arch/powerpc/include/asm/=
syscall.h
index 4b3c52ed6e9d..834fcc4f7b54 100644
--- a/arch/powerpc/include/asm/syscall.h
+++ b/arch/powerpc/include/asm/syscall.h
@@ -139,4 +139,9 @@ static inline int syscall_get_arch(struct task_struct *=
task)
 	else
 		return AUDIT_ARCH_PPC64;
 }
+
+static inline bool arch_syscall_is_vdso_sigreturn(struct pt_regs *regs)
+{
+	return false;
+}
 #endif	/* _ASM_SYSCALL_H */
diff --git a/arch/powerpc/include/asm/thread_info.h b/arch/powerpc/include/=
asm/thread_info.h
index b0f200aba2b3..9c8270354f0b 100644
--- a/arch/powerpc/include/asm/thread_info.h
+++ b/arch/powerpc/include/asm/thread_info.h
@@ -57,6 +57,7 @@ struct thread_info {
 #ifdef CONFIG_SMP
 	unsigned int	cpu;
 #endif
+	unsigned long	syscall_work;		/* SYSCALL_WORK_ flags */
 	unsigned long	local_flags;		/* private flags for thread */
 #ifdef CONFIG_LIVEPATCH_64
 	unsigned long *livepatch_sp;
--=20
2.52.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260123073916.956498-3-mkchauras%40linux.ibm.com.
