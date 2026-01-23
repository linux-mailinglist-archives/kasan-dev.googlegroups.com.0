Return-Path: <kasan-dev+bncBAABB66LZTFQMGQETMS3KUA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0IaIDP4lc2kAswAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB66LZTFQMGQETMS3KUA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9979D71DE5
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:45 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-8c6a5bc8c43sf536038385a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154044; cv=pass;
        d=google.com; s=arc-20240605;
        b=KhhWhxLvO1de1bWiaPihdeeYX9HNymQiF71i6s8KvFLUu0RXdvv3htDo+zoQsMg35Z
         XQpA574NzIljpW6UQG+oS0+ufsGWDbvGVGDKBPDapYersRJ3DDJGxqe/huQA/X+qbJgX
         F/fHReUNVnfXpCT8bXag67jMp7Ur3F0tw1GtEAhlJ2qlJg6ehU0KtwMxZRVE3xZKIH/n
         uX1P0SX3MyHVAtTK9+UMPgiwv/TnicbdcS5oQNX08InnVuCz5t2UwlISWJIH051j7i4f
         EjhOWgkAyanZSKgLSTUzY48wJZN8Wz7tRDsQrRWcTjbOV/WEVqc8GufidVkzT0W3HoIE
         wtYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=sWISKjah5g+8gfE0S/WNQFptsMlcCIwiobwKHTL6OEQ=;
        fh=RU9WjED+WV/VwE0arDNnokUUf/ZV3r1XuA6x2yZUkiE=;
        b=GWmsMkNkbCqfdQehLPujVxMmSXscdpIdf4hiG/ZkRGEjOXurXWxldfM5ZH7JKFCF8C
         CbUDFSeZnZDRuS1FrnHTgICePvOH/44oV/scXB4fcob2Xi+buI0ac/i9VLc0Rxs7Yg7S
         CgppDcwFPH6bu4mKymjY5Q1ZwLi+fOGWNwo5xU+AcrG44PA3JXMNJMpkBt79JzjyYrFA
         fulpUiOfGGDfNwngwgiuobbSrSExrzSvhbhrtn6Cht+NT/L9z3bMnnqQAuavL8u0U06a
         XwENfBMReNyyO2Od7J1gSN1ODxhE7Rxh/pihcVlB+SYe94thRgrnzxGkbr0L9LFI3hDr
         VvIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aGp7LAzB;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154044; x=1769758844; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sWISKjah5g+8gfE0S/WNQFptsMlcCIwiobwKHTL6OEQ=;
        b=AFVo7Y6sHndotuMCXmKRyO6+eKyTT8b/9y14L+FBW7i756alXS4ONWWlKlmLQhzr+g
         v9zchg8HPzk5vdRN7E8pRqQ1rbk3jXH6PXk0aFSs2kRCX15e0KgxmIEQgiWviwqGolMu
         avaZK+wQZh6Q+hIApreqsaefu+eMTDJbCfolVkZpe4VTAiT2yoFVOShraJMGudz6n4c9
         93DmSPWv24ciOlZfGtJNp0I+m+8pSnWegp64VLJr178XyRbSKtp3gIOJ1L5pLSBioY/o
         Y94vsIxaSRFiyYho9FmuHdkjzANPPMj7QJyeLVrPOftno9XizXVX1L6/Uj17nmf/aBfQ
         g+lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154044; x=1769758844;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sWISKjah5g+8gfE0S/WNQFptsMlcCIwiobwKHTL6OEQ=;
        b=sKeN3G48hb6K7c93QBbFDUUkNcNM3IH5n33S13ID5/9HN2/3PcQ7zYS0HPyIsz5xB/
         xPZn15da0flnVrP08fgMAoZRA2mkk0vNSNCP8Q8km4tp44WlaGTfmlFMh/rjr+iKlKJ8
         Q3A05sVDOwpkDkrlEvr5Fnh8wBZGwf34uw64vW1jKTHly1pWW+rzX3jhyyJzcZ1OdykY
         nQfy3xEefxWCUNiAZ+bxukyAfh5g8ss9QwBpopVa/jbAs/WCOIJUPM3y0tG6wjvKIIvy
         sZP2tU8v42S18G99Fb8rTuPqIcmepQzjKTbbbu+DOIyyUXjqoKgUcq5YW7cIPmvPj9s9
         aenQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVWzg7k8RsGfiC6Wu7IJ6rkU5uJhMjLBkWVqPYz3BZMgjH1eJtsTqupCSAIxpn8BfhShMCwtw==@lfdr.de
X-Gm-Message-State: AOJu0YzR8SjqHNaXnvZi9xqw4YRGWMjJ2g9O79VTYhkQXXtx+yIUyG0n
	3Xavllx4zXTZOaBjGJ6cBrvNWZfcHrMWFvzNpdh2gegogh2yyJ2mFPfz
X-Received: by 2002:a05:620a:4555:b0:8b2:e9d2:9c69 with SMTP id af79cd13be357-8c6e9122423mr37039685a.22.1769154044117;
        Thu, 22 Jan 2026 23:40:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FJU5C7MROeycHyJayVa61+eDQIsQA7YM+bHjwDno6qxg=="
Received: by 2002:ad4:5cad:0:b0:894:68d4:1236 with SMTP id 6a1803df08f44-8947df0e992ls34117926d6.2.-pod-prod-01-us;
 Thu, 22 Jan 2026 23:40:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWNeClSH5DUI0FwQn9zo7sKgM+++amganQyFTKzbEVf0upS6LILwBqbWcvDO5fiUpGXV5LSHTi+uSc=@googlegroups.com
X-Received: by 2002:a05:6214:1bc7:b0:894:7cd8:59b2 with SMTP id 6a1803df08f44-894982fe286mr2649566d6.58.1769154043175;
        Thu, 22 Jan 2026 23:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154043; cv=none;
        d=google.com; s=arc-20240605;
        b=lQyCJaym6uNZKBHAlBRX5ZXe5eIexGIXpoAlvs0V08+KGAiq+knTo3mDllennI0bqR
         p8i0l4Opc9IrdaWiil8T63iGGiU3Eo7CQnUzNnFxcOMwU7DFBll8xLGu8dAfhsvnSrOQ
         URgjlmQv1KUyv9k3dYsu0tspajZG6JAqICuWTZZnq2iW58IwNxGBEWOlx7W8DT2mVDp6
         HxdFWkd/uM5aGeRwkPBt8tCplK2WMqCqd/Ze8td2ACl6rizxN9GrrTLMJNcE37z1eNov
         0OvqfudYS6WNQ3FRmNQJb3rZ7/2Z69W/X1gLMM6RsaNyt7vwHmfow0l6BJyBYyBPHFW1
         XUig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2O5BBWPNDajCIf1g7d7+qYePYLSY6VGKOljloXnvQoU=;
        fh=fo0uf1ka2HDlpaZBTb0XY8JZ4PPCbF0KdSaHJOs60cc=;
        b=aiw2rraUwL1Iwm2mKucA45TcrAiiFwMprwqmwVsRcL3Ej42X6KrpBYIof1jM+cwmn3
         bNvrbeQ2xZU9az+AYadVJmzoXY3EWasVy3VQnc8nWekgWwfcXi02T5xZnVxnguNywlPj
         RqiC1VECAppRcgLzSbHMZj3ikMg86L1uWddENKzO7aLZH2MjuEVT5z7+S9RSwQ17JEID
         mXt5LIEWf1VqdwdBWbdygSZgSOubQGfJ11a9pWqkkTaFjY0gCyAh25IKLrdj/tj1LS3p
         5RkOIAOD2AYNiYtVMBP1znytdAzJcwDn6JrqwU/Jqu2+PCGPgycD9QW+aR1eNGGiUhOx
         xK4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aGp7LAzB;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502f7daeca0si593251cf.0.2026.01.22.23.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60ML7qC3007001;
	Fri, 23 Jan 2026 07:40:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br23senpv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:32 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7eV1Q031732;
	Fri, 23 Jan 2026 07:40:31 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br23senps-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:31 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N6qWG2027285;
	Fri, 23 Jan 2026 07:40:29 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brnrnfsr5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:29 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7ePfL44630304
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:40:25 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6682F2004B;
	Fri, 23 Jan 2026 07:40:25 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9161B2004F;
	Fri, 23 Jan 2026 07:40:19 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:40:19 +0000 (GMT)
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
Cc: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
Subject: [PATCH v4 7/8] powerpc: Enable GENERIC_ENTRY feature
Date: Fri, 23 Jan 2026 13:09:15 +0530
Message-ID: <20260123073916.956498-8-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ClPvhz5WSahE9H9aY7uwkwqTpoDVWaZg
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfX8F/rBy7fTOj/
 I6JfC+KWJpWid4ZZvXrQtEMFS1CLkVCg54qECAu+Hjo50Q7sfc0rod+6tReKhvKtfMk9ppH8a69
 DFkB/13f/5DlMe+cqtV9dErENuli75hSB1YDL894kg+etSEC90T/qbow0XsRNtDVVz2nhS3bKTg
 LErMVJP6GUwnHVK+3RJRFQUw8oOpMA9SinaCXLZn6cAMKss/RXmjp+5zcYF46m3h8UUfzk0Nqy8
 ly8hBG6UfFzz0YxR4sI12wQqbItjKmhKIsoeo5hcxZqL9EIDiyf/ZWowEdH6EnMsAKVoVSLXNTD
 c9XOW9qZQ6b/n0MecsvHuujkmh4+Vc22hDrChCyiFDswXbCBx1v26lsDT7dA6ltMcRvWGljF5U/
 7wZz4ypyLHKkjQdfUDe+bY2sgAJAWi3VTGAPfumK7qRx35LdmRbrtoFq9rKs2rhIYjivazfvf8M
 d7a7KyAItll41yFN9LQ==
X-Authority-Analysis: v=2.4 cv=J9SnLQnS c=1 sm=1 tr=0 ts=697325f0 cx=c_pps
 a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17
 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=hjeuGtSA9hLjmXCfMpgA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
X-Proofpoint-ORIG-GUID: CNelt1f47CSTXQN7XH55uRHtzqHc5v7O
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
 header.i=@ibm.com header.s=pp1 header.b=aGp7LAzB;       spf=pass (google.com:
 domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[32];
	TAGGED_FROM(0.00)[bncBAABB66LZTFQMGQETMS3KUA];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_TWELVE(0.00)[13];
	FROM_NEQ_ENVFROM(0.00)[mkchauras@linux.ibm.com,kasan-dev@googlegroups.com];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.998];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,googlegroups.com:email,googlegroups.com:dkim,mail-qk1-x73d.google.com:helo,mail-qk1-x73d.google.com:rdns]
X-Rspamd-Queue-Id: 9979D71DE5
X-Rspamd-Action: no action

Enable the generic IRQ entry/exit infrastructure on PowerPC by selecting
GENERIC_ENTRY and integrating the architecture-specific interrupt and
syscall handlers with the generic entry/exit APIs.

This change replaces PowerPC=E2=80=99s local interrupt entry/exit handling =
with
calls to the generic irqentry_* helpers, aligning the architecture with
the common kernel entry model. The macros that define interrupt, async,
and NMI handlers are updated to use irqentry_enter()/irqentry_exit()
and irqentry_nmi_enter()/irqentry_nmi_exit() where applicable also
convert the PowerPC syscall entry and exit paths to use the generic
entry/exit framework and integrating with the common syscall handling
routines.

Key updates include:
 - The architecture now selects GENERIC_ENTRY in Kconfig.
 - Replace interrupt_enter/exit_prepare() with arch_interrupt_* helpers.
 - Integrate irqentry_enter()/exit() in standard and async interrupt paths.
 - Integrate irqentry_nmi_enter()/exit() in NMI handlers.
 - Remove redundant irq_enter()/irq_exit() calls now handled generically.
 - Use irqentry_exit_cond_resched() for preemption checks.
 - interrupt.c and syscall.c are simplified to delegate context
   management and user exit handling to the generic entry path.
 - The new pt_regs field `exit_flags` introduced earlier is now used
   to carry per-syscall exit state flags (e.g. _TIF_RESTOREALL).
 - Remove unused code.

This change establishes the necessary wiring for PowerPC to use the
generic IRQ entry/exit framework while maintaining existing semantics.
This aligns PowerPC with the common entry code used by other
architectures and reduces duplicated logic around syscall tracing,
context tracking, and signal handling.

The performance benchmarks from perf bench basic syscall are below:

perf bench syscall usec/op (-ve is improvement)

| Syscall | Base        | test        | change % |
| ------- | ----------- | ----------- | -------- |
| basic   | 0.093543    | 0.093023    | -0.56    |
| execve  | 446.557781  | 450.107172  | +0.79    |
| fork    | 1142.204391 | 1156.377214 | +1.24    |
| getpgid | 0.097666    | 0.092677    | -5.11    |

perf bench syscall ops/sec (+ve is improvement)

| Syscall | Base     | New      | change % |
| ------- | -------- | -------- | -------- |
| basic   | 10690548 | 10750140 | +0.56    |
| execve  | 2239     | 2221     | -0.80    |
| fork    | 875      | 864      | -1.26    |
| getpgid | 10239026 | 10790324 | +5.38    |

IPI latency benchmark (-ve is improvement)

| Metric         | Base (ns)     | New (ns)      | % Change |
| -------------- | ------------- | ------------- | -------- |
| Dry run        | 583136.56     | 584136.35     | 0.17%    |
| Self IPI       | 4167393.42    | 4149093.90    | -0.44%   |
| Normal IPI     | 61769347.82   | 61753728.39   | -0.03%   |
| Broadcast IPI  | 2235584825.02 | 2227521401.45 | -0.36%   |
| Broadcast lock | 2164964433.31 | 2125658641.76 | -1.82%   |

Thats very close to performance earlier with arch specific handling.

Signed-off-by: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
---
 arch/powerpc/Kconfig                 |   1 +
 arch/powerpc/include/asm/interrupt.h | 384 +++++----------------------
 arch/powerpc/include/asm/kasan.h     |  15 +-
 arch/powerpc/kernel/interrupt.c      | 250 +++--------------
 arch/powerpc/kernel/ptrace/ptrace.c  |   3 -
 arch/powerpc/kernel/signal.c         |   8 +
 arch/powerpc/kernel/syscall.c        | 119 +--------
 7 files changed, 124 insertions(+), 656 deletions(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 9537a61ebae0..455dcc025eb9 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -204,6 +204,7 @@ config PPC
 	select GENERIC_CPU_AUTOPROBE
 	select GENERIC_CPU_VULNERABILITIES	if PPC_BARRIER_NOSPEC
 	select GENERIC_EARLY_IOREMAP
+	select GENERIC_ENTRY
 	select GENERIC_GETTIMEOFDAY
 	select GENERIC_IDLE_POLL_SETUP
 	select GENERIC_IOREMAP
diff --git a/arch/powerpc/include/asm/interrupt.h b/arch/powerpc/include/as=
m/interrupt.h
index 0e2cddf8bd21..fb42a664ae54 100644
--- a/arch/powerpc/include/asm/interrupt.h
+++ b/arch/powerpc/include/asm/interrupt.h
@@ -66,11 +66,9 @@
=20
 #ifndef __ASSEMBLER__
=20
-#include <linux/context_tracking.h>
-#include <linux/hardirq.h>
-#include <asm/cputime.h>
-#include <asm/firmware.h>
-#include <asm/ftrace.h>
+#include <linux/sched/debug.h> /* for show_regs */
+#include <linux/irq-entry-common.h>
+
 #include <asm/kprobes.h>
 #include <asm/runlatch.h>
=20
@@ -88,308 +86,6 @@ do {									\
 #define INT_SOFT_MASK_BUG_ON(regs, cond)
 #endif
=20
-#ifdef CONFIG_PPC_BOOK3S_64
-extern char __end_soft_masked[];
-bool search_kernel_soft_mask_table(unsigned long addr);
-unsigned long search_kernel_restart_table(unsigned long addr);
-
-DECLARE_STATIC_KEY_FALSE(interrupt_exit_not_reentrant);
-
-static inline bool is_implicit_soft_masked(struct pt_regs *regs)
-{
-	if (user_mode(regs))
-		return false;
-
-	if (regs->nip >=3D (unsigned long)__end_soft_masked)
-		return false;
-
-	return search_kernel_soft_mask_table(regs->nip);
-}
-
-static inline void srr_regs_clobbered(void)
-{
-	local_paca->srr_valid =3D 0;
-	local_paca->hsrr_valid =3D 0;
-}
-#else
-static inline unsigned long search_kernel_restart_table(unsigned long addr=
)
-{
-	return 0;
-}
-
-static inline bool is_implicit_soft_masked(struct pt_regs *regs)
-{
-	return false;
-}
-
-static inline void srr_regs_clobbered(void)
-{
-}
-#endif
-
-static inline void nap_adjust_return(struct pt_regs *regs)
-{
-#ifdef CONFIG_PPC_970_NAP
-	if (unlikely(test_thread_local_flags(_TLF_NAPPING))) {
-		/* Can avoid a test-and-clear because NMIs do not call this */
-		clear_thread_local_flags(_TLF_NAPPING);
-		regs_set_return_ip(regs, (unsigned long)power4_idle_nap_return);
-	}
-#endif
-}
-
-static inline void booke_restore_dbcr0(void)
-{
-#ifdef CONFIG_PPC_ADV_DEBUG_REGS
-	unsigned long dbcr0 =3D current->thread.debug.dbcr0;
-
-	if (IS_ENABLED(CONFIG_PPC32) && unlikely(dbcr0 & DBCR0_IDM)) {
-		mtspr(SPRN_DBSR, -1);
-		mtspr(SPRN_DBCR0, global_dbcr0[smp_processor_id()]);
-	}
-#endif
-}
-
-static inline void interrupt_enter_prepare(struct pt_regs *regs)
-{
-#ifdef CONFIG_PPC64
-	irq_soft_mask_set(IRQS_ALL_DISABLED);
-
-	/*
-	 * If the interrupt was taken with HARD_DIS clear, then enable MSR[EE].
-	 * Asynchronous interrupts get here with HARD_DIS set (see below), so
-	 * this enables MSR[EE] for synchronous interrupts. IRQs remain
-	 * soft-masked. The interrupt handler may later call
-	 * interrupt_cond_local_irq_enable() to achieve a regular process
-	 * context.
-	 */
-	if (!(local_paca->irq_happened & PACA_IRQ_HARD_DIS)) {
-		INT_SOFT_MASK_BUG_ON(regs, !(regs->msr & MSR_EE));
-		__hard_irq_enable();
-	} else {
-		__hard_RI_enable();
-	}
-	/* Enable MSR[RI] early, to support kernel SLB and hash faults */
-#endif
-
-	if (!regs_irqs_disabled(regs))
-		trace_hardirqs_off();
-
-	if (user_mode(regs)) {
-		kuap_lock();
-		CT_WARN_ON(ct_state() !=3D CT_STATE_USER);
-		user_exit_irqoff();
-
-		account_cpu_user_entry();
-		account_stolen_time();
-	} else {
-		kuap_save_and_lock(regs);
-		/*
-		 * CT_WARN_ON comes here via program_check_exception,
-		 * so avoid recursion.
-		 */
-		if (TRAP(regs) !=3D INTERRUPT_PROGRAM)
-			CT_WARN_ON(ct_state() !=3D CT_STATE_KERNEL &&
-				   ct_state() !=3D CT_STATE_IDLE);
-		INT_SOFT_MASK_BUG_ON(regs, is_implicit_soft_masked(regs));
-		INT_SOFT_MASK_BUG_ON(regs, regs_irqs_disabled(regs) &&
-				     search_kernel_restart_table(regs->nip));
-	}
-	INT_SOFT_MASK_BUG_ON(regs, !regs_irqs_disabled(regs) &&
-			     !(regs->msr & MSR_EE));
-
-	booke_restore_dbcr0();
-}
-
-/*
- * Care should be taken to note that interrupt_exit_prepare and
- * interrupt_async_exit_prepare do not necessarily return immediately to
- * regs context (e.g., if regs is usermode, we don't necessarily return to
- * user mode). Other interrupts might be taken between here and return,
- * context switch / preemption may occur in the exit path after this, or a
- * signal may be delivered, etc.
- *
- * The real interrupt exit code is platform specific, e.g.,
- * interrupt_exit_user_prepare / interrupt_exit_kernel_prepare for 64s.
- *
- * However interrupt_nmi_exit_prepare does return directly to regs, becaus=
e
- * NMIs do not do "exit work" or replay soft-masked interrupts.
- */
-static inline void interrupt_exit_prepare(struct pt_regs *regs)
-{
-}
-
-static inline void interrupt_async_enter_prepare(struct pt_regs *regs)
-{
-#ifdef CONFIG_PPC64
-	/* Ensure interrupt_enter_prepare does not enable MSR[EE] */
-	local_paca->irq_happened |=3D PACA_IRQ_HARD_DIS;
-#endif
-	interrupt_enter_prepare(regs);
-#ifdef CONFIG_PPC_BOOK3S_64
-	/*
-	 * RI=3D1 is set by interrupt_enter_prepare, so this thread flags access
-	 * has to come afterward (it can cause SLB faults).
-	 */
-	if (cpu_has_feature(CPU_FTR_CTRL) &&
-	    !test_thread_local_flags(_TLF_RUNLATCH))
-		__ppc64_runlatch_on();
-#endif
-	irq_enter();
-}
-
-static inline void interrupt_async_exit_prepare(struct pt_regs *regs)
-{
-	/*
-	 * Adjust at exit so the main handler sees the true NIA. This must
-	 * come before irq_exit() because irq_exit can enable interrupts, and
-	 * if another interrupt is taken before nap_adjust_return has run
-	 * here, then that interrupt would return directly to idle nap return.
-	 */
-	nap_adjust_return(regs);
-
-	irq_exit();
-	interrupt_exit_prepare(regs);
-}
-
-struct interrupt_nmi_state {
-#ifdef CONFIG_PPC64
-	u8 irq_soft_mask;
-	u8 irq_happened;
-	u8 ftrace_enabled;
-	u64 softe;
-#endif
-};
-
-static inline bool nmi_disables_ftrace(struct pt_regs *regs)
-{
-	/* Allow DEC and PMI to be traced when they are soft-NMI */
-	if (IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
-		if (TRAP(regs) =3D=3D INTERRUPT_DECREMENTER)
-		       return false;
-		if (TRAP(regs) =3D=3D INTERRUPT_PERFMON)
-		       return false;
-	}
-	if (IS_ENABLED(CONFIG_PPC_BOOK3E_64)) {
-		if (TRAP(regs) =3D=3D INTERRUPT_PERFMON)
-			return false;
-	}
-
-	return true;
-}
-
-static inline void interrupt_nmi_enter_prepare(struct pt_regs *regs, struc=
t interrupt_nmi_state *state)
-{
-#ifdef CONFIG_PPC64
-	state->irq_soft_mask =3D local_paca->irq_soft_mask;
-	state->irq_happened =3D local_paca->irq_happened;
-	state->softe =3D regs->softe;
-
-	/*
-	 * Set IRQS_ALL_DISABLED unconditionally so irqs_disabled() does
-	 * the right thing, and set IRQ_HARD_DIS. We do not want to reconcile
-	 * because that goes through irq tracing which we don't want in NMI.
-	 */
-	local_paca->irq_soft_mask =3D IRQS_ALL_DISABLED;
-	local_paca->irq_happened |=3D PACA_IRQ_HARD_DIS;
-
-	if (!(regs->msr & MSR_EE) || is_implicit_soft_masked(regs)) {
-		/*
-		 * Adjust regs->softe to be soft-masked if it had not been
-		 * reconcied (e.g., interrupt entry with MSR[EE]=3D0 but softe
-		 * not yet set disabled), or if it was in an implicit soft
-		 * masked state. This makes regs_irqs_disabled(regs)
-		 * behave as expected.
-		 */
-		regs->softe =3D IRQS_ALL_DISABLED;
-	}
-
-	__hard_RI_enable();
-
-	/* Don't do any per-CPU operations until interrupt state is fixed */
-
-	if (nmi_disables_ftrace(regs)) {
-		state->ftrace_enabled =3D this_cpu_get_ftrace_enabled();
-		this_cpu_set_ftrace_enabled(0);
-	}
-#endif
-
-	/* If data relocations are enabled, it's safe to use nmi_enter() */
-	if (mfmsr() & MSR_DR) {
-		nmi_enter();
-		return;
-	}
-
-	/*
-	 * But do not use nmi_enter() for pseries hash guest taking a real-mode
-	 * NMI because not everything it touches is within the RMA limit.
-	 */
-	if (IS_ENABLED(CONFIG_PPC_BOOK3S_64) &&
-	    firmware_has_feature(FW_FEATURE_LPAR) &&
-	    !radix_enabled())
-		return;
-
-	/*
-	 * Likewise, don't use it if we have some form of instrumentation (like
-	 * KASAN shadow) that is not safe to access in real mode (even on radix)
-	 */
-	if (IS_ENABLED(CONFIG_KASAN))
-		return;
-
-	/*
-	 * Likewise, do not use it in real mode if percpu first chunk is not
-	 * embedded. With CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK enabled there
-	 * are chances where percpu allocation can come from vmalloc area.
-	 */
-	if (percpu_first_chunk_is_paged)
-		return;
-
-	/* Otherwise, it should be safe to call it */
-	nmi_enter();
-}
-
-static inline void interrupt_nmi_exit_prepare(struct pt_regs *regs, struct=
 interrupt_nmi_state *state)
-{
-	if (mfmsr() & MSR_DR) {
-		// nmi_exit if relocations are on
-		nmi_exit();
-	} else if (IS_ENABLED(CONFIG_PPC_BOOK3S_64) &&
-		   firmware_has_feature(FW_FEATURE_LPAR) &&
-		   !radix_enabled()) {
-		// no nmi_exit for a pseries hash guest taking a real mode exception
-	} else if (IS_ENABLED(CONFIG_KASAN)) {
-		// no nmi_exit for KASAN in real mode
-	} else if (percpu_first_chunk_is_paged) {
-		// no nmi_exit if percpu first chunk is not embedded
-	} else {
-		nmi_exit();
-	}
-
-	/*
-	 * nmi does not call nap_adjust_return because nmi should not create
-	 * new work to do (must use irq_work for that).
-	 */
-
-#ifdef CONFIG_PPC64
-#ifdef CONFIG_PPC_BOOK3S
-	if (regs_irqs_disabled(regs)) {
-		unsigned long rst =3D search_kernel_restart_table(regs->nip);
-		if (rst)
-			regs_set_return_ip(regs, rst);
-	}
-#endif
-
-	if (nmi_disables_ftrace(regs))
-		this_cpu_set_ftrace_enabled(state->ftrace_enabled);
-
-	/* Check we didn't change the pending interrupt mask. */
-	WARN_ON_ONCE((state->irq_happened | PACA_IRQ_HARD_DIS) !=3D local_paca->i=
rq_happened);
-	regs->softe =3D state->softe;
-	local_paca->irq_happened =3D state->irq_happened;
-	local_paca->irq_soft_mask =3D state->irq_soft_mask;
-#endif
-}
-
 /*
  * Don't use noinstr here like x86, but rather add NOKPROBE_SYMBOL to each
  * function definition. The reason for this is the noinstr section is plac=
ed
@@ -470,11 +166,14 @@ static __always_inline void ____##func(struct pt_regs=
 *regs);		\
 									\
 interrupt_handler void func(struct pt_regs *regs)			\
 {									\
-	interrupt_enter_prepare(regs);					\
-									\
+	irqentry_state_t state;						\
+	arch_interrupt_enter_prepare(regs);				\
+	state =3D irqentry_enter(regs);					\
+	instrumentation_begin();					\
 	____##func (regs);						\
-									\
-	interrupt_exit_prepare(regs);					\
+	instrumentation_end();						\
+	arch_interrupt_exit_prepare(regs);				\
+	irqentry_exit(regs, state);					\
 }									\
 NOKPROBE_SYMBOL(func);							\
 									\
@@ -504,12 +203,15 @@ static __always_inline long ____##func(struct pt_regs=
 *regs);		\
 interrupt_handler long func(struct pt_regs *regs)			\
 {									\
 	long ret;							\
+	irqentry_state_t state;						\
 									\
-	interrupt_enter_prepare(regs);					\
-									\
+	arch_interrupt_enter_prepare(regs);				\
+	state =3D irqentry_enter(regs);					\
+	instrumentation_begin();					\
 	ret =3D ____##func (regs);					\
-									\
-	interrupt_exit_prepare(regs);					\
+	instrumentation_end();						\
+	arch_interrupt_exit_prepare(regs);				\
+	irqentry_exit(regs, state);					\
 									\
 	return ret;							\
 }									\
@@ -538,11 +240,16 @@ static __always_inline void ____##func(struct pt_regs=
 *regs);		\
 									\
 interrupt_handler void func(struct pt_regs *regs)			\
 {									\
-	interrupt_async_enter_prepare(regs);				\
-									\
+	irqentry_state_t state;						\
+	arch_interrupt_async_enter_prepare(regs);			\
+	state =3D irqentry_enter(regs);					\
+	instrumentation_begin();					\
+	irq_enter_rcu();						\
 	____##func (regs);						\
-									\
-	interrupt_async_exit_prepare(regs);				\
+	irq_exit_rcu();							\
+	instrumentation_end();						\
+	arch_interrupt_async_exit_prepare(regs);			\
+	irqentry_exit(regs, state);					\
 }									\
 NOKPROBE_SYMBOL(func);							\
 									\
@@ -572,14 +279,43 @@ ____##func(struct pt_regs *regs);					\
 									\
 interrupt_handler long func(struct pt_regs *regs)			\
 {									\
-	struct interrupt_nmi_state state;				\
+	irqentry_state_t state;						\
+	struct interrupt_nmi_state nmi_state;				\
 	long ret;							\
 									\
-	interrupt_nmi_enter_prepare(regs, &state);			\
-									\
+	arch_interrupt_nmi_enter_prepare(regs, &nmi_state);		\
+	if (mfmsr() & MSR_DR) {						\
+		/* nmi_entry if relocations are on */			\
+		state =3D irqentry_nmi_enter(regs);			\
+	} else if (IS_ENABLED(CONFIG_PPC_BOOK3S_64) &&			\
+		   firmware_has_feature(FW_FEATURE_LPAR) &&		\
+		   !radix_enabled()) {					\
+		/* no nmi_entry for a pseries hash guest		\
+		 * taking a real mode exception */			\
+	} else if (IS_ENABLED(CONFIG_KASAN)) {				\
+		/* no nmi_entry for KASAN in real mode */		\
+	} else if (percpu_first_chunk_is_paged) {			\
+		/* no nmi_entry if percpu first chunk is not embedded */\
+	} else {							\
+		state =3D irqentry_nmi_enter(regs);			\
+	}								\
 	ret =3D ____##func (regs);					\
-									\
-	interrupt_nmi_exit_prepare(regs, &state);			\
+	arch_interrupt_nmi_exit_prepare(regs, &nmi_state);		\
+	if (mfmsr() & MSR_DR) {						\
+		/* nmi_exit if relocations are on */			\
+		irqentry_nmi_exit(regs, state);				\
+	} else if (IS_ENABLED(CONFIG_PPC_BOOK3S_64) &&			\
+		   firmware_has_feature(FW_FEATURE_LPAR) &&		\
+		   !radix_enabled()) {					\
+		/* no nmi_exit for a pseries hash guest			\
+		 * taking a real mode exception */			\
+	} else if (IS_ENABLED(CONFIG_KASAN)) {				\
+		/* no nmi_exit for KASAN in real mode */		\
+	} else if (percpu_first_chunk_is_paged) {			\
+		/* no nmi_exit if percpu first chunk is not embedded */	\
+	} else {							\
+		irqentry_nmi_exit(regs, state);				\
+	}								\
 									\
 	return ret;							\
 }									\
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/ka=
san.h
index 045804a86f98..a690e7da53c2 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -3,14 +3,19 @@
 #define __ASM_KASAN_H
=20
 #if defined(CONFIG_KASAN) && !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PRE=
FIX)
-#define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
-#define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
-#define EXPORT_SYMBOL_KASAN(fn)	EXPORT_SYMBOL(__##fn)
-#else
+#define _GLOBAL_KASAN(fn)			\
+	_GLOBAL(fn);				\
+	_GLOBAL(__##fn)
+#define _GLOBAL_TOC_KASAN(fn)			\
+	_GLOBAL_TOC(fn);			\
+	_GLOBAL_TOC(__##fn)
+#define EXPORT_SYMBOL_KASAN(fn)			\
+	EXPORT_SYMBOL(__##fn)
+#else /* CONFIG_KASAN && !CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
 #define _GLOBAL_KASAN(fn)	_GLOBAL(fn)
 #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(fn)
 #define EXPORT_SYMBOL_KASAN(fn)
-#endif
+#endif /* CONFIG_KASAN && !CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
=20
 #ifndef __ASSEMBLER__
=20
diff --git a/arch/powerpc/kernel/interrupt.c b/arch/powerpc/kernel/interrup=
t.c
index 666eadb589a5..89a999be1352 100644
--- a/arch/powerpc/kernel/interrupt.c
+++ b/arch/powerpc/kernel/interrupt.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0-or-later
=20
 #include <linux/context_tracking.h>
+#include <linux/entry-common.h>
 #include <linux/err.h>
 #include <linux/compat.h>
 #include <linux/rseq.h>
@@ -25,10 +26,6 @@
 unsigned long global_dbcr0[NR_CPUS];
 #endif
=20
-#if defined(CONFIG_PREEMPT_DYNAMIC)
-DEFINE_STATIC_KEY_TRUE(sk_dynamic_irqentry_exit_cond_resched);
-#endif
-
 #ifdef CONFIG_PPC_BOOK3S_64
 DEFINE_STATIC_KEY_FALSE(interrupt_exit_not_reentrant);
 static inline bool exit_must_hard_disable(void)
@@ -78,181 +75,6 @@ static notrace __always_inline bool prep_irq_for_enable=
d_exit(bool restartable)
 	return true;
 }
=20
-static notrace void booke_load_dbcr0(void)
-{
-#ifdef CONFIG_PPC_ADV_DEBUG_REGS
-	unsigned long dbcr0 =3D current->thread.debug.dbcr0;
-
-	if (likely(!(dbcr0 & DBCR0_IDM)))
-		return;
-
-	/*
-	 * Check to see if the dbcr0 register is set up to debug.
-	 * Use the internal debug mode bit to do this.
-	 */
-	mtmsr(mfmsr() & ~MSR_DE);
-	if (IS_ENABLED(CONFIG_PPC32)) {
-		isync();
-		global_dbcr0[smp_processor_id()] =3D mfspr(SPRN_DBCR0);
-	}
-	mtspr(SPRN_DBCR0, dbcr0);
-	mtspr(SPRN_DBSR, -1);
-#endif
-}
-
-static notrace void check_return_regs_valid(struct pt_regs *regs)
-{
-#ifdef CONFIG_PPC_BOOK3S_64
-	unsigned long trap, srr0, srr1;
-	static bool warned;
-	u8 *validp;
-	char *h;
-
-	if (trap_is_scv(regs))
-		return;
-
-	trap =3D TRAP(regs);
-	// EE in HV mode sets HSRRs like 0xea0
-	if (cpu_has_feature(CPU_FTR_HVMODE) && trap =3D=3D INTERRUPT_EXTERNAL)
-		trap =3D 0xea0;
-
-	switch (trap) {
-	case 0x980:
-	case INTERRUPT_H_DATA_STORAGE:
-	case 0xe20:
-	case 0xe40:
-	case INTERRUPT_HMI:
-	case 0xe80:
-	case 0xea0:
-	case INTERRUPT_H_FAC_UNAVAIL:
-	case 0x1200:
-	case 0x1500:
-	case 0x1600:
-	case 0x1800:
-		validp =3D &local_paca->hsrr_valid;
-		if (!READ_ONCE(*validp))
-			return;
-
-		srr0 =3D mfspr(SPRN_HSRR0);
-		srr1 =3D mfspr(SPRN_HSRR1);
-		h =3D "H";
-
-		break;
-	default:
-		validp =3D &local_paca->srr_valid;
-		if (!READ_ONCE(*validp))
-			return;
-
-		srr0 =3D mfspr(SPRN_SRR0);
-		srr1 =3D mfspr(SPRN_SRR1);
-		h =3D "";
-		break;
-	}
-
-	if (srr0 =3D=3D regs->nip && srr1 =3D=3D regs->msr)
-		return;
-
-	/*
-	 * A NMI / soft-NMI interrupt may have come in after we found
-	 * srr_valid and before the SRRs are loaded. The interrupt then
-	 * comes in and clobbers SRRs and clears srr_valid. Then we load
-	 * the SRRs here and test them above and find they don't match.
-	 *
-	 * Test validity again after that, to catch such false positives.
-	 *
-	 * This test in general will have some window for false negatives
-	 * and may not catch and fix all such cases if an NMI comes in
-	 * later and clobbers SRRs without clearing srr_valid, but hopefully
-	 * such things will get caught most of the time, statistically
-	 * enough to be able to get a warning out.
-	 */
-	if (!READ_ONCE(*validp))
-		return;
-
-	if (!data_race(warned)) {
-		data_race(warned =3D true);
-		printk("%sSRR0 was: %lx should be: %lx\n", h, srr0, regs->nip);
-		printk("%sSRR1 was: %lx should be: %lx\n", h, srr1, regs->msr);
-		show_regs(regs);
-	}
-
-	WRITE_ONCE(*validp, 0); /* fixup */
-#endif
-}
-
-static notrace unsigned long
-interrupt_exit_user_prepare_main(unsigned long ret, struct pt_regs *regs)
-{
-	unsigned long ti_flags;
-
-again:
-	ti_flags =3D read_thread_flags();
-	while (unlikely(ti_flags & (_TIF_USER_WORK_MASK & ~_TIF_RESTORE_TM))) {
-		local_irq_enable();
-		if (ti_flags & (_TIF_NEED_RESCHED | _TIF_NEED_RESCHED_LAZY)) {
-			schedule();
-		} else {
-			/*
-			 * SIGPENDING must restore signal handler function
-			 * argument GPRs, and some non-volatiles (e.g., r1).
-			 * Restore all for now. This could be made lighter.
-			 */
-			if (ti_flags & _TIF_SIGPENDING)
-				ret |=3D _TIF_RESTOREALL;
-			do_notify_resume(regs, ti_flags);
-		}
-		local_irq_disable();
-		ti_flags =3D read_thread_flags();
-	}
-
-	if (IS_ENABLED(CONFIG_PPC_BOOK3S_64) && IS_ENABLED(CONFIG_PPC_FPU)) {
-		if (IS_ENABLED(CONFIG_PPC_TRANSACTIONAL_MEM) &&
-				unlikely((ti_flags & _TIF_RESTORE_TM))) {
-			restore_tm_state(regs);
-		} else {
-			unsigned long mathflags =3D MSR_FP;
-
-			if (cpu_has_feature(CPU_FTR_VSX))
-				mathflags |=3D MSR_VEC | MSR_VSX;
-			else if (cpu_has_feature(CPU_FTR_ALTIVEC))
-				mathflags |=3D MSR_VEC;
-
-			/*
-			 * If userspace MSR has all available FP bits set,
-			 * then they are live and no need to restore. If not,
-			 * it means the regs were given up and restore_math
-			 * may decide to restore them (to avoid taking an FP
-			 * fault).
-			 */
-			if ((regs->msr & mathflags) !=3D mathflags)
-				restore_math(regs);
-		}
-	}
-
-	check_return_regs_valid(regs);
-
-	user_enter_irqoff();
-	if (!prep_irq_for_enabled_exit(true)) {
-		user_exit_irqoff();
-		local_irq_enable();
-		local_irq_disable();
-		goto again;
-	}
-
-#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
-	local_paca->tm_scratch =3D regs->msr;
-#endif
-
-	booke_load_dbcr0();
-
-	account_cpu_user_exit();
-
-	/* Restore user access locks last */
-	kuap_user_restore(regs);
-
-	return ret;
-}
-
 /*
  * This should be called after a syscall returns, with r3 the return value
  * from the syscall. If this function returns non-zero, the system call
@@ -267,17 +89,12 @@ notrace unsigned long syscall_exit_prepare(unsigned lo=
ng r3,
 					   long scv)
 {
 	unsigned long ti_flags;
-	unsigned long ret =3D 0;
 	bool is_not_scv =3D !IS_ENABLED(CONFIG_PPC_BOOK3S_64) || !scv;
=20
-	CT_WARN_ON(ct_state() =3D=3D CT_STATE_USER);
-
 	kuap_assert_locked();
=20
 	regs->result =3D r3;
-
-	/* Check whether the syscall is issued inside a restartable sequence */
-	rseq_syscall(regs);
+	regs->exit_flags =3D 0;
=20
 	ti_flags =3D read_thread_flags();
=20
@@ -290,7 +107,7 @@ notrace unsigned long syscall_exit_prepare(unsigned lon=
g r3,
=20
 	if (unlikely(ti_flags & _TIF_PERSYSCALL_MASK)) {
 		if (ti_flags & _TIF_RESTOREALL)
-			ret =3D _TIF_RESTOREALL;
+			regs->exit_flags =3D _TIF_RESTOREALL;
 		else
 			regs->gpr[3] =3D r3;
 		clear_bits(_TIF_PERSYSCALL_MASK, &current_thread_info()->flags);
@@ -299,18 +116,28 @@ notrace unsigned long syscall_exit_prepare(unsigned l=
ong r3,
 	}
=20
 	if (unlikely(ti_flags & _TIF_SYSCALL_DOTRACE)) {
-		do_syscall_trace_leave(regs);
-		ret |=3D _TIF_RESTOREALL;
+		regs->exit_flags |=3D _TIF_RESTOREALL;
 	}
=20
-	local_irq_disable();
-	ret =3D interrupt_exit_user_prepare_main(ret, regs);
+	syscall_exit_to_user_mode(regs);
+
+again:
+	user_enter_irqoff();
+	if (!prep_irq_for_enabled_exit(true)) {
+		user_exit_irqoff();
+		local_irq_enable();
+		local_irq_disable();
+		goto again;
+	}
+
+	/* Restore user access locks last */
+	kuap_user_restore(regs);
=20
 #ifdef CONFIG_PPC64
-	regs->exit_result =3D ret;
+	regs->exit_result =3D regs->exit_flags;
 #endif
=20
-	return ret;
+	return regs->exit_flags;
 }
=20
 #ifdef CONFIG_PPC64
@@ -330,13 +157,16 @@ notrace unsigned long syscall_exit_restart(unsigned l=
ong r3, struct pt_regs *reg
 	set_kuap(AMR_KUAP_BLOCKED);
 #endif
=20
-	trace_hardirqs_off();
-	user_exit_irqoff();
-	account_cpu_user_entry();
-
-	BUG_ON(!user_mode(regs));
+again:
+	user_enter_irqoff();
+	if (!prep_irq_for_enabled_exit(true)) {
+		user_exit_irqoff();
+		local_irq_enable();
+		local_irq_disable();
+		goto again;
+	}
=20
-	regs->exit_result =3D interrupt_exit_user_prepare_main(regs->exit_result,=
 regs);
+	regs->exit_result |=3D regs->exit_flags;
=20
 	return regs->exit_result;
 }
@@ -348,7 +178,6 @@ notrace unsigned long interrupt_exit_user_prepare(struc=
t pt_regs *regs)
=20
 	BUG_ON(regs_is_unrecoverable(regs));
 	BUG_ON(regs_irqs_disabled(regs));
-	CT_WARN_ON(ct_state() =3D=3D CT_STATE_USER);
=20
 	/*
 	 * We don't need to restore AMR on the way back to userspace for KUAP.
@@ -357,8 +186,21 @@ notrace unsigned long interrupt_exit_user_prepare(stru=
ct pt_regs *regs)
 	kuap_assert_locked();
=20
 	local_irq_disable();
+	regs->exit_flags =3D 0;
+again:
+	check_return_regs_valid(regs);
+	user_enter_irqoff();
+	if (!prep_irq_for_enabled_exit(true)) {
+		user_exit_irqoff();
+		local_irq_enable();
+		local_irq_disable();
+		goto again;
+	}
+
+	/* Restore user access locks last */
+	kuap_user_restore(regs);
=20
-	ret =3D interrupt_exit_user_prepare_main(0, regs);
+	ret =3D regs->exit_flags;
=20
 #ifdef CONFIG_PPC64
 	regs->exit_result =3D ret;
@@ -400,13 +242,6 @@ notrace unsigned long interrupt_exit_kernel_prepare(st=
ruct pt_regs *regs)
 		/* Returning to a kernel context with local irqs enabled. */
 		WARN_ON_ONCE(!(regs->msr & MSR_EE));
 again:
-		if (need_irq_preemption()) {
-			/* Return to preemptible kernel context */
-			if (unlikely(read_thread_flags() & _TIF_NEED_RESCHED)) {
-				if (preempt_count() =3D=3D 0)
-					preempt_schedule_irq();
-			}
-		}
=20
 		check_return_regs_valid(regs);
=20
@@ -479,7 +314,6 @@ notrace unsigned long interrupt_exit_user_restart(struc=
t pt_regs *regs)
 #endif
=20
 	trace_hardirqs_off();
-	user_exit_irqoff();
 	account_cpu_user_entry();
=20
 	BUG_ON(!user_mode(regs));
diff --git a/arch/powerpc/kernel/ptrace/ptrace.c b/arch/powerpc/kernel/ptra=
ce/ptrace.c
index 2134b6d155ff..f006a03a0211 100644
--- a/arch/powerpc/kernel/ptrace/ptrace.c
+++ b/arch/powerpc/kernel/ptrace/ptrace.c
@@ -21,9 +21,6 @@
 #include <asm/switch_to.h>
 #include <asm/debug.h>
=20
-#define CREATE_TRACE_POINTS
-#include <trace/events/syscalls.h>
-
 #include "ptrace-decl.h"
=20
 /*
diff --git a/arch/powerpc/kernel/signal.c b/arch/powerpc/kernel/signal.c
index aa17e62f3754..9f1847b4742e 100644
--- a/arch/powerpc/kernel/signal.c
+++ b/arch/powerpc/kernel/signal.c
@@ -6,6 +6,7 @@
  *    Extracted from signal_32.c and signal_64.c
  */
=20
+#include <linux/entry-common.h>
 #include <linux/resume_user_mode.h>
 #include <linux/signal.h>
 #include <linux/uprobes.h>
@@ -368,3 +369,10 @@ void signal_fault(struct task_struct *tsk, struct pt_r=
egs *regs,
 		printk_ratelimited(regs->msr & MSR_64BIT ? fm64 : fm32, tsk->comm,
 				   task_pid_nr(tsk), where, ptr, regs->nip, regs->link);
 }
+
+void arch_do_signal_or_restart(struct pt_regs *regs)
+{
+	BUG_ON(regs !=3D current->thread.regs);
+	regs->exit_flags |=3D _TIF_RESTOREALL;
+	do_signal(current);
+}
diff --git a/arch/powerpc/kernel/syscall.c b/arch/powerpc/kernel/syscall.c
index 9f03a6263fb4..df1c9a8d62bc 100644
--- a/arch/powerpc/kernel/syscall.c
+++ b/arch/powerpc/kernel/syscall.c
@@ -3,6 +3,7 @@
 #include <linux/compat.h>
 #include <linux/context_tracking.h>
 #include <linux/randomize_kstack.h>
+#include <linux/entry-common.h>
=20
 #include <asm/interrupt.h>
 #include <asm/kup.h>
@@ -18,124 +19,10 @@ notrace long system_call_exception(struct pt_regs *reg=
s, unsigned long r0)
 	long ret;
 	syscall_fn f;
=20
-	kuap_lock();
-
 	add_random_kstack_offset();
+	r0 =3D syscall_enter_from_user_mode(regs, r0);
=20
-	if (IS_ENABLED(CONFIG_PPC_IRQ_SOFT_MASK_DEBUG))
-		BUG_ON(irq_soft_mask_return() !=3D IRQS_ALL_DISABLED);
-
-	trace_hardirqs_off(); /* finish reconciling */
-
-	CT_WARN_ON(ct_state() =3D=3D CT_STATE_KERNEL);
-	user_exit_irqoff();
-
-	BUG_ON(regs_is_unrecoverable(regs));
-	BUG_ON(!user_mode(regs));
-	BUG_ON(regs_irqs_disabled(regs));
-
-#ifdef CONFIG_PPC_PKEY
-	if (mmu_has_feature(MMU_FTR_PKEY)) {
-		unsigned long amr, iamr;
-		bool flush_needed =3D false;
-		/*
-		 * When entering from userspace we mostly have the AMR/IAMR
-		 * different from kernel default values. Hence don't compare.
-		 */
-		amr =3D mfspr(SPRN_AMR);
-		iamr =3D mfspr(SPRN_IAMR);
-		regs->amr  =3D amr;
-		regs->iamr =3D iamr;
-		if (mmu_has_feature(MMU_FTR_KUAP)) {
-			mtspr(SPRN_AMR, AMR_KUAP_BLOCKED);
-			flush_needed =3D true;
-		}
-		if (mmu_has_feature(MMU_FTR_BOOK3S_KUEP)) {
-			mtspr(SPRN_IAMR, AMR_KUEP_BLOCKED);
-			flush_needed =3D true;
-		}
-		if (flush_needed)
-			isync();
-	} else
-#endif
-		kuap_assert_locked();
-
-	booke_restore_dbcr0();
-
-	account_cpu_user_entry();
-
-	account_stolen_time();
-
-	/*
-	 * This is not required for the syscall exit path, but makes the
-	 * stack frame look nicer. If this was initialised in the first stack
-	 * frame, or if the unwinder was taught the first stack frame always
-	 * returns to user with IRQS_ENABLED, this store could be avoided!
-	 */
-	irq_soft_mask_regs_set_state(regs, IRQS_ENABLED);
-
-	/*
-	 * If system call is called with TM active, set _TIF_RESTOREALL to
-	 * prevent RFSCV being used to return to userspace, because POWER9
-	 * TM implementation has problems with this instruction returning to
-	 * transactional state. Final register values are not relevant because
-	 * the transaction will be aborted upon return anyway. Or in the case
-	 * of unsupported_scv SIGILL fault, the return state does not much
-	 * matter because it's an edge case.
-	 */
-	if (IS_ENABLED(CONFIG_PPC_TRANSACTIONAL_MEM) &&
-			unlikely(MSR_TM_TRANSACTIONAL(regs->msr)))
-		set_bits(_TIF_RESTOREALL, &current_thread_info()->flags);
-
-	/*
-	 * If the system call was made with a transaction active, doom it and
-	 * return without performing the system call. Unless it was an
-	 * unsupported scv vector, in which case it's treated like an illegal
-	 * instruction.
-	 */
-#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
-	if (unlikely(MSR_TM_TRANSACTIONAL(regs->msr)) &&
-	    !trap_is_unsupported_scv(regs)) {
-		/* Enable TM in the kernel, and disable EE (for scv) */
-		hard_irq_disable();
-		mtmsr(mfmsr() | MSR_TM);
-
-		/* tabort, this dooms the transaction, nothing else */
-		asm volatile(".long 0x7c00071d | ((%0) << 16)"
-				:: "r"(TM_CAUSE_SYSCALL|TM_CAUSE_PERSISTENT));
-
-		/*
-		 * Userspace will never see the return value. Execution will
-		 * resume after the tbegin. of the aborted transaction with the
-		 * checkpointed register state. A context switch could occur
-		 * or signal delivered to the process before resuming the
-		 * doomed transaction context, but that should all be handled
-		 * as expected.
-		 */
-		return -ENOSYS;
-	}
-#endif // CONFIG_PPC_TRANSACTIONAL_MEM
-
-	local_irq_enable();
-
-	if (unlikely(read_thread_flags() & _TIF_SYSCALL_DOTRACE)) {
-		if (unlikely(trap_is_unsupported_scv(regs))) {
-			/* Unsupported scv vector */
-			_exception(SIGILL, regs, ILL_ILLOPC, regs->nip);
-			return regs->gpr[3];
-		}
-		/*
-		 * We use the return value of do_syscall_trace_enter() as the
-		 * syscall number. If the syscall was rejected for any reason
-		 * do_syscall_trace_enter() returns an invalid syscall number
-		 * and the test against NR_syscalls will fail and the return
-		 * value to be used is in regs->gpr[3].
-		 */
-		r0 =3D do_syscall_trace_enter(regs);
-		if (unlikely(r0 >=3D NR_syscalls))
-			return regs->gpr[3];
-
-	} else if (unlikely(r0 >=3D NR_syscalls)) {
+	if (unlikely(r0 >=3D NR_syscalls)) {
 		if (unlikely(trap_is_unsupported_scv(regs))) {
 			/* Unsupported scv vector */
 			_exception(SIGILL, regs, ILL_ILLOPC, regs->nip);
--=20
2.52.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260123073916.956498-8-mkchauras%40linux.ibm.com.
