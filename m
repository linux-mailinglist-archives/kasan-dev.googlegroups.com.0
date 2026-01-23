Return-Path: <kasan-dev+bncBAABBSWLZTFQMGQESKZUT4Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GEZdJswlc2nCsgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBSWLZTFQMGQESKZUT4Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:39:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CE4F71D91
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:39:56 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-5014e9d9114sf46681151cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:39:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769153994; cv=pass;
        d=google.com; s=arc-20240605;
        b=IIFCh3q8ixH/uxcyYA7/0Zu05POQBmfAIak/3D6cx2AANhLnmA6z0wAdB5VqyoDj2R
         BfgiSH5mlX9FJOfyyJntc6NL3Gq4qIjQ9B8RFojtM+WijTFbU/yk1i1zBqEuzljCfSUZ
         nsShmGRPK6s1IA/jgfBHWXtjwotLQVojggtVCXpqP5f7opb888pLKhXIgZbsef4HY8bi
         zFCnL8zRfK6xRNuVFc64mT/u/s8b8pWuDfEnLIVTSw+dFh2FhQKjM0TRDA/foH6ir6SL
         ITNcdkdNjA4GeRxe5MqyD9n/mmGTubnRCT9Uk5PNak1UtXgM2xsVF1+QU+acVsSWqUPk
         tDPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Y5/3eB8k28t8qeOg/mLimIMkgLK93FFLoQ6fE1oCbX8=;
        fh=2A5AQ5AVQg5DSRsh9wW+RyFZqOod4qIWe/M8P7OF8y4=;
        b=Fr+2VqT5un2PGULgpSVu0xUw8sdZqOsKqjJEVSd1vEphERvtHXJ7aRX9ke5/SvYkXo
         EQ1HLA6dUOqmjowynOeXGSDPGxieCK4Z3SBvTSi7ULNJRZBm+crRqxOVCAXoTxyZmF0T
         cBaR83QLdcdWKzn/YE2A0HRQwCLzm12pMDZk7jWNeDDgnpCcQzyqRs7QaGuq1E/BZArB
         t5Le8stbRD4ROeJOQIu4GMZv2wta64VLgqDeKPYqKG/1CAKzLqHDzJ+7z229q4cs776c
         WYRnJEHDaf82R2sY4Z47vPcb//V6VZA+2z+8ty62VHzJBC8JBaidn/cECfwT+uptrPqh
         1k0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cqDbiFxf;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769153994; x=1769758794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y5/3eB8k28t8qeOg/mLimIMkgLK93FFLoQ6fE1oCbX8=;
        b=QOXy2Etx+FFvs3k+JHP982b62NHrLh43MLo5I7fd0NVW2thW1sr2MD65RL1lc0crC0
         zkYzTAdWXO48kV8TjkStLfAqbFHcsyygKndC15BOCUZVpx8pBdDDQW/YEiCgcO34jd9m
         dj3irJSeJya7zSnLkK91ZfKkUuzFfLURXA5Y+bD2yqQhg8O2oT7L5KmNsXd//fUe/v2O
         X7Ki71qdnLzBgW9lAhQ9vurfTZD7UzBB1FF78m/cLjhH9+VNj3JqyPI4OoHjsPy6yg8m
         at01PZygzPe46/2aXEdIz660h3Opxc6fAtPAM+sAUjtgynE81K/UR/YFuU4yCokG1RHa
         PUQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769153994; x=1769758794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y5/3eB8k28t8qeOg/mLimIMkgLK93FFLoQ6fE1oCbX8=;
        b=I3aVVy+fmAdEmJYrpfchtrShE1O5WQWPYNvR6EaRkzCsyduQFjh2dJzLSvbbY9iO6Z
         /77RJLKDNOB6LdY3+oI7CKYOpCdVEp26Iamq8VnSgpUVmAsNlQhrw+4JhxO+H8HZ/o8B
         UsZmIsEv0NOb8RquIndQF9VUZuQR2L7NiexGLBOgtf87UQ9ioJww+2QxdbhmeWcSCb8b
         OzBvj0RK/seImjEhwyc6hXBXujUwBQy2FociN9CJdiZ0OInDnWBDihJ+kA7dPFYIs3KJ
         i7cNrhayu2GZdipHpflIWsfjTDABrb7qIg4W6++HX0AVGe7xKyF+W33Zw11PfyLxMfGA
         DMwQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvkhce5Wqyi7qsDt3EAvzhXE2VwOssQUNHM2J48mJL7nrOTSouMqvDjoJcOXUdrBN2fJ9RFQ==@lfdr.de
X-Gm-Message-State: AOJu0YzFVeD8n/dss1NUyk6w7IyxiO/j7/imDq6F9ygCcgMSPbRpDlU6
	dCrSzhu1ft5qTGahp4CLsYd6akcfnRQfi+TkGtZ6jYzSYY/atCHWw150
X-Received: by 2002:ac8:5709:0:b0:502:a1c7:4080 with SMTP id d75a77b69052e-502fe37222bmr4233241cf.11.1769153994428;
        Thu, 22 Jan 2026 23:39:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ESHFmX4qevzi7MnC1qE/J/WmznSRcEV0bEvAA1sLTDEg=="
Received: by 2002:ad4:5cad:0:b0:894:68d4:1236 with SMTP id 6a1803df08f44-8947df0e992ls34110686d6.2.-pod-prod-01-us;
 Thu, 22 Jan 2026 23:39:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwyTjsm1Yu6k9tyROMJ1DP2lurC0x4TsbspaKZ/Wcq5mHdZjX4EcuLEOvkD6I/SzMJHCLyY7tA8K0=@googlegroups.com
X-Received: by 2002:a05:6122:4d88:b0:55b:305b:4e38 with SMTP id 71dfb90a1353d-56645de6019mr83530e0c.19.1769153993024;
        Thu, 22 Jan 2026 23:39:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769153993; cv=none;
        d=google.com; s=arc-20240605;
        b=S0PdJ6UvARDP9WjgP3xGW/zE3Dlgs6Hs6HgO2HuS01r8k4dvzVm3oS1MwK+Zu1PynF
         cLeIm6qeP9BhKgPW/iFGJef5olHb0YG9PYEkDFHq+b23+2cmmAAJTvYqdxmLuyl4v6LR
         ZYnhXQ5lScVh1zOd9gWIjhfxPZVBq0xrHzdx9w6HRWyPQSHN46hVKcIlpyZiI7GRfCZ1
         QV0zxFn56vZFOZ/KhypVx0WTGD66gexPfN2AC1Afd9rdaYnpFx8WEk9mS3MPaCbkBTTD
         apRr7kMPvelaJf0V1qiZKvuAE1FLrczWea13X0pb4l2VRGk9eD6dpmbxnPjNTtfN5ROe
         y8ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=xTPybRJP8OVYkXfG9/a0F4gqsEh0oX8DQVBiN4ibEiI=;
        fh=fo0uf1ka2HDlpaZBTb0XY8JZ4PPCbF0KdSaHJOs60cc=;
        b=TB9IebcdgrupobOXrI4xn4v+poedLQDgS9Ud39UYssj09SPS2AnwQ/Rl3nmJlix7uc
         tpemUjhCrHI4a5R0YLJUqc7iGQQBmkBPvNYrljFyLfMxJt9+qfzrKTFq09jhf9W1zxzd
         YhVNNMlY9m3lkfJYuOH+F/V7PaEO+rjjf/r9tt01t9Lqa7WOOHB71nB34G8nKZUgygt+
         HGFFGgJnngqnI/A9BjSAf0OBHlb4kIL3DzlvJP1/H4gFPwqloOXu+Fb/jfAPMv+OtiMR
         xBePWXS6XRvMKla8F9QGzIy8ESBNPIvk/0UcYT66e75z77/glDqcSLsCcO6J+g7RrphQ
         wxsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cqDbiFxf;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5663fa734fdsi69276e0c.1.2026.01.22.23.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:39:52 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60MKaHMN028492;
	Fri, 23 Jan 2026 07:39:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt60f271m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:40 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7XJ69004182;
	Fri, 23 Jan 2026 07:39:40 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt60f271h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:40 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N5F6I1006427;
	Fri, 23 Jan 2026 07:39:38 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 4brqf1yfxm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:38 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7dZNY19071450
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:39:35 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EC3BC20043;
	Fri, 23 Jan 2026 07:39:34 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 88AE720040;
	Fri, 23 Jan 2026 07:39:28 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:39:28 +0000 (GMT)
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
Subject: [PATCH v4 0/8] Generic IRQ entry/exit support for powerpc
Date: Fri, 23 Jan 2026 13:09:08 +0530
Message-ID: <20260123073916.956498-1-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=WMdyn3sR c=1 sm=1 tr=0 ts=697325bc cx=c_pps
 a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17
 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=qhNI7X2oh4BViAGumkMA:9 a=QEXdDO2ut3YA:10
X-Proofpoint-GUID: qxVIxZlClOMHmGUk7ZykNwueZcuO5f0a
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfX+cqIm8qm5B2D
 lKyP3IULHXZMQ8fs65NZ0lm+S+UXLae0OX8aRjq7Chs9XGhgNbrNEnibvfWMUG4VuYIewa71x4b
 494siLzDuzUYVt2HskyU0PHzkr5GF8hWgqoS/X8kgA4XAgOkIdTXc/F9i8yZaAov7xrFXnCUvuF
 5zFdqa1Cc+0RVNffmN9bCzI4PaVtpiIF8V6MG3Wi2XfKKRCPG3isf29PgCX2P44O/iTtrunHdpJ
 dvbafp8MgZnR1wVwsFjQBVkAL9ogPhbA7zzdDa/K1aUegMjc/Ff0nHcjm2b7nl81hQPfIFDf4AL
 CJlrf2LtPnAiSaHt+UmpY3F4Y3mCRAkT2DwRtOWHyBQxlxa1dojRGlnG+i0ktuT/ifvNMFp5nzd
 87AKbZVMOc2Ibez7Ng9PtcENuUvevh6KGiYBR6CFYzuueEjG4GWzSNxLJlTf9Is3llo/7/+Ury6
 Rt/Qeru9oPn4U7/Qf2A==
X-Proofpoint-ORIG-GUID: rQWVxKWvq52gHXGEXcwkidNjR42mBbsh
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 phishscore=0 malwarescore=0 suspectscore=0 bulkscore=0 adultscore=0
 impostorscore=0 spamscore=0 clxscore=1011 priorityscore=1501
 lowpriorityscore=0 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2601150000
 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cqDbiFxf;       spf=pass (google.com:
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
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
	TAGGED_FROM(0.00)[bncBAABBSWLZTFQMGQESKZUT4Q];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_TWELVE(0.00)[13];
	FROM_NEQ_ENVFROM(0.00)[mkchauras@linux.ibm.com,kasan-dev@googlegroups.com];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,mail-qt1-x83b.google.com:helo,mail-qt1-x83b.google.com:rdns]
X-Rspamd-Queue-Id: 1CE4F71D91
X-Rspamd-Action: no action

Adding support for the generic irq entry/exit handling for PowerPC. The
goal is to bring PowerPC in line with other architectures that already
use the common irq entry infrastructure, reducing duplicated code and
making it easier to share future changes in entry/exit paths.

This is slightly tested of ppc64le and ppc32.

The performance benchmarks are below:

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

Tests done:
 - Build and boot on ppc64le pseries.
 - Build and boot on ppc64le powernv8 powernv9 powernv10.
 - Build and boot on ppc32.
 - Performance benchmark done with perf syscall basic on pseries.

Changelog:
V3 -> V4
 - Fixed the issue in older gcc version where linker couldn't find
   mem functions
 - Merged IRQ enable and syscall enable into a single patch
 - Cleanup for unused functions done in separate patch.
 - Some other cosmetic changes
V3: https://lore.kernel.org/all/20251229045416.3193779-1-mkchauras@linux.ibm.com/

V2 -> V3
 - #ifdef CONFIG_GENERIC_IRQ_ENTRY removed from unnecessary places
 - Some functions made __always_inline
 - pt_regs padding changed to match 16byte interrupt stack alignment
 - And some cosmetic changes from reviews from earlier patch
V2: https://lore.kernel.org/all/20251214130245.43664-1-mkchauras@linux.ibm.com/

V1 -> V2
 - Fix an issue where context tracking was showing warnings for
   incorrect context
V1: https://lore.kernel.org/all/20251102115358.1744304-1-mkchauras@linux.ibm.com/

RFC -> PATCH V1
 - Fix for ppc32 spitting out kuap lock warnings.
 - ppc64le powernv8 crash fix.
 - Review comments incorporated from previous RFC.
RFC https://lore.kernel.org/all/20250908210235.137300-2-mchauras@linux.ibm.com/

Mukesh Kumar Chaurasiya (8):
  powerpc: rename arch_irq_disabled_regs
  powerpc: Prepare to build with generic entry/exit framework
  powerpc: introduce arch_enter_from_user_mode
  powerpc: Introduce syscall exit arch functions
  powerpc: add exit_flags field in pt_regs
  powerpc: Prepare for IRQ entry exit
  powerpc: Enable GENERIC_ENTRY feature
  powerpc: Remove unused functions

 arch/powerpc/Kconfig                    |   1 +
 arch/powerpc/include/asm/entry-common.h | 533 ++++++++++++++++++++++++
 arch/powerpc/include/asm/hw_irq.h       |   4 +-
 arch/powerpc/include/asm/interrupt.h    | 386 +++--------------
 arch/powerpc/include/asm/kasan.h        |  15 +-
 arch/powerpc/include/asm/ptrace.h       |   6 +-
 arch/powerpc/include/asm/signal.h       |   1 -
 arch/powerpc/include/asm/stacktrace.h   |   6 +
 arch/powerpc/include/asm/syscall.h      |   5 +
 arch/powerpc/include/asm/thread_info.h  |   1 +
 arch/powerpc/include/uapi/asm/ptrace.h  |  14 +-
 arch/powerpc/kernel/interrupt.c         | 254 ++---------
 arch/powerpc/kernel/ptrace/ptrace.c     | 142 +------
 arch/powerpc/kernel/signal.c            |  25 +-
 arch/powerpc/kernel/syscall.c           | 119 +-----
 arch/powerpc/kernel/traps.c             |   2 +-
 arch/powerpc/kernel/watchdog.c          |   2 +-
 arch/powerpc/perf/core-book3s.c         |   2 +-
 18 files changed, 690 insertions(+), 828 deletions(-)
 create mode 100644 arch/powerpc/include/asm/entry-common.h

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-1-mkchauras%40linux.ibm.com.
