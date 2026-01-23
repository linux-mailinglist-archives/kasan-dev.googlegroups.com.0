Return-Path: <kasan-dev+bncBAABBYPLZ3FQMGQEWPYPWDQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IDHWLeO1c2liyAAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBYPLZ3FQMGQEWPYPWDQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 18:54:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EE9079394
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 18:54:43 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id 5614622812f47-455ecc3689asf5529005b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 09:54:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769190881; cv=pass;
        d=google.com; s=arc-20240605;
        b=JeLIboSc8bSBaS3oryqv7jCFHRzS+OHaWywCSTwehNKJPLukuPBqwkAvo5lAUsbZA/
         EyLzcTNzp+bjtHe3ORtKYPrgmWLxUEliruQUyNGevYBVwCGNi5bZKW18u/WPmTEVNQPn
         fNBwQSNuKvH/qsGd0z2ksQZRrNKN+Dx9gyzUOjnjz5Q7U8RZ2Ef8xKXcnIv0F6tAjky6
         /Q6lbvbTnZSwWb5ZImUjM8TqAKQ8B84FkChP3kxSUVod4GCGSCN5KMWUV4J0oX4PPsIO
         8c+/ccaXzVAUhyI4M3u3xVzxGIJtBJl9CDs8uvNvCCwkfPn35uNEWTBHvDXT5K3qZl2T
         aYyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:cc:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=KD2bUzYtKrEUVG/Dw9EtwsXSs7DK9FxKwm2NYxibXgw=;
        fh=sp2aXXOGuCN2aXJVBQctIvqKMnVMNm9hWr/ssKYsy/4=;
        b=FZeAWx2MvqAE/Mt5oHnP0P/Kvm4nJcBz+Fq34IGk/eixGhFUwo2T1UvoskI0B7joVx
         tb34Fer1RDEXkUh/NCRgu4xzoMk1TTUU7g8AzNONUSS8VIe4rk+WYcquj0S59KPTeUxa
         po2ZGWz1WL33av2pLyh/9smXYwsgfc0kDddEhLG39Nx/oSJh5ZrVhALLTipv1xI28rlC
         hPqld0LbBLQZ+ANIvH+ewS5v3LHdgDXVEHReCaW23Ljci6qlxEzlKhwDSsDcBRzq0iSc
         anjcLRV/F89SBw+Hi19EhPeDVrbGzpDa4YAAqqiz77zUDdCPZtNaZdr/HmdYCr7Zpoy3
         DcQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Y8tzwRrG;
       spf=pass (google.com: domain of sshegde@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sshegde@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769190881; x=1769795681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:cc:from:content-language:references
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KD2bUzYtKrEUVG/Dw9EtwsXSs7DK9FxKwm2NYxibXgw=;
        b=UlprvjEUzJF1s0EiZsOP+U+xiWtAPp2ONmuTnbBO+aO/Xe8j+PwXqw2g9FDtFzxDvi
         R81IegDTYAiAQZ9xZBIURhms9V4qBQA6c15hrjWx85/mKdd5tPSYd5tDWThpXk354MUU
         vGQYr64nRVuUGUk8jKz0UgwSTU+3qK+xGsQlbx+5s+uZL0X0HYAY7nTGZ1CwjUNZRdO4
         q7nqj+QR2QksN3nfjerReR2WF6YMkCQdSqAOZd7dW77RO36Z2QKH6j1g1CFNGFJjkKBl
         7DRvyWfk3pE3XaH9JXWCYbBRHbDjxmxVZymyQMOqHtkA/yDDxcPBRKzQ3W6lOF6icIQ5
         Ao4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769190881; x=1769795681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to:cc
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KD2bUzYtKrEUVG/Dw9EtwsXSs7DK9FxKwm2NYxibXgw=;
        b=bVGjKQ/OvqLxMkMBerwECA5179OQXf43jo29fOcOemCjBYkfQCMm2/BFSGWhEzO1nk
         FuCHf8WARjA3bxH4Xz1GRhdWXKqUt/efyiBJC1D8BS/dkYwe5NTGS+Z6ov8TRAzFotVL
         3g8AAfsNhSIfAKmICAJeocvt/qy9/LPz0V8r8WYwX3k0usRz7l+ZpqbWN6597aFPxyjV
         6GwkSVNktQgQzVnnlPnsHY4Hrw3PZhQlD6chDT1VxyYkPlzt4JfW2Ubdb/s84s5atgDc
         qBAFZOYTKuUjClkc3tBFnfDBGYLoXmmqBLUOXNU6RGOe7h6nWksJW2xXZoTGC+S8ofY+
         +qWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6IsERCblcXDRtmH2kMh4GDdOf4Dji5euMiO/P4On2V8U4YOJ050P0hvTIiE0xnnwS3HFLmA==@lfdr.de
X-Gm-Message-State: AOJu0Yz6R5Z1qK6byfaZOjma+HBFez8R8HvzvtrLmOqfmo+omTXTX/Tt
	Sp4rHP9gU4jPlSVcafoIcxlPDR65ByC8GGLsJ0fWU02rv2JYBonysnuV
X-Received: by 2002:a05:6808:2229:b0:45e:aba8:124e with SMTP id 5614622812f47-45ebb7a05c5mr870645b6e.23.1769190881394;
        Fri, 23 Jan 2026 09:54:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E4Ap0kARDCw/D8Yxbdt81kBx2ixfnQyJAopktGe6JAKg=="
Received: by 2002:a05:6870:9619:b0:3d5:54c4:3245 with SMTP id
 586e51a60fabf-408825fdc12ls1419042fac.2.-pod-prod-01-us; Fri, 23 Jan 2026
 09:54:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVBbahxMKD2vrL7VSkl2gzriNwxdyMQJm9MwM9uoQ8BeqLv++9k2V8Y19/WSAUVStOWNXHa8EiaomI=@googlegroups.com
X-Received: by 2002:a05:6870:f151:b0:3ec:2fe5:2b44 with SMTP id 586e51a60fabf-408bd9bd32fmr875264fac.26.1769190880456;
        Fri, 23 Jan 2026 09:54:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769190880; cv=none;
        d=google.com; s=arc-20240605;
        b=WgyFcnRmFwpkHHjXAaKa1qpOjZcDvgOxZhSm5We7y22owndypKAseOWZxkIp+SSukx
         hQjjc5qpYobFvitryuvH6aerah1EQ341MLVfOHKNyblxOMg5tgfsk7IXJhpVn+0fwnV1
         Di548cgR2HWUSeBA2fhALhXJJSZX5AhWR4dNwtiKP+NHBa27ltWT7aeWobCzFtighjTw
         6fjT7mnzRR4cSqse8ozbPDUw+aDFl54kXWIWao6p6d2jIJDY8cySNze40S7xDQHp019O
         O9Bf/TjB9Zi/0iAdijDtf00p407mK1GchZQCp/4EV+99mXT+2KN1XS2yd20VywmWo3cM
         ggog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:cc:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=b8Mov375bZ6LpMbf3/ApUSOuke0Bc51Tv7nEe8J4Zf0=;
        fh=mHV92sX5pfjI8Qa8q3QeBr95eaR7uNRBCyurW/uJeP4=;
        b=iXWLKS34JNEwo0HNlSDi/WeduBI743ulqmJaexpJeWHSRImco+tz+CKnsw/KygQdbn
         Ch7G8p0E2khrB4ZgbdNOssRVcOiobgVPSDMaO0pe4aL4aH1IOcMAtk3/zW06ZpGzy3Jh
         /Qgc+biypXgNh6MlhboBTqEyhv/FzYUAj1/hGLn++aBcyvBPJ1dylXM1+q/04CPxXbPH
         S7Lml7bCiqpbWb3Oot3oxI9HEKOBMc3tScyvonErOJrtuKWFE17QmIX8/Gv2v8t6wW8r
         h9UOyeH4WWl+sYEPYgwQcayxcqJ9rJR9LufceI6C51ZTR0mpheL01hA98dyQHW91y3C5
         kD+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Y8tzwRrG;
       spf=pass (google.com: domain of sshegde@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=sshegde@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-408af8048afsi77842fac.1.2026.01.23.09.54.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Jan 2026 09:54:40 -0800 (PST)
Received-SPF: pass (google.com: domain of sshegde@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60NBluRl006766;
	Fri, 23 Jan 2026 17:54:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br23shkny-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 17:54:28 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60NHsRFa012047;
	Fri, 23 Jan 2026 17:54:27 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br23shknv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 17:54:27 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60NHfP0c001441;
	Fri, 23 Jan 2026 17:54:26 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 4brpykaa2c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 17:54:26 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60NHsMKv57475528
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 17:54:22 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AA34320043;
	Fri, 23 Jan 2026 17:54:22 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6BE7620040;
	Fri, 23 Jan 2026 17:54:16 +0000 (GMT)
Received: from [9.124.208.250] (unknown [9.124.208.250])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 17:54:16 +0000 (GMT)
Message-ID: <fe290d99-e81b-4af1-ac2f-5b2a603f2311@linux.ibm.com>
Date: Fri, 23 Jan 2026 23:24:15 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 0/8] Generic IRQ entry/exit support for powerpc
To: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>, maddy@linux.ibm.com,
        chleroy@kernel.org, linuxppc-dev@lists.ozlabs.org
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
Content-Language: en-US
From: Shrikanth Hegde <sshegde@linux.ibm.com>
Cc: npiggin@gmail.com, ryabinin.a.a@gmail.com, glider@google.com,
        andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        oleg@redhat.com, kees@kernel.org, luto@amacapital.net,
        wad@chromium.org, mchauras@linux.ibm.com, thuth@redhat.com,
        ruanjinjie@huawei.com, akpm@linux-foundation.org, charlie@rivosinc.com,
        deller@gmx.de, ldv@strace.io, macro@orcam.me.uk,
        segher@kernel.crashing.org, peterz@infradead.org,
        bigeasy@linutronix.de, namcao@linutronix.de, tglx@linutronix.de,
        mark.barnett@arm.com, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, mpe@ellerman.id.au
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: z8oFEMXIu77fQ1YXe_BcD7q1rWsCagL7
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDEzNSBTYWx0ZWRfXwBwhBbIRDSrI
 hDumUhXCeHKXZkbfJXqUlIGQnGgaBpFl+T9ODv+QvLODVGhzHW5nAGSY3wh6jSYWcrbftL04LlI
 2z1jXdlafDD9Aqx+LL6ZacupzbjLWDenRRZlwVDv1LmFTEdlhtdt8D3RzZ0ZdaT+HTeet+RaGpb
 KiSceCXyhfn0CLTrwgrRf0Nr8sK9CtGb4wgvdrffqYG5End6jfsVU70if+LdWvdw8SmwN3DRj8j
 T1syo3KXCDr3FkdSTuEP5rniakzu7aSK1bMSDhWnx671/uZ69VItObsGDW4CjRStWaKh1gglwkl
 vXnnfaW3uvau9rinouZ6izB3208spfAxiXCVlo2bFQZPGo8AcaEVfk1DHXbjJq/LTg66EiXET7+
 iE5UYFaMzWZm9uGyTfQHYIyQgQk6pBzt0QTAII/xhBe5I3dv8pFqE2I9wjK/fcGEu/tyEK1xzCR
 QTIQTJMMJYNse+gEftg==
X-Authority-Analysis: v=2.4 cv=J9SnLQnS c=1 sm=1 tr=0 ts=6973b5d4 cx=c_pps
 a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17
 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=sMalUQvjKGqCotWJyjAA:9 a=QEXdDO2ut3YA:10
X-Proofpoint-ORIG-GUID: WpN86vPm6XmpPwOybC2qdTa6o26ixkyz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-23_03,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 priorityscore=1501 impostorscore=0 adultscore=0 suspectscore=0 spamscore=0
 lowpriorityscore=0 malwarescore=0 clxscore=1011 bulkscore=0 phishscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2601150000 definitions=main-2601230135
X-Original-Sender: sshegde@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Y8tzwRrG;       spf=pass (google.com:
 domain of sshegde@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=sshegde@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE
 dis=NONE) header.from=ibm.com
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
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBAABBYPLZ3FQMGQEWPYPWDQ];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[31];
	FREEMAIL_CC(0.00)[gmail.com,google.com,arm.com,redhat.com,kernel.org,amacapital.net,chromium.org,linux.ibm.com,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,vger.kernel.org,googlegroups.com,ellerman.id.au];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWELVE(0.00)[13];
	FROM_NEQ_ENVFROM(0.00)[sshegde@linux.ibm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.993];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,mail-oi1-x23b.google.com:helo,mail-oi1-x23b.google.com:rdns]
X-Rspamd-Queue-Id: 0EE9079394
X-Rspamd-Action: no action

Hi Mukesh.

On 1/23/26 1:09 PM, Mukesh Kumar Chaurasiya wrote:
> Adding support for the generic irq entry/exit handling for PowerPC. The
> goal is to bring PowerPC in line with other architectures that already
> use the common irq entry infrastructure, reducing duplicated code and
> making it easier to share future changes in entry/exit paths.
> 
> This is slightly tested of ppc64le and ppc32.
> 
> The performance benchmarks are below:
> 
> perf bench syscall usec/op (-ve is improvement)
> 
> | Syscall | Base        | test        | change % |
> | ------- | ----------- | ----------- | -------- |
> | basic   | 0.093543    | 0.093023    | -0.56    |
> | execve  | 446.557781  | 450.107172  | +0.79    |
> | fork    | 1142.204391 | 1156.377214 | +1.24    |
> | getpgid | 0.097666    | 0.092677    | -5.11    |
> 
> perf bench syscall ops/sec (+ve is improvement)
> 
> | Syscall | Base     | New      | change % |
> | ------- | -------- | -------- | -------- |
> | basic   | 10690548 | 10750140 | +0.56    |
> | execve  | 2239     | 2221     | -0.80    |
> | fork    | 875      | 864      | -1.26    |
> | getpgid | 10239026 | 10790324 | +5.38    |
> 
> 
> IPI latency benchmark (-ve is improvement)
> 
> | Metric         | Base (ns)     | New (ns)      | % Change |
> | -------------- | ------------- | ------------- | -------- |
> | Dry run        | 583136.56     | 584136.35     | 0.17%    |
> | Self IPI       | 4167393.42    | 4149093.90    | -0.44%   |
> | Normal IPI     | 61769347.82   | 61753728.39   | -0.03%   |
> | Broadcast IPI  | 2235584825.02 | 2227521401.45 | -0.36%   |
> | Broadcast lock | 2164964433.31 | 2125658641.76 | -1.82%   |
> 
> 
> Thats very close to performance earlier with arch specific handling.
> 
> Tests done:
>   - Build and boot on ppc64le pseries.
>   - Build and boot on ppc64le powernv8 powernv9 powernv10.
>   - Build and boot on ppc32.
>   - Performance benchmark done with perf syscall basic on pseries.
> 
> Changelog:
> V3 -> V4
>   - Fixed the issue in older gcc version where linker couldn't find
>     mem functions
>   - Merged IRQ enable and syscall enable into a single patch
>   - Cleanup for unused functions done in separate patch.
>   - Some other cosmetic changes
> V3: https://lore.kernel.org/all/20251229045416.3193779-1-mkchauras@linux.ibm.com/
> 
> V2 -> V3
>   - #ifdef CONFIG_GENERIC_IRQ_ENTRY removed from unnecessary places
>   - Some functions made __always_inline
>   - pt_regs padding changed to match 16byte interrupt stack alignment
>   - And some cosmetic changes from reviews from earlier patch
> V2: https://lore.kernel.org/all/20251214130245.43664-1-mkchauras@linux.ibm.com/
> 
> V1 -> V2
>   - Fix an issue where context tracking was showing warnings for
>     incorrect context
> V1: https://lore.kernel.org/all/20251102115358.1744304-1-mkchauras@linux.ibm.com/
> 
> RFC -> PATCH V1
>   - Fix for ppc32 spitting out kuap lock warnings.
>   - ppc64le powernv8 crash fix.
>   - Review comments incorporated from previous RFC.
> RFC https://lore.kernel.org/all/20250908210235.137300-2-mchauras@linux.ibm.com/
> 
> Mukesh Kumar Chaurasiya (8):
>    powerpc: rename arch_irq_disabled_regs
>    powerpc: Prepare to build with generic entry/exit framework
>    powerpc: introduce arch_enter_from_user_mode
>    powerpc: Introduce syscall exit arch functions
>    powerpc: add exit_flags field in pt_regs
>    powerpc: Prepare for IRQ entry exit
>    powerpc: Enable GENERIC_ENTRY feature
>    powerpc: Remove unused functions
> 
>   arch/powerpc/Kconfig                    |   1 +
>   arch/powerpc/include/asm/entry-common.h | 533 ++++++++++++++++++++++++
>   arch/powerpc/include/asm/hw_irq.h       |   4 +-
>   arch/powerpc/include/asm/interrupt.h    | 386 +++--------------
>   arch/powerpc/include/asm/kasan.h        |  15 +-
>   arch/powerpc/include/asm/ptrace.h       |   6 +-
>   arch/powerpc/include/asm/signal.h       |   1 -
>   arch/powerpc/include/asm/stacktrace.h   |   6 +
>   arch/powerpc/include/asm/syscall.h      |   5 +
>   arch/powerpc/include/asm/thread_info.h  |   1 +
>   arch/powerpc/include/uapi/asm/ptrace.h  |  14 +-
>   arch/powerpc/kernel/interrupt.c         | 254 ++---------
>   arch/powerpc/kernel/ptrace/ptrace.c     | 142 +------
>   arch/powerpc/kernel/signal.c            |  25 +-
>   arch/powerpc/kernel/syscall.c           | 119 +-----
>   arch/powerpc/kernel/traps.c             |   2 +-
>   arch/powerpc/kernel/watchdog.c          |   2 +-
>   arch/powerpc/perf/core-book3s.c         |   2 +-
>   18 files changed, 690 insertions(+), 828 deletions(-)
>   create mode 100644 arch/powerpc/include/asm/entry-common.h
> 

Ran it a bit on powernv (power9) too. Not warnings and similar
micro benchmark numbers.

I think this is in better shape now. With that,

for the series.
Reviewed-by: Shrikanth Hegde <sshegde@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fe290d99-e81b-4af1-ac2f-5b2a603f2311%40linux.ibm.com.
