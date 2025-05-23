Return-Path: <kasan-dev+bncBDHZF6PSRMKRBKMNYDAQMGQEDT36LNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 62FF8AC1BC9
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 07:24:59 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-231de0e1ca3sf64761645ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 22:24:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747977897; cv=pass;
        d=google.com; s=arc-20240605;
        b=aNT357kq4JDr9lhwyle1FS0NWMMeJCPeyuLievdrmjRHpfvXhPSFJjuO5xW0ITiE6J
         6yjblYV200JIWce4+IQKZJHEGIgB95LC/GL82tQu7pBH7RM5g5zP5bjSXWovvU2GXgAz
         rnn8r2zAOCykzG7nlLHq5rFDohKrhIoAwz5wxRI6cTmSJqCR0HOFFEPmadShhD7+lNWC
         vj5W/2KUi3RkYALOw3I3sY1Sh7GQR/sHA6/gvUfpM0mL6xWS4G703BFOsV/VsXA/46i2
         nX4krW48Q1P3/lH1utZdIrROnaU5W4Wz7Aesii8RfqiPPmlCq/l7toiHj9A0jwHbgylH
         TKPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=OaWeQf97sRohotGLk9FRsYHup/O/1r9Gkm+umS6yUG4=;
        fh=VBu+VTIqYswkpYqh4ER2lLMFWzBUNzgvC/vJGhg0ooY=;
        b=I4fvqNcFIhCJ5uafoha5aPA5DCns2bv3Vc7+hxlXVTgSTP4pHtVy+fuGkvA1EG4DzK
         d11QN+ZaIR5CuYFLpOb/nBx2ChCIh9pFLOxL2FyeTfk+5t4efw/bNp/cagvY5kAd+lXX
         4/nbzN+FlUe4VnMB/2oZTjNqOkyWiZktYtNnpvkDnacHqrkAXUH+pSf9dAzyQWUaMVAv
         jjRQA4rsJrhAIuDeqCDT5SYkXKVhy8Ck+RE61XTLr7rF9bY+2arttD4oo+JXZHqL1vUH
         zE7+uglQBEyeMFqXAFsasHZ4iZZRBUuw99sakJuFKVaWFoQUP+jzFlD9yIFTwj5D+w08
         qmfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gkPzzSJS;
       spf=pass (google.com: domain of ajd@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=ajd@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747977897; x=1748582697; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OaWeQf97sRohotGLk9FRsYHup/O/1r9Gkm+umS6yUG4=;
        b=b+ahk5bSAkI3gAtWyo6RaBwg1XaL/XiV1Y4hvOYon+nCP+wfxIA3sVYfWduO+mUH8q
         nuR9Er0AgxCkE2ELzGQZSIKIxA6VzmsYFI7kubXnIDxa4AL20/Q/Hj4XxsdodvcWgymp
         vncId6xZ4W1GWa+QyhpnvpNxi4Gmm4hlegILHrVLwgp4gZNm7gtOI3QeegrhTf8VAr03
         yEqoZpbph9iW5LS3Uwv+JK7VLNRF7J5Li2bDhiz0rz1DHIfV7G+ajEnWO7YzigmemW5f
         ce8jZDi9k1NMsyiPeXwuJyFQFbI1oUjh/XKPz++HP7e1m1wZZCChqdoB2afdlolw9TZr
         WslQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747977897; x=1748582697;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=OaWeQf97sRohotGLk9FRsYHup/O/1r9Gkm+umS6yUG4=;
        b=oDjmPbT38SYRjjXodsG7TBQGd3/yQqXC4nmmoZYI75clZb9zL/TDgUr2CQpuz1wlyO
         NKAjaMa8USsfShOPeEhvpza72guYKtckhXaj+6QEp9nLPsX3J8NAp2ZCqmkeBNzRBGi7
         twK3awNvsu4KcOUY1DH1hSg87G2opOJ5KXyrGA5MbkWzfFUYr36yRVwI9YAAsSrp58wF
         m5Fr+/ULgt1St62OowBbQC6VJUzhzsJboqARX4EwNkbrM7jULkWNeyLw9Tmn5EMNnTw3
         LgRpskZWU7sVumGbY2N6gut5+vvktKCb0qsy97mgsMKv80NAL7Dq7Jz0nAGhEhohRoj5
         TmPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXz8RkMD5PTkXgpIFBhPYBzCeps/bd4rba+rrmoLrbGAtUuiTGMqWF+4wyavobAyZrzD1pvmA==@lfdr.de
X-Gm-Message-State: AOJu0YykUJL17NOhWDpy7AlxtRImaCOmN0TgFC4Bn24t+ePvlj7Io9EV
	Nk7rtcXoPgkidRspoiefQKmiGHt1mCYxT8T0NEoY6BwGp/C8bGTDThL8
X-Google-Smtp-Source: AGHT+IGA6+6SFIn3yuKmvEpScSaX0HO/KJHBOgBvcWVCbBQGGIQJO+Td+kqueNJPJYUhj6dC27u61Q==
X-Received: by 2002:a17:903:234f:b0:223:47d9:1964 with SMTP id d9443c01a7336-231d459a55dmr384697115ad.34.1747977897465;
        Thu, 22 May 2025 22:24:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHH8m2voo/2jDi4WQA5RTWrFQb7Vjg5myqQQOpXPEzuig==
Received: by 2002:a17:903:3247:b0:231:df04:c5a8 with SMTP id
 d9443c01a7336-231df04c729ls46279155ad.0.-pod-prod-02-us; Thu, 22 May 2025
 22:24:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4UwbPtv+RPJp+aD9qDtyNljaM1sij6bw05vcDgE0Vif7wrMXl8bMuTTgTEDK5Zu1LsyTJIoqjEN0=@googlegroups.com
X-Received: by 2002:a17:903:2449:b0:231:c2e8:89df with SMTP id d9443c01a7336-231d4535a98mr422124375ad.28.1747977895881;
        Thu, 22 May 2025 22:24:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747977895; cv=none;
        d=google.com; s=arc-20240605;
        b=XLtPjdCfNozL8d0IoEQ037bLKEtK5Nyk2Fz2AunlnnJ7rjnuhhCn4Uj7hHF0y+1imC
         0SyZT2u8/AWcNwrNoAbgPwJKbjBVYGCy1GlazPp03ZjUg30LGM3EDNtVWoAu2/zH0g6B
         nij4WidfKWsprNaaEjV001Xrh3LW/KEL1CDIVQ90316mtpR4kJp48kMMXYlkcqVKmDS0
         FpxwOghD/SHz1XVXWe1IXp0LtZ23HYkJJ0uJ1EzsU3nGDoMj6PGGItYQ3m/PP/BrF12F
         BB926RZ9746+gYK+u5xHqbIC9ey2BSY6bigXZolJa51C9mPidElKAI4NQLH+zfy6AVq5
         CkbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=T9QR0vRv/b0B11JDYax3wCR+tNiJcsp+EMocfpzOxi8=;
        fh=+VnJbOQfjbvs6ovGpKa/9u06/2vsUPDV1q9WZx4X8TI=;
        b=BQ5/nGl1UMyitXydWsHCLWPlZ8Y0/YananFKHuS00qEgmVGmxrk9gqwcDBrB33zFCt
         y0bdtO648oI2RSDR01/jy7TkSkWPZWCsy8kN63XZwWuNsnAs763HrBYRjDdV4yhCzBys
         dLkZe7ULBDLJKfTOMq5oDX098toXOk83Cyh3LOT8fIPHoa1Tynfb/jNWRwuEHymM61Jc
         OcE32NOpt9ZqMt/gYIzyDVBZd+hf1Sse/OSZwxBSXp43JPIgm8Gpme08pnp5ckdMnPaY
         5A+qiu1uKqkCTHX3FKik4vKLJINIWe/3ZA8u4IbZ8Weftmr7Imafy54TKodLc+NULV1O
         LhEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=gkPzzSJS;
       spf=pass (google.com: domain of ajd@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=ajd@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-231d47cd58dsi1768735ad.0.2025.05.22.22.24.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 May 2025 22:24:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of ajd@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54MNWEn5006420;
	Fri, 23 May 2025 05:24:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46t9m7t7sq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 May 2025 05:24:43 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54N5Ogd1008988;
	Fri, 23 May 2025 05:24:42 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46t9m7t7sh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 May 2025 05:24:42 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54N1ugL2015431;
	Fri, 23 May 2025 05:24:41 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 46rwnnn2at-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 May 2025 05:24:41 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54N5OdfJ51446136
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 May 2025 05:24:40 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DFC2C20043;
	Fri, 23 May 2025 05:24:39 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6FB4920040;
	Fri, 23 May 2025 05:24:39 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.63.197.14])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 May 2025 05:24:39 +0000 (GMT)
Received: from jarvis.ozlabs.ibm.com (haven.au.ibm.com [9.63.198.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id A792F60213;
	Fri, 23 May 2025 15:24:35 +1000 (AEST)
Message-ID: <e50abba6c962772c73342bacf20fb87dc99dd542.camel@linux.ibm.com>
Subject: Re: [PATCH v2 08/14] powerpc: Handle KCOV __init vs inline
 mismatches
From: Andrew Donnellan <ajd@linux.ibm.com>
To: Kees Cook <kees@kernel.org>, Arnd Bergmann <arnd@arndb.de>
Cc: Madhavan Srinivasan <maddy@linux.ibm.com>,
        Michael Ellerman	
 <mpe@ellerman.id.au>,
        Nicholas Piggin <npiggin@gmail.com>,
        Christophe Leroy
	 <christophe.leroy@csgroup.eu>,
        Naveen N Rao <naveen@kernel.org>,
        "Ritesh
 Harjani (IBM)" <ritesh.list@gmail.com>,
        "Aneesh Kumar K.V"
 <aneesh.kumar@linux.ibm.com>,
        Andrew Morton	 <akpm@linux-foundation.org>,
        linuxppc-dev@lists.ozlabs.org,
        "Gustavo A. R. Silva"
 <gustavoars@kernel.org>,
        Christoph Hellwig <hch@lst.de>, Marco Elver
 <elver@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Andrey
 Ryabinin <ryabinin.a.a@gmail.com>,
        Ard Biesheuvel <ardb@kernel.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Nathan Chancellor
 <nathan@kernel.org>,
        Nicolas Schier	 <nicolas.schier@linux.dev>,
        Nick
 Desaulniers <nick.desaulniers+lkml@gmail.com>,
        Bill Wendling
 <morbo@google.com>,
        Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
        x86@kernel.org, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
        linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org,
        linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org,
        linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
        llvm@lists.linux.dev
Date: Fri, 23 May 2025 15:24:30 +1000
In-Reply-To: <20250523043935.2009972-8-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
	 <20250523043935.2009972-8-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.1 (3.56.1-1.fc42)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=SMZCVPvH c=1 sm=1 tr=0 ts=6830069b cx=c_pps a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17 a=IkcTkHD0fZMA:10 a=dt9VzEwgFbYA:10 a=VnNF1IyMAAAA:8 a=REYBSQJbgk_QW_Jsg8sA:9 a=QEXdDO2ut3YA:10
X-Proofpoint-GUID: oQb5v6M7wutfrMtk1qvZQMEXsUNMAS6C
X-Proofpoint-ORIG-GUID: 5IyYPtP_M7W6sx6jcc6-H4GkEZFAEAEb
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTIzMDA0MyBTYWx0ZWRfX8CeyVmgZNEOz 8pmB+9RdT5ZsQ98qxplPqvRkrNpOOYwsSTFPDm5ofvI1Vh4bbudIby6HA8NmTGhtWKTGCbPb+Vc ncpDniBcH8eQ2V6TvH4/WOR7hWwc72H7W3tmeVLVHUbkift9S50W47R4EZG5vRt+eQh2UiWAsBK
 iE2vMgtZCKgIB8ryEScHd2O4ZVBu+fZQ71R6KP7ZepPiveo0szKoP5GtVDvnlETC92QyKZ6dJPA 9F354NXkUaazXC5GwoeLMpIeHZomJ+1xdeYZUMVAtJ78BfchmFk42UaDhV8BLvtV9oREWNDxTxG /JkwdDWhrq02gBuo/giLPxFbLNIIh1tgMIxMCWOWwczwEbDPV9zml+heRweY+Jd/oul5iu2Dl1O
 bQSsYl9qhOX4fnuFfAi63sra+qJkyo0qkV3/wv1tj0wVD9FBgFyh3pEhli53wYP0l6epaDcF
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-23_02,2025-05-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 mlxlogscore=480 suspectscore=0 bulkscore=0 clxscore=1011 adultscore=0
 phishscore=0 mlxscore=0 impostorscore=0 spamscore=0 lowpriorityscore=0
 malwarescore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505160000
 definitions=main-2505230043
X-Original-Sender: ajd@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=gkPzzSJS;       spf=pass (google.com:
 domain of ajd@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=ajd@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, 2025-05-22 at 21:39 -0700, Kees Cook wrote:
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved.
> For
> s390 this requires forcing a couple functions to be inline with

I assume you mean powerpc here, though I'm sure my employer is happy
that you're at least confusing us with IBM's other architecture :)

-- 
Andrew Donnellan    OzLabs, ADL Canberra
ajd@linux.ibm.com   IBM Australia Limited

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e50abba6c962772c73342bacf20fb87dc99dd542.camel%40linux.ibm.com.
