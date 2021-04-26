Return-Path: <kasan-dev+bncBCDYRIOG7QBRBTW2TGCAMGQEZXRLZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FF2A36AD2A
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Apr 2021 09:35:44 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id z200-20020aca4cd10000b02901865d9b3b3bsf11506726oia.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Apr 2021 00:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619422543; cv=pass;
        d=google.com; s=arc-20160816;
        b=e4QoBKiauROTIJ1QZ5hOVnwmqe1oN2Gt1nPg8o3kJKnSfTJhqQnEuGBbGZ95lXNEOp
         a9Xo35Y2cCe3uTLr6ZzOcnfdmnLKkBlFRrb5dwrxqBlzWhBodIXhhe1FkW7w2NIE9wo9
         zW6A8jMSe4tm2ZJy1XRUcNuJWcvSKrn9nrGSjl3B9ASRF4xC03+dcON6Ux/AewbLbUZV
         FNEXGU7TS129wZHIHXsmMe3di7/kJ93GSqQaiFAyStUVgfVT9OQO23dtzKu9l31o3uCl
         iuBWpl2F5ga8AGlWb/cYwGSvHn4kCB2kKkD/n1OazdoD91WMX3STlxPFR9sRUS5dXjpI
         LmQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZED56L0+KaGJzNUJMtZYqBIxNnosBGNW8vnFyKOW3WU=;
        b=s/7RNFJ4/FdV2b4B5DPNyN55XXZ9OKS8duqb1985E3p5ywR1VJ4q+6BSowCr/8u5zr
         tTYiNI7FoxHE8pbFpPcWmpCiAUVR4ziixr1TzJuynGTNIG1XKza9VIsPyZHqeHVfNBaz
         O2m69VznmWKlGYggGk+M2yQ8N3SskWONx8OwwPR2etxvmG5cQOdikrkG5hVevCSFmazr
         8VW5/kAff88RPIFcvIUxRssafSh5s6J84ZuuCiRi7/d/4NKp/QBkHpIKOgs+/xqouCXm
         inkpggly7Bwlm9GI5/XV9vgUt784/BAvEz8Mjkqi9VjV70VchmIMF/08NqkGZBXSZms1
         gGDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pZmvAi6S;
       spf=pass (google.com: domain of egorenar@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=egorenar@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZED56L0+KaGJzNUJMtZYqBIxNnosBGNW8vnFyKOW3WU=;
        b=gueF9BWCiBPSVKA8A0GkXBRGCnWIG5fUOY3FQcB00/95c9o/KcFjARVommBaTF2kiR
         b014UTCb6LW3jZ6F3tuDwCJqZKj0NlpDuBny8n4Kq+WVEI041AQWjACAAvd6HYvIJETQ
         TabEWCMZcY3Sj2knno2kRXoCLHRYj/Omw5WkHBMgSSDRZ+ksYhGlgaeolcIyFv6XdUGG
         fplbzn7CG2qXaFZjMvMPimndXHXiyDHsmCRH5Sui9iBveHmHf7tbdKQnVqNb9v26OFVn
         xsm4hhDxu8so6sUF/88rYAqDGQHl4acTlwSLoi0LKvzrh/S3tx5dRpc61JFkvUBHAIVC
         gBeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZED56L0+KaGJzNUJMtZYqBIxNnosBGNW8vnFyKOW3WU=;
        b=r5ktN/k9kkqSN+gA6gh6LH34M0G5TrizXj6Q8OiVx6WmpxHaonYJtyWOS+cCFExjn7
         yb+A5Y22qZTctgJR4ucFlcZ7a9K0sLmWeZm6/Meb9aHqabny3IT/+Z8JA27t34RUjkrA
         BR7rDHF7u276aVmImkFja4/HEPF4vB5W1xDW43ZaiLbdyDjJG8glwA7z4+RmLJ1V0Sw4
         Z5Anxaamw4A5o44jVOrVSFpxC75p37EIOjNBW5RK6aI8R/JGKIKixhTY9xWpm62yt0qD
         Y+2nJTASlbHIHBUGQ71CrYMnJji8iwl9WDLcDTXQOzZowFlZvMfL9Y8P6LvP2OZNqs15
         HV1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336o8LWX8n4QL20O8+CFO5OyFTmiuQCi6wffEQ5g1jytQDuconl
	slgvSP3rkcczrbKZPbYekpg=
X-Google-Smtp-Source: ABdhPJwMN2U4mit9Wejh0ULZfJRtTeEyTnudWNIxXC03u0Zxem4c4rnRvVB4xjc5+lJU4rJSJ1lSaw==
X-Received: by 2002:a05:6830:400f:: with SMTP id h15mr13795516ots.32.1619422542895;
        Mon, 26 Apr 2021 00:35:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:71cf:: with SMTP id z15ls4477700otj.2.gmail; Mon, 26 Apr
 2021 00:35:42 -0700 (PDT)
X-Received: by 2002:a9d:4b9d:: with SMTP id k29mr6107482otf.240.1619422542415;
        Mon, 26 Apr 2021 00:35:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619422542; cv=none;
        d=google.com; s=arc-20160816;
        b=L+ikp9A/LLB1dq0w1TlKexI791Oxk/XLLf5ESt6nQ1FOk7RnBcKDHXXdla7Zj6BVog
         DC0Zl0bD8WkQsFyyLXq1jXMpZN9xrwlB1HuQKkKj/azN3Iho/GZxRN/gaecZqWthwAdc
         V8lba48NK6PHRKt8vkU21Pkxs7yU2mlFVdmyCz1L4QXU/tS4KwZ3Fg30evNKO+qE+tOm
         Pzo9RtoEGHSxlavNZ+cB87VvCyDHLbNpELVL3YK6vrL9WfKGVIxe4oYMduq29/xcBHYa
         xuMBaLQUo8/rUJP9RiFdEs9v4QLdF5yFL/iWT+wzH3g03qUqy8bQY2hgsl/LzL5HYfrk
         V/2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vj2OQzjjLqs7BiSXWVriVvTs25SIobcYvo68jiLw4Uk=;
        b=P22E+sVptopcwfEyw1E+O7mtL6z9Plgs8wIuos7sRtKW5Lr1x4ptA2/agzIThr7+uh
         OVJXMfpmxOoBcmSXBCyNCDXlYAfZ3vuqEFJvlyIwPkCrbXlDMUWNexm7Erg5VYGFKUH8
         mvqMBlS4vXEN/vdBct5p7hqe2qhSjBpXDIhC7hWzSKt36MZyXt1auGbNmfJXTw8jn8R0
         Vu/im7qsm8yh89JDjkoHVw/hkzlLcP9Yftp3/5E+k5x5Tk5QiEl9fcJNYpdzSHnO1zRn
         7WVK49qhr8YKEehF8aW2YgMajOCrqRVX0giKRSti7BOe9SiYual5ncFPmAGubk0/gjem
         tWgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pZmvAi6S;
       spf=pass (google.com: domain of egorenar@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=egorenar@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id n10si208768oib.3.2021.04.26.00.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Apr 2021 00:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of egorenar@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098417.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 13Q7XxWP121133;
	Mon, 26 Apr 2021 03:35:36 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 385ry00h6e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 26 Apr 2021 03:35:36 -0400
Received: from m0098417.ppops.net (m0098417.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 13Q7Y96u121861;
	Mon, 26 Apr 2021 03:35:35 -0400
Received: from ppma05fra.de.ibm.com (6c.4a.5195.ip4.static.sl-reverse.com [149.81.74.108])
	by mx0a-001b2d01.pphosted.com with ESMTP id 385ry00h55-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 26 Apr 2021 03:35:35 -0400
Received: from pps.filterd (ppma05fra.de.ibm.com [127.0.0.1])
	by ppma05fra.de.ibm.com (8.16.0.43/8.16.0.43) with SMTP id 13Q7TTCD031842;
	Mon, 26 Apr 2021 07:35:33 GMT
Received: from b06cxnps4076.portsmouth.uk.ibm.com (d06relay13.portsmouth.uk.ibm.com [9.149.109.198])
	by ppma05fra.de.ibm.com with ESMTP id 384gjxradp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 26 Apr 2021 07:35:32 +0000
Received: from d06av21.portsmouth.uk.ibm.com (d06av21.portsmouth.uk.ibm.com [9.149.105.232])
	by b06cxnps4076.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 13Q7ZTiC28377576
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 26 Apr 2021 07:35:29 GMT
Received: from d06av21.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3C76E5205A;
	Mon, 26 Apr 2021 07:35:29 +0000 (GMT)
Received: from oc8242746057.ibm.com.com (unknown [9.171.71.219])
	by d06av21.portsmouth.uk.ibm.com (Postfix) with ESMTP id C5D5E52057;
	Mon, 26 Apr 2021 07:35:27 +0000 (GMT)
From: Alexander Egorenkov <egorenar@linux.ibm.com>
To: elver@google.com
Cc: acme@kernel.org, alexander.shishkin@linux.intel.com, arnd@arndb.de,
        axboe@kernel.dk, b.zolnierkie@samsung.com, christian@brauner.io,
        dvyukov@google.com, geert@linux-m68k.org, glider@google.com,
        irogers@google.com, jannh@google.com, jolsa@redhat.com,
        jonathanh@nvidia.com, kasan-dev@googlegroups.com,
        linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
        linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-tegra@vger.kernel.org,
        m.szyprowski@samsung.com, mark.rutland@arm.com, mascasa@google.com,
        mingo@redhat.com, namhyung@kernel.org, oleg@redhat.com, pcc@google.com,
        peterz@infradead.org, tglx@linutronix.de, viro@zeniv.linux.org.uk,
        x86@kernel.org, Alexander Egorenkov <egorenar@linux.ibm.com>
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf to siginfo
Date: Mon, 26 Apr 2021 09:35:11 +0200
Message-Id: <20210426073511.270990-1-egorenar@linux.ibm.com>
X-Mailer: git-send-email 2.26.3
In-Reply-To: <CANpmjNPbMOUd_Wh5aHGdH8WLrYpyBFUpwx6g3Kj2D6eevvaU8w@mail.gmail.com>
References: <CANpmjNPbMOUd_Wh5aHGdH8WLrYpyBFUpwx6g3Kj2D6eevvaU8w@mail.gmail.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: QwXFwizg1FxfiD25IzOGoHgPL-LRsFTX
X-Proofpoint-ORIG-GUID: 5lSoIFOb8pvez6BcVwFc5uehLV_UXxCL
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.761
 definitions=2021-04-25_11:2021-04-23,2021-04-25 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 lowpriorityscore=0 spamscore=0 suspectscore=0
 mlxlogscore=905 phishscore=0 adultscore=0 malwarescore=0 clxscore=1011
 mlxscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2104060000 definitions=main-2104260057
X-Original-Sender: egorenar@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=pZmvAi6S;       spf=pass (google.com:
 domain of egorenar@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=egorenar@linux.ibm.com;       dmarc=pass (p=NONE
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

Hi,

this also fixes s390.
strace's tests-m32 on s390 were failing.

Regards
Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210426073511.270990-1-egorenar%40linux.ibm.com.
