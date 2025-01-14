Return-Path: <kasan-dev+bncBCLMXXWM5YBBBEFWTG6AMGQE3O2TWYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id B9AE2A106DF
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 13:39:46 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2166e907b5esf103232935ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 04:39:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736858385; cv=pass;
        d=google.com; s=arc-20240605;
        b=PTWm19Ya9HkJXe93CTQChwHoplT7AuuTIra5OL3mH52f7bjrOWWsBb2ySopHTSqDRc
         tjQupNiDCVtOvAeSUsbh29Oxy7mL+X8OWpoFfQg70AzD8BmBo62rrocFFfZ9VNLsTKhw
         aePGtjddsD27P4YphOGwk3F9MuCYsP7oCSxFkESUGlXSSSBQE4+n6IYrr7yRiD0g4xk0
         ozkPT0DdtRkKq2kHXRcHGXB7EZZyCOlXn4OPu0S692mjbiu/gA3zkGKWf6JYo6q79S5q
         FWP0BdtvFwVrmh4jzAR8O3jYfg9M1O5sOYz+jLyZzboUtFkXppKHYF5lftZLSKbIFJq7
         fYnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AjsNhIn1y8sPJnGADBJZrXCRqKWDfpX9bkVGeuDHF/8=;
        fh=U41cR7rzILAds3QYqaPlkal1nnVfquGrR7TDINbuOJo=;
        b=M6DVZD7iDOr84u0Vp1/ALydbz4GtpgVGn/7B38QTijfBiqF/SsDEoM+jwt/ezjZw8V
         LzaWuvUUQH0tXRS2bXP3GrUJh7pnoEIqGis5MaprbeX+k28wFEfpZooCxVAzap9bT2x6
         PkYv1lQ2jW+ztprzBDTMigrj+BlHFj/2oay3B7dEpLWQSo2amMGsgr64BTK0Lu5qy4NU
         QzK84zCAlNOUhdvlg/2TrxP+hw3I7Nc/UdN6oL0kBO54ukFnN71LPqltSL+TzvOLZkJF
         xxGuzr47mX2kL726mQanrTUuIqrC3gKdcQD50Of90NFcBaOoTx6GY5yDBjaxrSQ3Fgaq
         jaXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Cpwb9zYI;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736858385; x=1737463185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AjsNhIn1y8sPJnGADBJZrXCRqKWDfpX9bkVGeuDHF/8=;
        b=Dwp/hkk1YmDcAVoueR9y7VVNQYGmQc5P9shOgjEDICxdaHvxl3d/wyz8NOraz7PWIU
         gqaMS+HEa7Rgj5HtreXQvOohT8Ga5f9jkTfW20NZu2Hi2zlvBUsPN9yXKcAE7zKEuxVA
         CWnOyR5tM5YWnX2GfnkgkD/9iwNJOeQRXA/NECa/S7XzXVCOpSUcb3YqvqiUR/Nb7z6T
         HPqgfaraTqZE0+eFKdvEZru+FH1898KXlf1jZb4U5r/HLggP5bRnGALCDtEjrW8QXv6C
         g63C20nNpUrTXPCdinyyjWXvCQNPHjieJDnBgj0u9WrrDasz3YxIyOgA4MtZsiPCAYUh
         dseg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736858385; x=1737463185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AjsNhIn1y8sPJnGADBJZrXCRqKWDfpX9bkVGeuDHF/8=;
        b=d4ZWTWu9OHkHPaTwAhGROYEFpvSV5up2QhERUe3tla6afgI8wdJZjr3ypAgbXKVf3/
         Hr47h6/QuKVQgyrMdXN4xKFamATkA5vkh/LPbj2hE09mtc/GjJlxGJpto3GdcdWzYlRT
         UIFTiNdD8vwv0HiEDVzejaRKdRtFNjlfAr7+x/DX7ZW/wdkBSbOvzGW4CBjNgb6fDNRp
         30TehAoEoUiUHLSeQvSr2rF363ii9T/dQ6A/oH0i6I8711hTpCyCfrVDN/cWH2OCVV7s
         0hUSeT1sr9PWRTFpWSPIm00+r0y0RGUdkrLQF9IzphQ/EuIahI2dUvhyGyg1OdJloLQC
         yVOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWH4WE1okn8sVD9kI9akan/RLWFXwUao+SJ7vMoUBDMBj+lvKaN2iR8qLtuWnDCaaRDaubqLQ==@lfdr.de
X-Gm-Message-State: AOJu0YyqXw96GmqfynTs2N2DtsreFnINmTkPHgVPt1ibg/5Xp72rZUA7
	G7U1DuaLyK3EXpiijyIRLjYFmxRZDllj/KgGJV2os3zbXpP+l+qI
X-Google-Smtp-Source: AGHT+IE8TAaY3ma8J9ByVHtLUQcL/pxkn6j8D15PoAzPRCx2q64U/M1l5clfbS/FFCHcbxYYTrxf5Q==
X-Received: by 2002:a05:6a20:1592:b0:1e1:a8b7:b45d with SMTP id adf61e73a8af0-1e88cf7bf8dmr41607588637.4.1736858384751;
        Tue, 14 Jan 2025 04:39:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3999:b0:728:ed3e:b036 with SMTP id
 d2e1a72fcca58-72d2fc50386ls2479420b3a.1.-pod-prod-09-us; Tue, 14 Jan 2025
 04:39:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV3zkMjwdgdQjDH9HtHo3AUp5hKKU0t0dcltFxOZ8MlnbLwn4vzxb3mvnGikFeQZqH9K1X2O/9ZLeQ=@googlegroups.com
X-Received: by 2002:a05:6a00:2306:b0:725:322a:922c with SMTP id d2e1a72fcca58-72d21f16052mr2738656b3a.3.1736858383324;
        Tue, 14 Jan 2025 04:39:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736858383; cv=none;
        d=google.com; s=arc-20240605;
        b=IdBqgolMPAy3OrO/rj9yi2CLqiad4teYGtLj7HU2A4QVmuuknX7FvQ4ZD2agdmCSbt
         uoHTVG/beCWmVvY7oCaYHYh4mtS9fdgf6bXy7lvht0vOaFFcy3yinUnbSNb1JH8TGFhp
         4BqLJAcW8aDKpx5r/d/3a9l50vKG3EOq5U5HE0V8LFo90OhNb6uWlLGx2Qrm3YQoNTQz
         LvxQHrdHPkNuwZxXYMJXmlrIzDJ71vmGpTDL69VJkxH5tBpgGrOuBj0xKBPEcyyxqB82
         5A8EhYJE6E4IulOdmQOQxw4YOOvzct224LjwVf1gP7BZCt8qBOf+HVLN0kR8U3wwrGiW
         SFPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mLKLiLaeqNSpkNvN0pu0c0rjtZRgVlaoo0nPXj6GPfg=;
        fh=hygZiRs3abiNFCRCQV8SCxB+Tf88NjoSUBjwL/Bqs3U=;
        b=ZOY7QiIu5OAsmXhBPJ9DWGVIyzdlsYgjqiTeUd/fcCRlMo3YHiGyO9QkvsfV5juTOL
         NrnhIsKUFzIpHqLxPceq7j5ztC+bD8+MIv+d2LAA3iXl0tl5TML4tKArjDJSldnksT8m
         hsIjurMT3E/c5lO4eqC9bsue7Vpg4BpZOtUiv2S3LcCaBi1kNyZXKN2vL+DWqS5nX8k0
         jiVUPK6CaE9kyP4U/t3K/AzDrseaecFnv90520dTaiukAOqwCmnV5p9SwhZKmykBA8n2
         9DZDSS0UuI7KE1QJ6iS1AqfkN6dOHXIJjJkMMSuI6pZ7f+KmqzMBPdlPdUrLdyrxayNc
         1Mjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Cpwb9zYI;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72d33fc5d70si421259b3a.3.2025.01.14.04.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Jan 2025 04:39:43 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279866.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50E7Sbug024112;
	Tue, 14 Jan 2025 12:39:38 GMT
Received: from nasanppmta01.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445kjq0n27-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 12:39:37 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA01.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50ECdbwG001123
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 12:39:37 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Tue, 14 Jan 2025 04:39:31 -0800
Date: Tue, 14 Jan 2025 18:09:27 +0530
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Andrew Morton <akpm@linux-foundation.org>,
        Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
        Christoph Lameter
	<cl@linux.com>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon
	<will@kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-kernel@vger.kernel.org>, <workflows@vger.kernel.org>,
        <linux-doc@vger.kernel.org>, <linux-mm@kvack.org>,
        <linux-arm-kernel@lists.infradead.org>, <kernel@quicinc.com>
Subject: Re: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
Message-ID: <Z4Za/3Vz7t5NSbE6@hu-jiangenj-sha.qualcomm.com>
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
 <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
 <CACT4Y+badwgw=ku--uJRWA94SA6bGXdtT+J9eO_VQxqWDxGheg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+badwgw=ku--uJRWA94SA6bGXdtT+J9eO_VQxqWDxGheg@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 7224EfXEZdMQZV_igTObt1jrINb3Kk-J
X-Proofpoint-ORIG-GUID: 7224EfXEZdMQZV_igTObt1jrINb3Kk-J
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 mlxscore=0
 bulkscore=0 malwarescore=0 clxscore=1015 adultscore=0 mlxlogscore=999
 lowpriorityscore=0 impostorscore=0 spamscore=0 priorityscore=1501
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501140105
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Cpwb9zYI;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
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

On Tue, Jan 14, 2025 at 12:02:31PM +0100, Dmitry Vyukov wrote:
> On Tue, 14 Jan 2025 at 11:43, Marco Elver <elver@google.com> wrote:
> > On Tue, 14 Jan 2025 at 06:35, Jiao, Joey <quic_jiangenj@quicinc.com> wrote:
> > >
> > > Hi,
> > >
> > > This patch series introduces new kcov unique modes:
> > > `KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique PC, EDGE,
> > > CMP information.
> > >
> > > Background
> > > ----------
> > >
> > > In the current kcov implementation, when `__sanitizer_cov_trace_pc` is hit,
> > > the instruction pointer (IP) is stored sequentially in an area. Userspace
> > > programs then read this area to record covered PCs and calculate covered
> > > edges.  However, recent syzkaller runs show that many syscalls likely have
> > > `pos > t->kcov_size`, leading to kcov overflow. To address this issue, we
> > > introduce new kcov unique modes.
> >
> > Overflow by how much? How much space is missing?
> >
> > > Solution Overview
> > > -----------------
> > >
> > > 1. [P 1] Introduce `KCOV_TRACE_UNIQ_PC` Mode:
> > >    - Export `KCOV_TRACE_UNIQ_PC` to userspace.
> > >    - Add `kcov_map` struct to manage memory during the KCOV lifecycle.
> > >      - `kcov_entry` struct as a hashtable entry containing unique PCs.
> > >      - Use hashtable buckets to link `kcov_entry`.
> > >      - Preallocate memory using genpool during KCOV initialization.
> > >      - Move `area` inside `kcov_map` for easier management.
> > >    - Use `jhash` for hash key calculation to support `KCOV_TRACE_UNIQ_CMP`
> > >      mode.
> > >
> > > 2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
> > >    - Save `prev_pc` to calculate edges with the current IP.
> > >    - Add unique edges to the hashmap.
> > >    - Use a lower 12-bit mask to make hash independent of module offsets.
> > >    - Distinguish areas for `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
> > >      modes using `offset` during mmap.
> > >    - Support enabling `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
> > >      together.
> > >
> > > 3. [P 4] Introduce `KCOV_TRACE_UNIQ_CMP` Mode:
> > >    - Shares the area with `KCOV_TRACE_UNIQ_PC`, making these modes
> > >      exclusive.
> > >
> > > 4. [P 5] Add Example Code Documentation:
> > >    - Provide examples for testing different modes:
> > >      - `KCOV_TRACE_PC`: `./kcov` or `./kcov 0`
> > >      - `KCOV_TRACE_CMP`: `./kcov 1`
> > >      - `KCOV_TRACE_UNIQ_PC`: `./kcov 2`
> > >      - `KCOV_TRACE_UNIQ_EDGE`: `./kcov 4`
> > >      - `KCOV_TRACE_UNIQ_PC|KCOV_TRACE_UNIQ_EDGE`: `./kcov 6`
> > >      - `KCOV_TRACE_UNIQ_CMP`: `./kcov 8`
> > >
> > > 5. [P 6-7] Disable KCOV Instrumentation:
> > >    - Disable instrumentation like genpool to prevent recursive calls.
> > >
> > > Caveats
> > > -------
> > >
> > > The userspace program has been tested on Qemu x86_64 and two real Android
> > > phones with different ARM64 chips. More syzkaller-compatible tests have
> > > been conducted. However, due to limited knowledge of other platforms,
> > > assistance from those with access to other systems is needed.
> > >
> > > Results and Analysis
> > > --------------------
> > >
> > > 1. KMEMLEAK Test on Qemu x86_64:
> > >    - No memory leaks found during the `kcov` program run.
> > >
> > > 2. KCSAN Test on Qemu x86_64:
> > >    - No KCSAN issues found during the `kcov` program run.
> > >
> > > 3. Existing Syzkaller on Qemu x86_64 and Real ARM64 Device:
> > >    - Syzkaller can fuzz, show coverage, and find bugs. Adjusting `procs`
> > >      and `vm mem` settings can avoid OOM issues caused by genpool in the
> > >      patches, so `procs:4 + vm:2GB` or `procs:4 + vm:2GB` are used for
> > >      Qemu x86_64.
> > >    - `procs:8` is kept on Real ARM64 Device with 12GB/16GB mem.
> > >
> > > 4. Modified Syzkaller to Support New KCOV Unique Modes:
> > >    - Syzkaller runs fine on both Qemu x86_64 and ARM64 real devices.
> > >      Limited `Cover overflows` and `Comps overflows` observed.
> > >
> > > 5. Modified Syzkaller + Upstream Kernel Without Patch Series:
> > >    - Not tested. The modified syzkaller will fall back to `KCOV_TRACE_PC`
> > >      or `KCOV_TRACE_CMP` if `ioctl` fails for Unique mode.
> > >
> > > Possible Further Enhancements
> > > -----------------------------
> > >
> > > 1. Test more cases and setups, including those in syzbot.
> > > 2. Ensure `hash_for_each_possible_rcu` is protected for reentrance
> > >    and atomicity.
> > > 3. Find a simpler and more efficient way to store unique coverage.
> > >
> > > Conclusion
> > > ----------
> > >
> > > These patches add new kcov unique modes to mitigate the kcov overflow
> > > issue, compatible with both existing and new syzkaller versions.
> >
> > Thanks for the analysis, it's clearer now.
> >
> > However, the new design you introduce here adds lots of complexity.
> > Answering the question of how much overflow is happening, might give
> > better clues if this is the best design or not. Because if the
> > overflow amount is relatively small, a better design (IMHO) might be
> > simply implementing a compression scheme, e.g. a simple delta
> > encoding.
> 
> Joey, do you have corresponding patches for syzkaller? I wonder how
> the integration looks like, in particular when/how these maps are
> cleared.
Uploaded in https://github.com/google/syzkaller/pull/5673

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z4Za/3Vz7t5NSbE6%40hu-jiangenj-sha.qualcomm.com.
