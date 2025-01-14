Return-Path: <kasan-dev+bncBCLMXXWM5YBBBYV7TG6AMGQETSYD2PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C47A10734
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 14:00:20 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id 5614622812f47-3eb8dc40be1sf1140134b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 05:00:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736859619; cv=pass;
        d=google.com; s=arc-20240605;
        b=KIsYKGLnCzCiyk8o3HqGCzkAbnnMaHSD7JfKMnaactFbPFYVnsTFLYek8J7SWsJcs0
         uSopzt8JuS34ykH2QP1CLku56RzILuLm8FQ1HtWSqq/0kM63ctF/v1SZQZ6E14Oe8UPu
         X3lTJ2my/kqt6VcLw7JSkz53Lkr6ED7d+APxONyArp+AU1DWvlKuRgQRqQgbht/+2Tt8
         08wosc9VJeNP3A4rafarS6krXrRVwn3on0js6EAdQ1WVhLd+nSTdgM6to1thNqDYZTn+
         uf4sWPhIi/vw2NqZmHi1kC7JohKs/hyORIFa/QJORpHPbZNXnmUNhnQk4914WiwuMPd1
         jqtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wti7Nbez10yUKRhT3hCsaTmewgOwb+oUYsJyPCwang4=;
        fh=mmEIaZtsS5Ss80LGkNqFR4w/tISbTLZWjUIKekFPDjI=;
        b=S2YF7CidFnG3IvZNzBiWWARUObNlVbtVhLxnr9l/cXuzAjCZtOR3Igkxj3iV2KGtHl
         /EdkKKjn/8nPnCD4/gp4PsGDg3Y1yBBaTdzxXmei9wCuDrvou9tDY2zezNodBn7lkjV7
         clnPLQPiEdyiQ72fU7YJHSrePULeBhfk7jLJdMGxu/9JCc2ub9H89WEIlpu56MusKDnn
         +JCkZFhUJ5054430ysJVb1jBWBfPwnaNlIfwzdnyvLAUlfeEc5TcCF00O1Y0dOQFx02I
         xQBVNobMJOhpKHWlj4qJgw7+gwCYHhWN2pOUomEimX9Uxidc44dM49FpPrKyPfEEIz2p
         x7LQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Wi8ITHJc;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736859619; x=1737464419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wti7Nbez10yUKRhT3hCsaTmewgOwb+oUYsJyPCwang4=;
        b=Qp2jYZ733NAF9FmzGXj0TCcZULsMtEHvarBhdDJFAoMPzfONPlAaVm3ajSo9eI7bTf
         zw17wvpHKJCOlzlpgPlGBJZ+1AvkdTaFC33eVBALxi6mAmLMQ7jxL6Xfi5rUaK0nrhtp
         3AK/x53TZE3sjK9NZ/mhtPboyZ4IOwsqnpfZwUmuJTmZm86Yhcud0BHT6OVOxAEYd+u1
         +NxvxaD0pXJxopqXeiinsjVNKpiMC6VPDp0yZ1NsAt3Mw3LbZ1MMkDVn3j/cFeByWi0d
         THHooHPIxsah/AAQSx4aXfEus9fWeZR5WGdznKiALPucADnaQLEOtnWgb/HLn92hoLiB
         loNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736859619; x=1737464419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wti7Nbez10yUKRhT3hCsaTmewgOwb+oUYsJyPCwang4=;
        b=RHjD/xQ+ZZoEY9twuxL45wObc3BfpECuuR272aLC24DAcOYZyCc4pVcgGKysFAnxYN
         BZKOIEkBf0yzJFhBccLLrwwIi0AbSWe6VknYhcq/rMm0yXTgoIHxM7puPp9M8pPrwGAj
         USVqqw0mtJPk3pghvFzRqeOgqigyc0ZKO7Et/vhagoLmU2No/K3BBFG2r1EDQKTnTMZv
         t8McqjBz/x4m+tbjzjJ2AannB5jqfSBn+KVmNsB+xAzSOPzlK/qGrdrtvBXPlqQDQWLU
         YBzGE9l9y0JhIW03xk0lz+paG/GJpXl5IgE6juYNBZN2QjC/4aL93x/76dxJrAWqPt5K
         VebQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbPbauWG9F32zWbRsHzzxMarqHACqj1QiuV7PaXHA9hDNDFcNpKWx/QwL1lUdnlrfn+u5mQg==@lfdr.de
X-Gm-Message-State: AOJu0Yy/gHYPToWNckNWxQWaxxCd5efnwY7TNL3Z0h/4jHUElZYR4cur
	3DUbHZaWeSVeJTiuZmsbFOyJFahjt3SA6SZ6rh77UB4bQIMp1Khe
X-Google-Smtp-Source: AGHT+IHe12Vf1sL0evrfP+9IYWiQE1+axCjM3rAJQHVigoInY5gNBb7U7jAqXsJSAy5ST7VqZzdRMw==
X-Received: by 2002:a05:6871:a115:b0:29e:7603:be65 with SMTP id 586e51a60fabf-2aa06549eafmr12209002fac.1.1736859619124;
        Tue, 14 Jan 2025 05:00:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:6daf:b0:2a0:39b:9275 with SMTP id
 586e51a60fabf-2aaad6e6bb8ls176829fac.2.-pod-prod-02-us; Tue, 14 Jan 2025
 05:00:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMTea6rk2CiOy9EMvlfos1nrRKjkI6ji2rUCW7fVqL3ThKlSYfguki4WcjCZYVj+DNruVWRdONoHI=@googlegroups.com
X-Received: by 2002:a05:6808:10c5:b0:3eb:6044:5a85 with SMTP id 5614622812f47-3ef2ec3e09bmr16446641b6e.20.1736859618113;
        Tue, 14 Jan 2025 05:00:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736859618; cv=none;
        d=google.com; s=arc-20240605;
        b=f4wSftEI86JCeY1TYPb5VsFpM4ES//ZmC/rri1n38wwgg2mLo08UK54SMpY6/NB02O
         e6envZLFEeH8sZG/SSytn2e0B3w3Qu66GJNlyla5GRqJtHV5eWbGZOx3nmiuq0ztf2JN
         NI7AGrT480PQeirSLIdxlB+NVxIQC1gi2n9H+kWw7grxz+a8vnh6y9kt67RvR++KFErO
         JWX8FClPXaDJnYj2IlJ1TDc+qnBjd8e5+RM8P1/JW+2Yv2f41X42k4Ehn3bgMx6wh+Yf
         ZnFw8Rn9XgUDoBV5m+sRkasks4XrTurV3a39IkR4zHEsPU9qAFczw4zo0fj0Ae2YB2dp
         3A8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pHaapRq9KPEM5wkA9qBkuMynp0US/1hBcSuicBhsMLQ=;
        fh=NNRuhSq2ttR3CNapzm+JSAR8spJ1MrdaGE2126q41Mg=;
        b=Ryx0cbUPwrqJ5ySnQj4ha9QQLDMmIY6MTHmn47BBubZvNuNLHk3TcX3vd35VlV2TOY
         u9hQj0OuAOHoILwGWbZr8OOY0epEfA6wHlOPOtdq5dtZRAkpc8PYuvPe7ZCG5TJx6W+c
         6o1VB02TiZ6+4sGilTOXflGR9pzxLx+EBuKIhyYwro2PWcoNBu+L/kATdEYmHE62uKMI
         7KYgYNwerbE3WB0SBcyL7VSQ122FkgcUYefyIXhBZG8J+6lrBYRsEZgduty1PagoKd2Z
         0zZEPlrG3ePoTjp/KVwxUDMGd/WISjoPpuJRkVx2P7EKyFLxuUqBlYfDyWbMufGKB/Si
         lM1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Wi8ITHJc;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f0379f4115si513603b6e.5.2025.01.14.05.00.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Jan 2025 05:00:18 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279873.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50ECvaDA029334;
	Tue, 14 Jan 2025 13:00:10 GMT
Received: from nasanppmta01.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445rcy0046-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 13:00:09 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA01.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50ED08Nx031490
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 13:00:08 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Tue, 14 Jan 2025 05:00:02 -0800
Date: Tue, 14 Jan 2025 18:29:58 +0530
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Marco Elver <elver@google.com>
CC: Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Andrew Morton
	<akpm@linux-foundation.org>,
        Dennis Zhou <dennis@kernel.org>, Tejun Heo
	<tj@kernel.org>,
        Christoph Lameter <cl@linux.com>,
        Catalin Marinas
	<catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-kernel@vger.kernel.org>, <workflows@vger.kernel.org>,
        <linux-doc@vger.kernel.org>, <linux-mm@kvack.org>,
        <linux-arm-kernel@lists.infradead.org>, <kernel@quicinc.com>
Subject: Re: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
Message-ID: <Z4ZfzoqhrJA0jeQI@hu-jiangenj-sha.qualcomm.com>
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
 <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 9bWMrs7yTO1d9x5OkhyqPh_zpoALy6eE
X-Proofpoint-ORIG-GUID: 9bWMrs7yTO1d9x5OkhyqPh_zpoALy6eE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 clxscore=1015 adultscore=0 phishscore=0 bulkscore=0
 impostorscore=0 malwarescore=0 priorityscore=1501 mlxlogscore=999
 mlxscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501140108
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Wi8ITHJc;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
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

On Tue, Jan 14, 2025 at 11:43:08AM +0100, Marco Elver wrote:
> On Tue, 14 Jan 2025 at 06:35, Jiao, Joey <quic_jiangenj@quicinc.com> wrote:
> >
> > Hi,
> >
> > This patch series introduces new kcov unique modes:
> > `KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique PC, EDGE,
> > CMP information.
> >
> > Background
> > ----------
> >
> > In the current kcov implementation, when `__sanitizer_cov_trace_pc` is hit,
> > the instruction pointer (IP) is stored sequentially in an area. Userspace
> > programs then read this area to record covered PCs and calculate covered
> > edges.  However, recent syzkaller runs show that many syscalls likely have
> > `pos > t->kcov_size`, leading to kcov overflow. To address this issue, we
> > introduce new kcov unique modes.
> 
> Overflow by how much? How much space is missing?
Ideally we should get the pos, but the test in syzkaller only counts how many 
times the overflow occurs. Actually I guess the pos is much bigger than cover 
size because originally we have 64KB cover size, the overflow happens; then now 
syzkaller set it to 1MB, but still 3535 times overflow for 
`ioctl$DMA_HEAP_IOCTL_ALLOC` syscall which has only 19 inputs. mmap syscall is 
also likely to overflow for 10873 times with 181 inputs in my case. Internally, 
I tried also 64MB cover size, but I still see the overflow case. Using 
syz-execprog together with -cover options shows many pcs are hit frequently, 
but disabling instrumentation for each these PC is less efficient and sometimes 
no lucky to fix the overflow problem.
I think the overflow happens more frequent on arm64 device as I found functions 
in header files hit frequently.
And I'm not able to access syzbot backend syz-manager data, perhaps qemu x86_64 
setup has more info.
> 
> > Solution Overview
> > -----------------
> >
> > 1. [P 1] Introduce `KCOV_TRACE_UNIQ_PC` Mode:
> >    - Export `KCOV_TRACE_UNIQ_PC` to userspace.
> >    - Add `kcov_map` struct to manage memory during the KCOV lifecycle.
> >      - `kcov_entry` struct as a hashtable entry containing unique PCs.
> >      - Use hashtable buckets to link `kcov_entry`.
> >      - Preallocate memory using genpool during KCOV initialization.
> >      - Move `area` inside `kcov_map` for easier management.
> >    - Use `jhash` for hash key calculation to support `KCOV_TRACE_UNIQ_CMP`
> >      mode.
> >
> > 2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
> >    - Save `prev_pc` to calculate edges with the current IP.
> >    - Add unique edges to the hashmap.
> >    - Use a lower 12-bit mask to make hash independent of module offsets.
> >    - Distinguish areas for `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
> >      modes using `offset` during mmap.
> >    - Support enabling `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
> >      together.
> >
> > 3. [P 4] Introduce `KCOV_TRACE_UNIQ_CMP` Mode:
> >    - Shares the area with `KCOV_TRACE_UNIQ_PC`, making these modes
> >      exclusive.
> >
> > 4. [P 5] Add Example Code Documentation:
> >    - Provide examples for testing different modes:
> >      - `KCOV_TRACE_PC`: `./kcov` or `./kcov 0`
> >      - `KCOV_TRACE_CMP`: `./kcov 1`
> >      - `KCOV_TRACE_UNIQ_PC`: `./kcov 2`
> >      - `KCOV_TRACE_UNIQ_EDGE`: `./kcov 4`
> >      - `KCOV_TRACE_UNIQ_PC|KCOV_TRACE_UNIQ_EDGE`: `./kcov 6`
> >      - `KCOV_TRACE_UNIQ_CMP`: `./kcov 8`
> >
> > 5. [P 6-7] Disable KCOV Instrumentation:
> >    - Disable instrumentation like genpool to prevent recursive calls.
> >
> > Caveats
> > -------
> >
> > The userspace program has been tested on Qemu x86_64 and two real Android
> > phones with different ARM64 chips. More syzkaller-compatible tests have
> > been conducted. However, due to limited knowledge of other platforms,
> > assistance from those with access to other systems is needed.
> >
> > Results and Analysis
> > --------------------
> >
> > 1. KMEMLEAK Test on Qemu x86_64:
> >    - No memory leaks found during the `kcov` program run.
> >
> > 2. KCSAN Test on Qemu x86_64:
> >    - No KCSAN issues found during the `kcov` program run.
> >
> > 3. Existing Syzkaller on Qemu x86_64 and Real ARM64 Device:
> >    - Syzkaller can fuzz, show coverage, and find bugs. Adjusting `procs`
> >      and `vm mem` settings can avoid OOM issues caused by genpool in the
> >      patches, so `procs:4 + vm:2GB` or `procs:4 + vm:2GB` are used for
> >      Qemu x86_64.
> >    - `procs:8` is kept on Real ARM64 Device with 12GB/16GB mem.
> >
> > 4. Modified Syzkaller to Support New KCOV Unique Modes:
> >    - Syzkaller runs fine on both Qemu x86_64 and ARM64 real devices.
> >      Limited `Cover overflows` and `Comps overflows` observed.
> >
> > 5. Modified Syzkaller + Upstream Kernel Without Patch Series:
> >    - Not tested. The modified syzkaller will fall back to `KCOV_TRACE_PC`
> >      or `KCOV_TRACE_CMP` if `ioctl` fails for Unique mode.
> >
> > Possible Further Enhancements
> > -----------------------------
> >
> > 1. Test more cases and setups, including those in syzbot.
> > 2. Ensure `hash_for_each_possible_rcu` is protected for reentrance
> >    and atomicity.
> > 3. Find a simpler and more efficient way to store unique coverage.
> >
> > Conclusion
> > ----------
> >
> > These patches add new kcov unique modes to mitigate the kcov overflow
> > issue, compatible with both existing and new syzkaller versions.
> 
> Thanks for the analysis, it's clearer now.
> 
> However, the new design you introduce here adds lots of complexity.
> Answering the question of how much overflow is happening, might give
> better clues if this is the best design or not. Because if the
> overflow amount is relatively small, a better design (IMHO) might be
> simply implementing a compression scheme, e.g. a simple delta
> encoding.
I tried many ways to store the uniq info, like bitmap, segment bitmap, 
customized allocator + allocation index, also considering rhashmap, but perhaps 
hashmap (maybe rhashmap) is better.
I also tried a full bitmap to record all PCs from all threads which shows that
syzkaller can't find the new coverage while the full bitmap recorded it. If I 
replay the syzkaller log (or prog), kernel GCOV can also show these 
functions/lines are hit (not because flaky or interrupt) but syzkaller coverage 
doesn't have that data, which can be another proof of the kcov overflow.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z4ZfzoqhrJA0jeQI%40hu-jiangenj-sha.qualcomm.com.
