Return-Path: <kasan-dev+bncBCLMXXWM5YBBBPHPS66AMGQEBQT2GVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A14EA1005D
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:35:59 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2161d5b3eb5sf93294505ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:35:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736832957; cv=pass;
        d=google.com; s=arc-20240605;
        b=lDRLGlUHZZBZC3jxzQtHw4jtwspFBAK8CaPQzPqAsabAg64Aue1YmfWLKk1srAi5Iy
         O1NV37TxrS865JBZUOpz4GOu59BuXh8SBQ/oX1ui9iR0mLA+do1NCmTKPa09+APqb/jQ
         d2ZMB8tDq40VMBQGNSDLiYGxHokaMQGMmzMbiAaz695ZPGoraBeT9ZnEqNuBOrETkB2i
         mvKxKKc0xFxLkMrfPDE9+WV9JqBchZGYdSBvB3FymZaBOowzIqAFdZ5cM7w0zwlLYR09
         /gphbF+4vx1tdc77JHU45cv69c/9tIC7qXsBnKCoGZJKbtK0LntUFYk2XjmyLRS5B6pj
         zwxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=i7h6uQxSeFl3y/69o96fuTOQ+iGgseDdEzeraacvCgM=;
        fh=2yOsU6f/sw+/dYSTPeSrJnztqkzcoIBUf1UgHsuEanI=;
        b=iyJ0hMY4qwDU3wzsFWO8v3LofDNyD9J0q4vwe6IEyw5EZtzxu2PQme7Ra0oN+r41LH
         NNBBU8gZIyuaVKSjkmK1AjeD5fqtIntx8nWqu6eBkFfFL4fkpqWPj/uRbMcl90PiCIJJ
         1EN9aalQtVf0ntPySpAFbVdpwQrJFvpqaNU1O8aylIr+IjCGDm6pZpRQFT7+imvYedLt
         rHlKzVaH8FOrTCD20j943UC+qVN4MmAQlniUgMT8EUySnSb+RJ+xkG33+L6Kr2l2x0cm
         DlsaczeQuX7rIr7R0N4psckcaJONfNzNbCZjiF8ZNA1eN7j968jYVPwaTYOlAAPR7UTk
         Sbyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nyGQ2yT1;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736832957; x=1737437757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=i7h6uQxSeFl3y/69o96fuTOQ+iGgseDdEzeraacvCgM=;
        b=ausQWHZTu+Rh+HCjg1bRuaUf0QKjvwdLMfdPCXnQI2HfHCAR13vYWwKZtHSdPEXokp
         vjF+n86nXGmBIYH3yr7xmVbCmezbZZ/dUJL/FfP6q8NfoUo6GnY9pV0t9bopaMKjTYad
         dXxCjPJS5UW2hfpO0Muo8hvGrH9iSjgsyxZbe40IwjtK001JsmHQlIdxohLjwaNCks8O
         7ZWPYFkAQkj0HzRIbolcMeaoG+oI4oToyVF8gYBej8UbVxMDQKEG/hh0BJSE+MIE56hO
         u7XKmmr30S5Yvu96aJxs8B+687XPAJSG1WLSKOMQ6QvRsNyqkgUxGn/e4ZgHDblQN8qs
         qeiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736832957; x=1737437757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i7h6uQxSeFl3y/69o96fuTOQ+iGgseDdEzeraacvCgM=;
        b=nvJhkyeOs/o4VmBxFCJMJsJYurIVzsYZhBrjeUvOjPIHwj0f+TutdnXuqLIFzwSYiE
         STWDjRDO/FI2wE7FXlwRmC2rj3lPuLg0G63K9o7BeZ2Je9SeZWPjAZeEStvwiEJR85cq
         UuhWSJ069v6FaGzyXULL5U4ZLDuYLDc11PbKn41U/zdLEFCzj5QSZjZzJKIf1QDLDc8Z
         RVF27p+pk7jwKVU++FxTDW97mHXIUJi/BZHUvyu1lCH0WwKuHja9XPbgZkgVXJ5tAiRl
         4TONQGY3K8QY1mINGRepyaLO+YA8QkIfrT3G8OYjR8N8In9gpyIa6ij1Ispzq4thKyCV
         Tl1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9IwvkguDi4GvGn9R+C0p60mrdLWPO+LMskoTle96x6aPxz0BMOp3pZPi9Dsenm5kb+X2Flg==@lfdr.de
X-Gm-Message-State: AOJu0YzaqQVvgFWcYsk97PdeGTANCYoYXpjV8CF1Ui9k9wc7b/dxdc4R
	fdGcn7avH2KWqv17MG1Rg93iBYEYL8dQ58hcIct4bT5D5qzSzUvj
X-Google-Smtp-Source: AGHT+IGIItQpVqbIcp8oESDhC1E4KVJZoMftGY2s/SvkkemrJJfsOI88ByC29wX4KULObBz7uU5Hug==
X-Received: by 2002:a05:6a00:e8e:b0:725:460e:6bc0 with SMTP id d2e1a72fcca58-72d21df408dmr33825957b3a.0.1736832957123;
        Mon, 13 Jan 2025 21:35:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a85:b0:725:c875:26a3 with SMTP id
 d2e1a72fcca58-72d2fb5574dls4896982b3a.0.-pod-prod-04-us; Mon, 13 Jan 2025
 21:35:56 -0800 (PST)
X-Received: by 2002:a05:6a20:9193:b0:1e1:b883:3c56 with SMTP id adf61e73a8af0-1e88cfd2184mr40032031637.23.1736832955760;
        Mon, 13 Jan 2025 21:35:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736832955; cv=none;
        d=google.com; s=arc-20240605;
        b=fV1IvQKoZXb+6iYmJo9o5DQe6nX9HuaiNPG59mvlthT1daSLBpQ9vZYbyMAm1A55RN
         BlDmLp4pkrX68a+ihKNGVKQLSnqAIsyFpuYf/KrZtkKGWOoLSnOss2AHKuonpg5PMVG2
         wLH82Z4zBp1T52avWkv/0/Khi8GTeIp++jKc7xNuhZmDqGMZxrd5r56nuzkYZ4ylrJ8G
         1rztrJPlgc5u2BiSaX0TQrtLqwMR8LHFoGZhBo2JgAmj5FNK64TXIS6CbwOSb4Sxb4HG
         iSGQYA0/FnUjVPZ8FWcDz0biY1H7NGTr40OWsxp35dg0fDLsHZ5nX4EBChAduRih0Lhe
         oTYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=fGXqRSIT8iEokM5NpyWSUnu+CJKUU08IeXrkQyvtOR8=;
        fh=IrFMU56A0U8g6WEnzuhC3mVEK/1VXa8G0j09OJ6Nq3U=;
        b=Ou24++K9ngnfs9il3nU6Qokz5wQRGHfyXLm1OA/75ql1cGGN+er/FwpZVnKTUBQEsV
         7zSK7wGBA0a2WITBIj1vtJ6W91pEB8d2zq/0Mot6H4KExcTUQqXtaAOkbjccT9kFM2Qc
         Rx3FCbhThP8K9FC42XnaXjBYivhETFahak5zuusiD0oF4glR4pU+r9+OfY+mYjDVXjZY
         zrjkNrdHOS6xeITItQ6a2aHpk+hTDTmmy614/0cJUWJXnlhE7N22Tnej1uJZ98Y367vW
         o4pxuLiM0CpzZMjDysB2a/bqXXxj36Zd0B1AT+IYJ9ncu+4LN71/7qPEIGyIOAnXNNvj
         egQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nyGQ2yT1;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72d33f4080csi438536b3a.2.2025.01.13.21.35.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:35:55 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50DJLZn7002853;
	Tue, 14 Jan 2025 05:35:50 GMT
Received: from nasanppmta02.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 4458ww943r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:35:49 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA02.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5ZnsK019741
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:35:49 GMT
Received: from la-sh002-lnx.ap.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:35:42 -0800
From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Subject: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
Date: Tue, 14 Jan 2025 13:34:30 +0800
Message-ID: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAGf3hWcC/6tWKk4tykwtVrJSqFYqSi3LLM7MzwNyDHUUlJIzE
 vPSU3UzU4B8JSMDI1MDQ0MT3ezk/DJdS9Pk1JTU5FQTM1MTJaDSgqLUtMwKsDHRsbW1AKxXN/F
 WAAAA
X-Change-ID: 20250114-kcov-95cedece4654
To: Dmitry Vyukov <dvyukov@google.com>,
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
        Will Deacon <will@kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
        <workflows@vger.kernel.org>, <linux-doc@vger.kernel.org>,
        <linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
        <kernel@quicinc.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=ed25519-sha256; t=1736832941; l=4982;
 i=quic_jiangenj@quicinc.com; s=20250114; h=from:subject:message-id;
 bh=KF+hdYTmC0kaoWHPMMW6dtsTZWgnKqQ/QLSr+4P37p8=;
 b=nAwxJxgoU1Q8LXtKwFqlrO6wF8qseE8RRM3mpTnNkDOJW0S2nAezeabZxQjA4mCxTlAmyGo8a
 DfF4x/4tIOJActPFgWO0910pfQVzG+JdHbQjV5X7EQQJQL55VWc6VYf
X-Developer-Key: i=quic_jiangenj@quicinc.com; a=ed25519;
 pk=JPzmfEvx11SW1Q1qtMhFcAx46KP1Ui36jcetDgbev28=
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: W6wLUaQRtXns5-yBsMSVi63JGdBpU7pd
X-Proofpoint-ORIG-GUID: W6wLUaQRtXns5-yBsMSVi63JGdBpU7pd
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 spamscore=0 mlxlogscore=864 mlxscore=0 clxscore=1015 impostorscore=0
 malwarescore=0 adultscore=0 bulkscore=0 phishscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501140044
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=nyGQ2yT1;       spf=pass
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

Hi,

This patch series introduces new kcov unique modes: 
`KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique PC, EDGE,
CMP information.

Background
----------

In the current kcov implementation, when `__sanitizer_cov_trace_pc` is hit,
the instruction pointer (IP) is stored sequentially in an area. Userspace 
programs then read this area to record covered PCs and calculate covered
edges.  However, recent syzkaller runs show that many syscalls likely have
`pos > t->kcov_size`, leading to kcov overflow. To address this issue, we 
introduce new kcov unique modes.

Solution Overview
-----------------

1. [P 1] Introduce `KCOV_TRACE_UNIQ_PC` Mode:
   - Export `KCOV_TRACE_UNIQ_PC` to userspace.
   - Add `kcov_map` struct to manage memory during the KCOV lifecycle.
     - `kcov_entry` struct as a hashtable entry containing unique PCs.
     - Use hashtable buckets to link `kcov_entry`.
     - Preallocate memory using genpool during KCOV initialization.
     - Move `area` inside `kcov_map` for easier management.
   - Use `jhash` for hash key calculation to support `KCOV_TRACE_UNIQ_CMP` 
     mode.

2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
   - Save `prev_pc` to calculate edges with the current IP.
   - Add unique edges to the hashmap.
   - Use a lower 12-bit mask to make hash independent of module offsets.
   - Distinguish areas for `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
     modes using `offset` during mmap.
   - Support enabling `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
     together.

3. [P 4] Introduce `KCOV_TRACE_UNIQ_CMP` Mode:
   - Shares the area with `KCOV_TRACE_UNIQ_PC`, making these modes
     exclusive.

4. [P 5] Add Example Code Documentation:
   - Provide examples for testing different modes:
     - `KCOV_TRACE_PC`: `./kcov` or `./kcov 0`
     - `KCOV_TRACE_CMP`: `./kcov 1`
     - `KCOV_TRACE_UNIQ_PC`: `./kcov 2`
     - `KCOV_TRACE_UNIQ_EDGE`: `./kcov 4`
     - `KCOV_TRACE_UNIQ_PC|KCOV_TRACE_UNIQ_EDGE`: `./kcov 6`
     - `KCOV_TRACE_UNIQ_CMP`: `./kcov 8`

5. [P 6-7] Disable KCOV Instrumentation:
   - Disable instrumentation like genpool to prevent recursive calls.

Caveats
-------

The userspace program has been tested on Qemu x86_64 and two real Android
phones with different ARM64 chips. More syzkaller-compatible tests have
been conducted. However, due to limited knowledge of other platforms, 
assistance from those with access to other systems is needed.

Results and Analysis
--------------------

1. KMEMLEAK Test on Qemu x86_64:
   - No memory leaks found during the `kcov` program run.

2. KCSAN Test on Qemu x86_64:
   - No KCSAN issues found during the `kcov` program run.

3. Existing Syzkaller on Qemu x86_64 and Real ARM64 Device:
   - Syzkaller can fuzz, show coverage, and find bugs. Adjusting `procs`
     and `vm mem` settings can avoid OOM issues caused by genpool in the
     patches, so `procs:4 + vm:2GB` or `procs:4 + vm:2GB` are used for
     Qemu x86_64.
   - `procs:8` is kept on Real ARM64 Device with 12GB/16GB mem.

4. Modified Syzkaller to Support New KCOV Unique Modes:
   - Syzkaller runs fine on both Qemu x86_64 and ARM64 real devices.
     Limited `Cover overflows` and `Comps overflows` observed.

5. Modified Syzkaller + Upstream Kernel Without Patch Series:
   - Not tested. The modified syzkaller will fall back to `KCOV_TRACE_PC`
     or `KCOV_TRACE_CMP` if `ioctl` fails for Unique mode.

Possible Further Enhancements
-----------------------------

1. Test more cases and setups, including those in syzbot.
2. Ensure `hash_for_each_possible_rcu` is protected for reentrance
   and atomicity.
3. Find a simpler and more efficient way to store unique coverage.

Conclusion
----------

These patches add new kcov unique modes to mitigate the kcov overflow
issue, compatible with both existing and new syzkaller versions.

Thanks,
Joey Jiao

---
Jiao, Joey (7):
      kcov: introduce new kcov KCOV_TRACE_UNIQ_PC mode
      kcov: introduce new kcov KCOV_TRACE_UNIQ_EDGE mode
      kcov: allow using KCOV_TRACE_UNIQ_[PC|EDGE] modes together
      kcov: introduce new kcov KCOV_TRACE_UNIQ_CMP mode
      kcov: add the new KCOV uniq modes example code
      kcov: disable instrumentation for genalloc and bitmap
      arm64: disable kcov instrument in header files

 Documentation/dev-tools/kcov.rst | 243 ++++++++++++++--------------
 arch/arm64/include/asm/percpu.h  |   2 +-
 arch/arm64/include/asm/preempt.h |   2 +-
 include/linux/kcov.h             |  10 +-
 include/uapi/linux/kcov.h        |   6 +
 kernel/kcov.c                    | 333 +++++++++++++++++++++++++++++++++------
 lib/Makefile                     |   2 +
 7 files changed, 423 insertions(+), 175 deletions(-)
---
base-commit: 9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe
change-id: 20250114-kcov-95cedece4654

Best regards,
-- 
<Jiao, Joey> <quic_jiangenj@quicinc.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114-kcov-v1-0-004294b931a2%40quicinc.com.
