Return-Path: <kasan-dev+bncBDOJT7EVXMDBBJEZ2SXAMGQERSMV5UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5C2285C5D4
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:33:42 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-29976f92420sf2675202a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 12:33:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708461221; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1ttXlpwBXm+bEjs5/REJ6AFxWgncVuZWmMmAuaG72OXft7LRvCdFnEbCQIIRioJYn
         Ea9LwpRr1eMadW3FGyFXIWNAOiF57B7pA4fO4Qcf2uAcpiaOFqIrVeZLyMiMz6rl9bkw
         zlxp4T1hYzSE5n9lfiNb5NXtmHSMTwgWnbbEHuTbJw9RJ6Ymzd+SG0UMpJ2n6ThmQIgu
         Dudl5Q6PVycqYNz/dgqzQxcxQ0IQyHw2dmVA0GBy8R0GrKqlychiiDUFa+cDkYNb2p8L
         RPAw245tbR0UA3vNMU/ZZYsmAkya8ieGbipjMxMxUCE9ZEHvNnVJdVgR5ttXG3vivN9M
         ebDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=8xxa2d6hURfmTzwixEzHalOb99PHtJm+ExV75njgz1U=;
        fh=riBf+aWaS+c0nWeymqL+BMQ3o1RdpvTyk+p8n/SSy8c=;
        b=ZEjH0AGFmQCF/DOhgk9zhpldfK89o9dEEvEqO1c3eIT18Se7cDKdu3kVWGP4f8SON6
         4sxx0qTv1VXikMQUX0CmfdczHYfQmCFgMEaQXV2WuCAdlvMBTjafhdWlQGopN1tvMhgY
         QIoFEfQb5D3YgwRu4Hlanah1zMdaSoFxL80UNbxhTEwX5XYJrGTOQiUnZZu1oaSfpzNc
         JlGdUnuxqrXWKAGkbM7U2ZL40Ieb71Apu8RHUG0fsNeqm5RLLknzd+tmgkIAuMwKvZFG
         +RYxUd55t7ijtJx8ghT/jLTIuxiCtJbF4gR7wBt8X5+YXPUoUD3h0lrWEgiySPMjS275
         fzHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=TCM9V8XE;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708461221; x=1709066021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:date:subject:cc:to:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8xxa2d6hURfmTzwixEzHalOb99PHtJm+ExV75njgz1U=;
        b=BDb1obfKj/zLvSQIPbvjaZFBDxeEIuzEf5quJVnPW0VIlOqH8kqKsgWCou4JvzQljZ
         A8C963ph5UhVPbBHQgSgxmEbvpaKmDdXsZ4YyFNlZYo3xzafN5RtoJ4UlH3YC6QYMq89
         dS6avUdV6rQurECqXF7duvW6nx62m1lp/jz2ozrKXV6GADHw/HHDrKGeewf6sKYiy/eN
         hX6BAYlIKGxS+D7kyeQPmWfKA2vYvSwpqzYPTxV7JIo+LyIaKNRnKFm8cbebPApGXhHj
         +IYic4vzhlz8O0uX9LuJmiVEbBrOhZH1t7CMcFmCWPoAoZRhbZbJxvQxVF6wM0YTsQdO
         DB+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708461221; x=1709066021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id:date
         :subject:cc:to:from:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8xxa2d6hURfmTzwixEzHalOb99PHtJm+ExV75njgz1U=;
        b=fzR51EsroMg+2HtyJjZkP/iIjgtkzvAJZXvqudKZnblxkLq/JA1KQtEV1R8A5RZKxX
         KnvCdc5vrac5KW9CD6axAmbalWvdJu/Mv24Pz2G52dXSoQixTvEIu0JhQtdvJ9cn8a1V
         Kyvbo5fuon2f/vLWaQZTW6IR6qNedNK+UMMszWAeq91tC+ZArE1SUGUvHwXAIj3pktD8
         FJjhYi9xEo2eUlYy4qHCYo8Uu7nli/dXZCa5Ena9vJ4qB6tl98mbrv+wG0wIsiSk/9u9
         JOVPRFcWbDeeX935amfDObcraVigyZOuDcNZOUgghzRJoSsXiZw4wr4f9spwO0bjkDje
         5QFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXqGNMNpqNoSuxTGaik3WjZO2Sp5WJor/96mzv4DTNNa7HNcJ/ys4FIiO9wsFsmsobrLdLCu82jjH9KFOQSFgzMg5oewI9ApA==
X-Gm-Message-State: AOJu0YwIjcGyakRJU9xbuwvzVg631ja8INEmrwaRr5JbUcrt7SN0Q0lM
	6tMrCP97bS5ELj4WeCv4m2a4FR8zllL2aTIcw2SKKqojQykNTR/n
X-Google-Smtp-Source: AGHT+IHNFmM/tX7q7zyRe31Bv6YGnTTr33JwxahDDrNPDByWOvbt8x8jjozT2AcAyj++7GjHBzLjuA==
X-Received: by 2002:a17:90a:ac01:b0:296:530:996e with SMTP id o1-20020a17090aac0100b002960530996emr21371023pjq.20.1708461221126;
        Tue, 20 Feb 2024 12:33:41 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:dc0a:b0:299:54a4:4a31 with SMTP id
 i10-20020a17090adc0a00b0029954a44a31ls530755pjv.2.-pod-prod-00-us; Tue, 20
 Feb 2024 12:33:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVX9TX1/h3R1/C+VMQQ/p3FL+M1a8NFfaHGKD9kGqtaGzsSZGL5abgKCeahPiGDBrOmoLyBt3IQnAo4aVyKVBHcA7r4px8F6WefwQ==
X-Received: by 2002:a17:90a:df93:b0:299:3bff:4e55 with SMTP id p19-20020a17090adf9300b002993bff4e55mr16067505pjv.20.1708461219288;
        Tue, 20 Feb 2024 12:33:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708461219; cv=none;
        d=google.com; s=arc-20160816;
        b=Aos7pGUPrNiWNhMPZ4kXnBSGcDz7J5RQR02Il+BnzMsoIv0ANmGg8K7yosmFqJrXRK
         gd7sVn/G4KZuz/is5+njdo83r4rTJdjfwPLlvEh5kkkJEV08cr6pmL57fiX7VR+CNszX
         dmfyNkR55CPOqDKku3vERJ2yRQOH8szRa3IcCMAO5HWflMi/aEcn3D5ryA/ZZtx5kg+H
         UIjbf2n0lVT1dQcyhRjH/OAYevOtDflCK0GrD7ucXGVmumAxMcxe50ctJU+EnI4GvD+j
         h3v7SaL2QrUNZ2R/qqLPhiHf22OWGiHPolS2jMukxSiOK2UiU2OXz12kfo5vHe8aTtqM
         ArgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=apTduRvBWpkBsoALNYmwCiUzyclrqb5Qqfle8axRCBQ=;
        fh=FkeYy9VFhDbdZf7Wr1j+kC7C7CaCFd0E6M33TF/KxqU=;
        b=wsOFg6ZH/SYEORL1EOQFMVFype1UUpR+Rn92tsxt6qdseKomKYk0GceazNvLSNI/91
         F4qPiaroTt990saJNGdNABPYMKthivbhi8Yg9KruPW5rLyUd/Sb/k9pC8kMvhTLTzv6j
         un0B5V4prJc5CjVHO+aV3hypWIBmg/LgkbTtoDmsrKqawPBHF7at1n+jWhghd7OmD18t
         QtIharbPfYaltMmYQMHHuD/GI1yutC+Ris117OoacGrwp09OZeCcsc36SrauJQ9GIA5K
         vNUdBLd/0hksYJNbmsUdLqLOmf67P8s4N+T68YaQiXH4G05U5pf8iJzLIumqKOXQmWhX
         TfqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=TCM9V8XE;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0b-00823401.pphosted.com (mx0b-00823401.pphosted.com. [148.163.152.46])
        by gmr-mx.google.com with ESMTPS id o20-20020a17090ad25400b0029986d3c1e7si2305pjw.1.2024.02.20.12.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 12:33:39 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) client-ip=148.163.152.46;
Received: from pps.filterd (m0355092.ppops.net [127.0.0.1])
	by mx0b-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41KJHdhj012449;
	Tue, 20 Feb 2024 20:33:15 GMT
Received: from va32lpfpp02.lenovo.com ([104.232.228.22])
	by mx0b-00823401.pphosted.com (PPS) with ESMTPS id 3wd243r5x8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 20 Feb 2024 20:33:15 +0000 (GMT)
Received: from ilclmmrp01.lenovo.com (ilclmmrp01.mot.com [100.65.83.165])
	(using TLSv1.2 with cipher ADH-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by va32lpfpp02.lenovo.com (Postfix) with ESMTPS id 4TfWLy335pz50TkT;
	Tue, 20 Feb 2024 20:33:14 +0000 (UTC)
Received: from ilclasset01.mot.com (ilclasset01.mot.com [100.64.7.105])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: mbland)
	by ilclmmrp01.lenovo.com (Postfix) with ESMTPSA id 4TfWLy0zLHz3n3fr;
	Tue, 20 Feb 2024 20:33:14 +0000 (UTC)
From: Maxwell Bland <mbland@motorola.com>
To: linux-arm-kernel@lists.infradead.org
Cc: gregkh@linuxfoundation.org, agordeev@linux.ibm.com,
        akpm@linux-foundation.org, andreyknvl@gmail.com, andrii@kernel.org,
        aneesh.kumar@kernel.org, aou@eecs.berkeley.edu, ardb@kernel.org,
        arnd@arndb.de, ast@kernel.org, borntraeger@linux.ibm.com,
        bpf@vger.kernel.org, brauner@kernel.org, catalin.marinas@arm.com,
        christophe.leroy@csgroup.eu, cl@linux.com, daniel@iogearbox.net,
        dave.hansen@linux.intel.com, david@redhat.com, dennis@kernel.org,
        dvyukov@google.com, glider@google.com, gor@linux.ibm.com,
        guoren@kernel.org, haoluo@google.com, hca@linux.ibm.com,
        hch@infradead.org, john.fastabend@gmail.com, jolsa@kernel.org,
        kasan-dev@googlegroups.com, kpsingh@kernel.org,
        linux-arch@vger.kernel.org, linux@armlinux.org.uk,
        linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        lstoakes@gmail.com, mark.rutland@arm.com, martin.lau@linux.dev,
        meted@linux.ibm.com, michael.christie@oracle.com, mjguzik@gmail.com,
        mpe@ellerman.id.au, mst@redhat.com, muchun.song@linux.dev,
        naveen.n.rao@linux.ibm.com, npiggin@gmail.com, palmer@dabbelt.com,
        paul.walmsley@sifive.com, quic_nprakash@quicinc.com,
        quic_pkondeti@quicinc.com, rick.p.edgecombe@intel.com,
        ryabinin.a.a@gmail.com, ryan.roberts@arm.com, samitolvanen@google.com,
        sdf@google.com, song@kernel.org, surenb@google.com,
        svens@linux.ibm.com, tj@kernel.org, urezki@gmail.com,
        vincenzo.frascino@arm.com, will@kernel.org, wuqiang.matt@bytedance.com,
        yonghong.song@linux.dev, zlim.lnx@gmail.com, mbland@motorola.com,
        awheeler@motorola.com
Subject: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd configuration
Date: Tue, 20 Feb 2024 14:32:52 -0600
Message-Id: <20240220203256.31153-1-mbland@motorola.com>
X-Mailer: git-send-email 2.17.1
X-Proofpoint-ORIG-GUID: Dixf0RDdq0FDklrUtANPOUW76nLLA88z
X-Proofpoint-GUID: Dixf0RDdq0FDklrUtANPOUW76nLLA88z
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=550 mlxscore=0
 bulkscore=0 phishscore=0 adultscore=0 clxscore=1011 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402200146
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=TCM9V8XE;       spf=pass
 (google.com: domain of mbland@motorola.com designates 148.163.152.46 as
 permitted sender) smtp.mailfrom=mbland@motorola.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=motorola.com
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

Reworks ARM's virtual memory allocation infrastructure to support
dynamic enforcement of page middle directory PXNTable restrictions
rather than only during the initial memory mapping. Runtime enforcement
of this bit prevents write-then-execute attacks, where malicious code is
staged in vmalloc'd data regions, and later the page table is changed to
make this code executable.

Previously the entire region from VMALLOC_START to VMALLOC_END was
vulnerable, but now the vulnerable region is restricted to the 2GB
reserved by module_alloc, a region which is generally read-only and more
difficult to inject staging code into, e.g., data must pass the BPF
verifier. These changes also set the stage for other systems, such as
KVM-level (EL2) changes to mark page tables immutable and code page
verification changes, forging a path toward complete mitigation of
kernel exploits on ARM.

Implementing this required minimal changes to the generic vmalloc
interface in the kernel to allow architecture overrides of some vmalloc
wrapper functions, refactoring vmalloc calls to use a standard interface
in the generic kernel, and passing the address parameter already passed
into PTE allocation to the pte_allocate child function call.

The new arm64 vmalloc wrapper functions ensure vmalloc data is not
allocated into the region reserved for module_alloc. arm64 BPF and
kprobe code also see a two-line-change ensuring their allocations abide
by the segmentation of code from data. Finally, arm64's pmd_populate
function is modified to set the PXNTable bit appropriately.

Signed-off-by: Maxwell Bland <mbland@motorola.com>

---

After Mark Rutland's feedback last week on my more minimal patch, see

<CAP5Mv+ydhk=Ob4b40ZahGMgT-5+-VEHxtmA=-LkJiEOOU+K6hw@mail.gmail.com>

I adopted a more sweeping and more correct overhaul of ARM's virtual
memory allocation infrastructure to support these changes. This patch
guarantees our ability to write future systems with a strong and
accessible distinction between code and data at the page allocation
layer, bolstering the guarantees of complementary contributions, i.e.
W^X and kCFI.

The current patch minimally reduces available vmalloc space, removing
the 2GB that should be reserved for code allocations regardless, and I
feel really benefits the kernel by making several memory allocation
interfaces more uniform, and providing hooks for non-ARM architectures
to follow suit.

I have done some minimal runtime testing using Torvald's test-tlb script
on a QEMU VM, but maybe more extensive benchmarking is needed?

Size: Before Patch -> After Patch
4k: 4.09ns  4.15ns  4.41ns  4.43ns -> 3.68ns  3.73ns  3.67ns  3.73ns 
8k: 4.22ns  4.19ns  4.30ns  4.15ns -> 3.99ns  3.89ns  4.12ns  4.04ns 
16k: 3.97ns  4.31ns  4.30ns  4.28ns -> 4.03ns  3.98ns  4.06ns  4.06ns 
32k: 3.82ns  4.51ns  4.25ns  4.31ns -> 3.99ns  4.09ns  4.07ns  5.17ns 
64k: 4.50ns  5.59ns  6.13ns  6.14ns -> 4.23ns  4.26ns  5.91ns  5.93ns 
128k: 5.06ns  4.47ns  6.75ns  6.69ns -> 4.47ns  4.71ns  6.54ns  6.44ns 
256k: 4.83ns  4.43ns  6.62ns  6.21ns -> 4.39ns  4.62ns  6.71ns  6.65ns 
512k: 4.45ns  4.75ns  6.19ns  6.65ns -> 4.86ns  5.26ns  7.77ns  6.68ns 
1M: 4.72ns  4.73ns  6.74ns  6.47ns -> 4.29ns  4.45ns  6.87ns  6.59ns 
2M: 4.66ns  4.86ns  14.49ns  15.00ns -> 4.53ns  4.57ns  15.91ns  15.90ns 
4M: 4.85ns  4.95ns  15.90ns  15.98ns -> 4.48ns  4.74ns  17.27ns  17.36ns 
6M: 4.94ns  5.03ns  17.19ns  17.31ns -> 4.70ns  4.93ns  18.02ns  18.23ns 
8M: 5.05ns  5.18ns  17.49ns  17.64ns -> 4.96ns  5.07ns  18.84ns  18.72ns 
16M: 5.55ns  5.79ns  20.99ns  23.70ns -> 5.46ns  5.72ns  22.76ns  26.51ns
32M: 8.54ns  9.06ns  124.61ns 125.07ns -> 8.43ns  8.59ns  116.83ns 138.83ns
64M: 8.42ns  8.63ns  196.17ns 204.52ns -> 8.26ns  8.43ns  193.49ns 203.85ns
128M: 8.31ns  8.58ns  230.46ns 242.63ns -> 8.22ns  8.39ns  227.99ns 240.29ns
256M: 8.80ns  8.80ns  248.24ns 261.68ns -> 8.35ns  8.55ns  250.18ns 262.20ns

Note I also chose to enforce PXNTable at the PMD layer only (for now),
since the 194 descriptors which are affected by this change on my
testing setup are not sufficient to warrant enforcement at a coarser
granularity.

The architecture-independent changes (I term "generic") can be
classified only as refactoring, but I feel are also major improvements
in that they standardize most uses of the vmalloc interface across the
kernel.

Note this patch reduces the arm64 allocated region for BPF and kprobes,
but only to match with the existing allocation choices made by the
generic kernel. I will admit I do not understand why BPF JIT allocation
code was duplicated into arm64, but I also feel that this was either an
artifact or that these overrides for generic allocation should require a
specific KConfig as they trade off between security and space. That
said, I have chosen not to wrap this patch in a KConfig interface, as I
feel the changes provide significant benefit to the arm64 kernel's
baseline security, though a KConfig could certainly be added if the
maintainers see the need.

Maxwell Bland (4):
  mm/vmalloc: allow arch-specific vmalloc_node overrides
  mm: pgalloc: support address-conditional pmd allocation
  arm64: separate code and data virtual memory allocation
  arm64: dynamic enforcement of pmd-level PXNTable

 arch/arm/kernel/irq.c               |  2 +-
 arch/arm64/include/asm/pgalloc.h    | 11 +++++-
 arch/arm64/include/asm/vmalloc.h    |  8 ++++
 arch/arm64/include/asm/vmap_stack.h |  2 +-
 arch/arm64/kernel/efi.c             |  2 +-
 arch/arm64/kernel/module.c          |  7 ++++
 arch/arm64/kernel/probes/kprobes.c  |  2 +-
 arch/arm64/mm/Makefile              |  3 +-
 arch/arm64/mm/trans_pgd.c           |  2 +-
 arch/arm64/mm/vmalloc.c             | 57 +++++++++++++++++++++++++++++
 arch/arm64/net/bpf_jit_comp.c       |  5 ++-
 arch/powerpc/kernel/irq.c           |  2 +-
 arch/riscv/include/asm/irq_stack.h  |  2 +-
 arch/s390/hypfs/hypfs_diag.c        |  2 +-
 arch/s390/kernel/setup.c            |  6 +--
 arch/s390/kernel/sthyi.c            |  2 +-
 include/asm-generic/pgalloc.h       | 18 +++++++++
 include/linux/mm.h                  |  4 +-
 include/linux/vmalloc.h             | 15 +++++++-
 kernel/bpf/syscall.c                |  4 +-
 kernel/fork.c                       |  4 +-
 kernel/scs.c                        |  3 +-
 lib/objpool.c                       |  2 +-
 lib/test_vmalloc.c                  |  6 +--
 mm/hugetlb_vmemmap.c                |  4 +-
 mm/kasan/init.c                     | 22 ++++++-----
 mm/memory.c                         |  4 +-
 mm/percpu.c                         |  2 +-
 mm/pgalloc-track.h                  |  3 +-
 mm/sparse-vmemmap.c                 |  2 +-
 mm/util.c                           |  3 +-
 mm/vmalloc.c                        | 39 +++++++-------------
 32 files changed, 176 insertions(+), 74 deletions(-)
 create mode 100644 arch/arm64/mm/vmalloc.c


base-commit: b401b621758e46812da61fa58a67c3fd8d91de0d
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220203256.31153-1-mbland%40motorola.com.
