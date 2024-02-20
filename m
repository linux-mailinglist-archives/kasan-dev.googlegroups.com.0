Return-Path: <kasan-dev+bncBDOJT7EVXMDBBJEZ2SXAMGQERSMV5UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id A997085C5D3
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:33:42 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1dbcf647a9dsf28738855ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 12:33:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708461221; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECbcghQwg0fTYN89qYEnGrzZz7K9uzbScYemWWTatnILLJPO6k3jmc32i+qbo6g9Yh
         xy8qCzflh3wtG4xdXRzvm4HZOO5QMayDkfhhMXKtMqytB6dGzilxWuO+NmVLSHhFCueh
         7l7sia1GJMR/lxGv/a78+rcUb4TGdfSrGyRq8onBLMKhtrWsrjGJAuZnsyIMZw68Eyv9
         VuJ2Sqh6IniIgBHzKmOu6SbU6ShZmOPY8C7jFq3Wa8NCMhmud6RKLVvEdXuSIqKUT9WA
         Mbi1Q1/aiSlxumV5TZK6ufD85gBNiBv7GO9bm9/PjnH2yc7eXGmT8Rm6YraBRVgAPeH9
         df1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=yRkPGxJPiQqbqE55NRy/zYK0YABnyFljLDUOpdOK3eI=;
        fh=28x8Fsal6Xm+HA2Pz9mIU5qBD4HRt+WT/xkLhbLbN6s=;
        b=jWdP8Lz3/BVBN0zx4Ra8solvpBydH2OkGh00MqsGZd3uJILpEiA/lJhIxT8okEFaI4
         dhULRtE+/kLO0j2M7vOVmzwCLKjw8O9XqymTZEzhRIlBoEyueGIZQ3jM5gypKzqZXosH
         d3gRXk1RJ4XmzLKS0kbDWBJsHR4xyMtxXw4wiQgcJVLp2/zm6iwrYBH5baPSYK1Qu5Ic
         CAFEdPmLlA6YvsUbW+joobGnD57bTVNvAQM5C6CWfG9esKnXT6XdVrkml3sgBVOsRp81
         qzxeMB4V8EmaInVClV2HQs90hlI9aoCP38HTMbtte9S/4Dbj7nMdZLEN7Rzy9yzIjwcM
         4eag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=UXr8sKPP;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708461221; x=1709066021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:message-id:date:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yRkPGxJPiQqbqE55NRy/zYK0YABnyFljLDUOpdOK3eI=;
        b=j+3t3l4ITzBVCVP5KNMqlM2EXPYbqu7LkSXQ3+A/XksdDuKk3GzX1N1JiTnqc+O6sx
         Um44h/c+glmcC3vNYmQ3U2O60SdGZvYfh5T3n2bgsq46Glvxrs2HdIiR6V8Ne2gUV02d
         bVRaTUfYEdKvQrbGYM73lPHibCtw79J0cmHHerz6gqJhl6lbXKAFSK35k+pUYja+ML90
         o8bB+TS9o/ixPaj33KJL4ojLCQLbfMGP3GZ5cQ6u/xnv+ib5gxCL7R5TUWUrECzaW8v5
         60EEZItxeOG+t5zDeZjr1X4WvEoIacsV+1W8OKgcrVxbfV+39Xa+fXtXKPVzrJpIMLy0
         5G4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708461221; x=1709066021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:message-id:date:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yRkPGxJPiQqbqE55NRy/zYK0YABnyFljLDUOpdOK3eI=;
        b=bazfH/ky1MjN9TbtOXVs0r8xVqBbLLKdmnNG7idIoBh17aQ3z1NpPQ2ow/RAFGMKB4
         Kmqtlv/51SETWnh6RIijVohX8jMVeg3/SC+tAT+q8vspbQl2zWmjibch1kkAUEB01YPz
         EopSZyPQ2yWLK/Zrige01k2TqwAtN0k0z238AD1+rdNWMLoeDHd4ANvbSKqtbb+8YSn9
         f9rO8VClqkfH6wDt7m2BO5mQ0RNqI5qzkaSbDhwJniP+Cez2jAuHFGHbCU2+Yn+SD3A9
         608ZFMTmFLjB3fj42+TpImWGtfDheeOsvt7sTNuEjFFkDER85kR46DYB+4G0Z/5c1+sV
         TADg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIfm09gTbsL6yR/vL9M/YG7TK2nGulgDZMkzhENHzz6KRIz/uuaBUuCDDEAY0pHcZv8YM+fzi9wgLv7dhiU8kd+92ZJaOh/w==
X-Gm-Message-State: AOJu0YwyS/Jb/SuaYITcRLMFMK4zjUlPg2pz4qQOnN4/1OMuGWjbisJm
	MUhskiYUMAbvM8pp2M2hzZ+cgFOlHWQD97mowocnfxofuxnG+k6+
X-Google-Smtp-Source: AGHT+IEI4ONjk9ET3bgB6UJuZRL9HHyLAZxR5IpTNfHa3AzlfsBRfgvtGb1Zo6UEsLhAtELJZ/AKcA==
X-Received: by 2002:a17:903:483:b0:1db:b96f:4a50 with SMTP id jj3-20020a170903048300b001dbb96f4a50mr12717929plb.14.1708461220805;
        Tue, 20 Feb 2024 12:33:40 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c20b:b0:1d9:10f0:ac29 with SMTP id
 11-20020a170902c20b00b001d910f0ac29ls2489155pll.2.-pod-prod-00-us; Tue, 20
 Feb 2024 12:33:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVWlmoYuajqJJgtqWXLiL6B8r8iuSJku450HXEWpq6CiE0oRG6aaf9JXuhxO/3fFlhVr8WJFNsQoPesmdCEUvtDhL/ALw+C5GazQA==
X-Received: by 2002:a17:902:e746:b0:1d9:a15:615d with SMTP id p6-20020a170902e74600b001d90a15615dmr24187044plf.1.1708461219475;
        Tue, 20 Feb 2024 12:33:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708461219; cv=none;
        d=google.com; s=arc-20160816;
        b=ASLIkEm7cSrsWoLX7rF9phheTMvhSNoZea6hWTrLaN6Mx2H4tcIztv3tGS//PYfGq9
         4p4Rw6ykaifTRWvyecS956lFg9YMTvY/tAZyYY1Uqg5KCLvstFM+6OiJpE+2GbmfkiIw
         9AqZOQCokTySqLqfkimZqVuJJfvJsqScW0R3juGHAGUwk4r+vuRu8RSeUqUaE474Dfyz
         VodZCHo2e7yzso/Ow7L2fBCqm7oTjoQzknDXn0muAB4Qc/hKk98t4iTnfdbwyIIixZpv
         Qi+x0woBFpbJcSVZGZg52RCJ1JP/sQkLA0cRBk87eFjnR+woLiPRrNSnJ2dMo8l56xTv
         lA5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=73sw9qCcfHZDBF19mVjUh6QeXe6a4xhn7+e2L7eQ6wM=;
        fh=FkeYy9VFhDbdZf7Wr1j+kC7C7CaCFd0E6M33TF/KxqU=;
        b=0EzxW/vwDznFUV5GLy7XKbI0yjagO0ReawGR1/M4zhtE0jD3U6L2w1NTUJhJTSZko5
         ljWE3+rGKZZ0OrIniiZlcsbLVqoY2y4HvvDJlMp2WQMmr8iPu6JprA+5Rlg1LsPf1wRS
         oxDbB28Thtt1QfWHM2O8n/+CCMDf034iQLfO29MoeFbn5SYjjNqukNOLQ/L/kKMs10S5
         aZ/hGNnglEB5/mK4NVNOeXOSs5wZp0AwlshjlG2RZzi5ldQZnUJGft5TSfWA3h+6p0rq
         xqAv5D6GAmaW6s/o2j+i19grJIYEwxwYqL2GKjlYpi4tGKRa8Kt8i3rdAiGM1V/A+BS9
         RucQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=UXr8sKPP;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0b-00823401.pphosted.com (mx0b-00823401.pphosted.com. [148.163.152.46])
        by gmr-mx.google.com with ESMTPS id kv5-20020a17090328c500b001db63388676si515386plb.8.2024.02.20.12.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 12:33:39 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) client-ip=148.163.152.46;
Received: from pps.filterd (m0355092.ppops.net [127.0.0.1])
	by mx0b-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41KJHi73012543;
	Tue, 20 Feb 2024 20:33:18 GMT
Received: from va32lpfpp01.lenovo.com ([104.232.228.21])
	by mx0b-00823401.pphosted.com (PPS) with ESMTPS id 3wd243r5xa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 20 Feb 2024 20:33:18 +0000 (GMT)
Received: from ilclmmrp01.lenovo.com (ilclmmrp01.mot.com [100.65.83.165])
	(using TLSv1.2 with cipher ADH-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by va32lpfpp01.lenovo.com (Postfix) with ESMTPS id 4TfWM156fyzldQm;
	Tue, 20 Feb 2024 20:33:17 +0000 (UTC)
Received: from ilclasset01.mot.com (ilclasset01.mot.com [100.64.7.105])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: mbland)
	by ilclmmrp01.lenovo.com (Postfix) with ESMTPSA id 4TfWM13X59z3n3fr;
	Tue, 20 Feb 2024 20:33:17 +0000 (UTC)
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
Subject: [PATCH 1/4] mm/vmalloc: allow arch-specific vmalloc_node overrides
Date: Tue, 20 Feb 2024 14:32:53 -0600
Message-Id: <20240220203256.31153-2-mbland@motorola.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20240220203256.31153-1-mbland@motorola.com>
References: <20240220203256.31153-1-mbland@motorola.com>
X-Proofpoint-ORIG-GUID: 1BOL4_DErfcL9zeY20ilUxwJWM2r8GsL
X-Proofpoint-GUID: 1BOL4_DErfcL9zeY20ilUxwJWM2r8GsL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 mlxscore=0
 bulkscore=0 phishscore=0 adultscore=0 clxscore=1015 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402200146
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=UXr8sKPP;       spf=pass
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

Present non-uniform use of __vmalloc_node and __vmalloc_node_range makes
enforcing appropriate code and data seperation untenable on certain
microarchitectures, as VMALLOC_START and VMALLOC_END are monolithic
while the use of the vmalloc interface is non-monolithic: in particular,
appropriate randomness in ASLR makes it such that code regions must fall
in some region between VMALLOC_START and VMALLOC_end, but this
necessitates that code pages are intermingled with data pages, meaning
code-specific protections, such as arm64's PXNTable, cannot be
performantly runtime enforced.

The solution to this problem allows architectures to override the
vmalloc wrapper functions by enforcing that the rest of the kernel does
not reimplement __vmalloc_node by using __vmalloc_node_range with the
same parameters as __vmalloc_node or provides a __weak tag to those
functions using __vmalloc_node_range with parameters repeating those of
__vmalloc_node.

Two benefits of this approach are (1) greater flexibility to each
architecture for handling of virtual memory while not compromising the
kernel's vmalloc logic and (2) more uniform use of the __vmalloc_node
interface, reserving the more specialized __vmalloc_node_range for more
specialized cases, such as kasan's shadow memory.

Signed-off-by: Maxwell Bland <mbland@motorola.com>
---
 arch/arm/kernel/irq.c               |  2 +-
 arch/arm64/include/asm/vmap_stack.h |  2 +-
 arch/arm64/kernel/efi.c             |  2 +-
 arch/powerpc/kernel/irq.c           |  2 +-
 arch/riscv/include/asm/irq_stack.h  |  2 +-
 arch/s390/hypfs/hypfs_diag.c        |  2 +-
 arch/s390/kernel/setup.c            |  6 ++---
 arch/s390/kernel/sthyi.c            |  2 +-
 include/linux/vmalloc.h             | 15 ++++++++++-
 kernel/bpf/syscall.c                |  4 +--
 kernel/fork.c                       |  4 +--
 kernel/scs.c                        |  3 +--
 lib/objpool.c                       |  2 +-
 lib/test_vmalloc.c                  |  6 ++---
 mm/util.c                           |  3 +--
 mm/vmalloc.c                        | 39 +++++++++++------------------
 16 files changed, 47 insertions(+), 49 deletions(-)

diff --git a/arch/arm/kernel/irq.c b/arch/arm/kernel/irq.c
index fe28fc1f759d..109f4f363621 100644
--- a/arch/arm/kernel/irq.c
+++ b/arch/arm/kernel/irq.c
@@ -61,7 +61,7 @@ static void __init init_irq_stacks(void)
 						       THREAD_SIZE_ORDER);
 		else
 			stack = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN,
-					       THREADINFO_GFP, NUMA_NO_NODE,
+					       THREADINFO_GFP, 0, NUMA_NO_NODE,
 					       __builtin_return_address(0));
 
 		if (WARN_ON(!stack))
diff --git a/arch/arm64/include/asm/vmap_stack.h b/arch/arm64/include/asm/vmap_stack.h
index 20873099c035..57a7eaa720d5 100644
--- a/arch/arm64/include/asm/vmap_stack.h
+++ b/arch/arm64/include/asm/vmap_stack.h
@@ -21,7 +21,7 @@ static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
 
 	BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));
 
-	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
+	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, 0, node,
 			__builtin_return_address(0));
 	return kasan_reset_tag(p);
 }
diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
index 0228001347be..48efa31a9161 100644
--- a/arch/arm64/kernel/efi.c
+++ b/arch/arm64/kernel/efi.c
@@ -205,7 +205,7 @@ static int __init arm64_efi_rt_init(void)
 		return 0;
 
 	p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
-			   NUMA_NO_NODE, &&l);
+			   0, NUMA_NO_NODE, &&l);
 l:	if (!p) {
 		pr_warn("Failed to allocate EFI runtime stack\n");
 		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
diff --git a/arch/powerpc/kernel/irq.c b/arch/powerpc/kernel/irq.c
index 6f7d4edaa0bc..ceb7ea07ca28 100644
--- a/arch/powerpc/kernel/irq.c
+++ b/arch/powerpc/kernel/irq.c
@@ -308,7 +308,7 @@ DEFINE_INTERRUPT_HANDLER_ASYNC(do_IRQ)
 static void *__init alloc_vm_stack(void)
 {
 	return __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, THREADINFO_GFP,
-			      NUMA_NO_NODE, (void *)_RET_IP_);
+			      0, NUMA_NO_NODE, (void *)_RET_IP_);
 }
 
 static void __init vmap_irqstack_init(void)
diff --git a/arch/riscv/include/asm/irq_stack.h b/arch/riscv/include/asm/irq_stack.h
index 6441ded3b0cf..d2410735bde0 100644
--- a/arch/riscv/include/asm/irq_stack.h
+++ b/arch/riscv/include/asm/irq_stack.h
@@ -24,7 +24,7 @@ static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
 {
 	void *p;
 
-	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
+	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, 0, node,
 			__builtin_return_address(0));
 	return kasan_reset_tag(p);
 }
diff --git a/arch/s390/hypfs/hypfs_diag.c b/arch/s390/hypfs/hypfs_diag.c
index 279b7bba4d43..16359d854288 100644
--- a/arch/s390/hypfs/hypfs_diag.c
+++ b/arch/s390/hypfs/hypfs_diag.c
@@ -70,7 +70,7 @@ void *diag204_get_buffer(enum diag204_format fmt, int *pages)
 			return ERR_PTR(-EOPNOTSUPP);
 	}
 	diag204_buf = __vmalloc_node(array_size(*pages, PAGE_SIZE),
-				     PAGE_SIZE, GFP_KERNEL, NUMA_NO_NODE,
+				     PAGE_SIZE, GFP_KERNEL, 0, NUMA_NO_NODE,
 				     __builtin_return_address(0));
 	if (!diag204_buf)
 		return ERR_PTR(-ENOMEM);
diff --git a/arch/s390/kernel/setup.c b/arch/s390/kernel/setup.c
index d1f3b56e7afc..2c25b4e9f20a 100644
--- a/arch/s390/kernel/setup.c
+++ b/arch/s390/kernel/setup.c
@@ -254,7 +254,7 @@ static void __init conmode_default(void)
 		cpcmd("QUERY TERM", query_buffer, 1024, NULL);
 		ptr = strstr(query_buffer, "CONMODE");
 		/*
-		 * Set the conmode to 3215 so that the device recognition 
+		 * Set the conmode to 3215 so that the device recognition
 		 * will set the cu_type of the console to 3215. If the
 		 * conmode is 3270 and we don't set it back then both
 		 * 3215 and the 3270 driver will try to access the console
@@ -314,7 +314,7 @@ static inline void setup_zfcpdump(void) {}
 
  /*
  * Reboot, halt and power_off stubs. They just call _machine_restart,
- * _machine_halt or _machine_power_off. 
+ * _machine_halt or _machine_power_off.
  */
 
 void machine_restart(char *command)
@@ -364,7 +364,7 @@ unsigned long stack_alloc(void)
 	void *ret;
 
 	ret = __vmalloc_node(THREAD_SIZE, THREAD_SIZE, THREADINFO_GFP,
-			     NUMA_NO_NODE, __builtin_return_address(0));
+			     0, NUMA_NO_NODE, __builtin_return_address(0));
 	kmemleak_not_leak(ret);
 	return (unsigned long)ret;
 #else
diff --git a/arch/s390/kernel/sthyi.c b/arch/s390/kernel/sthyi.c
index 30bb20461db4..5bf239bcdae9 100644
--- a/arch/s390/kernel/sthyi.c
+++ b/arch/s390/kernel/sthyi.c
@@ -318,7 +318,7 @@ static void fill_diag(struct sthyi_sctns *sctns)
 		return;
 
 	diag204_buf = __vmalloc_node(array_size(pages, PAGE_SIZE),
-				     PAGE_SIZE, GFP_KERNEL, NUMA_NO_NODE,
+				     PAGE_SIZE, GFP_KERNEL, 0, NUMA_NO_NODE,
 				     __builtin_return_address(0));
 	if (!diag204_buf)
 		return;
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index c720be70c8dd..f13bd711ad7d 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -150,7 +150,8 @@ extern void *__vmalloc_node_range(unsigned long size, unsigned long align,
 			pgprot_t prot, unsigned long vm_flags, int node,
 			const void *caller) __alloc_size(1);
 void *__vmalloc_node(unsigned long size, unsigned long align, gfp_t gfp_mask,
-		int node, const void *caller) __alloc_size(1);
+		unsigned long vm_flags, int node, const void *caller)
+		__alloc_size(1);
 void *vmalloc_huge(unsigned long size, gfp_t gfp_mask) __alloc_size(1);
 
 extern void *__vmalloc_array(size_t n, size_t size, gfp_t flags) __alloc_size(1, 2);
@@ -295,4 +296,16 @@ bool vmalloc_dump_obj(void *object);
 static inline bool vmalloc_dump_obj(void *object) { return false; }
 #endif
 
+#if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
+#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
+#elif defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA)
+#define GFP_VMALLOC32 (GFP_DMA | GFP_KERNEL)
+#else
+/*
+ * 64b systems should always have either DMA or DMA32 zones. For others
+ * GFP_DMA32 should do the right thing and use the normal zone.
+ */
+#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
+#endif
+
 #endif /* _LINUX_VMALLOC_H */
diff --git a/kernel/bpf/syscall.c b/kernel/bpf/syscall.c
index a1f18681721c..79c11307ff40 100644
--- a/kernel/bpf/syscall.c
+++ b/kernel/bpf/syscall.c
@@ -303,8 +303,8 @@ static void *__bpf_map_area_alloc(u64 size, int numa_node, bool mmapable)
 			return area;
 	}
 
-	return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
-			gfp | GFP_KERNEL | __GFP_RETRY_MAYFAIL, PAGE_KERNEL,
+	return __vmalloc_node(size, align,
+			gfp | GFP_KERNEL | __GFP_RETRY_MAYFAIL,
 			flags, numa_node, __builtin_return_address(0));
 }
 
diff --git a/kernel/fork.c b/kernel/fork.c
index 0d944e92a43f..800bb1c76000 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -304,10 +304,8 @@ static int alloc_thread_stack_node(struct task_struct *tsk, int node)
 	 * so memcg accounting is performed manually on assigning/releasing
 	 * stacks to tasks. Drop __GFP_ACCOUNT.
 	 */
-	stack = __vmalloc_node_range(THREAD_SIZE, THREAD_ALIGN,
-				     VMALLOC_START, VMALLOC_END,
+	stack = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN,
 				     THREADINFO_GFP & ~__GFP_ACCOUNT,
-				     PAGE_KERNEL,
 				     0, node, __builtin_return_address(0));
 	if (!stack)
 		return -ENOMEM;
diff --git a/kernel/scs.c b/kernel/scs.c
index d7809affe740..5b89fb08a392 100644
--- a/kernel/scs.c
+++ b/kernel/scs.c
@@ -43,8 +43,7 @@ static void *__scs_alloc(int node)
 		}
 	}
 
-	s = __vmalloc_node_range(SCS_SIZE, 1, VMALLOC_START, VMALLOC_END,
-				    GFP_SCS, PAGE_KERNEL, 0, node,
+	s = __vmalloc_node(SCS_SIZE, 1, GFP_SCS, 0, node,
 				    __builtin_return_address(0));
 
 out:
diff --git a/lib/objpool.c b/lib/objpool.c
index cfdc02420884..f0acd421a652 100644
--- a/lib/objpool.c
+++ b/lib/objpool.c
@@ -80,7 +80,7 @@ objpool_init_percpu_slots(struct objpool_head *pool, int nr_objs,
 			slot = kmalloc_node(size, pool->gfp, cpu_to_node(i));
 		else
 			slot = __vmalloc_node(size, sizeof(void *), pool->gfp,
-				cpu_to_node(i), __builtin_return_address(0));
+				0, cpu_to_node(i), __builtin_return_address(0));
 		if (!slot)
 			return -ENOMEM;
 		memset(slot, 0, size);
diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
index 3718d9886407..6bde73f892f9 100644
--- a/lib/test_vmalloc.c
+++ b/lib/test_vmalloc.c
@@ -97,7 +97,7 @@ static int random_size_align_alloc_test(void)
 		size = ((rnd % 10) + 1) * PAGE_SIZE;
 
 		ptr = __vmalloc_node(size, align, GFP_KERNEL | __GFP_ZERO, 0,
-				__builtin_return_address(0));
+				0, __builtin_return_address(0));
 		if (!ptr)
 			return -1;
 
@@ -120,7 +120,7 @@ static int align_shift_alloc_test(void)
 		align = ((unsigned long) 1) << i;
 
 		ptr = __vmalloc_node(PAGE_SIZE, align, GFP_KERNEL|__GFP_ZERO, 0,
-				__builtin_return_address(0));
+				0, __builtin_return_address(0));
 		if (!ptr)
 			return -1;
 
@@ -138,7 +138,7 @@ static int fix_align_alloc_test(void)
 	for (i = 0; i < test_loop_count; i++) {
 		ptr = __vmalloc_node(5 * PAGE_SIZE, THREAD_ALIGN << 1,
 				GFP_KERNEL | __GFP_ZERO, 0,
-				__builtin_return_address(0));
+				0, __builtin_return_address(0));
 		if (!ptr)
 			return -1;
 
diff --git a/mm/util.c b/mm/util.c
index 5a6a9802583b..c6b7111215e2 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -639,8 +639,7 @@ void *kvmalloc_node(size_t size, gfp_t flags, int node)
 	 * about the resulting pointer, and cannot play
 	 * protection games.
 	 */
-	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
-			flags, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
+	return __vmalloc_node(size, 1, flags, VM_ALLOW_HUGE_VMAP,
 			node, __builtin_return_address(0));
 }
 EXPORT_SYMBOL(kvmalloc_node);
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d12a17fc0c17..18ece28e79d3 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3119,7 +3119,7 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
 
 	/* Please note that the recursion is strictly bounded. */
 	if (array_size > PAGE_SIZE) {
-		area->pages = __vmalloc_node(array_size, 1, nested_gfp, node,
+		area->pages = __vmalloc_node(array_size, 1, nested_gfp, 0, node,
 					area->caller);
 	} else {
 		area->pages = kmalloc_node(array_size, nested_gfp, node);
@@ -3379,11 +3379,12 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *__vmalloc_node(unsigned long size, unsigned long align,
-			    gfp_t gfp_mask, int node, const void *caller)
+__weak void *__vmalloc_node(unsigned long size, unsigned long align,
+			    gfp_t gfp_mask, unsigned long vm_flags, int node,
+			    const void *caller)
 {
 	return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
-				gfp_mask, PAGE_KERNEL, 0, node, caller);
+				gfp_mask, PAGE_KERNEL, vm_flags, node, caller);
 }
 /*
  * This is only for performance analysis of vmalloc and stress purpose.
@@ -3396,7 +3397,7 @@ EXPORT_SYMBOL_GPL(__vmalloc_node);
 
 void *__vmalloc(unsigned long size, gfp_t gfp_mask)
 {
-	return __vmalloc_node(size, 1, gfp_mask, NUMA_NO_NODE,
+	return __vmalloc_node(size, 1, gfp_mask, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 }
 EXPORT_SYMBOL(__vmalloc);
@@ -3415,7 +3416,7 @@ EXPORT_SYMBOL(__vmalloc);
  */
 void *vmalloc(unsigned long size)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL, NUMA_NO_NODE,
+	return __vmalloc_node(size, 1, GFP_KERNEL, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 }
 EXPORT_SYMBOL(vmalloc);
@@ -3432,7 +3433,7 @@ EXPORT_SYMBOL(vmalloc);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_huge(unsigned long size, gfp_t gfp_mask)
+__weak void *vmalloc_huge(unsigned long size, gfp_t gfp_mask)
 {
 	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
 				    gfp_mask, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
@@ -3455,7 +3456,7 @@ EXPORT_SYMBOL_GPL(vmalloc_huge);
  */
 void *vzalloc(unsigned long size)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, NUMA_NO_NODE,
+	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 }
 EXPORT_SYMBOL(vzalloc);
@@ -3469,7 +3470,7 @@ EXPORT_SYMBOL(vzalloc);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_user(unsigned long size)
+__weak void *vmalloc_user(unsigned long size)
 {
 	return __vmalloc_node_range(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
 				    GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
@@ -3493,7 +3494,7 @@ EXPORT_SYMBOL(vmalloc_user);
  */
 void *vmalloc_node(unsigned long size, int node)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL, node,
+	return __vmalloc_node(size, 1, GFP_KERNEL, 0, node,
 			__builtin_return_address(0));
 }
 EXPORT_SYMBOL(vmalloc_node);
@@ -3511,23 +3512,11 @@ EXPORT_SYMBOL(vmalloc_node);
  */
 void *vzalloc_node(unsigned long size, int node)
 {
-	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, node,
+	return __vmalloc_node(size, 1, GFP_KERNEL | __GFP_ZERO, 0, node,
 				__builtin_return_address(0));
 }
 EXPORT_SYMBOL(vzalloc_node);
 
-#if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
-#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
-#elif defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA)
-#define GFP_VMALLOC32 (GFP_DMA | GFP_KERNEL)
-#else
-/*
- * 64b systems should always have either DMA or DMA32 zones. For others
- * GFP_DMA32 should do the right thing and use the normal zone.
- */
-#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
-#endif
-
 /**
  * vmalloc_32 - allocate virtually contiguous memory (32bit addressable)
  * @size:	allocation size
@@ -3539,7 +3528,7 @@ EXPORT_SYMBOL(vzalloc_node);
  */
 void *vmalloc_32(unsigned long size)
 {
-	return __vmalloc_node(size, 1, GFP_VMALLOC32, NUMA_NO_NODE,
+	return __vmalloc_node(size, 1, GFP_VMALLOC32, 0, NUMA_NO_NODE,
 			__builtin_return_address(0));
 }
 EXPORT_SYMBOL(vmalloc_32);
@@ -3553,7 +3542,7 @@ EXPORT_SYMBOL(vmalloc_32);
  *
  * Return: pointer to the allocated memory or %NULL on error
  */
-void *vmalloc_32_user(unsigned long size)
+__weak void *vmalloc_32_user(unsigned long size)
 {
 	return __vmalloc_node_range(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
 				    GFP_VMALLOC32 | __GFP_ZERO, PAGE_KERNEL,
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220203256.31153-2-mbland%40motorola.com.
