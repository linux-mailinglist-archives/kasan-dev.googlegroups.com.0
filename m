Return-Path: <kasan-dev+bncBDOJT7EVXMDBBJEZ2SXAMGQERSMV5UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id ED6A085C5D2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:33:41 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3652275e581sf25462445ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 12:33:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708461220; cv=pass;
        d=google.com; s=arc-20160816;
        b=LZvFCI5AGRn3l6chWJwGODzbNWq7GsDE91AwCEndB30D8AizbD1ygz+U1KaVXN3DVe
         QJHJ3/VRycIokRnpQgu8fuEQHSEOhqyXi/xAFF/VPtY0zeDkYUelLswVn2OBLtDFWRGQ
         k589coT/sHZhjmWG3+CK+iqhRdVSkwdmBZj2T1eRcWvWcLEx16MbFgb235MhT+hyV3+d
         CTyS9j5KswflR1TeYHsOl2kcDmEwCdE7/xUNBqjhVV+HaYH+zSu976GvnHLOf2CuxK8R
         S16r4oToUUu4tP2cpC57bB+TjdTLnYU/Ao4K20awrw5BVRLi3sP5948aLeqq8rAgc87V
         k0ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=j6fQvRJWG3lYtQ6N+HqpzEUq5S1xWO2qNvanLnktmp0=;
        fh=CkE0nMQj+XuZNcsBFzWGfPRADB2yxsX0roeEpa2Sjh0=;
        b=M43l3MfL2Q5xtExvTXKAjG+kbweiPPBhT9VW3Gdfr8SY5ZghFWTDKu0m1ifHZtlztb
         yFWOPYto6BzTlnAxh8TlsDJ/+lu8dnGd2vxa1qofZi3N48aGF+OWTogXrPLJCs6q9eLB
         wcB7RmzsHSuEiiqRmXbWd5XUG+qmS1cG36+PRERyT3S6C9C8ratrd7ZpMJyvafACcAn+
         4Or0XaRiIYlES0DiQcmaAVF99Pg/GplyJ9QdZTUQUcFNK74INoKkK7kF3AOK5+mU1w+P
         S0l1MYABNSyFC6Z/LGfhIBfP2zM6Owa4GOy8KKd7ZfMumJqIuoPi/HQvZKVHls/Bzlxa
         q8nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=G8c3FTHW;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708461220; x=1709066020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:message-id:date:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j6fQvRJWG3lYtQ6N+HqpzEUq5S1xWO2qNvanLnktmp0=;
        b=jOiwmjtW29MIEKUhtX5iat3UCPxXOngU9gB1zXfvnJ7A8z56BR3jedKFDZIwF59WKG
         nCwuIFiTcC27iCi5YpmHy19mDC0ptaOXco/p+hWBQaJr9SOOkhsRRSfmPj1R2K9imeKs
         23F1UfAZmWGqwO49/tGA4L/ecxPaJauGvZUBBsiX9JrDTqeAVyi2XZd8z0+KZ2wVox5M
         RGYcu1N/92MwvGO/cc13HrNPFijo35bj+8G4VGNtJV9DnctVbLPuzc/yQWyvaKadhG4n
         W4v+NR42mCaqC1gZUW6De0Gyf11BBQ3hcQwehUKqWzcvcwbe6eUiagW/9ILKY5bPoHLW
         83KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708461220; x=1709066020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:message-id:date:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j6fQvRJWG3lYtQ6N+HqpzEUq5S1xWO2qNvanLnktmp0=;
        b=T0fTP7BZe6xpaxYvhlE7SBIZcb+atBA9Wx8kodXPkM/grdBSr4t4tKyT4+zhznzxmk
         yVs0HGCObTJOdsKtSsmS4XJT9Pu6Va3cePT3V+KBYlw14Cx12vUPQkF1wyOeqzc5opa8
         v+bBYr881/weL3fzdh4AxpVvUgPeJR2X+q2wnWARAuSGhVAlu9GdALenRvLPe5v6JNB0
         slOT7m69OlpC1CDVejPekIzXWSseUGjBrlK+bl6sUdTzuWDzE6f5bWA6JhIA4pjC8t2g
         bq1zsfrG2Fky2qTLK+G+bN1xp3F/XdHfs84e5/O4D5VA6R5qcjY+xuCdsyToAtDUqwzd
         phKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrE+GTEi/K8o6Jt87hwvonM3gHEWKXSrxHnmzoi3tPxWZcca5OCzMkK6EYk2dW3GQiydhMTfS8+H2Utiuf0bKBcmdyBH2bdA==
X-Gm-Message-State: AOJu0YxiIDPSXJ9eSVzQ3dvzZe8NyspX1AdTHC1NzfOCgInvnBxxhkiT
	7UljGnkljbQor43NPZqm+6vczAQiPx0xHTdD85a9s0Wp4UBVFdTP
X-Google-Smtp-Source: AGHT+IFrlQjLin0+WBaIuiDruw43zgtdZFpnJHYRIb/yZQIERouwR1NiculQ4Omo8cUYGfnm6oWyJg==
X-Received: by 2002:a05:6e02:1d8f:b0:365:858:d6d1 with SMTP id h15-20020a056e021d8f00b003650858d6d1mr20133311ila.1.1708461220641;
        Tue, 20 Feb 2024 12:33:40 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e51:b0:363:8ef4:5a93 with SMTP id
 l17-20020a056e020e5100b003638ef45a93ls2626943ilk.2.-pod-prod-05-us; Tue, 20
 Feb 2024 12:33:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUwxyR+q1UYt615HJYkdGDP2wosd5lMkRQsrZAcMZsbmgaVa8qfTnXP0FDEEvNI5IxY75eds9sULUHrXjtQxL9gvO9lIOxKRFrU+Q==
X-Received: by 2002:a05:6e02:12e3:b0:364:279c:4a08 with SMTP id l3-20020a056e0212e300b00364279c4a08mr23665881iln.23.1708461219607;
        Tue, 20 Feb 2024 12:33:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708461219; cv=none;
        d=google.com; s=arc-20160816;
        b=H1qCTVDpEOsPM/psG/MzvIKWxq1ZE3JTR1h7N771nLrNsgibkrIm9QoBC8K3X3pZQM
         cRusZT+h80rVCVH1bGsjxoW2KHkh6yFonaIt3Vl8XUbqgzt30PFOE5/y6cqwcS7cSwjo
         50Um4Qz/3vYmuFwMxFyhEKMijrHZDR8B+uW8YPLYzoTkt9H63NG+W2RzNReiB0vXyZ4y
         wdta2sTkQusnJm74+oYJ7KA+4lMPGTUG/e21jwQa/u4w1n3fWS0dWAxQxnyWrDkd9HX8
         byshHWwB9ocwhbaPBH1QK2urh8db+SrRx5DGUku3//2eEfXQS03gpJ1ybhTO1bN68Ecz
         GKJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=bbMfJLfH6G5a4s+Z0cFe2wOzrCFA0lQFMo+SQbxfAvI=;
        fh=FkeYy9VFhDbdZf7Wr1j+kC7C7CaCFd0E6M33TF/KxqU=;
        b=xzkY4ha24TyrmVr+OqoztFIktXQxmig+OkoUeJ+YzzmeOmCka4des7Kr5lesWgIqqh
         Ak10jv9byztVYSHFouEtMoHJvYClzqbk/3kMd26aOhIP5SCimAtE+CVBQrrMheJJPOtz
         owQSQaeZSgsbsGXwCRyL/p86NIlrtY+geRI8IZci7sohurLbZ477s9l4vQgbRGEfzC5m
         Cnk/zcAdj7miRzHFlJ8QtKxqPP/bRya4EosdrHGRHL+YwFa/+MB7vsi0p/rqK9BMbX/M
         mPsd/x9T6Bld+jCm61wdFYjfVpTPHVsRvyIZUHBqPeK+vPZrriWUFD38jKEWqfPSTqqM
         UVLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=G8c3FTHW;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0b-00823401.pphosted.com (mx0b-00823401.pphosted.com. [148.163.152.46])
        by gmr-mx.google.com with ESMTPS id b9-20020a056e02048900b0036458258671si737527ils.3.2024.02.20.12.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 12:33:39 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) client-ip=148.163.152.46;
Received: from pps.filterd (m0355092.ppops.net [127.0.0.1])
	by mx0b-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41KJHnit012600;
	Tue, 20 Feb 2024 20:33:22 GMT
Received: from va32lpfpp02.lenovo.com ([104.232.228.22])
	by mx0b-00823401.pphosted.com (PPS) with ESMTPS id 3wd243r5xe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 20 Feb 2024 20:33:22 +0000 (GMT)
Received: from ilclmmrp01.lenovo.com (ilclmmrp01.mot.com [100.65.83.165])
	(using TLSv1.2 with cipher ADH-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by va32lpfpp02.lenovo.com (Postfix) with ESMTPS id 4TfWM54JXDz50TkT;
	Tue, 20 Feb 2024 20:33:21 +0000 (UTC)
Received: from ilclasset01.mot.com (ilclasset01.mot.com [100.64.7.105])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: mbland)
	by ilclmmrp01.lenovo.com (Postfix) with ESMTPSA id 4TfWM52tFkz3n3fr;
	Tue, 20 Feb 2024 20:33:21 +0000 (UTC)
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
Subject: [PATCH 3/4] arm64: separate code and data virtual memory allocation
Date: Tue, 20 Feb 2024 14:32:55 -0600
Message-Id: <20240220203256.31153-4-mbland@motorola.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20240220203256.31153-1-mbland@motorola.com>
References: <20240220203256.31153-1-mbland@motorola.com>
X-Proofpoint-ORIG-GUID: b8j4dy_LLal3K6w9ma10ijvTf2cYSkmA
X-Proofpoint-GUID: b8j4dy_LLal3K6w9ma10ijvTf2cYSkmA
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
 header.i=@motorola.com header.s=DKIM202306 header.b=G8c3FTHW;       spf=pass
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

Current BPF and kprobe instruction allocation interfaces do not match
the base kernel and intermingle code and data pages within the same
sections. In the case of BPF, this appears to be a result of code
duplication between the kernel's JIT compiler and arm64's JIT.  However,
This is no longer necessary given the possibility of overriding vmalloc
wrapper functions.

arm64's vmalloc_node routines now include a layer of indirection which
splits the vmalloc region into two segments surrounding the middle
module_alloc region determined by ASLR. To support this,
code_region_start and code_region_end are defined to match the 2GB
boundary chosen by the kernel module ASLR initialization routine.

The result is a large benefits to overall kernel security, as code pages
now remain protected by this ASLR routine and protections can be defined
linearly for code regions rather than through PTE-level tracking.

Signed-off-by: Maxwell Bland <mbland@motorola.com>
---
 arch/arm64/include/asm/vmalloc.h   |  3 ++
 arch/arm64/kernel/module.c         |  7 ++++
 arch/arm64/kernel/probes/kprobes.c |  2 +-
 arch/arm64/mm/Makefile             |  3 +-
 arch/arm64/mm/vmalloc.c            | 57 ++++++++++++++++++++++++++++++
 arch/arm64/net/bpf_jit_comp.c      |  5 +--
 6 files changed, 73 insertions(+), 4 deletions(-)
 create mode 100644 arch/arm64/mm/vmalloc.c

diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
index 38fafffe699f..dbcf8ad20265 100644
--- a/arch/arm64/include/asm/vmalloc.h
+++ b/arch/arm64/include/asm/vmalloc.h
@@ -31,4 +31,7 @@ static inline pgprot_t arch_vmap_pgprot_tagged(pgprot_t prot)
 	return pgprot_tagged(prot);
 }
 
+extern unsigned long code_region_start __ro_after_init;
+extern unsigned long code_region_end __ro_after_init;
+
 #endif /* _ASM_ARM64_VMALLOC_H */
diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index dd851297596e..c4fe753a71a9 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -29,6 +29,10 @@
 static u64 module_direct_base __ro_after_init = 0;
 static u64 module_plt_base __ro_after_init = 0;
 
+/* For pre-init vmalloc, assume the worst-case code range */
+unsigned long code_region_start __ro_after_init = (u64) (_end - SZ_2G);
+unsigned long code_region_end __ro_after_init = (u64) (_text + SZ_2G);
+
 /*
  * Choose a random page-aligned base address for a window of 'size' bytes which
  * entirely contains the interval [start, end - 1].
@@ -101,6 +105,9 @@ static int __init module_init_limits(void)
 		module_plt_base = random_bounding_box(SZ_2G, min, max);
 	}
 
+	code_region_start = module_plt_base;
+	code_region_end = module_plt_base + SZ_2G;
+
 	pr_info("%llu pages in range for non-PLT usage",
 		module_direct_base ? (SZ_128M - kernel_size) / PAGE_SIZE : 0);
 	pr_info("%llu pages in range for PLT usage",
diff --git a/arch/arm64/kernel/probes/kprobes.c b/arch/arm64/kernel/probes/kprobes.c
index 70b91a8c6bb3..c9e109d6c8bc 100644
--- a/arch/arm64/kernel/probes/kprobes.c
+++ b/arch/arm64/kernel/probes/kprobes.c
@@ -131,7 +131,7 @@ int __kprobes arch_prepare_kprobe(struct kprobe *p)
 
 void *alloc_insn_page(void)
 {
-	return __vmalloc_node_range(PAGE_SIZE, 1, VMALLOC_START, VMALLOC_END,
+	return __vmalloc_node_range(PAGE_SIZE, 1, code_region_start, code_region_end,
 			GFP_KERNEL, PAGE_KERNEL_ROX, VM_FLUSH_RESET_PERMS,
 			NUMA_NO_NODE, __builtin_return_address(0));
 }
diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
index dbd1bc95967d..730b805d8388 100644
--- a/arch/arm64/mm/Makefile
+++ b/arch/arm64/mm/Makefile
@@ -2,7 +2,8 @@
 obj-y				:= dma-mapping.o extable.o fault.o init.o \
 				   cache.o copypage.o flush.o \
 				   ioremap.o mmap.o pgd.o mmu.o \
-				   context.o proc.o pageattr.o fixmap.o
+				   context.o proc.o pageattr.o fixmap.o \
+				   vmalloc.o
 obj-$(CONFIG_HUGETLB_PAGE)	+= hugetlbpage.o
 obj-$(CONFIG_PTDUMP_CORE)	+= ptdump.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
diff --git a/arch/arm64/mm/vmalloc.c b/arch/arm64/mm/vmalloc.c
new file mode 100644
index 000000000000..b6d2fa841f90
--- /dev/null
+++ b/arch/arm64/mm/vmalloc.c
@@ -0,0 +1,57 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <linux/vmalloc.h>
+#include <linux/mm.h>
+
+static void *__vmalloc_node_range_split(unsigned long size, unsigned long align,
+			unsigned long start, unsigned long end,
+			unsigned long exclusion_start, unsigned long exclusion_end, gfp_t gfp_mask,
+			pgprot_t prot, unsigned long vm_flags, int node,
+			const void *caller)
+{
+	void *res = NULL;
+
+	res = __vmalloc_node_range(size, align, start, exclusion_start,
+				gfp_mask, prot, vm_flags, node, caller);
+	if (!res)
+		res = __vmalloc_node_range(size, align, exclusion_end, end,
+				gfp_mask, prot, vm_flags, node, caller);
+
+	return res;
+}
+
+void *__vmalloc_node(unsigned long size, unsigned long align,
+			    gfp_t gfp_mask, unsigned long vm_flags, int node,
+			    const void *caller)
+{
+	return __vmalloc_node_range_split(size, align, VMALLOC_START,
+				VMALLOC_END, code_region_start, code_region_end,
+				gfp_mask, PAGE_KERNEL, vm_flags, node, caller);
+}
+
+void *vmalloc_huge(unsigned long size, gfp_t gfp_mask)
+{
+	return __vmalloc_node_range_split(size, 1, VMALLOC_START, VMALLOC_END,
+				code_region_start, code_region_end,
+				gfp_mask, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
+				NUMA_NO_NODE, __builtin_return_address(0));
+}
+
+void *vmalloc_user(unsigned long size)
+{
+	return __vmalloc_node_range_split(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
+				code_region_start, code_region_end,
+				GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
+				VM_USERMAP, NUMA_NO_NODE,
+				__builtin_return_address(0));
+}
+
+void *vmalloc_32_user(unsigned long size)
+{
+	return __vmalloc_node_range_split(size, SHMLBA,  VMALLOC_START, VMALLOC_END,
+				code_region_start, code_region_end,
+				GFP_VMALLOC32 | __GFP_ZERO, PAGE_KERNEL,
+				VM_USERMAP, NUMA_NO_NODE,
+				__builtin_return_address(0));
+}
+
diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
index 8955da5c47cf..40426f3a9bdf 100644
--- a/arch/arm64/net/bpf_jit_comp.c
+++ b/arch/arm64/net/bpf_jit_comp.c
@@ -13,6 +13,7 @@
 #include <linux/memory.h>
 #include <linux/printk.h>
 #include <linux/slab.h>
+#include <linux/moduleloader.h>
 
 #include <asm/asm-extable.h>
 #include <asm/byteorder.h>
@@ -1690,12 +1691,12 @@ u64 bpf_jit_alloc_exec_limit(void)
 void *bpf_jit_alloc_exec(unsigned long size)
 {
 	/* Memory is intended to be executable, reset the pointer tag. */
-	return kasan_reset_tag(vmalloc(size));
+	return kasan_reset_tag(module_alloc(size));
 }
 
 void bpf_jit_free_exec(void *addr)
 {
-	return vfree(addr);
+	return module_memfree(addr);
 }
 
 /* Indicate the JIT backend supports mixing bpf2bpf and tailcalls. */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220203256.31153-4-mbland%40motorola.com.
