Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZGNZCPAMGQE5W2HCGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DEE767C4A4
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 08:08:21 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id d2-20020a0565123d0200b004d1b23f2047sf559897lfv.20
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 23:08:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674716900; cv=pass;
        d=google.com; s=arc-20160816;
        b=gyt3gMr2mCCLEb3r5gx4jdPj9gQC9sUa8n+Ba6Fn6V3MdDOcE22I7uAxyx4r3El3FG
         B/qChzK56uVqdi3WjXneh0gNVzRtKnG9mF/WHfUu1RXXaBOgoZVe18BtUHIl3JC8Ocer
         sKGwrHJsmSnATVYBRmH+S5Dcd4cy19NMkGf8XtXYTzaS9HtSt3YqgCfuqZkILMsiyv4R
         vFleMYTeCtRbczoY6BznMTFk6IOf+SjQkYNUnXJL6RjZlUByFTftLprkFfSurDBuaRRF
         m6U0Ci0HdNc9UmSsIWKcK32qOHvtmyrcqdVbcTEvbzw+kLErM7ZN3nRRTntg+99iKOT3
         2OaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=CnI5NvZ6B6DJ/HbU2wfqmc9ygOksY6K40z4i8rCKiXU=;
        b=1H2OlzKULLAbmVRiwYa9uLZzODmjvXfGT+fQqkbMrBemPw821nqgSMHa/SIdsae6a6
         Sk4kSqO3kLE+dobfQtBvnbM3a+4S+qu98pbF3O5DBOCj5E1jRU+6Vb3sFVVaka8WJP4W
         z3nXQZ2OmVFPvp/itWammtmXM/GUfkpeefPKyI5KbLKzMn08tijaSaqZ70cPYlK+H0PC
         ckqg3g0E6uqaCI6qhI2zI1hAaEKYscmGwNON/egeR+BIGC8Ra/8veybZqmfdYi76MVKK
         bmoo4NbsDd5il4QNj1eIpdjQygfXcpzro/VlcvRhpUAb7MF3ZxHQeRcYFmPcuOJM+7YY
         KfXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CnI5NvZ6B6DJ/HbU2wfqmc9ygOksY6K40z4i8rCKiXU=;
        b=BodlkTNxNQXXlvgs6l4vIzkt3VeZR+gO1X6CFv51wUZWlRTg/BQDSABq4i5Ly+XoGg
         4LwtMGJQFwMaOFaQp+wNG+HuV/q5kTAURUy0H/0wvYUFC1vLzjtNelZBbMkrm8UDZU9l
         AEdPT4rwPEnTuJepEwo261SYuJ5Fj3ANCE/VtbcS/cj6+idxMhoCnW83Lny5FqbYlinq
         AiJqIX+Dt6h3/lJSEt55eNRx/NxHzhyZtGJyYHxL5KJ04WRpCS9xrt+8aqpAesr8VWIq
         pBpN0B5WegI6RvrhCbt16EJ+qT3xSKPwXqUkf7h6a2FC0TLipG4TpE5mAbwE3++V6Lg5
         mU/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CnI5NvZ6B6DJ/HbU2wfqmc9ygOksY6K40z4i8rCKiXU=;
        b=LqLjBXGpnokYZoo6KsEuPm7AwMUNxc3EHngbRmEM9I7/v2PdtiO+yPYwS7QMfOuFOt
         jP/bALQytESzJbNaub99EkKweFuIlgTOZDxxUY+4L2Ai/zmjR6pdd9J1kP821qTEiJ5c
         HqwQ9bfkQNBWYgIjyKsAD3glbIJ0QNXG/t0lycHuQ+M04vKqDSVFduk17VCxiuMiYpoQ
         d0JbsfssPXDwcGelo6CMXjMTKervNmDbAYEtRZq8IDj/YRLaSnnB0V08TqetKt6tCqNm
         BJIKBjdMYLWDHARAA1SAdeLYRQmwYDjhtijOvR4XwtRzxaeO1ccyqi4pzR890dCXnRER
         dm3A==
X-Gm-Message-State: AFqh2kqx/vCbzPjY9t7c/gwR0ci/yio7Zb2Qe5nh5N9+quFAilR7trMn
	hkHy3A7LphFoynB2AArHAPI=
X-Google-Smtp-Source: AMrXdXu6V8hlEJeE3LjJ5J5M7hqfEcwJ5vbsoheyEckus8BD5ixq5Wtks84KS9VO9RMLnngSEzc33g==
X-Received: by 2002:a05:6512:36c1:b0:4b5:6cff:a6f2 with SMTP id e1-20020a05651236c100b004b56cffa6f2mr2058717lfs.340.1674716900475;
        Wed, 25 Jan 2023 23:08:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls723341lfc.0.-pod-prod-gmail;
 Wed, 25 Jan 2023 23:08:19 -0800 (PST)
X-Received: by 2002:ac2:50cf:0:b0:4d5:7f73:e894 with SMTP id h15-20020ac250cf000000b004d57f73e894mr7553918lfm.19.1674716899087;
        Wed, 25 Jan 2023 23:08:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674716899; cv=none;
        d=google.com; s=arc-20160816;
        b=kB2i9LdFsur21FmgoDzGF/W6j2/QE4+SDrcwVvWk4XL+gXX5q1RzxpF4lLBSZFL//x
         AzsGIaKlb9nC4X5UehLQHVS29NjTy3eg/vAjKJVaYXzbjHvHS/ToumfLblouXYG4Ew9T
         53UV9RvugkJaNK3uHz48Wq06wMpNsOwTd1dX3GegQJq0MACh1mdDbZ4S8ShVA5RY7m8C
         60sXk3USOec2//94Z7U0UE2FXBurwruanGj9wOzcjJzguVn2ck7ncPopVZ1Qd7p3PD5b
         LwTIApl0XmEpjk0GKxlnsG7LKNsJvbMFlqHy1VkkhzPXVvYu3J4LvoKMEtA5KO9t1Cww
         2pyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=NnEClH9buGlde9xoDbgRujb6/SO7GUV1JxVEplD1JL4=;
        b=MkY/81Nxh1dnqoJ1P878WrtmW7NOHM19fDnk/10BU4qFy7WCL4WifxmoVybsg6BYCC
         L+pC+HujLjtaLOoEz1QrFkfDycPk2/IvVY9zE3tN8VH6LkU3eQu8NdoUKTnIaMA+wpnB
         y1sb9//f/ym/9/HIsoM32rjO+oMKT8Ok3zi/mgTraTcvVqv2d1HPreBq/W8Lo/zZJ9q8
         OcNevJH6xO8oMjB5MU3pRYb9kF0NF0IzQkTSHF/lqG3HZumPGvsNNa8PTllnI5EEJILb
         HLjpUMSqFsv/pB+LPwmyyWpESv8RVkvmHBw+KYj//lQ0kO4ROz0zCSXfWXbuTZztp5Xy
         5XnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id x8-20020a056512130800b004ce3ceb0e80si24607lfu.5.2023.01.25.23.08.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 23:08:19 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4P2WyB0M6Yz9sd7;
	Thu, 26 Jan 2023 08:08:18 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id zR25zrkcDSUr; Thu, 26 Jan 2023 08:08:17 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4P2Wy863Mpz9sdB;
	Thu, 26 Jan 2023 08:08:16 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BF56E8B76D;
	Thu, 26 Jan 2023 08:08:16 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 2SJtYN5JNx8I; Thu, 26 Jan 2023 08:08:16 +0100 (CET)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [192.168.5.2])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 800A48B763;
	Thu, 26 Jan 2023 08:08:16 +0100 (CET)
Received: from PO20335.IDSI0.si.c-s.fr (localhost [127.0.0.1])
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.16.1) with ESMTPS id 30Q74xEu2764291
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Thu, 26 Jan 2023 08:04:59 +0100
Received: (from chleroy@localhost)
	by PO20335.IDSI0.si.c-s.fr (8.17.1/8.17.1/Submit) id 30Q74uJB2764288;
	Thu, 26 Jan 2023 08:04:56 +0100
X-Authentication-Warning: PO20335.IDSI0.si.c-s.fr: chleroy set sender to christophe.leroy@csgroup.eu using -f
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Andrew Morton <akpm@linux-foundation.org>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
        linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        Nathan Lynch <nathanl@linux.ibm.com>,
        Michael Ellerman <mpe@ellerman.id.au>
Subject: [PATCH] kasan: Fix Oops due to missing calls to kasan_arch_is_ready()
Date: Thu, 26 Jan 2023 08:04:47 +0100
Message-Id: <150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu>
X-Mailer: git-send-email 2.38.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=ed25519-sha256; t=1674716683; l=7054; s=20211009; h=from:subject:message-id; bh=GpOaHGWHkRLK3w+qELfaGMG8mIxKwVDUBSOVaCUA3e0=; b=ur0fVC6TvQtoPHkKCNrcuxg4+ha3+GW2lsw3we8TWNoDIr2bcKf4t9U+usHU28Jq1T1cwH+xi8we gQ/xU8BbDUDZD3kTNEGCjWsEj23j+wSD3T9zmXq7qSmIg6Q5Wby+
X-Developer-Key: i=christophe.leroy@csgroup.eu; a=ed25519; pk=HIzTzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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

On powerpc64, you can build a kernel with KASAN as soon as you build it
with RADIX MMU support. However if the CPU doesn't have RADIX MMU,
KASAN isn't enabled at init and the following Oops is encountered.

  [    0.000000][    T0] KASAN not enabled as it requires radix!

  [    4.484295][   T26] BUG: Unable to handle kernel data access at 0xc00e000000804a04
  [    4.485270][   T26] Faulting instruction address: 0xc00000000062ec6c
  [    4.485748][   T26] Oops: Kernel access of bad area, sig: 11 [#1]
  [    4.485920][   T26] BE PAGE_SIZE=64K MMU=Hash SMP NR_CPUS=2048 NUMA pSeries
  [    4.486259][   T26] Modules linked in:
  [    4.486637][   T26] CPU: 0 PID: 26 Comm: kworker/u2:2 Not tainted 6.2.0-rc3-02590-gf8a023b0a805 #249
  [    4.486907][   T26] Hardware name: IBM pSeries (emulated by qemu) POWER9 (raw) 0x4e1200 0xf000005 of:SLOF,HEAD pSeries
  [    4.487445][   T26] Workqueue: eval_map_wq .tracer_init_tracefs_work_func
  [    4.488744][   T26] NIP:  c00000000062ec6c LR: c00000000062bb84 CTR: c0000000002ebcd0
  [    4.488867][   T26] REGS: c0000000049175c0 TRAP: 0380   Not tainted  (6.2.0-rc3-02590-gf8a023b0a805)
  [    4.489028][   T26] MSR:  8000000002009032 <SF,VEC,EE,ME,IR,DR,RI>  CR: 44002808  XER: 00000000
  [    4.489584][   T26] CFAR: c00000000062bb80 IRQMASK: 0
  [    4.489584][   T26] GPR00: c0000000005624d4 c000000004917860 c000000001cfc000 1800000000804a04
  [    4.489584][   T26] GPR04: c0000000003a2650 0000000000000cc0 c00000000000d3d8 c00000000000d3d8
  [    4.489584][   T26] GPR08: c0000000049175b0 a80e000000000000 0000000000000000 0000000017d78400
  [    4.489584][   T26] GPR12: 0000000044002204 c000000003790000 c00000000435003c c0000000043f1c40
  [    4.489584][   T26] GPR16: c0000000043f1c68 c0000000043501a0 c000000002106138 c0000000043f1c08
  [    4.489584][   T26] GPR20: c0000000043f1c10 c0000000043f1c20 c000000004146c40 c000000002fdb7f8
  [    4.489584][   T26] GPR24: c000000002fdb834 c000000003685e00 c000000004025030 c000000003522e90
  [    4.489584][   T26] GPR28: 0000000000000cc0 c0000000003a2650 c000000004025020 c000000004025020
  [    4.491201][   T26] NIP [c00000000062ec6c] .kasan_byte_accessible+0xc/0x20
  [    4.491430][   T26] LR [c00000000062bb84] .__kasan_check_byte+0x24/0x90
  [    4.491767][   T26] Call Trace:
  [    4.491941][   T26] [c000000004917860] [c00000000062ae70] .__kasan_kmalloc+0xc0/0x110 (unreliable)
  [    4.492270][   T26] [c0000000049178f0] [c0000000005624d4] .krealloc+0x54/0x1c0
  [    4.492453][   T26] [c000000004917990] [c0000000003a2650] .create_trace_option_files+0x280/0x530
  [    4.492613][   T26] [c000000004917a90] [c000000002050d90] .tracer_init_tracefs_work_func+0x274/0x2c0
  [    4.492771][   T26] [c000000004917b40] [c0000000001f9948] .process_one_work+0x578/0x9f0
  [    4.492927][   T26] [c000000004917c30] [c0000000001f9ebc] .worker_thread+0xfc/0x950
  [    4.493084][   T26] [c000000004917d60] [c00000000020be84] .kthread+0x1a4/0x1b0
  [    4.493232][   T26] [c000000004917e10] [c00000000000d3d8] .ret_from_kernel_thread+0x58/0x60
  [    4.495642][   T26] Code: 60000000 7cc802a6 38a00000 4bfffc78 60000000 7cc802a6 38a00001 4bfffc68 60000000 3d20a80e 7863e8c2 792907c6 <7c6348ae> 20630007 78630fe0 68630001
  [    4.496704][   T26] ---[ end trace 0000000000000000 ]---

The Oops is due to kasan_byte_accessible() not checking the readiness
of KASAN. Add missing call to kasan_arch_is_ready() and bail out when
not ready. The same problem is observed with ____kasan_kfree_large()
so fix it the same.

Also, as KASAN is not available and no shadow area is allocated for
linear memory mapping, there is no point in allocating shadow mem for
vmalloc memory as shown below in /sys/kernel/debug/kernel_page_tables

  ---[ kasan shadow mem start ]---
  0xc00f000000000000-0xc00f00000006ffff  0x00000000040f0000       448K         r  w       pte  valid  present        dirty  accessed
  0xc00f000000860000-0xc00f00000086ffff  0x000000000ac10000        64K         r  w       pte  valid  present        dirty  accessed
  0xc00f3ffffffe0000-0xc00f3fffffffffff  0x0000000004d10000       128K         r  w       pte  valid  present        dirty  accessed
  ---[ kasan shadow mem end ]---

So, also verify KASAN readiness before allocating and poisoning
shadow mem for VMAs.

Reported-by: Nathan Lynch <nathanl@linux.ibm.com>
Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
 mm/kasan/common.c  |  3 +++
 mm/kasan/generic.c |  7 ++++++-
 mm/kasan/shadow.c  | 12 ++++++++++++
 3 files changed, 21 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 833bf2cfd2a3..21e66d7f261d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -246,6 +246,9 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 {
+	if (!kasan_arch_is_ready())
+		return false;
+
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index b076f597a378..cb762982c8ba 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -191,7 +191,12 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 
 bool kasan_byte_accessible(const void *addr)
 {
-	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+	s8 shadow_byte;
+
+	if (!kasan_arch_is_ready())
+		return true;
+
+	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
 
 	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
 }
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 2fba1f51f042..15cfb34d16a1 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -291,6 +291,9 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
+	if (!kasan_arch_is_ready())
+		return 0;
+
 	if (!is_vmalloc_or_module_addr((void *)addr))
 		return 0;
 
@@ -459,6 +462,9 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
+	if (!kasan_arch_is_ready())
+		return;
+
 	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
 	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
@@ -502,6 +508,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
 
+	if (!kasan_arch_is_ready())
+		return (void *)start;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
@@ -524,6 +533,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
+	if (!kasan_arch_is_ready())
+		return;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-- 
2.38.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy%40csgroup.eu.
