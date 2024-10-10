Return-Path: <kasan-dev+bncBAABBHM6TW4AMGQEHTCCADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C92B997B79
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 05:50:55 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6cbc68c6a62sf10168256d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 20:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728532254; cv=pass;
        d=google.com; s=arc-20240605;
        b=cZffd+p2PUTXyDmZHG2+c9HN7kv5vAFfsO3F9KKgnlNbi61jww4sg9nbe4pEWNponp
         C13ltHUcByiRw1L0OeWI+kJasWRLMqotF5AwD3QE+DUNB1FnoJrU8kVOBjP0opPu93cI
         bSWp5afGjH5R4LDCgtt8vimc7dBXKc2T93UoSjMwqz2KfilBKHQpeoV5fan5YcrHfP2V
         mWbe4fTXM1xZAzK0DWdm/f//cDctm3jEjUZyJLxgbUeH1pkBha3DyCbiSfc4sl/MlTC+
         enpjWIPt9Ci5xyNqhLHq1gayXRq9LkrsANrZAwRfZTbkR1J9NjKdWCm/P6jXjNX7+wRS
         J7hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FA6BNWjBrvs0PMqatQUvB69fXFukgl2T/tr4YACDe70=;
        fh=OmgjPkogoLP0S/iagM/YGsLcDJwiMzRDZbpqCjhEDeM=;
        b=QABpsxBW5tH7vPohf6D/AVrboNnqeJrNyUZC12Mc9ikE6lbgL/tNJj06aVDJICFtrG
         Rv3EfftepnYB070i6FmnWGrz0hH/VBDLq0mywAs08YXB3FfsnAtreExGxfydW7Sj9cFi
         UcSIgmA/s0DmfvI1Xo++jC/sFahTRe2Vi0LKm2XBwwAfo6bqqQJRdIxTy0537LdW9Fbw
         /9OxyQdbxXvE+gPeOi1kV+pOGPkmwkiPcx/QA9iMeJkMqVNdBzgwgYaRkyqYGwZ7/mdd
         qsaxzzZQ/lPuqjSaBPcNPgPsrLQoECPEcvGnTXrahkZZZcH0WaufL1BJjBu3cz5nozy0
         OHrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728532254; x=1729137054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FA6BNWjBrvs0PMqatQUvB69fXFukgl2T/tr4YACDe70=;
        b=s+EvYaFE2eJ87lCfqCgFUSHleUgFJOWhnMGsaan0kAckOswBEe9J/cPzu9n9BTChxi
         CYR7vy6J+G4Ha8QPwvw91uMK2Sl1UjOBdsP3QawQ+W3djWNcuCZxnxDQMcVyOs333gI3
         t2ASQGIAr5dyVUrM39W/kV3zlrf5f4zerLMVH0GCWHgEcmFeN2AJ03kze9wxUdZHhG14
         ZrYAIyGv7sj11WlsBdB30oSlLaOIlia+mKfLFtd6b/1toCzr/VX0ZROB0VPxH2tu4jGC
         HqS841wBLNwiSa/T50mz5uAaaTfpJIlMWPY0ErfTyoBQxPEdXTJxfAFNBtL+ln0jWaT7
         92Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728532254; x=1729137054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FA6BNWjBrvs0PMqatQUvB69fXFukgl2T/tr4YACDe70=;
        b=daqOMNRIafmnY0u5Jxi8Oc9Zuqm2GC76NIIr5b+i4iS8vWUbr8MKZzPIepRLi7Z/jV
         kOrocTNKRyUdCaf9E5JiLPiJYGE4L4QEuMe9MHLru+rW4bUNpmHmpwKLul26ntuSH9gx
         r2k07BrcusJxCtXxoENulFIvRtznM1xBwyjBQ6b4Rd4nLN5y5SC7HiHXDgYVWuASNTCK
         3melaUWOKdv0H8Yr1e2KxBQcoZETCAHWZEQq6mA6BuMTLeRraTmLXtvtD5jUBkU3ydEY
         EuOrfl/IkGl+yULJaw4aix9x1M4uV21q8Q6ah6Dt/7W5UyjiMGqkkU0I1HQ8zw83mqMA
         XDFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLlpTbsQ0/d7aDz+ICcghH+Ob82kkMeq8RMCyJ0A8YbcBxpLj3D0GoGDX5TvNKdWy0oE+TXg==@lfdr.de
X-Gm-Message-State: AOJu0YyZy0QfnxAnG/KUtwqGQCYf6wvGemOd63RIyl1Hpl05ZV7VYHSl
	5ez8sE5ALUVw9skw37YXgu9xABuE1IMowXTKT93ZEGcRDOltdzIf
X-Google-Smtp-Source: AGHT+IGZuv8zQoSMinDuHhIi5u0xT2/+fECs/buFoeC5k1VK8Vg7o9NuWdfrkczPid9dvfCKXy2l2g==
X-Received: by 2002:a05:6214:4982:b0:6cb:370b:d5c0 with SMTP id 6a1803df08f44-6cbc9548c90mr93853906d6.34.1728532253727;
        Wed, 09 Oct 2024 20:50:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:21c4:b0:6cb:7ce9:f52c with SMTP id
 6a1803df08f44-6cbe549245fls11322616d6.0.-pod-prod-07-us; Wed, 09 Oct 2024
 20:50:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmawUXv50dZY9e68W/zM12VMPCOZdL2aaXMJIaEr0CwfCTvS9kfmaLC5y2cEXEhLYXXR5QwfbpvnM=@googlegroups.com
X-Received: by 2002:a05:6214:2c01:b0:6cb:2e7c:a10e with SMTP id 6a1803df08f44-6cbc9581aa5mr67968756d6.48.1728532253166;
        Wed, 09 Oct 2024 20:50:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728532253; cv=none;
        d=google.com; s=arc-20240605;
        b=h1/iKSO+0ShhZPmtjChUD8vV03u8/GTr/k4wmma3OhilSBRdRHdSrYFcLPp/1vSSjM
         Rb0Ev9BUV8MAEpHfdABRKkIPvWB0EmGmwZa8kfhTdWTM/9huyt7Gz5rrGXejSH6w9wV4
         Xvob3NBT22rHu1D6sC7v/h0g+DPUFNmFnSNJSsGciaqTS3sR75SRBZu2/K+btrKPGk2z
         1Wpn998qu88RhC7hg7tb/S67Vi+r+0LwWl4eTMv5QDFtC3uRp0p/YnE2zurjM0UjJoWz
         S5YT/5yfZ/1MZUicc6g4QnlrCas5ImFs6Bj60QV6jooL/LIWfeTbQX3E+bjFS7sXzwpL
         BG/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=SY+h6Ni7p6nx6T0SONPCF3V0fwnPtdpc12KhvEyP5Mk=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=en+MaxQgmoYfq2LKyX5lAGU8PEaLkFMonw6jy4BoNJhFg/Q9Azjvvb+glXtLXBiF3F
         Kzz4Sd8OJ7/rGGFLEAZYPnRVdZFfE9lD3vLaRarIo3vxKuSKYtXWMusl5JxSPGBsJ/u3
         YQ4AWnxMJofOfNbPdQZ7Jo8A76GH+GwCaqPr1/d7ZQpOijrV4gjLD5/Q2Sk8Hkz2fh/j
         AGkfAwNTUklJM1wkZ3VT6CP60XwWMWHUBQGnHGqNjtrAMIT5e0dyBsIdacpAxPhQ86h8
         3FXx+4fnIBd72JqH4fIKb4L1HyoBYY75h2kx2riNVKCuATEP+pW5iaOuyph870EPEIce
         f8lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-460427d44acsi230781cf.2.2024.10.09.20.50.51
        for <kasan-dev@googlegroups.com>;
        Wed, 09 Oct 2024 20:50:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8DxurIZTwdnvLsRAA--.25092S3;
	Thu, 10 Oct 2024 11:50:49 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMDx7tUZTwdnFP8hAA--.52915S2;
	Thu, 10 Oct 2024 11:50:49 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 0/4] LoongArch: Fix vmalloc test issue
Date: Thu, 10 Oct 2024 11:50:44 +0800
Message-Id: <20241010035048.3422527-1-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: qMiowMDx7tUZTwdnFP8hAA--.52915S2
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

On LoongArch 3C5000 Dual-Way machine, there are 32 CPUs and 128G RAM,
there are some errors with run vmalloc test with command like this
  insmod test_vmalloc.ko   nr_threads=32  run_test_mask=0x3af

Here is part of error message,
 WARNING: CPU: 13 PID: 1457 at mm/vmalloc.c:503 vmap_small_pages_range_noflush+0x388/0x510
 CPU: 13 UID: 0 PID: 1457 Comm: vmalloc_test/15 Not tainted 6.12.0-rc2+ #93

 Trying to vfree() nonexistent vm area (000000004dec9ced)
 WARNING: CPU: 3 PID: 1444 at mm/vmalloc.c:3345 vfree+0x1e8/0x4c8
 CPU: 3 UID: 0 PID: 1444 Comm: vmalloc_test/2

 Trying to vfree() bad address (00000000fc7c9da5)
 WARNING: CPU: 10 PID: 1552 at mm/vmalloc.c:3210 remove_vm_area+0x88/0x98
 CPU: 10 UID: 0 PID: 1552 Comm: kworker/u144:3

The mainly problem is that function set_pte() and pte_free() is atomic,
there is contension between them. Since these functions need modify
two consecutive pte entries for kernel space area, to assure that both
pte entries with PAGE_GLOBAL bit set.

With this patchset, vmalloc test case passes to run with command
  insmod test_vmalloc.ko   nr_threads=32  run_test_mask=0x3af

Bibo Mao (4):
  LoongArch: Set pte entry with PAGE_GLOBAL for kernel space
  mm/sparse-vmemmap: set pte_init when vmemmap is created
  LoongArch: Add barrier between set_pte and memory access
  LoongArch: Use atomic operation with set_pte and pte_clear function

 arch/loongarch/include/asm/cacheflush.h | 14 +++++++-
 arch/loongarch/include/asm/pgalloc.h    | 13 +++++++
 arch/loongarch/include/asm/pgtable.h    | 45 +++++++++----------------
 arch/loongarch/mm/init.c                |  4 ++-
 arch/loongarch/mm/kasan_init.c          |  4 ++-
 arch/loongarch/mm/pgtable.c             | 22 ++++++++++++
 mm/sparse-vmemmap.c                     |  5 +++
 7 files changed, 75 insertions(+), 32 deletions(-)


base-commit: 87d6aab2389e5ce0197d8257d5f8ee965a67c4cd
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241010035048.3422527-1-maobibo%40loongson.cn.
