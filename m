Return-Path: <kasan-dev+bncBCSL7B6LWYHBBHMG4CNAMGQEJ4YHWUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id CCEB060D0D5
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 17:39:10 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id m20-20020a056402511400b0045da52f2d3csf12361787edd.20
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 08:39:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666712350; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpYmYtrmjqvawkkLRIresDiQV8gMBAAR0wZoYc92HVn2FY2BkR5DJeFjfSBr2SzS6e
         iP0f/c/S+5LktG10xDrU/Xd1UnJBg+Lf3pzkRUoAzamWkEHAvbvXRS2Oi8V0ChpwyJj/
         EAu0/m+nEaZ3dvFPbwS+9x0tqIX5ck0VStMj5LZGHKI50tD+HUThHzggmkjFUrsVjhqi
         dHpT93iInzwzwXZB2tcTWc/v8kPX9LRu/K2Kl5v7oADnu0Dt7IZFWzP0pUvC+8Za3fCg
         kjX1fXPg65Ks2YzeZ0yRmtvJamFy+OGSD2j+hVmhpPMrQ18kGJMdnS+GkjEqDusC4kI6
         QfKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=dYTVBdwVzxVEmL38CulSNFN9D4w1oVbRixpF3vOoLxw=;
        b=hTvFIBKsDmzqU67ErNuMntodbvheknfcB7Vx7tHWknzgfbvEiaiWF29a4oMaVTjflc
         FnW1h9EytdTM6LFp5lP6jFdIeWFjiDE5EMJ8pyCFoyNcFgwK0usGD/1k8ixMqF10eMD1
         T/eMLYkCal2dIdWl5csBLGnSA4/aP5SmDBqt0Wsdzl48UnnALK7YRZ9/kcVb2c7B70CN
         XBtGS+o49Gl9HW/JNXAb7Zu574IGeHV6BBRss61Q/Pp9XvjeRjiZyz58/xKCqgbIlNQ2
         Tqv7k8HNtkhQbmZ5RqqJUhxD1jAT8WUKwZIeISEaBwFy0vBj07KIs8Icr+44OUmB5AtZ
         CTJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NHQQEGq7;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dYTVBdwVzxVEmL38CulSNFN9D4w1oVbRixpF3vOoLxw=;
        b=IhnMVXhXQyTtSMgkOwGtqVp/w32gf5AqxWGtbigwHUBuYU1M56SfjMwO1Tb4M7PLr6
         rgvET8vby4A4quIUVl0OaWxzLbsGpScOetp1AxEGwAUKMXlzoSC2vAIHhH0/fWZIVE6R
         YYrMljqH4K92Q67I/Kmv0OxbkQLuQa+Hj1znQBbfKqLf3EfRyE2cg7Q5OI9uX2/lVacs
         yP8FgdbaqTm4pqD/efZ3LdS7XKYAW+/QYaYxLO4F2DA4uanY4I0mpPAJHQZDSpkFoL0y
         6HVLou9RrZl4BbnngcbnZ230/jExhJgsiUMrVk6H5SbVIsqXKdevqSGh6v31mcNzSuEP
         WmOw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dYTVBdwVzxVEmL38CulSNFN9D4w1oVbRixpF3vOoLxw=;
        b=TjU1Mh6qJq4OsS+0LI0dTcYOFeYh38EpoebRc1q8lvC2XuL3Rzg6DRJgaEIlziprNR
         fNDbfo/+TqM5LqCc0XbSFxZvXdN7h2LiK2z0SDly64mYsPQ90HLh5H34hJL4NtAcdYBY
         Wx8fPWZ6saKwixNBhflwXaIvak+jfP7P7OD8qhDsGOX8BQOJDEUxw1L2mSBKjiBdR1Sb
         Ae11s+SSLjDhgtKf8XcMLVjU3UWoYr1Qwid6gGMos85C/3fAOGD/XfQAqd/yo9h0IPgS
         I1pVBOi/iSymoWuw5UUctZco0FfZfYftx/6CgDbupPjgRb6FKYPGkR5TVXX1z3r9DxfF
         7qvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dYTVBdwVzxVEmL38CulSNFN9D4w1oVbRixpF3vOoLxw=;
        b=FRe/YUzlsrRCMfR1L7H3/8DuWNYa+YVR52g+XwGf2wFNA6ZBIYXN9iwOC28ySUQIPK
         Cu7JBEZMEv4m9nJRjAn8wBfla5tpzh5VVqCmm7dPDKrKVeFLWND5v+jIvd+rmwv6oQSO
         TO35PXVjgY2ulI6TPhKq5gbX7+G7U0rD19oCN/c2zvu3lyZ5MrQ6dZFQ4fwIbzDWYjCa
         1ckk9yuH6TvOj/9qFC7MzS0s1Sz/0WPBqxf6yP/EFb8LOBzOthcdiH2/owU68/dVSjhL
         MlJjtQn1yBxefQpi7L45PvtUkrCK9j7yfwRLUcNvgDTsviVlwVlFyx7V+bNIEoFOe28w
         6Cxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1slSdB4wg4rBdC877BSiGoRf+tTsEX/CE8Zo+ylXt4LoAknMHY
	WSvLip68R/ZJD2BezL8/sAQ=
X-Google-Smtp-Source: AMsMyM6gaRrVunWaPe+divD1VziYUDOq25vklC8bG1n1mlFSkMVyUvhLm8wHR4rugbe+8etfMJMXcw==
X-Received: by 2002:a17:906:8b81:b0:78e:1cb:e411 with SMTP id nr1-20020a1709068b8100b0078e01cbe411mr32192382ejc.681.1666712350152;
        Tue, 25 Oct 2022 08:39:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:8616:b0:78d:14b3:67b2 with SMTP id
 o22-20020a170906861600b0078d14b367b2ls6661391ejx.7.-pod-prod-gmail; Tue, 25
 Oct 2022 08:39:08 -0700 (PDT)
X-Received: by 2002:a17:907:3f19:b0:7a3:2317:4221 with SMTP id hq25-20020a1709073f1900b007a323174221mr13428418ejc.562.1666712348759;
        Tue, 25 Oct 2022 08:39:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666712348; cv=none;
        d=google.com; s=arc-20160816;
        b=lx27pbnfx6qMaSmN1UHrXW5mIB2zockWGUWs18mtRZQjbyBvPd/f/B5VsF6p9pYJ6M
         2bYzEo1b/a2tV0x73v+tlinC7DMlWryXa9N9LXOuJYFfTSyRtol24WYqd3/GFZoRwtDt
         M5j/o4sWT9KmXVUIp8YQkH4pFXBdPDJKOUv5NJ494GcQKQH9tgVHoa4rz0FIA36+RGFM
         oQtMoYP3riCKq6poadycD2oxP3lmG4ERIRfEl4ENos1xYo7A6sS/Eul+7TJvqZJdKpN3
         P73CShHd4AuEkbr+G2DPTpF/Y52h31JyO8eYGypf13ImtibkK5ScIn4xr8QVLvnFmCAg
         /d5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Rc6vP6aw0tpiHFL5bJLFi2OMc2JAOBh2wNmcX8c+8ps=;
        b=tvNgflmz6yloKuKBX98KYoFe0ixnRrFEBl82vqvEVmZSdq+MuNmLG3ddP+t8rOM+ul
         06U5y/s5NCuyjcaREZ/kTuVc9PcVO7pQSP09O19ZrCo9zX8zwRQULHB0HaAS4pA7DFgP
         +P1yryx/1iynN0ebyGy1L6W5favLft6T6RtIzA82BeOPRF4jejuZ5qnTVbB+3nLbFU+v
         QR8MdhB5bK4qkAal1X8t4Y8W9jeoLxmtqCawVe4i1hgPihN3337X43hc3frqLmDMyDIQ
         xEnO2xBvLmyiw1ZRUtiOczIK1SonRPwgdcv5+8/32WxjSjteeWVZ5pEcblK39zAUE/HO
         EdOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NHQQEGq7;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id t11-20020aa7d4cb000000b0045757c7cb91si110792edr.4.2022.10.25.08.39.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Oct 2022 08:39:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id d6so22711491lfs.10
        for <kasan-dev@googlegroups.com>; Tue, 25 Oct 2022 08:39:08 -0700 (PDT)
X-Received: by 2002:a05:6512:261c:b0:49f:af36:d47 with SMTP id bt28-20020a056512261c00b0049faf360d47mr13775733lfb.284.1666712348133;
        Tue, 25 Oct 2022 08:39:08 -0700 (PDT)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id p8-20020a2eba08000000b0026e00df2ed0sm547761lja.30.2022.10.25.08.39.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Oct 2022 08:39:07 -0700 (PDT)
Message-ID: <278cc353-6289-19e8-f7a9-0acd70bc8e11@gmail.com>
Date: Tue, 25 Oct 2022 18:39:07 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [tip:x86/mm] [x86/mm] 1248fb6a82:
 Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page
Content-Language: en-US
To: Peter Zijlstra <peterz@infradead.org>,
 kernel test robot <yujie.liu@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com,
 Dave Hansen <dave.hansen@linux.intel.com>,
 Seth Jenkins <sethjenkins@google.com>, Kees Cook <keescook@chromium.org>,
 linux-kernel@vger.kernel.org, x86@kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "Yin, Fengwei" <fengwei.yin@intel.com>
References: <202210241508.2e203c3d-yujie.liu@intel.com>
 <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=NHQQEGq7;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12c
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 10/25/22 13:33, Peter Zijlstra wrote:
> On Tue, Oct 25, 2022 at 12:54:40PM +0800, kernel test robot wrote:
>> Hi Peter,
>>
>> We noticed that below commit changed the value of
>> CPU_ENTRY_AREA_MAP_SIZE. Seems KASAN uses this value to allocate memory,
>> and failed during initialization after this change, so we send this
>> mail and Cc KASAN folks. Please kindly check below report for more
>> details. Thanks.
>>
>>
>> Greeting,
>>
>> FYI, we noticed Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page due to commit (built with gcc-11):
>>
>> commit: 1248fb6a8201ddac1c86a202f05a0a1765efbfce ("x86/mm: Randomize per-cpu entry area")
>> https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git x86/mm
>>
>> in testcase: boot
>>
>> on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
>>
>> caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
>>
>>
>> [    7.114808][    T0] Kernel panic - not syncing: kasan_populate_pmd+0x142/0x1d2: Failed to allocate page, nid=0 from=1000000
>> [    7.119742][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc1-00001-g1248fb6a8201 #1
>> [    7.122122][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
>> [    7.124976][    T0] Call Trace:
>> [    7.125849][    T0]  <TASK>
>> [    7.126642][    T0]  ? dump_stack_lvl+0x45/0x5d
>> [    7.127908][    T0]  ? panic+0x21e/0x46a
>> [    7.129009][    T0]  ? panic_print_sys_info+0x77/0x77
>> [    7.130618][    T0]  ? memblock_alloc_try_nid_raw+0x106/0x106
>> [    7.132224][    T0]  ? memblock_alloc_try_nid+0xd9/0x118
>> [    7.133717][    T0]  ? memblock_alloc_try_nid_raw+0x106/0x106
>> [    7.135252][    T0]  ? kasan_populate_pmd+0x142/0x1d2
>> [    7.136655][    T0]  ? early_alloc+0x95/0x9d
>> [    7.137738][    T0]  ? kasan_populate_pmd+0x142/0x1d2
>> [    7.138936][    T0]  ? kasan_populate_pud+0x182/0x19f
>> [    7.140335][    T0]  ? kasan_populate_shadow+0x1e0/0x233
>> [    7.141759][    T0]  ? kasan_init+0x3be/0x57f
>> [    7.142942][    T0]  ? setup_arch+0x101d/0x11f0
>> [    7.144229][    T0]  ? start_kernel+0x6f/0x3d0
>> [    7.145449][    T0]  ? secondary_startup_64_no_verify+0xe0/0xeb
>> [    7.147051][    T0]  </TASK>
>> [    7.147868][    T0] ---[ end Kernel panic - not syncing: kasan_populate_pmd+0x142/0x1d2: Failed to allocate page, nid=0 from=1000000 ]---
> 
> Ufff, no idea about what KASAN wants here; Andrey, you have clue?
> 
> Are you trying to allocate backing space for .5T of vspace and failing
> that because the kvm thing doesn't have enough memory?
> 

KASAN tries to allocate shadow memory for the whole cpu entry area.
The size is CPU_ENTRY_AREA_MAP_SIZE/8 and this is obviously fails after your patch.
The fix this might be something like this:


---
 arch/x86/include/asm/kasan.h |  2 ++
 arch/x86/mm/cpu_entry_area.c |  3 +++
 arch/x86/mm/kasan_init_64.c  | 16 +++++++++++++---
 3 files changed, 18 insertions(+), 3 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 13e70da38bed..77dd8b57f1e2 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -28,9 +28,11 @@
 #ifdef CONFIG_KASAN
 void __init kasan_early_init(void);
 void __init kasan_init(void);
+void __init kasan_populate_shadow_for_vaddr(void *va, size_t size);
 #else
 static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
+static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size) { }
 #endif
 
 #endif
diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
index ad1f750517a1..602daa550543 100644
--- a/arch/x86/mm/cpu_entry_area.c
+++ b/arch/x86/mm/cpu_entry_area.c
@@ -9,6 +9,7 @@
 #include <asm/cpu_entry_area.h>
 #include <asm/fixmap.h>
 #include <asm/desc.h>
+#include <asm/kasan.h>
 
 static DEFINE_PER_CPU_PAGE_ALIGNED(struct entry_stack_page, entry_stack_storage);
 
@@ -91,6 +92,8 @@ void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags)
 static void __init
 cea_map_percpu_pages(void *cea_vaddr, void *ptr, int pages, pgprot_t prot)
 {
+	kasan_populate_shadow_for_vaddr(cea_vaddr, pages*PAGE_SIZE);
+
 	for ( ; pages; pages--, cea_vaddr+= PAGE_SIZE, ptr += PAGE_SIZE)
 		cea_set_pte(cea_vaddr, per_cpu_ptr_to_phys(ptr), prot);
 }
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index e7b9b464a82f..dbee52f14700 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -316,6 +316,19 @@ void __init kasan_early_init(void)
 	kasan_map_early_shadow(init_top_pgt);
 }
 
+void __init kasan_populate_shadow_for_vaddr(void *va, size_t size)
+{
+	unsigned long shadow_start, shadow_end;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(va);
+	shadow_start = round_down(shadow_start, PAGE_SIZE);
+	shadow_end = (unsigned long)kasan_mem_to_shadow(va + size);
+	shadow_end = round_up(shadow_end, PAGE_SIZE);
+
+	kasan_populate_shadow(shadow_start, shadow_end,
+			      early_pfn_to_nid(__pa(va)));
+}
+
 void __init kasan_init(void)
 {
 	int i;
@@ -393,9 +406,6 @@ void __init kasan_init(void)
 		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
 		shadow_cpu_entry_begin);
 
-	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
-			      (unsigned long)shadow_cpu_entry_end, 0);
-
 	kasan_populate_early_shadow(shadow_cpu_entry_end,
 			kasan_mem_to_shadow((void *)__START_KERNEL_map));
 
-- 
2.37.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/278cc353-6289-19e8-f7a9-0acd70bc8e11%40gmail.com.
