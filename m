Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBG6MRLYQKGQE4DPHEEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id BDBF9141631
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 07:30:52 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id t10sf14438654otc.9
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 22:30:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579329051; cv=pass;
        d=google.com; s=arc-20160816;
        b=wH81k5SoDlq+LqiKHBLH9v8SdRSUaYT8JRPparyORsds8QtqlqLSNv1dzwJ4GrCZOZ
         yz5qG8pQV+LHPr6FAaniIqhWI4hTUsW2pmzhunSoxSd8XXo6K57Pk0D861t6bU+0Xn0U
         a6LkLWv5VxQSCiBMsh2hUc0hC8e+7XRZGDSuOXiWBygc2Bin/I7gJrehVhL/KJWHzTzd
         kuvXQNCQlqn3RROklx20dO5ebL5SUxymGP5gzgRq9W3711ug06w5yE441DUopiH0FfOP
         fRynqst/vFhQT7ANVqmHs8+MSm18xAhyCojkvZt2QSlOO5lY7AdNpHrgR3CLTJoH9gNm
         lusA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fKUGTSLmnwZGdjAyuA6vMJKNd5jIMTmpcC3Vf6du/NM=;
        b=eyNQg5T7sci3nw/TnxeYhMggejo8N4RTfb0htkL2L/viHAsdfRlKmBaMT8yNgR88/h
         lCQw20QMMWDfmSLqVmhZ0EnO7ahOvfnPfjNtQ7cKkmKeu9+cWl7E10xj9yxVcSBpHSmT
         QYT0m7EUJGSaHqHrK9rHQ/shTFoOaNFFnj2+kLHUuk4VXa+vGolJLkYL2OQVczj7rSuO
         FXB7mkjbCCUBoAI/van67KlwUCWQXVYDOmxjQvrCicCQg0Xtb26CG7l/vf2AH15S7Dtm
         AuCLtj9ev2tDUu6kDaPT/Jl1JQYpf220iVMTSRmYZyruFg879NS5gOTuJ57Idu8bHytF
         Q7Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=eUVvGMBg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fKUGTSLmnwZGdjAyuA6vMJKNd5jIMTmpcC3Vf6du/NM=;
        b=dYANX/1D/lC/biRXR4ecE5rvRsvnpPJPc3zzuo3CLFC6CBOpvgqPGZgEzaE6DMTouq
         fbApV7MVsJs2YL94JieQSY17NukkiCQVtrSq7H4ylL720+0NZ4g8X+PMnrYokKW70dwL
         4n4PgkovMnnptJdTu6PqotuXdxZB3ho8H5y0hpLpfpkznCuUa7P8/XJVlr4gikFKRqpu
         xXxUJ0u09+Qel3BwgjK0mOzYiOyhA6zZSy5C0K9mnr2t+QjyX5SJAJHr/2CclwSMYsuO
         fT/jQrBddGd6b6JhzWNlC5F46q2+uTYV682e+twwmYJrhPOaahWUbozbojWd23HhJ4Ac
         uGcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fKUGTSLmnwZGdjAyuA6vMJKNd5jIMTmpcC3Vf6du/NM=;
        b=kYg2WPB9r00McL1CdWtmTfd+c36JAdkNILMi2zQGKuDi1javTpsdwl+Pe5ubVJ4Ubq
         oitzpJQKmfdAEQMKjxeuHrO5W/WuzOyagjL3f80aEZBpMhaXbvACqr2gj6Na14x6GAks
         jIG2fe3kY5AZwyUZPv9cyPoDWiWq4LWBIVJJOGupdszVgFXouK5PAA5BiUV5TkdycSjT
         p6icPoB7YLiLC0ixXswaEp4oH+y5tgzc2SQYrafdRLLWpxTK7dEqAiyjCCvH/S+jGPJB
         HnQGIxZVjlo6wPUZ5kU+AUeKdQtrjp90OPVGk+lwIJONXnkrRd4+nR9abfDzJ+b2fiGF
         Brqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUgZut+OooM5LaaDgrUxf87NDiaTeNx4WlgtYNS0gS9+kFkl+S+
	WhT2LLCnQP6gEyEsrzm8JBg=
X-Google-Smtp-Source: APXvYqy8m7iFek2Oo7XGz+licV8URYo55kqQWoZZEXdO+r604RT0VKp2o0hU1MkjXbgHaDY9yjDX1g==
X-Received: by 2002:a9d:6c06:: with SMTP id f6mr9131776otq.318.1579329051314;
        Fri, 17 Jan 2020 22:30:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60d0:: with SMTP id b16ls5041415otk.0.gmail; Fri, 17 Jan
 2020 22:30:50 -0800 (PST)
X-Received: by 2002:a05:6830:1442:: with SMTP id w2mr9153527otp.143.1579329050890;
        Fri, 17 Jan 2020 22:30:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579329050; cv=none;
        d=google.com; s=arc-20160816;
        b=oUMs/cSZjlfGCTV2WmXShRQv8ERus+e0qx3mlFIHtJr4cnvaruAuC6FSbpysSe8euz
         TIb+/BvZV+6R/cPDRtPXdx3RC3bdAO0A2A00Zw0wDA0E2AiYWAs2WhlVamn2LRC3gn6B
         no7mdUYy2joIPeBiBWgkxYOe3+UwhLZbNd9hWYIHQCpuGPLo25iCOq9wubmIBzmLXb3s
         tKHKtmqG22oM7ss5OhwbKj0nre8VfuAcuJMDWEEaujRYEZpoJrbOEsBujs4J0oZq61qz
         hcE/brwXUXDF1wV+nnNCx08EjegmWriD68CpcslCFf47jjIH1I3vbB//Gq3Bm7WtkjDw
         fpRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=rS4UKrLn3wFLir64JOAKmcnkWFvXo9oMWz1xNRyZqa0=;
        b=aAEF8T2bYF/LM2wH0713hU/y0BFTKkXylpVI0irVlr9/fOTxW6Cy7c7aLpPF7EpCab
         fruzvg4vHrljYbEZfJf9183RuGAegD7O7Ez8h7aVxc0ut42B/wQDzKf2krseq/gfjNPc
         2qtw626lhi86NRxDfCZXFSCrpX5T6IFaa0c8sUpS+4q4cvMvn7dMIOmal+FBdsh8jwZn
         NzsN8lEdsGEW3Dyibxxpp1o+VLvH8RHXhFJwyv4BTjkCX+1ybSycLXPCtMvv2KCfj75K
         UPI/WGs1WeJCyA3VI+dGqUeQIDSIf7muV/ydiuRGWTjD4LifiiX5cz62AV23Rz21bXX+
         aDuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=eUVvGMBg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id d189si935556oif.0.2020.01.17.22.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 22:30:50 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id x1so11768450qvr.8
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 22:30:50 -0800 (PST)
X-Received: by 2002:a05:6214:287:: with SMTP id l7mr11513554qvv.142.1579329050165;
        Fri, 17 Jan 2020 22:30:50 -0800 (PST)
Received: from ovpn-120-112.rdu2.redhat.com (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id u55sm14693498qtc.28.2020.01.17.22.30.48
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 22:30:49 -0800 (PST)
From: Qian Cai <cai@lca.pw>
To: ardb@kernel.org
Cc: mingo@redhat.com,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
Date: Sat, 18 Jan 2020 01:30:22 -0500
Message-Id: <20200118063022.21743-1-cai@lca.pw>
X-Mailer: git-send-email 2.21.0 (Apple Git-122.2)
MIME-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=eUVvGMBg;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f43 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

The commit 698294704573 ("efi/x86: Split SetVirtualAddresMap() wrappers
into 32 and 64 bit versions") introduced a KASAN error during boot,

 BUG: KASAN: user-memory-access in efi_set_virtual_address_map+0x4d3/0x574
 Read of size 8 at addr 00000000788fee50 by task swapper/0/0

 Hardware name: HP ProLiant XL450 Gen9 Server/ProLiant XL450 Gen9
 Server, BIOS U21 05/05/2016
 Call Trace:
  dump_stack+0xa0/0xea
  __kasan_report.cold.8+0xb0/0xc0
  kasan_report+0x12/0x20
  __asan_load8+0x71/0xa0
  efi_set_virtual_address_map+0x4d3/0x574
  efi_enter_virtual_mode+0x5f3/0x64e
  start_kernel+0x53a/0x5dc
  x86_64_start_reservations+0x24/0x26
  x86_64_start_kernel+0xf4/0xfb
  secondary_startup_64+0xb6/0xc0

It points to this line,

status = efi_call(efi.systab->runtime->set_virtual_address_map,

efi.systab->runtime's address is 00000000788fee18 which is an address in
EFI runtime service and does not have a KASAN shadow page. Fix it by
doing a copy_from_user() first instead.

Fixes: 698294704573 ("efi/x86: Split SetVirtualAddresMap() wrappers into 32 and 64 bit versions")
Signed-off-by: Qian Cai <cai@lca.pw>
---
 arch/x86/platform/efi/efi_64.c | 9 ++++++---
 1 file changed, 6 insertions(+), 3 deletions(-)

diff --git a/arch/x86/platform/efi/efi_64.c b/arch/x86/platform/efi/efi_64.c
index 515eab388b56..d6712c9cb9d8 100644
--- a/arch/x86/platform/efi/efi_64.c
+++ b/arch/x86/platform/efi/efi_64.c
@@ -1023,6 +1023,7 @@ efi_status_t __init efi_set_virtual_address_map(unsigned long memory_map_size,
 						u32 descriptor_version,
 						efi_memory_desc_t *virtual_map)
 {
+	efi_runtime_services_t runtime;
 	efi_status_t status;
 	unsigned long flags;
 	pgd_t *save_pgd = NULL;
@@ -1041,13 +1042,15 @@ efi_status_t __init efi_set_virtual_address_map(unsigned long memory_map_size,
 		efi_switch_mm(&efi_mm);
 	}
 
+	if (copy_from_user(&runtime, efi.systab->runtime, sizeof(runtime)))
+		return EFI_ABORTED;
+
 	kernel_fpu_begin();
 
 	/* Disable interrupts around EFI calls: */
 	local_irq_save(flags);
-	status = efi_call(efi.systab->runtime->set_virtual_address_map,
-			  memory_map_size, descriptor_size,
-			  descriptor_version, virtual_map);
+	status = efi_call(runtime.set_virtual_address_map, memory_map_size,
+			  descriptor_size, descriptor_version, virtual_map);
 	local_irq_restore(flags);
 
 	kernel_fpu_end();
-- 
2.21.0 (Apple Git-122.2)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200118063022.21743-1-cai%40lca.pw.
