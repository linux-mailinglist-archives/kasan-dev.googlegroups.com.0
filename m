Return-Path: <kasan-dev+bncBDXY7I6V6AMRBR6PYOPAMGQE57T2PLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A32F567AB94
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:26:47 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id k34-20020a05600c1ca200b003db30c3ed63sf8704980wms.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:26:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635207; cv=pass;
        d=google.com; s=arc-20160816;
        b=f331NWSQ3xweUsgXkLRdhQjLCrl4lq4W7XCec8Q0K7PBkOcOyhxF4aMZe9a44hYOrh
         PcZfpUDEPOst4TSE9cATJ0gowstKqYYpSTdIH3gMGOBWkXbYJ0f+lSllLnjVGEwB823x
         yHDKfMY2YFF2Zf9EWMa6qcGRLl5JnpRLIOVnQZAfUFhNHHDRoeN7nwqTXlvW/E9vm+r9
         j9hVcqKFPw2zK14E99DfJJYwENgEzR2g6/L5ja9UBGmd3kCp1o7Ad/d0Zq7SObISca9S
         j7xRz4WNyafRpymfYWhTXouOkCRklxWHCbzlfWx80w/BvqZFKzUr8S8YN7zDEdg7qzyw
         2tWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E6JiRh2zwG7Z6onv4wOYOuNIUxUbxnOnHftXC0ZBgMg=;
        b=pWGInxUM8gxE+5WfIBVWy/OxqlgcBs0ftjizx5yCfRaKcPupFyLo5RiPgg1mHBcLTz
         WxnafHALs7uhHvcjfr+D0hjZpwKB5y8cFy7H8NJ9DhZoOY5jDldk7ud+sfM3hUwQjeb/
         RKd/j0v0edyMwQFFWx6aDErQsWRBZ7nlEo8Z7MU2EvTJMI28Ev8ji0ibuPscgHCMqI4C
         wXyyQ3rmBHcE2xgBKszp02pQlulzzwsQryVsfCQ5VteQ49TqrzeRQ7L7+7SohQM9vic2
         CcnTvD52532stZPAQ8+3G9yYNvaDLK58FA8rhWCkJgxexk+Eu3S9LskTebs1ZLNtRk64
         Gkgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=43RnMhlz;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E6JiRh2zwG7Z6onv4wOYOuNIUxUbxnOnHftXC0ZBgMg=;
        b=eBpCPMJl3jof5IfXE46kCEgn+gUCWjYXBOxqeevL7gWSE2DZdyqcHujNUYgK2QJG5R
         rJR+yRWH4JORRzvo26VTezkt3kZCxRyZzZCUYf8c6vaJUFMvyvVLGIeNBmCuhRAp4+2o
         T+iWgHWBWw6fQVlVmHxBsYln4gwXo1fgha26WxNgSgvQTBQKZYmlMIfVHpVU0qFYo2ba
         5i2q6ss5LWCgYPEGzR9DlDzh5nWJQ9Wfx/Q6zzCuLIzP5RlnOrw2k77iNiMKN3mvL5Yw
         MB6l2YwR3aG0AABSHJY3G8XSJPZBwbntF7HQBnNSMLvMB5jwbjnpb/FowCiCobcMqjqn
         NbhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E6JiRh2zwG7Z6onv4wOYOuNIUxUbxnOnHftXC0ZBgMg=;
        b=zIuo5ABFf5yFPc6B3c/rsuzg6zQwZJY3zDtaD9M6BBlSb8zNpnk2Ytoi1EFK4abtvt
         PUlXmJRKmSGPQFdzPFalwZ/Hrc/yEDsyOAb9FywYQxoes1TB0Gve6PyoU12+vCRKDi3y
         UmBHtNVTUr16Kkhu7R4gYrIGBdkRmd1tMJW47Gpy35B5+64zYNX5jY1lLOV7xftHBU8E
         hkAchCDcJMEpcHvlKRhr7Tc6wlGJJMXnDcCuG/kINcsdXpw9O1ivdLYG6XHdrSpObLzJ
         7HgsuzWzKq6iA4iX4ZUvx/9sw5PoZ4MQ2k4f7N3J1b/R7u5GxQD+DVxBTJiA8mdV2ocs
         FdjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp0YYI29D2jgEkGWULbKce2ws4r2hBlrejQeQGE43V16PKqA4Zd
	N2gKpv3knfuBxAgZ4RsKFeo=
X-Google-Smtp-Source: AMrXdXuu4wkj7lFPZE4FZlASpLSBHhao+xRHVLWBLGgvGNrenA4Vdpl638vUCUqXMNhHAbD7A/hNDg==
X-Received: by 2002:a05:600c:220e:b0:3d9:e44c:666a with SMTP id z14-20020a05600c220e00b003d9e44c666amr2510231wml.205.1674635207376;
        Wed, 25 Jan 2023 00:26:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47a9:0:b0:298:bd4a:4dd9 with SMTP id 9-20020a5d47a9000000b00298bd4a4dd9ls348225wrb.1.-pod-prod-gmail;
 Wed, 25 Jan 2023 00:26:46 -0800 (PST)
X-Received: by 2002:a5d:490e:0:b0:2bf:b839:c48b with SMTP id x14-20020a5d490e000000b002bfb839c48bmr1537870wrq.51.1674635206354;
        Wed, 25 Jan 2023 00:26:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635206; cv=none;
        d=google.com; s=arc-20160816;
        b=MGYSiwjTNAGF0EEYJ+yAafq2xjPW3YU5b+V0zst3YWwMW4xPKwmsJNzfcFaLPBh9CK
         PDxxC+E50d4azaI5gqgDSCFOLAguF0IfkyomrqrLxjRIoOBX7AhelsPN3jC/0crtjEAU
         dK77W0dEmFucG60WkoJUwdREROTsNVsRhguorBecOY+YJbGfzD0vQ1t+SXYIzUZLUxsq
         PmF8c+fkAc/MS4D9m71K9nJRiHGIzTFRZeNUKfViuYMb1BEUz7a8UZwNjwicY0AHJGZ/
         e0qaZwf/XwcJiOTCrEHPW2kwJ1fTJzDueXsXb1cHaieXhONMtZDM6mKFkSLXKKd2wcls
         8o3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VzLCWkEIOjhYvr7p7s7uKUj96vyQiWAZD9+xORl+Fd4=;
        b=cpgy4b8KiveYa3NEMHRn5lBzSu94827u3KvoC0xK0EppJ5zTaB40XpbECryQmKbn93
         RLovLllbD0d7d2D6E98JPNB2RWbRGcCj2nBEX/xYZZikS/ucLtfbo4dGzqImA0Twh7NJ
         gEpQrLK9j1UklWEQYunaPf96b9ttUSHRoe1J5/npZzV6f008G/GFsDBVLNe6jxfmepOl
         lsOcKRobsxM3olyXpplAgbWXVaRfAlPPy3ByC6KPp0PgR5pQioOAUnoNBupVMxfyEpQE
         ouaW20nXbQ7ydcoSwOOLLEQXjXkmh896ZcPuG8pK6alwKArywEDgYpNaRSwmxwRpURxL
         7SHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=43RnMhlz;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id l15-20020adff48f000000b0023677081f0esi209596wro.7.2023.01.25.00.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:26:46 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id r9so16206497wrw.4
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:26:46 -0800 (PST)
X-Received: by 2002:a5d:4536:0:b0:2bf:b1a1:efc2 with SMTP id j22-20020a5d4536000000b002bfb1a1efc2mr4073913wra.18.1674635206045;
        Wed, 25 Jan 2023 00:26:46 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id j14-20020a5d452e000000b002bfb6b9f55bsm1607974wra.16.2023.01.25.00.26.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:26:45 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v3 3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
Date: Wed, 25 Jan 2023 09:23:30 +0100
Message-Id: <20230125082333.1577572-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230125082333.1577572-1-alexghiti@rivosinc.com>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=43RnMhlz;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The early virtual address should lie in the kernel address space for
inline kasan instrumentation to succeed, otherwise kasan tries to
dereference an address that does not exist in the address space (since
kasan only maps *kernel* address space, not the userspace).

Simply use the very first address of the kernel address space for the
early fdt mapping.

It allowed an Ubuntu kernel to boot successfully with inline
instrumentation.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 478d6763a01a..87f6a5d475a6 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -57,7 +57,7 @@ unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
 EXPORT_SYMBOL(empty_zero_page);
 
 extern char _start[];
-#define DTB_EARLY_BASE_VA      PGDIR_SIZE
+#define DTB_EARLY_BASE_VA      (ADDRESS_SPACE_END - (PTRS_PER_PGD / 2 * PGDIR_SIZE) + 1)
 void *_dtb_early_va __initdata;
 uintptr_t _dtb_early_pa __initdata;
 
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-4-alexghiti%40rivosinc.com.
