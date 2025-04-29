Return-Path: <kasan-dev+bncBCD353VB3ABBBO5AYHAAMGQE4BME3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id C2122AA0113
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:20 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6ead629f6c6sf88086266d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mj9KEx7bDciblYKDQH+BzaHB1NFPBpzlQ7rHzCrUK6WkwBEny5TOkAsmTeEYJQ8v74
         qSdRmUOcGZ/2vFmGlMdi3N54SOEB0CCflFTcU3KJQvMZTLE4NeG5rlLFYvRq3TEbP7+D
         HDSfkfqy+/4EmhapiEqRt1EvwnNSm6ZrkLJ0OTKjO9NO7dd1nfAdOssCmy81K8k+IngV
         ep2F6dl/hbZX+fR899DjnMf4gV1OOHjw1gA9ROehcYRewAl7BFlm5eIOZp7rooVr4Evn
         IL0wrAjN1t885hFKcaOqBN7KFBIMSjIQspbOESD6HBWrA/4EHK3jKOscADo8rjX4FQ3A
         oOiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=LtzwdhezaksYZuB3JSJNGDV3J4H5ePkTO/riXnnxgjY=;
        fh=4wZ5nIzyJEVtzqF2LqpD1FoSjGCdI6CfE7/irkfsRkw=;
        b=Fw7gzgT9ze6A5OC0andx5+blYq/zSrE5yMksZgFGFLEPO2r2ieya/OT01shbXXVERF
         gfthTAWap+0AD7wP0A+ke8VTuBy8Wpk1bekvSPSq79aq+HWQnmMzjxbfxISyjNX+xaZv
         M5kibEVUb07rmF2mePsBUENqg+zcpqiprezzIsh7St2EfOHB0W6cb/vA/y+EJuHhn4vr
         HdEDx1AQYLhAqpnGdEA52ca9hxlmNyK6FoWCHRJJmDlj/nscOple8YRwUMI/gaHtbBkR
         rQZzjydWZ45jhZswNwcvCBYWTUneRuvA8SsJsS4zr78A9QGWQo6AxB4J9TDbI+/adJLg
         R4/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JE0vEjoK;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LtzwdhezaksYZuB3JSJNGDV3J4H5ePkTO/riXnnxgjY=;
        b=elCeZ4USDqzvjrPIbqzegpSFSmgiRl0thauM2dIPxaa13428hYClVnqWi2QnzTJKR9
         Iu4anoB+hosiZd2ibFHWwUksuPiy3oxMaLxDToSY6T51Sfr64VF3K9uYMhZG1Jnb0Xzs
         LIor758G7sP0GBtRwS62zigYzqovXuBCUofMvTS/NvuD5pPM4ETXHCuSG6W1kIFGZeSD
         8EDMIfzCEaViphZf+oCUQV8Y7KiKntMV03faFA3T5WHRfe3zG9ICVxeUq5cIpH8cnf/i
         QJtoT1HqoM9TIaMNPIFaZLzcln9G0gB1pC6V0vK8VGe7EHC+aFmZGgUWtMB2NaJWqCIi
         Xmiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LtzwdhezaksYZuB3JSJNGDV3J4H5ePkTO/riXnnxgjY=;
        b=SomarOUaNJSZK4r03GucQVvG9M/21rphSbpQ5WK0Xpw5Cnpsi4wn/lPUeQlcttlhJD
         W+7SBce7DcIjW19iBuRlPObDGfsW9b4SQo9Snc/SIjV2lBkBDFBKhZD8iAhPyrNCLKGi
         lgxlKyhW8HXwoeTWSMsK554nj0XU8bvekk4X1CqCHGr5zto3f394agxEQ48bWp9YT3eB
         EBR+KTfXjOHkN9DSq8Vzr6/eNBc4+MF8ex8mr1d/KXHQl6rItsC9S7wDY6oXn7WeaDAR
         DC+nAI/ErUBAfKehwp6BATxb/a0IcJTFp7UgrBMGYsoKhxvp/1mzPs3F5NDFHZOzQW9e
         ImNg==
X-Forwarded-Encrypted: i=2; AJvYcCUWCOyvUIp/Pk4ZjSWRznjnUUM4vXfgft8ft5hYiYvq5O+IWqAU8ZWkVf+VxOEwdQUwiHw5JA==@lfdr.de
X-Gm-Message-State: AOJu0YzjSGdz+VtF6umfqJ5QhGYaNThf5USevs+94JbolPCkN0C9lY/V
	enxj/pwayoJPHMtthK8ckI+C06hHWzkkeX0OirXyi3L8V9Gy63b1
X-Google-Smtp-Source: AGHT+IG4A02pd5Pbyx+RF9VGBOOSpXSCzR6BF6klDaggb3/xQH/5L3RG7PnKkc7HHTsg6viPRH4mUg==
X-Received: by 2002:a05:6214:5287:b0:6e6:6505:ceb2 with SMTP id 6a1803df08f44-6f4f0613c3dmr46650596d6.36.1745899579266;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFRuwYPqoFwx3Zg0U0HLY5NGUaZpA1xCUcwy+7yE9CAnw==
Received: by 2002:a0c:cdc5:0:b0:6e8:f47a:25ef with SMTP id 6a1803df08f44-6f4be49bd28ls67315116d6.2.-pod-prod-07-us;
 Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZ9fqOxBkFMSaansk73RqrK9NoSctwf0dcs5NP+eoEfNlBpXUa/09xrx19pY9Imk5v30jSUNVh/Pw=@googlegroups.com
X-Received: by 2002:a05:6214:1cc9:b0:6e8:9a55:8259 with SMTP id 6a1803df08f44-6f4f052eadamr32893426d6.9.1745899578381;
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899578; cv=none;
        d=google.com; s=arc-20240605;
        b=Xs/YBNWVHHekdVyLAtEFdag8dLunTXI035Jpk54O7R2/sLF8+M2gWqf3soYiw4S3Gw
         GBqoNsaPysP/WlBmcFP6wxemtbBJMk5hEUQhX9CJBf0LvuevcRzP5ayTZOxHkYk1ysIk
         Lx7SrF3bDDnE8uyxvFF3n6vGZvP9YOslL6kOCRKIDwSp1W3cuBDX5XoT24Pvy48Mor18
         Az2x7bk8o64Abkyo51j8kNNUbp3z/1xSq2GsmLIdM1tPGYtWakIxLh9OX8s/5ExZU8NH
         WgS0VOntJ4n1BeaEUbZtOWmD50crXEEpikD5U54GgCeiV7E8kEVYS5VS7AaaUe33LElx
         gHQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=wdxfb83sz64pVXY/N1P48YSO3Ovk6I4U3rA1Q3+Ucd8=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=NcX/tq4UXCK4rBxF8SlO5tzCkYFKWOxCXU7b/7uvlIMFhufFTDHc3d3afyc2bstLh8
         oXVAgO6ED0GXbEG0FHKspdd1yhOmiKD9taJsptdnvXsNJyw+8jP47uEV7oJCfoI1UR6x
         6thTJNH2v3HH6BHWjk6x5lCmlKNjffHpus5iz5OkZu2FTfGBhZOJU80K5LcpyIcDyZbo
         xHASQcLPtDTG2K/mmfSFYwxQaYmfT7YBpMuOssDeXe9koIzKDyqeVJGGJo2ERibVvZ0q
         XypLo7dzCzCVrZzQjo37QBrlQz8pCJ//xRMU7+P2KxL88lZAG+NGIMrjjS+GIrm+6ztm
         /3jA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JE0vEjoK;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4c07a0021si5224086d6.0.2025.04.28.21.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id CDFCCA4BB08;
	Tue, 29 Apr 2025 04:00:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 58FE1C4CEFF;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id 4C8CFC3ABA8;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:12 +0800
Subject: [PATCH RFC v3 8/8] lib/Kconfig.debug: introduce
 CONFIG_NO_AUTO_INLINE
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-8-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=4279;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=Bd93x7WuEFeV0iOsS3dMjqDGQS+n9awf6aimsKD9UOk=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFA1dN0rUHGv15CSgUAacYmKqLp9Xxxon6yon
 c7TiGmprM+JAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQNQAKCRB2HuYUOZmu
 i55nD/9Z3vTJGmV0EjUhmeI4qXKmcdAMAq1X/bMvCKKqJb8nDqxr3XzOsrgtlGbWtGbSRpAcMRC
 kIBZwz/EFrXdSky2mgTEfswE2JzuHKo+Mt434POfvbTmTZzfhinHk2rveNLn14K6QQxOZNTHzoq
 DY3XtiBsr5/6XiSk58sFs0UB2do+v1RDxbRgPVRbwakBRf2EpGtYK+ZkSVPourJzkqG7PrIvHKY
 FyKSLRcxh2ehQ+zdjfMyhxbXKMW3rLF6KyReLohSbuPnAZH9vBG07d85cT+hlqayZ2VFrTJWayX
 ogvHBmQbs0jd6kEOOcqxulI9+HLWeFHpLWXkscXCbtKYFnN3of88CFc5dM1NBfTsa2bE/5c69eS
 TXaS9CEvSaJLZP2bguKxeYXuKMcX7aCIEmkb5ywt+zXQ2sBHHXVo62B2vH+ZEPTvJ0JBvREoDHA
 Z07bh3e0yi+U/gCk96uDLgnOmSkQUjen6r/WDp03CqP8r46lIU2aWAN8mPN0/bL6Leb+yx3Y5Gf
 MfHerWdPEqYeBh6stf8GRI22HdoAjnaigM4iGlYaLrvgjiuVjR2tHFFGtnPEviP7O+74W7AnPTn
 n9vHmKNe5H9AurNLXL/K7j5eRYSPpaBVROMuUUngVLHw7qljfnSQMwRNYonB6pGCO3WTd5AnIHj
 tq2/DJ+5MgngDcg==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JE0vEjoK;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

From: Chen Linxuan <chenlinxuan@uniontech.com>

Add a new kernel hacking option CONFIG_NO_AUTO_INLINE that prevents the
compiler from auto-inlining functions not explicitly marked with the
'inline' keyword.

This enhancement improves function tracer capabilities as it can only
trace functions that haven't been inlined by the compiler.

Previous discussions:

Link: https://lore.kernel.org/all/20181028130945.23581-3-changbin.du@gmail.com/

This patch is modified from commit 917fad29febd ("kernel hacking: add a
config option to disable compiler auto-inlining") which can be founded
in linux-next-history:

Link: https://web.git.kernel.org/pub/scm/linux/kernel/git/next/linux-next-history.git/commit/?id=917fad29febd

Cc: Changbin Du <changbin.du@gmail.com>
Co-developed-by: Winston Wen <wentao@uniontech.com>
Signed-off-by: Winston Wen <wentao@uniontech.com>
Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
---
 Makefile          | 16 ++++++++++++++++
 lib/Kconfig.debug | 21 +++++++++++++++++++++
 lib/Makefile      |  3 +++
 3 files changed, 40 insertions(+)

diff --git a/Makefile b/Makefile
index 5aa9ee52a765b7aed27f44028cdcc34a90979acb..60dec6c123543150a3332a9a819fa6933e94db4f 100644
--- a/Makefile
+++ b/Makefile
@@ -1073,6 +1073,22 @@ endif
 # Ensure compilers do not transform certain loops into calls to wcslen()
 KBUILD_CFLAGS += -fno-builtin-wcslen
 
+ifdef CONFIG_NO_AUTO_INLINE
+# -fno-inline-functions behaves differently between gcc and clang.
+# With gcc, it prevents auto-inlining of functions but still considers functions
+# explicitly marked with "inline" for inlining. However, with clang, the flag
+# prevents inlining of all functions, including those explicitly marked with
+# inline. Clang provides the "-finline-hint-functions" option, which
+# specifically allows inlining of functions marked with "inline".
+#
+# In summary, to achieve equivalent behavior across compilers:
+# -fno-inline-functions (gcc) = -fno-inline-functions + -finline-hint-functions (clang)
+KBUILD_CFLAGS   += -fno-inline-functions \
+		   $(call cc-option, -finline-hint-functions) \
+		   $(call cc-option, -fno-inline-small-functions) \
+		   $(call cc-option, -fno-inline-functions-called-once)
+endif
+
 # change __FILE__ to the relative path to the source directory
 ifdef building_out_of_srctree
 KBUILD_CPPFLAGS += $(call cc-option,-ffile-prefix-map=$(srcroot)/=)
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index f9051ab610d54358b21d61c141b737bb345b4cee..56530f0145c885e9846dae1d2f8c6125c610d25b 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -436,8 +436,29 @@ config GDB_SCRIPTS
 	  instance. See Documentation/process/debugging/gdb-kernel-debugging.rst
 	  for further details.
 
+
 endif # DEBUG_INFO
 
+config NO_AUTO_INLINE
+	bool "Disable compiler auto-inline optimizations (EXPERIMENTAL)"
+	default n
+	help
+	  This will prevent the compiler from optimizing the kernel by
+	  auto-inlining functions not marked with the inline keyword.
+	  With this option, only functions explicitly marked with
+	  "inline" will be inlined. This will allow the function tracer
+	  to trace more functions because it only traces functions that
+	  the compiler has not inlined.
+
+	  Note that Clang with -O2 optimization does not fully support
+	  disabling all inline-related optimizations,
+	  as Clang does not support options like
+	  -fno-inline-small-functions and -fno-inline-functions-called-once
+	  that gcc does.
+	  Some functions without the inline keyword may still be inlined.
+
+	  If unsure, select N.
+
 config FRAME_WARN
 	int "Warn for stack frames larger than"
 	range 0 8192
diff --git a/lib/Makefile b/lib/Makefile
index f07b24ce1b3f8db28796e461db1324d97133fdd5..2ac97f0856a12f66e6c3825af6aabafa61869262 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -87,6 +87,9 @@ obj-$(CONFIG_TEST_BITMAP) += test_bitmap.o
 ifeq ($(CONFIG_CC_IS_CLANG)$(CONFIG_KASAN),yy)
 # FIXME: Clang breaks test_bitmap_const_eval when KASAN and GCOV are enabled
 GCOV_PROFILE_test_bitmap.o := n
+# FIXME:
+# Clang breaks test_bitmap_const_eval when NO_AUTO_INLINE and KASAN are enabled
+CFLAGS_test_bitmap.o += -finline-functions
 endif
 
 obj-$(CONFIG_TEST_UUID) += test_uuid.o

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-8-4c49f28ea5b5%40uniontech.com.
