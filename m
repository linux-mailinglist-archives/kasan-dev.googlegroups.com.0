Return-Path: <kasan-dev+bncBDP6DZOSRENBBBEF6LBAMGQEU3UFHBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 20AE1AE919D
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:12 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3ddbd339f3dsf4593915ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893188; cv=pass;
        d=google.com; s=arc-20240605;
        b=NKlPxQXcVuZG1hHOWjoUh3D1GrHeCv4LzqhbVHCWETNkGltOgYzq+QGh7TtZ2oqcac
         sfqiqvFhw0JkAmDoNOmlhUuCIh8MCbaUMFlQfsLbNkSn/wJgUtQfIVywGrlXlrlvwiUe
         o68IwfAVsiJTuNQeBB+8f6OdmjRh573lgyjVB9QY1aMlj8XyJibtvtrI+WXweTQ0Wd+U
         W+SvB690lSHFcR9xkm88Jar0FK8sO8IY9bM/pG/Hy4aFgLlRVuEuVHKIOXwElwqZ88ZD
         ipBuGTWYYYZA83UUQzY+Fbul+//NZw2WdruyqGcVuahrDlIUjgFcW+bmHLtyoJdRDLQx
         0eaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=8CJmGFQi1xCTxplnGeiEYj7X8AWTz6F7SQ5PzLbwcLw=;
        fh=PKVe2ZAc9ZuhGPIhoorQlhy94jI1HX05uivAkCGbZkQ=;
        b=bq8+5WBjE053yjkfAbVAQX8EoQdr1e8el7lpSRd7CVBWSri88g3QdN7nx1nPObkEPE
         i/VCrYNoT7oe++f0G/CJ8/CKV6l/XWl/GCm+JpU73lO0Pbo3eQ54GTolJKuT7JeL6PwV
         9ZrokKJOIAKE36FbKBkapNG925631ghb4+JK95OAS40AzglY3/7o9apCST6rysc4e72j
         EHQP3XrwPxlkZuSB6t+IW6tICdh5sWpV+Uft9ptxasrGnjHVJRH4oVl7J13fAqROj4Xw
         iWzchdO6z8KsfOoUWKUWsxdgiOYuAnDx4Nm5VTpm0SAjqASkSipaf2adYNQ6g5V+2vhA
         8w0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=L3i7mbNO;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893188; x=1751497988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=8CJmGFQi1xCTxplnGeiEYj7X8AWTz6F7SQ5PzLbwcLw=;
        b=d6mwn7tJWH5p9YeGj+mH3I3c37FyZlq3+vT2paX2PXmy/BcQtugeEjD7/ubyFVkJjy
         B7mkWWx73TsAldZHVcQPRCxq+qMgSHAqxNfwXj5uKVAtzTRAEV64QAUEG2M1n3hGEyZ7
         YH7PmkPZlXD8/0yd6afVZJ5lbtA18mCEzQbmZuyRxL/wZsdeFCiK98gRHSPlWaXIgxlR
         YYM5PjfqsaWI6Hv//xLgnLCD/SMLCD1Nhd00/CG2gfq1wUo4wyD9AYvik33UEjtlwbwF
         9ezfgTVUyNEsS19adh34GJSkzPsorUpzo9eqzi2TRBh/es7xcWy0cB0gjLzBBDp8XMhU
         PMnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893188; x=1751497988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8CJmGFQi1xCTxplnGeiEYj7X8AWTz6F7SQ5PzLbwcLw=;
        b=rIdL6VUMWoPtWtGgN0+4O6cO6M2+yC/ikIancJmB2RIKm95fhSgB1IS3glIaBc+pVU
         sT6/v7akCf6a3QochIleDfsch2/xgAz9cU9qo73EekrB+AxN+V/GrDmrvWWdpALeAmgZ
         OGwwYnMUVNZKwsMsrKNNCOzGmUt0XTq2wbYoXYBMcnL+zvdibcxg8acbEThwj6vfD6f+
         Z/qIYK7LHU7caxM+rGsh+pXey5Mjg5bY9nvfuW5jGKBxS6pymZtQS84BsYeedGqXLnFD
         y+BLmnyFH3efGXZwYzvrqJJ6yKpJ3hQ5VEmHJFCh9Ia+PUO8fyI4yU/4f6bACVl7RWF2
         e6Cg==
X-Forwarded-Encrypted: i=2; AJvYcCVMZQ3gtluUA85yKyz0wJSlPDJyxAmIq60OQVZpa06Pl+c5COzlCNRdNTLifazomIiZBmGwrQ==@lfdr.de
X-Gm-Message-State: AOJu0YyQiaTsYK1nml/0cQHnh3qm5cSio9vHqayP7oDx7C/MmlAm+kMX
	TsMjgaaMWQh2L9VGV3X7cGeIhznzW18q9VXUiPhVDDG474OA+SuDbfuU
X-Google-Smtp-Source: AGHT+IG+I/sbYzNv1cII3b8rRaZZnrbh2WRqcasjIVFmdSVKhVwLfdjJL8qXU9F9wIxbVuezNMsOuw==
X-Received: by 2002:a05:6e02:b27:b0:3df:4046:93a9 with SMTP id e9e14a558f8ab-3df40469704mr8963595ab.5.1750893188570;
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfj14ncw1xz9sZli+hofxkDwB42QREl1WjjU1oIti3FuA==
Received: by 2002:a05:6e02:3090:b0:3de:1366:8612 with SMTP id
 e9e14a558f8ab-3df3dc38ee9ls3576025ab.0.-pod-prod-03-us; Wed, 25 Jun 2025
 16:13:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWMoZ8eWazBksDv+8xChwEG5w0vl32y6n4EVbVj6d3csieUYdgjXt2DxbKIZiVozNMteOs2yAXJ7M=@googlegroups.com
X-Received: by 2002:a05:6e02:190a:b0:3dd:d90a:af30 with SMTP id e9e14a558f8ab-3df329364f2mr66166995ab.10.1750893187674;
        Wed, 25 Jun 2025 16:13:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893187; cv=none;
        d=google.com; s=arc-20240605;
        b=N1qn5PIIQ8zdvGfVY2NPkhZhG4t/hI9Iw/MrQ/gZ/m8i7IpHPWIB2Qm/WB8DIVClDg
         PEPaacCigiKBwRe6Ff2ZQGFmjLvVT+J9uYYFMDVxWhSje9qU0Lhss9C0o+9Qx2CoMlpz
         c/SRagGAgqsnhzkIKvW8B+3KiJ/G4YCUWVeN416HjxORZvHY8e3wxdTbvrgvHILmOaiq
         BD5PHtcFvHuwbXb1HlqDdSu04laqbCvx/qwYbjLbWqZHJ9n2+6AHE8Znl0l68hBH5x9Z
         K/EgfGDL3UUEqdLSVM4Div2qyZDflNamxIDnSM1/uefU/durGjNDAvIN2m0JGxlHgN83
         ZFDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=J87pcc6Ohn1If+oVDb5fMjwzxQyZmpttAMcoikLe90Y=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=GOkC/0VjPb5LERY+iggc1KIO8lKXTUbGV/vFvA4jM8J2/UzZfwCkZuNFbRoHIG5M89
         rrn57aBucEgsNLYsXiL/tOT6vjQBPmUHLfos8cHk8UzJBK/3Y4VUAO29UDPYNyHswAUw
         mI1BHjyc/3GS9VZwpv2jwz1RoebFKnNrTIqLz7w5CFOedByD0h7AFZZWX5T/aRA94bMs
         0GZi9BZYjJkp/IQGPqq8t7PNziSiIglYEQ7AifhD3L6BXW+Oz9udMRVYR0+dL3EmV1eS
         0PoyYHjnDKH5CNnCshNs+Tn5CtsAGuDEIjcYJ2Ta5UKuhcDqqNyijPkVz6rAUojN+6G1
         1AYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=L3i7mbNO;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.205])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3df3477fce5si1262265ab.5.2025.06.25.16.13.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) client-ip=192.19.144.205;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id E3FB6C00282F;
	Wed, 25 Jun 2025 16:13:06 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com E3FB6C00282F
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 3913418000530;
	Wed, 25 Jun 2025 16:13:06 -0700 (PDT)
From: "'Florian Fainelli' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: Florian Fainelli <florian.fainelli@broadcom.com>,
	Jan Kiszka <jan.kiszka@siemens.com>,
	Kieran Bingham <kbingham@kernel.org>,
	Michael Turquette <mturquette@baylibre.com>,
	Stephen Boyd <sboyd@kernel.org>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@gentwo.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Danilo Krummrich <dakr@kernel.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Daniel Gomez <da.gomez@samsung.com>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	Frederic Weisbecker <frederic@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>,
	Jan Kara <jack@suse.cz>,
	Uladzislau Rezki <urezki@gmail.com>,
	Matthew Wilcox <willy@infradead.org>,
	Kuan-Ying Lee <kuan-ying.lee@canonical.com>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Etienne Buira <etienne.buira@free.fr>,
	Antonio Quartulli <antonio@mandelbit.com>,
	Illia Ostapyshyn <illia@yshyn.com>,
	linux-clk@vger.kernel.org (open list:COMMON CLK FRAMEWORK),
	linux-mm@kvack.org (open list:PER-CPU MEMORY ALLOCATOR),
	linux-pm@vger.kernel.org (open list:GENERIC PM DOMAINS),
	kasan-dev@googlegroups.com (open list:KASAN),
	maple-tree@lists.infradead.org (open list:MAPLE TREE),
	linux-modules@vger.kernel.org (open list:MODULE SUPPORT),
	linux-fsdevel@vger.kernel.org (open list:PROC FILESYSTEM)
Subject: [PATCH 02/16] MAINTAINERS: Include device.py under DRIVER CORE entry
Date: Wed, 25 Jun 2025 16:10:39 -0700
Message-ID: <20250625231053.1134589-3-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=L3i7mbNO;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
X-Original-From: Florian Fainelli <florian.fainelli@broadcom.com>
Reply-To: Florian Fainelli <florian.fainelli@broadcom.com>
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

Include the GDB scripts file under scripts/gdb/linux/device.py under the
DRIVER CORE, KOBJECTS, DEBUGFS AND SYSFS subsystem since it parses
internal data structures that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 27521a01d462..d92a78bf66e9 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -7381,6 +7381,7 @@ F:	rust/kernel/faux.rs
 F:	rust/kernel/platform.rs
 F:	samples/rust/rust_driver_platform.rs
 F:	samples/rust/rust_driver_faux.rs
+F:	scripts/gdb/linux/device.py
 
 DRIVERS FOR OMAP ADAPTIVE VOLTAGE SCALING (AVS)
 M:	Nishanth Menon <nm@ti.com>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-3-florian.fainelli%40broadcom.com.
