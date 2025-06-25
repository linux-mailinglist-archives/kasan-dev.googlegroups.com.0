Return-Path: <kasan-dev+bncBDP6DZOSRENBBCUF6LBAMGQELBUGUZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id F29D5AE91AA
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:17 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-23632fd6248sf2805075ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893195; cv=pass;
        d=google.com; s=arc-20240605;
        b=K+AzLNlH+QLQa1GpGPYo/fi52Me0n8zsYE+X4zGVIWqNwmbvRyhGJiIYozaSB97zn6
         9Ab80LsEYI2IItr8YeF0OBBfNSBfvvOHW/4I26E6NOWK3LdXD1hjpBtQzBaiWAz6Cjju
         duCwtV/9dH83Vq7uUZOMqkbEBNNq5Pd+sUuLpiGdzSRLnRsLLN6N0r7eIgSuyf+Hx9fS
         dw+rM9p8r32CSHKO2VshpQGw5jSPCxX2REoGnK0b8L5a3MzS5Uki8w9l9157QdqmACz9
         WEBaxa6X8cDGzG+ASvhgAi26WLkJ6e1o4CuYqlfiLU/slIqKxExVFMW62XV/Zf6eV4J/
         HYNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=jL7/rU3zXBMU5Hda2JihsgwUxunRDqnMBpOYm6T9Jeo=;
        fh=UkEhNx0tGsncrfIZeuiCygjkhJSQ7FPXUZvmhIx8zcg=;
        b=d99Xm+uHRFsYXRuk3VgBotIPew0ehDZLikaSgPKvcXSDzDhN3M7ajqcKpxS1+zKUka
         mLlurxh8VuQD7L9vg4XGftzAWOHu/eC5bJTWkYAlEq/XNBNqVKiChFax5AXIa4qJWHul
         9HC/xV+frSQ+nCZCT8xTySSz94lI7EXLrfLybeOi6972fAgzzz5CMQ5UTbK2d2YjlVpR
         D0vGeinvltoR+m1T9N2tqd0sgdrb1L2bu22ttCcLynuJZlQvD43F7Tb8P2Zcd9UUWwLZ
         ulO2L2sUYbphqZx5TwG+JFz0KEWyimf9jJfj4yYmitgeScbghZoyI+P8276Bi1Rer0Ot
         JVzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b="cS/h4p5V";
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893195; x=1751497995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=jL7/rU3zXBMU5Hda2JihsgwUxunRDqnMBpOYm6T9Jeo=;
        b=Jlk55b8Zaakpewx0LnlHzreekzI9EangquEtmOQYrRLWlZYdrpOe5Es32VaF3vfE38
         lLXMa3wDP2fKwdTGhbpFKLupB0bqDpGiE8KYxRlGedstXwUuF6iVnB5plwZT6OVfbgvv
         6iTUdFBp2fsQcacy4gIX9nY+xS9XF8d8e/3Ueu9QmJhA1gdYQiswWH+zqnXVqQ47SQw7
         /pCXOeKLM1zvrpAJ32Y4YR7lDB624YsSKBbpv+mnnMwK27dUBeWuWaHMpla/Zm4kBA7u
         ZN+xoXICbvrygHj2BkbBcs5MRrxc9huWUn7luxYPPrgMslWRo1OvwLd+YdNkyL5ZZOJW
         NuJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893195; x=1751497995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jL7/rU3zXBMU5Hda2JihsgwUxunRDqnMBpOYm6T9Jeo=;
        b=Vs3YJ6lL7OtSWU+TWgefeUPHMxG/EOgUk1FX67BNpmDmMY3NWc5UPsY8J8PkJzUrrX
         z+O/nS6kGCPiizy8HaPBvj+V7MDFo+OX2dfZZwf7NfnZEs9IT7kzTJ6gL9Z6AHdJlt4W
         9kv3amOHc5NkznmcN9UPqwNcVDMiakUS9sBq6cfgAFUqrgvQu4rtTM6ld93CGNGSvNPK
         G7Wb8pRMjHSOxmM+oLnzWHpZHd68T2Ho0waQ8G45T5+K+uFKX9xVXb9qGu/vfOeWW6Gi
         Mo9Fuib8RJ10aDGzIkxgGS6oPkhjKD0y5/3FIqXdC9+/3IgWTwIfnX79s7zOdv1BmLXy
         C/ww==
X-Forwarded-Encrypted: i=2; AJvYcCVsxrtroW9TEDlU2Jsprvuz8c01Nw9ZNgLO4kMC3u+IWNax8agPLd1VZoPN7TcmVcgJQTTFCQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw9S+OkYaa2CWbt/tYtAMMuHd0vJyI6EmW/KZ+MWvUMU9UkTC+a
	udNICYnMdCJM/R2W0NYs9p504gx0tsL8WQLDzfHIptUPs/tMp32LaFGT
X-Google-Smtp-Source: AGHT+IEwmEXlVZm57YaSI4mlit01PVhAuOtvBlINBGCfsiwQ4K6v5wJWF138zkvzm/TY4j3ngeJpSg==
X-Received: by 2002:a17:903:244d:b0:237:c8de:f289 with SMTP id d9443c01a7336-2382404744cmr83795765ad.36.1750893194804;
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc3BhgTSmCsPqzqkY8s0eEt8ml4qaLKjQuUr0zkKJsnPw==
Received: by 2002:a17:903:310c:b0:235:f4e3:9c7c with SMTP id
 d9443c01a7336-238a7ff92b6ls2268575ad.1.-pod-prod-05-us; Wed, 25 Jun 2025
 16:13:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJLTFt+GH0tPrvCqXwqlB6EInw4fGQ+Xna7uJ0LyvXPiVqVphoj2CAZsk/W/ZJeeciQH61iBbz2uI=@googlegroups.com
X-Received: by 2002:a17:902:e80f:b0:234:d7b2:2ab4 with SMTP id d9443c01a7336-23823fc5707mr86142125ad.17.1750893193632;
        Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893193; cv=none;
        d=google.com; s=arc-20240605;
        b=M3//gVz7C3IOlocV5pRYw44bXNlJ3RbJN6xRNAHXVE+YSsXxsJYMvHDE85Qmq9zDeC
         AdIzibjmSEJhDWcPMwfL07XKZvljXhKbV/UfMEzjCWStmZzKenA+MkIu8j0jdu2tMp70
         4X2O1pPh9TaXV0CFaGgBW5C68177C3998PjXPUarDeaYtpdwrEwuXXLrOjr97NK/eZcj
         iEZXVlTphT8zKwksToeR5ahfol4mf2mWJUcE/eSA2xnDZiIBM1qGpfaDc7yOQovmENCe
         odwKn8hXsxori2j/uzC4svSjtWxntu8O9vv6apoinXHkrS2fkzGNAP8ITkgFq4Bv7qas
         03dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=tAUikm9tH5BkCLUQcQdTeFqQCAxSZpw47A3jK/SgxXE=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=MdFgmBwIVD8ACGSCBgcGUA5SQCISwKjnvBEsc+n06/LkKyxWg2VgXl5VN8YYWVTexS
         zi0ZTUy7NwZiV/RNdv5xnYDKyZpyevtWTGz+qiYR3H8uuFIL8RBI6cNGDgk5pNAz2cqT
         U/FBUsCW73B0cUM9v+YNVspRChibsfX1EiGS7P0/7QMK1+MWP3N5r58xgSC6LWtAAIEu
         vX5CzvJPpymz/DYUgDgiIo5TNI+Z3YZW6S3ET5C5h0LS6U1Ifnvw/RnoffduuFyC2Lgw
         P+sP4khbONf/eQ6FzsttbRslhckFck5g6x84S23mVEBD5AsHO741CDEt8GLt2BrF9Cbm
         VCIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b="cS/h4p5V";
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-237d85318easi5827195ad.7.2025.06.25.16.13.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id B9D87C002831;
	Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com B9D87C002831
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 2C99718000853;
	Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
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
Subject: [PATCH 13/16] MAINTAINERS: Include proc.py under PROC FILESYSTEM entry
Date: Wed, 25 Jun 2025 16:10:50 -0700
Message-ID: <20250625231053.1134589-14-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b="cS/h4p5V";       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
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

Include the GDB scripts file under scripts/gdb/linux/proc.py under the
PROC FILESYSTEM subsystem since it parses internal data structures that
depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 0931440c890b..610828010cca 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -19998,6 +19998,7 @@ S:	Maintained
 F:	Documentation/filesystems/proc.rst
 F:	fs/proc/
 F:	include/linux/proc_fs.h
+F:	scripts/gdb/linux/proc.py
 F:	tools/testing/selftests/proc/
 
 PROC SYSCTL
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-14-florian.fainelli%40broadcom.com.
