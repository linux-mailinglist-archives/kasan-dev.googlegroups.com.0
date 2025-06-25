Return-Path: <kasan-dev+bncBDP6DZOSRENBBBMF6LBAMGQEWVR2CQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 072FAAE91A2
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:14 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-31218e2d5b0sf633402a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893190; cv=pass;
        d=google.com; s=arc-20240605;
        b=F2anVDoIE1uDLIUlgwFw1aB9dbDD8YMXenIW+K1i++xMn3WPkIB5wl948s4PCVBGlg
         FiT0Ui9zY2tXAV80hjlpJv8pkHd5t9cq2fqCgJnvFM7eTpBLYYkogVTEYTwNDrvhrXRo
         QyyUIMnZbahrxHx7GwHR/an9rRTCSq3GrOz2wQ+SpA6FzMReZWHc0lVmWGllvaNa5Zd7
         GFPNemLUzxQXV/cUt3fk50kzyccbHmo0ymeFqB6eCUpUq/xg89TQWW16Jqqt4DOLW6cV
         diJRx/zWRPt+lfOW9uWt37b+JWGHahQLdOlAELh7Z5ekED49M+taXbHhW3ba0qiQkdzI
         J70A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=jjmlzXwbr845hgHH4KxAsNOHPmmnVDBmoAlFJ35tnAk=;
        fh=pGa9MTsoNvQY+/kIShaJIrhAna9XGWRx9NLEVnfIBNk=;
        b=gLb9pBE4rPTY0bcguEY5RrnXoBR5pABxPt3HQ3zWMhBN73kN7EK6ah6KZvRS070qxj
         e9ZxTXFbo4wvRRw3Z7QoGxQuAUFHAqFimE1PkEUzJESlD1VXkL+mmkQ2qeVq962DAt52
         vkkiyRqGkolnJ3agAv5/Xb4Qv8iz9xVcUKinq68x5oyZPWWJEI7j7IPHMNkgGaoh3BGP
         2rF0U6TLnRTFVLdvzgHG0qdIWEoY/mDAcIp9gTDRq4FqwPKbSaNfe4Pwdgfvp2phphKh
         iKQzAhLE55I6h8f6ju20C107UQC0vwDzIHYFAsH3s6wuKnP8QHmR1xfYFJyDVvBh5T0p
         udxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=Xzc8jX20;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893190; x=1751497990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=jjmlzXwbr845hgHH4KxAsNOHPmmnVDBmoAlFJ35tnAk=;
        b=qvVgw1cY8xos0IBfLDyOeQHsgaOF2iTLTN/VwWiOEIxS/s/YtKcl3Lx2VSkVxYJOeT
         Yfb/PPkJP/LBFolQPPm3tC2d7yXJwSXRkx2zzq+3qG0B07wW4byv1EcD81Vc1MvD6ics
         AY60pUNqlhjAOaa2EXEOf2hjPJL+uouGlckDk9c9XwfMTlc2Rw8ldHnHoNiFRex0p9WT
         Ihf9UaJKzoB3CYsIGWha1gQyQ55UX6Zj4mnPViguR9jceej+0zY+H9QjxBNswDbNv1ly
         9ltpR/L9tEYQeWHtPGbAo6PysDRD5Dch5jDnfaJXZ5xjJgwvG+tY/IMt15BCK2rJc0Rf
         bo6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893190; x=1751497990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jjmlzXwbr845hgHH4KxAsNOHPmmnVDBmoAlFJ35tnAk=;
        b=Cvpu5bAY+gz3UW7+dxioTlOET2CsJjoWHm5PxhzLuNQF0L77tZG7rbCjmbrtRd0sEt
         X44yrRiM12kE7Y3HOWKKHZEqi4o51NJWDzNG74zOarPDbwimrZk+nS8nUGiLYMjNKUX8
         kO+FmbbZ2yGcECye/l3+ciF30JKzmwOJSzBPCIHfBQz5M7LGBbT6NldwH1hkfgDPlE+X
         miPSoO1K8waTiShy43UUBB3YhxQGaiyaU9vygfB82hqCUNsqBusPjjmoXuMaZ5Ch9Acx
         AaHcwn9MTtqnChXAoiD3QOVyRwQ+PF+dx8TLAFvqvlpcEiYoRHa4Optg55iVauxNXfO8
         qDUQ==
X-Forwarded-Encrypted: i=2; AJvYcCXo7+ncEzTFFujdu9jbcVrv+y2eycqV0d+NuZ2O/eeIgLv9rSy8UD/JnXDJE651ZLbBv1Nz7Q==@lfdr.de
X-Gm-Message-State: AOJu0YzmNCPdxqkCzx1HNTR4//xeRe+hhctAG55FxcxvM72YUnly12Pl
	4EZcCNGu25z4qMo+GI2GPcwwBUgKStileCkAWp2FysMiMyQKUEwUdsF/
X-Google-Smtp-Source: AGHT+IH7/pvIWFPD9Z8Bg+F4TBeAC55w1O7lLm8leg//6Wr+8V2FGif/IfG1jeHQktnAScqIQ0Ba4g==
X-Received: by 2002:a17:90b:53c5:b0:312:1508:fb4e with SMTP id 98e67ed59e1d1-315f2675bbbmr7301538a91.17.1750893190218;
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcX1dcgNtQnMhQq9Y3wYLRjveJ4l2FEjpR7nnUONjat8w==
Received: by 2002:a17:90a:6d02:b0:314:21ab:c5d3 with SMTP id
 98e67ed59e1d1-3169dc71dd6ls360364a91.1.-pod-prod-06-us; Wed, 25 Jun 2025
 16:13:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVthd504qXyzInyOxz3PFw5eRGlwfJQcEfkz5K5WcbXK34o4FKGohduEXjnyepeIWfS/+HaPXdAqRI=@googlegroups.com
X-Received: by 2002:a17:902:cec4:b0:235:15f3:ef16 with SMTP id d9443c01a7336-23823fcc7a1mr77783495ad.13.1750893188908;
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893188; cv=none;
        d=google.com; s=arc-20240605;
        b=UOj+XwscQ3RHstYQALrrsYvY0PDIU4cNmmJIyEZ1ZnjgF2dELwfJZ66Vm8PpxzjkFB
         c5d8HqucFnj/3CIb4Bfa3gKpwLiuTmWPfBx7FlHcQ4jjR3CtcpqlHvclyo3WqNADVLGr
         /aFFZJthsyV0wk6FFjlFHFFtX20P8zmFzSPj3N8fWpLH1AB1xNp48PLflR/XVdS0R82R
         P9ARp7vdkjMZYMK6UvSLgKiWantUFr1r0SLDNTb/ZNzuUbaDnWvwORN6j5w/G+6YeKlb
         YDGta/YnXRcGoH1QOBpr6xqhQzYKEWUkL3r5TMJIEbUDUYMNf9u2W860elzRuTTMLzjY
         h8aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=sFKSgkiCf84GvTmnaru1XPt1GCOOVlepFGX8sBN9ScI=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=g0o1hXuNAsAMmutxkRHHt/Tyns6gF9rKGwvoXgN/UTnaKnBfI2p6pkFKpUlZZ3C3f2
         i7vtbbWYHKkfUJwrSWSZ/2WDrbZp27cqBDT+6zajf7ECkm8ycXf+4tkBNUV/2mNofDU1
         DG3ojtZl7B0udpaATfeQRLDbQxE0pz1i4glNewNIRK6bBpizD4UBSrVg6gURdK4CfbIT
         TehLRkTXjqsYMT5VEkN5TOlqgdOGngRHMFl+bwx5LJsPFoTPqBMolilUwL7LCl9i6AlX
         3LIIIymf24L06Ao5dcuoWta6mX0jGVj0xusa9lW+mInfWL3zOMvX6gsDIXCR2q/ufBUS
         /ntA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=Xzc8jX20;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.205])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-237d860605fsi5565935ad.10.2025.06.25.16.13.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) client-ip=192.19.144.205;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 011F3C002813;
	Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 011F3C002813
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 47A6418000530;
	Wed, 25 Jun 2025 16:13:07 -0700 (PDT)
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
Subject: [PATCH 04/16] MAINTAINERS: Include radixtree.py under GENERIC RADIX TREE entry
Date: Wed, 25 Jun 2025 16:10:41 -0700
Message-ID: <20250625231053.1134589-5-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=Xzc8jX20;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/radix.py under the
GENERIC RADIX TREE subsystem since it parses internal data structures
that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index d51eeb1248be..cfb0d60ef069 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10171,6 +10171,7 @@ S:	Supported
 C:	irc://irc.oftc.net/bcache
 F:	include/linux/generic-radix-tree.h
 F:	lib/generic-radix-tree.c
+F:	scripts/gdb/linux/radixtree.py
 
 GENERIC RESISTIVE TOUCHSCREEN ADC DRIVER
 M:	Eugen Hristev <eugen.hristev@microchip.com>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-5-florian.fainelli%40broadcom.com.
