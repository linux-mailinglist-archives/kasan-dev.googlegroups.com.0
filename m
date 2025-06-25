Return-Path: <kasan-dev+bncBDP6DZOSRENBBBEF6LBAMGQEU3UFHBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 520C6AE919E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:12 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6fac4b26c69sf4020296d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893189; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZsbioQMo6UzpsApCwIQ6Ot8JxV1TMYQpx5Eam+gl8gqTSm9JxZFcETWQgqnn4vVc2h
         Eij7cddK5Mrjf9yngvNPVYyt+KFHndZZlEiWeT4jKLa2dsUAVVzcg3xdMFF/366HYjZY
         WpVUeSyuDp012o1pyEFZOciUg/QGnmi4dchXS/s0n24LQ11XrrZ0pVk3uihn6OOLSpEe
         InRb8gKe7eCrBAaHJSkr5sfTdWsyED33eaGAAHhwqnyccZmJoiOZKeR1osclZJw3I58x
         cLeFqZvJJAsI/cMl5V083Lu1aYJF0Uhp8efpek+WmgOsx6SBGrSAGAaGTbXxvhmruikF
         i9tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=SGgUBM+J915l5VV+bj5LNbCN9yWwsOC9VlN/6ZXby+Y=;
        fh=B+73tcIyNnySnZSAMxBnpngFwshwZ4+Hp1sxv0fu1Yg=;
        b=iXUL/6feUWtfIkQbADdOpX4EToVi+budwemw7r3eyNa7uZ29OxHlOWTZKtH3z84ybL
         DLpLCoSAsW6uw4+uzbIWZl3ga54S8/eZnD/8gd7eDITc2tm4H2y9HtSWQv+K4rdu5z0d
         KlExBI9P9e92faWNHZKr8qNuBpIAzf+kON45hgQ3xlmzfMrUfFwVkJnYgjL/HIuqcK61
         UX6OJG/OSDVI6oyIwRJhenwCPurazkWwfaBEKX7tEMGOn/ro3lpwvAbfXStWsGZI0NBH
         GWgqNfYQqB1ZT+hnF262yLaEuGzi38zFeg9+a9GUdbm0uoq8FWzaQ2856ZG3R63E3n8i
         s7BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=hn0bsjZU;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893189; x=1751497989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=SGgUBM+J915l5VV+bj5LNbCN9yWwsOC9VlN/6ZXby+Y=;
        b=vkoGrrA07nMiCrQHvX8NamW1Q8qlivNeJ8TCxH0i+lwYXnrtxYWtCFIUfbnIZDv2Kh
         9g1z50jzHNVLCXLnzqK82QXThCT08TnaTEvk60SZmIpHKnCgJgYhYZ7inypsd+UOaRJz
         gvQqCer/gJ0xIldLnKNqrjcs6SDMGU06pVaZNPDqm96ks1Z6dHN5kmC/yIXmWew2qytf
         DYY+6YqtJDoyLpJJ8cRCEGErvYzVyBdNCec7FyXJhIffPzxymJzJTweSDXOTPrPtIicD
         f6lTLrna0uiIHDtfbAaXVdNS5eK7b9EcQ8oppkWlyo5uTeeFykiyyjenI5c3YYzZSsMp
         ydpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893189; x=1751497989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SGgUBM+J915l5VV+bj5LNbCN9yWwsOC9VlN/6ZXby+Y=;
        b=Ec+6Mkk6MoXQR8uJnSrKtWZGa9KnG0Ppi264vEfKsxa0yXAe/fDX2A6/nLRSoVKlSx
         P21yLQlzlKJA3PAEx9ZCkJ88muKFo79sOJWy2pd8TQf3hRq6dQinee8PB31DtHEavsXQ
         Lf7YeQBZ9uqTt1OYAeGJlZJJXmf5wPCH6mCPlMy+Kzje6KD3WbhxRPq+TOTq47JsXd4C
         BBOvVYwKYsi3gthU5f7hCxSjN1kg4EOqJEgjPccui8SwXSKt182RJ2hzwGWDvzoSrqIT
         nQCp2DsTwquNvbM9b5unGQuITC8FIg312AFdq0ajzfYhGQkagwVbml5D/THrDtjPMadR
         OWIw==
X-Forwarded-Encrypted: i=2; AJvYcCVkW2CUPNHIuot0Ri1Up4qmm0MQ9/lPid9sVRbjZE/IWDDpoSCsiN4WBeOr1qKvauReolvupA==@lfdr.de
X-Gm-Message-State: AOJu0Yysx/jrvux90Q5i2ddmV1fkj6O+34icL/bfcPcNTWA06Ezz47l2
	Z7fbNbc5sZ9KNGt2caB4YLUWCCN05BnyGL/f9JwNc9Ce2xQMiH8ySqaX
X-Google-Smtp-Source: AGHT+IF/TY5jQ0nQXPR5IuZzwBrOljEpsdkYDVYh0IV+CJje+4pXMJCfVCqWcCgwYk9vq/Y3pFqeYw==
X-Received: by 2002:a0c:f088:0:20b0:6fd:74d4:b6 with SMTP id 6a1803df08f44-6fd74d401a8mr23223486d6.28.1750893188929;
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeWEFsms14N2ZW2iJEao1W+QOedI52ybXtk2DCW5t+71g==
Received: by 2002:ad4:596c:0:b0:6fb:4df4:35dc with SMTP id 6a1803df08f44-6fd751469f0ls5824766d6.1.-pod-prod-08-us;
 Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkdOMtWvNvYrPIcgixJJq2adBWVA8IbX6G6+ylT5ikY0KsZLFy1otlQ43lhINPLtU3cAOoDkXmku0=@googlegroups.com
X-Received: by 2002:a05:6214:4009:b0:6fa:c5be:daca with SMTP id 6a1803df08f44-6fd5ef2aeb3mr76854696d6.7.1750893188015;
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893188; cv=none;
        d=google.com; s=arc-20240605;
        b=DWScM+/VM9E/TJy9nU/ojuGb6LNlWfp5CIR2Ziga5txytT9l5HoNyzu+5ls87RKh0G
         nv3PPlKnCqtLB5FJ+K112ZQX5lSe7cIhEkSFDi1OPCw1eORbYjDe8O8SDH5PQyzapgrI
         yC0wsem0po24HXqQxs/5ciYSZVP7rwfXlxDkgykS67v4DCzo98YL+Rw5sxAI2+rtjPmj
         T4L+1f/r2sDXp9qTeRBOu0mEhsgy6F10jbCZXpOXwHs1fnj5s93eXgE5OF21KavxNkop
         CqAde4OpV5QoBmPvTbihEww19YX2MefFA93keS6RzTWyCSUnmfmEe6lDBpr0Ipbz2d9e
         paGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=DcXQQ4/S996oeRv73ZkzELZ/+Waaj2rm5h5ZDj0KVD0=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=k+i7x4MiM5xB0gD3PqIJU3cLnfnNERjaX/9J9JUGZqP39JEeAJ3gJ7OFmEdRtOAse0
         t4YT/kUCnAyIjGQj72u+9FhOjDSm1UwAzpKctjdIuHLNp4qW0oXj1WJuibktWRPjigJb
         sBNsWDh6nyS2eYNMFGH1cX/7uQSpBMEhukI4Lo6hfzufZzY2BkCclMExWM3lW+HkE+KH
         9Mteai/EGeay/bEJmaVSl9snU5srzhod4i1VfbJsBEmKZP6DAHhPNWzwVUaQ2oA2fllO
         b8iJdbdBa8ix0sHH36lj0Mt7eb78pRfp54yhwfwDuaaNDzyusaUda4UBOkxHv2x+O4gj
         iVlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=hn0bsjZU;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.205])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd772cb5easi76736d6.3.2025.06.25.16.13.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.205 as permitted sender) client-ip=192.19.144.205;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 65137C002812;
	Wed, 25 Jun 2025 16:13:06 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 65137C002812
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id A7563180004FC;
	Wed, 25 Jun 2025 16:13:05 -0700 (PDT)
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
Subject: [PATCH 01/16] MAINTAINERS: Include clk.py under COMMON CLK FRAMEWORK entry
Date: Wed, 25 Jun 2025 16:10:38 -0700
Message-ID: <20250625231053.1134589-2-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=hn0bsjZU;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/clk.py under the
COMMON CLK subsystem since it parses internal data structures that
depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 2192d373610f..27521a01d462 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5987,6 +5987,7 @@ F:	include/dt-bindings/clock/
 F:	include/linux/clk-pr*
 F:	include/linux/clk/
 F:	include/linux/of_clk.h
+F:	scripts/gdb/linux/clk.py
 F:	rust/helpers/clk.c
 F:	rust/kernel/clk.rs
 X:	drivers/clk/clkdev.c
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-2-florian.fainelli%40broadcom.com.
