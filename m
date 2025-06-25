Return-Path: <kasan-dev+bncBDP6DZOSRENBBB4F6LBAMGQEGLSHJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AFC9AE91A4
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:14 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-610bf6f2c8bsf321983eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893192; cv=pass;
        d=google.com; s=arc-20240605;
        b=g6q1L3GYeLH1HxW1VqTgHDOt71XktBhMQuIzIwHMfVvkFvTzleXa03vzbTD4AnhK26
         aVcHlbZyX/C+W5t6+j35gLgjt09ppxLu+6LVMS43zmpPysQHTPyB5o9ToeRGQiIYsd6U
         ptky4jH/uPZsBSlewtRgR255StGrT7EpzfM68zVlCt/nf8jxxb8xocWgxIZyYU47Wpwu
         5XnP04eF9BBnb3vwy81HhknfRhrTzQY4v6j03n71+69esHmmcSSE4KTzLZsiQg9TKgmG
         ZEjg80ZvxC62pwkCvVti9FRQSy/lhsAtcrguYTI/18nCsh5Ac+6klLjpS5SAKatOr7/V
         N3kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=zzPWzyBQZq+FIBe3L9MX1vJc4Gsoq90ADl8EhMMAFIA=;
        fh=gsa4KCT7+k8e5XA1+GZJgD22tKMtZxnrfH6ttIXiCPM=;
        b=gSvuTAcd9HaTPazIrBNjamq2+mzyM6VG4PLj90lmVHW+0MK/lht0ZSHjnPc7IhhCHS
         zVdiiSbjAwgl/ULvEo9LBX2zQvihxSnOTxYb3TxfMoiLnTQ+F74UBFObPbnR8OnYoGDE
         1sZ1MDuutWcWhN2dkHkyapQykR9nO0UGhgLtVFqfmS8iqGZ7+V7JHCLLzcxg0b/G36dl
         JDFOzOXWmB+6Z9TrARfhMF+dL4LVpsegNs9PFaQyTrw9JhjPMmJyztZboQKsF8x60luz
         RMNJD4F2xlM4lKl3j42kuuiWVptag0ZVymSNQEKtvYCQx3OHcWHjcjs3bxwS1tj7uqxj
         3McA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=TSaImOo5;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893192; x=1751497992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=zzPWzyBQZq+FIBe3L9MX1vJc4Gsoq90ADl8EhMMAFIA=;
        b=vDRvAcC7zLR9ZwIHJJp03iRxdkmnM6NcNIUwTz+pae53qA8TDSVcjQ4bEMqUMq3Fhx
         UE4ffPdT75xydAM/H7oTObEyGkxFaGC+WlPgElIXKREAvK9wc6CgE62V7h3w65wZ8Jsw
         23SVP6kodwIM+uauKLLSwuvEGNfHBPbmJhHJrYRSf5BKx1evt9UZKz73qpRf0kyfr4Y5
         h7VaiOngEnr47l5Kx9JYRNRNBAJkbF+idXiWIQmwaM1k9tfQhDDzabAkYW3/UxCOh+sS
         k6b7y2U+6q0Ns5pPOsXxEUjvwqEMrfSbvv4GuoUmeMZqZHiAV77Nm2YmW4G2MIStQShz
         GEYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893192; x=1751497992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zzPWzyBQZq+FIBe3L9MX1vJc4Gsoq90ADl8EhMMAFIA=;
        b=b1BXHJTsJnI3j7y+ClH5NlUZe+fLF94rdvVVThj87zO/1NkTVOY/3Q2lTCTgqHQQ3d
         qHB2zGzlcHfM4lX3l37zm6JaeDLhDc5ZTY3XPmjqOms0sEiYDP20E032DCE+FFhzlE3N
         EtsP5Po9ONswBtJOnK3QctRzYsGbaBsk8K6vEJTpqdGlip4wD2Uysx1f4kcrS62KmNaM
         +MuBQBkCvpTLFp7BzfAiUEaM7zNWIHjVlBOMnJ59B3CJ6dpO3yjrx2ZPaE3s0pK1fWka
         /3uvX8XEa1ajR43vSgDU50JrJC7VZPFnV+psBmwxwU+TkDytzZQwvU2SxqkY6t/ZIVyA
         O/Eg==
X-Forwarded-Encrypted: i=2; AJvYcCVI4QmV1Bxn9cz5yYinVMZDVh9qTZGzmBOeguVlzITVQooDj0YQunm3UNQUS2wabTvB4v1JVA==@lfdr.de
X-Gm-Message-State: AOJu0YyvMsnvDaQ86BIjEzfdyyYETj6vPWgGXxVP84zuqmKIZiYx3fzw
	/IiBAszx1NUmlPSRi5h7Hp6YoXZf9RFZ6tT8+m6owuV7HlBSFKmGGtQ4
X-Google-Smtp-Source: AGHT+IFSfKWFuujmm4zNjXCqAD6anf+kV4Pp7nEOkYJGvMuhPHB3g5hAdDrfnK/uVnCDAEZoo6qzfA==
X-Received: by 2002:a05:6820:200b:b0:60b:ad9e:2bbf with SMTP id 006d021491bc7-611aa57d36amr1310064eaf.8.1750893191785;
        Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuePRvXe5jAxFlUz9PJEzH5meyqsQBA7Jz8m2fTNPNmA==
Received: by 2002:a05:6820:4106:b0:611:8e9b:ff15 with SMTP id
 006d021491bc7-611ab006afdls116009eaf.0.-pod-prod-01-us; Wed, 25 Jun 2025
 16:13:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWG9yfodr7zv80pppLAzmr8RHfAQZoWBWjMqQhbsM9+QbMFA1skhbXHe1i/S+jybo+pz8jEp0A4BDg=@googlegroups.com
X-Received: by 2002:a05:6808:10d6:b0:403:34b3:c986 with SMTP id 5614622812f47-40b1c2a27d3mr1430880b6e.17.1750893190180;
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893190; cv=none;
        d=google.com; s=arc-20240605;
        b=PDCuI0AqatneKvF7RiKOGhB7i//MQ7u5i2+oj3+f5Ok37cvbV+IovOBN2xUbGm3Vss
         Efm0nGv/NHzfUDtYArIKqN6O99SWynwoS4CTEBYqY61NHV7iOVby+HWQtkIYovPcRKIx
         oIQSPx6e6zmwSeQO0EYahrXxRtAXrUg1olTCLK8o5S/jhEB8zL7h2/vd1jlHRur4n+Xj
         DjJKpoGUMPKjV4h5ViLK5KVRjKEaIeyv7+MmWQmm1/DF01JeAc2dw7hdgxFiwtQOLAuL
         aSQr6WWgNNAugG4LdM6Z9eIGqj+XwIGmPdbcBfU9XjHtS5T8vlO0CIb+4Bm1iEnoVf1F
         oFSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=E7UTdRwPsJHG8wcJ6kVKWxrcXzfIplMuv3E3gNcJi8E=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=dHmyfl6J+ILtct/oQ1WXGTBAURqk5ji0skqX7DaXc+wmDc/GdIMBEwQG9IGE0eI5WR
         8rXOlo1ZVaFW3hRwSDUJmlezAd6xapd/lsJ9G21Wm0IoceDMGnYjF4tbpszc3ODDmZe0
         8eXH0XcPomcqfAxD/Vj+iEZ7eh9ucuyieicrCmdGAWJiFTPPfHNpQbELGQyd5sPMXZI/
         r55WI39l8WQP0oaJ3wJr7YAlIBZxuqhBIRS9tr0iIVlLr38JVdGPy+HLWTwibeyzUN0A
         WE+q2IB7KsXp6BVrlnRAHDsYwpiXW3oRPucdU9pjgL1GGKpYQFWATEGdH/t1S2+fY2oO
         7QGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=TSaImOo5;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40ac6d458c8si657067b6e.5.2025.06.25.16.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 7E611C00281F;
	Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 7E611C00281F
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id E304318000853;
	Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
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
Subject: [PATCH 07/16] MAINTAINERS: Include mapletree.py under MAPLE TREE entry
Date: Wed, 25 Jun 2025 16:10:44 -0700
Message-ID: <20250625231053.1134589-8-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=TSaImOo5;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/mapletree.py under
the MAPLE TREE subsystem since it parses internal data structures that
depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index d997995a92e3..cad5d613cab0 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -14525,6 +14525,7 @@ F:	include/linux/maple_tree.h
 F:	include/trace/events/maple_tree.h
 F:	lib/maple_tree.c
 F:	lib/test_maple_tree.c
+F:	scripts/gdb/linux/mapletree.py
 F:	tools/testing/radix-tree/maple.c
 F:	tools/testing/shared/linux/maple_tree.h
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-8-florian.fainelli%40broadcom.com.
