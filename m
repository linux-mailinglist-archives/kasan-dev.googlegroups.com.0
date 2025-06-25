Return-Path: <kasan-dev+bncBDP6DZOSRENBBB4F6LBAMGQEGLSHJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BBE4AE91A3
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:14 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-86d0aa2dc99sf47816339f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893191; cv=pass;
        d=google.com; s=arc-20240605;
        b=LfRh+DRLV4Kua5OYrHuWsN69TIwwpp7Mp+AJBr6B3K7UXzdpLPU8C+ChSSfVbKrWeb
         WCVz6Nx0Vkvjl3mHKr9WBtN2+Qo0J1HcVveH4KVYAChD0u7dqeWmRnkPX1AoPNx3cm2M
         ec+KVP5DyCnHQ+DR4P+dRPeKwbS+7a0kLJtKzFWusci1T4bg8EmsPRbkc5suP9ci/t16
         RGreXAkU1dgIFEA/Cluz+MIw2I7XxFgNRFDiAXnPAofGwDoTybvvZuZvOW0fgqh52+1X
         Cv018KxhzrOX9i15rvjLd7KHosnYV3SKqYu9os5H+ExFF3e4rRvQJIcPsmf/LpI9wojW
         BjVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=mcR3bi47VsrR+T/7QwCSjHGhrepSn1c/rGWMe92uiQ4=;
        fh=g1mGLF9CSKldf4xikQV1oaob6r/wRXZACuUWU61Dj60=;
        b=cHDFBsOVWaxz2i76xQCv078N7kt7N2t+YZPc+fAVSqrvwlKOVrCgafHR/tLkTjFoe2
         uIPSwbXp/B5eNDq1B4cAtKJSLrPCOEV42G4J1E5DBQPZqHp7pUeKmfAkbCNJ+MZpGfjk
         Txct9Owj/8H1+rZ4c/zz09bSYQyN/ZgaB4bUgWb0sw5DaEIcV3u5R76fqHzyteR3NO/R
         epkALELVne5NkmzwWP/20Ky6onxMAFWKtdcdSZBCvSfnVNTcDZbE5COub2oq9Dak6YuA
         pCMDinj+y+GSQYCHufDKEf/tyG+47nQws9QrDXk9wm2njux0Tt0dJUkfa/Zm3yvM+qAd
         /w+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=KT1eXZq4;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893191; x=1751497991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=mcR3bi47VsrR+T/7QwCSjHGhrepSn1c/rGWMe92uiQ4=;
        b=AdUyWHmg9HBD7GABQcMhn2RavUpmYCrDLOUQQUpQ40uPvKSPOvmla1wjKla6Nrm+FM
         fmk16Bdfx0mAfwUkFOQ5HBKvva/sjkml3s1v+JZ7fUiqCphpkpK6JNnbb1pRxr81Dvq7
         lAtPL/bVB2PajtAgn1cTayVeifc/6QzWIotH9DdvkxSHYRkrwHRxouq97yqY2W+VI6BA
         eqRLywrvzF+XtlhWbUIrkwMvylCS+T/T+5ENfbyAjhESZE1oXa1w02JHMJOPrK43OaC7
         7hrxpFgKarBWynu6fKI6dmjV2n/yvD5jKWVEcJSVhWeMyzRVa2E0boGrZU3gsQM2PJ2P
         9oog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893191; x=1751497991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mcR3bi47VsrR+T/7QwCSjHGhrepSn1c/rGWMe92uiQ4=;
        b=R6LErq1NNU2bJTlzMZJbZvDb8WmKcLIU2qZ8a1ErFGfyaAmUb029b3N2WEJrGCSRJ+
         PkTvtLoPQ7Qwt9xZ3Dqpze3Bc6U6+8pJ83j+UsKF++pl7qh/X/tSmhH1WFUQpEOiOY08
         Qwo0MRi46PRHG/EhMMQ+bRbUPsMSBQ67QO0V6hIhdciZs6Oma+hY6SxHxEougjrTjQCF
         iGjOdpxnShg1S0GuiRDIXbY74UeXdQ4ouy53b8E7z2xtiP4E/I4Kq44E7UnTbMW4Bhu7
         mtkGb5IR9KwvLNBd5d9sM8n/jWRPRkflmTSKdEOie/byV7n78XFTOswtXjcwaWAmbEv6
         C+9w==
X-Forwarded-Encrypted: i=2; AJvYcCW+WXHDVOilYfk6eifv433AKIRTupoWiWfiXdq8MH4NDLOwp5nuwzwtJIycUobJlgmTkULlVA==@lfdr.de
X-Gm-Message-State: AOJu0YzGeXw1Z4xvQououElZeUM8QNLp1Bu/I9MsclgWXGjFR78PYRAh
	TYAEEEcKv4itxR37Cdl6n2ZYV+0GHvjxp0EmBNmi6XGeRqFA+yXihrBT
X-Google-Smtp-Source: AGHT+IEldOuscSSrh6kjcXSR5QOFMdZfgI9+k3nAHZaQYDc4YecMJpJkhlLSayCbdP0Rz9CkK8LW5A==
X-Received: by 2002:a92:cd81:0:b0:3df:2e87:7190 with SMTP id e9e14a558f8ab-3df32a13615mr63911195ab.20.1750893191466;
        Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZejIdg/ApqRXcdK2tJlTjgTtLHSVErJ6Z73evMMaEO/1A==
Received: by 2002:a05:6e02:490b:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-3df3dfcf3b0ls4525425ab.2.-pod-prod-06-us; Wed, 25 Jun 2025
 16:13:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXt8jtTL9+pIsKdhn5zC8DVQeSeLvIJQ5uO5LhSNnes/Q8B8bD3S46PkDEtbLL01+/ZysruKOogHXY=@googlegroups.com
X-Received: by 2002:a05:6602:3cc:b0:86c:ee8b:c089 with SMTP id ca18e2360f4ac-8766b73ddd7mr693030639f.3.1750893190693;
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893190; cv=none;
        d=google.com; s=arc-20240605;
        b=KNuZApwgmOBKxRaSVGECQW4YLH82Qm623YdggdyUSSysz3QvcQMdbrnmwFXKQ6c7Fr
         h5vDnJPHT2FTw6OLOob6bPlx/7sb+PI3xt1wtC+pJi2x+lBH5cJf0pY1bXw8HiH2fTye
         h4m6r4EFzzU3WdmNJXDMCMW8/rzSeBlyuiAfz9pVIchF9Wx5+4GzzJ6YsxtmclBNOBHZ
         edSfFeCFDL0gae+lziZAsvIGF9rJdksEqevNZqKNvDC01rO+XL8TDOb4YgpgBmBHwyzw
         3lfTRlXgHvMc/AJu2AeKt5f+kp63+FhoXD8iPdnmuMwtbpQJg5a/kP4M9aMdo614wYAw
         Nkzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=kVZiWLHbHXubyrwzclKTzngb9NxOvLNimzbKvWKRUSU=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=hMI4ppFvmmPHyu1XyB7MDQuJQRnN9AI2dz30KpvfjqJ8MzpgyHGJA7hKhhwa0FvVQH
         OHX93bp/bBsNuUxAxk9JjBZuhNzUUhbMZ4lWT0/y7UUGUajHtZZIzAYeOmUiMSSYW3Vp
         el2eOnyq90L4TiBcRZjkwhiCF4kYevM39wqJQbG9/j31GRoSWExblGBDI/h8U8X4fszh
         KQcUI0U7qcZiFrMhl9yBEu5DVigpQAg5ioAmfUykQ/O15vvV2B3akRLPaK69xZXz7KHG
         XJbYyxkZ96YQpMf8Bo7nGkZmBTzG/VvAAnjUicX8Gapuqr7qK9oiQN28Ucn4TWnUcqD1
         dUYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=KT1eXZq4;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8762b4dcf70si56842639f.0.2025.06.25.16.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 112CEC002821;
	Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 112CEC002821
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 7630118000530;
	Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
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
Subject: [PATCH 08/16] MAINTAINERS: Include GDB scripts under MEMORY MANAGEMENT entry
Date: Wed, 25 Jun 2025 16:10:45 -0700
Message-ID: <20250625231053.1134589-9-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=KT1eXZq4;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/ that deal with
memory mamagenement code under the MEMORY MANAGEMENT subsystem since
they parses internal data structures that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index cad5d613cab0..52b37196d024 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -15812,6 +15812,10 @@ F:	include/linux/mmu_notifier.h
 F:	include/linux/pagewalk.h
 F:	include/trace/events/ksm.h
 F:	mm/
+F:	scripts/gdb/linux/mm.py
+F:	scripts/gdb/linux/page_owner.py
+F:	scripts/gdb/linux/pgtable.py
+F:	scripts/gdb/linux/slab.py
 F:	tools/mm/
 F:	tools/testing/selftests/mm/
 N:	include/linux/page[-_]*
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-9-florian.fainelli%40broadcom.com.
