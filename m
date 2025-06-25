Return-Path: <kasan-dev+bncBDP6DZOSRENBBC4F6LBAMGQEA2U5BRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 673DBAE91AD
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:18 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-234f1acc707sf2960845ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893195; cv=pass;
        d=google.com; s=arc-20240605;
        b=SfqUMs6xTWKsNqT66d5DyPDOQ4QU0mf1jIEI0ASabZmTj823r4mEqFbutiPIqapQtH
         x6mF5upi6YX+Cd/uSRRNEDtVIBTj7IPaTAniU+niRoCqw9WlGbOcluZb/QwGKFTyjd4f
         N60RF4vulyZBF87j5SdGAgff/CEBHVt4vt65XAUtRfGitm13LJgOPr7fBA4R1FdoS2Oi
         GdFvzuN5VvJuamiT3OQ40IcY5nhDk6tUoXK5iBQSTUztb/GloGfjujXjkciWlQuJ/mzn
         opc8G95OvJY3JZ7kUDVJPDubKLkotI46Z/riX76QoklyrTBBsV4IQsDsA/A0NytPwWGP
         vZzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=eEh+dFvwXAhFz5Py4fijtec34IvhXRK+UvX39Q83zm0=;
        fh=twzySMwZyqGhhwJq6gI0X1sUGjmp3CByLTBqDCvlVmI=;
        b=NMFFCGIfe+WlAa6pE701Xza7MzzlI5D2Nej5e+flnYXehwYYS5gpLS2AxffebkHy34
         0S2bILKmX77P8k80Go+Tgktlfbidj3VbjhIFWaYX1XJW3qeLT+s/5/sUt6fPOL9szoAW
         1EQ280UVM7ZosDZjIp7xMcGXDqIOYvsd9032Uan9BA1jFDx1mtspXOE0YqNRqkRA4TgR
         W18J8bQ7nCdKKvOVj6Okl65YzJTAJmhuzEw5EgCr/T+/UfRoM7cQRFsTwBDV8/3XRpLc
         kgBAZOWUnZvH5b4Vgw7CGyViMFLVixwhJg8xdpuhPRL2bLYfvZ/IZm9MCos/quWOirSn
         hrHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=inTefrWH;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893195; x=1751497995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=eEh+dFvwXAhFz5Py4fijtec34IvhXRK+UvX39Q83zm0=;
        b=DxBaMYCbwZYkBy44DpG6GhpBoLlhDqYXq9aszaHalTyvpmh8C+IzCgVYOokrvSDvV6
         2RbIZCi4ng4yBpZ78oycQ8TeuKE7tVNSTDZKFgVHO9A9buCmusNfqsaXBG3LMPJFkZlF
         DWsPRNGeIybir+K08xJLGM2pNzxI1nDcxRLonU7mO3bPxFwUSin6JQ0eRHaxiIUjKMZY
         fKeRiszzfa6rKJCdwPj4IRkZFpM+WCdAZy4Ww7t+Y+6mJnJpm2zvroieyzia4Ae6m2GM
         rkb2xZh9iKcVWkcitXJ8tDxstDhaUeXpdqTNQE/ppsAQ6QuGaRzPfPnU7vRbcHwpyB/d
         eCrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893195; x=1751497995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eEh+dFvwXAhFz5Py4fijtec34IvhXRK+UvX39Q83zm0=;
        b=O/Np8WiWoLwbU67JzEhYjgwQiBgNUnmW+tRzsG9nqfF4RDQH9zNRIqBImyGdnOFN8t
         mpDVlUTGUJodpHFuAZdyntY6morzyEKbVt7bo3nedmD/i9FZds/v38Ib03pJm8Xx6qWN
         CcTAtL9eDZSftfK+G23ykLT7EeVJnlNUlC9VNSDHdPEqNCX2ad2t2DHA1IUAIeDbTJ5Z
         7JMZFmoBndfCOiyzd3tgMmjq1IW9PdZZDbl4w1jcjvJUZ5x5p57s1a9tBAlN/FSU0UDJ
         +yLyXzjU4BXfxO2TeJ3rmLsmyKj9uOZfmW/9NcOPleLi4HLdVJy5Fzz7OeAH24nXTj+p
         Coxg==
X-Forwarded-Encrypted: i=2; AJvYcCWDhuMsg81ktrNFo05P5K/DCT/N7/SC98Oq6mQfy04YLe2Il3y13T0b3dHT1khuUxYM0LnIQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw58WvciEBvaGDdvxTHztqeWpZUMxZUmkNCZRnSvounYErWNxKD
	C+h1iWK3Q2tVEH5QmigOhZ4mS5GLsFAmp6SAByn1VdTD/+ZKtjdtvqrK
X-Google-Smtp-Source: AGHT+IHYCsNkmmeQshJPMWxmY3lG8iBVP7/9z9R/LyCx5+MC2GXrp+Fzcoou5xMEGf/ujcjtRQJMew==
X-Received: by 2002:a17:903:32c3:b0:234:8e78:ce8a with SMTP id d9443c01a7336-23824086befmr83598385ad.48.1750893195389;
        Wed, 25 Jun 2025 16:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdvORnu+VIp3jn565iuqbSbShO9yFzrpeFFdBWLTyr3aA==
Received: by 2002:a17:903:1aa6:b0:234:aa6d:511a with SMTP id
 d9443c01a7336-238902fd23els3357965ad.0.-pod-prod-07-us; Wed, 25 Jun 2025
 16:13:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzWFyUneeoCZFvOopF6IJRujB+L9WDj5LqWKu995V6IKWy5T3fW97hBTq5pKS4hwgJaFmNsB+9p18=@googlegroups.com
X-Received: by 2002:a17:902:f689:b0:22e:4d50:4f58 with SMTP id d9443c01a7336-2382403e0f5mr84862605ad.31.1750893194158;
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893194; cv=none;
        d=google.com; s=arc-20240605;
        b=aaNeT68Ko8MWtGxyn2+0yu2Eo1GQQpm5yR1/FL7dH6EhFl/taBsHTD321+6eaIVPIY
         LSYvRnY2b+VHtHpil7kcpQGPrZeBWTf1W9A4mvfkBXNo1JlwUadQv+0d16YlMeZa+Rdh
         xCOchjJ5ItkhIUm23awiGkUcXQUvNv4G3J29Ff09EhY4Vwq9CqctMSKL9jZfzti5Hm1n
         2EDOaJwJc1tph2Slr3pY/BABbMuvdGxiPA2Nn9kg5eUObZ29dpWlhdK1STIZ+ze0epRA
         fANqAAcRW1DOjsa81xSGKkG5mz7SeOEupyTDWlWIqwVpzhIiLLAeuAN6yoYiQNdCMdBv
         COhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=+j4iSnXmFtPnK0YxDF/n1q4snnUGpD95v2UZG4MSxio=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=NFCL3ve03VbRzXc3ozsTgyOVonfLkK3rU4d2ky/rIkr1kRZGiMmxkchU03YVXAdO94
         JRsCzpHB1Fd55Cxpb1CPohh+2KfQ3Rus7F/BLKsUfPeav5NeW7HE4Y4e6DYQ0HAeNSg+
         tE9nFzWjCSB7APgJQEa62emEL2shYCY8YaX24NerYzA4e7oEFQwnpTIdZLtPaCIKsZmY
         udq85Agd8/rtS7dv68zmn0pP0d5DwdgCifJG4Qa04OrwGuq1539D8Zb1bwTOr+2dG+GA
         nRDrUPSHdy2gpAyYjrp6PQ1zMwaLgnNl/J4RR7GeWH9lVSHYmPR4erLjbglTLFqn9+su
         b17w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=inTefrWH;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-237d83c6a56si659915ad.3.2025.06.25.16.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 45833C002832;
	Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 45833C002832
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id A9F5A18000530;
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
Subject: [PATCH 14/16] MAINTAINERS: Include vmalloc.py under VMALLOC entry
Date: Wed, 25 Jun 2025 16:10:51 -0700
Message-ID: <20250625231053.1134589-15-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=inTefrWH;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/vmalloc.py under
the VMALLOC subsystem since it parses internal data structures that
depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 610828010cca..8e86acd63739 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -26577,6 +26577,7 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
 F:	include/linux/vmalloc.h
 F:	mm/vmalloc.c
 F:	lib/test_vmalloc.c
+F:	scripts/gdb/linux/vmalloc.py
 
 VME SUBSYSTEM
 L:	linux-kernel@vger.kernel.org
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-15-florian.fainelli%40broadcom.com.
