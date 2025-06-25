Return-Path: <kasan-dev+bncBDP6DZOSRENBBCUF6LBAMGQELBUGUZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0504FAE91AB
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:18 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2eaf00d1b3bsf473184fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893195; cv=pass;
        d=google.com; s=arc-20240605;
        b=BTJKDbV4dp3cmtFfRr2u0F0TwFvExgHsY70uxo4ukZEt2KL7P8wyuxFk4PB/Zir8/S
         k72+Ao9J5YrBZD+p4QaKfyPKXIB1ylP3fLvQZwhKCghdtsDLx23Xui/5L5gZOnDdEXPU
         4EbpiuNW3OSTk4mw7sQMtACv72hIdqZZLCGIe5gEaRQww5iRC48KMX6GU8BzPqYvKXek
         MxjdvZ3UGqG/phOkr0aah4VtMj1xTfVZG0UVIm0UUdK+ziwqHWs6SboxpaiYOnV3gQp0
         jVAroww2IPW89lLv2np1dFikB5Tz+ipXeyrNTnoYlFpCao1aiT5PpkNj5U/JHmIrlO8X
         GTig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=p4AyQew4DNc3uEO0Mt+gkPwyBjgDczpQhB6GfN9il+M=;
        fh=41Y0Y7GK8Wq95atPI0MHsrzbVnhuLPu7pBVZD3rnk4o=;
        b=AEjHRJIg+d23ulfbRsm2lsG6DPPuRDqL2uljzB9hfU0AtLLS+f+dslpEdn79c6VmVW
         by8a+Ae8QWOPbdztmW62fzVQvpheHfPnD2nL8JD+30WrDDDRqs+cg4Yueb2EelsodDq/
         0pQdJHvc5AXw9BC+7zVEn7s3+raMGhAsSa+82Q8brFoVIA4QugEc5Wa/ZwYvX1m5flWm
         0IK4VSn8jRRxmNyHez2h8xf3xuoRUncE6zM5fAc1Scbwrzr/iyRd7EuEe3eOUi8jRXIX
         bJws3EjoxVTGzOEjPe/k3BBuTY8+ZlWoVy2Y/z9rVLk9DkGt6lojto1B7yccG1QsdvG9
         6lvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=pKoUJLsG;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893195; x=1751497995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=p4AyQew4DNc3uEO0Mt+gkPwyBjgDczpQhB6GfN9il+M=;
        b=NzkEZoXTPDHD1uGgyehbdNVUs8v5UbiwZ+T5WMrp2Gigq8jBIrHAk7uNBR2llUoVjk
         Z/LWNq9Ed1c4PcMFAZUEw/AXhB0nUlZlqU7O2tnEGbTygbH+rJ1+s00F8Mk6WEGu2xR2
         /+v+XxmiHOw2YeinsOIdIyPaomdx5QDfDsModo11/6RWHfB1UGkeQ+N0XBDyIKgDbqss
         E1J/93T7DG36mZUK9/7Y3zIhD1CTyqIFY62rmSOlOnXiz3V5COWGpu9nTn+EwMLq5Y2l
         t/VwL/Ffgb7a+NQwiG23PSDCWTBGeHmra1VW0NeL5fa25aaA5tHF7KU30hhlVzP48WKC
         ewCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893195; x=1751497995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=p4AyQew4DNc3uEO0Mt+gkPwyBjgDczpQhB6GfN9il+M=;
        b=VCSqFjDrmrGwXCnjt9qE7YPS3RZ0btC8CdTcqsickvL3vUjOkp+cbeZM4jq48zEJH3
         EbpSZIXTHe9/s/Aa/ZZkgFXVtrVhnChiSMP8xTDXAdP71NMr3zX64kCXvwXsm10N8dC3
         yigLlG5aNe6N/jFu46vR0fE2tElbhyx7McXgspjGXtZZ2GJP7DPRYHO01+iGvXGimHoV
         tcbFa0NZiXADU91YyRy7pQNcsp1vJ5yZ0GSCQZ3WHH3deE2w+q/0mx5lN0ZJmyvWcGln
         ET5kXek9/DtnUePypGkhcB/qgoCynh509AQ71Lx8Tx5bI7s4BmEAX7Jc3DRNmsN3SKln
         V6FA==
X-Forwarded-Encrypted: i=2; AJvYcCV3wd66Ppol699aYxAfjrY2Z6G/PfmLGV8cQ03m84fBXgfMv3wPIB5RTLe3IsQvWPJXrZjkYw==@lfdr.de
X-Gm-Message-State: AOJu0YxHfvHrHj8D8wZXU7VURSWBT0dLBRrMiQfPTuh6r8By7OtuOW2n
	CYOerhYM1C9FnBfq0NN2MNNscgvxgXKzPsuThQDiatq4wApzDdUwKKqf
X-Google-Smtp-Source: AGHT+IFRX2KerUWvcYMJnaOWrT8lH+G6FSgd7M6Ir7Qale9xCSuvJQyJSXx42yfs5AxoXZCha9FM0Q==
X-Received: by 2002:a05:6871:72c:b0:2bc:8c4a:aac2 with SMTP id 586e51a60fabf-2efce32bf94mr1323834fac.27.1750893194720;
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZef6YSe+9KkQKRgLpS4eduqNEZJ+LcFe4entBMbe1YsCA==
Received: by 2002:a05:6870:91d5:b0:2c2:2ed7:fb78 with SMTP id
 586e51a60fabf-2efceea298bls195314fac.0.-pod-prod-01-us; Wed, 25 Jun 2025
 16:13:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDeXY7tZo1Ev+4BFyP3i5js/v3cp1CeZZuVJNJLxA0e3yw7ngQwGqB/jgTKT2Xo2dY6bl6Wyx6oP8=@googlegroups.com
X-Received: by 2002:a05:6870:d0a:b0:2d5:2955:aa5c with SMTP id 586e51a60fabf-2efcdda663amr1237848fac.0.1750893192352;
        Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893192; cv=none;
        d=google.com; s=arc-20240605;
        b=hJ+1Ci50Fkz9sVMusa5ao/nJ3HgOuVK3vtb089MoFSbcBa6UAY/0Sh+vcPXzDHWk2Z
         /SGKlGRnSjmC87kwjgE8WBUp+iewudL7IhhPPJwG7tyvnh1wN1cjtHB0Uz9ui8U99CUY
         CEhOIzHrvBKhNdN/WXtXMkUIsBtyk4os6YnETjVK+1sPzl8i0wQhjG/o31L/C78BfQBr
         LJsSEI0Rb/BdHQgbIfSEa/RUm1aSxVOTM7JIZEEYmqpxyRumOi2PO2hMY0KquSENUXpE
         GeJy3irwNTx5O0rnQ6h3qLfxZaggVuErkAB1TImZ8IFH1ytAHs/FdUvS9tfz+fmrQLv5
         /YaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=aIMaM4ibbWSp+1YyAgspl9CK//LWmQPq0AAdZ8caZGk=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=eG54LAUtYwG5DtvhMoD7Uwx9nTw0OQ7YuxUwFuZdyyj8viafU6SeLuEv6zL3W8aP+t
         IRYuNGj7egzjivW2eKu8+rowjwJfCiWf4ir4zgkdgAfk7fR+ZWwt8w4pVmZ8kkpzbVdu
         1iUCxtTda04tQqguh1BnzYPL05OTM46zOc9EWxsOVAmIEPPRSBRFi26xkV/nN1AyZNpy
         y6h3Ab/jC8OLDqiXGgXhLFrRv8xJ2BhfYRXNo44HJxvPz07YsCzdjyM7RWCIQBBBiVvQ
         /RQkNf3waR9mhO6xsRRFYyZL4VRFuqgdFVqnD7uSHASUseFmU4QZcP6p7u5Mwzg0HtSl
         W29A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=pKoUJLsG;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2efd509ebebsi8848fac.3.2025.06.25.16.13.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id A9C5AC00282F;
	Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com A9C5AC00282F
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 1A0C318000853;
	Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
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
Subject: [PATCH 11/16] MAINTAINERS: Include timerlist.py under POSIX CLOCKS and TIMERS entry
Date: Wed, 25 Jun 2025 16:10:48 -0700
Message-ID: <20250625231053.1134589-12-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=pKoUJLsG;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/timerlist.py under
the POSIX CLOCKS and TIMERS subsystem since it parses internal data
structures that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 687f2b7cd382..224825ddea83 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -19866,6 +19866,7 @@ F:	include/trace/events/timer*
 F:	kernel/time/itimer.c
 F:	kernel/time/posix-*
 F:	kernel/time/namespace.c
+F:	scripts/gdb/linux/timerlist.py
 
 POWER MANAGEMENT CORE
 M:	"Rafael J. Wysocki" <rafael@kernel.org>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-12-florian.fainelli%40broadcom.com.
