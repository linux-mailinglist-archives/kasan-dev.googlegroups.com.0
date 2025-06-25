Return-Path: <kasan-dev+bncBDP6DZOSRENBBBUF6LBAMGQEGISDMLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DE54AE91A1
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:13 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4a762876813sf6995101cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893190; cv=pass;
        d=google.com; s=arc-20240605;
        b=Eq5RueDk3LX/bCE5F9tZ8pN0DW3velo64iSaDuL7t7CezCNOCJ1rSDCGXZ3DuEOdwP
         AHRsx0Mv8MUnQYyYi50gvFvgUvbI28U1Vbcgk6cLHHKqMRb0fAnGVcdNN/Qjbe7yJrVi
         PNRkkR9RCYIxo1GPHD1g1grrBaI36dQE7er24TDfepvBHSyTBvUDfldg5hyke161TRTP
         kVUbRSX92XgSDjIoPBmxd7xoH/9cyfiU5rgyGXHVzR7IndLXB/f1mD2jfqs3QD/eRiCE
         tyzgO0hXcl6fziHsLO58BvlFKYk1uMwBOC1+fkjDKNIY2BWzEQ9Dy65dBSpUwK7O/Vuf
         GPcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=vQNjC2I1ahteV7/0vYE8eaSIZ90H3HBhzOb/329zh3A=;
        fh=YGWaI2LI1ZYCUQSoObpx8EI89cSPLMW/KbklwgpcRiw=;
        b=g5F3ni/xSyRGxuSXdi/bPZoKe+zeTUHrZQgHpk5WAXZKTBPbdMRRaneB30qRKQ6mdA
         BhRTNHc0ER2gC5sO/Z4k7Hl5yIP2b+NbY/kelkbdDuLGw/7iR7Ecib7Sm6WAvpV176CT
         HSRI9D35tqYbHsPeFsjdYqTGg3i9w0GuEOI3pKDTYnxNcOchTS1m/vtFSM+rGEaj8HjD
         O5XwtQ/EwVhjBe+24LHuBYFgfy01AzhKQm2uLkWsFXhLspIq/IQLleHO1GhREQXFgsG+
         xSv4bPRR+yy0ACQxMfLwvdQxCbHDbHdIl0T8Xg27+7tU/xWT27l4OBF0H58m/mbQir++
         YUeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b="H/Hr1Is/";
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893190; x=1751497990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=vQNjC2I1ahteV7/0vYE8eaSIZ90H3HBhzOb/329zh3A=;
        b=SQL05CJphnf1AZ571xQ1j2lerZl4gBfsK3eJmGUY7ZOFVO70uelIYvljDLksjVdd4D
         x/4yoVZkk4/FLXM10Rj4jqjlpbnfuDbSGtRgvW+MlZjfPt/3Roz41b/xGmxekEZkBHmV
         /czcv01sg27dcZzgWK0bdLeS6mW/k2H6IiV6ZRYb5456QtRxbioZaU2qWUmQSiU2PBkx
         oaFp/bc4aDAX4SvjAggYzuVEA1ld25skbdeRUC+kZe6ITFYnyVqVvCuOc6/N8SNin8e8
         flGira23YY9bqd47d91irlFKPz7Cc2kZb0/UeGRSqV3/pO8k5c5RWfQSYcaru4PW4KMT
         8hGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893190; x=1751497990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vQNjC2I1ahteV7/0vYE8eaSIZ90H3HBhzOb/329zh3A=;
        b=wbMCpjyjZM9TlNJBdMkZ7LWFh/26zSj1j6LBODRMgL5MPmj2aYoLGM0hx7F0l/LL0P
         +y6CmWBpx8K/pMuYzF2bDRdUR/D/TnDiuvVtRWKe74TKdvp6t7qJq2JQbrMBPztLv/5W
         22EnTzvQn3QVUHnYGvorjZvQ0qDKyHT+sHLYyXnlFLfACqbEJUMjvWKkniBA3OnFgffx
         zJvPuL6wzQacVuL6Rrvu3lmhnjW1BaUkJnVmJvb74KYJ3V9DjY154LR7DvbhBXl35MV1
         KdtcMhDCgRq76J7AYjHs6fCfLvORgC66vsrZO+FYQ+YGXmVlrB/ee7K+QZPNKVu9urK+
         p23Q==
X-Forwarded-Encrypted: i=2; AJvYcCWAogqbJgDko8d8tZE/vWi/HzdyFKQfZTk7bHNxv5Sh/xkjQwc06OC+2PHiMNIxCyYZKt0QnA==@lfdr.de
X-Gm-Message-State: AOJu0Yys0K3eFwd4EpHTkxhMvnoYjT+YnM9J+gwpRo0tCqQaLRrfrFe5
	/ZO8ylxIVFuu1N9Sjb5ZAsirZx19EpjnMxF2gTjKdzcwd57x3tWXA7JW
X-Google-Smtp-Source: AGHT+IFm5qTHPKJfGmw8uZaJAsBweUf1ra5hpHbXrMiXE7aEuvCnsHaplQURu6Kt5+/Sm1QiFLCycg==
X-Received: by 2002:a05:622a:400d:b0:494:acf1:bd0f with SMTP id d75a77b69052e-4a7c080d7ffmr67639311cf.42.1750893190252;
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdayNFXIOXY3zcUiXcl2Zx7tE9MfsrGL5HW8RH1mq9Mzg==
Received: by 2002:a05:622a:391:b0:477:c8a:e60b with SMTP id
 d75a77b69052e-4a7f322a5efls6132481cf.1.-pod-prod-02-us; Wed, 25 Jun 2025
 16:13:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVgPcz5wHYn+dfVIC1rjWX5Y7EXoXeKD1+Bf3+thDdEoC2T2E8FoIfJeU4PkwDfzjSEAfWtP2+EU/E=@googlegroups.com
X-Received: by 2002:ac8:5808:0:b0:4a7:5c21:d4d with SMTP id d75a77b69052e-4a7c05fbdf4mr82282571cf.3.1750893189050;
        Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893189; cv=none;
        d=google.com; s=arc-20240605;
        b=Zd3sbBdkGt7Q6mOuVHtBfc6mSyBs+xK55Oz7Pm7uesHV4TH8khWr5q5QLBZ7Kwk0Aa
         vkun3NJ6V0ShKmF5iK469vmbT0NJEbRgoBm5mKH2yv+/kOfsHM3Aj4t/GMQ0ao84Er+B
         RqEfOzQLlSHDgiLz60+VTiJZZtDW1je3NSZJ9BouK04mzF0n+rbmgStbDZ78CIyLO3ai
         MAAmqXt136gt+4eXq16aXPw4iBpID/ka4qp+6XQvgFbO8D8ptynYfpBxmEJlu6tIotbS
         PQkYdclTU7tPJBfWjQlPkWVVvFCNh8Q2Z8iRZBBUwhxakP5DrO8SrTh9M1T8QBSuHtYn
         9gSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=2XhSG1nzR/OFmrsDBDixED1uXOJiWXv8aL2z9IzOhsA=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=Ykdkrg26zh4vVHzVAiliUpXFsVpZdQbQHrqkc1ufOFS2uUFGjb2NjyvvuA64tPsfmQ
         ZjtVyhoi/X7iSfgEQDXEkgCNFnoRV99aminIj1nC67TFrtHSGaSj02WtLnK9wuk06nMX
         VgEQVqawsYB4EBkyvtyZxbJwSWlynG7wcSkzH/Wje/z/KBMM8keW9quwGHTyVlpbJvaN
         9moHphGNGgd0+muziu4UB2oP/qPIvbCf3ZnBTa/7eOIEzGRV6Ap8M+Zi11ED6c1OZ206
         QSTfs3T3XCc/j+wmXCK2Td5iywxsS0NczhvwwtwQSmZrAYPREKfi4Z9/7B73fBUKHjxq
         W34Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b="H/Hr1Is/";
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4a779cf1538si5427041cf.0.2025.06.25.16.13.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 94E64C00280D;
	Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 94E64C00280D
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id CE7FC18000853;
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
Subject: [PATCH 05/16] MAINTAINERS: Include interrupts.py under IRQ SUBSYSTEM entry
Date: Wed, 25 Jun 2025 16:10:42 -0700
Message-ID: <20250625231053.1134589-6-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b="H/Hr1Is/";       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/interrupts.py under
the IRQ SUBSYSTEM entry since it parses internal data structures that
depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index cfb0d60ef069..e1eda0d9d671 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12803,6 +12803,7 @@ F:	include/linux/irqnr.h
 F:	include/linux/irqreturn.h
 F:	kernel/irq/
 F:	lib/group_cpus.c
+F:	scripts/gdb/linux/interrupts.py
 
 IRQCHIP DRIVERS
 M:	Thomas Gleixner <tglx@linutronix.de>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-6-florian.fainelli%40broadcom.com.
