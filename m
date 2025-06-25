Return-Path: <kasan-dev+bncBDP6DZOSRENBBCMF6LBAMGQEZGZV7LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E36FAE91A7
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:16 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7caee990721sf107396685a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893193; cv=pass;
        d=google.com; s=arc-20240605;
        b=QC6J97ccObBxEvQml4wT3tNDR86BmhQmzymDtXdXNlsTpUN/dZa3u31ALaocuDjhqk
         ZYZ83dJdFJOaOMsBbaueP843i4lfdjZfZQKBhlBS6GdHrnEEV5crGcQI+9OWUhFjE4ch
         l2ktnMja+DyGVH6BBy9flXI5KWzQb0wt9cxxNEB4ZQNAkGWgYNttt8rIQ2p/9XmVxBNl
         JgCOsU+eU3tjDxrfopFwBoNUioKT2kGQwuR7Ty2AaqLBRt4weIV6TVSCMwVaHBI8Wmjz
         iAPICTnaedEuRk+u3dOKKqDatp6nUsDd6aE2h+HIktFfaHwEzbzsgjuWhwMvenhFopjO
         Wy5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=tS0LhZvKn29lcAYl48n1ADofeb2Kg4uA1Zxlk8EpoxM=;
        fh=+Oit38z/a3fyUL4zAHWTSau2C5CVWfHCIUBvVqPBR2o=;
        b=VaDKp0wGh8BwNyDLWjcVFkAVJrUVdoBcKi3Zgf0n4c4KAjhX62HfNPi9ZTrtMQe0/N
         y92lOO7DB5xOjQtHevaE/S0eMV/m/fahVaIHSqFKPCQY/ZNB7ErS3M9DCtHYaqEmmy1a
         WBJNIRhIOh85wHAefUBKmaFjKrm5X0rSD3nOES94cG6BX/Il69cAGF94ITqT7ofsmM0h
         FmQ/53CA/lk6GP+UNtS6HFKK+lFsCWAEtrCBMluJ6ODWNkpyzvArq7zV79Xl+3l3sX3z
         cm5kgW2ny3viy0J31Rg6VWf6lAhFdPURG199NK0Vci2KknUuuHUEOsuF4DLy51MXs2XV
         BTpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=l5eguNNw;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893193; x=1751497993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=tS0LhZvKn29lcAYl48n1ADofeb2Kg4uA1Zxlk8EpoxM=;
        b=XfwknfmSymPQReMHP00N0WIusPJ2UqlSUORAVVbIVfUDMLoU3f9j+pa71M5tPF/0UN
         RwnDt3oqZLXhjy3u9275ZXDLONfHB345vcQtjJNUVZ+qVDryLMbo7LGiNthgRfligTu+
         bwKyhogfq08Z3pBxGvpTKGZNwcOExQ22imaLafbMKMyyNT6LhCCRpufx2b+dFSPym/Oj
         Hogz9KgUB9fUyKshst4pz6tCkn9G9s777qZz6qijsoZ1EnNfsyud/OyEAArwph7J0+dJ
         3kluicOc6wrnLZReQdf8gktsNbJuw4hOxgvwq1HDZuX1XLYfPA5mkxhpArq9YdjZqhJl
         dP4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893193; x=1751497993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tS0LhZvKn29lcAYl48n1ADofeb2Kg4uA1Zxlk8EpoxM=;
        b=WEOMnKGOf9MEl5xpMX+Be1dk3cQOgo1uAWmf7GRazBnBNdhZscz9bVHpGappp1k6Gd
         VAhDslWn3xGGfyn5rvwTwD9kY6mV/mZ51zkSlEHr+fd0/c9yf7xuOBm7uxlybqHGg76J
         AjAup/tMkim6F1OpceIy3q7aZi+SOBsAO7vMfpHLOYyW5BDZVbxA8dRMZqVZKXL4a/88
         a4xmTQsIaxfEuZXqeUi/CmyCQdAhDA4QPmwAF8zSJotWuL6MMOLcdwaudlYmfwL6vmt9
         51q79lql1Jq5Wq7w6eIZ+dV3ubKriISraz4ewsRaHsGlXNU4MvSNdgCGeFzw6WkG7EmI
         8NvQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUG6YuyMxkm3b3qD52nSRJXssMJh45RFpXyCqUoQUBe6RjR7dM7Kk2CQSXbc62xTxwGOZwmg==@lfdr.de
X-Gm-Message-State: AOJu0YzypvsPi1BiPRj5KRy3oRtvGUNI8npCHM1JnxOWH+PoYsEBfmAF
	5DpghIXq6orJ3P3Tf9l36tLVm5yOJbgyP55DHnrIEj8tbB8wmOhWfWLs
X-Google-Smtp-Source: AGHT+IFEc/Pzhu3So3ypXIGq/89kG4RopxcJbBTdCGt59VYGX41Ck9uepD8PPG828E/BzLQSVgKokA==
X-Received: by 2002:a05:620a:44d0:b0:7d0:a10c:95b4 with SMTP id af79cd13be357-7d4296c9faemr665540985a.1.1750893193563;
        Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcAoTMIoUNoDDyAfkpsPk1IlM1vk+4c+PV7AZLE1iE2Kw==
Received: by 2002:a0c:f096:0:10b0:6fb:4bc7:dc0d with SMTP id
 6a1803df08f44-6fd75126538ls6574136d6.1.-pod-prod-06-us; Wed, 25 Jun 2025
 16:13:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOhd0RuBswE/qBrYMV2FgxZUIpaKhAeGoxE0GwUlQLENGJ8hDKZx9/UJBZ+DV7tN3fgURPGOJby6Y=@googlegroups.com
X-Received: by 2002:ad4:576f:0:b0:6fa:fb7d:6e4c with SMTP id 6a1803df08f44-6fd5ef81cddmr77906966d6.25.1750893192607;
        Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893192; cv=none;
        d=google.com; s=arc-20240605;
        b=eHsX3Su9nwGVV/OG9i5Estno/V7ClQTfIuKI2ADYHF2aBN0DqzaPanHBXpni0/+11Y
         ThoTqgk7oN6DygzB/6QaV9GzO/RwJbxbkOulumAykseS8gfoeivoK8nXUcgmCJDf94I6
         /mnmKNkIWClmpvBATQ1Kjm0/ugAnWhmf9oy4KI5mRumIHVUo1zqACA8MXSXSY1GN/p1K
         9GOu1XVuiGj8A4s1SwygAy4GBYrn8XW0wYR8UDUxNjt/OEuAOHNLomjg1AeV6jTPQMpt
         OjIRf4fQP9xM80M5rMaGkl8aai5roLYz9JFIp0bh3YWF6MzMHDK5g3dbncMIy58i2iyh
         ntEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=OSywoB4j80jM/NWz/WB2jbc7zvOmdw+0j7s10pJqte0=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=dwVOcXqCP3vW9YK3EopJwd6Ha9W1rL/9+iaPb/qlDCJas8EoI4zGis3txAXHVTidlC
         E2CLTn19wwsfNr/2AVJx4dpUKr2xu/JpvBNwN1D6HOSoWv32VXWsnxXVVQAHd/aaBL+J
         aBCtJiZE50xtlj1Zv82B/5pkqCUIbs3r376466MWVEg+YlmasrQaVXFIcCVKurz8Oh/i
         6yFlI3a3esu3m9Yq0Ow3qL/8Ge3DwOO7XqNzz36wGliWuLbfGqGFDWNT1f+8wAZ5OD+M
         ZFe5ZeANknYVnrGNlaNm/H07hNwwHQKo8X8t0nn1mw8RA3/xsYc3zT36pLfiR4elA8TG
         0zqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=l5eguNNw;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd772468eesi84636d6.1.2025.06.25.16.13.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 39D83C002830;
	Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 39D83C002830
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id A0DB818000530;
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
Subject: [PATCH 12/16] MAINTAINERS: Include dmesg.py under PRINTK entry
Date: Wed, 25 Jun 2025 16:10:49 -0700
Message-ID: <20250625231053.1134589-13-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=l5eguNNw;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/dmesg.py under the
PRINTK subsystem since it parses internal data structures that depend
upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 224825ddea83..0931440c890b 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -19982,6 +19982,7 @@ S:	Maintained
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/printk/linux.git
 F:	include/linux/printk.h
 F:	kernel/printk/
+F:	scripts/gdb/linux/dmesg.py
 
 PRINTK INDEXING
 R:	Chris Down <chris@chrisdown.name>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-13-florian.fainelli%40broadcom.com.
