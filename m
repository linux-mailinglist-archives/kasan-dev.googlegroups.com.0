Return-Path: <kasan-dev+bncBDP6DZOSRENBBCMF6LBAMGQEZGZV7LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 81D56AE91A9
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:16 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-740270e168asf304278b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893193; cv=pass;
        d=google.com; s=arc-20240605;
        b=gtWIR755Hv+aJ5F5KARE4kUvGuZp2Yal1QNZIZkldYkL5HFq7OTlQ/R5wq2NFaszqn
         gblY7uOpotXx7RRQuIXVdhvraU46A7eYpeO6px9Li6BpX6Tasad5nCN4XTLRzHP2NN+v
         g/nS/9/IbXYG07+zHnmrop4VKECSq4WVourfMkhryhmpWci7rYFOftft6muOs9QipkSn
         Nb0eUZHHU1TiZwxbbnDKpufz9xwqXK5JJ3eSP5x4C3tJX4qdwuwqfuaAVT6u4a6lEy2r
         wREjuY8vPO6YACif0cuipLHPd9dj8HMQRrfojFsDi6lJrOEqCh+79lVrHWESNYO4azOE
         2QyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=GbwgXRhIu5K/Z5+UUHGephtAZQUH43IRK8bipy5RE2g=;
        fh=QaZsu7eOApJPh7otqBYAEYB4UhK+XRyDgXUS5sDHEJE=;
        b=a4edZO+otpljdneAhPsfkDcGPEefOm7kB4pGaiMZTBu3YbxYibufOalUXUJXpv980P
         6xOIAmRzMo9OQt+BoLWOhA9dBzHNDnXYdscLc7jl2r88Bxgnn/fI0UAYwQb/G6WzXJBl
         KDIzexvdwzi/KnaM+Irus/86VbWaLarA8dULaozVqrFQdt+HMXme4nOSfdCSvv7GgQbZ
         HCoeWcZxtrU8uX1dTymhLPhzeDnGTMbLzvwFd7gsmX1+taogDtl6sT9Bey8To88cU7Wf
         eu2JmEtJEM/zTq9S4GL+3vmVAAUlVCOQA+uBzq7OLYUZK1lagsIbDSCgr449GDWPd2w+
         C9rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=PWBNHzoA;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893193; x=1751497993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=GbwgXRhIu5K/Z5+UUHGephtAZQUH43IRK8bipy5RE2g=;
        b=a50u5InqgBK35QkciBwLwvHeKaocDdfEQmTqkS7hBnfHSoDN33trp0znbjMgZsabdw
         XawyMPSXeNpdbh3GX/DKbv9BRzHRWWN5Z9h5ftTT55bxZAHhg0HJGTnTZx2m/Xr/yeA4
         t44g6lC9U8ButlqZ1En/qfb4bdvJVI08TmProfl+ilGK0ZGn5DqZ9lTjtawKkEM190qe
         a8+OICs4NXBqKZATZEDh4a9uyoUh8GqfB1hmlZbgBmPSF2PbNkw6SuJnsDVMFoCxOgv/
         ROBC5rOzG5Fcjn9R7uNr2nYMI8bsGDd65h2NDuGfYUIbZwMMQCk2nWFu9gTVWbIR7ng7
         ZJbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893193; x=1751497993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GbwgXRhIu5K/Z5+UUHGephtAZQUH43IRK8bipy5RE2g=;
        b=aXTyeQqt6l8BO6rYVohY1wixLI8xE9OAF4ZqlrWov+ytlQBHZNAhNkOX1IQX/47Onh
         PHCOZ5nxHqB0wLIBwnfJkklbDDTyne+aMYSlBzqWaa7gbiETyppso74kTmYd8+wlVdUk
         Xx35NeUfS9riU4jqIxhamh0Jb9VpAvrMEMt9tWVrqYW/eLETFesKlrLcXE8MLRXXfteR
         IbPezJ0Z5tKoqeDQol2m7ecbReVV3b/RtWjMfEQkhIz+hxEuRNFkTQCiLgCfI2NU6RcY
         TCOYnHcKDUoIu/pQVsTlu6K2pFe4sB/VAHxSckuZHlMOXyVefAdEPvJgjLBq3vVycP+C
         HJ9Q==
X-Forwarded-Encrypted: i=2; AJvYcCUYEINQ1HIJQYHKQztLvdljYISKEF4Mj3f29DSX5l6lnnWzaXmhVfvzLsm6R7rRSA/ZT4Pu2Q==@lfdr.de
X-Gm-Message-State: AOJu0YyS9wuBIQ3OXBbsA+aXuEVelUTPi0I9TjRNApF6WuH40g6q8AsA
	SitSWQ9chEYpd/xn6aYcjqTR9sR6lR4MLDUL33jH8CIN3HLk9SQRWiAB
X-Google-Smtp-Source: AGHT+IHRFSEEsIk6Ovd9sG2uUsXpp8TruJ1BxJdDbOvzB7ihQTeYzukoTDSgZijx84QXSt4+o1Gsvg==
X-Received: by 2002:a05:6a00:3e16:b0:73e:2dc5:a93c with SMTP id d2e1a72fcca58-74ad44b09c7mr6324537b3a.11.1750893193443;
        Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+SNn38hzmiKUBOq3jEO9zaPhxr5qxEt1jELVsn+qLHQ==
Received: by 2002:a05:6a00:2295:b0:725:e3f6:b149 with SMTP id
 d2e1a72fcca58-74ae364f066ls341809b3a.1.-pod-prod-02-us; Wed, 25 Jun 2025
 16:13:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5rggF27isPMp45yBr6p6ziARIUk0w9BxnAIM51GQkY9WANezsdPHOa8PNQ2vK0VnNnoh3lMAK7uc=@googlegroups.com
X-Received: by 2002:a05:6a20:728e:b0:220:17dc:eb79 with SMTP id adf61e73a8af0-2207f26a1f0mr6790302637.20.1750893192181;
        Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893192; cv=none;
        d=google.com; s=arc-20240605;
        b=MIRFDtaXZHNfRfX4mq05XQqK6lKUHt/hdQN7WbvovUY5JWu6Gk9EQ+Dl5Ya+9SWKnn
         WKVzf2417eKooFsGSaqo4PLUEy9Bi8Ogj0ZSqtvunJCh/UFXRTN7YYJe2F6w7gnheOw0
         ANfyj//n8D9LMoIKBVlzNzY5MG4gueJe0WOBNMLL0T2LQk/ByzRFeSFiAfYEuD3zllxj
         u8V7yRoZof8QF/LTB/1VjUtrbJiuEwIz9CzjBKgGjQS/xmE36SfN5ffVdRpbuXb9X+uJ
         PIL30g3u+VN2EeQKSK7jot2nQujOP8+SsnSyCtCBtHfRLkecWmqXonOLBtZvWZWx0kCb
         tGsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=6gZ+lY6yUBZxNDzrVBvGYj157wtSKM3Y84/wefo95dw=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=DSOSV6G9S07zLuW3m+BTgF16IPgYpcit+RPaYXGxg2kdIvYcnCUf06My4oN9mzWeIt
         4TkrEBonQ1jRzNHGLUPW5Ii5szJQEsLWVv7jOfOtOlyxgLG3zvNS3WXSDNhqUCFPYprT
         8BM/SZKsAAVIIJ/2gXdGGoiV+7t5JiTnMXQOSh70eYhswRKmuGULQb3yJfzA3Ws/1/es
         K/UpqkOg8ERQ1GwhXWG7hGuZvVg+05U6iYmPE/u3cOOrvBL1itkoOi5qJJ5OrCe8gGiU
         gPJD4NxyxPwxWjzN9cD/g/uXxN0iehzoHRvgnYNRq9NUojIZO9zCReC9L/TKtaPa9gN6
         V2Ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=PWBNHzoA;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-749c86d7efesi232262b3a.3.2025.06.25.16.13.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 2953BC002828;
	Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 2953BC002828
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 8FC3318000530;
	Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
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
Subject: [PATCH 10/16] MAINTAINERS: Include cpus.py under PER-CPU MEMORY ALLOCATOR entry
Date: Wed, 25 Jun 2025 16:10:47 -0700
Message-ID: <20250625231053.1134589-11-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=PWBNHzoA;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/cpus.py under the
PER-CPU MEMORY ALLOCATOR subsystem since it parses internal data
structures that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 7aca81142520..687f2b7cd382 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -19525,6 +19525,7 @@ F:	arch/*/include/asm/percpu.h
 F:	include/linux/percpu*.h
 F:	lib/percpu*.c
 F:	mm/percpu*.c
+F:	scripts/gdb/linux/cpus.py
 
 PER-TASK DELAY ACCOUNTING
 M:	Balbir Singh <bsingharora@gmail.com>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-11-florian.fainelli%40broadcom.com.
