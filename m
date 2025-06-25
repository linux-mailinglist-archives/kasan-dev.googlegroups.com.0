Return-Path: <kasan-dev+bncBDP6DZOSRENBBC4F6LBAMGQEA2U5BRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A1C5AE91AC
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:18 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-7d09ed509aasf52011985a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893195; cv=pass;
        d=google.com; s=arc-20240605;
        b=VS5MSPRMd1/B+ksWJfSUjcTRXOfiqlw299sg4Eiw8WruT2TJ+KD0DlN+k36PCzm43X
         5weyX3FC3q76oHEYZQr952XX2qd+X5M+k6lPy/K99AYH+9geFTnsRDtpRlJBdPqvcll+
         UNqx7gxblnt1OX9TrMJUflSamtVCl/QDxNrP7FXHSEiDGUI+3uZvMxDwdyd6Xz9k9rXw
         QQROc5z7ozESHXoFwzOyQv3/3DFQkS8xyGJI1iPEF8Ua8PKuacMWn4zdr1WTTSeJETqZ
         orjQonCY0V7w0J9DD43gNPQCloz1qnoFr9Z4P4wT0rKf3XgERYrFEZowwESekcIwr00m
         tzTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=6On9lhMPtIobW71qDGif8L+kkftKeTXEt8Oo1+AlSMw=;
        fh=vELUiBKTlmMEezuJr0jb2rKiheSv8Cskdfh33gAN3Tk=;
        b=PLE6uqApUsbrJqJV5en9oSv+stt+jMEh1Q8axrXaniCIV6MUsmEi6Jxebjjzyq3Ol+
         Ue2kKEMiuHq86MDyTZhtGMPjfPC/8jAmcjRLC6UPhSDkkmUYJLv8qIA5g8WjQVslGz0m
         WjZYXJUX9OoeuqtBTJZIcDsali0uPLbRHMLOebYV2NzTVtF1eM38uHRvvHuq5mFpJV8i
         uWm9WUTpHrRYVzJq30Y1KNTlphNQb4SUSbUg6b16C3lZiCzohw5ez1bO9I+A+Yf9qEFS
         /uMWfCcmi3Vl9/wPNTIEfebvXb2Fr7iLYHTwcX0b26mznBZeLLcckXM6Hx5zYBjrR+N0
         gIjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=BZpIJlTm;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893195; x=1751497995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=6On9lhMPtIobW71qDGif8L+kkftKeTXEt8Oo1+AlSMw=;
        b=gcvKy9q6uBSNucZvLMX1qrx5CLSCpwj68s+4jhPaUn9ibu9oKLC+emUc//30Ffnc/w
         SQw+FDJ+hacO0hbzyUUNW9gsJ70oP7j/ui3eROY+cgPws/p59z0A5mmAON7/moobd0qO
         du+rXef+1Ficsy93tUoNVfkFgiy/Io4jPIYjK8VztdNsLE7NHZbYSvNCrxD74WGTyror
         HRdG1ufQoX2l8/DDeyUqMH9k1a5hbwjwuIMEPFTbgkb/n5qUMPqLwEfVk3R0NIImmQF1
         yvs2mSafDr5t+7++DJ22YwhCipPoABYVFhOcHENv3FKNVlxhqVgwyFP3hL+rRZbMIQ32
         xbBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893195; x=1751497995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6On9lhMPtIobW71qDGif8L+kkftKeTXEt8Oo1+AlSMw=;
        b=wG5a74e2cXrYU7K2aiQsRIKiz1vEuxJyi+Q/lWMBlfDuQ5J5J4cFqc9XwhdqSZWi5b
         eJwBYsXa8wckAffC9eCGjIyPI9n4cPo5+9Z3yuqeFGnor5sTQ9p7w3BBr8DvgUikmaJz
         25V+8Lpx/vk0XlY5BJKQBzAuAPTnbvfijjJblCfTMk+D1ZwXjZyXJP7LYpweP9YWX6Bf
         ut1p3eNVJ/7K2Hhb2SfJByv9/ZxkrG9lB5jKZHA3VkKZy3W9dlenBEr6iTOvuSS3DBNd
         UlTPj77M/KX1t7Kn9dpg0sQ4EnLT+r/f8ZN9ia+z9eIoHOstrgWAP9B4ZtOa1QTJqCum
         tH4w==
X-Forwarded-Encrypted: i=2; AJvYcCU6vsyKt7bR5hQbakv9qLfk++pcv58p4ct8KNdiQHAz4skodaZIWHsdQOFCqZNsd1BewWp9+g==@lfdr.de
X-Gm-Message-State: AOJu0YzKaIg0OihV9g0uGRcQAkYYQ3rLl52IvYjBCEh2oxaLnxvmKd6g
	3eEhZhSAkm8awK/KUuRMHn26UaiGFpmHWQj0v4XGaiT033WAkMWZKUR+
X-Google-Smtp-Source: AGHT+IGRVQ7Anhnyu9iCbTWM+EQ5cblU/oeR8uBlsSm+opR0yMjAJWDzJW4YmauCv5NmzB9TEZnsaA==
X-Received: by 2002:a05:620a:bc9:b0:7d3:f3a5:71d7 with SMTP id af79cd13be357-7d42973f34emr724094085a.40.1750893195260;
        Wed, 25 Jun 2025 16:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcN1DPy8XdyF03AjmFFLlNYuaJAVtOa6OxUslgBjmIysQ==
Received: by 2002:a05:6214:d66:b0:6fa:c4e4:78b3 with SMTP id
 6a1803df08f44-6fd7511d39cls6825006d6.1.-pod-prod-03-us; Wed, 25 Jun 2025
 16:13:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmjQLeC87AjVuTsDDjHxvV+V+x9UYgTUE61Maa5FY1r9DrVOpXjv/mkhLSeU18odKJ1fdxRBNPkHU=@googlegroups.com
X-Received: by 2002:a05:6102:304f:b0:4de:81a:7d42 with SMTP id ada2fe7eead31-4ecc6a67bcemr3932435137.1.1750893194251;
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893194; cv=none;
        d=google.com; s=arc-20240605;
        b=NJmfC7FsvsVjfyAaQPFunXm/SnyArsr8a5eRAnH5WGncn6AAaaZMgKIcVwReuOCyaJ
         coRxujd9/kS98ktj6jXZz5aMMMGsMWi+d8JvVFed4kXR3sShgMgtxBPGdn4Hq1TITuHY
         ut8WDUM4fnNI1KIsd0oxoD8QtwIO5c8rJIrqtedMKHhNukgPMO1cILllHv4867giajsk
         abuBCpKnQ0GezwOMtv37p4PSCpZ24Hw+7qOWFxjl88Xs6nLk9tWFKaNj1S9sDDG3btt5
         P7c3mJISqgT7Z6eKyxhxXIpGynHOogz19M3fG/CoivTYkUatXOmngNqoGXX3WHnAHCjG
         z/YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=tWCpEfwjr+fzFt8XJXgucqAtGVouiGFWKO4iJHSNchs=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=dGM9rHy0mulS1CXwnisN3gXTzC3vluE2kDM7CxyTO8qGao6wnqJA1oVzZdUBuEO1SI
         4jIk0q6nzD66UhPeOXnmSLLQ69TBHgdZfMXkJnU1J+Ch90UTJ/IYqDMJpVqW9klaHajS
         yeCVb+qIi3M/47gcnRRTD9aY7djFF0vHU6wUSw5iuQmRO7e0Gm+sec4r5k0JZ51MX0Y6
         37+ZvT70VWIvcFxJeuuHByiBuXb+w75X7L8WZB48cic8EfQa3KCjiisT9H0am0tt8KOA
         UNPDCVij4wwkn4jQjcOe2mseJLA1DU67pXw3B+jNg5NJPra9ftTwIB2neA0ZlxQrOzmO
         hlvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=BZpIJlTm;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-884d1c621dbsi8110241.2.2025.06.25.16.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id CAB9AC003ABF;
	Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com CAB9AC003ABF
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 3D26918000853;
	Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
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
Subject: [PATCH 15/16] MAINTAINERS: Include xarray.py under XARRAY entry
Date: Wed, 25 Jun 2025 16:10:52 -0700
Message-ID: <20250625231053.1134589-16-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=BZpIJlTm;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/xarray.py under the
XARRAY subsystem since it parses internal data structures that depend
upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 8e86acd63739..a90d926c90a0 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -27087,6 +27087,7 @@ F:	include/linux/xarray.h
 F:	lib/idr.c
 F:	lib/test_xarray.c
 F:	lib/xarray.c
+F:	scripts/gdb/linux/xarray.py
 F:	tools/testing/radix-tree
 
 XARRAY API [RUST]
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-16-florian.fainelli%40broadcom.com.
