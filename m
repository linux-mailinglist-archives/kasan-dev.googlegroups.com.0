Return-Path: <kasan-dev+bncBDP6DZOSRENBBBMF6LBAMGQEWVR2CQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id C59BDAE919F
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:12 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6fb4eed1914sf9367836d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893190; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uaiu/xTjQ7wEFF68xymUl6I7oCl/v7OzBTmxMjiWREOOfR8Z4XhH8ikqokilLkUK/K
         FXkhxshAR+S+QzmKIGt5Sb+BmyKFx1GA87jbz2dq0LljeJe5m5fMi5lnEi+77pCYLwF2
         XGiSN6XV6fzeNP+crUQD2UC25dVw64PJj+gBIQ2E5IWARZZSKQamSdHyVS9fI8BNd9hW
         uW4T03NOFvPCKsI1363w18xWgL9sNrSwC9Ii4JiA2nHbhnZJUepI9SJA+GuhNwfttWEC
         E/ksKyu4naQEmKD1Qu9fCUdlHPuFanyL1ZDkuUp4Fwmd1Dh2Xz39S7wMGjuClWqF8EcX
         ySdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-filter:dkim-signature;
        bh=6XFFi6g6Qp9lVvQq2AszOhAW0slLfNNMJjL/tjMeKKs=;
        fh=yzCcghHLGoF82eNOEx5wHg94ZgBhkMyuamDGmJSbIDY=;
        b=HfJ4q30dKWc75D70ne1yzULKH9CK0lef9YexBhRTDf82sP6koQCRCc5s9lN6B21mGw
         6qcUol55qHj3tbJ509t7j+LwxqG534MvYe0mxWtLL0Qwa4D3bFRDQnqLxbfpDVC10RIb
         9vWN5PXtPwJsHlpHJNOkV/+CGWUjhpcAu/Wg6mlWfv9fl2CqIJ511zRWVYwUmJs7Vi7z
         dBOndx3QcVoJDBIvQRYV0ovaY6W9nNfkVoxNbN1qTBEldLmuf/lkrDHNDXSc0OzLY6DR
         itIAKGkfbqYAHGelzoZklpFufrA5pfGCpxk2TnE4MAZBrriqUZvBnGeLXmT//CGEKIy5
         kdNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=UR97XCXw;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.166.228 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893190; x=1751497990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:dkim-filter:from:to:cc:subject
         :date:message-id:reply-to;
        bh=6XFFi6g6Qp9lVvQq2AszOhAW0slLfNNMJjL/tjMeKKs=;
        b=ZHR83KNGS7k+0umV/iDqM5XgeRNi6GZQjMuznFrNtN3PJmjrTQ/xSXIQiuBSOPmj+a
         g6YpZk2ZycLruYS5SY6HRgcRJBMzKoD5MKScgzcReT2W2va8VPusKKhay27K1V/R4HM4
         cC/odjDXdfpb0/ywZpfIIELDpnqhzA74QcUE6o2udI5twe8tFEVN/FvRFTzaa5UloqKN
         5xdI8rcdsaNEJ3R2WibsQc3ynQ/kH6n1zX9xFQpCHldEvJPw2LjGAGcZKqu1jO9iuuD4
         NKImkcedRZnDbcehEIDHQOAviExVbDJHYtHbelA306YEhvaFnHroMFGWu+k39faEigmT
         8Ypg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893190; x=1751497990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:dkim-filter:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=6XFFi6g6Qp9lVvQq2AszOhAW0slLfNNMJjL/tjMeKKs=;
        b=nlJArGpPGWqcwD6Uu/4fVJ0kUqBaWbSfm1OnmEjtdgslhHaZVuwBY6d9Bi9EdtjOcV
         3kZkHWC2kEKRZ2L0ulfdw7XJrSZTsky5O0Z1Yg5BKJ3TIdFWCZ8LcXR/puAJ+eIxgvLJ
         8p36kwdGNqGWUZJl3m6oSQV90bW3yaUf9fE3wmvPJ95ossdQadMxV/oFywyAYI7Pui4V
         ePdiifKzQf4tg+vi+qTV8doIU1lzYt2GowBq7bKRxrFdUeuRgn7o7JlSJkDrY22HgDOw
         HOL3RcDZlx1BVV1Jg0069YTY2cmiJj9NzR2CN4TP0zOxOgsnLEE/LYVhKgaJwhrMjv3Y
         EVag==
X-Forwarded-Encrypted: i=2; AJvYcCXMUCkgaWGKj+5rHJYaRiYQB9gANhDObZBhn1jh4t4V1PB3DdJMZnBw3ohj1NjhmzppBLYX2Q==@lfdr.de
X-Gm-Message-State: AOJu0YxMyBolK1Bn1Gr7MHOHHAmcjGMYSS5lnKbwITbz7AnUxFvziCPn
	TZqjHqp52ax2l4psKHi5DPbF5iv1i5pWKofa4uUvpzrGRxsqSNYRqkxU
X-Google-Smtp-Source: AGHT+IFrdGBG5pC4xUSI86oGnDXc5MmuAoz/dPwwnDBS7tRr9y90l/MoKcgRXWRfc8IK+lvph1wfZQ==
X-Received: by 2002:a05:6214:e65:b0:6fb:25f:ac78 with SMTP id 6a1803df08f44-6fd5efe0450mr68138556d6.40.1750893189624;
        Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJo38P5qOjaRlomwqhxDD1i2PUSLQmbSHrFymEbbqtYw==
Received: by 2002:a05:6214:226e:b0:6fa:c598:5a6e with SMTP id
 6a1803df08f44-6fd750848d7ls7574906d6.1.-pod-prod-09-us; Wed, 25 Jun 2025
 16:13:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXo/dV8KR0HX88g0GtBkL/9XzU6IuiPhRVMi4nKBGRQ87DpouWxlVVhuGTUqdGbJHNrgVpuA5LZv1s=@googlegroups.com
X-Received: by 2002:a05:6214:5d86:b0:6fb:6882:e385 with SMTP id 6a1803df08f44-6fd5efb034emr62611516d6.25.1750893188177;
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893188; cv=none;
        d=google.com; s=arc-20240605;
        b=I8fynueX6/uussgjMZIAd0cm+b6kp+NiXl1PhEPXAIJfT+l5DVcweIynjqOSWMKwKg
         YhYUU/QqRG4kPKXwrDjkyigfIgYj4O1DG7Z5r41V8ctXPmRSchGj6036QqYjiKMW2wVA
         uPeSlOlDXkzsX3u7Hlz4fkTYyctn+hv0Ncszz5xcWE23pIW5ZuJtQ1jLjKF67/yBd0sv
         xN1jdQaUsx0q3YfkjanRo+THllOmUM76hi9j1SAbCBp+Ws1DFOdN98GsoNkvI99q16k/
         ekRQTDm1cpmLne+MhcA/iYu8LrX3QyCui6rRaw0oOc4gZhztxT6xxm9v69ymw1nFbS0F
         +NvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-filter;
        bh=m+w+37otRPKmkcJfqzbL5XPqeiwMrp9ICEplYc7ohRY=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=GCaUnWEdc0A7n6eRnu6gWxkB4AyKPvb6ksd+y44qjbIj9FXEaKe1weky7qi6Xli58l
         KSMYaEurtIAdVrbP5WhJUJjURw6kJ5Y8D3X9xhAy2o6V6h+r4jfCDU36ykSvOrZ2Adso
         ve+9E/Fo1G1iEwzxPu2CxEzFz+hCIoXTeRekkmbUG6Z7GSRwqJVw6+EuH1Wa92nDjLmj
         HJICLF3JLy7IUwI+UzCHFMRYsPBc2vctF6+1upEozGKw7FaQtEQGbkFrBwDZEYfRFDb6
         Ry/MWCCmm4xASRjpt8/OrJlc/bDPqAJq46arEkeUnvdtRbfs+yYCksFHcOUCsg0igzlp
         2Oxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=UR97XCXw;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.166.228 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.166.228])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd772cb594si66236d6.4.2025.06.25.16.13.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.166.228 as permitted sender) client-ip=192.19.166.228;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id A7625C0008FB;
	Wed, 25 Jun 2025 16:13:05 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com A7625C0008FB
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 215DC18000530;
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
Subject: [PATCH 00/16] MAINTAINERS: Include GDB scripts under their relevant subsystems
Date: Wed, 25 Jun 2025 16:10:37 -0700
Message-ID: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=UR97XCXw;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 192.19.166.228 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
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

Linux has a number of very useful GDB scripts under scripts/gdb/linux/*
that provide OS awareness for debuggers and allows for debugging of a
variety of data structures (lists, timers, radix tree, mapletree, etc.)
as well as subsystems (clocks, devices, classes, busses, etc.).

These scripts are typically maintained in isolation from the subsystem
that they parse the data structures and symbols of, which can lead to
people playing catch up with fixing bugs or updating the script to work
with updates made to the internal APIs/objects etc. Here are some
recents examples:

https://lore.kernel.org/all/20250601055027.3661480-1-tony.ambardar@gmail.com/
https://lore.kernel.org/all/20250619225105.320729-1-florian.fainelli@broadcom.com/
https://lore.kernel.org/all/20250625021020.1056930-1-florian.fainelli@broadcom.com/

This patch series is intentionally split such that each subsystem
maintainer can decide whether to accept the extra
review/maintenance/guidance that can be offered when GDB scripts are
being updated or added.

Thanks!

Florian Fainelli (16):
  MAINTAINERS: Include clk.py under COMMON CLK FRAMEWORK entry
  MAINTAINERS: Include device.py under DRIVER CORE entry
  MAINTAINERS: Include genpd.py under GENERIC PM DOMAINS entry
  MAINTAINERS: Include radixtree.py under GENERIC RADIX TREE entry
  MAINTAINERS: Include interrupts.py under IRQ SUBSYSTEM entry
  MAINTAINERS: Include kasan.py under KASAN entry
  MAINTAINERS: Include mapletree.py under MAPLE TREE entry
  MAINTAINERS: Include GDB scripts under MEMORY MANAGEMENT entry
  MAINTAINERS: Include modules.py under MODULE SUPPORT entry
  MAINTAINERS: Include cpus.py under PER-CPU MEMORY ALLOCATOR entry
  MAINTAINERS: Include timerlist.py under POSIX CLOCKS and TIMERS entry
  MAINTAINERS: Include dmesg.py under PRINTK entry
  MAINTAINERS: Include proc.py under PROC FILESYSTEM entry
  MAINTAINERS: Include vmalloc.py under VMALLOC entry
  MAINTAINERS: Include xarray.py under XARRAY entry
  MAINTAINERS: Include vfs.py under FILESYSTEMS entry

 MAINTAINERS | 19 +++++++++++++++++++
 1 file changed, 19 insertions(+)

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-1-florian.fainelli%40broadcom.com.
