Return-Path: <kasan-dev+bncBDP6DZOSRENBBI4F6LBAMGQE2J6ZJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 87B38AE91BA
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:42 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2d50f1673ddsf333843fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893219; cv=pass;
        d=google.com; s=arc-20240605;
        b=LSjBq3VEGQ8Ld6PCFHtoPZZ9jaD1tCGYTl90O5k3iwMa4ywwRx3K21bgF8VYhvhcuM
         rRZAdPbtXY8bZcsNr4/zdKXxVsJikldrI4EWU7bA3pQEs/aJrM+UTYhBV3x679Q9aztE
         gIFGSjK/OsbyqTq8seWub+E/karI1q3j13OR+v6r3+y09kT9PWL1kdppUDSOeS8em/Hm
         ADFlpzVlql6LmeRoX2Kl2CE6thBRnpE5iXU+Q9iMbEb/taxLDMS49N30acdDZ0wtm54H
         ksxZiyguQIXHU8QlPP94Qh2CDmAi0eOEnMLW9AYVGmvx9Pai99l0HNdRtp5/02sRBQBp
         GEiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=WtWNCrOijmU0AKd/ebTlIPFqxm8e2zMBnvOwMUcmIx0=;
        fh=eGQmkWeXzVj/aJdpO2qIrlj5IYUUsPTdn3jJzmJorec=;
        b=baA8Hee3qkg4OwVutWMvRCJhzxDXiaK80IPlRLagG0Gw26h5M1HtfuaCKskx0hYRVs
         /M5nWuR7edBIRqBFieSBDj8L5+Q4iAWzic8ebV3KlA5ASXcDp9B/vdwbLNkwVZis5qcn
         DLsNuybChsBwCIO9M79xXJ1PJNMlhAuJEfxJNUts9Mj/YIhR2iVL+F7TDGh0Jjp3SU4r
         LAZ3YxSgBz40bNyDtV4n/EpIfhoxWWxPNTWAK1AJAy7Vx10mwCbkVCv4rNgkF9L7uwIW
         U8VbJlcHTfQiSBF0yADf2xmY6GL2Nu9sB8BvgiaaT+lAz7KBvSb0qnIfa9S2vRoX7P3d
         L15w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=PpYl0bye;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893219; x=1751498019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=WtWNCrOijmU0AKd/ebTlIPFqxm8e2zMBnvOwMUcmIx0=;
        b=VXCd8GPxvIeqIQlOgV8EUsXwnRFtpuxZhdD/+hkDCE0CjG6DOKzoA62v/CnZhEus3q
         4A1+lmz4zH9D+DJlHY5RbsC/r+mVjqU3n/vWMTcZwUivEa6YxqOq3N8MBy5iJz2TD679
         HKddwhql+GKDkNnb6/iPmwfZ7pbnt2pMhLZDR+fMkogT1Or8pPeu/LMF6kttWEaMeVRR
         aSjEOy+Wq273VENK3ZF2GHE+yYYmzfxum1uJBHy0UfsFFClyrd3UXiVBcuvOhwjcujmb
         yEO4GNsGaMPpF7NgRxqiv8sbjt2uyD97VFcqH6Pp6iQJb31q80vdQ4PpAiSrxQnpK/HP
         xNJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893219; x=1751498019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WtWNCrOijmU0AKd/ebTlIPFqxm8e2zMBnvOwMUcmIx0=;
        b=pvOQvyQX6qFNm/O9GTK0BL6Tx28SW8CAVY+wm3N+XVlZfXD1gQT1Ez/pndgyA6H6GQ
         1+pq1j/gj/x6XQbrP9Gf/znwbG7eOziOFJ6kUI5Omvb3AiccDqlPlTqqp1qhp87MaIYZ
         ITxphBmENL0D+2LFHWmjuyvgfzTQK8ivcG3XkwQbcu5FLo2Q9Bcz0XPnIT1eLb34JsxR
         AfmsXpj+gZRHFgE+3QVMVoq1dFPBQdIfEN2XG1etdFNStYezCbsO+X5n93ApBzksMliS
         n8+1RTEndkRT3zgP315ZRKdO0YFnwu1e4JUWPJ5NzE1J3Kco4iCxHwYk8473msBvf4+t
         TkMA==
X-Forwarded-Encrypted: i=2; AJvYcCW+shtFrpkxY8TWEtbUJlBGrt+pi6AZh9BKYkd+BpNWXEbhTNf93or2rKhiuZHoxKR2ViE+UA==@lfdr.de
X-Gm-Message-State: AOJu0Yzi+Vnk014M7U5Af2ASDc56kkkKNAPd/lRvcJeV0jd/CajdJnmn
	X3mCk4cAWWFn0i87KmG3rb5wcL4WwUYD3t3E5cv/5g3oWeii3UeUEvLD
X-Google-Smtp-Source: AGHT+IFck9wxhxw3dg2jy33SUSPVFhSZNlm4jU+JqKuWGh7y8VV8zXU84KpHgS1L0Fz2etm5/M2bZA==
X-Received: by 2002:a05:6870:ac1e:b0:2c1:461f:309a with SMTP id 586e51a60fabf-2efb2159d97mr3493349fac.8.1750893219201;
        Wed, 25 Jun 2025 16:13:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekg4oVjZ9Um+Nhwt8xf9U3pvSIwk82ARJUL1Q3eiVE6Q==
Received: by 2002:a05:6870:6eca:b0:2ea:701f:7255 with SMTP id
 586e51a60fabf-2efcf1ac833ls174766fac.1.-pod-prod-07-us; Wed, 25 Jun 2025
 16:13:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZdeHArIyUzzLrMkAq0n05t4EmkGJka9Jr8kq8VcD95zes/uGp/bzr4Tt2yFbHSMGz9cmJVJibb8s=@googlegroups.com
X-Received: by 2002:a05:6871:331d:b0:2eb:b01d:c552 with SMTP id 586e51a60fabf-2efb21595bcmr3136636fac.1.1750893218032;
        Wed, 25 Jun 2025 16:13:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893218; cv=none;
        d=google.com; s=arc-20240605;
        b=aGVPlnTb16yWdkPnCK3JTCOtiHUvtGus3MDNbpCiCGPSAlZ0Nd4kQSZVQ0K6+645AE
         FaX3WdvQu0cEmEL9oRaekF5ijqv+vPN0suSUKjOz9QFH3FnqFi6qfprBBARgXwUUq7xl
         lVtlcFX6Yda3GEdoH58WAaaoNdDCs++sr4FkCEYwhaQ972heCtr70KsKnIDeuCRVQOQy
         u/rBUPD3sL+Um+OkUT2jxvC+u9az1IPioWkzp3w6AYN8STCkUjvOzkS6x71xSrvJ6BAI
         1v8IpNh28o2pNcktjxOoWoShUr/w4n70H2WshyU9bH4n7ojCEE56wMgYcr24ukVzQK4P
         LNFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=4R5oxdBR5sQlHJHFeBVpomGD01/gGmkDft0KsCVzSMs=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=ERrSXdb6BvkAq8Lx8+hOkeCegLpoQgqa93zouF65GxAgLqRS3ZkEVijukJ3xx0cXis
         ToBCbs2HBzil6emADAgKt3yYcbOpBsYvhj7PHnUJwyA1C9egRkVrVzTSncb+qD5BzIXJ
         QGR3dBn4KnrSj+2XNkykmWWmAO8wRLUbcfJZ1L+OxhilcygfoT66WmPUDnkg016aWSce
         /LAcuOkSCsByL7DeBujZSm2xpAXuZ5SDCocnQ8KuHH9j0skdJCd0IYZAxUSY7Debe0Oo
         SJgu7VcZuCBrcY4c9wZ2AFRjUArLOs0k1KxDYrUDE2VEQaFlr0DbfL4v9jUXZ4qqwjTS
         xX8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=PpYl0bye;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2efd4f00ec7si9398fac.2.2025.06.25.16.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 7BFD0C003ABF;
	Wed, 25 Jun 2025 16:13:37 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 7BFD0C003ABF
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id BA6B3180004FC;
	Wed, 25 Jun 2025 16:13:06 -0700 (PDT)
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
Subject: [PATCH 03/16] MAINTAINERS: Include genpd.py under GENERIC PM DOMAINS entry
Date: Wed, 25 Jun 2025 16:10:40 -0700
Message-ID: <20250625231053.1134589-4-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=PpYl0bye;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/genpd.py under the
GENERIC PM DOMAINS subsystem since it parses internal data structures
that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index d92a78bf66e9..d51eeb1248be 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -10163,6 +10163,7 @@ F:	Documentation/devicetree/bindings/power/power?domain*
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/ulfh/linux-pm.git
 F:	drivers/pmdomain/
 F:	include/linux/pm_domain.h
+F:	scripts/gdb/linux/genpd.py
 
 GENERIC RADIX TREE
 M:	Kent Overstreet <kent.overstreet@linux.dev>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-4-florian.fainelli%40broadcom.com.
