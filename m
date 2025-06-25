Return-Path: <kasan-dev+bncBDP6DZOSRENBBCEF6LBAMGQERORPVXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 340CAAE91A6
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:16 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-234f1acc707sf2960675ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893193; cv=pass;
        d=google.com; s=arc-20240605;
        b=KSsYWwVHkuf2KnKQw2vlZbXpqR8QowZ79sv6ssMQkPUKTO8A7hiFUn60A+QbG5r/2L
         pOWdV3cj6m7ZseSihNhWE2fz1bYSpc7Wb75ZUy4r6aKkRUwq6tO46jyXE8enqPW+ARoT
         xpDqV9rC/GkSwo0Hf/A6qI0EUNGJmRUh7zeuV3NtzyUTcxm680QbOLstivQxTcF1RDlB
         pWdqsle9HFAhRql69doXduoz8+eqwE/yWjkZYmbqeT3LGTaWTRDj+XFuDzSEDvRxk1+2
         mRxvF7m26+43XPx6FsECZ0tvOqp0W65Mu21KlMqJO+sUsofojbUHwaFHgUI6wKwfaYas
         jRHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=1engIyaNHja0HG1+nKdMEDBxURC6QLynrADwO/jyiRY=;
        fh=qNFbThykktGGVhzDyTun3z5Z5ulfp6j3ejLNyhAw51k=;
        b=JnoGC4TT86eeFGM1A1r/Fp1GhWhE+vBE0iWPXZoI2l85o2uItwyaW/HYDiPsjqXThE
         BbplPiGINCuTuTx4s5HZKAbvnDN9QEX7rmIqF7BGkpKmv2sSTYbc0uAtlyLZggnnooXO
         AZ5xSrfWlSXe85zZ78Bd31ylRNXHcBgXCjaouc5Tv1FHcjEGGgUH02vZ/iBo76VQL1Sq
         dGtCUXGoRrJrvnPiaWhj0xGAsqoiK1Xb35ssUXTYvxHl3QqIVLu3ycn3+2Z8kba0OOOj
         nPJv1+9NGSXDhJNv6UoQZ/ZZHX5GW4Otp0z17T39re1zBtFFQEagttmr2O5oyM5zb4sn
         9kQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=Tfxv9dwE;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893193; x=1751497993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=1engIyaNHja0HG1+nKdMEDBxURC6QLynrADwO/jyiRY=;
        b=SnJZrMqAE7/L7VX8Wcs5P7Xo2mbGeqjwU+OAeYvzkcMgf9BKJvgFo5dTuTcwUQUEvO
         e8S0nxmxEChxslUJc97hoUIQ1G52W0w7sbc5QKga2tty5gxl9WL12OpET9gKd2l7Frlu
         sPJ17ev2iC9inu+QRETDNBF1Dhz7nV3KqhV4CtJIrhD3JIrKAjpMtz13rV784Pg/EOWP
         JC71UFG5PMh8BzlmXYYipJbTVw1Ghtbd6UXnP85hlzYhKOhlRlGoigK/qT2516kF5XVy
         ACwDXwyT5Y1KhenVwwi1Q0EbYPPTQkPKJKst3NDDt46BTA0ZjCqN1hg1l/7Y4wMdFIJO
         aYGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893193; x=1751497993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1engIyaNHja0HG1+nKdMEDBxURC6QLynrADwO/jyiRY=;
        b=dUI9y0Y0/F6sRswMNCcvFDwvgThzpNmzGGCXlpsFJPUaJ9eqhBvKTqnDNn9Wieh2Ci
         a1tDvlaMH0m/Uu0H7iOQiDxyNWfgHVFcDejSfxaWjn+RDeq04S5HnoizBwqEz102g9ab
         3SAXE145TpTDWKMoht8IS8jWPwJwVX9vbYkwPVsrhCnaAsi6r7wRpzuqSA2vo4GITrUH
         phm+a748nSq9/+Lt0aUegPD5oytDrVJ/P27+PcLgluiXV+m7fkx+gX/B6TACH8WzIg1m
         eUbEc1PB3x9G9ThPwpfXwpkgy2xQuz99GH9pTeQSE95ng1vhFSbJsC75iBbTLvrQU5sp
         Gucw==
X-Forwarded-Encrypted: i=2; AJvYcCWkTHk73Rh9veTvnagClpK+4i8fqHYF1NXfa9smSQQnJppfgT5E2+4euuy8HibKA3ZoZN8h+Q==@lfdr.de
X-Gm-Message-State: AOJu0YxQXkl4LGE7JfBN39EOPPbwT1i8rBrAluYKCRfR6B9W6nzYTEC7
	LutVu5USDA1VIcsHjS9CxOdd9Sf1Kvt0PyNRorZ1Jm6N6bl/mfMAqJfB
X-Google-Smtp-Source: AGHT+IHRoJC3ieoV908Cg4/TGCLyKb4TbRpemFFrpd5doxWot4gYSSl/wCHrj0TfnxubBzJYImZDRA==
X-Received: by 2002:a17:902:d50d:b0:234:c2e7:a102 with SMTP id d9443c01a7336-23824068a75mr88530655ad.43.1750893193066;
        Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcrrWHSM0thGKL6K462HizWBNFPECj32lZ0rEq8H3IGjA==
Received: by 2002:a17:903:1aa6:b0:234:aa6d:511a with SMTP id
 d9443c01a7336-238902fd23els3357725ad.0.-pod-prod-07-us; Wed, 25 Jun 2025
 16:13:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpHkzZP005gw3xhzzqsv46nlAFq7X0VXtWscxFSEVVPM1+a9deflIsHPfBkthx9I/rWeALoY2uhqQ=@googlegroups.com
X-Received: by 2002:a17:902:e84f:b0:235:1b3e:c01c with SMTP id d9443c01a7336-23824062820mr78276915ad.39.1750893191530;
        Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893191; cv=none;
        d=google.com; s=arc-20240605;
        b=fX0FZPSC5VlA8m0uk912Dum9cc5QpBI8HgEk1l+PQOwk2zF08ahedUrbh/clROvjdM
         flIoEci0evlo6ij08KufHdqHZlHK7X01i80wj8gPofb2DplctUvRcESVqluGlmA4TC4f
         MXg502MldCG60lVCdZdUDEpHdC4t4FNWE/LaMrG+4p99VpsuHRQjncB7c0m9kbzKuhXt
         Cv2TV36hkrNwzb/cczeBI1A07lIJzmZVQ6/ZckZ3wQANFGS+NxWC/FEFmEKyOLfDJw7/
         8TnKd/mqKjEe93hKx8ggMq62DSAblse8P3XU0EkyjxWdZtosto2j3HNy0/VqkATRMXh/
         WhzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=ZjKCZx7MQQ4R1/ld3SWrTPXuRTUruOguKY6V+nvv2bU=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=Q7FFUtHbX1SJCjF51z2r2f3912O4N5JZJsbz8oR8CvpAyodcjMvKw3UhVEG6zCuGjQ
         9w0A/uIQQoVXckOCYcpWdofeOjrbyVhUqdMGGKwMClcK7KKkk8Gi66TeXRh8pv9bIYU8
         etLcSClKKpNv7GmHXqMdtGEk8YNJ7KVrr/IyFIWq0rQ+I+pk9bczH33Oe59SV3PFqjTY
         mlPmH29EMYA18SZ85x7Y0wPoSfjGE5oFjnYcZo4cQDrIfY2zDKTiEm3OhlbHfBIPhvCy
         zl0rs4fYOXoNubaWAuxqncTuIF1cJofplx2pCypHsQcK1qdpheA4McqWNf7Ntm7psn57
         vkDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=Tfxv9dwE;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-237d856ec85si5446625ad.8.2025.06.25.16.13.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 97B1FC002826;
	Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 97B1FC002826
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 0972218000853;
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
Subject: [PATCH 09/16] MAINTAINERS: Include modules.py under MODULE SUPPORT entry
Date: Wed, 25 Jun 2025 16:10:46 -0700
Message-ID: <20250625231053.1134589-10-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=Tfxv9dwE;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/modules.py under
the MODULE SUPPORT subsystem since it parses internal data structures
that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 52b37196d024..7aca81142520 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -16897,6 +16897,7 @@ F:	include/linux/module*.h
 F:	kernel/module/
 F:	lib/test_kmod.c
 F:	lib/tests/module/
+F:	scripts/gdb/linux/modules.py
 F:	scripts/module*
 F:	tools/testing/selftests/kmod/
 F:	tools/testing/selftests/module/
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-10-florian.fainelli%40broadcom.com.
