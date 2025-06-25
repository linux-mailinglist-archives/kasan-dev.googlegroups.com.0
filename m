Return-Path: <kasan-dev+bncBDP6DZOSRENBBBMF6LBAMGQEWVR2CQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B49BAE91A0
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:13 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-7d3d3f71813sf50952785a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893190; cv=pass;
        d=google.com; s=arc-20240605;
        b=g9VaUM50EJ1yQ+D0c1Vy1smOEtyMjSAYuYwdQz7OYok0JJ2gdEBmoe+VMruoPnXb2Z
         /CthuHif1e17AthfDnMmipAIZQS70Qsus79GEih/CsBIJAE5K/PCSht6pUtQGkQ5FJkY
         QyFtlKIFeQXWR8C63aVoo8QI7Ol9Dvr8qfyFGsmzxk0WdKYpq1ukugQkplMGwrBt+Pu2
         Bj4UqTgyC7AFdhaEeMuZ9Vw6ffWCmpF0bPTeoOicZEpwklhgoDD83INxzVLmwmrviqMO
         1ei5ogoLlJcj48EdCSwA2jjSLESXB+qO/XVQjfCCrC+zZuOA99Q3oIUkk4IpX1CWbxVr
         QPlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=yTpmbuzmOlyLP5z3Btj854Db95mQjYvLmQ3hXqw35pU=;
        fh=VFgK37f0Fh9e1iQL6M2cL9BfecmrbxvXeSVlsRrLwas=;
        b=hubYsljPfwVfZWHQDbnQ+plTEMM8XTT6iV9L/TWQUngF9bo0Do/AdEHydkypMMg/wq
         LByBh6iZlj1qwBKiCAEa/9nBejZrsdpRRV2p9sJEsHB+3zPYdUrcPlI4jZtITmUNCbZ6
         +WUvdFXfAGhPT9jGLCiGJtIN9bcFBixIiZbd3XC4Ppx/M40p6gBmuY4XiouVeqcdAQ38
         4jkw2QM6iXHsDaxMjvZRadKwN09WwVltUTTWzWHs9JulCZhGH8VYfQ7mMOekmKsA9KZl
         X7faxNzPclkLolFhi6BzMJc3RDeZ1SD5bDm8tflrpHCcxyWlmeSTOIJffNd/QecsJmcu
         WB6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=saXXHqU6;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893190; x=1751497990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=yTpmbuzmOlyLP5z3Btj854Db95mQjYvLmQ3hXqw35pU=;
        b=bVJYQ1BOnmxmX9XSc4MN2zB66Z3yWks9UpJNWkmEg3ydbQmjDET1oBrvOvXS+uw4fJ
         cDc8+XgrH5x7JDalePbcLlL5huCL5jSGA2+qvVFtFB9ewM4qIgfFoP23aSghmna0NPa7
         rFEkib7tKwVlCD+hjHSyRHNzYtu7ofyJ+zrLtP3x+CpAdiO3/4t1gU2nWaVUrcYsplk2
         rgB4zphWYCU4c5HdM2uMjeXogZk0XrFLgHvfFrK4Ga+0tkQuLIGXY4SZ15aLItY6JXyA
         lwXVvMzKKU2HIHWXYn0rOG5qd8tOOM1/bjjwjIpuqv71DPN++89kOX18YhrdR+W2pOrk
         KhNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893190; x=1751497990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yTpmbuzmOlyLP5z3Btj854Db95mQjYvLmQ3hXqw35pU=;
        b=tUObpl6aemGsmwfwRmS0CVq4BD78aPgp9SDUJaLLuDnDCYvp1DeRpXjNjmjwn9MELa
         62I0R4tYu1pztasiJ73f/7qnGWvKj/3uNm/Ma5ksqGfwG29/+C6ycP1vtLLDcpV9z7ik
         oU/QjIJulfOzU8rhzF9GxSjaRIIgghNThdO0A3hqBWVU/S0r4IBjwlsl4USAONIMmxA2
         ipVn0m4TJS/xZAIIyMt4x+wKaWh8Hz0o3Tb3AS4fdKDIjoAPFRNxnW8PDhDA1DTzlHNy
         +m53YzoSUSfElpWUloXDOLgGC96bfjjmylIIcVCngzWpRRLCwY7cAF39gx8CvbBC5xnR
         LHqA==
X-Forwarded-Encrypted: i=2; AJvYcCWvpBtlvhg3dvDKFdPfZ0aYqYsNIKJbDCK/OxSC9Nk8Dp+eqAr32my1u58PYFsB33x6/WZyaw==@lfdr.de
X-Gm-Message-State: AOJu0YyqiIE5EaMI34IABeSnj2fWS0I1hUpqzClo6v5Rqw8Q5A4oH5DI
	vjTJjCco+ztCc1nmjPgJL9fnL9EhIObe4p/XFMBDmtDKYMR9rKIXPHNV
X-Google-Smtp-Source: AGHT+IFYBOmIDaYK/mq0eG1+n/qiTmwCImgygvEV/PhLjpLZ0Pij6EdkcNkO40pFUOSulcJKUSHPKA==
X-Received: by 2002:a05:620a:6087:b0:7d3:8cc5:8a45 with SMTP id af79cd13be357-7d429753d16mr697742785a.53.1750893190106;
        Wed, 25 Jun 2025 16:13:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf3G2L5v37jWF2rVW7vKg0lwUt719aULFdSRl+jnO2p5A==
Received: by 2002:a05:6214:d66:b0:6fa:c4e4:78b3 with SMTP id
 6a1803df08f44-6fd7511d39cls6824576d6.1.-pod-prod-03-us; Wed, 25 Jun 2025
 16:13:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+BIb86Vye+COz9qLLp6rVyM36KiIgTf2DXkpbKt6eDeYZFxbnOXBAc6qz2RSpkgti6gU+9oI0aHI=@googlegroups.com
X-Received: by 2002:a05:6214:3c9d:b0:6f8:bfbf:5d47 with SMTP id 6a1803df08f44-6fd5efac5f8mr62335776d6.24.1750893189434;
        Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893189; cv=none;
        d=google.com; s=arc-20240605;
        b=Sy4SzOzerTxv5QI9bm8aj0Vdxm05hnwlpZ1kjC2heM3TU32z6BDm+cU+85jh79aE+N
         xP1LSzf5WKyLVDNaeR0fNF4PWLgOm1/rCWDXCIzhVrGTGrGaJlMvtolnmFw+Y+oyYEDO
         O7D+etSjysd/Gj/jx0d+84eVynZAaKdF/xgGOta2jfFFb+zqY37QVfXj2mpSFeRN46eC
         Eb4X6jdsWM4eS+nczB4qyvZ6vqMOUkEJh2WRbJgjh/k7Qp8IpQNMclT6nBOUAHvHn8hd
         OpMumE3z9Tuc2VCRwAnOVBG6V4CLwGgZHcNsZhhVtj8IPMD62sH1rNDJsiqe3QFlWFWM
         L+3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=crJ6SOALyFPQRQ9EiUDEHLfPUjNYV2/w39L1pdOsfNU=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=ciE9ps/ElDIvw08CSA17/63SyrSH+MDNGsM1dxW1tcnOjt62RIwT55OA2jVoTtto7V
         ifubRtnCNdY+5mkI17/d7J7Kxlze3I9M0SC9v05dHP881Ya8IwRunLPnjKUGjZCStdz8
         +wezd0+JoX8uzTl6+AnK6SFV5PxCYBs04yyjAm85klmlDz1CnP54cQfVylcvuJfiRAlL
         q3h5TkD//BAnQejAjDAwQrYwrI2m1RbRiJeUxq9unSU7ccEQGfUIuX2HjE0DruS48moF
         2tMfw3pQOfqG3lrie14DxxszgryaNHDZ9NHF4LwBMv9v4eZga9BFj785DjeElKKVtdPp
         XJZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=saXXHqU6;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd772ed1ebsi77816d6.5.2025.06.25.16.13.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id F1E92C002817;
	Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com F1E92C002817
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id 62AC118000530;
	Wed, 25 Jun 2025 16:13:08 -0700 (PDT)
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
Subject: [PATCH 06/16] MAINTAINERS: Include kasan.py under KASAN entry
Date: Wed, 25 Jun 2025 16:10:43 -0700
Message-ID: <20250625231053.1134589-7-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=saXXHqU6;       spf=pass
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

Include the GDB scripts file under scripts/gdb/linux/kasan.py under the
KASAN subsystem since it parses internal data structures that depend
upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index e1eda0d9d671..d997995a92e3 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13039,6 +13039,7 @@ F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
 F:	mm/kasan/
 F:	scripts/Makefile.kasan
+F:	scripts/gdb/linux/kasan.py
 
 KCONFIG
 M:	Masahiro Yamada <masahiroy@kernel.org>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-7-florian.fainelli%40broadcom.com.
