Return-Path: <kasan-dev+bncBDRLVLXLTULBBG4Q6TBAMGQEPUO5TVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B188AE98B4
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 10:43:10 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-32b93fa2e51sf2886951fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:43:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750927389; cv=pass;
        d=google.com; s=arc-20240605;
        b=jSBJP9zhNQnF7Yaic8biz/G6F93iwOtInxFfqT22jRrjIUJgcyB/fJ7hGNxvQDSn1N
         2u1civ8UXIpXUoDFci4eGJ/LXxLxsH5E1YHKw6X3U+tYau8WnTA2qEMrUP1sethJLGzY
         JM+iHTmb5LN7OB5Ttm//8ZXYh5cov09hwXlN5yVugm+x9DbEdlN2ELqQvmwqlfM0HZod
         +7opmjZoSum92Zg1JAyAX5OovkZt5pXjEQ2ECz2PHd5X7PN7m193CR/SmxczCy46tY+A
         l3z6atVPX2LNwShVI3Yozs/IZ0q4W7joodM963R0E9+nI4fW7O06O7bk7O6rCBAu6Bi2
         JLSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=9mlX8RXptQ6uJFSuwm95J4QJgxTO6tB3ssCtA+dXfpY=;
        fh=pWCpoKGL7nVhQKFzyTY/sphuxTXi2D0Hm1MqBEDIPaQ=;
        b=faLh6705qd9NBZ4LjnKoLmx1TMkLqdrEbqAqet6dsy+32ZTN//PIGghT7WLQY3dwaB
         3aanSozRIH1KasYg5uIblABm3RjLICmCDAs4G3apFX8jozhvW4aveLtkipfrQuzQBRVP
         EScoICgy0hkamhJIYa7enhVpsiS2VdkhtI1Jg/N67fkPLChZ31AJotlqv9ma16v8I3xU
         I19tntj+ci5D2g6R9/Mk6pJO62lqXWCHLgYJy2PZJljWPlmwKzTfgvPe9LFjMOksXLPU
         IiYP5K3/gsYupIyerA1do+osqgEoPd5u57R964nWVmWzLWByU4HsFsFC4g/L2LZeBJS5
         vfAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="tjA/Rnk+";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750927389; x=1751532189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9mlX8RXptQ6uJFSuwm95J4QJgxTO6tB3ssCtA+dXfpY=;
        b=CJxN2m9DIZVOpq7U+holeZIE+6ayamHtWtUFb/6tizhLBjOzqkVf47EGxcFcxO5qDh
         QAAeQ8j0nw7fVJeIyPYHOimhCO2lfJaCLGlo21E80cLl6L0qP+tGnaUkPN/yRbxM2Ott
         YoNszkwW/QKvL+N+HxmfVO3Sdc0b+XJ2hdpBa8nvP4EJoEv1RhJryfg7wlnV8bO694RI
         tONZwywXONRVCbeN/I5hVkjuADN5nSn8pGcrPHJculHr1KrnBr7/2y6g2R9WyvwgaUzS
         IvQa578ZnVBcG9p66XrJ878oXSlPkGHwRWJe4kh1AqcWdUjOzzb73EgEr6SqhkhzE/Fu
         gXLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750927389; x=1751532189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9mlX8RXptQ6uJFSuwm95J4QJgxTO6tB3ssCtA+dXfpY=;
        b=gUkMW0w6cLraitWH27ERGIin8HpUoKXz9M8cC7lOj9YLQ8bT+GrN9s6yE5ridVpq1b
         HvFHLRAAgRxRMaITHfUZUTMV9bC0krUr4qUKzM0mUp0cAe+thN5eLIRvQziGNXQ1Awb8
         SO41lpFwAEaSeRighikIOPCeeknpHoVl9fNkFVmAcKIOtRUEKEJVyfdMfjpb/+MXUfmu
         hm7avxtyVpSfBJpUt4DPHxOscSmLMAr5f/ZtyEnoImP82Xznt9NlP+9+xgAdv44S7cVy
         X0aRmmDf62rcPdC07/ErGpb3ISfhVMXwoEm8NrVtEJCbVesivAOtFm2Z3vcTyRG3RSV+
         lWUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU7Lju9UKRmuHcAnXrOsN7uxcrxv/A6dZXpTzRivLKOzaRvT3RTi9lTNqfHPeDWpiyUer29Kg==@lfdr.de
X-Gm-Message-State: AOJu0YwQaVtytq6NhE2jLuthouUVBNsSWgOvEGRPeVsBXe7CmAFg+0d4
	E3AfCbJmR72HVV826ol3ReNLNUIdtZEqObQ1hssyViWyyzxkMXGvInHP
X-Google-Smtp-Source: AGHT+IGYh4f/yL5gLCfhbxitqRX6+G769dtGCDaaSMdSYwOFuIHiSXLZsOV7gCoEst8Ce1jrKt7yiw==
X-Received: by 2002:a05:651c:10ae:b0:32b:5a32:1849 with SMTP id 38308e7fff4ca-32cc65210a5mr15114301fa.18.1750927388813;
        Thu, 26 Jun 2025 01:43:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZek4FGA/6Sk/cQrCdO2dPHpkk3EFDQxnOopYQv8lXbcCw==
Received: by 2002:a2e:1302:0:b0:32a:dddf:7d59 with SMTP id 38308e7fff4ca-32cd046cea5ls1466871fa.2.-pod-prod-05-eu;
 Thu, 26 Jun 2025 01:43:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbqj02lg3hpSCOkCpeVlwimw1o+Tc/RYy23Vn/rsKC8VLJmthnmn87/zNaTzhDD0pZPPCU74Z1eWg=@googlegroups.com
X-Received: by 2002:a05:651c:4098:b0:327:fe96:f4fd with SMTP id 38308e7fff4ca-32cc65cc457mr14008661fa.41.1750927385244;
        Thu, 26 Jun 2025 01:43:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750927385; cv=none;
        d=google.com; s=arc-20240605;
        b=RQVX6wXO2h5CjS6Fv3FuIII7ujVv6mCRW3L1FJC3CSHvnHzWH5LA8q6wfSQubFSyTr
         EKR12XjDyxhhMZYRCK4QX1jowDo46UUMe+uJCrz4HWDMvxsG2ZUfu12OLs1U46P3La6c
         dh1F10TkaQ09U9Vr9p/xhQ6daAtrkw4YfIzD7EplDMfTjlp+KppejnhyZZF9tTvGOeAy
         /VN0a21gCKpIZCE2VyYM25P0Du/giCRfbj/MTbrsIgIrWLkIgdcQwx4XuhlkU4coB3n3
         df/OZv2vrWf70MyswphJ29fj2I6d0LqlWPFtHh0e8ENkT0hDbBSZ1D3+Mj0NdbrwxPqy
         azLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=lIEWFzd10izeW8NDAm48DU86YG8FHDrpuX4aNPjS3Jo=;
        fh=653936bsFNMk+cLYXS9jzIvxQ1Sc9QLBZQtKByXGiGc=;
        b=iS+XyYyq0AO6+m/Do0U1vuQyK+IlWVgm8eaqz9MBvL8s+hdyV4fKEJ7onnKxTOqqmq
         vMvvHzSdAWUiJjMXPyRmcXC5zWRakMtNsLc5vCQWbc1yqcnqiKcZQGdSkRzjPrP69nSh
         Ws+Ib0UTaeouvdbwfYq5GHWgdG67fy+I/6j+4uMbAcVk8LgCKap4BfB3Jc4Bi4kc2gkD
         frad8Qq0yWKiY0paEMg6utgwr8bEkWJogsRtEToA+CJmqzUaZXHvfQy2QbGu9E2GBgbv
         eHhsKNSeuN4OSEbAXubh3vitJCDdwIQmAFJKya1azblpkohQYUwPapW+Vz4ectWkS2ii
         bFeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="tjA/Rnk+";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2ead65csi214131fa.5.2025.06.26.01.43.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 01:43:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: John Ogness <john.ogness@linutronix.de>
To: Florian Fainelli <florian.fainelli@broadcom.com>,
 linux-kernel@vger.kernel.org
Cc: Florian Fainelli <florian.fainelli@broadcom.com>, Jan Kiszka
 <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Michael
 Turquette <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>,
 Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph
 Lameter <cl@gentwo.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Rafael J. Wysocki" <rafael@kernel.org>, Danilo Krummrich
 <dakr@kernel.org>, Petr Mladek <pmladek@suse.com>, Steven Rostedt
 <rostedt@goodmis.org>, Sergey Senozhatsky <senozhatsky@chromium.org>, Ulf
 Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>, Luis Chamberlain
 <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>, Sami Tolvanen
 <samitolvanen@google.com>, Daniel Gomez <da.gomez@samsung.com>, Kent
 Overstreet <kent.overstreet@linux.dev>, Anna-Maria Behnsen
 <anna-maria@linutronix.de>, Frederic Weisbecker <frederic@kernel.org>,
 Alexander Viro <viro@zeniv.linux.org.uk>, Christian Brauner
 <brauner@kernel.org>, Jan Kara <jack@suse.cz>, Uladzislau Rezki
 <urezki@gmail.com>, Matthew Wilcox <willy@infradead.org>, Kuan-Ying Lee
 <kuan-ying.lee@canonical.com>, Ilya Leoshkevich <iii@linux.ibm.com>,
 Etienne Buira <etienne.buira@free.fr>, Antonio Quartulli
 <antonio@mandelbit.com>, Illia Ostapyshyn <illia@yshyn.com>, "open
 list:COMMON CLK FRAMEWORK" <linux-clk@vger.kernel.org>, "open list:PER-CPU
 MEMORY ALLOCATOR" <linux-mm@kvack.org>, "open list:GENERIC PM DOMAINS"
 <linux-pm@vger.kernel.org>, "open list:KASAN"
 <kasan-dev@googlegroups.com>, "open list:MAPLE TREE"
 <maple-tree@lists.infradead.org>, "open list:MODULE SUPPORT"
 <linux-modules@vger.kernel.org>, "open list:PROC FILESYSTEM"
 <linux-fsdevel@vger.kernel.org>
Subject: Re: [PATCH 12/16] MAINTAINERS: Include dmesg.py under PRINTK entry
In-Reply-To: <20250625231053.1134589-13-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
 <20250625231053.1134589-13-florian.fainelli@broadcom.com>
Date: Thu, 26 Jun 2025 10:49:02 +0206
Message-ID: <84v7oic2qx.fsf@jogness.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: john.ogness@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="tjA/Rnk+";       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=john.ogness@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2025-06-25, Florian Fainelli <florian.fainelli@broadcom.com> wrote:
> Include the GDB scripts file under scripts/gdb/linux/dmesg.py under the
> PRINTK subsystem since it parses internal data structures that depend
> upon that subsystem.
>
> Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
> ---
>  MAINTAINERS | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 224825ddea83..0931440c890b 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -19982,6 +19982,7 @@ S:	Maintained
>  T:	git git://git.kernel.org/pub/scm/linux/kernel/git/printk/linux.git
>  F:	include/linux/printk.h
>  F:	kernel/printk/
> +F:	scripts/gdb/linux/dmesg.py

Note that Documentation/admin-guide/kdump/gdbmacros.txt also contains a
similar macro (dmesg). If something needs fixing in
scripts/gdb/linux/dmesg.py, it usually needs fixing in
Documentation/admin-guide/kdump/gdbmacros.txt as well.

So perhaps while at it, we can also add here:

F:	Documentation/admin-guide/kdump/gdbmacros.txt

John Ogness

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/84v7oic2qx.fsf%40jogness.linutronix.de.
