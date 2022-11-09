Return-Path: <kasan-dev+bncBCF5XGNWYQBRB54NWCNQMGQEYZRY55Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 84B64623412
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:56 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id r197-20020a6b8fce000000b006c3fc33424dsf11888452iod.5
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024055; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ha8pI5WgeDZAG5VRYXDknwpT9/ZY0PrI7sS4Tz/BzIFfVrUmME4lRfvczlAptUpkND
         eDmXfXIVBcUNhE6H7AJYQp/Y0T5p8FNRNIB0AESezu8S1ssN8AIo9NaUSbbBDy3wPEAD
         2nMNiC+A5VPMx+jHMbgTL+F0x/1Ik0R/XWr8FiOusx1MqJKnGpSg85bKlz2XmVKziY3u
         WH7eiL1qZ6yAbiXtMnkRtOw1wozfGgWjdQHlrJyxA5wypF/GYG+T7rF5mUAbLFWeWwuq
         tUA/ugiLW84AOf2enbiKClXGZYS58OKVuq/xHlAXp8CNtTiHWch8PbHS6VlP+D3Eq4/K
         z2Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=n540i9rIb5uUP+YD3uBEeXW7+JJuev4RDJdWJm0kCLo=;
        b=OacSDXDpA+2OhPElkO+ZiFrN2vVDV16HwJFwvRcgaRGNHoK7ep9md4aUFCX7oOtJ9s
         1zrZwFN/+zdcCY2IOKI4DjoxbaHaWjl8yEX/VKvo0DMQ0H0itPM2wkDpQB8IMTdyPx3j
         NnBeCS9MvoVtKm/a93rFfPBXLDCvXaIrhg6BHdlcaydzp3zAJ6J1PPz0JQGfR+7/CCCl
         JCrCcLZ6DMFDadjJwNoAfZ9ArCfRJrsIwgcOB85G7+qGdG64RBrDJ6dAnH6U7JM4r/E4
         ia39plETj6tu4yWlh0IOwbGnXCJgFTNHeO0g7wBUtK96V6Q8Rw7jeJyriEVUkJ11yEyJ
         MPYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PhMz0SvI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=n540i9rIb5uUP+YD3uBEeXW7+JJuev4RDJdWJm0kCLo=;
        b=fo/uj5mucWeo6cWWPpmopVMAi93bYmjQpf0MvXhOZqwg7F1is0l33ykF2/nHVggKgY
         aaxm/mHeihuPvOY5hUO6wYyiAZZsFyXIjUMvlOpTaM1on3bQZC7yxJMqk36eSqCvoXfC
         FJeOXkZAICjCdk/9kmZwMqwRtl/6qeBz/ACBVOxBEZxQKaRz0MQ9lb31SgmzZ7qmsOLe
         5X9Fo5FI+DxK6pVkzPApNjBRyijtEk7ZxjDSH3DnBtplLfcC5EWikNOokzXVRQcJpwEx
         fbrVj7vwtgfU+Ugh6DaKTxXER4CGtTaQ3mQFQRCg12SzIP8FKbt1Ji/gk5YwzdpVgVyT
         W21w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=n540i9rIb5uUP+YD3uBEeXW7+JJuev4RDJdWJm0kCLo=;
        b=PnKUu16o8XTOSFqbbHSGAIaeqNyWvi/FXYUopP/NLgmu/jlYlkVVHJgucm774Cv83X
         4cnhkh3Dq7vEMlnC6mLHxmfKed/UMSJMeQ57iG4GKadsFVA5Khd4YMfrURpPP1gG7EaK
         QJz3Fqt04FuhcISupK31omTSNkldLsuROL4p4RkBmNQdZsCk7ci+xCRrI1jxK1zAJQYW
         n+M5D1LZBYxuiKwy5w9oJSyt/38WvR+ifE1KXcP6asJSugIkXFgGEY4gzrpqfUYa8sqV
         Gq/1ZkssByCguU3Nx6MSlPT/gleZDAEPZ5Mh2o15lE9EH/fnQctOj0DT0XeL0qGf1uKd
         /nIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1C7y/E4C/8q/p3HvbIWb3FF0acrXOw6mLdo0Oniw7AN5oNOdAk
	uDBJnUUhxT5KB3B0j9wEgLw=
X-Google-Smtp-Source: AMsMyM6KbXxchKSsML7SBgDN0f2q/cquk338dGhzkNC+icmVOVGQRjcfwZR/TwsM1/JCsH6+TuWbyg==
X-Received: by 2002:a05:6e02:5aa:b0:300:ebdd:794 with SMTP id k10-20020a056e0205aa00b00300ebdd0794mr14666295ils.228.1668024055458;
        Wed, 09 Nov 2022 12:00:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f48:b0:300:d333:1bb9 with SMTP id
 y8-20020a056e020f4800b00300d3331bb9ls3887982ilj.2.-pod-prod-gmail; Wed, 09
 Nov 2022 12:00:55 -0800 (PST)
X-Received: by 2002:a05:6e02:1aab:b0:302:770:3997 with SMTP id l11-20020a056e021aab00b0030207703997mr11021824ilv.34.1668024054947;
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024054; cv=none;
        d=google.com; s=arc-20160816;
        b=Gt4yFfBSZ0+gttLp10L4caXFaFjzysr767LYXv8Qn6qr4FV9pKEqWKOo2YKDvaU7lq
         y2bAneJ5fsdXN+wc1ISiX+IsdOHN+iLoekspX0n34EzD8K0/XK41/eoampt6yWD0cpdS
         VnwWhTs4mNqxMNOe1HPAvb0XhhCVIji+PWYo5Q95ng1yOfDed60qyi1xcH1SezfO+V/G
         S3/gZ8IIKJA3q5UZlu9M+yEwQ1RLM67YSgbEdeUukq8UwQdOGQ52XAbn0dVBUFHHOWet
         1Eg1ycjp34/j8Pust4i+hf5tqasvZg6pCVw69HeDeU1Sf7qj3oKFQdWyr2ED3+QyeNWJ
         6zWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=KGQv9g3ODjs6GFRrqXnKxOhm5DKhXRVSdXb+tdSOpIY=;
        b=bPC5xSaVOGsqQ8g+2ndMoQBJ7CZ5eYouNSCE/hldcLl4XApuuZwGoyN4gX2hXy4i42
         pH72Kqegy074fGzrImvMZTQ6wc6E6DbwuK5QCkxtxGRVT+8SDzkam4qG7BowACSm8cYl
         sdvqZTyVGBX17HEXOO5PmhlotGOlrqr/ESRZcy308ZlZ+oJkNAS3qg/Mccq2cbdwzD8x
         +EWaD5wq+Xjnm7TTEUilErC6jjzDhWv0Ik7Avm3std+NnnnixPIu0U/WJ//qR7/xIglS
         ph5XLjsesP96ObMffno5ERTJdbHU0MHbGAoR7e3Z8055z9OUucivL2tV1LQG9bQZFwS0
         YxGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PhMz0SvI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id r22-20020a02c856000000b003748fd49976si668615jao.0.2022.11.09.12.00.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id u6so18075549plq.12
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:54 -0800 (PST)
X-Received: by 2002:a17:90a:49c9:b0:217:c5f6:4092 with SMTP id l9-20020a17090a49c900b00217c5f64092mr21353250pjm.33.1668024054274;
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id t24-20020aa79478000000b0056be1d7d4a3sm8668553pfq.73.2022.11.09.12.00.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:51 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH next v2 0/6] exit: Put an upper limit on how often we can oops
Date: Wed,  9 Nov 2022 12:00:43 -0800
Message-Id: <20221109194404.gonna.558-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1576; h=from:subject:message-id; bh=f6yYT1z0j34/tTr0B+65L7ktUKTQPrMyBqrftF9wr6M=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbvE87tT3kRd5r9yYOWLJwPzhKiyHMFu0vH4T8P yoDh5syJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG7wAKCRCJcvTf3G3AJitzEA CncSpVOXlgXdbb/hwP3379EIiZDAVaMRKgUjhCrB5C1AG8xFxO6JBJoQ4+l2O231mX/ddD+z+SYMfX HHZ95D8VX3sAWmOtoadA7shTHqEF0FsiXkKpQl7f6JgcaNkKdJ+q2tS3f9H6r92zj3NC0e+WJLLAEl hZ68EYM1yBHu3NbBwKNCGg2c0yF6si6geFbjeUnYiOy6tW6UYvePIrwcwCn7KlYhqgl4KNv36+jWHc Y778i1cRX76eeiUzpHniT2B2T0Evn913bHmuLUL+FIttpmCIIKod6ACYcJcj/GNRNqzRV07wl0Key/ z2s25RNqy72RUf87fAkxXXF1SUj/Zlyrtv+1amMRLYK+YJZk2xVsnpjJ12EXvXy1aRog1ya0Uu2Xbh JiED6THw9bgM6qjUfC1P3K+hxbbADTaXDKq/YmanOFpM2dQ0x6gPSL9K77ITM4epSlnxzEFYPW38VO aey2ABBPLLf1x6INkY63BahlYSW0lEFsPq/SwtRtk96yvfx7cnX/3s5yJ69e/KOOeqympJ94EqAHMS uiHCzAG5wBKimts9Ev+ASgD5grPm+aNTMzg7YGHLR1H8CtIvP14gAmvYaDBunKlhjowNMBxntTuhq/ yQXowZnvWi80+NGf5Y6I3gintRa/hcEra2VTAWXPBDlREGitdn3tljFvyzMA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=PhMz0SvI;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Hi,

This builds on Jann's v1 patch[1]. Changes in v2:
- move sysctl into kernel/exit.c (where it belongs)
- expand Documentation slightly

New stuff in v2:
- expose oops_count to sysfs
- consolidate panic_on_warn usage
- introduce warn_limit
- expose warn_count to sysfs

[1] https://lore.kernel.org/lkml/20221107201317.324457-1-jannh@google.com

Jann Horn (1):
  exit: Put an upper limit on how often we can oops

Kees Cook (5):
  panic: Separate sysctl logic from CONFIG_SMP
  exit: Expose "oops_count" to sysfs
  panic: Consolidate open-coded panic_on_warn checks
  panic: Introduce warn_limit
  panic: Expose "warn_count" to sysfs

 .../ABI/testing/sysfs-kernel-oops_count       |  6 ++
 .../ABI/testing/sysfs-kernel-warn_count       |  6 ++
 Documentation/admin-guide/sysctl/kernel.rst   | 17 ++++++
 MAINTAINERS                                   |  2 +
 include/linux/panic.h                         |  1 +
 kernel/exit.c                                 | 60 +++++++++++++++++++
 kernel/kcsan/report.c                         |  3 +-
 kernel/panic.c                                | 44 +++++++++++++-
 kernel/sched/core.c                           |  3 +-
 lib/ubsan.c                                   |  3 +-
 mm/kasan/report.c                             |  4 +-
 mm/kfence/report.c                            |  3 +-
 12 files changed, 139 insertions(+), 13 deletions(-)
 create mode 100644 Documentation/ABI/testing/sysfs-kernel-oops_count
 create mode 100644 Documentation/ABI/testing/sysfs-kernel-warn_count

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109194404.gonna.558-kees%40kernel.org.
