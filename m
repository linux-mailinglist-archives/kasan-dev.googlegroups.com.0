Return-Path: <kasan-dev+bncBCF5XGNWYQBRBIUO3ONQMGQE244CF3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B497362E9B8
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:32 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id k16-20020a635a50000000b0042986056df6sf2083253pgm.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728611; cv=pass;
        d=google.com; s=arc-20160816;
        b=tD0ADIKfB+M37XMig5O/68uGhKooXT50raHJXKzOAytLfqQj3XA8QaVBYS+9BgJHf3
         pcz2f/LLF+G1eFNjx2dwKmXX/2lskXDmqUx2Vkw+9jRfRSPb4FNCAOckv2Z7bDh/0GTQ
         AKCdzdU1NyFmXfZURiwrVY8jPWxc+iX4yKTwqDn9HhY7kL0IMT2GP88RvrDjNH6sWioY
         ZvRXdD2mzeBMJEM7qY/ov8/hxMP1upfchW68QS86w9gBb9qSSgSHOVy+Ubb901aXjqBw
         VPquUqXPUdxOT1Y23Z3NsQr47YknzCvMFHPQCEYAnS77vSzBFrTq3EgWfj6+dakfNhTK
         DM/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rmy+uKpA++XxslWS487apS497YKC82k7ntkPTqbpiZM=;
        b=KdY4sak9TMDUc0/GmQiGpUSVwtHvCPcX21UcukgYgDyNEBy5DKAMrl0THO2drafy1m
         CAaOHvHCx0YJYxxGhfmi0nmln7au/TqxgXE+0nU992Lp/ibmAb8VRdrW0EKKhQVqq488
         15QUkRf1gmqaZTqUKhkHuqz2TgYIqsiRXYMtciZ5YWc2WWkPrfSTeVm+Tan1/jcKuamW
         vhkxKC9gFHdxlJcYSntE3FafSax/51CkTbT7HfXJWd/knTXaH17XFbaU20jvnPa/ShzG
         0OJ1pfuOoevjLrzv9LI1oy93xHSzZFSXIJSugb2Hruwecy95ndoySp6J77fg+pJTt2F+
         Pyzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=gzgQ67tG;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rmy+uKpA++XxslWS487apS497YKC82k7ntkPTqbpiZM=;
        b=C+FWyFQEieyhKLFDkpHqsDX6Xl7GW56KFeKxFs5HSD3K2bRzal6Z70ZvfS13no3FFy
         yER8c7KKMiqEAOdtACbrdEfRIdGhXmPdEbeGV4gaR73ONMufV/QuRgRD7LrhVVYgiAG5
         cPcWgYR2X3KlJTczj0AXBR5Ft9iyDLyNusulNvarfl+/whInzQ7cRrn0wCCrPsSI7aE+
         DU9E34cuPwfaZpAIDI5YOD7NCN+xYavbC9ac/1bQeN31eqp9KFrmI5dbLqjup+t0OWm7
         OE+GhKH6byuVv1hl+tTIICB2AjO+DlYg8hlgPmyXoGR54iPVfkp8f8Y/DtvWrAywm4Uz
         CELg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=rmy+uKpA++XxslWS487apS497YKC82k7ntkPTqbpiZM=;
        b=Kv1RwIy6hP5h8vt0myzSPEY+CM1PYjW3/XzWKEN0q9Sx292yeAtNCyNuLdWUVgOFoC
         A6GAp320+30gHjOcHn03L/KUmX+mkkY0tCalreTWcmeNxGp2fSZZvcDIl0/qM/Cysz6t
         JVkEJieP/f3haDW/kq80TrsHxJmynkPkPYzjJsCi8/X/V9B/Sm0GGClXiEcMAR3SP7SL
         mD3V0g2s/xZfZou+USIqPu2ElVXPpX4UiziZWXB01i9C6PyCoFbbmnFdYuHLL2eUG9Gq
         yn72Yu8O8OmhQqgmeQcmdC9igAMcskYfvBgcbrMMt9wJnfMR9F9FO7mYPFAi9d1h3Ho4
         a5hA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmNF0TwVg6tCOY4LXRj+rZcPmJlk7Ml3uBFLd7AXlqbY2Ss16oi
	COUxuesVzXEcuzoSJbguHGU=
X-Google-Smtp-Source: AA0mqf6mv7gAEYfV3WRJvl4v84M0+hLveTfNr69JWQLlKlX7lOB8r/8QZ/hAK3pc50sPilqmQqQovQ==
X-Received: by 2002:aa7:9469:0:b0:56a:7c3b:1bea with SMTP id t9-20020aa79469000000b0056a7c3b1beamr5180332pfq.58.1668728611097;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1c06:0:b0:561:e77b:c7c2 with SMTP id c6-20020a621c06000000b00561e77bc7c2ls1691274pfc.4.-pod-prod-gmail;
 Thu, 17 Nov 2022 15:43:30 -0800 (PST)
X-Received: by 2002:aa7:9293:0:b0:56b:9bf4:c1c4 with SMTP id j19-20020aa79293000000b0056b9bf4c1c4mr5218508pfa.67.1668728610411;
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728610; cv=none;
        d=google.com; s=arc-20160816;
        b=grgPCs+xzf++OPOWUqTR3Qw8IO8PLC8HTc6/TlZQhEUzPzSkIF7PYkRAbY8MLGPU0p
         JDP8T6Dpr1tWoFamamQ7i1RlVa48XY1KVMnW5GmPtJCTm5/7ITrSCPaMbmopB2ShzIx/
         ZANfsuMWP/BKK7//Vd9ldsAB3L1r8qUCxsKvhSBQz6LR4auUr2W05YVvsHmpuyTZ2RhV
         L4WX+kawp03c9a3nnA0/4ep30wBxyvKPKa9Mdqgknu3gWoPaPQ9xFlSwz4ImxhwsI5HV
         xnN2Lwa5gaUxGGwN/KQ9QOIJI2aKVIN+GHQYSNBMxayg1IUyrSDQYmuGL8s2I9FLFZn4
         CT+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LQKoNHkwXKQHXK1Rm3137rvxsN3jeB7ychTw9wiMCoA=;
        b=njoEAVZFd2g6Zx/AaHujw4t4/6T72MCDPVvMTgSBzFMw08BBxc6CZG82QDZaI4AvgN
         ugLwzG6AUbDoIJkS/O3GNOfNGm59dxYYiqSXvNM/3NdnDscaibbdPJ9Y53Iv3E0nBcA3
         vlIkBp4pYPUX/rM23Z38INBWlD1BjtpyeALzKGLmmX/aMoIEs0P7VgXEytZVpMJSo6ej
         EJVrheVBwnBu7do408hyz5aM+qMTURfUCT+9bKAdPADiX9wHxsgz9FslkYyboI8PMkY1
         yFra43scOzjvWPK4oXj32DHmlkkBiM8guarfjkGwSRN1/qUmQ8d6tb8WG5lQ9q+Nv61p
         kyUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=gzgQ67tG;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id w203-20020a627bd4000000b0056611e6228dsi141987pfc.1.2022.11.17.15.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id 140so3294739pfz.6
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:30 -0800 (PST)
X-Received: by 2002:a63:3d8:0:b0:476:eee6:d394 with SMTP id 207-20020a6303d8000000b00476eee6d394mr4235676pgd.228.1668728610079;
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id o9-20020a655bc9000000b004582e25a595sm1614221pgr.41.2022.11.17.15.43.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:29 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
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
Subject: [PATCH v3 0/6] exit: Put an upper limit on how often we can oops
Date: Thu, 17 Nov 2022 15:43:20 -0800
Message-Id: <20221117233838.give.484-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1558; h=from:subject:message-id; bh=Mevv31fJaznFTh44cD9Wkn2q46wN2KwgT2JblND2tEw=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdsccuB5/7Dud9dthXxlatod2tm4x+MLt8lSkzhG8 v6L92dWJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHAAKCRCJcvTf3G3AJuVdD/ 0eNAawmC+gMqkT2rEKRxW1q1K4WlSNG660mYF+W/EAMANgbt6w31eLw4F1zcWZUz+34y5smj0BBaCU y5rzvHB47A7fuA9hXjcwb8TuxsSnjq3pkDquhBH7Y3KFkj90GGVkL/Mh9gVP+uOLjCYvc48iwOt2eG YHZ/y3jAgGhcr2jxeAYCwOwalTeHyyCeurbdvX7Oq+a45aPDWcVfffZbFVfHn8DxxTVcNQ7N/628uE z2kYsHca4qJwFAzPpArSYyVloSVtbEW5ckjt+Iq6kLO3u+oTgu+PvJpLJ9F8bnjbFIklvAwkomHvfV fixggchvSkevDB43e+wQvPrcKfiNN71mlbGfuMLs2VVFuzNQUGAZXRhHR3lwG9UIaNDuCzzxa1UWr9 3ktCososbPal1YX12fJhSFl8vzBMk7JLQEbTTHcYUAbjWHdpNJodiID252O9pAdmG1E9muAIZGy4qC tcH0IouHdUSPs2DP9Y16vdrEMok25wZU7rIjZ0VxdtGIMrgiqMZmxweeRnhXSgy/HFG+1IXtXgb9Ir Ro+U3RGzEYBu6Wklay2Dr6Gca6606I6a51/zw0fPXanLvL+dGU0ZHeXbx7SaSYZ0n2zPaL+1ET1p19 gLeTIC7R+E3l0BJ0ilq4VBoffYDaepF8i1hdfUaDnHhkEMaoDGmjbuFOnslg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=gzgQ67tG;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f
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

This builds on Jann's v1 patch[1]. Changes in v3:
- fix #if/#ifdef confusion (Bill)
- rename from "reason" or "origin" and add it to the warn output (Marco)

v2: https://lore.kernel.org/lkml/20221109194404.gonna.558-kees@kernel.org/

Thanks,

-Kees

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
 kernel/panic.c                                | 45 +++++++++++++-
 kernel/sched/core.c                           |  3 +-
 lib/ubsan.c                                   |  3 +-
 mm/kasan/report.c                             |  4 +-
 mm/kfence/report.c                            |  3 +-
 12 files changed, 140 insertions(+), 13 deletions(-)
 create mode 100644 Documentation/ABI/testing/sysfs-kernel-oops_count
 create mode 100644 Documentation/ABI/testing/sysfs-kernel-warn_count

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117233838.give.484-kees%40kernel.org.
