Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNSVKPQMGQE2HGPDVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E913C69516B
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 21:10:50 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id y7-20020a05651c154700b002907d8e46e4sf3176081ljp.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:10:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676319050; cv=pass;
        d=google.com; s=arc-20160816;
        b=NjnGQOdfLbjJKc3mYkbLXhhVdJbxgV6PAXklMF/3A00yeVgef0jiSP4+Rod1fdtl9L
         JTETFWvCYkTgGyS+pCXpkNgAJ7qLNmerCCPbqe3+u3jPLpMe48226dl8kEANPIVvvG0E
         keb6o5j2xSEd++Q/laeYqWXXlMMntxWLOddZ6x9rFO+XypWk8KYgO7/W9IyvoPs0rLbV
         1APks/CSR4xiTQNa4ZgTCUKz1DA7p/36Jhjr3pamVwLP7M1GdDbUEyduRIxois92ZAZI
         6WROZlNSR94EJxO5tIaO7EiUeYk7G4ULVWbEvuR5BbqteoiYzMe4fk8GrmrKwcJR77BZ
         Nd2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=rxL4gA6s7MCdmFTL9HyqvtCPCJPJor4fWBZszAWJRsQ=;
        b=cxpdVmEyLDuCtauLsoMrhrCzxDvXLjM+O2dVgMQKabLyr/iFT4C6oh99CBehKSTyzd
         +ebCag1tA8qUp/dEKY+ogVQ2tbcyZQ5mEo0b+MFEk6s1FHfJWfxL+H5gcUFl5VAmGltM
         4aWD+3kPagorVwOpsFTzOqsp/VlY4io0eA9gKusJnercFtnJy2m9JGBKwfDLXF7+eE+o
         LfSds68fkBYNbOiOTWkBRitQv4Ok81oHdgdgnZRcu5qRX5ZiyfwTfQyJ/mTmEJ6DVAIF
         MwrT9RkNTZKJRW63UB5Aw+IfWBjFjpvCah8bvPbT9ZA63cNEhWkwVhX7gUNLRXtiTJyi
         nEAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nPgGXYua;
       spf=pass (google.com: domain of 3r5nqywukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3R5nqYwUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rxL4gA6s7MCdmFTL9HyqvtCPCJPJor4fWBZszAWJRsQ=;
        b=I109YaWIty/Wv2qtVbdeu6/L6o/hHiVLmB/93RjiBz8E7FNvHrep9VVCme8duINhHb
         k8F7a02kyWBhTaNwL+pdNcu+ZOovvj9Nzn0CvLDlh+ZwqBTLs5sldPwHxnftj08gZCm6
         xM2Grn/bjqDcqU9ah9XGKuOeUjpXqQEvK8I+ISmXriziOrLS3zowPCyETzTWvNCaMgT1
         82L1NR2JtdMgQHNx/mboaN4de0Io/Be/Vimq9k7RbNjRfxHET3F0l/gThnazfXkFqVvC
         NTxn8r0GjdutwIhepD3fBxLrz0TJ+ReSKSyOrWPX49vT8eABtc/1T/eJwhu/R56YzytF
         8eDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rxL4gA6s7MCdmFTL9HyqvtCPCJPJor4fWBZszAWJRsQ=;
        b=Wu95SesCa615nPe9EPmNvVnb+epeVlYlA71tpL44vFtOYHcU+S9gCSnZuGyzuDh0wG
         aKYQit9cz7ED8EqqgDRjI/IBSHJ7g6sWkQNX27twbxXj0zfruanM+3RbnwGnS9J4fyIJ
         YiRJxnV0hwVO+rCOFlXdIvaYUVROelyvCv6x2uuljazNixaRtjaUgrzdg6UE3eSvrfLJ
         f1FICQGOGpidBUYFu6g9oSYYTod57Ikairbgxylg/NnPDbtxgIjTDaAGuT3QA8JHFh+8
         FsYR7JZmtleCAYIkxklbl1cZhMGn7iI0Ua45gkHU2duZ+9r3Nt/K6ur9xI/acNCLmunD
         tU0g==
X-Gm-Message-State: AO0yUKWzteBoXXPcl4eIMrGOxiiK3Ukk4x8p6vmuD3EdksjNjz7rBXVy
	8AsINfiu24GPl2DJ6VvVNcc=
X-Google-Smtp-Source: AK7set8qNMlf+fJmZAWhU6OLxRydV55FC9DFYt481ToCfhFViOkb9dsDQOBNeNiIacsiUfwcSX82ag==
X-Received: by 2002:a2e:87da:0:b0:293:4e16:89b2 with SMTP id v26-20020a2e87da000000b002934e1689b2mr53002ljj.4.1676319049992;
        Mon, 13 Feb 2023 12:10:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b25:b0:4d5:7ca1:c92f with SMTP id
 f37-20020a0565123b2500b004d57ca1c92fls312616lfv.2.-pod-prod-gmail; Mon, 13
 Feb 2023 12:10:48 -0800 (PST)
X-Received: by 2002:a05:6512:398e:b0:4d8:86c1:4772 with SMTP id j14-20020a056512398e00b004d886c14772mr6957033lfu.7.1676319048118;
        Mon, 13 Feb 2023 12:10:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676319048; cv=none;
        d=google.com; s=arc-20160816;
        b=kN/a+ZzaV+GHrhUMEj6a0Jv887Emp9ve+Tsm/fsKq82kEufz0O74mPuJ4KVKkXD7Pf
         HNSMh6yCb7BrsfykL7g0i7da9LwE9MBlfFt1aVnG8ARVOCdZPsy5Cfj/Hsp3cWvnD+OP
         wh2I0H80/Yupy3JuxNBu3Vr71ED95wQOvVlmt4KpTb9ud3crGOLFUvuRvbJQPvM36Vls
         mJ8O77nWeW2GYhq2KhmaInZK5zqD8P03f9S0gjbr9w8R9DmG62x8QkLFwJ1FQfuDtNYR
         odQrpxHTIL7WzTB5agMRifypBFeDt6IrFEqq6hPMrKlkralM/0UW6Da+qQ2OKy2kMydo
         P6Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=H/B0iwxSfZGzTMto/wFUe2mHRnomv/i3ZrRWf1XIjx4=;
        b=cdT8ktYHPuTZmKlR0CotE5ePjTqwf1l72gvy1cXxV2HXZYrXhRTjNSvyWNdK6HCSpb
         8/9pB69wJwkrCvDcgG1TeqRN+xnD9b80WEatbKbP39kKnjgHIDxV0tg8ZtSMiMhWCshQ
         VxTUt2ycRinx+ZQF08HZQk2ePbfPu3pLPVVsKmSShbVaMhj8zGvOdoijw+bZlsizkOnq
         VJfSiGt0DQYuaermZVk0bhzHu4iMG0YTfdxA48bVzi14nkxNOlX9YD7lSdKxG9FuZ+Sm
         LEu1X2hTps6eM9MfxpjKFwvSV9H+kMQPjzdxx1vSwscttKPDUU8npST7PrccVTOCKNiY
         NfAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nPgGXYua;
       spf=pass (google.com: domain of 3r5nqywukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3R5nqYwUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id w12-20020a05651204cc00b004ce3ceb0e80si727168lfq.5.2023.02.13.12.10.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 12:10:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r5nqywukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id l18-20020a1709067d5200b008af415fdd80so7719805ejp.21
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 12:10:48 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6cba:3834:3b50:a0b2])
 (user=elver job=sendgmr) by 2002:a17:906:5a62:b0:877:7480:c75d with SMTP id
 my34-20020a1709065a6200b008777480c75dmr112334ejc.0.1676319047593; Mon, 13 Feb
 2023 12:10:47 -0800 (PST)
Date: Mon, 13 Feb 2023 21:10:40 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.581.gbfd45094c4-goog
Message-ID: <20230213201040.1493405-1-elver@google.com>
Subject: [PATCH -tip v2] kasan: Emit different calls for instrumentable memintrinsics
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, Jakub Jelinek <jakub@redhat.com>, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nPgGXYua;       spf=pass
 (google.com: domain of 3r5nqywukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3R5nqYwUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
with __asan_ in instrumented functions: https://reviews.llvm.org/D122724

GCC will add support in future:
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777

Use it to regain KASAN instrumentation of memcpy/memset/memmove on
architectures that require noinstr to be really free from instrumented
mem*() functions (all GENERIC_ENTRY architectures).

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use asan-kernel-mem-intrinsic-prefix=1, so that once GCC supports the
  param, it also works there (it needs the =1).

The Fixes tag is just there to show the dependency, and that people
shouldn't apply this patch without 69d4c0d32186.
---
 scripts/Makefile.kasan | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index b9e94c5e7097..78336b04c077 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -38,6 +38,13 @@ endif
 
 CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
 
+ifdef CONFIG_GENERIC_ENTRY
+# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
+# instead. With compilers that don't support this option, compiler-inserted
+# memintrinsics won't be checked by KASAN.
+CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix)
+endif
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
-- 
2.39.1.581.gbfd45094c4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230213201040.1493405-1-elver%40google.com.
