Return-Path: <kasan-dev+bncBCMIZB7QWENRBFGBYL7AKGQEMVG7FVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 0317C2D3F60
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 11:01:58 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id e14sf836717qtr.8
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 02:01:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607508117; cv=pass;
        d=google.com; s=arc-20160816;
        b=YDdcxMA6C5RS41kw7F22ueQl3I4jQPLqWKeTnfqdhc/os85ntlIIJHLE9QjVaFadb/
         zfgadk5P31zHJht9tvIi6+1Cplbs1Tf5rnzkB5iFk8IqqOFTWnhhvhU9npzAZWVCDvcY
         1pf7WGtd0Q2brm7Jh3id2JTkVxlua04XGO+7cBJnGQ1fyNXGltIteo+g+fFR2LtgFXbG
         7lKfzVgbXhACqgbKAI1WssjUMGiWf8Sjtw5TKm0kWb7+s2/zfHTlbDmmPWtfZ9LUcfvl
         KrSQEMHThvWczZiKl4TASIN1ft7Q8bc+Tjm24z/r+q2G+FxDxGew5frHNEmi1OGeVn5/
         HZ2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=1HTty9PgYiYkvkyn9StM14yIp3yJ4jyECUEB+75DXaA=;
        b=eI/4pGaY2poBobEEm7HD4g9/z7T+IuuF+QXYn+CgogguMYe8Ryp7ffIMnoiJusiOvj
         kSLxDV/LKDRmqMhsu9Z7BoB2KcD6IIldQOxt0m/RK0SRrnqR5nk/+dOllv4UrZYeEIjj
         9UdL0nQLKEDW+sIC3JqYF2wGORyAbBQHwNClykfutySD+aQuptSZN2uXnEry8dc8L8qo
         pdP+/03ogjWGgJFhZoYixZZ1aEbVgJnWZhCjCXlNjMslh/KvZTizQXMhiYQO0eFmDzlo
         eX2znbyX8EJp95G6Fp0fSxADygtOpVpguRtD1CMvqAWtGrIXYtXSUIyEaGLXt09SzG80
         XjsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jbjrQ7nK;
       spf=pass (google.com: domain of 3lkdqxwckcr06orndho9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--dvyukov.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3lKDQXwcKCR06ORNDHO9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HTty9PgYiYkvkyn9StM14yIp3yJ4jyECUEB+75DXaA=;
        b=Jr9EyZnHWL0YmlQrjkKblcwTqdPJS14heoXHJWOzZ7kOcN+ZLbxOQhM0Qkd1oDOnYi
         OYuL9tr+tCHopljGMwc08zgv2vJG9laLNY0ElKu8JaI2ZWFfKnoQdsrrW6T+ffNh/JVX
         BtNnJXuV7zfu1LcNjW3QUmaosSFT2/8hlRdehg4VG2lJ7wdL3RBL1N+gaOnMaqwmHn9C
         SVfV05thhfBfcJBZXIZacUjvyclOf2r7TroNRdo4tSLnz6xPKLXY/DYCqvcwCDzzGcc8
         hTtW+Ux/EXuhHeFJk9OutYYyVlpO8+HniQjYFDIlqO+1RbAd/69ARYr9ItU/GHK9s+qO
         jJGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1HTty9PgYiYkvkyn9StM14yIp3yJ4jyECUEB+75DXaA=;
        b=mpQhHfhGLGxrpb32QGUhItRRnIsXp8WGhIc7lH6kyxqf+84KUm2gx/F/z7vIscvUNS
         EZQQEqZNauQC30ZDjK11hqC9dCtAKIGK9P53USiphk8icQrCIf+NoJ7BdyYZtyl7t6WB
         s5MaoCSu0WHH04j0WJ783bgCf26UqLfV8ZE4LXY0A6bULGt0JW0JvVKzyte13zIicozx
         HpqUBS0o+bOoD6O/eN4c6Tf6aNeWVgoVUyI8t3q2iDBcL/cYfz1epHjyH1H/1LyaFmbu
         1Ka9Y79cMD54M0MDl1XaY9sAUSwjWuqDNS4rbU6nw+/9TfDQ7d/z89DlnLykyPkXSU++
         aj8Q==
X-Gm-Message-State: AOAM533SHCnh0PwKUcVdy30FCaFLliQiWWtQ8JTJNHN6BAtpeXqgmIzI
	WBhjvy96TgNRlrlcuhvy3QM=
X-Google-Smtp-Source: ABdhPJws4l30LseIRkAnzqu+GWbIx/NKxbFGLQx91Q0ZPqRNBxot27YMB4yqzy2TbMuDyE9EqJ1Jaw==
X-Received: by 2002:a05:620a:218e:: with SMTP id g14mr2277646qka.243.1607508117090;
        Wed, 09 Dec 2020 02:01:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:572:: with SMTP id p18ls570384qkp.0.gmail; Wed, 09
 Dec 2020 02:01:56 -0800 (PST)
X-Received: by 2002:a05:620a:2088:: with SMTP id e8mr1961156qka.339.1607508116638;
        Wed, 09 Dec 2020 02:01:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607508116; cv=none;
        d=google.com; s=arc-20160816;
        b=SMo5feIHIh8rUmHx9QRtJLbcqAL4FwsR8GOEOdPs1ruSW0Uc4jzDlOpO2WDIBdoE2S
         Zaf7B9qOLSsyhZfXmcSSvTntyLqmuQ6WW009FMeUzGhqXmU9oixEGB46D33TOjMWsIUy
         nwHZ1P4IDDZV2mDI8sQ8c6XpXWXO0NMYJqDO87iPOa5TDLnrJr1e3voT3HSgkroXELP3
         ISvslY8hGLUALnpxlYoKMB1iJscQKFV7M6CZjUxheUwFFWxS2pPDS1x1ff2LphJ+PGVw
         oa0DKEteiOKNcXoEg9yIYv6hAVUClBCNzLxdVKYLqyexlOnxOb9Q8+2c/pVsPxsjR5NB
         TSHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=tU0bH/ZopN0B+Ye8Q+EH0DzWrhlff2/lJmGr/Ir10cg=;
        b=XWsU2nqinIzCo41q2xzOL+cwnLV1rz7hLUSRFAUyhrpHF2aZy3lFmDnmzHej4o1TGv
         NOuhFSv4+QrJ67Tb2ushYK5S8VxVOXLkEI2OFZ18n7teGFF802sXM8jQ7MPB7DlhVVTE
         xH8DrIGcX47ZEZqldoE05EBkB+L5G+X4tvr0yV1wCwgsQHI/3xDD6+JhZJS+WTpyROBo
         L7lib/jBxxHf7S8mMVJ36MFF3QQgea0DhzzUq6/GYPxNUwA5+JLMjA9NCn0bR9z6n1sZ
         lE2LK01KxKyUzu59UMCWBopo1LNl2WfFn4YOgvXwR534ucZ8isCQDuAepTqq3RN7H0no
         1m4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jbjrQ7nK;
       spf=pass (google.com: domain of 3lkdqxwckcr06orndho9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--dvyukov.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3lKDQXwcKCR06ORNDHO9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id a8si125394qto.0.2020.12.09.02.01.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 02:01:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lkdqxwckcr06orndho9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--dvyukov.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id z129so653391qkb.13
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 02:01:56 -0800 (PST)
Sender: "dvyukov via sendgmr" <dvyukov@dvyukov-desk.muc.corp.google.com>
X-Received: from dvyukov-desk.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:a2ec])
 (user=dvyukov job=sendgmr) by 2002:ad4:4ee3:: with SMTP id
 dv3mr2224365qvb.58.1607508116142; Wed, 09 Dec 2020 02:01:56 -0800 (PST)
Date: Wed,  9 Dec 2020 11:01:52 +0100
Message-Id: <20201209100152.2492072-1-dvyukov@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.576.ga3fc446d84-goog
Subject: [PATCH] kcov: don't instrument with UBSAN
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Dmitry Vyukov <dvyukov@google.com>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jbjrQ7nK;       spf=pass
 (google.com: domain of 3lkdqxwckcr06orndho9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--dvyukov.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3lKDQXwcKCR06ORNDHO9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--dvyukov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

Both KCOV and UBSAN use compiler instrumentation. If UBSAN detects a bug
in KCOV, it may cause infinite recursion via printk and other common
functions. We already don't instrument KCOV with KASAN/KCSAN for this
reason, don't instrument it with UBSAN as well.

As a side effect this also resolves the following gcc warning:

conflicting types for built-in function '__sanitizer_cov_trace_switch';
expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]

It's only reported when kcov.c is compiled with any of the sanitizers
enabled. Size of the arguments is correct, it's just that gcc uses 'long'
on 64-bit arches and 'long long' on 32-bit arches, while kernel type is
always 'long long'.

Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
---
 kernel/Makefile | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/Makefile b/kernel/Makefile
index aac15aeb9d69..efa42857532b 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -34,8 +34,11 @@ KCOV_INSTRUMENT_extable.o := n
 KCOV_INSTRUMENT_stacktrace.o := n
 # Don't self-instrument.
 KCOV_INSTRUMENT_kcov.o := n
+# If sanitizers detect any issues in kcov, it may lead to recursion
+# via printk, etc.
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
+UBSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 obj-y += sched/
-- 
2.29.2.576.ga3fc446d84-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201209100152.2492072-1-dvyukov%40google.com.
