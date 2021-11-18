Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRUV3CGAMGQETUP2TTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id C20B5455690
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:50 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id y4-20020adfd084000000b00186b16950f3sf874986wrh.14
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223110; cv=pass;
        d=google.com; s=arc-20160816;
        b=j2Zkh7Z0DgabVQu4N17WI5ZXTsQH7uHbedFM3LPgVT0NP53t/5nOFsFDCmriWKIJ5I
         ySsAfXclU4uu+6Rl5m8jhK/VlBQ3P7TU8vponAvtgXqELNHeE44UW4GYIxidQxhrMrrw
         ALpKvsZ0GkH2hvUCxRnoYBY2+SwL19vODs1Vq2sEdh7UFtAHh6JOsNTTaRdH0SXsDUc+
         G327XktmE6pOrLiMaj5YaedalONY9NNKDQ08GE8JMlDYW/h+bgneHG9yzvcz+on2wHTv
         QwhhYSfvYYcH8yivR1dQwP1sI5rC4XYy5ngHhNe5A3MKWWSekh8KvW+p9bhHa6JDvyef
         6Y5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=luHaMljHImWeFwF3gZTmxn57EZZb9xybESKHyvT115I=;
        b=OwNAtqWOYBCM0/y6fkY14PGpkds1H4A/2SFN6BplbIgm7sAWhx79ryseQUdVa4tiIN
         uQL760m2dRJLYmsoM/rSuq/8m4O7ebjJQzZVktbhRpQluzC33PpN7SXGCVpKUIqDDSOy
         a0iOB0pa7yWrgNT4qBoAd9WfrGjY0en5FB83y5LwV3Z8QusVf7IlJ17Go1mou9cAq+0N
         ibGOkFtr3DqgzcxDbGHfusF+O0DrA8GszmlCRhR/ITMEw44fBvJwnv2eIzds1TQn2fes
         n05ntGGpMTz7LO5dKGEtxNQyaN1reliTE0ALV+lwZB9Qd+OQlPJ4itA6soW4rgBUtjHi
         LZrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q8lE9LF6;
       spf=pass (google.com: domain of 3xqqwyqukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xQqWYQUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=luHaMljHImWeFwF3gZTmxn57EZZb9xybESKHyvT115I=;
        b=K7c2GGQaHfTR6/ZDsVMwNl7PZxkx7+rASQyaakjOvmDVbIjgT6H6z9oDZEHs+nJYzd
         8mnrcV63AxQcRvBoND9XZkdu49+0mnaalJTtAmNEnipEfBjETeVTHIQWnlQIO8MxOI/B
         tOTkiX9dvbITBySN2Ce0Dq2Zkf9YwNw6q0sq0itd0tJ+9xV8wXWut070MAvjNtyrL9to
         nvbANy6puz5vvlFq9tKxxpqOlf1rhtCaVbFEvlB8Tgte/jl3XsOyZ7SZrYiSHiXTlKJD
         6hvmuaRzn1DAkzw98ryq21nDgTKncyFRm2VgNdeNNKHMKhsq/N+7mgLyYc1SgO5kHaay
         IMQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=luHaMljHImWeFwF3gZTmxn57EZZb9xybESKHyvT115I=;
        b=aYA7y0BV6dR2UgZNCzV1kL8Le4PogeeIzEVrPYePJs5EAn5Ph8hagWTRw1f99pTcJ9
         dKkIElqQ3Fw6bQY9kaF1uyR9K/2X14Ew87/zJ7PzbhrtDOwVxuI3gKyzWw7N+S9+NVKA
         ts95clGTxaa07+ElKC5rwRQSVT9kIRRsrcsP5MMO+8RQ6yMeAXjDYbQNQXz36TBobN70
         2hqIjJd96gV1liOGaHj2fYENnBBvab/wdwjHpnwhtWl+JP2lySh0BM9P0CmA8JVVEKZV
         49JFxaLCzVIZSYZD/95t/urntSap4MjAos7Qm6WbL/DJuoEfN320XbKQ3lpzSLit5JWm
         LuFQ==
X-Gm-Message-State: AOAM532F0LgZ/p8IBxrDZKVKLt4EVhN1EkZzIu0iveoOfLRNW031aYqf
	dVWOT9mt7eeIUfVlWBJqIbM=
X-Google-Smtp-Source: ABdhPJyK1L9IuKLtMTCEtNi1uPV3qSoHMtRfowoFBNy3jztXVRgPvreD0go2PROU031RxDP1047E5g==
X-Received: by 2002:a5d:680b:: with SMTP id w11mr28802190wru.345.1637223110584;
        Thu, 18 Nov 2021 00:11:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls2321537wrp.1.gmail; Thu, 18 Nov
 2021 00:11:49 -0800 (PST)
X-Received: by 2002:adf:df89:: with SMTP id z9mr28291164wrl.336.1637223109620;
        Thu, 18 Nov 2021 00:11:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223109; cv=none;
        d=google.com; s=arc-20160816;
        b=f/s4S/hIiOZrWlNWSNnscmBhzClNkvOQXz7C0aND7dHVq1ilJGFGDJ5Q9RuZ66l91P
         RMvlUl+ftF5lPTDOMJkOVTWCXbXwaawJX2zGv3war8WM6jySCzzcu29M4+49VNYV1CKe
         Rm7nr4j+p5oS81OuAsQ3+ZT1NnOqP00ztDBhybH8MTukXE66hQ+WbqGJW3RG9fJfmqFE
         jEMPEVQ5JvVTE9zDjeclHkAgN1ORUYjjmRgeW5jWXg4S4cW1d+eM+Or1/VZ0J6uKV9LZ
         4vIn0X7TxGgq6euZEQkygSDtbAkOQI9fJT8a+aR2VQ7UxX9ai+mWuh5xhSZrEiBAaHpi
         YnaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SnYVQxLC6YSHg0QBspCa3KEICf+BvvptqJyS2cHTmDQ=;
        b=q31FKCDVChhNUaki24ioadtICoPblZy78fuA9XLWFNJn0V67tslpGEpoT3zgtNkKup
         2AGWpVpzFeI7WPEKWp+Ch8+a+Se8IDcuwsoYExRwhF8x+x93G6yPo9dHwwsH/X+7J7fT
         3OoW++AFk3de8lMs2h5pdURvSfi2oXES/0ALmUCt0AWBPxWNoLsuJhV52paPQdJF1Pxj
         6+e2+7oeNl5h6IXe4+7bhpIiYkjNjP/qsieTVdnxJgROXtas8tBtG3Ik7Kw96X/fDppn
         0A0SnWb1LUmO2zuh0CL/UPDD5fOjQMoPkOdCb17VZXdNkgaOtMoZgo7gadxSeufeO3eb
         lknQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q8lE9LF6;
       spf=pass (google.com: domain of 3xqqwyqukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xQqWYQUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id s138si585645wme.1.2021.11.18.00.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xqqwyqukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m18-20020a05600c3b1200b0033283ea5facso1986760wms.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:49 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:1987:: with SMTP id
 t7mr7663727wmq.24.1637223109239; Thu, 18 Nov 2021 00:11:49 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:25 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-22-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 21/23] sched, kcsan: Enable memory barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q8lE9LF6;       spf=pass
 (google.com: domain of 3xqqwyqukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xQqWYQUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

There's no fundamental reason to disable KCSAN for scheduler code,
except for excessive noise and performance concerns (instrumenting
scheduler code is usually a good way to stress test KCSAN itself).

However, several core sched functions imply memory barriers that are
invisible to KCSAN without instrumentation, but are required to avoid
false positives. Therefore, unconditionally enable instrumentation of
memory barriers in scheduler code. Also update the comment to reflect
this and be a bit more brief.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/sched/Makefile | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index c7421f2d05e1..c83b37af155b 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -11,11 +11,10 @@ ccflags-y += $(call cc-disable-warning, unused-but-set-variable)
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
-# There are numerous data races here, however, most of them are due to plain accesses.
-# This would make it even harder for syzbot to find reproducers, because these
-# bugs trigger without specific input. Disable by default, but should re-enable
-# eventually.
+# Disable KCSAN to avoid excessive noise and performance degradation. To avoid
+# false positives ensure barriers implied by sched functions are instrumented.
 KCSAN_SANITIZE := n
+KCSAN_INSTRUMENT_BARRIERS := y
 
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-22-elver%40google.com.
