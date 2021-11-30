Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37SS6GQMGQEQL7IQWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 881234630C6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 11:14:08 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id t9-20020a056512068900b00417ba105469sf5346422lfe.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 02:14:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638267248; cv=pass;
        d=google.com; s=arc-20160816;
        b=PHQl9w+teu35qI3QKWgBCVNJK6oGHcobFTRYhIWq7lOCHMgJvvDerAWH/hi2T1FjG4
         JrjDXTAXiDjEVHU9p7kLGJVJZSoIDG5C9UIQZjsg4/tshri70+XFJmG/8anSsG9E+1TE
         ylVo/TevkW6oCWtNig7Pv/Fv1F7Duu554YIs9OVEaFJ4uOlVj7uPBA3MCz8/Z+YkDYRV
         uO+rfyiER2x6R+FQgI7jFVJOFf0pWEgjNWETVr9ZOxNxM177Yvd9/K07rLkjzHw2DsJ6
         rkNtYbOr1GnMAxXCRSruR7O2+iut4wlkhNo76xD2Kp8EyW+epmM1dyJ7hzJOqQ5T6y+Z
         Kbjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=r6ng7C/ZLPcDn/0/6YWUAtKOM2QwzN5z6ampmfHT+fc=;
        b=Vwio1Srk9QZw5GBBZUwu/6efzAmMaPvwSNVAR6obVu4A50k6v2qprIQ9GrXCGaAp7N
         +/ABcKD+w1SIKrWaeTNRiSpsyke0bM1poT8CkgU3QULs6cKYJ69KRqTQL0uh9nvJwsiF
         rq+aMRKl3KhBP2EVpyvRUb40RFqFB8Yx9P3ES1GFZb1KavjeQBQ1k/RSgjvBWLB+65Gp
         nTS4t7/WzO5TqJ7Rtc9PvKiuQpOVkjK5qHlW5GmtosVTIxjIvjrYov+iEOrd0aST5puo
         LXVIFwte05XeCSRsogEiDoTC2xlYpdK0QgHgUhyaukRuwYbQ/PD4KHbLCM0uagn5A+fv
         a9vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PGw1FmJ+;
       spf=pass (google.com: domain of 3bvmlyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3bvmlYQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=r6ng7C/ZLPcDn/0/6YWUAtKOM2QwzN5z6ampmfHT+fc=;
        b=DDtunHCm5Jt+P+fH2V4l8EP10cOpvCcC9Eshp/U/CSHbwDsyk9mVEsLEyCPz54sARV
         KdVsz/PTr8yBMUwCap3N/5BwuumjB2+WvnentkquSQaiIjlot8hzZaV6DRzk0wQnefdi
         DZ78pUcJStwj/JQGncJXjXXY6PnmW8aDlk0xXb0tP2Ho30PIPGFiM7S0EyLfauAaiXyy
         yz5UMW4UW7NSg1mbqXsLNfNzdVnIf9E5u08JyQRkvWno15j8aTHpEn2BIkcMsbpRtmR5
         sCuh6tYGTY6jWIuxWwPcMSE/RlXJoWYIn63OB5Rox2wuc3a3nxKzJn3lZ3TcGRmlJwLc
         H0kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r6ng7C/ZLPcDn/0/6YWUAtKOM2QwzN5z6ampmfHT+fc=;
        b=s7rokLXMMPYDKe7Er3hg11EKooJWdH4w5gWgbGYPDJaX+OKpE0RZwWFqH+JAX4VsbX
         bnFuHXr4uVk6twgfSIHg7/HayzuDrSaoFMiTX7NZz0DkWYd7heW0UgLS1Ni7HRTd94GY
         QkPB1rU5sovfQwuFo4+2MaYlDr45XEK6SeawTStOLXiJvHTqPzLFcAgQ6ecZOEumrXR3
         7A92vLbLtvk5qfD7wyjkpReU7U7kOFtWn9yrWSYl1y7NI52lr4fOncMUprbNWwn9h28M
         sbI092+fNfYWMt9wNXd7e95gI7TuL8tAxakeGQnr3TusjSGgvPKkj0G8wNl9vmk5EDUv
         oxng==
X-Gm-Message-State: AOAM533sdFOSnW7WNgMnvRumvPAMzWbOQb1ssZFT7qwjxm0e0PMOs5u9
	WlNhwJRocDOFVaWEV2kKsaE=
X-Google-Smtp-Source: ABdhPJynVTn3rl2Aow5Eq0N9HGoJn5gblghR2AjY+cpPJ5xZtMbbX03wqhK587L7Z2mZCHHoRW58YQ==
X-Received: by 2002:a19:f603:: with SMTP id x3mr53319020lfe.222.1638267248095;
        Tue, 30 Nov 2021 02:14:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls279023lfu.2.gmail; Tue, 30
 Nov 2021 02:14:07 -0800 (PST)
X-Received: by 2002:a05:6512:320b:: with SMTP id d11mr52517423lfe.221.1638267246980;
        Tue, 30 Nov 2021 02:14:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638267246; cv=none;
        d=google.com; s=arc-20160816;
        b=rIDF9YSXkTi3zxAoRMycBbhOGOEiqa8RbaTormDAW5gFbT6dwSUj4WSikcDSn9xRsC
         zBwjweQ1eUGjbaPto5y4A71Og/JrOmfs921yQTNByOhCni/k7ep0b7/tzmXsszYaSVpd
         5IAEtNpqIWPt/aOWAR+/44ewtXlqe/EK5mHK27hSjh2Iq2cVEbDPuXv5StRKX+AHrlwq
         hAGB5GNqFKeq7EfmVt9SxTpEaX2qFLnCKgjlD7rrtZqugBSajj/GFajv1H0JuD00L4wi
         dJo8wfjBoPMZR4oz1QWk5FQQ7hqAXw5bUBOCocfmn4MdM2xCeNfYg5/cLdkIH/5rZTNR
         h/2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=GIp7EQn2UnohoTj+yPMh1P0FmhJDYsjIC78ghQsH60U=;
        b=yTMEdMC9Iad3zqTbayhRbyBZURtSgaAgAZwC4ZRPYIjYYtPBB+AAgsvGV2RP/2IIZ7
         MKULaD/jQU0qwHySmze64FhULGJdQ1kbABVTrKTAo/XRvzODFZuyJRaB0450ctSYXAoG
         rqAnhn3+koUNRJOL9fzAFyvdvwmuN3SDrAuO0/Y3bc88qEl1rCS48PHEjTNVF3kWIFv0
         7RQxI9sQvUMEC7K/sF01/aDZvE2als0fWSmWygZmcHF4gB9JfJe4jOHwHmBV8JXGbWsY
         3G9H0jjJ9ONd1R9wyFc/K8T6n1e5h8Mv0cgFGezn9bLUFhuwLH6pVC5lBlBEtZKCWtdC
         0pfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PGw1FmJ+;
       spf=pass (google.com: domain of 3bvmlyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3bvmlYQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i16si1630417lfv.2.2021.11.30.02.14.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 02:14:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bvmlyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id bg20-20020a05600c3c9400b0033a9300b44bso12570110wmb.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 02:14:06 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:adf:dd0a:: with SMTP id a10mr39649481wrm.60.1638267246341;
 Tue, 30 Nov 2021 02:14:06 -0800 (PST)
Date: Tue, 30 Nov 2021 10:57:27 +0100
Message-Id: <20211130095727.2378739-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH] lib/stackdepot: always do filter_irq_stacks() in stack_depot_save()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Imran Khan <imran.f.khan@oracle.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Chris Wilson <chris@chris-wilson.co.uk>, Jani Nikula <jani.nikula@intel.com>, 
	Mika Kuoppala <mika.kuoppala@linux.intel.com>, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PGw1FmJ+;       spf=pass
 (google.com: domain of 3bvmlyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3bvmlYQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

The non-interrupt portion of interrupt stack traces before interrupt
entry is usually arbitrary. Therefore, saving stack traces of interrupts
(that include entries before interrupt entry) to stack depot leads to
unbounded stackdepot growth.

As such, use of filter_irq_stacks() is a requirement to ensure
stackdepot can efficiently deduplicate interrupt stacks.

Looking through all current users of stack_depot_save(), none (except
KASAN) pass the stack trace through filter_irq_stacks() before passing
it on to stack_depot_save().

Rather than adding filter_irq_stacks() to all current users of
stack_depot_save(), it became clear that stack_depot_save() should
simply do filter_irq_stacks().

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/stackdepot.c  | 13 +++++++++++++
 mm/kasan/common.c |  1 -
 2 files changed, 13 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index b437ae79aca1..519c7898c7f2 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -305,6 +305,9 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
  * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
  * any allocations and will fail if no space is left to store the stack trace.
  *
+ * If the stack trace in @entries is from an interrupt, only the portion up to
+ * interrupt entry is saved.
+ *
  * Context: Any context, but setting @can_alloc to %false is required if
  *          alloc_pages() cannot be used from the current context. Currently
  *          this is the case from contexts where neither %GFP_ATOMIC nor
@@ -323,6 +326,16 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	unsigned long flags;
 	u32 hash;
 
+	/*
+	 * If this stack trace is from an interrupt, including anything before
+	 * interrupt entry usually leads to unbounded stackdepot growth.
+	 *
+	 * Because use of filter_irq_stacks() is a requirement to ensure
+	 * stackdepot can efficiently deduplicate interrupt stacks, always
+	 * filter_irq_stacks() to simplify all callers' use of stackdepot.
+	 */
+	nr_entries = filter_irq_stacks(entries, nr_entries);
+
 	if (unlikely(nr_entries == 0) || stack_depot_disable)
 		goto fast_exit;
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8428da2aaf17..efaa836e5132 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -36,7 +36,6 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
-	nr_entries = filter_irq_stacks(entries, nr_entries);
 	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
 }
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130095727.2378739-1-elver%40google.com.
