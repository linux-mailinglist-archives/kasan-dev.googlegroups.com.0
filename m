Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEX27WAQMGQEH3QPP4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 16ADF32B7BE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 13:12:05 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id j8sf1698712wmq.6
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 04:12:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614773524; cv=pass;
        d=google.com; s=arc-20160816;
        b=qDhtwjOfykSPg+lJ3PS/OeJqpanP7vRQcdWRzeq1w5gjuv0WjyoDhry+XgmAKJYb5k
         gAb9Or5DBaUlqGXjnXSoltrIpH5dn9TadRYp4MUsbQlu71T7a4ItsoRvHYHM7xEoDr1x
         VlY1/FrxvUihGazxvPdow7FRogjYiyuKOOlJctQG+liomPCnVNDdfW0iUZuZucWOXIIj
         2TC4sD39rdhXCUuiBgdzLJalHJ81RhQj/hSWr/2QWE5xTbTIUGZluA0cwDET2e3BXy83
         6Z+XL5d+e46fDGQOb/pDdx91UHZSKx19Ppfg9UW+lJIpdd6GKVOR6zU8gZo+IW3HveYJ
         C8WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=rc7BjjMQCiicMBP6P24IhD9cWofNLGC1ujdlBQxMEmw=;
        b=hjHy2ZvniuStvdGVJXnMJyxcvmi4zPQtPBcRhCUo+VOlRvFNNpmEnxY4rZo9BCuoVh
         INZCvFaY0wxA8rcbMuYlORuPyGqZWF4DmJhX4zNf0FfutQ6Bla6RTXfozW236rS8lUT/
         QF0GnJM73E07qbbru81K3+4jZnaxaSNeM796RZd0NiMnqweewE7W/A/jduPkp8BNvqaB
         DWnAmol4pTqjdIXfPN15ruWy9nUWgN5lvuUhS3xMAOcM6Vr/9EpfC+WLixMhk98gy9Aq
         URvVihkh3K6P4aH/8oRbfeLnLsODfV2GfUCXQhSRAr1CJaD6hrP3dKfDMnTe4sZ+mfax
         Uaiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eOYSOVRO;
       spf=pass (google.com: domain of 3ex0_yaukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3EX0_YAUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rc7BjjMQCiicMBP6P24IhD9cWofNLGC1ujdlBQxMEmw=;
        b=Eco0LayVCMfzf2bI1V1AT1rOu12Ox9sa/EjE/a1jflYPIlZrJFMi6CDawa8PWU+WSW
         3sk9mc+pPty2gnGGm771lrJUWrppPpj6ig9vdaPiYS3ce8MTw4svZZg3r0Tm201O4A4n
         GBmXGpcR5O6ytvbv2eyEzwozPoi+k8Ze0lFdgAL/N7k9Czdi0i2h3RHEQXdrB7irK9K8
         vlkqprAXGzfUH/Ytm8yp5KpN5aA+3VhYtmdptm1Y/aTMwCGS3EspjRC5XCs96ySZKNlC
         FoRGvOe7nnsfOMbXOky/+IkuMfoewnI76+H6bkQvPm+Q7far46lBqXRO4Lar4gu3qMpv
         9mCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rc7BjjMQCiicMBP6P24IhD9cWofNLGC1ujdlBQxMEmw=;
        b=ijv64qxy6xi9B+5sQyo+WXS69xsbaermyo24ItZXo+1Tlbrz085wT8VkY+a9gSWTE5
         plD6pfhLI+PjtCRS3iFt5z2CG9gg65EvbWX/yUo11Fio9jb6XXnDqiy76CPJxqEdTPry
         WWIT/BpddNCp1Pa8VDXG4GiDimNnMHDLiCs42TKz3LyLJY3JC1NBNaG+und2jEw/nLOb
         vKrGw6y8fnNnUvOvgfHSzOFPv6E0e91k6hfxbsOM2fzLCsEvh7KegxkZrfNvUg6JxAyv
         3+25GjHH6xEF7/251KBErd8lWARWmSudGXDh+tsYQFNFml0QmMmtze3U97B/bXTziw6Y
         srow==
X-Gm-Message-State: AOAM532cIK63AtIThc/uFcNDUhF2Lc+DT4WZvLYEYwSJK7cGFyIA/zpw
	LZwlv2Gigr3V7MgiP190YfA=
X-Google-Smtp-Source: ABdhPJxFsfVdXN1+68QVY2uBz0KtcYuQyHAP1nucAX0rTvT9eHp024BFadGGS4QqKhys3cql+jWONw==
X-Received: by 2002:a5d:4445:: with SMTP id x5mr25692656wrr.30.1614773524814;
        Wed, 03 Mar 2021 04:12:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c2:: with SMTP id u2ls1111488wmm.3.canary-gmail;
 Wed, 03 Mar 2021 04:12:02 -0800 (PST)
X-Received: by 2002:a05:600c:19cf:: with SMTP id u15mr8834056wmq.139.1614773521945;
        Wed, 03 Mar 2021 04:12:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614773521; cv=none;
        d=google.com; s=arc-20160816;
        b=CSEmOURW/GJb1enO6TfGQDJswoTEOfdW1WPcOA2u9F/OIfnmBYwLWu8oyG2/t9JuI9
         WeeH094hMaWZ9XwaV2y/DKleFZ8CL42TmbaGLn+ChZueXW93P3eaUv1dVAXyE8kXmRji
         SuwNXoue46zNDwd7dpjnX8x+zwdwELwVZhnrnt2F4SAxuDoyqsxuBZb8En8dLu0mCZUq
         tFbsSx6Dt6aRO4EOnGuOjyBtCjKOJLtV5WcagVDewlcsW17S7Q2o74y2dqcEizoRtm88
         2lqOiJeyS9aSESGSQ20KwD4pHwNgD65wnJ27pUgHQhxuOby6yt5qTUolHmZoTPkaLsah
         S6lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=iJEzlqcbA6uhEUEuHAVXPzScMobXeq18I/DGTA3EYs8=;
        b=R4y9v3JnojU3zQN93+GmPUxfA3kAUR2IcaADsiRkX2QtoFyUR4cfwCjtCn3+yaArHv
         rLMjbIE/aVHcDzEFZ3ssUu77EXySMeUY6u4O3IiZaLwT331pMQZ++1uTwrP+Ij4yqBS3
         h5VwvsZ4Xfb28muY37Cs0YgMvimgI1ZUz51/k5Wi24FmxVNhnVoh+crEq9uPmhejOnoK
         tUcoJ3Wxb2l40y6GwITZ3Vshtd53R9cuLGGWirJGyGC6beFQJyH/66bAS+6Ar3RqjvqZ
         AjCaVNnBOjZ05+H9Jn64E5ucKjxLdOpV/RT3Z8Fru4691uyX6mhvls/7fakMJ9iCZ45B
         91pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eOYSOVRO;
       spf=pass (google.com: domain of 3ex0_yaukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3EX0_YAUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id g17si263962wmq.1.2021.03.03.04.12.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 04:12:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ex0_yaukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id q2so11956855edt.16
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 04:12:01 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:811:228c:e84:3381])
 (user=elver job=sendgmr) by 2002:aa7:cd8d:: with SMTP id x13mr24619685edv.286.1614773521450;
 Wed, 03 Mar 2021 04:12:01 -0800 (PST)
Date: Wed,  3 Mar 2021 13:11:57 +0100
Message-Id: <20210303121157.3430807-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH mm] kfence: fix printk format for ptrdiff_t
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Christophe Leroy <christophe.leroy@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eOYSOVRO;       spf=pass
 (google.com: domain of 3ex0_yaukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3EX0_YAUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Use %td for ptrdiff_t.

Link: https://lkml.kernel.org/r/3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu
Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/report.c | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index ab83d5a59bb1..519f037720f5 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -116,12 +116,12 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
 	lockdep_assert_held(&meta->lock);
 
 	if (meta->state == KFENCE_OBJECT_UNUSED) {
-		seq_con_printf(seq, "kfence-#%zd unused\n", meta - kfence_metadata);
+		seq_con_printf(seq, "kfence-#%td unused\n", meta - kfence_metadata);
 		return;
 	}
 
 	seq_con_printf(seq,
-		       "kfence-#%zd [0x%p-0x%p"
+		       "kfence-#%td [0x%p-0x%p"
 		       ", size=%d, cache=%s] allocated by task %d:\n",
 		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
 		       (cache && cache->name) ? cache->name : "<destroyed>", meta->alloc_track.pid);
@@ -204,7 +204,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 		pr_err("BUG: KFENCE: out-of-bounds %s in %pS\n\n", get_access_type(is_write),
 		       (void *)stack_entries[skipnr]);
-		pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%zd):\n",
+		pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%td):\n",
 		       get_access_type(is_write), (void *)address,
 		       left_of_object ? meta->addr - address : address - meta->addr,
 		       left_of_object ? "left" : "right", object_index);
@@ -213,14 +213,14 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	case KFENCE_ERROR_UAF:
 		pr_err("BUG: KFENCE: use-after-free %s in %pS\n\n", get_access_type(is_write),
 		       (void *)stack_entries[skipnr]);
-		pr_err("Use-after-free %s at 0x%p (in kfence-#%zd):\n",
+		pr_err("Use-after-free %s at 0x%p (in kfence-#%td):\n",
 		       get_access_type(is_write), (void *)address, object_index);
 		break;
 	case KFENCE_ERROR_CORRUPTION:
 		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
 		pr_err("Corrupted memory at 0x%p ", (void *)address);
 		print_diff_canary(address, 16, meta);
-		pr_cont(" (in kfence-#%zd):\n", object_index);
+		pr_cont(" (in kfence-#%td):\n", object_index);
 		break;
 	case KFENCE_ERROR_INVALID:
 		pr_err("BUG: KFENCE: invalid %s in %pS\n\n", get_access_type(is_write),
@@ -230,7 +230,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
 		pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[skipnr]);
-		pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)address,
+		pr_err("Invalid free of 0x%p (in kfence-#%td):\n", (void *)address,
 		       object_index);
 		break;
 	}
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210303121157.3430807-1-elver%40google.com.
