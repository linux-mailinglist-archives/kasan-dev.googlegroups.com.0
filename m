Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYP6RSMQMGQE7ZWCHDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D2D95B9E2B
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:09 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id qf40-20020a1709077f2800b0077b43f8b94csf6164414ejc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254369; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y4v+r/GU8OJTLiA6M1z1eo1W2aaDrXbLyzJmtEFASt6xDZsn0t/0SAf/eK0L5OkGzM
         gI7yRS6yYUS7Xgp5Zl0nOYVMbjtphldyOuj4OJXfaO0eF+xVuzhhE5hPZG5mLgyCOV/Q
         KTeoStan+qaQJ9vucZNu8CeWESPkIn5DC3sTcSnz79owCEvfEwyI/ea2pzFLR4sBXI3j
         6mTTyXTjgw0cAQxG/8+fJK8QspWXbg31hVnIaQt3mKWKYPkXs0UUCxzcom00Fdxtlrqj
         IITgXXRFE49U7kKraW166k1n+6w9rITMOz7cJppQ09lm/UW690m10DHaFqgm8lGD6jIf
         GCbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TnHOc7DOx3bVnMHB6O2awMiwBsj7Gk+RPPO/dKSboPI=;
        b=xGib0sAp1vCsI0dlSviU8j/ADQVmAGyYW6/TuT7DsYUOw9ycLT9MDkQGMJZDspiXJ+
         vPWH29Zv8dT09x7uoGyXrTtYYwQuCOYuvrpK9O6vlB0Tb4AdNrXXAZEH+Y6gIe1ggj4b
         4qjYkz/FwZtrKC+/G+PT0jsbkTnaiKXWxAyBJHXFbh9M0do6DhKBPGtbYWOsJJ3Pf7Hp
         774LAn6hUjwRN+inURrVO+yYrgmj+FNx4vJ9Uk54b7lfq7iDGJj2DwlXeFYdUUVNRDZ8
         +2C7jvNGIxZ/J3BFakaz0shFk+wWnImTTk2bQ+QmF6ZYlKnuODTY8Wh3VTbbKID8yN2X
         DL+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qfYRjxVX;
       spf=pass (google.com: domain of 3yd8jywykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3YD8jYwYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=TnHOc7DOx3bVnMHB6O2awMiwBsj7Gk+RPPO/dKSboPI=;
        b=g9Wjv6YnF75f2FV7PFlgVtyb/gaXAVrtx1gzZ4DPjKifR+RrlEWXGVMZxNi7UE4Och
         kfDRQOgadtji46My90Kb9BeD506kqX3mwE7FHu1bsa0avD9/UsGH2CFGSDQ+jUtkuNUf
         MTs1IAi12tzb5q2nw1e/fCrH76EZ9wIFL5jrMSWv6bUK5CdtIWIWBxQIoYl6GVNZmazX
         y/xQFrAflxFx76uQC/Zv53/oGn7DjCofHZl21zZv22wld0qoKlO6XHEl29XQxspbrPL4
         +YGR9NsODLt00EacuYqnVsUuNBFz/DIBIzpC/c1OJqRkWCqKKppW+zxMVNHdhyk9P7/l
         Ch6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=TnHOc7DOx3bVnMHB6O2awMiwBsj7Gk+RPPO/dKSboPI=;
        b=B2p0fzTyOeE4w/ehrnrzXMM81cNWg0m3Fazv/jqY1XEvprdvLXHH9rHRRWBSAYotfg
         AFAfLWrdisBfsWb86XKkiYTFvJS4dciWc3XmpapfUyztt0pD54Pryo5+N0V9ph186pVd
         YB7p/d9jwjiUD/BvakKlCJz7mkAuhSTwjDlyJoDEcoozC8qxDzvtTyrXBVs7EqLS9uS0
         LRXhm8DM4Z2oPorVvUTC9PpKew6jPJkdKdLZX3v5zDzE04oYFXpxIeqsPVCEQAWYUalS
         2jJ0drA1EBlI1/kIPL7Wmvv5NZc//Hfgb6txCMeNCkxKP+osuARE+FjT7GVu4cDz4Q+z
         vPbQ==
X-Gm-Message-State: ACrzQf2v/wlEp9JwnXfzEjBTG/lFxpg07Wy7Saq44Ie8m7jdggLYC5Lp
	9bXErv5JwWHXNi24LNlG7CI=
X-Google-Smtp-Source: AMsMyM75CiqdO/rmJni7PBGP0m0H7rT4uQqJTC7wEjcHwQj39vjYSnC9BV2TmgUawVbp8DOrNc+fRg==
X-Received: by 2002:a50:a69d:0:b0:44e:bf40:395f with SMTP id e29-20020a50a69d000000b0044ebf40395fmr281497edc.234.1663254369362;
        Thu, 15 Sep 2022 08:06:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:278e:b0:44e:93b9:21c8 with SMTP id
 b14-20020a056402278e00b0044e93b921c8ls2972958ede.1.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:08 -0700 (PDT)
X-Received: by 2002:a05:6402:268d:b0:451:d6e9:5572 with SMTP id w13-20020a056402268d00b00451d6e95572mr265062edd.390.1663254368414;
        Thu, 15 Sep 2022 08:06:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254368; cv=none;
        d=google.com; s=arc-20160816;
        b=ITKcgF9zMp5PDrOKZWI59caasEhIIfIxvo5zaFHPij6W6sdytzBc1iRbvDpR4hjQz0
         00WvjDMlw9fk2CWVLs698aSS2PFB25isaMW64ECOLslg9ZeJf5Y9IuKpQynl90L3XNvT
         q7/oMJKzMXCWQqEKv67l7gt9udb4EKIOC8xGp7OC/sqPtlBRZ+5qyEXEL39sIAX7bO3r
         c5kHt7Z2QD0UdqLZyEuFaLdMjyYGLTVoWynjaVS7IcKo+qMGCQyh0M8g9XAj6m8ZsEp9
         sF9mKfDOIiu1CvnjeOOJclivJdOu4hpuFbysJYGtGky8M0Nd4iuZ8EEV50bdSS+jA08a
         UMlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VswCSWA+rV4PC5eDv8SsttMbBbTb1fmAEKvfw1RwEtM=;
        b=ic1Jp1iCeQi7KdhLtcuZvv9R8bghNFc3QfR/cS+8DKY2/jlWBq/X8xpdsOk6UMXL3J
         3sSDLloAMpXpIgQ4vdX4cxzdTONpGFgAhVAJCXMD8DsMGv3ntzvrbnVncEA34c1tnXbV
         WnR/V0O6Y8KUa5W/yapS8kXWHYrnBe9tDOzGT+fgLx5fpNY7HEG5dOXi+fZkR2V9F12m
         YGulCO3YeRHbt7jS1Tiaa7ZyTc1g/5w81SDlzGEazOHF/VayWdlBSe5w2DvW6BQwG90H
         IV5Akd2lopdVgffgKjzDyPKUz/dA0jbEEEJhsqOnF9DG1o+3jA6mTf6qUyaT2PNxd3FN
         B20w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qfYRjxVX;
       spf=pass (google.com: domain of 3yd8jywykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3YD8jYwYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c12-20020a056402158c00b0044608a57fbesi551893edv.4.2022.09.15.08.06.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yd8jywykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r11-20020a05640251cb00b004516feb8c09so10386662edd.10
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:08 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:1655:b0:44e:b208:746d with SMTP id
 s21-20020a056402165500b0044eb208746dmr253604edx.229.1663254368151; Thu, 15
 Sep 2022 08:06:08 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:07 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-34-glider@google.com>
Subject: [PATCH v7 33/43] x86: kmsan: skip shadow checks in __switch_to()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qfYRjxVX;       spf=pass
 (google.com: domain of 3yd8jywykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3YD8jYwYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

When instrumenting functions, KMSAN obtains the per-task state (mostly
pointers to metadata for function arguments and return values) once per
function at its beginning, using the `current` pointer.

Every time the instrumented function calls another function, this state
(`struct kmsan_context_state`) is updated with shadow/origin data of the
passed and returned values.

When `current` changes in the low-level arch code, instrumented code can
not notice that, and will still refer to the old state, possibly corrupting
it or using stale data. This may result in false positive reports.

To deal with that, we need to apply __no_kmsan_checks to the functions
performing context switching - this will result in skipping all KMSAN
shadow checks and marking newly created values as initialized,
preventing all false positive reports in those functions. False negatives
are still possible, but we expect them to be rare and impersistent.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 -- This patch was previously called "kmsan: skip shadow checks in files
    doing context switches". Per Mark Rutland's suggestion, we now only
    skip checks in low-level arch-specific code, as context switches in
    common code should be invisible to KMSAN. We also apply the checks
    to precisely the functions performing the context switch instead of
    the whole file.

v5:
 -- Replace KMSAN_ENABLE_CHECKS_process_64.o with __no_kmsan_checks

Link: https://linux-review.googlesource.com/id/I45e3ed9c5f66ee79b0409d1673d66ae419029bcb
---
 arch/x86/kernel/process_64.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index 1962008fe7437..6b3418bff3261 100644
--- a/arch/x86/kernel/process_64.c
+++ b/arch/x86/kernel/process_64.c
@@ -553,6 +553,7 @@ void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp, bool x32)
  * Kprobes not supported here. Set the probe on schedule instead.
  * Function graph tracer not supported too.
  */
+__no_kmsan_checks
 __visible __notrace_funcgraph struct task_struct *
 __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
 {
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-34-glider%40google.com.
