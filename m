Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC7JXCGQMGQE6QUV4QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 19FF346A09A
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 17:04:28 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id o18-20020a05600c511200b00332fa17a02esf70755wms.5
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 08:04:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638806667; cv=pass;
        d=google.com; s=arc-20160816;
        b=AcOXRg7h3vbWGfhwrg5rItJ08IRYPncF7a69bYmIGXpa0a777F+M87E8rNWQHcfWsO
         VIDuU+0zP1frehkmVEyfKq7REJJysgBZ0DfofnM7bWaXqk0ilv6V0/ODBT/J2BxxStF2
         iHx12RLxaW6nvYlIq4BBkobbojFmUR1ydCuCR/WLMujSGqhFIVSPQxLFMwYTYO45R8zu
         lMkAtW+n0KO5Q8mUPYRA2T/9d24vfBS558pxizNXpeZotoAAgIYfj3uz717U6W9xrDHl
         31xS3NptvgE/Bq7umpkMkaCj8EiO50EQ2gZXT/Vx4wTZfskiX6j7qDMogjkIqFZuq2yr
         H7mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cekP+V65iT+LPMIbE2JIYEHogD8+QjSsCAX+Zziwk6w=;
        b=CipasIGDjZcKJt7OIOkGdxex38LoqaDgGws+t2l9e7vm5xmvGCQtd69Bb+WOsboLkY
         LiORqTUY5FFkU+Jiyfk948pB3jTw9iaxpVx3+G6vX2ge9llUDOrI6HRAzC+uP6fyurbk
         eBltL2ncmMAZhebnDGRefEOjNXQAy+/BQZP6ctQEVN7y/EIwiza8yzKpvUmgSEcQYxhL
         x5IbHqLPJRulP19rGOqvtqqYynlAmHfgsOUPQeyxM3Mojq83tTD45Aa7N3QLgmytber/
         jmTIwiFg0GaViF9kXutDjpz+Bmbfp03oKiXl7YKEF1fBwV4WfwLMAz9xSNuQbm1eEe1Q
         AeQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CXhtCLa0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cekP+V65iT+LPMIbE2JIYEHogD8+QjSsCAX+Zziwk6w=;
        b=WCgjOLlAP0SY6q9mBHhXv5z0KhnKKRDiRi0pbsDziTVjEQXdewZVxZ0ClHU1/Err4z
         3hWWDwssSdVjh/egrXO8A2U5lQTRYN+6Be+Hfl254Gq9YS9xptU8gBX2kvS6LPwl+YK0
         ThXLgZP5Z08gzBz1PTxgwfyQPfk5vYwNyibpt2Avi6uQin6ddTH2yeOvF1g0N9y0ww/q
         zkrilAP6nDjfnlXyyHCQqpjy6p6/SbZb8ez2Pt5OhA0Vq2MKm0Xn7o4tUwHtMBPnzoZP
         ordUvceYavYNiS/PaWO5x+a3VFZr2KBD9stgi/UyfpeqAThnJEH7mt7D/AFvqTjuRXbk
         woGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cekP+V65iT+LPMIbE2JIYEHogD8+QjSsCAX+Zziwk6w=;
        b=hs8vo3Mhp15b5OrJ3gptdeL4vaqk8nU+YOVlgMW4JIccUesz2RWnDQ0YJ8o2D32m9A
         FLTGLP+ki4F//w9an3kh2Kj3eCdh3m4yVarJOn4F688Uw/39Pds+del5BR3f7KNfDKaZ
         nzsF1nH8BB42oQc6FC4gkPqoBJvZxja2uwGZj/s3wJfnNKJc6MOtFTbt4/VGdcxJVSzB
         jLdENSzrpn6CKF2EKbh8+60R4KML/fO3dZV1wbsujZlB3/tYi/hgJojoGhMEQfsZplXv
         Fm8kJ1vlMHMyiK8qg5uaAbRVnzAzE+iKZtRaP2iC8oe5K97eWX0sRqRM25+23tJx4FA/
         XRAQ==
X-Gm-Message-State: AOAM533dtHLPcXRSauUBseUQHNFEFXH5JwUCxwFQtqBRK/wPy8fl2P3H
	BLDLFEC1eeY/6E7TD6HxHnE=
X-Google-Smtp-Source: ABdhPJx5B8CdJ0S6d22S4y3RF0xYnFAoCTZTDImUnkPgfFMM6AuiqgLTxUgqtsANG5zaNBjiQQqFaA==
X-Received: by 2002:a5d:6a89:: with SMTP id s9mr45036558wru.123.1638806667890;
        Mon, 06 Dec 2021 08:04:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls10396750wmc.2.canary-gmail;
 Mon, 06 Dec 2021 08:04:26 -0800 (PST)
X-Received: by 2002:a05:600c:a42:: with SMTP id c2mr40273997wmq.154.1638806666901;
        Mon, 06 Dec 2021 08:04:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638806666; cv=none;
        d=google.com; s=arc-20160816;
        b=wpjvvLToQ4YIJD+shgTQ7rzL7ZsV7ptv0u9nNMDyVoV9fwzXF9gM+kXsWTboqEMot4
         65aqEmgySj5apIGeHZ8uUimEtls071EGditK1Q7XbOKo9IM/irF2kCHMpq4dQ+j6KtZB
         RSl11R7n+3O9bJZgFRCX9sebJqJHliL63ssvSBskqXsVQar20xqhitFyJIH1oAd3UxGu
         NzheqkW+Y8QhQJ5TANDzTWrsouq9sAQyS81uK4XGF89fK3eVP/KTLQ7JXLaPoSzQLDpQ
         DcePyjxI4KWwlKTIOI+nMBUKmFnKymTPin1g+xoLo0XeObsRMwuXYi+OFyV1/ooU2cMx
         /Edg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=nMw+1lOhPz92ldC1eztxTws1Eot0vmOAhw9KFEmlatA=;
        b=F3k/o1BZ7N5se8Q/xmGtA6BVtpjYhjfg999CQd9sulSMw1kOfOZNvNFXAwwWGbO2vW
         QtdtlFiWulfx4qmXEKUexZvWNysdCPOJ/SX+NelytwpLQUr5yTBiybx8NLSq4rYo3gUY
         oRgvGU65JUBoiCojGdTigMwpBG5gMoR6wOS13yOrqFSt5C/b2b5tF2sDWrZ7BBHNX38E
         6dXEnbKpeR3AgTiD2+mUtz2lh+cvnSiCUE7Nkiy6+6OsV+Cs7bE+bF6maK+uZeE6iLYO
         UvWyWQEBVwP7ZyrufgiRn1eRIvYuVgM1010ohGhtkd3Icc+jsymzRm7V2y6G+/LY419C
         Xhkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CXhtCLa0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id c10si15128wmq.4.2021.12.06.08.04.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 08:04:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id u17so16128178wrt.3
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 08:04:26 -0800 (PST)
X-Received: by 2002:adf:d1c2:: with SMTP id b2mr44013090wrd.114.1638806666388;
        Mon, 06 Dec 2021 08:04:26 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:88f3:db53:e34:7bb0])
        by smtp.gmail.com with ESMTPSA id o3sm14929749wms.10.2021.12.06.08.04.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 08:04:25 -0800 (PST)
Date: Mon, 6 Dec 2021 17:04:20 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 08/25] kcsan: Show location access was reordered to
Message-ID: <Ya40hEQv5SEu7ZeL@elver.google.com>
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-9-elver@google.com>
 <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
 <CANpmjNMirKGSBW2m+bWRM9_FnjK3_HjnJC=dhyMktx50mwh1GQ@mail.gmail.com>
 <Ya4evHE7uQ9eXpax@boqun-archlinux>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ya4evHE7uQ9eXpax@boqun-archlinux>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CXhtCLa0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Dec 06, 2021 at 10:31PM +0800, Boqun Feng wrote:
[...]
> Thanks for the explanation, I was missing the swap here. However...
> 
> > So in your above example you need to swap "reordered to" and the top
> > frame of the stack trace.
> > 

Apologies, I wasn't entirely precise ... what you say below is correct.

> IIUC, the report for my above example will be:
> 
>          | write (reordered) to 0xaaaa of ...:
>          | foo+0x... // address of the write to A
>          | ...
>          |  |
>          |  +-> reordered to: foo+0x... // address of the callsite to bar() in foo()
> 
> , right? Because in replace_stack_entry(), it's not the top frame where
> the race occurred that gets swapped, it's the frame which belongs to the
> same function as the original access that gets swapped. In other words,
> when KCSAN finds the problem, top entries of the calling stack are:
> 
> 	[0] bar+0x.. // address of the write to B
> 	[1] foo+0x.. // address of the callsite to bar() in foo()
> 
> after replace_stack_entry(), they changes to:
> 
> 	[0] bar+0x.. // address of the write to B
> skip  ->[1] foo+0x.. // address of the write to A
> 
> , as a result the report won't mention bar() at all.

Correct.

> And I think a better report will be:
> 
>          | write (reordered) to 0xaaaa of ...:
>          | foo+0x... // address of the write to A
>          | ...
>          |  |
>          |  +-> reordered to: bar+0x... // address of the write to B in bar()
> 
> because it tells users the exact place the accesses get reordered. That
> means maybe we want something as below? Not completely tested, but I
> play with scope checking a bit, seems it gives what I want. Thoughts?

This is problematic because it makes it much harder to actually figure
out what's going on, given "reordered to" isn't a full stack trace. So
if you're deep in some call hierarchy, seeing a random "reordered to"
line is quite useless. What I want to see, at the very least, is the ip
to the same function where the original access happened.

We could of course try and generate a full stack trace at "reordered
to", but this would entail

	a) allocating 2x unsigned long[64] on the stack (or moving to
	   static storage),
	b) further increasing the report length,
	c) an even larger number of possibly distinct reports for the
	   same issue; this makes deduplication even harder.

The reason I couldn't justify all that is that when I looked through
several dozen "reordered to" reports, I never found anything other than
the ip in the function frame of the original access useful. That, and in
most cases the "reordered to" location was in the same function or in an
inlined function.

The below patch would do what you'd want I think.

My opinion is to err on the side of simplicity until there is evidence
we need it. Of course, if you have a compelling reason that we need it
from the beginning, happy to send it as a separate patch on top.

What do you think?

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Mon, 6 Dec 2021 16:35:02 +0100
Subject: [PATCH] kcsan: Show full stack trace of reordered-to accesses

Change reports involving reordered accesses to show the full stack trace
of "reordered to" accesses. For example:

 | ==================================================================
 | BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
 |
 | read-write to 0xffffffffc02d01e8 of 8 bytes by task 2481 on cpu 2:
 |  test_kernel_wrong_memorder+0x57/0x90
 |  access_thread+0xb7/0x100
 |  kthread+0x2ed/0x320
 |  ret_from_fork+0x22/0x30
 |
 | read-write (reordered) to 0xffffffffc02d01e8 of 8 bytes by task 2480 on cpu 0:
 |  test_kernel_wrong_memorder+0x57/0x90
 |  access_thread+0xb7/0x100
 |  kthread+0x2ed/0x320
 |  ret_from_fork+0x22/0x30
 |   |
 |   +-> reordered to: test_delay+0x31/0x110
 |                     test_kernel_wrong_memorder+0x80/0x90
 |
 | Reported by Kernel Concurrency Sanitizer on:
 | CPU: 0 PID: 2480 Comm: access_thread Not tainted 5.16.0-rc1+ #2
 | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
 | ==================================================================

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 33 +++++++++++++++++++++++----------
 1 file changed, 23 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 67794404042a..a8317d5f5123 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -317,22 +317,29 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
 {
 	unsigned long symbolsize, offset;
 	unsigned long target_func;
-	int skip;
+	int skip, i;
 
 	if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
 		target_func = ip - offset;
 	else
 		goto fallback;
 
-	for (skip = 0; skip < num_entries; ++skip) {
+	skip = get_stack_skipnr(stack_entries, num_entries);
+	for (i = 0; skip < num_entries; ++skip, ++i) {
 		unsigned long func = stack_entries[skip];
 
 		if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
 			goto fallback;
 		func -= offset;
 
+		replaced[i] = stack_entries[skip];
 		if (func == target_func) {
-			*replaced = stack_entries[skip];
+			/*
+			 * There must be at least 1 entry left in the original
+			 * @stack_entries, so we know that we will never occupy
+			 * more than @num_entries - 1 of @replaced.
+			 */
+			replaced[i + 1] = 0;
 			stack_entries[skip] = ip;
 			return skip;
 		}
@@ -341,6 +348,7 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
 fallback:
 	/* Should not happen; the resulting stack trace is likely misleading. */
 	WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
+	replaced[0] = 0;
 	return get_stack_skipnr(stack_entries, num_entries);
 }
 
@@ -365,11 +373,16 @@ static int sym_strcmp(void *addr1, void *addr2)
 }
 
 static void
-print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
+print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long *reordered_to)
 {
 	stack_trace_print(stack_entries, num_entries, 0);
-	if (reordered_to)
-		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
+	if (reordered_to[0]) {
+		int i;
+
+		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to[0]);
+		for (i = 1; i < NUM_STACK_ENTRIES && reordered_to[i]; ++i)
+			pr_err("                    %pS\n", (void *)reordered_to[i]);
+	}
 }
 
 static void print_verbose_info(struct task_struct *task)
@@ -390,12 +403,12 @@ static void print_report(enum kcsan_value_change value_change,
 			 struct other_info *other_info,
 			 u64 old, u64 new, u64 mask)
 {
-	unsigned long reordered_to = 0;
+	unsigned long reordered_to[NUM_STACK_ENTRIES] = { 0 };
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
-	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, &reordered_to);
+	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, reordered_to);
 	unsigned long this_frame = stack_entries[skipnr];
-	unsigned long other_reordered_to = 0;
+	unsigned long other_reordered_to[NUM_STACK_ENTRIES] = { 0 };
 	unsigned long other_frame = 0;
 	int other_skipnr = 0; /* silence uninit warnings */
 
@@ -408,7 +421,7 @@ static void print_report(enum kcsan_value_change value_change,
 	if (other_info) {
 		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
 						      other_info->num_stack_entries,
-						      other_info->ai.ip, &other_reordered_to);
+						      other_info->ai.ip, other_reordered_to);
 		other_frame = other_info->stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
-- 
2.34.1.400.ga245620fadb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ya40hEQv5SEu7ZeL%40elver.google.com.
