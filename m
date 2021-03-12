Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLXTVWBAMGQEBGW6NEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 44D7D338FE1
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:47 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 6sf9825354ljr.11
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559086; cv=pass;
        d=google.com; s=arc-20160816;
        b=amR3u6Mm30zVgkQr1cQ+c5slGg8MNt9hBY0CDk/kGakOxhIZ7RDALH/LoG5R/QttJ9
         qCCXuyX7SySrxrSSqEo/dBYpMRdiNw3qUql0TJJ6hScSStjn26XzgyowMNaXkJ10UvGV
         ihNXpZt8ZTQfNkC+5SP60fvgEUjtu/QgkxMoYPG/zfQLdLRaiePnYyL0ycdwRbHvY/1M
         1r4ZPOtJXhwAgy78gPqljubW3khLuoHIpeDswDAzgWAXbrJNAghspVXKS2H42bWc9ovD
         R2gbD+YL+LIuuMxqC68p497Cc3cPJEVTPoEz4+KZOUMpWLaH91fGrO5oN3A4YQnBUi4S
         Fm3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=18JgjZTkG5zrugMgiY3t92tK4RJfEFQiK4F6QgRzc/w=;
        b=0vJRoyxpUn/serLLVgdhqxF0ATWNtpGiGrRa7k+MA6Oh4r3Z3jwisRYy2VFEOLQiot
         ypBdICX33S0uSkst/RoPlYHeyaHyeuChAW1dm0VdaKsBJYCV/FXQtGFzgmNrYeh08kwa
         s99uAkwh9UBS9xPlmnCnBaKaCPlPk6X9XS3BWv1ZJvDjyuXgMN02TmPDRfmtIvmd5E2J
         BWnvprOwTAd8kRckeXf9ICVdLpLaTn0p48DwNZtj3QMAuG49pHDq5l8BDMbG7eze5pf9
         F5428YTK+YQsFacUbJ4OU6NhkTpJXRkuOdD/MWWLIkyPXZQIIm18sOj+xgyGwdYgo1ri
         HHyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sNp2DgDm;
       spf=pass (google.com: domain of 3rxllyaokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3rXlLYAoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=18JgjZTkG5zrugMgiY3t92tK4RJfEFQiK4F6QgRzc/w=;
        b=kwjhYef8PP5v7qvTO3034u4gpKv0+CL2y6zQ8rkWzEWU28GXX9PZxLLON3JV55VM+h
         EhJiZH3G365nCDLFCw9VgnKkVF7EgmLJK0nrdDcknPOn/6iQbsnn2nTHLrfz94yFIAEK
         n8UaHpoZjrH2IrVro6m9mATz6gj2aKa0CJj05iSAGOGER/GW22nA9jA/1nmMTeFdEyjc
         3Qwg14y09izJbRqSgm3KfaHiT7FQe0HYgZlkiuv7c1zMDuFFliUXtTjUTcnERNsj4CiM
         a8Re0CcZjvt4b0sl2foWoM7AgcdHqp2bRe15BA5RnWddbwJr+RV5NrJfgZQyzEqXsIyw
         YbXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=18JgjZTkG5zrugMgiY3t92tK4RJfEFQiK4F6QgRzc/w=;
        b=hMmFbHuZuQfix44G7h8GYvGQ+wdFI5D6IRtoyaRXX2jtxa+XShFrEjnjQAqCGq/GZJ
         trB5aLa2BLaFH3ImfJC9LR9qrPuCOfXoEBtWbl3E6J56dI+SBnPKtr1fZOlX95tVhpL/
         mvGEH/pBcwN3uo/QZnZgHMQmajJp77hIDU2QOuizVhzUyVnl4u8FmabslDvQ1/pT1otq
         WwwJZbsszbjXrDeKt+nVuRHnNUQX1zRBHLXtAHZUdd/ehbbxMFBJ2LJowniQK0SJrpWQ
         2XKRXnRf9ThCDxUOfDuGstqYdmtL4a8cWTHPz62SVR3tEMuewnfVBpDiIkAH06vp0lKz
         GkjQ==
X-Gm-Message-State: AOAM531x6NwhIM7tnNoOgI5v+In/LHuP1ZwFpMr0JnLMVXB5NeH7XAvY
	Uw82p4jRhAK17iytl49xBX8=
X-Google-Smtp-Source: ABdhPJwHDsh6zo9rIbwvuZjUDFn9COo7xAD3CYgrOMRMNjmKzw//PjoL2D1COWjdRi2/3VG8nBwfEQ==
X-Received: by 2002:a19:74c:: with SMTP id 73mr5491326lfh.316.1615559086848;
        Fri, 12 Mar 2021 06:24:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls3508001lfo.0.gmail; Fri, 12 Mar
 2021 06:24:45 -0800 (PST)
X-Received: by 2002:ac2:5f0c:: with SMTP id 12mr5349220lfq.116.1615559085857;
        Fri, 12 Mar 2021 06:24:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559085; cv=none;
        d=google.com; s=arc-20160816;
        b=plmA987fuUP5yjQRkOHN3598eT6eviVTHlmCSCSywk9V8wRUAIQCtNM5eZqzEH5enk
         DNhFFqNQCJQhC6lOBKlL0MmzBt9FPb5aEz3jgWvNW5a46irVLVPzrUE1wd6qh46SfXJV
         3NWJjCeubSqL/Ys5IWh/2R8Yvb7gAMP1B0HqJzQ25x+a0t4dhK/qUHTbKpfPzfiYeFzg
         u1SCMTZmf6T1ijSzMoZWyi82sEIJIxmtsZX/7E3cCRnv9KbEzAWjvY/tWNPUgIvlnFqL
         YgvQlYi7AAjsFEukrBPjGLWdRgapxa+kFZT7bcYwEFkBeCbAJQ7mL6owDIu6VS5/paGU
         GDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0tHYzYXuuuKT6r1BbOh9jnZkvIRx4Zusj9wo+yaKFLc=;
        b=X5CoBLGa8zRk+tD6pHeT4bSuM9b1fColPDaN0nypwKZGEt7eQQhEPxhPs8VSJV8/z5
         YTDEXdkuTdj+dlehgOQ5hEvnI8GE5F+WE4gYhMcs3f9ln99sTkndmBESNOqq4RbB60Ub
         vhWPJ2Cnpq51x5B0gmQfZsc9yQn8RCw2BtRuMOWK0QB0Ju0MTrNaQWlpAaHGvGkhKj4Z
         ZKYyLhwGPNSWRjhbH/+xnqhWphRf135/QuDbgHuKWjknWRh+bUxWckOSp6oHE81ArCu6
         u/wxv4P5EIy292zsBRrJbDy6l3j5YYovY3+fEd/89quiBAJ1SD0CS9XkrIlvnUCtXY3W
         hsEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sNp2DgDm;
       spf=pass (google.com: domain of 3rxllyaokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3rXlLYAoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i30si243416lfj.6.2021.03.12.06.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rxllyaokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s192so5408677wme.6
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:45 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4145:: with SMTP id
 o66mr8525472wma.68.1615559085218; Fri, 12 Mar 2021 06:24:45 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:27 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <3531e8fe6972cf39d1954e3643237b19eb21227e.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 04/11] kasan: docs: update error reports section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sNp2DgDm;       spf=pass
 (google.com: domain of 3rxllyaokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3rXlLYAoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Error reports" section in KASAN documentation:

- Mention that bug titles are best-effort.
- Move and reword the part about auxiliary stacks from
  "Implementation details".
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 46 +++++++++++++++++--------------
 1 file changed, 26 insertions(+), 20 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 46f4e9680805..cd12c890b888 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -60,7 +60,7 @@ physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
 Error reports
 ~~~~~~~~~~~~~
 
-A typical out-of-bounds access generic KASAN report looks like this::
+A typical KASAN report looks like this::
 
     ==================================================================
     BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_kasan]
@@ -133,33 +133,43 @@ A typical out-of-bounds access generic KASAN report looks like this::
      ffff8801f44ec400: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
     ==================================================================
 
-The header of the report provides a short summary of what kind of bug happened
-and what kind of access caused it. It's followed by a stack trace of the bad
-access, a stack trace of where the accessed memory was allocated (in case bad
-access happens on a slab object), and a stack trace of where the object was
-freed (in case of a use-after-free bug report). Next comes a description of
-the accessed slab object and information about the accessed memory page.
+The report header summarizes what kind of bug happened and what kind of access
+caused it. It is followed by a stack trace of the bad access, a stack trace of
+where the accessed memory was allocated (in case a slab object was accessed),
+and a stack trace of where the object was freed (in case of a use-after-free
+bug report). Next comes a description of the accessed slab object and the
+information about the accessed memory page.
 
-In the last section the report shows memory state around the accessed address.
-Internally KASAN tracks memory state separately for each memory granule, which
+In the end, the report shows the memory state around the accessed address.
+Internally, KASAN tracks memory state separately for each memory granule, which
 is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
 memory state section of the report shows the state of one of the memory
 granules that surround the accessed address.
 
-For generic KASAN the size of each memory granule is 8. The state of each
+For generic KASAN, the size of each memory granule is 8. The state of each
 granule is encoded in one shadow byte. Those 8 bytes can be accessible,
-partially accessible, freed or be a part of a redzone. KASAN uses the following
-encoding for each shadow byte: 0 means that all 8 bytes of the corresponding
+partially accessible, freed, or be a part of a redzone. KASAN uses the following
+encoding for each shadow byte: 00 means that all 8 bytes of the corresponding
 memory region are accessible; number N (1 <= N <= 7) means that the first N
 bytes are accessible, and other (8 - N) bytes are not; any negative value
 indicates that the entire 8-byte word is inaccessible. KASAN uses different
 negative values to distinguish between different kinds of inaccessible memory
 like redzones or freed memory (see mm/kasan/kasan.h).
 
-In the report above the arrows point to the shadow byte 03, which means that
-the accessed address is partially accessible. For tag-based KASAN modes this
-last report section shows the memory tags around the accessed address
-(see the `Implementation details`_ section).
+In the report above, the arrow points to the shadow byte ``03``, which means
+that the accessed address is partially accessible.
+
+For tag-based KASAN modes, this last report section shows the memory tags around
+the accessed address (see the `Implementation details`_ section).
+
+Note that KASAN bug titles (like ``slab-out-of-bounds`` or ``use-after-free``)
+are best-effort: KASAN prints the most probable bug type based on the limited
+information it has. The actual type of the bug might be different.
+
+Generic KASAN also reports up to two auxiliary call stack traces. These stack
+traces point to places in code that interacted with the object but that are not
+directly present in the bad access stack trace. Currently, this includes
+call_rcu() and workqueue queuing.
 
 Boot parameters
 ~~~~~~~~~~~~~~~
@@ -214,10 +224,6 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN also reports the last 2 call stacks to creation of work that
-potentially has access to an object. Call stacks for the following are shown:
-call_rcu() and workqueue queuing.
-
 Generic KASAN is the only mode that delays the reuse of freed object via
 quarantine (see mm/kasan/quarantine.c for implementation).
 
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3531e8fe6972cf39d1954e3643237b19eb21227e.1615559068.git.andreyknvl%40google.com.
