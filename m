Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK6GWT5QKGQE4TM4SXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DA01277BFE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:28 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id 33sf284609wrk.12
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987947; cv=pass;
        d=google.com; s=arc-20160816;
        b=WnzCrfMEBVUkpELwzoKiel7rx9q6O4y6j15KlVCrsV/BAquqigGnsRy56vcaQRxt7D
         axx8s3h8eS+zd5qFYAcP2TPgjCV8qmQtCea9Uty9KkTsiJHHA+h9O7QYkV5or4Zg747/
         qMafFCnYpozT9it56OKfFfCR/nALfc9Mkrv+r0+M/mWvIFkhnk1RLMnBvQnZh4ReNdDp
         IgPGcJVlBYiCvxg1M5tgS6eVuDrVIXCggnqMND//TE6cVdMwlA17yEmB4blvM+7FBXJV
         ciyV6LdrIDWmcYo0+HEhYd5q9dwEZ9ZMzgl9eHzf7S0zVOefJaa2NqYt+DNDmxxM2Y1/
         Bntw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UnCNs9riRdA9CQs8F5hAUAlwTSxe1TdbNnDziGDTE68=;
        b=yugAPlE76lVRmeFeWSKXHqjTeN/xUx/6vF/o9tU5Z3Qze2i1B+IqP/lsx0KHcrwSFX
         j1z5hiTNzKozKkS9iWzwBsvQ1sYu7Ej0kZ9F5VRTHrMN3BmPPFvihBWPOBNJA3Omm+yj
         o4stB1aEADw8pywTUEYtV6ZE3WGE4iyvi7HIQRImEsSjXX+dp7h61XgMor9+qPpxfXvh
         iMsEEGrfbISuuTfFWGUe3wvPMXqfIQcwjw2xXCM+lMrqS8TefOk/qdp50/d7V7A+sJq/
         8HUpqOwv+qtbjI+qQ948XrOfpVaL5QiOFtB16vmjKQlXMmabzYbcxBnq7wsdDraPMOb/
         sARw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CORF9gJC;
       spf=pass (google.com: domain of 3kintxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KiNtXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UnCNs9riRdA9CQs8F5hAUAlwTSxe1TdbNnDziGDTE68=;
        b=P22FsnvZb2Ig/wY7JjgziW8MY/FDP1iyCBZ3fQUXZCW/a6BLNbXSmHhiyppnLVn1RF
         yowGnvmGmMZA4xLyrbQVWZFgemhgdAXeRx8dIbuA0lyH9z+Mf8Vnop9viL4/pNa6la63
         5f4qtnBkEEz9laBg0OSsNrft9+avv+ukC/YMdKD31TUGSF6bX7W8y7+xTx0mqW8EE0Iy
         MYIkDraUGMmR8meC+RsavO5J2DPnED6Skr8DRP1EjLSwssDcvRI4+kGCdD8Eiijiigpt
         /zgb2CwLJbiHq3tNB1DBgPHqJMtCY+ojykC0YaAkRTqxlkvytd3iTwF60V/FfAbTZRKw
         7Ysg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UnCNs9riRdA9CQs8F5hAUAlwTSxe1TdbNnDziGDTE68=;
        b=RXdxTv7VQtnBoLA4jrVsw++eZIqAb1HfrnZUYjhNhPtYytJxhgVUs4nlBcNl1tN1pQ
         eRmihMsfK6QWdjdmn1lpm0PKdetwiokDPQqP0WyJd2fGUnem9/d07zE1HadmdqsNAgiW
         bc9FwDKHo8vp3/FhAPZIaaIeXtdHPdgeUB5bdaAbaxYcu3xwDF7IjhGEWv94cjfr5w3u
         RUw9kM2lsPvPbdlIlcAdQMutnmRjG0sjQt8PqKFXeWJ3Z3kjPsOq0syooIStIVQJxpXV
         Ov28cuoql42EJBYyRR5IUbVRw24LHsniR97bTrF7QdKf99wyWJedM/ofRKoKkrQ9TxYE
         XQig==
X-Gm-Message-State: AOAM531Giy7mRH+gvzaEFyQW6hPtwB7+w+r/GUNOKyprUvZwRVBbo9gM
	0uvpfRxBOWqoHphfIXlj97g=
X-Google-Smtp-Source: ABdhPJy84VVPcEbu+WgBorEq7BOtJszVPAf1KpCqdT9bvxal8AxFCBh+9FuqZjxuBcznkqpr+bai+Q==
X-Received: by 2002:a5d:60c6:: with SMTP id x6mr1270543wrt.157.1600987947719;
        Thu, 24 Sep 2020 15:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:230d:: with SMTP id 13ls227497wmo.0.canary-gmail;
 Thu, 24 Sep 2020 15:52:27 -0700 (PDT)
X-Received: by 2002:a1c:6487:: with SMTP id y129mr908418wmb.90.1600987947001;
        Thu, 24 Sep 2020 15:52:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987946; cv=none;
        d=google.com; s=arc-20160816;
        b=dFGGgiFwvS2dorrG1rITDPQwGWaayMVO8PD/WPTHsPYx93HJTH6XBJTa5XKuV1Wli8
         RCbHn8OlV+UumkiG95ztfRl5GEwajaahojXMY5KgVYAuUIU9QuVXaOwy3qNvZXEcqqxK
         65ESUG2V3JTuXzhr7o3441rAOneQJcEKtdxTYE/BwWf0oNQcCKdrkHy8Cn+PVZeg6mPj
         bfNUmyP1UAkOALG11kWfpYvDYIzGjL3QTP1I6v4Y4uJTI46cAnZz1DTA80GGcAtdo8CF
         +QNvYLfTqfbUqoCH3fyhffUgfhY0/0PNf0exWVa2BhO04sKlZQzn/SsUacgtbXr+ElfB
         Yg7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hlOyvh18y00ONf+aBfuERwpVlPPlvhg4reGb29KekE0=;
        b=KjIXIP9zh/Z1ARf+Eqh1U0U8YFJmqq1r/fg/OCqG7wbb90LiVPHgIEb/DuRqc6S8ED
         03OEWsPHdNtk7MabSfyHXKxGefcg6VJ4RS25lbWZcwKy1mmYhAAI5cKow2ubXoBYyvRy
         FsDJrScMdZyyZZ8ryUf0NSa3P6OTDVKpVZPAwkzxN6F2KhqI+iuEsJNZ6UpoFmaOKZhb
         HValb7xabxol0vXcRbI0nD5KT7DmmFAnNe/+rapHxWDkK7jkQj3aJYWsmC0MAWlO3Ium
         +3WkpclQepasETmbzvoTQ8vD+YnlXU1ETzOprQ6q51AuGDBZgDlbpw/t19uzVrJ3zzOM
         k/MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CORF9gJC;
       spf=pass (google.com: domain of 3kintxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KiNtXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id s192si20574wme.1.2020.09.24.15.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kintxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m10so275456wmf.5
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:26 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:db4d:: with SMTP id
 f13mr1162110wrj.155.1600987946571; Thu, 24 Sep 2020 15:52:26 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:46 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <b6edb566f7439224c3e235186305bc07de8d27b9.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 39/39] kasan: add documentation for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CORF9gJC;       spf=pass
 (google.com: domain of 3kintxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KiNtXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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

Add documentation for hardware tag-based KASAN mode and also add some
clarifications for software tag-based mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
---
 Documentation/dev-tools/kasan.rst | 78 ++++++++++++++++++++++---------
 1 file changed, 57 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a3030fc6afe5..d2d47c82a7b9 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -5,12 +5,14 @@ Overview
 --------
 
 KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
-find out-of-bound and use-after-free bugs. KASAN has two modes: generic KASAN
-(similar to userspace ASan) and software tag-based KASAN (similar to userspace
-HWASan).
+find out-of-bound and use-after-free bugs. KASAN has three modes:
+1. generic KASAN (similar to userspace ASan),
+2. software tag-based KASAN (similar to userspace HWASan),
+3. hardware tag-based KASAN (based on hardware memory tagging).
 
-KASAN uses compile-time instrumentation to insert validity checks before every
-memory access, and therefore requires a compiler version that supports that.
+Software KASAN modes (1 and 2) use compile-time instrumentation to insert
+validity checks before every memory access, and therefore require a compiler
+version that supports that.
 
 Generic KASAN is supported in both GCC and Clang. With GCC it requires version
 8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
@@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures, and tag-based KASAN modes are supported only for arm64.
 
 Usage
 -----
@@ -28,14 +30,16 @@ To enable KASAN configure kernel with::
 
 	  CONFIG_KASAN = y
 
-and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN) and
-CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN).
+and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
+CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
+CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
 
-You also need to choose between CONFIG_KASAN_OUTLINE and CONFIG_KASAN_INLINE.
-Outline and inline are compiler instrumentation types. The former produces
-smaller binary while the latter is 1.1 - 2 times faster.
+For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
+CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
+The former produces smaller binary while the latter is 1.1 - 2 times faster.
 
-Both KASAN modes work with both SLUB and SLAB memory allocators.
+Both software KASAN modes work with both SLUB and SLAB memory allocators,
+hardware tag-based KASAN currently only support SLUB.
 For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
 
 To augment reports with last allocation and freeing stack of the physical page,
@@ -196,17 +200,24 @@ and the second to last.
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
-store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
-uses shadow memory to store memory tags associated with each 16-byte memory
+Software tag-based KASAN requires software memory tagging support in the form
+of HWASan-like compiler instrumentation (see HWASan documentation for details).
+
+Software tag-based KASAN is currently only implemented for arm64 architecture.
+
+Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
+to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
+it uses shadow memory to store memory tags associated with each 16-byte memory
 cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
 
-On each memory allocation tag-based KASAN generates a random tag, tags the
-allocated memory with this tag, and embeds this tag into the returned pointer.
+On each memory allocation software tag-based KASAN generates a random tag, tags
+the allocated memory with this tag, and embeds this tag into the returned
+pointer.
+
 Software tag-based KASAN uses compile-time instrumentation to insert checks
 before each memory access. These checks make sure that tag of the memory that
 is being accessed is equal to tag of the pointer that is used to access this
-memory. In case of a tag mismatch tag-based KASAN prints a bug report.
+memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
 
 Software tag-based KASAN also has two instrumentation modes (outline, that
 emits callbacks to check memory accesses; and inline, that performs the shadow
@@ -215,9 +226,34 @@ simply printed from the function that performs the access check. With inline
 instrumentation a brk instruction is emitted by the compiler, and a dedicated
 brk handler is used to print bug reports.
 
-A potential expansion of this mode is a hardware tag-based mode, which would
-use hardware memory tagging support instead of compiler instrumentation and
-manual shadow memory manipulation.
+Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Software tag-based KASAN currently only supports tagging of slab memory.
+
+Hardware tag-based KASAN
+~~~~~~~~~~~~~~~~~~~~~~~~
+
+Hardware tag-based KASAN is similar to the software mode in concept, but uses
+hardware memory tagging support instead of compiler instrumentation and
+shadow memory.
+
+Hardware tag-based KASAN is currently only implemented for arm64 architecture
+and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
+Instruction Set Architecture, and Top Byte Ignore (TBI).
+
+Special arm64 instructions are used to assign memory tags for each allocation.
+Same tags are assigned to pointers to those allocations. On every memory
+access, hardware makes sure that tag of the memory that is being accessed is
+equal to tag of the pointer that is used to access this memory. In case of a
+tag mismatch a fault is generated and a report is printed.
+
+Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+reserved to tag freed memory regions.
+
+Hardware tag-based KASAN currently only supports tagging of slab memory.
 
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b6edb566f7439224c3e235186305bc07de8d27b9.1600987622.git.andreyknvl%40google.com.
