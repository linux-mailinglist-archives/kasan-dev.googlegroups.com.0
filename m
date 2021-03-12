Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOXTVWBAMGQEXSTV23I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 70B84338FE9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:59 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 3sf9900269ljf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559099; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bc//zxM2zNJ5NVrsJ33jGilQSW48iDO1ImZ2NpenGNGGO1Uk1zre4s9rAsROR7j+k/
         2IFQ223O7MLP6sMVq4hikUwGMhxXIRIXQeLNiS6A9D3MCBvbOPrXbJIidwwzqzltUv+B
         rP76W+QhtA1Gq6kWJNc+NgnkruE9AtH8aDXZbEOSn26CaG1qq/kdIk3uvAfFpj4zLYsu
         JDkaLLxZuAxsNI5cirt13yJd4rOAgzdXxFZ+MWfWoOTk+OLY/PGVb3lZKxCQqMf8UcOz
         VpdSlDvxnJglSqAkcfodpeexUtYbwju5kQKfnD6i8+T6IkTIGu/BQ83O9cp2FOTyzn95
         8zfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Hu6fYmizjza+reZksgKvnSQSjrmmBKn43rN3sDHQbyg=;
        b=ANoy5JK3ZxzWy0GrUrA8hGmEPf0NK0hHD/htyg2cGIDKSxVLFJb5oB49Buf6n9Va1F
         POXROlhnn3dTErvcxOeJIUFWK8q06x30vHfkIll0J1y5dQsJvFDnfUwh6u62hSHnfZ0Z
         T3LQGX/jtQQnnH4J2RbaozdjWypIYOConrObCi49VMA1UcjrKArBgGZJJGeZY44TiPui
         OoYAZy1AWSyUZS+ovfROP2zUFL12i0c0JLzxZTeCVymA9XkjTjR3HmlC2wugdKbLU774
         nHCHqP2Xwziei7RYewvRK/VTMVK0Mo8yF2SgVbr+jllSsLoVhzKf42GRzeqw1deCRbaW
         QlCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nXr9UV9/";
       spf=pass (google.com: domain of 3uxllyaokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uXlLYAoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hu6fYmizjza+reZksgKvnSQSjrmmBKn43rN3sDHQbyg=;
        b=cwW+BJaZ8pFJneytvId2HRFm1cRl2XjrltrcABclpDkRZ9fOSpfbRXuAd7hv4oUZsR
         PQ8dLzPEHiwIN0sR+ihjjvFbS5My+LtctL/Fe4Y3NBcWSHzeOqUJ0uFCJ7CMqbMsd/T9
         +zE8zopU4jCfmDovgYlFpoIBXHiLwMRUKXYmHOzgNzCjKu6XmcW30emu5LBzCfLcPG7W
         wj7ulPc+ghH3CJpmJec+7R7e/ArMYYHiVaQf7cLtUrEEl+cWGljEmpiWnOODc4B37oGc
         GMxyE17zufExcsLo3G5ShGYXrQqYMql2UQkWO9jN/kDvQYwen0VlMTuHWdPcd0NHvG3w
         3pNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hu6fYmizjza+reZksgKvnSQSjrmmBKn43rN3sDHQbyg=;
        b=ns6BT5iRP2rOXzGncTnvMfxJ/mri7kDQQAZQ/UJrgWEePxdTp9NFJk3IzkEeNsOSer
         9/Gwc/klbbciQhS9SvmXiih0/yb/u60Nc7SXnqPgU0/ETg95+jNJp5anVVoWz0MP9XAa
         trI2/GHFy6IsQDzjsW4e27r+t/x1IZtAQn0bc7PekQf1NWTIGLR9L120IAeVRdR/rPzr
         /VcYqfw7FTESoqgDIJCgulThMOPWG80Js1coLqheexc9IYc158u7AFWCjwT9H6bO2wFR
         vGnssVPRsVi7KY6mCZpfEwj/dTLkDI0xQstVJRie8C/XWX0dtdPP9I3cdPLLalRUJdWP
         Mb7w==
X-Gm-Message-State: AOAM530IAaWs4ysP63cX1yWQS+1p6iB8j2GWRRd+s7Mc284ZqQPdM1yz
	hS6AiMMu9Q2DvRWg0f+Cu2I=
X-Google-Smtp-Source: ABdhPJycim3zp5qzRTlmjdRE03aqOujwWlU7ZIPFjozhyvh1QD0dMkK/laJJp8YE2O4RvA65VRboxg==
X-Received: by 2002:a05:6512:1195:: with SMTP id g21mr5281760lfr.512.1615559099039;
        Fri, 12 Mar 2021 06:24:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls3508449lfo.0.gmail; Fri, 12 Mar
 2021 06:24:58 -0800 (PST)
X-Received: by 2002:a05:6512:3a93:: with SMTP id q19mr5554775lfu.186.1615559098078;
        Fri, 12 Mar 2021 06:24:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559098; cv=none;
        d=google.com; s=arc-20160816;
        b=k2y6dTNMTMzC9QyjUZZbigdQJKGUsFc+bYwC7pv+Kz8JVW7exF/MrjwpTuEApe1xjv
         Qp0Q/vfyZynmwjOctOM6bQhlX3dMHnEWxTRcJOsmIqzh/bDp2SrGff6kKGCdiq5u2yyp
         6IUnWC8RHJyzRjUgxqG7tfw1feBoeN6jP0T7xDiZ2TB8F1z2TQFu3Byxpb+jwjoR/n0h
         QGdbStI87IZMW3KpgCnTD8epbmw8VCgRVfwNZ7a5ScXAowwPStc5T2EXw++eFIWw54cB
         sA76wWln/7bEWsy1/u/N64VgBcCfgdpiH5XNSGorEhq8gax0rLikFW1wCwrl/fRaGUui
         wv0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=hsoBR6E8KwmiptK80mQJVFHGCa6Vkbo97hvfJKQe5xQ=;
        b=up3UAonw4/58itFw4EvTx0VHGkVrqYlyuaNt7x2QYLUf2LetxoZC9DnDO7LECBMnaO
         jmpHEoj/oy6VJUtX9C9QIohn9hC/JFvgxl+7OybM0JR5c0JOUi555pO0rGUhIcpem4Dl
         QuQaqli6Zxz9ym5P6qJGp5td4KUpuyT3TOIAJoZJdO/D1InZ8bGk2ceXfvxY0izCiGAa
         kNLakxDyw/f8ER4TA5wxv5QbJNf1u+37tIxiIRQLTbRcw5TyOZLdk0GHWSMjt+pjuXgS
         qud9TgN1MTwyexx7Mw/doDoE22sTEh867WwPVYK8MTKELWRBt++kXUaQyqrlLtLPCrR8
         Adfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nXr9UV9/";
       spf=pass (google.com: domain of 3uxllyaokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uXlLYAoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 63si212687lfd.1.2021.03.12.06.24.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uxllyaokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h30so11250865wrh.10
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:58 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6243:: with SMTP id
 w64mr2250680wmb.0.1615559097271; Fri, 12 Mar 2021 06:24:57 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:32 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <00f8c38b0fd5290a3f4dced04eaba41383e67e14.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 09/11] kasan: docs: update shadow memory section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="nXr9UV9/";       spf=pass
 (google.com: domain of 3uxllyaokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uXlLYAoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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

Update the "Shadow memory" section in KASAN documentation:

- Rearrange the introduction paragraph do it doesn't give a
  "KASAN has an issue" impression.
- Update the list of architectures with vmalloc support.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 31 ++++++++++++++-----------------
 1 file changed, 14 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2744ae6347c6..d0c1796122df 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -304,14 +304,11 @@ checking gets disabled.
 Shadow memory
 -------------
 
-The kernel maps memory in a number of different parts of the address
-space. This poses something of a problem for KASAN, which requires
-that all addresses accessed by instrumented code have a valid shadow
-region.
-
-The range of kernel virtual addresses is large: there is not enough
-real memory to support a real shadow region for every address that
-could be accessed by the kernel.
+The kernel maps memory in several different parts of the address space.
+The range of kernel virtual addresses is large: there is not enough real
+memory to support a real shadow region for every address that could be
+accessed by the kernel. Therefore, KASAN only maps real shadow for certain
+parts of the address space.
 
 Default behaviour
 ~~~~~~~~~~~~~~~~~
@@ -323,10 +320,9 @@ page is mapped over the shadow area. This read-only shadow page
 declares all memory accesses as permitted.
 
 This presents a problem for modules: they do not live in the linear
-mapping, but in a dedicated module space. By hooking in to the module
-allocator, KASAN can temporarily map real shadow memory to cover
-them. This allows detection of invalid accesses to module globals, for
-example.
+mapping but in a dedicated module space. By hooking into the module
+allocator, KASAN temporarily maps real shadow memory to cover them.
+This allows detection of invalid accesses to module globals, for example.
 
 This also creates an incompatibility with ``VMAP_STACK``: if the stack
 lives in vmalloc space, it will be shadowed by the read-only page, and
@@ -337,9 +333,10 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently, this is supported on x86,
+riscv, s390, and powerpc.
 
-This works by hooking into vmalloc and vmap, and dynamically
+This works by hooking into vmalloc and vmap and dynamically
 allocating real shadow memory to back the mappings.
 
 Most mappings in vmalloc space are small, requiring less than a full
@@ -358,10 +355,10 @@ memory.
 
 To avoid the difficulties around swapping mappings around, KASAN expects
 that the part of the shadow region that covers the vmalloc space will
-not be covered by the early shadow page, but will be left
-unmapped. This will require changes in arch-specific code.
+not be covered by the early shadow page but will be left unmapped.
+This will require changes in arch-specific code.
 
-This allows ``VMAP_STACK`` support on x86, and can simplify support of
+This allows ``VMAP_STACK`` support on x86 and can simplify support of
 architectures that do not have a fixed module region.
 
 For developers
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00f8c38b0fd5290a3f4dced04eaba41383e67e14.1615559068.git.andreyknvl%40google.com.
