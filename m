Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WV26MAMGQE4H7LX2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C1065AD26D
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:27 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id b16-20020a05600c4e1000b003a5a47762c3sf5304835wmq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380787; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwiRaoplil17WavMKRRHItChPu9UNIE7e/QnUnjRK+kKTC7+jnrBPEgyz1aHKbne8L
         4ZtyJiythdiij5SpAnPW18BazwSbzVaE2Ptyh+uGL6gPMi5Uj7a5GHJvj2op/C4R+a7u
         KPDbmoD7aBgc2y1/tNx6st67G6umv+yk1bmSwPP5U51qYV2QlBH86ThjIojTHUe4lZiR
         AWvHNf6fDaTNththFAldSTzG83U0/6lCWsViF2hBfOfNOGmjc0/o6urPCKtaNTpetXq5
         vhks7WbM0rKY5NvR90yAs+EY46gqFrOVZL0vic0DiRqO+x5EiONgLNVzkkiKwyF7rkHn
         1+QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lWqT9qhy5kzmwDyIu2U9yqWaerqg6csgekMOQ2Vfewk=;
        b=y8do/3GHVEtSBR218XOAJlF0G1YGk8LqKFzc1AXrJWA4Q4hmQ362p2mZJxBM5KrjrC
         mABCl+qRuVyce1kw777i1xx2+QCpWTmc45dKDcLb1Fiqqd5/JufKeVEagJH2LWgNiDsE
         FWFTJ3anRJtatx58v7epUxRPXC+IV2MKoU8eULFB0tZnyjc87FBUPtgeR5fT2e86NvKW
         DxbQNKDL9RFoWipN+aB4DxdC7YZJ0fzLXO5M6rOSyFRAzbDB//FBx3jrgIe6q/HheNEO
         SkPXyEfHA3nELKbPk9KW2t6SbTrhCbD9K7zfruZ7any5yE0xLUqPkd7UT1vc1up0TJlo
         89yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hll0XPDm;
       spf=pass (google.com: domain of 38eovywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=38eoVYwYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=lWqT9qhy5kzmwDyIu2U9yqWaerqg6csgekMOQ2Vfewk=;
        b=ESVszIhT3zDm8KhDfSUDjaSGjBIoN2LvM7DolrgFNS8b0dkKbfET7m1xysz7ahPnNm
         nzlUvU+sIiGB2KiWhlvrKGx1ONspGx40gVrvttGeV0OdcJEgZ7uCITcsPASjxIt8Q/ZG
         TGgw7Q0YLQMmPZ3dqsO/R5F/daxb1Gx2NwK2ShiDBhhLNBCiXj0doHHMbWDzKMg5MAQS
         mfzBifM0HhRd+CW2BwpuD2mfIoE1zjC7jOXRYdQaUwRs1xOhUqod7MzCDm+fulz/Vh8N
         hJW5bZG8QnM9Kqa19YaAcSyeS8UEfnKww6hgTToYr3y55WJ1ZslE8N/n3Eiv0zsya0G2
         JXzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=lWqT9qhy5kzmwDyIu2U9yqWaerqg6csgekMOQ2Vfewk=;
        b=lNMcNEObfXkMKTQB5akR6riFrYqXcFPEeJwuAlihXjwhGcgdZjwl2Ybcd5UZbbFm0x
         iUT74l/+zhAcSaso7Zx0ZF5GGB2zichf86PzspwMlat4arqzdayJYzOX8JGGFfdy7OIX
         LhoVtv8s+ei05hVMcYO1ygqNuZbxqMM4iqu+oW8g1xgoHTH/VG1xih+Jft5CjloJID5u
         mDO6lqzP/IEGNXGTzOPgAo7AFNtvNBUbMDHpBgglfaDMr5LZ6I0NAWGlAheexv2H1nLd
         0EEEdMbU65PnirZeSJQIJ13UC7Zrxyh5xHoqQfh4qHZBcTIaJaksQQEFIIINYspvr5th
         vMgw==
X-Gm-Message-State: ACgBeo1uuPNnmZvxYNc9zGMQNS5j8RD+V6qz72LUW4JNgTRwiAqNIji0
	BL7HgjxTWVkxgI0hcj7ItdU=
X-Google-Smtp-Source: AA6agR4xrQ1HfmhslZqVZ3d5+IdCVtyp1TUREgyZzkKaBjb7Yg3HVh6olNVAeUaiYV8iIViVcgp7Fw==
X-Received: by 2002:a05:600c:1497:b0:3a5:f608:d765 with SMTP id c23-20020a05600c149700b003a5f608d765mr10110772wmh.19.1662380787022;
        Mon, 05 Sep 2022 05:26:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb44:0:b0:3a5:2d3d:d97a with SMTP id v4-20020a7bcb44000000b003a52d3dd97als3786983wmj.3.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:26 -0700 (PDT)
X-Received: by 2002:a05:600c:255:b0:3aa:2150:b184 with SMTP id 21-20020a05600c025500b003aa2150b184mr10346619wmj.138.1662380786061;
        Mon, 05 Sep 2022 05:26:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380786; cv=none;
        d=google.com; s=arc-20160816;
        b=IyrOr6O8dBQUaVObD0pUAWkPioezows3qAt5K3sBLa1d2igSKMbfE38Lthb8DCAojr
         IixFsEmZdz4llLWk7/lF3VkPPplOqPjOQa0ZuN8FbPJQyUxc4QBflPxFxlBFQk9eNJEv
         OK+u3gWXi4NiUSMBiLo/87YYahlhLnTxcSTANR5UFZGCi4uZiGmdCsHlTHgUom9XVkgB
         pJmM/n7/sRPDV5wA9go4bk/9PDAgFXFMu0wkKTzFPgMXF+t668fx+lyfzKgX0tEPMYN3
         ZK00ID2lXtuUir+EQPgKCZybehQW5Z5oJSsrdXf1luf7TWkdqPhkV3wQgnWTKMCUtf2o
         9mkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mxKrKakNES2O6WNVUjUiVAG/aqg8NEyyXmfzwvDy3M8=;
        b=mKqSYmufHJASzS1PI8QNFfy/xcRRVTj+EPuz2QLhmMc+QakwnTJcBu0OPLlP04j83n
         29qgwCfsJijZwbriV5Zq3G2PeP2+yXIMTttGRGY52Dq4Lv8poQt6j7kArGGE9MaK5l/Y
         NmEZ/jI2wUGfemdN46a2oIaDglyoqgenLQSkf82WU9iZwbG6RLmvA704wZ3djsVrrAUE
         NrY41p7k/DFXSFjo/XfL27mn2kSuL8MFyaaxiq2xz27V3fKChpkyRM/X5iEoktFDuNcV
         uMYdkBzpTkdIX4EZnljuluOvo6KnGh6PW3htJj4CgeeB/gDCAx665WthHRgKyJ/gjbsc
         vDXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hll0XPDm;
       spf=pass (google.com: domain of 38eovywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=38eoVYwYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bo17-20020a056000069100b00226e3ba2090si404784wrb.1.2022.09.05.05.26.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38eovywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hp14-20020a1709073e0e00b00741a2093c4aso2312090ejc.20
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:26 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:845c:b0:730:bbf1:196a with SMTP id
 e28-20020a170906845c00b00730bbf1196amr36512046ejy.13.1662380785638; Mon, 05
 Sep 2022 05:26:25 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:40 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-33-glider@google.com>
Subject: [PATCH v6 32/44] objtool: kmsan: list KMSAN API functions as uaccess-safe
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Hll0XPDm;       spf=pass
 (google.com: domain of 38eovywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=38eoVYwYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
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

KMSAN inserts API function calls in a lot of places (function entries
and exits, local variables, memory accesses), so they may get called
from the uaccess regions as well.

KMSAN API functions are used to update the metadata (shadow/origin pages)
for kernel memory accesses. The metadata pages for kernel pointers are
also located in the kernel memory, so touching them is not a problem.
For userspace pointers, no metadata is allocated.

If an API function is supposed to read or modify the metadata, it does so
for kernel pointers and ignores userspace pointers.
If an API function is supposed to return a pair of metadata pointers for
the instrumentation to use (like all __msan_metadata_ptr_for_TYPE_SIZE()
functions do), it returns the allocated metadata for kernel pointers and
special dummy buffers residing in the kernel memory for userspace
pointers.

As a result, none of KMSAN API functions perform userspace accesses, but
since they might be called from UACCESS regions they use
user_access_save/restore().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v3:
 -- updated the patch description

v4:
 -- add kmsan_unpoison_entry_regs()

Link: https://linux-review.googlesource.com/id/I242bc9816273fecad4ea3d977393784396bb3c35
---
 tools/objtool/check.c | 20 ++++++++++++++++++++
 1 file changed, 20 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e55fdf952a3a1..7c048c11ce7da 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1062,6 +1062,26 @@ static const char *uaccess_safe_builtin[] = {
 	"__sanitizer_cov_trace_cmp4",
 	"__sanitizer_cov_trace_cmp8",
 	"__sanitizer_cov_trace_switch",
+	/* KMSAN */
+	"kmsan_copy_to_user",
+	"kmsan_report",
+	"kmsan_unpoison_entry_regs",
+	"kmsan_unpoison_memory",
+	"__msan_chain_origin",
+	"__msan_get_context_state",
+	"__msan_instrument_asm_store",
+	"__msan_metadata_ptr_for_load_1",
+	"__msan_metadata_ptr_for_load_2",
+	"__msan_metadata_ptr_for_load_4",
+	"__msan_metadata_ptr_for_load_8",
+	"__msan_metadata_ptr_for_load_n",
+	"__msan_metadata_ptr_for_store_1",
+	"__msan_metadata_ptr_for_store_2",
+	"__msan_metadata_ptr_for_store_4",
+	"__msan_metadata_ptr_for_store_8",
+	"__msan_metadata_ptr_for_store_n",
+	"__msan_poison_alloca",
+	"__msan_warning",
 	/* UBSAN */
 	"ubsan_type_mismatch_common",
 	"__ubsan_handle_type_mismatch",
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-33-glider%40google.com.
