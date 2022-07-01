Return-Path: <kasan-dev+bncBCCMH5WKTMGRBL4H7SKQMGQEJMIK34Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B659A563534
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:47 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id p2-20020a05651212c200b004814102d512sf1179926lfg.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685487; cv=pass;
        d=google.com; s=arc-20160816;
        b=XImmttoQBGl9GCxquZUHNop22v415258KKhgYAhNVnbSOu+MfUcAJQ6KBxfqnlEOll
         YA1DP5IaeUqg03iT1D8q105WTxEqrMWaIs2cnFOwYZaetmr2KfonmsaglEE1U691rAck
         5sLrtWDDUztrAde1JKNeMlZxpEvHmZkEUA+FqGCXhbxQycmw15svRISN6MX8aULbNJSD
         uz04qwe7GzXJRGB06K+dFhh0woFxV26vDv1PA7VIYiV4W2xTWbVr0jdrpwgj6j6GyZ89
         Anx+W6D6XsYB2Z7qgoa7xhcrhEA+cUEMKwF2hH+2KYaJjOnF6j6rwgArMFKLYMUmK/gG
         FRlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=2ewBjitpjXyHtGyyd3z7TF8R4cuCrKm6tudpg0JI2/g=;
        b=i/VHUz3IKsofAkX98jV7lPdzursxMSwg3gg5/5xmzx1yXmMJuUfuVPSJRRECPEn0PB
         amSs4DM38ilq+Cunfq/SRLhTdmSXDnbJG/JTQ+OcInlo4PNkHzfNmXml/MHEyT6YUfqq
         XpjZsMp4V3n1DA0YZPtwQs4fsUX/pcqUrZjGFUkDCP7Ts7o+gPmdoOrMt4AriDJXQM+2
         aZtUowZTz2rTtlkQ3R/3Bk8pu77hMxyUrByF0g27OmQiwtwbnTapcx8dJCwt02UGftdv
         tB5JYEpkNFTfB1FeXzs04OpacRdJnS6MIsvpWLXhC+PB6wRkGTsZxl0AmEzyUo/hpAp0
         paDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qnQCWjKq;
       spf=pass (google.com: domain of 3rqo_ygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rQO_YgYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ewBjitpjXyHtGyyd3z7TF8R4cuCrKm6tudpg0JI2/g=;
        b=J0oEC4A2TGNUqJQDPUrQEXD6PfHyXrMRkCxz98yBhssGVoocwaFD2OmSVHuemAvNY4
         Voe5pP0aNCcw2b9UU/yylz7wGdOQyRgYrn5SHSMOcDNRqX7T23fi/M5uMQFumV3V08q8
         Hl1UOVPRG/OQCNarydajNaEC6pk4f0l1BweaJsqbyeg/IA2HK96SIg15CS2fEL7+sOnr
         r9PBbCNsUJ2JyJjUISVnGVXXix2q0P0VIEXmEUFuWAW+/UfuXrsSjtOMnLwffqAwdCR3
         67R3go4tU3wa3R78VLkX+jGjWkUvX1lBiaafvbcz6HNtsaTc1WZ6dF0y08Eibym3QJO3
         deCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ewBjitpjXyHtGyyd3z7TF8R4cuCrKm6tudpg0JI2/g=;
        b=5Z7/Fsc0l+D5KdnmeytPGgexOcRDauBjKaa4cv9icLy+D6ypeTliCbyKS9YX2VTfYK
         dG/2lQsHO/ckq0/3eH7vLPv1asNfM9up5W6PDXfbTQaVnTLIgFwrac99Vf4tweVamS/x
         RCc3Z/FfF1dEiTWQ/jnl8cje/K2LzN7PWAPbqvLkuynlswTnYVaBOlgCQ/290b9dcju3
         hxv0JE9R4tDO2fwTkoEpeClsJ3mb0YGXFOkV6TF5Cvd/xUDcIhVJtYgRx7YtJ8iM+OrH
         tpcWHfNHIlboryhwC5JXK0PLVDSMHOa4VJYeVXRd8GVryzAxvqEOk6bpCNdXcS0eX2Hl
         d4sA==
X-Gm-Message-State: AJIora+ArZAbVt8PYDaVrwgqwTTjkzv7Ly67ccNmqcgB0kiGqOQsKFAK
	2Xp1QFvU4j/d9CxR+Uz6vc0=
X-Google-Smtp-Source: AGRyM1vuNBqQZJ7CfZEugEz2BLZWyZkzmUBwv7hEIFVh87r8rhz74zQm+Gv82Qbb1/YBHoyLLEKkRw==
X-Received: by 2002:ac2:5f86:0:b0:47f:6395:b266 with SMTP id r6-20020ac25f86000000b0047f6395b266mr9289818lfe.549.1656685487303;
        Fri, 01 Jul 2022 07:24:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:864e:0:b0:25a:6d5e:adb1 with SMTP id i14-20020a2e864e000000b0025a6d5eadb1ls5855574ljj.2.gmail;
 Fri, 01 Jul 2022 07:24:45 -0700 (PDT)
X-Received: by 2002:a2e:9808:0:b0:25a:a30c:e5cb with SMTP id a8-20020a2e9808000000b0025aa30ce5cbmr8727667ljj.312.1656685485795;
        Fri, 01 Jul 2022 07:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685485; cv=none;
        d=google.com; s=arc-20160816;
        b=I9WPLrD4FrpmVg5KB0xLM5roOpV+VNfeU65wuRLKdkT80n8CXAo/kqcGfgSANT0QMH
         mMTlK5F6CtU65I+In+nHzTWIt2eREmZfesAKAwynbywPwy7fsNwEWglaPIVYUfO4+Ddt
         2sGleYIK002BRNvJ2R2jihq5JUsOc983eyGwbtoMqTgqWm2l45wH9aMvQZ+t4OGiYUd3
         9mooyZ0xt5rmffzc0OrEgYe9qwNWNlK4koRVYGSOZjghioh3zMaJeCUEoRZrT2V4hmLi
         NIPZfscvSNSYxJ6AP+IngU+bBPvg66x1hgjX1MvuGDqb1cl/hsIvhTv9wN9sH7KGUGS4
         +Egw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=z3bEqNJSKGgtE+5cRSN2oSZAKY283RHsG2GOYMoI00Y=;
        b=xuZ9WYn8BFqNGbwBqpHcHfwvYzvJSl759bsJiw/QOXpKnT+Gt20SPJ9yi5+HYHKo+U
         JR5tFuhYdHJh4HHOzk+vDUMN85k2sUXJ5gk3a9JEtTBMq7q7NmJEvTeqFlRBtyQ2YYzz
         CF72Ql4NxFy1NsZhSzuUhVZ9QGdLXcJ0BmBrxiKi2FkLkXQ0Nx6i+6XrD5cTXf8GCm1D
         Ew4IWpj3evskWsgyixBTlHEzpH+2TvqA8u0Jw0WnPYr2kIvXSOuz16kv5JCacaruqZy+
         hUxxclK5J85GnPDVGbR7NzaBHAlm+bFqa3T1IZVFR1NUvbrpo0AF9rg8/LsFTIwqzxTl
         X43Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qnQCWjKq;
       spf=pass (google.com: domain of 3rqo_ygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rQO_YgYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si845332ljo.8.2022.07.01.07.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rqo_ygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id n8-20020a05640205c800b00434fb0c150cso1848809edx.19
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:45 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:906:2086:b0:717:4e91:f1db with SMTP id
 6-20020a170906208600b007174e91f1dbmr14229924ejq.345.1656685485180; Fri, 01
 Jul 2022 07:24:45 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:57 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-33-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 32/45] objtool: kmsan: list KMSAN API functions as uaccess-safe
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
 header.i=@google.com header.s=20210112 header.b=qnQCWjKq;       spf=pass
 (google.com: domain of 3rqo_ygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rQO_YgYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
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
index 864bb9dd35845..1cf260c966441 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1013,6 +1013,26 @@ static const char *uaccess_safe_builtin[] = {
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-33-glider%40google.com.
