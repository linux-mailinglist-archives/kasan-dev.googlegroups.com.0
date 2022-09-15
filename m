Return-Path: <kasan-dev+bncBCCMH5WKTMGRBW76RSMQMGQESMRPHHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E67F5B9E27
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:05 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-10e88633e1csf9470015fac.21
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254364; cv=pass;
        d=google.com; s=arc-20160816;
        b=nQN0jfgMvBZgpvmsB+AaWx8twsa6fXazK6r1EZZAyDs8WBx1jSMtqrMMVc04cT4P3g
         zv+7/LZkPKC10/hefrdWRyUYDSe1rnnXhv8mv11VsFn5du4yDYwr8FGOKsgczIOnFP93
         wWDByL84MXHPBA4G72csM/L03Tz7gc27M/hpyoOKW5+q+/HimfE+rHrP0XBIkUPd0gbE
         qYEE7OWFTppIa3yQgvc/hHoVZS5YqvjjBBgQxCaz2SY+YqJtwkojwAjvMWvLMlX8794J
         nKf7cyDKaIvmsZmfUoBdOyRfPGysxlHnWitf/kZEMuDgB8xWNb+6p05QygEFUVdHbs+R
         M+4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=l6oTB/n0QErfPNSBuowMJyUDOcgZsc+9DbIbrD02DVE=;
        b=hFFm9Av6isQxrPZmzr/8vtlJKLBIznPnfzuvYXD8tZX6M6/xv/h4bz3zO0TRWxwu23
         bsSxd217aEDqn9d6a4W3O+Wj/gT1/OflCHrVy+vt7CacPjTHHIY7kVE5RW/R9MbWjd+P
         qjvyuuVWdt+tbYN7uqryvCA2jTvaDQJKDYRhlTGTQuQ0L3tImDUaYIJbcONVti01nTDP
         YGmy6GRy6bI/EdhPi2/jGXIJFRmJ5iK8FbOP2np3hDhAE++laxMcx7zN78mSspYjSVKd
         FS5vLAg9TCRRSijKNXgVzfx8uVtwRH7q3SqsMRgY4t26rw7a3S7HHGF6jN+jQdHGly6l
         XI+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QcWSJZZk;
       spf=pass (google.com: domain of 3wj8jywykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Wj8jYwYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=l6oTB/n0QErfPNSBuowMJyUDOcgZsc+9DbIbrD02DVE=;
        b=Ynzqv0Fs/bV58+3n+M0EG+5pjmriJ9abG0Ot0ouysB/0/ednPBDU9f902TQ1kdWJTw
         IASjgD/ssXPl6PIUMX2dj3rpWW6D3q2i8OCGb/kVL+I1Yd9K2sFO+mZgQqynpz9qOv1l
         FK2l+uDn4PAv6Fib2BWvnrYr575Omw5P5r5aa7EgTxsRfQDv3+5NN3f8zhIAdbmDfE3z
         q96PHgLort8PH1kM5msSNbKSxrNy+00aQ78haaqfvFLzCZ7s24tN0rNc4h4wmzK2J3BR
         1DaSaCLQnbSRAbcmV0dWG/ADLbJy3vbvxiScYiw0CGe6rR+XCQkRZz228c1aKXMyGhv5
         lpjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=l6oTB/n0QErfPNSBuowMJyUDOcgZsc+9DbIbrD02DVE=;
        b=e35oaqVi59ydVOo8ByUH0nyuDXuGwmhE13o/ceRaPBNz4t6pttblMjq6BK4um1lNCE
         KM5LgcC31N+SuQG1p5nUU/5NJZ3t5j80A4PSNy36Zs0t9xIP4zTmAnys1MA8uwI2YFW7
         76KD24StbDVyBTMrLKjnZHHdDHfFdNZ57OdHTe1BK9YEftbvCOinfjG11gOwqt5jWISi
         xnUkMH6QgvveoSoDi/MlhSNBdCmIZgdGcm2OXOOsWrATex2Lhkd1xHtyGaFXmaVM4rDQ
         BtGtdEGY4AbZQqaWrbOevTzsgWatL4NNhVrwM6qXA50ksf/w2OPFsIS53ikIt8JhQeeV
         edLQ==
X-Gm-Message-State: ACgBeo3Ag4cUAEObjMWzYfpE12C3sheOL7OkvsUUg3uwgP7tkiSKpAP9
	Hbpy9dgNjUUp3veJt9G0QM4=
X-Google-Smtp-Source: AA6agR4+Dpp5gVhtG8d8g8w7gXzG1PZN2sAGCNPDzVVjfxHiqk6RTPfX1jdHU9NtZaWR+x1mFRxgFA==
X-Received: by 2002:a05:6870:6027:b0:101:696e:d594 with SMTP id t39-20020a056870602700b00101696ed594mr5816853oaa.245.1663254364080;
        Thu, 15 Sep 2022 08:06:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:6c4:b0:34f:df0b:2e1e with SMTP id
 m4-20020a05680806c400b0034fdf0b2e1els3206139oih.8.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:03 -0700 (PDT)
X-Received: by 2002:aca:bb44:0:b0:343:6f16:f264 with SMTP id l65-20020acabb44000000b003436f16f264mr4272624oif.59.1663254363193;
        Thu, 15 Sep 2022 08:06:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254363; cv=none;
        d=google.com; s=arc-20160816;
        b=XBk1wtZFXoUTvrYZoy/RfGequFQiUfHB/REqEvCzHAVOjMVQXntI6gsTMQt60F3Plc
         Sbk1cKUy416vD20vCfcClsbEr/j5NDj3SX0Xr3LivuOojJy7oqZ49Pz6bF1rkRfyABdt
         YvbAMWjlwciQPqg2hSp+iJn07eJxCNBSM7aaE82RZd3Ub4NOnB6oootMGuR5z2+8Xqdq
         LiSqDy9CXqHXIDYL7Xx/wSP/ugXSWKMJL/FoX5UCBCH0vbH49ThJLCd8sdayiczjQauH
         VSGupKTvQwj3kqRe1IxU+5BolSnhxuM6ZfN9/cAMTPROqcSnzcxKaSytzvXJ3AGbJ4yl
         pb9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mxKrKakNES2O6WNVUjUiVAG/aqg8NEyyXmfzwvDy3M8=;
        b=DzOHueV2E9la4jtfjJvZnkKKMIwMKKcoiXaLH85PKoWKNuraWACNTeIAPou+WuuUak
         jotXXQMjCSK4g3AVuIR1jjHjuj3Sra4DU8PhkKmvyJZ2UPka5CsvFpTlEbPLmpui27BC
         G9c/x5zye0mtOcMvk0oDLSlgbOu54WQ6UPVj47nDAovv+j20u61fLkuWZE3XAuSobKd/
         SxyuWzDrBMVcdgoe1ksfatzLP9gRsnHFDpmNTlc1Q7GesjOW5++gfjr9qRbpT4e0f2iC
         1vO1iNMpUSnRysruoGsww+G/4LqdXq8kf22V2n3pPxnu+l374ZzWJ7d3yq9+V5gTwarb
         I5DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QcWSJZZk;
       spf=pass (google.com: domain of 3wj8jywykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Wj8jYwYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id x126-20020acae084000000b0035028762f01si184243oig.3.2022.09.15.08.06.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wj8jywykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-34546b03773so160207177b3.9
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:03 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a81:a503:0:b0:349:f6c6:434 with SMTP id
 u3-20020a81a503000000b00349f6c60434mr248211ywg.70.1663254362758; Thu, 15 Sep
 2022 08:06:02 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:05 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-32-glider@google.com>
Subject: [PATCH v7 31/43] objtool: kmsan: list KMSAN API functions as uaccess-safe
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
 header.i=@google.com header.s=20210112 header.b=QcWSJZZk;       spf=pass
 (google.com: domain of 3wj8jywykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Wj8jYwYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-32-glider%40google.com.
