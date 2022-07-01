Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2EG7SKQMGQEG6EQJJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DA7456350D
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:37 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id bp15-20020a056512158f00b0047f603e5f92sf1180047lfb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685417; cv=pass;
        d=google.com; s=arc-20160816;
        b=CSdcAjZKy6M/PfjYRtEvDBr/gCD5Qj1LeCi02eR6BdnqyA7Wc70PjV5kUdJ8FBAJGp
         Z7jZ74N9osv8fjFmoquw0WNUx+pm1jBNxE+6qVx00k5UaD/vqcDTQ+Jo9DKmu9fGjWng
         WgSbNuQAsOC3fyx/UFzizWbvRb6O/C4J8GbyX/D3m1eEBxb9h+keegzzhYNfQXcpcLZ2
         YBdmqyJRnB94OVDhESbLrv/GGYoMht28l4Ii1QG6pN6v8Srb6XqXlgrIYokSH/Rr+FFv
         bVNbUZn29FGYEWovaJLMQj3PCbUO/lIAKvcnSPFeiR8eaPRkXhGF3XyQi2uujivIMg9m
         OraA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Pl8EuXu5iMtkJaNXYqJG9ahzVr5kecPnlxgXODYKrl8=;
        b=SQfcmSOTTJjosQX1n2CrjX3MLWvC18QJxJ3esSmJKVU5j2QOzrqSG8sURL56ldcHvw
         lFbvYuX+pXbB6TWiVpyoUVzv+Ua/ZeDhUwo5Q41JbDBT6dflWvHh80Loi5MhkS/RIOYj
         6/gcwgDHvN2BlZ/Ri1uvjMZ1vlvqbBnHPiXxPzzHXaj7XYvoxVFKBaFobGcfjTJslxWr
         ktoSu9O+Oc6cRfiR+hR0sES0M51vVWkNvjnGd0jZVocON8mPmvmxgEeuMdNwa8S/ON9K
         OfGCv88/+cTkFEAHiXYp8ALoL2hFLNhjTxRXWNPjrNMzlFUSdjVTeWfZbH/0m2eTPCRv
         tMHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DJbRcfFJ;
       spf=pass (google.com: domain of 3zgo_ygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ZgO_YgYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pl8EuXu5iMtkJaNXYqJG9ahzVr5kecPnlxgXODYKrl8=;
        b=GKFd+rkAZzh3lwtcbSdFWwxlJCDwH4u1Usn2Eef6yrgqrMfyh86NIjv2lHikscms/u
         zYtlR02vFYT01TMAAVYhB58p4/zhgDEfXeOdZVfl7hhSq8yOVwS2MvdQhvIQ7UCTOsBX
         q0jj970QGIZWVTz6CIps+b/Si7vy7HqtAcVN6dSpSpTNs6zA/wV4nskhAC/FtNDv7wyB
         SHRchKe8LtoD3Cv8uH6F+P6jWDiNpR+daF5y18LRUf38idPPO/hfEnYp2do9l6equ8+X
         AH0OIyajQego63Te96He1g1cPMhbg+PnQ8oD2i1LlYOavScMzfyPTTxZuHXGPMHKJ+pn
         Lxsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pl8EuXu5iMtkJaNXYqJG9ahzVr5kecPnlxgXODYKrl8=;
        b=5a8gm9wDaXBOwR5MsKdH16+wRpFa17Gzyxdilhjapok95rRq98DvuyBL7JC4bQwOwD
         dGVgKyBkTyhuaa/mf0QDEA2eFVl0yX5xEyRmbjL3cui4KjksQw03XRQ5h3Wmh+ojrfP7
         cs9lJQ7WmqNLXOOR9ZpJu/dsq8Hl1/fMesNF+pEEeGhF8qXvb7XSvVh+FpRdb5RDYkwF
         4M5oRs+pmGqO/6+cLr7Ug9sbiDyUW9xhNXh5WoQdyJ3POfNOJflZLwUH0VAZQvA6XcFo
         0c/VWiRW6P39ql2xWR18yMsnnbpLBBmMayxUBKpMAg1/k9o0BcU4QkBVoGSJp7YwMO+m
         AKQQ==
X-Gm-Message-State: AJIora+FO5L6LcGsjJ4tBYXsfXVoiztVCja0zgmdHaiGvMffWpIR8Kk/
	V6P0RP5Tpnwp4i4rY31uxvI=
X-Google-Smtp-Source: AGRyM1uYGMl/dSDbfAPdk4qe6JQKTgy0bQdanG1/3mlANgi3cC/QJOeJ7RKTpJn2WrJKnrwMcRdAJA==
X-Received: by 2002:a05:6512:3b8c:b0:47f:a2f4:5180 with SMTP id g12-20020a0565123b8c00b0047fa2f45180mr9243333lfv.348.1656685416752;
        Fri, 01 Jul 2022 07:23:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:99c6:0:b0:25a:89ff:c693 with SMTP id l6-20020a2e99c6000000b0025a89ffc693ls4623416ljj.9.gmail;
 Fri, 01 Jul 2022 07:23:35 -0700 (PDT)
X-Received: by 2002:a2e:2c0e:0:b0:25a:6b43:eff8 with SMTP id s14-20020a2e2c0e000000b0025a6b43eff8mr8692174ljs.299.1656685415503;
        Fri, 01 Jul 2022 07:23:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685415; cv=none;
        d=google.com; s=arc-20160816;
        b=TbORPsefUPynKxIamRYpy5wM+9yypXh7BeHtEPaGsjVhooIeJCt3Ndy/JvOKYnF9b5
         z3hlO8hindyF5Ch+9VedvBLYsYONM0C2W5nyrKiNT+Lc7oe+oYYU33E202p/qHPNdbLq
         d/eXSlN/LfJz7SWrKreqWKzceu6AA+vscSpN3uIm4bTO+L5HmPDSJ0TMTgwDIVAUSmwY
         Na84LiYBxsQX1qqVFPMYgHqOMt2tEG1pi9vE1AZMslsj/nsCfLrET2Bp0w61x75HPUJu
         QfbvbV4Axsm/6LripvBm8Hy6jMMvfcsdvdFgb1ch1SmgTDy4fbN+0Rr54sbT5keEkBsL
         NCLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gkw9YA7vb5ti0YajzjGN1OXbVHAqDO+SEh0OPXXltUo=;
        b=A5rQqLKne2kmNNALXJ4dnjWwxEFBsXU1yYC8u0SrYkgtro+4PKr7uWV97jKgMf37fD
         869CINlMHVlyZgW4oN4GiD7/JTPWWhOhQpA2Q38aHrg45tMqxOubDK9+ktrVCBUiaA8q
         d8b8HXe/4QP3QcGPZ/IluhjxpoZASo7jgfBf91A2lTn8CXivaVNEIdqot5C7ci6j6euU
         7e5iWWMpLa2PvENxNNE6yPJPwRuj8Y7MI0hK7pprHfzAEcpFH2PygKlDM9Chv/7M+pNk
         +EAh1GUPPoYOLXsKMRypMGbSyKa/nfnrdawBt7TQRuAqlVB4VHT0wDTqiAxRiOTosGHD
         rO3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DJbRcfFJ;
       spf=pass (google.com: domain of 3zgo_ygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ZgO_YgYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i2-20020a056512340200b004793442a7f0si1008054lfr.6.2022.07.01.07.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zgo_ygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id x8-20020a056402414800b0042d8498f50aso1885341eda.23
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:35 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:518b:b0:435:c1ed:3121 with SMTP id
 q11-20020a056402518b00b00435c1ed3121mr19002047edd.405.1656685414953; Fri, 01
 Jul 2022 07:23:34 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:32 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-8-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 07/45] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
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
 header.i=@google.com header.s=20210112 header.b=DJbRcfFJ;       spf=pass
 (google.com: domain of 3zgo_ygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ZgO_YgYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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

__no_sanitize_memory is a function attribute that instructs KMSAN to
skip a function during instrumentation. This is needed to e.g. implement
the noinstr functions.

__no_kmsan_checks is a function attribute that makes KMSAN
ignore the uninitialized values coming from the function's
inputs, and initialize the function's outputs.

Functions marked with this attribute can't be inlined into functions
not marked with it, and vice versa. This behavior is overridden by
__always_inline.

__SANITIZE_MEMORY__ is a macro that's defined iff the file is
instrumented with KMSAN. This is not the same as CONFIG_KMSAN, which is
defined for every file.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I004ff0360c918d3cd8b18767ddd1381c6d3281be
---
 include/linux/compiler-clang.h | 23 +++++++++++++++++++++++
 include/linux/compiler-gcc.h   |  6 ++++++
 2 files changed, 29 insertions(+)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index c84fec767445d..4fa0cc4cbd2c8 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -51,6 +51,29 @@
 #define __no_sanitize_undefined
 #endif
 
+#if __has_feature(memory_sanitizer)
+#define __SANITIZE_MEMORY__
+/*
+ * Unlike other sanitizers, KMSAN still inserts code into functions marked with
+ * no_sanitize("kernel-memory"). Using disable_sanitizer_instrumentation
+ * provides the behavior consistent with other __no_sanitize_ attributes,
+ * guaranteeing that __no_sanitize_memory functions remain uninstrumented.
+ */
+#define __no_sanitize_memory __disable_sanitizer_instrumentation
+
+/*
+ * The __no_kmsan_checks attribute ensures that a function does not produce
+ * false positive reports by:
+ *  - initializing all local variables and memory stores in this function;
+ *  - skipping all shadow checks;
+ *  - passing initialized arguments to this function's callees.
+ */
+#define __no_kmsan_checks __attribute__((no_sanitize("kernel-memory")))
+#else
+#define __no_sanitize_memory
+#define __no_kmsan_checks
+#endif
+
 /*
  * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
  * with no_sanitize("coverage"). Prior versions of Clang support coverage
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index a0c55eeaeaf16..63eb90eddad77 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -125,6 +125,12 @@
 #define __SANITIZE_ADDRESS__
 #endif
 
+/*
+ * GCC does not support KMSAN.
+ */
+#define __no_sanitize_memory
+#define __no_kmsan_checks
+
 /*
  * Turn individual warnings and errors on and off locally, depending
  * on version.
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-8-glider%40google.com.
