Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVXA6CFAMGQEAKX2N2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id A0A0442243D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:39 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id i3-20020aa79083000000b003efb4fd360dsf7883936pfa.8
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431638; cv=pass;
        d=google.com; s=arc-20160816;
        b=yEUUiM8zNTS1AI6L38BEdTu+ZqgiUYQTR/HS4xXgqMFwVv2xNh0XTi9TlnO59b5SSu
         mHHgWhcwwikVC8+OFKNHjTKQL7Y/G7aMvI3h6Rx+fCohYA0XYb2nzycsZ0P5kXtlkvfE
         TNOUW8ZgBn/lKceN1JbqscfgpmZn4yb+sXATJqODPVTdTqZPBBveedmrhuEt0StDBPWL
         REw7Ykq/iGtaj/a1qzAAmF0JhA5zibB4kHNVNKgTa+sUiQatILMT9XGG9HD879ltFg+2
         DBQA95UnCR7/vJum54z2F4dShWgDtdreF2jUQJZcrWY1pxYVDvIiaNAdXAg4PyI5uc1N
         mwig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3wfqB36tNcDVDkDOo02kuaLXQGaBwtrAfmJmxNSF+qg=;
        b=p6u1Gn5W/Nf+3YtFF42aMY4v8xIfKHdgw/pYejUDYnH1CuWdLMdBxjz5aa6h8Dnax2
         vDgeZwt/+Xb0gS3Mk/7+jtbJgmA1sXdG1lb2dIDolCskIm7COym6Z621iZzm/GMJhe3l
         +cHkVk3nsW2HYKerasw32uUbmgGlL/Q/dNAa7HBJhW8M4p9YPQZ8sYXdDt2CoXcr/PjN
         9k+Fg/RW4rMVzwBKHZsKE3WVNgLOrOdwN3085o0zmFmwZl9J/TGqN2F+R57O2KlIDzJV
         aBKZd0k0Z5CU8Yoc823HffPcuEMhzLFCkQrIYBcgFJzoiHBCa+EP0Sg8Y2DFieWCJdP1
         Un+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eBKhKFS4;
       spf=pass (google.com: domain of 3vdbcyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3VDBcYQUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3wfqB36tNcDVDkDOo02kuaLXQGaBwtrAfmJmxNSF+qg=;
        b=su8/R84S65FH84zVH2VPi+TmC6gYLTE+KeXrEv8iRt+whxlrkRNz5b1iF6lR8npvBJ
         MBpswe3ZVGK/3gw601+5SS87zk7QYeuLQuKF/+JTfcAzAkU2Etn4AAf0U6JRA5j6bWrE
         K8j55CTWQgYUetPtIIIo8/OZT3hkaE+ehxxa+KhrH178F3IYHb1lAkQ6EYgdD5J0GZDE
         fyRo/ld7MEUAx6cH0FnVtiqgVBNr6/U0y2UKpUjnV5K8N+K0ODBqnGUOSQ9P/n/n2CWo
         NcIMqRV1dL2GZgXZTk+jjELKij74YrUwvn0mLV9b42tngVjUbVmzE6neM2JhA4TEsvrL
         rK6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3wfqB36tNcDVDkDOo02kuaLXQGaBwtrAfmJmxNSF+qg=;
        b=aLTLsbsWXmpiuVqvdMCCTPyKC0eqAZCf7Celrp03IcJonDlSJMLy1GklYYF2N0+7Fd
         JKcYqaADJh+X+sq9x8e+zZWbccrFgmqUcn3cB11n3LlirXh5r348pR58DhhMbrrbZqkA
         zFfmSuQFNJxgMByRhx1+MFaAHLvX2jwe9vLofIdNtLcGzG9Vvvlh3kvkgb/tYfT47mtC
         yPlUW4sOrSJqUELsDFgxdOefjmoBkvArcgDoST9EPNC+Om2IbmbrraML+z+Q4rjx33dA
         dl9H0/7VKeKjKRs9TQcP4vc0RWHTl69E3K/WE7xIsA9jd58tYSx0xdVVrssGJV02Xrk8
         jN6w==
X-Gm-Message-State: AOAM5313Iqh4rL/p2FB0GXckZSbZZnxbBzdKJG9xxMRn9rziOzfyqv11
	klAx/eQkOKa8YRGo03w5vbU=
X-Google-Smtp-Source: ABdhPJzZti3OM7hHcLW0ONWtxmJRjZz3d730WshfChTsMFAVWKPuiFWBfk1vqhyeKJGdqRf+WLoAzA==
X-Received: by 2002:a63:5902:: with SMTP id n2mr15244903pgb.305.1633431638195;
        Tue, 05 Oct 2021 04:00:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a708:: with SMTP id w8ls11504387plq.6.gmail; Tue, 05
 Oct 2021 04:00:37 -0700 (PDT)
X-Received: by 2002:a63:dc03:: with SMTP id s3mr15050948pgg.88.1633431637435;
        Tue, 05 Oct 2021 04:00:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431637; cv=none;
        d=google.com; s=arc-20160816;
        b=oHezUpHq163aFQsJYBpIem2ZIaNnerazIvcFz/egJuc57IEK7gnA6CpIHvu3iCTC1p
         pS56BI9eab2BtNoYPHiNA5NHlt765wyi78Lxxdwb3uxuPOtQlP+c0gQUhAEkmoLthNM1
         gxvAHGK4cVv5qRjenPIOtnEYh2v0llyJ6rSPrrdEO+yTJGvwWrLWtrwe2iHbB9xqv35e
         jW18juW/y5ovlCMW2iNnH+4uuhZvXIk3CH8he+fuplf0xy1P7HKixx3NGGDoJ5sNZ78N
         Jtdrx2jeSYIg+UmlUFWZzi6EoGKNHj9cvZnOz8FPouq8lWCIFj2zAsMxCUSjylLLqyvl
         ImQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=GVi87uCC9iTMZ0tahcA01mPlZX23fhUUuaenbQ1/OXU=;
        b=EFKrv4g8WMMibJTEOXRC12UVuUNHQMvsdGj/B7+xnL3BS/6UGLPKOD6Xpzl+xKH+Cx
         fMaRXP5ZHicEMFqctPqRWHZB7y2qqMDHfpeRj/q04hwheAvQh6419BVTHgAbPjW2I1j4
         KqbgtfR13GoYSnJGZAUTGdvjIPtNsTA7dwo6eMuSbD+ybD+pxQycyW8xd5Sbx7LmvOHY
         jo9z+6aXuRbNuD3KzTJdi7/yGnh5Ojj+TtXD3zWyM5xSInUl3Z2ktSXG2E57wIUPdPCy
         xCAr3IoHDxFH3uCJSnaSAUx+MhGVvzYj3pxmTRYMZ7Njufa54GEMVvNyUH/N536pmfGe
         x19w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eBKhKFS4;
       spf=pass (google.com: domain of 3vdbcyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3VDBcYQUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id z23si66083pje.3.2021.10.05.04.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vdbcyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id q24-20020ac84118000000b002a6d14f21e9so22768156qtl.9
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:37 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:1305:: with SMTP id
 a5mr21006975qvv.64.1633431636934; Tue, 05 Oct 2021 04:00:36 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:59:05 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-24-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eBKhKFS4;       spf=pass
 (google.com: domain of 3vdbcyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3VDBcYQUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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

Teach objtool to turn instrumentation required for memory barrier
modeling into nops in noinstr text.

The __tsan_func_entry/exit calls are still emitted by compilers even
with the __no_sanitize_thread attribute. The memory barrier
instrumentation will be inserted explicitly (without compiler help), and
thus needs to also explicitly be removed.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 32 ++++++++++++++++++++++++++------
 1 file changed, 26 insertions(+), 6 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 7e8cd3ba5482..7b694e639164 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -965,6 +965,31 @@ static struct symbol *find_call_destination(struct section *sec, unsigned long o
 	return call_dest;
 }
 
+static bool should_remove_if_noinstr(const char *name)
+{
+	/*
+	 * Many compilers cannot disable KCOV with a function attribute so they
+	 * need a little help, NOP out any KCOV calls from noinstr text.
+	 */
+	if (!strncmp(name, "__sanitizer_cov_", 16))
+		return true;
+
+	/*
+	 * Compilers currently do not remove __tsan_func_entry/exit with the
+	 * __no_sanitize_thread attribute, remove them. Memory barrier
+	 * instrumentation is not emitted by the compiler, but inserted
+	 * explicitly, so we need to also remove them.
+	 */
+	if (!strncmp(name, "__tsan_func_", 12) ||
+	    !strcmp(name, "__kcsan_mb") ||
+	    !strcmp(name, "__kcsan_wmb") ||
+	    !strcmp(name, "__kcsan_rmb") ||
+	    !strcmp(name, "__kcsan_release"))
+		return true;
+
+	return false;
+}
+
 /*
  * Find the destination instructions for all calls.
  */
@@ -1031,13 +1056,8 @@ static int add_call_destinations(struct objtool_file *file)
 				      &file->static_call_list);
 		}
 
-		/*
-		 * Many compilers cannot disable KCOV with a function attribute
-		 * so they need a little help, NOP out any KCOV calls from noinstr
-		 * text.
-		 */
 		if (insn->sec->noinstr &&
-		    !strncmp(insn->call_dest->name, "__sanitizer_cov_", 16)) {
+		    should_remove_if_noinstr(insn->call_dest->name)) {
 			if (reloc) {
 				reloc->type = R_NONE;
 				elf_write_reloc(file->elf, reloc);
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-24-elver%40google.com.
