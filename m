Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTXA6CFAMGQEPBQKTVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AA8F42243A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:31 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id f10-20020a9f2bca000000b002c9abdb45f7sf10383447uaj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431630; cv=pass;
        d=google.com; s=arc-20160816;
        b=LmIRAkjBizlTtBsl9DNZE1EVuSmnLIkrgCmkif7Vs9+0mtco1QEEL/E31C95ofjVPC
         PfTQmvem/j2pXlERkIqTfFQyAjCAZn3Wh2uRcvPm5MVuBcz0UrZU5mbc003H5EYqATdF
         uEI3+5aalV7A2K+25SCgXH0mlftksz4R2FgTwsUQoEU7jYIJ0lfaS0FPXOS5/vVK9Wbf
         JAUeK7f2+3VFJ3U23XJsWA2/+/7dD0eKmaF+hDw+XwfbSXpDi/tF9JceHchao5Agc+Ek
         F2/W77v+/BRYJUA0qO8Jm72Cj8t/a3qiHoC0ohqWBunWaOVwCOmUdsE/bwJBEXiUaewY
         bxWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=eI6sWt8im2BHCrQ3hVmXAjFAEWJTxANIaujEdxwhSR0=;
        b=uyb+M2D3ubmg2GviE+QvwPCRXRdkBNhBUhU7bU2DRECUvDU0VZ+XOHPTIxRpIS7tqp
         SXPOBWjaBe+fmNOkHACz7RCsFXl4eZd61qWd1NrWNasw0rVZ8M4mhB/2UxkkAu118nPp
         rVCHcoXEFGJGVWhPuiIylnBzbdatSdSHzcpqK1lO8pzUFbxRGPJTW8TTl/7JaIqdmvQZ
         QB2HEeWiGfOEXambQK4195+lPI7SoI1ybWsBnzoTOJx6/VdQSc3OmUYkC4vRmIf79KUr
         1pOofv9L49BwCBCUG34lLe4jESgRGzppr8tJrTti0TAZPO7XZqtW3zVt+yfjrgcuvBfp
         PcMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FUiAxTnf;
       spf=pass (google.com: domain of 3ttbcyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3TTBcYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eI6sWt8im2BHCrQ3hVmXAjFAEWJTxANIaujEdxwhSR0=;
        b=Zyp+sUmuEX+8+Ha4BfyTw/A43QBdaGXFaogMLpMtKw7bAn2q7SaWnYCqc75NS1og8E
         vT2D85sHdJRwYS8EubDAjBf4FdIV/IcGCLcQs+5pwS+v/PBOIKl4LJGtUDyn0jdrJg4V
         Kbgt3bg9nLUtB0PSz3YlfXp1SXrKDMJ7RNN4Qc4fb1V4w0uPCHNzxCHbA1/rtYWjDfTJ
         z9hULkXwl9HWVx/2/bTw96WxP4W1OOPVNun7AfP5SGPbIPBKaVyOGauiOT3/osBBGJp0
         Gk75HEl5TzhDFsbOn8xNtvrCC97FzopnKfLzNvTNUF5ZTs7AdE9AbOhB25sASmrHoC6+
         UQOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eI6sWt8im2BHCrQ3hVmXAjFAEWJTxANIaujEdxwhSR0=;
        b=JiAj3iaTEHd2Ezlo3Dd7CjYM8PtDCi9lg/pp3/2cSKKaFAhoAbBbyqTnF4POVNFQcS
         fV50eWfmFJAbe2QoxZJCw+NOC+wMb6ZngOAPKaasI4590/v984FLUAPNiSl8868Rhbsk
         3PtLkInY4lr03WAC/bb+TWsRLT+hjXrZH6mAwJBSdEGmaOxrRSIkqoXgkmaota2YnUsG
         nCr8jrQqPoQ5D8AYU638EkJ5u5HGpUxI0s3HHlSbXS5RcRBbTae1GNgJfOncIfOOYw9V
         +ngVo3LvoWBDY98OQ2Qi7ra7MRTxOg6Vmce2pxirkczLfAN9kT/OS6QN2xkjJFnMvDSw
         um/Q==
X-Gm-Message-State: AOAM5324aI1nX272RtdRp6QP20QyfqyB2i6fM1ZGmJq6otX3grR92Scq
	kQAElPcL0nIlDlRKAxpP5IM=
X-Google-Smtp-Source: ABdhPJxQCa90mE8//uJAxbhTkv/8wjLPndqVAuZ4baZI2+wtdDImQspKDP12JMb+g11rbDvsuRTLZQ==
X-Received: by 2002:a67:f48c:: with SMTP id o12mr9010006vsn.22.1633431630709;
        Tue, 05 Oct 2021 04:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:cf4a:: with SMTP id f10ls5165535vsm.4.gmail; Tue, 05 Oct
 2021 04:00:30 -0700 (PDT)
X-Received: by 2002:a67:ed5a:: with SMTP id m26mr17625315vsp.35.1633431630199;
        Tue, 05 Oct 2021 04:00:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431630; cv=none;
        d=google.com; s=arc-20160816;
        b=g0A/A1NcPfEYioWeMK/wqVM45KAsqEy+Hv67fVuXn2ZQqXPFD0mOo3eO1/s/IW8xHn
         tpU4Y46jhkDoGvjv6spzdeux0O4cXk9t/9VABejQUAsNB47EilmzJdc21ct7oMcNPHw3
         HhYi3K8+2tjFn//Kmi1Sz0/NEqyzfHjtqmYZXFkLDsZcHfezs4e0b1MBl5I0Q92j/1vg
         4BSRsudZxOXBNMkA5sTEvY0kqU4VfoeRn+BQMHq9sgwYVs/fh6UwZZKMFAjbF5Sx93mL
         PApx1ElkBMogcSiOizy7jTHEOg1BMxXeUjgJpdbwGNbxKW1j6DLPkpvfvBk2VUJCqd+j
         cMKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=GLbylOcVG6Z3Pa9zRtQvvZApReh1K+etnDrS06Ovq3M=;
        b=jrsl8hxfDIbg24KmlyqLCb1y7sBqKsmic7PviIwCOqUDX2V9MXJpivaPmsfT1a8cDP
         zjxO+glBSq0AOf519OBsQiFv2I6oyJ+08jaylZKv7eviRC5sNF2oijxq5VkhShr8dBzu
         oxeZXZp8QG0Exwy94biDUWhec4XFQJTJDF7ywdJCB2OWkuLhNuWVutQuigTatNiKsX/i
         6FhNlZv/haGalZa2TLV32Vyflbm86qSj5t49BE+vI87Y+xZ78F5auamqJYr/akIXueKr
         YT8JPut+2ZtQ0ZhpSdUpVjsKTK8xHdIGphAc1zleGXGNKCYdcwzzVGvevjeq3BQQx24g
         EJrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FUiAxTnf;
       spf=pass (google.com: domain of 3ttbcyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3TTBcYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id u23si807228vsn.2.2021.10.05.04.00.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ttbcyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id r5-20020a05620a298500b0045dac5fb940so26459355qkp.17
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:30 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a0c:c1c9:: with SMTP id v9mr26722583qvh.31.1633431629848;
 Tue, 05 Oct 2021 04:00:29 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:59:02 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-21-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 20/23] mm, kcsan: Enable barrier instrumentation
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
 header.i=@google.com header.s=20210112 header.b=FUiAxTnf;       spf=pass
 (google.com: domain of 3ttbcyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3TTBcYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Some memory management calls imply memory barriers that are required to
avoid false positives. For example, without the correct instrumentation,
we could observe data races of the following variant:

                   T0           |           T1
        ------------------------+------------------------
                                |
         *a = 42;    ---+       |
         kfree(a);      |       |
                        |       | b = kmalloc(..); // b == a
          <reordered> <-+       | *b = 42;         // not a data race!
                                |

Therefore, instrument memory barriers in all allocator code currently
not being instrumented in a default build.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/Makefile b/mm/Makefile
index fc60a40ce954..11e9fcd410be 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -15,6 +15,8 @@ KCSAN_SANITIZE_slab_common.o := n
 KCSAN_SANITIZE_slab.o := n
 KCSAN_SANITIZE_slub.o := n
 KCSAN_SANITIZE_page_alloc.o := n
+# But enable explicit instrumentation for memory barriers.
+KCSAN_INSTRUMENT_BARRIERS := y
 
 # These files are disabled because they produce non-interesting and/or
 # flaky coverage that is not a function of syscall inputs. E.g. slab is out of
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-21-elver%40google.com.
