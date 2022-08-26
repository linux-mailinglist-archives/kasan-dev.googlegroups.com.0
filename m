Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPOEUOMAMGQEOO7STEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id AE2925A2A8C
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:49 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id q32-20020a05640224a000b004462f105fa9sf1239988eda.4
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526589; cv=pass;
        d=google.com; s=arc-20160816;
        b=yArpdYa2hNl9GDyQ7KPbIG/0KI4DzCnpGWJqXYdkDPkZgBm3xxb6a8Ihp4KqhSJfhZ
         9cMRB2pQbauDad0LdT21raB2blTA/j3eETZ/GIA2aBZ+WXjisV+NAkWh7TH2vtTAEhcn
         9T8sjlGstsr6mkoUmvA5nR1bXvcrVwRg09Hqti6q6Klep58lAsOzYn5V9mogQ4cmX6Bv
         rjY3/1o0qlnrjcfzUzWuaF60KH0kQSfk2RsCIEuy25xcKGua88sf1dn9Ab3Hlg4Hepeg
         VsihYt3l0WPupciOT58k8XV72CQBHT832AJGQAcQFEYE3F5YXELFvGf6dwjpkNB6rqLO
         4Oeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=E2R81ebAuN2tANfQehkkmtqE17q3grlFkZVkVsNsAQA=;
        b=ssE5XUOU/x3SFCz+1oHJUfqpZwn2h+w8xf9nY47Jig7KZUCknYoaz6cB+n7fGix1J2
         VyQK3P+R+qDLehA9+eoGaAQpTr+geO3PaxNz1t70A05W33n0mz5RM+NRlWA04pBKQ0Bq
         XNorr6N7lRb6NqP5HhCjblZBVLJR1kCAUqrTfPhxars9mmozb9bsuvEvLT4HeqdAWcIC
         krtuMplzsw6AemdrFcIkRAGtmN7nb+WF0GRAY2mSr0ZrOC1Tvnt0gQ9KfmHbMplj6wzv
         4SqOL3zrEr3GEE6zMm/cOb7XN+K1moiSCC/wtxBoO7aJuaK8x7/SK88ERzQIk8oQgVPE
         9R7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iowtS53R;
       spf=pass (google.com: domain of 3poiiywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3POIIYwYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=E2R81ebAuN2tANfQehkkmtqE17q3grlFkZVkVsNsAQA=;
        b=qRZDHFkUXNrJH/3LuJYufdd/LFV0S6XDedgT4EWClOQociMg/yvvPnoWjkaMxVzHBN
         vhF7Cyve9pElxPmGtgPxDv4MjDh6EyLgNGSTBkTyNJHtraonndLM2OTz1ikmfSnWeiII
         Sf5RAd8eIabKZxQCs6bilcQ4ycsjueBjB9+xdsZyfHdjH+B8h3b5iR+jg2NpGNZBU0HR
         cr+a5AMJo2aowZTXhCr8s/Re2DlRdtkHrn4gfPFADxUHiu/uBvGju9DN1ARlRmY0mHuW
         VltilIhGp7Ct0qdoz3zRAtUtUxN5e538YC/Qr4ghNgpWg1KKOFmLdtJ+PQjzKT241PuJ
         2jMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=E2R81ebAuN2tANfQehkkmtqE17q3grlFkZVkVsNsAQA=;
        b=WHru45IdDk1MV/NpO7aTyrE7mEbuXX+LWrEUGJdwexZHVT+MNPOQYhK+dJYWMfU602
         hhsAycxrEMMphqDB/yjKhz1OtS/dMeuXWU76438Wh0QOk+aDv3v+PtQg9Asfz2gPw0x2
         wLxUfquNZHgujB8t6YF7Ss7KTHEMfJDT0GYQdeZi04XMghypnvFs9m+4utOn17kecj8/
         UtYfQ0ciDLxGkm7cNQsDR0FKKMhkReqW81g1oDMdmLGYd2V6a9lWNuimPLDTG6+MOa4L
         j6nCb3UWc+u5cCSfXKZ29YiZtlYSuTL2LuNZMRv6Mmd7V4LUvglgSTXzgoX47Sy7+uF3
         H2ZA==
X-Gm-Message-State: ACgBeo1ysGA+MKzeBG1Hh5yj+yLQ6I4YGpEc9rpCuQWi0HY5Jkm2lIbx
	LqH6cRYrStyk/RMEydLUYkM=
X-Google-Smtp-Source: AA6agR4l7Sa6nyf4TU4sqiKahCYty8TEV2/AgST/le76WqT5YiFM2RL9EzZqrXTCV6NlWiVzWNiXdQ==
X-Received: by 2002:a17:906:c2d3:b0:73d:ac2e:662a with SMTP id ch19-20020a170906c2d300b0073dac2e662amr5663609ejb.498.1661526589403;
        Fri, 26 Aug 2022 08:09:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:76ad:b0:73c:b61c:65e3 with SMTP id
 jw13-20020a17090776ad00b0073cb61c65e3ls2140485ejc.11.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:48 -0700 (PDT)
X-Received: by 2002:a17:907:7fa5:b0:730:5d54:4c24 with SMTP id qk37-20020a1709077fa500b007305d544c24mr5763248ejc.641.1661526588389;
        Fri, 26 Aug 2022 08:09:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526588; cv=none;
        d=google.com; s=arc-20160816;
        b=MbvgAjhcRiizUkVlFTXnZ3m/jw2rMK3RRg7af85zjxcPhg4Q5DYZhVo8P5qMcc3ujL
         TB3dpZm7ALDK2s16GFUPFpF8475hMRyHLUmD2qkBJCqU205Xh3k9JIY1jkWO76b9W2JY
         /3Xhnu9dK1pcIgCrDjOuPljL+ZZbQjYWPJJGs1QSrrgyV3D1qosYUOW3K6spzl/jbJQp
         wA82Yp8pdp707t7GfMCCRZupw3SmP9lUWRnAFf/iyrSNEwgPu/dPdGo7kRYEYWkGxDE9
         J78PX3dJTyqVdZnagKJirSR17ZFz0p/LRZkOlvwO93kNVIE21MUyF018E3H5NqB9BCJ/
         gHIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3xJV8lOEjvc/s3Zvuma5zSeTndu+UAUJOaQAKluuQYo=;
        b=p9N8uqrTPAnXkfw0a/x+LMh7VuNv2fjr/Jj5bgtWGJmILWbCr8T2cJuvR/pYvc6Vx/
         ElTeKTfQVH+AK7q6++8Bc9X8HgqOiwUYqWMmAymSUhnx0jkvm3bGmKXVkJ11TfgP+0D7
         mfdbcf9uVhrrpL+Jte7Z77lH0o7FkuOMvzeO7m5uvxeMjzK3gw6SaGNeArdOHMZWfVvS
         18QSfgDM4oiuV/VkTYfpJI/wXG4ONrd5rmeuVnyde1LwoyR71kQjSslyVxtTqWVv3r6C
         1qkl/uTrVUWKHEJOkbyViSx89QMv9xpjprhj/peD2DQ7QOvEmpESdwD8JsZaX5vMQV4+
         67kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iowtS53R;
       spf=pass (google.com: domain of 3poiiywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3POIIYwYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c2-20020a056402120200b00448019f3895si34426edw.2.2022.08.26.08.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3poiiywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s3-20020a056402520300b00446f5068565so1236800edd.7
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:48 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:3491:b0:446:ea7d:8d9c with SMTP id
 v17-20020a056402349100b00446ea7d8d9cmr7130674edc.184.1661526588030; Fri, 26
 Aug 2022 08:09:48 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:57 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-35-glider@google.com>
Subject: [PATCH v5 34/44] x86: kmsan: skip shadow checks in __switch_to()
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
 header.i=@google.com header.s=20210112 header.b=iowtS53R;       spf=pass
 (google.com: domain of 3poiiywykcumlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3POIIYwYKCUMlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
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

When instrumenting functions, KMSAN obtains the per-task state (mostly
pointers to metadata for function arguments and return values) once per
function at its beginning, using the `current` pointer.

Every time the instrumented function calls another function, this state
(`struct kmsan_context_state`) is updated with shadow/origin data of the
passed and returned values.

When `current` changes in the low-level arch code, instrumented code can
not notice that, and will still refer to the old state, possibly corrupting
it or using stale data. This may result in false positive reports.

To deal with that, we need to apply __no_kmsan_checks to the functions
performing context switching - this will result in skipping all KMSAN
shadow checks and marking newly created values as initialized,
preventing all false positive reports in those functions. False negatives
are still possible, but we expect them to be rare and impersistent.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Link: https://linux-review.googlesource.com/id/I520c414f52c19f3ea22377a9c570fff0d5943a95

---
v2:
 -- This patch was previously called "kmsan: skip shadow checks in files
    doing context switches". Per Mark Rutland's suggestion, we now only
    skip checks in low-level arch-specific code, as context switches in
    common code should be invisible to KMSAN. We also apply the checks
    to precisely the functions performing the context switch instead of
    the whole file.

v5:
 -- Replace KMSAN_ENABLE_CHECKS_process_64.o with __no_kmsan_checks

Link: https://linux-review.googlesource.com/id/I45e3ed9c5f66ee79b0409d1673d66ae419029bcb
---
 arch/x86/kernel/process_64.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index 1962008fe7437..6b3418bff3261 100644
--- a/arch/x86/kernel/process_64.c
+++ b/arch/x86/kernel/process_64.c
@@ -553,6 +553,7 @@ void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp, bool x32)
  * Kprobes not supported here. Set the probe on schedule instead.
  * Function graph tracer not supported too.
  */
+__no_kmsan_checks
 __visible __notrace_funcgraph struct task_struct *
 __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-35-glider%40google.com.
