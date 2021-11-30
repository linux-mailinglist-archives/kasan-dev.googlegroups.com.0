Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4E5TCGQMGQESSAF4IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 292804632F4
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:54 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id 7-20020a6b0107000000b005ed196a2546sf23377774iob.11
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272752; cv=pass;
        d=google.com; s=arc-20160816;
        b=HYJFwhap1jxeCP20YHN+OZ7s05A0yNFd3UiXv4JF+ZG7+XD6ctM39JD2wi18uZviRb
         OMiQ3SRYrjVS415AvsjnwjjWeiCH3B+bQ66/T3mxw/svPt87D/ggI2uH8HTX24c6Lnmv
         U1TEWGowNDQlmYtXjIT+lm+4KKdquvdd5kPea4DhqK8SE5XeSvbyS9+hbKF6ctRjcpcr
         +hDt23+AsofzRxIk9BlOjZbLZmExQpbx1X6KuvLXQYIazcuT0NhK3s6cRg4f5SKJwTJ+
         V4i9FHpVGyKYmt9kDshPi40orajH9R05I2yvsi6SkUPy99x7Bhm3VJLrFl8cdJlDtD20
         mrKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=JOOXKu88PPFhiNVN+SuLS55cIJT3Enrqe07paKwIBjI=;
        b=CopXSYKafIWpUf4VvLQ5ZUs8yIsnHyUZLi/58hLnnVLOl4jbT5KW3xyBobiyulvlpr
         BpDM5BsrWD8/5eRG3sJwxqph47uaExpJ52f4Zv0EjeNZxfstZPaQTn0sSOpJ/yB930TF
         bhecXqUyoraQ01Z0HgyblxVDsXfb8KGEfVWUiP3VQRcj5JzM+EKE49j2OxlSHwj4/rEU
         A66YFS8lf5gDPe7FVC7cN8rgj5zgPHeOxwg/+AI1pA3y/YZKnRWI6NqbpFwrLmSn7slB
         HUU0vLkJftMDHVNeh+t12q0kj++ZW27jIFcbm0h7omwNcHtx7afMt1v5v8Bk8cY05oLS
         M0rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="iiJU/NFx";
       spf=pass (google.com: domain of 37w6myqukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=37w6mYQUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JOOXKu88PPFhiNVN+SuLS55cIJT3Enrqe07paKwIBjI=;
        b=N6oQ9bqGgO2iNze5B6c2MDGj60s6KJnOtGqhHLQRb2d3JX+/iX0xdMPNRX8FkdkKBw
         vpFNCAm0KLKciY9Go5zesOZd65ol270MrWIOj60PZv/4tCTgvFbtQkBgMSpzHyfFVghy
         /fcq6c44QTNPiG9UjNcXomC+XEAKNwSUw4ODiwdMoJb/q/73jdVW3h7NevorTIv5um91
         RSVBKAhbrf1vzCyRLV0hX8eEBrBS20Kl9kyzm/WtF9VL9pnW1ak6ooenaiKQGzDFPhkU
         dlBnykiIP0pPnsml8+my23zhOPGcf7k/ogTOAoPFDgM3R2hbZTCHoIq896sQ8CbpzbGn
         JX4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JOOXKu88PPFhiNVN+SuLS55cIJT3Enrqe07paKwIBjI=;
        b=y4zLn2IIQa87P6NS7EDZ1+9fIzKpxV7aSbu+NnT+CaQiVd0S22fWzEJhI+m4Fvah/n
         xj1Uz7PBxHVZgFxKPTvoGh2AasbCgUNNQ7YAHBXmqoxmcqdDFcqgbVd+EzUC/2Tq5bPp
         sWMRom1aLuDQ2rc+/n4hrLK6gtYo1AJINJAzgtKDbLYhBYjCeEc05AuCCYRaXiVmQ1EX
         aiLtmJuIfdclTp0q32fLDv6iQwE0/nFXkeP9ehLV3pbWXUXji3QlNE/YYt8g9ZLnsBPx
         c9S3ppUrjd0HpvrJiXT83ijNUGfLLULkF1H+IqJXJ0G6Gh4/mopSZ7stFO1smllPy7ZZ
         OLYg==
X-Gm-Message-State: AOAM531mmztMNkWzarRTl1PezMPmmQmjf0O7lCH6Zm0DUIqUFLzVwaxs
	vyN4QQ2TNFkCOBKdsgAvfEE=
X-Google-Smtp-Source: ABdhPJxeWgdqAIMv9QkHjs38iXV8Oll1upDpNZSbgpu4KoKpKKRB0Bvirye0fr0AslulWh/Qo3LWzg==
X-Received: by 2002:a05:6e02:114f:: with SMTP id o15mr56825621ill.307.1638272752689;
        Tue, 30 Nov 2021 03:45:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a02:: with SMTP id w2ls1666074jaw.1.gmail; Tue, 30 Nov
 2021 03:45:52 -0800 (PST)
X-Received: by 2002:a02:a11d:: with SMTP id f29mr69119697jag.78.1638272752275;
        Tue, 30 Nov 2021 03:45:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272752; cv=none;
        d=google.com; s=arc-20160816;
        b=bhDbJem00oD2RBdrOgRv9RUmvyBe6j3xbuwQLCR2t/dR234qnbcC+gcHvUTm/m5AYW
         9u9DDfhDHbu8sueeBobkMrJ1R7gMvCooRN2q9ioVH9ZzXwsL6SZBw1rHLMzORWWw0uMv
         F6CgagKsHYHRkeUBIUnDbTuDpNmyP2bi9QAXvgX/ffQHwd2vlkkTh47ALlMy11kquvyG
         UyfZT7UvWoJ/GCU/hitNul4cniWS1UdU/hjkcOmVpdYQObAdEYeXCWJXH2tyzCXwDpc4
         IPX1t3cPLDJo8yvyJ/G2S4QBlA/UOdv8xWarCOc2mmJuWaGITcwp9FF2sVLsjjN9rvje
         ph4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rzdCErYR7QVJMqQ7C8iOEn+pKBOJL+BpLP2uqDT2sRI=;
        b=YnwuNMx6zHfEIY4JeJSpXkcZXB/9iFgO/ygaMywqjP/G6D89Ni8NjPlfSiy3Q9ZZ+V
         iX/MsaOqYbdNFUV4zQHAQzrgFJpJ02sK3pJRavSFa6RdX0TOq5EAUyqNC5gB+bUkpZp3
         9F6/hlv6dzfLQzT0Age0tOwPINVnjXGSUjfh6jEQ1GdVK6p15OcoIyNPSQjI1KmA7Id7
         dGc61HdveWqiZuZeNchXkiulxBeXLjIldFCa3Qp1Tr7iiDIBee1TXqM0VK9qghWmLhZJ
         lNNz6CrlYbaGnO5KrHSwSqW3rN60Oh7lDYL+ioVeJA7hCsXJYFaucvKlgyGkuKvrtbsA
         qqfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="iiJU/NFx";
       spf=pass (google.com: domain of 37w6myqukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=37w6mYQUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id l7si1736148ilh.5.2021.11.30.03.45.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 37w6myqukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id de12-20020a05620a370c00b00467697ab8a7so28328720qkb.9
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:52 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:ac8:5c45:: with SMTP id j5mr51253786qtj.58.1638272751779;
 Tue, 30 Nov 2021 03:45:51 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:28 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-21-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 20/25] mm, kcsan: Enable barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="iiJU/NFx";       spf=pass
 (google.com: domain of 37w6myqukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=37w6mYQUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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
index d6c0042e3aa0..7919cd7f13f2 100644
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
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-21-elver%40google.com.
