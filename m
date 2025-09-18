Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4FDWDDAMGQENUUUR4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B3921B84FE4
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:41 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-45f2b9b958asf9460065e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204401; cv=pass;
        d=google.com; s=arc-20240605;
        b=F3Pp2tiVOGdCjJlMAGKmkCQ3MJeb513epTOZg3VT2SMYF4eHbfnwIH7tm0jNmdF1pI
         SXWOJDp9CTURTWh1Z5OsNxpMKP/qUojXeuW45XhkO/EiUZyyccoyCd5yNY14N5kHxEiI
         0X7XXcLppNDkRFPFYdNPSSmpIdw/FYmFut0DxdeSCYxe6waXIushATb2562pdhvnFwQr
         /j7QCwaVJtWBLYxQq2CkF/EATog6BoI9Z8LvYA2DVaWSnlfZZ1aKxSzaFpY1BdZ2mwKH
         GeCqXrUvIDJ/uddxZufJwsCagdMFDikckbUgujTL8c89+xocE5X2CIcM/ca1fu8IZM6A
         R5Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jHoPj0Ab8T7KK6l7ZijtddwdtdUPHqsla/L8kQvluxI=;
        fh=O9qkToslDLOrwuz2padi0aS5X7oC/0GSZhEvJh4OVLc=;
        b=AU5yYACnRJe9CBmSw5IBMY6fSlTtK3Uu8OEWLam+IBpEz2wbwzoLfLgpx7TbX+Stzk
         VzzfdxlTQmL8PTqzckNGFiGD2jRfhyyLRS9Dlqk2fDpeHLdnIfkv0bpH2iY4d51QOF+F
         GDAFcsxW6igtYbNOIw1E4NW/krItkI3lbEYcHlV6hLuFzCmAUdjD5YN2y5CAiJSRr2B8
         TF0R8tvW4vQ4iXkFC4c+fsHD6jrIUaPrtFEMh3a2YvvXsC55aM/re+/rqNPiFpIgY4ii
         PtVioyH8YMwBfTjlh5PezjpSAviiRVURY2c24XIAmIyrW/VrrcXLGsQhmTDHxqNrQ0q1
         0zcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gJryK739;
       spf=pass (google.com: domain of 37rhmaaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37RHMaAUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204401; x=1758809201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jHoPj0Ab8T7KK6l7ZijtddwdtdUPHqsla/L8kQvluxI=;
        b=Y7/1FILlrvLExAE09Vu4nkgMUyFfbcERku5xkywfmq4uqI3oRS+fYuuK250JEevg6d
         7w7nbeEw7meWdlYDZk+egLBZJapoRkkGZPT7+awEiNoUHdAfCiYz1uRUZwTdrdlQhpFE
         d0fv8wy3spvhtQH8FQZNRapIo6vMzzoE0H3mVHs32SQLkJx+NSa6e3wzDDK5BclvnHDK
         KKD15BMsbpSzeoFa1hMOUHWHigizYOeXHQW5GheH7tJYkcuIulyRI3mC2lBeDyjswQuD
         z/7OYocylibiB1W2SvpaIMqv13/jBE0DSRO3vvDR/JAVCmf0Qf+fua7DOy4lQ42mz2oG
         T7+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204401; x=1758809201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jHoPj0Ab8T7KK6l7ZijtddwdtdUPHqsla/L8kQvluxI=;
        b=WqkI1ER1kTDZy8yD8GofNiW9DLM7WOlhXoPqCSAJx7XZ/79cNCBvUU3Yd+zCMZ+h2A
         hg5m02d1Bd9st7n0B5dhEWMgxM8eEaU2XP1epHM2PUbSaAf0+26H2az5Uzn29woHtHiK
         bshxAasP/qXcYuSf4D63WiXPgoBCRDeWREakzBYCDGrQa/mnG5hu38AcVMJmIE791+I1
         4eql0vtazdtLSCTIGcCKdoLnyJ18iju5Jc89ODQfWT4U5K9/RB/N8KDl5kQfa4eZDN1j
         0gHQ8g01hkA0a38nabGVafHLOH1mXP3ZG+TMqKtFpjUtLuuKhduuuUerncK8O1Fiwb8z
         vbqg==
X-Forwarded-Encrypted: i=2; AJvYcCWvq/ruL9blh8pNNddBvU+KJ5wmHfwyHnj75A6D523ROVLoSFemZnSC2T7CynB5MNuZlDm6Ng==@lfdr.de
X-Gm-Message-State: AOJu0YyU6aGrEtRSVboq+n8v3VbaFlV8I6r6xcm1GINLa0OWxA2AKbzi
	DS1LjbERtuEvKDjIVjBPyGmu5q0xk9tA4OfIrtGx8el4JoxBj6TIpXfD
X-Google-Smtp-Source: AGHT+IEaJhFLVqazaZaXOaJ16L7KxjUP4Nsy5wIFmbmo8bSjXVs3zGe4hoYxx0K4Qj8AqTJ2JhoBEw==
X-Received: by 2002:a05:600c:138b:b0:45f:2828:6a69 with SMTP id 5b1f17b1804b1-46206b2e15dmr57886225e9.28.1758204400876;
        Thu, 18 Sep 2025 07:06:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd59FfxYAj3bDKya1qRxQ73ftr/BVExFUDOUFZAX+wGOUA==
Received: by 2002:a05:600c:8419:b0:45b:4b3a:86f0 with SMTP id
 5b1f17b1804b1-46544956c47ls5427675e9.1.-pod-prod-07-eu; Thu, 18 Sep 2025
 07:06:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSaHgNgfurtuV35LWbQjTTLUYuwZ4qXlvONzpYrzfUoRTMMOgGM8dN4nhJsh4mpAiIAuZ9zZ+tcsU=@googlegroups.com
X-Received: by 2002:a05:600c:45d0:b0:45d:d13f:6061 with SMTP id 5b1f17b1804b1-46206b2e2bbmr68069835e9.30.1758204398065;
        Thu, 18 Sep 2025 07:06:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204398; cv=none;
        d=google.com; s=arc-20240605;
        b=CT4OKPCAuWogxLMh7RSV4KgaCUrI3E8iXLWaCyHL5T5PqtLh/jHjXrJ6+6Uml5KCk/
         scZHcXpttgosdBJh20kHnAqPtBolprRVvEUSXSX526nw9JfQmI6WLa8L6tGYyJdAurTh
         PtHt9dno2i/2NY0mannTvev4M0/6qvgn+BwyFiDhgmxuEQC6g0KajnKnO9HsXxo2X9gC
         Gfi/8WUYkNCHOs9MC5BGyCm0KQRGFerjikm328uxyc0XfyuqPOmpJO1kb6R18g+A6CrJ
         2KHRYor4VKOwzzOSIf1fzBdNan8cimV1seZi2S+Ag/afP42R/pnkkM18j2+tapaQI2nb
         SN/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Dhic53vYgugE24TxlxF+xx8w5glItenUyktwwUAacwI=;
        fh=aRGTr40XEjim0OVz0Y/3OIhFMKXS31yYIYI2U2RWomc=;
        b=Q2aDV1GWgcLKLkfSS75fuqewu82fLLKJCiFonOCP+dujunlMTu5Rik50HQuL7vydSQ
         iqyVOxy2pv2kjbvqBXLgdxIwp8C/AAMXQa8QRznGHN2FSUgOEFEdwB3f6UgeR8yhcnQi
         36JHac89v8FeeEb/y2XSO4pfkw2N49l4ZRCGg+AphEssHsNv6jFTrbMmb0DakHbJ0LNK
         LaFiT3n+SlI8jpomv+a9s+wRl/P84a8P4V58JGtW/yWJ+FuSgN0jRxh8yNL2McS+cvk1
         Dlzf43VFn8QVC+Z0LGdMfeHXjqvj2v7KOJ7YGyHMU8UBpq8Zoa+SaX2sRejaPwMiYteK
         g6sg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gJryK739;
       spf=pass (google.com: domain of 37rhmaaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37RHMaAUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-464e96dc627si422545e9.0.2025.09.18.07.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37rhmaaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45cb604427fso6368585e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5BeCvghUojIrKClSm6M0SwwjM4I8RDBcYMr4t6T2/kRDCn8Kk4uwhpQrF07cC5fLfp8PIspeYUj0=@googlegroups.com
X-Received: from wmqb11.prod.google.com ([2002:a05:600c:4e0b:b0:45f:2306:167])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1c9b:b0:45d:d9ab:b85a
 with SMTP id 5b1f17b1804b1-46201f8b09fmr54309365e9.7.1758204397465; Thu, 18
 Sep 2025 07:06:37 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:37 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-27-elver@google.com>
Subject: [PATCH v3 26/35] MAINTAINERS: Add entry for Capability Analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gJryK739;       spf=pass
 (google.com: domain of 37rhmaaukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37RHMaAUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add entry for all new files added for Clang's capability analysis.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index cd7ff55b5d32..da4c8196c1b7 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5951,6 +5951,17 @@ M:	Nelson Escobar <neescoba@cisco.com>
 S:	Supported
 F:	drivers/infiniband/hw/usnic/
 
+CLANG CAPABILITY ANALYSIS
+M:	Marco Elver <elver@google.com>
+R:	Bart Van Assche <bvanassche@acm.org>
+L:	llvm@lists.linux.dev
+S:	Maintained
+F:	Documentation/dev-tools/capability-analysis.rst
+F:	include/linux/compiler-capability-analysis.h
+F:	lib/test_capability-analysis.c
+F:	scripts/Makefile.capability-analysis
+F:	scripts/capability-analysis-suppression.txt
+
 CLANG CONTROL FLOW INTEGRITY SUPPORT
 M:	Sami Tolvanen <samitolvanen@google.com>
 M:	Kees Cook <kees@kernel.org>
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-27-elver%40google.com.
