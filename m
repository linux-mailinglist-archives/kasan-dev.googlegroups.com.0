Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3PZSO6QMGQEMT32SZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id CBDF9A2B059
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:23 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5da03762497sf1300160a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865903; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y+Cox0HE3I1jzkJyMsp//JMol88nXA+R2bVKred3rilfohUywrgjzshO1BytthM31f
         QjifxBNmYk0GZbpw59vVITaDY54sdBPO6tBKxkAqJqF6Kz6J26vCou0KjovGvwoKh155
         PDYEZaxal7zoto4BfcqfTqM/MdKg4kyehrs3K2rz5Al2rXDStg2V0GQvplyBDmjP2h5N
         wHzFEk3Vcz3/bece7Pp8yFqEJYQC9Ky4gYs2FUkS0oF6PuAmyOxq53FYyLJlyuNp8pcw
         GYRcK1EanlhzGWkyDzCGI5FjFU5/NWemcT9eQAdPUtf9VKnsLExg/azNXLI6oRXHRkIB
         82pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=HLMlCdcRe4ZBsMxb61gFgv8LXwFuOzjWZVtZg7RwFno=;
        fh=SozXOY1xzkoGCq438a5msXIB/jbM+QhNf3rBK67YeNE=;
        b=WYo1L/XpaJUO0UBD0YgX6uCodC3O4WG9uPsGXnh8x36bFB32VpcQ+0ZAcHZgw2JWm4
         nlcI5DDOYpiFmKz7mp3RoDX3jP0bbZPNJUiU4ya8cW4+0nixfWVReM+x0ykH7xTv8JMk
         UUKEhneiyKrdQfL2qI48v5IubSqI4vdTj1VVa6gDpB26FXwaKcDzzt5//raxiz5cnPMw
         Tw2bcEyV8CNttHFxobxk+AUtPs1YzvnH4jGcGL+RkAuBMfkqK9D+VkHIGMUHKizX/xEc
         DATV39CfPRxrCay96iMz6xxv1DertGHBNW9NM9BBXXahAbnSSRFLnLCXZ8FlFfAY7SFz
         2Mew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pyV/IZOe";
       spf=pass (google.com: domain of 36vykzwukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=36vykZwUKCbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865903; x=1739470703; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HLMlCdcRe4ZBsMxb61gFgv8LXwFuOzjWZVtZg7RwFno=;
        b=TCCk0htVROufbYEul/7QQFmIzXgSl02Zdf7mRa207JgXqeYLu2AXL1vHyS5Oz6FvaP
         fVbGdMf3W53+lP4w2K4LD5ffR6L0nFPLkJSL2u7rqh24HSakjw7pBpk/BcP4IaNoFfJt
         AL7phwvdpBCbczpZLkj41kc7c0mrt+JGSNDPcdnqFcNas314Dlu5lv2JNQjrdYC6E+58
         WSzkMkzgyxFRKETF3kN+NNjeT9BCkVIOql7Ma/4ZNHpFRAnRGs2bCdOPXkR7OTPsr/vR
         Ooenvnlrl7sJxqDrc6KV9JQ4NxBtljxub3D8TehYcmCcrPYtLXLQFAmY/UfDmNzt9q0Y
         Mqzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865903; x=1739470703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HLMlCdcRe4ZBsMxb61gFgv8LXwFuOzjWZVtZg7RwFno=;
        b=CyRFZ8R5QpaVSBnv6gk+JA5wO6A2NsYdH6+Tr+etD8paV5+7aa9x2FKT0vHcpI2a0F
         nPVyxrzcsPJbX5Git/zyYppuWCHqbLhhy9qujTr1+A+b4zxnVTE6JyUO2facp2qq+KX5
         KoTNJMJUfmwHm8cq5uFmAYpV5CMWgpAnv/wm7fZo0r664IZoRVFDQAAVTy1/n9iSwG2k
         X+KNCPpPfleukJ6dm9KqMqhYkYm/LKDjxb3MgdSC6Wa1gAOVDVwIBjFifcabkAFBAeJk
         spZ1rmqVv/gS+EJvLw6e2qCPr0UQ7eumOqIetnTgWQ38HKJotB4n74haLPhxt5DEXKJK
         LTFQ==
X-Forwarded-Encrypted: i=2; AJvYcCW5qbkJwcAu2AO5xVG2jYWH6LKlHdVkfP3nnBGj9mD2830VagR3WfWBGDP1rzs9EG0bd2QnoQ==@lfdr.de
X-Gm-Message-State: AOJu0YwyACoBfAUknScygHFOPXE11v922z1r0ZMHdoFJktCytEhl1kj7
	8Dybcu0L8ZRoMZw4B+VLGiVj2JgvP7H6Q4B/VZwQZXA/w94fDmfy
X-Google-Smtp-Source: AGHT+IH7+yNdCPZBXz7H8pdvL+J7jK08/vKil+LzNfO+5+X0AvURC/KY1E+KfappsC6myUtrpdwfeQ==
X-Received: by 2002:a05:6402:5251:b0:5dc:e3e8:20f9 with SMTP id 4fb4d7f45d1cf-5dcecd16f3dmr5216802a12.10.1738865901954;
        Thu, 06 Feb 2025 10:18:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:f607:0:b0:5db:6865:43f6 with SMTP id 4fb4d7f45d1cf-5dcebdafbcfls451258a12.2.-pod-prod-00-eu;
 Thu, 06 Feb 2025 10:18:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQR1NWBa5NGyvW4YK80XlpO+sB70WFP+zzgjVSFUIA7iH0ldl0dLt2X2MH6pR+cYcCsMDplzsxWl0=@googlegroups.com
X-Received: by 2002:a05:6402:2344:b0:5dc:80ba:ddb1 with SMTP id 4fb4d7f45d1cf-5dceccdcbf7mr4661474a12.14.1738865899129;
        Thu, 06 Feb 2025 10:18:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865899; cv=none;
        d=google.com; s=arc-20240605;
        b=ZUDfRRNH5s8lMmR3/5ZSK9B5D9LHIVUPSh1jGZyMpH2KFPPE4rrcl48HppUU5rANWt
         IrGlKRNdru4512AntdS/hbYavkGgWQ6huNLNQhI19quV7PrL2QnaYKyGy1HECQCBZgUf
         xGAroT/kBLKZChejTtlej26rgUh2MsRyqywR5DFezT/Ce4k7+46TIiPewCJd+GHDuuHh
         edMlnLPDRUiPqqX4kIFGxEN94CJfFwFI6X6dpgkwc9HSDmD4ERV8Ce4le9FBHLhbVMr+
         b+5s9KoI30BZCrtyjwbJlgqND6DXblmPgZTBHzm/Zm/eQAc82o6ok6Mlg+7OdOLAYYDX
         HayA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nywgR7jAINvHiuDVB4pmE7YTMO7Utfq2UN01exAeezk=;
        fh=v+sueAkxWEX+Jx5VtI0LBJP/Pk/ZIF+GLs6cpeQtOEc=;
        b=ZCp5+3t8gbynxwcH3UREmcvVGM9DwQKvAplge5AhgFvIfE9ThMx3QsU2K8OvVaPTKr
         HbISwWkUWr2cxx5L1LA7Afb8e0quy93m7Xhe4uDHf3HuCiWhRWy+zzcK7YHF/vd/I1zL
         18STGEZiF90FgPPF+LHs0WkEvNWDKMuOLDzqKXOD/ORCKH3MU2kxt/TR01gaSvsMXYEL
         Y6loo6zeVpILhoEddc8KKAyxR1NS54qNIriBkvX+ri6Gr0kw0GjJAQLM5s36aTU198K9
         QZR+LpiCXuCeiBgP+ff3GcvJChjS7q4ITAArXolbtCQvmGrer0OuPivjl7BHGWN0lFX2
         GBBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pyV/IZOe";
       spf=pass (google.com: domain of 36vykzwukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=36vykZwUKCbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf1b739ccsi43235a12.1.2025.02.06.10.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 36vykzwukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5d9fcb4a122so1483472a12.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpVitWtpaSw1K4grcVA4CprBvvE94pcZUJebEKHq74z6eXG/5ekThyzX+lE7rMoil5kKIPf7SCpmM=@googlegroups.com
X-Received: from edag6.prod.google.com ([2002:a05:6402:3206:b0:5de:3ce0:a49b])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:51cb:b0:5dc:88dd:38aa
 with SMTP id 4fb4d7f45d1cf-5de45005a73mr490615a12.8.1738865898851; Thu, 06
 Feb 2025 10:18:18 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:07 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-14-elver@google.com>
Subject: [PATCH RFC 13/24] bit_spinlock: Include missing <asm/processor.h>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="pyV/IZOe";       spf=pass
 (google.com: domain of 36vykzwukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=36vykZwUKCbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

Including <linux/bit_spinlock.h> into an empty TU will result in the
compiler complaining:

./include/linux/bit_spinlock.h:34:4: error: call to undeclared function 'cpu_relax'; <...>
   34 |                         cpu_relax();
      |                         ^
1 error generated.

Include <asm/processor.h> to allow including bit_spinlock.h where
<asm/processor.h> is not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/bit_spinlock.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index bbc4730a6505..f1174a2fcc4d 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -7,6 +7,8 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 
+#include <asm/processor.h>  /* for cpu_relax() */
+
 /*
  *  bit-based spin_lock()
  *
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-14-elver%40google.com.
