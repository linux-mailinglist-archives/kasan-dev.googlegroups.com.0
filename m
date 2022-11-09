Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6ENWCNQMGQEJHBJOQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1481623414
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:57 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id h6-20020a92c266000000b00300624bf414sf14430316ild.14
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024056; cv=pass;
        d=google.com; s=arc-20160816;
        b=q2i2CHYGT5DwwmCrvdWa0tUh7xv1FJdg35cXmqLG20/NkOod5l1sytxa/Lu0k+QGsA
         AsxF5BO2Si5w89hp0R4rQhgHzTwcI52eXdL/hl6Ml1k0Yrg8Of8y1uCVInnpmn5rFVjf
         3oTT729EyFIEH9dgu2HtEdVwLxFPl6u1cIGmvydJd0JdWHPGlOFLF2/5odOjTDj5a6iZ
         DOVrsXvntzl3SUggtFJEZ5HXM78BRUbxZVwZzrVdWrjtww3CjsA82CEY5D/iFe0ETvHZ
         Rdc6pAGXK8aWo1D+szNqs7kVER1gMHr1h16/kHzQcZO/HAoDbmCGQ4JZKOf3W9iDNcFG
         iSfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wXYNzIJYUGU5MBFxpzklLT7iEuI3mg9pjiUij/ROV0Q=;
        b=CHhMYW40hJdSYapV/jRiS5eA0gBv/oFyO2YvTC7YM/uIIg21vAo2FWrSt6Qinv2SnM
         s2+mZY8LKz81qfRxv9QVw37RCQ/vxrV5y+ZqXFSxn8oqdvIBc+AGF36GYS8QbadcactL
         qkosQqNIvdFO1Bfs4WXfphvGSoqKPb4JjIr0Tq+HFF7sWOlOdEqUt6N6B/OZFe2O2n51
         O/IcfKl5Doz1M9tjRMeixpJmnwKjZnnYeSte+EaFsK92FEfVHN896C1WXMz4sxJE2+OS
         xbOIf2vMg8u2btGWUOL88vl6EaIDM+2Sfj7ItzbF6jfWHH/0O3ji9TuDEciIQ5FafqUB
         yeaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=I1GTcHYt;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wXYNzIJYUGU5MBFxpzklLT7iEuI3mg9pjiUij/ROV0Q=;
        b=AOkboa+DfMfEC4qiDSGbVhzHc+IdjR184JcHVdKJDx+IpCgSyRcshPqmHLgOfCU8Gm
         YAKZWZbTaAwU/Y6L9HRsnwIzLfOcKRt7nUv2z+X3KSxP7ojnZrg7DFoH3amrlYJEoDCL
         Zfz4AwKpzqYYWYqbnOjXoNGSygd5mwu5OKcdkDzdoLEFeR3cdzdUfowo/ygYTzHLBv9e
         37Slns97QZ5MwJx+WhArynGQF8MxElugudlHvse6GF5ar1P4+sKlKVY0n2TwUkp+VB2J
         qcscYAkRHNSO44vF+P1U3hA5coT4B+NDDpkMhsr1my1GqFGvIfPYfC1aELmCxmx53Bk5
         2D8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wXYNzIJYUGU5MBFxpzklLT7iEuI3mg9pjiUij/ROV0Q=;
        b=x2rlGRG07JKSk0QgECh0JDrzH0mQHT2+2D/bsq2JR5KoAGwjDP+35h6Hl0hJltA9hd
         7murITY+3qkxDmN/hqKUcaJK4SeUKzhrjNmmTYUlIMs6ZyV9Ry4lxN4ZfFQNBhvcQXIY
         +Yfz63LnCiZVd9BjgDJ0JMED+NmEq/AjlmyC3G3FhoNBmRnoGoHT1Ys5+9e3jm8dWTV2
         NK3Qf+mUa5Ly/D6ANK8xbk0CqNvdKpXDY07yYuzOSRfJN4XoZXDAhgDMAtrHClcZJ3pM
         ZJr4XyT/dxS807KgNVWxtKTGQgKDhD/Adpr3IwqQ1UTil8PZf+0FKSIwwOPuhMJN34JI
         FhTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0VTX2ZZkV/ypyNWADzcyGk3g6iK65jWcfJCg+WSvjuFcNdJKmi
	O8SODs4PFmcBOcbrsad8Yjo=
X-Google-Smtp-Source: AMsMyM63r42Nx1+knZby8tdZbAa8a7wPWaj+ZN6VLBF/LxwAz/wNo4Nem+jnQI9FnjlbT+ooFOIVuA==
X-Received: by 2002:a02:cf17:0:b0:375:6b39:c553 with SMTP id q23-20020a02cf17000000b003756b39c553mr27250556jar.4.1668024056596;
        Wed, 09 Nov 2022 12:00:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:628e:0:b0:358:3055:3faa with SMTP id d136-20020a02628e000000b0035830553faals4053312jac.6.-pod-prod-gmail;
 Wed, 09 Nov 2022 12:00:56 -0800 (PST)
X-Received: by 2002:a02:19c1:0:b0:36a:1bbd:47cb with SMTP id b184-20020a0219c1000000b0036a1bbd47cbmr35260659jab.198.1668024055991;
        Wed, 09 Nov 2022 12:00:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024055; cv=none;
        d=google.com; s=arc-20160816;
        b=zObKVaxM0QujL1iwF91Io2rduqspt4P2AyGsk3Z1I0bCCFBC0mtx/uVsgJ1awvwFNQ
         Rz8VD0WoiFYBZ2jLug+lYFlXwoA9ROwKomAX88HoQ5PjumnWhRFjcntzfy1xbh2uwNah
         8jWSFydK7I6PrTgtIIbuVZpjAKEkGB0K2lcfrITgfjUxvCDbTtMjqcbrUGlrohDnFx8/
         0jySrKdpPrULCIGC9ykJLjz2qZSM4pq8LO8rKEv/mU5e5YCHmmWAO5L9aMohCsyg9jZG
         ZhigaiCEXFiAsPlmcMpGXOpBKxMqvz4C3xqLtbYJ7RXRqf9c7zQ9iuqJ0wGpr7AfcAn0
         vs5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=t5tPw3hkeTB324+bIPHjvhZ9LhWv7TTl0XHczdtESK4=;
        b=RQ0zkQ2KOH+g0NeS4ogf5+EPnbFFrNPrYOJxBs+/BsKn7HwmvQB6bQvUYzzmphYKtS
         3lbmw3xpioyvlUWGcR3pF9MzzYFB3wjceqd0SffsITwpUb0oNNb7U7Q33ZBTy6gQ3aUV
         dz+wh9emSpKUpxYxg/W53+2HVHGSRDOf6tcL7sxAd+wQXTs6gwTi6L5PIxIBJ/ID/lOf
         olFzAMMfw2ZpZzkliApGAYLXG2isYag0usw9YwMjJHuBHA1hQTJLguxPo9p5wmfvhhPy
         eMq/lEwaly8q9ulpNC0meIvGb6vBtJQhkA7LrMDFUaFKlPH0Kk+RJ/aOa445Dq85mzi5
         D0TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=I1GTcHYt;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id u18-20020a02cb92000000b0035a25c888bcsi597169jap.2.2022.11.09.12.00.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:55 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id b11so17708337pjp.2
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:55 -0800 (PST)
X-Received: by 2002:a17:903:40d2:b0:186:6f1d:608c with SMTP id t18-20020a17090340d200b001866f1d608cmr63246987pld.52.1668024055366;
        Wed, 09 Nov 2022 12:00:55 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id l5-20020a622505000000b0056be1581126sm8965936pfl.143.2022.11.09.12.00.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Petr Mladek <pmladek@suse.com>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-doc@vger.kernel.org,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 5/6] panic: Introduce warn_limit
Date: Wed,  9 Nov 2022 12:00:48 -0800
Message-Id: <20221109200050.3400857-5-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2660; h=from:subject; bh=Rm+lJ6u++jsmLEQkzPRQ5ICHP8+KAUDhfRVS5zjHPJE=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbwcHBlBplI6+7kNyZcKwP+Sml/277Z4LaSTf0u 9eRZjBiJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG8AAKCRCJcvTf3G3AJh1aD/ 9xflRviDrYBqPld0yVa3h4GYZgnj9k/BudvGLDeZgQ06918EaiTlebzGcxbEnFK/Au8S4maFKSwALy TFXCJWRYa99rQHPpbupXdfXoEa5jCKoNbrmLRQfssWJeQK8sCfP2uSAsDa7MVpgHm3DdjJrDhPsGcj IKq2X6+Bp8tvNslJm2CGJGLmdxv8catsbbA4u3nnxUyVoC4TSGDGnT/0qgrcmjnzD7FgJ/0zzWkS/z JO9QWa92/1FFddRhRdTYL4i/Zb8DcTUf1Zs/FFAPPy2YVN5nDMdBZmnRfHu8MRnhCV6EvaIATcF1mv hzaDeqIB5a6IHWQt1o3fkIhnTClQpvKn5KGSbt3WdCQL3UIvDQyDPPb7SkleOAHv7JUtDilQwn0CI/ ITPXTBIFuT9wcUQISWWb5hK2LsGhlqoIVigQx1I35f+TLjd13Jb9Kw8BuOuFKWyY9jxsBKl0t7g5VQ 7RpZubqS/13Dn6lCOtASVrfQ4hBlefUop5zVkeIOa1td6YoKFEgu0wNjV19haFm/xfZLZkEbIkafel yZHFuA5KEjrUh9vxzO6KXOhJv9bya2JKJ37BPoZCdFEPtjynjSfxcICwraUUOg8KX06Yz/OVFnktJa GgDhFRMJXgvpB4ir9DCwhcXC2BmPk900nMHvxiJUihERg0jE+/9VpX8wHjIg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=I1GTcHYt;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

Like oops_limit, add warn_limit for limiting the number of warnings when
panic_on_warn is not set.

Cc: Jonathan Corbet <corbet@lwn.net>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Baolin Wang <baolin.wang@linux.alibaba.com>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Eric Biggers <ebiggers@google.com>
Cc: Huang Ying <ying.huang@intel.com>
Cc: Petr Mladek <pmladek@suse.com>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: linux-doc@vger.kernel.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 Documentation/admin-guide/sysctl/kernel.rst |  9 +++++++++
 kernel/panic.c                              | 13 +++++++++++++
 2 files changed, 22 insertions(+)

diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
index 09f3fb2f8585..c385d5319cdf 100644
--- a/Documentation/admin-guide/sysctl/kernel.rst
+++ b/Documentation/admin-guide/sysctl/kernel.rst
@@ -1508,6 +1508,15 @@ entry will default to 2 instead of 0.
 2 Unprivileged calls to ``bpf()`` are disabled
 = =============================================================
 
+
+warn_limit
+==========
+
+Number of kernel warnings after which the kernel should panic when
+``panic_on_warn`` is not set. Setting this to 0 or 1 has the same effect
+as setting ``panic_on_warn=1``.
+
+
 watchdog
 ========
 
diff --git a/kernel/panic.c b/kernel/panic.c
index 3afd234767bc..b235fa4a6fc8 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -58,6 +58,7 @@ bool crash_kexec_post_notifiers;
 int panic_on_warn __read_mostly;
 unsigned long panic_on_taint;
 bool panic_on_taint_nousertaint = false;
+static unsigned int warn_limit __read_mostly = 10000;
 
 int panic_timeout = CONFIG_PANIC_TIMEOUT;
 EXPORT_SYMBOL_GPL(panic_timeout);
@@ -88,6 +89,13 @@ static struct ctl_table kern_panic_table[] = {
 		.extra2         = SYSCTL_ONE,
 	},
 #endif
+	{
+		.procname       = "warn_limit",
+		.data           = &warn_limit,
+		.maxlen         = sizeof(warn_limit),
+		.mode           = 0644,
+		.proc_handler   = proc_douintvec,
+	},
 	{ }
 };
 
@@ -203,8 +211,13 @@ static void panic_print_sys_info(bool console_flush)
 
 void check_panic_on_warn(const char *reason)
 {
+	static atomic_t warn_count = ATOMIC_INIT(0);
+
 	if (panic_on_warn)
 		panic("%s: panic_on_warn set ...\n", reason);
+
+	if (atomic_inc_return(&warn_count) >= READ_ONCE(warn_limit))
+		panic("Warned too often (warn_limit is %d)", warn_limit);
 }
 
 /**
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109200050.3400857-5-keescook%40chromium.org.
