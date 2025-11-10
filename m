Return-Path: <kasan-dev+bncBD53XBUFWQDBBLNJZDEAMGQEW5QGYZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 36A7EC47FAD
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:03 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-63e35e48a1asf4383601d50.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792622; cv=pass;
        d=google.com; s=arc-20240605;
        b=NRJAVlCXb5i46FLp/Gxiqu3Ns2SPFAZbNKdELl3XXTWwKqC3ebjYfYTaL3vz2zMSh3
         d3tWZnZeQoWcr/kRYsnheAPDZolkI9QzLTHvyhUU6qo0QijVIZyhQJyjezqzibxEUV6m
         +XhHMbyzxpqI1hAq3FqJWNHdlhqWW6xf0KUalri31Svac15k0CZFWWa5vNL+yISN8OOE
         VeAFV/3vseIY5hVW7GRj1L5Q9C/0DHDnCzOEgnSEiCi1AKGVt5Hkl4H4YMkB6kb/xpsv
         L4KAp7DeSpRGpvVO1Eq0OaoLrNJleS73WBEMShdqBPBzy/8gjYFM9AMEjstNRj/1+Xid
         FHVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Ibea4xHvLbMb5WzryeTRqfycFalWpeYVpXlMMc09Pns=;
        fh=T5cBTiLjTNJpmF3hPiYO6lHS//Hju39CKNgoOU1diMg=;
        b=ENVhEedfbPjLOCaI7jQdqhQ2mM+4BL0rOmKF58uv4wJXMQyfRs2Gla8NWPyQOG0wD6
         xWUcpyRbPKkVNqap4VLdiNnEj5f/1VbU756mUcZBjpjE+vhakLK/an9AKF6d1Eplejog
         CFnnNkR6dofsZ/BN1b+vngJPJk8CL9OdSaRFBKut/GDQLFd7DUKQzt8E+lLnN9fYguyM
         no2eGuAORUibBWlxkYWNaO5XFBjoAi7RkEnHSzCtOdWt7ijkd3SKwmTbNshRaOH6/asc
         2R8wbPkyn2mKRdCPzIgZaAPpqiPxK4wbqyzlSQpGo4j49FNsaeeFdys/c2g3FmWa+oN2
         3FGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ROsR+SxY;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792622; x=1763397422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ibea4xHvLbMb5WzryeTRqfycFalWpeYVpXlMMc09Pns=;
        b=PqA0G5Zo5BAKF1Bya6URwRHgGTBxEIjjnR6DAHPDr285GniagppI+FanNuWexEnemw
         8Wo9Own4DHwEeCTI/LuM5lev9iy0XRALgggGyVnwnJ3J79ym8vPFxbuY0lJXXHbqSVq8
         ke0NIzimVykpCqPuQTUL5ZWjW4WMJR5+PRleev23X0hJfcOvqASXcWmIav6fjD9xPRcb
         5Ql041YKkgJvRHZMsp3t+9h+JGh2eIekvH78MdGwXPSK2FdFGz8ySFpCyHsiCKgSwl/P
         pknSa5M+FZQvMOWWkEudpj/55E8tjn95D12hF5wNre1qvyrdPOA/zEEiURc22z9kaYC7
         cVkg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792622; x=1763397422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Ibea4xHvLbMb5WzryeTRqfycFalWpeYVpXlMMc09Pns=;
        b=fCieou3c/lpA0bofDZRB+/uSDCE47gzBB2zU+/s9lK2GrKfbzS1FjarqH711ka1VYQ
         MF2n4GOh/1aE9reME5btv31ybBQW5FBTc9dPRTFbwphsw1BkrLcVFvlWH6LpvtvXyPrt
         wBdwBZuQxGIbUsgNuqwcxpv4ck+REu05RShrDj0eh9EarX28wHCMOwMu4JvTZ3vFDm/U
         x3nYs21gdpxI05Fo50i5O+CIgJwhlzxwu7ErjRZnJv9xz6qkBVeu17hql0jFe5+rEZlN
         HOaMbqMYlKJlWOQbm5XPZVgAibTJqUJt1MuLYvhSorszMdgKQaV9U/kTpy+oGa+TzYV7
         vweg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792622; x=1763397422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ibea4xHvLbMb5WzryeTRqfycFalWpeYVpXlMMc09Pns=;
        b=tH2wuT8VQKesZ3GwbNzLIxrsQaPRLK3xNGt+l1uSePGskTxtlCYaYVPRyNG8YAI1CI
         GeAh8OqsQRJT7arIqqoqQOokw2sYxJg9iYqBVZMxxpRys4UX95mpm4HMrWn2+HZMe9B4
         PQWms3cLtdFxZEKzaTR+ryiJXKfWsO79Cn0g/WoQktqoJkAne9PvGCqkKwZobBi+6Tn1
         pFu4d/OrwGbTUFpANqL2y/EqbU2T/szVd1KbPa9OXtu2xz2QDjrvBVvPUWkuVRA7Gw5m
         ddFqrgT94CgVx1MbDShPo2yVSLenhrZZfkjprpPhvc+LQYUe4edsIjI8SILG2t+bF7I5
         WHrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCXjgxRyVIa0b9YFSGhueCxTpscMQMXSmT1SCqbpiQ1+DbRVXiBoPXom7E4lzOWVarv5GYZg==@lfdr.de
X-Gm-Message-State: AOJu0YzimoWxNlLxsOBLbXbeRQ1zz2w3DF8p0T9ub3iKPOzySEdjk/iJ
	QukJ+KYix8hAYklyCtktFNTdMUHWZY/swNTbYG/137/Gp06/vxtXalcX
X-Google-Smtp-Source: AGHT+IHaes8+cW8TF7nU4U2usVg30fVoW/E2e1DNr9TlsgadM1js2ElLn7abnLWuXCYHHVBkgyu6CQ==
X-Received: by 2002:a53:b10d:0:b0:63f:b4d8:1f4b with SMTP id 956f58d0204a3-640d45a9290mr5821160d50.33.1762792621549;
        Mon, 10 Nov 2025 08:37:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZxqsrZYF/BWJVjeIhCbBVRwhNEi9h3YFbb+VdZXcbK2Q=="
Received: by 2002:a05:690e:1547:20b0:63f:9498:be0b with SMTP id
 956f58d0204a3-640b567b21fls4546408d50.2.-pod-prod-06-us; Mon, 10 Nov 2025
 08:37:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW+e7UBApfBwC2iH/+L5gUOFKUYKQ/cxE9G2GwKIfnsoZNd/aI1B8KMte+u8SRyPStNXYDBylwev90=@googlegroups.com
X-Received: by 2002:a53:d01c:0:b0:63f:af64:ae5a with SMTP id 956f58d0204a3-640d45d1d59mr6380667d50.58.1762792620437;
        Mon, 10 Nov 2025 08:37:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792620; cv=none;
        d=google.com; s=arc-20240605;
        b=LB0RtInAu4AvsKgrOUlDSK2iskxGn/q5q975rH+vLhJaiUDqOieefBf7NaeCZVkPVE
         +OY9Up+WNwd7BhUsnUmuQzYRwpTenG0OTrsaMo8cJOhzWUUAIa4U7PWP1For1NSQftRb
         LqOGK2DJgHRlJi3N6vymij60cX4ivTowBDn2fL8ADUak+l9ftJxrRBDPK1AiQSBzJ7sH
         WGbfeOUbV+ZwKnJfUU1Lq3gN23lRv9vy0YyLoha6R+kG3TFgEbUYN53wwHxo8gXQ5sCI
         EtKGndJUz40ogztpXaIsWXzYtsPgKSSHDvoGCvQGQLqgADJwjBK32aHgT7JcsKj0jAOX
         Cp6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=3XURKXnAmZnyauprzc95LAi6JcC8IVZIZCwVkARWD9E=;
        fh=yLriT8YVO83D+M0HL/SCd9NRLs4s1UsL5Biyc7kIJJY=;
        b=LLLbljhzh2hG2wff0zyBKdH61Ov8VqVIKBdltjcho+B6OALNzTWyAxSFBQUmqWONTE
         kQCR9GqoDwl9kyPFd/N66ehUAboo291AlDdSm780ZhqYKhvp3xcvMiMaHpb9fif7hyvI
         rs1eCH/eE/8SAwFELIIYgTcRXEeBSdkZ46y505zAQvBhiWBwZi80Q5ATYJlEFONOwaH9
         a29fG43xCBKLKQKAvcEH8ppKqWdTFhFnaogmMR+EOARIvTAd8sljPKGNHqNK0eK5YGCE
         MQGoWswejF/xvO1tOg5aynE+ue4k+47CYDFvsmkxPdUdlIUInp3MH3fAI9p1al7MHRSr
         WJ5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ROsR+SxY;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-640b5bb93fesi232808d50.0.2025.11.10.08.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:00 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-7a59ec9bef4so3560460b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUEChNvVOb1xo7/3krZgVt1zXRvaODJzbxRn0jopL1Z6r0+gNpsDSPkExuswoLktdH87B2wXyYP3eY=@googlegroups.com
X-Gm-Gg: ASbGncvgex7nInjbE42u0Kzp6vTGSz4wy/IccHP3wbtvvOwbsSIgR/qUoK3W7TXbaGw
	FBywaBH0oqd2L37/1jR1giFgSZFt/J/hTDS20dQNxu4xhsdvW0wd5eJsMVtoU05Um8dZH/qlho1
	mhTPnzCoSsseUIetzS1AkwmPhvDSHbiQS2YrxYxLDYUYDkT9+5H3IIBROVkYsU6j2V8+epGfZbv
	t9/TDaiPcdoQTz8rvT4LlRQDUJPWAwbgJ5CJFlDfWPjJURSquIXzd5/PYDFaaU6PhqoitHczrKY
	D4RZOFx0oilWqIOpNQJY1jW+a7EKOEDMMLFW70uX8HRbNmQ33QyD6eSdywYScqK/Ni5Z0ndYpoV
	QvSrY+GO5mae8T/InYd2CyvUkn7F51c5VxyT1JGAyod/m5rA7vAkZT6LWMsx0QqGxYVI6OnSLvb
	o9kLo9fUM5AGn0q80deyut/A==
X-Received: by 2002:a05:6a21:681:b0:334:97a6:17f2 with SMTP id adf61e73a8af0-353a18b7968mr11417885637.14.1762792619356;
        Mon, 10 Nov 2025 08:36:59 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-ba900eab130sm13106983a12.25.2025.11.10.08.36.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:36:58 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 04/27] mm/ksw: add build system support
Date: Tue, 11 Nov 2025 00:35:59 +0800
Message-ID: <20251110163634.3686676-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ROsR+SxY;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Add Kconfig and Makefile infrastructure.

The implementation is located under `mm/kstackwatch/`.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch.h |  5 +++++
 mm/Kconfig                  |  1 +
 mm/Makefile                 |  1 +
 mm/kstackwatch/Kconfig      | 14 ++++++++++++++
 mm/kstackwatch/Makefile     |  2 ++
 mm/kstackwatch/kernel.c     | 23 +++++++++++++++++++++++
 mm/kstackwatch/stack.c      |  1 +
 mm/kstackwatch/watch.c      |  1 +
 8 files changed, 48 insertions(+)
 create mode 100644 include/linux/kstackwatch.h
 create mode 100644 mm/kstackwatch/Kconfig
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/watch.c

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
new file mode 100644
index 000000000000..0273ef478a26
--- /dev/null
+++ b/include/linux/kstackwatch.h
@@ -0,0 +1,5 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _KSTACKWATCH_H
+#define _KSTACKWATCH_H
+
+#endif /* _KSTACKWATCH_H */
diff --git a/mm/Kconfig b/mm/Kconfig
index 0e26f4fc8717..61d4e6edadf2 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -1373,5 +1373,6 @@ config FIND_NORMAL_PAGE
 	def_bool n
 
 source "mm/damon/Kconfig"
+source "mm/kstackwatch/Kconfig"
 
 endmenu
diff --git a/mm/Makefile b/mm/Makefile
index 21abb3353550..efc101816f00 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -92,6 +92,7 @@ obj-$(CONFIG_PAGE_POISONING) += page_poison.o
 obj-$(CONFIG_KASAN)	+= kasan/
 obj-$(CONFIG_KFENCE) += kfence/
 obj-$(CONFIG_KMSAN)	+= kmsan/
+obj-$(CONFIG_KSTACKWATCH)	+= kstackwatch/
 obj-$(CONFIG_FAILSLAB) += failslab.o
 obj-$(CONFIG_FAIL_PAGE_ALLOC) += fail_page_alloc.o
 obj-$(CONFIG_MEMTEST)		+= memtest.o
diff --git a/mm/kstackwatch/Kconfig b/mm/kstackwatch/Kconfig
new file mode 100644
index 000000000000..496caf264f35
--- /dev/null
+++ b/mm/kstackwatch/Kconfig
@@ -0,0 +1,14 @@
+config KSTACKWATCH
+	bool "Kernel Stack Watch"
+	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE && STACKTRACE
+	help
+	  A lightweight real-time debugging tool to detect stack corruption
+	  and abnormal stack usage patterns in the kernel. It monitors stack
+	  boundaries and detects overwrites in real time using hardware
+	  breakpoints and probe-based instrumentation.
+
+	  This feature is intended for kernel developers or advanced users
+	  diagnosing rare stack overflow or memory corruption bugs. It may
+	  introduce minor overhead during runtime monitoring.
+
+	  If unsure, say N.
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
new file mode 100644
index 000000000000..c99c621eac02
--- /dev/null
+++ b/mm/kstackwatch/Makefile
@@ -0,0 +1,2 @@
+obj-$(CONFIG_KSTACKWATCH)	+= kstackwatch.o
+kstackwatch-y := kernel.o stack.o watch.o
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
new file mode 100644
index 000000000000..78f1d019225f
--- /dev/null
+++ b/mm/kstackwatch/kernel.c
@@ -0,0 +1,23 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/module.h>
+
+static int __init kstackwatch_init(void)
+{
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_exit(void)
+{
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_init);
+module_exit(kstackwatch_exit);
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Kernel Stack Watch");
+MODULE_LICENSE("GPL");
+
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/stack.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/watch.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-5-wangjinchao600%40gmail.com.
