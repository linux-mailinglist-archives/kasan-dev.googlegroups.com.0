Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBMOTO7AMGQE75JOYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CB40A4D7F8
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:26 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4394c489babsf29779865e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080326; cv=pass;
        d=google.com; s=arc-20240605;
        b=O4t4gcWjYq6RZylwg2YzXGGtzfHxc/SZcJ/Z/kvkHW9plf3bDNf+gNQdnlVCBkLyAf
         bCsKaKC/Gtn8PiJb/OZ4FJHqP6gMfMeL3ucO/Q/pEQ4JYe271Lm7Y2uAO+14GACZaB5O
         Shr/9HeL15I7nbGmvq6qOR/nlONXJ6Chc+pJZ2Rde9K4lqwfOwPtW6AqNidXHHbVez8+
         +o0Zu7RhdTBkYRMS8bbFAnXrAic383Z4Edayn8NHyq13ZlRm9+iyeGhjnHtFPkYwqEnQ
         lPMWTtCIkHXJlaFGzadzQQLV2kA3rsVaWvrepVum2pE879MSQ4ZmLWIrffHxfgRHY922
         MnIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=O5npT3zEL6iW4pc3yUfwlFHGgJgxTPAMr5oEDHoZzco=;
        fh=DuO0VTNYBVeG8fYdgOtOu0shPq9paJOfOvesl66PLwc=;
        b=YuNMCxUcH7WCvKckPShDsKcvGV7OLKb7RB05YHWl+5vc8f1z+ytcHnRemkuT5xf7Ou
         7Iaxweb4kVnwe9XdMq8/L2ncIj01MhyOnzLzgjnIynXhFeOjJJE0pAqKx7fa1lm6E9oA
         Vvits7SJP3oPqzIMBXwxRTz/eJkUF9o1PJeCrMadIDVOZUr9f5KTutLUOvDQ7AvNusk1
         n7aV07L3PiokJoZFoMZfPjQRPUUTQGtPzPpjVX1XIqDKnmsguezpqUDeMl6X+WyZ6mlj
         HdvMn17D2wH/g1yaQlpZooQpANr7sXQCN8/uZtBoYcw4o5l3KTfcB67A7LreEl26Jb43
         UbtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MA9QLROK;
       spf=pass (google.com: domain of 3asfgzwukce8vcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3AsfGZwUKCe8VcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080326; x=1741685126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=O5npT3zEL6iW4pc3yUfwlFHGgJgxTPAMr5oEDHoZzco=;
        b=jEdqZM82RQ+xn16dA6Q9vtNH88I3xBoDwqITEbmir+WpsJb4JNPN/TG0eRIM6Uk8L4
         757Y8V2fX40TdgelrpK3CU3/aF5zarcXmV0ec4uCCT5KwTfpNPaDravBB5c0BykkBXNT
         3YsLn7771nqKHEXa1ZfHDtPuJ7sNIL6zpE1l6/g6NchsGqK2GiG70jVT5Znb6vG/4ccB
         kph8si6fp2DbZX/cwzcAcLwDT+Di5hC2/LakKfS0m3a2/Vo0uAzObc6Pf0hxrcSEeNeZ
         2XWCdXLeXhLekTeowMkp7kNq257w8M6mYXqMXB2l+5NM6N8IUL3tWEO8m5vA/J1DLCxK
         azYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080326; x=1741685126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O5npT3zEL6iW4pc3yUfwlFHGgJgxTPAMr5oEDHoZzco=;
        b=fFR8S4y5ye0/rRsAw2qarbHMawDqdc7V/eYae4HeNJCsTLtyY7GAmQkbCh2MWcrAZ7
         lilIvVlNxVHyVkAxAv0ApFAymwZthwbTFfHvXc6/gv4DBHz7gvH0B+y/p24wyz0Z8+Zp
         lyK2OhRwI5u0oG05eErNQL7XmQDgGBGVK1tmAnhTcU0CIzL1G/Dz4+UTB2qHti75EixF
         qwRNOgd9LmDi2IPleKxPRYZgTLEY+YZdEwsxldwnK9/5U8CrY89rgrn4imgpHQ14Risx
         do2+v8hVpsQI7pITAh+STVSHvFFH96FTPtfibfgcDh6bTqKbB8uzH2NO4KkrDWVyIhvU
         7Z1g==
X-Forwarded-Encrypted: i=2; AJvYcCWKkFS1WMHkl0fu53XPJmdy8UrvavzSo8vd7Iu5j2qOErGQ7ZHD/xe+4eP8WkmgCywjjWJqPw==@lfdr.de
X-Gm-Message-State: AOJu0Yyzo2A+8oU0v70GEDovzrAPfN6VZyOQJXPBRleztEggiBwXCmEp
	G60SVhEGJBZDHEC8p05QQFyR0OeB8kGLQbiCaw6x4xEusjB1CV+n
X-Google-Smtp-Source: AGHT+IFSiA6UHvzcI1KbT18PzJpEJMujsWj/voYLTOjcEaTwuuMPP4iFvqCk8rRyZrwkk1Mw0FutOA==
X-Received: by 2002:a05:600c:1c1a:b0:43b:ce3d:1278 with SMTP id 5b1f17b1804b1-43bce3d1343mr4698865e9.31.1741080325472;
        Tue, 04 Mar 2025 01:25:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFM5KVSWrneyoxlgGhSjpiNY1rf7KC0bE53/XJhO2sf6g==
Received: by 2002:a05:600c:1884:b0:43b:c27e:601c with SMTP id
 5b1f17b1804b1-43bc27e60b0ls7556675e9.2.-pod-prod-06-eu; Tue, 04 Mar 2025
 01:25:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWb0423iscPk0OusdZAq+nzSRjzUYZIhbQUVVNkeUN5U2atm3G08ob+5rVV0GpjM5/1wFKHpDOSAyg=@googlegroups.com
X-Received: by 2002:a05:600c:198c:b0:439:9ac3:a8b3 with SMTP id 5b1f17b1804b1-43ba67130d3mr138398795e9.18.1741080322893;
        Tue, 04 Mar 2025 01:25:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080322; cv=none;
        d=google.com; s=arc-20240605;
        b=M3hAHwOz1mhGVe/OarhJeAXCW0Qv5SnIw9PkgMqqptnWsfHcdWVvK8N4OibghXEAwc
         Dj8Bbd1s2PX0+8u/V6yckaf32K/hPvmzbkG8avYSZ51sKU69uZgaU/P0n+s48r00JclC
         ctxspRx53qbPBcnoJ+BMI+YqtL1a2Aw6FsQi07Oety9f/Zo4gTMwM18X+OPMF8MAyekv
         25mrlcyg/VFq9W+MhvzPfIe9q6x1RunF5GAO2Wgv+6iC5+GBLaROkDP6ZrH6GChru5cF
         eXgRhPjQjba9Tc+iD90sfi0t0dCwl3fF+MbMT4macZ6mDxpJ+SuEq/H5YxswextcTrVG
         ax+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Pp+E8sKoonvgdGAMVoQXSiL/gMXgRdJZHQEkz4wDB8k=;
        fh=qguhvrWUzYz5DqFBxb137zFBiLXvN+IosTlgj960C+A=;
        b=kyhyCjbAwZR0iDTuNNxY84u/meytUF6jJr9YsW3YR6jZQybpCFILUzSegPSP8W6DdE
         OlgR1o6WFzjqwmYlyTkXQ1ZdlySed9ZnvdAbk7LSnXcMWqq15IDw7h/ipSilmlVeS/o4
         22NhflgCt+bV8+r/NEEBWARFdMnh5l7YtgoStYywqp8TDSKqzr57rzes4lPuJbIhvOlp
         hscH1YtIaXw3FHEhbNb2b2NhYXUfI+R/cUJAP4nGN9faDpH+pQApZZ8NttL/dVEBBv9c
         gcUwxS0cjgIBPOghc55m4gLzEPeDnwMf4gi8auk6MSb2g0UJlu0lZ/A4/9LIsEUBRAK7
         1hFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MA9QLROK;
       spf=pass (google.com: domain of 3asfgzwukce8vcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3AsfGZwUKCe8VcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc13b8a9si394505e9.1.2025.03.04.01.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3asfgzwukce8vcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5e496b51f38so6578430a12.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXhQFzD2bAJ+PMfZy2egzer0cnTlLcXD6VwWq7QTMCBcg8u0cZ2O8H1iXrIYezzNP1WDr33HqDBwUI=@googlegroups.com
X-Received: from edpr11.prod.google.com ([2002:aa7:c14b:0:b0:5dc:578d:62e9])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3487:b0:5de:3478:269b
 with SMTP id 4fb4d7f45d1cf-5e4d6b75ef2mr15880706a12.32.1741080322290; Tue, 04
 Mar 2025 01:25:22 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:04 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-6-elver@google.com>
Subject: [PATCH v2 05/34] checkpatch: Warn about capability_unsafe() without comment
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MA9QLROK;       spf=pass
 (google.com: domain of 3asfgzwukce8vcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3AsfGZwUKCe8VcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

Warn about applications of capability_unsafe() without a comment, to
encourage documenting the reasoning behind why it was deemed safe.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/checkpatch.pl | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index 7b28ad331742..c28efdb1d404 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -6693,6 +6693,14 @@ sub process {
 			}
 		}
 
+# check for capability_unsafe without a comment.
+		if ($line =~ /\bcapability_unsafe\b/) {
+			if (!ctx_has_comment($first_line, $linenr)) {
+				WARN("CAPABILITY_UNSAFE",
+				     "capability_unsafe without comment\n" . $herecurr);
+			}
+		}
+
 # check of hardware specific defines
 		if ($line =~ m@^.\s*\#\s*if.*\b(__i386__|__powerpc64__|__sun__|__s390x__)\b@ && $realfile !~ m@include/asm-@) {
 			CHK("ARCH_DEFINES",
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-6-elver%40google.com.
