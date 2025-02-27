Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB43QC7AMGQEID4E26I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 92C1AA4762F
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 08:00:25 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2fc3e239675sf2253708a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 23:00:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740639624; cv=pass;
        d=google.com; s=arc-20240605;
        b=iIGFhsvKql4uhNaj+hWIZjf5QVrWCNYegweij9ShHIOXYhme7k64h4gFdeXvSb19ci
         0rbWIyhKnw0cufzP7Ri/NsExTWx+Vx0nPABuhebVP6HOy5e4BdFOSY6lUESdt1ZmfwN4
         BlzpNg8qqGgaI5qU8gvlvT7ntBAva3w1teZMrMMoXpPiLyZhPci9JT7vDbiV3iaifEJJ
         33k54I4yRjZ5P3Wdu1zEZVnf7pXuc38qhGKWjqR0ronRITWb1NfN74/8PAN+a/2Pu98u
         Mmh9IrGPXgZAk0BDFZRhtLXV9gvoBXIrAGIBWqK/ZGwfYNqjD4kEl284Oi0Nof4e+B+R
         xTfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pWWJlO17Lv/qYouLXo9ssE2MStGyz+nU6TxI7R3borQ=;
        fh=iEzutKplXy9SPt/G5EHlTzX2lXxqrDaL6uy3DsPjHHs=;
        b=YAxmHiCwT4LEECM9eO2GwOtqOG4uGm4dpocz2PSQh8KBdRrO0uefk8zuZxLM9GXGDE
         IcGidPi4AfDfYBM6bCEnRXYyRiqPWc5NyNkbfeIXQWmGC8USrFT/ynGAHBKATA0rkSST
         oJZ5unkONBwLNBgoLYlaD5//h4VNkdo3bDNVGmHlZen9qItyTFlOnzHqah6zaxZ0yrtb
         3COT7Vf3oYnXCEtPnX+YXWCi45pCh2NfplHx2NmN/gmg99VmtTK4S1MLoxDFDv4zPllm
         itcYNNlOMDiHMqcCRmRS7V3/FAH+fUVyZthO+64yOLFVTGlFO2ubZwAzVRLvqtkZbliJ
         id+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wQUBSCy1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740639624; x=1741244424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pWWJlO17Lv/qYouLXo9ssE2MStGyz+nU6TxI7R3borQ=;
        b=LyMNJECFnU3qruelsS0NvOlJ+JtQqFUpPDWoNvL9iqk/BfXuzcIzhtuEX+QVsKkrnQ
         26z2ei1SfMDrWDiRwJufT3iTma+D6U7a9m+oxjD0eZJE723g4I3g0gpCzRqDBv3ruK+S
         7Xx05HiIvCKcE2jDx+o0G2QocNheHsqLlOlu3LCh3wqJduWIZ5eNJ3vwUC/C3hx0b18i
         YUUjBeTdViSGi/0s7tDBo+pT5sjXFzS/mx2V24/WBN2YxLEyZ+25RcvUOkjgQFs1aWHV
         TuUp+IDVrMVeiVaUkRcFefxobQwTajBVU/3XeKM8fFp4hkOoJyVlTz7fVrbikVALQ1WS
         8jPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740639624; x=1741244424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pWWJlO17Lv/qYouLXo9ssE2MStGyz+nU6TxI7R3borQ=;
        b=jnbKWZ+esa1m5yHKaUWcUtOJokTXMu1G3W7wdEVLK5s4XH/ZchizYmO11uiOAbdAQr
         GU6htND7Jshu6pwJWCH6Nw1dOLRheekR75VPhnns/pXLqeR2sEPb14H1M9qA7CNBheR3
         tXXYCXBhSMwlCMYVClYH9Sk7Sr91ETBuMnnUPbcANxeS6GBvrQ+qJlyO3iUc+SffAlba
         n0GrNfJ+hmBMdIecJMnJMsiM08trxqqnaAQdb3MiHURn7eYNYC4xXTL+xgwt1U6i9o4G
         37/2Ail9idz5KHoBr5gPpv4VvK6y+S502J5TN+Zpu6fKSIO25kqucgdL/iuQH97GWEHW
         /xNw==
X-Forwarded-Encrypted: i=2; AJvYcCVxEo//yGt0dRc7VkQi1clZ5czpNZFY0wv9EY9TZEieapBOvDBH+21U2txbCGkS+D1HBpEDKA==@lfdr.de
X-Gm-Message-State: AOJu0YwvMgbFLD7hCd8q4jo/8VfEbPbNdwidLFUmemEE/pDjOaHwIqlo
	f29HbA+QUjJJJoH/Vfwlyk967C84Lk4KRWwq+yKCsicGM2GiV3u/
X-Google-Smtp-Source: AGHT+IGrrcBZg6MDHwD8O8/exx/H0a4Oi8P3gjA8CI01aI4ibBgq3z9dcxflvgKzF7rJ2wgElARiVQ==
X-Received: by 2002:a17:90a:fa14:b0:2fe:84d6:cdfc with SMTP id 98e67ed59e1d1-2fe84d6cf88mr8095716a91.35.1740639623650;
        Wed, 26 Feb 2025 23:00:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGynYwH/avWKIQQSpbJ4jdC0aHiM1AFw0drLcxXj34p9Q==
Received: by 2002:a17:90a:1b86:b0:2fc:153:370c with SMTP id
 98e67ed59e1d1-2fe9fe12c46ls751360a91.0.-pod-prod-03-us; Wed, 26 Feb 2025
 23:00:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWoGo/5yjw5ppgO7YNl5Zg31pm6uL8LjzzoRfxMKl9vlJ/JlmQI7LeMA0lGVuDn+jTGWDQMPiRC8qk=@googlegroups.com
X-Received: by 2002:a17:903:2441:b0:215:a179:14ca with SMTP id d9443c01a7336-221a0ec35cbmr383067615ad.2.1740639622227;
        Wed, 26 Feb 2025 23:00:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740639622; cv=none;
        d=google.com; s=arc-20240605;
        b=cgjcQSz5xXetyGQ7LNdKzEO1mYEKEuZbmdTROxUmVnEE1gPS0LM/Ajd2bTDpMtk8Qq
         97VoQFZiNK5wro0XQ6XrQvl14Px7uh5tItwh+VUdh3aAkpy4iyvn3GljvAh1kx/gYPgO
         Yvtn3QhrWNQvuKdHF9AwmmNAvBqgnxk461BCH7Nl1feaxVd8p05U4XqJLVAKvy9QvI45
         h4cULdWs7vA7WkI47vFlo5QL+GoyGMlBcea8wGVFTOVwOesYsw7Ih2w4k1O5lBhlJFXr
         d7jXTF/aOvBuo1twx2++n49WOidlOyBUNRC/yo09dqrRGTLbZx+12XP2xaYWZsl+S5HZ
         fUew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3B7a9PKqDfPLxt+uZdMSLJc6wZgnR8JO787nsEWqq0U=;
        fh=hEeRm4IJpAOQs+DcI2dS5vOpvPe50lqCNbZrsAAUj9g=;
        b=FebDfdnu3/W/OjJNY3+nrIhpUi1AOsKP87xNQOIHD11T96iIlmkmAjgezsVsEY1R3b
         8E6+8Vg5sHiKz+zawo79QViHXiHNm33yupd4Y6WR2+DKnejrFRc0P+29TrTp7mqOHgxT
         W8K6orgbmZsu4DHcLuVNBk6HAWObJmbEXZc93T/MZJnLYYW83F0ablAE6dYU9OKp30vX
         JZsQXbnxDUxuBQb3xtKlCZ92PHxRAC8yXwGuldPQoQ/upW1E9I4E2cgIIKkNwS79ott8
         iLV/2OmFHIH/2FUygiRm6rfpDXxULGUBpg6pveVzlyzMLCRu+wMJ6BDQKS/QCjpNB/G/
         9sZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wQUBSCy1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2235028fd88si434645ad.6.2025.02.26.23.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 23:00:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2fea47bcb51so912559a91.2
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 23:00:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+L/Azyl3E8qTKkOy8ucoCjFqVZdeCeWvbU3osTH7g+wmjv+d9wbR1jiRt+iXwAEtOzmc9NzL3gt0=@googlegroups.com
X-Gm-Gg: ASbGncuK1lUDQ/P6yWC4ZVyBtfsw5WdkBMnsT9zgvj/GVeFMdqtVIUnJl2mcNMTA8ht
	vVtADoiHt0VywsGjnitZ1wuxP+hHMnAreIa1saSnoS247kLp0hm311Q0WGK++sjfcEVH0Xub5z3
	VnejRvwPpxCU/e9xcX6iEOnRiL91UUEH+2FWl3DA==
X-Received: by 2002:a17:90b:5148:b0:2fa:17dd:6afa with SMTP id
 98e67ed59e1d1-2fce86cdeddmr44583103a91.17.1740639621455; Wed, 26 Feb 2025
 23:00:21 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Feb 2025 08:00:00 +0100
X-Gm-Features: AQ5f1JrZWnMR4OE-NBvXmFaojOYjcgWnnmEzRSN2Q8FKZWV0JX5T-ip-Qb4DfME
Message-ID: <CANpmjNNxb8f4QNQE+3oprwfhbhZNkiN+JJMRAzMa8mHXFkksow@mail.gmail.com>
Subject: Re: [PATCH RFC 00/24] Compiler-Based Capability- and Locking-Analysis
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
 header.i=@google.com header.s=20230601 header.b=wQUBSCy1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 6 Feb 2025 at 19:17, Marco Elver <elver@google.com> wrote:
[...]
> Capability analysis is a C language extension, which enables statically
> checking that user-definable "capabilities" are acquired and released where
> required. An obvious application is lock-safety checking for the kernel's
> various synchronization primitives (each of which represents a "capability"),
> and checking that locking rules are not violated.
[...]
> This series is also available at this Git tree:

   https://web.git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=cap-analysis/dev

I'm planning to send a v2 soon (Clang just gained
-Wthread-safety-pointer which I wanted to have committed before).
Preview at the above tree.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNxb8f4QNQE%2B3oprwfhbhZNkiN%2BJJMRAzMa8mHXFkksow%40mail.gmail.com.
