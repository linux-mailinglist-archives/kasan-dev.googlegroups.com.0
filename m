Return-Path: <kasan-dev+bncBCD353VB3ABBBO5AYHAAMGQE4BME3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BD1B7AA0112
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:20 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6e8f184b916sf132032106d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=IeA8485waYnf0PoxJUCU6mGLyTqCwewXMVi+zmvvEZAafmbMWFlsBGaWQAfzO36OlY
         Oc+O7hYW8W0d7a4Irgxkl7WwA0EnSIs8Reb0d1l3yk+kI49rF8mJudURhbYDPWuEVzl7
         ngMo3jC14dT8+eNKwS2rEKnHsT+6C56ptUVBvkfKUAW2qdO1jaH6eDhubpLdLo/4pEIs
         c2a4I4oVBxgbr3T5I7XBf+f4VLRzt3BV0/m0d8BJY/Mwn6CZRgRqfZRq0k/w3ltDOxeb
         BINjbjmtJi+IuedPtPNNaELGWMy2cgC3BLeF2kQXemy4Y1pnYkXQK9c4qMdSNPE78/z4
         jUBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=BL7ghzOvTf6Vpp+vF9M3cdR6G3btCUohYFnib6kW5uo=;
        fh=Jx8HgBiJvLTRE93Jph00KFjey9ahuFnQ+gIyh/pcOxE=;
        b=eAAB77sAylemGOUU7DBZ7Ra43G8620LZP5y5HSnSZyHfCvocqhG7BoRGCi8OtSVUNB
         1GgqcasynlT/NnS63kZc0EiIRiREU8TMxYeL5FTibQLrk7k9EeC8GG9hpmUaMyhJRDwh
         9EJy+koORoFcF+iGMLnwliIklQX6DLWg8w6bMR8I7uyMn2fseJEO+EpS+NJ3rqcdpA5B
         Kbt1y/iLYD10kabN9KiC8dj7kqs8bCZmOzCRMjxG48QLlb4xdQyk7XPRHs+YbszMWUOf
         yFypaJK8viSFM6FZmRmeC3pwSGFHG1FyIoMHc2aKJnCtld1Je+w4cG+5cMQ9MOMXbNaJ
         wSCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FyUVqYls;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BL7ghzOvTf6Vpp+vF9M3cdR6G3btCUohYFnib6kW5uo=;
        b=pETunqISZgNAH4ZRpLlSwzWyaCWS7GoMncfScabEaWH+xqmMnwtuwA6CtgcTXmyTlN
         RwxWV9xY2nc2Cl2vRAkdO5XrKMsA1iQ3a2giRbEjZgFRaa5eBaxcTO0iHxXMPd5HJQiE
         KrAROGYdCScQOsJMISbj0KY5KnPuFdjBKrGbWctCUL45SX6VSVQKEo5wuNDv4FLNCnPK
         6egLYJ4PgOrNtUU9zMzle0neP5muQvLsm/LNfCsBpqaJZoYap7c5TMVUKYMrPcIGEDpR
         Wc0F5HCCD6rVQD+PaOdwJXpagESBIhf9rh8lCCdKYKA91jRGLXvQ1o5594zq/1lysevz
         qL6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BL7ghzOvTf6Vpp+vF9M3cdR6G3btCUohYFnib6kW5uo=;
        b=nLXlv7xldjF3TxjQB4a9PaPGKzCWwg8qkGPY5dS2a8DY+nArxY7V+3Gr8D172MiD5w
         ln2FRMP7kNRdaRMbt7/e2ozzJLm9TAqq5X7Wtd6RjGtTxBPabM+QAWFeb1LnYglPyOyK
         YucbahpJulX0HoNP01or6D/g9MnPPmjj+nj3cmO1oHktvDJpUnaKur5bDcJQq6+fyVwb
         On1qOzNlNwbKg2U0MW5MInNrtfPkrZPtYOpOoL4JedJy/pFAbXbyjoxI8zstp/rAyx5O
         N7B0xqxAoxz2g8IlyNtH4OtTL/f/9bsROP9ttVg6kiV/E+J//rNOoLMiMNMsPC51E0OS
         DiLg==
X-Forwarded-Encrypted: i=2; AJvYcCXZOET0CZz/a4WYcm5htSjcFZKZJ6U3UOT8kPZaQkmrRLg8zBkLt0Ke80GlpHWCbAGNF5vNqg==@lfdr.de
X-Gm-Message-State: AOJu0Yx7JpVRrXPv3FcXEq1SYsOUC6eTOgDafHsH/nsj9DKbgcOvolWf
	8ocFe35NovZHrwAc8LpZeY2BHUiGg3lqBo4JL9zfkndiBPjZ4V/T
X-Google-Smtp-Source: AGHT+IHFL0WeBAp6xGK/e8AC1zy7mmBPQxxjbW15Y1yMbGR7gY24PiSp0iwbLhIRA3Uy/ZP9cQ6umA==
X-Received: by 2002:a05:6214:1d26:b0:6f2:d25e:8cfc with SMTP id 6a1803df08f44-6f4d1eee1fdmr169951526d6.9.1745899579342;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGJEjOkZgNDk5CxVrcbv1G2gtVWTALI3gx5+Zktmog19w==
Received: by 2002:a0c:fa42:0:b0:6f2:bb36:d3f3 with SMTP id 6a1803df08f44-6f4be2846f2ls55851416d6.1.-pod-prod-06-us;
 Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXP3k1ZYWJexMXZ9kIUrACSHp3Fm3xwUITySXMdHGJy44yzrV5H7gqR9MioxqRDBnfSsKNC6z7x/LI=@googlegroups.com
X-Received: by 2002:a05:6214:1c48:b0:6e8:ec85:831c with SMTP id 6a1803df08f44-6f4d1f90cc6mr226673936d6.35.1745899578542;
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899578; cv=none;
        d=google.com; s=arc-20240605;
        b=A5L5UW/l089g1AoAIfKFe37Gx9mD7aF5T51n1G20CqK2YS/8D23Xb7NanII7wagLZh
         WgyzguKX5DU8tB1zzhIagNRjOiM1GHfaj/FitLN/foEHtPpOlKFO0O5HpL6csujxD+54
         4Fng5WdgtITE8/kbj7borcws5WKCkX6XXQr7kUOpkEjAr2dTqkXUhLWiH/AS91XJchIC
         OE3RKq+CPtpI6fRaYxAXMOgMyoc2ISeae9WU9VFr0Z7sRQ+I4hKmhokjoQPb9IViCGcC
         Ri9ft1SzY0sViOTkw2EgPkRpBLbTbkNyVDuhtYe5LWDdL35OtJYoay65QuDitu2ZUzGE
         WUZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=32GUHxOnJ3+ew70SHa0f65jKdkmGy6tQFDGoZR2Kj/Q=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=dk8Fdnvl38uIC7D8aakNlx4T8Gr5tEPgBVsrzKa+LWdWbWnEUXXcg8YXC/T87FMdKT
         3UaHDbmPwMcbQWa5MDcparXP5OVOLfSHBBs9LlP97tIiZaKBEpUJrde9EBvmSTGKudrr
         D1I2DNklNB+y79tRQ+bEfzfYN9qWmIc8Rrn8WhFqJRWBeKBQNfkcMQT8l0iKyKFgwEb9
         Kai+KqxKEbtZj7arWc6g9fvfT/DbvTn1WKXnF7tEy4Ea1dJn1ajAchlIsRHHE8ZEGEhF
         /sqN1N7OwzVad577ZR5xufHATUayUvXWnOejx/kDKNnVMu30MHYYTrinWBhFA6mKEM4D
         pRqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FyUVqYls;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4c099da79si141486d6.4.2025.04.28.21.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D24B068429;
	Tue, 29 Apr 2025 04:05:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CD555C4CEF1;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id BD4A1C3ABA6;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:06 +0800
Subject: [PATCH RFC v3 2/8] mm: add __always_inline for
 page_contains_unaccepted
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-2-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=2614;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=+y8wKlsn55GLtsirs4Essnozl8lVGDb1RUHKRb3UGRw=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAvQHTkSNXJxyOgEHVD9PhzBBGToDo54ToKB
 JTzQ3Bt13uJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQLwAKCRB2HuYUOZmu
 i2wDD/94Tikof0KqTbmGNltSJN0BkZfS5swTBN23SRIvCigAsJMsSAEE8+hsOfF5ug0IHuwNOI/
 1Qnd48PesFnCihU7hm3JfucE304u3ikq3JpHS8byjD3Iq2171RsPQwl30uxz+vEZ8hzs0TpTQBL
 tbOgvO5HS5tVi2N8UEoiRrD/AIGE1AKJx646BKh7BWEfqlVn8Piwh3FS7UZcthV+4LqoV/TILJ5
 CqwIUJDj8ZerV5DorB5SDBkZEPqwYLdujwzVjj9cp8vZwKMj+w/cFPS+07AzMtQNZybB8QumHsU
 DHQmASWQEn05ggN/6NnlkKJvxaDxaREGdoSN4rVPnwenoh7XG44AwW+NWt2oRVUae7CdZaTJ02f
 UozQggCd6pQA5H1c2SG9aalj7diOg0zrkq7srXqL9aVnJGeGkbSHAIxpmoG3bA+uXmBJSKWtr2+
 7DF6eO6UhF2ql4ur4skO7HIRADaqOFdEcIXMoQ8iutz4ml3kKwVIMhsOOAXwoXgNTZw6dPFvTUK
 oOGrXVNKLy/fJX/0x7AiWVUMQSMsG/Kuios2R+atYaJYgzNmP+h2IF2Il+UfCg1zti1vGWy17fO
 jFSai1Av+dm6o4iuFeMJx4Tgo52MAnqfyksIfcNlB+/tDcM4IwZn3C7WTQp9uxdiHyZV0edPtRS
 Z2AKjqx+hU/5gsw==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FyUVqYls;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

From: Winston Wen <wentao@uniontech.com>

On x86_64 with gcc version 13.3.0, I compile mm/page_alloc.c with:

  make defconfig
  make KCFLAGS="-fno-inline-small-functions -fno-inline-functions-called-once" \
    mm/page_alloc.o

Then I get a compile error:

    CALL    scripts/checksyscalls.sh
    DESCEND objtool
    INSTALL libsubcmd_headers
    CC      mm/page_alloc.o
  In file included from <command-line>:
  mm/page_alloc.c: In function '__free_unaccepted.isra':
  ././include/linux/compiler_types.h:557:45: error: call to '__compiletime_assert_1013' declared with attribute error: BUILD_BUG failed
    557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |                                             ^
  ././include/linux/compiler_types.h:538:25: note: in definition of macro '__compiletime_assert'
    538 |                         prefix ## suffix();                             \
        |                         ^~~~~~
  ././include/linux/compiler_types.h:557:9: note: in expansion of macro '_compiletime_assert'
    557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |         ^~~~~~~~~~~~~~~~~~~
  ./include/linux/build_bug.h:39:37: note: in expansion of macro 'compiletime_assert'
     39 | #define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
        |                                     ^~~~~~~~~~~~~~~~~~
  ./include/linux/build_bug.h:59:21: note: in expansion of macro 'BUILD_BUG_ON_MSG'
     59 | #define BUILD_BUG() BUILD_BUG_ON_MSG(1, "BUILD_BUG failed")
        |                     ^~~~~~~~~~~~~~~~
  mm/page_alloc.c:7301:9: note: in expansion of macro 'BUILD_BUG'
   7301 |         BUILD_BUG();
        |         ^~~~~~~~~

Marking page_contains_unaccepted with __always_inline and let dead code
elimination remove reference to __free_unaccepted() here.

Co-developed-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Winston Wen <wentao@uniontech.com>
---
 mm/page_alloc.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 5669baf2a6fea75c17b2be426443a6cf29051f52..433dc1936114469a323c8f3659730747965b2c3d 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -7346,7 +7346,7 @@ static bool __free_unaccepted(struct page *page)
 
 #else
 
-static bool page_contains_unaccepted(struct page *page, unsigned int order)
+static __always_inline bool page_contains_unaccepted(struct page *page, unsigned int order)
 {
 	return false;
 }

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-2-4c49f28ea5b5%40uniontech.com.
