Return-Path: <kasan-dev+bncBC7OD3FKWUERBSFAVKXAMGQEBK6QIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 03408851FE5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:26 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1da23e32563sf15801685ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774024; cv=pass;
        d=google.com; s=arc-20160816;
        b=XfS074nqNGeTh/P4nmdv+m+zM5VvhVeUFtK0UghJsuo9L4H7+N/wh4RU2yKuTAIso7
         Q/MEh30p7OoQG9nRx6K/uWoBftS9tovEmry/6qvSNsB+Tb3h4U7ZdsjvpY3XXFg6p5ph
         Ax9Omupgsi5dnvXSGY+FX9xEhenge56/7ce93esKAC0OMF1iaI3Ja+J3ttC52MiVaXe9
         1MDGNM2Nr9JQNWlSIUntg4+DZeJbiHX8grSBpgAotcjdYDW9smQH9Bvp/d33x/4dCzLx
         SMXJjACCPDfX/N7bmlNy1dCGLQESh3OHf6rt0zvTE+Wp93tTPqHWG4xnZz9FCLZ2LBKs
         Kb+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=w1nqtcGS3zZOCxlhIRLp0WwBkkE6IzMZBTL2a9UVFDA=;
        fh=MbntOlAOsYNJgEPEXF0J9yVxUi3xvQ9Do/zwvJgM52s=;
        b=v2eYQSeggHJgTwo2IpIYAAQ+Dngc/bu4M2XrWpo2t8HC3KPPM5CuLGLQf+69sd2m/r
         5ZspyvvF2L2YvYcoOblE7LUnJLJcvarzwiSahl2+u8JbVfETUNjeQ/sXnR1W6aV5iYer
         9HvBzeh2mGJhnlmDH1k/scRuQEQyAAaHNs5SJ4VETB6TePCDumn8tCRYSszQ4nw/4OCl
         L4yNcY9NLjgOvSS6yS9RQbwAKhre9yMzSYxplOXfMWA++Ner2oVK9Khtpu8fLmXO20pp
         uSBtN3OD36zlkptON3rq40AIZ2gKqWnOxoz3rnVjLfWMJ6jmaHZpKaLsCEUL3AVMSmhS
         btlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=j57WSelI;
       spf=pass (google.com: domain of 3rpdkzqykccu352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3RpDKZQYKCcU352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774024; x=1708378824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=w1nqtcGS3zZOCxlhIRLp0WwBkkE6IzMZBTL2a9UVFDA=;
        b=KHinJ0vdGEt/7cmHs6vciGPAhsrv1n8EiQ0M/LGIJniwjRalIwrmg+Qp5vWxvTY6ZX
         LbKw4Xy1T6nX7XNltEFOCtbDm4fmYLmwd9U2F73QB7SRcCl4N1BjBe45IoXgmczUbOO+
         FgbrklI5PXE/SsnQj/QFe/Ccjp/KU4gF0UupSudhfIDtXb2HMEVW4DB9SrsCI0Qrt1GS
         Sro+wuoMLD1t1EP8WrzieVrol+BEbgiVCFLaD9hqvVRM4BJYq1YszvPTzuzr+dGUG5xC
         RY4WB7Mw0XOlTBGN97SSsptsh0h1htS3H6OHQ9B+lSeplp4oGmKPxWwhYTumoNOL0MNT
         Ndlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774024; x=1708378824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w1nqtcGS3zZOCxlhIRLp0WwBkkE6IzMZBTL2a9UVFDA=;
        b=Zii3Prg2w5Xj/qoE7O4HZC+a13xeEHX0HqbfFQSQzxxweDIVLjE8w76xlBjPZTz13e
         iXm/34LYZFvd4IdA9u92sbwcpmeUdKUX8DVEV8/mwoHt8Pp7JXYBSt9un6Qs4RDlOX0N
         beUrYv250wnxgPhRsc1RJxwEeqSBxHAdE/gMF/j1cL/WIitBO0uyk5CVX/kbj67yVrQT
         edpXnbVDwfanY5HmbL932NzALxW4+9qOn0vp0+dyxLg/ptNny7uEhRoeoRjq5ZFoRzV6
         266v3gtVhAR0NJ2RdRJT5KFNA5D+zqvKZUKDUcEZyxWUiyLmltyNu+6mGUePViJDHZo6
         1FQg==
X-Forwarded-Encrypted: i=2; AJvYcCUNl/fWdWikc1EVRo3H3Pf1rGSMj/oHVBV2Y+VI0VrMvjadQXbL9iYKMukF5Hu2Vu9aQkGdX9O/OqQOMATCOFhl6YLkwaHt+Q==
X-Gm-Message-State: AOJu0Yy2sa9hW9TvxpL4uo5V/NZgmKJmR5Xehj8OY9p8F66K5Fi16MW4
	XldZv13zgSzzTmQCA6Mz3VJ4Ta/kzYFQBKW2/73CogP5U5qR8QWi
X-Google-Smtp-Source: AGHT+IHYPuqwMAQK4JWYdfmdnqb4Dt6tf1e0cVNqdBqpxzac5Fk/DUvCmC5WRxVWSCwJxKyy5IPdFg==
X-Received: by 2002:a17:903:2988:b0:1d8:debb:4125 with SMTP id lm8-20020a170903298800b001d8debb4125mr10098472plb.38.1707774024635;
        Mon, 12 Feb 2024 13:40:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e9d5:b0:1d8:da19:683c with SMTP id
 21-20020a170902e9d500b001d8da19683cls1532068plk.0.-pod-prod-04-us; Mon, 12
 Feb 2024 13:40:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVVyHf7i1wA2w9pXglRKGzwxz2JwCjZ41yLFNkSLqz0I5SMksVGUJSQib6Ft2Oy8xi9NFGv7H7CpioP6BLzcbXw5TqT+v8MezFZsA==
X-Received: by 2002:a05:6a20:9f47:b0:19e:31dd:3ac2 with SMTP id ml7-20020a056a209f4700b0019e31dd3ac2mr7543852pzb.10.1707774023670;
        Mon, 12 Feb 2024 13:40:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774023; cv=none;
        d=google.com; s=arc-20160816;
        b=uG1/ecSDBCwkC0CLCIkyjetsU1PS1VeZoj5OcA4BHiTYB87FK0i0Ox96Yty5pGBb/f
         SefdS65Z2i5MiQHRkXOqdG5SC4Vx58IK/fEAXchvHVmo+XwqdUBWMlg8KxZwwZLcM+A4
         z/WnGKammkkRwIyS7zzo183Mz0EZ1SNg3s2C7DlNTKx/HI/iyMkTd+gkB+LBPOfaDtn8
         g7H3akzIi2OTvIw83feQFFadWJmZSmJUK/FFsHsaxt6RdJyD6mA824RstuVBmjaZcUe9
         dcbOSb385KcJoo62q4HvW1CLyTLGzjjl7uCg+ugWG8Fq1AqXeUuoEMFbVUwxXg8aafQD
         0RDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QVjGOqS2/C9DQQqaQQFc7iw3YwNnxSDsGz2z4KoUl2k=;
        fh=fZpeecPzTRXaTx4JP57u53c17oPSNyy/6W573vYyod8=;
        b=N65j0ZUCVkar1ba6yL6YpOPQF6UAsleJ1F3sNVgregBeb7t7u+JLbvI2yVcUYTV1+e
         lUYr6/tT68/sy+121lrzz899rG6JqPxQxDcGn7DNzfNk1+FmD0XHbLwj9iEediO63VD1
         lBGLWovGtSYx7oLUxBxlP8rpdcYyrObg42yrlZEpVLjYz0trKNLZFFEBX+3/TnnoYdtW
         W7Mvxaj1OlHT1kZ5kZR/Z2iP3VwcF3sV1DLM5WnVtAVDRrGY9rpTAd2oR8OCtXCOd6SO
         W1/7bXqpctotIY6hLVHZJvkfy9RGr9Q9r6kvotyvzGsmxmDfq9+LcbIsHUCll5u5MZ/w
         j/EA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=j57WSelI;
       spf=pass (google.com: domain of 3rpdkzqykccu352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3RpDKZQYKCcU352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWuDQnbr+x7zZFnNg9F3oV0mCHCyaSk/7DGFPrrWgKBy3gmUs2IEJIgEHBttPNCnHovGL8maH6Sh+AgwkolXOOTpEEvEoYnXLFtbA==
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e14-20020aa78c4e000000b006e0542545eesi596032pfd.2.2024.02.12.13.40.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rpdkzqykccu352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dcc73148612so66132276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUeua9qn1U9czb+FKvNkDjCsPO3qPA/bKLZ/CYKJDu8Di8WjEA2BlfUskrr9ekqHKq/24qUHTeN5m9u0oKjYr6NskUGNQKZVAtvpA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:709:b0:dbd:73bd:e55a with SMTP id
 k9-20020a056902070900b00dbd73bde55amr364194ybt.4.1707774022635; Mon, 12 Feb
 2024 13:40:22 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:09 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-24-surenb@google.com>
Subject: [PATCH v3 23/35] mm/slub: Mark slab_free_freelist_hook() __always_inline
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=j57WSelI;       spf=pass
 (google.com: domain of 3rpdkzqykccu352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3RpDKZQYKCcU352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

It seems we need to be more forceful with the compiler on this one.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/slub.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 9ea03d6e9c9d..4d480784942e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2124,7 +2124,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 	return !kasan_slab_free(s, x, init);
 }
 
-static inline bool slab_free_freelist_hook(struct kmem_cache *s,
+static __always_inline bool slab_free_freelist_hook(struct kmem_cache *s,
 					   void **head, void **tail,
 					   int *cnt)
 {
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-24-surenb%40google.com.
