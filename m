Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBKUE2HXAKGQEBKDSW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CCFE102C8A
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 20:27:40 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id k8sf13691904plt.7
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 11:27:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574191658; cv=pass;
        d=google.com; s=arc-20160816;
        b=NgX/3VWoyI02H69kWaUWMdKXNJbxBFq30DhNrFjC4cSJLLGjUd3L26XldNMeFp9leH
         xJTGTnuJ/RhbkP+9IhwC/NIWrrUNcGWT81QEFlQEre3uap4k9obnhcqYp8ri8n8+8+xO
         ubW36L7VCZ7WpVnThDkzqssATsQsFWyZrFhJ+dWZfFY8/6DOD55mPIKkaEjxlK4AnNyF
         6hJBN2Iui3ysX1+m0lvGZtPtfk0EBQEv16aPWN1AZIlelxdsIeci/UY+a9cYHVKIfw28
         4vN6b/eHHT6PwrZZPD+/187cfkJVMorluUZ+uSarGHPvOwCPyONmYd7+XCT2FbjaIKf/
         p66A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=kzJK+KA7xGLm5RUlIkrWKKFO0AUYeJt6OMlqNGQ1HsE=;
        b=0/H7//uOp/nF3nibaqnXYz59MP5mxt0KpbHB2hKh9sYTRFEEE00JFJnbFlhR6+vDJv
         dyqFwSRfj23eLNpz4Zj6Feb8oZD5CGiOf5nfFYAvAtCjbXJlgGuApLfJ8XXfF6OVhJg0
         i/fCghheiJmm1Ktb8cX18kGz2fdRa0MHyUa8AltgEjgV8n9ASUpHCoAu5sDCsPV6yuPq
         a3S7vn4cAWGsNOoBUHpj3JEtXGTEAiTc9GABLfdGe0ttv+O2sgY1eID671TdWfE0nBnR
         tRsnlyeV0SQ6r/17zW2cdff8kHeyUkf6Zj/1ulqXBfaanPqXs2uozgVAqkkwfaLEAPvm
         DXmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=cOwJdQ3Q;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzJK+KA7xGLm5RUlIkrWKKFO0AUYeJt6OMlqNGQ1HsE=;
        b=N1hn5pb2W/YbL2tw9fhUQ89Tpuda4x0KAZwjdMvWrwSWBCBVU5Ecs8mCw9DHAPr5WA
         6Qzi9hEY6tamYZsYWAD0/YyK+UghHUD5wcZRl0ui2/5muAjye+g7K7wwi4rvHT37b/y6
         mtDdVytaUVhKetg6S7tAjK0p66VlIXIgj0/ZvLpS/XKsiqq7cI/1QUAJCdvs9TK3FKQL
         wJMY3mHHqjetlZyEbmq393e9anEYlMQK7VjlDKdV/DVWtlK/9ptRvfXvU2T7Q73Gno+q
         MGiiHd4EB+lq1thlXjA2Eo22e26BDkwhOWTpeaIYvVrmr5yJNLmS2LqEv1zpMP8UOY3s
         0QsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzJK+KA7xGLm5RUlIkrWKKFO0AUYeJt6OMlqNGQ1HsE=;
        b=ofUa3ltYQCIGc+P3FtQECzO3sLm/nqxPVidH7vQer5ilgxfjSBYdFFNlPjceG0wG0U
         qeUa80XJDhG14lxif44AVYZYt3XOtAW3Cpnqi+t8smsBDPpN0cZKa+d6GL1kdwpHedBK
         2Hc7IW1sYaztrFibg2syazyv9YgRyIiw2mr4k1ykmwRi5uoE+k3ysB0jWyc9tcGBQMZa
         7e7K9VO3AjHFFrm5jS3Z/S1VaX6o20bK0ZBXvMWP2qIz26IiMXPZw7XqOwJwyuCST8A7
         61yydmvVXJKdcYHJggtIIH86l2EOxPVXaL8N6WpnxbLbKK3DVFZ8r+vgy9r8g550jXo2
         B5EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWzfgPcuztPfBpQiMx4hpT4irU4ksBLMBkFxNCqtAujj9WvXU0h
	wLlDx52Kc/475pY2WXyS9Gs=
X-Google-Smtp-Source: APXvYqyXkldeE+M+QNe/qWLyLsdpvQDEGblR6y+vorihSJynqJxJ/bjLYgvT0mfpIDM6Q3jHXukqUg==
X-Received: by 2002:a63:ff26:: with SMTP id k38mr7711522pgi.128.1574191658748;
        Tue, 19 Nov 2019 11:27:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:216c:: with SMTP id a99ls1411922pje.5.gmail; Tue, 19
 Nov 2019 11:27:38 -0800 (PST)
X-Received: by 2002:a17:90a:fae:: with SMTP id 43mr8948725pjz.58.1574191658393;
        Tue, 19 Nov 2019 11:27:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574191658; cv=none;
        d=google.com; s=arc-20160816;
        b=tvQ1YfxErvP34uvctbN0u6YhwbjWvY523R3LATAkHBMH+94h0Xl8ghAFJWl5d+P8hr
         LpG7eXN0mookqEcBzTYzCt2V6uKyasg+ocsswHhTMVuaVgJNz3kRh3YGZ8pyX+T+2BRg
         sSslZSVbHfLYjrzMTwJqb2gmrP57NXomkQT7rS7PlN2KJ+XFBUmPa9Xvti9qxYKbh23E
         CLJyk1qQ8SlzGU5K/uQWShbJzBmGpudpXiiHYflBxBjF6cskPxxn51++FxdTzQsQG4b6
         d8KYAv6tg+qQetKqrgFHf6+S/W50BI0KEC8dJAbu7a2lV0BFJRyptsC2fsq/dm3OL7eh
         S/gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=wWke+FPRS6Ykc0nO40qrsc1dQ72uzYDMM9s/rffQgXo=;
        b=sKcFBdFQFkl8gTjsybsN2jvgJySB+KDFZ6nRehZmzkaBEkBdjDlNYGIqUXYFkW7pZS
         m/QuR/H7h88REID79hwG0uzJaRRolnsK/g7Q3RWGeV3Uyuvt4BeyIIw/83HlIiydfB6+
         ijfpp3kRkLEx0ZsM81FuJShDGuva00q8i0pJy+DyQGl+7bx5CEV7s+iU3H452wThvPgm
         WH0CAxjLYsU9oydAvBBYXXM2ky08gdzOGAOFvr8/BJYdv4/j4pY/+H3AXxcXKjIvG0zp
         wsKu3K0GY6133X4P9ZaWG8ysKfybg9tRbynr3yOT/DHMLSF37Lg7ddFRUPGOtfV4JAgv
         XTyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=cOwJdQ3Q;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id l7si135173pjy.0.2019.11.19.11.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:27:38 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id o11so25913110qtr.11
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 11:27:38 -0800 (PST)
X-Received: by 2002:ac8:244e:: with SMTP id d14mr35262717qtd.388.1574191657402;
        Tue, 19 Nov 2019 11:27:37 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id 134sm10319529qkn.24.2019.11.19.11.27.34
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:27:36 -0800 (PST)
Message-ID: <1574191653.9585.6.camel@lca.pw>
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
 parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
 ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
 bp@alien8.de,  dja@axtens.net, dlustig@nvidia.com,
 dave.hansen@linux.intel.com,  dhowells@redhat.com, dvyukov@google.com,
 hpa@zytor.com, mingo@redhat.com,  j.alglave@ucl.ac.uk,
 joel@joelfernandes.org, corbet@lwn.net, jpoimboe@redhat.com, 
 luc.maranget@inria.fr, mark.rutland@arm.com, npiggin@gmail.com,
 paulmck@kernel.org,  peterz@infradead.org, tglx@linutronix.de,
 will@kernel.org, edumazet@google.com,  kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org,  linux-doc@vger.kernel.org,
 linux-efi@vger.kernel.org,  linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,  x86@kernel.org
Date: Tue, 19 Nov 2019 14:27:33 -0500
In-Reply-To: <20191114180303.66955-2-elver@google.com>
References: <20191114180303.66955-1-elver@google.com>
	 <20191114180303.66955-2-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=cOwJdQ3Q;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Thu, 2019-11-14 at 19:02 +0100, 'Marco Elver' via kasan-dev wrote:

> +menuconfig KCSAN
> +	bool "KCSAN: watchpoint-based dynamic data race detector"
> +	depends on HAVE_ARCH_KCSAN && !KASAN && STACKTRACE

"!KASAN" makes me sorrow. What's problem of those two?

> +	default n
> +	help
> +	  Kernel Concurrency Sanitizer is a dynamic data race detector, which
> +	  uses a watchpoint-based sampling approach to detect races. See
> +	  <file:Documentation/dev-tools/kcsan.rst> for more details.
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1574191653.9585.6.camel%40lca.pw.
