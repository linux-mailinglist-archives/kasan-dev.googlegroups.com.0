Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNVLST6QKGQEUIRCVQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id EE0D42A9262
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 10:21:58 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id y187sf201208wmy.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 01:21:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604654518; cv=pass;
        d=google.com; s=arc-20160816;
        b=a4ai6V6RHPwi05uvbtskKdgrJMYmQYWd1pBJCG4GWzqdkCiqSOTK2zVW07CcJWBYWl
         NlDzJrTVW0WeG4l7kaQQVw0BzBnXe0sMqdn2q6j9bjQNfU0MfGf3e4MHpt5ABtWdrcvw
         CZ9LKpU7Rr7SZ73KSrWetLEuEM0uRwykiROajHYS/lfdjw8NHPkTIhwMEkcEThuLUzep
         blT1tR3qa/9tCIOKvzpF3HMV/43TGskFu1lQZ1lqL2GG4ox91miNoLRTd0LnY4mXE6Nw
         u7uDBqE6PFx4l4xlt7bVixsCZeq4KI3Tjx5Q3aIDsEJC18Z6G35zSffmDCh9K2ytA5hN
         WkPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YZXMf5KUa7vo0SyVl/3a9e0qFBnTpiZNKBNRSpkBDMU=;
        b=WaPFFyA3i7nVSlH8SxKBx8C/K2SMg6xo8FJLTeleqMAQZFWZSMFl+CMNeG64IkfCcw
         0lymkAdYe7X/O7rZEPuEH5vfc4G/+zmvhud/YBzuskeRKFJwSUl6uT5841/fKUQJ2JDz
         TyscJHbL5tCZCRyE2XoEeGWvBxiqumMHU2j7dWXB7MUwgsdFZtZ/94XNHk3baMvoyV8a
         Elo5lAWACZEPKFKDDSzRq9syn48sUbsA1YRyPw63rg6vp6D+H8yP7XvernKiaRFuS6Pw
         PUEUgYT95DCoSZj0ZbL22GxCYoGcH3V0fYdTsFDbh3qYYmj02oQrwMJ+LGHPJRM1vMkg
         eV/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pdAwI7BY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YZXMf5KUa7vo0SyVl/3a9e0qFBnTpiZNKBNRSpkBDMU=;
        b=P0yfL3WCcovrq913Ahxo8VN8kIs8BYX3Tp0REK/Lpg31vpaxjk7K4TeKhEDEcHMaro
         7gtfZgv7l8SPO+/GEBLyIjrXyDSwNO60p/96XXfhO5aKf1LE32bDISXSLLKLw2t9TzKP
         NJW2JoePcWZ5GHpTksV9kMMO22VnkTYvgvH5yR3WfA3dzktQGY+S0dBw35TVpD+rsPZa
         Np1fgiqcBwEQwohHbPxb0TJsBGuTbQy/Ld7kT7THpRAeuZzKDWKdzjTnlps6+iQH1jTc
         PIYnoypCOnysvS7uAcaaTtD3svCuIS/bzvkfCwzUAmD9AeoFLdiw9+2TgEtDkCxDKoqN
         D5uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YZXMf5KUa7vo0SyVl/3a9e0qFBnTpiZNKBNRSpkBDMU=;
        b=exmbo+8zPx5LVrcvxzsppTLNGMsPhiLY6nOZ/t+RjsWTwh/q+aB3yKFpXrNPr7zWb7
         3z66tziHP5s0eneT5oIHFdvFRW1u7zW75hqvTPSSGX7ZQjpIrtmLSAqdYRdfm+CE3X4h
         x8vpbD9vLshmMwOYv2tasagQuLFmlbkS/GIab97Vxs9V0pGBT7F6ckpxTZDQBWh7kxuk
         AqIq0jTA1rWBKjeJdOOZJvi0kyFAj2rv3UHajbVP2PvqG1ujn9u2JNnTtjdGuv7PAhGu
         X0X69R6y7dP63w1POHPyrQrAOPg7kRxoqjm/NSzlCR1xI4vJzzbItA4n3Jpa9zkqGsIh
         rRjg==
X-Gm-Message-State: AOAM533pMKRw1jQ+bjXGO+hQsM0DQHpuyeMubyOcd+etPlNpH3JH6vXn
	BBkD7GdzPOtvi6Q9ATlNvcg=
X-Google-Smtp-Source: ABdhPJzLH4slHLZEZycbiJsrCKubrPtwJwIeVX5DfvGX8yAgfDRkyqrBHz3jHT00X7qZV9UqUkPQeg==
X-Received: by 2002:a5d:4f92:: with SMTP id d18mr1676556wru.118.1604654518774;
        Fri, 06 Nov 2020 01:21:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls513071wro.2.gmail; Fri, 06 Nov
 2020 01:21:57 -0800 (PST)
X-Received: by 2002:adf:c58f:: with SMTP id m15mr1643026wrg.144.1604654517768;
        Fri, 06 Nov 2020 01:21:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604654517; cv=none;
        d=google.com; s=arc-20160816;
        b=kUAwASTJAhsVBigLjsghH/Ls2yNayadz4rr2cF1ej77GJlz4JQTugtvSI4eqTsZAPv
         0DQb+UvVRk6ogdPOjSR0O5hf7dig21xUcfKx1i+GCwAdYkLY0BO8dOXy/XsNTi5yabpo
         XXtzpuFb20L1Aowjz2f7J2KLS7ReGNbcngO1s0cpcMKZ0KcPEn2SVmYdKCkOpkCOt5GI
         LgyvV125q7TdkW13V6j0mXu7jOz5eEz5m892mVOUSWcz4Gobf2mO/vf1HLHCss2sJygW
         EDxbZHWC/OmRPG+GvbOL5SWoZ4CWXyKbyEbiySAYpcxoIawDNHPXzevLPLn/Pl5K+GfC
         LAkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xECvU3FABW/JOy42DkSlWBBqPmissQ1l6KjhuN6QHIU=;
        b=Sz1Iwv+dzAzGE4BV94HtV/oDVAhBgdwnQzVyT9gOaXa7pjlyC+8eKd0SE7zWL2VPDS
         FHZd4AwE7uKymIPRW0jQi2JXXOoRwBd5tK1bhh3rLW80m+Ry4sUMj0+5w5fb++Nd55oq
         Er/Dm6zOUlQXj6yuWVjUycQyIe0tRDzwgBYKHFdF+EJLQV7FHPcbARxV9Us32wdGz8dw
         92LhmYyxF7Yc1GzFPOk6Guui6Fgw6B9gjf8jBnl8G5C4WBh8DeKzobd6luTKlxZMQW8Q
         YqLrd/c6PcXlUDxTM8t+cwmIfA1SHOC7vvWijSs+DxFL+KfBalmFTJUwPWXpB0SJVG4h
         r4lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pdAwI7BY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id z83si29290wmc.3.2020.11.06.01.21.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 01:21:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id h22so658862wmb.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 01:21:57 -0800 (PST)
X-Received: by 2002:a1c:490b:: with SMTP id w11mr1347316wma.101.1604654517289;
        Fri, 06 Nov 2020 01:21:57 -0800 (PST)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id v123sm1383820wme.7.2020.11.06.01.21.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Nov 2020 01:21:56 -0800 (PST)
Date: Fri, 6 Nov 2020 10:21:49 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Alexander Potapenko <glider@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux Next Mailing List <linux-next@vger.kernel.org>,
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Subject: [PATCH] kfence: Fix parameter description for kfence_object_start()
Message-ID: <20201106092149.GA2851373@elver.google.com>
References: <20201106172616.4a27b3b3@canb.auug.org.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201106172616.4a27b3b3@canb.auug.org.au>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pdAwI7BY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Describe parameter @addr correctly by delimiting with ':'.

Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kfence.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 98a97f9d43cd..76246889ecdb 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -125,7 +125,7 @@ size_t kfence_ksize(const void *addr);
 
 /**
  * kfence_object_start() - find the beginning of a KFENCE object
- * @addr - address within a KFENCE-allocated object
+ * @addr: address within a KFENCE-allocated object
  *
  * Return: address of the beginning of the object.
  *
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106092149.GA2851373%40elver.google.com.
