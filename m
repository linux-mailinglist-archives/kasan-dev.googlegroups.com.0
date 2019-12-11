Return-Path: <kasan-dev+bncBCT4XGV33UIBBZENYHXQKGQEWZTLOSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id B4F0811A080
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 02:31:17 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id p12sf3346892qtu.6
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 17:31:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576027876; cv=pass;
        d=google.com; s=arc-20160816;
        b=ImgYAvarpnUPOH6zCz7QOqf+NTlRimu9ZKHTzvAzVNCH3IGMuiQqOBbWEkJU7/Qdyt
         6Eqx/IRxgo7k65zbkCbpnm7NT6Z10R69pU5hmiyJVKnqZgpPB9tGoy719u2+XvRPPSjy
         Ty3Yghrjgi8PxnNMcD3mTC+IttqWYCc5kxRh1jZ2qASURAWmoGAaQQdFK896taIBWlAw
         yT9Q7rSIE3F573hzjlHscL11Qi/rU90CV44eMfk5fPc/AIepkrgAqBMpOox5CxCudliY
         5nW3zhgOfKoXzYEdASL4iwOlK//y1t+qZ9vSlCLzsTD/RHZBVBe2LueRhX9DNOClS9Vx
         Qplg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=9u5RhiXhBTYeTIJ3jlhiVZXW+sFed9cO1KkHwfT5smI=;
        b=LjriT9KOng/CJDkQQ5FiZpffzvT262jottzKQCvEOfOOgJMUg0IgssE8SJl2OiDAgY
         /rQ0vxUbYTIGrv8+l2iYlS19HLXdgcTwmND348BI+dvk+b37gw0IBYRtea5+ui5csy77
         i6+KoV1bOgi353PMWtm50H3CrzLpSZT97lPGxn+oKkKS9bypW0vY5cpN4yJoxN0iZogp
         0qxewQysqlUGPfOQQFP2la6BZpW24tij6cP0zHMxJTkhn/uU2V8i0O/bDDJgiGuV1Q9W
         fVuusJ0UDYdm+lgWES34rNw2beBRSzJhZgJiDCFaIsu4YMEGFPMAkS3vddpY/aN3wXeB
         0ufQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0PE2HvuI;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9u5RhiXhBTYeTIJ3jlhiVZXW+sFed9cO1KkHwfT5smI=;
        b=BpUTPJhVoAfDEoDJEJ42Fk41eiqhDPkjXpcQy6HsWn6eS5RycM/d3yZi4QlFkIl2Nv
         aMTDFzGii9ycwKftY13tyZNvbjRaeQUwe/W2cFpfQU9OIupuBP/6k8iilbUfg1E3FmGH
         Vtcs55YLN9nJcg0dAMamIOkmROx62AiZiSSX4VbsQU6+S9CLGtmlIxH8zJG6FNAcj79Z
         cM0woYlIrMgQ1gzFEaq28m84Pal7m+TuAR5D6ijGx/wVPvcMxXlz9S/nsH/BbfmSppWM
         2JN5+3Hk4MEQr0twc/IvM7gEm9J/CXxhy7+79xQQ7BnUl8ip+vtj35NBFdKkAGTjNO/7
         N5qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9u5RhiXhBTYeTIJ3jlhiVZXW+sFed9cO1KkHwfT5smI=;
        b=UgmYUt5Pd0y9J1il6vJZ+4esqjEL/Dlbu7IZX5VMfm+CZ0ZOYrZpKbYMX43wUgKK4W
         LoUvekzbwPtbDjHWOeLS/Z4KjM7JV+nm/4WsHGHM84Z8ANbJ5yQcTUTqL6QSgqcI+Yt/
         zhJ4tLOpep+3SlCEopDti7E23QI2cvGebYjTWSaLbyba1YGzFLPNv8lfey3SBEYGmtnW
         0/vEU8QY7KKZ65Wtjjmgjsl4gvDJLfh8hDKero3+pffuWY71cimiMmQqWQmgZuu9Up+x
         RV9LZQ85rDmWcrK6zqQxYQHTpDCLJPg38EJfZcGhny3Su5Jfi9yGZN+gO08EyOcP70Wq
         y8Cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVFDudxWPQ6+OHw5opnuMy86A7S1u+bTADvJWgx9npWivJ8HFl
	werNIzXl7i2fUFVWC3bXlk4=
X-Google-Smtp-Source: APXvYqx2/cwxvSPzRnUGT71Qtk+f9g44y92feSWt2kK8ALOeGoIZSSasWFvHWJqNrePYcjOy0PP4vQ==
X-Received: by 2002:a0c:fc12:: with SMTP id z18mr777315qvo.17.1576027876530;
        Tue, 10 Dec 2019 17:31:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3ea4:: with SMTP id n33ls152747qtf.13.gmail; Tue, 10 Dec
 2019 17:31:16 -0800 (PST)
X-Received: by 2002:ac8:173c:: with SMTP id w57mr734075qtj.39.1576027876141;
        Tue, 10 Dec 2019 17:31:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576027876; cv=none;
        d=google.com; s=arc-20160816;
        b=RhajKpUX4zXs3a4s2wianqhFzpxmsbaQSyOO7wb1AECt0hVe//fY1D4JKR7k8ZEiSH
         8epBKX94A0ANi19taLzHa2VQUQsKc/4+T8pScyWQVcyKeD6J8VDBUYfj+pPtMrXaghN+
         sDu61wS1+8981YB8JiFXf2P/Dedhuzgkx9UZitmit3kwaWkHCjA/K7VOo8NW2wlRcY3+
         gdzN1fSk2Ott81q/5B3j2CCKBCJtvJgqkEVJt5UIZIqVre4h+4uoeCJtGGN1e384ZBW6
         K1KAgpZs4bDaK3QAfMzfVL3A3ebH+R6PJwwHLElaAYyekfaecBuXchhqBBPVvNSAbNK7
         hOIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9W9FU4s+XkpxX8+vpBjIEwCd+3BXy2AcoZVWQymmBso=;
        b=c6XP/7yOkIumw5z9HexwXlUfK3CVmiW8vgaf/hKovrH4e2BhqIV4+0VDHX5DK1K7wM
         wnjerNj+BFLQWtw+uFxXfW6LYQ5Oz0zKpPje7fhi+VUnnexFjb3nmpQW1tMyFOET+Oi5
         JHU3iXPSKqD8vd9VWknoqWVcg+EQGbl8lhrzCh243ZBSSBpzhEfCAWhoKEum2Mqhs9gJ
         3mD0H3QPgo5NTXGTJEDG30n5gLW5u2a+8DuloE42QFyHq+2MccVCiwzM6zrZMtYulTYD
         CqAIOq4aCr7WPKzfw22/a3n5JkFfCVQszQfP7j1+F7UMhUcTgU5wxowR4PxRRTs3/tXt
         Cn+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0PE2HvuI;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n22si10733qkg.2.2019.12.10.17.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Dec 2019 17:31:16 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 90C61206D5;
	Wed, 11 Dec 2019 01:31:14 +0000 (UTC)
Date: Tue, 10 Dec 2019 17:31:14 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Christoph Hellwig <hch@infradead.org>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, aryabinin@virtuozzo.com, glider@google.com,
 linux-kernel@vger.kernel.org, dvyukov@google.com, daniel@iogearbox.net,
 cai@lca.pw
Subject: Re: [PATCH 1/3] mm: add apply_to_existing_pages helper
Message-Id: <20191210173114.31a6f3e868f94173de76f5cb@linux-foundation.org>
In-Reply-To: <20191209073458.GA3852@infradead.org>
References: <20191205140407.1874-1-dja@axtens.net>
	<20191206163853.cdeb5dc80a8622fb6323a8d2@linux-foundation.org>
	<20191209073458.GA3852@infradead.org>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=0PE2HvuI;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sun, 8 Dec 2019 23:34:58 -0800 Christoph Hellwig <hch@infradead.org> wrote:

> Or a flags argument with descriptive flags to the existing function?
> These magic bool arguments don't scale..

True.  But it's easy enough to do s/bool create/enum mode/ in the
future should the need arise.  For now, the code is clearer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191210173114.31a6f3e868f94173de76f5cb%40linux-foundation.org.
