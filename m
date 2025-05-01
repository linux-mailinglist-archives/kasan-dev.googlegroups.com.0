Return-Path: <kasan-dev+bncBDBK55H2UQKRBGE2Z3AAMGQEM743I2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F02DAA605F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 17:02:51 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-30c165885fdsf7374121fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 08:02:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746111770; cv=pass;
        d=google.com; s=arc-20240605;
        b=cyUhOHbBKSK4tYp3WwfqFPzWwWnpwwtoAR+IEqzAC2U/Vq+baIrZardioyWleyiGiV
         Z375g4u6Zw08VZKLOEOm/+tsfDu7Qepdw2lIBlbqlQrKg6s441iAMl155bU9SaW//gIz
         nha5rEdZR7jCA/iAT24N23OJfXiMmAGw95JC0ZJW/VQyeKKNFW5NFWboSGKvGIW2FJ7N
         AAUv9Nt30O2441ABVQFRrAov0Sv9suKEJR338JakdEFfokccOVBsdBipfZN5zQV76daw
         TN5ayYo8RXMSR5WqtoP1P97vlcRlFDvN+Iex8iJmWwDIbETgzVgKccI6S46kkHYwb9Cr
         EXFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1FU0LduOo9cr8kDChiXmKnAf4GGZgrY/rPm0IiKDPaw=;
        fh=28x8xUigBR6blkl2XXrRz9D1z56dYcgRi/iSrycO1Tg=;
        b=Q9hlUi2PU+rq444jDyps61ovKcp/TPGl7tU/fn6r5UVKHjzOr9KUDHu62ZUWlY9b16
         8Wg6Zbcu+WxcTTux1t1dXIsqL5FJr3ds4Og3jhRhMtiLK8l8KBZqh8yE3kfnnS+7zi8+
         DChzjZW3NGrJzDVxIfbBrFfh9HXmc500xby5uE9Juv/7wDCPYHOyPR39Mepbg4KRQyfi
         wHnRVDedlfYPfSnwXxFyd0scKtozCs0FmXQYq9Q4qa3bQ3kIB9+sngSRRHP2UsMtKKsb
         UjBKb+fimtFhEZm0NmF4z4KL9HvwzUAG70IcXthI0fxpWXynsYSlSuC1xKIkj3N3bHD9
         D/1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QE9K7S0F;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746111770; x=1746716570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1FU0LduOo9cr8kDChiXmKnAf4GGZgrY/rPm0IiKDPaw=;
        b=dLDAdSonA3UT3HuM99kxK0MzmuM4yeHx7d3JodRG2+0SRfnjdymDEemzn37WZHTKdN
         Vt0jIy5HbzbaSKmThBhqRLHX6omkIR2QKYMWuOrrhnYXY9D7D9Mb/W0bmy3Uha9oP/ml
         NGkNOrqobSICNdHYWuFF0IXWZuhABJ+DTqRLxsyZgXaNC6cnAVJqlAxzpfxvG2LE08NG
         eWAHIl9bYnMtoilCNjc80KyQpTXTgJ0qtCSNm2Uf170B29DwzNp1Kn1F1wghTjUwsLl9
         MtNxzPz1pKJVQUVcm52yd3EFKbWRh6hvnIf9Te85JgMo/wS4hFt95h23s73wxqZ6zVvw
         ChsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746111770; x=1746716570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1FU0LduOo9cr8kDChiXmKnAf4GGZgrY/rPm0IiKDPaw=;
        b=clOrHb6KdhbYyV2jBHe0kfjZFq6kvE1IY4HDE7ZIN9azAQ1oIvh/luke4Qm5WzwNRL
         somcACtNtZd1WbZGMFE+oDr256KdbnGAYFBpwoTMwnqzQUR8EV5kqAoNnwTVUN7zc1VX
         Zbid50rBIN2Q5EdKe1zof/hpJJeiE6wzFT/DFtzAIcDYkM3LtL/FH0Vr73DtdIjDH7cr
         QkYUcnhfOCQqtdRCiHFqwVOqr9JU8S7Cdzvxx1mMhSRbVarZpF2AEhv7miQOo6xVPB92
         Uz9dFzVpLMS15MnmA63MEIhxJ2zbuBZbCQKL0ezo3dEwO60qPUuDVeCGMfqsjEXl1o+R
         crzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+FqS8+yoU19u1r7Lxb0bK+2f7IzsWiyByLj9CIbOmPi1OStjHJM0VnI/lP8w12xrWQyJClQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx3oyDtYloBCA9m4KJo+/vRg3+rnGvx/WxMx3R3FA0EgwjogEs4
	mEBsGHj3uiezj0AoUmeF+1S5Vsidn6zXRK/uamdznNXZgiEdlcG7
X-Google-Smtp-Source: AGHT+IFoWZGwmWQwdYiYVu+5qdYh4GJATiHTl9iOknPJMELVf9VNpKa5bxYLsaFXEQpxhA1/aDFQDg==
X-Received: by 2002:a2e:bea1:0:b0:30d:7c13:8a88 with SMTP id 38308e7fff4ca-31fc1d9e68bmr7752701fa.7.1746111769394;
        Thu, 01 May 2025 08:02:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHgF03G4AZLZ/eV4Bs/JbsHgQLI84gqkw56DbRglXbf9A==
Received: by 2002:a2e:b8c3:0:b0:30b:bda3:2e7c with SMTP id 38308e7fff4ca-31f7a68922dls4318541fa.2.-pod-prod-07-eu;
 Thu, 01 May 2025 08:02:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXObfPkhYh6gzD0rVFtBH44ASFeajXvY9edzTF59MlNbIiaJe9+jUZaiX+JRYaosJLyraqA+Lr7U14=@googlegroups.com
X-Received: by 2002:a05:6512:3e14:b0:545:eef:83f1 with SMTP id 2adb3069b0e04-54ea7644674mr899037e87.17.1746111765644;
        Thu, 01 May 2025 08:02:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746111765; cv=none;
        d=google.com; s=arc-20240605;
        b=S8N/v+tp9P1cds2Tj/C/DBTKeuWkmh0/p0NJx0QQI6rLjZ+5tI+cw1vHIFhPg/bzc3
         Oj4/KDZj+LWeWuqVrQLPlMh5KtxeHBC04e2L2gszMj0qBLOcxJt0mSMg2lGQQr1YJVKO
         DJ+humUHxwcriYE2+CLnSQ4holftrPlLStbphAJZEsfOdGsxPy69s9l0fbZtn5CMhGx0
         PJp/Wx7OPn3t32wv0KGVv84giJ2ohnH52maF0fq0cd+SOU6cg34xiu3LGgqqT5Lye0uQ
         QCz2xqJesFRrHpLGh1tm2JRA30RByAKo0XWo+P5oPRR/tcHpNK2DMClwUqcVQpzVHjpX
         YD5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SknNweDJMYv6Cc7JXUCuginAJHi4T0ZKllMpOn1Yf9A=;
        fh=ZuwnSeP6FwlyaXPSOCgT792irPNp9/xqhWcm2Z0rZvQ=;
        b=WS6e420gm4QTwfognue6AMAtTlURPzb2oDpbtjAoQ//9Gsl8/6vQRaWx4SSFfr8Uia
         sZy3ib4ceFoHoHZb8qvKCgEWT8hfs5lY2c0QKccOwhynhXvyHWfcjgEn5KnRGL66S8pB
         +xp+jmSsW01u6rOi9kveOzYuT4fW4Iao5nwI7Dydz34oQ+8Hfd4jq4F40dC7a9Zq2akG
         VB71PeVGpRTn1vBc+7B/aCHenu1E5tW2f/q4GC3E/6uSXyDcrm7qVrF3n7cbWwHyQ2Fa
         0BADHbv3UfqdslCk42BCL4Infr4BNC0WVRIF/+px8gNw9FJhKJCbj4nn7SkJ1Y691XWC
         Q8Fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QE9K7S0F;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3202a5b2067si309151fa.5.2025.05.01.08.02.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 May 2025 08:02:45 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uAVQk-00000000oH8-33tB;
	Thu, 01 May 2025 15:02:30 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1B7DC30072F; Thu,  1 May 2025 17:02:30 +0200 (CEST)
Date: Thu, 1 May 2025 17:02:29 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Brendan Jackman <jackmanb@google.com>
Cc: Christoph Hellwig <hch@lst.de>, chenlinxuan@uniontech.com,
	Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>,
	Sagi Grimberg <sagi@grimberg.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Juergen Gross <jgross@suse.com>,
	Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-nvme@lists.infradead.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kvm@vger.kernel.org, virtualization@lists.linux.dev,
	linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>,
	kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org,
	Changbin Du <changbin.du@intel.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce
 CONFIG_NO_AUTO_INLINE
Message-ID: <20250501150229.GU4439@noisy.programming.kicks-ass.net>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
 <20250429123504.GA13093@lst.de>
 <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=QE9K7S0F;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, May 01, 2025 at 02:19:47PM +0000, Brendan Jackman wrote:
> On Tue Apr 29, 2025 at 12:35 PM UTC, Christoph Hellwig wrote:
> > On Tue, Apr 29, 2025 at 12:06:04PM +0800, Chen Linxuan via B4 Relay wrote:
> >> This series introduces a new kernel configuration option NO_AUTO_INLINE,
> >> which can be used to disable the automatic inlining of functions.
> >> 
> >> This will allow the function tracer to trace more functions
> >> because it only traces functions that the compiler has not inlined.
> >
> > This still feels like a bad idea because it is extremely fragile.
> 
> Can you elaborate on that - does it introduce new fragility?

given it needs to sprinkle __always_inline around where it wasn't needed
before, yeah.

Also, why would you want this? function tracer is already too much
output. Why would you want even more?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501150229.GU4439%40noisy.programming.kicks-ass.net.
