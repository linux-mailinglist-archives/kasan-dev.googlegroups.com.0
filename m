Return-Path: <kasan-dev+bncBDBK55H2UQKRB34AR6KAMGQEQ5CYEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A097A52A6C2
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 17:34:08 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id m2-20020a0565120a8200b00473a809c6e0sf8131883lfu.11
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 08:34:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652801648; cv=pass;
        d=google.com; s=arc-20160816;
        b=N4cfUpejHVpbknc9FMiwqquLRyF218EK1dWONjkvP9RyA8qGMjUqrU7ebRG04kjDM2
         ll2xux/TrfEfxGmkUdF3SM/zKRj5c22fK8FFLQjSgqp26SxuinWbB4+m+7r8/H5kWhik
         omnn1axkgc5RFkUPTa0+KdrE35w2IRAKcflEMFxwFFOZkV4HGgFAOCJjGdOY42VKph3F
         IK3iwX9XrignmMuzTq1KekWiibMET9vCqoGE51bubXBsd7VupuV3zg3rEuH94N4QEnM7
         +XaVZH9J8Q9qYDitu9WAhn/fK2gocUuKRyGcB5PgiERCoIZpsq29Xzl/Y58XWSygGD3N
         I4qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MH69HXv3u+dvqSzqNmQepBD44/yymGJdPnzTEGT6CHU=;
        b=kK55tb2JmxYx7SaXafbrFKg8EL6w3ybOLGSziCzNmUdx0e1coXVzM6PRorsi7R1FuJ
         xjEQAQBtA+BWRoaWn27B95szaiJXzULUf2OK0xqrK7NsxZR5mYjLZ6z2BvGAAZNOUo11
         H4hJ32uo11ZHfaO3UlT7vdOSsEZ3B5La3N8X2QAlGplRKRltYVlhseEcfM8tXGZEtRAm
         bq2qPvFz3cpMcUbgmBeBfzssiukpI2lAGhYtDW8GIq6jDv+r95TdQ4bxyWDsh7EAtlQY
         X8UbgBqcddabYgYj4oRzI25jfYQk1uZd0KQGq1evmRLNFg7p/Ui26PSilcMt6IA3vf/s
         4jwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=MKqNRY0K;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MH69HXv3u+dvqSzqNmQepBD44/yymGJdPnzTEGT6CHU=;
        b=pHxKyrT+xUlJjoIYPbTe4muMbXzr8qp3fQoqb8phAHOvbVNrjAgdH9U8wUh3Whp1Lh
         p3HZIII8pTM3S6G/SZWvrEFH05+nRvTZGDCeszORPwVdNxCwS/+O8WG2q2X79xwXGumE
         FO27rWxtccGSNuRfpPAx4veaNLw6WBrGnOvzXeAvSqxn6Fk6JfMOKfTjKPTtJuPjdhjn
         jWla3s0tSQnH9S+LC4BBBugbwy8iVaUWnBDnNe7nWgGGowDOzjXn7F32W0u5WbZK8P06
         ZO1QtgGZeFP0OW2sc90rhygdEYVJ7EBPe4QBiIsqH+o4YS8L1nVzrKhuWCRYMkWcEX5g
         u8ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MH69HXv3u+dvqSzqNmQepBD44/yymGJdPnzTEGT6CHU=;
        b=mozR0iDSmznhfQFDxioWELQglJ4dh2RU2jYGSzglbKEP55m/2LOdQAtJA+xu18RWGC
         QyOo/cXL7F/AtApGVBnJ2xZ5+8nt41TEi7XVI/en6oI4cRdiQQ+dXRsJt7TqPgNcHX4n
         YF/L6b353orZVYeSl090CvfjIaE97DzvSRe9B+zf0wwipcV/2Xgre1OHRMCZIOFzw5Qu
         MFU6XTBlA6EeY+0VrACvKFCmSSDrV9QXIM+GlTJPtYsumVw4Dr10oSnX/SdawPofWLtD
         khlZVQS6n51Q/DOFX1tQ2Aqo+DHM5aVhKWQhMaIneC/L0fJU8MqXEG5H6an+3xsmJAWj
         vrCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533sW1AeDi63GrYS1LvNoxfKALQGh929EpDhkzlSqQa9fTLD0eCd
	Cht8L5A8nvmr1zL9WS2MwXI=
X-Google-Smtp-Source: ABdhPJxj8/2Ck7odSYmWCJ0MS7VxDC7a9Gc2Q/ftL9lin36Hp0PDGjxR72qdsj/G8iiV8SZtVX1qWQ==
X-Received: by 2002:a05:6512:ea1:b0:473:bf79:e124 with SMTP id bi33-20020a0565120ea100b00473bf79e124mr16888902lfb.191.1652801648060;
        Tue, 17 May 2022 08:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls11922669lfu.0.gmail; Tue, 17 May 2022
 08:34:06 -0700 (PDT)
X-Received: by 2002:a05:6512:1095:b0:473:bf36:b6b with SMTP id j21-20020a056512109500b00473bf360b6bmr17512001lfg.479.1652801646652;
        Tue, 17 May 2022 08:34:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652801646; cv=none;
        d=google.com; s=arc-20160816;
        b=cUUNpT2a/BtavAKzHsOMKS/6tE7o8Rgz0sXz194d7CNaYWOmTHBBgfEGUpoWkUurLp
         rdRzRGKKwANMiqh9XmOnl4UHi3wbadfmKxsDIgqp/7ZAhq3sRIQuzgqyuffo09a19A+H
         gcg7N7Vh0BKuWr+yvZj2CSYgRn/Fmfrz0YRl1y6VZbuMmw6QeY4N4KreuAvc7C/W1jdZ
         qwsYx0OwZ19HbmodMpXavBJPgc42jheV74xQu9FdW15vrpqvVrLxSQhH8SjvlbOjoc5j
         /rjib4adbcu961CPAnEAJKwsGojn3zEliU9OjG0MmwdCD1B3ZW23AOJUPFQDAyvR2RAU
         qCYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QUA40l27Atipc/0PNxihSWYvuPeTEXNlJJYQ6mlD0PE=;
        b=sIUIgZOndjCPY14pg65CM1TERqD43KevcubQbkgCH2KlSDy4I9VBxS+1npVopBiQSd
         PyWAr/0wd59R5KxhLtENt5h41+oc9iz6QBr+nFU9bm8Vbs/Jwt1Oi7qeYo251dpoOV5T
         DazmnMZ1Dw089xcbLO+5oiM7ij5QNRmtpBQmU30QMP62piU9opfE8KMzXb8hyHE2ZxBA
         9eRGfooyN6xazE+aZvbDZinHjMXQCtBRAAWPfM3vxUX43noJh1hFgvAli7GBo0QCVjsR
         TLd3Fg21sbGblIG1FHuLN9//fCF2WCEfZQgTotFD8lVJjM22q4keyi/DsZ5XsJcikFLL
         474A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=MKqNRY0K;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c1-20020a05651c014100b0024f2df47312si2337ljd.6.2022.05.17.08.34.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 May 2022 08:34:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nqzCz-00Axmb-FX; Tue, 17 May 2022 15:34:01 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2BA64300642;
	Tue, 17 May 2022 17:33:59 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 11E29206DE508; Tue, 17 May 2022 17:33:59 +0200 (CEST)
Date: Tue, 17 May 2022 17:33:59 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=MKqNRY0K;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, May 16, 2022 at 11:40:06PM +0200, Peter Zijlstra wrote:
> Does something simple like this work? If not, I'll try and reproduce
> tomorrow, it shouldn't be too hard to fix.

Oh, man, I so shouldn't have said that :/

I have something that almost works, except it now mightly upsets
modpost.

I'm not entirely sure how the old code worked as well as it did. Oh
well, I'll get it sorted.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoPAZ6JfsF0LrQNc%40hirez.programming.kicks-ass.net.
