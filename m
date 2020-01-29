Return-Path: <kasan-dev+bncBAABBX5AYPYQKGQE5V4BDDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id CBBFE14C3EC
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 01:22:56 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id n17sf6493030plp.10
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 16:22:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580257375; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y/cpXUgro/FAV2l6tg8fVlKWdzOieMhwTIigyvpnJ4zdQnucr+E2cAxaWtuK+KE3st
         z2z2BSvvnbJ+mGPN0QLMCA9s78bBO5Lct9ZZ80UTK/UznZOSRopa8eNo4p8ly8KWi7++
         by73a91LE2QNJ3fonDkJ3n4i8Yf3eUcNC/0GjdjFhCu4O+gKVKVDtf5szhtzq8sQSngT
         L6jw/xGzX9qzdnmUYX6/vR290oQ1hqyWEtl9X5Hk31tMBI7P+5BnqZY/1X93QmG9YNOX
         wkPzFN+SKDrEXB2DPnUYpx1vzMcIRfE5Dr3ji3+WD+6xQQKApNkZM1miVEDvQD1bOzGk
         cE3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=w+O2k8Adhmwv2+LE5uctI/v2yRsF5VNxV9vlFH0ADlQ=;
        b=wQv7RT74H8RxHSwYCe1AVeSAqPBGQYFT24JAdlEpEieQTnwlqOffRQ4ZdcgA94d7IJ
         5dkdF7NATFFqhV0SypcadJLlYONaYzAxIRYpMCl+obhHiQfxP6MvZOZ4oMl+j9SifM2S
         vxZcDlPRqD73yjmubmtb8NogevAoB2N6Qb0BYkRlsUi77XiK2ZMezZ/SewMxa5t2KEhO
         FD22FBgWUIA93thFhITlIylRurJ+CM1i7MxoeEL8ur2HsADFMvGvZYf9ml+a4QQHu+Wc
         V0gv+9iyRIw9zpgmh7LaULCiQSfiex++TachNMfwbY3y36zn6PhohIarOuMSgeo1j10o
         La5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Jtv85/HY";
       spf=pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+O2k8Adhmwv2+LE5uctI/v2yRsF5VNxV9vlFH0ADlQ=;
        b=BxbF+90BNDpF/LLfNoMsVLUyv6ai9CQjyQeJuraUJwHrtjwzEgNFZI0ACAA8OCcLmK
         OinZtdxkST4UHoS2Aaq3gpGetI8h4hXf2jNZHWb4RgmamhHw6dMnPaPxHfoJbS0Iu806
         EzAMASYEQLvY3/9RP9vbCsdRNUNxtGbcXrjGBOqmNdgPH/6eigQ3Iyl9oTJlladIas14
         5FneMb/UWPJZLJjbQBuUoWQ9OrTHmevpSZdoRUVGQFekrfH45ZN0SXUL5PDrBO92Kxfb
         4hIwnjPKj8JKaYqEjAkyXZvbJFf/3Qb4wD4F/Lo7ErO6DSmdGVWNqSeVjNo9d5lBgv4Z
         +rIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w+O2k8Adhmwv2+LE5uctI/v2yRsF5VNxV9vlFH0ADlQ=;
        b=rz/E1FBRCRysJpbPnLTVteBXRszlWLWuv2/nai6Slo6QMCydzOQgyqTFdG9M2fq2qL
         69Ce0rRu1ZXl+mJvMaShg+lkPoFBDqRoAZ3uBjHyialeR4nKpqdczOP07Ht8kUtfWEnm
         swml4dIOeCyDBj1CfYutN5iccH33F4hBQnTSdt8Mt3eJWNM3Mhd6itxyjyQB4vdlENWC
         XmoNLZ8KGtUdfeMZODf6YlQnV706GSM8Sa7pFjMAn6yWB/RLy41DMXIy+YpSKwqg3AZg
         hrJM0nKAAOEEFlNaxQw7/7Vgw7QfPMfqt4i/2wSJsQNfCjvCRGiG38zeESnjcMUj657e
         OkpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW9WEFl5L/qQsYfAv5B/uTWth0xVouC/DXjsFngfhavwOrns2Lr
	sgjsP7jDvEPXerauvRUbIqU=
X-Google-Smtp-Source: APXvYqy5yKj/WuYjhCp79bvqY49DK2pDx6huncvxeEEzS3uAtDnux+NZERwaKOv6LSqFDsXvAhBdKQ==
X-Received: by 2002:a17:902:9003:: with SMTP id a3mr24543529plp.339.1580257375298;
        Tue, 28 Jan 2020 16:22:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9891:: with SMTP id r17ls5528717pfl.5.gmail; Tue, 28 Jan
 2020 16:22:55 -0800 (PST)
X-Received: by 2002:a63:c652:: with SMTP id x18mr28260519pgg.211.1580257374936;
        Tue, 28 Jan 2020 16:22:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580257374; cv=none;
        d=google.com; s=arc-20160816;
        b=PRmlOKcs38HQ8T/qIQhMXpjtq87+jTNVfgz1juc9CIv+AXrXWLOtFhBa2Zq4hT5KTP
         5CE53QKuHtgdiNiUoTsu2uKpK9Cuj4zGKdeBL3vuK6QKAN8vi6Nm4MV/TTFrrNcFjMHM
         Zg+tbyPAERG6i5MTK5ZA1/rKVqVjWVysx290XmKGUjBqyoaXGo8L42lzPvZb9Ewnr+kZ
         s48JyIA3gFkKHuAlq1xN4HaLaAW5FrKbalaQNUwuHQkqz7JRXFAUDf9U0cuIAueyJGVJ
         vLFdX5wUgP2Z21uFAqH7zAC7bqLxZDGbomOo+VS8h1wWXDRkJB8xkc9NeNhmjY2SVxjl
         P27w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=S76747lBrI4yuCdNVC7l/zrn7Bh5HOmFiO+OEZzKzn0=;
        b=ThROzqg37KhkmxIxzS9/y6z7BW8kjGaQMulLNHdulARLNhbyCmlk1R5tdkUKkOyROU
         zM9ng6p3Wxn2T1NVdzmEYgTKSsk/Rv6MnsW5Hvwn5Fu2CQsn1SNmAtDD10BPxN40ucn1
         rGIR/0BGC0oWa/AumVWzzxp8Q3kNnFZr68iY/0jXLUe6XxrG2RXrT009dK+Yk5XbCBNd
         A6nQ1g0ShTSIwYR+8ItbhCQiVZiIxMgVsg6Hh2YbQrx2VKXHt7jGwMjRfSY47IyLFGa9
         G7MOggT8CirIZ7JExEWHobAn5gFxecFFJxh5WvWFuoWjycYsziD4H1s6FwPjpHGKwopm
         NOPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Jtv85/HY";
       spf=pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r18si16946pfc.2.2020.01.28.16.22.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 16:22:54 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.134])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8A3DB2173E;
	Wed, 29 Jan 2020 00:22:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 0084C352273D; Tue, 28 Jan 2020 16:22:53 -0800 (PST)
Date: Tue, 28 Jan 2020 16:22:53 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Qian Cai <cai@lca.pw>,
	Will Deacon <will@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200129002253.GT2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200122165938.GA16974@willie-the-truck>
 <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200128165655.GM14914@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="Jtv85/HY";       spf=pass
 (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jan 28, 2020 at 05:56:55PM +0100, Peter Zijlstra wrote:
> On Tue, Jan 28, 2020 at 12:46:26PM +0100, Marco Elver wrote:
> 
> > > Marco, any thought on improving KCSAN for this to reduce the false
> > > positives?
> > 
> > Define 'false positive'.
> 
> I'll use it where the code as written is correct while the tool
> complains about it.

I could be wrong, but I would guess that Marco is looking for something
a little less subjective and a little more specific.  ;-)

> > From what I can tell, all 'false positives' that have come up are data
> > races where the consequences on the behaviour of the code is
> > inconsequential. In other words, all of them would require
> > understanding of the intended logic of the code, and understanding if
> > the worst possible outcome of a data race changes the behaviour of the
> > code in such a way that we may end up with an erroneously behaving
> > system.
> > 
> > As I have said before, KCSAN (or any data race detector) by definition
> > only works at the language level. Any semantic analysis, beyond simple
> > rules (such as ignore same-value stores) and annotations, is simply
> > impossible since the tool can't know about the logic that the
> > programmer intended.
> > 
> > That being said, if there are simple rules (like ignore same-value
> > stores) or other minimal annotations that can help reduce such 'false
> > positives', more than happy to add them.
> 
> OK, so KCSAN knows about same-value-stores? If so, that ->cpu =
> smp_processor_id() case really doesn't need annotation, right?

If smp_processor_id() returns the value already stored in ->cpu,
I believe that the default KCSAN setup refrains from complaining.

Which reminds me, I need to disable this in my RCU runs.  If I create a
bug that causes me to unknowingly access something that is supposed to
be CPU-private from the wrong CPU, I want to know about it.

> > What to do about osq_lock here? If people agree that no further
> > annotations are wanted, and the reasoning above concludes there are no
> > bugs, we can blacklist the file. That would, however, miss new data
> > races in future.
> 
> I'm still hoping to convince you that the other case is one of those
> 'simple-rules' too :-)

On this I must defer to Marco.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200129002253.GT2935%40paulmck-ThinkPad-P72.
