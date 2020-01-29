Return-Path: <kasan-dev+bncBCV5TUXXRUIBBR5HY7YQKGQEOGPGCXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id CA3A414D0B2
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 19:49:44 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id o185sf220778vsc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 10:49:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580323783; cv=pass;
        d=google.com; s=arc-20160816;
        b=OTEFfUDAC3oewnS33LsVAzv+LcqZJBrNWzFsdlnTKlGX/7JaghNbWy5adz387V6sld
         ZeOMibgfnkL1WipKVdoJ79Jn7eolwO84kDXTN1pKA2Cu1FdXOKSWY6bNqW7VdxeXn4Sa
         XblFibv3TdkQfQjt8w6ZsvfyqGHhe7+FI5H5y51Mb6k1KVQRtJGZTuEUaK8/X9CqIcGH
         QOd0lwkqXfaK9lmwj8tRVHcB4ptWKtFKUrLyAwNOGfYUPKYxDuHfrik2kg6CQQTX9wOW
         a9lvZOwJ0UqcnW3lZ7/D7KJ7G8W+VYis64dDKU/Qo5iSvf1m8havyhN6WiavT7CjmFxR
         KHKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=GjzW+7ZK8C4JAmZ9fygE4rsVkRLao/4b93l1UkzKCXQ=;
        b=d2eNykiCS1XjyBCh00Yp71e/9akV/seBNVbhf6gKeoU0eDcAunriI4b2tSqTKLCowr
         HDh3/zOSbNDUmILXjTnViemOJARojJQgrCyKcROfiniLZMxa6C8FdLKrkAlQuBUuGqtZ
         iEb95PB56lTPXaQD8cT3eVzzpffiUiK61L9MPIOFbWv90VYUElMTRAbkckeVkfjumE3k
         UuS4cTrqSE40DPqipsqzap6POuA6Ild0hVeg3SID4wEnUxf7q+7YtAKs5zrAoH51L+lJ
         NmhU888lfzN3TLqb/nZJOku/NYarNq97fr8OPYnumuIylmgAL21aEtO5wKkTLdj84TXl
         Yrlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="sr/jic7X";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GjzW+7ZK8C4JAmZ9fygE4rsVkRLao/4b93l1UkzKCXQ=;
        b=NjHMi0xcYFPBNo0BPmMCI6Bz4RQwr8PXV4LsSQruisiqXYlaJXZMDnj7NiIs/7C9Zc
         vteN88+l0GZJgnER+JXeX4turvNjzhgnDv+pv+zEdYgclh2siIBOyOxT1+xwUDv+Sgyr
         Jj4wmkVLjB/h3EetombjZstise34P9FZMvVUB2vV6lTrhzUtubKr4/oJSeVw9s957OkO
         H1m/4PiIGpX2+07ZrVlDLESYbmrCYAlRWcSjDZPIT27h1LevnzPyGFZZOanbFyVr93Wy
         LcEA9zR6YlJoNZ1QeY/GlzeEGG5aq4JkniqWIcJShYefWd+b+sTH6E1/D4GPR4faIHVf
         5Gsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GjzW+7ZK8C4JAmZ9fygE4rsVkRLao/4b93l1UkzKCXQ=;
        b=HYa6wrPVXcs84DtLeba1DBfkjrOiNJgyQj5h7R/VHNtL1RyUqDCSiXagYeC+GZ6/R8
         5/31oLBJ5yiiPK5MjFdQug0FayVrdpznL3JbB3sc8jiC9i9xMw/FpmWimrP53fhJuu7x
         lR5n2zElEOx69fVW88vtfzQUa6xtGxd/WNZiqtvRkBLN0TRYd21WRGxI2Vyu5cGebwQi
         fLXnDB3p25yy7CUHBjQfMv3Iw3lvh68qBICM2cUyhqwacMN74Cc0pjd4tSBEdW52CUrZ
         4XlFPGQiamcKFkteie9txuOml0wuoysE8xH3GOTOC12d3mMrc2D0gBn4GTYf3k7YSLFA
         mHpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXiZjn9MFHrIGLcX7fywaQEv6jqDOS9dCTzoiadae2UwiW3aOgp
	Zz81X3My7ILAJiyA+E6qCJg=
X-Google-Smtp-Source: APXvYqyFpHIqMjt9JQ3i24cxHc1ZqejFjtQTcYakGJq+txpTyIBVMlmEgi9Uybw4Zc46t99sSYP/mA==
X-Received: by 2002:a67:31d8:: with SMTP id x207mr695782vsx.192.1580323783568;
        Wed, 29 Jan 2020 10:49:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:20a9:: with SMTP id y9ls40454ual.9.gmail; Wed, 29 Jan
 2020 10:49:43 -0800 (PST)
X-Received: by 2002:a9f:21aa:: with SMTP id 39mr156093uac.138.1580323783219;
        Wed, 29 Jan 2020 10:49:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580323783; cv=none;
        d=google.com; s=arc-20160816;
        b=gz4wWKEDppbwZ7zAAybXhApG9hFRn2ajdq7ymNpuZ5wZ5xuH6ZWcbd+KmnmYY4TRPe
         8S6AveMCEeWytRXn/PocAdGoyVVACXK2NS/reGqy+62dcuZa7PqTevhjzxYPnsLFy99t
         Vlt8ODm+dVU38GnFKizkCmNRGxu7tF+jIIRyzO2+0QqZl6OKM3h4dIMtNJNjTU4ozEfE
         OGuIXhzBtkMieHJSzz9R3tKaIwM4R72AMBoKzbgDhUnfe2voxLZQBrU+eL/Xtv4EuWUO
         wrbzwp4JxHH2i5BbscHXaUT6s6U0ERgvpcgUGhJ9GcU8dC6mfF21PhxJo3+KKdJzDz/8
         /Eyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KUyQBoXhEovxNfF4eKqrkEbw0GAhd/ZaP73j2VawXbg=;
        b=b09MAwVVWee7l7dMTLWEc81HGUwo9lG9v8nzkdxTWXv+ERQEuET7EzCXlLOxxwINCa
         dz9whvhWmWAIn26mrvXWLkhlNsolMxt5Y6ZEu1O6gUKBvoy5hosgIRh43cgNCXwbSe2X
         iYTBAVY6oG3nh1GxqrE37ROrocVk5+5pxb/E8PGTHRDemfnmw8hFRdJjcTOra7VYBoZj
         w5A6dUiZdu4VxoDC1QWJXIcalf18MvJFZ07zvfO9hVqlKwt9DgoJWfp5MAQ+3qaCc23n
         dRt8EtKi+RzSFLxm0w+9hE+q6oWgz5TxF6/visotQ1VZAFfamTkwXl3UtnwBp79KfoK1
         8hNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="sr/jic7X";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id o19si174680vka.4.2020.01.29.10.49.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Jan 2020 10:49:43 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iwsPB-00028n-UZ; Wed, 29 Jan 2020 18:49:40 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 178F33035D4;
	Wed, 29 Jan 2020 19:47:53 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id F082D2B7A8620; Wed, 29 Jan 2020 19:49:35 +0100 (CET)
Date: Wed, 29 Jan 2020 19:49:35 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Qian Cai <cai@lca.pw>,
	Will Deacon <will@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200129184935.GU14879@hirez.programming.kicks-ass.net>
References: <20200122165938.GA16974@willie-the-truck>
 <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net>
 <20200129002253.GT2935@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200129002253.GT2935@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="sr/jic7X";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jan 28, 2020 at 04:22:53PM -0800, Paul E. McKenney wrote:
> On Tue, Jan 28, 2020 at 05:56:55PM +0100, Peter Zijlstra wrote:
> > On Tue, Jan 28, 2020 at 12:46:26PM +0100, Marco Elver wrote:
> > 
> > > > Marco, any thought on improving KCSAN for this to reduce the false
> > > > positives?
> > > 
> > > Define 'false positive'.
> > 
> > I'll use it where the code as written is correct while the tool
> > complains about it.
> 
> I could be wrong, but I would guess that Marco is looking for something
> a little less subjective and a little more specific.  ;-)

How is that either? If any valid translation by a compile results in
correct functionality, yet the tool complains, then surely we can speak
of a objective fact.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200129184935.GU14879%40hirez.programming.kicks-ass.net.
