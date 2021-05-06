Return-Path: <kasan-dev+bncBCV5TUXXRUIBBXUVZ6CAMGQEPN44M6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5827B3752A6
	for <lists+kasan-dev@lfdr.de>; Thu,  6 May 2021 12:54:23 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id d13-20020a056402144db0290387e63c95d8sf2431106edx.11
        for <lists+kasan-dev@lfdr.de>; Thu, 06 May 2021 03:54:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620298463; cv=pass;
        d=google.com; s=arc-20160816;
        b=DV0sD29HMIZnUnxjNOeZYQcpECPfnv7ZKEr6kdWh++ZjvNyvIupfItzWcvscHIM3ts
         ai6g5Ony24izs+10C5YxAnIZ9DtJx1hQ2Rza5jAExf/TwK89JXjulndc6ALtE5Ff0OL2
         MCcwSuZmwmXnyYcGr+QF+zy/+zNbiuQ3FJ3k28Pe1TZwLPTvVJGzab/1GOvpObyZ1z9k
         3G46vOeFVgvFXFUIsfTYs2bFAHvL/i6pMa0Xz+0zOesTFrtDQybkCPqhzTrgG5hVsfCz
         Y6xp4LNWlOxh+a7JlaQ9gzp5/gRaDnWICijqFx187AdifAKkdDO73Hgd3ZvaT1YBb4J8
         asXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eC7uGsdVf9KbMoWX1kJ6NfwU7OeWXhwM7Hn7ubN4BTc=;
        b=qd71+WIgS/hkjejYxoXSV9APRd7zpcBUM48cwfQ6fB77Ppg6kHgjBU6ceEgzV04yox
         N4W1Ee5V576Qgqn51UPkD/NRgphHLOpOkv3tqp9Y2dkNrQx2qiBtQbAoDE+farAfgOrv
         xGmchUz5R9xc5VbYNtB5kDVEnu84xsUu6fL/s573phM/pTo2/OLe70uVW3Lksbl/eR5Q
         BrxSO5tZPX9Lb1wxis+lTZnCMBSUs4WKCF3WAWm6EftGshCvong5x1G6Pn0YM4TXirUB
         QlQHw+DtgWjsQDhnTq2sZRjdY35o9CAxkry6yHO+pSVJArXMGv4OL8i2eimkyTnYxXAv
         +BBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="j/1aaMed";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eC7uGsdVf9KbMoWX1kJ6NfwU7OeWXhwM7Hn7ubN4BTc=;
        b=mAh7/RKVpi1BInYKTa7dbtyElInqHegow1qIkXo/PmC+B/h69LEuycgkpL0OYP5ZIS
         d5C8UpAIWEKnBl0cXqyZmCKfY+HzR0COQHhD2HIJhTr1l/G13oM/gq0UJYuz5C0C+j6Y
         zhwswHoDqDuhQaw1e14notic4j0nwJ8uWvw3MPOC4Eb8J8lk56Pt8exWZ4U+YHw68ZK/
         BusKKh5TQdYlTYkDZrcIkg4p3LTTSQv1JSCpy2vZ4Dz+fdJi6CKy2Z3ToqijbAvtDiVl
         zQ/1wuH/t6E2ozpOSH9vZBkwAjT/PT19tJ9n5yNNZcAhk7VOIA7ttf18FIlzserVEoIM
         arLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eC7uGsdVf9KbMoWX1kJ6NfwU7OeWXhwM7Hn7ubN4BTc=;
        b=KLD+TNtceDHV+DXQJChIRukYCoFqb4oqt3oMkPw+7dMI+kP087rdqSORch51jmHx2h
         Wnp3rWIJoRAlOv0Oq0P2giPk9xzxCFAlDGwtANszMIOhWtN+qD/1nKXs/Mouz9cx638T
         MvNNa4nXIFUQ+v6M6xGaK0nVuTkUMGNkger7xhnrEa+dHn78XBzSH/ZfLNXaX4aq1uS4
         YZBhfENwFZV7IfdEmdWSRrimYggidxe4OkPHF1fnISLrPtjC1ugGKLIG18K5K2WHdf4S
         MuLRx9n9eZ7I/+MRFGo9ZWvFzVjZMuF5hmI70bqP9eF0QiYfsXnpWZpPoo0DozyDw/7N
         wcLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Jl5GnguEXRxugERBZ93/rkDT1ty6nII/I9ikeDBEuMMDRCC83
	x77Z5dNPsJ6wxk/8VkNBVBE=
X-Google-Smtp-Source: ABdhPJzSsje2m/gEVScc71/e+OB+FwELKq4ij9ajgoNcB6SWvGZchhvPs2icEYoHR8R47/nvVERziA==
X-Received: by 2002:a17:906:3bc6:: with SMTP id v6mr3781101ejf.165.1620298463065;
        Thu, 06 May 2021 03:54:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:acb:: with SMTP id z11ls1124216ejf.2.gmail; Thu, 06
 May 2021 03:54:22 -0700 (PDT)
X-Received: by 2002:a17:907:174a:: with SMTP id lf10mr3845062ejc.433.1620298462042;
        Thu, 06 May 2021 03:54:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620298462; cv=none;
        d=google.com; s=arc-20160816;
        b=oNYIgDSWktMMoD7wYyZ97+YIFKSSeQXBLsn2xXh01fK9ASX88PO2nxUxsQKELStmQm
         7wfS3jqu8fFnP56ODbYU8o/jgGPafjUXTRs72zJlIXroSyNdaiJI4Pj3Rxy0vp/1eUHx
         XzZuOpREWCJd9T74/A6dKEV+5i7Z0BBrXyN1eCGJfspu+6LWNlCYNlaVdEpOahUfkcl6
         9H6bE5c30R+zaFkCgYzSu9U892jCtdf8H8aDhmagbAGsXRe2cPr/PV2TrtGJTrQ8ORY3
         JbpO7igzA3bXnJiry/hCH+9Pj6OTHim7aIrPqbGr7IL4afDNuKIcVlNvKgcOFjuXD53B
         guOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OGAgGqtk2aQf4lRyJ1TmlGnAs66cYrU1G5wL3SCCxF4=;
        b=VNGmoWr/r4vWqdoaTP1zTkNOVja5Kb52S+drh3icEqpkV9lh9AbYKFiNOUgJCujJ3F
         dOmOMUWGv5VcKBnadJJvQ6Xkooxvy8hpfZYR70MJ4g7fE3wlb+3suYZxyC6TVxWuq1Y5
         B896D+H77AB4f5n2J7jGH66I7dQf/PxthmMxZTg3ypPL+ntTwpjGT0Bx1bimcHI1MjFL
         1/6a7DI+4Vl8CkjrMZog3yHrTg6O2SD1LT84mJfQY8YmCmdzFsgcbWNNIU5UKgij0rmc
         VQq1AX7gIPtP6OcKbGOHOzZGPnhFmV/Y9n5piziPxlpYXDpE16Icp74PHmCLsrilZJkr
         LtGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="j/1aaMed";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id g7si59875edm.3.2021.05.06.03.54.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 May 2021 03:54:22 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lebdz-0042wA-Ex; Thu, 06 May 2021 10:54:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 94500300103;
	Thu,  6 May 2021 12:54:10 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7B8D32C328C4D; Thu,  6 May 2021 12:54:10 +0200 (CEST)
Date: Thu, 6 May 2021 12:54:10 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Eric W. Beiderman" <ebiederm@xmission.com>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@arndb.de>,
	Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 10/12] signal: Factor force_sig_perf out of
 perf_sigtrap
Message-ID: <YJPK0oWD8t+BYvMQ@hirez.programming.kicks-ass.net>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-10-ebiederm@xmission.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210505141101.11519-10-ebiederm@xmission.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="j/1aaMed";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, May 05, 2021 at 09:10:59AM -0500, Eric W. Beiderman wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
> 
> Separate generating the signal from deciding it needs to be sent.
> 
> v1: https://lkml.kernel.org/r/m17dkjqqxz.fsf_-_@fess.ebiederm.org
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Thanks for cleaning all that up.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YJPK0oWD8t%2BBYvMQ%40hirez.programming.kicks-ass.net.
