Return-Path: <kasan-dev+bncBAABB74JT73QKGQEVLDBDVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B8B81F9FD3
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 20:59:13 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id nh9sf481928pjb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:59:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592247552; cv=pass;
        d=google.com; s=arc-20160816;
        b=jDypw2UxuQSXSUe1D67JkRVIssZYlB+R3BsBHiVTSULHNBC/KnY5adji5G2iZ9DzCg
         a9gyxwMoUoqtY2xbmknDmK6usRZzprk/gLOZBQ9mQEfvdikEMzwJwE27wnmRSnRAlEB1
         amtN7t7pHZZFVO0moivm73TM9X9p0pqoa/fxYkSpT07ph/KT5vJPmu/rFvNDWYOoA2d1
         3FyIrUnwapPtc7Xg2/qKdK1C8/XNjPqAOBfTbAH3jSqDfKSZ1OxGa6LFM19wTORk3XRv
         Ds23dqubap18rnN3d0dbqs+eoUNmpf8VxPZDO7cBnDKLwgwbp6aisWcPjKuxnZiSXWe5
         B7aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=2Wx+fH7FMV6BVUfT9cpLuM4IUhiK/eNATz/6lXhkI+g=;
        b=XLRhHkcTWkA3ETz9aerck4l1zaHhzi0rr1gTDl4dIAFsrm7MT6t7vfd4Zi9hOjDx5I
         79bNiZCNVnB3HHJxXW7lmRjiQ0Y8jyVUbRnxhQj+6RwD3Tg8YtGNS4ZYLWKL20b1pNHG
         xl14oNwS/uJMtpMRJC90wesdJQy625Mi0eQPDkSdaHINI5YnlNeaEDmc7TqJembzNX/V
         fpnooyk3wC9bF3njHkSpz+MumiRLAMhigQ/iXhVfdbz0fXTOjq+84p8SwEOmw4tiH+OL
         Y+S1S5pSxmaaPpyjrTBDIPC0rfvLRHkcJjliLu31syrsoVIrfG8K17FZu3ZNJVpUn0Kx
         dl9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="kE/HXzcy";
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2Wx+fH7FMV6BVUfT9cpLuM4IUhiK/eNATz/6lXhkI+g=;
        b=XILQT75mpyPfocS6bFMX3WFCXL7WvMqR6RofY4rPjnDCpGuDr6Ftz3mPd7Mg4FBSkQ
         gkxa0D0JgdFsAoxP0dwOVQpt3W2+LEugn2bw6irFNDj36S3C2DZBKH4ezcvwNSUj43QB
         Jac7iGs8HXd0sUUDzzc7gVIbmjQy4CDBvX6v/EcIVfpwvKMwAhpjRVhDgQyQ+mRi1HVc
         gQqRw6Qbomis5OQ6qJCPIqlF1C9GUM7xrrVdabzT2ZGTjVwOaPEZ0tESzs9OpNYEkHFa
         j34jAZU0TcGcSmK2WMhukSYC98iwp8/GiVTcXh4U9z2gkVbBacHFhsNuBfsRjHg471r/
         bJpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2Wx+fH7FMV6BVUfT9cpLuM4IUhiK/eNATz/6lXhkI+g=;
        b=bTXZeQXLqlibR+whIVymzOXflIMNAo26763W2Cr8bsjK/73mSoRc2aFeHCqyv2k+1G
         32WQkCisFKFa5t773s9om54qDFKTSL+3GI6sh6/TlCPm21o166cqxc0xCT0+U+fFnlwk
         K+20wr3/Jlc9rHJXYfjDfiVLiVv+pdDfhmdwLR0/306MgeGbfMnSUW4N0NBy3wjjYiZq
         DW2fDlh7c/R6QDruUuCXvkRoBiz5xzMX8IkY2Z2MliQQeZ+ITV8Zko9om5QJJ5+XZTkG
         L8q2IG0kC589iZzkJkpf06KuySRcRkIaqYWDHqJDnLC3HgMExb2NEl8/LXH39yHNtTlh
         hakg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533l1vRNE51J3XZADGu8bYnlMs8JWpZTpeVdDhivNXYxk4O5GWaT
	qYR4GPVakfNdcn5b8M4uMDE=
X-Google-Smtp-Source: ABdhPJwrgIkkJPEKYVxYHtFvdnUof24nbjcagQINMDztIs2h/CHG3eIXHLHhtWfOf5bvqZNFk128fg==
X-Received: by 2002:a17:90a:8b98:: with SMTP id z24mr690111pjn.159.1592247551852;
        Mon, 15 Jun 2020 11:59:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:dd4d:: with SMTP id w74ls3805060pff.4.gmail; Mon, 15 Jun
 2020 11:59:11 -0700 (PDT)
X-Received: by 2002:a05:6a00:2c3:: with SMTP id b3mr25828058pft.20.1592247551440;
        Mon, 15 Jun 2020 11:59:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592247551; cv=none;
        d=google.com; s=arc-20160816;
        b=KFeU5PhGgA1DSzcEtLZOrxWBcvE5VP2huc+Q/umRDG3pMEZ/2WunZbi1LMW2IKxzST
         EprHD553ELq1rE2eB6Pg9nRdJbNvmVc10nO8gi2UuBUI6tgGCOcgc3VX2okWDUB5222v
         JDxe/HV4Y9tTE2ygPgZLDheZtjkf1C0UQxLdffrI+AGWiRUJ70pt2QuSFCfmXHrIHvTf
         pk2CfjwXizR0cxmEElYoBA/gQg3QM96CsJKUCyMkTV5yaRTPWJrgSTAouzADWPaBIeaZ
         wv/WMjlFcWrasznureqb3Ku3Uc2v20QlWajuMZ0acLZ6hhBGpD8/C1XyXmvVObMFisiL
         zSeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=hykCyBUB8Lr2LHf80P4nlJBTolxiXkUmGxCdrS/mEio=;
        b=KUf3qxPRaZJCKrg+R4nAy4+4M02RMKmfEPIWNzWCgxVWNtZgIpVYSDQQvKiDvvnJIL
         eiVvpXhnfaWDYWAGrAJBTk0WEQFXfz0SDMuOrCzYYL4xMhnZtq95bBNxhvIGFz4Sfq/a
         ks001yFLa/RlMRQFTDC1yh012dlJMeEuqihBQho9BmGldubcN6tbBM8VGOYLWRyYw+uy
         EkGdSq7rcOL7z1Er+SWRa2CyvQtkJWGA108mzI1AjjtS9Jy91ltLPO9FLIVwMm/nIXGG
         CB0ZLZ9pFGpJ6pH3teQVq2KtIL/2zhqayw5XO/1GDfoidJM6WVUcB91RLhISlML800Cs
         yrDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="kE/HXzcy";
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m204si1084534pfd.1.2020.06.15.11.59.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 11:59:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2257E20656;
	Mon, 15 Jun 2020 18:59:11 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 04EDE35218F0; Mon, 15 Jun 2020 11:59:11 -0700 (PDT)
Date: Mon, 15 Jun 2020 11:59:10 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615185910.GK2723@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
 <20200615183325.GF2531@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615183325.GF2531@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="kE/HXzcy";       spf=pass
 (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Jun 15, 2020 at 08:33:25PM +0200, Peter Zijlstra wrote:
> On Mon, Jun 15, 2020 at 10:14:04AM -0700, Paul E. McKenney wrote:
> 
> > This merge window has been quite the trainwreck, hasn't it?  :-/
> 
> Keeps life interesting I suppose..

;-) ;-) ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615185910.GK2723%40paulmck-ThinkPad-P72.
