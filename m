Return-Path: <kasan-dev+bncBCLI747UVAFRBXNY42NAMGQEARZDPUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A24860EA7D
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 22:45:18 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id c13-20020a2ea78d000000b0026fc3f582c5sf7275747ljf.6
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 13:45:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666817117; cv=pass;
        d=google.com; s=arc-20160816;
        b=u+dzs6APzl1Gaco7ZNTDc9OCcGQI4lKwYuPS9r1VwY6bRotfirBUD7sN2oCEEnCy0d
         twGi4oKaY/6pYFjCszC9lX44UKJCAsVtHMpU7OQNg1sHFhACo2INQi6fk0tpXjCK/KxQ
         /06YRiZXwvITAdv9I7eY0mMTx9givt6NOcDvjAbt1A2Wp9lGU8XTsMhRdSa893Lw2/2H
         fb5hQaIhI/yJu1lH1V2xBcpfxt5bY+yqKhkZcEzEpF1zFWAe8vMCYzYNP90jOWf+H7w/
         ZX/MzkhTGBeQ2u3vY7If1/oBWShR+hHQVXTAcJkqd5YAtnyku67FUd5GlKDnyLQ0TmGG
         E+7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EF4rHbE4hXJqTl2aMeKZOogPB7GwxWpKryMuJ6NjrDY=;
        b=Nh5AzuzLs5cmBr5zS9N7gwFs/ZLRSJnXIRwCVE6bw7qslkDq8awygTmSMFqzylNf/C
         lWEDfp/RKFQl7u8y4zbzqj8fB9FrN2j4CZMNeRBzv3rQ87cjj/Dt9RCriiJUB9Fjtnp+
         k3E0WwuwcRkTYMNcj6jqersG1JY0OUuDQcdlVv88e0+LIhL2USFzubdG+kdVwmToYyny
         bTeAuoyiZAebPVCFpDGBMPmQj+6zpWXp/uuEcmnr3mSFPS0sqzq/qFTAA4Fp0QJ2Abo5
         NaIpbUKEmTd7gRRAZwKSgzCR41QP9Tpdb+kVDt+g4KoEsIooR+2cmMAADxzRTsxDh7+l
         fJPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=pH1rSdfh;
       spf=pass (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=RjEe=23=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EF4rHbE4hXJqTl2aMeKZOogPB7GwxWpKryMuJ6NjrDY=;
        b=kxT/W+R62rbOiAWP62CvVsYsiOQW+GLkhvxv7IKWZyd7UNTqkVQ2pwJ6/Dx6rDiVNU
         YhXV1NYLkEe9DnsrNeJAZZviDFiShBG8e5yQvDM/veSpP2vMN5hqJzeYas5HG4pDno6/
         Or633gVQFZIGQJyn3ZgLNPECEr0NA82n0RX18+Dm/egjjLgFuHVNAIXBkYk2sAs4DMH4
         jaFU3pKGWwkzVoufQXjbl7tBpTWKkg1P009xVGOkdPBLSN6f21Q/Wk1QYMkUAwcJ0eVC
         AXyt31Cl36S7DpUbXV+SYvv6AeDHQoXrYbbsdAn0y0l4PL6K090eVquOXqq7GHcm7VPl
         XWew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EF4rHbE4hXJqTl2aMeKZOogPB7GwxWpKryMuJ6NjrDY=;
        b=GrMITUe+Bn8c6TUKYpBh3OSWMBuh4ai2dF9OuaOj7ad7fpO6E3zJmwMhRtH9FD3iDE
         lUdSSD8hM4KZs0OyOQ18aQXeziZPE28vY+OaDvpC0X95wfoRubc97fA7ETI+eV7lK9BI
         s6EW2A5oelAPhciNuxuUfy726O6Cd5kTuD8BfdZFccv6K14zRkN114frFImaWJS1W+DD
         I72RAlmJ955nf8o/1grZUBqUtFJgUi3rjViZ051VxNv5YlgbJIWFRZ4nZWVV1M2b2Mdw
         SmjZyj9Wt64ihIEdhfKoivskltUf5BzB3UbYsdnA9ZwSdYmfSZVw5mBbp7+YR2AmGYu4
         1gpg==
X-Gm-Message-State: ACrzQf39MHDDF13uce4yl2AsTv+Hi97bHAUEXX8XOn/NavY9kmuPjqUt
	fk3MTcGjZC1qOn7/C/229cQ=
X-Google-Smtp-Source: AMsMyM4eWjSyqzA90SzJ1PJNo23xLeLwspF6EVsqY+30B6p4HxmU4qFGDqdbGeBc0ApHvJXsYskFig==
X-Received: by 2002:a05:651c:4d4:b0:277:254d:9a0f with SMTP id e20-20020a05651c04d400b00277254d9a0fmr1177933lji.471.1666817117417;
        Wed, 26 Oct 2022 13:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e42:0:b0:26b:db66:8dd4 with SMTP id g2-20020a2e9e42000000b0026bdb668dd4ls3606940ljk.8.-pod-prod-gmail;
 Wed, 26 Oct 2022 13:45:16 -0700 (PDT)
X-Received: by 2002:a2e:a4a9:0:b0:277:2544:f945 with SMTP id g9-20020a2ea4a9000000b002772544f945mr1202972ljm.39.1666817116247;
        Wed, 26 Oct 2022 13:45:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666817116; cv=none;
        d=google.com; s=arc-20160816;
        b=gYSQMZgNjkSLu4uNkymThLgTn1HbWmhwdybCA2WsW73zH9daKyE8/BacTZUVc2AoDP
         54wzPiR4YlaBXtBDyXsvKLS4l6XCvALOXK9o5sDYbdqqenqCtlGGdbPr/KQEsvScBzJS
         Z1BzJaV1KcJOODtV1nFNO4iCDif/f1QNbiuXYrN/+r407J+P4qZVWoIZNw7t2dRwXJNg
         JYQKsJoqqW4bqMT3M//ZBUDu0rod7VaGSc7pwIzneEbgfu2ejVH/1zRdKb1w8yew4Red
         WvvCNtAlfZvhEhS8nLN0rA0eYk1w80awSPSaIusWwOu81+fvfjUIw4+EgvS7+CWtc1/W
         yqyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nNeamkc4JAtTmIrGRdah4akNhJHCUZoQ7Huk4q1sT7E=;
        b=vZyFFbfqXeEQEPxceL7RrKUZvvIiEXnvOPHr5vzIM4opJ54tqD11qCaGH/Erqm3Yh1
         pH6hx6wyZf6KT303HKH57iIk6cW54zJLLG6Ym9gamF0rvMf9v1Q371ZEwMqt7S2GtN9R
         w0I+Uj+0WDthCmEcTPem21eq2Ou4NemkX8Dfpk4lPTYQMeudUqH4bO/yXvlCqxubjwFu
         F3zQIj9VSvCcHapYfBU8b9NHbvPdvFSJvynj7RQOxVpfmyVwdN2ZiPy7ckJPV+Ub4Bmq
         8oMRK3yZUK5R3Hkg1FnqCB2iyIdA6TSOoOrqs8VW4H2nwYwgpUH/0q4r+hrtWIGgxad2
         zJXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=pH1rSdfh;
       spf=pass (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=RjEe=23=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v4-20020a05651203a400b004a608a3d90asi220860lfp.6.2022.10.26.13.45.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Oct 2022 13:45:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 82552B82456;
	Wed, 26 Oct 2022 20:45:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 95938C433C1;
	Wed, 26 Oct 2022 20:45:13 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 61349750 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Wed, 26 Oct 2022 20:45:11 +0000 (UTC)
Date: Wed, 26 Oct 2022 22:45:08 +0200
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, elver@google.com, patches@lists.linux.dev
Subject: Re: [PATCH] kfence: buffer random bools in bitmask
Message-ID: <Y1mcVEzAwxXz5v70@zx2c4.com>
References: <20221026204031.1699061-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221026204031.1699061-1-Jason@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=pH1rSdfh;       spf=pass
 (google.com: domain of srs0=rjee=23=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=RjEe=23=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

Hi Sebastian,

On Wed, Oct 26, 2022 at 10:40:31PM +0200, Jason A. Donenfeld wrote:
> +	if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +		raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> +	else
> +		raw_spin_lock(&kfence_freelist_lock);
[...]
> +	if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +		raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> +	else
> +		raw_spin_unlock(&kfence_freelist_lock);
> +	local_unlock_irqrestore(&pcpu_bools.lock, flags);

I assume those conditionals are really upsetting to you. If you don't
want those, can you propose something that has the same good codegen but
doesn't need the conditional?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1mcVEzAwxXz5v70%40zx2c4.com.
