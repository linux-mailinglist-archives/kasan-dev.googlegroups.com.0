Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQVOR35QKGQER5M5GYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DD3B26E1AE
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:05:07 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id v3sf2789030yba.12
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:05:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362306; cv=pass;
        d=google.com; s=arc-20160816;
        b=kRg3p98GcVbl8qmt6eg9qrCwXRFlzoNbBwwfy9p8f8/9fjyB3R5E1VtOT/bX94js7L
         crEGKL5cK5ghUeDVaidbqqVWk9Uc3YwflheVI7NjRSetDKejnuKhoObcGCqbtohN8Ymo
         ebCDcXAc98+KnNqSWsV24ochW1xVCUcYtLdK2R520XMf8SjwmhQJcTzIr0rFuesC9BCN
         u2YajuKxsxZc9U7+BnDd2O/nPs3nLWNmQrfIMdLIiJtPK1dOgm8IxNDzg4eWfo+JM0hw
         0aa1fch0qZ+/E3P4AeumHMB91zUX9iq71WhE+acX8/vmTWLDGxe8RqK7fQIK6BmouYWe
         BymA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=H0wYMiKyMyVJtwABOWEVQkTkurMgNNmADOX7Pyv5vUM=;
        b=RSZWbgjkjquqCUYlUx8phlYQYeq9CQqIcoiCqKuc/l6fWzOYdz5ou4I+DdmE/AAVTJ
         lGD4w2tSM607UmfP6TcPwfctDatmlKENZt8ie8D7bp9MTfR7XMGEPh8rwZ/3h0pURm8k
         xZfSWYR+eC00CV+DpLK5Pd6A58wfv3sDsBlyt6YFpqrolbofOmuIdiPnm8ml2FLWtmSM
         duFoOyZV6zhfgwoqIQuQE8rTybZBxDXsHew2pBz/1OUuM01bzIrdLuUJskxfPwvqa6uN
         SmUvAqe84tlzj3Cu6Su7iECw1MQb5naPDVUdX1pOWjSmup+jC8NhcozQTWpmobkiyuBF
         QqIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H0wYMiKyMyVJtwABOWEVQkTkurMgNNmADOX7Pyv5vUM=;
        b=lzIBF6eEnTBam+Pvn9eoHDNhaS0eVIVAAAdXmrDAh7g3lgqDOMWgZK4zezJHp5r6Ep
         2OfxGPH9AsokslU9wgpg9DN7igyPhXHFF1Gn0SHlT7XTajpvUYTGV0+DU0C25eA7Ddxs
         4mRd/GMbhBCmz4r1Z+gNp3oy5Ey6ikn2FWGnDtxa2FheJFO+cgsn9a6tH1zV9NRue2LU
         aBDBDJO0ItUdMzkIDYbrHHt+W2ALYsFuqRQXXC8nr+wN1DnhTe3vNA8HV3UISJKgUuNr
         3kyHw6TgPJXB9J0aC0Lfg2x4enTczMG9zUGeu3aEC6fAF+btjNBfZqDCvhga2VmviPbq
         /V9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H0wYMiKyMyVJtwABOWEVQkTkurMgNNmADOX7Pyv5vUM=;
        b=RK+6JjoKY7HzP84RSRlyc+Dwf/o8uv1IgSUnp7gDz9bGHPs0XBaO+v583Gk9XUcvKW
         HmrbktGeYCvYkvlV2D7jhywNX6X81weWH+SU4NkwT83kS8SFUvdZAPi+zeJ4880tezxP
         Qol2huRy4/JfUBWmu7uXGENsSI3gMGL8ZoDaKMiC5iB9lAJzLGTIS7hSmf0ExzQbQIp6
         kChmBKsV4IrlVXaoWPV+GRJM8noaxkrXLoT+yL+DjZsZtSz6nPkQrS1SxeL2xRX2VKPT
         1MbVNxtW2uih6oxiWC9w0SE9ALNF5R7k0vf4HWv10gZODR0cgtz2L7iAzL4j9F+oMaMd
         tSkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y11L+rEhYsUisgYuyF1gKXYLzIK691ghdUTQjd4XnpbtkpAOD
	etzOmAVQGRlgY2jsGX4KkKY=
X-Google-Smtp-Source: ABdhPJwlFRJeOX+L6Ygo7c9/d2REdUqi9lOX5OHaIZZkJfX89LXdfyYy+WbkuKZNgKrvUq75OAVOQA==
X-Received: by 2002:a25:ae90:: with SMTP id b16mr10637320ybj.128.1600362306592;
        Thu, 17 Sep 2020 10:05:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5755:: with SMTP id l82ls1215253ybb.5.gmail; Thu, 17 Sep
 2020 10:05:06 -0700 (PDT)
X-Received: by 2002:a25:8209:: with SMTP id q9mr29844743ybk.353.1600362306083;
        Thu, 17 Sep 2020 10:05:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362306; cv=none;
        d=google.com; s=arc-20160816;
        b=T/nQF9rDN7vgebP/sjXmLijTL7GJBdSt6jRj8KAEaOTZNyi+hAzVznkuLubwkO+Kyr
         pSoT9H1kSn71jlDbTlAf1xL25FsqzD3tAZYEb+bJYtRNpri5Bcx1bgfaH7AKs4qCABpN
         ftAkDuH4T0rEEO7t5Tww6sm9I4y4Li0zYo/i7JfGhI3FTF1Urns4GwibFq4LjpHyVr+W
         KY0eC2xGyAJeOeWqHhherLsscUCtOLlfWnltHTw7+zs5AME5HyFRsxblNPEhGSSvfe+s
         268fUqadpuLCnDS3uJZt4V7GZrv77u3kcfmRtRtqVdHMpyDo7XUnAGDUT9Tz/ffp7InE
         L+cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Ju9TjqxCBugy5HIi7vNbYoXp55lsfpQtUYLNymYdZe0=;
        b=TFry47TMZmscWhOf8Wv8hVvjQha3XJiELeHhtjxCP+6JuypOo4JOyY8UiA5mOqvrXT
         ubS801jfPclQ5/boSqm8jWCiwLVrDC/MoHnUkKrUNgc1uKy4MZpgkPK1QEP/N9+DcEwV
         mxupotuwLJAn5ruIjQvXDZhFxejLa2//579Nf+61qD9oAuG3pmjxEZhtarBKbV0KtTF0
         Ua45h0oOifUwuZMKVlhNeUueADV0KudOZGImRCHBxzmzybnmFZ7gNyGpQXf1aAHzZxoa
         OqJW2k4an3AHl52X+21FREQku+tdTT7wHI7D6CWWkoGxywetHgtdMIurGT8X8j5VCF1f
         JWKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t12si26330ybp.2.2020.09.17.10.05.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:05:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B96CD206A2;
	Thu, 17 Sep 2020 17:05:02 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:05:00 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 12/37] kasan, arm64: only init shadow for software
 modes
Message-ID: <20200917170459.GK10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <2d009928ca496df0d7c061749c6a74d9ad36588c.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2d009928ca496df0d7c061749c6a74d9ad36588c.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:15:54PM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Hardware tag-based KASAN won't be using shadow memory. Only initialize
> it when one of the software KASAN modes are enabled.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170459.GK10662%40gaia.
