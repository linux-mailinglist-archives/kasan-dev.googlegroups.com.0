Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIGEWOPQMGQECGSHX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id D76B8697DBC
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:46:09 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id v14-20020a17090a0c8e00b0023412acbabbsf1145086pja.7
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:46:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676468768; cv=pass;
        d=google.com; s=arc-20160816;
        b=XqhvgFDBotPzA8cJUfj1Os5hN60Z0NeP/HfCwHA6hlv3UiDN86J09CW4fZKbvI741C
         /Zl+HqJanp7l52UCzBC+sZewcH4ylw6cKIL733o4nBI8qDbaSv44HwBX58QnOevkV8qF
         Go7a0hXvKdcYNuOqYKjYYwNk9/R1ei2JVDVt6tKCTjPlQXrWu/VFy2FAiIem1c4P8hX8
         B8OLCrpRYYwFR6Ykem32pZJtzLReNhXZ+710UIZXc96yMZ0VBeXavG9p+yZy4GcUueEo
         0UdLwENDupfMltYkUeID57s4p3XpAYoeyAILm80xDyxKLQfN78nvOdST8yIss8P+1NmN
         IiIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AWHeDREo14fKiqPTkK231R4fUkknOedEwuNvfyWQS2A=;
        b=jMXFIlauQCHXSOj6Q4Hk/xEJGSmFVZKneiaOJgcy8IIm/azLMZxIdiGuabsuFWaQ3l
         g5Z4HOODwno91ApFm1+Pqx/2/7vQvD3TWLXwtzu9ofTODznise8xqF+ee9ZSpQCP6z8Y
         YNlaE61WKPLeFtpuIoQ0ayftvW5yWPfKXLYxeZJ61bUyEhEJSPVfeF+ccXJPZmEMlOqR
         d5DdUV52FBwXX2KeQaR8YR1TXLPFlO1qAdZToLdHtLmQSAc90mb341zZHgyV6Byrwyii
         iF7BqSewNr2+f69nRe7ebKBWqE0mgIHCIxGe06Valu68Mu7Ye957uBEOhEKt13dmOuac
         C0+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AWHeDREo14fKiqPTkK231R4fUkknOedEwuNvfyWQS2A=;
        b=RwW03CjQrx4b9xWIM6xIo47gZsHrCPnb0MC59zfXQ4QEiUNmVNw3AQqqOvJOxWcadQ
         VPfkHgVbtZ2tkvEvhbme9WUfUOR2Q5oUfvxM9GdEHhNc/sswcTsLHfi1tOzzqgekF0WB
         g5g8adt0CBjtFOKdJ55PMSTke+fyQ8xtfz7O9WLFco7GXidVLNmhkF8qcb5E9hqNFjbj
         Yq59KyVeQhOoyRSuA16hDLMXEFaRf7OGYbecULiEAPRNIGKq96nwdkPrSjqjRLwDbWba
         vI3zIu27r9RDFn5G42fMhcA/qpO2Vmmlw/UV1RgekN0oZJhSGCvCxPyO8HId/Fe9C/7O
         U+mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AWHeDREo14fKiqPTkK231R4fUkknOedEwuNvfyWQS2A=;
        b=r6MIxzwqQKkEEmyIn+wXQMqSaVawshOIleOlI8FVWfk2ztpT+7TSfjrVf3/Pnp7Y4I
         XysrmNF+IK+s6cAlDYOI1DFlNQDQ/v7y5CxxdpUGHXikKkr/ffyOGqke9Dw/N/uY+zdx
         vySknw/9XmK3c8t+WSprBQG9Fnbuhlh9jqUduGuCjRKanc/WUFbrDH82bBOh7iS6tQqi
         0VjViw5xMDAfUZqbjkPlmwcO6oI1rqto85873u5PCxs15kIp+1FTNWnEaK9UMLM7daNv
         sw09PGbJpXzOjPEmJheSsVvfQsF7htu985aWyZeI/7VTQpaQ0tc5wDTU21NRhqxKZqXN
         k1gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVov2ZA9qfDjjb6/wXksRpXbD+zW6iI7VcN/s72dmqkCc1GUC2F
	As0VkfgZiKfBo+O47pwQivE=
X-Google-Smtp-Source: AK7set8tJDrDqNJvZuaVPR8gkrm+M6Ykpn/2sducP2oJ3Vu+N1ndzfmjMbhILSnM8JtsnfjhWM7mNg==
X-Received: by 2002:a17:90a:2808:b0:22b:e754:fe0 with SMTP id e8-20020a17090a280800b0022be7540fe0mr682150pjd.58.1676468768453;
        Wed, 15 Feb 2023 05:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ef51:b0:196:2e27:844e with SMTP id
 e17-20020a170902ef5100b001962e27844els19323733plx.7.-pod-prod-gmail; Wed, 15
 Feb 2023 05:46:07 -0800 (PST)
X-Received: by 2002:a17:90b:3511:b0:234:190d:e653 with SMTP id ls17-20020a17090b351100b00234190de653mr2966281pjb.6.1676468767530;
        Wed, 15 Feb 2023 05:46:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676468767; cv=none;
        d=google.com; s=arc-20160816;
        b=Y/x/5+VNknrOKd7ALEEEQulP/PBsjBfsEswYA37RbIEWjktKvQO7rIBFYxmt28le2l
         66rAsAzvfEhhNjgc1Fkk1gLdyJnKuM3XqrBCyYMGh3o7bKeSuYmJr23BY2r7aoIWwaWK
         mY8QuRFnZHcha9aCAUs0lc9bLIDq1rBxVpjfnLDcg2Z/gx23gcCkRSkXpPjGwChZ7U/e
         O2ImOW/f0R8CeEX4uO1tNSuZ1bJ9/p90bLAXdyhgQIBxvRkKNDljMaN1MCUDCzvNrlXh
         nXMizlRHC4JKK3w9ze+Jh65hdMTSPSAKK40TntjujU4gbY5QIgwOJWJywtiak8EA9kSv
         ae0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=0jTbtDE2BijSj4qeZ7dgyYZuSGd2CP4FoFEV/HDuMHI=;
        b=UZq1o6I05hjAfFAox6g8uG1VfG7oT9DARJseB3bJNmd5RguTtGnZWiabm/+TGZy2Uu
         /7lKgToztamAjzS4nXY7SCEqpqMOmEhx2435ob7s1jp/fHj+g3/NEvxrGwaDJ21Xtub7
         kNP77n5ibNasKFiJbhPeIzpc0U4uH6lIh8PUv4OdlSxZ7Zte9WSt1zgoJynxOnhlBNDC
         dEuG2GWE/UBlJXJVOyRv+EMmBh+5j+a9K4lJVtRAGNco6B7JLy9WXiUPVS+to6EijWcH
         yidjExv5P7ea87YFiUlrhqh0wreGsoJ9Z7QV82fmsj3mZp6+u2AAMxPxAcVNuQs6xIM5
         4Pyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id gg13-20020a17090b0a0d00b00213290fa218si174843pjb.2.2023.02.15.05.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 05:46:07 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EE62761BC8;
	Wed, 15 Feb 2023 13:46:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E8CFAC433EF;
	Wed, 15 Feb 2023 13:46:03 +0000 (UTC)
Date: Wed, 15 Feb 2023 13:46:01 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: andreyknvl@gmail.com,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	Guangye Yang =?utf-8?B?KOadqOWFieS4mik=?= <guangye.yang@mediatek.com>,
	linux-mm@kvack.org,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com,
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com,
	will@kernel.org, eugenis@google.com,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH] arm64: Reset KASAN tag in copy_highpage with HW tags only
Message-ID: <Y+ziGQAB3nhVqFY3@arm.com>
References: <20230214015214.747873-1-pcc@google.com>
 <Y+vKyZQVeofdcX4V@arm.com>
 <CAMn1gO4mKL4od8_4+RH9T2C+6+-7=rsdLrSNpghsbMyoVExCjA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMn1gO4mKL4od8_4+RH9T2C+6+-7=rsdLrSNpghsbMyoVExCjA@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 14, 2023 at 08:44:36PM -0800, Peter Collingbourne wrote:
> On Tue, Feb 14, 2023 at 9:54 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > If yes, I think we should use:
> >
> > Fixes: 20794545c146 ("arm64: kasan: Revert "arm64: mte: reset the page tag in page->flags"")
> > Cc: <stable@vger.kernel.org> # 6.0.x
> 
> I agree with the Fixes tag, but are you sure that 6.0.y is still
> supported as a stable kernel release? kernel.org only lists 6.1, and I
> don't see any updates to Greg's linux-6.0.y branch since January 12.

Yeah, that doesn't matter. I normally generate this with a git alias and
it matches the release containing the commit. I don't have to think
about which stable kernels are still maintained.

> I'm having some email trouble at the moment so I can't send a v2, so
> please feel free to add the Fixes tag yourself.

I can add the fixes tag.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BziGQAB3nhVqFY3%40arm.com.
