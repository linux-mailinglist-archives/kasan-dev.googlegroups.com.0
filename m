Return-Path: <kasan-dev+bncBDBK55H2UQKRBXF63WNQMGQERPJLS2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D077062F29F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 11:33:01 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id p6-20020a2e8046000000b0027703bb5701sf1564553ljg.11
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 02:33:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668767581; cv=pass;
        d=google.com; s=arc-20160816;
        b=y3XVX89MTnKKpMyurITfAjlxQpd6Pd1e78x20VQZuRQbeN9FArIiEVrpjKspy+/wKC
         35KMhwbbZTl3QiLv5oYWi+jocsIyOFqYHOVnifBsc8IkgJ7Gat4UrejXtnnZNJU4rYmU
         rgvewHrDOPo3n5LhUAK4ouGVL5GgmiJ6kJrvT7c1ZIOZJMqNGMl9Am3LNMbqxE934Ka8
         ZR9YF+fZrs6b8O0c9w8mFQVRPrIFEbVVNZdyeOq8KyVxAYpGQSc8it7AbO+QlxlDhpdZ
         Ly2Bfr/DERgeV6r187iAtd0MTg46Rv+aG8AnUIFKH86OC3a8Ng5q61m2weckbYQwxmGp
         QUgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gL6adphfLGnHGBb+L2xukD/WgsTfney/lmyoD4E618E=;
        b=WrwBcKYhvWYB8q2gaM1BuJ1E+vsTZsogNg1V1tAfbte6HZBLyJUNlzYG6zJqrWG/zb
         6XMbj9blwftnuJCMgOe5zOJXAANRZRmYevuyRK/rLPlKjaQJSi2PCqtRCztX3xQPiwm5
         BSMBP/NGmSxiBKVLZVdYHvKVeXFYCKNR4Uykd2r16vwwFYlT9wm6Y7QgeQtk/V4taQPd
         HQAcR1cmo1HTXqjrLW60GwKqWzZCoDS79QwZovs4vyDJVzQBC22eY4/7+irMSCCijoTe
         Z42fxKoDx2BahwpIKYxycch8S8CsKYKE1vz/0h5LJP+5NGIWIPfhTfirL5nzQRBsVakm
         nmsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EIGeQOPH;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gL6adphfLGnHGBb+L2xukD/WgsTfney/lmyoD4E618E=;
        b=mvBR2AK5OZzvv4iZjZajh3pmNZytEzPcNx0Se2MG2WE+/oHmVo5gONfjXS4l7/XqAv
         mLOwwBI3ic68J0qPKqyRVameJH+aFKrhP+ZH/+Qv3F09jFOx1y7Vgn/WkcyQZBjod75W
         xo9Sa8KVX5hdn9RsC+NDoyUcbaQ5EV5AEzyKRlQDQVKgqdneaVxVJhHku/igjEmsm4XH
         rWd887wOHyS2xAF67QIBKAsxDT6rvr8d2cGjhA4rxTth2VKCPI5sN4o5xFmL1q7jDsbm
         defbUi8FqjCDxaWsH6D7J3a1PoWFFLxAQ2DutDn0awpRE6gm6Yn/ByRN/1vTw0dV/FRU
         cVsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gL6adphfLGnHGBb+L2xukD/WgsTfney/lmyoD4E618E=;
        b=08emk4StK1NwmgRahMTOg9Wh4SQ2DH62IJVCpOk0Jldfhe0kZrYaZHb4mQwvbPj61q
         UG+a1y03ZdfcTLTyLHqzGm5KhKsTwIOeHZRvrNj6kCGKvVC5ft154mkSflVGOlccyv27
         QqeDtJgrCeuYlC/kCfoBLBLBZjMOT73zIOqF8r6Mb5pJR4kh7P7LVpccsQPR0DWULQiN
         W1PO2u7h5kX9AekWF2hpKuwkCUsjIYOhSRHpU1Ja57BKZBytiRLpWN91U6s/2Gz18To6
         0PtwsNx2AsF5YVpe4xZp6iutUyEm7AvNC+XVEgA3xKAP1FHcJrUDrPxgE7KXVDvMIy7K
         OfRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmOVIP2Zphh5VXiJlmAWTxd3Zo0o89RTlMANPeL0UYbnTFyrtdg
	yx0Z9QAbJKzhLaP5gRGyp48=
X-Google-Smtp-Source: AA0mqf6dB1rj0/heGef5tvZKdNr0tfAl2ncLTP9VqO6yF2kxELeKTVLsEdacntPFYMyhZuyvts3QPw==
X-Received: by 2002:a2e:b55b:0:b0:26c:554f:87a5 with SMTP id a27-20020a2eb55b000000b0026c554f87a5mr2375942ljn.452.1668767581168;
        Fri, 18 Nov 2022 02:33:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8d6:0:b0:277:2e6e:e039 with SMTP id s22-20020a2eb8d6000000b002772e6ee039ls848196ljp.9.-pod-prod-gmail;
 Fri, 18 Nov 2022 02:32:59 -0800 (PST)
X-Received: by 2002:a2e:7e0a:0:b0:277:6f0:5239 with SMTP id z10-20020a2e7e0a000000b0027706f05239mr2116869ljc.186.1668767579702;
        Fri, 18 Nov 2022 02:32:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668767579; cv=none;
        d=google.com; s=arc-20160816;
        b=qhXZA3gphauw7oHUjbyPIqJfAtBW1KYLnMlJ0hdOKOkbNSQrAVtkqBxmXyZUlmj+Jo
         HUCx4DsIanSAU7Ryr0mh3MbRPNNBBb3lE/AHj8UmY2xJcoyMaAACPz38a/gDekFWq1EU
         9D4nGPnJIAZPcUkZFrgz1wouktqcEgf1h5g1cZaq6GY6h2GkhXPVZ1szKMAdv3z17Bb/
         0Ysej7zCEnCQ2xewQRfeu+8PaumOegHeaWJ1LLUDsyFfwTrb+YGxFhB6q5vWXA2wVkvB
         ZL8pB09byzqWGlXs1e+Pm1INhpaGAP7iOMJb51DZF27/Beq33nHhf/H+oXDs+Anzvavr
         +GHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ery4e7DXynGUHcFDdPwXSq/cHJt8hNQ6mXrrfbI6xLk=;
        b=p43Tk6D+ij+tA7oMSI4p9VuIcmnS5gL84Lw0IPHxvMuwZO9AGQD9e7fRuFRlmBvO+c
         T6vNPaxUWzpZDDNsJs0MdBizCSSpDLFrETc+tvtayfrv0JdRCk9FelzQyTFBIFD1rb9t
         76j5GHfqM/vcH3cLosz9Tz4xWn5ccFGHRcPZzYsUFm9Z9cgd6PGsusDE3pe/Y78nwycE
         L/wrpFF7TJDQyunwqUDDrl1ylrTeweXk8lpwXAPhjaa0VgJPBiaP+WtwSm4vSHvy3EL4
         s9jh/JcmIJMF2h2JRpLRKAGB268q9Cp9jZmIbut/kxvLBotvDLI3vxg98roaJlgmKA0u
         0gtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EIGeQOPH;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id s15-20020a05651c200f00b0027724b9e43fsi104612ljo.8.2022.11.18.02.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Nov 2022 02:32:59 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ovyg3-001x27-EE; Fri, 18 Nov 2022 10:32:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6F817300462;
	Fri, 18 Nov 2022 11:32:54 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 527C520C9821C; Fri, 18 Nov 2022 11:32:54 +0100 (CET)
Date: Fri, 18 Nov 2022 11:32:54 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dave Hansen <dave.hansen@intel.com>
Cc: Marco Elver <elver@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	linux-mm <linux-mm@kvack.org>, regressions@lists.linux.dev,
	lkft-triage@lists.linaro.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46
 kfence_protect
Message-ID: <Y3dfVtYINF/u7Sar@hirez.programming.kicks-ass.net>
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com>
 <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
 <Y3bCV6VckVUEF7Pq@elver.google.com>
 <41ac24c4-6c95-d946-2679-c1be2cb20536@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <41ac24c4-6c95-d946-2679-c1be2cb20536@intel.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EIGeQOPH;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Nov 17, 2022 at 03:54:21PM -0800, Dave Hansen wrote:
> On 11/17/22 15:23, Marco Elver wrote:
> > Yes - it's the 'level != PG_LEVEL_4K'.
> 
> That plus the bisect made it pretty easy to find, thanks for the effort!
> 
> Could you double-check that the attached patch fixes it?  It seemed to
> for me.
> 
> The issue was that the new "No changes, easy!" check in the suspect
> commit didn't check the cpa->force_split option.  It didn't split down
> to 4k and then all hell broke loose.
> 
> Oh, and I totally misread the kfence ability to tolerate partial TLB
> flushes.  Sorry for the noise there!

> diff --git a/arch/x86/mm/pat/set_memory.c b/arch/x86/mm/pat/set_memory.c
> index 220361ceb997..9b4e2ad957f6 100644
> --- a/arch/x86/mm/pat/set_memory.c
> +++ b/arch/x86/mm/pat/set_memory.c
> @@ -1727,7 +1727,8 @@ static int __change_page_attr_set_clr(struct cpa_data *cpa, int primary)
>  	/*
>  	 * No changes, easy!
>  	 */
> -	if (!(pgprot_val(cpa->mask_set) | pgprot_val(cpa->mask_clr)))
> +	if (!(pgprot_val(cpa->mask_set) | pgprot_val(cpa->mask_clr))
> +	    && !cpa->force_split)

(operators go at the end of the previous line)

>  		return ret;
>  
>  	while (rempages) {

Urgh.. sorry about that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3dfVtYINF/u7Sar%40hirez.programming.kicks-ass.net.
