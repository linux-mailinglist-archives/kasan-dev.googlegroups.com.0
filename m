Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJE43WNQMGQETM5HNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3080462F0E3
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 10:19:33 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id f19-20020ac25333000000b004a96ab958d9sf1565189lfh.19
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 01:19:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668763172; cv=pass;
        d=google.com; s=arc-20160816;
        b=R5CCUI+9v0awgf1V1AlhbJVeawoH8Ifi6eJ4ZLIdUHg8WPY78khnYZxfEyyo9OXqfK
         FCyL1GJ7XbZthJOoZjdWaBpwi02EcDI3BsTsLE3BrBf1obZNPljKAVtMEvt58Peikbm5
         v2BJhYaJUKLuK+nf7Iu8zlJ8h8Uih9V+3hPH2G43KncOsvM1T/HsrI2OMkamHVou6ZIa
         IjMI0t267rqQ6NvK5tOcxj5/uyVqYoDgJMkysWjaAqS5sWSfaI3BQ/DCjiDLC1AsQDff
         qcXWIElMzoi1Bb/oOvXB/RpJ/la4PjGXoOhebX3mFj6vw1fQvDo2rrqN3QzehdEk8ZSX
         pn0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eGJ/252+xOZAdgshsk25MPXGsesW3zjhgxypbXXK53k=;
        b=G/fPwNZ57Sqwc+T+WojnIQqt5+0eFZ8SmnIwM851T94gjIA5F7XRLgpmAuG/hHmbCZ
         oh4TuZZxPGPZuLROoG/ZR5u67H2bvRhP3sculqeiewOR6XqDlJsbayah6ljBBKfQT2RG
         P1NE90N1EpzYQYfKSmmR+pYxC1+AYLjGWnRqc1ZgiqMxAHdwz8HwPQIkhlFRhJI5x00F
         bDvb5MT1N9JJdsrLoH4J3PgPqZbdv00/UrYw+ZF9hVTJjzz7U8I2mNKQH7xN2N7tAYaw
         gdJzPndVZLB3vxTORwy60p3Twd3kNF6+nCWxXm4yCTAjHPZquTWa7Kk1lQZbn9Tk2GlK
         +QQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XPRDdbxS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eGJ/252+xOZAdgshsk25MPXGsesW3zjhgxypbXXK53k=;
        b=dGSFjWxDpDWSwFM5zPB+yw7M0HrPE37rmKT1QYQQKtjregjD5Y4r8yI5kJTBkbPwNL
         K5mWEkjb03UICttsv/g0eb79diDEii/ULphqZeP6qVx7/SaUprF6ONTWEzqM7LHsdQrZ
         ft68OzhizIFneoxQNJ+CEO5nLKtIIMdqUhJdPOV4Tj9vn4GYSpDPeAYqKQGweSmgq5t+
         xftb1A6XB8dW0ma6J5CNYpUy6DD+CGnhoTtc68WbCt2vA1owIqcdmhy2ZTE8pE8MMK0w
         8OXKN7ToDvWQ0jrXPFHS3XTYBmw1TZy33n4pxmGVw8pCF8D0cf6muaQVkB63ysqKlKV0
         jsJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eGJ/252+xOZAdgshsk25MPXGsesW3zjhgxypbXXK53k=;
        b=CFlmtbwVgvdQ6OnPumIGhamHi2zCFcIywBElEyVydiCag8U2+Wwu76eROZnPaIzPmI
         suL5JFj/wt+eHV/duZQlgKCJxAfd05qJNrSeA7m+EPE/YNKgYn4LtYXDdOZMzPFchvgP
         CylMNVIDEV7IKuQAD5RfEOHg4PHPx6BJX0sdusOuHdTgpFUtBAYcdLDk2qIn7qQYuWGV
         TRe5BjM39CKoHu5XZ3OqikdrXmMABlNkJCxe+PiwjSB0FPeuaMpUky16Fc5kMKqvAVx+
         /zLtPGqA674hE4hjDfIQx4fw3V2CJYrtD6M0T/wCP4wUDgtqZZY0VNoztfSH5nYf/ocw
         wBuA==
X-Gm-Message-State: ANoB5pnwpRsTj9C6oV1Da40obuouAT/HhyohUfopHHV8oq3vTtuIA6j4
	s0jVYiBWvbn+L0aF6RZ8qHs=
X-Google-Smtp-Source: AA0mqf5N2r0trIyQZBHAqbFUG43nfMVHHj7ZBzjtl2chK8qDwyEqO4O6InopoBey6rpB3VMUWAp4dA==
X-Received: by 2002:a2e:a4b6:0:b0:277:34a:f656 with SMTP id g22-20020a2ea4b6000000b00277034af656mr2401993ljm.78.1668763172455;
        Fri, 18 Nov 2022 01:19:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ecf:0:b0:49a:b814:856d with SMTP id p15-20020ac24ecf000000b0049ab814856dls3296742lfr.1.-pod-prod-gmail;
 Fri, 18 Nov 2022 01:19:31 -0800 (PST)
X-Received: by 2002:a19:5e01:0:b0:4a2:2b5d:b95d with SMTP id s1-20020a195e01000000b004a22b5db95dmr2038084lfb.589.1668763170915;
        Fri, 18 Nov 2022 01:19:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668763170; cv=none;
        d=google.com; s=arc-20160816;
        b=nwNG5GSwE3+GgxTsQUd6lBC2JcrNzifjLU/BrLdEnRQM+ig+3EbXBGn9PRSrUpwvoy
         gxM8e+Ci+6EFPLm43ISKn/c1LXnEvla9JfK0GRHKpsuIvncpkRocVjoPTaQB7d8UMLQW
         yUi4e6KuCOpYLKOSligBb4FWc9jop14SZFJM0wjLWnWt2/JzcoDHSdQ4k5jz6G6A0snI
         vZqiQ959pge6iUAKX4vs3q0xFuu3d9Xq0bxDzHkcUcaghkPOwtQHfxPEYzin04yGUc/P
         tED4jtOTHa3c5L4tTxItGpeRQBlSbysCtXRjOtXX1XWF03R7R1F+JCJXv9GRMR34hpzt
         vmnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ywmGO6HZoPeDk5pta/Zgi0l/H8NSLfPp6KexyZfvyDg=;
        b=KLbVGKNTr16SoQdClzrRm3SXVX1s00JHDuMjmy1IQcrfmVxnKJqVZjkSDct6TLacpm
         pPlGhOutEPyDVPqd3COU+7viTqLmxMHAKDML2vu43lO0P2ZYpN4romL096m7+AmYYtF/
         0PznSioqauUmDhQsVziAYiyb86Pmi8XLHkpRDMqDclh426WR1D0WTT6FGTU3pvlSP8W6
         5mxWWp5xa8sAk3xy5qY6WP8drfxcSgJy7+5Us+k3O+ua8zdrYfcPLMvy42BcRygAsr6L
         bR15L8NFQ/VuA9bUJH9kB5Ef6z8h3b6+6yk0/qqxB7tROA1Lx20SFGADuisa++MSNoaD
         D/AQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XPRDdbxS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id f16-20020a05651c02d000b0027760dd5b20si122348ljo.3.2022.11.18.01.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 01:19:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id cl5so8295735wrb.9
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 01:19:30 -0800 (PST)
X-Received: by 2002:a5d:53cd:0:b0:231:355b:211c with SMTP id a13-20020a5d53cd000000b00231355b211cmr3562614wrw.509.1668763170487;
        Fri, 18 Nov 2022 01:19:30 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:4799:a943:410e:976])
        by smtp.gmail.com with ESMTPSA id l8-20020adfa388000000b002417f35767asm3200743wrb.40.2022.11.18.01.19.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Nov 2022 01:19:29 -0800 (PST)
Date: Fri, 18 Nov 2022 10:19:24 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@intel.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	linux-mm <linux-mm@kvack.org>, regressions@lists.linux.dev,
	lkft-triage@lists.linaro.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46
 kfence_protect
Message-ID: <Y3dOHNh82NQboctR@elver.google.com>
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com>
 <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
 <Y3bCV6VckVUEF7Pq@elver.google.com>
 <41ac24c4-6c95-d946-2679-c1be2cb20536@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <41ac24c4-6c95-d946-2679-c1be2cb20536@intel.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XPRDdbxS;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Nov 17, 2022 at 03:54PM -0800, Dave Hansen wrote:
> On 11/17/22 15:23, Marco Elver wrote:
> > Yes - it's the 'level != PG_LEVEL_4K'.
> 
> That plus the bisect made it pretty easy to find, thanks for the effort!
> 
> Could you double-check that the attached patch fixes it?  It seemed to
> for me.

Yes, that works - thanks!

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
>  		return ret;
>  
>  	while (rempages) {

Tested-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3dOHNh82NQboctR%40elver.google.com.
