Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPFV335AKGQECLZC4CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 754A22612FE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:52:45 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id u206sf3345070vsc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:52:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599576764; cv=pass;
        d=google.com; s=arc-20160816;
        b=GkF5c5yHZZvJNvt9CDygvBR+InfDH6iCfulkmVAXCoNrlh1/9NQLzF4DeokgIKFNXC
         j0ZWuOg8AtgiRMEDLxNe0OfBfbnWeiN8STq9VV7o2h+mbqfvCzZ8j00QLWpOXHcxWR4M
         gOSTvv1NsszODDFtOYyn7BM778EpWJuP6CaANkZh0kyU5dQR8ANIp5k0AJrlWuP53fGY
         hFvbTUCm+0lVgr5QpdvfQvSMXCU7n3uzvX3hj6+8MHF8r9LKMqeZw48JtLYrgFWhejLy
         8hjI7R7w5yUny5tJDTd/efCHaEppF8VUzSrHGDC09Y4Sp8xvhop6Pplzz8+E0y87AHNo
         k9sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=xrbpQTWdRoN3u+s8R7cDIXItOAt/VAHMPIOQeR2dqjU=;
        b=lV4OglDf+oaubl9pm/GOLmsak3XK9qXgEhM3ptfpcLKJnqE9nvUkv0fRxlzCeiAPYq
         cxztf1TGcWSuaLHPrOdafJVcmiuqD05g+YVVFYZ6VCLzav+nHjbabdoMnwx0yYfsZJh/
         h+pmagHOa78sPZT9geJeDwVeEnXHkm2Js21+9d156inE8Dg5vLFv7nTIz9qB9toOxXnp
         Fj/wR5I+0Igg84sp9TK9hS1OCm7RMH8a9BDrjFDfKebih7INT6Nt62xY1/N/5etsFNJA
         hXAWe8U5uJBzb9BY09DmctWqJtHG6Av5f9EMiJ5ePdSntkJLH0FV7sPZN+0ZFRmyRPIW
         R8tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xrbpQTWdRoN3u+s8R7cDIXItOAt/VAHMPIOQeR2dqjU=;
        b=TzUQ3SLrzEVCtowfN17DQgerLxk+4Ops24Nsn0/25dNgIj8K6JRM3R0G2zXZHeKdUA
         59IrMymry3Hf2zdsr9Mjq1+jmmF2IiEbHRV1W7exUF1oNrf/Tr0nrTZK8p0tvVd9wC0X
         zehmwnICKXSKwYO0ZDIa5tKy6B7b6ekAXfNnKmCCYo8kfy7QMfjRLJHzP5MaDJFBiAL6
         ooEdFZj/TEd5kvairDp98d3iaduwjEvqKZP19ISDAI8qf3rlWwDeHW0sXPGupvAP3Mfy
         gmIYKI49uRCWu7TtnFRT9APaigyO8ma8BE8HmyJoMmOUev9xBhmmlFnHBRC0n3rLT5QD
         TZWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xrbpQTWdRoN3u+s8R7cDIXItOAt/VAHMPIOQeR2dqjU=;
        b=gYlBNj3a9RAO1WQcrMvKc4Mt/SheQ0O/GlIkudtv8ktX4kUUFxkaWmm3+0up1DWWUd
         1X3Ew+Znac+LA8nnmqubjfG4xFZ9ECg7hFt3gWkr+zef1JG4/emMWvnvRdVh5c1sk2ZE
         9yI7H80i+VadBaEsdqrODbMMmejZPtNAmIev7wJwnIHt9oaXpQ40iFkqztQqlq4EiZDL
         2ZxkDn6Rs6R/5Pq8twHWIeRIpoHuvvhV9ImT+OFgAS5DtbaP9Xe/BF662tl7mwX8+hkj
         M5ZJMGsERQydjuqPvb6IY1P2uT8IUAnhWLUsZ1dPsEzKJhbp5Vf7OOuEOUm/A7kGMcIh
         670A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532l1KfExR86z2MEgvQkG2x2GlysPqTzYm0ar0RU7OcGN2z1q9Is
	cS5Ltdk87F058YBMsYwfGsY=
X-Google-Smtp-Source: ABdhPJyspBWdPz97gNwSEaqsRXLepiZIezp6lJrcFdHlRiXAq8o01gaiTTudIUaT5/SLBbtvjd1quw==
X-Received: by 2002:a67:d193:: with SMTP id w19mr1036347vsi.17.1599576764538;
        Tue, 08 Sep 2020 07:52:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:604c:: with SMTP id o12ls406517ual.6.gmail; Tue, 08 Sep
 2020 07:52:44 -0700 (PDT)
X-Received: by 2002:ab0:2904:: with SMTP id v4mr13099288uap.15.1599576763898;
        Tue, 08 Sep 2020 07:52:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599576763; cv=none;
        d=google.com; s=arc-20160816;
        b=ZsHhSSPuxlw87HhSmHbaBvghrbtk43sxJoGQxnuRZT6BXdHbnbRNFa/cgH7EnLmhDa
         Rm2HgYyDZZk6nzlypS0PrIDHmC7Iz1A54DcoZ69bV6HNrKKvqizJny5Osj/jaPZjUqeJ
         trnpBnyKzhMpr4WxodnKg+4mc7gnIuWHgp3KACY32Bsnimi1b80RkKyXXn8OYBrI2rOG
         VF0x165n1sh37aoKk/xKvxn+TzP+TJHZmD2aM1ajBXSQLYGmvwwC8ScZpnr1NgTKZ7LO
         gLDUYFxABfwChIA/PBJnSxvjA2dQFgh7gjhSEqYft3ZW56KgtPsa3iMbamJezO9WnVim
         eKRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=BpqtfenlTX83+6Cjb2uL5fTK+xGqR469d9bEpaF0aWc=;
        b=bBYnorVKQq7uImsNOZdal+fJm3Dc91Qb3V6MOambIdTuV1ESI7qm6WtOY9T4ohVbjI
         n48xoCZ6oXFCigWAqeYvsv/XtompJigtnDwNTtaCopm6xvwZ/3bTc7NqwHeoIu32Q1M2
         JjSd4h7LrB9SwLIJ9VdZiguEaMTbduDQ+Qu7D+buLabyHBVViMDoKDRddJEVtSpvcY/r
         0Vmi1NvHp7z3p2jCSltduBpO8gPY4S5yDzrvxgOyObNwNGBSEF4pgMg7p3mTfQd3aIAy
         ebgy6sswASYfXgdln/SPkufcsTYWGgvRJm7iyhvVVNTY9Ei3b8ZdpEH0Sq2004iiHyTF
         qMNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u19si977720vsl.0.2020.09.08.07.52.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:52:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3E3942074D;
	Tue,  8 Sep 2020 14:52:40 +0000 (UTC)
Date: Tue, 8 Sep 2020 15:52:37 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 22/35] arm64: mte: Enable in-kernel MTE
Message-ID: <20200908145237.GI25591@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
 <CAAeHK+y-gJ5JKcGZYfZutKtb=BoM3qfkOyoTi7CtW6apHUcCAw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+y-gJ5JKcGZYfZutKtb=BoM3qfkOyoTi7CtW6apHUcCAw@mail.gmail.com>
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

On Tue, Sep 08, 2020 at 04:39:35PM +0200, Andrey Konovalov wrote:
> On Fri, Aug 14, 2020 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >
> > The Tag Checking operation causes a synchronous data abort as
> > a consequence of a tag check fault when MTE is configured in
> > synchronous mode.
> >
> > Enable MTE in Synchronous mode in EL1 to provide a more immediate
> > way of tag check failure detection in the kernel.
> >
> > As part of this change enable match-all tag for EL1 to allow the
> > kernel to access user pages without faulting. This is required because
> > the kernel does not have knowledge of the tags set by the user in a
> > page.
> >
> > Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
> > similar way as TCF0 affects EL0.
> >
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  arch/arm64/kernel/cpufeature.c | 6 ++++++
> >  1 file changed, 6 insertions(+)
> >
> > diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> > index 4d3abb51f7d4..4d94af19d8f6 100644
> > --- a/arch/arm64/kernel/cpufeature.c
> > +++ b/arch/arm64/kernel/cpufeature.c
> > @@ -1670,6 +1670,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
> >         write_sysreg_s(0, SYS_TFSR_EL1);
> >         write_sysreg_s(0, SYS_TFSRE0_EL1);
> >
> > +       /* Enable Match-All at EL1 */
> > +       sysreg_clear_set(tcr_el1, 0, SYS_TCR_EL1_TCMA1);
> > +
> >         /*
> >          * CnP must be enabled only after the MAIR_EL1 register has been set
> >          * up. Inconsistent MAIR_EL1 between CPUs sharing the same TLB may
> > @@ -1687,6 +1690,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
> >         mair &= ~MAIR_ATTRIDX(MAIR_ATTR_MASK, MT_NORMAL_TAGGED);
> >         mair |= MAIR_ATTRIDX(MAIR_ATTR_NORMAL_TAGGED, MT_NORMAL_TAGGED);
> >         write_sysreg_s(mair, SYS_MAIR_EL1);
> > +
> > +       /* Enable MTE Sync Mode for EL1 */
> > +       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> >         isb();
> >
> >         local_flush_tlb_all();
> > --
> > 2.28.0.220.ged08abb693-goog
> >
> 
> Should we change this commit to enable in-kernel MTE only if
> KASAN_HW_TAGS is enabled?

I think so. We don't currently have any patchset decoupling MTE from
KASAN.

See my other comment on TCR_EL1.TBI1, you'd need to set TCMA1 as well in
the same proc.S file.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908145237.GI25591%40gaia.
