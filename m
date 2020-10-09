Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEPRQD6AKGQE7X74CMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 801EF2886B3
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 12:16:51 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id s4sf6198537pgk.17
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 03:16:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602238610; cv=pass;
        d=google.com; s=arc-20160816;
        b=wStJzcGxC0fJ5oHD5KM9zItsOXkNmUX+iSvnLDsf9qFnxQqfBGD3tXqWFmJu53xHjC
         X3Zw4dRFrSRef8pSBtR9K5RqAAXJRTIb1vqFqZSnnukwdGtntIxsuMxW59U/OQEieeW6
         htTH+eGeBVGzufZIETh0i9Q47ROPRIJrnQov5dwsKsElJ71jQGY0JT1GtAPCa+szlrl2
         P2nbjVn6/TnUnm+lC69dI20/GBqOK3xefr4GZsmU3PP+b732IWNK+V6F8Q8ufYEG/wxT
         U7TcDa2Eixp6ECRa7X6aMDyhWuSdYRt/HrVjcvG0nozGtu+eblVHdNE3MbH1VQl1QazU
         23NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OrlY/q92sHHRes9xK8CQe6+HKyEh047TlxvmeHPZb3A=;
        b=lVoQXsx2sSD069+sGviOcrVvGFslbeyuA+RgClR2KW1g3hnZmM0iVIhzISx+ejSaUu
         EOe3lxP7cl09Zh6475ngJxsgaj18d8cxEjXS5kjtnshMqnh1BMk27YZ/aE7JEwV03i54
         gE4eafWwz3CkiY40ZWrUOWc49TFvCver+lvwaqzzTZFWx2KVfpVKKAUx+SZ7but/T7VG
         LKTV6/ze2MwYUgkwsWqTQb4l/HaPPBHOpTy49T84FftZhuVdnCA/0T8EXivtzZPzNw+4
         bvH2svvFXoySmFEBDqhWg4r2iixiVsLv+HL4geSzyMuhb5W80QdFTEUg1AAocB+JMNsa
         LNaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OrlY/q92sHHRes9xK8CQe6+HKyEh047TlxvmeHPZb3A=;
        b=iGqBsoZVJh3pzG1C+2S16G5RTl5CaGkMGTOZ1Zw5KdQcH9XCoSQRuWK66XN+yufBLR
         +OC7Cta4FIw7DQam8a3ED07Io7EzSmLYmKGH0j/83LkOo4VbsW6/RNjhLH5fNJDFlJ4C
         Co6NAFauQNEsiXNtoxmiUmuoi19M9jZa2XUa20WRnDNRBam2n5vZBs6+CoJtcC1ZL8Ct
         dmJJgERFVwRNT235lreGZFmA3YxGZ3I+0dALNvpkI6mNeB2wQGmwWh+G+s+FwDulQXfg
         gYfN8Is4LGgK4/kpED1jgoTQWff6k5JM9nXfcOBOy74OfgK7snsqkg4DXIxvutaj7/vZ
         +MyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OrlY/q92sHHRes9xK8CQe6+HKyEh047TlxvmeHPZb3A=;
        b=MCPchO5XKQACBNfHwgL6t+BwGaZUlwAItDm6DLS+8bAk1N3rmtxyHq4x3Y/zZA2BIO
         rCXH1ShDJhYgPVham9aMN0O8eKDCymbvuI49Ja/sEujluCJFh+FCGT/ZXptXNtU+w0IA
         Z3KwVHcRGITdxfU721TLPI5VvV/O44ztVkxGG4yhQhmVSr05VuxBVAezsNiTAqxsmmmS
         1hvmBQNB6Kqb+Lmvmj8fm5QQFVLUOFp/n5uDsvC86bDqra8NUfCvG9WHCKsdrT7HzMkp
         gCeFpXQ56NznNS8twe6rdCOTW8X36L+EFTEpwT45Ch3Z81NK3W7Eoo3t6E39rgHiXvCO
         1veA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aCfequoOrjYhJgfAw2gQvp97s9cQ3K7jgI/HMqh4BTeCF95b9
	jAObnXO6NK116O524lYLdUc=
X-Google-Smtp-Source: ABdhPJwcrjXluXQXEIeyeSE1TO0RaO01tV4vGplqCUDg7k49DbqEdVhp1ldQk/FAqUTz9WsFosAS5A==
X-Received: by 2002:a17:90a:514e:: with SMTP id k14mr3925310pjm.48.1602238609991;
        Fri, 09 Oct 2020 03:16:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7b05:: with SMTP id w5ls2331173pfc.11.gmail; Fri, 09 Oct
 2020 03:16:49 -0700 (PDT)
X-Received: by 2002:a63:5d58:: with SMTP id o24mr2884582pgm.115.1602238609391;
        Fri, 09 Oct 2020 03:16:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602238609; cv=none;
        d=google.com; s=arc-20160816;
        b=MSB2O9CHOr/RQpI3KA61R58R5dY2z3HVEOiVqL8AtOBHNKzzLATuUQGpivZHWZHfvM
         kA2PhQt38GkSeqrPT1fOKLnNZIo8/btZYY5UtwkouYHv48Sg4rFoAB5RAY1hTP/Kk5Uh
         r1OZiZJGz2Og30BjE+ejGIkM7nYHDIDRsZ/a8/2+BYaeCARQdfe4YWtE9OYMAsAjivM2
         jnlsKAcjU5VlxayDlOJqDoSdEZ/uOKQ3z+3WvILS1rg4shmIQLduUKwIq3W3EpMiDuvy
         XNqVOCPLWjkVXBfGk60a8WezN6mf6xPZ4aODEZvUZ3smuVpZnbwPn4FkV5Kcaef8EEHG
         QxHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Z+Iwox2qfnACsZpB0SVcPqK07AKYhYr0qDSCmIE42Qg=;
        b=OAfdQuSn9banQ6bMTt+yYI0/hNomdSecNRR6F9yKwj+jrEMndUwM33H8ERPzmpIel1
         y1DSm0Kjm44C4OpaRhe0UNZMEnmmGmKCW18kzMM/wvA4JRgBTAOtWaw804heI7VH2Jdq
         EAEH4RBeG/Bqn6nGy+1D7RgTiBSnoMSCCNLDEsBbWdAIHckFmTaXm06oY4ENAiHM0cNm
         jlRUnbjdKjupkqJ+wbQfUNXt/qFPg9AH+MV6t00xFc9DQrGEmj721llIzbLRrvK1WngW
         ukVxDwAY9wLUpqrun0OaMe7nY/MNku6Xo1P8VeKX4Dwi0KBbJigUHuzbO1AZe9R+1e6D
         +xtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z15si471823plo.4.2020.10.09.03.16.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Oct 2020 03:16:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.149.105.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3CB2822276;
	Fri,  9 Oct 2020 10:16:46 +0000 (UTC)
Date: Fri, 9 Oct 2020 11:16:43 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
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
Subject: Re: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201009101643.GG23638@gaia>
References: <cover.1601593784.git.andreyknvl@google.com>
 <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
 <20201002140652.GG7034@gaia>
 <1b2327ee-5f30-e412-7359-32a7a38b4c8d@arm.com>
 <20201009081111.GA23638@gaia>
 <106f8670-3dd0-70ad-91ac-4f419585df50@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <106f8670-3dd0-70ad-91ac-4f419585df50@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Fri, Oct 09, 2020 at 10:56:02AM +0100, Vincenzo Frascino wrote:
> On 10/9/20 9:11 AM, Catalin Marinas wrote:
> > On Thu, Oct 08, 2020 at 07:24:12PM +0100, Vincenzo Frascino wrote:
> >> On 10/2/20 3:06 PM, Catalin Marinas wrote:
> >>> On Fri, Oct 02, 2020 at 01:10:30AM +0200, Andrey Konovalov wrote:
> >>>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >>>> index 7c67ac6f08df..d1847f29f59b 100644
> >>>> --- a/arch/arm64/kernel/mte.c
> >>>> +++ b/arch/arm64/kernel/mte.c
> >>>> @@ -23,6 +23,8 @@
> >>>>  #include <asm/ptrace.h>
> >>>>  #include <asm/sysreg.h>
> >>>>  
> >>>> +u64 gcr_kernel_excl __ro_after_init;
> >>>> +
> >>>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
> >>>>  {
> >>>>  	pte_t old_pte = READ_ONCE(*ptep);
> >>>> @@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >>>>  	return ptr;
> >>>>  }
> >>>>  
> >>>> +void mte_init_tags(u64 max_tag)
> >>>> +{
> >>>> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
> >>>
> >>> Nitpick: it's not obvious that MTE_TAG_MAX is a mask, so better write
> >>> this as GENMASK(min(max_tag, MTE_TAG_MAX), 0).
> >>
> >> The two things do not seem equivalent because the format of the tags in KASAN is
> >> 0xFF and in MTE is 0xF, hence if extract the minimum whatever is the tag passed
> >> by KASAN it will always be MTE_TAG_MAX.
> >>
> >> To make it cleaner I propose: GENMASK(FIELD_GET(MTE_TAG_MAX, max_tag), 0);
> > 
> > I don't think that's any clearer since FIELD_GET still assumes that
> > MTE_TAG_MAX is a mask. I think it's better to add a comment on why this
> > is needed, as you explained above that the KASAN tags go to 0xff.
> > 
> > If you want to get rid of MTE_TAG_MAX altogether, just do a
> > 
> > 	max_tag &= (1 << MAX_TAG_SIZE) - 1;
> > 
> > before setting incl (a comment is still useful).
> > 
> 
> Agree, but still think we should use FIELD_GET here since it is common language
> in the kernel.
> 
> How about we get rid of MTE_TAG_MAX and we do something like:
> 
> GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT, max_tag), 0);

It works for me and you can drop the MTE_TAG_MAX definition (I think
it's only used here).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201009101643.GG23638%40gaia.
