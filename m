Return-Path: <kasan-dev+bncBDDL3KWR4EBRBCNGZ2GQMGQEQWVPGYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AD2794707A2
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 18:48:58 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id x5-20020a056122118500b002efcd7b7990sf6362342vkn.15
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 09:48:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639158537; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMqp33wr+oNm1MIT8SdQQOwjQKeGhnvIWhAXspFW3nWfl6fvx+ImAHvuvCxdwSc1HY
         8C0KgTwdvspxjQkdDXZh6pES4aAFOuPovLIKdv8qwa0FELGxQxlegCFxZgrtNkuPkrt0
         6S3o+ozXw0zCRyi5EM1lVuJgSUhWtog48x6a2loZRIkSX/VaeS41EOCxKJ6I4n5ssBKJ
         nqKZY5OpkIcI9+rrR9mMl/SVFCYzbkUbgNmxTmjQ+8UzErIUWZFNH5ihZlygHEhzanqV
         kG86UMRJ7SHkGelMUaqMLpV1hq1UQ8YCP+tlIelb0d8I+916XKzH6Wgb7Hs0CeglsHvR
         LVUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7diy/kkucMjjVnSMwJHnbMt1Ic/5Sd/8ey9NlbolvEA=;
        b=Yfaw8CCsP4ByXf12cJLkMJrTThZvSnhly+VE3qY1O0CwZhKnBuV9myIS5a5fM0AoZh
         BdAD7xf3ddVO4FvU8TUz3EpXYzJWb/yHfrRiDC1cpjq3xuxgFb8yGqpPiR39S4qH1V7j
         Ui6bW0j/kU5wtwgf0UQFxZtrrFJFVb6Dz3pOU3pLo8CuIOZwbh/wdjJXY/VzeYwXjVCL
         2kxjvDssxvEtxo5iuDWgIsvZhLH4d0qCd+3FqcQiRzHz+nztFKJVoGJL6bNlWiXgEnxx
         AbnP1EXmO6gflX0OfyXOcpECYD11CogEDHmTxuF4wamtr9ToRiIkLq96MacNPfjAPSDR
         a93w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7diy/kkucMjjVnSMwJHnbMt1Ic/5Sd/8ey9NlbolvEA=;
        b=ryKjEC6K/fKCc+48K3hWzxluPqPMvotEqYSOLVGqakhoZvE1IO9+5mORiyS9LyYXIC
         Yr80DHkn6fq8w7zik2tiOv2Uarxu/zToy9g2+Pd8upCk7/p9W5fMzJjJAiNI+cl2F1lC
         mJAyuGHHQnMAu2gNmGnAiV6f6H1Ce8oB2HC8+Vm+WEhPaPXTmZJSPf1VRBaNGN6eu5HO
         D0sMmQvy4PTd/896DXBrU4e1FteYrvTaRp6B2nm0jC7bsPNBNwKzhEgfNh16bnk2OqYX
         HHKWGkwsuTRdHWj8YDAVwpxU1NMoCdMzSJHaG0Xoh9p5Pv2YgQSjUKYYFwkA03PVgO5p
         A3zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7diy/kkucMjjVnSMwJHnbMt1Ic/5Sd/8ey9NlbolvEA=;
        b=BK9LJGFHCaHmPgX6U8mTrm/V76ItqLbX3Io3w9GU+IR8ZSEJcOeZK5H5CIGmE+zMh8
         vOBZDRYRj1TbXnZ4xBV39L0VwALFgexpjVl4+cYY2wi8/Xlr07lNWdZt/96F4XrEOl8X
         j5RfXCB9QzPlgD7Rkh1CFaMXqdEkbxJiCsi31/vYWgtVJ+gv2bPh55rr37W4HSH3NtFF
         M5GFPuknSYpmkC2XYiw3S/JoBDiQ7xwflcOYrzWz1WLM1Wu3QZzz6M2yBdYa5UMcxoWA
         yhMjKYpQrd0d9r9Lp8EngxLrhKth+wLyLeXfyd619J5mkVGmXIccrBrNpxhzlJi8g09I
         vApA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Fo8gb5DKs+j3PoKwj3FWCOU49tOmXXNwx21eCayEBtUorGzp1
	Xx5jBfzXuVbC1a1StBNUuBY=
X-Google-Smtp-Source: ABdhPJyB3eQYzq8oFGaMpnRYmHMMkTOcEzofy8pO1ZCboYw/ri78ZilUFpGRWBZZ+T/VkmiHB26s7w==
X-Received: by 2002:ab0:39cb:: with SMTP id g11mr30201127uaw.53.1639158537614;
        Fri, 10 Dec 2021 09:48:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6130:41e:: with SMTP id ba30ls1569506uab.9.gmail; Fri,
 10 Dec 2021 09:48:57 -0800 (PST)
X-Received: by 2002:ab0:6ecf:: with SMTP id c15mr31596748uav.113.1639158537054;
        Fri, 10 Dec 2021 09:48:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639158537; cv=none;
        d=google.com; s=arc-20160816;
        b=YP53HThzY/vnvBBI0K4xcpYT+08e4lfAnX1l0D6kHBB+mqOQUX/n/IvcnTZJK1Y7i3
         /vVV0Eqls4hCFqpn7KrhUxfSMf/NAO+0YgFz7zCv+PuVqiBul+3qjCabmq9Pu+wdI5iv
         npIhkySEzFXVfWg3Numj8PZ8/j//xJ0R5LIm7lBtHhp9TloHuRKja3Ja5qER3gZ1s2q0
         WCcfCrftL0qVmDcvV/uxwDffyYeA/+UeR2SBgQh9FKuxSrjH3zUS9weLCxHUMvtXSiO0
         MFsJslmEfi5OvCosYxDmPrvCBLBxti09Ny/+iumzkFwm4hBxuiCLB4P63uIUN9lQ8Qnd
         VBuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=02omnLPmUujgDiXWGqdC8xgFcmh5Vv59hFGQXG6heg0=;
        b=B+oxyHVtbRrys/S0HiV1VUzE/RtO1/l6XDiwpFcqlv5vr9WfVQb/pC1Z8iL24ZRJo3
         4ezjFrNysrdTq5x+QfFn7hnV+9XI5oU/awigFTz0dn9DUCZYx4X6VH38T8Go33KSqsaH
         gN6OvFDwc+EY3NlDsuWDEGT3+MWT+LX38XKpAIh39Q7cRjkWZyp1Err75NHI1IlYzvie
         XLjouhDoA+j+1hAN55xVpQWJsB9NFNQU33mLO0f7iZ45dcXfpKkdqESB+KpA3YqsHdeJ
         o+0jiMnSofHSYElXebmH1fCnzJjOzV140Zn8XuTWhtHgsJGHR5Vn1gcdyK2VFlGEJSTv
         Imuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id v5si418337vsm.1.2021.12.10.09.48.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Dec 2021 09:48:57 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 7E674CE2C73;
	Fri, 10 Dec 2021 17:48:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 94365C00446;
	Fri, 10 Dec 2021 17:48:49 +0000 (UTC)
Date: Fri, 10 Dec 2021 17:48:46 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 08/34] kasan: only apply __GFP_ZEROTAGS when memory is
 zeroed
Message-ID: <YbOS/jskofqqOc0y@arm.com>
References: <cover.1638825394.git.andreyknvl@google.com>
 <cca947c05c4881cf5b7548614909f1625f47be61.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cca947c05c4881cf5b7548614909f1625f47be61.1638825394.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.73.55 as
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

On Mon, Dec 06, 2021 at 10:43:45PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> __GFP_ZEROTAGS should only be effective if memory is being zeroed.
> Currently, hardware tag-based KASAN violates this requirement.
> 
> Fix by including an initialization check along with checking for
> __GFP_ZEROTAGS.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kasan/hw_tags.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 0b8225add2e4..c643740b8599 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
>  	 * page_alloc.c.
>  	 */
>  	bool init = !want_init_on_free() && want_init_on_alloc(flags);
> +	bool init_tags = init && (flags & __GFP_ZEROTAGS);
>  
>  	if (flags & __GFP_SKIP_KASAN_POISON)
>  		SetPageSkipKASanPoison(page);
>  
> -	if (flags & __GFP_ZEROTAGS) {
> +	if (init_tags) {

You can probably leave this unchanged but add a WARN_ON_ONCE() if !init.
AFAICT there's only a single place where __GFP_ZEROTAGS is passed.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbOS/jskofqqOc0y%40arm.com.
