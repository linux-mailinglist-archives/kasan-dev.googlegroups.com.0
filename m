Return-Path: <kasan-dev+bncBDDL3KWR4EBRB6UWQ6AAMGQEKHO6UBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id DAE282F818A
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:06:03 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 26sf6795660pgl.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:06:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610730362; cv=pass;
        d=google.com; s=arc-20160816;
        b=L43tbE3RFfmh7HPJkGkYEbpQ8pCmTaaAcXYUTWwhg2HA65HRJlhKLsAnoJCtQUViop
         oZNlS0UCkjFb6Il/Ch5fEwosUmPgeaDSUWoUEcpYHy5UNr+soJaokmTcVvSb4a9BvSwA
         5SjrcLbvPkv76zlqOqZSV48KuKmpDhbFHxhkMDg7ki9tuUhW8x0XYopNPZz8q6G6YRCc
         xT6h5EZMVGDaJ5QNFg+yWylJW4eGLdHI8/0KyKx7mf3sLX8vEonXN19dVgHgYEC1cdPv
         WA/UGofoZ9c6Q70JeR5hbHd7QDfRMNsVgzNppFlheDiW489U0i9AUdjh2pDZfNq1Z/ZP
         WMkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2xtuH5ooS3JGc3Z6zWaZ4PUUtJb/p1VdXBT1wrrZZFk=;
        b=VFoygP47VH6ZYVtFtFcQeDX5k3ptNbXPH9TgA6e7f6YPDfkPQnsKTiVgqMDQa6BGD4
         4Cx4bpFM5C+FCBCbvF815blR5jOMpZbeX7pJ8nWJ1lFRs+tHk5K4jJdgxVmlBIqkcRba
         DspyK0tre6kzo0NY89GzyqsJhuc8tJBgPnz+kcBELl6JBxS/W15DTt2ZUOGleKgla8mT
         7dbsHIrIMqq89pANQElsJh1M5DRyt2e03XuNRCE9qzJSdwXaWAj9rSTYucJzHoARezvV
         zQEz4OgxG7ubx5tfHJfBxbpklX8HWXjp06U+vqGqBmg6d9xVXQHotGeDpWI2wPgefEqY
         jsnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2xtuH5ooS3JGc3Z6zWaZ4PUUtJb/p1VdXBT1wrrZZFk=;
        b=ti3F9jGBE955ZxJIP9uBlcrXT5Yjhnsiwbl518G0CjBCcNfIsbDmjxHhH+ppTn21jB
         +GaX/3LMI4FrrUDs1jkkWQGBKLXtBB3ApHkUVWk7s9pHz46MN7Hul2gfXPQaAMRpr0Xh
         8RGJxO3kaiKr9R/8+ZsnWZIP1VNVXShcA/bWTpTIZDZA/jBc4ltFGpvB7l/fseTogIL/
         6c2rYGGFp9wz2cd6L5qFed1r9b+cuLF1FvrdPNWNFr6y84sDH8tZKaQujLYS3cWsPw3R
         bLIlGHcR9j+JN9Q+H5Nh8qwEZcZNkVKec/Cy4F30xv7l9woJJK3Smf0BG+WfqAYXWSQW
         rAGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2xtuH5ooS3JGc3Z6zWaZ4PUUtJb/p1VdXBT1wrrZZFk=;
        b=Oh+EOyF9V4pPba74NktQLSr5RyJdnDcVbyL5l3w9M5eQ+onkYPVL73DtoJ34bgj2Rs
         kIlynWxgf+tD+NE6rDlS6p435r28rFcr0wSlnJvL5b1S4AbY/WUNVFE7vvQrNvv2Onmh
         uPr7gPalo9PGsAk2t4eJBeoHbRAEvOR57ANHf/nTWeMegZ9GEtCihULqSn6yZvWkrV6W
         7c0NRCdn9CTBDfJjM4bB2Rk6Qmhqho27N/FObxWc48AZkPDAxxDovQpubLbSKQK7T+Vr
         msUMuWM8aKWsu/Kf115/QcCWKGXPXNHoWwxndlmQSfXNqWMFEuheR16h6JmNO1cZAtXi
         uR2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531S69BP9y7zw7TrMUuOPKUOmz2YvKLIgQ/KO6/qOmkd97Bo3jN2
	RFjfhwC2m1sutT6Drn20Y2c=
X-Google-Smtp-Source: ABdhPJwusxk6LBK/wFlGz6vj25e0yoJUsk/D6FBliVqpF5lNdh0Kn5H/cHzMmzY5C8HDV75Xb0fzew==
X-Received: by 2002:a17:902:c40b:b029:de:2f1e:825c with SMTP id k11-20020a170902c40bb02900de2f1e825cmr13845292plk.64.1610730362619;
        Fri, 15 Jan 2021 09:06:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a609:: with SMTP id u9ls4639812plq.7.gmail; Fri, 15
 Jan 2021 09:06:01 -0800 (PST)
X-Received: by 2002:a17:90b:ec2:: with SMTP id gz2mr11542091pjb.143.1610730361887;
        Fri, 15 Jan 2021 09:06:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610730361; cv=none;
        d=google.com; s=arc-20160816;
        b=0xR+watT2wtRKFlOS3m+GzkVzN2EengjsYN2Bar9+1PgD/dW+gT/LZfh995MutOn1o
         pW6Rdmiqvi10P4YPuHcyKG/z729prGwHfhavm9DxhiOESqVI+7CqJTO2dM0HxkjnlOXd
         deNfPoKFGlrftXwIeoF7ixPQfCyqwS2Mfr5f0liy8Q6/AhHFNRlDnQiDta63/p+YVIr9
         64Vo/26zyG81XSoIYWeKScxpqA0rzJ46OatXIm+ykUa42O7Z7DHHWpW64flZBv1CanZs
         GKmWEhGU0saikD2TYp+mIZ1pLcq4qk/eAqpXn6IkXfrFhEAQRBzchqyNh+aSl/ZuXv+5
         eckQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=hvPX2SImHvJ1W0hULLoXCX4XjHtKmdt+nT/p2qXObik=;
        b=dt32LrOsdLUdXpAgaeGxx8nqC1ecgBpmEJ9PRA6d/F0uAGQ51+B0Sxl8ZADGpjIw2I
         KGaccnXajNJNI5wuYgVwqzfTBouAKPrlRFSuRNwkvojL+Rq4UCuil5OgvUSHX2+jF+tB
         CVNFp3g3b7lw1caEOix4rFRPxaG9JOHNmRNkxI9CafME/yI38FTl1KH7g4GRY3Gjfxf5
         nd2YY1Fjsv2S06UkmEAkSzK/D06a3QFhO4j+EY1V90oBOo+KZj3mtK+j06pFRc2hrNgG
         AutWXn92oznpAA/9RY/qjJvhqArmxtfMIAeSehbx48VVYE4M2Glf4J6QBo25bzeqGw7b
         fTJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h11si1053327pjv.3.2021.01.15.09.06.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:06:01 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2CB0E222B3;
	Fri, 15 Jan 2021 17:05:59 +0000 (UTC)
Date: Fri, 15 Jan 2021 17:05:56 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
Message-ID: <20210115170556.GG16707@gaia>
References: <cover.1610553773.git.andreyknvl@google.com>
 <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia>
 <CAAeHK+y8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw@mail.gmail.com>
 <20210115165558.GF16707@gaia>
 <CAAeHK+wNOcA4Zgi5R8+ODMuDkLuMSYHoLinPhoeGstd78TsPjQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wNOcA4Zgi5R8+ODMuDkLuMSYHoLinPhoeGstd78TsPjQ@mail.gmail.com>
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

On Fri, Jan 15, 2021 at 06:00:36PM +0100, Andrey Konovalov wrote:
> On Fri, Jan 15, 2021 at 5:56 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
> > On Fri, Jan 15, 2021 at 05:30:40PM +0100, Andrey Konovalov wrote:
> > > On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > > > > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > > > > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > > > > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> > > > >
> > > > > Fix up the pointer tag before calling kasan_report.
> > > > >
> > > > > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > > > > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > > > > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > > ---
> > > > >  arch/arm64/mm/fault.c | 2 ++
> > > > >  1 file changed, 2 insertions(+)
> > > > >
> > > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > > index 3c40da479899..a218f6f2fdc8 100644
> > > > > --- a/arch/arm64/mm/fault.c
> > > > > +++ b/arch/arm64/mm/fault.c
> > > > > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> > > > >  {
> > > > >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > > > >
> > > > > +     /* The format of KASAN tags is 0xF<x>. */
> > > > > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
> > > >
> > > > Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> > > > was added, the only tag faults were generated for user addresses.
> > > >
> > > > Anyway, I'd rather fix it in there based on bit 55, something like (only
> > > > compile-tested):
> > > >
> > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > index 3c40da479899..2b71079d2d32 100644
> > > > --- a/arch/arm64/mm/fault.c
> > > > +++ b/arch/arm64/mm/fault.c
> > > > @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
> > > >                               struct pt_regs *regs)
> > > >  {
> > > >         /*
> > > > -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> > > > -        * check faults. Mask them out now so that userspace doesn't see them.
> > > > +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> > > > +        * for tag check faults. Set them to the corresponding bits in the
> > > > +        * untagged address.
> > > >          */
> > > > -       far &= (1UL << 60) - 1;
> > > > +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
> > > >         do_bad_area(far, esr, regs);
> > > >         return 0;
> > > >  }
> > >
> > > BTW, we can do "untagged_addr(far) | (far & MTE_TAG_MASK)" here, as
> > > untagged_addr() doesn't change kernel pointers.
> >
> > untagged_addr() does change tagged kernel pointers, it sign-extends from
> > bit 55. So the top byte becomes 0xff and you can no longer or the tag
> > bits in.
> 
> That's __untagged_addr(), untagged_addr() keeps the bits for kernel
> pointers as of  597399d0cb91.

Ah, you are right. In this case I think we should use __untagged_addr()
above. Even if the tag check fault happened on a kernel address, bits
63:60 are still unknown.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115170556.GG16707%40gaia.
