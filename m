Return-Path: <kasan-dev+bncBDW2JDUY5AORBPED36GQMGQENNV3FQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 95664473718
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:57:18 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id z13-20020a63e10d000000b0033b165097ccsf2770705pgh.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:57:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432637; cv=pass;
        d=google.com; s=arc-20160816;
        b=szuD4Zqmd2SbPyPDVr3CVN70VGA7GOgitNYyQD4onHVzik7WhCgJMtCZcVL9k7GO1U
         qumJI0Vi4rrLgrLJe/c6VUtDrcpRhgfW235BwU/3UYD3zUGK9txExed2VXu+OEcOEgNy
         rFwJZfckZwAlML3oMSBU6h+92RQCRH/SXJXL5C88EicuoYe5h6azooDh2+bNU682FCTT
         gxL9TlCEalm3xhQdx+pwRoUHbES0iS+gqbKjiYA8H+r5H+ODmuxU3CWa26FxQYRBHGCP
         1sF9C+0HbdSx0RJ9TsU0UlZi19iY1hcV6eCYiuglHfRIuhKDjHn+0F6bQokGupEMLnZP
         2vdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=wq5atPVcl0G4TRU/IUgu7PO1BicQotUhjLB6S/Ex96E=;
        b=l5rK2axj/4G1s/oiVeEhtd7jZK+nPcnk+siHIfpjZXoed3eev33Jla1V22f8sz4WHQ
         V4wgmCA19k7lY7P8FaK6KEaelSKcu5oudRUiMogGu2sNMmbpB1PE9xXoH1g31tZqeMOF
         I3m8calEgoQWiXDuUvQiTHVUV/5rBTD8R/eHWX/RYfLt7AAQAsoGEYPhkP154FMpSdX6
         KGjYj27e6UCgo6IkHX7nIIuePnexYKqxRCNVEUI9wonzqnBhRAnxOr3zj3pkFClSKTe9
         hBaiqbiFFmwS5H9FPQWJ7v+E2Acr3DjtVx//iC5edwkyIOkzCARoJZQRx7fkjXFq40bp
         5GoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ic0VaoHZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wq5atPVcl0G4TRU/IUgu7PO1BicQotUhjLB6S/Ex96E=;
        b=QMMk+5DfHf5tHhakGVw6hTP1jCvG1V21/MoxQFG40Td7a+neMWzg2hWqTRyOHDaiwm
         GYeG/dv9ChiPIZ4+fG57J4jza6KpMO1wvDd+wwyMNA6daoutKcx0wkI2cNLoffaxoz2P
         lBwWb9i28mKVSY7b1+k9VtiMH1Mgazc1ekxiGlDWsmF4AEc/2GH/pxERtVkQqcqu8mqU
         M3lWuG3yNMIIGd5beUiT6iE3UAqFnjTpMIOUxOAW48gtOdqzFJREP+PsRskkntDce7DS
         MxYKFVwzs6qFQ125NBGl0GEKRKOXZYGO/DO1Lf4p79iB46Ezf0X/+foeTD6fcV0QhCXa
         9B+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wq5atPVcl0G4TRU/IUgu7PO1BicQotUhjLB6S/Ex96E=;
        b=da47rlW2pdZWxeuxfhSZyWjqqQ4WnupgXtXfkiNGqzSzEsnSJ685eJclEbebT/XZ1b
         1jsd6W3NRLP9FHzEtYEqbWjEo5a5TFYF1lUdy+SgJJ5sGKKOUcbz35pWvxfbRSRTs89z
         e0Lqn7TalHN3JtH4OJCDJEQBS/RG4zCuda8TJ27nV93ddwiGOlZgu2sAV49c4y0R9Yc0
         7jM1cOjEObnf9JmXpGXND7BzI4ClFG5DPIYZvVA0KCtFA3jvNDtOt6OHMfE9mYpX3QWB
         ujOt7xt4g2bgI4BUxA2xKL8h7uC4Xz+OgMfJC58QFSun4GJqZMXoTvOXQlodvUPZPIsw
         tLfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wq5atPVcl0G4TRU/IUgu7PO1BicQotUhjLB6S/Ex96E=;
        b=laxKjXQutkSbF7UWlMjFW8r4HIlFnPXwLnauDm4InHuq7df6dqaQirUye8k/SqKa7A
         HinZMeeGBiRX64f9mhYFGPjlQU2hRj4ZVriWCEA40vlWVnfU2AcOxYtD/ZJqBGR6NT42
         TPSlT5oOFykk1KBhWvIbnwbwrffEW8cNBn6hZBtORS6j8abzbszgR55gv6RYfzHuE4ha
         StSr8/ldkvSYjgrne1+7oRshFHAidyu6yANFC9iCiJ7HDA4/EetPmL1Ilu6ExGl40Tkd
         OCbkRQLLH47JASTYk3NRAc2r6LuISm62Gk9NRtIZo/y2C0csug8c314RggLKnZKfVt9V
         BHhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531R1V1Z+SY3k5+TXJjwKN2Ntv7gG55/AE5T/C6qGRsV3LI1wIuJ
	zTlLFytpi9wnPJviRUGPBSc=
X-Google-Smtp-Source: ABdhPJzFVFkYtfsboGOHtr+eTbRa6XSr5pYx3yDvReritmdDt5xXAiNIBFEw5vJFCPEmlMwVEn4MDQ==
X-Received: by 2002:a17:902:c410:b0:142:2506:cb5b with SMTP id k16-20020a170902c41000b001422506cb5bmr1294715plk.36.1639432636807;
        Mon, 13 Dec 2021 13:57:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f20c:: with SMTP id m12ls8504221plc.3.gmail; Mon, 13
 Dec 2021 13:57:16 -0800 (PST)
X-Received: by 2002:a17:90b:38c1:: with SMTP id nn1mr964279pjb.91.1639432636245;
        Mon, 13 Dec 2021 13:57:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432636; cv=none;
        d=google.com; s=arc-20160816;
        b=Ftkeb9+bnvwmjVsWKQFhSDXgFJ1f/ZnjY8BnNDBwUNzkvkQuFWbJ36j+lgGfaTnhe3
         xdA0noyeKoUjEHIH30/Y/KTm3UGl3Wk0lwsLFM9jJWkkWWqIutIvaxCxBblfFJ/dHFIF
         izs3QY+PQQJAWgui92AMUU0b4G2L0kXpw2qHyvrp2oSJsnr5bTQR4echxkClLU6xotz1
         Y0MGN2VXYHQ6u54usqZTsK0z5waHfkSmu2iNaPyFTYcXVlsbbx30Q57ZMWnMn38kCLl5
         RhhR7bJEMP4wlrjPrC80ik8kJolY1J88ueZyQui1ADeNRMh8xUSQV0NJDtSThK7B7qbl
         E0Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SMKUwfdVnZa0OC/+PlApSfDHQCaCth1VpxrX4nAiO2A=;
        b=gbyFT78NARZGwC8IGD37oW5AqC0SzH7i4DDLOD/wsR0Sur1LXlaPj/PSUF2GwTCIT/
         fqR1Jn7Z5VWx9SLEStwNt7tfuH7rbg2ZZgAjpa49IhkmcEsdxDNFBMnh4+6Iu4JdQLfa
         gDj6zE4vUBX3+Uglvum+gy9lKebeEjGdl5qSaFFu9uaCgiMuhUA4jrKweKndzZ85rKS3
         Sw02J0iryIQQiQBzV30nicMsznnFiRFwVwkJ2oT5LO/dOfV1h/fEL+1sQdI3xO2WIOJ/
         DF7kaboCkcbtWKzTi48+usUMorjTXNePJiFUG2ueOl6QCv56WzUrfV+7FExiwsZDHH6R
         J6wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ic0VaoHZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id mu12si55648pjb.3.2021.12.13.13.57.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Dec 2021 13:57:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id e128so20649274iof.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Dec 2021 13:57:16 -0800 (PST)
X-Received: by 2002:a05:6638:2608:: with SMTP id m8mr562528jat.57.1639432635722;
 Mon, 13 Dec 2021 13:57:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com> <cca947c05c4881cf5b7548614909f1625f47be61.1638825394.git.andreyknvl@google.com>
 <YbOS/jskofqqOc0y@arm.com>
In-Reply-To: <YbOS/jskofqqOc0y@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 13 Dec 2021 22:57:05 +0100
Message-ID: <CA+fCnZd7znwWCc11NS9g+6m7G3KT=1jq1cJi7crF6QXMCky7ag@mail.gmail.com>
Subject: Re: [PATCH v2 08/34] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ic0VaoHZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 10, 2021 at 6:48 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Dec 06, 2021 at 10:43:45PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > __GFP_ZEROTAGS should only be effective if memory is being zeroed.
> > Currently, hardware tag-based KASAN violates this requirement.
> >
> > Fix by including an initialization check along with checking for
> > __GFP_ZEROTAGS.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Reviewed-by: Alexander Potapenko <glider@google.com>
> > ---
> >  mm/kasan/hw_tags.c | 3 ++-
> >  1 file changed, 2 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 0b8225add2e4..c643740b8599 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
> >        * page_alloc.c.
> >        */
> >       bool init = !want_init_on_free() && want_init_on_alloc(flags);
> > +     bool init_tags = init && (flags & __GFP_ZEROTAGS);
> >
> >       if (flags & __GFP_SKIP_KASAN_POISON)
> >               SetPageSkipKASanPoison(page);
> >
> > -     if (flags & __GFP_ZEROTAGS) {
> > +     if (init_tags) {
>
> You can probably leave this unchanged but add a WARN_ON_ONCE() if !init.
> AFAICT there's only a single place where __GFP_ZEROTAGS is passed.

Yes, there's only one such place.

In a later patch, I implement handling __GFP_ZEROTAGS in regardless of
having __GFP_ZERO present or not, so adding WARN_ON() here and then
removing it probably doesn't make much sense.

As per what you said in the other message, I've left this unchanged.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd7znwWCc11NS9g%2B6m7G3KT%3D1jq1cJi7crF6QXMCky7ag%40mail.gmail.com.
