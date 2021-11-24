Return-Path: <kasan-dev+bncBCSJ7B6JQALRBBXY7GGAMGQETWFEXKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A7E45CB6F
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 18:53:11 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id z16-20020a056830129000b0055c7b3ceaf5sf2047692otp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 09:53:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637776390; cv=pass;
        d=google.com; s=arc-20160816;
        b=owoJO48+kOl4wIdFc7mhHrJmng4g+ltWVomQVQ0XIhKWlPBJHKWem71jyMgtopZ4+X
         2K0AnoVU+1i6p8W7PV7XBPzGdONrTWUiPBmNhDQm9WRzTI84iyOAcKbjkm8l0+KWXoAJ
         hyqUZ/SM3B7ePOi/HeBbBQ7QIENb6izzNpH4yu7IGe2yUf8SK6w0x3a1QzOAwFMRRy85
         q/I/EdjRj1EXy7yS9sv9rg86S9yxmXqpe7oVbrUhGnyqEE7sZcaB9txEGrLYvPcGM/1V
         9fYc3Fx/fLWTXtxiuUVaVyKI4pzmR/SRONJnZGGRtXd7MwkpOBxg1wV9pOh/zq96KW1K
         lIkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=miXZa6K9xexqAduuOVXQROfQFXts5eHXXEm2H+qKTRQ=;
        b=m+zPvcAJ2nhV6cKw/g7aN5x3EEKFyj+lKr8XrvxC1DPOPP9f9sf994FZpMki4J7C3E
         4gOfQMBtXuvf5EJZbSBK0woqCZv5x52Gjs5O3R7IFcVZE5wxVuV7BivDqTNvLamTqcSq
         rUifAtApLH0OJHOiuV3mlXn1S2LpXdOz8l+qhBYI/f8FkB6XIZlDhmvvF5VCyLUJbEY4
         hPHIc0ivWVHtYf85EFzQ/1WvhPjQB/jBQTtDbZzYm5doKljUo4QPXvZH9LIvhq25THw6
         jIPerk5keSFOE0CPoGGGPItSZNNezk8Gh0JR/zvgdoIcIsCKjV5QDUs4rTo22CdN9yJk
         c+lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gqtDLTFm;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=miXZa6K9xexqAduuOVXQROfQFXts5eHXXEm2H+qKTRQ=;
        b=sLGD1nsAvT8btjqxInMeioX4cQFLDB89R1h8mudyEvQybtg8lQ/QAmix25Qj9AUm89
         MVj/LBrUufL/kev9YbEPpLABRsvp4mrb1pdsSZBi178uj+n15Henji3p251bynzynaNV
         6PYZLw7mPSYwa1UdDgP0FWVCgeSzREFTLUbPvfgsTEbO4ATQhPinM+q04I/J3GGJM68o
         CY2xkr+UqKXaHjAk2LYvGpoaYCXlE5VNuVRd2tT6H81tfYqSdMLKUmkAy0O2q+UZ4mxM
         g62jjXMDTrRUZgIzozdl1g/bPD1Vy37tPnNwEbybSNCobCUxHBlg3gVRhqtoxlASe7i0
         WqeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=miXZa6K9xexqAduuOVXQROfQFXts5eHXXEm2H+qKTRQ=;
        b=U5m5JM7zycGuP4enpHS6NWJ17JX7ubv/UNxOZYrGnNjh9aHx6tbi8xy7wOIKhflRX0
         hOjzMcbUCHtall5ehWmC/id+Q1xQp0VaKxjpdrLS+I+XrS5gMq9B66bAH8ivyyGScehI
         VocPWHxuVjbU8Fuc573JSDNFZDQCOsgkT//d5vvK7rQ9CqDypUXYmhEzGwq6H286COIg
         ddK7oPSuEn+4JuNXKuMLlrLj/Q+lPnqxQqqYuoaCPTNhO3mX1DaEAecCfbWIv7dZ/YoY
         UvtZ5oYjZkNk3ftGMvtNepIsmshrWvYMF2KzWIlHLT95APFiwTFLjfDNRudz4mUKy6qj
         gvVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5337KdsCAFmSdiVTd0DsDYumrt18ikY+lbaIwd9/VPYtrJpZZ8+5
	O42zseE+a1w7mfuAm9QFR/w=
X-Google-Smtp-Source: ABdhPJy1Tay7CAtjxkh8gXzmwxY4xSDXbJBwnnUl+A5rFx8/Q46k5n8uW+J5BQoSnesVHHipMWTQtg==
X-Received: by 2002:a05:6808:b0d:: with SMTP id s13mr8402883oij.53.1637776390309;
        Wed, 24 Nov 2021 09:53:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4110:: with SMTP id w16ls195098ott.6.gmail; Wed, 24
 Nov 2021 09:53:10 -0800 (PST)
X-Received: by 2002:a9d:62c2:: with SMTP id z2mr15713872otk.163.1637776389917;
        Wed, 24 Nov 2021 09:53:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637776389; cv=none;
        d=google.com; s=arc-20160816;
        b=taT/MOxByZXkcMknOzACRPQ9tm1KAIl5Bp2VZJIM1F1zomrK4rEVoWdib9NqugNgLj
         NlnyKBQIG6+V8Bl+lJ27aKq++YqDIetnYVqgp86nsNZ9h9ylV5/VvdLi2Ni7FddX0ChE
         tnEubn6ufEc76vKnuMxoNCzhoMd0g+cx5WeTdxQAruJ25YSlNx0DXRbqPvTrlUI/MjwU
         PkUBTbzCIfOvnBScEjtPDWJ03I4FvSZEYoeN4mgtrXWgu41d3cYRa3OpWKmeLpVyh3wn
         oEJZBKmeOurC/E8VOXmAxKwu3uSYvzMyl/rW4XXERaS8NmRCch/kbkAO/Dnuhmnpluq+
         CgiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mASyT0OMl03qWDFFy00mhqeWIkZHCHpjVkFxkJ6erhk=;
        b=1FLDwpFn+Mf+hKeH9XEoGVHnFbqLJlnzhC0poJ/iHZ+QUX6eeiCCO7LW12QijNtMbH
         YYa4VmCnLNKW9rq5H3f4GXxGeSEZeJNZY9CgGfOEw4vV/kP3zgzWYDNywEXcj4tUIQEl
         UlUVTLoMkaSzcUSUlnF8q+Qm2iY/5/1Wfd6DLLOHN3IgMRJrUUvo74zDodmYlhA/y8Wu
         zWmOsj22L5DmRo3Jyy4KdSfLzV8QO9H+BwttgoQ4pPx7VjJbD5WEdgGMY8ZYC/ZvJfq/
         AWUBxU061ZMMSNcERtq9Ty3mykf2ftVs00lk0SsTmj5adTno5uZ2wwBz0xfOqPcM2Om3
         U7Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gqtDLTFm;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id bj28si110806oib.2.2021.11.24.09.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Nov 2021 09:53:09 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-oi1-f200.google.com (mail-oi1-f200.google.com
 [209.85.167.200]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-82-5LTXg9fPNTiGuz5xchU4Vw-1; Wed, 24 Nov 2021 12:53:08 -0500
X-MC-Unique: 5LTXg9fPNTiGuz5xchU4Vw-1
Received: by mail-oi1-f200.google.com with SMTP id r15-20020acaa80f000000b002bcc50ca40dso1992190oie.5
        for <kasan-dev@googlegroups.com>; Wed, 24 Nov 2021 09:53:08 -0800 (PST)
X-Received: by 2002:a54:4f1d:: with SMTP id e29mr8178819oiy.179.1637776387523;
        Wed, 24 Nov 2021 09:53:07 -0800 (PST)
X-Received: by 2002:a54:4f1d:: with SMTP id e29mr8178778oiy.179.1637776387316;
        Wed, 24 Nov 2021 09:53:07 -0800 (PST)
Received: from treble ([2600:1700:6e32:6c00::15])
        by smtp.gmail.com with ESMTPSA id bj8sm123395oib.51.2021.11.24.09.53.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Nov 2021 09:53:06 -0800 (PST)
Date: Wed, 24 Nov 2021 09:53:03 -0800
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
Message-ID: <20211124175303.nwuk2zlnwkr7fj5f@treble>
References: <20211118081027.3175699-1-elver@google.com>
 <20211118081027.3175699-24-elver@google.com>
 <20211119203135.clplwzh3hyo5xddg@treble>
 <YZzQoz0e/oiutuq5@elver.google.com>
MIME-Version: 1.0
In-Reply-To: <YZzQoz0e/oiutuq5@elver.google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gqtDLTFm;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Tue, Nov 23, 2021 at 12:29:39PM +0100, Marco Elver wrote:
> On Fri, Nov 19, 2021 at 12:31PM -0800, Josh Poimboeuf wrote:
> > On Thu, Nov 18, 2021 at 09:10:27AM +0100, Marco Elver wrote:
> [...]
> > > +	if (insn->sec->noinstr && sym->removable_instr) {
> [...]
> > I'd love to have a clearer name than 'removable_instr', though I'm
> > having trouble coming up with something.
> [...]
> 
> I now have the below as v3 of this patch. The naming isn't entirely
> obvious, but coming up with a short name for this is tricky, but
> hopefully the comments make it clear. We can of course still pick
> another name.
> 
> Does that look reasonable?
> 
> Note, I'd like this series to sit in -next for a while (probably from
> some time next week after sending v3 if there are no further
> complaints). By default everything will be picked up by the -rcu tree,
> and we're targeting Linux 5.18.
> 
> If you feel there might be objtool conflicts coming, this patch could be
> taken through another tree as there are no hard dependencies, as long as
> this patch reaches mainline before or with the rest.
> 
> Thanks,
> -- Marco

Looks good to me.  I don't know of any upcoming conflicts, feel free to
carry it with your series for now.

Acked-by: Josh Poimboeuf <jpoimboe@redhat.com>

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211124175303.nwuk2zlnwkr7fj5f%40treble.
