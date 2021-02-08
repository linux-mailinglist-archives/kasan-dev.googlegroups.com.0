Return-Path: <kasan-dev+bncBCSJ7B6JQALRBN76QWAQMGQEUS2YYIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DDC6313CE0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 19:13:12 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 8sf11357569pgn.8
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 10:13:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612807991; cv=pass;
        d=google.com; s=arc-20160816;
        b=oNDOUUky3dt9Ejdaa33/+Ve/6vkSFw+5gf6EkmJ6zTfa5vdZyAtKZRr4PEzyrqRlWe
         6bQaIObnxBGvDYQxNwG50VH9JGn2BnLYOSVwTofCAk5V7qPLRvc3WVOfrV6K0RdLYYLl
         UMf2SpCfwI7cTtLX8xVwe+moeu2vsthtYTx1QcQ5eoO4nGzhRpIGdY6hRckBmELorsso
         cGv7OTQAjonf3v56392mECsh2XuIEL2PUuryG/OijFP0RkfLeqeRvOrB74TI/dVE5ir5
         Ct25QkRsO723ks3fxbG+eFM2P01nwFW8zIZ/GAfqOSpQ7CUBns+VTBnGvxHAyt1N7np+
         lnwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bED9tzO3yEVXO1B2PKABA5Cf0ukbcpHj4BCLzrfp5y8=;
        b=hUBhphjNpV5PADLaAmMVGtFfUxzGOJCj5bWySf/K5JyfhPZd9YgaAd++p00C2snImc
         xeLD4s3nB2RAJnvk+EKbIKSh97S3kEcmbiFjB/TEl8x+AOd9W5LO2JpCaJMtx/JDBji3
         JSlayuc8EHjBGlCgqu7Nb1ZTDp84Wep7VpUOlPrGbPxM7xY8M66ZrRdS8Fw85IWvMaEI
         QYUznANydkCwSQwH1xF3Rh7+Z2q18yxBjlKDJR7XzeSaTHciyzeWMuZ/0tckEFUJgfd1
         UlFWSCqyi1ofFTNqBndKSwqhBVoBxVKMZYSjMrIbhpehuFzS0EG8WdV6zj1OYq8wKAI+
         WTnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LyDZuhy3;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bED9tzO3yEVXO1B2PKABA5Cf0ukbcpHj4BCLzrfp5y8=;
        b=AF6jFlgjRrXkEPNVu3Sli1mIfWJRmkXfxk0okRPQORfigYwlQrdcX0E8wglfdOtZWP
         +c0Ac33Eq9kWrzhYzwp1Gag13StgxTODSusuoFE6j7kYomIZPxXuy2dDUKPWATvg/nT6
         OFNztrVwGB/LzSi6kXf/z4quk41S2leCle4fNOh1O+fRE5Jch/Zkm1F+ig+Wq0ZDg5cB
         GbIEEtFZhsZ+8Hug6r5D2kWea7pSbwEZA01bjp9OsI8MWn1MBS9xWcNTja62mMYgChmq
         r3ymjPWg2oFkKnxlohVqzZYz7h+IicWJpxs1i4gntF4KnU/RYlAeaPq9PzcyhFeyDEiw
         PVfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bED9tzO3yEVXO1B2PKABA5Cf0ukbcpHj4BCLzrfp5y8=;
        b=ruALd99QsGr/NbIUyer9VOQzMwyhLtd4Q9vfbNPcwze+cG8SX+nXszbCDINYgEUhfU
         kvG+FlJ23zongziJj7P3FQIkvkNbVrqLJNAs6EQ53KT45uqOCjphFHyawEIU02rqJiuz
         26CXc57yIFCEuuYJr+9AAVpeHCCc2RmOkjLADDK6/QyLN7+Q+g/H6yBQV8BrAAPALkHN
         SYf99RmolA4gTpjDC5RHPWmvBE+mhaekJMXk/H8JpaBe8Lcud0w/lIpVa/CC6dJOc9v7
         L1+puoR0uQ6aPxOKlALfPpbUnAV7bTcgliXzHFgGmISnam2tgBuajHyjsN0K15fYNZAG
         a+WA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dEdMRUkZTlmB3qr1TExC4CzZr2mHoOG2TJcMu/elwLbEYrCQi
	FNFdyIiJROXe/5yUWblJMeA=
X-Google-Smtp-Source: ABdhPJyBz6q+5vzb0QrKV+ej5QhEr3q0iBZpdq+S7zhHjY7gpaUz2e7RpB9Ai7ybJVgC9J7JLIzghg==
X-Received: by 2002:a17:902:ac8b:b029:e0:e42:dc26 with SMTP id h11-20020a170902ac8bb02900e00e42dc26mr17431280plr.44.1612807991369;
        Mon, 08 Feb 2021 10:13:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4c89:: with SMTP id m9ls3844044pgt.8.gmail; Mon, 08 Feb
 2021 10:13:10 -0800 (PST)
X-Received: by 2002:a63:9dc9:: with SMTP id i192mr18301365pgd.271.1612807990780;
        Mon, 08 Feb 2021 10:13:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612807990; cv=none;
        d=google.com; s=arc-20160816;
        b=OnAZzloE0E4WCJ9f8rvYVZJo75oTKCppEcCbrRV3w+cG5s88sg31eXN0IcewDq+FBU
         rw/5MDkIdu3MFvLwHBGRJlLBdymjBXCv21k5Crw+B4W/UzzDDzKiFpcvgP2wJIs/HG57
         Vevac5Y/rDdP6BMoBxW11D719IQRmsYK+OB1ypDYqgaHA+BEErZ+sDF85wXaB0IczBC2
         KJfrQmgoIaZlIDe8N0q4diOAJn+tVVT/poI08we0URD/gTd8PdTjAwkRtCH/7YWYShhQ
         PARD0aXZUDQuOkXiNbtg+FTHEmDObkmfP/4LHFKixUXRBUFCsqet2gaFrjJgyHmiah1b
         DgDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Vna1UpISDhhzy62RgmCODV7iVBrOXqSLXKC77p47hCA=;
        b=pm7cHSU4H9GL4/MrlFth4LH7giiOZJ9lYDZAjDSD+ez88AZRtrsMUvqoP5BVR6Dpqo
         sI49IpDqHYiAfYW9GAckiUTU2GTbr6Dq5V8VUiUJevlffzns7zac+yNoMJo6q5wXOL+Q
         WXkCESpLAmS72bNAC/WMzcb6cF74kVlA19Eflxszcl41+pKd6oWjdISvjfpqT8Yyr+LH
         O3V7Vy1j+zSDd32lT+yg6a8lTd7xhHdjrZciH9WawDi5rcj7afQoGA7l4/DbTSX6fs71
         rZRrMaVfcd+R6Fr+uYkrX0w6UeLe/m2XGq66Y39M/vKrFNWuNd0+myievsxV3V78lpeX
         pvYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LyDZuhy3;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id my11si503pjb.1.2021.02.08.10.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Feb 2021 10:13:10 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-152-LIm0O2BmNA-BWgTWAaL5AQ-1; Mon, 08 Feb 2021 13:13:07 -0500
X-MC-Unique: LIm0O2BmNA-BWgTWAaL5AQ-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id A8B141936B65;
	Mon,  8 Feb 2021 18:13:04 +0000 (UTC)
Received: from treble (ovpn-118-142.rdu2.redhat.com [10.10.118.142])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 9924860C04;
	Mon,  8 Feb 2021 18:13:02 +0000 (UTC)
Date: Mon, 8 Feb 2021 12:12:59 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Borislav Petkov <bp@suse.de>
Cc: AC <achirvasub@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	nborisov@suse.com, seth.forshee@canonical.com,
	yamada.masahiro@socionext.com
Subject: Re: [PATCH] x86/build: Disable CET instrumentation in the kernel for
 32-bit too
Message-ID: <20210208181259.hwmnoldx627jhvlm@treble>
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
 <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
 <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
 <20210208121227.GD17908@zn.tnic>
 <82FA27E6-A46F-41E2-B7D3-2FEBEA8A4D70@gmail.com>
 <20210208162543.GH17908@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210208162543.GH17908@zn.tnic>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LyDZuhy3;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Mon, Feb 08, 2021 at 05:25:43PM +0100, Borislav Petkov wrote:
> On Mon, Feb 08, 2021 at 10:19:33AM -0500, AC wrote:
> > That did fix it, thank you!
> 
> Thanks!
> 
> ---
> From: Borislav Petkov <bp@suse.de>
> Date: Mon, 8 Feb 2021 16:43:30 +0100
> Subject: [PATCH] x86/build: Disable CET instrumentation in the kernel for 32-bit too
> 
> Commit
> 
>   20bf2b378729 ("x86/build: Disable CET instrumentation in the kernel")
> 
> disabled CET instrumentation which gets added by default by the Ubuntu
> gcc9 and 10 by default, but did that only for 64-bit builds. It would
> still fail when building a 32-bit target. So disable CET for all x86
> builds.
> 
> Fixes: 20bf2b378729 ("x86/build: Disable CET instrumentation in the kernel")
> Reported-by: AC <achirvasub@gmail.com>
> Signed-off-by: Borislav Petkov <bp@suse.de>
> Tested-by: AC <achirvasub@gmail.com>
> Link: https://lkml.kernel.org/r/YCCIgMHkzh/xT4ex@arch-chirva.localdomain

Acked-by: Josh Poimboeuf <jpoimboe@redhat.com>

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208181259.hwmnoldx627jhvlm%40treble.
