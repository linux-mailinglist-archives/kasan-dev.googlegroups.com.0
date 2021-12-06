Return-Path: <kasan-dev+bncBC6LHPWNU4DBBPELXGGQMGQEFLWSIII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4F9D46A297
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 18:17:49 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id t135-20020a1f5f8d000000b002fe5b910f44sf4399738vkb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 09:17:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638811068; cv=pass;
        d=google.com; s=arc-20160816;
        b=M/7m4GoU5GqB9wEOCkP25AdPSjjM6l/p4CekRX2pDQjYYJfk/OWpl3EELQIT+9yDn0
         VN8/UE9A/pRTcsMnK164uyGAT7Z0dJFRLGuFLVGGT4enbE3OAWZVis2sC97FeZqz+lMA
         /oHeaHamlTssro/9IE/8jTP4t0M3BHFOpFehRVMuN546hqmU3ljJ6v69KsY6vMrVYdpw
         l5mCz48KYb4G92X0LSKznI273j6qT2EtiAmRC+9nNyNYK+FtmNiZfCPdFAumf3qM83Ja
         akbuJPWIf7pMTBzUdE3yWiYTr5WwrkTqS09z5CVgLGUH3FosjnGtVZ/pe4RxBeLXwj+g
         DE5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=rpsyu6iOfidl0Hw8ShN18NREhFcAhV29PAN2BhMGVNk=;
        b=mvcNZaJWejLGXt7aAiknWNcxdmiFmpFK7Fg8AT0eoHfe13tOAl+2NpsgBKE1OujRz8
         /X6JqmzgiXdM7B+GbIwkUznOx4Vs3OjxMLudMtyK2AzNTUNLzw1e52JwQl9lO0xmbTVT
         I9k+rCHnBxxMyUo2L2Bn7SHbSfgDiNIzSGZopX+qz+ciIlpeiy35hLJJn4A1NFZaLZOh
         IOG35Bxy7Xc0U+yKgWbHfM8K7ignC6nLPh9GsEABwefD47ulwJm9yth7kMW6wbmCfrKY
         svyguMRpsoE7/p4RQnfo+ROZaJnmX7caDKk2GT1U+xogHrWlLnf6x68DD7sEnX4YWYO+
         sz3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AwTjbe4J;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rpsyu6iOfidl0Hw8ShN18NREhFcAhV29PAN2BhMGVNk=;
        b=acH1OEmGf+zd+dnHb6kfun9gVSN6UIPWiYI1u6bjbNBdMsyhgDROzoi8vL9TI5sHjb
         yVIHIaKs0No8cOVulIiLbiJhNIoy2e97GDBAdL+1B7ZYHWUQTDjJ+8yZL+tu0LyKBlxu
         ugn9x0NgpcekEZySA5pC+Q+D6EMQgFzJnVAfBJbeT9izt3QRDnV32S+SwTBqoHsE0XVL
         QzrnYiQ2+aRb5yBY6v3FOWfFbp95VuHjtUMTC6cCqHWlW852spGG0FnnTOsdg1aZFGVK
         4POPI7LedT6NiEjPpCfWOoU5UrAzcqsvCLcrVziEF9kMKp2Uit9O/3lol7k3bICXc6ne
         3vBw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rpsyu6iOfidl0Hw8ShN18NREhFcAhV29PAN2BhMGVNk=;
        b=YX62e0wmsfPjBhfO4qMcyLfQLi+xwdeEZ9BRcahGalYoruEQMmvHZHwSb71RInBSVV
         /jh2OHCBnoVEYMmVIB2T3zbiqPlleqSDDYUCilTUCPfYamCYSECIurhbJ36cnlmZHWPk
         /ArfB+voyY65jA1+WZMg1RLZt5rIsj5pDU42rxKsPwB9VgFP+1AB5NjB7ojOwbKhIcR8
         uYvm9Nq74YeHiPaHU4AznMhBmU/NzTZwpg52pQNUdQyecwcNwJdc3sFh5+t47a2lVXHG
         TLgnny/wTCA9x4U9RCsqq+eA9EhsZRebHGp5VwntjmMI3qWFRryDl3J42SzTYefE/VpM
         pCYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rpsyu6iOfidl0Hw8ShN18NREhFcAhV29PAN2BhMGVNk=;
        b=sYEaAx0SGnPXQojAJ9q2pQRAlRrMPdqoHI5IdHWMqRfB341esiy1Q3ovMtmkeNW5Fc
         F0iETXDC4AmsaCOi25ceaVb8MR7TJgUNEz/smr7/gOU+7W/g2D5XQV9H4wKH9m5t58M9
         odJT3IFvtMVLVqC+zpKrcesdroz6xClumkoNqC7x+mRnm2x/7g5k2ZT29waF+d2m0ZiQ
         I75+kF476D+AcyMT7JKGUt7DCPiZva6ZfZbE/3CFwhHqIWIPxhWqRiKWFf6vGUWabBmI
         KLPXuxcU8z6P+TxrYsSgw7RKwE1iiuIGM77X2BukDdGQkV0mRL6VUQb460abagWzJXIN
         eamA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QDUVTfIvSpY1tQ/M89YqRPAQBnaBZyEmtuTPbS4/vRJW9me6N
	K4nJr/T16nEsHYgJWdOk88w=
X-Google-Smtp-Source: ABdhPJxvndRTX4oigbIdc7G+nEkIM7LoBDzN1eYIEBBiL8j5/1Vqiyfs1fZyHHbjgv8Tjr+AFE9sFw==
X-Received: by 2002:a05:6122:d08:: with SMTP id az8mr41910204vkb.15.1638811068599;
        Mon, 06 Dec 2021 09:17:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:12c:: with SMTP id a12ls2836425vko.3.gmail; Mon, 06
 Dec 2021 09:17:47 -0800 (PST)
X-Received: by 2002:a1f:2849:: with SMTP id o70mr42062891vko.35.1638811067923;
        Mon, 06 Dec 2021 09:17:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638811067; cv=none;
        d=google.com; s=arc-20160816;
        b=yaJnOntLpWAfsivFAmOf7QDamFqsCRPVaR0JcpMWARV/nC9B/qQkJR5It8wxCaQOF6
         lurRIxMAPnslqnIV+A5MizKX2Uf19gEQhnAENCdtzwEb7BHmNDu19kpkzx1zc1Iz8kul
         iy64sN/X2pro45OL12fkqGLIynjCTu5qupH2C6JjRhzN5GT0mlZl02N3q158sNOuSOb3
         lcK4Xgt+9mXdANhipks9oPWMvlk83758+RvuZzJ9jH6ticA7bXkuoKS1oDGAcE7QvhH1
         AXJq3IQSmK7HVdksz5RqOx9wH8fJ/NfekPPJCQ9DhqDHlCIAw35X3g5yp8rLaZFUfxk2
         ilwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aNz3Q2mlKF711FA8wRX14koPJl39WuNweWYokTQs3qU=;
        b=QS0Szzlcf58jinTauudLvXy2RqHBOaDZxGXY3xbtgudu4m/gh0B1TLGHtN0DSKXvSx
         OdVirajheoYH75kQhLqz+DCiutjyPCZDuzI7LW8TYm+5ruyf1E8pXR9WkGMsiGBrPmWp
         dKcK2oSNvQvm99CSM3Z9zzvs99fizHSRj2fah+6JbnP6tYgPCrpMCtcTUZBmP8QL+tiB
         dvanvjZcI4BXK1ly/iksjkAXdGn95nRwNCM3PBWxD504DS1Uv2FndE9EX7dVSoGaPQCA
         qxce9MOs5koaPkCNZPurs6LiXQnkKFDWb1jQs40qmBGyQvuEEAaMEDW/hKO4OO0a7mhj
         7gsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AwTjbe4J;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id 140si605009vky.3.2021.12.06.09.17.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 09:17:47 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id q72so9176276iod.12
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 09:17:47 -0800 (PST)
X-Received: by 2002:a05:6602:1609:: with SMTP id x9mr34726304iow.6.1638811067376;
        Mon, 06 Dec 2021 09:17:47 -0800 (PST)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id r3sm7030982iob.0.2021.12.06.09.17.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 09:17:46 -0800 (PST)
Received: from compute1.internal (compute1.nyi.internal [10.202.2.41])
	by mailauth.nyi.internal (Postfix) with ESMTP id 25CDA27C0064;
	Mon,  6 Dec 2021 12:17:45 -0500 (EST)
Received: from mailfrontend1 ([10.202.2.162])
  by compute1.internal (MEProxy); Mon, 06 Dec 2021 12:17:45 -0500
X-ME-Sender: <xms:uEWuYRL6RqCVh9V3LkBudn5KYREbsDRCjuiN-cl8F70X7lyS0mr_rg>
    <xme:uEWuYdLBcm8HMsTIZHEtW3eC5SLqY5ZixKc0iNd6yNf7oDRyfKBxpvc6_IQmuznM9
    lK2wG3c54QHTKjPPg>
X-ME-Received: <xmr:uEWuYZuK907atpfMNOGoJQhb2DJdLvggEQr5O0xJcD-wP4az-iZ1jntpGAg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvuddrjeefgdellecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpedvleeigedugfegveejhfejveeuveeiteejieekvdfgjeefudehfefhgfegvdeg
    jeenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsoh
    hquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedq
    udejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmh
    gvrdhnrghmvg
X-ME-Proxy: <xmx:uEWuYSaytHv6obCwpvVYsaka6TAVJfASY-_U-6UHW7fT8npY7zLJgw>
    <xmx:uEWuYYbCSW8fc1jNaUS3QD9CpdcyfsjkGo05j9PrYu_W-wiiEgY8VQ>
    <xmx:uEWuYWDTmq8SilnEKWAlXn5qYibumEtJumw0ZCN9X2wrVA_EuUkn5w>
    <xmx:uEWuYVRqeVwd13UKriZ4Y4jbXM16FeexZmySUNfPq7czO1EXmpb6_uWshfo>
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Mon,
 6 Dec 2021 12:17:44 -0500 (EST)
Date: Tue, 7 Dec 2021 01:16:25 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 08/25] kcsan: Show location access was reordered to
Message-ID: <Ya5FaU9e6XY8vHJR@boqun-archlinux>
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-9-elver@google.com>
 <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
 <CANpmjNMirKGSBW2m+bWRM9_FnjK3_HjnJC=dhyMktx50mwh1GQ@mail.gmail.com>
 <Ya4evHE7uQ9eXpax@boqun-archlinux>
 <Ya40hEQv5SEu7ZeL@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ya40hEQv5SEu7ZeL@elver.google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=AwTjbe4J;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d2b
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Mon, Dec 06, 2021 at 05:04:20PM +0100, Marco Elver wrote:
> On Mon, Dec 06, 2021 at 10:31PM +0800, Boqun Feng wrote:
> [...]
> > Thanks for the explanation, I was missing the swap here. However...
> > 
> > > So in your above example you need to swap "reordered to" and the top
> > > frame of the stack trace.
> > > 
> 
> Apologies, I wasn't entirely precise ... what you say below is correct.
> 
> > IIUC, the report for my above example will be:
> > 
> >          | write (reordered) to 0xaaaa of ...:
> >          | foo+0x... // address of the write to A
> >          | ...
> >          |  |
> >          |  +-> reordered to: foo+0x... // address of the callsite to bar() in foo()
> > 
> > , right? Because in replace_stack_entry(), it's not the top frame where
> > the race occurred that gets swapped, it's the frame which belongs to the
> > same function as the original access that gets swapped. In other words,
> > when KCSAN finds the problem, top entries of the calling stack are:
> > 
> > 	[0] bar+0x.. // address of the write to B
> > 	[1] foo+0x.. // address of the callsite to bar() in foo()
> > 
> > after replace_stack_entry(), they changes to:
> > 
> > 	[0] bar+0x.. // address of the write to B
> > skip  ->[1] foo+0x.. // address of the write to A
> > 
> > , as a result the report won't mention bar() at all.
> 
> Correct.
> 
> > And I think a better report will be:
> > 
> >          | write (reordered) to 0xaaaa of ...:
> >          | foo+0x... // address of the write to A
> >          | ...
> >          |  |
> >          |  +-> reordered to: bar+0x... // address of the write to B in bar()
> > 
> > because it tells users the exact place the accesses get reordered. That
> > means maybe we want something as below? Not completely tested, but I
> > play with scope checking a bit, seems it gives what I want. Thoughts?
> 
> This is problematic because it makes it much harder to actually figure
> out what's going on, given "reordered to" isn't a full stack trace. So
> if you're deep in some call hierarchy, seeing a random "reordered to"
> line is quite useless. What I want to see, at the very least, is the ip
> to the same function where the original access happened.
> 
> We could of course try and generate a full stack trace at "reordered
> to", but this would entail
> 
> 	a) allocating 2x unsigned long[64] on the stack (or moving to
> 	   static storage),
> 	b) further increasing the report length,
> 	c) an even larger number of possibly distinct reports for the
> 	   same issue; this makes deduplication even harder.
> 
> The reason I couldn't justify all that is that when I looked through
> several dozen "reordered to" reports, I never found anything other than
> the ip in the function frame of the original access useful. That, and in
> most cases the "reordered to" location was in the same function or in an
> inlined function.
> 
> The below patch would do what you'd want I think.
> 
> My opinion is to err on the side of simplicity until there is evidence
> we need it. Of course, if you have a compelling reason that we need it
> from the beginning, happy to send it as a separate patch on top.
> 
> What do you think?
> 

Totally agreed. It's better to keep it simple until people report that
they want to see more information to resolve the issues. And thanks for
looking into the "double stack traces", that looks good to me too.

For the original patch, feel free to add:

Reviewed-by: Boqun Feng <boqun.feng@gmail.com>

Regards,
Boqun

> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> From: Marco Elver <elver@google.com>
> Date: Mon, 6 Dec 2021 16:35:02 +0100
> Subject: [PATCH] kcsan: Show full stack trace of reordered-to accesses
> 
> Change reports involving reordered accesses to show the full stack trace
> of "reordered to" accesses. For example:
> 
>  | ==================================================================
>  | BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
>  |
>  | read-write to 0xffffffffc02d01e8 of 8 bytes by task 2481 on cpu 2:
>  |  test_kernel_wrong_memorder+0x57/0x90
>  |  access_thread+0xb7/0x100
>  |  kthread+0x2ed/0x320
>  |  ret_from_fork+0x22/0x30
>  |
>  | read-write (reordered) to 0xffffffffc02d01e8 of 8 bytes by task 2480 on cpu 0:
>  |  test_kernel_wrong_memorder+0x57/0x90
>  |  access_thread+0xb7/0x100
>  |  kthread+0x2ed/0x320
>  |  ret_from_fork+0x22/0x30
>  |   |
>  |   +-> reordered to: test_delay+0x31/0x110
>  |                     test_kernel_wrong_memorder+0x80/0x90
>  |
>  | Reported by Kernel Concurrency Sanitizer on:
>  | CPU: 0 PID: 2480 Comm: access_thread Not tainted 5.16.0-rc1+ #2
>  | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
>  | ==================================================================
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/report.c | 33 +++++++++++++++++++++++----------
>  1 file changed, 23 insertions(+), 10 deletions(-)
> 
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 67794404042a..a8317d5f5123 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -317,22 +317,29 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
>  {
>  	unsigned long symbolsize, offset;
>  	unsigned long target_func;
> -	int skip;
> +	int skip, i;
>  
>  	if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
>  		target_func = ip - offset;
>  	else
>  		goto fallback;
>  
> -	for (skip = 0; skip < num_entries; ++skip) {
> +	skip = get_stack_skipnr(stack_entries, num_entries);
> +	for (i = 0; skip < num_entries; ++skip, ++i) {
>  		unsigned long func = stack_entries[skip];
>  
>  		if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
>  			goto fallback;
>  		func -= offset;
>  
> +		replaced[i] = stack_entries[skip];
>  		if (func == target_func) {
> -			*replaced = stack_entries[skip];
> +			/*
> +			 * There must be at least 1 entry left in the original
> +			 * @stack_entries, so we know that we will never occupy
> +			 * more than @num_entries - 1 of @replaced.
> +			 */
> +			replaced[i + 1] = 0;
>  			stack_entries[skip] = ip;
>  			return skip;
>  		}
> @@ -341,6 +348,7 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
>  fallback:
>  	/* Should not happen; the resulting stack trace is likely misleading. */
>  	WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
> +	replaced[0] = 0;
>  	return get_stack_skipnr(stack_entries, num_entries);
>  }
>  
> @@ -365,11 +373,16 @@ static int sym_strcmp(void *addr1, void *addr2)
>  }
>  
>  static void
> -print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
> +print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long *reordered_to)
>  {
>  	stack_trace_print(stack_entries, num_entries, 0);
> -	if (reordered_to)
> -		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
> +	if (reordered_to[0]) {
> +		int i;
> +
> +		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to[0]);
> +		for (i = 1; i < NUM_STACK_ENTRIES && reordered_to[i]; ++i)
> +			pr_err("                    %pS\n", (void *)reordered_to[i]);
> +	}
>  }
>  
>  static void print_verbose_info(struct task_struct *task)
> @@ -390,12 +403,12 @@ static void print_report(enum kcsan_value_change value_change,
>  			 struct other_info *other_info,
>  			 u64 old, u64 new, u64 mask)
>  {
> -	unsigned long reordered_to = 0;
> +	unsigned long reordered_to[NUM_STACK_ENTRIES] = { 0 };
>  	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
>  	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
> -	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, &reordered_to);
> +	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, reordered_to);
>  	unsigned long this_frame = stack_entries[skipnr];
> -	unsigned long other_reordered_to = 0;
> +	unsigned long other_reordered_to[NUM_STACK_ENTRIES] = { 0 };
>  	unsigned long other_frame = 0;
>  	int other_skipnr = 0; /* silence uninit warnings */
>  
> @@ -408,7 +421,7 @@ static void print_report(enum kcsan_value_change value_change,
>  	if (other_info) {
>  		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
>  						      other_info->num_stack_entries,
> -						      other_info->ai.ip, &other_reordered_to);
> +						      other_info->ai.ip, other_reordered_to);
>  		other_frame = other_info->stack_entries[other_skipnr];
>  
>  		/* @value_change is only known for the other thread */
> -- 
> 2.34.1.400.ga245620fadb-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ya5FaU9e6XY8vHJR%40boqun-archlinux.
