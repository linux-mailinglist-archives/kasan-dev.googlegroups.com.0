Return-Path: <kasan-dev+bncBCF5XGNWYQBRB35S5P4QKGQEVKIMYLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F0FF247581
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 21:24:33 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id j11sf5479737plj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 12:24:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597692272; cv=pass;
        d=google.com; s=arc-20160816;
        b=OyvJLcmF752U+/GsFAN0wQbXjgxM+9fKDL4l1+GRfuA5h/WndBhsr5X80oW6LulWIp
         btxHvd7ATv8SRxuFpy61pdU7M+mQucK85E4VwmVY252TWcC5ImwN75ZytFWVPd8ihBfs
         SnScrlCaUJ1o+hLlRLw9R18TjobavrYwm9Lou+B9IfadJ0yHBRHC+M+dasKxzMG76vjd
         hS/ok9aw8YXXHY4oMddx38uAGfXU12jOKGD8yFn4M8TxhpuRJiKlI6vJy359mX88C8UH
         sUR6Ne4Rti3Y97coN1MY99YLjbWN0s7Y0ys7rICKv9g7SZXsKQJ26JCBaQmmbXoBWXTL
         IGJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=axGkbX0zbvW0KETusmTSOofygN4HVJKrSWvgwb98b10=;
        b=fDcESPN169w+GxsUQVc8LKzwEdTCuXBo1XA5vk1tO9OjJ1hQju6YQowUfAkisEtQmX
         PXpeA8cS1h1+/Y+Ye8dAEjEQIRr6ZfoY3P/AwDkHnJEzghVZONeEISCoQb4unJ8jgyGH
         Oz1AHHxecQIvuoFR316FXIDGJSjMcG0lAMUkMHHSKd6Ee+zGJWlWJcA05YA+/f4b3gkI
         GmzNi+kxpmlF2k/WhAxYlTARoeUjZa0zaxSGE/rasjUF8JiRCnU2/TKm9c0TJze+/ff4
         6yTLVlesWt3u34ExLBrHbY9/m45eXVa2yWqfKpP4msAwxTMhpVVLoe49It2CaCK2M3Hh
         znKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=kl0qMavr;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=axGkbX0zbvW0KETusmTSOofygN4HVJKrSWvgwb98b10=;
        b=sxyxBjYuOIZxuE4X2Q1HW2VThdRGkH9WzWWvZBJFI18xVDnW+Mv8cPWtUXnXlYWGqn
         igwXa6DOipCjFa3NCDjeH57CPOLeKYKr8al0dEQkJZgiLN+8kPpR1iqkeBOFZ8dMvMGc
         bFHSZsifEkIIKD83NNRvXW+tw/NlMrf9ZSsUZPEM8NZD98UtZBUr9gxoGHZImXiG1osP
         ahi6MdkGq8wVPPnQqUbvdrR6o04fOsB2s8JEld3pp4ioYZBp1ks8OdhJ9laucOf/Bz3I
         IxqX8tLXNzqUKbsEltm4Gf0gHwLuE6ctP+EhMBzXN0qTvP6Xstu99x3JQRBgesYaIKh9
         +jTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=axGkbX0zbvW0KETusmTSOofygN4HVJKrSWvgwb98b10=;
        b=ObPAPpqQzTfucPwjPaGwBRHyI3NztStrEQrVYkRHhUybINBz2TaS5P3VzRFuJisEro
         fIewJTEtXzgLSyQ8GElizY9qVnG/83P/Iiq/7J2TVBnHOcWG1DH6pO30vH4FFnOGSFaV
         xTzc6NLvz/CyYM9ZAKsqnyHxxojhGlHIqVwGOENRhgP0UkG5hdmjmOeBj22Cpo9QcFnz
         SyaSJeuaBg8ogB0AqtyxJh/O2ynre/hiIe5YTHcbd+AKNKep3Xso2DBrftQm2PdHI6ZX
         xH6KdOuceiX/MRDajsiAF8dJpDINuwoinEIPluB2TydTviK3z5QjUaEKLsD8drquvspM
         Eq2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cNPqLSztGRcM6JdqBHk0079bkeoG0mFKCEYboypK0mPDvOuFB
	CBX+ZwPbBdDjgTbC/8U2BM4=
X-Google-Smtp-Source: ABdhPJxjsAZVitE6DMbgTTF0T7HNtBsKvXiqbXg8Ga52y8MmrIskE+dctWem5zKsuBxLLJvTJZUFSQ==
X-Received: by 2002:a62:3641:: with SMTP id d62mr11600968pfa.82.1597692272038;
        Mon, 17 Aug 2020 12:24:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee0c:: with SMTP id z12ls7423676plb.6.gmail; Mon, 17
 Aug 2020 12:24:31 -0700 (PDT)
X-Received: by 2002:a17:902:c40d:: with SMTP id k13mr12559757plk.220.1597692271543;
        Mon, 17 Aug 2020 12:24:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597692271; cv=none;
        d=google.com; s=arc-20160816;
        b=OySzVlP9eP+0FDxCrBIwdkWK1aKDCeeGjFjPXgxg0KVLWJju4yaH+JPLz1r1iSom+Z
         8WWqeMkIJGVIM7il1UMm3C/kSjHFw54MApcQ+h10+4KSq5x4cAmYUYPH2GcUWO1F1+72
         yRa1uG11Dui/EVxCblHLDj1VHolAmNqNiQ6jKYlxHP/04Eyat1kauhYxLKR9r5bT9YV+
         1WWAaZg7v3a6a5C+cRjNYUkSzrAJC1+/bZ7G26OHe+3tc7z29+SbvqD1Kn31osmrrSoz
         GRqriVrF6BFNB4xTtzDePH4sksrx6gqDmrmvLJjxB0Q6TRz4/THR6sfh6N2yG3kjBbdY
         Mfug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=n32LWoSrsD3yQ3rMPfKnibY9bI4SixyCGhqWBe/ljHM=;
        b=liebNQvUDMj49REOxERgxuURyr+zbystML5X5xibpYtwZTnCKGqGdOOPgR/XyOizau
         V7dqHxRZuyNIEUp09qOG75u2uU80BdAC9RsgHupWVqlQnUoP6bslsH7oy2+CB1B/8R6V
         5FIU7EAKTSVzxJPf7Z4reoR80GgX7eewVqQOeeeUy7A0sJU5vOPGCMjWjGeZDBitvRId
         dYytgg0Vs9dhCNnWARENbuA8MSEu6yYnay5umd4INlJuQQZVq71b3mFs/y3IHv1c3K4z
         2OHjevszIvvTxnWz9M9bE3P01LDz9qbNt/pld8m5jrJwFbcpy1nNzY3EtrzHrX5RdO0d
         xMbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=kl0qMavr;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id kr1si1367002pjb.2.2020.08.17.12.24.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 12:24:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id s15so8572246pgc.8
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 12:24:31 -0700 (PDT)
X-Received: by 2002:a62:928d:: with SMTP id o135mr9014150pfd.22.1597692271280;
        Mon, 17 Aug 2020 12:24:31 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id i1sm21321974pfo.212.2020.08.17.12.24.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Aug 2020 12:24:30 -0700 (PDT)
Date: Mon, 17 Aug 2020 12:24:29 -0700
From: Kees Cook <keescook@chromium.org>
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Alexander Popov <alex.popov@linux.com>, Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com, linux-kernel@vger.kernel.org,
	notify@kernel.org, Kexec Mailing List <kexec@lists.infradead.org>
Subject: Re: [PATCH RFC 2/2] lkdtm: Add heap spraying test
Message-ID: <202008171222.3F206231E@keescook>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-3-alex.popov@linux.com>
 <87zh6t9llm.fsf@x220.int.ebiederm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87zh6t9llm.fsf@x220.int.ebiederm.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=kl0qMavr;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Aug 17, 2020 at 01:24:37PM -0500, Eric W. Biederman wrote:
> Alexander Popov <alex.popov@linux.com> writes:
> 
> > Add a simple test for CONFIG_SLAB_QUARANTINE.
> >
> > It performs heap spraying that aims to reallocate the recently freed heap
> > object. This technique is used for exploiting use-after-free
> > vulnerabilities in the kernel code.
> >
> > This test shows that CONFIG_SLAB_QUARANTINE breaks heap spraying
> > exploitation technique.
> >
> > Signed-off-by: Alexander Popov <alex.popov@linux.com>
> 
> Why put this test in the linux kernel dump test module?
> 
> I have no problem with tests, and I may be wrong but this
> does not look like you are testing to see if heap corruption
> triggers a crash dump.  Which is what the rest of the tests
> in lkdtm are about.  Seeing if the test triggers successfully
> triggers a crash dump.

The scope of LKDTM has shifted a bit, and I'm fine with tests that
don't cause crashes as long as they're part of testing system-wide
defenses, etc. It's easier to collect similar tests together (even if
they don't break the system).

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202008171222.3F206231E%40keescook.
