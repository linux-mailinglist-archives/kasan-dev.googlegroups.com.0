Return-Path: <kasan-dev+bncBDZKHAFW3AGBBR5U5WTAMGQEXIMVVLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7291C77CB5F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 12:58:17 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe356c71d6sf5203282e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 03:58:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692097097; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHjZOynN5JNgpgq14CaGww+B2UAQ3LH2fnnAT2rw55xng33G72LKyiARqevQJO3hdr
         F8U8S9VfxRH4N7xwboCKHPkYD7QNOglNGSxh8PdlT9dsa9vML14duSXZWNdeSQMFZdeX
         QHAEix4CPrqVbMM5gcADBbWZgCmBjwxUA9ThT9JVGXLV1opksjZgr4yXBzquQFpkqBLF
         8luq0xte7zqwn0WHovxNHcCCjAsC7lCymHv1zn7pG4ET3uyN2Fr08jn3mdHS9rKvY3KL
         Ha1Wn6smmcJP/6sP92GEMguqvuTiJ0ExFxdhoz2w9TFkFRbDBpJR+CWtC6xKgFOYtBCh
         HEOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MMuaiu4sjRJ7LU34gbMJx1lHLDrquhn2+97J2lqipLY=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=ozlbFWUTyXiVp+TIoKHwrCQchovq8OiCuH8zmTI9JkQK7DorjSjHR4gXwGhcKxK5g7
         k2XhHU9l6CpdUJc4ocPX9TZ14Q09B2lCegSdAmez8NQj+ULDX0w6Ik92Kuh1ksqFibyg
         L9c5aQM9BFHdcmRwCjGLcWG43eayYeMxNoYcVvT6zEitIvafjMS6kSSyoC4nKCkJbIhv
         GeBhrkooaDomHMBqqcg3cw0ehh9p+Mu/2PsPndJ+XrSXZa1HgQXLsz/1+PClkOuvnxq6
         CWcvswgeN1JmntvGIeVG1qggvll786X+D3dRVufIHBdBoa+PCxjk/e6uyGgo5uIxxq0W
         bR0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ROLcrlmm;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692097097; x=1692701897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MMuaiu4sjRJ7LU34gbMJx1lHLDrquhn2+97J2lqipLY=;
        b=chnuu8TL2iNZav6YEApABB42m/dOeLQIcUhBApSeJGTC2/fes0/oNCHYUhOT1DU9FN
         OY01MlcJE6mCkpRkbmBV54oyyZnpYcRLr/7ko/5qABTAJvaTJdF7u5Svcvgv9aTY4ZPY
         O//dc1yQAMGJJ8wTcLOEIZZEKYaoCXbDQ0DRahbjEe8PyMQX7GrynXbUohX7bm7N+n4B
         4NOeVRuScxbKdr72liZTs3Hiq4f6ZxSs3k5VzPx6quEdgBuXIP8wb6YzaY85bJxAlrZZ
         8IqaltZZWRLaY2xabbTAj/y1oCEvP08kiu1oy7Gnp1HjQaQ+PCfHT5wQrOvYauQ5zYib
         rNZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692097097; x=1692701897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MMuaiu4sjRJ7LU34gbMJx1lHLDrquhn2+97J2lqipLY=;
        b=DsZbmDt3ETI+4gNx3w09FuNUvM+MqNKIiNWcBc+ZcXnQblZa6cEmzBYWRwn0hx/A/w
         0k/KpDHKbtYkxV4qhNKsWijAmfdX54qs74q09G1zsJbSi6rhBvx53ncijhCbJ3J/5bLD
         AvgOed/OrPdVCODuTeT4IQcDgD0TwDVoP6DUE1O+i3Gwu+4+pXIiqKZ3mbhcJWuEWDvq
         sHbLlxnuzSgIJ06hN51wezbjMfX7AVJFtlOJ0Dnk4Lp+hHQOKyBkuzFChY00hCHQxCxN
         6JaH+i6D0J2HufUCSm1Tvm5hs8eyTkRqo6TzeWIIkXXZ5RwAlkXm1EUtrkvFpp0uDLjT
         lT4g==
X-Gm-Message-State: AOJu0YwafJEHhjfo9zD++NaFQhxwExknMp/7oe1g+Cor/L+BQN94kodA
	jLaE5PqFXGJzgiZNXtWgHdk=
X-Google-Smtp-Source: AGHT+IFSe4SZpsz/pW1XJH8k5ZzsuWKcFmavfWEKbUYaBg5fvsb+Vz5bbqOKlVR8JbYhpoe3i9ieBA==
X-Received: by 2002:ac2:5f0b:0:b0:4fb:9129:705b with SMTP id 11-20020ac25f0b000000b004fb9129705bmr7343846lfq.6.1692097095949;
        Tue, 15 Aug 2023 03:58:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:381b:0:b0:4fe:28f1:9bff with SMTP id f27-20020a19381b000000b004fe28f19bffls30659lfa.2.-pod-prod-07-eu;
 Tue, 15 Aug 2023 03:58:14 -0700 (PDT)
X-Received: by 2002:ac2:58c6:0:b0:4f8:71bf:a259 with SMTP id u6-20020ac258c6000000b004f871bfa259mr7653986lfo.67.1692097093990;
        Tue, 15 Aug 2023 03:58:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692097093; cv=none;
        d=google.com; s=arc-20160816;
        b=L2tixqCwklz2I8XjJg4ijLQig4xT+xcParVRE3TA/GPiaPDyWmv/3JFUB5viFlYfxd
         /UTGPT9UQA7A+35ATVYFEd6Kx54PwnUHwacGR0CPGXJX9eLpIrmhxCvL86lWuYnIIDae
         U//F5mq9c+3tgksQWQylhjSu67vSOiVuwJ6uWpb1i9tbXvRw8O+O0C2wZRbRb9+SpCc3
         82MjtJvxm765jdRrdVKdeXI1fMznQM+zr4NYehrwCOHH3ExRgwXNJzkyC8MpSJlzR4Oa
         DFNGNDMZwW2PocnjNdUSU/LWvqrYa99hTV+yo17vrCZGgT2zbwVsT9sbEW4KTgmcwuvf
         fhfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gqsOuPS9rp7yOJSb8hcTBqYPEnMfqvlMSYmee45nQek=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=h68oa8pxyKp69ow29ZVQtx5iuqMgP/NUFmLZbGJk/KwKC/Z4PEsd63dWmvBZcdWo9K
         kX7AFaoTAq8h4C5kFwqsmO07w1hGxTCVJPtoULfvmZjbhDC0G5PeqgGWLXwN9vMF3eaI
         CYiTXbdCd7/RArkgnJlRp6Ll/yVFjEk7n/cOanZv3mGm9Fb8Nl7RKTbNmx3gI55KwdO1
         PeNT2CFjek8ZZENPc+Tsfsj+y+NCaOuJkfZYwHX2iwWr87NphKLpCK93Ai3FlAqQIoGg
         Ri5Gfmeyvg8IRhhfNRbFJsYMaYrehsRc6zIIMmoLe+ip+PdOTBNo4rePear0RDgC2XJX
         oLCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ROLcrlmm;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id u7-20020ac258c7000000b004fe35588f4asi883678lfo.6.2023.08.15.03.58.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Aug 2023 03:58:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 2BC1C1F8B8;
	Tue, 15 Aug 2023 10:58:13 +0000 (UTC)
Received: from suse.cz (pmladek.udp.ovpn2.prg.suse.de [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 93B692C143;
	Tue, 15 Aug 2023 10:58:12 +0000 (UTC)
Date: Tue, 15 Aug 2023 12:58:11 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v3 1/2] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNtaQ0ZwL3lQ1S1M@alley>
References: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
 <20230814163344.17429-2-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230814163344.17429-2-andriy.shevchenko@linux.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=ROLcrlmm;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Mon 2023-08-14 19:33:43, Andy Shevchenko wrote:
> kernel.h is being used as a dump for all kinds of stuff for a long time.
> sprintf() and friends are used in many drivers without need of the full
> kernel.h dependency train with it.
> 
> Here is the attempt on cleaning it up by splitting out sprintf() and
> friends.
> 
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>

Reviewed-by: Petr Mladek <pmladek@suse.com>

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNtaQ0ZwL3lQ1S1M%40alley.
