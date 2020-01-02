Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB7X6W3YAKGQEOQL5XPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 4548812E4AE
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jan 2020 11:01:35 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id s25sf7974098ljm.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jan 2020 02:01:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577959295; cv=pass;
        d=google.com; s=arc-20160816;
        b=whAR1UDeU1f8YcZTbjCk/G/czuj4EhDQgKrumpAXCkuqPuwjR1o7RDWnkFGSMVMhUP
         qWtY2HdPl/YWiYe3NwR1AdjFPFbpS5+WAJRzDQbCFnThVBKHssxjcdealoS4b2Z/Pz6+
         z3TH+/xaHr2sSFNbdOv0W4aB6uubcliyTVnXc7rg7q5kFRKvVQgdInudEvSmo5G8DK9D
         0fQrYlLZANZ1UhuY7r8yI9fzRpKVTnj/3R664QZKfuYiLwN66ZZEJqYYFaidDoQeC9dI
         wtavhX0QESxCSc1Sl9EFCQL5Y9MVBHudln1q0HSxR2g578phehtPYoSfxNfcE4xaIPnL
         apAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=+6eWnY9BrAQrtlYW1ZoDyOLFhPIDnf836pydp157/2Y=;
        b=pdY9GhCm1dpLQOq7v5MULEFppsO2cFFncjLJuo5fA7GvYYKFA48I5eCD2k59Np/rWM
         ZWzZDDMyPXJgV8aeD4eURy9x1IH9yMfqNsqBdRbTlVx32GtOCUnzdInLSa0r4NJCCWrU
         K7dB9aiqP3F4zfKA3En5Nc/XKdIzAaeZ45tsEWEP79btz9bI0RZNbPQScaTEHKFK34bX
         s06bpzDDmSJu+fgkoIqcU4NPww2F8jIQ6CLoqQNPVUjjxO/RnoZlNEvvIhd6dl/0oxNk
         +VnEiAs1FA+gSod1o+DrPAbWEWyHBtXS4SBN3xW0PL9JNlladUeL5uG/LyeNiPc69B1q
         1PFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=THNzId3f;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+6eWnY9BrAQrtlYW1ZoDyOLFhPIDnf836pydp157/2Y=;
        b=LDqPJmIEzup46GpnIQZEwBu2BQK1MxhymInPIsHVkjLG3kCtuNKELtLCi2JZeTnWAx
         h4SXRjlHbYnFmLYCnZGzkvjA2MiSgWgRDrW4y4J1kWJYWSn7GtAsc3FM4WuSeeLEDr31
         pfsD2XlYXkNO5bATmc91dfhpLJ/XMW2rqKIq9pDLeKw+KqGYSFQbqsM1FUAfLWQN1CvC
         OE7NFMPb6wvOlbEJPT1S4I2sUwxPRxjaPCPi5TA7Yyr95HXgpQ4YVumUxhQqtYQyiDmA
         +aHFxrMupd5YDWxfQYUndbblfUG9SPWfTtG4h8c0oAG/oMY4WVgcebPiEeYck0UPqfUA
         /osw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+6eWnY9BrAQrtlYW1ZoDyOLFhPIDnf836pydp157/2Y=;
        b=D+jpc2oF9SYSRChY3mEvbVwDRiuZcMBG190lAROpi5qxjLu4dJhYD9oUEKPCLrKg8M
         5OIyE17Bz6GleFCmjfjd2kXzuRfYWCE8CF2x6e/oB1uLAf9+fMme2TnRyT2O2824jftF
         0pbJdHLqmo+1ZFZHy+T+7pFbp3m7wUjtHAJA1v2PlZHqQeL6c2AOgHvhawnntaRHxgIX
         OdUPH50s1VhUNbUmmz2knvlKRcjgvQUep8jLHfzB5y/LY4Zaeps0fhIk3Gs/Zz3ey6LO
         7cODWpUhdV7WSiLHlAgEyiNReXw4XEKLnRdbLCLgMiHJzykVNrbVaJI6VexSp4SxVvYN
         l6GA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUR+i0+GIyzPxn4Z1es7p/vCxHHTgY7E6IA1nP4XzBP9/jspoEx
	9/WvbE/bm6fUfOZ+oIsR0uI=
X-Google-Smtp-Source: APXvYqweNv3pZ2p2E8iTfosdszErfjqpjN2IjCVfPwvTYEQHhla8n8ecXtbk7ZpMLLXXbLmjog4ktg==
X-Received: by 2002:a19:7015:: with SMTP id h21mr45667670lfc.68.1577959294886;
        Thu, 02 Jan 2020 02:01:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4e7:: with SMTP id s7ls4609095ljm.10.gmail; Thu, 02 Jan
 2020 02:01:34 -0800 (PST)
X-Received: by 2002:a2e:9c04:: with SMTP id s4mr29599268lji.147.1577959294382;
        Thu, 02 Jan 2020 02:01:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577959294; cv=none;
        d=google.com; s=arc-20160816;
        b=vzLOAl4BQn2994xjGOBc704Gn+8ZAFD8c16XKg6yQnjr3luaOXLS3QqP9TtSeCk0L+
         GTg4P4LRxXlt/xkHpClLQ9c4dAt9OCvaA0Rk3CsuZGfcXRzQvRyAy8z4LF/k1hwz8e8/
         jc8qAi8qQoKiu+d3UtQ+ZlikxUgUsky+oeDEcqdWixM+prMsaKP8MTqDx0SYuO968Cb7
         MCuJfphEgegSNBSvkW2QnfmB0tqZssY9UqpQGZPpPS0EIxAexy3gAqrqbH0jFgFJY6uB
         SQVFsu6Za1GtCCJ5MIBQgcdav+FQtiOOBqyTTIg1kwXAN3xY02wgMvnxxJtsDrxRUUph
         Kubg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=maDj4h+HahgtslAbCIK0Uoo902uNLg7RsleRmS1ioo4=;
        b=YWQjMpXU+0K59NwtzrWj1xr0+5siwLyOlBCtDkNZ9JwhxOuLxN3OI4xFm0rIBoY0AI
         QHMdmxd2ZHmnqpoGTQXoMW0H++DY+XUr/ATOplOnujRwOHMYQ0OchwpadkccbOO1AIsk
         6tgbJjHQ11PKCxeLY1XhMB4bJVJibGqOXOJZZXfbFBLCURme0mSctllwwOUbbNMF3HYW
         tIoebJCn1NiSB8dWUq6EuQP3WZJF7QRmu+UklxsaBfyCk4ElXNGOnLhfU+d6ks4yoq8u
         YdGpCgU+4u5yzeVxiXCf+3dZFVzvPzXKcQtLdS64KhOkd0Ncmns1xi/cJTMlizQDf8iH
         Gnpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=THNzId3f;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id u5si2304028lfm.0.2020.01.02.02.01.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Jan 2020 02:01:34 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F00E700329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f00:e700:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 727051EC02FE;
	Thu,  2 Jan 2020 11:01:33 +0100 (CET)
Date: Thu, 2 Jan 2020 11:01:25 +0100
From: Borislav Petkov <bp@alien8.de>
To: "Kirill A. Shutemov" <kirill@shutemov.name>
Cc: Andy Lutomirski <luto@amacapital.net>, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v7 1/4] x86/insn-eval: Add support for 64-bit kernel mode
Message-ID: <20200102100125.GC8345@zn.tnic>
References: <20200102074705.n6cnvxrcojhlxqr5@box.shutemov.name>
 <498AAA9C-4779-4557-BBF5-A05C55563204@amacapital.net>
 <20200102092733.GA8345@zn.tnic>
 <20200102094946.3vtwrvxcyohlqoxh@box.shutemov.name>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200102094946.3vtwrvxcyohlqoxh@box.shutemov.name>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=THNzId3f;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Thu, Jan 02, 2020 at 12:49:46PM +0300, Kirill A. Shutemov wrote:
> Caller can indicate the bitness directly. It's always 32-bit for UMIP and
> get_seg_base_limit() can use insn->x86_64.

You can always send patches.

Just don't "fix" it for the sake of fixing it and the "cleanup" should
really be a cleanup not just converting it to something else. Oh, and
you need to test it too...

But you know all that. :-)

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200102100125.GC8345%40zn.tnic.
